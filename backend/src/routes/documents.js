const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const db = require('../db');
const config = require('../config');

const uuidv4 = () => crypto.randomUUID();
const { requireAuth } = require('../middleware/auth');
const { validateUploadedFile } = require('../utils/fileValidator');
const { encryptDocument, decryptDocument } = require('../services/cryptoService');
const { generateFourCharPassword, validateFourCharPassword, hashPassword } = require('../services/passwordService');
const { 
  generateQrToken, 
  hashQrToken, 
  getDocumentAccessUrl, 
  generateQrDataUrl, 
  generateQrPngBuffer 
} = require('../services/qrService');
const storageService = require('../services/storageService');

const router = express.Router();

// Configure multer memory storage (unencrypted files stay in RAM only during encryption)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: config.maxFileSize,
    files: 10, // Up to 10 files in multiple upload
  },
});

/**
 * Strips sensitive storage and encryption fields before returning document rows to clients.
 */
function sanitizeDocSummary(doc) {
  return {
    id: doc.id,
    document_name: doc.document_name,
    original_name: doc.original_name,
    file_type: doc.file_type,
    mime_type: doc.mime_type,
    file_size: doc.file_size,
    allow_download: doc.allow_download !== false,
    block_screenshots: Boolean(doc.block_screenshots),
    expiry_date: doc.expiry_date,
    access_status: doc.access_status,
    failed_attempts: doc.failed_attempts,
    lockout_until: doc.lockout_until,
    created_at: doc.created_at,
    updated_at: doc.updated_at,
  };
}

/**
 * Process a single uploaded file buffer into encrypted storage and DB records
 */
async function processDocumentUpload({
  file,
  userId,
  customPassword,
  expiryDate,
  requestOrigin,
  allowDownload = true,
  blockScreenshots = false,
}) {
  // 1. Validate file (extension, magic bytes, size, dangerous types)
  const validation = validateUploadedFile(file);
  if (!validation.valid) {
    throw new Error(validation.error);
  }

  // 2. Determine 4-character password
  let plainPassword = customPassword;
  if (plainPassword) {
    const pwdVal = validateFourCharPassword(plainPassword);
    if (!pwdVal.valid) {
      throw new Error(pwdVal.message);
    }
  } else {
    plainPassword = generateFourCharPassword();
  }

  // 3. Hash 4-character password with Argon2id
  const argon2Hash = await hashPassword(plainPassword);

  // 4. Encrypt document with AES-256-GCM Envelope Encryption
  const { encryptedData, encryptedStorageKey, iv, authTag } = encryptDocument(file.buffer);

  // 5. Save encrypted document to private vault storage
  const storageFilePath = await storageService.saveEncryptedFile(encryptedData);

  // 6. Generate QR token and hash
  const rawQrToken = generateQrToken();
  const tokenHash = hashQrToken(rawQrToken);
  const accessUrl = getDocumentAccessUrl(rawQrToken, requestOrigin);
  const qrDataUrl = await generateQrDataUrl(accessUrl);

  const docId = uuidv4();
  const expiryIso = expiryDate ? new Date(expiryDate).toISOString() : null;
  const encryptedPayloadBase64 = encryptedData.toString('base64');

  // 7. Insert into documents table
  await db.query(
    `INSERT INTO documents (
      id, user_id, document_name, original_name, file_type, mime_type, file_size,
      encrypted_file_path, encrypted_storage_key, encrypted_payload, iv, auth_tag,
      allow_download, block_screenshots, expiry_date, access_status
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)`,
    [
      docId,
      userId,
      validation.sanitizedName,
      file.originalname,
      validation.ext,
      file.mimetype || 'application/octet-stream',
      file.size,
      storageFilePath,
      encryptedStorageKey,
      encryptedPayloadBase64,
      iv,
      authTag,
      Boolean(allowDownload),
      Boolean(blockScreenshots),
      expiryIso,
      'active',
    ]
  );

  // 8. Insert into document_access table
  await db.query(
    `INSERT INTO document_access (
      document_id, password_hash, qr_token_hash, failed_attempts
    ) VALUES ($1, $2, $3, $4)`,
    [docId, argon2Hash, tokenHash, 0]
  );

  return {
    id: docId,
    document_name: validation.sanitizedName,
    original_name: file.originalname,
    file_type: validation.ext,
    file_size: file.size,
    mime_type: file.mimetype,
    allow_download: Boolean(allowDownload),
    block_screenshots: Boolean(blockScreenshots),
    expiry_date: expiryIso,
    access_status: 'active',
    rawQrToken,
    accessUrl,
    qrDataUrl,
    plainPassword, // Shown to owner on upload
    created_at: new Date().toISOString(),
  };
}

/**
 * POST /api/documents/upload
 * Handles single or multiple document uploads.
 */
router.post('/upload', requireAuth, upload.array('files', 10), async (req, res) => {
  try {
    if (!req.files || req.files.length === 0) {
      return res.status(400).json({ success: false, error: 'Please select at least one file to upload.' });
    }

    const { custom_password, expiry_date, allow_download, block_screenshots } = req.body;
    const allowDownloadBool = allow_download === undefined ? true : String(allow_download).toLowerCase() !== 'false';
    const blockScreenshotsBool = String(block_screenshots).toLowerCase() === 'true';

    const uploadedDocs = [];
    const errors = [];

    for (const file of req.files) {
      try {
        const result = await processDocumentUpload({
          file,
          userId: req.user.id,
          customPassword: custom_password ? String(custom_password).trim() : null,
          expiryDate: expiry_date,
          requestOrigin: req.headers.origin,
          allowDownload: allowDownloadBool,
          blockScreenshots: blockScreenshotsBool,
        });
        uploadedDocs.push(result);
      } catch (err) {
        errors.push({ file: file.originalname, error: err.message });
      }
    }

    if (uploadedDocs.length === 0) {
      return res.status(400).json({
        success: false,
        error: errors.map(e => `${e.file}: ${e.error}`).join('; '),
        errors,
      });
    }

    return res.status(201).json({
      success: true,
      message: `Successfully uploaded and encrypted ${uploadedDocs.length} document(s).`,
      documents: uploadedDocs,
      errors: errors.length > 0 ? errors : undefined,
    });
  } catch (err) {
    console.error('[Document Upload Error]', err);
    return res.status(500).json({ success: false, error: 'Upload failed: ' + err.message });
  }
});

/**
 * GET /api/documents/stats
 * Dashboard statistics for authenticated user.
 */
router.get('/stats', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;

    // Fetch user documents
    const docsRes = await db.query(
      `SELECT id, access_status, created_at, expiry_date FROM documents WHERE user_id = $1`,
      [userId]
    );

    const docs = docsRes.rows;
    const now = new Date();

    const totalUploaded = docs.length;
    let totalActive = 0;
    let totalRevoked = 0;
    let totalExpired = 0;

    docs.forEach(doc => {
      if (doc.access_status === 'revoked') {
        totalRevoked++;
      } else if (doc.expiry_date && new Date(doc.expiry_date) < now) {
        totalExpired++;
      } else if (doc.access_status === 'active') {
        totalActive++;
      }
    });

    // Recent 5 uploads
    const recentRes = await db.query(
      `SELECT id, document_name, file_type, file_size, allow_download, block_screenshots, access_status, created_at 
       FROM documents 
       WHERE user_id = $1 
       ORDER BY created_at DESC 
       LIMIT 5`,
      [userId]
    );

    return res.json({
      success: true,
      stats: {
        totalUploaded,
        totalActiveQrCodes: totalActive,
        totalActiveDocuments: totalActive,
        totalRevokedDocuments: totalRevoked,
        totalExpiredDocuments: totalExpired,
        recentUploads: recentRes.rows.map(sanitizeDocSummary),
      },
    });
  } catch (err) {
    console.error('[Stats Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to load dashboard statistics.' });
  }
});

/**
 * GET /api/documents
 * List documents with search, type filtering, sorting, and pagination.
 */
router.get('/', requireAuth, async (req, res) => {
  try {
    const userId = req.user.id;
    const { search, file_type, status, sort_by = 'created_at', order = 'desc', page = 1, limit = 10 } = req.query;

    const pageNum = Math.max(1, parseInt(page, 10));
    const limitNum = Math.min(50, Math.max(1, parseInt(limit, 10)));
    const offset = (pageNum - 1) * limitNum;

    let queryStr = `
      SELECT 
        d.id, d.document_name, d.original_name, d.file_type, d.mime_type, 
        d.file_size, d.allow_download, d.block_screenshots, d.expiry_date, d.access_status, d.created_at, d.updated_at,
        da.failed_attempts, da.lockout_until
      FROM documents d
      LEFT JOIN document_access da ON d.id = da.document_id
      WHERE d.user_id = $1
    `;
    const params = [userId];

    if (search && search.trim()) {
      params.push(`%${search.trim()}%`);
      queryStr += ` AND d.document_name ILIKE $${params.length}`;
    }

    if (file_type && file_type !== 'all') {
      params.push(file_type.toLowerCase());
      queryStr += ` AND d.file_type = $${params.length}`;
    }

    if (status && status !== 'all') {
      params.push(status.toLowerCase());
      queryStr += ` AND d.access_status = $${params.length}`;
    }

    // Sort order
    const validSortCols = {
      created_at: 'd.created_at',
      document_name: 'd.document_name',
      file_size: 'd.file_size',
    };
    const sortCol = validSortCols[sort_by] || 'd.created_at';
    const sortOrder = order.toLowerCase() === 'asc' ? 'ASC' : 'DESC';

    queryStr += ` ORDER BY ${sortCol} ${sortOrder} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    params.push(limitNum, offset);

    const result = await db.query(queryStr, params);

    // Count total for pagination
    let countSql = `SELECT COUNT(*) FROM documents WHERE user_id = $1`;
    const countParams = [userId];
    if (search && search.trim()) {
      countParams.push(`%${search.trim()}%`);
      countSql += ` AND document_name ILIKE $${countParams.length}`;
    }
    if (file_type && file_type !== 'all') {
      countParams.push(file_type.toLowerCase());
      countSql += ` AND file_type = $${countParams.length}`;
    }
    if (status && status !== 'all') {
      countParams.push(status.toLowerCase());
      countSql += ` AND access_status = $${countParams.length}`;
    }
    const countRes = await db.query(countSql, countParams);
    const totalCount = parseInt(countRes.rows[0].count, 10);

    return res.json({
      success: true,
      documents: result.rows.map(sanitizeDocSummary),
      pagination: {
        page: pageNum,
        limit: limitNum,
        total: totalCount,
        totalPages: Math.ceil(totalCount / limitNum),
      },
    });
  } catch (err) {
    console.error('[Document List Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to retrieve documents.' });
  }
});

/**
 * GET /api/documents/:id
 * Retrieves document details and current QR code.
 */
router.get('/:id', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query(
      `SELECT d.*, da.failed_attempts, da.lockout_until 
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE d.id = $1 AND d.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    return res.json({
      success: true,
      document: sanitizeDocSummary(doc),
    });
  } catch (err) {
    console.error('[Document Detail Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to load document.' });
  }
});

/**
 * GET /api/documents/:id/download
 * Owner direct download (decrypts file on the fly).
 */
router.get('/:id/download', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query(
      `SELECT * FROM documents WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // Read encrypted data from storage (disk or DB payload fallback)
    const encryptedBuffer = await storageService.readEncryptedDocument(doc);

    // Decrypt on the fly using AES-256-GCM
    const decryptedBuffer = decryptDocument(
      encryptedBuffer,
      doc.encrypted_storage_key,
      doc.iv,
      doc.auth_tag
    );

    res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `attachment; filename="${encodeURIComponent(doc.original_name)}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);

    return res.send(decryptedBuffer);
  } catch (err) {
    console.error('[Download Error]', err);
    return res.status(500).json({ success: false, error: 'Decryption or download failed: ' + err.message });
  }
});

/**
 * GET /api/documents/:id/preview
 * Owner preview/stream (decrypts file on the fly for browser viewing).
 */
router.get('/:id/preview', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query(
      `SELECT * FROM documents WHERE id = $1 AND user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    const encryptedBuffer = await storageService.readEncryptedDocument(doc);
    const decryptedBuffer = decryptDocument(
      encryptedBuffer,
      doc.encrypted_storage_key,
      doc.iv,
      doc.auth_tag
    );

    res.setHeader('Content-Type', doc.mime_type || 'application/octet-stream');
    res.setHeader('Content-Disposition', `inline; filename="${encodeURIComponent(doc.original_name)}"`);
    res.setHeader('Content-Length', decryptedBuffer.length);

    return res.send(decryptedBuffer);
  } catch (err) {
    console.error('[Preview Error]', err);
    return res.status(500).json({ success: false, error: 'Decryption or preview failed.' });
  }
});

/**
 * GET /api/documents/:id/qr-download
 * Downloads downloadable PNG QR code image.
 */
router.get('/:id/qr-download', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query(
      `SELECT d.id, d.document_name, da.qr_token_hash 
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE d.id = $1 AND d.user_id = $2`,
      [req.params.id, req.user.id]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // Note: The database stores the hash of the QR token. When regenerated or requested,
    // if accessUrl query param is passed, we generate direct PNG buffer.
    const accessUrl = req.query.url || `${config.frontendUrl}/access/${doc.id}`;
    const pngBuffer = await generateQrPngBuffer(accessUrl);

    res.setHeader('Content-Type', 'image/png');
    res.setHeader('Content-Disposition', `attachment; filename="QR-${doc.document_name}.png"`);
    return res.send(pngBuffer);
  } catch (err) {
    console.error('[QR Download Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to generate QR code PNG.' });
  }
});

/**
 * PUT /api/documents/:id/password
 * Owner sets a new 4-character password (custom or auto-generated).
 */
router.put('/:id/password', requireAuth, async (req, res) => {
  try {
    const { new_password, auto_generate } = req.body;

    let plainPassword = new_password;
    if (auto_generate || !plainPassword) {
      plainPassword = generateFourCharPassword();
    } else {
      const pwdVal = validateFourCharPassword(plainPassword);
      if (!pwdVal.valid) {
        return res.status(400).json({ success: false, error: pwdVal.message });
      }
    }

    const docRes = await db.query('SELECT id FROM documents WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.user.id,
    ]);

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const newHash = await hashPassword(plainPassword);

    await db.query(
      `UPDATE document_access 
       SET password_hash = $1, failed_attempts = 0, lockout_until = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE document_id = $2`,
      [newHash, req.params.id]
    );

    return res.json({
      success: true,
      message: '4-character password updated successfully.',
      password: plainPassword, // Return so owner can view & copy
    });
  } catch (err) {
    console.error('[Password Update Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to update password.' });
  }
});

/**
 * POST /api/documents/:id/regenerate-qr
 * Revokes old QR code and issues a brand new unpredictable access token and QR code.
 */
router.post('/:id/regenerate-qr', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query('SELECT id FROM documents WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.user.id,
    ]);

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const newRawToken = generateQrToken();
    const newTokenHash = hashQrToken(newRawToken);
    const accessUrl = getDocumentAccessUrl(newRawToken, req.headers.origin);
    const qrDataUrl = await generateQrDataUrl(accessUrl);

    // Update document_access with new QR token hash and reset lockouts
    await db.query(
      `UPDATE document_access 
       SET qr_token_hash = $1, failed_attempts = 0, lockout_until = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE document_id = $2`,
      [newTokenHash, req.params.id]
    );

    // Ensure document access status is active
    await db.query(
      `UPDATE documents SET access_status = 'active', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
      [req.params.id]
    );

    return res.json({
      success: true,
      message: 'QR code regenerated successfully. Previous QR codes have been invalidated.',
      rawQrToken: newRawToken,
      accessUrl,
      qrDataUrl,
    });
  } catch (err) {
    console.error('[Regenerate QR Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to regenerate QR code.' });
  }
});

/**
 * PUT /api/documents/:id/status
 * Updates document status (active, inactive, revoked) and expiry date.
 */
router.put('/:id/status', requireAuth, async (req, res) => {
  try {
    const { access_status, expiry_date, allow_download, block_screenshots } = req.body;

    const validStatuses = ['active', 'inactive', 'revoked'];
    if (access_status && !validStatuses.includes(access_status)) {
      return res.status(400).json({ success: false, error: 'Invalid access status.' });
    }

    const docRes = await db.query('SELECT id FROM documents WHERE id = $1 AND user_id = $2', [
      req.params.id,
      req.user.id,
    ]);

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const updateFields = [];
    const params = [req.params.id, req.user.id];

    if (access_status) {
      params.push(access_status);
      updateFields.push(`access_status = $${params.length}`);
    }

    if (expiry_date !== undefined) {
      const expVal = expiry_date ? new Date(expiry_date).toISOString() : null;
      params.push(expVal);
      updateFields.push(`expiry_date = $${params.length}`);
    }

    if (allow_download !== undefined) {
      params.push(Boolean(allow_download));
      updateFields.push(`allow_download = $${params.length}`);
    }

    if (block_screenshots !== undefined) {
      params.push(Boolean(block_screenshots));
      updateFields.push(`block_screenshots = $${params.length}`);
    }

    if (updateFields.length === 0) {
      return res.status(400).json({ success: false, error: 'No fields to update.' });
    }

    updateFields.push('updated_at = CURRENT_TIMESTAMP');

    const updateSql = `
      UPDATE documents 
      SET ${updateFields.join(', ')} 
      WHERE id = $1 AND user_id = $2 
      RETURNING id, document_name, access_status, allow_download, block_screenshots, expiry_date, updated_at
    `;

    const updated = await db.query(updateSql, params);

    return res.json({
      success: true,
      message: 'Document access settings updated.',
      document: updated.rows[0],
    });
  } catch (err) {
    console.error('[Status Update Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to update access settings.' });
  }
});

/**
 * DELETE /api/documents/:id
 * Permanently deletes encrypted document from vault and clears DB records.
 */
router.delete('/:id', requireAuth, async (req, res) => {
  try {
    const docRes = await db.query(
      'SELECT id, encrypted_file_path FROM documents WHERE id = $1 AND user_id = $2',
      [req.params.id, req.user.id]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Document not found.' });
    }

    const doc = docRes.rows[0];

    // 1. Delete physical encrypted file from vault
    await storageService.deleteEncryptedFile(doc.encrypted_file_path);

    // 2. Cascade delete database records (documents, document_access, access_logs)
    await db.query('DELETE FROM documents WHERE id = $1', [doc.id]);

    return res.json({
      success: true,
      message: 'Document deleted permanently from vault.',
    });
  } catch (err) {
    console.error('[Delete Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to delete document.' });
  }
});

module.exports = router;
