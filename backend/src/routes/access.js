const express = require('express');
const jwt = require('jsonwebtoken');
const db = require('../db');
const config = require('../config');
const { hashQrToken } = require('../services/qrService');
const { verifyPassword, validateFourCharPassword } = require('../services/passwordService');
const { decryptDocument } = require('../services/cryptoService');
const storageService = require('../services/storageService');
const { logAccessAttempt } = require('../services/auditService');
const { accessAttemptLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

/**
 * Middleware: Verifies short-lived access session token for public document download/preview.
 */
function requireAccessSession(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    let token = null;

    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.slice(7).trim();
    } else if (req.query.session) {
      token = req.query.session;
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authorized access session required. Please verify the 4-character password first.',
      });
    }

    const decoded = jwt.verify(token, config.jwtSecret);
    if (!decoded.documentId || !decoded.isAccessSession) {
      return res.status(401).json({ success: false, error: 'Invalid access session token.' });
    }

    req.accessSession = decoded;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Your 15-minute access session has expired. Please enter the password again.',
        code: 'SESSION_EXPIRED',
      });
    }
    return res.status(401).json({ success: false, error: 'Access unauthorized.' });
  }
}

/**
 * GET /api/access/:qrToken/info
 * Returns document preview info (safe public metadata) for authentication screen.
 */
router.get('/:qrToken/info', async (req, res) => {
  try {
    const { qrToken } = req.params;
    const tokenHash = hashQrToken(qrToken);

    const docRes = await db.query(
      `SELECT 
        d.id, d.document_name, d.file_type, d.file_size, d.allow_download, d.block_screenshots,
        d.access_status, d.expiry_date, da.failed_attempts, da.lockout_until
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE da.qr_token_hash = $1`,
      [tokenHash]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invalid or expired QR code. The document owner may have revoked or regenerated this link.',
        code: 'QR_NOT_FOUND',
      });
    }

    const doc = docRes.rows[0];

    // Check if revoked or inactive
    if (doc.access_status === 'revoked' || doc.access_status === 'inactive') {
      return res.status(403).json({
        success: false,
        error: 'Access to this document has been revoked by the owner.',
        code: 'ACCESS_REVOKED',
      });
    }

    // Check expiry
    if (doc.expiry_date && new Date(doc.expiry_date) < new Date()) {
      return res.status(410).json({
        success: false,
        error: 'Access to this document has expired.',
        code: 'DOCUMENT_EXPIRED',
      });
    }

    // Check lockout status
    const now = new Date();
    let isLockedOut = false;
    let lockoutRemainingSeconds = 0;

    if (doc.lockout_until && new Date(doc.lockout_until) > now) {
      isLockedOut = true;
      lockoutRemainingSeconds = Math.ceil((new Date(doc.lockout_until).getTime() - now.getTime()) / 1000);
    }

    return res.json({
      success: true,
      document: {
        document_name: doc.document_name,
        file_type: doc.file_type,
        file_size: doc.file_size,
        allow_download: doc.allow_download !== false,
        block_screenshots: Boolean(doc.block_screenshots),
        isLockedOut,
        lockoutRemainingSeconds,
        failedAttempts: isLockedOut ? doc.failed_attempts : undefined,
      },
    });
  } catch (err) {
    console.error('[Access Info Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to verify QR access link.' });
  }
});

/**
 * POST /api/access/:qrToken/verify
 * Verifies 4-character password, applies rate limiting & lockout rules,
 * and issues short-lived session token.
 */
router.post('/:qrToken/verify', accessAttemptLimiter, async (req, res) => {
  const ip = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const userAgent = req.headers['user-agent'];

  try {
    const { qrToken } = req.params;
    const { password } = req.body;

    // STEP 4: Validate that exactly 4 characters are entered
    const pwdVal = validateFourCharPassword(password);
    if (!pwdVal.valid) {
      return res.status(400).json({
        success: false,
        error: pwdVal.message,
      });
    }

    const tokenHash = hashQrToken(qrToken);

    // Look up document and access record
    const docRes = await db.query(
      `SELECT 
        d.id, d.document_name, d.file_type, d.file_size, d.allow_download, d.block_screenshots,
        d.access_status, d.expiry_date, da.id as access_id, da.password_hash, da.failed_attempts, da.lockout_until
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE da.qr_token_hash = $1`,
      [tokenHash]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: 'Invalid access link. Please verify your QR code.',
      });
    }

    const doc = docRes.rows[0];

    // Status checks
    if (doc.access_status === 'revoked' || doc.access_status === 'inactive') {
      await logAccessAttempt({ documentId: doc.id, status: 'revoked', ip, userAgent });
      return res.status(403).json({
        success: false,
        error: 'Access to this document has been revoked by the owner.',
      });
    }

    if (doc.expiry_date && new Date(doc.expiry_date) < new Date()) {
      await logAccessAttempt({ documentId: doc.id, status: 'expired', ip, userAgent });
      return res.status(410).json({
        success: false,
        error: 'Access to this document has expired.',
      });
    }

    // Check Lockout
    const now = new Date();
    if (doc.lockout_until && new Date(doc.lockout_until) > now) {
      const remainingSeconds = Math.ceil((new Date(doc.lockout_until).getTime() - now.getTime()) / 1000);
      await logAccessAttempt({ documentId: doc.id, status: 'locked_out', ip, userAgent });
      return res.status(429).json({
        success: false,
        error: `Document access is temporarily locked due to repeated incorrect password attempts. Please wait ${remainingSeconds} seconds.`,
        code: 'LOCKED_OUT',
        lockoutRemainingSeconds: remainingSeconds,
      });
    }

    // STEP 6: Verify the password hash on the backend using Argon2id
    const isCorrect = await verifyPassword(doc.password_hash, String(password).trim());

    if (!isCorrect) {
      const newFailedAttempts = (doc.failed_attempts || 0) + 1;
      let lockoutDate = null;
      let isNowLocked = false;
      let lockoutSeconds = 0;

      // Section 6 requirement: Maximum 5 incorrect attempts before temporary lockout
      if (newFailedAttempts >= config.maxFailedAttempts) {
        lockoutDate = new Date(Date.now() + config.lockoutDurationMinutes * 60 * 1000).toISOString();
        isNowLocked = true;
        lockoutSeconds = config.lockoutDurationMinutes * 60;
      }

      await db.query(
        `UPDATE document_access 
         SET failed_attempts = $1, lockout_until = $2, updated_at = CURRENT_TIMESTAMP
         WHERE id = $3`,
        [newFailedAttempts, lockoutDate, doc.access_id]
      );

      await logAccessAttempt({ documentId: doc.id, status: 'failed_password', ip, userAgent });

      const remainingAttempts = Math.max(0, config.maxFailedAttempts - newFailedAttempts);

      if (isNowLocked) {
        return res.status(429).json({
          success: false,
          error: `Maximum incorrect attempts reached (5). This document is now locked for ${config.lockoutDurationMinutes} minutes to prevent unauthorized access.`,
          code: 'LOCKED_OUT',
          lockoutRemainingSeconds: lockoutSeconds,
        });
      }

      return res.status(401).json({
        success: false,
        error: `Incorrect 4-character password. You have ${remainingAttempts} attempt(s) remaining before temporary lockout.`,
        code: 'INCORRECT_PASSWORD',
        remainingAttempts,
      });
    }

    // Correct password: reset failed attempts
    await db.query(
      `UPDATE document_access 
       SET failed_attempts = 0, lockout_until = NULL, updated_at = CURRENT_TIMESTAMP
       WHERE id = $1`,
      [doc.access_id]
    );

    // STEP 7: Create a short-lived authorized session (15 minutes)
    const accessSessionToken = jwt.sign(
      {
        documentId: doc.id,
        isAccessSession: true,
      },
      config.jwtSecret,
      { expiresIn: config.accessSessionExpiresIn }
    );

    // Log successful access
    await logAccessAttempt({ documentId: doc.id, status: 'success', ip, userAgent });

    // STEP 8: Return authorized session token and document info
    return res.json({
      success: true,
      message: 'Password verified successfully! Access granted.',
      accessSessionToken,
      document: {
        id: doc.id,
        document_name: doc.document_name,
        file_type: doc.file_type,
        file_size: doc.file_size,
        allow_download: doc.allow_download !== false,
        block_screenshots: Boolean(doc.block_screenshots),
      },
    });
  } catch (err) {
    console.error('[Password Verify Error]', err);
    return res.status(500).json({ success: false, error: 'Verification failed. Please try again.' });
  }
});

/**
 * GET /api/access/:qrToken/preview
 * Streams decrypted document to recipient after successful password verification.
 */
router.get('/:qrToken/preview', requireAccessSession, async (req, res) => {
  try {
    const { qrToken } = req.params;
    const tokenHash = hashQrToken(qrToken);

    const docRes = await db.query(
      `SELECT d.* 
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE da.qr_token_hash = $1 AND d.id = $2`,
      [tokenHash, req.accessSession.documentId]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Authorized document not found.' });
    }

    const doc = docRes.rows[0];

    // Decrypt on the fly using AES-256-GCM
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
    if (doc.allow_download === false || doc.block_screenshots) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
    }

    return res.send(decryptedBuffer);
  } catch (err) {
    console.error('[Public Preview Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to preview authorized document.' });
  }
});

/**
 * GET /api/access/:qrToken/download
 * Downloads decrypted document to recipient after successful password verification.
 */
router.get('/:qrToken/download', requireAccessSession, async (req, res) => {
  try {
    const { qrToken } = req.params;
    const tokenHash = hashQrToken(qrToken);

    const docRes = await db.query(
      `SELECT d.* 
       FROM documents d
       JOIN document_access da ON d.id = da.document_id
       WHERE da.qr_token_hash = $1 AND d.id = $2`,
      [tokenHash, req.accessSession.documentId]
    );

    if (docRes.rows.length === 0) {
      return res.status(404).json({ success: false, error: 'Authorized document not found.' });
    }

    const doc = docRes.rows[0];

    if (doc.allow_download === false) {
      return res.status(403).json({
        success: false,
        error: 'Downloading has been disabled by the document owner. This file is view-only.',
        code: 'DOWNLOAD_DISABLED',
      });
    }

    const encryptedBuffer = await storageService.readEncryptedDocument(doc);
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
    console.error('[Public Download Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to download authorized document.' });
  }
});

module.exports = router;
