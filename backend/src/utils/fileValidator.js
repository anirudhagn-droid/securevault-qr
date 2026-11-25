const path = require('path');
const config = require('../config');

// Supported extensions and canonical MIME types
const ALLOWED_EXTENSIONS = new Set([
  'pdf',
  'doc',
  'docx',
  'jpg',
  'jpeg',
  'png',
  'ppt',
  'pptx',
  'xls',
  'xlsx',
  'txt',
]);

const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'sh', 'bash', 'vbs', 'vbe', 'js', 'jse', 'wsf', 'wsh',
  'msi', 'msp', 'dll', 'sys', 'com', 'scr', 'cpl', 'jar', 'py', 'ps1', 'php'
]);

/**
 * Checks magic byte signatures for uploaded buffers.
 * Sniffs first few bytes to prevent file extension spoofing attacks (e.g. evil.exe renamed to evil.png).
 * 
 * @param {Buffer} buffer 
 * @param {string} ext 
 * @returns {boolean}
 */
function verifyMagicBytes(buffer, ext) {
  if (!buffer || buffer.length < 4) return false;

  switch (ext) {
    case 'pdf':
      // PDF header: %PDF (0x25 0x50 0x44 0x46)
      return buffer.slice(0, 4).toString('utf8') === '%PDF';

    case 'png':
      // PNG header: 0x89 0x50 0x4E 0x47
      return (
        buffer[0] === 0x89 &&
        buffer[1] === 0x50 &&
        buffer[2] === 0x4e &&
        buffer[3] === 0x47
      );

    case 'jpg':
    case 'jpeg':
      // JPEG header: 0xFF 0xD8 0xFF
      return buffer[0] === 0xff && buffer[1] === 0xd8 && buffer[2] === 0xff;

    case 'docx':
    case 'pptx':
    case 'xlsx':
      // Modern Office files are PKZip archives: 0x50 0x4B 0x03 0x04
      return buffer[0] === 0x50 && buffer[1] === 0x4b && buffer[2] === 0x03 && buffer[3] === 0x04;

    case 'doc':
    case 'ppt':
    case 'xls':
      // Legacy Office compound document header: 0xD0 0xCF 0x11 0xE0
      return buffer[0] === 0xd0 && buffer[1] === 0xcf && buffer[2] === 0x11 && buffer[3] === 0xe0;

    case 'txt':
      // Plain text: check first 512 bytes for non-printable binary characters (excluding tabs, newlines)
      for (let i = 0; i < Math.min(buffer.length, 512); i++) {
        const byte = buffer[i];
        if (byte === 0) return false; // Null byte indicates binary
      }
      return true;

    default:
      return false;
  }
}

/**
 * Validates an uploaded file.
 * 
 * @param {Express.Multer.File} file 
 * @returns {{ valid: boolean, error?: string, sanitizedName?: string, ext?: string }}
 */
function validateUploadedFile(file) {
  if (!file) {
    return { valid: false, error: 'No file was provided.' };
  }

  // 1. File size check
  if (file.size > config.maxFileSize) {
    const maxMb = Math.round(config.maxFileSize / (1024 * 1024));
    return { valid: false, error: `File size exceeds the maximum limit of ${maxMb}MB.` };
  }

  if (file.size === 0) {
    return { valid: false, error: 'Uploaded file cannot be empty.' };
  }

  // 2. Extract and sanitize extension
  const rawExt = path.extname(file.originalname).toLowerCase().replace('.', '');
  if (!rawExt) {
    return { valid: false, error: 'Files must have a valid extension.' };
  }

  // 3. Reject dangerous executables/scripts immediately
  if (DANGEROUS_EXTENSIONS.has(rawExt)) {
    return { valid: false, error: `Executable or script files (.${rawExt}) are strictly prohibited.` };
  }

  // 4. Check against allowed extensions
  if (!ALLOWED_EXTENSIONS.has(rawExt)) {
    return {
      valid: false,
      error: `File type .${rawExt} is not supported. Supported types: PDF, DOC, DOCX, JPG, PNG, PPT, PPTX, XLS, XLSX, TXT.`,
    };
  }

  // 5. Inspect magic bytes signature
  const isSignatureValid = verifyMagicBytes(file.buffer, rawExt);
  if (!isSignatureValid) {
    return {
      valid: false,
      error: `File signature mismatch for .${rawExt}. File content does not match its extension.`,
    };
  }

  // 6. Sanitize document name to prevent path traversal / XSS
  const sanitizedName = path.basename(file.originalname).replace(/[^a-zA-Z0-9_\-\. ]/g, '_');

  return {
    valid: true,
    sanitizedName,
    ext: rawExt,
  };
}

module.exports = {
  ALLOWED_EXTENSIONS,
  validateUploadedFile,
  verifyMagicBytes,
};
