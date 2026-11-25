const crypto = require('crypto');
const QRCode = require('qrcode');
const config = require('../config');

/**
 * Generates an unpredictable, cryptographically secure 256-bit (32 bytes) access token.
 * 
 * @returns {string} 64-character hex string
 */
function generateQrToken() {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Computes a SHA-256 hash of the raw QR token for safe storage in the database.
 * The database never stores raw tokens; if the database is leaked, tokens cannot be used.
 * 
 * @param {string} token - Raw hex token
 * @returns {string} SHA-256 hex digest
 */
function hashQrToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

/**
 * Constructs the public access URL for a given QR token.
 * 
 * @param {string} token 
 * @returns {string}
 */
function getDocumentAccessUrl(token, originOverride) {
  let baseUrl = config.frontendUrl;
  if (originOverride && /^https?:\/\/[^/]+$/i.test(originOverride.trim())) {
    baseUrl = originOverride.trim();
  }
  return `${baseUrl}/access/${token}`;
}

/**
 * Generates a PNG Data URL representing the QR code for embedding in frontend UI.
 * 
 * @param {string} accessUrl 
 * @returns {Promise<string>} Base64 Data URL
 */
async function generateQrDataUrl(accessUrl) {
  return await QRCode.toDataURL(accessUrl, {
    errorCorrectionLevel: 'H', // High error correction
    type: 'image/png',
    margin: 2,
    width: 360,
    color: {
      dark: '#0b152d', // Deep navy
      light: '#ffffff', // Crisp white background
    },
  });
}

/**
 * Generates a raw PNG Buffer for downloadable QR code images.
 * 
 * @param {string} accessUrl 
 * @returns {Promise<Buffer>}
 */
async function generateQrPngBuffer(accessUrl) {
  return await QRCode.toBuffer(accessUrl, {
    errorCorrectionLevel: 'H',
    type: 'png',
    margin: 2,
    width: 600,
    color: {
      dark: '#0b152d',
      light: '#ffffff',
    },
  });
}

module.exports = {
  generateQrToken,
  hashQrToken,
  getDocumentAccessUrl,
  generateQrDataUrl,
  generateQrPngBuffer,
};
