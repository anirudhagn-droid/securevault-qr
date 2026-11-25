const crypto = require('crypto');
const db = require('../db');

/**
 * Anonymizes client IP address to adhere to privacy regulations (GDPR/CCPA).
 * e.g., 192.168.1.100 -> 192.168.1.0 or SHA-256 hash prefix.
 * 
 * @param {string} ip 
 * @returns {string} Anonymized IP
 */
function anonymizeIp(ip) {
  if (!ip) return 'unknown';
  if (ip === '::1' || ip === '127.0.0.1') return '127.0.0.1 (localhost)';
  const parts = ip.split('.');
  if (parts.length === 4) {
    return `${parts[0]}.${parts[1]}.${parts[2]}.xxx`;
  }
  // IPv6: hash and return first 12 hex characters
  return crypto.createHash('sha256').update(ip).digest('hex').slice(0, 12);
}

/**
 * Logs an access attempt (QR scan & verification).
 * Never stores raw passwords or full tokens.
 * 
 * @param {string} documentId 
 * @param {string} status - 'success', 'failed_password', 'locked_out', 'expired', 'revoked'
 * @param {string} ip 
 * @param {string} userAgent 
 * @param {string} method - 'qr_scan', 'direct_link', etc.
 */
async function logAccessAttempt({ documentId, status, ip, userAgent, method = 'qr_scan' }) {
  try {
    const maskedIp = anonymizeIp(ip);
    const cleanUserAgent = userAgent ? String(userAgent).slice(0, 255) : 'unknown';

    await db.query(
      `INSERT INTO access_logs (document_id, access_status, ip_address, user_agent, access_method)
       VALUES ($1, $2, $3, $4, $5)`,
      [documentId, status, maskedIp, cleanUserAgent, method]
    );
  } catch (err) {
    console.error('[Audit Log Error]', err.message);
  }
}

/**
 * Retrieves access history for all documents belonging to a user.
 * 
 * @param {string} userId 
 * @param {number} limit 
 * @param {number} offset 
 * @returns {Promise<Array>}
 */
async function getUserAccessHistory(userId, limit = 50, offset = 0) {
  const sql = `
    SELECT 
      l.id,
      l.document_id,
      d.document_name,
      d.file_type,
      l.access_time,
      l.access_status,
      l.ip_address,
      l.user_agent,
      l.access_method
    FROM access_logs l
    JOIN documents d ON l.document_id = d.id
    WHERE d.user_id = $1
    ORDER BY l.access_time DESC
    LIMIT $2 OFFSET $3
  `;
  const result = await db.query(sql, [userId, limit, offset]);
  return result.rows;
}

module.exports = {
  logAccessAttempt,
  getUserAccessHistory,
  anonymizeIp,
};
