const jwt = require('jsonwebtoken');
const config = require('../config');
const db = require('../db');

/**
 * Authentication Middleware.
 * Protects owner dashboard, file upload, and document management endpoints.
 */
async function requireAuth(req, res, next) {
  try {
    let token = null;

    // 1. Check HTTP-only cookie
    if (req.cookies && req.cookies.session_token) {
      token = req.cookies.session_token;
    } 
    // 2. Check Authorization Bearer header
    else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
      token = req.headers.authorization.slice(7).trim();
    }

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required. Please log in to access this resource.',
      });
    }

    // Verify JWT
    const decoded = jwt.verify(token, config.jwtSecret);

    // Verify user exists in database
    const userRes = await db.query(
      'SELECT id, full_name, email, created_at FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Session invalid or user account no longer exists.',
      });
    }

    req.user = userRes.rows[0];
    req.token = token;
    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Your session has expired. Please log in again.',
        code: 'TOKEN_EXPIRED',
      });
    }
    return res.status(401).json({
      success: false,
      error: 'Invalid session authentication.',
    });
  }
}

module.exports = {
  requireAuth,
};
