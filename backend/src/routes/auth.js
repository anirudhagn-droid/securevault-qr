const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const argon2 = require('@node-rs/argon2');
const db = require('../db');
const config = require('../config');
const { requireAuth } = require('../middleware/auth');
const { authLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

/**
 * Helper to issue session JWT and set HTTP-only cookie
 */
function sendSessionResponse(res, user, statusCode = 200) {
  const token = jwt.sign(
    { userId: user.id, email: user.email },
    config.jwtSecret,
    { expiresIn: config.jwtExpiresIn }
  );

  res.cookie('session_token', token, {
    httpOnly: true,
    secure: config.env === 'production',
    sameSite: config.env === 'production' ? 'none' : 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });

  return res.status(statusCode).json({
    success: true,
    token,
    user: {
      id: user.id,
      full_name: user.full_name,
      email: user.email,
      created_at: user.created_at,
    },
  });
}

/**
 * POST /api/auth/register
 * Registers a new user with Argon2id password hashing.
 */
router.post('/register', authLimiter, async (req, res) => {
  try {
    const { full_name, email, password, confirm_password } = req.body;

    if (!full_name || !email || !password || !confirm_password) {
      return res.status(400).json({
        success: false,
        error: 'All fields (full_name, email, password, confirm_password) are required.',
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(cleanEmail)) {
      return res.status(400).json({
        success: false,
        error: 'Please provide a valid email address.',
      });
    }

    if (password !== confirm_password) {
      return res.status(400).json({
        success: false,
        error: 'Passwords do not match.',
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Account password must be at least 8 characters long.',
      });
    }

    // Check if email already registered
    const existing = await db.query('SELECT id FROM users WHERE email = $1', [cleanEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({
        success: false,
        error: 'An account with this email address already exists. Please log in.',
      });
    }

    // Hash password with Argon2id
    const passwordHash = await argon2.hash(password, {
      memoryCost: config.argon2.memoryCost,
      timeCost: config.argon2.timeCost,
      parallelism: config.argon2.parallelism,
      algorithm: argon2.Algorithm.Argon2id,
    });

    // Insert user into database
    const insertRes = await db.query(
      `INSERT INTO users (full_name, email, password_hash)
       VALUES ($1, $2, $3)
       RETURNING id, full_name, email, created_at`,
      [full_name.trim(), cleanEmail, passwordHash]
    );

    const newUser = insertRes.rows[0];
    return sendSessionResponse(res, newUser, 201);
  } catch (err) {
    console.error('[Registration Error]', err);
    return res.status(500).json({
      success: false,
      error: 'An error occurred during account registration. Please try again.',
    });
  }
});

/**
 * POST /api/auth/login
 * Verifies credentials using Argon2id and creates session.
 */
router.post('/login', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({
        success: false,
        error: 'Email and password are required.',
      });
    }

    const cleanEmail = String(email).trim().toLowerCase();

    // Query user
    const userRes = await db.query(
      'SELECT id, full_name, email, password_hash, created_at FROM users WHERE email = $1',
      [cleanEmail]
    );

    if (userRes.rows.length === 0) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email address or password.',
      });
    }

    const user = userRes.rows[0];

    // Verify Argon2id password hash
    const isMatch = await argon2.verify(user.password_hash, password);
    if (!isMatch) {
      return res.status(401).json({
        success: false,
        error: 'Invalid email address or password.',
      });
    }

    return sendSessionResponse(res, user);
  } catch (err) {
    console.error('[Login Error]', err);
    return res.status(500).json({
      success: false,
      error: 'An error occurred during login. Please try again.',
    });
  }
});

/**
 * POST /api/auth/logout
 * Clears session cookie.
 */
router.post('/logout', (req, res) => {
  res.clearCookie('session_token');
  return res.json({
    success: true,
    message: 'Logged out successfully.',
  });
});

/**
 * GET /api/auth/me
 * Returns current authenticated user profile.
 */
router.get('/me', requireAuth, (req, res) => {
  return res.json({
    success: true,
    user: req.user,
  });
});

/**
 * POST /api/auth/forgot-password
 * Initiates password reset flow.
 */
router.post('/forgot-password', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) {
      return res.status(400).json({ success: false, error: 'Email is required.' });
    }

    const cleanEmail = String(email).trim().toLowerCase();
    const userRes = await db.query('SELECT id FROM users WHERE email = $1', [cleanEmail]);

    // Constant-time generic response to prevent user enumeration
    if (userRes.rows.length === 0) {
      return res.json({
        success: true,
        message: 'If an account exists with that email, a password reset token has been issued.',
      });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
    const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

    await db.query(
      `UPDATE users 
       SET reset_token_hash = $1, reset_token_expires_at = $2
       WHERE id = $3`,
      [resetTokenHash, expiresAt, userRes.rows[0].id]
    );

    return res.json({
      success: true,
      message: 'If an account exists with that email, a password reset token has been issued.',
      // In development mode, return token so developer can test without SMTP server
      devResetToken: config.env !== 'production' ? resetToken : undefined,
    });
  } catch (err) {
    console.error('[Forgot Password Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to process password reset request.' });
  }
});

/**
 * POST /api/auth/reset-password
 * Resets user password using reset token.
 */
router.post('/reset-password', authLimiter, async (req, res) => {
  try {
    const { token, new_password, confirm_password } = req.body;

    if (!token || !new_password || !confirm_password) {
      return res.status(400).json({
        success: false,
        error: 'Token, new password, and confirm password are required.',
      });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({ success: false, error: 'Passwords do not match.' });
    }

    if (new_password.length < 8) {
      return res.status(400).json({
        success: false,
        error: 'Password must be at least 8 characters long.',
      });
    }

    const tokenHash = crypto.createHash('sha256').update(token).digest('hex');

    const userRes = await db.query(
      `SELECT id, reset_token_expires_at FROM users 
       WHERE reset_token_hash = $1`,
      [tokenHash]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({ success: false, error: 'Invalid or expired password reset token.' });
    }

    const user = userRes.rows[0];
    if (new Date(user.reset_token_expires_at) < new Date()) {
      return res.status(400).json({ success: false, error: 'Password reset token has expired.' });
    }

    const newHash = await argon2.hash(new_password, {
      memoryCost: config.argon2.memoryCost,
      timeCost: config.argon2.timeCost,
      parallelism: config.argon2.parallelism,
      algorithm: argon2.Algorithm.Argon2id,
    });

    await db.query(
      `UPDATE users 
       SET password_hash = $1, reset_token_hash = NULL, reset_token_expires_at = NULL
       WHERE id = $2`,
      [newHash, user.id]
    );

    return res.json({
      success: true,
      message: 'Password reset successfully! You can now log in with your new password.',
    });
  } catch (err) {
    console.error('[Reset Password Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to reset password.' });
  }
});

/**
 * PUT /api/auth/profile
 * Updates user full name.
 */
router.put('/profile', requireAuth, async (req, res) => {
  try {
    const { full_name } = req.body;
    if (!full_name || full_name.trim().length === 0) {
      return res.status(400).json({ success: false, error: 'Full name cannot be blank.' });
    }

    await db.query(
      'UPDATE users SET full_name = $1 WHERE id = $2',
      [full_name.trim(), req.user.id]
    );

    return res.json({
      success: true,
      message: 'Profile updated successfully.',
      user: {
        ...req.user,
        full_name: full_name.trim(),
      },
    });
  } catch (err) {
    console.error('[Profile Update Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to update profile.' });
  }
});

/**
 * PUT /api/auth/change-password
 * Allows user to change account password.
 */
router.put('/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;

    if (!current_password || !new_password || !confirm_password) {
      return res.status(400).json({
        success: false,
        error: 'Current password, new password, and confirmation are required.',
      });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({ success: false, error: 'New passwords do not match.' });
    }

    if (new_password.length < 8) {
      return res.status(400).json({ success: false, error: 'Password must be at least 8 characters long.' });
    }

    const userRes = await db.query('SELECT password_hash FROM users WHERE id = $1', [req.user.id]);
    const isMatch = await argon2.verify(userRes.rows[0].password_hash, current_password);
    if (!isMatch) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect.' });
    }

    const newHash = await argon2.hash(new_password, {
      memoryCost: config.argon2.memoryCost,
      timeCost: config.argon2.timeCost,
      parallelism: config.argon2.parallelism,
      algorithm: argon2.Algorithm.Argon2id,
    });

    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [newHash, req.user.id]);

    return res.json({
      success: true,
      message: 'Account password changed successfully.',
    });
  } catch (err) {
    console.error('[Change Password Error]', err);
    return res.status(500).json({ success: false, error: 'Failed to change password.' });
  }
});

module.exports = router;
