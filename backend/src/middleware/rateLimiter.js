const rateLimit = require('express-rate-limit');

/**
 * Standard API Rate Limiter
 * 200 requests per 15 minutes per IP
 */
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many requests from this IP. Please try again after 15 minutes.',
  },
});

/**
 * Authentication Limiter (Registration, Login, Reset)
 * 15 requests per 15 minutes per IP
 */
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many authentication attempts. Please try again in 15 minutes.',
  },
});

/**
 * Document QR Password Verification Rate Limiter
 * 10 attempts per 15 minutes per IP
 * (Additional fine-grained document-level lockout is handled in access.js)
 */
const accessAttemptLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    success: false,
    error: 'Too many password attempts on this network. Access is temporarily delayed.',
    code: 'RATE_LIMITED',
  },
});

module.exports = {
  apiLimiter,
  authLimiter,
  accessAttemptLimiter,
};
