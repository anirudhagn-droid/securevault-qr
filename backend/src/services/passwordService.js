const crypto = require('crypto');
const argon2 = require('@node-rs/argon2');
const config = require('../config');

// Safe, unambiguous character sets for 4-character PINs
// Avoids 0/O, 1/I/l to minimize recipient typing mistakes on mobile
const UPPERCASE = 'ABCDEFGHJKLMNPQRSTUVWXYZ';
const LOWERCASE = 'abcdefghijkmnpqrstuvwxyz';
const NUMBERS = '23456789';
const SYMBOLS = '#$@!%&*?';

const ALL_CHARS = UPPERCASE + LOWERCASE + NUMBERS + SYMBOLS;

/**
 * Generates a cryptographically secure 4-character password containing
 * a diverse mix of uppercase, lowercase, numbers, and symbols.
 * Example: A7#k, 9x$R, m4!T
 * 
 * @returns {string} Exactly 4 characters
 */
function generateFourCharPassword() {
  // Ensure diversity: pick 1 uppercase, 1 lowercase, 1 number, 1 symbol
  const pool = [
    UPPERCASE[crypto.randomInt(0, UPPERCASE.length)],
    LOWERCASE[crypto.randomInt(0, LOWERCASE.length)],
    NUMBERS[crypto.randomInt(0, NUMBERS.length)],
    SYMBOLS[crypto.randomInt(0, SYMBOLS.length)],
  ];

  // Fisher-Yates cryptographically secure shuffle
  for (let i = pool.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [pool[i], pool[j]] = [pool[j], pool[i]];
  }

  return pool.join('');
}

/**
 * Validates that a password satisfies the 4-character requirement.
 * 
 * @param {string} password 
 * @returns {{ valid: boolean, message?: string }}
 */
function validateFourCharPassword(password) {
  if (typeof password !== 'string') {
    return { valid: false, message: 'Password must be a string.' };
  }
  const trimmed = password.trim();
  if (trimmed.length !== 4) {
    return { valid: false, message: 'Password must be exactly 4 characters.' };
  }
  return { valid: true };
}

/**
 * Hashes a 4-character password using Argon2id.
 * 
 * @param {string} password - 4-character plaintext password
 * @returns {Promise<string>} - Argon2id PHC hash string
 */
async function hashPassword(password) {
  return await argon2.hash(password, {
    memoryCost: config.argon2.memoryCost,
    timeCost: config.argon2.timeCost,
    parallelism: config.argon2.parallelism,
    algorithm: argon2.Algorithm.Argon2id,
  });
}

/**
 * Verifies a plaintext password against an Argon2id hash.
 * 
 * @param {string} hash - Argon2id hash from database
 * @param {string} plainPassword - User entered password
 * @returns {Promise<boolean>}
 */
async function verifyPassword(hash, plainPassword) {
  try {
    return await argon2.verify(hash, plainPassword);
  } catch (err) {
    return false;
  }
}

module.exports = {
  generateFourCharPassword,
  validateFourCharPassword,
  hashPassword,
  verifyPassword,
};
