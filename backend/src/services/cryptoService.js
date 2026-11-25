const crypto = require('crypto');
const { getMasterEncryptionKey } = require('../config/keys');

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // 96 bits recommended for AES-GCM
const KEY_LENGTH = 32; // 256 bits

/**
 * Encrypts a plaintext document buffer using AES-256-GCM and Envelope Encryption.
 * 
 * Flow:
 * 1. Generates a unique 256-bit Data Encryption Key (DEK) for this document.
 * 2. Encrypts the document buffer with DEK and random 12-byte IV.
 * 3. Retrieves the 16-byte authentication tag (ensures tamper-proof integrity).
 * 4. Encrypts the DEK using the Master Encryption Key (KEK).
 * 5. Returns the encrypted document, encrypted DEK, IV, and Auth Tag.
 * 
 * @param {Buffer} buffer - Plaintext file data
 * @returns {{ encryptedData: Buffer, encryptedStorageKey: string, iv: string, authTag: string }}
 */
function encryptDocument(buffer) {
  const masterKey = getMasterEncryptionKey();

  // 1. Generate unique DEK for this document
  const dek = crypto.randomBytes(KEY_LENGTH);
  const iv = crypto.randomBytes(IV_LENGTH);

  // 2. Encrypt document with DEK
  const cipher = crypto.createCipheriv(ALGORITHM, dek, iv);
  const encryptedBuffer = Buffer.concat([cipher.update(buffer), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // 3. Encrypt DEK with Master Key (KEK) using AES-256-GCM
  const kekIv = crypto.randomBytes(IV_LENGTH);
  const kekCipher = crypto.createCipheriv(ALGORITHM, masterKey, kekIv);
  const encryptedDek = Buffer.concat([kekCipher.update(dek), kekCipher.final()]);
  const kekAuthTag = kekCipher.getAuthTag();

  // Format encryptedStorageKey as kekIv:kekAuthTag:encryptedDek (all hex)
  const encryptedStorageKey = `${kekIv.toString('hex')}:${kekAuthTag.toString('hex')}:${encryptedDek.toString('hex')}`;

  return {
    encryptedData: encryptedBuffer,
    encryptedStorageKey,
    iv: iv.toString('hex'),
    authTag: authTag.toString('hex'),
  };
}

/**
 * Decrypts an encrypted document buffer using AES-256-GCM and Envelope Encryption.
 * 
 * Flow:
 * 1. Decrypts the DEK using Master Encryption Key.
 * 2. Decrypts the document buffer with DEK, IV, and checks Auth Tag.
 * 3. Throws an error if any byte was tampered with.
 * 
 * @param {Buffer} encryptedData - Encrypted document content
 * @param {string} encryptedStorageKey - Encrypted DEK
 * @param {string} ivHex - Hex encoded IV
 * @param {string} authTagHex - Hex encoded Auth Tag
 * @returns {Buffer} - Decrypted plaintext file data
 */
function decryptDocument(encryptedData, encryptedStorageKey, ivHex, authTagHex) {
  const masterKey = getMasterEncryptionKey();

  // 1. Unpack and decrypt the DEK
  const parts = encryptedStorageKey.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted storage key format.');
  }

  const kekIv = Buffer.from(parts[0], 'hex');
  const kekAuthTag = Buffer.from(parts[1], 'hex');
  const encryptedDek = Buffer.from(parts[2], 'hex');

  const kekDecipher = crypto.createDecipheriv(ALGORITHM, masterKey, kekIv);
  kekDecipher.setAuthTag(kekAuthTag);
  const dek = Buffer.concat([kekDecipher.update(encryptedDek), kekDecipher.final()]);

  // 2. Decrypt document buffer with DEK
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, dek, iv);
  decipher.setAuthTag(authTag);
  const decryptedBuffer = Buffer.concat([decipher.update(encryptedData), decipher.final()]);

  return decryptedBuffer;
}

module.exports = {
  encryptDocument,
  decryptDocument,
};
