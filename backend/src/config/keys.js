const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const KEY_FILE_PATH = path.resolve(__dirname, '../../storage/master.key');

/**
 * Retrieves or generates the 256-bit (32 bytes) Master Encryption Key.
 * In production, this can be fetched from AWS KMS, HashiCorp Vault, or Azure Key Vault.
 */
function getMasterEncryptionKey() {
  // 1. Check environment variable
  if (process.env.MASTER_ENCRYPTION_KEY) {
    const envKey = process.env.MASTER_ENCRYPTION_KEY.trim();
    if (/^[0-9a-fA-F]{64}$/.test(envKey)) {
      return Buffer.from(envKey, 'hex');
    }
    if (Buffer.from(envKey, 'utf8').length === 32) {
      return Buffer.from(envKey, 'utf8');
    }
    // Derive a deterministic 256-bit key from arbitrary length secret
    return crypto.createHash('sha256').update(envKey).digest();
  }

  // 2. Check local key file
  const storageDir = path.dirname(KEY_FILE_PATH);
  if (!fs.existsSync(storageDir)) {
    fs.mkdirSync(storageDir, { recursive: true });
  }

  if (fs.existsSync(KEY_FILE_PATH)) {
    const fileContent = fs.readFileSync(KEY_FILE_PATH, 'utf8').trim();
    const keyBuf = Buffer.from(fileContent, 'hex');
    if (keyBuf.length === 32) {
      return keyBuf;
    }
  }

  // 3. Generate a new secure 256-bit key and save it to storage
  const newKey = crypto.randomBytes(32);
  fs.writeFileSync(KEY_FILE_PATH, newKey.toString('hex'), { mode: 0o600 });
  console.log('[Security] Generated a new 256-bit Master Encryption Key in storage/master.key');
  return newKey;
}

module.exports = {
  getMasterEncryptionKey,
};
