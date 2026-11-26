const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const config = require('../config');

const uuidv4 = () => crypto.randomUUID();

/**
 * Storage Service abstraction layer.
 * Manages private, isolated encrypted document storage on the host filesystem.
 * Easily swappable for S3/GCS adapters in production.
 */
class StorageService {
  constructor() {
    this.vaultDir = config.storageDir;
    this.ensureVaultDir();
  }

  ensureVaultDir() {
    if (!fs.existsSync(this.vaultDir)) {
      fs.mkdirSync(this.vaultDir, { recursive: true, mode: 0o700 });
    }
  }

  /**
   * Saves an encrypted document buffer to private storage.
   * 
   * @param {Buffer} encryptedBuffer 
   * @returns {Promise<string>} Relative or absolute storage path
   */
  async saveEncryptedFile(encryptedBuffer) {
    this.ensureVaultDir();
    const filename = `${uuidv4()}.enc`;
    const fullPath = path.join(this.vaultDir, filename);

    await fs.promises.writeFile(fullPath, encryptedBuffer, { mode: 0o600 });
    return fullPath;
  }

  /**
   * Reads an encrypted document file from private storage.
   * 
   * @param {string} filePath 
   * @returns {Promise<Buffer>}
   */
  async readEncryptedFile(filePath) {
    if (!fs.existsSync(filePath)) {
      throw new Error('Encrypted file not found in storage vault.');
    }
    return await fs.promises.readFile(filePath);
  }

  /**
   * Reads encrypted document bytes from local vault disk, falling back
   * to the encrypted database payload if ephemeral local storage was reset.
   *
   * @param {{ encrypted_file_path: string, encrypted_payload?: string }} doc
   * @returns {Promise<Buffer>}
   */
  async readEncryptedDocument(doc) {
    if (doc.encrypted_file_path && fs.existsSync(doc.encrypted_file_path)) {
      return await fs.promises.readFile(doc.encrypted_file_path);
    }
    if (doc.encrypted_payload) {
      return Buffer.from(doc.encrypted_payload, 'base64');
    }
    throw new Error('Encrypted file not found in storage vault.');
  }

  /**
   * Securely deletes an encrypted document file from private storage.
   * 
   * @param {string} filePath 
   * @returns {Promise<boolean>}
   */
  async deleteEncryptedFile(filePath) {
    try {
      if (fs.existsSync(filePath)) {
        await fs.promises.unlink(filePath);
        return true;
      }
      return false;
    } catch (err) {
      console.error('[Storage Error] Failed to delete file:', filePath, err.message);
      return false;
    }
  }
}

module.exports = new StorageService();
