'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class BackupManager {
  constructor(authorityKeyPair = null) {
    this.authorityKeyPair = authorityKeyPair || crypto.generateKeyPairSync('ml-dsa-65');
  }

  getPublicKey() {
    return this.authorityKeyPair.publicKey;
  }

  createBackup(keyRegistry, backupPasswordOrSecret) {
    const rawData = JSON.stringify(keyRegistry);

    // 1. Compute SHA-256 manifest hash over unencrypted keys
    const manifestHash = crypto.createHash('sha256').update(rawData).digest('hex');

    // 2. Derive 32-byte backup encryption key using HKDF
    const salt = crypto.randomBytes(16);
    const backupKey = crypto.hkdfSync(
      'sha256',
      Buffer.from(backupPasswordOrSecret, 'utf8'),
      salt,
      Buffer.from('track4-backup-integrity', 'utf8'),
      32
    );

    // 3. Encrypt backup data with AES-256-GCM (AEAD)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', backupKey, iv);
    let ciphertext = cipher.update(rawData, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();

    const backupPayload = {
      manifest_hash: manifestHash,
      salt_hex: salt.toString('hex'),
      iv_hex: iv.toString('hex'),
      tag_hex: tag.toString('hex'),
      ciphertext_b64: ciphertext.toString('base64'),
      created_at: Date.now()
    };

    // 4. Sign manifest and ciphertext using authority ML-DSA-65
    const toSign = Buffer.from(JSON.stringify({
      manifest_hash: manifestHash,
      ciphertext_b64: backupPayload.ciphertext_b64
    }), 'utf8');

    const signature = crypto.sign(null, toSign, this.authorityKeyPair.privateKey);
    backupPayload.signature_b64 = signature.toString('base64');

    return backupPayload;
  }

  restoreBackup(backupPayload, backupPasswordOrSecret, trustedAuthorityPublicKey = null) {
    const pubKey = trustedAuthorityPublicKey || this.authorityKeyPair.publicKey;

    // 1. Verify ML-DSA-65 digital signature FIRST
    const toVerify = Buffer.from(JSON.stringify({
      manifest_hash: backupPayload.manifest_hash,
      ciphertext_b64: backupPayload.ciphertext_b64
    }), 'utf8');

    const signature = Buffer.from(backupPayload.signature_b64, 'base64');
    const isSignatureValid = crypto.verify(null, toVerify, pubKey, signature);
    if (!isSignatureValid) {
      throw new Error('BACKUP_TAMPERED: Invalid authority signature on backup');
    }

    // 2. Derive key and Decrypt with AEAD (AES-256-GCM)
    const salt = Buffer.from(backupPayload.salt_hex, 'hex');
    const backupKey = crypto.hkdfSync(
      'sha256',
      Buffer.from(backupPasswordOrSecret, 'utf8'),
      salt,
      Buffer.from('track4-backup-integrity', 'utf8'),
      32
    );

    const iv = Buffer.from(backupPayload.iv_hex, 'hex');
    const tag = Buffer.from(backupPayload.tag_hex, 'hex');
    const ciphertext = Buffer.from(backupPayload.ciphertext_b64, 'base64');

    let decryptedRaw;
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', backupKey, iv);
      decipher.setAuthTag(tag);
      let dec = decipher.update(ciphertext, null, 'utf8');
      dec += decipher.final('utf8');
      decryptedRaw = dec;
    } catch (err) {
      throw new Error(`BACKUP_AUTH_FAILED: AEAD tag authentication failed: ${err.message}`);
    }

    // 3. Verify Manifest SHA-256 hash
    const computedHash = crypto.createHash('sha256').update(decryptedRaw).digest('hex');
    if (computedHash !== backupPayload.manifest_hash) {
      throw new Error('BACKUP_MANIFEST_MISMATCH: Computed hash does not match backup manifest');
    }

    return JSON.parse(decryptedRaw);
  }
}

module.exports = {
  BackupManager
};
