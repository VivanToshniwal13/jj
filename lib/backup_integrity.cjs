'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Documented Scrypt Parameters (RFC 7914 compliant)
// N = 32768 (2^15 CPU/memory cost), r = 8 (block size), p = 1 (parallelization)
const SCRYPT_PARAMS = {
  N: 32768,
  r: 8,
  p: 1,
  maxmem: 64 * 1024 * 1024
};

class BackupManager {
  constructor(authorityKeyPair = null, stateDir = null) {
    this.stateDir = stateDir;
    if (authorityKeyPair) {
      this.authorityKeyPair = authorityKeyPair;
    } else {
      this.authorityKeyPair = this._loadOrGenerateKey();
    }
  }

  _loadOrGenerateKey() {
    // Check environment variable or fallback to state directory
    const keyPath = process.env.TRACK4_BACKUP_KEY_PATH || 
      (this.stateDir ? path.join(this.stateDir, 'backup_mldsa_sk.bin') : null);

    if (keyPath && fs.existsSync(keyPath)) {
      try {
        const raw = fs.readFileSync(keyPath);
        // If stored as raw or SPKI/PKCS8
        return crypto.createPrivateKey({ key: raw, format: 'der', type: 'pkcs8' });
      } catch {}
    }

    const kp = crypto.generateKeyPairSync('ml-dsa-65');
    if (keyPath) {
      try {
        const der = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
        fs.writeFileSync(keyPath, der, { mode: 0o600 });
      } catch {}
    }
    return kp;
  }

  getPublicKey() {
    return this.authorityKeyPair.publicKey;
  }

  createBackup(statePayload, backupPassword, currentEpoch = 1) {
    if (!backupPassword || typeof backupPassword !== 'string' || backupPassword.length < 8) {
      throw new Error('Backup password must be at least 8 characters');
    }

    const rawData = JSON.stringify(statePayload);

    // 1. Derive 32-byte backup key using scrypt (Password-based KDF with random salt)
    const salt = crypto.randomBytes(16);
    const backupKey = crypto.scryptSync(backupPassword, salt, 32, SCRYPT_PARAMS);

    // 2. Encrypt with AES-256-GCM (AEAD)
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', backupKey, iv);
    let ciphertext = cipher.update(rawData, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const tag = cipher.getAuthTag();

    const backupPayload = {
      epoch: currentEpoch,
      salt_hex: salt.toString('hex'),
      iv_hex: iv.toString('hex'),
      tag_hex: tag.toString('hex'),
      ciphertext_b64: ciphertext.toString('base64'),
      created_at: Date.now()
    };

    // 3. Digital signature over CIPHERTEXT and METADATA ONLY (no plaintext manifest)
    const toSign = Buffer.from(JSON.stringify({
      epoch: backupPayload.epoch,
      salt_hex: backupPayload.salt_hex,
      iv_hex: backupPayload.iv_hex,
      tag_hex: backupPayload.tag_hex,
      ciphertext_b64: backupPayload.ciphertext_b64,
      created_at: backupPayload.created_at
    }), 'utf8');

    const signature = crypto.sign(null, toSign, this.authorityKeyPair.privateKey);
    backupPayload.signature_b64 = signature.toString('base64');

    return backupPayload;
  }

  restoreBackup(backupPayload, backupPassword, currentSystemState = null, trustedAuthorityPublicKey = null) {
    if (!backupPayload || typeof backupPayload !== 'object' || !backupPayload.ciphertext_b64 || !backupPayload.signature_b64) {
      throw new Error('BACKUP_INTEGRITY_CHECK_FAILED: Corrupted or truncated backup payload structure');
    }

    const pubKey = trustedAuthorityPublicKey || this.authorityKeyPair.publicKey;

    // 1. Verify ML-DSA-65 signature over ciphertext and metadata FIRST
    const toVerify = Buffer.from(JSON.stringify({
      epoch: backupPayload.epoch,
      salt_hex: backupPayload.salt_hex,
      iv_hex: backupPayload.iv_hex,
      tag_hex: backupPayload.tag_hex,
      ciphertext_b64: backupPayload.ciphertext_b64,
      created_at: backupPayload.created_at
    }), 'utf8');

    const signature = Buffer.from(backupPayload.signature_b64, 'base64');
    const isSignatureValid = crypto.verify(null, toVerify, pubKey, signature);
    if (!isSignatureValid) {
      throw new Error('BACKUP_INTEGRITY_CHECK_FAILED: BACKUP_TAMPERED: Invalid authority signature on backup metadata/ciphertext');
    }

    // 2. Derive key with scrypt using identical parameters
    const salt = Buffer.from(backupPayload.salt_hex, 'hex');
    const backupKey = crypto.scryptSync(backupPassword, salt, 32, SCRYPT_PARAMS);

    // 3. Authenticate and decrypt with AES-256-GCM
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
      throw new Error(`BACKUP_INTEGRITY_CHECK_FAILED: BACKUP_AUTH_FAILED: AEAD tag authentication failed: ${err.message}`);
    }

    const restoredData = JSON.parse(decryptedRaw);

    // 4. Rollback Protection:
    // If current system state exists, preserve all active revocations so an older backup
    // cannot resurrect a revoked actor or replay stale credentials.
    if (currentSystemState) {
      // Re-apply current revocations to restored data
      if (currentSystemState.revoked) {
        if (!restoredData.revoked) restoredData.revoked = [];
        const restoredRevokedSet = new Set(restoredData.revoked);
        for (const actor of currentSystemState.revoked) {
          restoredRevokedSet.add(actor);
        }
        restoredData.revoked = Array.from(restoredRevokedSet);
      }

      // Advance monotonic epoch
      const currentEpoch = currentSystemState.epoch || 1;
      restoredData.epoch = Math.max(currentEpoch, backupPayload.epoch) + 1;
    } else {
      restoredData.epoch = backupPayload.epoch + 1;
    }

    return restoredData;
  }
}

module.exports = {
  SCRYPT_PARAMS,
  BackupManager,
  BackupIntegrityManager: BackupManager
};
