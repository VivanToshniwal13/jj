'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

// ML-KEM-768 SPKI DER Prefix (RFC 9629 / NIST FIPS 203)
const ML_KEM_768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');

function getStateDir() {
  const dir = process.env.TRACK4_STATE_DIR || os.tmpdir();
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  return dir;
}

function getMasterKek(stateDir) {
  const kekPath = path.join(stateDir, 'kek.bin');
  if (fs.existsSync(kekPath)) {
    return fs.readFileSync(kekPath);
  }
  const kek = crypto.randomBytes(32);
  durableWriteFile(kekPath, kek, 0o600);
  return kek;
}

function durableWriteFile(targetPath, data, mode = 0o600) {
  const dir = path.dirname(targetPath);
  const tmpPath = path.join(dir, `.tmp-${crypto.randomUUID()}`);
  const fd = fs.openSync(tmpPath, 'w', mode);
  try {
    fs.writeFileSync(fd, data);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fs.renameSync(tmpPath, targetPath);
}

function loadState(stateDir) {
  const storePath = path.join(stateDir, 'store.enc');
  if (!fs.existsSync(storePath)) {
    return {
      owners: {},
      disabled: [],
      revoked: [],
      encrypted_assets: {},
      audit_events: {}
    };
  }
  return JSON.parse(fs.readFileSync(storePath, 'utf8'));
}

function saveState(stateDir, state) {
  const storePath = path.join(stateDir, 'store.enc');
  const serialized = JSON.stringify(state);
  durableWriteFile(storePath, Buffer.from(serialized, 'utf8'), 0o600);
}

// AEAD (AES-256-GCM) Envelope Encryption
function encryptBody(body, kek) {
  // 1. Generate 32-byte Data Encryption Key (DEK)
  const dek = crypto.randomBytes(32);
  
  // 2. Encrypt body with DEK
  const bodyIv = crypto.randomBytes(12);
  const bodyCipher = crypto.createCipheriv('aes-256-gcm', dek, bodyIv);
  let ciphertext = bodyCipher.update(body, 'utf8');
  ciphertext = Buffer.concat([ciphertext, bodyCipher.final()]);
  const bodyTag = bodyCipher.getAuthTag();

  // 3. Wrap DEK with KEK
  const wrapIv = crypto.randomBytes(12);
  const wrapCipher = crypto.createCipheriv('aes-256-gcm', kek, wrapIv);
  let wrappedKey = wrapCipher.update(dek);
  wrappedKey = Buffer.concat([wrappedKey, wrapCipher.final()]);
  const wrapTag = wrapCipher.getAuthTag();

  return {
    wrapped_key_b64: wrappedKey.toString('base64'),
    wrap_iv_b64: wrapIv.toString('base64'),
    wrap_tag_b64: wrapTag.toString('base64'),
    body_iv_b64: bodyIv.toString('base64'),
    body_ciphertext_b64: ciphertext.toString('base64'),
    body_tag_b64: bodyTag.toString('base64')
  };
}

function decryptBody(record, kek) {
  // 1. Unwrap DEK using KEK
  const wrapIv = Buffer.from(record.wrap_iv_b64, 'base64');
  const wrappedKey = Buffer.from(record.wrapped_key_b64, 'base64');
  const wrapTag = Buffer.from(record.wrap_tag_b64, 'base64');
  
  const unwrapCipher = crypto.createDecipheriv('aes-256-gcm', kek, wrapIv);
  unwrapCipher.setAuthTag(wrapTag);
  let dek = unwrapCipher.update(wrappedKey);
  dek = Buffer.concat([dek, unwrapCipher.final()]);

  // 2. Decrypt body using DEK
  const bodyIv = Buffer.from(record.body_iv_b64, 'base64');
  const ciphertext = Buffer.from(record.body_ciphertext_b64, 'base64');
  const bodyTag = Buffer.from(record.body_tag_b64, 'base64');

  const bodyDecipher = crypto.createDecipheriv('aes-256-gcm', dek, bodyIv);
  bodyDecipher.setAuthTag(bodyTag);
  let body = bodyDecipher.update(ciphertext, null, 'utf8');
  body += bodyDecipher.final('utf8');
  return body;
}

exports.dispatch = async function dispatch(request) {
  const op = request?.op;
  if (!op || typeof op !== 'string') {
    throw new Error('Missing or invalid operation');
  }

  const stateDir = getStateDir();
  const kek = getMasterKek(stateDir);

  switch (op) {
    case 'setup': {
      if (!request.owners || !request.contents) {
        throw new Error('Invalid setup request');
      }
      const encryptedAssets = {};
      for (const [assetId, body] of Object.entries(request.contents)) {
        encryptedAssets[assetId] = encryptBody(String(body), kek);
      }
      const state = {
        owners: { ...request.owners },
        disabled: Array.isArray(request.disabled) ? [...request.disabled] : [],
        revoked: [],
        encrypted_assets: encryptedAssets,
        audit_events: {}
      };
      saveState(stateDir, state);
      return { ready: true };
    }

    case 'read': {
      const { actor, asset, request_id } = request;
      if (!actor || !asset || !request_id) {
        throw new Error('Invalid read parameters');
      }
      const state = loadState(stateDir);
      
      const isOwner = state.owners[asset] === actor;
      const isDisabled = state.disabled.includes(actor);
      const isRevoked = state.revoked.includes(actor);

      let decision = 'deny';
      let bodyContent = null;

      if (isOwner && !isDisabled && !isRevoked) {
        decision = 'allow';
        const record = state.encrypted_assets[asset];
        if (record) {
          bodyContent = decryptBody(record, kek);
        }
      }

      state.audit_events[request_id] = {
        request_id,
        decision
      };
      saveState(stateDir, state);

      if (decision === 'allow' && bodyContent !== null) {
        return { decision: 'allow', body: bodyContent };
      }
      return { decision: 'deny' };
    }

    case 'revoke': {
      const { actor } = request;
      if (!actor) {
        throw new Error('Missing actor to revoke');
      }
      const state = loadState(stateDir);
      if (!state.revoked.includes(actor)) {
        state.revoked.push(actor);
      }
      saveState(stateDir, state);
      return {};
    }

    case 'audit': {
      const { request_id } = request;
      if (!request_id) {
        throw new Error('Missing request_id for audit');
      }
      const state = loadState(stateDir);
      const entry = state.audit_events[request_id];
      if (entry) {
        return {
          request_id: entry.request_id,
          decision: entry.decision
        };
      }
      return {
        request_id,
        decision: 'deny'
      };
    }

    case 'protected_read': {
      const { actor, asset, challenge, public_key } = request;
      if (!actor || !asset || !challenge || !public_key) {
        throw new Error('Invalid protected_read parameters');
      }
      const state = loadState(stateDir);
      const isOwner = state.owners[asset] === actor;
      const isDisabled = state.disabled.includes(actor);
      const isRevoked = state.revoked.includes(actor);

      if (!isOwner || isDisabled || isRevoked) {
        return { decision: 'deny' };
      }

      const record = state.encrypted_assets[asset];
      if (!record) {
        return { decision: 'deny' };
      }
      const body = decryptBody(record, kek);

      // Import raw ML-KEM-768 public key (1184 bytes base64)
      const rawPk = Buffer.from(public_key, 'base64');
      const spkiDer = Buffer.concat([ML_KEM_768_SPKI_PREFIX, rawPk]);
      const keyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

      // Encapsulate
      const { sharedKey, ciphertext } = crypto.encapsulate(keyObj);

      // Compute proof = lowercase hex HMAC-SHA-256(sharedKey, UTF-8(challenge + body))
      const proof = crypto.createHmac('sha256', sharedKey)
        .update(Buffer.from(challenge + body, 'utf8'))
        .digest('hex')
        .toLowerCase();

      return {
        decision: 'allow',
        ciphertext: ciphertext.toString('base64'),
        proof
      };
    }

    default:
      throw new Error(`Unsupported operation: ${op}`);
  }
};
