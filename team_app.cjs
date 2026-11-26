'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

// ML-KEM-768 SPKI DER Prefix (RFC 9629 / NIST FIPS 203)
const ML_KEM_768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');

// Strict Base64 validation regex
const STRICT_BASE64_REGEX = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

// Size limits for safety against resource exhaustion
const MAX_ID_LEN = 256;
const MAX_BODY_LEN = 1048576; // 1 MB
const MAX_CHALLENGE_LEN = 1024;
const LOCK_TIMEOUT_MS = 8000;
const LOCK_RETRY_MS = 25;

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

// O_EXCL Lockfile for atomic read-modify-write concurrency
async function withStateLock(stateDir, fn) {
  const lockPath = path.join(stateDir, 'state.lock');
  const start = Date.now();
  let fd = null;

  while (Date.now() - start < LOCK_TIMEOUT_MS) {
    try {
      fd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY, 0o600);
      break;
    } catch (err) {
      if (err.code === 'EEXIST') {
        try {
          const stat = fs.statSync(lockPath);
          if (Date.now() - stat.mtimeMs > LOCK_TIMEOUT_MS) {
            fs.unlinkSync(lockPath);
            continue;
          }
        } catch {
          // Lock might have been released in between
        }
        await new Promise(r => setTimeout(r, LOCK_RETRY_MS + Math.floor(Math.random() * 15)));
      } else {
        throw err;
      }
    }
  }

  if (fd === null) {
    throw new Error('Lock acquisition timeout');
  }

  try {
    return await fn();
  } finally {
    try { fs.closeSync(fd); } catch {}
    try {
      if (fs.existsSync(lockPath)) {
        fs.unlinkSync(lockPath);
      }
    } catch {}
  }
}

// In-Memory State Model using Map & Set to prevent prototype pollution
function createEmptyState() {
  return {
    owners: new Map(),           // asset_id -> actor_id
    disabled: new Set(),         // Set of actor_id
    revoked: new Set(),          // Set of actor_id
    encrypted_assets: new Map(), // asset_id -> encrypted_record
    audit_events: new Map()      // request_id -> { request_id, decision }
  };
}

function loadState(stateDir) {
  const storePath = path.join(stateDir, 'store.enc');
  if (!fs.existsSync(storePath)) {
    return createEmptyState();
  }
  const raw = fs.readFileSync(storePath, 'utf8');
  const parsed = JSON.parse(raw);

  return {
    owners: new Map(parsed.owners || []),
    disabled: new Set(parsed.disabled || []),
    revoked: new Set(parsed.revoked || []),
    encrypted_assets: new Map(parsed.encrypted_assets || []),
    audit_events: new Map(parsed.audit_events || [])
  };
}

function saveState(stateDir, state) {
  const storePath = path.join(stateDir, 'store.enc');
  const serialized = JSON.stringify({
    owners: Array.from(state.owners.entries()),
    disabled: Array.from(state.disabled),
    revoked: Array.from(state.revoked),
    encrypted_assets: Array.from(state.encrypted_assets.entries()),
    audit_events: Array.from(state.audit_events.entries())
  });
  durableWriteFile(storePath, Buffer.from(serialized, 'utf8'), 0o600);
}

// Safe ID and Input Validation
function validateStringId(val, name, maxLen = MAX_ID_LEN) {
  if (typeof val !== 'string' || val.length === 0 || val.length > maxLen) {
    throw new Error(`Invalid ${name}: must be non-empty string <= ${maxLen} chars`);
  }
  if (val.includes('\0')) {
    throw new Error(`NUL character detected in ${name}`);
  }
  return val;
}

// AEAD (AES-256-GCM) Envelope Encryption
function encryptBody(body, kek) {
  const dek = crypto.randomBytes(32);
  
  const bodyIv = crypto.randomBytes(12);
  const bodyCipher = crypto.createCipheriv('aes-256-gcm', dek, bodyIv);
  let ciphertext = bodyCipher.update(body, 'utf8');
  ciphertext = Buffer.concat([ciphertext, bodyCipher.final()]);
  const bodyTag = bodyCipher.getAuthTag();

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
  const wrapIv = Buffer.from(record.wrap_iv_b64, 'base64');
  const wrappedKey = Buffer.from(record.wrapped_key_b64, 'base64');
  const wrapTag = Buffer.from(record.wrap_tag_b64, 'base64');
  
  const unwrapCipher = crypto.createDecipheriv('aes-256-gcm', kek, wrapIv);
  unwrapCipher.setAuthTag(wrapTag);
  let dek = unwrapCipher.update(wrappedKey);
  dek = Buffer.concat([dek, unwrapCipher.final()]);

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
  if (!request || typeof request !== 'object' || Array.isArray(request)) {
    throw new Error('Request must be a JSON object');
  }

  const op = request.op;
  if (!op || typeof op !== 'string') {
    throw new Error('Missing or invalid operation');
  }

  const stateDir = getStateDir();
  const kek = getMasterKek(stateDir);

  return await withStateLock(stateDir, async () => {
    switch (op) {
      case 'setup': {
        if (!request.owners || typeof request.owners !== 'object' || Array.isArray(request.owners) ||
            !request.contents || typeof request.contents !== 'object' || Array.isArray(request.contents)) {
          throw new Error('Invalid setup request structure');
        }

        const state = createEmptyState();

        // Populate owners using Map (prototype-safe)
        for (const [rawAsset, rawActor] of Object.entries(request.owners)) {
          const asset = validateStringId(rawAsset, 'asset');
          const actor = validateStringId(rawActor, 'actor');
          state.owners.set(asset, actor);
        }

        // Populate and encrypt contents using Map
        for (const [rawAsset, rawBody] of Object.entries(request.contents)) {
          const asset = validateStringId(rawAsset, 'asset');
          if (typeof rawBody !== 'string' || rawBody.length > MAX_BODY_LEN) {
            throw new Error('Invalid content body');
          }
          state.encrypted_assets.set(asset, encryptBody(rawBody, kek));
        }

        // Populate disabled list using Set
        if (Array.isArray(request.disabled)) {
          for (const rawActor of request.disabled) {
            if (typeof rawActor === 'string') {
              state.disabled.add(validateStringId(rawActor, 'disabled actor'));
            }
          }
        }

        // key_material is sensitive: never stored in plaintext
        saveState(stateDir, state);
        return { ready: true };
      }

      case 'read': {
        const actor = validateStringId(request.actor, 'actor');
        const asset = validateStringId(request.asset, 'asset');
        const requestId = validateStringId(request.request_id, 'request_id');

        const state = loadState(stateDir);

        const isOwner = state.owners.get(asset) === actor;
        const isDisabled = state.disabled.has(actor);
        const isRevoked = state.revoked.has(actor);

        let decision = 'deny';
        let bodyContent = null;

        if (isOwner && !isDisabled && !isRevoked) {
          const record = state.encrypted_assets.get(asset);
          if (record) {
            decision = 'allow';
            bodyContent = decryptBody(record, kek);
          }
        }

        // Audit integrity: First-Write-Wins (do not overwrite existing request_id)
        if (!state.audit_events.has(requestId)) {
          state.audit_events.set(requestId, {
            request_id: requestId,
            decision
          });
          saveState(stateDir, state);
        }

        if (decision === 'allow' && bodyContent !== null) {
          return { decision: 'allow', body: bodyContent };
        }
        return { decision: 'deny' };
      }

      case 'revoke': {
        const actor = validateStringId(request.actor, 'actor');
        const state = loadState(stateDir);
        state.revoked.add(actor);
        saveState(stateDir, state);
        return {};
      }

      case 'audit': {
        const requestId = validateStringId(request.request_id, 'request_id');
        const state = loadState(stateDir);
        const entry = state.audit_events.get(requestId);
        if (entry) {
          return {
            request_id: entry.request_id,
            decision: entry.decision
          };
        }
        // Unknown request_id returns safe not-found / deny without crashing
        return {
          request_id: requestId,
          decision: 'deny'
        };
      }

      case 'protected_read': {
        const actor = validateStringId(request.actor, 'actor');
        const asset = validateStringId(request.asset, 'asset');
        const challenge = validateStringId(request.challenge, 'challenge', MAX_CHALLENGE_LEN);
        const publicKeyB64 = request.public_key;

        // Strict Base64 validation
        if (typeof publicKeyB64 !== 'string' || !STRICT_BASE64_REGEX.test(publicKeyB64.trim())) {
          return { decision: 'deny' };
        }

        const rawPk = Buffer.from(publicKeyB64.trim(), 'base64');
        if (rawPk.length !== 1184) {
          return { decision: 'deny' };
        }

        const state = loadState(stateDir);

        // Authorization check BEFORE any KEM operation (prevents oracle & timing attacks)
        const isOwner = state.owners.get(asset) === actor;
        const isDisabled = state.disabled.has(actor);
        const isRevoked = state.revoked.has(actor);
        const record = state.encrypted_assets.get(asset);

        // If unauthorized or unknown asset, deny immediately
        if (!isOwner || isDisabled || isRevoked || !record) {
          if (request.request_id && typeof request.request_id === 'string') {
            if (!state.audit_events.has(request.request_id)) {
              state.audit_events.set(request.request_id, {
                request_id: request.request_id,
                decision: 'deny'
              });
              saveState(stateDir, state);
            }
          }
          return { decision: 'deny' };
        }

        // Decrypt stored body
        const body = decryptBody(record, kek);

        // Import standard raw ML-KEM-768 public key
        const spkiDer = Buffer.concat([ML_KEM_768_SPKI_PREFIX, rawPk]);
        const keyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

        // Native KEM encapsulation
        const { sharedKey, ciphertext } = crypto.encapsulate(keyObj);

        // Compute HMAC proof: HMAC-SHA256(sharedKey, UTF-8(challenge + body))
        const proof = crypto.createHmac('sha256', sharedKey)
          .update(Buffer.from(challenge + body, 'utf8'))
          .digest('hex')
          .toLowerCase();

        // Audit log allowed protected_read if request_id provided
        if (request.request_id && typeof request.request_id === 'string') {
          if (!state.audit_events.has(request.request_id)) {
            state.audit_events.set(request.request_id, {
              request_id: request.request_id,
              decision: 'allow'
            });
            saveState(stateDir, state);
          }
        }

        return {
          decision: 'allow',
          ciphertext: ciphertext.toString('base64'),
          proof
        };
      }

      default:
        throw new Error(`Unsupported operation: ${op}`);
    }
  });
};
