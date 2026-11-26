'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');
const { KeyLifecycleManager } = require('./lib/key_lifecycle.cjs');
const { TamperEvidentLog } = require('./lib/tamper_log.cjs');

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
      try {
        fs.writeSync(fd, `${process.pid}\n`);
      } catch {}
      break;
    } catch (err) {
      if (err.code === 'EEXIST') {
        try {
          const content = fs.readFileSync(lockPath, 'utf8').trim();
          const lockPid = parseInt(content, 10);
          if (!isNaN(lockPid)) {
            try {
              process.kill(lockPid, 0); // Check if process still exists
            } catch (kerr) {
              if (kerr.code === 'ESRCH') {
                // Process holding lock is dead - break stale lock immediately
                fs.unlinkSync(lockPath);
                continue;
              }
            }
          }
          const stat = fs.statSync(lockPath);
          if (Date.now() - stat.mtimeMs > LOCK_TIMEOUT_MS) {
            fs.unlinkSync(lockPath);
            continue;
          }
        } catch {
          // Lock might have been released or stat failed
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
    epoch: 1,
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
    epoch: parsed.epoch || 1,
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
    epoch: state.epoch || 1,
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

// AEAD (AES-256-GCM) Envelope Encryption with Versioned KEK
function encryptBodyWithKey(body, kek, keyVersion = 1) {
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
    key_version: keyVersion,
    wrapped_key_b64: wrappedKey.toString('base64'),
    wrap_iv_b64: wrapIv.toString('base64'),
    wrap_tag_b64: wrapTag.toString('base64'),
    body_iv_b64: bodyIv.toString('base64'),
    body_ciphertext_b64: ciphertext.toString('base64'),
    body_tag_b64: bodyTag.toString('base64')
  };
}

function decryptBodyWithKey(record, kek) {
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
  const km = new KeyLifecycleManager(stateDir);
  const tamperLog = new TamperEvidentLog(stateDir);

  return await withStateLock(stateDir, async () => {
    switch (op) {
      case 'setup': {
        if (!request.owners || typeof request.owners !== 'object' || Array.isArray(request.owners) ||
            !request.contents || typeof request.contents !== 'object' || Array.isArray(request.contents)) {
          throw new Error('Invalid setup request structure');
        }

        const activeKekObj = km.getActiveKey();
        const activeKek = Buffer.from(activeKekObj.keyHex, 'hex');

        const state = createEmptyState();

        // Populate owners using Map
        for (const [rawAsset, rawActor] of Object.entries(request.owners)) {
          const asset = validateStringId(rawAsset, 'asset');
          const actor = validateStringId(rawActor, 'actor');
          state.owners.set(asset, actor);
        }

        // Populate and encrypt contents with active KEK
        for (const [rawAsset, rawBody] of Object.entries(request.contents)) {
          const asset = validateStringId(rawAsset, 'asset');
          if (typeof rawBody !== 'string' || rawBody.length > MAX_BODY_LEN) {
            throw new Error('Invalid content body');
          }
          state.encrypted_assets.set(asset, encryptBodyWithKey(rawBody, activeKek, activeKekObj.version));
        }

        // Populate disabled list using Set
        if (Array.isArray(request.disabled)) {
          for (const rawActor of request.disabled) {
            if (typeof rawActor === 'string') {
              state.disabled.add(validateStringId(rawActor, 'disabled actor'));
            }
          }
        }

        // Fault hook injection for crash recovery testing (disabled by default)
        if (process.env.TRACK4_FAULT_HOOK === 'mid_setup') {
          process.kill(process.pid, 'SIGKILL');
        }

        saveState(stateDir, state);
        tamperLog.appendRecord('system', 'setup', { owners_count: state.owners.size });
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
            const keyVer = record.key_version || 1;
            if (km.canUseForDecryption(keyVer)) {
              const kekObj = km.getKeyByVersion(keyVer);
              if (kekObj) {
                const kek = Buffer.from(kekObj.keyHex, 'hex');
                decision = 'allow';
                bodyContent = decryptBodyWithKey(record, kek);
              }
            }
          }
        }

        // Audit integrity: First-Write-Wins
        if (!state.audit_events.has(requestId)) {
          state.audit_events.set(requestId, {
            request_id: requestId,
            decision
          });
          saveState(stateDir, state);
        }

        tamperLog.appendRecord(actor, 'read', { asset, request_id: requestId, decision });

        if (decision === 'allow' && bodyContent !== null) {
          return { decision: 'allow', body: bodyContent };
        }
        return { decision: 'deny' };
      }

      case 'revoke': {
        const actor = validateStringId(request.actor, 'actor');
        const state = loadState(stateDir);

        // Fault hook injection for crash recovery testing
        if (process.env.TRACK4_FAULT_HOOK === 'mid_revoke') {
          process.kill(process.pid, 'SIGKILL');
        }

        state.revoked.add(actor);
        state.epoch = (state.epoch || 1) + 1;
        saveState(stateDir, state);
        tamperLog.appendRecord('admin', 'revoke', { target_actor: actor });
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
        // Requirement 8: For unknown request_id, return safe deny response
        // without inventing a phantom entry in the audit database.
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

        // Authorization check BEFORE any KEM operation
        const isOwner = state.owners.get(asset) === actor;
        const isDisabled = state.disabled.has(actor);
        const isRevoked = state.revoked.has(actor);
        const record = state.encrypted_assets.get(asset);

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
          tamperLog.appendRecord(actor, 'protected_read', { asset, decision: 'deny' });
          return { decision: 'deny' };
        }

        const keyVer = record.key_version || 1;
        if (!km.canUseForDecryption(keyVer)) {
          tamperLog.appendRecord(actor, 'protected_read', { asset, decision: 'deny' });
          return { decision: 'deny' };
        }
        const kekObj = km.getKeyByVersion(keyVer);
        if (!kekObj) {
          tamperLog.appendRecord(actor, 'protected_read', { asset, decision: 'deny' });
          return { decision: 'deny' };
        }
        const kek = Buffer.from(kekObj.keyHex, 'hex');

        // Decrypt stored body
        const body = decryptBodyWithKey(record, kek);

        // Import standard raw ML-KEM-768 public key
        const spkiDer = Buffer.concat([ML_KEM_768_SPKI_PREFIX, rawPk]);
        const keyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

        // Native KEM encapsulation
        const { sharedKey, ciphertext } = crypto.encapsulate(keyObj);

        // Compute HMAC proof
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

        tamperLog.appendRecord(actor, 'protected_read', { asset, decision: 'allow' });

        return {
          decision: 'allow',
          ciphertext: ciphertext.toString('base64'),
          proof
        };
      }

      // Integrated re-wrap operation on key rotation
      case 'rewrap_keys': {
        const activeKekObj = km.getActiveKey();
        const activeKek = Buffer.from(activeKekObj.keyHex, 'hex');
        const state = loadState(stateDir);

        for (const [assetId, record] of state.encrypted_assets.entries()) {
          const oldVer = record.key_version || 1;
          if (oldVer !== activeKekObj.version) {
            const oldKekObj = km.getKeyByVersion(oldVer);
            if (oldKekObj) {
              const oldKek = Buffer.from(oldKekObj.keyHex, 'hex');
              const body = decryptBodyWithKey(record, oldKek);
              state.encrypted_assets.set(assetId, encryptBodyWithKey(body, activeKek, activeKekObj.version));
            }
          }
        }
        saveState(stateDir, state);
        return { rewrapped: true, active_version: activeKekObj.version };
      }

      default:
        throw new Error(`Unsupported operation: ${op}`);
    }
  });
};
