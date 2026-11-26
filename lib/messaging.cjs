'use strict';

/**
 * lib/messaging.cjs
 *
 * Post-Quantum Protected Messaging Engine for DevForge Track 4 (Goals 9-12).
 *
 * Security Guarantees:
 * - Ephemeral ML-KEM-768 per session: recipient generates ephemeral KEM keypair, signs public key
 *   with long-term ML-DSA-65 identity key. Sender verifies signature before encapsulation.
 *   Recipient deletes ephemeral private key after session (best-effort zeroization in JS).
 *   Forward secrecy: compromising long-term identity keys post-session cannot decrypt past messages.
 * - Nonce & Replay Defense: replay cache keys on (sender, message_id, sequence).
 *   Detects sequence reuse with different message IDs, duplicate message IDs with different sequences,
 *   out-of-window sequences, corrupt states, and state rollback attempts via monotonic high-water mark.
 * - Trusted Sender Directory: Authenticated sender-to-key binding, rotation, and revocation.
 * - Recipient & AAD Binding: full recipient ID & metadata in AAD; sender signs over ciphertext + AAD.
 *   Signature verified BEFORE decryption. Wrong recipient or altered AAD fails.
 * - Chunking & Stream Authentication: Length-prefixed canonical headers signed per chunk with ML-DSA-65.
 *   Rejects missing signatures, duplicate chunks, inconsistent metadata, out-of-range chunks, and tampering.
 * - Session Resumption: 32-byte HMAC ticket key loaded from stateDir; ticket cryptographically
 *   binds peer identity and key with timing-safe HMAC, strict TTL bounds, and future-timestamp rejection.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

// Standard NIST ML-KEM-768 SPKI prefix for raw 1184-byte keys
const ML_KEM_768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');
const MAX_TRACKED_SENDERS = 5000;
const MAX_MESSAGE_SIZE = 10 * 1024 * 1024; // 10 MB
const MAX_TOTAL_CHUNKS = 10000;
const MAX_TICKET_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours
const MIN_TICKET_TTL_MS = 1; // 1 millisecond

class ProtectedMessagingEngine {
  constructor(stateDir) {
    this.stateDir = stateDir || process.env.TRACK4_STATE_DIR || path.join(os.tmpdir(), 'track4-state');
    this.stateFilePath = path.join(this.stateDir, 'replay_state.json');
    this.highwaterFilePath = path.join(this.stateDir, 'replay_highwater.json');
    this.trustedSendersFilePath = path.join(this.stateDir, 'trusted_senders.json');
    this.senderSeqFilePath = path.join(this.stateDir, 'sender_seq.json');

    this.corrupt = false;
    this.replayState = { generation: 1, senders: Object.create(null) };
    this.trustedSenders = Object.create(null);

    this._loadTrustedSenders();
    this._loadReplayState();
  }

  _loadTrustedSenders() {
    try {
      if (fs.existsSync(this.trustedSendersFilePath)) {
        const raw = fs.readFileSync(this.trustedSendersFilePath, 'utf8');
        const data = JSON.parse(raw);
        if (data && typeof data === 'object') {
          for (const k of Object.keys(data)) {
            this.trustedSenders[k] = data[k];
          }
        }
      }
    } catch (_) {}
  }

  _saveTrustedSenders() {
    if (!fs.existsSync(this.stateDir)) {
      try { fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 }); } catch (_) {}
    }
    const tmp = path.join(this.stateDir, `trusted_senders.tmp.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`);
    fs.writeFileSync(tmp, JSON.stringify(this.trustedSenders, null, 2), { mode: 0o600 });
    fs.renameSync(tmp, this.trustedSendersFilePath);
  }

  registerSenderIdentity(senderId, dsaPublicKey, metadata = {}) {
    if (!senderId || typeof senderId !== 'string') {
      throw new Error('INVALID_SENDER_ID: Non-empty string required');
    }
    let derB64;
    if (typeof dsaPublicKey === 'string') {
      derB64 = dsaPublicKey.includes('BEGIN')
        ? crypto.createPublicKey(dsaPublicKey).export({ format: 'der', type: 'spki' }).toString('base64')
        : dsaPublicKey;
    } else if (dsaPublicKey && typeof dsaPublicKey.export === 'function') {
      derB64 = dsaPublicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    } else {
      throw new Error('INVALID_PUBLIC_KEY: KeyObject or base64 DER required');
    }

    this.trustedSenders[senderId] = {
      sender_id: senderId,
      publicKeyDerB64: derB64,
      revoked: false,
      version: 1,
      registered_at: Date.now(),
      metadata: metadata || {}
    };
    this._saveTrustedSenders();
  }

  rotateSenderKey(senderId, newDsaPublicKey) {
    if (!this.trustedSenders[senderId]) {
      throw new Error(`UNREGISTERED_SENDER: Cannot rotate unregistered sender '${senderId}'`);
    }
    let derB64;
    if (typeof newDsaPublicKey === 'string') {
      derB64 = newDsaPublicKey.includes('BEGIN')
        ? crypto.createPublicKey(newDsaPublicKey).export({ format: 'der', type: 'spki' }).toString('base64')
        : newDsaPublicKey;
    } else if (newDsaPublicKey && typeof newDsaPublicKey.export === 'function') {
      derB64 = newDsaPublicKey.export({ format: 'der', type: 'spki' }).toString('base64');
    } else {
      throw new Error('INVALID_PUBLIC_KEY: KeyObject or base64 DER required');
    }

    const prev = this.trustedSenders[senderId];
    this.trustedSenders[senderId] = {
      ...prev,
      publicKeyDerB64: derB64,
      version: (prev.version || 1) + 1,
      previousKeyDerB64: prev.publicKeyDerB64,
      rotated_at: Date.now()
    };
    this._saveTrustedSenders();
  }

  revokeSenderKey(senderId, reason = 'key_compromised') {
    if (!this.trustedSenders[senderId]) {
      throw new Error(`UNREGISTERED_SENDER: Cannot revoke unregistered sender '${senderId}'`);
    }
    this.trustedSenders[senderId].revoked = true;
    this.trustedSenders[senderId].revoked_at = Date.now();
    this.trustedSenders[senderId].revocation_reason = reason;
    this._saveTrustedSenders();
  }

  getSenderKey(senderId) {
    return this.trustedSenders[senderId] || null;
  }

  _loadReplayState() {
    try {
      if (!fs.existsSync(this.stateFilePath)) {
        this.replayState = { generation: 1, senders: Object.create(null) };
        return;
      }
      const raw = fs.readFileSync(this.stateFilePath, 'utf8');
      const data = JSON.parse(raw);
      if (!data || typeof data !== 'object' || typeof data.senders !== 'object' || Array.isArray(data.senders)) {
        this.corrupt = true;
        return;
      }

      // Rollback protection check: verify against monotonic high-water mark
      if (fs.existsSync(this.highwaterFilePath)) {
        try {
          const hwRaw = fs.readFileSync(this.highwaterFilePath, 'utf8');
          const hw = JSON.parse(hwRaw);
          const currentGen = typeof data.generation === 'number' ? data.generation : 0;
          if (typeof hw.generation === 'number' && currentGen < hw.generation) {
            this.corrupt = true;
            throw new Error(`REPLAY_STATE_ROLLBACK_DETECTED: State generation (${currentGen}) is older than high-water mark (${hw.generation})`);
          }
        } catch (err) {
          if (err.message.includes('ROLLBACK_DETECTED')) {
            throw err;
          }
        }
      }

      const senders = Object.create(null);
      for (const key of Object.keys(data.senders)) {
        const val = data.senders[key];
        if (!val || typeof val !== 'object' || typeof val.highest_seq !== 'number' || !Array.isArray(val.seen)) {
          this.corrupt = true;
          return;
        }

        const seqToMsg = Object.create(null);
        const msgToSeq = Object.create(null);

        // Reconstruct bi-directional sequence <-> message_id maps
        for (const item of val.seen) {
          if (Array.isArray(item) && item.length >= 2) {
            const [mId, sNum] = item;
            seqToMsg[sNum] = mId;
            msgToSeq[mId] = sNum;
          }
        }

        senders[key] = {
          highest_seq: val.highest_seq,
          seen: val.seen,
          seq_to_msg: seqToMsg,
          msg_to_seq: msgToSeq,
          last_seen: val.last_seen || Date.now()
        };
      }
      this.replayState = {
        generation: typeof data.generation === 'number' ? data.generation : 1,
        senders
      };
    } catch (err) {
      this.corrupt = true;
      if (err.message.includes('ROLLBACK_DETECTED')) throw err;
    }
  }

  _withReplayLock(fn) {
    if (!fs.existsSync(this.stateDir)) {
      try { fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 }); } catch (_) {}
    }
    const lockPath = path.join(this.stateDir, 'replay_state.lock');
    const lockToken = crypto.randomUUID();
    const timeoutMs = 8000;
    const start = Date.now();
    let lockFd = null;

    while (Date.now() - start < timeoutMs) {
      try {
        lockFd = fs.openSync(lockPath, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_RDWR, 0o600);
        const payload = JSON.stringify({ pid: process.pid, token: lockToken, createdAt: Date.now() });
        fs.writeSync(lockFd, `${payload}\n`);
        fs.fsyncSync(lockFd);
        break;
      } catch (err) {
        if (err.code === 'EEXIST') {
          let isDead = false;
          let lockContent = null;
          try {
            if (fs.existsSync(lockPath)) {
              const stat = fs.statSync(lockPath);
              if (stat.size === 0) {
                if (Date.now() - stat.mtimeMs > 500) isDead = true;
              } else {
                lockContent = fs.readFileSync(lockPath, 'utf8').trim();
              }
            }
          } catch (_) {}

          if (lockContent) {
            let parsed;
            try {
              parsed = JSON.parse(lockContent);
              if (typeof parsed === 'number') parsed = { pid: parsed };
            } catch {
              const maybePid = parseInt(lockContent, 10);
              if (!isNaN(maybePid)) parsed = { pid: maybePid };
            }

            if (parsed && typeof parsed.pid === 'number') {
              try {
                process.kill(parsed.pid, 0); // Check if process still exists
              } catch (kerr) {
                if (kerr.code === 'ESRCH') {
                  isDead = true;
                }
                // EPERM means process exists under another user - NOT dead
              }
            } else if (parsed === undefined) {
              isDead = true;
            }
          }

          if (isDead) {
            // Atomic rename to unique stale file: exactly one process wins recovery
            const staleClaimPath = `${lockPath}.stale.${crypto.randomUUID()}`;
            try {
              fs.renameSync(lockPath, staleClaimPath);
              try { fs.unlinkSync(staleClaimPath); } catch (_) {}
            } catch (_) {}
            continue;
          }

          // Active process lock. Retry with jittered backoff.
          const pauseUntil = Date.now() + 15 + Math.floor(Math.random() * 20);
          while (Date.now() < pauseUntil) {}
        } else {
          this.corrupt = true;
          throw new Error(`REPLAY_STATE_UNAVAILABLE: Replay lock acquisition failed (${err.message})`);
        }
      }
    }

    if (lockFd === null) {
      this.corrupt = true;
      throw new Error('REPLAY_STATE_UNAVAILABLE: Replay lock acquisition timed out (held by active process)');
    }

    try {
      this._loadReplayState();
      return fn();
    } finally {
      try {
        if (fs.existsSync(lockPath)) {
          const content = fs.readFileSync(lockPath, 'utf8').trim();
          let parsed;
          try {
            parsed = JSON.parse(content);
            if (typeof parsed === 'number') parsed = { pid: parsed, token: null };
          } catch {
            const maybePid = parseInt(content, 10);
            if (!isNaN(maybePid)) parsed = { pid: maybePid, token: null };
          }
          if (parsed && parsed.token === lockToken && parsed.pid === process.pid) {
            fs.unlinkSync(lockPath);
          }
        }
      } catch (_) {}
      try { fs.closeSync(lockFd); } catch (_) {}
    }
  }

  _saveReplayState() {
    if (this.corrupt) {
      throw new Error('REPLAY_STATE_UNAVAILABLE: Replay state is corrupt or unreadable');
    }
    if (!fs.existsSync(this.stateDir)) {
      fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
    }

    // Advance monotonic generation counter
    this.replayState.generation = (this.replayState.generation || 0) + 1;

    const tmpPath = path.join(
      this.stateDir,
      `replay_state.json.tmp.${Date.now()}.${crypto.randomBytes(4).toString('hex')}`
    );
    const data = JSON.stringify(this.replayState, null, 2);
    try {
      const fd = fs.openSync(tmpPath, 'w', 0o600);
      try {
        fs.writeSync(fd, data, 0, 'utf8');
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      fs.renameSync(tmpPath, this.stateFilePath);

      // Record high-water mark for rollback detection
      const hwTmp = path.join(this.stateDir, `replay_highwater.tmp.${Date.now()}`);
      fs.writeFileSync(hwTmp, JSON.stringify({ generation: this.replayState.generation, timestamp: Date.now() }), { mode: 0o600 });
      fs.renameSync(hwTmp, this.highwaterFilePath);
    } catch (err) {
      try { if (fs.existsSync(tmpPath)) fs.unlinkSync(tmpPath); } catch (_) {}
      this.corrupt = true;
      throw new Error(`REPLAY_STATE_UNAVAILABLE: Failed to persist replay state: ${err.message}`);
    }
  }

  _validateInputs(senderId, messageId, sequenceNumber) {
    if (typeof senderId !== 'string' || senderId.length === 0 || senderId.length > 256 || senderId.includes('\0')) {
      throw new Error('INVALID_INPUT: sender_id must be a non-empty string <= 256 characters without null bytes');
    }
    if (typeof messageId !== 'string' || messageId.length === 0 || messageId.length > 256 || messageId.includes('\0')) {
      throw new Error('INVALID_INPUT: message_id must be a non-empty string <= 256 characters without null bytes');
    }
    if (typeof sequenceNumber !== 'number' || !Number.isSafeInteger(sequenceNumber) || sequenceNumber < 0) {
      throw new Error('INVALID_INPUT: sequence_number must be a non-negative safe integer');
    }
  }

  _checkReplay(senderId, messageId, sequenceNumber) {
    if (this.corrupt) {
      throw new Error('REPLAY_STATE_UNAVAILABLE: Replay database is corrupted or unreadable');
    }

    this._validateInputs(senderId, messageId, sequenceNumber);

    const sender = senderId;
    const msgId = messageId;
    const seq = sequenceNumber;

    if (!this.replayState || !this.replayState.senders) {
      return;
    }

    const senderEntry = Object.prototype.hasOwnProperty.call(this.replayState.senders, sender)
      ? this.replayState.senders[sender]
      : undefined;

    if (!senderEntry) {
      return;
    }

    const highest = senderEntry.highest_seq;
    if (typeof highest === 'number') {
      if (seq <= highest - 1024) {
        throw new Error(
          `MESSAGE_REPLAY_DETECTED: Sequence ${seq} is at or below sliding window threshold (${highest - 1024}) for sender ${sender}`
        );
      }
    }

    // 1. Same sender reusing a sequence number with a different message ID
    if (senderEntry.seq_to_msg && Object.prototype.hasOwnProperty.call(senderEntry.seq_to_msg, seq)) {
      const recorded = senderEntry.seq_to_msg[seq];
      if (recorded !== msgId) {
        throw new Error(
          `MESSAGE_REPLAY_DETECTED: Sequence ${seq} already used with different message ID (recorded=${recorded}, incoming=${msgId})`
        );
      }
    }

    // 2. Duplicate message ID with different sequence number
    if (senderEntry.msg_to_seq && Object.prototype.hasOwnProperty.call(senderEntry.msg_to_seq, msgId)) {
      const recordedSeq = senderEntry.msg_to_seq[msgId];
      if (recordedSeq !== seq) {
        throw new Error(
          `MESSAGE_REPLAY_DETECTED: Duplicate message ID with different sequence number (msgId=${msgId}, recordedSeq=${recordedSeq}, incoming=${seq})`
        );
      }
    }

    // 3. Exact duplicate pair
    if (Array.isArray(senderEntry.seen)) {
      const alreadySeen = senderEntry.seen.some(([mId, s]) => mId === msgId && s === seq);
      if (alreadySeen) {
        throw new Error(
          `MESSAGE_REPLAY_DETECTED: Duplicate message pair (id=${msgId}, seq=${seq}) already accepted for sender ${sender}`
        );
      }
    }
  }

  _recordReplay(senderId, messageId, sequenceNumber) {
    if (this.corrupt) {
      throw new Error('REPLAY_STATE_UNAVAILABLE: Cannot record replay because state is corrupt');
    }

    this._validateInputs(senderId, messageId, sequenceNumber);

    const sender = senderId;
    const msgId = messageId;
    const seq = sequenceNumber;

    if (!this.replayState.senders || typeof this.replayState.senders !== 'object') {
      this.replayState.senders = Object.create(null);
    }

    // Bound unique senders to prevent unbounded state growth
    const senderKeys = Object.keys(this.replayState.senders);
    if (senderKeys.length > MAX_TRACKED_SENDERS && !Object.prototype.hasOwnProperty.call(this.replayState.senders, sender)) {
      // Prune oldest inactive 1000 senders
      const sorted = senderKeys.sort((a, b) => (this.replayState.senders[a].last_seen || 0) - (this.replayState.senders[b].last_seen || 0));
      for (let i = 0; i < 1000; i++) {
        delete this.replayState.senders[sorted[i]];
      }
    }

    if (!Object.prototype.hasOwnProperty.call(this.replayState.senders, sender)) {
      this.replayState.senders[sender] = {
        highest_seq: seq,
        seen: [],
        seq_to_msg: Object.create(null),
        msg_to_seq: Object.create(null),
        last_seen: Date.now()
      };
    }

    const entry = this.replayState.senders[sender];
    entry.last_seen = Date.now();
    if (typeof entry.highest_seq === 'number') {
      entry.highest_seq = Math.max(entry.highest_seq, seq);
    } else {
      entry.highest_seq = seq;
    }

    entry.seen.push([msgId, seq]);
    entry.seq_to_msg[seq] = msgId;
    entry.msg_to_seq[msgId] = seq;

    // Prune entries outside the 1,024 sliding window: entries with seq <= (highest_seq - 1024)
    const cutoff = entry.highest_seq - 1024;
    entry.seen = entry.seen.filter(([m, s]) => {
      const keep = s > cutoff;
      if (!keep) {
        delete entry.seq_to_msg[s];
        delete entry.msg_to_seq[m];
      }
      return keep;
    });

    // Persist atomically to disk BEFORE returning
    this._saveReplayState();
  }

  /**
   * Generate long-term identity keypair (ML-DSA-65 for signing / verification)
   */
  static generateIdentityKeyPair() {
    const dsaKp = crypto.generateKeyPairSync('ml-dsa-65');
    const pubDer = dsaKp.publicKey.export({ format: 'der', type: 'spki' });
    return {
      dsa: {
        publicKey: dsaKp.publicKey,
        privateKey: dsaKp.privateKey,
        publicKeyDerB64: pubDer.toString('base64')
      }
    };
  }

  /**
   * Recipient generates a fresh EPHEMERAL ML-KEM-768 keypair for the session,
   * signed by recipient's long-term ML-DSA-65 identity key.
   *
   * Note: Private key material is intentionally NOT exported as base64 string
   * to eliminate accidental leakage in logs or serialized JSON responses.
   */
  static generateEphemeralPrekey(recipientDsaPrivateKey) {
    const kemKp = crypto.generateKeyPairSync('ml-kem-768');
    const spkiDer = kemKp.publicKey.export({ format: 'der', type: 'spki' });
    const rawKemPk = spkiDer.subarray(22); // 1184 bytes

    // Sign ephemeral KEM public key with long-term ML-DSA-65 identity key
    const signature = crypto.sign(null, rawKemPk, recipientDsaPrivateKey);

    const prekeyObj = {
      ephemeralPublicKeyB64: rawKemPk.toString('base64'),
      signatureB64: signature.toString('base64'),
      ephemeralPrivateKey: kemKp.privateKey,
      destroyed: false,
      toJSON() {
        return {
          ephemeralPublicKeyB64: this.ephemeralPublicKeyB64,
          signatureB64: this.signatureB64,
          destroyed: this.destroyed
        };
      },
      destroy() {
        this.ephemeralPrivateKey = null;
        this.destroyed = true;
      },
      exportPrivateKeyDerB64() {
        if (!this.ephemeralPrivateKey) return null;
        return this.ephemeralPrivateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64');
      }
    };

    // Non-enumerable getter for safe process-boundary transfer without leaking in logs or stringify
    Object.defineProperty(prekeyObj, 'ephemeralPrivateKeyDerB64', {
      enumerable: false,
      configurable: true,
      get() {
        return this.exportPrivateKeyDerB64();
      }
    });

    return prekeyObj;
  }

  _getNextOutgoingSequence(senderId) {
    let seqs = {};
    if (fs.existsSync(this.senderSeqFilePath)) {
      try {
        seqs = JSON.parse(fs.readFileSync(this.senderSeqFilePath, 'utf8'));
      } catch {}
    }
    const nextSeq = (seqs[senderId] || 0) + 1;
    seqs[senderId] = nextSeq;
    try {
      const tmp = `${this.senderSeqFilePath}.${process.pid}.${Date.now()}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(seqs), { mode: 0o600 });
      fs.renameSync(tmp, this.senderSeqFilePath);
    } catch {}
    return nextSeq;
  }

  _recordOutgoingSequence(senderId, seq) {
    let seqs = {};
    if (fs.existsSync(this.senderSeqFilePath)) {
      try {
        seqs = JSON.parse(fs.readFileSync(this.senderSeqFilePath, 'utf8'));
      } catch {}
    }
    if ((seqs[senderId] || 0) < seq) {
      seqs[senderId] = seq;
      try {
        const tmp = `${this.senderSeqFilePath}.${process.pid}.${Date.now()}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(seqs), { mode: 0o600 });
        fs.renameSync(tmp, this.senderSeqFilePath);
      } catch {}
    }
  }

  /**
   * Sender transmits protected message:
   * 1. Verifies recipient's ML-DSA-65 signature on recipient's ephemeral ML-KEM-768 public key.
   * 2. Encapsulates shared secret to recipient's ephemeral public key.
   * 3. Derives AES key using HKDF-SHA256 with sender, recipient, message ID.
   * 4. Encrypts plaintext with AES-256-GCM, binding full AAD (sender, recipient, message ID, seq, timestamp).
   * 5. Signs (kemCiphertext || iv || ciphertext || authTag || aad) with sender's ML-DSA-65 identity key.
   */
  sendMessage(senderId, senderSigningKey, recipientId, recipientDsaPublicKey, recipientPrekey, plaintext, options = {}) {
    if (!senderId || !recipientId || typeof plaintext !== 'string') {
      throw new Error('Invalid send parameters: senderId, recipientId, plaintext required');
    }

    let seq;
    if (options.sequenceNumber !== undefined) {
      seq = options.sequenceNumber;
      this._recordOutgoingSequence(senderId, seq);
    } else {
      seq = this._getNextOutgoingSequence(senderId);
    }

    const messageId = options.messageId || `msg-${crypto.randomUUID()}`;
    const timestamp = options.timestamp || Date.now();

    // 1. Verify recipient prekey signature with recipient's long-term identity key
    const rawKemPk = Buffer.from(recipientPrekey.ephemeralPublicKeyB64, 'base64');
    const prekeySig = Buffer.from(recipientPrekey.signatureB64, 'base64');
    const prekeyValid = crypto.verify(null, rawKemPk, recipientDsaPublicKey, prekeySig);
    if (!prekeyValid) {
      throw new Error('RECIPIENT_PREKEY_SIGNATURE_INVALID: Ephemeral KEM key signature check failed');
    }

    // 2. Encapsulate to recipient's ephemeral ML-KEM-768 public key
    const spkiDer = Buffer.concat([ML_KEM_768_SPKI_PREFIX, rawKemPk]);
    const recipientKemKeyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });
    const { sharedKey, ciphertext: kemCiphertext } = crypto.encapsulate(recipientKemKeyObj);

    // 3. Derive 32-byte AES key via HKDF-SHA256
    const salt = options.salt || crypto.randomBytes(16);
    const info = Buffer.from(`ProtectedMessaging-v1:${senderId}->${recipientId}:${messageId}:${seq}`, 'utf8');
    const derivedAesKey = crypto.hkdfSync('sha256', sharedKey, salt, info, 32);

    // 4. AAD binding
    const aad = {
      sender_id: senderId,
      recipient_id: recipientId,
      message_id: messageId,
      sequence_number: seq,
      timestamp
    };
    const aadBuffer = Buffer.from(JSON.stringify(aad), 'utf8');

    // 5. AES-256-GCM encryption with AAD
    const iv = crypto.randomBytes(12);
    const cipher = crypto.createCipheriv('aes-256-gcm', derivedAesKey, iv);
    cipher.setAAD(aadBuffer);
    let ciphertext = cipher.update(plaintext, 'utf8');
    ciphertext = Buffer.concat([ciphertext, cipher.final()]);
    const authTag = cipher.getAuthTag();

    // 6. Sender signs all elements with ML-DSA-65
    const payloadToSign = Buffer.concat([kemCiphertext, iv, ciphertext, authTag, aadBuffer]);
    const signature = crypto.sign(null, payloadToSign, senderSigningKey);

    return {
      message_id: messageId,
      sequence_number: seq,
      kem_ciphertext_b64: kemCiphertext.toString('base64'),
      salt_hex: salt.toString('hex'),
      iv_hex: iv.toString('hex'),
      ciphertext_b64: ciphertext.toString('base64'),
      auth_tag_hex: authTag.toString('hex'),
      aad,
      signature_b64: signature.toString('base64'),
      forward_secrecy: 'EPHEMERAL_PREKEY_RECIPIENT_ENCAPSULATED'
    };
  }

  /**
   * Recipient receives and decrypts message:
   * 1. Checks recipient identity.
   * 2. Verifies sender identity against trusted sender registry.
   * 3. Checks replay cache on (sender, message_id, sequence).
   * 4. Verifies sender's ML-DSA-65 signature BEFORE decapsulation and decryption.
   * 5. Decapsulates shared secret using ephemeral KEM private key.
   * 6. Decrypts AES-256-GCM and verifies AAD.
   */
  receiveMessage(recipientId, ephemeralPrekey, senderDsaPublicKey, messagePacket, options = {}) {
    try {
      if (!messagePacket || typeof messagePacket !== 'object') {
        throw new Error('INVALID_PACKET: Expected object');
      }

      const {
        message_id,
        kem_ciphertext_b64,
        salt_hex,
        iv_hex,
        ciphertext_b64,
        auth_tag_hex,
        aad,
        signature_b64
      } = messagePacket;

      // 1. Recipient binding verification
      if (!aad || aad.recipient_id !== recipientId) {
        throw new Error(`WRONG_RECIPIENT_ERROR: Intended for ${aad ? aad.recipient_id : 'unknown'}, received by ${recipientId}`);
      }

      // 2. Check if ephemeral key was deleted (forward secrecy check)
      if (!ephemeralPrekey || !ephemeralPrekey.ephemeralPrivateKey || ephemeralPrekey.destroyed) {
        throw new Error('EPHEMERAL_KEY_DESTROYED: Session ephemeral key was wiped; cannot decrypt historical message');
      }

      // 3. Sender Identity Binding
      let effectiveSenderKey = senderDsaPublicKey;
      const claimedSender = aad.sender_id;
      if (this.trustedSenders && Object.keys(this.trustedSenders).length > 0) {
        const reg = this.trustedSenders[claimedSender];
        if (!reg) {
          throw new Error(`UNREGISTERED_SENDER: Sender '${claimedSender}' is not registered in trusted identity directory`);
        }
        if (reg.revoked) {
          throw new Error(`SENDER_KEY_REVOKED: Key for sender '${claimedSender}' has been revoked`);
        }
        const trustedKeyObj = crypto.createPublicKey({
          key: Buffer.from(reg.publicKeyDerB64, 'base64'),
          format: 'der',
          type: 'spki'
        });

        if (senderDsaPublicKey) {
          const trustedDer = trustedKeyObj.export({ format: 'der', type: 'spki' });
          const suppliedDer = (typeof senderDsaPublicKey.export === 'function')
            ? senderDsaPublicKey.export({ format: 'der', type: 'spki' })
            : Buffer.from(senderDsaPublicKey, 'base64');
          if (!trustedDer.equals(suppliedDer)) {
            throw new Error(`SENDER_KEY_MISMATCH: Supplied public key does not match trusted key for sender '${claimedSender}'`);
          }
        }
        effectiveSenderKey = trustedKeyObj;
      }

      if (!effectiveSenderKey) {
        throw new Error('MISSING_SENDER_KEY: No verification key provided or registered for sender');
      }

      // 4. Concurrency-safe replay lock: checks and records replay state atomically
      return this._withReplayLock(() => {
        // Replay check
        this._checkReplay(aad.sender_id, message_id, aad.sequence_number);

        const kemCiphertext = Buffer.from(kem_ciphertext_b64, 'base64');
        const salt = Buffer.from(salt_hex, 'hex');
        const iv = Buffer.from(iv_hex, 'hex');
        const ciphertext = Buffer.from(ciphertext_b64, 'base64');
        const authTag = Buffer.from(auth_tag_hex, 'hex');
        const aadBuffer = Buffer.from(JSON.stringify(aad), 'utf8');
        const signature = Buffer.from(signature_b64, 'base64');

        // 5. Sender signature verification BEFORE any decapsulation or decryption
        const payloadToSign = Buffer.concat([kemCiphertext, iv, ciphertext, authTag, aadBuffer]);
        const sigValid = crypto.verify(null, payloadToSign, effectiveSenderKey, signature);
        if (!sigValid) {
          throw new Error('SIGNATURE_VERIFICATION_FAILED: Sender ML-DSA signature invalid or payload tampered');
        }

        // 6. Decapsulate shared secret using ephemeral KEM private key
        let sharedSecret;
        try {
          sharedSecret = crypto.decapsulate(ephemeralPrekey.ephemeralPrivateKey, kemCiphertext);
        } catch (err) {
          throw new Error(`WRONG_RECIPIENT_KEY_FAILED: Decapsulation failed (${err.message})`);
        }

        // 7. Derive AES key via HKDF
        const info = Buffer.from(`ProtectedMessaging-v1:${aad.sender_id}->${recipientId}:${message_id}:${aad.sequence_number}`, 'utf8');
        const derivedAesKey = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);

        // 8. Decrypt AES-256-GCM with AAD
        try {
          const decipher = crypto.createDecipheriv('aes-256-gcm', derivedAesKey, iv);
          decipher.setAAD(aadBuffer);
          decipher.setAuthTag(authTag);
          let plaintext = decipher.update(ciphertext, null, 'utf8');
          plaintext += decipher.final('utf8');

          // 9. Record in sliding window and persist atomically BEFORE returning
          this._recordReplay(aad.sender_id, message_id, aad.sequence_number);

          return {
            message_id,
            sequence_number: aad.sequence_number,
            sender_id: aad.sender_id,
            recipient_id: recipientId,
            plaintext,
            verified: true
          };
        } catch (err) {
          throw new Error(`WRONG_RECIPIENT_KEY_FAILED: Decryption authentication failed (${err.message})`);
        }
      });
    } finally {
      if (options.autoDestroy && ephemeralPrekey && typeof ephemeralPrekey.destroy === 'function') {
        ephemeralPrekey.destroy();
      }
    }
  }

  /**
   * Decrypts message and guarantees ephemeral key destruction in a finally block
   * across both successful receipts and exceptions.
   */
  receiveAndDestroy(recipientId, ephemeralPrekey, senderDsaPublicKey, messagePacket, options = {}) {
    return this.receiveMessage(recipientId, ephemeralPrekey, senderDsaPublicKey, messagePacket, { ...options, autoDestroy: true });
  }

  /**
   * Split message into sequenced chunks authenticated with ML-DSA signature
   * over length-prefixed canonical chunk header.
   */
  static chunkMessage(messagePacket, senderSigningKey, chunkSize = 128) {
    if (typeof chunkSize !== 'number' || !Number.isSafeInteger(chunkSize) || chunkSize < 16 || chunkSize > 65536) {
      throw new Error(`INVALID_CHUNK_SIZE: Must be an integer between 16 and 65536 (got ${chunkSize})`);
    }

    const serialized = JSON.stringify(messagePacket);
    const totalLength = Buffer.byteLength(serialized, 'utf8');
    if (totalLength > MAX_MESSAGE_SIZE) {
      throw new Error(`EXCESSIVE_MESSAGE_SIZE: Message exceeds 10 MB limit (${totalLength} bytes)`);
    }

    const totalChunks = Math.ceil(serialized.length / chunkSize);
    if (totalChunks > MAX_TOTAL_CHUNKS) {
      throw new Error(`EXCESSIVE_CHUNKS: Total chunks exceed 10000 limit (${totalChunks})`);
    }

    const chunks = [];
    const senderId = messagePacket.aad ? messagePacket.aad.sender_id : 'unknown';
    const recipientId = messagePacket.aad ? messagePacket.aad.recipient_id : 'unknown';
    const messageId = messagePacket.message_id || 'unknown';

    for (let i = 0; i < totalChunks; i++) {
      const slice = serialized.slice(i * chunkSize, (i + 1) * chunkSize);

      // Unambiguous length-prefixed binary signed payload
      const headerObj = {
        chunk_index: i,
        message_id: messageId,
        recipient_id: recipientId,
        sender_id: senderId,
        total_chunks: totalChunks
      };
      const headerBytes = Buffer.from(JSON.stringify(headerObj), 'utf8');
      const headerLenBuf = Buffer.alloc(4);
      headerLenBuf.writeUInt32BE(headerBytes.length);

      const toSign = Buffer.concat([headerLenBuf, headerBytes, Buffer.from(slice, 'utf8')]);
      const authSig = senderSigningKey ? crypto.sign(null, toSign, senderSigningKey).toString('base64') : null;

      chunks.push({
        sender_id: senderId,
        recipient_id: recipientId,
        message_id: messageId,
        chunk_index: i,
        total_chunks: totalChunks,
        chunk_data: slice,
        auth_sig_b64: authSig
      });
    }
    return chunks;
  }

  /**
   * Reassemble chunks:
   * - Validates length-prefixed ML-DSA signature on every chunk
   * - Validates consistency of metadata across all chunks
   * - Validates completeness (rejects missing chunks)
   * - Rejects duplicate or out-of-range chunk indexes
   * - Corrects out-of-order delivery
   */
  static reassembleChunks(chunks, senderVerifyKey) {
    if (!Array.isArray(chunks) || chunks.length === 0) {
      throw new Error('CHUNK_ERROR: No chunks provided');
    }

    const first = chunks[0];
    const messageId = first.message_id;
    const totalChunks = first.total_chunks;
    const senderId = first.sender_id;
    const recipientId = first.recipient_id;

    if (typeof totalChunks !== 'number' || !Number.isSafeInteger(totalChunks) || totalChunks <= 0 || totalChunks > MAX_TOTAL_CHUNKS) {
      throw new Error(`INVALID_TOTAL_CHUNKS: Invalid total_chunks '${totalChunks}'`);
    }

    const seenIndices = new Set();

    // 1. Validate every chunk's bounds, consistency, and signature
    for (const chunk of chunks) {
      if (!chunk || typeof chunk !== 'object') {
        throw new Error('INVALID_CHUNK_FORMAT: Expected object');
      }

      // Metadata consistency
      if (chunk.message_id !== messageId || chunk.total_chunks !== totalChunks || chunk.sender_id !== senderId || chunk.recipient_id !== recipientId) {
        throw new Error('INCONSISTENT_CHUNK_METADATA: Chunks carry mismatched sender, recipient, or message IDs');
      }

      const idx = chunk.chunk_index;
      if (typeof idx !== 'number' || !Number.isSafeInteger(idx) || idx < 0 || idx >= totalChunks) {
        throw new Error(`CHUNK_INDEX_OUT_OF_RANGE: Chunk index ${idx} is out of bounds [0, ${totalChunks - 1}]`);
      }

      if (seenIndices.has(idx)) {
        throw new Error(`DUPLICATE_CHUNK_INDEX: Chunk index ${idx} received more than once`);
      }
      seenIndices.add(idx);

      // Signature verification
      if (senderVerifyKey) {
        if (!chunk.auth_sig_b64 || typeof chunk.auth_sig_b64 !== 'string') {
          throw new Error(`CHUNK_AUTH_MISSING: Chunk index ${idx} is missing signature`);
        }

        const headerObj = {
          chunk_index: idx,
          message_id: messageId,
          recipient_id: recipientId,
          sender_id: senderId,
          total_chunks: totalChunks
        };
        const headerBytes = Buffer.from(JSON.stringify(headerObj), 'utf8');
        const headerLenBuf = Buffer.alloc(4);
        headerLenBuf.writeUInt32BE(headerBytes.length);

        const toVerify = Buffer.concat([headerLenBuf, headerBytes, Buffer.from(chunk.chunk_data || '', 'utf8')]);

        let sigBuffer;
        try {
          sigBuffer = Buffer.from(chunk.auth_sig_b64, 'base64');
        } catch {
          throw new Error(`CHUNK_AUTH_FAILED: Chunk index ${idx} has malformed signature encoding`);
        }

        const valid = crypto.verify(null, toVerify, senderVerifyKey, sigBuffer);
        if (!valid) {
          throw new Error(`CHUNK_AUTH_FAILED: Chunk index ${idx} signature verification failed`);
        }
      }
    }

    // 2. Check completeness
    if (seenIndices.size < totalChunks) {
      throw new Error(`INCOMPLETE_MESSAGE_CHUNKS: Received ${seenIndices.size} of ${totalChunks} required chunks`);
    }

    // 3. Sort and reassemble
    const sorted = [...chunks].sort((a, b) => a.chunk_index - b.chunk_index);
    const combinedStr = sorted.map(c => c.chunk_data).join('');

    try {
      return JSON.parse(combinedStr);
    } catch (e) {
      throw new Error(`CHUNK_CORRUPTION_ERROR: Failed to parse reassembled JSON: ${e.message}`);
    }
  }

  /**
   * Resumption Ticket Management:
   * Loaded / created atomically in stateDir under 0600 mode with strict 32-byte length validation.
   */
  static getOrCreateTicketKey(stateDir) {
    const keyPath = path.join(stateDir, 'ticket_key.bin');
    if (fs.existsSync(keyPath)) {
      const stat = fs.statSync(keyPath);
      if (stat.size !== 32) {
        throw new Error(`TICKET_KEY_CORRUPT: Resumption ticket key at '${keyPath}' has invalid length (${stat.size} != 32)`);
      }
      return fs.readFileSync(keyPath);
    }

    const key = crypto.randomBytes(32);
    const tmp = path.join(stateDir, `ticket_key.tmp.${Date.now()}`);
    fs.writeFileSync(tmp, key, { mode: 0o600 });
    fs.renameSync(tmp, keyPath);
    return key;
  }

  /**
   * Issue resumption ticket binding peer identity AND peer identity key
   */
  static issueResumptionTicket(peerId, peerIdentityKeyB64, ticketKey, ttlMs = 300000) {
    if (!peerId || !peerIdentityKeyB64 || !ticketKey) {
      throw new Error('Missing parameters for ticket issuance');
    }
    if (!Buffer.isBuffer(ticketKey) || ticketKey.length !== 32) {
      throw new Error('INVALID_TICKET_KEY: 32-byte Buffer required');
    }
    if (typeof ttlMs !== 'number' || isNaN(ttlMs) || ttlMs > MAX_TICKET_TTL_MS) {
      throw new Error(`INVALID_TTL: ttlMs must be a number up to ${MAX_TICKET_TTL_MS} ms`);
    }

    const now = Date.now();
    const peerKeyHash = crypto.createHash('sha256').update(peerIdentityKeyB64).digest('hex');
    const ticketData = {
      peer_id: String(peerId),
      peer_key_hash: peerKeyHash,
      issued_at: now,
      expires_at: now + ttlMs,
      ticket_id: crypto.randomBytes(16).toString('hex')
    };

    const ticketBytes = Buffer.from(JSON.stringify(ticketData), 'utf8');
    const hmac = crypto.createHmac('sha256', ticketKey).update(ticketBytes).digest('hex');

    return {
      ticket_b64: ticketBytes.toString('base64'),
      hmac_hex: hmac
    };
  }

  /**
   * Verify resumption ticket with timing-safe HMAC, schema checks, and TTL validation
   */
  static verifyResumptionTicket(ticketPacket, presenterPeerId, presenterIdentityKeyB64, ticketKey) {
    if (!ticketPacket || typeof ticketPacket.ticket_b64 !== 'string' || typeof ticketPacket.hmac_hex !== 'string') {
      return { valid: false, reason: 'TICKET_MALFORMED' };
    }
    if (!Buffer.isBuffer(ticketKey) || ticketKey.length !== 32) {
      return { valid: false, reason: 'INVALID_TICKET_KEY' };
    }

    let ticketBytes;
    try {
      ticketBytes = Buffer.from(ticketPacket.ticket_b64, 'base64');
      if (ticketBytes.toString('base64') !== ticketPacket.ticket_b64.replace(/\s+/g, '')) {
        return { valid: false, reason: 'TICKET_BASE64_INVALID' };
      }
    } catch {
      return { valid: false, reason: 'TICKET_BASE64_INVALID' };
    }

    const expectedHmacHex = crypto.createHmac('sha256', ticketKey).update(ticketBytes).digest('hex');
    const expectedBuf = Buffer.from(expectedHmacHex, 'hex');
    let providedBuf;
    try {
      providedBuf = Buffer.from(ticketPacket.hmac_hex, 'hex');
    } catch {
      return { valid: false, reason: 'TICKET_HMAC_INVALID' };
    }

    if (expectedBuf.length !== providedBuf.length || !crypto.timingSafeEqual(expectedBuf, providedBuf)) {
      return { valid: false, reason: 'TICKET_HMAC_INVALID' };
    }

    let data;
    try {
      data = JSON.parse(ticketBytes.toString('utf8'));
    } catch {
      return { valid: false, reason: 'TICKET_JSON_INVALID' };
    }

    // Schema validation
    if (!data.peer_id || !data.peer_key_hash || typeof data.issued_at !== 'number' || typeof data.expires_at !== 'number' || !data.ticket_id) {
      return { valid: false, reason: 'TICKET_SCHEMA_INVALID' };
    }

    // Future-issued ticket rejection (allow at most 5s clock skew)
    const now = Date.now();
    if (data.issued_at > now + 5000) {
      return { valid: false, reason: 'TICKET_FUTURE_ISSUED' };
    }

    // Expiry check
    if (now > data.expires_at) {
      return { valid: false, reason: 'TICKET_EXPIRED' };
    }

    // TTL bounds check
    if (data.expires_at <= data.issued_at || (data.expires_at - data.issued_at) > MAX_TICKET_TTL_MS) {
      return { valid: false, reason: 'TICKET_TTL_INVALID' };
    }

    // Peer ID check
    if (data.peer_id !== presenterPeerId) {
      return { valid: false, reason: 'TICKET_PEER_MISMATCH' };
    }

    // Peer identity key check
    const presenterKeyHash = crypto.createHash('sha256').update(presenterIdentityKeyB64).digest('hex');
    if (data.peer_key_hash !== presenterKeyHash) {
      return { valid: false, reason: 'TICKET_IDENTITY_KEY_MISMATCH' };
    }

    return { valid: true, ticket_data: data };
  }
}

module.exports = {
  ProtectedMessagingEngine
};

