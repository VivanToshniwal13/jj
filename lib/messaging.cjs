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
 * - Recipient & AAD Binding: full recipient ID & metadata in AAD; sender signs over ciphertext + AAD.
 *   Signature verified BEFORE decryption. Wrong recipient or altered AAD fails.
 * - Chunking, Reordering & Drop/Tamper Detection: sequenced chunks with SHA-256 chunk hashes.
 * - Session Resumption: random per-run HMAC ticket key loaded from stateDir; ticket cryptographically
 *   binds peer identity and peer identity public key.
 */

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

// Standard NIST ML-KEM-768 SPKI prefix for raw 1184-byte keys
const ML_KEM_768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');

class ProtectedMessagingEngine {
  constructor() {
    // Replay cache keying on `${sender}:${messageId}:${sequence}`
    this.replayCache = new Set();
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
   */
  static generateEphemeralPrekey(recipientDsaPrivateKey) {
    const kemKp = crypto.generateKeyPairSync('ml-kem-768');
    const spkiDer = kemKp.publicKey.export({ format: 'der', type: 'spki' });
    const rawKemPk = spkiDer.subarray(22); // 1184 bytes

    // Sign ephemeral KEM public key with long-term ML-DSA-65 identity key
    const signature = crypto.sign(null, rawKemPk, recipientDsaPrivateKey);

    return {
      ephemeralPublicKeyB64: rawKemPk.toString('base64'),
      signatureB64: signature.toString('base64'),
      ephemeralPrivateKey: kemKp.privateKey,
      destroyed: false,
      destroy() {
        // Ephemeral key deletion (best effort in JS garbage-collected runtime)
        this.ephemeralPrivateKey = null;
        this.destroyed = true;
      }
    };
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

    const messageId = options.messageId || `msg-${crypto.randomUUID()}`;
    const seq = options.sequenceNumber !== undefined ? options.sequenceNumber : 1;
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
   * 2. Checks replay cache on (sender, message_id, sequence).
   * 3. Verifies sender's ML-DSA-65 signature BEFORE decapsulation and decryption.
   * 4. Decapsulates shared secret using ephemeral KEM private key.
   * 5. Decrypts AES-256-GCM and verifies AAD.
   */
  receiveMessage(recipientId, ephemeralPrekey, senderDsaPublicKey, messagePacket) {
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

    // 2. Replay check keyed on (sender, message_id, sequence)
    const replayKey = `${aad.sender_id}:${message_id}:${aad.sequence_number}`;
    if (this.replayCache.has(replayKey)) {
      throw new Error(`MESSAGE_REPLAY_DETECTED: Duplicate message (sender=${aad.sender_id}, id=${message_id}, seq=${aad.sequence_number}) rejected`);
    }

    const kemCiphertext = Buffer.from(kem_ciphertext_b64, 'base64');
    const salt = Buffer.from(salt_hex, 'hex');
    const iv = Buffer.from(iv_hex, 'hex');
    const ciphertext = Buffer.from(ciphertext_b64, 'base64');
    const authTag = Buffer.from(auth_tag_hex, 'hex');
    const aadBuffer = Buffer.from(JSON.stringify(aad), 'utf8');
    const signature = Buffer.from(signature_b64, 'base64');

    // 3. Sender signature verification BEFORE any decapsulation or decryption
    const payloadToSign = Buffer.concat([kemCiphertext, iv, ciphertext, authTag, aadBuffer]);
    const sigValid = crypto.verify(null, payloadToSign, senderDsaPublicKey, signature);
    if (!sigValid) {
      throw new Error('SIGNATURE_VERIFICATION_FAILED: Sender ML-DSA signature invalid or payload tampered');
    }

    // 4. Check if ephemeral key was deleted (forward secrecy check)
    if (!ephemeralPrekey || !ephemeralPrekey.ephemeralPrivateKey || ephemeralPrekey.destroyed) {
      throw new Error('EPHEMERAL_KEY_DESTROYED: Session ephemeral key was wiped; cannot decrypt historical message');
    }

    // 5. Decapsulate shared secret using ephemeral KEM private key
    let sharedSecret;
    try {
      sharedSecret = crypto.decapsulate(ephemeralPrekey.ephemeralPrivateKey, kemCiphertext);
    } catch (err) {
      throw new Error(`WRONG_RECIPIENT_KEY_FAILED: Decapsulation failed (${err.message})`);
    }

    // 6. Derive AES key via HKDF
    const info = Buffer.from(`ProtectedMessaging-v1:${aad.sender_id}->${recipientId}:${message_id}:${aad.sequence_number}`, 'utf8');
    const derivedAesKey = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);

    // 7. Decrypt AES-256-GCM with AAD
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedAesKey, iv);
      decipher.setAAD(aadBuffer);
      decipher.setAuthTag(authTag);
      let plaintext = decipher.update(ciphertext, null, 'utf8');
      plaintext += decipher.final('utf8');

      // Record in replay cache upon successful receipt
      this.replayCache.add(replayKey);

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
  }

  /**
   * Split message into sequenced chunks with per-chunk SHA-256 checksums
   */
  static chunkMessage(messagePacket, chunkSize = 128) {
    const serialized = JSON.stringify(messagePacket);
    const totalLength = serialized.length;
    const totalChunks = Math.ceil(totalLength / chunkSize);
    const chunks = [];

    for (let i = 0; i < totalChunks; i++) {
      const slice = serialized.slice(i * chunkSize, (i + 1) * chunkSize);
      const chunkHash = crypto.createHash('sha256').update(slice).digest('hex');
      chunks.push({
        message_id: messagePacket.message_id,
        chunk_index: i,
        total_chunks: totalChunks,
        chunk_hash: chunkHash,
        chunk_data: slice
      });
    }
    return chunks;
  }

  /**
   * Reassemble chunks:
   * - Validates per-chunk SHA-256 integrity (rejects tampered chunks)
   * - Validates completeness (reports and rejects missing chunks)
   * - Corrects out-of-order delivery
   */
  static reassembleChunks(chunks) {
    if (!Array.isArray(chunks) || chunks.length === 0) {
      throw new Error('CHUNK_ERROR: No chunks provided');
    }

    const messageId = chunks[0].message_id;
    const totalChunks = chunks[0].total_chunks;

    // 1. Check completeness
    if (chunks.length < totalChunks) {
      throw new Error(`INCOMPLETE_MESSAGE_CHUNKS: Received ${chunks.length} of ${totalChunks} required chunks`);
    }

    // 2. Verify per-chunk SHA-256 checksum
    for (const chunk of chunks) {
      const calculatedHash = crypto.createHash('sha256').update(chunk.chunk_data).digest('hex');
      if (chunk.chunk_hash && chunk.chunk_hash !== calculatedHash) {
        throw new Error(`CHUNK_CHECKSUM_FAILED: Chunk index ${chunk.chunk_index} has corrupted hash`);
      }
    }

    // 3. Sort by sequence chunk_index
    const sorted = [...chunks].sort((a, b) => a.chunk_index - b.chunk_index);

    // 4. Check for missing indices
    for (let i = 0; i < totalChunks; i++) {
      if (sorted[i].chunk_index !== i) {
        throw new Error(`INCOMPLETE_MESSAGE_CHUNKS: Missing chunk index ${i}`);
      }
    }

    const combinedStr = sorted.map(c => c.chunk_data).join('');
    try {
      return JSON.parse(combinedStr);
    } catch (e) {
      throw new Error(`CHUNK_CORRUPTION_ERROR: Failed to parse reassembled JSON: ${e.message}`);
    }
  }

  /**
   * Resumption Ticket Management:
   * Loaded / created in stateDir under 0600 mode (never hardcoded)
   */
  static getOrCreateTicketKey(stateDir) {
    const keyPath = path.join(stateDir, 'ticket_key.bin');
    if (fs.existsSync(keyPath)) {
      return fs.readFileSync(keyPath);
    }
    const key = crypto.randomBytes(32);
    fs.writeFileSync(keyPath, key, { mode: 0o600 });
    return key;
  }

  /**
   * Issue resumption ticket binding peer identity AND peer identity key
   */
  static issueResumptionTicket(peerId, peerIdentityKeyB64, ticketKey, ttlMs = 300000) {
    if (!peerId || !peerIdentityKeyB64 || !ticketKey) {
      throw new Error('Missing parameters for ticket issuance');
    }
    const peerKeyHash = crypto.createHash('sha256').update(peerIdentityKeyB64).digest('hex');
    const ticketData = {
      peer_id: peerId,
      peer_key_hash: peerKeyHash,
      issued_at: Date.now(),
      expires_at: Date.now() + ttlMs,
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
   * Verify resumption ticket
   */
  static verifyResumptionTicket(ticketPacket, presenterPeerId, presenterIdentityKeyB64, ticketKey) {
    if (!ticketPacket || !ticketPacket.ticket_b64 || !ticketPacket.hmac_hex) {
      return { valid: false, reason: 'TICKET_MALFORMED' };
    }
    const ticketBytes = Buffer.from(ticketPacket.ticket_b64, 'base64');
    const expectedHmac = crypto.createHmac('sha256', ticketKey).update(ticketBytes).digest('hex');
    if (expectedHmac !== ticketPacket.hmac_hex) {
      return { valid: false, reason: 'TICKET_HMAC_INVALID' };
    }
    let data;
    try {
      data = JSON.parse(ticketBytes.toString('utf8'));
    } catch {
      return { valid: false, reason: 'TICKET_JSON_INVALID' };
    }

    // Bind peer ID
    if (data.peer_id !== presenterPeerId) {
      return { valid: false, reason: 'TICKET_PEER_MISMATCH' };
    }

    // Bind peer identity key
    const presenterKeyHash = crypto.createHash('sha256').update(presenterIdentityKeyB64).digest('hex');
    if (data.peer_key_hash !== presenterKeyHash) {
      return { valid: false, reason: 'TICKET_IDENTITY_KEY_MISMATCH' };
    }

    // Expiry check
    if (Date.now() > data.expires_at) {
      return { valid: false, reason: 'TICKET_EXPIRED' };
    }

    return { valid: true, ticket_data: data };
  }
}

module.exports = {
  ProtectedMessagingEngine
};
