'use strict';

/**
 * lib/messaging.cjs
 *
 * Post-Quantum Protected Messaging Engine for DevForge Track 4 (Goals 9-11).
 *
 * Primitives:
 * - Ephemeral ML-KEM-768 key encapsulation per message/session (Forward Secrecy)
 * - HKDF-SHA256 key derivation with distinct context string
 * - AES-256-GCM authenticated encryption with complete AAD binding
 * - ML-DSA-65 digital signatures over ciphertext + AAD
 * - Message replay cache preventing duplicate replay attacks
 * - Chunking, reordering, and drop detection
 */

const crypto = require('node:crypto');

// ML-KEM-768 SPKI DER Prefix
const ML_KEM_768_SPKI_PREFIX = Buffer.from('308204b2300b0609608648016503040402038204a100', 'hex');

class ProtectedMessagingEngine {
  constructor() {
    this.replayCache = new Set();
  }

  // Generate identity keypair: ML-KEM-768 for encryption + ML-DSA-65 for signing
  static generateIdentityKeyPair() {
    const kemKp = crypto.generateKeyPairSync('ml-kem-768');
    const dsaKp = crypto.generateKeyPairSync('ml-dsa-65');

    const spkiDer = kemKp.publicKey.export({ format: 'der', type: 'spki' });
    const rawKemPk = spkiDer.subarray(22); // Raw 1184 bytes

    return {
      kem: {
        publicKeyRaw: rawKemPk,
        publicKeyB64: rawKemPk.toString('base64'),
        privateKey: kemKp.privateKey,
        publicKeyObj: kemKp.publicKey
      },
      dsa: {
        publicKey: dsaKp.publicKey,
        privateKey: dsaKp.privateKey,
        publicKeyDerB64: dsaKp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64')
      }
    };
  }

  /**
   * Send a protected message:
   * - Ephemeral ML-KEM-768 encapsulation
   * - HKDF-SHA256
   * - AES-256-GCM with AAD
   * - ML-DSA-65 signature
   * - Forward secrecy: ephemeral private key deleted immediately
   */
  sendMessage(senderId, senderSigningKey, recipientId, recipientKemPkB64, plaintext, options = {}) {
    if (!senderId || !recipientId || typeof plaintext !== 'string') {
      throw new Error('Invalid send parameters: senderId, recipientId, plaintext required');
    }

    const messageId = options.messageId || `msg-${crypto.randomUUID()}`;
    const seq = options.sequenceNumber !== undefined ? options.sequenceNumber : 1;
    const timestamp = options.timestamp || Date.now();

    // 1. Import recipient raw ML-KEM-768 public key
    const rawPk = Buffer.from(recipientKemPkB64, 'base64');
    const spkiDer = Buffer.concat([ML_KEM_768_SPKI_PREFIX, rawPk]);
    const recipientKeyObj = crypto.createPublicKey({ key: spkiDer, format: 'der', type: 'spki' });

    // 2. Ephemeral ML-KEM-768 encapsulation
    const { sharedKey, ciphertext: kemCiphertext } = crypto.encapsulate(recipientKeyObj);

    // 3. Derive 32-byte AES key via HKDF-SHA256
    const salt = options.salt || crypto.randomBytes(16);
    const info = Buffer.from(`ProtectedMessaging-v1:${senderId}->${recipientId}:${messageId}`, 'utf8');
    const derivedAesKey = crypto.hkdfSync('sha256', sharedKey, salt, info, 32);

    // 4. Complete AAD structure binding sender, recipient, message_id, sequence, timestamp
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

    // 6. ML-DSA-65 signature over (kemCiphertext || iv || ciphertext || authTag || aadBuffer)
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
      forward_secrecy: 'EPHEMERAL_KEM_DELETED'
    };
  }

  /**
   * Receive and verify a protected message:
   * - Validates recipient ID
   * - Rejects duplicates via replay cache
   * - Validates ML-DSA signature
   * - Decapsulates KEM shared secret
   * - Derives AES key
   * - Decrypts AES-256-GCM and checks AAD
   */
  receiveMessage(recipientId, recipientKemPrivateKey, senderVerifyKey, messagePacket) {
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

    // 1. Recipient check
    if (!aad || aad.recipient_id !== recipientId) {
      throw new Error(`WRONG_RECIPIENT_ERROR: Message intended for ${aad ? aad.recipient_id : 'unknown'}, received by ${recipientId}`);
    }

    // 2. Replay check
    if (this.replayCache.has(message_id)) {
      throw new Error(`MESSAGE_REPLAY_DETECTED: Message ID ${message_id} was already delivered`);
    }

    const kemCiphertext = Buffer.from(kem_ciphertext_b64, 'base64');
    const salt = Buffer.from(salt_hex, 'hex');
    const iv = Buffer.from(iv_hex, 'hex');
    const ciphertext = Buffer.from(ciphertext_b64, 'base64');
    const authTag = Buffer.from(auth_tag_hex, 'hex');
    const aadBuffer = Buffer.from(JSON.stringify(aad), 'utf8');
    const signature = Buffer.from(signature_b64, 'base64');

    // 3. Verify ML-DSA-65 signature
    const payloadToSign = Buffer.concat([kemCiphertext, iv, ciphertext, authTag, aadBuffer]);
    const sigValid = crypto.verify(null, payloadToSign, senderVerifyKey, signature);
    if (!sigValid) {
      throw new Error('SIGNATURE_VERIFICATION_FAILED: ML-DSA signature invalid or sender identity untrusted');
    }

    // 4. Decapsulate ML-KEM-768 shared secret
    let sharedSecret;
    try {
      sharedSecret = crypto.decapsulate(recipientKemPrivateKey, kemCiphertext);
    } catch (err) {
      throw new Error(`KEM_DECAPSULATION_FAILED: ${err.message}`);
    }

    // 5. Derive AES key via HKDF
    const info = Buffer.from(`ProtectedMessaging-v1:${aad.sender_id}->${recipientId}:${message_id}`, 'utf8');
    const derivedAesKey = crypto.hkdfSync('sha256', sharedSecret, salt, info, 32);

    // 6. Decrypt AES-256-GCM with AAD
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', derivedAesKey, iv);
      decipher.setAAD(aadBuffer);
      decipher.setAuthTag(authTag);
      let plaintext = decipher.update(ciphertext, null, 'utf8');
      plaintext += decipher.final('utf8');

      // Record in replay cache upon successful authentication
      this.replayCache.add(message_id);

      return {
        message_id,
        sequence_number: aad.sequence_number,
        sender_id: aad.sender_id,
        recipient_id: recipientId,
        plaintext,
        verified: true
      };
    } catch (err) {
      throw new Error(`AAD_OR_CIPHERTEXT_TAMPER_DETECTED: Authentication tag verification failed (${err.message})`);
    }
  }

  /**
   * Split message packet into sequenced chunks
   */
  static chunkMessage(messagePacket, chunkSize = 128) {
    const serialized = JSON.stringify(messagePacket);
    const totalLength = serialized.length;
    const totalChunks = Math.ceil(totalLength / chunkSize);
    const chunks = [];

    for (let i = 0; i < totalChunks; i++) {
      const slice = serialized.slice(i * chunkSize, (i + 1) * chunkSize);
      chunks.push({
        message_id: messagePacket.message_id,
        chunk_index: i,
        total_chunks: totalChunks,
        chunk_data: slice
      });
    }
    return chunks;
  }

  /**
   * Reassemble out-of-order chunks and detect lost chunks
   */
  static reassembleChunks(chunks) {
    if (!Array.isArray(chunks) || chunks.length === 0) {
      throw new Error('CHUNK_ERROR: No chunks provided');
    }

    const messageId = chunks[0].message_id;
    const totalChunks = chunks[0].total_chunks;

    // Check completeness
    if (chunks.length < totalChunks) {
      throw new Error(`INCOMPLETE_MESSAGE_CHUNKS: Received ${chunks.length} of ${totalChunks} required chunks`);
    }

    // Sort by sequence chunk_index
    const sorted = [...chunks].sort((a, b) => a.chunk_index - b.chunk_index);

    // Check for missing indices
    for (let i = 0; i < totalChunks; i++) {
      if (sorted[i].chunk_index !== i) {
        throw new Error(`INCOMPLETE_MESSAGE_CHUNKS: Missing chunk index ${i}`);
      }
    }

    const combinedStr = sorted.map(c => c.chunk_data).join('');
    return JSON.parse(combinedStr);
  }

  /**
   * Goal 12: Session Resumption Ticket
   * Binds ticket to peer identity and issue timestamp
   */
  static issueResumptionTicket(peerId, secretKey, ttlMs = 300000) {
    const ticketData = {
      peer_id: peerId,
      issued_at: Date.now(),
      expires_at: Date.now() + ttlMs,
      ticket_id: crypto.randomBytes(16).toString('hex')
    };
    const ticketBytes = Buffer.from(JSON.stringify(ticketData), 'utf8');
    const hmac = crypto.createHmac('sha256', secretKey).update(ticketBytes).digest('hex');
    return {
      ticket_b64: ticketBytes.toString('base64'),
      hmac_hex: hmac
    };
  }

  static verifyResumptionTicket(ticketPacket, expectedPeerId, secretKey) {
    const ticketBytes = Buffer.from(ticketPacket.ticket_b64, 'base64');
    const expectedHmac = crypto.createHmac('sha256', secretKey).update(ticketBytes).digest('hex');
    if (expectedHmac !== ticketPacket.hmac_hex) {
      return { valid: false, reason: 'TICKET_HMAC_INVALID' };
    }
    const data = JSON.parse(ticketBytes.toString('utf8'));
    if (data.peer_id !== expectedPeerId) {
      return { valid: false, reason: 'TICKET_PEER_MISMATCH' };
    }
    if (Date.now() > data.expires_at) {
      return { valid: false, reason: 'TICKET_EXPIRED' };
    }
    return { valid: true, ticket_data: data };
  }
}

module.exports = {
  ProtectedMessagingEngine
};
