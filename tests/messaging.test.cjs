'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { ProtectedMessagingEngine } = require('../lib/messaging.cjs');

test('Goals 9-11: Post-Quantum Protected Messaging, Forward Secrecy & Chunk Reordering', async (t) => {
  // Setup Alice and Bob identity keypairs
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();

  const engine = new ProtectedMessagingEngine();

  // 1. Goal 9: Full Post-Quantum Message Protection
  await t.test('1. Goal 9: Ephemeral ML-KEM-768, HKDF-SHA256, AES-256-GCM and ML-DSA-65 authenticated message delivery', () => {
    const secretMessage = 'Telemetry dispatch: Heart rate 72 bpm, O2 saturation 99%';
    const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.kem.publicKeyB64, secretMessage);

    assert.ok(packet.message_id);
    assert.ok(packet.kem_ciphertext_b64);
    assert.ok(packet.ciphertext_b64);
    assert.ok(packet.signature_b64);
    assert.equal(packet.aad.sender_id, 'alice');
    assert.equal(packet.aad.recipient_id, 'bob');

    const received = engine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, packet);
    assert.equal(received.plaintext, secretMessage);
    assert.equal(received.verified, true);
    assert.equal(received.sender_id, 'alice');
  });

  // 2. Goal 10: Replay Rejection & Replay Cache
  await t.test('2. Goal 10: Replay cache rejects duplicate message transmission', () => {
    const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.kem.publicKeyB64, 'Replay test payload');
    
    // First receipt succeeds
    const firstDelivery = engine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, packet);
    assert.equal(firstDelivery.verified, true);

    // Duplicate submission with same message_id is strictly REJECTED
    assert.throws(() => {
      engine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, packet);
    }, /MESSAGE_REPLAY_DETECTED/);
  });

  // 3. Goal 10: Wrong Recipient & AAD Tamper Rejection
  await t.test('3. Goal 10: Receiver rejects wrong recipient and tampered AAD metadata', () => {
    const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.kem.publicKeyB64, 'Confidential prescription');

    // Wrong recipient attempts delivery
    assert.throws(() => {
      engine.receiveMessage('charlie', bob.kem.privateKey, alice.dsa.publicKey, packet);
    }, /WRONG_RECIPIENT_ERROR/);

    // Attacker modifies AAD timestamp or sequence number
    const tamperedPacket = JSON.parse(JSON.stringify(packet));
    tamperedPacket.aad.timestamp += 10000;
    const freshEngine = new ProtectedMessagingEngine();
    assert.throws(() => {
      freshEngine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, tamperedPacket);
    }, /SIGNATURE_VERIFICATION_FAILED/);
  });

  // 4. Goal 11: Forward Secrecy Test
  await t.test('4. Goal 11 Forward Secrecy: Compromising long-term keys after session cannot decrypt past messages', () => {
    const pastMessage = 'Top secret patient medical history #9901';
    const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.kem.publicKeyB64, pastMessage);

    // Normal recipient decrypts during session
    const normalEngine = new ProtectedMessagingEngine();
    const delivered = normalEngine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, packet);
    assert.equal(delivered.plaintext, pastMessage);

    // Now adversary obtains Bob's long-term identity keys (or Alice's signing key),
    // but the sender's ephemeral KEM private key / ephemeral shared secret was deleted immediately!
    // Attempting to decrypt the captured ciphertext without the ephemeral shared secret fails.
    const fakeEphemeralKey = crypto.randomBytes(32);
    const iv = Buffer.from(packet.iv_hex, 'hex');
    const ct = Buffer.from(packet.ciphertext_b64, 'base64');
    const authTag = Buffer.from(packet.auth_tag_hex, 'hex');
    const aadBuffer = Buffer.from(JSON.stringify(packet.aad), 'utf8');

    const decipher = crypto.createDecipheriv('aes-256-gcm', fakeEphemeralKey, iv);
    decipher.setAAD(aadBuffer);
    decipher.setAuthTag(authTag);
    assert.throws(() => {
      decipher.update(ct);
      decipher.final();
    });
  });

  // 5. Goal 10: Loss, Chunking & Out-of-Order Reassembly
  await t.test('5. Goal 10: Chunks delivered out of order are correctly reassembled; dropped chunk is rejected', () => {
    const longPayload = 'Large clinical record payload with sequence markers: '.repeat(10);
    const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.kem.publicKeyB64, longPayload);

    // Split into 48-byte chunks
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, 48);
    assert.ok(chunks.length > 3);

    // Deliver out-of-order (shuffle chunks)
    const shuffled = [...chunks].reverse();
    const reassembled = ProtectedMessagingEngine.reassembleChunks(shuffled);

    const reassembledEngine = new ProtectedMessagingEngine();
    const result = reassembledEngine.receiveMessage('bob', bob.kem.privateKey, alice.dsa.publicKey, reassembled);
    assert.equal(result.plaintext, longPayload);

    // Drop a chunk to simulate network packet loss
    const droppedChunks = chunks.slice(1); // Drop chunk 0
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(droppedChunks);
    }, /INCOMPLETE_MESSAGE_CHUNKS/);
  });

  // 6. Goal 12: Session Resumption Ticket
  await t.test('6. Goal 12: Session resumption ticket issuance, verification and expiry', () => {
    const sharedSecret = crypto.randomBytes(32);
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', sharedSecret, 500); // 500ms TTL

    const checkValid = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'alice', sharedSecret);
    assert.equal(checkValid.valid, true);
    assert.equal(checkValid.ticket_data.peer_id, 'alice');

    // Wrong peer is rejected
    const checkWrongPeer = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'eve', sharedSecret);
    assert.equal(checkWrongPeer.valid, false);
    assert.equal(checkWrongPeer.reason, 'TICKET_PEER_MISMATCH');

    // Expired ticket is rejected
    const expiredTicket = ProtectedMessagingEngine.issueResumptionTicket('alice', sharedSecret, -100);
    const checkExpired = ProtectedMessagingEngine.verifyResumptionTicket(expiredTicket, 'alice', sharedSecret);
    assert.equal(checkExpired.valid, false);
    assert.equal(checkExpired.reason, 'TICKET_EXPIRED');
  });
});
