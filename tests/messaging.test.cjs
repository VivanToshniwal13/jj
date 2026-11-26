'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ProtectedMessagingEngine } = require('../lib/messaging.cjs');

test('Goals 9-12: Post-Quantum Protected Messaging, Forward Secrecy & Session Resumption', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-msg-test-'));
  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  // Setup Alice and Bob long-term ML-DSA-65 identity keypairs
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();
  const charlie = ProtectedMessagingEngine.generateIdentityKeyPair();

  const engine = new ProtectedMessagingEngine();

  // 1. Goal 9: Full Post-Quantum Message Protection with Ephemeral KEM Prekey
  await t.test('1. Goal 9: Ephemeral ML-KEM-768, HKDF-SHA256, AES-256-GCM and ML-DSA-65 authenticated message delivery', () => {
    // Bob generates fresh per-session ephemeral KEM prekey, signed by Bob's ML-DSA identity key
    const bobSessionPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

    const secretMessage = 'Telemetry dispatch: Heart rate 72 bpm, O2 saturation 99%';
    const packet = engine.sendMessage(
      'alice',
      alice.dsa.privateKey,
      'bob',
      bob.dsa.publicKey,
      bobSessionPrekey,
      secretMessage
    );

    assert.ok(packet.message_id);
    assert.ok(packet.kem_ciphertext_b64);
    assert.ok(packet.ciphertext_b64);
    assert.ok(packet.signature_b64);
    assert.equal(packet.aad.sender_id, 'alice');
    assert.equal(packet.aad.recipient_id, 'bob');

    const received = engine.receiveMessage('bob', bobSessionPrekey, alice.dsa.publicKey, packet);
    assert.equal(received.plaintext, secretMessage);
    assert.equal(received.verified, true);
    assert.equal(received.sender_id, 'alice');
  });

  // 2. Goal 9: Replay Rejection on (sender, message_id, sequence)
  await t.test('2. Goal 9: Replay cache rejects duplicate (sender, message_id, sequence) transmission', () => {
    const bobSessionPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const packet = engine.sendMessage(
      'alice',
      alice.dsa.privateKey,
      'bob',
      bob.dsa.publicKey,
      bobSessionPrekey,
      'Replay test payload',
      { messageId: 'msg-replay-001', sequenceNumber: 1 }
    );

    // First receipt succeeds
    const firstDelivery = engine.receiveMessage('bob', bobSessionPrekey, alice.dsa.publicKey, packet);
    assert.equal(firstDelivery.verified, true);

    // Duplicate submission with same (sender, message_id, sequence) is strictly REJECTED
    assert.throws(() => {
      engine.receiveMessage('bob', bobSessionPrekey, alice.dsa.publicKey, packet);
    }, /MESSAGE_REPLAY_DETECTED/);
  });

  // 3. Goal 9: Recipient and AAD Tamper Rejection
  await t.test('3. Goal 9: Receiver rejects wrong recipient, wrong recipient key, and tampered AAD metadata', () => {
    const bobSessionPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const packet = engine.sendMessage(
      'alice',
      alice.dsa.privateKey,
      'bob',
      bob.dsa.publicKey,
      bobSessionPrekey,
      'Confidential prescription'
    );

    // Case A: Wrong recipient ID in receiver call -> WRONG_RECIPIENT_ERROR
    assert.throws(() => {
      engine.receiveMessage('charlie', bobSessionPrekey, alice.dsa.publicKey, packet);
    }, /WRONG_RECIPIENT_ERROR/);

    // Case B: Attacker attempts to decapsulate using a different recipient's KEM prekey -> WRONG_RECIPIENT_KEY_FAILED
    const charliePrekey = ProtectedMessagingEngine.generateEphemeralPrekey(charlie.dsa.privateKey);
    assert.throws(() => {
      engine.receiveMessage('bob', charliePrekey, alice.dsa.publicKey, packet);
    }, /WRONG_RECIPIENT_KEY_FAILED/);

    // Case C: Attacker modifies AAD timestamp or sequence -> SIGNATURE_VERIFICATION_FAILED
    const tamperedPacket = JSON.parse(JSON.stringify(packet));
    tamperedPacket.aad.timestamp += 10000;
    const freshEngine = new ProtectedMessagingEngine();
    assert.throws(() => {
      freshEngine.receiveMessage('bob', bobSessionPrekey, alice.dsa.publicKey, tamperedPacket);
    }, /SIGNATURE_VERIFICATION_FAILED/);
  });

  // 4. Goal 10: Forward Secrecy Proof (Cryptographic Wire Bytes & Leaked Long-Term Keys)
  await t.test('4. Goal 10 Forward Secrecy: Compromising long-term identity keys post-session cannot decrypt past recorded ciphertexts', () => {
    // Bob also holds a long-term ML-KEM identity keypair in addition to ML-DSA identity key
    const bobLongTermKem = crypto.generateKeyPairSync('ml-kem-768');

    // 1. Recipient generates ephemeral ML-KEM prekey for this session
    const bobEphemeralPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

    const pastMessage = 'Top secret patient medical history #9901';
    const packet = engine.sendMessage(
      'alice',
      alice.dsa.privateKey,
      'bob',
      bob.dsa.publicKey,
      bobEphemeralPrekey,
      pastMessage
    );

    // 2. Normal recipient decrypts during the active session
    const normalEngine = new ProtectedMessagingEngine();
    const delivered = normalEngine.receiveMessage('bob', bobEphemeralPrekey, alice.dsa.publicKey, packet);
    assert.equal(delivered.plaintext, pastMessage);

    // 3. Session completes: recipient deletes/destroys ephemeral KEM private key
    // (Note: in JavaScript V8 runtime, memory zeroization is best-effort upon reference wipe)
    bobEphemeralPrekey.destroy();
    assert.equal(bobEphemeralPrekey.destroyed, true);
    assert.equal(bobEphemeralPrekey.ephemeralPrivateKey, null);

    // 4. Code-path guard check
    const attackerEngine = new ProtectedMessagingEngine();
    assert.throws(() => {
      attackerEngine.receiveMessage('bob', bobEphemeralPrekey, alice.dsa.publicKey, packet);
    }, /EPHEMERAL_KEY_DESTROYED/);

    // 5. Cryptographic Proof: Attacker holds ONLY the recorded wire bytes and ALL leaked long-term identity secret keys
    const wireKemCiphertext = Buffer.from(packet.kem_ciphertext_b64, 'base64');
    const wireSalt = Buffer.from(packet.salt_hex, 'hex');
    const wireIv = Buffer.from(packet.iv_hex, 'hex');
    const wireCiphertext = Buffer.from(packet.ciphertext_b64, 'base64');
    const wireAuthTag = Buffer.from(packet.auth_tag_hex, 'hex');
    const wireAadBuffer = Buffer.from(JSON.stringify(packet.aad), 'utf8');

    const leakedKeys = [
      { name: 'bob_long_term_dsa_key', key: bob.dsa.privateKey, isKem: false },
      { name: 'bob_long_term_kem_key', key: bobLongTermKem.privateKey, isKem: true },
      { name: 'alice_long_term_dsa_key', key: alice.dsa.privateKey, isKem: false }
    ];

    let recoveredPlaintext = null;

    for (const leaked of leakedKeys) {
      if (!leaked.isKem) {
        // ML-DSA keys cannot decapsulate ML-KEM ciphertexts
        assert.throws(() => {
          crypto.decapsulate(leaked.key, wireKemCiphertext);
        });
      } else {
        // Bob's long-term ML-KEM key is NOT the ephemeral prekey that was encapsulated against
        let attackerSharedKey;
        try {
          attackerSharedKey = crypto.decapsulate(leaked.key, wireKemCiphertext);
        } catch {
          // Some implementations throw on invalid ciphertext
          attackerSharedKey = null;
        }

        if (attackerSharedKey) {
          const info = Buffer.from(`ProtectedMessaging-v1:${packet.aad.sender_id}->${packet.aad.recipient_id}:${packet.message_id}:${packet.aad.sequence_number}`, 'utf8');
          const attackerAesKey = crypto.hkdfSync('sha256', attackerSharedKey, wireSalt, info, 32);

          // AES-256-GCM authentication tag verification MUST fail
          assert.throws(() => {
            const decipher = crypto.createDecipheriv('aes-256-gcm', attackerAesKey, wireIv);
            decipher.setAAD(wireAadBuffer);
            decipher.setAuthTag(wireAuthTag);
            let pt = decipher.update(wireCiphertext, null, 'utf8');
            pt += decipher.final('utf8');
            recoveredPlaintext = pt;
          }, /Unsupported state or unable to authenticate data/);
        }
      }
    }

    // Cryptographic assertion: Zero plaintext recovered by adversary with all long-term keys
    assert.equal(recoveredPlaintext, null);
  });

  // 5. Goal 11: Loss, Chunking, Reordering & Tamper Rejection (Authenticated Chunks)
  await t.test('5. Goal 11 Delivery: Chunks out of order are reassembled, dropped chunk is reported, tampered chunk is rejected', () => {
    const bobSessionPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const longPayload = 'Large clinical record payload with sequence markers: '.repeat(10);
    const packet = engine.sendMessage(
      'alice',
      alice.dsa.privateKey,
      'bob',
      bob.dsa.publicKey,
      bobSessionPrekey,
      longPayload
    );

    // Split into 48-byte chunks authenticated with Alice's ML-DSA identity key
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 48);
    assert.ok(chunks.length > 3);
    assert.ok(chunks[0].auth_sig_b64);

    // Case A: Deliver out-of-order (reversed) -> successfully reassembles
    const shuffled = [...chunks].reverse();
    const reassembled = ProtectedMessagingEngine.reassembleChunks(shuffled, alice.dsa.publicKey);

    const reassembledEngine = new ProtectedMessagingEngine();
    const result = reassembledEngine.receiveMessage('bob', bobSessionPrekey, alice.dsa.publicKey, reassembled);
    assert.equal(result.plaintext, longPayload);

    // Case B: Drop chunk 1 to simulate network loss -> INCOMPLETE_MESSAGE_CHUNKS reported
    const droppedChunks = [chunks[0], chunks[2], chunks[3]];
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(droppedChunks, alice.dsa.publicKey);
    }, /INCOMPLETE_MESSAGE_CHUNKS/);

    // Case C: Tamper with chunk data -> CHUNK_AUTH_FAILED rejected
    const tamperedChunks = JSON.parse(JSON.stringify(chunks));
    tamperedChunks[0].chunk_data = tamperedChunks[0].chunk_data.replace('{', ' ');
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(tamperedChunks, alice.dsa.publicKey);
    }, /CHUNK_AUTH_FAILED/);
  });

  // 6. Goal 12: Session Resumption Ticket with StateDir Storage & Peer Identity Binding
  await t.test('6. Goal 12: Session resumption ticket loaded from stateDir, binds peer identity and key', () => {
    // Ticket HMAC key must be random per run and persisted in stateDir/ticket_key.bin (0600 mode)
    const ticketKey = ProtectedMessagingEngine.getOrCreateTicketKey(stateDir);
    assert.equal(ticketKey.length, 32);
    const ticketKeyPath = path.join(stateDir, 'ticket_key.bin');
    assert.ok(fs.existsSync(ticketKeyPath));
    assert.equal(fs.statSync(ticketKeyPath).mode & 0o777, 0o600);

    // Alice issues ticket for Bob, binding Bob's identity ID and ML-DSA public key
    const bobKeyB64 = bob.dsa.publicKeyDerB64;
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('bob', bobKeyB64, ticketKey, 500); // 500ms TTL

    // Valid presentation by Bob
    const checkValid = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'bob', bobKeyB64, ticketKey);
    assert.equal(checkValid.valid, true);
    assert.equal(checkValid.ticket_data.peer_id, 'bob');

    // Case A: Different actor ID presenting Bob's ticket -> TICKET_PEER_MISMATCH
    const checkWrongPeer = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'eve', bobKeyB64, ticketKey);
    assert.equal(checkWrongPeer.valid, false);
    assert.equal(checkWrongPeer.reason, 'TICKET_PEER_MISMATCH');

    // Case B: Same actor ID presenting with different identity key -> TICKET_IDENTITY_KEY_MISMATCH
    const fakeKeyB64 = charlie.dsa.publicKeyDerB64;
    const checkWrongKey = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'bob', fakeKeyB64, ticketKey);
    assert.equal(checkWrongKey.valid, false);
    assert.equal(checkWrongKey.reason, 'TICKET_IDENTITY_KEY_MISMATCH');

    // Case C: Expired ticket -> TICKET_EXPIRED
    const expiredTicket = ProtectedMessagingEngine.issueResumptionTicket('bob', bobKeyB64, ticketKey, -100);
    const checkExpired = ProtectedMessagingEngine.verifyResumptionTicket(expiredTicket, 'bob', bobKeyB64, ticketKey);
    assert.equal(checkExpired.valid, false);
    assert.equal(checkExpired.reason, 'TICKET_EXPIRED');
  });
});
