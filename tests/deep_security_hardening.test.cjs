'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { ProtectedMessagingEngine } = require('../lib/messaging.cjs');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

test('Phase 2 & 3: Advanced Replay, Rollback & Trusted Sender Hardening', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-sec-hardening-'));
  const engine = new ProtectedMessagingEngine(stateDir);

  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();

  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('1. Same sender sequence reuse with different message_id is rejected', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt1 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'msg1', {
      messageId: 'msg-unique-001',
      sequenceNumber: 50
    });
    const res1 = engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt1);
    assert.equal(res1.verified, true);

    // Reuse sequence 50 with a different message ID
    const bobPrekey2 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt2 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey2, 'msg2', {
      messageId: 'msg-unique-002',
      sequenceNumber: 50
    });

    assert.throws(() => {
      engine.receiveMessage('bob', bobPrekey2, alice.dsa.publicKey, pkt2);
    }, /Sequence 50 already used with different message ID/);
  });

  await t.test('2. Same sender duplicate message_id with different sequence is rejected', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt1 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'msg1', {
      messageId: 'msg-dup-id-test',
      sequenceNumber: 60
    });
    const res1 = engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt1);
    assert.equal(res1.verified, true);

    // Reuse messageId with sequence 61
    const bobPrekey2 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt2 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey2, 'msg2', {
      messageId: 'msg-dup-id-test',
      sequenceNumber: 61
    });

    assert.throws(() => {
      engine.receiveMessage('bob', bobPrekey2, alice.dsa.publicKey, pkt2);
    }, /Duplicate message ID with different sequence number/);
  });

  await t.test('3. Replay state rollback detection via monotonic high-water mark', () => {
    const freshDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-rollback-'));
    try {
      const eng1 = new ProtectedMessagingEngine(freshDir);
      const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

      // Send and receive message to advance state
      const pkt = eng1.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'test');
      eng1.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt);

      // Now backup replay_state.json
      const backupState = fs.readFileSync(path.join(freshDir, 'replay_state.json'), 'utf8');

      // Advance state with another message
      const bobPrekey2 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const pkt2 = eng1.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey2, 'test2');
      eng1.receiveMessage('bob', bobPrekey2, alice.dsa.publicKey, pkt2);

      // Simulate malicious attacker rolling back replay_state.json to old backup
      fs.writeFileSync(path.join(freshDir, 'replay_state.json'), backupState, 'utf8');

      // New receiver instance on same stateDir must detect the rollback and fail closed
      assert.throws(() => {
        new ProtectedMessagingEngine(freshDir);
      }, /ROLLBACK_DETECTED/);
    } finally {
      fs.rmSync(freshDir, { recursive: true, force: true });
    }
  });

  await t.test('4. Trusted Sender Directory: registration, key rotation, revocation, and rejection', () => {
    const dirState = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-sender-dir-'));
    try {
      const eng = new ProtectedMessagingEngine(dirState);
      const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

      // Register Alice
      eng.registerSenderIdentity('alice', alice.dsa.publicKeyDerB64);

      // Send message from Alice to Bob
      const pkt = eng.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'trusted hello');
      const rec = eng.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt);
      assert.equal(rec.verified, true);

      // Case A: Unregistered sender
      const mallory = ProtectedMessagingEngine.generateIdentityKeyPair();
      const bobPrekey2 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const pktUnreg = eng.sendMessage('mallory', mallory.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey2, 'unreg');
      assert.throws(() => {
        eng.receiveMessage('bob', bobPrekey2, mallory.dsa.publicKey, pktUnreg);
      }, /UNREGISTERED_SENDER/);

      // Case B: Public key mismatch
      const fakeAlice = ProtectedMessagingEngine.generateIdentityKeyPair();
      const bobPrekey3 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const pktFake = eng.sendMessage('alice', fakeAlice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey3, 'impostor');
      assert.throws(() => {
        eng.receiveMessage('bob', bobPrekey3, fakeAlice.dsa.publicKey, pktFake);
      }, /SENDER_KEY_MISMATCH/);

      // Case C: Key rotation
      const newAlice = ProtectedMessagingEngine.generateIdentityKeyPair();
      eng.rotateSenderKey('alice', newAlice.dsa.publicKeyDerB64);
      const bobPrekey4 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const pktRot = eng.sendMessage('alice', newAlice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey4, 'rotated');
      const recRot = eng.receiveMessage('bob', bobPrekey4, newAlice.dsa.publicKey, pktRot);
      assert.equal(recRot.verified, true);

      // Case D: Revocation
      eng.revokeSenderKey('alice');
      const bobPrekey5 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const pktRev = eng.sendMessage('alice', newAlice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey5, 'after rev');
      assert.throws(() => {
        eng.receiveMessage('bob', bobPrekey5, newAlice.dsa.publicKey, pktRev);
      }, /SENDER_KEY_REVOKED/);
    } finally {
      fs.rmSync(dirState, { recursive: true, force: true });
    }
  });
});

test('Phase 5 & 6: Chunking & Session Resumption Edge Cases', async (t) => {
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();

  await t.test('1. Chunking rejects chunk size below 16 or above 65536', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const eng = new ProtectedMessagingEngine();
    const packet = eng.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'test data');

    assert.throws(() => {
      ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 10); // < 16
    }, /INVALID_CHUNK_SIZE/);

    assert.throws(() => {
      ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 70000); // > 65536
    }, /INVALID_CHUNK_SIZE/);
  });

  await t.test('2. Chunking rejects tampered canonical header, duplicate chunk index, and inconsistent metadata', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const eng = new ProtectedMessagingEngine();
    const packet = eng.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'A'.repeat(500));
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 64);

    // Case A: Missing signature
    const noSigChunk = JSON.parse(JSON.stringify(chunks));
    delete noSigChunk[0].auth_sig_b64;
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(noSigChunk, alice.dsa.publicKey);
    }, /CHUNK_AUTH_MISSING/);

    // Case B: Duplicate chunk index
    const dupIndexChunks = [chunks[0], chunks[0], chunks[2]];
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(dupIndexChunks, alice.dsa.publicKey);
    }, /DUPLICATE_CHUNK_INDEX/);

    // Case C: Inconsistent message_id
    const badIdChunks = JSON.parse(JSON.stringify(chunks));
    badIdChunks[1].message_id = 'msg-different-id';
    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(badIdChunks, alice.dsa.publicKey);
    }, /INCONSISTENT_CHUNK_METADATA/);
  });

  await t.test('3. Resumption Ticket: rejects future-issued ticket, invalid key, and timing-safe HMAC verification', () => {
    const validKey = crypto.randomBytes(32);
    const peerKeyB64 = alice.dsa.publicKeyDerB64;

    // Case A: Non-32-byte key fails closed
    assert.throws(() => {
      ProtectedMessagingEngine.issueResumptionTicket('alice', peerKeyB64, crypto.randomBytes(16));
    }, /INVALID_TICKET_KEY/);

    // Case B: Future-issued ticket (> 5s in future) is rejected
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', peerKeyB64, validKey, 3600000);
    const parsedData = JSON.parse(Buffer.from(ticket.ticket_b64, 'base64').toString('utf8'));
    parsedData.issued_at = Date.now() + 100000; // 100s in future
    const tamperedBytes = Buffer.from(JSON.stringify(parsedData), 'utf8');
    const validHmac = crypto.createHmac('sha256', validKey).update(tamperedBytes).digest('hex');
    const futureTicket = { ticket_b64: tamperedBytes.toString('base64'), hmac_hex: validHmac };

    const checkFuture = ProtectedMessagingEngine.verifyResumptionTicket(futureTicket, 'alice', peerKeyB64, validKey);
    assert.equal(checkFuture.valid, false);
    assert.equal(checkFuture.reason, 'TICKET_FUTURE_ISSUED');

    // Case C: Corrupt HMAC fails
    const badHmacTicket = { ticket_b64: ticket.ticket_b64, hmac_hex: '00'.repeat(32) };
    const checkBadHmac = ProtectedMessagingEngine.verifyResumptionTicket(badHmacTicket, 'alice', peerKeyB64, validKey);
    assert.equal(checkBadHmac.valid, false);
    assert.equal(checkBadHmac.reason, 'TICKET_HMAC_INVALID');
  });
});

test('Phase 7: Tamper Log Advanced Integrity Hardening', async (t) => {
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-log-hardening-'));
  const logFile = path.join(logDir, 'audit.log');

  t.after(() => {
    try { fs.rmSync(logDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('1. Reject blank lines inside audit log as LOG_CORRUPT', () => {
    const log1 = new TamperEvidentLog(logDir);
    log1.appendRecord('actor-a', 'login');
    log1.appendRecord('actor-a', 'read');

    // Inject a blank line inside the log
    const content = fs.readFileSync(logFile, 'utf8');
    const lines = content.split('\n');
    lines.splice(1, 0, '   '); // blank line between record 0 and 1
    fs.writeFileSync(logFile, lines.join('\n'), 'utf8');

    // New instance must fail closed
    const log2 = new TamperEvidentLog(logDir);
    assert.equal(log2.corrupt, true);
    assert.ok(log2.corruptReason.includes('LOG_CORRUPT: Malformed blank line'));

    assert.throws(() => {
      log2.appendRecord('actor-b', 'read');
    }, /LOG_CORRUPT/);
  });

  await t.test('2. Audit authority key corruption fails closed and never silently replaces key', () => {
    const corruptKeyDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-corrupt-key-'));
    try {
      // First instance creates key
      const logA = new TamperEvidentLog(corruptKeyDir);
      logA.appendRecord('actor-1', 'test');

      // Corrupt the private key file
      const keyPath = path.join(corruptKeyDir, 'audit_authority_mldsa_sk.bin');
      fs.writeFileSync(keyPath, 'CORRUPTED_KEY_BYTES_NOT_DER');

      // Second instance must throw AUDIT_KEY_UNAVAILABLE without regenerating key
      assert.throws(() => {
        new TamperEvidentLog(corruptKeyDir);
      }, /AUDIT_KEY_UNAVAILABLE/);
    } finally {
      fs.rmSync(corruptKeyDir, { recursive: true, force: true });
    }
  });

  await t.test('3. Checkpoint sequence discontinuity is detected and rejected', () => {
    const cpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-cp-test-'));
    try {
      const log = new TamperEvidentLog(cpDir, null, 2);
      log.appendRecord('actor-1', 'op-1');
      log.appendRecord('actor-1', 'op-2'); // triggers checkpoint index 0

      // Read log and tamper checkpoint index to 5
      const cpLogPath = path.join(cpDir, 'audit.log');
      const lines = fs.readFileSync(cpLogPath, 'utf8').trim().split('\n');
      const cp = JSON.parse(lines[2]); // checkpoint record at index 2
      cp.checkpoint_index = 5; // Discontinuity!
      lines[2] = JSON.stringify(cp);
      fs.writeFileSync(cpLogPath, lines.join('\n') + '\n', 'utf8');

      const verifyRes = TamperEvidentLog.verifyLog(cpLogPath, log.authorityKeyPair.publicKey);
      assert.equal(verifyRes.valid, false);
      assert.equal(verifyRes.errorType, 'TAMPER_CHECKPOINT_DISCONTINUITY');
    } finally {
      fs.rmSync(cpDir, { recursive: true, force: true });
    }
  });
});
