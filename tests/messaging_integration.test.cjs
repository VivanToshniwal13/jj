'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { dispatch, ProtectedMessagingEngine } = require('../team_app.cjs');

test('Protected Messaging Integration with Main Application Dispatch (Goals 9-12)', async (t) => {
  const testStateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-integration-test-'));
  const origEnvStateDir = process.env.TRACK4_STATE_DIR;
  process.env.TRACK4_STATE_DIR = testStateDir;

  t.after(() => {
    if (origEnvStateDir !== undefined) {
      process.env.TRACK4_STATE_DIR = origEnvStateDir;
    } else {
      delete process.env.TRACK4_STATE_DIR;
    }
    try { fs.rmSync(testStateDir, { recursive: true, force: true }); } catch {}
  });

  // Setup Alice and Bob ML-DSA-65 identity keys
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();
  const charlie = ProtectedMessagingEngine.generateIdentityKeyPair();

  // Export keys as PEM strings for RPC/CLI compatibility
  const alicePrivPem = alice.dsa.privateKey.export({ format: 'pem', type: 'pkcs8' });
  const bobPubPem = bob.dsa.publicKey.export({ format: 'pem', type: 'spki' });
  const alicePubPem = alice.dsa.publicKey.export({ format: 'pem', type: 'spki' });

  // 1. End-to-end Send and Receive via dispatch()
  await t.test('1. End-to-end Send and Receive via team_app dispatch()', async () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

    const secretPayload = 'Critical synthetic telemetry: patient report #42901';

    // Send through dispatch()
    const sendResponse = await dispatch({
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: {
        ephemeralPublicKeyB64: bobPrekey.ephemeralPublicKeyB64,
        signatureB64: bobPrekey.signatureB64
      },
      plaintext: secretPayload,
      options: { messageId: 'msg-dispatch-001', sequenceNumber: 1 }
    });

    assert.equal(sendResponse.status, 'sent');
    assert.ok(sendResponse.packet);
    assert.equal(sendResponse.packet.message_id, 'msg-dispatch-001');

    // Receive through dispatch()
    const receiveResponse = await dispatch({
      op: 'receive_protected_message',
      recipient: 'bob',
      sender_public_key: alicePubPem,
      recipient_ephemeral_prekey: bobPrekey,
      packet: sendResponse.packet
    });

    assert.equal(receiveResponse.status, 'received');
    assert.equal(receiveResponse.sender_id, 'alice');
    assert.equal(receiveResponse.recipient_id, 'bob');
    assert.equal(receiveResponse.plaintext, secretPayload);
    assert.equal(receiveResponse.verified, true);
  });

  // 2. Dispatch Replay Rejection
  await t.test('2. Duplicate packet sent to dispatch() is rejected with MESSAGE_REPLAY_DETECTED', async () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const sendResponse = await dispatch({
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: {
        ephemeralPublicKeyB64: bobPrekey.ephemeralPublicKeyB64,
        signatureB64: bobPrekey.signatureB64
      },
      plaintext: 'Replay via dispatch test payload',
      options: { messageId: 'msg-dispatch-replay-001', sequenceNumber: 10 }
    });

    // First receive succeeds
    const firstRec = await dispatch({
      op: 'receive_protected_message',
      recipient: 'bob',
      sender_public_key: alicePubPem,
      recipient_ephemeral_prekey: bobPrekey,
      packet: sendResponse.packet
    });
    assert.equal(firstRec.status, 'received');

    // Second receive with same packet must throw MESSAGE_REPLAY_DETECTED
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'bob',
        sender_public_key: alicePubPem,
        recipient_ephemeral_prekey: bobPrekey,
        packet: sendResponse.packet
      });
    }, /MESSAGE_REPLAY_DETECTED/);
  });

  // 3. Dispatch Recipient Binding Enforcement
  await t.test('3. Dispatch enforces recipient binding; wrong recipient throws WRONG_RECIPIENT_ERROR', async () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const sendResponse = await dispatch({
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: {
        ephemeralPublicKeyB64: bobPrekey.ephemeralPublicKeyB64,
        signatureB64: bobPrekey.signatureB64
      },
      plaintext: 'Confidential dispatch'
    });

    // charlie tries to receive message meant for bob
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'charlie',
        sender_public_key: alicePubPem,
        recipient_ephemeral_prekey: bobPrekey,
        packet: sendResponse.packet
      });
    }, /WRONG_RECIPIENT_ERROR/);
  });

  // 4. Audit Log Integration
  await t.test('4. Protected messaging operations are recorded in tamper-evident audit.log', async () => {
    const logPath = path.join(testStateDir, 'audit.log');
    assert.ok(fs.existsSync(logPath));
    const logLines = fs.readFileSync(logPath, 'utf8').trim().split('\n');
    assert.ok(logLines.length >= 3);

    const parsedRecords = logLines.map(l => JSON.parse(l));
    const sendEvents = parsedRecords.filter(r => r.op === 'send_protected_message');
    const receiveEvents = parsedRecords.filter(r => r.op === 'receive_protected_message');

    assert.ok(sendEvents.length >= 2);
    assert.ok(receiveEvents.length >= 2);
  });
});
