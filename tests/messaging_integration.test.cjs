'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { dispatch, ProtectedMessagingEngine } = require('../team_app.cjs');

function runServiceProcess(requestObj, stateDir) {
  return new Promise((resolve, reject) => {
    const proc = spawn('node', [path.join(__dirname, '..', 'track4_service.cjs')], {
      env: { ...process.env, TRACK4_STATE_DIR: stateDir },
      stdio: ['pipe', 'pipe', 'pipe']
    });
    let stdout = '';
    let stderr = '';
    proc.stdout.on('data', d => { stdout += d.toString(); });
    proc.stderr.on('data', d => { stderr += d.toString(); });
    proc.on('close', code => {
      resolve({ code, stdout, stderr });
    });
    proc.on('error', reject);
    proc.stdin.write(JSON.stringify(requestObj));
    proc.stdin.end();
  });
}

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
    const bobPrekeyDerB64 = bobPrekey.ephemeralPrivateKeyDerB64;
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
      recipient_ephemeral_private_key_b64: bobPrekeyDerB64,
      packet: sendResponse.packet
    });
    assert.equal(firstRec.status, 'received');

    // Second receive with same packet must throw MESSAGE_REPLAY_DETECTED
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'bob',
        sender_public_key: alicePubPem,
        recipient_ephemeral_private_key_b64: bobPrekeyDerB64,
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

  // 5. Enforce Ephemeral Key Cleanup Across All 4 Paths in dispatch()
  await t.test('5. Enforce ephemeral key cleanup in dispatch finally across success, bad sig, wrong recipient, decrypt fail', async () => {
    // 5A: Success path destroys key
    const prekeySuccess = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const sendSuccess = await dispatch({
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: prekeySuccess,
      plaintext: 'Payload for success cleanup test'
    });
    const recSuccess = await dispatch({
      op: 'receive_protected_message',
      recipient: 'bob',
      sender_public_key: alicePubPem,
      recipient_ephemeral_prekey: prekeySuccess,
      packet: sendSuccess.packet
    });
    assert.equal(recSuccess.status, 'received');
    assert.equal(prekeySuccess.destroyed, true);
    assert.equal(prekeySuccess.ephemeralPrivateKey, null);

    // 5B: Invalid signature path destroys key
    const prekeyBadSig = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const badSigPacket = JSON.parse(JSON.stringify(sendSuccess.packet));
    badSigPacket.message_id = 'msg-badsig-001';
    badSigPacket.sequence_number = 999;
    badSigPacket.aad.sequence_number = 999;
    badSigPacket.aad.message_id = 'msg-badsig-001';
    badSigPacket.signature_b64 = Buffer.from('invalidsignaturebytes').toString('base64');
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'bob',
        sender_public_key: alicePubPem,
        recipient_ephemeral_prekey: prekeyBadSig,
        packet: badSigPacket
      });
    }, /SIGNATURE_VERIFICATION_FAILED/);
    assert.equal(prekeyBadSig.destroyed, true);
    assert.equal(prekeyBadSig.ephemeralPrivateKey, null);

    // 5C: Wrong recipient path destroys key
    const prekeyWrongRecipient = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'charlie',
        sender_public_key: alicePubPem,
        recipient_ephemeral_prekey: prekeyWrongRecipient,
        packet: sendSuccess.packet
      });
    }, /WRONG_RECIPIENT_ERROR/);
    assert.equal(prekeyWrongRecipient.destroyed, true);
    assert.equal(prekeyWrongRecipient.ephemeralPrivateKey, null);

    // 5D: Decryption failure path destroys key
    const prekeyDecFail = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    // Send packet encapsulated to prekeyDecFail
    const sendDecFail = await dispatch({
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: prekeyDecFail,
      plaintext: 'Decryption fail test'
    });
    // Attempt to receive using a DIFFERENT recipient's prekey (charlie's prekey)
    const charliePrekey = ProtectedMessagingEngine.generateEphemeralPrekey(charlie.dsa.privateKey);
    await assert.rejects(async () => {
      await dispatch({
        op: 'receive_protected_message',
        recipient: 'bob',
        sender_public_key: alicePubPem,
        recipient_ephemeral_prekey: charliePrekey,
        packet: sendDecFail.packet
      });
    }, /WRONG_RECIPIENT_KEY_FAILED/);
    assert.equal(charliePrekey.destroyed, true);
    assert.equal(charliePrekey.ephemeralPrivateKey, null);
  });

  // 6. Real Process-Level CLI Messaging Test over stdin/stdout
  await t.test('6. Real Process-Level CLI Messaging Test via track4_service.cjs stdin/stdout', async () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const cliPayload = 'Process boundary confidential synthetic test record #9901';

    // Step A: Send protected message via child process stdin/stdout
    const sendReq = {
      op: 'send_protected_message',
      sender: 'alice',
      recipient: 'bob',
      sender_signing_key: alicePrivPem,
      recipient_public_key: bobPubPem,
      recipient_prekey: {
        ephemeralPublicKeyB64: bobPrekey.ephemeralPublicKeyB64,
        signatureB64: bobPrekey.signatureB64
      },
      plaintext: cliPayload,
      options: { messageId: 'msg-cli-process-001', sequenceNumber: 100 }
    };

    const sendRes = await runServiceProcess(sendReq, testStateDir);
    assert.equal(sendRes.code, 0);
    const sendData = JSON.parse(sendRes.stdout);
    assert.equal(sendData.status, 'sent');
    assert.ok(sendData.packet);

    // Step B: Receive protected message via child process stdin/stdout
    // transferring ephemeral private key securely across the process boundary
    const receiveReq = {
      op: 'receive_protected_message',
      recipient: 'bob',
      sender_public_key: alicePubPem,
      recipient_ephemeral_private_key_b64: bobPrekey.ephemeralPrivateKeyDerB64,
      packet: sendData.packet
    };

    const receiveRes = await runServiceProcess(receiveReq, testStateDir);
    assert.equal(receiveRes.code, 0);
    const receiveData = JSON.parse(receiveRes.stdout);
    assert.equal(receiveData.status, 'received');
    assert.equal(receiveData.plaintext, cliPayload);
    assert.equal(receiveData.verified, true);
    assert.equal(receiveData.sender_id, 'alice');
    assert.equal(receiveData.recipient_id, 'bob');

    // Step C: Confirm no private key material is exposed in stdout or stderr
    assert.ok(!sendRes.stdout.includes('PRIVATE KEY'));
    assert.ok(!sendRes.stderr.includes('PRIVATE KEY'));
    assert.ok(!receiveRes.stdout.includes('PRIVATE KEY'));
    assert.ok(!receiveRes.stderr.includes('PRIVATE KEY'));

    // Step D: Confirm audit.log contains no private key material
    const auditContent = fs.readFileSync(path.join(testStateDir, 'audit.log'), 'utf8');
    assert.ok(!auditContent.includes('PRIVATE KEY'));
    assert.ok(!auditContent.includes(bobPrekey.ephemeralPrivateKeyDerB64));
  });
});
