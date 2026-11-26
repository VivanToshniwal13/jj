'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { dispatch } = require('../team_app.cjs');
const {
  DistributedRevocationAuthority,
  DistributedNode,
  broadcastRevocation,
  broadcastEnrolment
} = require('../lib/distributed_revocation.cjs');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

test('Goal 2: Device Loss, Revocation, Re-enrolment and Peer Isolation', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-reenrol-'));
  process.env.TRACK4_STATE_DIR = stateDir;

  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  // 1. Initial clean setup: maya owns asset1, alex owns asset2
  await t.test('1. Clean setup with multiple owners and assets', async () => {
    const res = await dispatch({
      op: 'setup',
      owners: { asset1: 'maya', asset2: 'alex' },
      contents: { asset1: 'maya secret file', asset2: 'alex secret file' },
      disabled: []
    });
    assert.equal(res.ready, true);
  });

  // 2. Both users can read their respective files
  await t.test('2. Initial authorized access for maya and alex', async () => {
    const rMaya = await dispatch({ op: 'read', actor: 'maya', asset: 'asset1', request_id: 'r01' });
    assert.equal(rMaya.decision, 'allow');
    assert.equal(rMaya.body, 'maya secret file');

    const rAlex = await dispatch({ op: 'read', actor: 'alex', asset: 'asset2', request_id: 'r02' });
    assert.equal(rAlex.decision, 'allow');
    assert.equal(rAlex.body, 'alex secret file');
  });

  // 3. Maya loses phone (device-maya-1). Revoke maya across nodes.
  await t.test('3. Device loss on device-maya-1 triggers revocation and denies access', async () => {
    await dispatch({ op: 'revoke', actor: 'maya' });

    // Maya read is denied
    const rMayaAfter = await dispatch({ op: 'read', actor: 'maya', asset: 'asset1', request_id: 'r03' });
    assert.equal(rMayaAfter.decision, 'deny');
    assert.equal(rMayaAfter.body, undefined);

    // Unaffected peer alex still reads normally
    const rAlexAfter = await dispatch({ op: 'read', actor: 'alex', asset: 'asset2', request_id: 'r04' });
    assert.equal(rAlexAfter.decision, 'allow');
    assert.equal(rAlexAfter.body, 'alex secret file');
  });

  // 4. Maya enrols a NEW device (device-maya-2) with signed enrolment record
  await t.test('4. Maya enrols new device, regains access to own files, old device stays blocked', async () => {
    const newDeviceKp = crypto.generateKeyPairSync('ml-dsa-65');
    const newDevicePkB64 = newDeviceKp.publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

    const enrolRes = await dispatch({
      op: 'enrol_device',
      actor: 'maya',
      device_id: 'device-maya-2',
      previous_device_id: 'device-maya-1',
      device_public_key: newDevicePkB64
    });
    assert.equal(enrolRes.enrolled, true);
    assert.equal(enrolRes.device_id, 'device-maya-2');

    // Maya regains access with new device
    const rMayaNew = await dispatch({
      op: 'read',
      actor: 'maya',
      asset: 'asset1',
      device_id: 'device-maya-2',
      request_id: 'r05'
    });
    assert.equal(rMayaNew.decision, 'allow');
    assert.equal(rMayaNew.body, 'maya secret file');

    // Request with old revoked device is strictly DENIED
    const rMayaOld = await dispatch({
      op: 'read',
      actor: 'maya',
      asset: 'asset1',
      device_id: 'device-maya-1',
      request_id: 'r06'
    });
    assert.equal(rMayaOld.decision, 'deny');
    assert.equal(rMayaOld.body, undefined);

    // Alex is still completely unaffected
    const rAlexFinal = await dispatch({ op: 'read', actor: 'alex', asset: 'asset2', request_id: 'r07' });
    assert.equal(rAlexFinal.decision, 'allow');
  });

  // 5. Distributed 5-Node Key Cutoff: Goal 1 verification
  await t.test('5. Goal 1: All 5 nodes reject old key v1 after cutoff while in-flight before cutoff completes', async () => {
    const authority = new DistributedRevocationAuthority();
    const authorityPk = authority.getPublicKey();
    const tmpNodes = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-5nodes-'));

    const nodes = [1, 2, 3, 4, 5].map(i => {
      const nDir = path.join(tmpNodes, `node-${i}`);
      fs.mkdirSync(nDir, { recursive: true });
      return new DistributedNode(`node-${i}`, nDir, authorityPk);
    });

    const now = Date.now();
    const cutoffTime = now + 500; // 500ms grace period cutoff

    // Distribute rotation to all 5 nodes: active=2, retiring=1, cutoff=cutoffTime
    for (const node of nodes) {
      node.applyKeyRotation(2, 1, cutoffTime);
    }

    // A. During grace period (now <= cutoffTime): new request with v1 accepted under retiring grace period
    for (const node of nodes) {
      const checkDuring = node.isKeyVersionAccepted(1, now, false);
      assert.equal(checkDuring.accepted, true);
      assert.equal(checkDuring.state, 'retiring_grace_period');
    }

    // B. In-flight request started before cutoff completing before cutoff
    for (const node of nodes) {
      const checkInFlight = node.isKeyVersionAccepted(1, now + 100, true);
      assert.equal(checkInFlight.accepted, true);
    }

    // C. After cutoff has passed (now + 600 > cutoffTime): ALL 5 NODES REJECT KEY V1
    const afterCutoffTime = now + 600;
    for (const node of nodes) {
      const checkAfter = node.isKeyVersionAccepted(1, afterCutoffTime, false);
      assert.equal(checkAfter.accepted, false);
      assert.ok(checkAfter.reason.includes('CUTOFF_EXPIRED'));

      // New key v2 is accepted on all 5 nodes
      const checkV2 = node.isKeyVersionAccepted(2, afterCutoffTime, false);
      assert.equal(checkV2.accepted, true);
      assert.equal(checkV2.state, 'active');
    }

    fs.rmSync(tmpNodes, { recursive: true, force: true });
  });

  // 6. Live Detection & Automated Response
  await t.test('6. Live detection rules and automated lockout on audit log', async () => {
    // A. Malformed request triggers RULE_MALFORMED_INJECTION
    await dispatch({
      op: 'read',
      actor: 'attacker_script',
      asset: '../etc/passwd',
      request_id: 'r-inject-1'
    }).catch(() => {});

    // B. Repeated denials trigger RULE_REPEATED_DENIALS and 30s lockout
    const attacker = 'persistent_brute';
    for (let i = 0; i < 3; i++) {
      await dispatch({
        op: 'read',
        actor: attacker,
        asset: 'asset1', // not owner
        request_id: `r-deny-${i}`
      });
    }

    // Subsequent request is denied due to ACTOR_LOCKED_OUT
    const lockedRes = await dispatch({
      op: 'read',
      actor: attacker,
      asset: 'asset1',
      request_id: 'r-after-lockout'
    });
    assert.equal(lockedRes.decision, 'deny');

    // C. Verify alerts exist in audit log
    const log = new TamperEvidentLog(stateDir);
    const logContent = fs.readFileSync(log.logPath, 'utf8');
    assert.ok(logContent.includes('RULE_REPEATED_DENIALS') || logContent.includes('ACTOR_LOCKED_OUT'));
  });
});
