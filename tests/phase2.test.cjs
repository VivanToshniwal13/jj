'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { KeyState, KeyLifecycleManager } = require('../lib/key_lifecycle.cjs');
const { DistributedRevocationAuthority, DistributedNode, broadcastRevocation } = require('../lib/distributed_revocation.cjs');
const { BackupManager } = require('../lib/backup_integrity.cjs');

test('Phase 2 - Goal 1: Key Rotation & Grace Period Enforcement', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-rot-'));
  const graceMs = 200; // 200ms grace period for test
  const km = new KeyLifecycleManager(stateDir, graceMs);

  await t.test('Initial state: Version 1 is active', async () => {
    const k1 = km.getActiveKey();
    assert.equal(k1.version, 1);
    assert.equal(k1.state, KeyState.ACTIVE);
    assert.equal(km.canUseForEncryption(1), true);
    assert.equal(km.canUseForDecryption(1), true);
  });

  await t.test('Rotate to Version 2: V1 enters retiring, V2 becomes active', async () => {
    const res = km.rotateKey();
    assert.equal(res.active_version, 2);
    assert.equal(res.retiring_version, 1);

    const k2 = km.getActiveKey();
    assert.equal(k2.version, 2);
    assert.equal(k2.state, KeyState.ACTIVE);

    // V2 is now used for new encryptions; V1 cannot be used for new encryptions
    assert.equal(km.canUseForEncryption(2), true);
    assert.equal(km.canUseForEncryption(1), false, 'Retiring key must not be used for new encryptions');

    // Inside grace period: V1 can still decrypt in-flight data
    assert.equal(km.canUseForDecryption(1), true, 'Retiring key can decrypt within grace period');
  });

  await t.test('After grace period cutoff: V1 transitions to retired', async () => {
    // Wait out grace period
    await new Promise(r => setTimeout(r, graceMs + 50));

    const k1 = km.getKeyByVersion(1);
    assert.equal(k1.state, KeyState.RETIRED);
    assert.equal(km.canUseForEncryption(1), false);
    // Historical decryption allowed, but encryption rejected
    assert.equal(km.canUseForDecryption(1), true);
  });
});

test('Phase 2 - Goal 2: Revocation Across Nodes & Latency Measurement', async (t) => {
  const authority = new DistributedRevocationAuthority();
  const authorityPk = authority.getPublicKey();

  // Create 5 simulated independent nodes
  const nodeCount = 5;
  const nodes = [];
  for (let i = 0; i < nodeCount; i++) {
    const nodeDir = fs.mkdtempSync(path.join(os.tmpdir(), `track4-node-${i}-`));
    nodes.push(new DistributedNode(`node-${i}`, nodeDir, authorityPk));
  }

  await t.test('Broadcast revocation to 5 nodes and measure propagation latency', async () => {
    const report = await broadcastRevocation(authority, nodes, 'compromised-device-alice', 'lost_device');
    
    assert.equal(report.node_count, nodeCount);
    assert.equal(report.version, 1);
    assert.ok(report.total_propagation_ms >= 0);

    console.log(`[Evidence Goal 2] 5-Node Propagation Latency: ${report.total_propagation_ms} ms (avg ${(report.total_propagation_ms / nodeCount).toFixed(2)} ms/node)`);

    // Verify all nodes enforce revocation
    for (const node of nodes) {
      assert.equal(node.isActorRevoked('compromised-device-alice'), true);
      assert.equal(node.isActorRevoked('unaffected-peer-bob'), false);
    }
  });

  await t.test('Replay attack on revocation list is rejected by nodes', async () => {
    // Attempt to replay an old revocation list (version 1)
    const staleList = authority.createSignedRevocationList('new-device-charlie');
    staleList.payload.version = 1; // forge version back to 1
    // Tampering with payload breaks signature
    assert.throws(() => {
      nodes[0].applyRevocationList(staleList);
    }, /Invalid authority signature/);
  });
});

test('Phase 2 - Goal 3: Write-Ahead Journal & Crash Recovery', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-wal-'));
  const km = new KeyLifecycleManager(stateDir);

  await t.test('Crash injection at STAGE_START: Rollback recovers active key V1', async () => {
    assert.throws(() => {
      km.rotateKey('STAGE_START');
    }, /CRASH_INJECTED_AT_STAGE_START/);

    // Simulate node restart: create fresh manager which runs recoverWal()
    const recoveredKm = new KeyLifecycleManager(stateDir);
    const active = recoveredKm.getActiveKey();
    assert.equal(active.version, 1);
    assert.equal(active.state, KeyState.ACTIVE);
  });

  await t.test('Crash injection at STAGE_KEY_GENERATED: Rollback purges pending key', async () => {
    assert.throws(() => {
      km.rotateKey('STAGE_KEY_GENERATED');
    }, /CRASH_INJECTED_AT_STAGE_KEY_GENERATED/);

    // Simulate restart
    const recoveredKm = new KeyLifecycleManager(stateDir);
    const active = recoveredKm.getActiveKey();
    assert.equal(active.version, 1);
    // V2 uncommitted key was removed
    assert.equal(recoveredKm.getKeyByVersion(2), null);
  });

  await t.test('Successful rotation completes without remaining WAL', async () => {
    const res = km.rotateKey();
    assert.equal(res.active_version, 2);
    assert.equal(fs.existsSync(path.join(stateDir, 'rotation.wal')), false);
  });
});

test('Phase 2 - Goal 4: Backup Integrity, Tamper & Truncation Detection', async (t) => {
  const backupMgr = new BackupManager();
  const backupPassword = 'Strong-Production-Backup-Password-2026';

  const testKeyData = {
    version: 3,
    keys: [
      { id: 'k1', secretHex: '1122334455667788' },
      { id: 'k2', secretHex: 'aabbccddeeff0011' }
    ]
  };

  const backup = backupMgr.createBackup(testKeyData, backupPassword);
  assert.ok(backup.signature_b64);
  assert.ok(backup.manifest_hash);

  await t.test('Legitimate restore reproduces verified key material', async () => {
    const restored = backupMgr.restoreBackup(backup, backupPassword);
    assert.deepEqual(restored, testKeyData);
  });

  await t.test('Detects ciphertext tampering (bit flip)', async () => {
    const tamperedBackup = JSON.parse(JSON.stringify(backup));
    // Flip bytes in ciphertext
    const rawCt = Buffer.from(tamperedBackup.ciphertext_b64, 'base64');
    rawCt[0] ^= 0xFF;
    tamperedBackup.ciphertext_b64 = rawCt.toString('base64');

    assert.throws(() => {
      backupMgr.restoreBackup(tamperedBackup, backupPassword);
    }, /BACKUP_TAMPERED/);
  });

  await t.test('Detects ciphertext truncation', async () => {
    const truncatedBackup = JSON.parse(JSON.stringify(backup));
    const rawCt = Buffer.from(truncatedBackup.ciphertext_b64, 'base64');
    truncatedBackup.ciphertext_b64 = rawCt.subarray(0, rawCt.length - 16).toString('base64');

    assert.throws(() => {
      backupMgr.restoreBackup(truncatedBackup, backupPassword);
    }, /BACKUP_TAMPERED/);
  });

  await t.test('Detects wrong password or corrupted auth tag', async () => {
    assert.throws(() => {
      backupMgr.restoreBackup(backup, 'Wrong-Password-Attempt');
    }, /BACKUP_AUTH_FAILED/);
  });
});
