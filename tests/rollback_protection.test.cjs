'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');
const { BackupManager } = require('../lib/backup_integrity.cjs');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function runService(inputObj, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVICE_PATH], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

    child.on('close', (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });

    child.stdin.write(JSON.stringify(inputObj));
    child.stdin.end();
  });
}

test('Phase 2.1: Rollback Protection & Revocation Preservation', async () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-rollback-'));
  const backupMgr = new BackupManager(null, stateDir);
  const backupPassword = 'SecureBackupPassword2026!';

  // 1. Initial setup: maya and alice both have assets
  await runService({
    op: 'setup',
    owners: { asset_maya: 'maya', asset_alice: 'alice' },
    contents: { asset_maya: 'maya_secret', asset_alice: 'alice_secret' },
    disabled: [],
    key_material: 'kek-rollback-protection'
  }, { TRACK4_STATE_DIR: stateDir });

  // Verify Maya has access initially
  const initRead = await runService({
    op: 'read',
    actor: 'maya',
    asset: 'asset_maya',
    request_id: 'init-maya'
  }, { TRACK4_STATE_DIR: stateDir });
  assert.equal(JSON.parse(initRead.stdout).decision, 'allow');

  // 2. Create signed backup at Epoch 1
  const storePath = path.join(stateDir, 'store.enc');
  const preRevocationState = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  const oldBackup = backupMgr.createBackup(preRevocationState, backupPassword, preRevocationState.epoch || 1);

  assert.equal(oldBackup.epoch, 1);
  assert.ok(oldBackup.signature_b64);
  assert.ok(oldBackup.salt_hex);

  // 3. Revoke Maya (advances system epoch to 2)
  await runService({
    op: 'revoke',
    actor: 'maya'
  }, { TRACK4_STATE_DIR: stateDir });

  // Verify Maya is denied immediately
  const postRevokeRead = await runService({
    op: 'read',
    actor: 'maya',
    asset: 'asset_maya',
    request_id: 'post-revoke-maya'
  }, { TRACK4_STATE_DIR: stateDir });
  assert.equal(JSON.parse(postRevokeRead.stdout).decision, 'deny');

  // 4. Restore the older Epoch 1 backup
  const currentStateBeforeRestore = JSON.parse(fs.readFileSync(storePath, 'utf8'));
  const restoredState = backupMgr.restoreBackup(oldBackup, backupPassword, currentStateBeforeRestore);

  // Write restored state back to store
  fs.writeFileSync(storePath, JSON.stringify(restoredState, null, 2), { mode: 0o600 });

  // 5. CRITICAL CHECK: Maya MUST STILL BE DENIED
  // Restoring the old backup must NOT resurrect revoked credentials or permissions
  const postRestoreRead = await runService({
    op: 'read',
    actor: 'maya',
    asset: 'asset_maya',
    request_id: 'post-restore-maya'
  }, { TRACK4_STATE_DIR: stateDir });

  const postRestoreParsed = JSON.parse(postRestoreRead.stdout);
  assert.equal(postRestoreParsed.decision, 'deny', 'Rollback protection failed: revoked actor was resurrected!');

  // Alice retains access
  const aliceRead = await runService({
    op: 'read',
    actor: 'alice',
    asset: 'asset_alice',
    request_id: 'post-restore-alice'
  }, { TRACK4_STATE_DIR: stateDir });
  assert.equal(JSON.parse(aliceRead.stdout).decision, 'allow');
  assert.equal(JSON.parse(aliceRead.stdout).body, 'alice_secret');
});
