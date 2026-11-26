'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');

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

test('Adapter Crash Recovery & Fault Injection', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-crash-'));

  await t.test('Crash injection mid-setup does not corrupt state and retry succeeds', async () => {
    // 1. Trigger SIGKILL mid-setup
    const crashRes = await runService({
      op: 'setup',
      owners: { asset1: 'maya' },
      contents: { asset1: 'confidential_payload' },
      disabled: [],
      key_material: 'kek-test-secret-12345'
    }, {
      TRACK4_STATE_DIR: stateDir,
      TRACK4_FAULT_HOOK: 'mid_setup'
    });

    // Child should have been killed by SIGKILL
    assert.ok(crashRes.signal === 'SIGKILL' || crashRes.code !== 0);

    // 2. Fresh setup succeeds and does not encounter unparseable corrupt JSON
    const retryRes = await runService({
      op: 'setup',
      owners: { asset1: 'maya' },
      contents: { asset1: 'confidential_payload' },
      disabled: [],
      key_material: 'kek-test-secret-12345'
    }, {
      TRACK4_STATE_DIR: stateDir
    });

    assert.equal(retryRes.code, 0);
    const parsed = JSON.parse(retryRes.stdout);
    assert.equal(parsed.ready, true);

    // Verify Maya can read
    const readRes = await runService({
      op: 'read',
      actor: 'maya',
      asset: 'asset1',
      request_id: 'req-maya-1'
    }, { TRACK4_STATE_DIR: stateDir });

    assert.equal(readRes.code, 0);
    const readParsed = JSON.parse(readRes.stdout);
    assert.equal(readParsed.decision, 'allow');
    assert.equal(readParsed.body, 'confidential_payload');
  });

  await t.test('Crash injection mid-revoke releases lock and retry enforces revocation', async () => {
    // 1. Trigger SIGKILL mid-revoke
    const crashRevoke = await runService({
      op: 'revoke',
      actor: 'maya'
    }, {
      TRACK4_STATE_DIR: stateDir,
      TRACK4_FAULT_HOOK: 'mid_revoke'
    });

    assert.ok(crashRevoke.signal === 'SIGKILL' || crashRevoke.code !== 0);

    // 2. Immediate next request should not hang indefinitely on stale lockfile
    const retryRevoke = await runService({
      op: 'revoke',
      actor: 'maya'
    }, {
      TRACK4_STATE_DIR: stateDir
    });

    assert.equal(retryRevoke.code, 0);

    // 3. Confirm Maya is now revoked and denied
    const deniedRead = await runService({
      op: 'read',
      actor: 'maya',
      asset: 'asset1',
      request_id: 'req-maya-denied'
    }, { TRACK4_STATE_DIR: stateDir });

    assert.equal(deniedRead.code, 0);
    const deniedParsed = JSON.parse(deniedRead.stdout);
    assert.equal(deniedParsed.decision, 'deny');
    assert.equal(deniedParsed.body, undefined);
  });
});
