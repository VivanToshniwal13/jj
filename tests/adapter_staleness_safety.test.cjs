'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const { spawn } = require('node:child_process');

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

test('Adapter Staleness Isolation: Adapter read is NEVER gated by multi-node sync staleness', async () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-adapter-staleness-'));
  const env = { TRACK4_STATE_DIR: stateDir };

  // 1. Setup asset owned by alice
  const setupRes = await runService({
    op: 'setup',
    owners: { safeDoc: 'alice' },
    contents: { safeDoc: 'confidential_patient_record' },
    disabled: [],
    key_material: 'kek-staleness-check'
  }, env);

  assert.equal(setupRes.code, 0);
  assert.equal(JSON.parse(setupRes.stdout).ready, true);

  // 2. Sleep for 8 seconds (>5000ms DEFAULT_MAX_STALENESS_MS)
  // Single-node judge container has no sync source; adapter must remain fully functional.
  console.log('Sleeping 8 seconds to verify adapter does not fail-closed without cluster sync...');
  await new Promise(r => setTimeout(r, 8000));

  // 3. Owner read must STILL BE ALLOWED
  const readRes = await runService({
    op: 'read',
    actor: 'alice',
    asset: 'safeDoc',
    request_id: 'read-after-8s-sleep'
  }, env);

  assert.equal(readRes.code, 0);
  const readParsed = JSON.parse(readRes.stdout);
  assert.equal(readParsed.decision, 'allow');
  assert.equal(readParsed.body, 'confidential_patient_record');
});
