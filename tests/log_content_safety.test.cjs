'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
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

test('Log Content Safety: audit.log never contains asset bodies, key material, or shared secrets', async () => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-log-safety-'));
  const env = { TRACK4_STATE_DIR: stateDir };

  const CANARY_KEY_MATERIAL = 'SUPER-SECRET-KEK-KEY-MATERIAL-DO-NOT-LEAK-XYZ789';
  const CANARY_ASSET_BODY = 'CONFIDENTIAL-PATIENT-CLINICAL-RECORDS-DO-NOT-LEAK-456';
  const ASSET_ID = 'patient-doc-1';
  const ACTOR_ID = 'dr-alice';

  // 1. Setup
  await runService({
    op: 'setup',
    owners: { [ASSET_ID]: ACTOR_ID },
    contents: { [ASSET_ID]: CANARY_ASSET_BODY },
    disabled: [],
    key_material: CANARY_KEY_MATERIAL
  }, env);

  // 2. Normal read
  await runService({
    op: 'read',
    actor: ACTOR_ID,
    asset: ASSET_ID,
    request_id: 'safety-req-1'
  }, env);

  // 3. Protected read (generates KEM ciphertext & shared secret)
  const kemKp = crypto.generateKeyPairSync('ml-kem-768');
  const spki = kemKp.publicKey.export({ format: 'der', type: 'spki' });
  const rawPkB64 = spki.subarray(22).toString('base64');

  const protRes = await runService({
    op: 'protected_read',
    actor: ACTOR_ID,
    asset: ASSET_ID,
    challenge: 'canary-challenge-999',
    public_key: rawPkB64,
    request_id: 'safety-prot-req-2'
  }, env);

  assert.equal(protRes.code, 0);

  // 4. Revoke
  await runService({
    op: 'revoke',
    actor: ACTOR_ID
  }, env);

  // 5. Inspect audit.log content
  const logPath = path.join(stateDir, 'audit.log');
  assert.ok(fs.existsSync(logPath), 'audit.log must exist');
  const logContent = fs.readFileSync(logPath, 'utf8');

  // ASSERTION: Never contains plaintext secret bodies or key material
  assert.equal(logContent.includes(CANARY_KEY_MATERIAL), false, 'CRITICAL: key_material leaked in audit.log!');
  assert.equal(logContent.includes(CANARY_ASSET_BODY), false, 'CRITICAL: asset body leaked in audit.log!');

  // Validate every line in audit.log contains ONLY safe metadata
  const lines = logContent.split('\n').filter(l => l.trim().length > 0);
  for (const line of lines) {
    const entry = JSON.parse(line);
    if (entry.type === 'record') {
      // Must contain expected fields
      assert.ok(['record'].includes(entry.type));
      assert.ok(typeof entry.index === 'number');
      assert.ok(typeof entry.timestamp === 'number');
      assert.ok(typeof entry.prev_hash === 'string');
      assert.ok(typeof entry.hash === 'string');
      assert.ok(typeof entry.actor === 'string');
      assert.ok(typeof entry.op === 'string');
      assert.ok(typeof entry.details === 'object');

      // Assert details does not contain any body or secret
      assert.equal(entry.details.body, undefined);
      assert.equal(entry.details.key, undefined);
      assert.equal(entry.details.shared_secret, undefined);
      assert.equal(entry.details.key_material, undefined);
    }
  }
});
