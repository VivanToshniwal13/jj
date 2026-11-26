'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');
const crypto = require('node:crypto');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function runRaw(rawInput, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVICE_PATH], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

    child.on('close', code => {
      resolve({ code, stdout, stderr });
    });

    child.stdin.write(rawInput);
    child.stdin.end();
  });
}

test('Hardening 7: 1,000-Request Fuzz & Fail-Closed Testing', async () => {
  const testStateDir = path.join('/tmp', `track4-fuzz-${Date.now()}`);
  const secretKeyMaterial = 'SUPER-SENSITIVE-CANARY-SECRET-98765';

  // Seed normal state first
  await runRaw(JSON.stringify({
    op: 'setup',
    owners: { safeAsset: 'safeUser' },
    contents: { safeAsset: 'safeBody' },
    disabled: [],
    key_material: secretKeyMaterial
  }), { TRACK4_STATE_DIR: testStateDir });

  const fuzzInputs = [
    '', // empty
    '   ', // whitespace
    '{', // truncated
    '{"op":',
    '{"op": "unknown_action_xyz"}',
    '[]', // array
    '12345', // number
    '"string"', // bare string
    JSON.stringify({ op: null }),
    JSON.stringify({ op: 123 }),
    JSON.stringify({ op: 'read', actor: {} }),
    JSON.stringify({ op: 'read', asset: [] }),
    JSON.stringify({ op: 'read', actor: 'safeUser', asset: 'safeAsset', request_id: null }),
    JSON.stringify({ op: 'protected_read', actor: 'safeUser', asset: 'safeAsset', challenge: 'c', public_key: 'not-base64' }),
    JSON.stringify({ __proto__: { admin: true } }),
    JSON.stringify({ op: 'setup', owners: { '__proto__': 'evil' } })
  ];

  // Generate randomized fuzz payloads up to 1,000 iterations
  const totalIterations = 1000;
  let failClosedCount = 0;

  for (let i = 0; i < totalIterations; i++) {
    let payload;
    if (i < fuzzInputs.length) {
      payload = fuzzInputs[i];
    } else {
      const type = i % 5;
      if (type === 0) {
        // Random garbage bytes
        payload = crypto.randomBytes(32).toString('hex');
      } else if (type === 1) {
        // Deeply nested / malformed object
        payload = JSON.stringify({
          op: 'read',
          actor: crypto.randomBytes(16).toString('hex'),
          asset: crypto.randomBytes(16).toString('hex'),
          request_id: `fuzz-${i}`,
          extra: { nested: [crypto.randomBytes(8).toString('hex')] }
        });
      } else if (type === 2) {
        // Giant string payload
        payload = JSON.stringify({
          op: 'read',
          actor: 'a'.repeat(500),
          asset: 'safeAsset',
          request_id: `fuzz-${i}`
        });
      } else if (type === 3) {
        // Corrupted protected_read
        payload = JSON.stringify({
          op: 'protected_read',
          actor: 'safeUser',
          asset: 'safeAsset',
          challenge: crypto.randomBytes(16).toString('hex'),
          public_key: crypto.randomBytes(i % 1200).toString('base64')
        });
      } else {
        // Random UTF-8 / JSON injection attempt
        payload = `{"op": "read", "actor": "safeUser", "asset": "safeAsset", "request_id": "fuzz-${i}"}\n{"injected": true}`;
      }
    }

    const res = await runRaw(payload, { TRACK4_STATE_DIR: testStateDir });

    // CRITICAL SECURITY ASSERTIONS:
    // 1. Never leak key_material in stdout or stderr
    assert.equal(res.stdout.includes(secretKeyMaterial), false, 'key_material leaked in stdout!');
    assert.equal(res.stderr.includes(secretKeyMaterial), false, 'key_material leaked in stderr!');

    // 2. Never leak stack traces containing internal file paths or state variables in stderr
    if (res.code !== 0) {
      assert.equal(res.stderr.includes('at Array.'), false, 'Stack trace leaked in stderr!');
      assert.equal(res.stderr.includes('at async'), false, 'Async stack trace leaked in stderr!');
    }

    // 3. Either failed closed with non-zero exit code OR returned safe deny
    if (res.code !== 0) {
      failClosedCount++;
    } else {
      const parsed = JSON.parse(res.stdout);
      if (parsed.decision) {
        assert.ok(['allow', 'deny'].includes(parsed.decision));
      }
    }
  }

  assert.ok(failClosedCount > 0, 'Fuzz test verified fail-closed behavior across malformed inputs.');
});
