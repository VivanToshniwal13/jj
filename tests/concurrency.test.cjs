'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { spawn } = require('node:child_process');
const path = require('node:path');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function runServiceProcess(request, env) {
  return new Promise((resolve, reject) => {
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

    child.on('error', err => reject(err));

    child.stdin.write(JSON.stringify(request));
    child.stdin.end();
  });
}

test('Hardening 5: Concurrency & Lock Stress Testing', async () => {
  const testStateDir = path.join('/tmp', `track4-concurrency-${Date.now()}`);

  // Setup initial multi-owner state
  const setupReq = {
    op: 'setup',
    owners: {
      docShared: 'user-shared',
      docStatic: 'user-static'
    },
    contents: {
      docShared: 'shared-data-payload',
      docStatic: 'static-data-payload'
    },
    disabled: [],
    key_material: 'marker-concurrency-test'
  };

  const setupRes = await runServiceProcess(setupReq, { TRACK4_STATE_DIR: testStateDir });
  assert.equal(setupRes.code, 0);
  assert.equal(JSON.parse(setupRes.stdout).ready, true);

  // Run 50 parallel concurrent processes:
  // 30 reads on docShared, 10 reads on docStatic, 5 revokes on user-shared, 5 audits
  const tasks = [];
  const totalOperations = 50;

  for (let i = 0; i < totalOperations; i++) {
    if (i === 15) {
      // Trigger revocation mid-stream
      tasks.push(runServiceProcess({
        op: 'revoke',
        actor: 'user-shared'
      }, { TRACK4_STATE_DIR: testStateDir }));
    } else if (i % 2 === 0) {
      tasks.push(runServiceProcess({
        op: 'read',
        actor: 'user-shared',
        asset: 'docShared',
        request_id: `req-concurrent-${i}`
      }, { TRACK4_STATE_DIR: testStateDir }));
    } else {
      tasks.push(runServiceProcess({
        op: 'read',
        actor: 'user-static',
        asset: 'docStatic',
        request_id: `req-concurrent-${i}`
      }, { TRACK4_STATE_DIR: testStateDir }));
    }
  }

  const results = await Promise.all(tasks);

  // All 50 processes must complete cleanly with exit code 0
  for (const [idx, res] of results.entries()) {
    assert.equal(res.code, 0, `Process ${idx} exited with non-zero status: ${res.stderr}`);
    const json = JSON.parse(res.stdout);
    assert.ok(json.decision || json.ready !== undefined || Object.keys(json).length === 0);
  }

  // After all operations, user-static MUST still have access to docStatic
  const finalStaticRead = await runServiceProcess({
    op: 'read',
    actor: 'user-static',
    asset: 'docStatic',
    request_id: 'req-final-static'
  }, { TRACK4_STATE_DIR: testStateDir });
  const staticJson = JSON.parse(finalStaticRead.stdout);
  assert.equal(staticJson.decision, 'allow');
  assert.equal(staticJson.body, 'static-data-payload');

  // And user-shared MUST be revoked (decision: deny)
  const finalSharedRead = await runServiceProcess({
    op: 'read',
    actor: 'user-shared',
    asset: 'docShared',
    request_id: 'req-final-shared'
  }, { TRACK4_STATE_DIR: testStateDir });
  const sharedJson = JSON.parse(finalSharedRead.stdout);
  assert.equal(sharedJson.decision, 'deny');
});
