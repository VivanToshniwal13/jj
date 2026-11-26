'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('Hardening 1: Prototype Pollution & Boundary Testing', async (t) => {
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-proto-'));
  process.env.TRACK4_STATE_DIR = testDir;
  const { dispatch } = require('../team_app.cjs');

  await t.test('Dangerous property names as IDs do not pollute Object.prototype', async () => {
    // Initial setup with prototype-like IDs parsed from JSON string (as from incoming stdin)
    const rawJson = '{"op":"setup","owners":{"__proto__":"constructor","prototype":"toString"},"contents":{"__proto__":"payload-for-proto","prototype":"payload-for-prototype"},"disabled":["valueOf"],"key_material":"marker-sensitive-xyz"}';
    const setupPayload = JSON.parse(rawJson);

    await dispatch(setupPayload);

    // Verify Object.prototype is untainted
    assert.equal({}.polluted, undefined);
    assert.equal(Object.prototype.polluted, undefined);
    assert.equal(typeof ({}).toString, 'function');
    assert.equal(typeof ({}).valueOf, 'function');

    // Read using constructor as actor for __proto__ asset
    const res1 = await dispatch({
      op: 'read',
      actor: 'constructor',
      asset: '__proto__',
      request_id: 'req-proto-1'
    });
    assert.equal(res1.decision, 'allow');
    assert.equal(res1.body, 'payload-for-proto');

    // Revoke 'constructor'
    await dispatch({ op: 'revoke', actor: 'constructor' });

    const res2 = await dispatch({
      op: 'read',
      actor: 'constructor',
      asset: '__proto__',
      request_id: 'req-proto-2'
    });
    assert.equal(res2.decision, 'deny');
  });

  await t.test('Rejects non-string types and invalid bounds', async () => {
    // Non-string actor
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: 12345, asset: 'asset1', request_id: 'r1' });
    });

    // Array actor
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: ['admin'], asset: 'asset1', request_id: 'r2' });
    });

    // Object asset
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: 'user', asset: { id: 'asset1' }, request_id: 'r3' });
    });

    // Overly long ID (> 256 chars)
    const longId = 'a'.repeat(300);
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: longId, asset: 'asset1', request_id: 'r4' });
    });

    // Empty ID
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: '', asset: 'asset1', request_id: 'r5' });
    });

    // ID with NUL character
    await assert.rejects(async () => {
      await dispatch({ op: 'read', actor: 'user\0admin', asset: 'asset1', request_id: 'r6' });
    });
  });
});
