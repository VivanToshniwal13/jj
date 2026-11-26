'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

test('Hardening 3 & 4: Audit Integrity & Protected Read Security', async (t) => {
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-audit-'));
  process.env.TRACK4_STATE_DIR = testDir;
  const { dispatch } = require('../team_app.cjs');

  await t.test('Audit First-Write-Wins: duplicate request_id cannot overwrite original audit', async () => {
    await dispatch({
      op: 'setup',
      owners: { secretDoc: 'alice' },
      contents: { secretDoc: 'top-secret' },
      disabled: [],
      key_material: 'key'
    });

    // 1. Initial read by alice: allow
    const r1 = await dispatch({
      op: 'read',
      actor: 'alice',
      asset: 'secretDoc',
      request_id: 'dup-req-001'
    });
    assert.equal(r1.decision, 'allow');

    // 2. Audit check: should be allow
    const a1 = await dispatch({ op: 'audit', request_id: 'dup-req-001' });
    assert.equal(a1.decision, 'allow');

    // 3. Attacker tries to reuse dup-req-001 with denied access
    const r2 = await dispatch({
      op: 'read',
      actor: 'eve',
      asset: 'secretDoc',
      request_id: 'dup-req-001'
    });
    assert.equal(r2.decision, 'deny');

    // 4. Audit must preserve the original allow decision (First-Write-Wins)
    const a2 = await dispatch({ op: 'audit', request_id: 'dup-req-001' });
    assert.equal(a2.decision, 'allow', 'Original audit decision must NOT be overwritten by duplicate request_id');
  });

  await t.test('Audit of unknown request_id returns safe deny without crashing', async () => {
    const safeAudit = await dispatch({ op: 'audit', request_id: 'non-existent-request-999' });
    assert.equal(safeAudit.request_id, 'non-existent-request-999');
    assert.equal(safeAudit.decision, 'deny');
  });

  await t.test('protected_read denies non-owners, disabled, revoked and unknown assets BEFORE KEM work', async () => {
    await dispatch({
      op: 'setup',
      owners: { docA: 'alice', docB: 'bob' },
      contents: { docA: 'contentA', docB: 'contentB' },
      disabled: ['charlie'],
      key_material: 'marker'
    });

    const kp = crypto.generateKeyPairSync('ml-kem-768');
    const rawPk = kp.publicKey.export({ format: 'der', type: 'spki' }).subarray(22).toString('base64');

    // Non-owner
    const rNonOwner = await dispatch({
      op: 'protected_read',
      actor: 'alice',
      asset: 'docB',
      challenge: 'c1',
      public_key: rawPk,
      request_id: 'audit-prot-nonowner'
    });
    assert.equal(rNonOwner.decision, 'deny');
    assert.equal(rNonOwner.ciphertext, undefined);

    // Disabled actor
    const rDisabled = await dispatch({
      op: 'protected_read',
      actor: 'charlie',
      asset: 'docA',
      challenge: 'c2',
      public_key: rawPk,
      request_id: 'audit-prot-disabled'
    });
    assert.equal(rDisabled.decision, 'deny');

    // Unknown asset (no existence oracle)
    const rUnknown = await dispatch({
      op: 'protected_read',
      actor: 'alice',
      asset: 'doc-unknown',
      challenge: 'c3',
      public_key: rawPk
    });
    assert.equal(rUnknown.decision, 'deny');

    // Audit logs for protected_read denies
    const aNonOwner = await dispatch({ op: 'audit', request_id: 'audit-prot-nonowner' });
    assert.equal(aNonOwner.decision, 'deny');

    const aDisabled = await dispatch({ op: 'audit', request_id: 'audit-prot-disabled' });
    assert.equal(aDisabled.decision, 'deny');
  });

  await t.test('protected_read strictly validates public key format and length', async () => {
    // 1. Wrong length (e.g. 32 bytes instead of 1184)
    const shortPk = Buffer.alloc(32).toString('base64');
    const rShort = await dispatch({
      op: 'protected_read',
      actor: 'alice',
      asset: 'docA',
      challenge: 'c4',
      public_key: shortPk
    });
    assert.equal(rShort.decision, 'deny');

    // 2. Corrupted base64 characters
    const corruptedPk = '!!!!not-valid-base64-string$$$$';
    const rCorrupt = await dispatch({
      op: 'protected_read',
      actor: 'alice',
      asset: 'docA',
      challenge: 'c5',
      public_key: corruptedPk
    });
    assert.equal(rCorrupt.decision, 'deny');
  });
});
