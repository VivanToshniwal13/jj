'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { dispatch } = require('../team_app.cjs');

test('Track 4 Adapter Contract Tests', async (t) => {
  await t.test('1. setup initializes state and returns ready: true', async () => {
    const res = await dispatch({
      op: 'setup',
      owners: { asset1: 'alice', asset2: 'bob' },
      contents: { asset1: 'secret-payload-1', asset2: 'secret-payload-2' },
      disabled: ['charlie'],
      key_material: 'synthetic-super-secret'
    });
    assert.deepEqual(res, { ready: true });
  });

  await t.test('2. read returns exact body for authorized owner', async () => {
    const res = await dispatch({
      op: 'read',
      actor: 'alice',
      asset: 'asset1',
      request_id: 'req-001'
    });
    assert.equal(res.decision, 'allow');
    assert.equal(res.body, 'secret-payload-1');
  });

  await t.test('3. read denies unauthorized actor without disclosing body', async () => {
    const res = await dispatch({
      op: 'read',
      actor: 'bob',
      asset: 'asset1',
      request_id: 'req-002'
    });
    assert.equal(res.decision, 'deny');
    assert.equal(res.body, undefined);
  });

  await t.test('4. read denies disabled actor', async () => {
    const res = await dispatch({
      op: 'read',
      actor: 'charlie',
      asset: 'asset1',
      request_id: 'req-003'
    });
    assert.equal(res.decision, 'deny');
  });

  await t.test('5. revoke immediately denies actor while peers retain access', async () => {
    const rev = await dispatch({ op: 'revoke', actor: 'alice' });
    assert.deepEqual(rev, {});

    const aliceRead = await dispatch({
      op: 'read',
      actor: 'alice',
      asset: 'asset1',
      request_id: 'req-004'
    });
    assert.equal(aliceRead.decision, 'deny');

    const bobRead = await dispatch({
      op: 'read',
      actor: 'bob',
      asset: 'asset2',
      request_id: 'req-005'
    });
    assert.equal(bobRead.decision, 'allow');
    assert.equal(bobRead.body, 'secret-payload-2');
  });

  await t.test('6. audit retrieves recorded request_id and decision', async () => {
    const auditRes = await dispatch({ op: 'audit', request_id: 'req-004' });
    assert.equal(auditRes.request_id, 'req-004');
    assert.equal(auditRes.decision, 'deny');

    const auditAllow = await dispatch({ op: 'audit', request_id: 'req-005' });
    assert.equal(auditAllow.request_id, 'req-005');
    assert.equal(auditAllow.decision, 'allow');
  });

  await t.test('7. protected_read interoperability with ML-KEM-768 and HMAC proof', async () => {
    // Generate ML-KEM-768 keypair in Node
    const kp = crypto.generateKeyPairSync('ml-kem-768');
    const spki = kp.publicKey.export({ format: 'der', type: 'spki' });
    const rawPk = spki.subarray(22); // 1184 bytes raw

    const prot = await dispatch({
      op: 'protected_read',
      actor: 'bob',
      asset: 'asset2',
      challenge: 'challenge-alpha',
      public_key: rawPk.toString('base64')
    });

    assert.equal(prot.decision, 'allow');
    assert.ok(prot.ciphertext);
    assert.ok(prot.proof);

    // Decapsulate with private key
    const ct = Buffer.from(prot.ciphertext, 'base64');
    const sharedSecret = crypto.decapsulate(kp.privateKey, ct);

    // Verify proof
    const expectedProof = crypto.createHmac('sha256', sharedSecret)
      .update(Buffer.from('challenge-alphasecret-payload-2', 'utf8'))
      .digest('hex')
      .toLowerCase();

    assert.equal(prot.proof, expectedProof);
  });
});
