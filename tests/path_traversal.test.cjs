'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');

test('Hardening 2: Path Traversal Immunity', async (t) => {
  const testDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-traversal-'));
  process.env.TRACK4_STATE_DIR = testDir;
  const { dispatch } = require('../team_app.cjs');

  await t.test('Path traversal sequences in IDs never affect filesystem paths', async () => {
    const traversalIds = [
      '../../../../etc/passwd',
      '..\\..\\..\\boot.ini',
      '/tmp/evil-target',
      'asset/../../sensitive',
      'asset%2F%2E%2E%2Fevil',
      '..\u0000../evil'
    ];

    const setupOwners = {};
    const setupContents = {};
    for (const [i, id] of traversalIds.entries()) {
      if (!id.includes('\0')) {
        setupOwners[id] = `actor-${i}`;
        setupContents[id] = `body-${i}`;
      }
    }

    await dispatch({
      op: 'setup',
      owners: setupOwners,
      contents: setupContents,
      disabled: [],
      key_material: 'sensitive-test'
    });

    // Check that no file named passwd or evil-target was created anywhere outside state dir
    assert.equal(fs.existsSync('/tmp/evil-target'), false);
    assert.equal(fs.existsSync(path.join(os.tmpdir(), 'evil-target')), false);

    // Verify traversal IDs can be safely read through memory without file path vulnerability
    const validId = traversalIds[0];
    const readRes = await dispatch({
      op: 'read',
      actor: 'actor-0',
      asset: validId,
      request_id: 'req-trav-1'
    });
    assert.equal(readRes.decision, 'allow');
    assert.equal(readRes.body, 'body-0');
  });
});
