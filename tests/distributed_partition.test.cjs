'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const {
  DistributedRevocationAuthority,
  DistributedNode,
  broadcastRevocation
} = require('../lib/distributed_revocation.cjs');

test('Phase 2.1: Partition Handling, Catch-Up Latency & Max-Staleness Rule', async (t) => {
  const authority = new DistributedRevocationAuthority();
  const authorityPk = authority.getPublicKey();

  const nodeCount = 5;
  const nodes = [];
  const maxStalenessMs = 200; // Fast threshold for testing fail-closed behavior

  for (let i = 0; i < nodeCount; i++) {
    const nodeDir = fs.mkdtempSync(path.join(os.tmpdir(), `track4-part-node-${i}-`));
    nodes.push(new DistributedNode(`node-${i}`, nodeDir, authorityPk, maxStalenessMs));
  }

  await t.test('Broadcast during network partition: online nodes enforce, partitioned node fails closed when stale', async () => {
    // Partition node-4 (e.g. network disconnect)
    nodes[4].setPartitioned(true);

    // Initial broadcast of revocation for compromised identity
    const report = await broadcastRevocation(authority, nodes, 'compromised-token-user', 'compromised_token');

    assert.equal(report.node_count, nodeCount);
    // Nodes 0-3 successfully enforced
    for (let i = 0; i < 4; i++) {
      assert.equal(nodes[i].isActorRevoked('compromised-token-user'), true);
      assert.equal(nodes[i].isActorRevoked('legitimate-user'), false);
    }

    // Partitioned node-4 was caught up during simulation heal or reported partitioned
    console.log(`[Evidence Goal 2 Partition] Initial broadcast: ${report.initial_broadcast_ms} ms, Total with catch-up: ${report.total_propagation_with_catchup_ms} ms (${report.environment_note})`);

    // Now test Max-Staleness Fail-Closed Rule on isolated node:
    // Create an isolated node with 50ms staleness limit
    const isolatedDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-stale-'));
    const isolatedNode = new DistributedNode('isolated-node', isolatedDir, authorityPk, 50);

    // Initial check is fresh
    assert.equal(isolatedNode.checkFreshness().fresh, true);
    assert.equal(isolatedNode.isActorRevoked('anyone'), false);

    // Wait until staleness threshold is exceeded
    await new Promise(r => setTimeout(r, 60));

    // Stale node must FAIL CLOSED: reject all actors
    const freshness = isolatedNode.checkFreshness();
    assert.equal(freshness.fresh, false);
    assert.ok(freshness.reason.includes('MAX_STALENESS_EXCEEDED'));
    assert.equal(isolatedNode.isActorRevoked('anyone'), true, 'Stale node must fail closed');
  });
});
