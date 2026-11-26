'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const DEFAULT_MAX_STALENESS_MS = 5000; // 5 seconds max staleness rule

class DistributedRevocationAuthority {
  constructor(authorityKeyPair = null, stateDir = null) {
    this.stateDir = stateDir;
    this.keyPair = authorityKeyPair || this._loadOrGenerateKey();
    this.version = 0;
    this.revokedActors = new Set();
  }

  _loadOrGenerateKey() {
    const keyPath = process.env.TRACK4_AUTHORITY_KEY_PATH || 
      (this.stateDir ? path.join(this.stateDir, 'authority_mldsa_sk.bin') : null);

    if (keyPath && fs.existsSync(keyPath)) {
      try {
        const raw = fs.readFileSync(keyPath);
        return crypto.createPrivateKey({ key: raw, format: 'der', type: 'pkcs8' });
      } catch {}
    }

    const kp = crypto.generateKeyPairSync('ml-dsa-65');
    if (keyPath) {
      try {
        const der = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
        fs.writeFileSync(keyPath, der, { mode: 0o600 });
      } catch {}
    }
    return kp;
  }

  getPublicKey() {
    return this.keyPair.publicKey;
  }

  createSignedRevocationList(actorToRevoke, reason = 'device_loss') {
    this.version++;
    if (actorToRevoke) {
      this.revokedActors.add(actorToRevoke);
    }

    const payload = {
      version: this.version,
      timestamp: Date.now(),
      revoked: Array.from(this.revokedActors),
      latest_revoked: actorToRevoke || null,
      reason
    };

    const serialized = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = crypto.sign(null, serialized, this.keyPair.privateKey);

    return {
      payload,
      signature_b64: signature.toString('base64')
    };
  }
}

class DistributedNode {
  constructor(nodeId, stateDir, authorityPublicKey, maxStalenessMs = DEFAULT_MAX_STALENESS_MS) {
    this.nodeId = nodeId;
    this.stateDir = stateDir;
    this.authorityPublicKey = authorityPublicKey;
    this.maxStalenessMs = maxStalenessMs;
    this.lastVersion = 0;
    this.lastSyncTimestamp = Date.now();
    this.isPartitioned = false;
    this.revoked = new Set();
    this.revocationFile = path.join(stateDir, 'node_revocations.json');
    this._load();
  }

  _load() {
    if (fs.existsSync(this.revocationFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(this.revocationFile, 'utf8'));
        this.lastVersion = data.version || 0;
        this.revoked = new Set(data.revoked || []);
        this.lastSyncTimestamp = data.last_sync || Date.now();
      } catch {}
    }
  }

  _save() {
    const tmp = path.join(this.stateDir, `.tmp-rev-${crypto.randomUUID()}`);
    fs.writeFileSync(tmp, JSON.stringify({
      version: this.lastVersion,
      last_sync: this.lastSyncTimestamp,
      revoked: Array.from(this.revoked)
    }, null, 2), { mode: 0o600 });
    const fd = fs.openSync(tmp, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.revocationFile);
  }

  setPartitioned(partitioned) {
    this.isPartitioned = Boolean(partitioned);
  }

  // Max-staleness rule: fails closed if stale
  checkFreshness(now = Date.now()) {
    if (now - this.lastSyncTimestamp > this.maxStalenessMs) {
      return { fresh: false, reason: 'MAX_STALENESS_EXCEEDED: Node failed closed' };
    }
    return { fresh: true };
  }

  applyRevocationList(signedList) {
    if (this.isPartitioned) {
      throw new Error(`[Node ${this.nodeId}] Network partition: unable to reach node`);
    }

    const { payload, signature_b64 } = signedList;
    const serialized = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = Buffer.from(signature_b64, 'base64');

    // 1. Verify ML-DSA-65 signature
    const verified = crypto.verify(null, serialized, this.authorityPublicKey, signature);
    if (!verified) {
      throw new Error(`[Node ${this.nodeId}] Invalid authority signature on revocation list`);
    }

    // 2. Monotonic version validation
    if (payload.version < this.lastVersion) {
      throw new Error(`[Node ${this.nodeId}] Replay attack detected: current ${this.lastVersion}, received ${payload.version}`);
    }

    // 3. Apply and persist
    this.lastVersion = payload.version;
    this.revoked = new Set(payload.revoked);
    this.lastSyncTimestamp = Date.now();
    this._save();

    return {
      nodeId: this.nodeId,
      applied_version: this.lastVersion,
      revoked_count: this.revoked.size,
      enforced_at: this.lastSyncTimestamp
    };
  }

  isActorRevoked(actor) {
    // If node exceeds staleness threshold, fail closed
    const freshness = this.checkFreshness();
    if (!freshness.fresh) {
      return true; // Treat all actors as revoked/denied when stale
    }
    return this.revoked.has(actor);
  }
}

// Broadcast with partition handling and measured catch-up
async function broadcastRevocation(authority, nodes, actorToRevoke, reason = 'device_loss') {
  const startTime = Date.now();
  const signedList = authority.createSignedRevocationList(actorToRevoke, reason);

  const results = [];
  const partitionedNodes = [];

  for (const node of nodes) {
    const nodeStart = Date.now();
    try {
      const res = node.applyRevocationList(signedList);
      results.push({ ...res, latencyMs: Date.now() - nodeStart, status: 'enforced' });
    } catch (err) {
      partitionedNodes.push(node);
      results.push({ nodeId: node.nodeId, status: 'partitioned', error: err.message });
    }
  }

  const initialBroadcastTimeMs = Date.now() - startTime;

  // Simulate catch-up for partitioned nodes
  let catchUpLatencyMs = 0;
  if (partitionedNodes.length > 0) {
    const catchUpStart = Date.now();
    for (const node of partitionedNodes) {
      // Heal partition
      node.setPartitioned(false);
      const res = node.applyRevocationList(signedList);
      results.push({ ...res, latencyMs: Date.now() - catchUpStart, status: 'caught_up' });
    }
    catchUpLatencyMs = Date.now() - catchUpStart;
  }

  const totalTimeWithCatchUpMs = Date.now() - startTime;

  return {
    actor: actorToRevoke,
    version: signedList.payload.version,
    node_count: nodes.length,
    initial_broadcast_ms: initialBroadcastTimeMs,
    total_propagation_ms: totalTimeWithCatchUpMs,
    total_propagation_with_catchup_ms: totalTimeWithCatchUpMs,
    environment_note: 'single-host simulation',
    node_results: results
  };
}

module.exports = {
  DEFAULT_MAX_STALENESS_MS,
  DistributedRevocationAuthority,
  DistributedNode,
  broadcastRevocation
};
