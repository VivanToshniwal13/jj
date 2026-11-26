'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class DistributedRevocationAuthority {
  constructor(authorityKeyPair = null) {
    // Generate or use authority ML-DSA-65 keypair
    this.keyPair = authorityKeyPair || crypto.generateKeyPairSync('ml-dsa-65');
    this.version = 0;
    this.revokedActors = new Set();
  }

  getPublicKey() {
    return this.keyPair.publicKey;
  }

  createSignedRevocationList(actorToRevoke, reason = 'device_loss') {
    this.version++;
    this.revokedActors.add(actorToRevoke);

    const payload = {
      version: this.version,
      timestamp: Date.now(),
      revoked: Array.from(this.revokedActors),
      latest_revoked: actorToRevoke,
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
  constructor(nodeId, stateDir, authorityPublicKey) {
    this.nodeId = nodeId;
    this.stateDir = stateDir;
    this.authorityPublicKey = authorityPublicKey;
    this.lastVersion = 0;
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
      } catch {}
    }
  }

  _save() {
    const tmp = path.join(this.stateDir, `.tmp-rev-${crypto.randomUUID()}`);
    fs.writeFileSync(tmp, JSON.stringify({
      version: this.lastVersion,
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

  applyRevocationList(signedList) {
    const { payload, signature_b64 } = signedList;
    const serialized = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = Buffer.from(signature_b64, 'base64');

    // 1. Verify ML-DSA-65 signature from trusted authority
    const verified = crypto.verify(null, serialized, this.authorityPublicKey, signature);
    if (!verified) {
      throw new Error(`[Node ${this.nodeId}] Invalid authority signature on revocation list`);
    }

    // 2. Enforce monotonic version check (reject replay of old lists)
    if (payload.version <= this.lastVersion) {
      throw new Error(`[Node ${this.nodeId}] Stale or replayed revocation list (current ${this.lastVersion}, received ${payload.version})`);
    }

    // 3. Apply revocation list and persist
    this.lastVersion = payload.version;
    this.revoked = new Set(payload.revoked);
    this._save();

    return {
      nodeId: this.nodeId,
      applied_version: this.lastVersion,
      revoked_count: this.revoked.size,
      enforced_at: Date.now()
    };
  }

  isActorRevoked(actor) {
    return this.revoked.has(actor);
  }
}

// Measure propagation across N simulated nodes
async function broadcastRevocation(authority, nodes, actorToRevoke, reason = 'device_loss') {
  const startTime = Date.now();
  const signedList = authority.createSignedRevocationList(actorToRevoke, reason);

  const results = [];
  for (const node of nodes) {
    const nodeStart = Date.now();
    const res = node.applyRevocationList(signedList);
    const latencyMs = Date.now() - nodeStart;
    results.push({ ...res, latencyMs });
  }

  const totalPropagationTimeMs = Date.now() - startTime;
  return {
    actor: actorToRevoke,
    version: signedList.payload.version,
    node_count: nodes.length,
    total_propagation_ms: totalPropagationTimeMs,
    node_results: results
  };
}

module.exports = {
  DistributedRevocationAuthority,
  DistributedNode,
  broadcastRevocation
};
