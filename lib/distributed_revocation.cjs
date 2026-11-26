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
    this.enrolledDevices = new Map(); // actor -> { active_device_id, public_key, enrolled_at }
    this.revokedDevices = new Set(); // set of permanently revoked device IDs
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

  createSignedRevocationList(actorToRevoke, reason = 'device_loss', revokedDeviceId = null) {
    this.version++;
    if (actorToRevoke) {
      this.revokedActors.add(actorToRevoke);
    }
    if (revokedDeviceId) {
      this.revokedDevices.add(revokedDeviceId);
    }

    const payload = {
      type: 'revocation_list',
      version: this.version,
      timestamp: Date.now(),
      revoked: Array.from(this.revokedActors),
      revoked_devices: Array.from(this.revokedDevices),
      latest_revoked: actorToRevoke || null,
      latest_revoked_device: revokedDeviceId || null,
      reason
    };

    const serialized = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = crypto.sign(null, serialized, this.keyPair.privateKey);

    return {
      payload,
      signature_b64: signature.toString('base64')
    };
  }

  // Device Re-enrolment: Issues signed approval certificate for actor's new device
  createSignedEnrolment(actor, newDeviceId, newDevicePublicKeyDerB64, previousRevokedDeviceId = null) {
    this.version++;
    if (previousRevokedDeviceId) {
      this.revokedDevices.add(previousRevokedDeviceId);
    }
    // Remove actor from global blacklisted actors since new device is approved
    this.revokedActors.delete(actor);

    const enrolmentData = {
      active_device_id: newDeviceId,
      public_key: newDevicePublicKeyDerB64,
      enrolled_at: Date.now()
    };
    this.enrolledDevices.set(actor, enrolmentData);

    const payload = {
      type: 'device_enrolment',
      version: this.version,
      timestamp: Date.now(),
      actor,
      new_device_id: newDeviceId,
      new_device_pk: newDevicePublicKeyDerB64,
      revoked_devices: Array.from(this.revokedDevices),
      revoked_actors: Array.from(this.revokedActors),
      approval: 'AUTHORITY_APPROVED_RE_ENROLMENT'
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
    this.revokedDevices = new Set();
    this.enrolledDevices = new Map(); // actor -> { device_id, pk }
    this.activeKeyVersion = 1;
    this.retiringKeyVersion = null;
    this.keyCutoffTimestamp = 0;
    this.revocationFile = path.join(stateDir, 'node_revocations.json');
    this._load();
  }

  _load() {
    if (fs.existsSync(this.revocationFile)) {
      try {
        const data = JSON.parse(fs.readFileSync(this.revocationFile, 'utf8'));
        this.lastVersion = data.version || 0;
        this.revoked = new Set(data.revoked || []);
        this.revokedDevices = new Set(data.revoked_devices || []);
        this.lastSyncTimestamp = data.last_sync || Date.now();
        this.activeKeyVersion = data.active_key_version || 1;
        this.retiringKeyVersion = data.retiring_key_version || null;
        this.keyCutoffTimestamp = data.key_cutoff_timestamp || 0;
      } catch {}
    }
  }

  _save() {
    const tmp = path.join(this.stateDir, `.tmp-rev-${crypto.randomUUID()}`);
    fs.writeFileSync(tmp, JSON.stringify({
      version: this.lastVersion,
      last_sync: this.lastSyncTimestamp,
      revoked: Array.from(this.revoked),
      revoked_devices: Array.from(this.revokedDevices),
      active_key_version: this.activeKeyVersion,
      retiring_key_version: this.retiringKeyVersion,
      key_cutoff_timestamp: this.keyCutoffTimestamp
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
    if (payload.revoked_devices) {
      this.revokedDevices = new Set(payload.revoked_devices);
    }
    this.lastSyncTimestamp = Date.now();
    this._save();

    return {
      nodeId: this.nodeId,
      applied_version: this.lastVersion,
      revoked_count: this.revoked.size,
      enforced_at: this.lastSyncTimestamp
    };
  }

  // Apply signed device re-enrolment
  applyEnrolment(signedEnrolment) {
    if (this.isPartitioned) {
      throw new Error(`[Node ${this.nodeId}] Network partition: unable to reach node`);
    }

    const { payload, signature_b64 } = signedEnrolment;
    const serialized = Buffer.from(JSON.stringify(payload), 'utf8');
    const signature = Buffer.from(signature_b64, 'base64');

    const verified = crypto.verify(null, serialized, this.authorityPublicKey, signature);
    if (!verified) {
      throw new Error(`[Node ${this.nodeId}] Invalid authority signature on enrolment`);
    }

    if (payload.version < this.lastVersion) {
      throw new Error(`[Node ${this.nodeId}] Replay attack detected on enrolment`);
    }

    this.lastVersion = payload.version;
    // Un-revoke actor for new device while keeping old device permanently revoked
    this.revoked.delete(payload.actor);
    if (payload.revoked_devices) {
      payload.revoked_devices.forEach(d => this.revokedDevices.add(d));
    }
    this.enrolledDevices.set(payload.actor, {
      device_id: payload.new_device_id,
      pk: payload.new_device_pk
    });
    this.lastSyncTimestamp = Date.now();
    this._save();

    return {
      nodeId: this.nodeId,
      applied_version: this.lastVersion,
      actor: payload.actor,
      active_device: payload.new_device_id,
      status: 'enrolled'
    };
  }

  // Key Rotation distribution to nodes with documented cutoff
  applyKeyRotation(activeVersion, retiringVersion, cutoffTimestamp) {
    this.activeKeyVersion = activeVersion;
    this.retiringKeyVersion = retiringVersion;
    this.keyCutoffTimestamp = cutoffTimestamp;
    this._save();
    return {
      nodeId: this.nodeId,
      activeKeyVersion: this.activeKeyVersion,
      retiringKeyVersion: this.retiringKeyVersion,
      cutoffTimestamp: this.keyCutoffTimestamp
    };
  }

  isActorRevoked(actor, deviceId = null) {
    const freshness = this.checkFreshness();
    if (!freshness.fresh) {
      return true; // Fail closed if stale
    }
    if (deviceId && this.revokedDevices.has(deviceId)) {
      return true; // Device is specifically revoked
    }
    return this.revoked.has(actor);
  }

  // Goal 1: Check whether a key version is valid at timestamp.
  // Rejects old key after cutoff on every node. In-flight allowed before cutoff.
  isKeyVersionAccepted(keyVersion, requestTimestamp = Date.now(), isInFlight = false) {
    if (keyVersion === this.activeKeyVersion) {
      return { accepted: true, state: 'active' };
    }
    if (keyVersion === this.retiringKeyVersion) {
      // In-flight authorized requests started before cutoff can complete
      if (isInFlight && requestTimestamp <= this.keyCutoffTimestamp) {
        return { accepted: true, state: 'retiring_inflight_allowed' };
      }
      // After cutoff, strictly reject
      if (requestTimestamp > this.keyCutoffTimestamp) {
        return { accepted: false, reason: 'KEY_VERSION_CUTOFF_EXPIRED: v1 is retired' };
      }
      // New requests during grace period
      return { accepted: true, state: 'retiring_grace_period' };
    }
    return { accepted: false, reason: `KEY_VERSION_UNKNOWN_OR_RETIRED: v${keyVersion}` };
  }
}

// Broadcast with partition handling and measured catch-up
async function broadcastRevocation(authority, nodes, actorToRevoke, reason = 'device_loss', deviceId = null) {
  const startTime = Date.now();
  const signedList = authority.createSignedRevocationList(actorToRevoke, reason, deviceId);

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

  let catchUpLatencyMs = 0;
  if (partitionedNodes.length > 0) {
    const catchUpStart = Date.now();
    for (const node of partitionedNodes) {
      node.setPartitioned(false);
      const res = node.applyRevocationList(signedList);
      results.push({ ...res, latencyMs: Date.now() - catchUpStart, status: 'caught_up' });
    }
    catchUpLatencyMs = Date.now() - catchUpStart;
  }

  const totalTimeWithCatchUpMs = Date.now() - startTime;

  return {
    actor: actorToRevoke,
    device_id: deviceId,
    version: signedList.payload.version,
    node_count: nodes.length,
    initial_broadcast_ms: initialBroadcastTimeMs,
    total_propagation_ms: totalTimeWithCatchUpMs,
    total_propagation_with_catchup_ms: totalTimeWithCatchUpMs,
    environment_note: 'single-host simulation',
    node_results: results
  };
}

// Broadcast re-enrolment across nodes
async function broadcastEnrolment(authority, nodes, actor, newDeviceId, newDevicePkB64, previousRevokedDeviceId = null) {
  const startTime = Date.now();
  const signedEnrolment = authority.createSignedEnrolment(actor, newDeviceId, newDevicePkB64, previousRevokedDeviceId);

  const results = [];
  for (const node of nodes) {
    const nodeStart = Date.now();
    const res = node.applyEnrolment(signedEnrolment);
    results.push({ ...res, latencyMs: Date.now() - nodeStart, status: 'enrolled' });
  }

  return {
    actor,
    new_device_id: newDeviceId,
    previous_device_id: previousRevokedDeviceId,
    version: signedEnrolment.payload.version,
    node_count: nodes.length,
    total_propagation_ms: Date.now() - startTime,
    node_results: results
  };
}

module.exports = {
  DEFAULT_MAX_STALENESS_MS,
  DistributedRevocationAuthority,
  DistributedNode,
  broadcastRevocation,
  broadcastEnrolment
};
