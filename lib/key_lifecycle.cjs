'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

// Key States
const KeyState = {
  PENDING: 'pending',
  ACTIVE: 'active',
  RETIRING: 'retiring',
  RETIRED: 'retired',
  REVOKED: 'revoked'
};

class KeyLifecycleManager {
  constructor(stateDir, gracePeriodMs = 500) {
    this.stateDir = stateDir;
    this.gracePeriodMs = gracePeriodMs;
    this.keysFile = path.join(stateDir, 'key_registry.json');
    this.walFile = path.join(stateDir, 'rotation.wal');
    this._ensureDir();
    this.recoverWal();
  }

  _ensureDir() {
    if (!fs.existsSync(this.stateDir)) {
      fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
    }
  }

  _appendWal(stage, data = {}) {
    const entry = JSON.stringify({
      timestamp: Date.now(),
      stage,
      data
    }) + '\n';
    fs.appendFileSync(this.walFile, entry, { mode: 0o600 });
    const fd = fs.openSync(this.walFile, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  _loadRegistry() {
    if (!fs.existsSync(this.keysFile)) {
      const initialKey = {
        version: 1,
        keyHex: crypto.randomBytes(32).toString('hex'),
        state: KeyState.ACTIVE,
        created_at: Date.now(),
        activated_at: Date.now(),
        retiring_until: null,
        retired_at: null
      };
      const registry = {
        active_version: 1,
        keys: [initialKey]
      };
      this._saveRegistry(registry);
      return registry;
    }
    return JSON.parse(fs.readFileSync(this.keysFile, 'utf8'));
  }

  _saveRegistry(registry) {
    const tmp = path.join(this.stateDir, `.tmp-reg-${crypto.randomUUID()}`);
    fs.writeFileSync(tmp, JSON.stringify(registry, null, 2), { mode: 0o600 });
    const fd = fs.openSync(tmp, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.keysFile);
  }

  getActiveKey() {
    const reg = this._loadRegistry();
    const now = Date.now();
    let changed = false;
    for (const k of reg.keys) {
      if (k.state === KeyState.RETIRING && k.retiring_until && now >= k.retiring_until) {
        k.state = KeyState.RETIRED;
        k.retired_at = now;
        changed = true;
      }
    }
    if (changed) {
      this._saveRegistry(reg);
    }

    const current = reg.keys.find(k => k.version === reg.active_version);
    if (!current || current.state === KeyState.REVOKED) {
      throw new Error('No active authorized key available');
    }
    return current;
  }

  getKeyByVersion(version) {
    const reg = this._loadRegistry();
    const now = Date.now();
    const key = reg.keys.find(k => k.version === version);
    if (!key) return null;

    if (key.state === KeyState.RETIRING && key.retiring_until && now >= key.retiring_until) {
      key.state = KeyState.RETIRED;
      key.retired_at = now;
      this._saveRegistry(reg);
    }
    return key;
  }

  canUseForDecryption(version) {
    const key = this.getKeyByVersion(version);
    if (!key) return false;
    if (key.state === KeyState.REVOKED) return false;
    if (key.state === KeyState.ACTIVE || key.state === KeyState.RETIRING) return true;
    if (key.state === KeyState.RETIRED) return true;
    return false;
  }

  canUseForEncryption(version) {
    const key = this.getKeyByVersion(version);
    if (!key) return false;
    return key.state === KeyState.ACTIVE;
  }

  revokeKey(version, reason = '') {
    const reg = this._loadRegistry();
    const key = reg.keys.find(k => k.version === version);
    if (!key) throw new Error(`Key version ${version} not found`);
    key.state = KeyState.REVOKED;
    key.revoked_at = Date.now();
    key.revocation_reason = reason;
    this._saveRegistry(reg);
    return key;
  }

  rotateKey(optionsOrCrashStage = null) {
    let crashInjectionStage = null;
    let gracePeriodMs = this.gracePeriodMs;
    if (typeof optionsOrCrashStage === 'string') {
      crashInjectionStage = optionsOrCrashStage;
    } else if (typeof optionsOrCrashStage === 'number') {
      gracePeriodMs = optionsOrCrashStage;
    } else if (optionsOrCrashStage && typeof optionsOrCrashStage === 'object') {
      crashInjectionStage = optionsOrCrashStage.crashInjectionStage || null;
      if (optionsOrCrashStage.gracePeriodMs) gracePeriodMs = optionsOrCrashStage.gracePeriodMs;
    }

    const reg = this._loadRegistry();
    const oldVersion = reg.active_version || 1;
    const newVersion = oldVersion + 1;
    const now = Date.now();

    this._appendWal('STAGE_START', { oldVersion, newVersion });
    if (crashInjectionStage === 'STAGE_START') throw new Error('CRASH_INJECTED_AT_STAGE_START');

    // 1. Generate new candidate key
    const newKey = {
      version: newVersion,
      keyHex: crypto.randomBytes(32).toString('hex'),
      state: KeyState.PENDING,
      created_at: now,
      activated_at: null,
      retiring_until: null,
      retired_at: null
    };
    reg.keys.push(newKey);
    this._saveRegistry(reg);

    this._appendWal('STAGE_KEY_GENERATED', { oldVersion, newVersion });
    if (crashInjectionStage === 'STAGE_KEY_GENERATED') throw new Error('CRASH_INJECTED_AT_STAGE_KEY_GENERATED');

    // 2. Mark old key as retiring with grace period cutoff
    const oldKey = reg.keys.find(k => k.version === oldVersion);
    if (oldKey) {
      oldKey.state = KeyState.RETIRING;
      oldKey.retiring_until = now + gracePeriodMs;
    }

    // 3. Activate new key
    newKey.state = KeyState.ACTIVE;
    newKey.activated_at = now;
    reg.active_version = newVersion;
    this._saveRegistry(reg);

    this._appendWal('STAGE_COMMITTED', { oldVersion, newVersion });
    if (crashInjectionStage === 'STAGE_COMMITTED') throw new Error('CRASH_INJECTED_AT_STAGE_COMMITTED');

    // Clean up completed WAL
    if (fs.existsSync(this.walFile)) {
      fs.unlinkSync(this.walFile);
    }

    return {
      version: newVersion,
      active_version: newVersion,
      state: KeyState.ACTIVE,
      retiring_version: oldVersion,
      grace_period_ms: gracePeriodMs,
      retiring_until: oldKey ? oldKey.retiring_until : null,
      cutoff_at: oldKey ? oldKey.retiring_until : null
    };
  }

  recoverWal() {
    if (!fs.existsSync(this.walFile)) return;

    const lines = fs.readFileSync(this.walFile, 'utf8').trim().split('\n').filter(Boolean);
    if (lines.length === 0) {
      try { fs.unlinkSync(this.walFile); } catch {}
      return;
    }

    let lastStage = null;
    let lastData = null;

    for (const line of lines) {
      try {
        const entry = JSON.parse(line);
        lastStage = entry.stage;
        lastData = entry.data;
      } catch {}
    }

    const reg = this._loadRegistry();

    // Rollback uncommitted pending keys if crashed before STAGE_COMMITTED
    if (lastStage === 'STAGE_START' || lastStage === 'STAGE_KEY_GENERATED') {
      if (lastData && lastData.newVersion) {
        reg.keys = reg.keys.filter(k => k.version !== lastData.newVersion);
      }
      if (lastData && lastData.oldVersion) {
        reg.active_version = lastData.oldVersion;
        const oldKey = reg.keys.find(k => k.version === lastData.oldVersion);
        if (oldKey && oldKey.state !== KeyState.REVOKED) {
          oldKey.state = KeyState.ACTIVE;
          oldKey.retiring_until = null;
        }
      }
      this._saveRegistry(reg);
    }

    if (fs.existsSync(this.walFile)) {
      try { fs.unlinkSync(this.walFile); } catch {}
    }
  }
}

module.exports = {
  KeyState,
  KeyLifecycleManager
};
