'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

class AuditIndex {
  constructor(stateDir) {
    this.stateDir = stateDir;
    this.indexPath = path.join(stateDir, 'audit_index.json');
    this.logPath = path.join(stateDir, 'audit.log');
    this.index = new Map(); // request_id -> decision ('allow' | 'deny')
    this._loadOrRebuild();
  }

  _loadOrRebuild() {
    if (fs.existsSync(this.indexPath)) {
      try {
        const raw = fs.readFileSync(this.indexPath, 'utf8');
        const parsed = JSON.parse(raw);
        for (const [k, v] of Object.entries(parsed)) {
          this.index.set(k, v);
        }
        return;
      } catch {
        // Fallback to rebuilding from audit.log if index is corrupted
      }
    }

    this.rebuildFromLog();
  }

  rebuildFromLog() {
    this.index.clear();
    if (!fs.existsSync(this.logPath)) {
      return;
    }

    try {
      const content = fs.readFileSync(this.logPath, 'utf8');
      const lines = content.split('\n');
      for (const line of lines) {
        if (!line.trim()) continue;
        try {
          const entry = JSON.parse(line);
          if (entry.type === 'record' && entry.details) {
            const reqId = entry.details.request_id;
            const dec = entry.details.decision;
            // First-Write-Wins
            if (reqId && dec && !this.index.has(reqId)) {
              this.index.set(reqId, dec);
            }
          }
        } catch {}
      }
    } catch {}

    this._save();
  }

  has(requestId) {
    return this.index.has(requestId);
  }

  get(requestId) {
    return this.index.get(requestId);
  }

  record(requestId, decision) {
    if (!requestId || typeof requestId !== 'string') return;
    // First-write-wins: do not overwrite
    if (this.index.has(requestId)) return;

    this.index.set(requestId, decision);
    this._save();
  }

  _save() {
    const tmp = path.join(this.stateDir, `.tmp-index-${crypto.randomUUID()}`);
    const obj = Object.fromEntries(this.index.entries());
    fs.writeFileSync(tmp, JSON.stringify(obj), { mode: 0o600 });
    const fd = fs.openSync(tmp, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(tmp, this.indexPath);
  }
}

module.exports = { AuditIndex };
