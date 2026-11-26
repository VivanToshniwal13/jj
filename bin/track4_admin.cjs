#!/usr/bin/env node
'use strict';

const path = require('node:path');
const fs = require('node:fs');
const { KeyLifecycleManager } = require('../lib/key_lifecycle.cjs');
const { DistributedRevocationAuthority, DistributedNode, broadcastRevocation } = require('../lib/distributed_revocation.cjs');
const { BackupManager } = require('../lib/backup_integrity.cjs');

const [,, cmd, ...args] = process.argv;

function printUsage() {
  console.log(`
Track 4 Admin CLI: Keys, Nodes & Recovery Operations

Commands:
  rotate-key <stateDir> [gracePeriodMs]
  broadcast-revocation <actor> <nodeDir1> [nodeDir2 ...]
  create-backup <stateDir> <backupOutputFile> <secret>
  restore-backup <backupFile> <targetStateDir> <secret>
`);
}

async function main() {
  switch (cmd) {
    case 'rotate-key': {
      const stateDir = args[0] || process.env.TRACK4_STATE_DIR;
      if (!stateDir) throw new Error('Missing state directory');
      const graceMs = parseInt(args[1] || '5000', 10);
      const km = new KeyLifecycleManager(stateDir, graceMs);
      const res = km.rotateKey();
      console.log(JSON.stringify(res, null, 2));
      break;
    }

    case 'broadcast-revocation': {
      const actor = args[0];
      const nodeDirs = args.slice(1);
      if (!actor || nodeDirs.length === 0) throw new Error('Usage: broadcast-revocation <actor> <nodeDirs...>');
      const authority = new DistributedRevocationAuthority();
      const nodes = nodeDirs.map((dir, i) => new DistributedNode(`node-${i}`, dir, authority.getPublicKey()));
      const res = await broadcastRevocation(authority, nodes, actor);
      console.log(JSON.stringify(res, null, 2));
      break;
    }

    case 'create-backup': {
      const stateDir = args[0];
      const outPath = args[1];
      const secret = args[2];
      if (!stateDir || !outPath || !secret) throw new Error('Usage: create-backup <stateDir> <outPath> <secret>');
      const km = new KeyLifecycleManager(stateDir);
      const reg = km._loadRegistry();
      const bm = new BackupManager();
      const backup = bm.createBackup(reg, secret);
      fs.writeFileSync(outPath, JSON.stringify(backup, null, 2), { mode: 0o600 });
      console.log(`Backup created successfully at ${outPath} (manifest: ${backup.manifest_hash})`);
      break;
    }

    case 'restore-backup': {
      const backupPath = args[0];
      const targetStateDir = args[1];
      const secret = args[2];
      if (!backupPath || !targetStateDir || !secret) throw new Error('Usage: restore-backup <backupPath> <targetStateDir> <secret>');
      const backupData = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
      const bm = new BackupManager();
      const restored = bm.restoreBackup(backupData, secret);
      const km = new KeyLifecycleManager(targetStateDir);
      km._saveRegistry(restored);
      console.log(`Backup restored successfully to ${targetStateDir} (active version: ${restored.active_version})`);
      break;
    }

    default:
      printUsage();
      process.exit(1);
  }
}

main().catch(err => {
  console.error(`Error: ${err.message}`);
  process.exit(1);
});
