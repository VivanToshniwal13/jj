#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

function printUsage() {
  console.log(`
Usage: verify_log <path-to-audit.log> [options]

Options:
  --key, -k <path>    Path to ML-DSA-65 authority public key (DER or PEM format)
  --json              Output verification results as machine-readable JSON
  --help, -h          Show this help message
`);
}

function parseArgs() {
  const args = process.argv.slice(2);
  let logPath = null;
  let keyPath = null;
  let jsonOutput = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    } else if (arg === '--json') {
      jsonOutput = true;
    } else if (arg === '--key' || arg === '-k') {
      keyPath = args[++i];
    } else if (!logPath && !arg.startsWith('-')) {
      logPath = arg;
    }
  }

  if (!logPath) {
    const defaultStateDir = process.env.TRACK4_STATE_DIR || path.join(__dirname, '..', 'tmp');
    logPath = path.join(defaultStateDir, 'audit.log');
  }

  return { logPath, keyPath, jsonOutput };
}

function main() {
  const { logPath, keyPath, jsonOutput } = parseArgs();

  let authorityPublicKey = null;
  if (keyPath && fs.existsSync(keyPath)) {
    try {
      const keyData = fs.readFileSync(keyPath);
      authorityPublicKey = crypto.createPublicKey(keyData);
    } catch (err) {
      console.error(`Error loading authority public key: ${err.message}`);
      process.exit(1);
    }
  }

  const result = TamperEvidentLog.verifyLog(logPath, authorityPublicKey);

  if (jsonOutput) {
    console.log(JSON.stringify(result, null, 2));
    process.exit(result.valid ? 0 : 2);
  }

  console.log('===============================================================');
  console.log('TRACK 4: TAMPER-EVIDENT AUDIT LOG VERIFICATION (GOAL 5)');
  console.log('===============================================================');
  console.log(`Target Log: ${logPath}`);
  console.log(`Authority Key: ${keyPath ? 'Configured & Enforced' : 'Unspecified (hash chain verified; signature skipped)'}`);
  console.log('---------------------------------------------------------------');

  if (result.valid) {
    console.log('STATUS: VERIFIED (NO TAMPERING DETECTED)');
    console.log(`Records Verified:      ${result.recordsVerified}`);
    console.log(`Checkpoints Verified:  ${result.checkpointsVerified}`);
    console.log(`Current Head Hash:     ${result.headHash}`);
    console.log('===============================================================');
    process.exit(0);
  } else {
    console.error('STATUS: FAILED (TAMPERING OR CORRUPTION DETECTED)');
    console.error(`Tamper Type:           ${result.errorType}`);
    if (result.lineIndex !== undefined) console.error(`Log Line:              ${result.lineIndex + 1}`);
    if (result.recordIndex !== undefined) console.error(`Record Index:          ${result.recordIndex}`);
    console.error(`Reason:                ${result.reason}`);
    console.log('===============================================================');
    process.exit(2);
  }
}

main();
