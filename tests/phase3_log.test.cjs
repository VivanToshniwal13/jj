'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const { TamperEvidentLog, canonicalJson } = require('../lib/tamper_log.cjs');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');
const VERIFY_CLI_PATH = path.join(__dirname, '..', 'bin', 'verify_log.cjs');

function runService(inputObj, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [SERVICE_PATH], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

    child.on('close', (code, signal) => {
      resolve({ code, signal, stdout, stderr });
    });

    child.stdin.write(JSON.stringify(inputObj));
    child.stdin.end();
  });
}

function runVerifyCli(args, env = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [VERIFY_CLI_PATH, ...args], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

    child.on('close', (code) => {
      resolve({ code, stdout, stderr });
    });
  });
}

test('Phase 3 - Goal 5: Tamper-Evident Hash-Chained Log & ML-DSA Checkpoints', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-log-test-'));
  const authorityKeyPair = crypto.generateKeyPairSync('ml-dsa-65');
  const authorityPk = authorityKeyPair.publicKey;

  // Use a checkpoint interval of 5 records for testing
  const log = new TamperEvidentLog(stateDir, authorityKeyPair, 5);

  await t.test('1. Normal append and hash chain verification', () => {
    for (let i = 0; i < 7; i++) {
      log.appendRecord(`user-${i}`, 'read', { asset: `asset-${i}`, index_test: i });
    }

    const verification = TamperEvidentLog.verifyLog(log.logPath, authorityPk);
    assert.equal(verification.valid, true);
    assert.equal(verification.recordsVerified, 7);
    assert.equal(verification.checkpointsVerified, 1); // Checkpoint triggered at record 5
    assert.ok(verification.headHash.length === 64);
  });

  await t.test('2. Injection resistance: Newlines and Unicode separators stay single-line escaped', () => {
    // Attempt CRLF injection and fake JSON line injection in actor and details
    const maliciousActor = 'attacker\n{"type":"record","injected":true}\r\n';
    const maliciousDetails = {
      note: 'line1\r\nline2\u2028line3\u2029line4',
      attack: 'fake_hash"}\n{"hacked":true}'
    };

    const record = log.appendRecord(maliciousActor, 'read', maliciousDetails);
    assert.ok(record.hash);

    // Verify raw file line count: exactly 1 new line was appended (not multiple raw lines)
    const content = fs.readFileSync(log.logPath, 'utf8');
    const lines = content.split('\n').filter(l => l.trim().length > 0);
    
    // 7 previous records + 1 checkpoint + 1 new record = 9 lines total
    assert.equal(lines.length, 9);

    // Full log remains strictly valid
    const verification = TamperEvidentLog.verifyLog(log.logPath, authorityPk);
    assert.equal(verification.valid, true);
    assert.equal(verification.recordsVerified, 8);
  });

  await t.test('3. Detects record modification (bit-flip or content edit)', () => {
    // Create copy of log file to tamper
    const tamperedLogPath = path.join(stateDir, 'tampered_mod.log');
    const originalContent = fs.readFileSync(log.logPath, 'utf8');
    const lines = originalContent.split('\n').filter(l => l.trim().length > 0);

    // Modify payload in record 2 without updating hash
    const record2 = JSON.parse(lines[2]);
    record2.actor = 'forged-attacker-identity';
    lines[2] = canonicalJson(record2);

    fs.writeFileSync(tamperedLogPath, lines.join('\n') + '\n', 'utf8');

    const result = TamperEvidentLog.verifyLog(tamperedLogPath, authorityPk);
    assert.equal(result.valid, false);
    assert.equal(result.errorType, 'TAMPER_MODIFICATION');
    assert.equal(result.recordIndex, 2);
    assert.ok(result.reason.includes('Data modification detected'));
  });

  await t.test('4. Detects record reordering (broken hash chain)', () => {
    const tamperedLogPath = path.join(stateDir, 'tampered_reorder.log');
    const originalContent = fs.readFileSync(log.logPath, 'utf8');
    const lines = originalContent.split('\n').filter(l => l.trim().length > 0);

    // Swap lines 1 and 2
    const tmp = lines[1];
    lines[1] = lines[2];
    lines[2] = tmp;

    fs.writeFileSync(tamperedLogPath, lines.join('\n') + '\n', 'utf8');

    const result = TamperEvidentLog.verifyLog(tamperedLogPath, authorityPk);
    assert.equal(result.valid, false);
    assert.equal(result.errorType, 'TAMPER_REORDER_OR_BROKEN_CHAIN');
    assert.ok(result.reason.includes('Hash chain broken'));
  });

  await t.test('5. Detects truncation when records covered by checkpoint are deleted', () => {
    const tamperedLogPath = path.join(stateDir, 'tampered_truncation.log');
    const originalContent = fs.readFileSync(log.logPath, 'utf8');
    const lines = originalContent.split('\n').filter(l => l.trim().length > 0);

    // Checkpoint at line index 5 promises 5 records. Remove record at index 4!
    const truncatedLines = lines.filter((_, idx) => idx !== 4);
    fs.writeFileSync(tamperedLogPath, truncatedLines.join('\n') + '\n', 'utf8');

    const result = TamperEvidentLog.verifyLog(tamperedLogPath, authorityPk);
    assert.equal(result.valid, false);
    // Since prev_hash of line 5 now points to deleted line 4, chain is immediately caught broken
    assert.ok(['TAMPER_REORDER_OR_BROKEN_CHAIN', 'TAMPER_TRUNCATION'].includes(result.errorType));
  });

  await t.test('6. Detects forged checkpoint signature', () => {
    const tamperedLogPath = path.join(stateDir, 'tampered_checkpoint.log');
    const originalContent = fs.readFileSync(log.logPath, 'utf8');
    const lines = originalContent.split('\n').filter(l => l.trim().length > 0);

    // Find the checkpoint line
    let cpIndex = -1;
    for (let i = 0; i < lines.length; i++) {
      if (lines[i].includes('"type":"checkpoint"')) {
        cpIndex = i;
        break;
      }
    }
    assert.ok(cpIndex >= 0);

    const cp = JSON.parse(lines[cpIndex]);
    const sig = Buffer.from(cp.signature_b64, 'base64');
    sig[0] ^= 0xFF; // Corrupt signature bytes
    cp.signature_b64 = sig.toString('base64');
    lines[cpIndex] = canonicalJson(cp);

    fs.writeFileSync(tamperedLogPath, lines.join('\n') + '\n', 'utf8');

    const result = TamperEvidentLog.verifyLog(tamperedLogPath, authorityPk);
    assert.equal(result.valid, false);
    assert.ok(['TAMPER_CHECKPOINT_FORGED', 'TAMPER_MODIFICATION'].includes(result.errorType));
  });
});

test('Phase 3: Integration with track4_service.cjs & verify_log CLI', async (t) => {
  const serviceStateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-service-log-'));
  const env = { TRACK4_STATE_DIR: serviceStateDir };

  // 1. Execute operations through track4_service
  await runService({
    op: 'setup',
    owners: { doc1: 'alice', doc2: 'bob' },
    contents: { doc1: 'content1', doc2: 'content2' },
    disabled: [],
    key_material: 'integration-test-kek'
  }, env);

  await runService({
    op: 'read',
    actor: 'alice',
    asset: 'doc1',
    request_id: 'req-audit-1'
  }, env);

  await runService({
    op: 'read',
    actor: 'eve',
    asset: 'doc1',
    request_id: 'req-audit-2'
  }, env);

  await runService({
    op: 'revoke',
    actor: 'bob'
  }, env);

  const logFile = path.join(serviceStateDir, 'audit.log');
  assert.ok(fs.existsSync(logFile), 'audit.log must exist after adapter operations');

  // 2. Run verify_log CLI with --json
  const cliRes = await runVerifyCli([logFile, '--json'], env);
  assert.equal(cliRes.code, 0, `CLI exited with ${cliRes.code}: ${cliRes.stderr}`);
  const cliParsed = JSON.parse(cliRes.stdout);
  assert.equal(cliParsed.valid, true);
  assert.equal(cliParsed.recordsVerified, 4); // setup, 2 reads, revoke
  assert.ok(cliParsed.headHash.length === 64);

  // 3. Run human-readable CLI
  const humanCliRes = await runVerifyCli([logFile], env);
  assert.equal(humanCliRes.code, 0);
  assert.ok(humanCliRes.stdout.includes('STATUS: VERIFIED (NO TAMPERING DETECTED)'));
  assert.ok(humanCliRes.stdout.includes('Records Verified:      4'));
});
