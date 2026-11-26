'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

const SERVICE_PATH = path.join(__dirname, '..', 'track4_service.cjs');

function runProcess(inputObj, env) {
  return new Promise((resolve, reject) => {
    const start = performance.now();
    const child = spawn(process.execPath, [SERVICE_PATH], {
      env: { ...process.env, ...env },
      stdio: ['pipe', 'pipe', 'pipe']
    });

    let stdout = '';
    let stderr = '';

    child.stdout.on('data', chunk => { stdout += chunk.toString('utf8'); });
    child.stderr.on('data', chunk => { stderr += chunk.toString('utf8'); });

    child.on('close', (code) => {
      const durationMs = performance.now() - start;
      if (code !== 0) {
        return reject(new Error(`Exit ${code}: ${stderr}`));
      }
      resolve({ durationMs, stdout: JSON.parse(stdout) });
    });

    child.stdin.write(JSON.stringify(inputObj));
    child.stdin.end();
  });
}

function calculatePercentiles(latencies) {
  const sorted = [...latencies].sort((a, b) => a - b);
  const p50 = sorted[Math.floor(sorted.length * 0.50)];
  const p95 = sorted[Math.floor(sorted.length * 0.95)];
  const p99 = sorted[Math.floor(sorted.length * 0.99)];
  const min = sorted[0];
  const max = sorted[sorted.length - 1];
  const mean = sorted.reduce((sum, val) => sum + val, 0) / sorted.length;
  return { min, mean, p50, p95, p99, max };
}

async function main() {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-scale-10k-'));
  const env = { TRACK4_STATE_DIR: stateDir };

  console.log(`Setting up state and seeding 10,000 audit records into ${stateDir}...`);

  // 1. Initial setup
  await runProcess({
    op: 'setup',
    owners: { bench_asset: 'bench_user' },
    contents: { bench_asset: 'confidential_payload_scale' },
    disabled: [],
    key_material: 'kek-scale-10k-secret'
  }, env);

  // 2. Fast-seed 10,000 audit records into audit.log and build audit index
  const tamperLog = new TamperEvidentLog(stateDir, null, 1000);
  const seedStart = performance.now();
  
  const lines = [];
  let lastHash = tamperLog.lastHash;
  const authorityKp = tamperLog.authorityKeyPair;
  let cpCount = 0;

  for (let i = 0; i < 10000; i++) {
    const entry = {
      type: 'record',
      index: i,
      timestamp: Date.now() - (10000 - i) * 10,
      prev_hash: lastHash,
      actor: `user-${i % 50}`,
      op: 'read',
      details: {
        asset: 'bench_asset',
        request_id: `seed-req-${i}`,
        decision: i % 2 === 0 ? 'allow' : 'deny'
      }
    };
    const cJson = require('../lib/tamper_log.cjs').canonicalJson(entry);
    const entryHash = crypto.createHash('sha256').update(cJson, 'utf8').digest('hex');
    const fullRecord = { ...entry, hash: entryHash };
    lines.push(require('../lib/tamper_log.cjs').canonicalJson(fullRecord));
    lastHash = entryHash;

    // Checkpoint every 1000
    if ((i + 1) % 1000 === 0) {
      const cpData = {
        type: 'checkpoint',
        checkpoint_index: cpCount++,
        covered_records: i + 1,
        head_hash: lastHash,
        timestamp: Date.now() - (10000 - i) * 10
      };
      const toSign = Buffer.from(require('../lib/tamper_log.cjs').canonicalJson(cpData), 'utf8');
      const sig = crypto.sign(null, toSign, authorityKp.privateKey);
      const cpRec = {
        ...cpData,
        signature_b64: sig.toString('base64'),
        prev_hash: lastHash
      };
      const cpCanonical = require('../lib/tamper_log.cjs').canonicalJson(cpRec);
      const cpHash = crypto.createHash('sha256').update(cpCanonical, 'utf8').digest('hex');
      lines.push(require('../lib/tamper_log.cjs').canonicalJson({ ...cpRec, hash: cpHash }));
      lastHash = cpHash;
    }
  }

  // Write seeded records to audit.log
  fs.writeFileSync(tamperLog.logPath, lines.join('\n') + '\n', { mode: 0o600 });
  const fd = fs.openSync(tamperLog.logPath, 'r');
  fs.fsyncSync(fd);
  fs.closeSync(fd);

  // Build high-performance O(1) audit index
  const { AuditIndex } = require('../lib/audit_index.cjs');
  const auditIndex = new AuditIndex(stateDir);
  auditIndex.rebuildFromLog();

  console.log(`Seeded 10,000 audit records and built index in ${(performance.now() - seedStart).toFixed(2)} ms`);

  // Verify log size on disk
  const logStats = fs.statSync(tamperLog.logPath);
  console.log(`Audit log size on disk: ${(logStats.size / (1024 * 1024)).toFixed(2)} MB`);

  // 3. Measure read latency across 100 fresh process runs
  const N = 100;
  console.log(`Benchmarking ${N} fresh cold-start runs of 'read' with 10,000 audit records...`);
  const readLatencies = [];
  for (let i = 0; i < N; i++) {
    const res = await runProcess({
      op: 'read',
      actor: 'bench_user',
      asset: 'bench_asset',
      request_id: `post-scale-read-${i}`
    }, env);
    readLatencies.push(res.durationMs);
  }

  // 4. Measure audit lookup latency across 100 fresh process runs (querying existing and unknown IDs)
  console.log(`Benchmarking ${N} fresh cold-start runs of 'audit' with 10,000 audit records...`);
  const auditLatencies = [];
  for (let i = 0; i < N; i++) {
    const targetReqId = i % 2 === 0 ? `seed-req-${i * 50}` : `unknown-req-${i}`;
    const res = await runProcess({
      op: 'audit',
      request_id: targetReqId
    }, env);
    auditLatencies.push(res.durationMs);
  }

  const readStats = calculatePercentiles(readLatencies);
  const auditStats = calculatePercentiles(auditLatencies);

  console.log('\n===============================================================');
  console.log('RESULTS: Scale Benchmark with 10,000 Audit Records');
  console.log('(Spawning fresh node process per request from cold start)');
  console.log('===============================================================');
  console.log(`read (N=${N}):`);
  console.log(`  p50: ${readStats.p50.toFixed(2)} ms | p95: ${readStats.p95.toFixed(2)} ms | p99: ${readStats.p99.toFixed(2)} ms (mean: ${readStats.mean.toFixed(2)} ms)`);
  console.log(`audit (N=${N}):`);
  console.log(`  p50: ${auditStats.p50.toFixed(2)} ms | p95: ${auditStats.p95.toFixed(2)} ms | p99: ${auditStats.p99.toFixed(2)} ms (mean: ${auditStats.mean.toFixed(2)} ms)`);
  console.log('===============================================================\n');

  const report = {
    records_seeded: 10000,
    log_size_bytes: logStats.size,
    read: readStats,
    audit: auditStats
  };
  fs.writeFileSync(path.join(__dirname, '..', 'scale_benchmark_results.json'), JSON.stringify(report, null, 2), 'utf8');
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
