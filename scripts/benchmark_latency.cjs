'use strict';

const { spawn } = require('node:child_process');
const path = require('node:path');
const fs = require('node:fs');
const os = require('node:os');
const crypto = require('node:crypto');

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
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-bench-'));
  const env = { TRACK4_STATE_DIR: stateDir };

  console.log(`Starting honest wall-clock process-per-request latency benchmark...`);
  console.log(`State Dir: ${stateDir}`);

  // 1. Setup initial state
  const setupStart = performance.now();
  await runProcess({
    op: 'setup',
    owners: { bench_asset: 'bench_user' },
    contents: { bench_asset: 'benchmark_confidential_payload' },
    disabled: [],
    key_material: 'kek-benchmark-secret'
  }, env);
  console.log(`Setup complete in ${(performance.now() - setupStart).toFixed(2)} ms`);

  // Generate ML-KEM-768 keypair for protected_read
  const kemKp = crypto.generateKeyPairSync('ml-kem-768');
  const spki = kemKp.publicKey.export({ format: 'der', type: 'spki' });
  const rawPk = spki.subarray(22); // 1184 bytes
  const rawPkB64 = rawPk.toString('base64');

  const N = 200;

  // 2. Benchmark read (200 processes)
  console.log(`\nBenchmarking ${N} runs of 'read'...`);
  const readLatencies = [];
  for (let i = 0; i < N; i++) {
    const res = await runProcess({
      op: 'read',
      actor: 'bench_user',
      asset: 'bench_asset',
      request_id: `bench-read-${i}`
    }, env);
    readLatencies.push(res.durationMs);
  }

  // 3. Benchmark protected_read (200 processes)
  console.log(`Benchmarking ${N} runs of 'protected_read'...`);
  const protectedLatencies = [];
  for (let i = 0; i < N; i++) {
    const res = await runProcess({
      op: 'protected_read',
      actor: 'bench_user',
      asset: 'bench_asset',
      challenge: `bench-challenge-${i}`,
      public_key: rawPkB64
    }, env);
    protectedLatencies.push(res.durationMs);
  }

  // 4. Benchmark revoke (200 processes)
  console.log(`Benchmarking ${N} runs of 'revoke'...`);
  const revokeLatencies = [];
  for (let i = 0; i < N; i++) {
    const res = await runProcess({
      op: 'revoke',
      actor: `bench_user_revoked_${i}`
    }, env);
    revokeLatencies.push(res.durationMs);
  }

  const readStats = calculatePercentiles(readLatencies);
  const protStats = calculatePercentiles(protectedLatencies);
  const revStats = calculatePercentiles(revokeLatencies);

  console.log('\n===============================================================');
  console.log('RESULTS: Wall-clock process-per-request latency on macOS/Linux');
  console.log('(Spawning fresh node process per request from cold start)');
  console.log('===============================================================');
  console.log(`read (N=${N}):`);
  console.log(`  p50: ${readStats.p50.toFixed(2)} ms | p95: ${readStats.p95.toFixed(2)} ms | p99: ${readStats.p99.toFixed(2)} ms (mean: ${readStats.mean.toFixed(2)} ms)`);

  console.log(`protected_read (N=${N}):`);
  console.log(`  p50: ${protStats.p50.toFixed(2)} ms | p95: ${protStats.p95.toFixed(2)} ms | p99: ${protStats.p99.toFixed(2)} ms (mean: ${protStats.mean.toFixed(2)} ms)`);

  console.log(`revoke (N=${N}):`);
  console.log(`  p50: ${revStats.p50.toFixed(2)} ms | p95: ${revStats.p95.toFixed(2)} ms | p99: ${revStats.p99.toFixed(2)} ms (mean: ${revStats.mean.toFixed(2)} ms)`);
  console.log('===============================================================\n');

  // Output JSON report for evidence sheet
  const evidenceReport = {
    benchmark_environment: 'macOS arm64 (host) / Node 24.11.1 / OpenSSL 3.5.4',
    invocation_model: 'fresh-process-per-request stdin/stdout JSON (CLI execution)',
    sample_size: N,
    operations: {
      read: readStats,
      protected_read: protStats,
      revoke: revStats
    }
  };

  const outPath = path.join(__dirname, '..', 'benchmark_results.json');
  fs.writeFileSync(outPath, JSON.stringify(evidenceReport, null, 2), 'utf8');
  console.log(`Saved benchmark report to ${outPath}`);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
