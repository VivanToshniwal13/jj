'use strict';

const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ProtectedMessagingEngine } = require('../lib/messaging.cjs');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

function calculateMedian(arr) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) return (sorted[mid - 1] + sorted[mid]) / 2;
  return sorted[mid];
}

function calculateP95(arr) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(Math.floor(sorted.length * 0.95), sorted.length - 1);
  return sorted[idx];
}

async function runBenchmarks() {
  console.log('================================================================');
  console.log('TRACK 4 PERFORMANCE & RELIABILITY BENCHMARK');
  console.log('================================================================');
  console.log(`Host Platform:       ${os.type()} ${os.release()} (${os.arch()})`);
  console.log(`CPU Model:           ${os.cpus()[0]?.model || 'Generic'}`);
  console.log(`CPU Cores:           ${os.cpus().length}`);
  console.log(`Total System Memory: ${(os.totalmem() / (1024 * 1024 * 1024)).toFixed(2)} GB`);
  console.log(`Node.js Runtime:     ${process.version}`);
  console.log(`OpenSSL Version:     ${process.versions.openssl}`);
  console.log('----------------------------------------------------------------\n');

  const results = {};

  // 1. Post-Quantum Signatures (ML-DSA-65) Benchmark
  console.log('1. ML-DSA-65 Digital Signatures (NIST FIPS 204):');
  const dsaKp = crypto.generateKeyPairSync('ml-dsa-65');
  const samplePayload = crypto.randomBytes(256);
  const sigCount = 200;

  const signTimes = [];
  for (let i = 0; i < sigCount; i++) {
    const t0 = process.hrtime.bigint();
    crypto.sign(null, samplePayload, dsaKp.privateKey);
    const diff = Number(process.hrtime.bigint() - t0) / 1e6;
    signTimes.push(diff);
  }

  const sampleSig = crypto.sign(null, samplePayload, dsaKp.privateKey);
  const verifyTimes = [];
  for (let i = 0; i < sigCount; i++) {
    const t0 = process.hrtime.bigint();
    crypto.verify(null, samplePayload, dsaKp.publicKey, sampleSig);
    const diff = Number(process.hrtime.bigint() - t0) / 1e6;
    verifyTimes.push(diff);
  }

  results.mldsa_sign = {
    iterations: sigCount,
    p50_ms: calculateMedian(signTimes),
    p95_ms: calculateP95(signTimes),
    throughput_ops_sec: Math.round(1000 / calculateMedian(signTimes))
  };
  results.mldsa_verify = {
    iterations: sigCount,
    p50_ms: calculateMedian(verifyTimes),
    p95_ms: calculateP95(verifyTimes),
    throughput_ops_sec: Math.round(1000 / calculateMedian(verifyTimes))
  };

  console.log(`  Sign:   p50 = ${results.mldsa_sign.p50_ms.toFixed(3)} ms | p95 = ${results.mldsa_sign.p95_ms.toFixed(3)} ms (~${results.mldsa_sign.throughput_ops_sec} ops/s)`);
  console.log(`  Verify: p50 = ${results.mldsa_verify.p50_ms.toFixed(3)} ms | p95 = ${results.mldsa_verify.p95_ms.toFixed(3)} ms (~${results.mldsa_verify.throughput_ops_sec} ops/s)`);

  // 2. Post-Quantum KEM (ML-KEM-768) Benchmark
  console.log('\n2. ML-KEM-768 Encapsulation / Decapsulation (NIST FIPS 203):');
  const kemKp = crypto.generateKeyPairSync('ml-kem-768');
  const kemCount = 200;

  const encapTimes = [];
  for (let i = 0; i < kemCount; i++) {
    const t0 = process.hrtime.bigint();
    crypto.encapsulate(kemKp.publicKey);
    const diff = Number(process.hrtime.bigint() - t0) / 1e6;
    encapTimes.push(diff);
  }

  const { ciphertext: sampleCt } = crypto.encapsulate(kemKp.publicKey);
  const decapTimes = [];
  for (let i = 0; i < kemCount; i++) {
    const t0 = process.hrtime.bigint();
    crypto.decapsulate(kemKp.privateKey, sampleCt);
    const diff = Number(process.hrtime.bigint() - t0) / 1e6;
    decapTimes.push(diff);
  }

  results.mlkem_encap = {
    iterations: kemCount,
    p50_ms: calculateMedian(encapTimes),
    p95_ms: calculateP95(encapTimes),
    throughput_ops_sec: Math.round(1000 / calculateMedian(encapTimes))
  };
  results.mlkem_decap = {
    iterations: kemCount,
    p50_ms: calculateMedian(decapTimes),
    p95_ms: calculateP95(decapTimes),
    throughput_ops_sec: Math.round(1000 / calculateMedian(decapTimes))
  };

  console.log(`  Encap: p50 = ${results.mlkem_encap.p50_ms.toFixed(3)} ms | p95 = ${results.mlkem_encap.p95_ms.toFixed(3)} ms (~${results.mlkem_encap.throughput_ops_sec} ops/s)`);
  console.log(`  Decap: p50 = ${results.mlkem_decap.p50_ms.toFixed(3)} ms | p95 = ${results.mlkem_decap.p95_ms.toFixed(3)} ms (~${results.mlkem_decap.throughput_ops_sec} ops/s)`);

  // 3. Symmetric Encryption & Decryption (AES-256-GCM)
  console.log('\n3. AES-256-GCM Authenticated Encryption & Decryption:');
  const aesKey = crypto.randomBytes(32);
  const plainBuffer = crypto.randomBytes(1024); // 1 KB payload
  const aesCount = 1000;

  const encTimes = [];
  const decTimes = [];
  for (let i = 0; i < aesCount; i++) {
    const iv = crypto.randomBytes(12);
    const t0 = process.hrtime.bigint();
    const c = crypto.createCipheriv('aes-256-gcm', aesKey, iv);
    c.setAAD(Buffer.from('test-aad'));
    const ct = Buffer.concat([c.update(plainBuffer), c.final()]);
    const tag = c.getAuthTag();
    encTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);

    const t1 = process.hrtime.bigint();
    const d = crypto.createDecipheriv('aes-256-gcm', aesKey, iv);
    d.setAAD(Buffer.from('test-aad'));
    d.setAuthTag(tag);
    Buffer.concat([d.update(ct), d.final()]);
    decTimes.push(Number(process.hrtime.bigint() - t1) / 1e6);
  }

  results.aes_encrypt = { p50_ms: calculateMedian(encTimes), throughput_mb_sec: Math.round(1024 / calculateMedian(encTimes) / 1000) };
  results.aes_decrypt = { p50_ms: calculateMedian(decTimes), throughput_mb_sec: Math.round(1024 / calculateMedian(decTimes) / 1000) };
  console.log(`  Encrypt (1KB): p50 = ${results.aes_encrypt.p50_ms.toFixed(3)} ms (~${results.aes_encrypt.throughput_mb_sec} MB/s)`);
  console.log(`  Decrypt (1KB): p50 = ${results.aes_decrypt.p50_ms.toFixed(3)} ms (~${results.aes_decrypt.throughput_mb_sec} MB/s)`);

  // 4. End-to-End Protected Message Throughput
  console.log('\n4. End-to-End Protected Messaging Pipeline (Goals 9-12):');
  const benchDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-bench-msg-'));
  try {
    const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
    const bob = ProtectedMessagingEngine.generateIdentityKeyPair();
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const engine = new ProtectedMessagingEngine(benchDir);

    const msgCount = 100;
    const sendTimes = [];
    const recvTimes = [];

    for (let i = 0; i < msgCount; i++) {
      const t0 = process.hrtime.bigint();
      const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, `Bench message ${i}`, { sequenceNumber: i + 1 });
      sendTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);

      const t1 = process.hrtime.bigint();
      engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, packet);
      recvTimes.push(Number(process.hrtime.bigint() - t1) / 1e6);
    }

    results.msg_send = { p50_ms: calculateMedian(sendTimes), p95_ms: calculateP95(sendTimes) };
    results.msg_receive = { p50_ms: calculateMedian(recvTimes), p95_ms: calculateP95(recvTimes) };
    const roundTripMedian = results.msg_send.p50_ms + results.msg_receive.p50_ms;
    const msgThroughput = Math.round(1000 / roundTripMedian);

    console.log(`  Send (Sign + Encap + HKDF + AES + Sign): p50 = ${results.msg_send.p50_ms.toFixed(3)} ms | p95 = ${results.msg_send.p95_ms.toFixed(3)} ms`);
    console.log(`  Receive (Replay + Verify + Decap + Decrypt): p50 = ${results.msg_receive.p50_ms.toFixed(3)} ms | p95 = ${results.msg_receive.p95_ms.toFixed(3)} ms`);
    console.log(`  Round-Trip Throughput: ~${msgThroughput} messages/sec`);
  } finally {
    fs.rmSync(benchDir, { recursive: true, force: true });
  }

  // 5. Tamper-Evident Audit Log Append & Verification
  console.log('\n5. Tamper-Evident Hash-Chained Audit Log (Goal 5):');
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-bench-log-'));
  try {
    const authorityKp = crypto.generateKeyPairSync('ml-dsa-65');
    const log = new TamperEvidentLog(logDir, authorityKp, 50);
    const logRecordsCount = 500;
    const appendTimes = [];

    for (let i = 0; i < logRecordsCount; i++) {
      const t0 = process.hrtime.bigint();
      log.appendRecord('user-bench', 'read', { asset: `doc-${i}`, req: `r-${i}` });
      appendTimes.push(Number(process.hrtime.bigint() - t0) / 1e6);
    }

    const tVerify = process.hrtime.bigint();
    const verifyRes = TamperEvidentLog.verifyLog(log.logPath, authorityKp.publicKey);
    const verifyDurationMs = Number(process.hrtime.bigint() - tVerify) / 1e6;

    results.audit_append = { p50_ms: calculateMedian(appendTimes), p95_ms: calculateP95(appendTimes) };
    results.audit_verify_500 = { duration_ms: verifyDurationMs, rate_records_sec: Math.round((500 / verifyDurationMs) * 1000) };

    console.log(`  Append (Canonical Hash + fsync): p50 = ${results.audit_append.p50_ms.toFixed(3)} ms | p95 = ${results.audit_append.p95_ms.toFixed(3)} ms`);
    console.log(`  Verify 500-Record Chain: ${verifyDurationMs.toFixed(2)} ms (~${results.audit_verify_500.rate_records_sec} records/sec)`);
    console.log(`  Chain Integrity Status:  ${verifyRes.valid ? 'VALID' : 'INVALID'}`);
  } finally {
    fs.rmSync(logDir, { recursive: true, force: true });
  }

  // 6. Crash Recovery & Stale Lock Recovery
  console.log('\n6. Crash Recovery & Atomic Lock Resolution:');
  const crashDir = fs.mkdtempSync(path.join(os.tmpdir(), 'track4-bench-crash-'));
  try {
    const engine = new ProtectedMessagingEngine(crashDir);
    const lockPath = path.join(crashDir, 'replay_state.lock');

    // Simulate dead process crash (PID 9999999 confirmed dead via ESRCH)
    fs.writeFileSync(lockPath, JSON.stringify({ pid: 9999999, token: 'crashed-token-xyz', createdAt: Date.now() - 5000 }) + '\n', { mode: 0o600 });

    const tCrash0 = process.hrtime.bigint();
    let recovered = false;
    engine._withReplayLock(() => {
      recovered = true;
    });
    const crashRecoveryMs = Number(process.hrtime.bigint() - tCrash0) / 1e6;

    results.crash_recovery = { recovered, duration_ms: crashRecoveryMs };
    console.log(`  Stale Lock Recovery Time: ${crashRecoveryMs.toFixed(3)} ms (status: ${recovered ? 'RECOVERED' : 'FAILED'})`);
  } finally {
    fs.rmSync(crashDir, { recursive: true, force: true });
  }

  console.log('================================================================\n');

  const resultsDir = path.join(__dirname, '..', 'docs', 'results');
  if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });
  fs.writeFileSync(path.join(resultsDir, 'benchmark_comprehensive_results.json'), JSON.stringify(results, null, 2), 'utf8');
}

runBenchmarks().catch(console.error);
