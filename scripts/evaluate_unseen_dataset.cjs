'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { ExplainableDetector } = require('../lib/detector.cjs');

function calculateMedian(arr) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 0) {
    return (sorted[mid - 1] + sorted[mid]) / 2;
  }
  return sorted[mid];
}

function calculateP95(arr) {
  if (!arr || arr.length === 0) return 0;
  const sorted = [...arr].sort((a, b) => a - b);
  const idx = Math.min(Math.floor(sorted.length * 0.95), sorted.length - 1);
  return sorted[idx];
}

/**
 * Generate unseen evaluation dataset (completely separate from practice/events.csv and evaluate_attack_set.cjs)
 * Features distinct actors, distinct services, novel lateral paths, and varying benign noise.
 */
function generateUnseenEvaluationSet(benignCount = 500, attackCount = 50) {
  const events = [];
  const groundTruth = new Map(); // id -> { isAttack: boolean, type: string }
  const baseTime = new Date('2026-06-15T12:00:00Z').getTime();

  // Baseline approvals for unseen test environment
  const approvalsData = {
    synthetic: true,
    changes: [
      {
        approval_id: 'unseen-app-01',
        approved_by: 'sec-lead-unseen',
        subject: 'worker-delta',
        operation: 'grant_role',
        role: 'data-scientist',
        scope: ['lakehouse-api', 'feature-store'],
        valid_from_utc: '2026-06-15T12:00:00Z',
        valid_until_utc: '2026-06-15T12:30:00Z'
      }
    ]
  };

  let evtIdx = 1;
  function add(ev, isAttack, type) {
    const id = `unseen-evt-${String(evtIdx++).padStart(4, '0')}`;
    events.push({ event_id: id, ...ev });
    groundTruth.set(id, { isAttack, type });
    return id;
  }

  // 1. Unseen Attacks (Role escalations, expired windows, lateral hops, out of scope)
  const attackers = ['attacker-x', 'attacker-y', 'attacker-z', 'rogue-svc-1', 'rogue-svc-2'];
  const sensitiveTargets = ['crypto-vault', 'payment-gateway', 'audit-db', 'pii-archive'];

  for (let i = 0; i < attackCount; i++) {
    const t = baseTime + i * 5000;
    const atk = attackers[i % attackers.length];
    const tgt = sensitiveTargets[i % sensitiveTargets.length];

    if (i % 3 === 0) {
      // Unapproved role change
      add({
        event_time_utc: new Date(t).toISOString(),
        received_time_utc: new Date(t + 75).toISOString(),
        source_clock_offset_ms: 0,
        actor: atk,
        source_service: 'ingress-proxy',
        target_service: 'auth-server',
        action: 'role_change',
        role_before: 'guest',
        role_after: 'super-admin',
        outcome: 'success',
        approval_id: '',
        session_id: `sess-atk-${i}`,
        correlation_id: `flow-atk-${i}`
      }, true, 'unapproved_role_change');
    } else if (i % 3 === 1) {
      // Out of scope access attempt
      add({
        event_time_utc: new Date(t).toISOString(),
        received_time_utc: new Date(t + 85).toISOString(),
        source_clock_offset_ms: 0,
        actor: 'worker-delta',
        source_service: 'ingress-proxy',
        target_service: tgt, // outside lakehouse-api/feature-store
        action: 'read',
        role_before: 'data-scientist',
        role_after: 'data-scientist',
        outcome: 'allow',
        approval_id: 'unseen-app-01',
        session_id: `sess-atk-${i}`,
        correlation_id: `flow-atk-${i}`
      }, true, 'out_of_scope_access');
    } else {
      // Multi-hop unexpected lateral movement
      const flow = `flow-lat-unseen-${i}`;
      add({
        event_time_utc: new Date(t).toISOString(),
        received_time_utc: new Date(t + 60).toISOString(),
        source_clock_offset_ms: 0,
        actor: atk,
        source_service: 'ingress-proxy',
        target_service: 'web-tier',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'allow',
        approval_id: '',
        session_id: `sess-lat-${i}`,
        correlation_id: flow
      }, false, 'benign_hop');

      add({
        event_time_utc: new Date(t + 1000).toISOString(),
        received_time_utc: new Date(t + 1070).toISOString(),
        source_clock_offset_ms: 0,
        actor: atk,
        source_service: 'web-tier',
        target_service: 'internal-cache',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'allow',
        approval_id: '',
        session_id: `sess-lat-${i}`,
        correlation_id: flow
      }, true, 'lateral_movement_hop2');

      add({
        event_time_utc: new Date(t + 2000).toISOString(),
        received_time_utc: new Date(t + 2080).toISOString(),
        source_clock_offset_ms: 0,
        actor: atk,
        source_service: 'internal-cache',
        target_service: tgt,
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'allow',
        approval_id: '',
        session_id: `sess-lat-${i}`,
        correlation_id: flow
      }, true, 'lateral_movement_hop3');
    }
  }

  // 2. Unseen Routine / Benign Events
  const benignUsers = ['analyst-01', 'analyst-02', 'dev-01', 'dev-02', 'batch-sync'];
  for (let i = 0; i < benignCount; i++) {
    const t = baseTime + (attackCount * 5000) + i * 2000;
    const user = benignUsers[i % benignUsers.length];

    events.push({
      event_id: `unseen-evt-${String(evtIdx++).padStart(4, '0')}`,
      event_time_utc: new Date(t).toISOString(),
      received_time_utc: new Date(t + 40 + Math.floor(Math.random() * 30)).toISOString(),
      source_clock_offset_ms: 0,
      actor: user,
      source_service: 'portal',
      target_service: 'catalog',
      action: 'read',
      role_before: 'analyst',
      role_after: 'analyst',
      outcome: 'allow',
      approval_id: '',
      session_id: `sess-routine-${user}-${Math.floor(i / 20)}`,
      correlation_id: `flow-routine-${Math.floor(i / 10)}`
    });
    groundTruth.set(events[events.length - 1].event_id, { isAttack: false, type: 'routine' });
  }

  return { events, groundTruth, approvalsData };
}

function runEvaluation() {
  console.log('================================================================');
  console.log('EVALUATION ON UNSEEN SYNTHETIC DATASET (SEPARATE FROM DEV/PRACTICE)');
  console.log('================================================================');

  const { events, groundTruth, approvalsData } = generateUnseenEvaluationSet(500, 50);

  const startMem = process.memoryUsage();
  const startCpu = process.cpuUsage();
  const startTime = Date.now();

  const detector = new ExplainableDetector(approvalsData);
  const results = detector.detect(events);

  const durationMs = Date.now() - startTime;
  const cpuDiff = process.cpuUsage(startCpu);
  const endMem = process.memoryUsage();

  const alertMap = new Map();
  for (const a of results.alerts) {
    if (Array.isArray(a.event_ids)) {
      for (const id of a.event_ids) {
        alertMap.set(id, a);
      }
    }
  }

  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;
  const latencies = [];

  // Per-category attack tracking
  const categoryStats = {
    unapproved_role_change: { expected: 0, detected: 0 },
    out_of_scope_access: { expected: 0, detected: 0 },
    lateral_movement: { expected: 0, detected: 0 }
  };

  for (const ev of events) {
    const truth = groundTruth.get(ev.event_id);
    const hasAlert = alertMap.has(ev.event_id);

    if (truth.isAttack) {
      const catKey = truth.type.startsWith('lateral_movement') ? 'lateral_movement' : truth.type;
      if (categoryStats[catKey]) {
        categoryStats[catKey].expected++;
      }

      if (hasAlert) {
        tp++;
        if (categoryStats[catKey]) {
          categoryStats[catKey].detected++;
        }
        const estimatedEvent = new Date(ev.event_time_utc).getTime() - (ev.source_clock_offset_ms || 0);
        const recvTime = new Date(ev.received_time_utc).getTime();
        latencies.push(recvTime - estimatedEvent);
      } else {
        fn++;
      }
    } else {
      if (hasAlert) {
        fp++;
      } else {
        tn++;
      }
    }
  }

  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 1;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 1;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
  const fpr = (fp + tn) > 0 ? fp / (fp + tn) : 0;

  const medianLatency = calculateMedian(latencies);
  const p95Latency = calculateP95(latencies);

  console.log(`Total Events Evaluated:      ${events.length}`);
  console.log(`Execution Wall Time:        ${durationMs} ms`);
  console.log(`Confusion Matrix:`);
  console.log(`  True Positives (TP):      ${tp}`);
  console.log(`  False Positives (FP):     ${fp}`);
  console.log(`  True Negatives (TN):      ${tn}`);
  console.log(`  False Negatives (FN):     ${fn}`);
  console.log(`Metrics:`);
  console.log(`  Precision:                ${(precision * 100).toFixed(1)}%`);
  console.log(`  Recall:                   ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score:                 ${(f1 * 100).toFixed(1)}%`);
  console.log(`  False Positive Rate (FPR): ${(fpr * 100).toFixed(2)}%`);
  console.log(`  Median Detection Latency: ${medianLatency} ms`);
  console.log(`  p95 Detection Latency:    ${p95Latency} ms`);
  console.log(`Per-Category Recall Breakdown:`);
  for (const [cat, stat] of Object.entries(categoryStats)) {
    const catRecall = stat.expected > 0 ? (stat.detected / stat.expected) * 100 : 100;
    console.log(`  - ${cat.padEnd(26)}: ${stat.detected}/${stat.expected} (${catRecall.toFixed(1)}%)`);
  }
  console.log(`  Recall:                   ${(recall * 100).toFixed(1)}%`);
  console.log(`  F1 Score:                 ${(f1 * 100).toFixed(1)}%`);
  console.log(`  False Positive Rate (FPR): ${(fpr * 100).toFixed(2)}%`);
  console.log(`  Median Detection Latency: ${medianLatency} ms`);
  console.log(`  p95 Detection Latency:    ${p95Latency} ms`);
  console.log(`Resource Usage:`);
  console.log(`  CPU User Time:            ${(cpuDiff.user / 1000).toFixed(2)} ms`);
  console.log(`  CPU System Time:          ${(cpuDiff.system / 1000).toFixed(2)} ms`);
  console.log(`  Heap Used Delta:          ${((endMem.heapUsed - startMem.heapUsed) / (1024 * 1024)).toFixed(2)} MB`);
  console.log(`  RSS Delta:                ${((endMem.rss - startMem.rss) / (1024 * 1024)).toFixed(2)} MB`);

  // Performance Scaling Test at Increasing Event Volumes
  console.log('\nPerformance at Increasing Event Volumes:');
  const volumeScales = [100, 500, 1000, 2500];
  const volumeResults = [];

  for (const vol of volumeScales) {
    const subset = generateUnseenEvaluationSet(vol, Math.floor(vol / 10));
    const t0 = Date.now();
    const d = new ExplainableDetector(subset.approvalsData);
    d.detect(subset.events);
    const elapsed = Date.now() - t0;
    const throughput = Math.round((subset.events.length / (elapsed || 1)) * 1000);
    console.log(`  ${String(subset.events.length).padStart(5)} events: ${String(elapsed).padStart(4)} ms (~${throughput} events/sec)`);
    volumeResults.push({ events: subset.events.length, duration_ms: elapsed, events_per_sec: throughput });
  }

  console.log('\nMethodology Note:');
  console.log('Results are measured on self-generated synthetic data for regression and scalability testing.');
  console.log('They demonstrate deterministic rule execution and graph scaling, not generalized production accuracy.');
  console.log('================================================================\n');

  const resultsDir = path.join(__dirname, '..', 'docs', 'results');
  if (!fs.existsSync(resultsDir)) fs.mkdirSync(resultsDir, { recursive: true });

  const report = {
    dataset: 'unseen_synthetic_evaluation',
    total_events: events.length,
    wall_duration_ms: durationMs,
    true_positives: tp,
    false_positives: fp,
    true_negatives: tn,
    false_negatives: fn,
    precision,
    recall,
    f1,
    false_positive_rate: fpr,
    category_breakdown: categoryStats,
    median_latency_ms: medianLatency,
    p95_latency_ms: p95Latency,
    cpu_user_ms: cpuDiff.user / 1000,
    cpu_system_ms: cpuDiff.system / 1000,
    heap_used_mb: (endMem.heapUsed - startMem.heapUsed) / (1024 * 1024),
    scaling: volumeResults,
    methodology: 'Separated unseen synthetic evaluation with no labels in detector runtime'
  };

  fs.writeFileSync(path.join(resultsDir, 'unseen_evaluation_results.json'), JSON.stringify(report, null, 2), 'utf8');
}

runEvaluation();
