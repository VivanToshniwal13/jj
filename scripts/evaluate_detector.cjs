'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ExplainableDetector } = require('../lib/detector.cjs');

function parseCsv(content) {
  const lines = content.split('\n').filter(l => l.trim().length > 0);
  if (lines.length === 0) return [];
  const headers = lines[0].split(',').map(h => h.trim());
  const rows = [];
  for (let i = 1; i < lines.length; i++) {
    const cols = lines[i].split(',').map(c => c.trim());
    const obj = {};
    for (let j = 0; j < headers.length; j++) {
      obj[headers[j]] = cols[j] !== undefined ? cols[j] : '';
    }
    rows.push(obj);
  }
  return rows;
}

function main() {
  const toolkitDir = path.join(__dirname, '..', '..', 'pseudora-secret-wards', 'Track-4-Toolkit', 'practice');
  const eventsPath = path.join(toolkitDir, 'events.csv');
  const approvalsPath = path.join(toolkitDir, 'approvals.json');
  const labelsPath = path.join(toolkitDir, 'labels.csv');

  if (!fs.existsSync(eventsPath) || !fs.existsSync(approvalsPath) || !fs.existsSync(labelsPath)) {
    console.error('Toolkit practice files not found at expected location');
    process.exit(1);
  }

  const rawEvents = parseCsv(fs.readFileSync(eventsPath, 'utf8'));
  const approvalsData = JSON.parse(fs.readFileSync(approvalsPath, 'utf8'));
  const trueLabels = parseCsv(fs.readFileSync(labelsPath, 'utf8'));

  const groundTruth = new Map();
  for (const row of trueLabels) {
    groundTruth.set(row.event_id, {
      label: row.label,
      reason: row.reason
    });
  }

  // Execute detector (labels.csv is strictly NOT passed to the detector)
  const detector = new ExplainableDetector(approvalsData);
  const results = detector.detect(rawEvents);

  const predictedMap = new Map();
  for (const c of results.classifications) {
    predictedMap.set(c.event_id, c);
  }

  // Calculate Precision, Recall, F1 for Security Alerts (unexpected_role_change, review_after_role_change, lateral_movement_candidate)
  const ALERT_CLASSES = new Set([
    'unexpected_role_change',
    'review_after_role_change',
    'lateral_movement_candidate'
  ]);

  let truePositives = 0;
  let falsePositives = 0;
  let falseNegatives = 0;
  let trueNegatives = 0;

  let totalExactMatches = 0;
  const alertLatencies = [];

  console.log('================================================================');
  console.log('DETECTOR EVALUATION AGAINST PRACTICE DATASET (GOALS 6, 7, 8)');
  console.log('================================================================');
  console.log('Per-Event Classification Comparison:\n');

  for (const ev of rawEvents) {
    const id = ev.event_id;
    const truth = groundTruth.get(id);
    const pred = predictedMap.get(id);

    const isTrueAlert = ALERT_CLASSES.has(truth.label);
    const isPredAlert = ALERT_CLASSES.has(pred.label);

    const match = truth.label === pred.label;
    if (match) totalExactMatches++;

    if (isTrueAlert && isPredAlert) {
      truePositives++;
      const eventTime = new Date(ev.event_time_utc).getTime();
      const recvTime = new Date(ev.received_time_utc).getTime();
      alertLatencies.push(recvTime - eventTime);
    } else if (!isTrueAlert && isPredAlert) {
      falsePositives++;
    } else if (isTrueAlert && !isPredAlert) {
      falseNegatives++;
    } else {
      trueNegatives++;
    }

    const mark = match ? '✔ PASS' : '✖ MISMATCH';
    console.log(`${mark} [${id}] Predicted: ${pred.label.padEnd(28)} | Expected: ${truth.label.padEnd(28)}`);
    if (!match) {
      console.log(`       Reason Pred: ${pred.reason}`);
      console.log(`       Reason True: ${truth.reason}`);
    }
  }

  const precision = truePositives + falsePositives > 0 ? truePositives / (truePositives + falsePositives) : 1;
  const recall = truePositives + falseNegatives > 0 ? truePositives / (truePositives + falseNegatives) : 1;
  const f1 = precision + recall > 0 ? (2 * precision * recall) / (precision + recall) : 1;

  alertLatencies.sort((a, b) => a - b);
  const medianAlertLatency = alertLatencies.length > 0 ? alertLatencies[Math.floor(alertLatencies.length / 2)] : 0;

  console.log('\n----------------------------------------------------------------');
  console.log('METRICS SUMMARY ON PRACTICE SET:');
  console.log(`  Total Events Analyzed:    ${rawEvents.length}`);
  console.log(`  Exact Label Matches:      ${totalExactMatches} / ${rawEvents.length} (${((totalExactMatches / rawEvents.length) * 100).toFixed(1)}%)`);
  console.log(`  Alert Detection Precision: ${(precision * 100).toFixed(1)}%`);
  console.log(`  Alert Detection Recall:    ${(recall * 100).toFixed(1)}%`);
  console.log(`  Alert Detection F1 Score:  ${(f1 * 100).toFixed(1)}%`);
  console.log(`  Median Ingestion Delay:    ${medianAlertLatency} ms`);
  console.log('----------------------------------------------------------------');
  console.log('HONEST METHODOLOGY DISCLAIMER:');
  console.log('Notice: 22 practice events demonstrate functional capabilities only');
  console.log('(role change checks, graph traversal chaining, and clock offset).');
  console.log('A small 22-event scenario cannot establish general statistical accuracy');
  console.log('or production false-positive rates without synthetic scale testing.');
  console.log('================================================================\n');

  const evalSummary = {
    dataset: 'practice/events.csv (22 events)',
    total_events: rawEvents.length,
    exact_label_accuracy: totalExactMatches / rawEvents.length,
    precision,
    recall,
    f1,
    median_time_to_alert_ms: medianAlertLatency,
    disclaimer: '22 practice events cannot establish broader accuracy or production baseline'
  };

  fs.writeFileSync(path.join(__dirname, '..', 'detector_practice_evaluation.json'), JSON.stringify(evalSummary, null, 2), 'utf8');
}

main();
