#!/usr/bin/env node
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { ExplainableDetector } = require('../lib/detector.cjs');

function printUsage() {
  console.log(`
Usage: detect [options]

Options:
  --events, -e <path>        Path to events.csv
  --approvals, -a <path>     Path to approvals.json
  --output, -o <path>        Output path for results JSON
  --json                     Print machine-readable JSON to stdout
  --help, -h                 Show this help message
`);
}

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

function parseArgs() {
  const args = process.argv.slice(2);
  let eventsPath = null;
  let approvalsPath = null;
  let outputPath = null;
  let jsonOutput = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--help' || arg === '-h') {
      printUsage();
      process.exit(0);
    } else if (arg === '--events' || arg === '-e') {
      eventsPath = args[++i];
    } else if (arg === '--approvals' || arg === '-a') {
      approvalsPath = args[++i];
    } else if (arg === '--output' || arg === '-o') {
      outputPath = args[++i];
    } else if (arg === '--json') {
      jsonOutput = true;
    }
  }

  // Fallbacks to default practice paths if available
  if (!eventsPath) {
    const defaultEvents = path.join(__dirname, '..', '..', 'pseudora-secret-wards', 'Track-4-Toolkit', 'practice', 'events.csv');
    if (fs.existsSync(defaultEvents)) eventsPath = defaultEvents;
  }
  if (!approvalsPath) {
    const defaultApprovals = path.join(__dirname, '..', '..', 'pseudora-secret-wards', 'Track-4-Toolkit', 'practice', 'approvals.json');
    if (fs.existsSync(defaultApprovals)) approvalsPath = defaultApprovals;
  }

  return { eventsPath, approvalsPath, outputPath, jsonOutput };
}

function main() {
  const { eventsPath, approvalsPath, outputPath, jsonOutput } = parseArgs();

  if (!eventsPath || !fs.existsSync(eventsPath)) {
    console.error(`Error: events.csv not found at ${eventsPath}`);
    process.exit(1);
  }
  if (!approvalsPath || !fs.existsSync(approvalsPath)) {
    console.error(`Error: approvals.json not found at ${approvalsPath}`);
    process.exit(1);
  }

  const rawEvents = parseCsv(fs.readFileSync(eventsPath, 'utf8'));
  const approvalsData = JSON.parse(fs.readFileSync(approvalsPath, 'utf8'));

  const detector = new ExplainableDetector(approvalsData);
  const results = detector.detect(rawEvents);

  if (outputPath) {
    fs.writeFileSync(outputPath, JSON.stringify(results, null, 2), 'utf8');
  }

  if (jsonOutput) {
    console.log(JSON.stringify(results, null, 2));
    process.exit(0);
  }

  console.log('================================================================');
  console.log('EXPLAINABLE DETECTOR REPORT (GOALS 6, 7, 8)');
  console.log('Team Ctrl+Alt+Delulu | Deterministic Rule & Graph Analysis');
  console.log('================================================================');
  console.log(`Events Analyzed:   ${results.events_analyzed}`);
  console.log(`Security Alerts:   ${results.alerts.length}`);
  console.log('----------------------------------------------------------------');

  if (results.alerts.length > 0) {
    console.log('ACTIVE SECURITY ALERTS:\n');
    for (const alt of results.alerts) {
      console.log(`[${alt.severity}] ${alt.alert_id} - ${alt.rule_id}`);
      console.log(`  Actor:      ${alt.actor}`);
      console.log(`  Events:     ${alt.event_ids.join(', ')}`);
      if (alt.graph_path) console.log(`  Graph Path: ${alt.graph_path}`);
      console.log(`  Reason:     ${alt.reason}`);
      console.log('');
    }
  } else {
    console.log('No security alerts triggered.');
  }

  console.log('----------------------------------------------------------------');
  console.log('EVENT CLASSIFICATION SUMMARY:');
  const counts = {};
  for (const c of results.classifications) {
    counts[c.label] = (counts[c.label] || 0) + 1;
  }
  for (const [lbl, cnt] of Object.entries(counts)) {
    console.log(`  ${lbl.padEnd(30)} : ${cnt}`);
  }
  console.log('================================================================');
}

main();
