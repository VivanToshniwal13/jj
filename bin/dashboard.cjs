#!/usr/bin/env node
/**
 * bin/dashboard.cjs
 *
 * Lightweight local HTTP server for the Pseudora Trust, but Verify
 * Security Operations Dashboard. Zero external dependencies.
 *
 * Usage:
 *   node bin/dashboard.cjs [--port 3400]
 */

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { execSync } = require('node:child_process');

const args = process.argv.slice(2);
let port = 3400;
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--port' && args[i + 1]) {
    port = parseInt(args[i + 1], 10);
  }
}
if (process.env.PORT) {
  port = parseInt(process.env.PORT, 10);
}

const rootDir = path.resolve(__dirname, '..');
const htmlPath = path.join(rootDir, 'dashboard', 'index.html');

function getMetrics() {
  const resultsDir = path.join(rootDir, 'docs', 'results');
  let attack = null;
  let practice = null;
  let benign = null;
  try {
    const f = path.join(resultsDir, 'attack_evaluation_results.json');
    if (fs.existsSync(f)) attack = JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch (_) {}
  try {
    const f = path.join(resultsDir, 'detector_practice_evaluation.json');
    if (fs.existsSync(f)) practice = JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch (_) {}
  try {
    const f = path.join(resultsDir, 'benign_evaluation_results.json');
    if (fs.existsSync(f)) benign = JSON.parse(fs.readFileSync(f, 'utf8'));
  } catch (_) {}

  return {
    node: process.version,
    openssl: process.versions.openssl,
    pqc_algorithms: ['ML-KEM-768', 'ML-DSA-65', 'AES-256-GCM', 'Scrypt'],
    branch: 'dev (local unpushed)',
    results: {
      synthetic_attacks: attack,
      benign_baseline: benign,
      practice_check: practice
    }
  };
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);

  if (url.pathname === '/' || url.pathname === '/index.html') {
    fs.readFile(htmlPath, 'utf8', (err, data) => {
      if (err) {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end('Error loading dashboard: ' + err.message);
        return;
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    });
    return;
  }

  if (url.pathname === '/api/status') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getMetrics(), null, 2));
    return;
  }

  if (url.pathname === '/api/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok', timestamp: new Date().toISOString() }));
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain' });
  res.end('Not Found');
});

server.listen(port, '127.0.0.1', () => {
  console.log(`[PSEUDORA DASHBOARD] Running at http://127.0.0.1:${port}`);
  console.log(`[PSEUDORA DASHBOARD] Post-Quantum & Access Control Security Operations`);
  console.log(`[PSEUDORA DASHBOARD] Press Ctrl+C to stop.`);
});

process.on('SIGINT', () => {
  server.close(() => process.exit(0));
});
process.on('SIGTERM', () => {
  server.close(() => process.exit(0));
});
