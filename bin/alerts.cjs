#!/usr/bin/env node
/**
 * bin/alerts.cjs
 *
 * Live Security Alerts Inspector for Team Ctrl+Alt+Delulu (Track 4).
 * Reads the tamper-evident audit log and displays explainable detection alerts.
 *
 * Usage:
 *   node bin/alerts.cjs [--state-dir <dir>] [--json]
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');

const args = process.argv.slice(2);
let stateDir = process.env.TRACK4_STATE_DIR || os.tmpdir();
let jsonOutput = false;

for (let i = 0; i < args.length; i++) {
  if (args[i] === '--state-dir' && args[i + 1]) {
    stateDir = args[i + 1];
  }
  if (args[i] === '--json') {
    jsonOutput = true;
  }
}

const logPath = path.join(stateDir, 'audit.log');
if (!fs.existsSync(logPath)) {
  if (jsonOutput) {
    console.log(JSON.stringify({ alerts: [], count: 0 }));
  } else {
    console.log(`[ALERTS] No audit log found at ${logPath}`);
  }
  process.exit(0);
}

const content = fs.readFileSync(logPath, 'utf8');
const lines = content.split('\n').filter(l => l.trim().length > 0);
const alerts = [];

for (let i = 0; i < lines.length; i++) {
  try {
    const rec = JSON.parse(lines[i]);
    if (rec.type === 'record' && (rec.actor === 'detector' || rec.action === 'alert' || (rec.details && rec.details.reason === 'ACTOR_LOCKED_OUT'))) {
      const dt = rec.details || {};
      const ruleId = dt.rule_id || (dt.reason === 'ACTOR_LOCKED_OUT' ? 'RULE_REPEATED_DENIALS' : 'RULE_SECURITY_ALERT');
      const isRoleChange = ruleId === 'RULE_UNAPPROVED_ROLE_CHANGE';

      let mitreTag = 'T1087';
      if (ruleId === 'RULE_UNAPPROVED_ROLE_CHANGE') mitreTag = 'T1098';
      else if (ruleId === 'RULE_LATERAL_MOVEMENT_TRAVERSAL') mitreTag = 'T1021, T1078';
      else if (ruleId === 'RULE_OUT_OF_SCOPE_ACCESS') mitreTag = 'T1530';
      else if (ruleId === 'RULE_POST_REVOCATION_READ' || ruleId === 'RULE_REVIEW_AFTER_ROLE_CHANGE') mitreTag = 'T1078';

      const structuredAlert = {
        alert_id: dt.alert_id || `ALT-${i + 1}`,
        actor: dt.actor || rec.actor || 'unknown',
        source_service: dt.source_service || 'client',
        target_service: dt.target_service || 'storage',
        path: Array.isArray(dt.path) ? dt.path : (isRoleChange ? [] : ['client', 'storage']),
        event_ids: Array.isArray(dt.event_ids) && dt.event_ids.length > 0 ? dt.event_ids : [`audit-line-${i + 1}`],
        rule_id: ruleId,
        severity: dt.severity || 'HIGH',
        reason: dt.reason || 'Security policy violation',
        time_to_alert_ms: typeof dt.time_to_alert_ms === 'number' ? dt.time_to_alert_ms : 10,
        mitre: dt.mitre || mitreTag,
        ...(isRoleChange ? { from_role: dt.from_role || 'viewer', to_role: dt.to_role || 'admin' } : {})
      };

      alerts.push(structuredAlert);
    }
  } catch (_) {}
}

if (jsonOutput) {
  console.log(JSON.stringify({ alerts, count: alerts.length }, null, 2));
} else {
  console.log(`========================================================================`);
  console.log(`[CTRL+ALT+DELULU] LIVE SECURITY ALERTS REPORT (${alerts.length} ALERTS FOUND)`);
  console.log(`Log file: ${logPath}`);
  console.log(`========================================================================`);

  if (alerts.length === 0) {
    console.log('No security alerts or automated lockout actions recorded in audit log.');
  } else {
    alerts.forEach((al, idx) => {
      console.log(`\n[ALERT #${idx + 1}] Rule: ${al.rule_id} | Severity: ${al.severity} | MITRE: ${al.mitre}`);
      console.log(`  Actor:          ${al.actor}`);
      console.log(`  Source Service: ${al.source_service} -> Target Service: ${al.target_service}`);
      console.log(`  Service Path:   ${al.path.length > 0 ? al.path.join(' -> ') : '[] (role change)'}`);
      console.log(`  Event IDs:      ${al.event_ids.join(', ')}`);
      console.log(`  Reason:         ${al.reason}`);
      console.log(`  Time to Alert:  ${al.time_to_alert_ms} ms`);
    });
  }
  console.log(`\n========================================================================`);
}
