'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const fs = require('node:fs');
const { ExplainableDetector, EventTimelineManager, ApprovalEngine } = require('../lib/detector.cjs');

test('Detector Isolation: labels.csv is NEVER accessed or read by detector logic', () => {
  // 1. Static code analysis: Assert lib/detector.cjs does not contain "labels.csv"
  const detectorSource = fs.readFileSync(path.join(__dirname, '..', 'lib', 'detector.cjs'), 'utf8');
  assert.equal(
    detectorSource.includes('labels.csv'),
    false,
    'CRITICAL ISOLATION FAILURE: detector code must not reference labels.csv!'
  );

  // 2. Runtime interception: Verify filesystem calls during detect() never open labels.csv
  let labelsCsvAccessed = false;
  const originalReadFileSync = fs.readFileSync;

  fs.readFileSync = function (targetPath, options) {
    if (typeof targetPath === 'string' && targetPath.toLowerCase().includes('labels.csv')) {
      labelsCsvAccessed = true;
      throw new Error('SECURITY VIOLATION: detector attempted to access labels.csv!');
    }
    return originalReadFileSync.apply(this, arguments);
  };

  try {
    const approvalsData = {
      synthetic: true,
      changes: [{
        approval_id: 'change-test',
        approved_by: 'user-admin',
        subject: 'user-alex',
        operation: 'grant_role',
        role: 'report-reader',
        scope: ['reports'],
        valid_from_utc: '2026-01-15T09:00:00Z',
        valid_until_utc: '2026-01-15T09:10:00Z'
      }]
    };

    const detector = new ExplainableDetector(approvalsData);
    const mockEvents = [
      {
        event_id: 'evt-test-1',
        event_time_utc: '2026-01-15T09:01:00.000Z',
        received_time_utc: '2026-01-15T09:01:00.200Z',
        source_clock_offset_ms: 0,
        actor: 'user-alex',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'allow',
        approval_id: '',
        session_id: 'sess-1',
        correlation_id: 'flow-1'
      }
    ];

    const res = detector.detect(mockEvents);
    assert.equal(res.events_analyzed, 1);
    assert.equal(labelsCsvAccessed, false, 'Runtime check: labels.csv was accessed during detection!');
  } finally {
    fs.readFileSync = originalReadFileSync;
  }
});

test('Detector Functional Logic: Out-of-order, Clock Skew, Lateral Movement & Approvals', async (t) => {
  const approvalsData = {
    synthetic: true,
    changes: [
      {
        approval_id: 'change-100',
        approved_by: 'user-admin',
        subject: 'user-alex',
        operation: 'grant_role',
        role: 'report-reader',
        scope: ['reports'],
        valid_from_utc: '2026-01-15T09:01:00Z',
        valid_until_utc: '2026-01-15T09:07:00Z'
      }
    ]
  };

  const detector = new ExplainableDetector(approvalsData);

  await t.test('Detects out-of-order event delivery (evt-B arrived before earlier evt-A)', () => {
    const rawEvents = [
      {
        event_id: 'evt-2',
        event_time_utc: '2026-01-15T09:05:02.000Z',
        received_time_utc: '2026-01-15T09:05:02.200Z',
        source_clock_offset_ms: 0,
        actor: 'user-alex',
        source_service: 'portal',
        target_service: 'reports',
        action: 'read',
        role_before: 'report-reader',
        role_after: 'report-reader',
        outcome: 'allow',
        approval_id: 'change-100'
      },
      {
        event_id: 'evt-1',
        event_time_utc: '2026-01-15T09:05:01.000Z',
        received_time_utc: '2026-01-15T09:05:04.000Z', // Arrived later!
        source_clock_offset_ms: 0,
        actor: 'user-alex',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        role_before: 'report-reader',
        role_after: 'report-reader',
        outcome: 'allow',
        approval_id: ''
      }
    ];

    const results = detector.detect(rawEvents);
    const classification = results.classifications.find(c => c.event_id === 'evt-1');
    assert.equal(classification.label, 'routine_delayed_delivery');
    assert.equal(classification.rule_id, 'RULE_TIMELINE_ORDERING');
  });

  await t.test('Corrects source clock offset (+2000 ms)', () => {
    const rawEvents = [
      {
        event_id: 'evt-skew',
        event_time_utc: '2026-01-15T09:06:03.000Z',
        received_time_utc: '2026-01-15T09:06:01.200Z',
        source_clock_offset_ms: 2000,
        actor: 'user-alex',
        source_service: 'portal',
        target_service: 'reports',
        action: 'read',
        role_before: 'report-reader',
        role_after: 'report-reader',
        outcome: 'allow',
        approval_id: 'change-100'
      }
    ];

    const results = detector.detect(rawEvents);
    const classification = results.classifications.find(c => c.event_id === 'evt-skew');
    assert.equal(classification.label, 'routine_clock_offset');
    assert.equal(classification.rule_id, 'RULE_SOURCE_CLOCK_OFFSET');
  });

  await t.test('Detects unapproved role change and subsequent read', () => {
    const rawEvents = [
      {
        event_id: 'evt-unapproved-role',
        event_time_utc: '2026-01-15T09:03:05.000Z',
        received_time_utc: '2026-01-15T09:03:05.200Z',
        source_clock_offset_ms: 0,
        actor: 'user-blair',
        source_service: 'admin-console',
        target_service: 'identity',
        action: 'role_change',
        role_before: 'viewer',
        role_after: 'operator',
        outcome: 'success',
        approval_id: '',
        session_id: 'sess-blair',
        correlation_id: 'flow-blair'
      },
      {
        event_id: 'evt-subsequent-read',
        event_time_utc: '2026-01-15T09:03:06.000Z',
        received_time_utc: '2026-01-15T09:03:06.200Z',
        source_clock_offset_ms: 0,
        actor: 'user-blair',
        source_service: 'portal',
        target_service: 'reports',
        action: 'read',
        role_before: 'operator',
        role_after: 'operator',
        outcome: 'allow',
        approval_id: '',
        session_id: 'sess-blair',
        correlation_id: 'flow-blair'
      }
    ];

    const results = detector.detect(rawEvents);
    assert.equal(results.alerts.length, 2);
    assert.equal(results.alerts[0].rule_id, 'RULE_UNAPPROVED_ROLE_CHANGE');
    assert.equal(results.alerts[1].rule_id, 'RULE_REVIEW_AFTER_ROLE_CHANGE');
  });

  await t.test('Chains lateral movement across unexpected service edges', () => {
    const rawEvents = [
      {
        event_id: 'evt-hop-1',
        event_time_utc: '2026-01-15T09:04:00.000Z',
        received_time_utc: '2026-01-15T09:04:00.100Z',
        source_clock_offset_ms: 0,
        actor: 'svc-report-worker',
        source_service: 'reports',
        target_service: 'billing',
        action: 'read',
        role_before: 'service-reader',
        role_after: 'service-reader',
        outcome: 'deny',
        session_id: 'sess-worker',
        correlation_id: 'flow-attack'
      },
      {
        event_id: 'evt-hop-2',
        event_time_utc: '2026-01-15T09:04:02.000Z',
        received_time_utc: '2026-01-15T09:04:02.100Z',
        source_clock_offset_ms: 0,
        actor: 'svc-report-worker',
        source_service: 'billing',
        target_service: 'archive',
        action: 'read',
        role_before: 'service-reader',
        role_after: 'service-reader',
        outcome: 'deny',
        session_id: 'sess-worker',
        correlation_id: 'flow-attack'
      }
    ];

    const results = detector.detect(rawEvents);
    const lateralAlert = results.alerts.find(a => a.rule_id === 'RULE_LATERAL_MOVEMENT_TRAVERSAL');
    assert.ok(lateralAlert);
    assert.equal(lateralAlert.graph_path, 'reports -> billing -> archive');
    assert.deepEqual(lateralAlert.event_ids, ['evt-hop-1', 'evt-hop-2']);
  });

  await t.test('Isolated single denial does not trigger lateral movement alarm', () => {
    const rawEvents = [
      {
        event_id: 'evt-isolated',
        event_time_utc: '2026-01-15T09:08:02.000Z',
        received_time_utc: '2026-01-15T09:08:02.200Z',
        source_clock_offset_ms: 0,
        actor: 'user-casey',
        source_service: 'portal',
        target_service: 'billing',
        action: 'read',
        role_before: 'viewer',
        role_after: 'viewer',
        outcome: 'deny',
        session_id: 'sess-casey',
        correlation_id: 'flow-casey'
      }
    ];

    const results = detector.detect(rawEvents);
    // Should NOT trigger HIGH lateral movement alert
    const lateralAlert = results.alerts.find(a => a.rule_id === 'RULE_LATERAL_MOVEMENT_TRAVERSAL');
    assert.equal(lateralAlert, undefined);
    const classification = results.classifications.find(c => c.event_id === 'evt-isolated');
    assert.equal(classification.label, 'isolated_denial');
  });

  await t.test('Every alert contains required structured fields and MITRE tags', () => {
    const rawEvents = [
      // 1. Role change without approval -> RULE_UNAPPROVED_ROLE_CHANGE
      {
        event_id: 'evt-test-role',
        event_time_utc: '2026-01-15T09:00:01.000Z',
        received_time_utc: '2026-01-15T09:00:01.100Z',
        source_clock_offset_ms: 0,
        actor: 'user-malicious',
        source_service: 'identity-service',
        target_service: 'identity-service',
        action: 'role_change',
        role_before: 'viewer',
        role_after: 'security-admin',
        outcome: 'allow',
        approval_id: '',
        session_id: 'sess-role',
        correlation_id: 'flow-role'
      },
      // 2. Out of scope access -> RULE_OUT_OF_SCOPE_ACCESS
      {
        event_id: 'evt-test-scope',
        event_time_utc: '2026-01-15T09:02:00.000Z',
        received_time_utc: '2026-01-15T09:02:00.100Z',
        source_clock_offset_ms: 0,
        actor: 'user-alex',
        source_service: 'portal',
        target_service: 'classified-records',
        action: 'read',
        role_before: 'report-reader',
        role_after: 'report-reader',
        outcome: 'allow',
        approval_id: 'change-100',
        session_id: 'sess-scope',
        correlation_id: 'flow-scope'
      },
      // 3. Lateral movement traversal -> RULE_LATERAL_MOVEMENT_TRAVERSAL
      {
        event_id: 'evt-test-lat1',
        event_time_utc: '2026-01-15T09:03:00.000Z',
        received_time_utc: '2026-01-15T09:03:00.100Z',
        source_clock_offset_ms: 0,
        actor: 'user-traversal',
        source_service: 'reports',
        target_service: 'billing',
        action: 'read',
        role_before: 'user',
        role_after: 'user',
        outcome: 'deny',
        session_id: 'sess-lat',
        correlation_id: 'flow-lat'
      },
      {
        event_id: 'evt-test-lat2',
        event_time_utc: '2026-01-15T09:03:02.000Z',
        received_time_utc: '2026-01-15T09:03:02.100Z',
        source_clock_offset_ms: 0,
        actor: 'user-traversal',
        source_service: 'billing',
        target_service: 'archive',
        action: 'read',
        role_before: 'user',
        role_after: 'user',
        outcome: 'deny',
        session_id: 'sess-lat',
        correlation_id: 'flow-lat'
      }
    ];

    const results = detector.detect(rawEvents);
    assert.ok(results.alerts.length >= 3);

    for (const al of results.alerts) {
      assert.ok(typeof al.actor === 'string' && al.actor.length > 0, 'actor must be non-empty string');
      assert.ok(typeof al.source_service === 'string' && al.source_service.length > 0, 'source_service must be non-empty string');
      assert.ok(typeof al.target_service === 'string' && al.target_service.length > 0, 'target_service must be non-empty string');
      assert.ok(Array.isArray(al.path), 'path must be an array');
      assert.ok(Array.isArray(al.event_ids) && al.event_ids.length > 0, 'event_ids must be non-empty array');
      assert.ok(typeof al.rule_id === 'string' && al.rule_id.length > 0, 'rule_id must be non-empty string');
      assert.ok(typeof al.severity === 'string' && al.severity.length > 0, 'severity must be non-empty string');
      assert.ok(typeof al.reason === 'string' && al.reason.length > 0, 'reason must be non-empty string');
      assert.ok(typeof al.time_to_alert_ms === 'number' && !isNaN(al.time_to_alert_ms), 'time_to_alert_ms must be a number');
      assert.ok(typeof al.mitre === 'string' && al.mitre.length > 0, 'mitre must be non-empty string');

      if (al.rule_id === 'RULE_UNAPPROVED_ROLE_CHANGE') {
        assert.equal(al.path.length, 0, 'path must be [] for role change');
        assert.ok(typeof al.from_role === 'string' && al.from_role.length > 0, 'from_role must be present for role change');
        assert.ok(typeof al.to_role === 'string' && al.to_role.length > 0, 'to_role must be present for role change');
        assert.equal(al.mitre, 'T1098');
      } else {
        assert.ok(al.path.length > 0, 'path must be non-empty for non-role-change alert');
      }
    }
  });
});
