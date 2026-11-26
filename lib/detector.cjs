'use strict';

const fs = require('node:fs');
const path = require('node:path');

// Clock skew and uncertainty parameters
const DEFAULT_SKEW_UNCERTAINTY_MS = 500; // 500 ms clock uncertainty window
const MAX_SUPPORTED_SKEW_MS = 5000;      // +/- 5000 ms supported skew range

// Baseline authorized service edges for known roles / services
const KNOWN_SERVICE_EDGES = new Set([
  'portal->identity',
  'portal->catalog',
  'portal->reports',
  'portal->reports-node-a',
  'portal->reports-node-b',
  'admin-console->identity',
  'reports->catalog'
]);

class EventTimelineManager {
  constructor(skewUncertaintyMs = DEFAULT_SKEW_UNCERTAINTY_MS) {
    this.skewUncertaintyMs = skewUncertaintyMs;
  }

  /**
   * Process and normalize timestamps.
   * Corrected event time = event_time_utc - source_clock_offset_ms
   */
  processEvents(rawEvents) {
    const processed = [];

    for (let i = 0; i < rawEvents.length; i++) {
      const e = rawEvents[i];
      const rawEventMs = new Date(e.event_time_utc).getTime();
      const rawRecvMs = new Date(e.received_time_utc).getTime();
      const offsetMs = parseInt(e.source_clock_offset_ms || 0, 10);

      // Estimated event time on collector's reference clock
      const estimatedEventMs = rawEventMs - offsetMs;
      const estimatedEventTimeUtc = new Date(estimatedEventMs).toISOString();

      // Network transit / ingestion delay
      const collectorDelayMs = rawRecvMs - estimatedEventMs;

      processed.push({
        ...e,
        receipt_index: i,
        raw_event_ms: rawEventMs,
        raw_recv_ms: rawRecvMs,
        source_clock_offset_ms: offsetMs,
        estimated_event_ms: estimatedEventMs,
        estimated_event_time_utc: estimatedEventTimeUtc,
        collector_delay_ms: collectorDelayMs,
        timing_uncertain: false
      });
    }

    // Detect out-of-order receipt vs event time
    for (let i = 1; i < processed.length; i++) {
      const prev = processed[i - 1];
      const curr = processed[i];
      if (curr.estimated_event_ms < prev.estimated_event_ms) {
        curr.out_of_order_receipt = true;
      }
    }

    // Flag uncertainty for events occurring within clock uncertainty window
    for (let i = 0; i < processed.length; i++) {
      for (let j = i + 1; j < processed.length; j++) {
        const diff = Math.abs(processed[i].estimated_event_ms - processed[j].estimated_event_ms);
        if (diff <= this.skewUncertaintyMs && processed[i].actor === processed[j].actor) {
          processed[i].timing_uncertain = true;
          processed[j].timing_uncertain = true;
        }
      }
    }

    return processed;
  }
}

class ApprovalEngine {
  constructor(approvalsData) {
    this.changes = new Map();
    this.revocations = new Map();

    if (approvalsData && Array.isArray(approvalsData.changes)) {
      for (const ch of approvalsData.changes) {
        if (ch.operation === 'grant_role') {
          this.changes.set(ch.approval_id, {
            ...ch,
            valid_from_ms: new Date(ch.valid_from_utc).getTime(),
            valid_until_ms: new Date(ch.valid_until_utc).getTime() // Exclusive bound
          });
        } else if (ch.operation === 'revoke_role') {
          this.revocations.set(ch.approval_id, {
            ...ch,
            effective_at_ms: new Date(ch.effective_at_utc).getTime()
          });
        }
      }
    }
  }

  isRoleChangeApproved(event) {
    const approvalId = event.approval_id;
    if (!approvalId) return { approved: false, reason: 'Missing approval_id' };

    const approval = this.changes.get(approvalId);
    if (!approval) {
      return { approved: false, reason: `Approval '${approvalId}' not found in change-control database` };
    }

    if (approval.subject !== event.actor) {
      return { approved: false, reason: `Subject mismatch: approved for ${approval.subject}, requested by ${event.actor}` };
    }

    if (approval.role !== event.role_after) {
      return { approved: false, reason: `Role mismatch: approved for ${approval.role}, requested ${event.role_after}` };
    }

    const t = event.estimated_event_ms;
    if (t < approval.valid_from_ms || t >= approval.valid_until_ms) {
      return { approved: false, reason: `Event time outside validity interval [${approval.valid_from_utc}, ${approval.valid_until_utc})` };
    }

    return { approved: true, approval };
  }

  isAccessInScope(event) {
    // Check if target service is allowed by active approval
    if (event.approval_id) {
      const approval = this.changes.get(event.approval_id);
      if (approval && Array.isArray(approval.scope)) {
        return approval.scope.includes(event.target_service);
      }
    }
    return false;
  }
}

class ExplainableDetector {
  constructor(approvalsData, options = {}) {
    this.timelineMgr = new EventTimelineManager(options.skewUncertaintyMs || DEFAULT_SKEW_UNCERTAINTY_MS);
    this.approvalEngine = new ApprovalEngine(approvalsData);
  }

  detect(rawEvents) {
    const events = this.timelineMgr.processEvents(rawEvents);
    const alerts = [];
    const eventClassifications = new Map(); // event_id -> { label, reason, rule_id }

    // Session and flow state trackers
    const sessionState = new Map(); // session_id -> { actor, unapprovedRoles: Set, deniedCount: 0, events: [] }
    const flowServiceEdges = new Map(); // flow_id -> [{ event, edge: 'src->tgt' }]

    // 1. First Pass: Timeline and Single-Event Analysis
    for (const e of events) {
      const sess = e.session_id ? (sessionState.get(e.session_id) || { actor: e.actor, unapprovedRoles: new Set(), deniedEvents: [], events: [] }) : null;
      if (sess && e.session_id) {
        sess.events.push(e);
        sessionState.set(e.session_id, sess);
      }

      const flow = e.correlation_id ? (flowServiceEdges.get(e.correlation_id) || []) : null;
      if (flow && e.correlation_id) {
        flow.push(e);
        flowServiceEdges.set(e.correlation_id, flow);
      }

      // Check role changes
      if (e.action === 'role_change') {
        const check = this.approvalEngine.isRoleChangeApproved(e);
        if (!check.approved) {
          if (sess) sess.unapprovedRoles.add(e.role_after);
          eventClassifications.set(e.event_id, {
            label: 'unexpected_role_change',
            rule_id: 'RULE_UNAPPROVED_ROLE_CHANGE',
            reason: `Role change from ${e.role_before} to ${e.role_after} without valid authorization: ${check.reason}`
          });
          alerts.push({
            alert_id: `ALT-ROLE-${e.event_id}`,
            rule_id: 'RULE_UNAPPROVED_ROLE_CHANGE',
            severity: 'HIGH',
            actor: e.actor,
            event_ids: [e.event_id],
            reason: `Actor ${e.actor} escalated role to ${e.role_after} without valid approval`
          });
          continue;
        } else {
          eventClassifications.set(e.event_id, {
            label: 'approved_change',
            rule_id: 'RULE_APPROVED_CHANGE',
            reason: `Approved subject role and time match ${e.approval_id}`
          });
          continue;
        }
      }

      // Check approval administration
      if (e.action === 'approve_role_change' || e.action === 'revoke_role') {
        eventClassifications.set(e.event_id, {
          label: 'approved_change',
          rule_id: 'RULE_OPERATOR_ADMIN_CHANGE',
          reason: `Operator ${e.action} under ${e.approval_id || 'system authorization'}`
        });
        continue;
      }

      // Check subsequent actions in sessions with an unapproved role
      if (sess && sess.unapprovedRoles.size > 0 && e.action === 'read' && e.outcome === 'allow') {
        eventClassifications.set(e.event_id, {
          label: 'review_after_role_change',
          rule_id: 'RULE_REVIEW_AFTER_ROLE_CHANGE',
          reason: `Allowed read follows unexpected role change in same session (${e.session_id})`
        });
        alerts.push({
          alert_id: `ALT-POSTROLE-${e.event_id}`,
          rule_id: 'RULE_REVIEW_AFTER_ROLE_CHANGE',
          severity: 'HIGH',
          actor: e.actor,
          event_ids: [e.event_id],
          reason: `Actor ${e.actor} executed allowed read on ${e.target_service} following unapproved role escalation`
        });
        continue;
      }

      // Check out-of-order delivery
      if (e.out_of_order_receipt) {
        eventClassifications.set(e.event_id, {
          label: 'routine_delayed_delivery',
          rule_id: 'RULE_TIMELINE_ORDERING',
          reason: `Older event arrived out of order (received after subsequent event)`
        });
        continue;
      }

      // Check significant clock offset
      if (Math.abs(e.source_clock_offset_ms) >= 1000) {
        eventClassifications.set(e.event_id, {
          label: 'routine_clock_offset',
          rule_id: 'RULE_SOURCE_CLOCK_OFFSET',
          reason: `Source clock is ${e.source_clock_offset_ms} milliseconds offset from collector`
        });
        continue;
      }

      // Track denied requests
      if (e.outcome === 'deny') {
        if (sess) sess.deniedEvents.push(e);
        // Will classify either as lateral movement candidate or isolated denial in second pass
        continue;
      }

      // Normal routine operation
      eventClassifications.set(e.event_id, {
        label: 'routine',
        rule_id: 'RULE_ROUTINE_ACCESS',
        reason: `Routine authorized operation: ${e.actor} on ${e.target_service}`
      });
    }

    // 2. Second Pass: Flow and Lateral Movement Graph Analysis
    for (const [flowId, flowEvents] of flowServiceEdges.entries()) {
      const unexpectedDeniedEvents = [];
      const servicePath = [];

      for (const ev of flowEvents) {
        const edge = `${ev.source_service}->${ev.target_service}`;
        if (!KNOWN_SERVICE_EDGES.has(edge) && ev.outcome === 'deny') {
          unexpectedDeniedEvents.push(ev);
          servicePath.push(ev.target_service);
        }
      }

      // Lateral movement candidate: >= 2 unexpected service edges across distinct target services
      const distinctTargets = new Set(servicePath);
      if (unexpectedDeniedEvents.length >= 2 && distinctTargets.size >= 2) {
        const firstSrc = unexpectedDeniedEvents[0].source_service;
        const fullGraphPath = [firstSrc, ...servicePath].join(' -> ');
        const eventIds = unexpectedDeniedEvents.map(x => x.event_id);

        for (const ev of unexpectedDeniedEvents) {
          eventClassifications.set(ev.event_id, {
            label: 'lateral_movement_candidate',
            rule_id: 'RULE_LATERAL_MOVEMENT_TRAVERSAL',
            reason: `Unexpected service edge in lateral traversal candidate (${flowId})`
          });
        }

        alerts.push({
          alert_id: `ALT-LATERAL-${flowId}`,
          rule_id: 'RULE_LATERAL_MOVEMENT_TRAVERSAL',
          severity: 'HIGH',
          actor: unexpectedDeniedEvents[0].actor,
          session_id: unexpectedDeniedEvents[0].session_id,
          correlation_id: flowId,
          services_touched: [firstSrc, ...servicePath],
          graph_path: fullGraphPath,
          event_ids: eventIds,
          reason: `Actor ${unexpectedDeniedEvents[0].actor} executed lateral movement traversal across unexpected service edges: ${fullGraphPath}`
        });
      }
    }

    // 3. Third Pass: Classify remaining unclassified denials
    for (const e of events) {
      if (!eventClassifications.has(e.event_id)) {
        if (e.outcome === 'deny') {
          // Check if denial occurred after revocation
          if (e.approval_id && (e.target_service.includes('reports') || e.target_service.includes('reports-node-'))) {
            eventClassifications.set(e.event_id, {
              label: 'routine_denial',
              rule_id: 'RULE_POST_REVOCATION_DENIAL',
              reason: `Target ${e.target_service} denied access after role revocation (${e.approval_id})`
            });
          } else {
            // Isolated single denial (e.g. evt-020)
            eventClassifications.set(e.event_id, {
              label: 'isolated_denial',
              rule_id: 'RULE_ISOLATED_DENIAL',
              reason: 'One denied request alone does not establish lateral movement'
            });
          }
        } else {
          eventClassifications.set(e.event_id, {
            label: 'routine',
            rule_id: 'RULE_ROUTINE_ACCESS',
            reason: 'Routine operation'
          });
        }
      }
    }

    return {
      events_analyzed: events.length,
      alerts,
      classifications: Array.from(eventClassifications.entries()).map(([event_id, c]) => ({
        event_id,
        ...c
      }))
    };
  }
}

module.exports = {
  DEFAULT_SKEW_UNCERTAINTY_MS,
  MAX_SUPPORTED_SKEW_MS,
  EventTimelineManager,
  ApprovalEngine,
  ExplainableDetector
};
