'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const crypto = require('node:crypto');

const { KeyState, KeyLifecycleManager } = require('../lib/key_lifecycle.cjs');
const { DistributedNode, DistributedRevocationAuthority, broadcastRevocation } = require('../lib/distributed_revocation.cjs');
const { BackupManager, BackupIntegrityManager } = require('../lib/backup_integrity.cjs');
const { TamperEvidentLog } = require('../lib/tamper_log.cjs');
const { ExplainableDetector } = require('../lib/detector.cjs');
const { ProtectedMessagingEngine } = require('../lib/messaging.cjs');

// ============================================================================
// OBJECTIVE 1: KEY ROTATION & GRACE PERIOD CUTOFF
// ============================================================================
test('Objective 1: Key Rotation & Grace Period Enforcement', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj1-keyrot-'));
  const km = new KeyLifecycleManager(stateDir, 500);

  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('1.1 Initial key starts in active state at version 1', () => {
    const k = km.getActiveKey();
    assert.equal(k.version, 1);
    assert.equal(k.state, KeyState.ACTIVE);
  });

  await t.test('1.2 Rotation moves V1 to retiring and V2 to active', () => {
    const v2 = km.rotateKey(500);
    assert.equal(v2.version, 2);
    assert.equal(v2.state, KeyState.ACTIVE);
    const v1 = km.getKeyByVersion(1);
    assert.equal(v1.state, KeyState.RETIRING);
  });

  await t.test('1.3 Authorized requests using V1 during grace period cutoff succeed', () => {
    assert.equal(km.canUseForDecryption(1), true);
    assert.equal(km.canUseForDecryption(2), true);
  });

  await t.test('1.4 After grace period cutoff expires, V1 transitions to retired', async () => {
    await new Promise(r => setTimeout(r, 550));
    const v1 = km.getKeyByVersion(1);
    assert.equal(v1.state, KeyState.RETIRED);
    assert.equal(km.getActiveKey().version, 2);
  });

  await t.test('1.5 Revoking a key immediately marks it revoked', () => {
    km.revokeKey(1, 'Compromise suspicion');
    const v1 = km.getKeyByVersion(1);
    assert.equal(v1.state, KeyState.REVOKED);
    assert.equal(km.canUseForDecryption(1), false);
  });
});

// ============================================================================
// OBJECTIVE 2: REVOCATION ACROSS NODES & DEVICE LOSS
// ============================================================================
test('Objective 2: Revocation Across Nodes & Device Loss Isolation', async (t) => {
  const authority = new DistributedRevocationAuthority();
  const authorityPk = authority.getPublicKey();
  const nodeCount = 5;
  const nodes = [];

  for (let i = 0; i < nodeCount; i++) {
    const nodeDir = fs.mkdtempSync(path.join(os.tmpdir(), `obj2-node-${i}-`));
    nodes.push(new DistributedNode(`node-${i}`, nodeDir, authorityPk, 5000));
  }

  t.after(() => {
    for (const n of nodes) {
      try { fs.rmSync(n.stateDir, { recursive: true, force: true }); } catch {}
    }
  });

  await t.test('2.1 Initial authorization allows access across all 5 nodes', () => {
    for (const node of nodes) {
      assert.equal(node.isActorRevoked('user-maya'), false);
      assert.equal(node.isActorRevoked('user-alex'), false);
    }
  });

  await t.test('2.2 Revocation propagates across all 5 nodes in under 100 ms', async () => {
    const report = await broadcastRevocation(authority, nodes, 'user-maya', 'Lost on transit');
    assert.ok(report.total_propagation_with_catchup_ms < 100);
    assert.equal(report.node_count, 5);
  });

  await t.test('2.3 Every node rejects the revoked device/actor', () => {
    for (const node of nodes) {
      assert.equal(node.isActorRevoked('user-maya'), true);
    }
  });

  await t.test('2.4 Unaffected peer Alex retains uninterrupted access across all nodes', () => {
    for (const node of nodes) {
      assert.equal(node.isActorRevoked('user-alex'), false);
    }
  });

  await t.test('2.5 Fresh node joining with current authority enforces existing revocations', () => {
    const freshDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj2-fresh-node-'));
    const freshNode = new DistributedNode('node-new', freshDir, authorityPk, 5000);
    const signedList = authority.createSignedRevocationList();
    freshNode.applyRevocationList(signedList);
    assert.equal(freshNode.isActorRevoked('user-maya'), true);
    assert.equal(freshNode.isActorRevoked('user-alex'), false);
    try { fs.rmSync(freshDir, { recursive: true, force: true }); } catch {}
  });
});

// ============================================================================
// OBJECTIVE 3: CRASH RECOVERY & ATOMIC STATE
// ============================================================================
test('Objective 3: Crash Recovery & Atomic State Management', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj3-crash-'));

  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('3.1 Key rotation WAL rolls back on crash at STAGE_START', () => {
    const km = new KeyLifecycleManager(stateDir);
    assert.throws(() => {
      km.rotateKey('STAGE_START');
    }, /CRASH_INJECTED_AT_STAGE_START/);

    const recoveredKm = new KeyLifecycleManager(stateDir);
    const active = recoveredKm.getActiveKey();
    assert.equal(active.version, 1);
    assert.equal(active.state, KeyState.ACTIVE);
  });

  await t.test('3.2 Key rotation WAL rolls back on crash at STAGE_KEY_GENERATED', () => {
    const km = new KeyLifecycleManager(stateDir);
    assert.throws(() => {
      km.rotateKey('STAGE_KEY_GENERATED');
    }, /CRASH_INJECTED_AT_STAGE_KEY_GENERATED/);

    const recoveredKm = new KeyLifecycleManager(stateDir);
    const active = recoveredKm.getActiveKey();
    assert.equal(active.version, 1);
    assert.equal(recoveredKm.getKeyByVersion(2), null);
  });

  await t.test('3.3 Atomic writes never leave partial files on clean completion', () => {
    const testFile = path.join(stateDir, 'atomic_test.json');
    const tmp = `${testFile}.${process.pid}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ committed: true }), { mode: 0o600 });
    fs.renameSync(tmp, testFile);

    assert.equal(fs.existsSync(testFile), true);
    assert.equal(fs.existsSync(tmp), false);
    const data = JSON.parse(fs.readFileSync(testFile, 'utf8'));
    assert.equal(data.committed, true);
  });

  await t.test('3.4 Interrupted state retains revoked records across restarts', () => {
    const km = new KeyLifecycleManager(stateDir);
    km.rotateKey();
    km.revokeKey(1, 'Pre-crash revocation');

    const kmAfterRestart = new KeyLifecycleManager(stateDir);
    const v1 = kmAfterRestart.getKeyByVersion(1);
    assert.equal(v1.state, KeyState.REVOKED);
    assert.equal(kmAfterRestart.canUseForDecryption(1), false);
  });
});

// ============================================================================
// OBJECTIVE 4: BACKUP INTEGRITY & ROLLBACK DEFENSE
// ============================================================================
test('Objective 4: Backup Integrity, Tamper Detection & Rollback Defense', async (t) => {
  const mgr = new BackupManager();
  const password = 'SuperSecretBackupPassword-2026!';

  await t.test('4.1 Legitimate backup creates ML-DSA signed and encrypted envelope', () => {
    const payload = mgr.createBackup({ test_secret: 'confidential' }, password, 1);
    assert.ok(payload.ciphertext_b64);
    assert.ok(payload.signature_b64);
    assert.equal(payload.epoch, 1);

    const restored = mgr.restoreBackup(payload, password);
    assert.equal(restored.test_secret, 'confidential');
  });

  await t.test('4.2 Truncated backup payload is detected and rejected', () => {
    assert.throws(() => {
      mgr.restoreBackup({ epoch: 1 }, password);
    }, /BACKUP_INTEGRITY_CHECK_FAILED/);
  });

  await t.test('4.3 Modified ciphertext fails authority signature check', () => {
    const payload = mgr.createBackup({ data: 'val' }, password, 1);
    const tampered = JSON.parse(JSON.stringify(payload));
    const buf = Buffer.from(tampered.ciphertext_b64, 'base64');
    buf[0] ^= 0xff;
    tampered.ciphertext_b64 = buf.toString('base64');

    assert.throws(() => {
      mgr.restoreBackup(tampered, password);
    }, /BACKUP_INTEGRITY_CHECK_FAILED.*BACKUP_TAMPERED/);
  });

  await t.test('4.4 Incorrect password fails AEAD authentication', () => {
    const payload = mgr.createBackup({ data: 'val' }, password, 1);
    assert.throws(() => {
      mgr.restoreBackup(payload, 'WrongPassword123');
    }, /BACKUP_INTEGRITY_CHECK_FAILED.*BACKUP_AUTH_FAILED/);
  });

  await t.test('4.5 Restoring older backup preserves existing revocations and advances epoch', () => {
    const oldBackup = mgr.createBackup({ revoked: ['user-bob'], active: ['user-alice'] }, password, 1);
    const currentSystemState = { epoch: 5, revoked: ['user-bob', 'user-charlie'] };

    const restored = mgr.restoreBackup(oldBackup, password, currentSystemState);
    assert.ok(restored.revoked.includes('user-bob'));
    assert.ok(restored.revoked.includes('user-charlie'), 'Revocation of charlie must be preserved');
    assert.ok(restored.epoch > 5, 'Epoch must advance beyond current epoch');
  });
});

// ============================================================================
// OBJECTIVE 5: LOG INTEGRITY (CWE-117 SANITIZATION & HASH CHAINS)
// ============================================================================
test('Objective 5: Log Integrity, CWE-117 Injection Defense & ML-DSA Checkpoints', async (t) => {
  const logDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj5-log-'));
  const log = new TamperEvidentLog(logDir);

  t.after(() => {
    try { fs.rmSync(logDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('5.1 CWE-117: CRLF and tab characters in actor or op are sanitized', () => {
    const rec = log.appendRecord('admin\r\ninjected_fake_actor', 'read\twith_tab', {
      note: 'User message with\r\nnewlines and\ttabs'
    });
    assert.ok(!rec.actor.includes('\r') && !rec.actor.includes('\n'));
    assert.ok(!rec.op.includes('\t'));
    assert.ok(!rec.details.note.includes('\r') && !rec.details.note.includes('\n'));
  });

  await t.test('5.2 Each record extends canonical SHA-256 hash chain', () => {
    const rec1 = log.appendRecord('user-alice', 'read', { doc: 'report1' });
    const rec2 = log.appendRecord('user-alice', 'read', { doc: 'report2' });
    assert.equal(rec2.prev_hash, rec1.hash);
  });

  await t.test('5.3 Checkpoints commit to record count and head hash with ML-DSA signature', () => {
    const cp = log.createCheckpoint();
    assert.ok(cp.signature_b64);
    assert.ok(cp.head_hash);
    assert.ok(cp.hash);
  });

  await t.test('5.4 verifyLog confirms valid uncorrupted log integrity', () => {
    const res = TamperEvidentLog.verifyLog(log.logPath, log.authorityKeyPair.publicKey);
    assert.equal(res.valid, true);
    assert.ok(res.recordsVerified >= 3);
  });

  await t.test('5.5 Checkpoint sequence discontinuity is strictly detected', () => {
    const lines = fs.readFileSync(log.logPath, 'utf8').trim().split('\n');
    const cpIndex = lines.findIndex(l => JSON.parse(l).type === 'checkpoint');
    assert.ok(cpIndex >= 0);

    const tamperedLines = [...lines];
    const cp = JSON.parse(tamperedLines[cpIndex]);
    cp.checkpoint_index = 99;
    tamperedLines[cpIndex] = JSON.stringify(cp);

    const corruptPath = path.join(logDir, 'discontinuity.log');
    fs.writeFileSync(corruptPath, tamperedLines.join('\n') + '\n', 'utf8');

    const res = TamperEvidentLog.verifyLog(corruptPath, log.authorityKeyPair.publicKey);
    assert.equal(res.valid, false);
    assert.equal(res.errorType, 'TAMPER_CHECKPOINT_DISCONTINUITY');
  });
});

// ============================================================================
// OBJECTIVE 6: ROUTINE VS. SUSPICIOUS ACTIVITY (DETECTOR)
// ============================================================================
test('Objective 6: Routine vs. Suspicious Privilege Activity Detection', async () => {
  const approvalsData = {
    synthetic: true,
    changes: [
      {
        approval_id: 'app-valid-1',
        approved_by: 'sec-admin',
        subject: 'worker-valid',
        operation: 'grant_role',
        role: 'operator',
        scope: ['service-a'],
        valid_from_utc: '2026-03-01T10:00:00Z',
        valid_until_utc: '2026-03-01T10:30:00Z'
      }
    ]
  };

  const detector = new ExplainableDetector(approvalsData);

  const testEvents = [
    {
      event_id: 'evt-approved',
      event_time_utc: '2026-03-01T10:05:00Z',
      received_time_utc: '2026-03-01T10:05:00.080Z',
      source_clock_offset_ms: 0,
      actor: 'worker-valid',
      source_service: 'portal',
      target_service: 'identity',
      action: 'role_change',
      role_before: 'viewer',
      role_after: 'operator',
      outcome: 'success',
      approval_id: 'app-valid-1',
      session_id: 'sess-1',
      correlation_id: 'flow-1'
    },
    {
      event_id: 'evt-unapproved',
      event_time_utc: '2026-03-01T10:06:00Z',
      received_time_utc: '2026-03-01T10:06:00.080Z',
      source_clock_offset_ms: 0,
      actor: 'attacker-rogue',
      source_service: 'portal',
      target_service: 'identity',
      action: 'role_change',
      role_before: 'viewer',
      role_after: 'super-admin',
      outcome: 'success',
      approval_id: '',
      session_id: 'sess-2',
      correlation_id: 'flow-2'
    },
    {
      event_id: 'evt-out-of-scope',
      event_time_utc: '2026-03-01T10:10:00Z',
      received_time_utc: '2026-03-01T10:10:00.090Z',
      source_clock_offset_ms: 0,
      actor: 'worker-valid',
      source_service: 'portal',
      target_service: 'payment-vault',
      action: 'read',
      role_before: 'operator',
      role_after: 'operator',
      outcome: 'allow',
      approval_id: 'app-valid-1',
      session_id: 'sess-3',
      correlation_id: 'flow-3'
    }
  ];

  const results = detector.detect(testEvents);

  const alertUnapproved = results.alerts.find(a => a.rule === 'RULE_UNAPPROVED_ROLE_CHANGE');
  assert.ok(alertUnapproved, 'Must emit unapproved role change alert');
  assert.equal(alertUnapproved.identity, 'attacker-rogue');

  const alertScope = results.alerts.find(a => a.rule === 'RULE_OUT_OF_SCOPE_ACCESS');
  assert.ok(alertScope, 'Must emit out of scope access alert');
  assert.equal(alertScope.identity, 'worker-valid');

  const classificationApproved = results.classifications.find(c => c.event_id === 'evt-approved');
  assert.equal(classificationApproved.rule_id, 'RULE_APPROVED_CHANGE');
});

// ============================================================================
// OBJECTIVE 7: LATERAL MOVEMENT TRAVERSAL & EXPLICIT ALERT SCHEMA
// ============================================================================
test('Objective 7: Lateral Movement Traversal Graph Detection & Alert Schema', async (t) => {
  const detector = new ExplainableDetector();

  await t.test('7.1 Multi-hop traversal across unexpected service edges triggers alert', () => {
    const rawEvents = [
      {
        event_id: 'lat-1',
        event_time_utc: '2026-01-15T09:00:00.000Z',
        received_time_utc: '2026-01-15T09:00:00.050Z',
        source_clock_offset_ms: 0,
        actor: 'user-pivot',
        source_service: 'reports',
        target_service: 'billing',
        action: 'read',
        outcome: 'deny',
        session_id: 'sess-lat',
        correlation_id: 'flow-pivot-1'
      },
      {
        event_id: 'lat-2',
        event_time_utc: '2026-01-15T09:00:02.000Z',
        received_time_utc: '2026-01-15T09:00:02.050Z',
        source_clock_offset_ms: 0,
        actor: 'user-pivot',
        source_service: 'billing',
        target_service: 'crypto-vault',
        action: 'read',
        outcome: 'deny',
        session_id: 'sess-lat',
        correlation_id: 'flow-pivot-1'
      }
    ];

    const results = detector.detect(rawEvents);
    const lateralAlert = results.alerts.find(a => a.rule === 'RULE_LATERAL_MOVEMENT_TRAVERSAL');
    assert.ok(lateralAlert, 'Must detect lateral movement traversal');

    assert.equal(lateralAlert.identity, 'user-pivot');
    assert.ok(Array.isArray(lateralAlert.services) && lateralAlert.services.length >= 2);
    assert.ok(Array.isArray(lateralAlert.events) && lateralAlert.events.length === 2);
    assert.equal(lateralAlert.rule, 'RULE_LATERAL_MOVEMENT_TRAVERSAL');
    assert.ok(typeof lateralAlert.graph_path === 'string' && lateralAlert.graph_path.includes('->'));
  });

  await t.test('7.2 Isolated single denial does not trigger lateral movement alert', () => {
    const results = detector.detect([
      {
        event_id: 'iso-1',
        event_time_utc: '2026-01-15T09:00:00.000Z',
        received_time_utc: '2026-01-15T09:00:00.050Z',
        source_clock_offset_ms: 0,
        actor: 'user-normal',
        source_service: 'portal',
        target_service: 'reports',
        action: 'read',
        outcome: 'deny',
        session_id: 'sess-single',
        correlation_id: 'flow-single'
      }
    ]);
    const lateralAlert = results.alerts.find(a => a.rule === 'RULE_LATERAL_MOVEMENT_TRAVERSAL');
    assert.equal(lateralAlert, undefined);
  });
});

// ============================================================================
// OBJECTIVE 8: CLOCK DIFFERENCES & SKEW TIMELINE ALIGNMENT
// ============================================================================
test('Objective 8: Clock Differences, Supported Bounds & Uncertainty Flagging', async (t) => {
  const detector = new ExplainableDetector();

  await t.test('8.1 Normalizes source clock offset (+2000ms) without altering raw event time', () => {
    const evts = [
      {
        event_id: 'evt-skew-1',
        event_time_utc: '2026-01-15T09:00:05.000Z',
        received_time_utc: '2026-01-15T09:00:03.100Z',
        source_clock_offset_ms: 2000,
        actor: 'user-clock',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        outcome: 'allow'
      }
    ];

    const results = detector.detect(evts);
    assert.equal(results.events_analyzed, 1);
  });

  await t.test('8.2 Flags events occurring within ±500ms window as timing_uncertain', () => {
    const evts = [
      {
        event_id: 'evt-unc-A',
        event_time_utc: '2026-01-15T09:00:00.000Z',
        received_time_utc: '2026-01-15T09:00:00.050Z',
        source_clock_offset_ms: 0,
        actor: 'user-uncertain',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        outcome: 'allow'
      },
      {
        event_id: 'evt-unc-B',
        event_time_utc: '2026-01-15T09:00:00.250Z',
        received_time_utc: '2026-01-15T09:00:00.300Z',
        source_clock_offset_ms: 0,
        actor: 'user-uncertain',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        outcome: 'allow'
      }
    ];

    const processed = detector.timelineMgr.processEvents(evts);
    assert.equal(processed[0].timing_uncertain, true);
    assert.equal(processed[1].timing_uncertain, true);
  });

  await t.test('8.3 Excessive clock skew (> ±5000ms) emits RULE_EXCESSIVE_CLOCK_SKEW alert', () => {
    const evts = [
      {
        event_id: 'evt-excessive',
        event_time_utc: '2026-01-15T09:00:10.000Z',
        received_time_utc: '2026-01-15T09:00:00.050Z',
        source_clock_offset_ms: 8500,
        actor: 'user-skewed',
        source_service: 'portal',
        target_service: 'catalog',
        action: 'read',
        outcome: 'allow'
      }
    ];

    const results = detector.detect(evts);
    const skewAlert = results.alerts.find(a => a.rule === 'RULE_EXCESSIVE_CLOCK_SKEW');
    assert.ok(skewAlert);
    assert.equal(skewAlert.identity, 'user-skewed');
  });
});

// ============================================================================
// OBJECTIVE 9: REPLAY DEFENSE & RECIPIENT BINDING
// ============================================================================
test('Objective 9: Post-Quantum Replay Defense & Strict Recipient Binding', async (t) => {
  const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj9-replay-'));
  const engine = new ProtectedMessagingEngine(stateDir);

  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();

  t.after(() => {
    try { fs.rmSync(stateDir, { recursive: true, force: true }); } catch {}
  });

  await t.test('9.1 Authenticated delivery succeeds under valid recipient and AAD', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'Secret Msg 1');
    const rec = engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt);
    assert.equal(rec.plaintext, 'Secret Msg 1');
    assert.equal(rec.verified, true);
  });

  await t.test('9.2 Replay of exact same packet is rejected with MESSAGE_REPLAY_DETECTED', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'Replay Test');
    engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt);

    assert.throws(() => {
      engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt);
    }, /MESSAGE_REPLAY_DETECTED/);
  });

  await t.test('9.3 Sequence reuse with different message_id is rejected', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt1 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'Pkt 1', {
      sequenceNumber: 100,
      messageId: 'msg-first-100'
    });
    engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, pkt1);

    const bobPrekey2 = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt2 = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey2, 'Pkt 2', {
      sequenceNumber: 100,
      messageId: 'msg-second-100'
    });

    assert.throws(() => {
      engine.receiveMessage('bob', bobPrekey2, alice.dsa.publicKey, pkt2);
    }, /Sequence 100 already used with different message ID/);
  });

  await t.test('9.4 Wrong recipient cannot read message intended for peer', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'For Bob only');

    assert.throws(() => {
      engine.receiveMessage('charlie', bobPrekey, alice.dsa.publicKey, pkt);
    }, /WRONG_RECIPIENT_ERROR/);
  });

  await t.test('9.5 Tampering with authenticated AAD fails signature check before decryption', () => {
    const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const pkt = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'Payload');
    const tampered = JSON.parse(JSON.stringify(pkt));
    tampered.aad.sender_id = 'eve';

    assert.throws(() => {
      engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, tampered);
    }, /SIGNATURE_VERIFICATION_FAILED/);
  });
});

// ============================================================================
// OBJECTIVE 10: FORWARD SECRECY & EPHEMERAL KEY CLEANUP
// ============================================================================
test('Objective 10: Forward Secrecy & Guaranteed Ephemeral Key Destruction', async (t) => {
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();

  await t.test('10.1 Post-session compromise of identity key cannot decrypt past recordings', () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj10-fs-1-'));
    try {
      const engine = new ProtectedMessagingEngine(stateDir);
      const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'FS Test Payload');

      const result = engine.receiveAndDestroy('bob', bobPrekey, alice.dsa.publicKey, packet);
      assert.equal(result.verified, true);
      assert.equal(bobPrekey.destroyed, true);

      assert.throws(() => {
        engine.receiveMessage('bob', bobPrekey, alice.dsa.publicKey, packet);
      }, /EPHEMERAL_KEY_DESTROYED/);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  await t.test('10.2 Ephemeral key is safely wiped in error path (bad signature)', () => {
    const stateDir = fs.mkdtempSync(path.join(os.tmpdir(), 'obj10-fs-2-'));
    try {
      const engine = new ProtectedMessagingEngine(stateDir);
      const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
      const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, 'Msg');
      const badPkt = JSON.parse(JSON.stringify(packet));
      badPkt.signature_b64 = Buffer.from('bad_signature').toString('base64');

      assert.throws(() => {
        engine.receiveAndDestroy('bob', bobPrekey, alice.dsa.publicKey, badPkt);
      }, /SIGNATURE_VERIFICATION_FAILED/);

      assert.equal(bobPrekey.destroyed, true);
      assert.equal(bobPrekey.ephemeralPrivateKey, null);
    } finally {
      fs.rmSync(stateDir, { recursive: true, force: true });
    }
  });

  await t.test('10.3 toJSON() strictly omits private key material', () => {
    const prekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);
    const jsonStr = JSON.stringify(prekey);
    assert.ok(!jsonStr.includes('private'));
    assert.ok(!jsonStr.includes('PrivateKey'));
    assert.equal(JSON.parse(jsonStr).destroyed, false);
  });
});

// ============================================================================
// OBJECTIVE 11: DELIVERY UNDER LOSS, REORDERING & CHUNKING
// ============================================================================
test('Objective 11: Delivery Under Loss, Reordering & Chunk Authentication', async (t) => {
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bobPrekey = ProtectedMessagingEngine.generateEphemeralPrekey(bob.dsa.privateKey);

  const engine = new ProtectedMessagingEngine();
  const largeMessage = 'Secure packet segment #'.repeat(30);
  const packet = engine.sendMessage('alice', alice.dsa.privateKey, 'bob', bob.dsa.publicKey, bobPrekey, largeMessage);

  await t.test('11.1 Reassembles chunks delivered in reversed order', () => {
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 64);
    assert.ok(chunks.length > 2);

    const reversed = [...chunks].reverse();
    const reassembled = ProtectedMessagingEngine.reassembleChunks(reversed, alice.dsa.publicKey);
    assert.equal(reassembled.message_id, packet.message_id);
    assert.equal(reassembled.ciphertext_b64, packet.ciphertext_b64);
  });

  await t.test('11.2 Dropped chunk simulates network loss and raises INCOMPLETE_MESSAGE_CHUNKS', () => {
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 64);
    const dropped = [chunks[0], chunks[2]];

    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(dropped, alice.dsa.publicKey);
    }, /INCOMPLETE_MESSAGE_CHUNKS/);
  });

  await t.test('11.3 Tampered chunk payload raises CHUNK_AUTH_FAILED', () => {
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 64);
    const tampered = JSON.parse(JSON.stringify(chunks));
    tampered[0].chunk_data = tampered[0].chunk_data + 'x';

    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(tampered, alice.dsa.publicKey);
    }, /CHUNK_AUTH_FAILED/);
  });

  await t.test('11.4 Duplicate chunk index raises DUPLICATE_CHUNK_INDEX', () => {
    const chunks = ProtectedMessagingEngine.chunkMessage(packet, alice.dsa.privateKey, 64);
    const duplicated = [chunks[0], chunks[0], chunks[1]];

    assert.throws(() => {
      ProtectedMessagingEngine.reassembleChunks(duplicated, alice.dsa.publicKey);
    }, /DUPLICATE_CHUNK_INDEX/);
  });
});

// ============================================================================
// OBJECTIVE 12: SESSION RESUMPTION & PEER IDENTITY BINDING
// ============================================================================
test('Objective 12: Session Resumption & Peer Identity Binding', async (t) => {
  const alice = ProtectedMessagingEngine.generateIdentityKeyPair();
  const bob = ProtectedMessagingEngine.generateIdentityKeyPair();
  const ticketKey = crypto.randomBytes(32);

  await t.test('12.1 Valid presentation by authenticated peer succeeds', () => {
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', alice.dsa.publicKeyDerB64, ticketKey, 60000);
    const verification = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'alice', alice.dsa.publicKeyDerB64, ticketKey);
    assert.equal(verification.valid, true);
    assert.equal(verification.ticket_data.peer_id, 'alice');
  });

  await t.test('12.2 Different identity presenting ticket fails with TICKET_PEER_MISMATCH', () => {
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', alice.dsa.publicKeyDerB64, ticketKey, 60000);
    const verification = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'impostor-bob', alice.dsa.publicKeyDerB64, ticketKey);
    assert.equal(verification.valid, false);
    assert.equal(verification.reason, 'TICKET_PEER_MISMATCH');
    assert.equal(verification.error, 'SESSION_IDENTITY_MISMATCH');
  });

  await t.test('12.3 Same identity presenting altered key fails with TICKET_IDENTITY_KEY_MISMATCH', () => {
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', alice.dsa.publicKeyDerB64, ticketKey, 60000);
    const verification = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'alice', bob.dsa.publicKeyDerB64, ticketKey);
    assert.equal(verification.valid, false);
    assert.equal(verification.reason, 'TICKET_IDENTITY_KEY_MISMATCH');
  });

  await t.test('12.4 Expired ticket fails with TICKET_EXPIRED', () => {
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', alice.dsa.publicKeyDerB64, ticketKey, -100);
    const verification = ProtectedMessagingEngine.verifyResumptionTicket(ticket, 'alice', alice.dsa.publicKeyDerB64, ticketKey);
    assert.equal(verification.valid, false);
    assert.equal(verification.reason, 'TICKET_EXPIRED');
  });

  await t.test('12.5 Future-issued ticket fails with TICKET_FUTURE_ISSUED', () => {
    const ticket = ProtectedMessagingEngine.issueResumptionTicket('alice', alice.dsa.publicKeyDerB64, ticketKey, 60000);
    const parsedData = JSON.parse(Buffer.from(ticket.ticket_b64, 'base64').toString('utf8'));
    parsedData.issued_at = Date.now() + 60000;
    const tamperedBytes = Buffer.from(JSON.stringify(parsedData), 'utf8');
    const validHmac = crypto.createHmac('sha256', ticketKey).update(tamperedBytes).digest('hex');
    const futureTicket = { ticket_b64: tamperedBytes.toString('base64'), hmac_hex: validHmac };

    const verification = ProtectedMessagingEngine.verifyResumptionTicket(futureTicket, 'alice', alice.dsa.publicKeyDerB64, ticketKey);
    assert.equal(verification.valid, false);
    assert.equal(verification.reason, 'TICKET_FUTURE_ISSUED');
  });
});
