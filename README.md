# Track 4: Trust, but verify - Team Ctrl+Alt+Delulu

**Submission Repository for Yugaantar DevForge Track 4**

Post-quantum cryptographic access control, tamper-evident audit logging, and explainable privilege-escalation/lateral-movement detection.

---

## 1. Quick Start & Verification (Clean-Machine Reproduction)

### Prerequisites
* **Runtime**: Node.js 24.11.1 (native OpenSSL 3.5.4 with built-in NIST FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65).
* **Dependencies**: **Zero runtime npm dependencies** (uses exclusively built-in standard library `node:crypto`, `node:fs`, `node:path`, `node:child_process`).
* **Python (Optional for cross-language verification only)**: Python 3.12+ with `pqcrypto==0.4.0`.

### Step 1: Clone Repository & Run Unit Test Suite
```bash
git clone https://github.com/VivanToshniwal13/ctrl-alt-delulu-track4.git
cd ctrl-alt-delulu-track4

# Run all 59 automated unit, hardening, and crash-recovery tests
./run-tests.sh
# or directly:
node --test --test-concurrency=1 tests/*.cjs
```

### Step 2: Validate Against Official Track 4 Toolkit
Clone the official toolkit into a separate directory and run the validator against the adapter entrypoint:
```bash
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git
python3 Track-4-Toolkit/validate.py --entry /path/to/ctrl-alt-delulu-track4/track4_service.cjs
```

---

## 2. Architecture & Security Model

```text
       [ Worker / Client Request (stdin JSON) ]
                          │
                          ▼
              [ track4_service.cjs ]
            (Fail-closed CLI Transport)
                          │
                          ▼
                 [ team_app.cjs ]
    ┌─────────────────────┼─────────────────────┐
    ▼                     ▼                     ▼
[ Authorization &     [ AES-256-GCM         [ PQC ML-KEM-768
Prototype Guard ]   Envelope Engine ]       Encapsulation ]
 (Map/Set strictly    (Per-asset DEK        (Raw 1184-byte
  bounded IDs)         wrapped by KEK)       SPKI + HMAC proof)
                          │
                          ▼
        [ O_EXCL Atomic File Locking ]
        (Atomic fsync RMW Persistence)
                          │
                          ▼
            [ $TRACK4_STATE_DIR ]
         ├── kek.bin           (mode 0600)
         ├── store.enc         (mode 0600)
         ├── audit.log         (mode 0600, hash-chained)
         ├── audit_index.json  (mode 0600, O(1) indexed)
         └── state.lock        (O_EXCL with PID stale-recovery)
```

### Cryptographic Primitives & Envelope Encryption
* **Post-Quantum KEM**: Native NIST FIPS 203 ML-KEM-768 (`crypto.encapsulate` via standard 22-byte SPKI prefix reconstruction for raw 1184-byte keys). Tested across 100 rounds with Python `pqcrypto` for byte-for-byte interop.
* **Proof Construction**: Lowercase hex HMAC-SHA-256 keyed by the 32-byte shared secret over `challenge + stored_body` (no delimiter).
* **Storage At Rest**: Envelope encryption using AES-256-GCM. Each asset body is encrypted with a distinct 32-byte Data Encryption Key (DEK). The DEK is wrapped with the versioned Key Encryption Key (KEK).
* **KEK Storage & Security Scope**:
  * The KEK is stored at `$TRACK4_STATE_DIR/kek.bin` with `0600` permissions.
  * *Honest Threat Model Limitation*: At-rest encryption protects against partial disclosure (stolen backup exports, leaked ciphertext records, or processes without read permission to `kek.bin`). An adversary with full container read access to the state directory can read both the KEK and ciphertext. Sensitive `key_material` from setup is never stored in plaintext.
* **Identity Assertion vs. Caller Authentication**:
  * Identity (`actor`) is asserted by the trusted caller (the worker harness) in the request payload; there is no cryptographic caller authentication in the process-per-request CLI adapter model. The adapter strictly enforces authorization policies (asset ownership, revocation lists, and disabled status) against the asserted identity.
* **Audit Log Anchoring & Limitations**:
  * The audit log is stored as append-only canonical JSON Lines with SHA-256 hash chaining and periodic ML-DSA-65 signed checkpoints.
  * *Honest Anchor Limitation*: If the authority private key sits in `$TRACK4_STATE_DIR`, an attacker with host filesystem write access can rewrite the log and re-sign checkpoints. To achieve immutable guarantees, signed heads can be exported externally via `bin/verify_log.cjs --export-head <path>` and verified with `--trusted-head`. Records appended *after* the latest checkpoint can be truncated without breaking the prior checkpoint.
* **Adapter Staleness Isolation**:
  * The cluster `maxStalenessMs` fail-closed rule applies only to multi-node simulations (`DistributedNode`) and is not enforced on the single-node adapter path, ensuring uninterrupted operation in judge environments without peer sync sources.

---

## 3. Explainable Anomaly & Lateral Movement Detector (Phase 4)

CLI Entrypoint: `bin/detect.cjs --events <events.csv> --approvals <approvals.json>`  
Evaluation Script: `node scripts/evaluate_detector.cjs`  
Benign Baseline Generator: `node scripts/generate_benign_workload.cjs`  
Synthetic Attack Set Evaluation: `node scripts/evaluate_attack_set.cjs`

* **Strictly No ML/AI**: Explainable detection implemented via deterministic rules, graph traversal, and clock skew correction. Each alert carries a human-readable rule ID, triggering fields, and graph path.
* **Configurable Baseline**: Baseline service edges and detection parameters are decoupled from code into `detector-config.json` (no hardcoded service or actor names).
* **Ground Truth Isolation**: Detection logic in `lib/detector.cjs` never references or opens `labels.csv` (enforced by `tests/detector_isolation.test.cjs`).
* **Lateral Movement Graph**: Correlates service edges (`source_service -> target_service`) across sessions and flows, chaining multi-hop traversals across distinct target services while isolating single-access denials.
* **Time & Skew Handling**: Preserves raw timestamps while computing collector-referenced `estimated_event_time_utc`. Flags events within clock uncertainty ($\pm 500$ ms) and alerts on excessive skew exceeding the supported threshold ($\pm 5,000$ ms).
* **Evaluation Results**:
  * **Practice Dataset (22 events)**: 100% exact match (Functional check, not accuracy; median time to alert: 100 ms).
  * **Synthetic Benign Workload (1,000 events)**: 0 false alerts (0 per 1,000 routine events).
  * **Synthetic Attack Set (51 events, 44 attacks)**: 100% recall (44/44 detected, 0 missed; median time to alert: 80 ms).

---

## 4. Hardening & Defenses (Phases 1.5 - 3)

1. **Prototype Pollution Immunity**: In-memory state uses `Map` and `Set` exclusively. User-controlled IDs never index plain JavaScript objects.
2. **Path Traversal Immunity**: Asset IDs and actor IDs are never incorporated into filesystem paths. All state files use fixed or SHA-256-hashed filenames.
3. **Audit First-Write-Wins**: Audit log entries for a given `request_id` cannot be overwritten or altered by subsequent requests. Unknown request queries return a safe deny response without crashing.
4. **Early Denial / Timing Safety**: Non-owners, revoked actors, disabled actors, and non-existent assets are denied before any KEM operations are invoked, eliminating existence oracles.
5. **Concurrency Safety**: High-concurrency operations are protected by an `O_EXCL` atomic lockfile with bounded retries and stale-lock recovery. Tested with 50 concurrent child processes.
6. **Crash Recovery & Rollback Protection**: State files use atomic rename and `fsync`. Backups use Scrypt KDF ($N=32768, r=8, p=1$) and ML-DSA-65 signatures, preserving prior revocations upon restore.
7. **Scale Resilience**: Tested with 10,000 historical audit records (3.11 MB log on disk). Decoupled `AuditIndex` maintains O(1) indexed lookup with flat ~58 ms cold-start CLI latency.

---

## 5. Verification Artifacts & Evidence

* Comprehensive evidence sheet: [`docs/evidence.md`](docs/evidence.md)
* Threat model: [`docs/threat-model.md`](docs/threat-model.md)
* Two-page project brief: [`docs/two-page-brief.md`](docs/two-page-brief.md)
* Benchmark and evaluation results: [`docs/results/`](docs/results/)
