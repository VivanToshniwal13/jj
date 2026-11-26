# Track 4: Trust, but verify - Team Ctrl+Alt+Delulu

**Submission Repository for Yugaantar DevForge Track 4**

Post-quantum cryptographic access control, device lifecycle & re-enrolment, tamper-evident audit logging, post-quantum protected messaging, and explainable privilege-escalation/lateral-movement detection.

---

## 1. Quick Start & Verification (Clean-Machine Reproduction)

### Prerequisites
* **Runtime**: Node.js 24.11.1 (native OpenSSL 3.5.4 with built-in NIST FIPS 203 ML-KEM-768 and FIPS 204 ML-DSA-65).
* **Dependencies**: **Zero runtime npm dependencies** (uses exclusively built-in standard library `node:crypto`, `node:fs`, `node:path`, `node:child_process`).
* **Python**: Python 3.12+ (for running the official toolkit validator).

### Step 1: Install Node.js 24.11.1
Ensure Node.js 24.11.1 is installed and on your PATH:
```bash
node -v  # v24.11.1
```

### Step 2: Clone Repositories Side-by-Side
Clone `jj` and clone the official toolkit next to `jj`:
```bash
git clone https://github.com/VivanToshniwal13/jj.git
git clone https://github.com/ScalerOpenSourceLabs/Track-4-Toolkit.git
```

### Step 3: Validate Against Official Track 4 Toolkit
Run the official validator from the toolkit directory against the adapter:
```bash
cd Track-4-Toolkit
python3 validate.py --entry "../jj/track4_service.cjs"
cd ../jj
```

### Step 4: Run Complete Automated Test Suite
From the `jj` repository, run all automated unit, hardening, messaging, and crash-recovery tests:
```bash
node --test --test-concurrency=1 tests/*.cjs
```

### Step 5: Launch Security Operations Dashboard
Start the local interactive operator dashboard:
```bash
node bin/dashboard.cjs
```
Open `http://127.0.0.1:3400` in your browser.

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
    │                     │                     │
    ▼                     ▼                     ▼
[ Device Lifecycle ] [ Replay & Lockout ] [ PQC Messaging ]
 (ML-DSA Enrolment)  (alert-only; lockout (Forward secrecy)
                           opt-in)
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
* **Device Enrolment & Boundary**:
  * Device-signed access is library-level (`lib/distributed_revocation.cjs`), not enforced by the adapter. Devices are authorized using NIST FIPS 204 ML-DSA-65 signatures. Lost devices are revoked across all nodes; users re-enrol new devices via signed records without impacting peers.
* **Key Rotation with 5-Node Cutoff (Goal 1)**:
  * Key rotation enforces a documented grace period and cutoff. In-flight requests initiated before cutoff complete, while requests after cutoff are rejected across all 5 nodes with `KEY_VERSION_CUTOFF_EXPIRED`.
* **Post-Quantum Protected Messaging (Goals 9, 10, 11, 12)**:
  * Ephemeral per-session ML-KEM-768 prekeys signed by ML-DSA-65 identity keys, HKDF-SHA256 derivation, AES-256-GCM encryption with complete AAD recipient binding, ML-DSA-65 signatures, persistent per-sender 1,024 sliding window replay protection with atomic concurrency locking (survives restarts, rejects duplicates), forward secrecy via ephemeral private key erasure, sequenced chunks authenticated with ML-DSA-65 (CHUNK_AUTH_FAILED on tamper; INCOMPLETE_MESSAGE_CHUNKS on loss), and resumption tickets loaded from `$TRACK4_STATE_DIR/ticket_key.bin` (mode 0600) binding peer identity. Fully integrated with `team_app.cjs` dispatch (`send_protected_message` and `receive_protected_message`).
* **Safe Alert-Only Default (Assessment Response)**:
  * To prevent denial-of-service through asserted caller identities, anomaly detection defaults to alert-only logging to `audit.log` and `stderr`. Automated 30s lockout is strictly opt-in via `TRACK4_LIVE_LOCKOUT=1`. An actor with 5 denied reads reading their own asset continues to receive `allow`.
* **Audit Log Anchoring & Limitations**:
  * The audit log is stored as append-only canonical JSON Lines with SHA-256 hash chaining and periodic ML-DSA-65 signed checkpoints.
  * *Honest Anchor Limitation*: If the authority private key sits in `$TRACK4_STATE_DIR`, an attacker with host filesystem write access can rewrite the log and re-sign checkpoints. To achieve immutable guarantees, signed heads can be exported externally via `bin/verify_log.cjs --export-head <path>` and verified with `--trusted-head`. Records appended *after* the latest checkpoint can be truncated without breaking the prior checkpoint.
* **Adapter Staleness Isolation**:
  * The cluster `maxStalenessMs` fail-closed rule applies only to multi-node simulations (`DistributedNode`) and is not enforced on the single-node adapter path, ensuring uninterrupted operation in judge environments without peer sync sources.
* **Explicitly Unimplemented Features (By Architectural Design)**:
  * **SLH-DSA (FIPS 205)**: Excluded in favor of NIST FIPS 204 ML-DSA-65 (compact 3.3 KB signatures vs. 17+ KB).
  * **Hybrid Classical + Post-Quantum Key Exchange**: Excluded in favor of native NIST FIPS 203 ML-KEM-768 with AES-256-GCM envelope encryption without classical ECDH legacy wrappers.
  * **Double Ratchet / PQXDH**: Excluded; we implement per-session ephemeral ML-KEM-768 + ML-DSA-65 signed prekeys + AES-256-GCM without continuous symmetric/asymmetric ratcheting complexity.
  * **Merkle Tree Logs**: Excluded in favor of canonical SHA-256 hash chains with periodic ML-DSA-65 digital signatures (sequential verification with periodic checkpoints rather than Merkle inclusion proof tree overhead).
  * **Hybrid Logical Clocks (HLC)**: Excluded in favor of collector-monotonic ordering with bounded skew ($\pm 5,000$ ms) and uncertainty flagging ($\pm 500$ ms).

---

## 3. Explainable Anomaly & Lateral Movement Detector (Phase 4)

CLI Entrypoints:
* Detector: `bin/detect.cjs --events <events.csv> --approvals <approvals.json>`
* Live Alerts Inspector: `bin/alerts.cjs [--log <path>] [--json]`

Evaluation Scripts:
* `node scripts/evaluate_detector.cjs` (Practice dataset evaluation)
* `node scripts/generate_benign_workload.cjs` (Benign baseline generator)
* `node scripts/evaluate_attack_set.cjs` (Synthetic attack set evaluation)

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

## 4. Hardening & Defenses (Phases 1.5 - 5)

1. **Prototype Pollution Immunity**: In-memory state uses `Map` and `Set` exclusively. User-controlled IDs never index plain JavaScript objects.
2. **Path Traversal Immunity**: Asset IDs and actor IDs are never incorporated into filesystem paths. All state files use fixed or SHA-256-hashed filenames.
3. **Audit First-Write-Wins**: Audit log entries for a given `request_id` cannot be overwritten or altered by subsequent requests. Unknown request queries return a safe deny response without crashing.
4. **Early Denial / Timing Safety**: Non-owners, revoked actors, disabled actors, and non-existent assets are denied before any KEM operations are invoked, eliminating existence oracles.
5. **Concurrency Safety**: High-concurrency operations are protected by an `O_EXCL` atomic lockfile with bounded retries and stale-lock recovery. Tested with 50 concurrent child processes.
6. **Crash Recovery & Rollback Protection**: State files use atomic rename and `fsync`. Backups use Scrypt KDF ($N=32768, r=8, p=1$) and ML-DSA-65 signatures, preserving prior revocations upon restore.
7. **Scale Resilience & Performance**: Tested with 10,000 historical audit records (3.11 MB log on disk). Decoupled `AuditIndex` maintains O(1) indexed lookup. Cold-start process execution takes 40–60 ms (mean 44 ms for read/revoke, ~58 ms for audit due to Node CLI process launch overhead), while steady-state in-process cryptographic operations execute in under 2 ms.
8. **Live Security Response**: repeated denials (>=3), asset enumeration and post-revocation reads raise alerts in audit.log and stderr. Default is alert-only; a 30 s lockout is opt-in via TRACK4_LIVE_LOCKOUT=1.

---

## 5. Verification Artifacts & Evidence

* Comprehensive evidence sheet: [`docs/evidence.md`](docs/evidence.md)
* Threat model: [`docs/threat-model.md`](docs/threat-model.md)
* Two-page project brief: [`docs/two-page-brief.md`](docs/two-page-brief.md)
* Benchmark and evaluation results: [`docs/results/`](docs/results/)
