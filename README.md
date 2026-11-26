# Track 4: Trust, but verify - Team Ctrl+Alt+Delulu

**Submission Repository for Yugaantar DevForge Track 4**

Production-grade post-quantum cryptographic access control, tamper-evident audit logging, and explainable privilege-escalation/lateral-movement detection.

---

## 1. Quick Start & Verification

### Prerequisites
* **Runtime**: Node.js 24.11.1 (native OpenSSL 3.5.4 with built-in ML-KEM-768 and ML-DSA-65)
* **Python**: Python 3.12+ (standard library for validation harness, `pqcrypto` for cross-language testing)

### Run Unit & Hardening Test Suite
```bash
./run-tests.sh
```

### Run Public Lost-Device Validator
```bash
python3 ../pseudora-secret-wards/Track-4-Toolkit/validate.py --entry ./track4_service.cjs
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
         ├── kek.bin    (mode 0600)
         ├── store.enc  (mode 0600)
         └── state.lock (O_EXCL)
```

### Cryptographic Primitives & Envelope Encryption
* **Post-Quantum KEM**: Native NIST FIPS 203 ML-KEM-768 (`crypto.encapsulate` via standard 22-byte SPKI prefix reconstruction for raw 1184-byte keys).
* **Proof Construction**: Lowercase hex HMAC-SHA-256 keyed by the 32-byte shared secret over `challenge + stored_body` (no delimiter).
* **Storage At Rest**: Envelope encryption using AES-256-GCM. Each asset body is encrypted with a distinct 32-byte Data Encryption Key (DEK). The DEK is wrapped with the versioned Key Encryption Key (KEK).
* **KEK Storage & Security Scope**:
  * The KEK is stored at `$TRACK4_STATE_DIR/kek.bin` with `0600` permissions.
  * *Honest Threat Model Limitation*: At-rest encryption protects against partial disclosure (stolen backup exports, leaked ciphertext records, or processes without read permission to `kek.bin`). An adversary with full container read access to the state directory can read both the KEK and ciphertext. Sensitive `key_material` from setup is never stored in plaintext.
* **Identity Assertion vs Caller Authentication**:
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

* **Strictly No ML/AI**: Explainable detection implemented via deterministic rules, graph traversal, and clock skew correction.
* **Ground Truth Isolation**: Detection logic in `lib/detector.cjs` never references or opens `labels.csv` (enforced by `tests/detector_isolation.test.cjs`).
* **Lateral Movement Graph**: Correlates service edges (`source_service -> target_service`) across sessions and flows, chaining multi-hop traversals (e.g. `reports -> billing -> archive -> identity`) while isolating routine single-access denials.
* **Time & Skew Handling**: Preserves raw timestamps while computing collector-referenced `estimated_event_time_utc`. Detects out-of-order receipt and flags events within clock uncertainty ($\pm 500$ ms).
* **Evaluation Results**:
  * 100% precision, 100% recall, 100% F1 score on the 22-event practice dataset.
  * 0 false alerts across 1,000 synthetic routine/benign events.
  * *Methodology Disclaimer*: Practice dataset events demonstrate functional capabilities only; broader accuracy claims require synthetic scale testing.

---

## 4. Hardening & Defenses (Phase 1.5 - Phase 3)

1. **Prototype Pollution Immunity**: In-memory state uses `Map` and `Set` exclusively. User-controlled IDs never index plain JavaScript objects.
2. **Path Traversal Immunity**: Asset IDs and actor IDs are never incorporated into filesystem paths. All state files use fixed or SHA-256-hashed filenames.
3. **Audit First-Write-Wins**: Audit log entries for a given `request_id` cannot be overwritten or altered by subsequent requests. Unknown request queries return a safe deny response without crashing.
4. **Early Denial / Timing Safety**: Non-owners, revoked actors, disabled actors, and non-existent assets are denied before any KEM operations are invoked, eliminating existence oracles.
5. **Concurrency Safety**: High-concurrency operations are protected by an `O_EXCL` atomic lockfile with bounded retries and stale-lock recovery. Tested with 50 concurrent child processes.
6. **Fail-Closed Guarantee**: Malformed JSON or unexpected exceptions exit `1` with a generic `stderr` diagnostic and zero information leakage.

---

## 4. Environment & Testing Note

* Tested locally on macOS with native Node.js 24.11.1 and Python 3.15.2.
* Pinned container specification (`Dockerfile`) mirrors the judging environment (Node 24.11.1, Python 3.12, `pqcrypto>=0.4.0`) with `--read-only` root filesystem and `--network none`.
