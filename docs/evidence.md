# Trust, but verify: Repository Evidence Sheet

Team: **Ctrl+Alt+Delulu** | Date: **2026-11-26** | Track: **Track 4 - Post-Quantum Cryptography, Identity & Access Control**  
Environment: macOS arm64 (host) / Node.js v24.11.1 / OpenSSL 3.5.4 / Python 3.15.2 (interop testing)

---

## Published Goals & Status Summary

Status values: `measured`, `partial`, `not tested`, `not supported`.

| Goal | Public demonstration and evidence to collect | Expected behavior you define before run | Actual result / status / evidence link |
| :--- | :--- | :--- | :--- |
| **1. Key rotation** | Use `bin/track4_admin.cjs rotate` or `KeyLifecycleManager`. Version IDs, activation times, normal read before & after. | Monotonic version transitions: Active -> Retiring -> Retired -> Revoked. Grace period allows historical decrypt, forbids new encrypt. | `measured` - Verified in `tests/phase2.test.cjs`. Version 1 transitions to retiring with active Version 2. Adapter DEKs rewrapped via `rewrap_keys`. |
| **2. Revocation across nodes** | `DistributedRevocationAuthority` ML-DSA-65 broadcast across 5 simulated nodes with network partition & staleness fail-closed check. | All active nodes enforce revocation. Partitioned nodes fail closed after `maxStalenessMs` (default 5000ms). | `measured` - Verified in `tests/distributed_partition.test.cjs`. 5-node broadcast: 16 ms initial, 20 ms total with catch-up (single-host simulation). Replay of old lists rejected by monotonic versioning. |
| **3. Crash recovery** | Write-Ahead Journal (WAL) for key rotation; atomic `fsync` & rename for store state; fault injection kills process mid-setup and mid-revoke. | Uncommitted pending keys wiped; active keys preserved; lock released; no corrupted half-written files. | `measured` - Verified in `tests/crash_recovery_adapter.test.cjs` & `tests/phase2.test.cjs`. Zero state corruption across `SIGKILL` fault hooks. |
| **4. Backup integrity** | Scrypt KDF (`N=32768, r=8, p=1`), AES-256-GCM encryption, ML-DSA-65 digital signature over ciphertext + metadata only. Monotonic rollback protection. | Detects bit flips, truncation, wrong password. Restoring older backup preserves existing revocations and advances epoch. | `measured` - Verified in `tests/rollback_protection.test.cjs` & `tests/phase2.test.cjs`. Maya remains revoked after restoring pre-revocation backup. |
| **5. Log integrity** | Tamper-evident hash chain (SHA-256 canonical lines) with periodic ML-DSA-65 signed checkpoints. | Verification pinpoints exact edited, injected, reordered, or truncated record. | `in_progress` (Phase 3) |
| **6. Routine and suspicious activity** | Graph and rule-based anomaly detector for privilege escalation, rapid traversal, and anomalous access. | Flags unapproved privilege spikes and suspicious off-hour lateral moves without ML. | `pending` (Phase 4) |
| **7. Lateral movement** | Correlate `events.csv` sessions, edge transitions, and unauthorized service jumps. | Chains suspicious event sequences from initial read to sensitive service hop. | `pending` (Phase 4) |
| **8. Clock differences** | NTP / logical clock offset handling with stated clock uncertainty bounds. | Corrected timelines without overwriting raw timestamps. | `pending` (Phase 4) |
| **9. Replay and recipient binding** | Freshness nonce + ML-KEM-768 ciphertext + recipient identity binding. | Duplicate message rejection and wrong-recipient decryption failure. | `pending` (Phase 5) |
| **10. Forward secrecy** | Ephemeral ML-KEM-768 key encapsulation per message exchange; zeroization of ephemeral secrets. | Compromise of long-term identity cannot decrypt historical ephemeral sessions. | `pending` (Phase 5) |
| **11. Delivery under loss or reordering** | Sequence numbers, retry tracking, and deduplication buffer. | Guaranteed in-order processing despite synthetic drops or reordering. | `pending` (Phase 5) |
| **12. Session resumption** | Ticket-based resumption with bounded validity and fresh policy re-evaluation. | Safe reconnect without full key handshake; revoked identity denied on resume. | `pending` (Phase 5) |

---

## Detailed Measurement Records

### Measurement 1: Adapter Latency (Process-per-Request CLI Model)
- **Claim:** Native Node 24.11.1 + OpenSSL 3.5.4 achieves sub-50ms wall-clock cold-start execution for all operations, including ML-KEM-768 encapsulation.
- **Setup & Workload:** 200 fresh child process spawns per operation (`read`, `protected_read`, `revoke`) using `scripts/benchmark_latency.cjs`.
- **Observed Results (macOS arm64 Host):**
  - `read` (N=200): p50 = **44.83 ms** | p95 = **46.59 ms** | p99 = **47.01 ms** (mean: 44.71 ms)
  - `protected_read` (N=200): p50 = **41.22 ms** | p95 = **42.16 ms** | p99 = **42.89 ms** (mean: 40.75 ms)
  - `revoke` (N=200): p50 = **44.70 ms** | p95 = **46.31 ms** | p99 = **46.80 ms** (mean: 44.26 ms)
- **Limits & Notes:** Process spawning cold-start dominates runtime (~35-40ms). In-memory cryptographic execution itself takes <2ms.

### Measurement 2: Distributed Revocation Propagation & Partition Staleness
- **Claim:** ML-DSA-65 signed revocation lists propagate across 5 nodes in <50ms in local simulation, and partitioned nodes fail closed upon exceeding max-staleness.
- **Setup & Workload:** 5 independent simulated nodes (`DistributedNode`), 1 node network-partitioned during broadcast, tested in `tests/distributed_partition.test.cjs`.
- **Observed Results:**
  - Initial 4-node broadcast: **16 ms** (single-host simulation).
  - Total propagation including partition catch-up: **20 ms**.
  - Partitioned node exceeding `maxStalenessMs` (200ms in test, 5000ms default): `checkFreshness()` returned `fresh: false` and denied all actors (failed closed).
- **Limits & Notes:** Measured on local filesystem simulation without real network socket jitter.

### Measurement 3: Backup Scrypt KDF & Rollback Protection
- **Claim:** Password derivation uses RFC 7914 scrypt ($N=32768, r=8, p=1$); restoring an older valid backup preserves prior revocations and advances epoch.
- **Observed Results:**
  - `tests/rollback_protection.test.cjs`: State initialized with Maya and Alice at Epoch 1. Signed backup created. Maya revoked (Epoch 2). Older Epoch 1 backup restored. Maya read request returned `decision: deny`. System epoch advanced to 3.
  - Plaintext manifest removed; ML-DSA-65 signature covers only ciphertext, IV, salt, tag, epoch, and creation timestamp.

---

## Cryptographic Key Storage & Threat Model Honesty

### 1. KEK & DEK Storage
- **Location:** The Key Encryption Key (KEK) and active key registry are stored in the state directory (`kek.bin` / `key_registry.json`) with strict Unix file permissions `0o600`.
- **Threat Model Boundary:**
  - **Protected Against:** Remote unauthenticated attackers, unprivileged local system users, path traversal attacks, prototype pollution, and accidental leak via stdout/stderr.
  - **NOT Protected Against:** Local root/administrator or attacker with raw filesystem read access to the host `TRACK4_STATE_DIR`. If the state directory is compromised, the at-rest KEK is exposed.

### 2. Revocation Authority & Backup Signing Keys
- **Location:** ML-DSA-65 private keys are loaded from `TRACK4_REVOCATION_KEY_PATH` or `TRACK4_BACKUP_KEY_PATH` (or dynamically generated in `stateDir` under `0o600` permissions).
- **Threat Model Boundary:**
  - **Protected Against:** Node-level tampering, forged revocation broadcasts by untrusted nodes, unauthorized backup injection, and replay of stale backups.
  - **NOT Protected Against:** Compromise of the authority host holding the ML-DSA-65 private signing key.
