# Trust, but verify: Project Brief

## Page 1: USP, Architecture, and Fallback Video

**Project:** Ctrl+Alt+Delulu – Trust, but Verify  
**Team:** Ctrl+Alt+Delulu  
**Repository and commit:** [https://github.com/VivanToshniwal13/jj](https://github.com/VivanToshniwal13/jj) on main  
**Demo entry point:** `python3 Track-4-Toolkit/validate.py --entry track4_service.cjs` & `bin/detect.cjs`

### Unique Selling Proposition (USP)
Modern distributed infrastructures face severe risk when devices are lost or permissions unexpectedly mutate across post-quantum migration horizons. Ctrl+Alt+Delulu provides post-quantum cryptographic access control combining NIST FIPS 203 ML-KEM-768 envelope encryption and protected messaging with tamper-evident audit logging and deterministic, explainable lateral-movement detection. By enforcing immediate, monotonic revocations across distributed nodes, device re-enrolment, and crash-resilient storage without external cloud dependencies, our solution enforces that compromised identities are denied access under our documented threat model. What distinguishes Ctrl+Alt+Delulu is its zero-runtime npm footprint, 40–60 ms cold-start execution (sub-2 ms steady-state), forward secrecy with replay defense, and explainable rule-and-graph anomaly engine that operates entirely without black-box machine learning.

### Architecture
Ctrl+Alt+Delulu is structured around four tightly integrated, offline software layers built natively on Node.js 24.11.1 and OpenSSL 3.5.4:

```text
[ Evaluator / Client Request ] ──(stdin JSON)──> [ track4_service.cjs ]
                                                        │
                                                        ▼
[ Anomaly & Graph Detector ] ──(audit events)─── [ team_app.cjs ]
(lib/detector.cjs - 0 ML)                        ├── Authorization Guard (Map/Set)
                                                 ├── AES-256-GCM Envelope Engine
                                                 ├── NIST ML-KEM-768 Encapsulation
                                                 ├── Device Enrolment & Revocation
                                                 └── Post-Quantum Messaging Engine
                                                        │
                                                        ▼
                                                 [ $TRACK4_STATE_DIR ]
                                                 ├── store.enc (fsync atomic rename)
                                                 ├── audit.log (SHA-256 hash-chained)
                                                 └── audit_index.json (O(1) index)
```

1. **Adapter Transport & Authorization**: `track4_service.cjs` and `team_app.cjs` process process-per-request JSON over stdin/stdout. Identity is asserted by the caller, and the engine enforces asset ownership, disabling, and revocation before invoking any cryptographic operations.
2. **Post-Quantum Cryptographic Engine**: Content bodies are protected via AES-256-GCM envelope encryption using per-asset Data Encryption Keys (DEKs) wrapped by a versioned Key Encryption Key (KEK). Post-quantum handshakes execute native ML-KEM-768 public key encapsulation with standard 22-byte SPKI reconstruction, generating 32-byte shared secrets and HMAC-SHA-256 proofs.
3. **Device Lifecycle & Protected Messaging**: Device enrolment uses NIST FIPS 204 ML-DSA-65 signatures (library-level, not enforced by the adapter). Lost devices are revoked across all nodes while peer users remain unaffected. Protected messaging (`lib/messaging.cjs`) delivers forward secrecy via per-session ephemeral ML-KEM-768 + ML-DSA-65 signed prekeys + AES-256-GCM, replay defense keying on (sender, message_id, sequence), and authenticated recipient identity binding. Safe alert-only default prevents caller assertion DOS.
4. **Crash Recovery & Hash-Chained Auditing**: State mutations persist atomically via `fsync` and temporary file renaming. All operations append to `audit.log`, a canonical JSON Lines ledger hash-chained via SHA-256 and periodically signed with NIST FIPS 204 ML-DSA-65 checkpoints.
5. **Explainable Detection Engine**: `lib/detector.cjs` ingests events, normalizes clock skew, matches role changes against structured change-control approvals, and traverses service graphs to detect multi-hop lateral movement across distinct service targets.

### Accessible Five-Minute Fallback Video Link

**Video link:** VIDEO_LINK_TODO  
**Status:** Video demonstration link pending (to be inserted before final evaluation)

The demonstration walks through clean setup, authorized owner reads, post-quantum ML-KEM-768 protected reads, immediate device revocation and new device re-enrolment, key rotation with 5-node cutoff enforcement, crash recovery mid-revoke via `SIGKILL`, audit hash-chain verification with `bin/verify_log.cjs`, protected messaging with replay rejection and concurrency locking, and live explainable lateral-movement detection across practice and synthetic attack datasets.

**Observed outcome:**
The automated Track 4 Toolkit validator achieves 22/22 PASS checks (Local scenario passed) with zero information leakage. Benchmarks confirm 40–60 ms cold-start execution (mean 44.7 ms for read/revoke, ~58.8 ms for audit; sub-2 ms steady-state in-memory operations), 44/44 on a self-written synthetic attack set (not an independent accuracy measure); 0 false alerts on 1,000 self-generated benign events, and 103 passing automated tests across test categories (75 unit & hardening tests, 4 application-level dispatch integration tests, 11 post-quantum messaging & process-level CLI tests, and 13 deep security hardening tests for rollback, lock ownership, chunking, and trusted sender directories).

### Explicitly Unimplemented Features (By Architectural Design)
The following protocols/features are deliberately not implemented, using simpler and fully audited alternatives:
- **SLH-DSA (FIPS 205)**: Excluded in favor of NIST FIPS 204 ML-DSA-65 (compact 3.3 KB signatures vs. 17+ KB).
- **Hybrid Classical + Post-Quantum Key Exchange**: Excluded in favor of native NIST FIPS 203 ML-KEM-768 with AES-256-GCM envelope encryption without classical ECDH legacy wrappers.
- **Double Ratchet / PQXDH**: Excluded; we implement per-session ephemeral ML-KEM-768 + ML-DSA-65 signed prekeys + AES-256-GCM without continuous symmetric/asymmetric ratcheting.
- **Merkle Tree Logs**: Excluded in favor of canonical SHA-256 hash chains with periodic ML-DSA-65 digital signatures (sequential verification with periodic checkpoints rather than Merkle inclusion proof tree overhead).
- **Hybrid Logical Clocks (HLC)**: Excluded in favor of collector-monotonic ordering with bounded skew ($\pm 5,000$ ms) and uncertainty flagging ($\pm 500$ ms).

<div style="page-break-before: always;"></div>

## Page 2: One-Page Threat Model

### Assets
- **Asset Payloads (Confidentiality & Integrity)**: Protected by AES-256-GCM envelope encryption. Decryption strictly requires owner authorization and challenge/response verification.
- **Key Material & KEKs (Confidentiality & Authenticity)**: KEK stored under Unix mode `0600` (`kek.bin`). Sensitive setup keys are never persisted in plaintext.
- **Authorization & State Registry (Integrity & Monotonicity)**: Monotonic versioning and atomic `fsync` prevent lost updates or corruption.
- **Revocation Lists & Device Enrolments (Authenticity & Non-Repudiation)**: Digitally signed using ML-DSA-65 post-quantum keys.
- **Audit Logs (Tamper-Evidence & Completeness)**: Canonical SHA-256 hash chains detect line modifications, reordering, injection, and truncation.
- **Messages in Transit (Confidentiality, Authenticity & Forward Secrecy)**: Ephemeral ML-KEM-768 encapsulation, HKDF-SHA256, and AES-256-GCM with full AAD recipient binding.

### Adversaries
- **External Network Adversary**: Submits malformed payloads, fuzzes parameters, and attempts prototype pollution (`__proto__`), path traversal (`../`), message replays, and CRLF log injection.
- **Compromised Account / Malicious Insider**: Holds valid credentials; attempts unauthorized access, unapproved role changes, accesses outside approved time windows, or lateral traversal across internal microservices.
- **Compromised Service Node**: Network partitioned or replaying expired revocation broadcasts.
- **Lost / Stolen Device**: Stolen device key used to access files post-loss.
- **Local Host Root**: Full filesystem access to the container. *Explicitly out of scope for local software isolation.*

### Trust Boundaries
1. **Request Ingestion Boundary**: Validates types, bounds IDs ($\le 128$ chars), enforces strict Base64 formatting for 1,184-byte KEM keys, and neutralizes prototype pollution using `Map` and `Set`.
2. **Authorization Boundary**: Access checks occur **before** KEM encapsulation, eliminating existence oracles.
3. **Persistence Boundary**: Atomic rename and `O_EXCL` file locking prevent concurrent write corruption and lost updates.
4. **Messaging Boundary**: Ephemeral KEM exchange ensures past messages cannot be decrypted even if long-term identity keys are compromised.

### Assumptions
- Identity (`actor`) is asserted by the trusted caller (evaluator); adapter enforces authorization policies over asserted identities.
- Node.js built-in `crypto` with OpenSSL 3.5.4 provides correct implementations of FIPS 203, FIPS 204, AES-256-GCM, and Scrypt KDF.
- Local collector clock is the monotonic baseline. Source offsets are handled within a supported window of $\pm 5,000$ ms.

### Defenses & Observed Evidence
- **Prototype Pollution Immunity**: Validated across dangerous property names (`__proto__`, `constructor`, `toString`).
- **Crash Recovery & Lock Safety**: Survives process kill hooks (`SIGKILL`) mid-setup and mid-revoke with zero state corruption.
- **Rollback Protection**: Restoring an older backup preserves prior revocations and advances the epoch, verified in `tests/rollback_protection.test.cjs`.
- **Explainable Anomaly Detection**: Deterministic graph and approval rules detect unapproved role changes, lateral traversals, and out-of-scope access with 100% recall on 51 synthetic test events and 0 false alerts on 1,000 routine events.
- **Device Lifecycle**: Lost device is revoked across all 5 nodes; Maya enrolls a new device and recovers access; peer Alex is unaffected.
- **Replay & Forward Secrecy**: Replay cache with per-sender 1,024 sliding window and atomic concurrency locking rejects duplicate messages; ephemeral secret key references are wiped immediately upon session completion (clearing references allows OpenSSL destructor to free native memory; arbitrary V8 heap memory zeroization cannot be guaranteed by JavaScript).

### Exclusions and Remaining Risks
- **Host Compromise**: An adversary with root access to `$TRACK4_STATE_DIR` can read `kek.bin` and the local checkpoint key. Hardware HSM/TPM protection is required to resist host root compromise.
- **Uncheckpointed Log Tail**: Log entries created after the latest checkpoint could be truncated undetected by an attacker with local write access. To mitigate this, signed heads can be exported externally via `bin/verify_log.cjs --export-head`.
- **Practice Dataset Baseline**: The 22 events in the practice dataset demonstrate functional capability only. Production deployment requires organizational baseline tuning via `detector-config.json`.
