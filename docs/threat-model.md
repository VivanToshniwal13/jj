# Threat Model: Trust, but verify

**Project:** Pseudora / Track 4 (Post-Quantum Cryptography, Identity & Access Control)  
**Team:** Ctrl+Alt+Delulu | **Date:** 2026-11-26 | **Version:** 1.0.0

---

### 1. Protected Assets & Security Properties

| Asset | Security Property | Protection Mechanism |
| :--- | :--- | :--- |
| **Asset Payloads (Bodies)** | Confidentiality & Integrity | AES-256-GCM envelope encryption with per-asset DEKs wrapped by versioned KEKs. Decryption gated by strict owner authorization and authenticated challenge/response. |
| **Decryption Credentials (KEK & DEK)** | Confidentiality & Authenticity | KEK stored with mode `0600` in `$TRACK4_STATE_DIR/kek.bin`. Setup `key_material` is never stored in plaintext. |
| **Identity & Policy State** | Integrity & Consistency | Monotonic versioning, atomic `fsync` persistence via temporary file rename, and `O_EXCL` concurrency lock with stale-lock PID recovery. |
| **Revocation Broadcasts** | Authenticity & Non-Repudiation | ML-DSA-65 post-quantum digital signatures over monotonic versioned lists. Replay attacks rejected. |
| **Audit Log Records** | Tamper-Evidence & Completeness | SHA-256 canonical JSON hash chaining with periodic ML-DSA-65 signed checkpoints. |
| **Service Availability** | Availability & Resilience | Fail-closed input parsing, prototype pollution guard, bounded timeouts, and max-staleness fail-closed rules. |

---

### 2. Adversaries & Threat Agents

1. **External Network / Unauthenticated Attacker**:
   - *Capabilities*: Submits malformed requests, fuzzes parameters, attempts prototype pollution (`__proto__`, `constructor`), path traversal (`../`), and injection of CRLF/Unicode delimiters.
   - *Scope*: Has no read or write access to `$TRACK4_STATE_DIR`.
2. **Compromised Account / Malicious Insider**:
   - *Capabilities*: Possesses valid credentials for viewer or operator roles; attempts unauthorized reads, unapproved role changes, accesses outside approved validity windows, or lateral traversals across services.
3. **Compromised Service Node**:
   - *Capabilities*: May disconnect, replay old revocation lists, or attempt to read data after revocation.
4. **Storage Snooper / Backup Interceptor**:
   - *Capabilities*: Gains read access to backup archives or ciphertext assets, but lacks the backup password or KEK.
5. **Local Host Administrator / Container Root**:
   - *Capabilities*: Full read/write access to `$TRACK4_STATE_DIR`. *Explicitly out of scope for local software isolation.*

---

### 3. Trust Boundaries & Enforcement Points

```text
[ Client / Evaluator ] ──(stdin JSON)──> [ Boundary 1: Transport & Validation ]
                                                       │
                                                       ▼
[ Local Filesystem ] <──(mode 0600)── [ Boundary 2: Authorization & Envelope Engine ]
                                                       │
                                                       ▼
[ Audit Log / Export ] <──(ML-DSA Sign)── [ Boundary 3: Tamper-Evident Chaining ]
```

- **Boundary 1 (Transport & Input Guard)**: Strict string type checks, length caps (IDs $\le 128$, bodies $\le 65,536$, challenges $\le 256$), strict Base64 validation (1,184-byte SPKI decode), and non-string type rejection.
- **Boundary 2 (Authorization & Crypto Engine)**: Authorization checks (owner match, not disabled, not revoked) execute **before** any cryptographic KEM encapsulation, eliminating timing and existence oracles.
- **Boundary 3 (Persistence & Audit)**: Atomically persisted with `fsync`. Every state mutation and access decision is logged with cryptographic hash chaining.

---

### 4. Assumptions & Environmental Constraints

1. **Identity Assertion Model**: The caller (worker process) asserts `actor`. The adapter enforces authorization policies against the asserted identity; caller authentication is out of scope for the process-per-request adapter.
2. **Vetted Cryptography**: Relies exclusively on Node.js built-in `crypto` (OpenSSL 3.5.4) implementing NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65), AES-256-GCM, and Scrypt KDF. No custom crypto primitives.
3. **Local Clock Reference**: Collector clock is the trusted monotonic baseline. Source clock offsets are accounted for within a supported window of $\pm 5,000$ ms; uncertainties $\le 500$ ms are flagged as timing-uncertain.

---

### 5. Working Defenses & Empirical Verification

- **Prototype Pollution Immunity**: In-memory state uses `Map` and `Set` exclusively. Tested with `__proto__`, `constructor`, `toString`.
- **Path Traversal Immunity**: IDs are never concatenated into filesystem paths.
- **Crash Recovery & Lock Safety**: Atomic rename ensures crash-safe writes. `state.lock` tracks PID; dead processes release locks immediately. Verified via mid-setup and mid-revoke `SIGKILL` fault hooks.
- **Monotonic Rollback Protection**: Restoring an older backup preserves prior revocations and advances epoch. Verified via `tests/rollback_protection.test.cjs`.
- **Explainable Anomaly Detection**: Deterministic graph and approval rules detect unapproved role changes, lateral traversals, and out-of-scope access with 100% recall on synthetic attacks and 0 false alerts per 1,000 benign events.

---

### 6. Exclusions & Remaining Risks

1. **Local Root Compromise in State Directory**:
   - If an adversary obtains root access to `$TRACK4_STATE_DIR`, they can read `kek.bin` and `audit_authority_mldsa_sk.bin`. Software-only encryption cannot withstand kernel/host root compromise without hardware TPM/HSM.
2. **Uncheckpointed Log Tail Truncation**:
   - Records appended after the latest signed checkpoint could be truncated undetected by an attacker with local write access. To mitigate this, signed heads must be exported externally via `bin/verify_log.cjs --export-head <external-path>`.
3. **Practice Dataset Scope**:
   - The 22 events in the practice dataset demonstrate functional capability only, not statistical accuracy. Production deployment requires organizational baseline tuning.
