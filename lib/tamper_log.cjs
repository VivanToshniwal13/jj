'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';
const DEFAULT_CHECKPOINT_INTERVAL = 10;

/**
 * Deterministic Canonical JSON serializer (RFC 8785 subset)
 * - Alphabetically sorted keys at all levels
 * - No extraneous whitespace
 * - Standard JSON escaping for special characters (newlines, quotes, etc.)
 */
function canonicalJson(val) {
  if (val === null || typeof val !== 'object') {
    return JSON.stringify(val);
  }
  if (Array.isArray(val)) {
    return '[' + val.map(canonicalJson).join(',') + ']';
  }
  const keys = Object.keys(val).sort();
  return '{' + keys.map(k => `${JSON.stringify(k)}:${canonicalJson(val[k])}`).join(',') + '}';
}

class TamperEvidentLog {
  constructor(stateDir, authorityKeyPair = null, checkpointInterval = null) {
    this.stateDir = stateDir;
    this.logPath = path.join(stateDir, 'audit.log');
    const envInterval = parseInt(process.env.TRACK4_CHECKPOINT_INTERVAL, 10);
    this.checkpointInterval = checkpointInterval || (isNaN(envInterval) ? DEFAULT_CHECKPOINT_INTERVAL : envInterval);
    this.authorityKeyPair = authorityKeyPair || this._loadOrGenerateKey();
    this.lastHash = GENESIS_HASH;
    this.currentRecordIndex = 0;
    this.checkpointCount = 0;
    this.latestCheckpoint = null;
    this._initializeFromExistingLog();
  }

  _loadOrGenerateKey() {
    const keyPath = process.env.TRACK4_AUDIT_KEY_PATH || 
      (this.stateDir ? path.join(this.stateDir, 'audit_authority_mldsa_sk.bin') : null);

    if (keyPath && fs.existsSync(keyPath)) {
      try {
        const raw = fs.readFileSync(keyPath);
        const privateKey = crypto.createPrivateKey({ key: raw, format: 'der', type: 'pkcs8' });
        const publicKey = crypto.createPublicKey(privateKey);
        return { privateKey, publicKey };
      } catch {}
    }

    const kp = crypto.generateKeyPairSync('ml-dsa-65');
    if (keyPath) {
      try {
        const der = kp.privateKey.export({ format: 'der', type: 'pkcs8' });
        fs.writeFileSync(keyPath, der, { mode: 0o600 });
      } catch {}
    }
    return kp;
  }

  getPublicKey() {
    return this.authorityKeyPair.publicKey;
  }

  _initializeFromExistingLog() {
    if (!fs.existsSync(this.logPath)) {
      return;
    }

    const content = fs.readFileSync(this.logPath, 'utf8');
    const lines = content.split('\n').filter(l => l.trim().length > 0);
    if (lines.length === 0) return;

    for (const line of lines) {
      try {
        const parsed = JSON.parse(line);
        if (parsed.hash) {
          this.lastHash = parsed.hash;
        }
        if (parsed.type === 'record' && typeof parsed.index === 'number') {
          this.currentRecordIndex = Math.max(this.currentRecordIndex, parsed.index + 1);
        }
        if (parsed.type === 'checkpoint') {
          this.checkpointCount++;
          this.latestCheckpoint = parsed;
        }
      } catch {}
    }
  }

  /**
   * Append an audit event to the hash-chained log.
   * Actor identity is asserted by the trusted caller (worker process) in the request;
   * the adapter enforces authorization policies over asserted identities, not authentication.
   */
  appendRecord(actor, op, details = {}) {
    // Sanitize actor and op
    const safeActor = String(actor || 'system');
    const safeOp = String(op || 'unknown');

    const entry = {
      type: 'record',
      index: this.currentRecordIndex,
      timestamp: Date.now(),
      prev_hash: this.lastHash,
      actor: safeActor,
      op: safeOp,
      details: details && typeof details === 'object' ? details : {}
    };

    const serializedPayload = canonicalJson(entry);
    const entryHash = crypto.createHash('sha256').update(serializedPayload, 'utf8').digest('hex');

    const fullRecord = {
      ...entry,
      hash: entryHash
    };

    // Serialize full record as a single canonical JSON line
    const line = canonicalJson(fullRecord);
    this._appendDurableLine(line);

    this.lastHash = entryHash;
    this.currentRecordIndex++;

    // Check if checkpoint is due
    if (this.currentRecordIndex % this.checkpointInterval === 0) {
      this.createCheckpoint();
    }

    return fullRecord;
  }

  /**
   * Generate an ML-DSA-65 signed checkpoint committing to current record count and head hash.
   */
  createCheckpoint() {
    if (this.lastHash === GENESIS_HASH) {
      return null;
    }

    const checkpointData = {
      type: 'checkpoint',
      checkpoint_index: this.checkpointCount,
      covered_records: this.currentRecordIndex,
      head_hash: this.lastHash,
      timestamp: Date.now()
    };

    const toSign = Buffer.from(canonicalJson(checkpointData), 'utf8');
    const signature = crypto.sign(null, toSign, this.authorityKeyPair.privateKey);

    const checkpointRecord = {
      ...checkpointData,
      signature_b64: signature.toString('base64'),
      prev_hash: this.lastHash
    };

    const serialized = canonicalJson(checkpointRecord);
    const cpHash = crypto.createHash('sha256').update(serialized, 'utf8').digest('hex');

    const fullCheckpoint = {
      ...checkpointRecord,
      hash: cpHash
    };

    const line = canonicalJson(fullCheckpoint);
    this._appendDurableLine(line);

    this.lastHash = cpHash;
    this.checkpointCount++;
    this.latestCheckpoint = fullCheckpoint;

    return fullCheckpoint;
  }

  getLatestCheckpoint() {
    return this.latestCheckpoint;
  }

  _appendDurableLine(line) {
    fs.appendFileSync(this.logPath, line + '\n', { mode: 0o600 });
    // Fsync log for durability
    const fd = fs.openSync(this.logPath, 'r');
    try {
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  }

  /**
   * Verify an audit log file.
   * Pinpoints exact record index and type of tampering:
   * - TAMPER_MODIFICATION: Line hash mismatch
   * - TAMPER_REORDER: prev_hash mismatch
   * - TAMPER_INJECTION: unexpected extra record or forged hash
   * - TAMPER_TRUNCATION: missing tail covered by signed checkpoint
   * - TAMPER_CHECKPOINT_FORGED: invalid ML-DSA-65 signature on checkpoint
   */
  static verifyLog(logPath, authorityPublicKey, trustedHead = null) {
    if (!fs.existsSync(logPath)) {
      return {
        valid: false,
        errorType: 'LOG_NOT_FOUND',
        reason: `Log file does not exist at ${logPath}`
      };
    }

    const content = fs.readFileSync(logPath, 'utf8');
    const rawLines = content.split('\n');
    const lines = [];

    for (let i = 0; i < rawLines.length; i++) {
      const line = rawLines[i].trim();
      if (line.length > 0) {
        lines.push({ lineIndex: i, text: line });
      }
    }

    if (lines.length === 0) {
      return {
        valid: true,
        recordCount: 0,
        checkpointCount: 0,
        headHash: GENESIS_HASH,
        message: 'Log is empty (valid genesis state)'
      };
    }

    let expectedPrevHash = GENESIS_HASH;
    let expectedNextRecordIndex = 0;
    let checkpointsVerified = 0;
    let lastSeenCheckpoint = null;
    let recordsSeen = 0;

    for (let i = 0; i < lines.length; i++) {
      const { lineIndex, text } = lines[i];

      let record;
      try {
        record = JSON.parse(text);
      } catch (err) {
        return {
          valid: false,
          errorType: 'TAMPER_MALFORMED_LINE',
          lineIndex,
          recordIndex: i,
          reason: `Line ${lineIndex + 1} contains invalid JSON: ${err.message}`
        };
      }

      // Check hash chain continuity
      if (record.prev_hash !== expectedPrevHash) {
        return {
          valid: false,
          errorType: 'TAMPER_REORDER_OR_BROKEN_CHAIN',
          lineIndex,
          recordIndex: i,
          expectedPrevHash,
          actualPrevHash: record.prev_hash,
          reason: `Hash chain broken at line ${lineIndex + 1}. Expected prev_hash ${expectedPrevHash}, found ${record.prev_hash}`
        };
      }

      const recordedHash = record.hash;
      if (!recordedHash || typeof recordedHash !== 'string' || recordedHash.length !== 64) {
        return {
          valid: false,
          errorType: 'TAMPER_MISSING_HASH',
          lineIndex,
          recordIndex: i,
          reason: `Record at line ${lineIndex + 1} is missing a valid 64-char hex SHA-256 hash`
        };
      }

      if (record.type === 'record') {
        // Monotonic record indexing
        if (record.index !== expectedNextRecordIndex) {
          return {
            valid: false,
            errorType: 'TAMPER_INDEX_DISCONTINUITY',
            lineIndex,
            recordIndex: record.index,
            expectedIndex: expectedNextRecordIndex,
            reason: `Record index sequence broken at line ${lineIndex + 1}: expected index ${expectedNextRecordIndex}, found ${record.index}`
          };
        }

        // Validate record integrity hash
        const entryToVerify = {
          type: 'record',
          index: record.index,
          timestamp: record.timestamp,
          prev_hash: record.prev_hash,
          actor: record.actor,
          op: record.op,
          details: record.details
        };

        const recomputedCanonical = canonicalJson(entryToVerify);
        const recomputedHash = crypto.createHash('sha256').update(recomputedCanonical, 'utf8').digest('hex');

        if (recomputedHash !== recordedHash) {
          return {
            valid: false,
            errorType: 'TAMPER_MODIFICATION',
            lineIndex,
            recordIndex: record.index,
            expectedHash: recordedHash,
            computedHash: recomputedHash,
            reason: `Data modification detected at line ${lineIndex + 1} (record index ${record.index}). Content was altered.`
          };
        }

        recordsSeen++;
        expectedNextRecordIndex++;
        expectedPrevHash = recordedHash;
      } else if (record.type === 'checkpoint') {
        // Verify checkpoint digital signature
        const checkpointDataToVerify = {
          type: 'checkpoint',
          checkpoint_index: record.checkpoint_index,
          covered_records: record.covered_records,
          head_hash: record.head_hash,
          timestamp: record.timestamp
        };

        if (authorityPublicKey) {
          const sigBuffer = Buffer.from(record.signature_b64 || '', 'base64');
          const canonicalData = Buffer.from(canonicalJson(checkpointDataToVerify), 'utf8');
          const isSigValid = crypto.verify(null, canonicalData, authorityPublicKey, sigBuffer);

          if (!isSigValid) {
            return {
              valid: false,
              errorType: 'TAMPER_CHECKPOINT_FORGED',
              lineIndex,
              checkpointIndex: record.checkpoint_index,
              reason: `Cryptographic signature verification failed on checkpoint at line ${lineIndex + 1}`
            };
          }
        }

        // Verify that head_hash matches the immediately preceding entry
        if (record.head_hash !== record.prev_hash) {
          return {
            valid: false,
            errorType: 'TAMPER_CHECKPOINT_HEAD_MISMATCH',
            lineIndex,
            checkpointIndex: record.checkpoint_index,
            reason: `Checkpoint head_hash ${record.head_hash} does not match prev_hash ${record.prev_hash}`
          };
        }

        // Verify checkpoint entry hash
        const checkpointEntryToVerify = {
          ...checkpointDataToVerify,
          signature_b64: record.signature_b64,
          prev_hash: record.prev_hash
        };
        const recomputedCpHash = crypto.createHash('sha256').update(canonicalJson(checkpointEntryToVerify), 'utf8').digest('hex');
        if (recomputedCpHash !== recordedHash) {
          return {
            valid: false,
            errorType: 'TAMPER_MODIFICATION',
            lineIndex,
            reason: `Checkpoint record modified at line ${lineIndex + 1}`
          };
        }

        lastSeenCheckpoint = record;
        checkpointsVerified++;
        expectedPrevHash = recordedHash;
      } else {
        return {
          valid: false,
          errorType: 'TAMPER_UNKNOWN_TYPE',
          lineIndex,
          reason: `Unknown record type '${record.type}' at line ${lineIndex + 1}`
        };
      }
    }

    // Check for truncation if a checkpoint promised more records than present
    if (lastSeenCheckpoint && recordsSeen < lastSeenCheckpoint.covered_records) {
      return {
        valid: false,
        errorType: 'TAMPER_TRUNCATION',
        promisedRecords: lastSeenCheckpoint.covered_records,
        actualRecords: recordsSeen,
        reason: `Truncation detected: checkpoint promised ${lastSeenCheckpoint.covered_records} records, but only ${recordsSeen} exist.`
      };
    }

    // Check for truncation against trusted external anchor
    if (trustedHead) {
      if (recordsSeen < (trustedHead.covered_records || 0)) {
        return {
          valid: false,
          errorType: 'TAMPER_TRUNCATION',
          reason: `Trusted anchor requires ${trustedHead.covered_records} records, but log only contains ${recordsSeen}`
        };
      }
      if (trustedHead.head_hash && lastSeenCheckpoint && lastSeenCheckpoint.covered_records === trustedHead.covered_records && lastSeenCheckpoint.head_hash !== trustedHead.head_hash) {
        return {
          valid: false,
          errorType: 'TAMPER_ANCHOR_MISMATCH',
          reason: `Checkpoint head hash does not match trusted external anchor`
        };
      }
    }

    return {
      valid: true,
      recordsVerified: recordsSeen,
      checkpointsVerified,
      headHash: expectedPrevHash
    };
  }
}

module.exports = {
  GENESIS_HASH,
  DEFAULT_CHECKPOINT_INTERVAL,
  canonicalJson,
  TamperEvidentLog
};
