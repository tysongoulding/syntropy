use std::path::Path;
use std::sync::{Arc, Mutex};
use chrono::Utc;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Error, Debug)]
pub enum LedgerError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Lock error: {0}")]
    LockError(String),

    #[error("Ledger corrupted: {0}")]
    Corrupted(String),
}

/// A single immutable audit trail record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEntry {
    pub entry_id: i64,
    pub timestamp: String,
    pub agent_id: String,
    pub action_type: String,
    pub payload_hash: String,
    pub previous_hash: String,
    pub entry_hash: String,
}

/// Detailed diagnosis of any audit log tampering detected by `verify_integrity`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntegrityViolation {
    GenesisMismatch {
        found: String,
    },
    NonContiguousId {
        expected: i64,
        found: i64,
    },
    BrokenChain {
        entry_id: i64,
        expected_previous_hash: String,
        found_previous_hash: String,
    },
    CorruptedEntry {
        entry_id: i64,
        expected_entry_hash: String,
        found_entry_hash: String,
    },
}

/// Result of an audit ledger integrity verification scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub is_valid: bool,
    pub verified_count: usize,
    pub latest_hash: Option<String>,
    pub violation: Option<IntegrityViolation>,
}

/// Compute SHA-256 hash of arbitrary bytes into a hex string.
pub fn hash_payload(payload: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(payload);
    hex::encode(hasher.finalize())
}

/// Compute canonical SHA-256 entry hash chaining the previous hash and entry metadata.
pub fn compute_entry_hash(
    entry_id: i64,
    timestamp: &str,
    agent_id: &str,
    action_type: &str,
    payload_hash: &str,
    previous_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(previous_hash.as_bytes());
    hasher.update(entry_id.to_be_bytes());
    hasher.update(timestamp.as_bytes());
    hasher.update(agent_id.as_bytes());
    hasher.update(action_type.as_bytes());
    hasher.update(payload_hash.as_bytes());
    hex::encode(hasher.finalize())
}

/// MerkleAuditLedger maintains a cryptographically chained, append-only audit trail
/// persisted in SQLite via `rusqlite`.
pub struct MerkleAuditLedger {
    conn: Arc<Mutex<Connection>>,
}

impl MerkleAuditLedger {
    /// Open or create an audit ledger at the specified SQLite database path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, LedgerError> {
        let path = path.as_ref();
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent).map_err(|e| rusqlite::Error::ToSqlConversionFailure(Box::new(e)))?;
            }
        }
        let conn = Connection::open(path)?;
        Self::init_connection(conn)
    }

    /// Open an in-memory SQLite audit ledger (useful for tests or ephemeral tasks).
    pub fn open_in_memory() -> Result<Self, LedgerError> {
        let conn = Connection::open_in_memory()?;
        Self::init_connection(conn)
    }

    /// Initialize a ledger from an existing rusqlite connection.
    pub fn from_connection(conn: Connection) -> Result<Self, LedgerError> {
        Self::init_connection(conn)
    }

    fn init_connection(conn: Connection) -> Result<Self, LedgerError> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS audit_ledger (
                 entry_id INTEGER PRIMARY KEY,
                 timestamp TEXT NOT NULL,
                 agent_id TEXT NOT NULL,
                 action_type TEXT NOT NULL,
                 payload_hash TEXT NOT NULL,
                 previous_hash TEXT NOT NULL,
                 entry_hash TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_ledger(agent_id);
             CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_ledger(timestamp);
             CREATE INDEX IF NOT EXISTS idx_audit_entry_hash ON audit_ledger(entry_hash);",
        )?;

        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    /// Append an audit event to the ledger with the raw payload bytes.
    pub fn append(&self, agent_id: &str, action_type: &str, payload: &[u8]) -> Result<AuditEntry, LedgerError> {
        let payload_hash = hash_payload(payload);
        self.append_with_hash(agent_id, action_type, &payload_hash)
    }

    /// Append an audit event to the ledger using a pre-computed SHA-256 payload hash.
    pub fn append_with_hash(&self, agent_id: &str, action_type: &str, payload_hash: &str) -> Result<AuditEntry, LedgerError> {
        let mut conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let tx = conn.transaction()?;

        let last_entry: Option<(i64, String)> = tx
            .query_row(
                "SELECT entry_id, entry_hash FROM audit_ledger ORDER BY entry_id DESC LIMIT 1",
                [],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        let (next_id, prev_hash) = match last_entry {
            Some((id, hash)) => (id + 1, hash),
            None => (1, GENESIS_HASH.to_string()),
        };

        let timestamp = Utc::now().to_rfc3339();
        let entry_hash = compute_entry_hash(next_id, &timestamp, agent_id, action_type, payload_hash, &prev_hash);

        tx.execute(
            "INSERT INTO audit_ledger (entry_id, timestamp, agent_id, action_type, payload_hash, previous_hash, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![next_id, &timestamp, agent_id, action_type, payload_hash, &prev_hash, &entry_hash],
        )?;

        tx.commit()?;

        Ok(AuditEntry {
            entry_id: next_id,
            timestamp,
            agent_id: agent_id.to_string(),
            action_type: action_type.to_string(),
            payload_hash: payload_hash.to_string(),
            previous_hash: prev_hash,
            entry_hash,
        })
    }

    /// Retrieve an audit entry by its sequential ID.
    pub fn get_entry(&self, entry_id: i64) -> Result<Option<AuditEntry>, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let entry = conn
            .query_row(
                "SELECT entry_id, timestamp, agent_id, action_type, payload_hash, previous_hash, entry_hash
                 FROM audit_ledger WHERE entry_id = ?1",
                params![entry_id],
                Self::row_to_entry,
            )
            .optional()?;
        Ok(entry)
    }

    /// Retrieve the most recently appended audit entry.
    pub fn get_latest_entry(&self) -> Result<Option<AuditEntry>, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let entry = conn
            .query_row(
                "SELECT entry_id, timestamp, agent_id, action_type, payload_hash, previous_hash, entry_hash
                 FROM audit_ledger ORDER BY entry_id DESC LIMIT 1",
                [],
                Self::row_to_entry,
            )
            .optional()?;
        Ok(entry)
    }

    /// Retrieve a range of audit entries for inspection or synchronization.
    pub fn get_entries(&self, offset: usize, limit: usize) -> Result<Vec<AuditEntry>, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, agent_id, action_type, payload_hash, previous_hash, entry_hash
             FROM audit_ledger ORDER BY entry_id ASC LIMIT ?1 OFFSET ?2",
        )?;

        let rows = stmt.query_map(params![limit as i64, offset as i64], Self::row_to_entry)?;
        let mut entries = Vec::new();
        for row in rows {
            entries.push(row?);
        }
        Ok(entries)
    }

    /// Total number of entries in the ledger.
    pub fn count(&self) -> Result<usize, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM audit_ledger", [], |r| r.get(0))?;
        Ok(count as usize)
    }

    /// Validate the cryptographic integrity of the entire audit chain.
    ///
    /// Verifies:
    /// 1. Genesis record chains correctly from GENESIS_HASH.
    /// 2. IDs are strictly consecutive without deletions or gaps.
    /// 3. Each entry's `previous_hash` matches the preceding record's `entry_hash`.
    /// 4. Recomputed entry SHA-256 matches the stored `entry_hash` exactly.
    pub fn verify_integrity(&self) -> Result<IntegrityReport, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let mut stmt = conn.prepare(
            "SELECT entry_id, timestamp, agent_id, action_type, payload_hash, previous_hash, entry_hash
             FROM audit_ledger ORDER BY entry_id ASC",
        )?;

        let mut rows = stmt.query([])?;
        let mut expected_id: i64 = 1;
        let mut expected_prev = GENESIS_HASH.to_string();
        let mut verified_count: usize = 0;
        let mut latest_hash = None;

        while let Some(row) = rows.next()? {
            let entry = Self::row_to_entry(row)?;

            // 1. Verify sequence ID continuity
            if entry.entry_id != expected_id {
                return Ok(IntegrityReport {
                    is_valid: false,
                    verified_count,
                    latest_hash,
                    violation: Some(IntegrityViolation::NonContiguousId {
                        expected: expected_id,
                        found: entry.entry_id,
                    }),
                });
            }

            // 2. Verify previous hash link
            if entry.previous_hash != expected_prev {
                if expected_id == 1 {
                    return Ok(IntegrityReport {
                        is_valid: false,
                        verified_count,
                        latest_hash,
                        violation: Some(IntegrityViolation::GenesisMismatch {
                            found: entry.previous_hash,
                        }),
                    });
                } else {
                    return Ok(IntegrityReport {
                        is_valid: false,
                        verified_count,
                        latest_hash,
                        violation: Some(IntegrityViolation::BrokenChain {
                            entry_id: entry.entry_id,
                            expected_previous_hash: expected_prev,
                            found_previous_hash: entry.previous_hash,
                        }),
                    });
                }
            }

            // 3. Recompute and verify entry hash
            let computed = compute_entry_hash(
                entry.entry_id,
                &entry.timestamp,
                &entry.agent_id,
                &entry.action_type,
                &entry.payload_hash,
                &entry.previous_hash,
            );

            if computed != entry.entry_hash {
                return Ok(IntegrityReport {
                    is_valid: false,
                    verified_count,
                    latest_hash,
                    violation: Some(IntegrityViolation::CorruptedEntry {
                        entry_id: entry.entry_id,
                        expected_entry_hash: computed,
                        found_entry_hash: entry.entry_hash,
                    }),
                });
            }

            expected_prev = entry.entry_hash.clone();
            latest_hash = Some(entry.entry_hash);
            expected_id += 1;
            verified_count += 1;
        }

        Ok(IntegrityReport {
            is_valid: true,
            verified_count,
            latest_hash,
            violation: None,
        })
    }

    /// Compute a Merkle tree root over all entry hashes in the ledger.
    pub fn compute_merkle_root(&self) -> Result<Option<String>, LedgerError> {
        let conn = self.conn.lock().map_err(|_| LedgerError::LockError("Failed to lock DB connection".into()))?;
        let mut stmt = conn.prepare("SELECT entry_hash FROM audit_ledger ORDER BY entry_id ASC")?;
        let hashes: Vec<String> = stmt.query_map([], |r| r.get(0))?.collect::<Result<_, _>>()?;

        if hashes.is_empty() {
            return Ok(None);
        }

        let mut current_level: Vec<Vec<u8>> = hashes
            .into_iter()
            .map(|h| hex::decode(h).unwrap_or_default())
            .collect();

        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let mut hasher = Sha256::new();
                hasher.update(&chunk[0]);
                if chunk.len() > 1 {
                    hasher.update(&chunk[1]);
                } else {
                    hasher.update(&chunk[0]);
                }
                next_level.push(hasher.finalize().to_vec());
            }
            current_level = next_level;
        }

        Ok(current_level.first().map(hex::encode))
    }

    fn row_to_entry(row: &rusqlite::Row) -> rusqlite::Result<AuditEntry> {
        Ok(AuditEntry {
            entry_id: row.get(0)?,
            timestamp: row.get(1)?,
            agent_id: row.get(2)?,
            action_type: row.get(3)?,
            payload_hash: row.get(4)?,
            previous_hash: row.get(5)?,
            entry_hash: row.get(6)?,
        })
    }

    /// Exposes raw connection for testing corruption scenarios.
    #[cfg(test)]
    pub(crate) fn raw_connection(&self) -> Arc<Mutex<Connection>> {
        self.conn.clone()
    }
}

// ----------------------------------------------------------------------------
// Unit Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_ledger_append_and_verify_integrity() {
        let ledger = MerkleAuditLedger::open_in_memory().unwrap();
        assert_eq!(ledger.count().unwrap(), 0);

        let e1 = ledger.append("agent-alpha", "fs_read", b"path=/etc/hosts").unwrap();
        assert_eq!(e1.entry_id, 1);
        assert_eq!(e1.previous_hash, GENESIS_HASH);

        let e2 = ledger.append("agent-beta", "exec_cmd", b"cmd=cargo check").unwrap();
        assert_eq!(e2.entry_id, 2);
        assert_eq!(e2.previous_hash, e1.entry_hash);

        let e3 = ledger.append("agent-alpha", "fs_write", b"path=out.txt;data=hello").unwrap();
        assert_eq!(e3.entry_id, 3);
        assert_eq!(e3.previous_hash, e2.entry_hash);

        assert_eq!(ledger.count().unwrap(), 3);

        let report = ledger.verify_integrity().unwrap();
        assert!(report.is_valid);
        assert_eq!(report.verified_count, 3);
        assert_eq!(report.latest_hash, Some(e3.entry_hash.clone()));
        assert_eq!(report.violation, None);

        let merkle_root = ledger.compute_merkle_root().unwrap();
        assert!(merkle_root.is_some());
    }

    #[test]
    fn test_merkle_ledger_tamper_detection_modified_payload() {
        let ledger = MerkleAuditLedger::open_in_memory().unwrap();
        ledger.append("agent-1", "action-1", b"original-payload-1").unwrap();
        ledger.append("agent-2", "action-2", b"original-payload-2").unwrap();
        ledger.append("agent-3", "action-3", b"original-payload-3").unwrap();

        // Tamper directly with the SQLite database row for entry 2
        {
            let conn = ledger.raw_connection();
            let locked = conn.lock().unwrap();
            locked
                .execute(
                    "UPDATE audit_ledger SET payload_hash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE entry_id = 2",
                    [],
                )
                .unwrap();
        }

        let report = ledger.verify_integrity().unwrap();
        assert!(!report.is_valid);
        assert_eq!(report.verified_count, 1); // Only entry 1 was verified before detecting violation at entry 2
        match report.violation {
            Some(IntegrityViolation::CorruptedEntry { entry_id, .. }) => {
                assert_eq!(entry_id, 2);
            }
            other => panic!("Expected CorruptedEntry violation, got {:?}", other),
        }
    }

    #[test]
    fn test_merkle_ledger_tamper_detection_deleted_row() {
        let ledger = MerkleAuditLedger::open_in_memory().unwrap();
        ledger.append("agent-1", "action-1", b"p1").unwrap();
        ledger.append("agent-2", "action-2", b"p2").unwrap();
        ledger.append("agent-3", "action-3", b"p3").unwrap();

        // Delete entry 2 from SQLite
        {
            let conn = ledger.raw_connection();
            let locked = conn.lock().unwrap();
            locked.execute("DELETE FROM audit_ledger WHERE entry_id = 2", []).unwrap();
        }

        let report = ledger.verify_integrity().unwrap();
        assert!(!report.is_valid);
        match report.violation {
            Some(IntegrityViolation::NonContiguousId { expected, found }) => {
                assert_eq!(expected, 2);
                assert_eq!(found, 3);
            }
            other => panic!("Expected NonContiguousId violation, got {:?}", other),
        }
    }

    #[test]
    fn test_merkle_ledger_tamper_detection_broken_chain() {
        let ledger = MerkleAuditLedger::open_in_memory().unwrap();
        ledger.append("agent-1", "action-1", b"p1").unwrap();
        ledger.append("agent-2", "action-2", b"p2").unwrap();

        // Tamper with previous_hash of entry 2 without modifying entry 1
        {
            let conn = ledger.raw_connection();
            let locked = conn.lock().unwrap();
            locked
                .execute(
                    "UPDATE audit_ledger SET previous_hash = '1111111111111111111111111111111111111111111111111111111111111111' WHERE entry_id = 2",
                    [],
                )
                .unwrap();
        }

        let report = ledger.verify_integrity().unwrap();
        assert!(!report.is_valid);
        match report.violation {
            Some(IntegrityViolation::BrokenChain { entry_id, .. }) => {
                assert_eq!(entry_id, 2);
            }
            other => panic!("Expected BrokenChain violation, got {:?}", other),
        }
    }
}
