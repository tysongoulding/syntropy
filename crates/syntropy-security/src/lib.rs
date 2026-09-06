//! Syntropy Security: Secure credential keystore, inverted token broker, and Merkle audit ledger.

pub mod keystore;
pub mod broker;
pub mod ledger;
pub mod credential_persistence;

pub use credential_persistence::{BackupSummary, CredentialPersistence, PersistenceError, RestoreSummary};

pub use keystore::{
    EncryptedFileKeyStore, InMemoryKeyStore, KeyStore, KeyStoreError,
};

#[cfg(target_os = "windows")]
pub use keystore::{dpapi, DpapiKeyStore};

pub use broker::{
    compute_hmac_sha256, BrokerAction, BrokerError, CredentialBinding, CredentialBroker,
    OAuthSession, WebAuthnCeremonyParams, WebAuthnCeremonyResult,
};

pub use ledger::{
    compute_entry_hash, hash_payload, AuditEntry, IntegrityReport, IntegrityViolation, LedgerError,
    MerkleAuditLedger, GENESIS_HASH,
};
