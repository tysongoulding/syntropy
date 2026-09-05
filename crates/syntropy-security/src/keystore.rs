use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum KeyStoreError {
    #[error("Credential not found: {0}")]
    NotFound(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("Platform error: {0}")]
    PlatformError(String),

    #[error("Invalid key: {0}")]
    InvalidKey(String),

    #[error("Corrupted keystore file: {0}")]
    CorruptedStore(String),

    #[error("Lock error: {0}")]
    LockError(String),
}

/// Cross-platform secure credential storage trait.
pub trait KeyStore: Send + Sync {
    /// Store a secret under the given key.
    fn set(&self, key: &str, secret: &[u8]) -> Result<(), KeyStoreError>;

    /// Retrieve a secret by key. Returns None if key does not exist.
    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyStoreError>;

    /// Delete a secret by key. Returns true if key was present.
    fn delete(&self, key: &str) -> Result<bool, KeyStoreError>;

    /// List all keys in the keystore.
    fn list(&self) -> Result<Vec<String>, KeyStoreError>;

    /// Check if a key exists in the keystore.
    fn contains(&self, key: &str) -> Result<bool, KeyStoreError> {
        Ok(self.get(key)?.is_some())
    }

    /// Convenience helper to store a UTF-8 string secret.
    fn set_str(&self, key: &str, secret: &str) -> Result<(), KeyStoreError> {
        self.set(key, secret.as_bytes())
    }

    /// Convenience helper to retrieve a UTF-8 string secret.
    fn get_str(&self, key: &str) -> Result<Option<String>, KeyStoreError> {
        match self.get(key)? {
            Some(bytes) => {
                let s = String::from_utf8(bytes)
                    .map_err(|e| KeyStoreError::DecryptionFailed(format!("Invalid UTF-8 sequence: {e}")))?;
                Ok(Some(s))
            }
            None => Ok(None),
        }
    }
}

// ----------------------------------------------------------------------------
// In-Memory KeyStore
// ----------------------------------------------------------------------------

/// Fast, in-memory credential storage primarily used for testing or transient sessions.
#[derive(Debug, Default, Clone)]
pub struct InMemoryKeyStore {
    entries: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl InMemoryKeyStore {
    pub fn new() -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl KeyStore for InMemoryKeyStore {
    fn set(&self, key: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
        map.insert(key.to_string(), secret.to_vec());
        Ok(())
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        Ok(map.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<bool, KeyStoreError> {
        let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
        Ok(map.remove(key).is_some())
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}

// ----------------------------------------------------------------------------
// File-Encrypted Software KeyStore
// ----------------------------------------------------------------------------

const FILE_MAGIC: &[u8; 9] = b"SYNKSTOR1";

/// File-backed secure keystore encrypting all stored secrets using authenticated
/// SHA-256 CTR keystream encryption with HMAC authentication.
pub struct EncryptedFileKeyStore {
    path: PathBuf,
    master_key: [u8; 32],
    entries: Arc<RwLock<HashMap<String, Vec<u8>>>>,
}

impl EncryptedFileKeyStore {
    /// Open or create an encrypted keystore at the given path using a 32-byte master key.
    pub fn open_or_create(path: impl AsRef<Path>, master_key: [u8; 32]) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            Self::read_and_decrypt(&path, &master_key)?
        } else {
            HashMap::new()
        };

        let store = Self {
            path,
            master_key,
            entries: Arc::new(RwLock::new(entries)),
        };

        // If file didn't exist, flush empty store
        if !store.path.exists() {
            store.persist()?;
        }

        Ok(store)
    }

    /// Helper to derive a 32-byte key from a passphrase string and salt.
    pub fn derive_key(passphrase: &str, salt: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(passphrase.as_bytes());
        hasher.update(salt);
        hasher.update(b"syntropy-key-derivation-v1");
        let result = hasher.finalize();
        let mut key = [0u8; 32];
        key.copy_from_slice(&result);
        key
    }

    fn persist(&self) -> Result<(), KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        let plaintext = serde_json::to_vec(&*map)?;
        let encrypted_payload = Self::encrypt_payload(&plaintext, &self.master_key);

        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let temp_path = self.path.with_file_name(format!(
            "{}.tmp.{}",
            self.path.file_name().and_then(|n| n.to_str()).unwrap_or("keystore"),
            uuid::Uuid::new_v4()
        ));
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(&encrypted_payload)?;
            file.sync_all()?;
        }
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }

    fn read_and_decrypt(path: &Path, master_key: &[u8; 32]) -> Result<HashMap<String, Vec<u8>>, KeyStoreError> {
        let mut file = File::open(path)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;

        let plaintext = Self::decrypt_payload(&data, master_key)?;
        let map: HashMap<String, Vec<u8>> = serde_json::from_slice(&plaintext)?;
        Ok(map)
    }

    fn encrypt_payload(plaintext: &[u8], master_key: &[u8; 32]) -> Vec<u8> {
        let salt = uuid::Uuid::new_v4().into_bytes();
        let nonce = uuid::Uuid::new_v4().into_bytes();

        let mut enc_hasher = Sha256::new();
        enc_hasher.update(master_key);
        enc_hasher.update(salt);
        enc_hasher.update(b"encryption");
        let enc_key = enc_hasher.finalize();

        let mut mac_hasher = Sha256::new();
        mac_hasher.update(master_key);
        mac_hasher.update(salt);
        mac_hasher.update(b"authentication");
        let mac_key = mac_hasher.finalize();

        let mut ciphertext = plaintext.to_vec();
        Self::apply_keystream(&mut ciphertext, &enc_key, &nonce);

        let tag = Self::compute_hmac(&mac_key, &salt, &nonce, &ciphertext);

        let mut out = Vec::with_capacity(FILE_MAGIC.len() + 16 + 16 + 32 + ciphertext.len());
        out.extend_from_slice(FILE_MAGIC);
        out.extend_from_slice(&salt);
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&tag);
        out.extend_from_slice(&ciphertext);
        out
    }

    fn decrypt_payload(data: &[u8], master_key: &[u8; 32]) -> Result<Vec<u8>, KeyStoreError> {
        let min_len = FILE_MAGIC.len() + 16 + 16 + 32;
        if data.len() < min_len {
            return Err(KeyStoreError::CorruptedStore("Payload is smaller than header".into()));
        }

        if &data[..FILE_MAGIC.len()] != FILE_MAGIC {
            return Err(KeyStoreError::CorruptedStore("Invalid magic header".into()));
        }

        let mut offset = FILE_MAGIC.len();
        let salt = &data[offset..offset + 16];
        offset += 16;
        let nonce = &data[offset..offset + 16];
        offset += 16;
        let expected_tag = &data[offset..offset + 32];
        offset += 32;
        let ciphertext = &data[offset..];

        let mut mac_hasher = Sha256::new();
        mac_hasher.update(master_key);
        mac_hasher.update(salt);
        mac_hasher.update(b"authentication");
        let mac_key = mac_hasher.finalize();

        let computed_tag = Self::compute_hmac(&mac_key, salt, nonce, ciphertext);
        if computed_tag != expected_tag {
            return Err(KeyStoreError::DecryptionFailed("Authentication tag mismatch or corrupted file".into()));
        }

        let mut enc_hasher = Sha256::new();
        enc_hasher.update(master_key);
        enc_hasher.update(salt);
        enc_hasher.update(b"encryption");
        let enc_key = enc_hasher.finalize();

        let mut plaintext = ciphertext.to_vec();
        Self::apply_keystream(&mut plaintext, &enc_key, nonce);
        Ok(plaintext)
    }

    fn apply_keystream(data: &mut [u8], enc_key: &[u8], nonce: &[u8]) {
        for (counter, chunk) in (0_u64..).zip(data.chunks_mut(32)) {
            let mut hasher = Sha256::new();
            hasher.update(enc_key);
            hasher.update(nonce);
            hasher.update(counter.to_be_bytes());
            let block = hasher.finalize();

            for (byte, key_byte) in chunk.iter_mut().zip(block.iter()) {
                *byte ^= *key_byte;
            }
        }
    }

    fn compute_hmac(mac_key: &[u8], salt: &[u8], nonce: &[u8], ciphertext: &[u8]) -> [u8; 32] {
        let mut inner = Sha256::new();
        inner.update(mac_key);
        inner.update(b"inner-pad");
        inner.update(salt);
        inner.update(nonce);
        inner.update(ciphertext);
        let inner_hash = inner.finalize();

        let mut outer = Sha256::new();
        outer.update(mac_key);
        outer.update(b"outer-pad");
        outer.update(inner_hash);
        let result = outer.finalize();

        let mut tag = [0u8; 32];
        tag.copy_from_slice(&result);
        tag
    }
}

impl KeyStore for EncryptedFileKeyStore {
    fn set(&self, key: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        {
            let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
            map.insert(key.to_string(), secret.to_vec());
        }
        self.persist()
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        Ok(map.get(key).cloned())
    }

    fn delete(&self, key: &str) -> Result<bool, KeyStoreError> {
        let removed = {
            let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
            map.remove(key).is_some()
        };
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}

// ----------------------------------------------------------------------------
// Windows DPAPI KeyStore
// ----------------------------------------------------------------------------

#[cfg(target_os = "windows")]
pub mod dpapi {
    use std::ptr;
    use std::os::raw::c_void;
    use super::KeyStoreError;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    #[link(name = "crypt32")]
    extern "system" {
        fn CryptProtectData(
            p_data_in: *const DataBlob,
            sz_data_descr: *const u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            p_data_in: *const DataBlob,
            ppsz_data_descr: *mut *mut u16,
            p_optional_entropy: *const DataBlob,
            pv_reserved: *mut c_void,
            p_prompt_struct: *mut c_void,
            dw_flags: u32,
            p_data_out: *mut DataBlob,
        ) -> i32;
    }

    #[link(name = "kernel32")]
    extern "system" {
        fn LocalFree(h_mem: *mut c_void) -> *mut c_void;
        fn GetLastError() -> u32;
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    /// Encrypt data using Windows Data Protection API (DPAPI).
    pub fn protect(data: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, KeyStoreError> {
        let in_blob = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut entropy_blob = entropy.map(|e| DataBlob {
            cb_data: e.len() as u32,
            pb_data: e.as_ptr() as *mut u8,
        });
        let p_entropy = match entropy_blob.as_mut() {
            Some(b) => b as *mut DataBlob,
            None => ptr::null_mut(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let res = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                p_entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if res == 0 {
            let err = unsafe { GetLastError() };
            return Err(KeyStoreError::PlatformError(format!("CryptProtectData failed with error code: {err}")));
        }

        let slice = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize)
        };
        let result = slice.to_vec();
        unsafe { LocalFree(out_blob.pb_data as *mut c_void) };
        Ok(result)
    }

    /// Decrypt data using Windows Data Protection API (DPAPI).
    pub fn unprotect(data: &[u8], entropy: Option<&[u8]>) -> Result<Vec<u8>, KeyStoreError> {
        let in_blob = DataBlob {
            cb_data: data.len() as u32,
            pb_data: data.as_ptr() as *mut u8,
        };
        let mut entropy_blob = entropy.map(|e| DataBlob {
            cb_data: e.len() as u32,
            pb_data: e.as_ptr() as *mut u8,
        });
        let p_entropy = match entropy_blob.as_mut() {
            Some(b) => b as *mut DataBlob,
            None => ptr::null_mut(),
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let res = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                p_entropy,
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if res == 0 {
            let err = unsafe { GetLastError() };
            return Err(KeyStoreError::PlatformError(format!("CryptUnprotectData failed with error code: {err}")));
        }

        let slice = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize)
        };
        let result = slice.to_vec();
        unsafe { LocalFree(out_blob.pb_data as *mut c_void) };
        Ok(result)
    }
}

/// Windows DPAPI-backed file keystore storing credentials encrypted with user login keys.
#[cfg(target_os = "windows")]
pub struct DpapiKeyStore {
    path: PathBuf,
    entries: Arc<RwLock<HashMap<String, Vec<u8>>>>, // key -> DPAPI protected ciphertext
}

#[cfg(target_os = "windows")]
impl DpapiKeyStore {
    pub fn default_path() -> Result<PathBuf, KeyStoreError> {
        let base = directories_next::ProjectDirs::from("com", "syntropy", "syntropy")
            .ok_or_else(|| KeyStoreError::Io(std::io::Error::new(std::io::ErrorKind::NotFound, "Could not determine project directories")))?;
        Ok(base.data_local_dir().join("keystore.dpapi"))
    }

    pub fn new() -> Result<Self, KeyStoreError> {
        let path = Self::default_path()?;
        Self::open_or_create(path)
    }

    pub fn open_or_create(path: impl AsRef<Path>) -> Result<Self, KeyStoreError> {
        let path = path.as_ref().to_path_buf();
        let entries = if path.exists() {
            let content = fs::read(&path)?;
            if content.is_empty() {
                HashMap::new()
            } else {
                serde_json::from_slice(&content)?
            }
        } else {
            HashMap::new()
        };

        let store = Self {
            path,
            entries: Arc::new(RwLock::new(entries)),
        };

        if !store.path.exists() {
            store.persist()?;
        }

        Ok(store)
    }

    fn persist(&self) -> Result<(), KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        let serialized = serde_json::to_vec(&*map)?;

        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)?;
            }
        }

        let temp_path = self.path.with_extension("tmp");
        {
            let mut file = File::create(&temp_path)?;
            file.write_all(&serialized)?;
            file.sync_all()?;
        }
        fs::rename(&temp_path, &self.path)?;
        Ok(())
    }
}

#[cfg(target_os = "windows")]
impl KeyStore for DpapiKeyStore {
    fn set(&self, key: &str, secret: &[u8]) -> Result<(), KeyStoreError> {
        let protected = dpapi::protect(secret, None)?;
        {
            let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
            map.insert(key.to_string(), protected);
        }
        self.persist()
    }

    fn get(&self, key: &str) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        match map.get(key) {
            Some(protected) => {
                let decrypted = dpapi::unprotect(protected, None)?;
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }

    fn delete(&self, key: &str) -> Result<bool, KeyStoreError> {
        let removed = {
            let mut map = self.entries.write().map_err(|_| KeyStoreError::LockError("Failed to acquire write lock".into()))?;
            map.remove(key).is_some()
        };
        if removed {
            self.persist()?;
        }
        Ok(removed)
    }

    fn list(&self) -> Result<Vec<String>, KeyStoreError> {
        let map = self.entries.read().map_err(|_| KeyStoreError::LockError("Failed to acquire read lock".into()))?;
        let mut keys: Vec<String> = map.keys().cloned().collect();
        keys.sort();
        Ok(keys)
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_keystore() {
        let ks = InMemoryKeyStore::new();
        assert!(ks.list().unwrap().is_empty());

        ks.set_str("github_pat", "ghp_secret123").unwrap();
        assert_eq!(ks.get_str("github_pat").unwrap(), Some("ghp_secret123".to_string()));
        assert!(ks.contains("github_pat").unwrap());

        let keys = ks.list().unwrap();
        assert_eq!(keys, vec!["github_pat".to_string()]);

        let deleted = ks.delete("github_pat").unwrap();
        assert!(deleted);
        assert_eq!(ks.get_str("github_pat").unwrap(), None);
        assert!(!ks.contains("github_pat").unwrap());
    }

    #[test]
    fn test_encrypted_file_keystore_roundtrip() {
        let temp_dir = std::env::temp_dir().join(format!("syn_test_ks_{}", uuid::Uuid::new_v4()));
        let file_path = temp_dir.join("creds.enc");

        let master_key = EncryptedFileKeyStore::derive_key("super-secret-passphrase", b"salt123");

        {
            let ks = EncryptedFileKeyStore::open_or_create(&file_path, master_key).unwrap();
            ks.set_str("aws_secret", "AKIAIOSFODNN7EXAMPLE").unwrap();
            ks.set("binary_key", &[0x01, 0x02, 0x03, 0x04]).unwrap();
        }

        // Re-open from disk and verify
        {
            let ks = EncryptedFileKeyStore::open_or_create(&file_path, master_key).unwrap();
            assert_eq!(ks.get_str("aws_secret").unwrap(), Some("AKIAIOSFODNN7EXAMPLE".to_string()));
            assert_eq!(ks.get("binary_key").unwrap(), Some(vec![0x01, 0x02, 0x03, 0x04]));
            assert_eq!(ks.list().unwrap(), vec!["aws_secret".to_string(), "binary_key".to_string()]);
        }

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_encrypted_file_keystore_tamper_detection() {
        let temp_dir = std::env::temp_dir().join(format!("syn_test_tamper_{}", uuid::Uuid::new_v4()));
        let file_path = temp_dir.join("creds.enc");

        let master_key = [7u8; 32];
        {
            let ks = EncryptedFileKeyStore::open_or_create(&file_path, master_key).unwrap();
            ks.set_str("key1", "val1").unwrap();
        }

        // Tamper with the file contents by modifying one byte
        let mut content = fs::read(&file_path).unwrap();
        let last = content.len() - 1;
        content[last] ^= 0xFF;
        fs::write(&file_path, &content).unwrap();

        // Reopening or decrypting must fail
        let result = EncryptedFileKeyStore::open_or_create(&file_path, master_key);
        assert!(result.is_err());

        // Cleanup
        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn test_windows_dpapi_keystore() {
        let temp_dir = std::env::temp_dir().join(format!("syn_test_dpapi_{}", uuid::Uuid::new_v4()));
        let file_path = temp_dir.join("creds.dpapi");

        {
            let ks = DpapiKeyStore::open_or_create(&file_path).unwrap();
            ks.set_str("dpapi_token", "secure_windows_token_xyz").unwrap();
        }

        // Verify stored file does not contain plain secret
        let raw_bytes = fs::read(&file_path).unwrap();
        let raw_str = String::from_utf8_lossy(&raw_bytes);
        assert!(!raw_str.contains("secure_windows_token_xyz"));

        // Reopen and retrieve
        {
            let ks = DpapiKeyStore::open_or_create(&file_path).unwrap();
            assert_eq!(ks.get_str("dpapi_token").unwrap(), Some("secure_windows_token_xyz".to_string()));
            assert!(ks.delete("dpapi_token").unwrap());
            assert_eq!(ks.get_str("dpapi_token").unwrap(), None);
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }
}
