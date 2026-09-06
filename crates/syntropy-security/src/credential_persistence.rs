use std::collections::HashSet;
use std::fs;
use std::path::Path;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tracing::{debug, info};

#[derive(Error, Debug)]
pub enum PersistenceError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Oversized payload ({size} bytes > {cap} bytes cap)")]
    Oversized { size: u64, cap: u64 },
}

#[derive(Debug, Default)]
pub struct BackupSummary {
    pub persisted: usize,
    pub unchanged: usize,
    pub absent: usize,
    pub pruned: usize,
}

#[derive(Debug, Default)]
pub struct RestoreSummary {
    pub restored: usize,
    pub kept_local: usize,
}

pub struct CredentialPersistence {
    prune_names: HashSet<String>,
    dir_cap_bytes: u64,
}

impl Default for CredentialPersistence {
    fn default() -> Self {
        let mut prune = HashSet::new();
        for name in &["Cache", "cache", "GPUCache", "logs", "buildx", "scout"] {
            prune.insert((*name).to_string());
        }
        Self {
            prune_names: prune,
            dir_cap_bytes: 50 * 1024 * 1024, // 50 MiB cap
        }
    }
}

impl CredentialPersistence {
    pub fn new(dir_cap_bytes: u64) -> Self {
        Self {
            dir_cap_bytes,
            ..Default::default()
        }
    }

    pub fn dir_cap_bytes(&self) -> u64 {
        self.dir_cap_bytes
    }

    pub fn compute_content_sig(&self, path: &Path) -> Result<String, PersistenceError> {
        if !path.exists() {
            return Ok(String::new());
        }
        if path.is_file() {
            let data = fs::read(path)?;
            let mut hasher = Sha256::new();
            hasher.update(&data);
            return Ok(format!("{:x}", hasher.finalize()));
        }

        let mut file_hashes = Vec::new();
        self.collect_hashes(path, path, &mut file_hashes)?;
        file_hashes.sort();

        let mut overall = Sha256::new();
        for (rel_path, hash) in file_hashes {
            overall.update(rel_path.as_bytes());
            overall.update(hash.as_bytes());
        }
        Ok(format!("{:x}", overall.finalize()))
    }

    fn collect_hashes(
        &self,
        root: &Path,
        current: &Path,
        acc: &mut Vec<(String, String)>,
    ) -> Result<(), PersistenceError> {
        if !current.is_dir() {
            return Ok(());
        }
        for entry in fs::read_dir(current)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() && self.prune_names.contains(&file_name) {
                continue;
            }

            if path.is_file() {
                let data = fs::read(&path)?;
                if !data.is_empty() {
                    let mut h = Sha256::new();
                    h.update(&data);
                    let rel = path.strip_prefix(root).unwrap_or(&path).to_string_lossy().to_string();
                    acc.push((rel, format!("{:x}", h.finalize())));
                }
            } else if path.is_dir() {
                self.collect_hashes(root, &path, acc)?;
            }
        }
        Ok(())
    }

    pub fn backup_one(
        &self,
        src_path: &Path,
        dst_path: &Path,
        sig_path: &Path,
    ) -> Result<bool, PersistenceError> {
        if !src_path.exists() {
            if dst_path.exists() {
                let _ = fs::remove_dir_all(dst_path);
                let _ = fs::remove_file(sig_path);
                return Ok(false);
            }
            return Ok(false);
        }

        let current_sig = self.compute_content_sig(src_path)?;
        if current_sig.is_empty() {
            return Ok(false);
        }

        if sig_path.exists() && dst_path.exists() {
            if let Ok(prev_sig) = fs::read_to_string(sig_path) {
                if prev_sig.trim() == current_sig {
                    debug!("Unchanged credential at {:?}", src_path);
                    return Ok(false);
                }
            }
        }

        if let Some(parent) = dst_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if let Some(parent) = sig_path.parent() {
            fs::create_dir_all(parent)?;
        }

        if src_path.is_file() {
            fs::copy(src_path, dst_path)?;
        } else {
            self.copy_dir_pruned(src_path, dst_path)?;
        }

        Self::harden_permissions(dst_path)?;
        fs::write(sig_path, &current_sig)?;
        info!("Persisted credential from {:?} to {:?}", src_path, dst_path);
        Ok(true)
    }

    fn copy_dir_pruned(&self, src: &Path, dst: &Path) -> Result<(), PersistenceError> {
        if !dst.exists() {
            fs::create_dir_all(dst)?;
        }
        for entry in fs::read_dir(src)? {
            let entry = entry?;
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();

            if path.is_dir() && self.prune_names.contains(&file_name) {
                continue;
            }

            let target = dst.join(entry.file_name());
            if path.is_file() {
                fs::copy(&path, &target)?;
                Self::harden_permissions(&target)?;
            } else if path.is_dir() {
                self.copy_dir_pruned(&path, &target)?;
            }
        }
        Ok(())
    }

    pub fn restore_one(&self, msrc: &Path, dst: &Path) -> Result<bool, PersistenceError> {
        if !msrc.exists() {
            return Ok(false);
        }

        if dst.exists() {
            let live_sig = self.compute_content_sig(dst)?;
            if !live_sig.is_empty() {
                // Local wins when live credentials already exist
                return Ok(false);
            }
        }

        if let Some(parent) = dst.parent() {
            fs::create_dir_all(parent)?;
        }

        if msrc.is_file() {
            fs::copy(msrc, dst)?;
            Self::harden_permissions(dst)?;
        } else {
            self.copy_dir_pruned(msrc, dst)?;
            Self::harden_permissions(dst)?;
        }

        info!("Restored credential from {:?} to {:?}", msrc, dst);
        Ok(true)
    }

    pub fn harden_permissions(path: &Path) -> Result<(), PersistenceError> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if path.is_dir() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
            } else if path.is_file() {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
            }
        }
        #[cfg(not(unix))]
        {
            let _ = path;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_credential_backup_and_restore_lifecycle() {
        let base_tmp = std::env::temp_dir().join(format!("syntropy-cred-test-{}", uuid::Uuid::new_v4()));
        let home = base_tmp.join("home");
        let mirror = base_tmp.join("mirror");
        let new_home = base_tmp.join("new_home");
        fs::create_dir_all(&home).unwrap();
        fs::create_dir_all(&mirror).unwrap();
        fs::create_dir_all(&new_home).unwrap();

        let persistence = CredentialPersistence::default();

        let ssh_dir = home.join(".ssh");
        fs::create_dir_all(&ssh_dir).unwrap();
        let id_rsa = ssh_dir.join("id_rsa");
        fs::write(&id_rsa, "FAKE_RSA_KEY_DATA_CONTENT").unwrap();

        // Also create a Cache dir that should be pruned
        let cache_dir = ssh_dir.join("Cache");
        fs::create_dir_all(&cache_dir).unwrap();
        fs::write(cache_dir.join("temp.cache"), "transient_data").unwrap();

        let mirror_ssh = mirror.join(".ssh");
        let sig_file = mirror.join(".ssh.sig");

        // 1. Backup
        let changed = persistence.backup_one(&ssh_dir, &mirror_ssh, &sig_file).unwrap();
        assert!(changed);
        assert!(mirror_ssh.join("id_rsa").exists());
        assert!(!mirror_ssh.join("Cache").exists(), "Cache dir should have been pruned");

        // Second backup without modification should report unchanged (false)
        let changed2 = persistence.backup_one(&ssh_dir, &mirror_ssh, &sig_file).unwrap();
        assert!(!changed2);

        // 2. Restore to clean target
        let new_ssh = new_home.join(".ssh");
        let restored = persistence.restore_one(&mirror_ssh, &new_ssh).unwrap();
        assert!(restored);
        assert!(new_ssh.join("id_rsa").exists());
        assert_eq!(
            fs::read_to_string(new_ssh.join("id_rsa")).unwrap(),
            "FAKE_RSA_KEY_DATA_CONTENT"
        );

        // Cleanup
        let _ = fs::remove_dir_all(base_tmp);
    }
}
