//! Workspace containment jail enforcing path boundaries and preventing directory traversal attacks.

use std::path::{Component, Path, PathBuf};
use thiserror::Error;

/// Errors produced during jail boundary enforcement and path resolution.
#[derive(Debug, Error)]
pub enum JailError {
    #[error("Workspace root does not exist: {0}")]
    RootNotFound(PathBuf),

    #[error("Workspace root is not a directory: {0}")]
    RootNotDirectory(PathBuf),

    #[error("Access denied: path '{path}' is outside permitted workspace root '{root}'")]
    OutsideWorkspace { path: PathBuf, root: PathBuf },

    #[error("Invalid path: {0}")]
    InvalidPath(String),

    #[error("Working directory does not exist or is not a directory: {0}")]
    InvalidWorkingDirectory(PathBuf),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Enforces containment boundaries for agent file operations and execution cwd.
#[derive(Debug, Clone)]
pub struct WorkspaceJail {
    root: PathBuf,
    canonical_root: PathBuf,
    allowed_paths: Vec<PathBuf>,
    canonical_allowed_paths: Vec<PathBuf>,
}

impl WorkspaceJail {
    /// Creates a new `WorkspaceJail` rooted at `root`.
    ///
    /// The root path must exist and be a directory.
    pub fn new(root: impl AsRef<Path>) -> Result<Self, JailError> {
        Self::with_allowed_paths(root, Vec::new())
    }

    /// Creates a new `WorkspaceJail` with additional allowed paths.
    pub fn with_allowed_paths(
        root: impl AsRef<Path>,
        allowed_paths: Vec<PathBuf>,
    ) -> Result<Self, JailError> {
        let root = root.as_ref().to_path_buf();
        if !root.exists() {
            return Err(JailError::RootNotFound(root));
        }
        if !root.is_dir() {
            return Err(JailError::RootNotDirectory(root));
        }

        let canonical_root = std::fs::canonicalize(&root)?;

        let mut canonical_allowed = Vec::with_capacity(allowed_paths.len());
        for path in &allowed_paths {
            if path.exists() {
                canonical_allowed.push(std::fs::canonicalize(path)?);
            } else {
                canonical_allowed.push(path.clone());
            }
        }

        Ok(Self {
            root,
            canonical_root,
            allowed_paths,
            canonical_allowed_paths: canonical_allowed,
        })
    }

    /// Returns the declared workspace root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Returns the canonical workspace root.
    pub fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    /// Returns the additional allowed paths.
    pub fn allowed_paths(&self) -> &[PathBuf] {
        &self.allowed_paths
    }

    /// Checks whether `path` is contained within the canonical root or any allowed path.
    pub fn is_contained(&self, path: &Path) -> bool {
        if is_path_within(&self.canonical_root, path) {
            return true;
        }

        for allowed in &self.canonical_allowed_paths {
            if is_path_within(allowed, path) {
                return true;
            }
        }

        false
    }

    /// Validates that a path is strictly contained within the workspace boundaries.
    pub fn check_contained(&self, path: &Path) -> Result<PathBuf, JailError> {
        let resolved = self.resolve_path(path)?;
        if !self.is_contained(&resolved) {
            return Err(JailError::OutsideWorkspace {
                path: resolved,
                root: self.canonical_root.clone(),
            });
        }
        Ok(resolved)
    }

    /// Resolves and canonicalizes a path, ensuring containment within the jail.
    ///
    /// If the path is relative, it is joined to `canonical_root`.
    /// If the target file/directory exists, it is directly canonicalized.
    /// If the target does not exist yet (e.g. creating a new file), its deepest
    /// existing ancestor is canonicalized and validated, and subsequent path
    /// components are checked for traversal attempts (`..`, symlink illusions).
    pub fn resolve_path(&self, path: impl AsRef<Path>) -> Result<PathBuf, JailError> {
        let path = path.as_ref();

        // An empty path resolves to the canonical root
        if path.as_os_str().is_empty() {
            return Ok(self.canonical_root.clone());
        }

        // Determine base path to evaluate
        let target_path = if path.is_relative() {
            self.canonical_root.join(path)
        } else {
            path.to_path_buf()
        };

        // If target exists on disk, canonicalize directly
        if target_path.exists() {
            let canonical = std::fs::canonicalize(&target_path)?;
            if !self.is_contained(&canonical) {
                return Err(JailError::OutsideWorkspace {
                    path: canonical,
                    root: self.canonical_root.clone(),
                });
            }
            return Ok(canonical);
        }

        // Target does not exist: walk up to find deepest existing ancestor
        let mut non_existing_components = Vec::new();
        let mut current = target_path.as_path();

        while !current.exists() {
            if let Some(name) = current.file_name() {
                non_existing_components.push(name.to_os_string());
                if let Some(parent) = current.parent() {
                    current = parent;
                } else {
                    break;
                }
            } else {
                break;
            }
        }

        if !current.exists() {
            return Err(JailError::OutsideWorkspace {
                path: target_path,
                root: self.canonical_root.clone(),
            });
        }

        // Canonicalize existing ancestor
        let canonical_ancestor = std::fs::canonicalize(current)?;
        if !self.is_contained(&canonical_ancestor) {
            return Err(JailError::OutsideWorkspace {
                path: canonical_ancestor,
                root: self.canonical_root.clone(),
            });
        }

        // Verify that none of the non-existing components attempt traversal
        let mut resolved = canonical_ancestor;
        while let Some(comp_os) = non_existing_components.pop() {
            let comp_str = comp_os.to_string_lossy();
            if comp_str == ".." || comp_str == "." {
                return Err(JailError::OutsideWorkspace {
                    path: target_path,
                    root: self.canonical_root.clone(),
                });
            }
            resolved.push(comp_os);
        }

        if !self.is_contained(&resolved) {
            return Err(JailError::OutsideWorkspace {
                path: resolved,
                root: self.canonical_root.clone(),
            });
        }

        Ok(resolved)
    }

    /// Validates an optional working directory for command execution.
    ///
    /// If `None`, returns the canonical root.
    /// If `Some(cwd)`, ensures that `cwd` exists, is a directory, and is within the jail.
    pub fn validate_cwd(&self, cwd: Option<&Path>) -> Result<PathBuf, JailError> {
        match cwd {
            None => Ok(normalize_path_prefix(&self.canonical_root)),
            Some(dir) => {
                let resolved = self.resolve_path(dir)?;
                if !resolved.is_dir() {
                    return Err(JailError::InvalidWorkingDirectory(resolved));
                }
                Ok(normalize_path_prefix(&resolved))
            }
        }
    }
}

/// Helper to strip Windows verbatim prefix (`\\?\`) if present.
fn normalize_path_prefix(path: &Path) -> PathBuf {
    let s = path.to_string_lossy();
    if let Some(stripped) = s.strip_prefix(r"\\?\") {
        PathBuf::from(stripped)
    } else {
        path.to_path_buf()
    }
}

/// Checks whether `target` starts with `base`, accounting for OS-specific nuances.
fn is_path_within(base: &Path, target: &Path) -> bool {
    let base_norm = normalize_path_prefix(base);
    let target_norm = normalize_path_prefix(target);

    #[cfg(windows)]
    {
        // On Windows, compare components case-insensitively
        let base_comps: Vec<_> = base_norm.components().collect();
        let target_comps: Vec<_> = target_norm.components().collect();

        if target_comps.len() < base_comps.len() {
            return false;
        }

        for (b, t) in base_comps.iter().zip(target_comps.iter()) {
            match (b, t) {
                (Component::Prefix(p1), Component::Prefix(p2)) => {
                    if p1.as_os_str().to_string_lossy().to_lowercase()
                        != p2.as_os_str().to_string_lossy().to_lowercase()
                    {
                        return false;
                    }
                }
                (Component::RootDir, Component::RootDir) => {}
                (Component::Normal(n1), Component::Normal(n2)) => {
                    if n1.to_string_lossy().to_lowercase() != n2.to_string_lossy().to_lowercase() {
                        return false;
                    }
                }
                _ => {
                    if b != t {
                        return false;
                    }
                }
            }
        }
        true
    }

    #[cfg(not(windows))]
    {
        target_norm.starts_with(&base_norm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{self, File};

    #[test]
    fn test_jail_root_validation() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_jail_test_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let jail = WorkspaceJail::new(&temp_dir).unwrap();
        assert_eq!(jail.root(), temp_dir.as_path());

        // Non-existent directory
        let non_existent = temp_dir.join("does_not_exist");
        assert!(WorkspaceJail::new(&non_existent).is_err());

        // File instead of directory
        let file_path = temp_dir.join("a_file.txt");
        File::create(&file_path).unwrap();
        assert!(WorkspaceJail::new(&file_path).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_traversal_attacks_prevented() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_jail_traversal_{}", uuid::Uuid::new_v4()));
        let inner = temp_dir.join("workspace");
        fs::create_dir_all(&inner).unwrap();

        let jail = WorkspaceJail::new(&inner).unwrap();

        // Traversal using ..
        assert!(jail.resolve_path("../outside.txt").is_err());
        assert!(jail.resolve_path("../../etc/passwd").is_err());
        assert!(jail.resolve_path(r"..\..\Windows\System32").is_err());

        // Legitimate child path
        let child_file = inner.join("allowed.txt");
        File::create(&child_file).unwrap();
        assert!(jail.resolve_path("allowed.txt").is_ok());
        assert!(jail.resolve_path(&child_file).is_ok());

        // Legitimate non-existent child path
        assert!(jail.resolve_path("new_folder/new_file.rs").is_ok());

        // Non-existent traversal
        assert!(jail.resolve_path("new_folder/../../escape.txt").is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_validate_cwd() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_jail_cwd_{}", uuid::Uuid::new_v4()));
        let sub_dir = temp_dir.join("subdir");
        fs::create_dir_all(&sub_dir).unwrap();

        let jail = WorkspaceJail::new(&temp_dir).unwrap();

        // None defaults to root
        let default_cwd = jail.validate_cwd(None).unwrap();
        assert_eq!(default_cwd, normalize_path_prefix(jail.canonical_root()));

        // Valid sub dir
        let valid_cwd = jail.validate_cwd(Some(&sub_dir)).unwrap();
        assert_eq!(valid_cwd, normalize_path_prefix(&fs::canonicalize(&sub_dir).unwrap()));

        // File as cwd must fail
        let file_path = temp_dir.join("file.txt");
        File::create(&file_path).unwrap();
        assert!(jail.validate_cwd(Some(&file_path)).is_err());

        // Traversal cwd must fail
        assert!(jail.validate_cwd(Some(Path::new(".."))).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_allowed_paths() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_jail_allowed_{}", uuid::Uuid::new_v4()));
        let root = temp_dir.join("root");
        let external = temp_dir.join("external_allowed");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&external).unwrap();

        let jail = WorkspaceJail::with_allowed_paths(&root, vec![external.clone()]).unwrap();

        let ext_file = external.join("ext.txt");
        File::create(&ext_file).unwrap();

        assert!(jail.resolve_path(&ext_file).is_ok());

        // Disallowed external path
        let secret = temp_dir.join("secret");
        fs::create_dir_all(&secret).unwrap();
        let secret_file = secret.join("secret.txt");
        File::create(&secret_file).unwrap();

        assert!(jail.resolve_path(&secret_file).is_err());

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

