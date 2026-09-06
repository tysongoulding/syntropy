//! Ephemeral Git worktree management for isolated agent execution.
//!
//! Allocates isolated worktree environments under `.syntropy/worktrees/<agent_id>`
//! branched from a specified commit or branch, and tears them down safely.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;

/// Errors returned by the worktree manager.
#[derive(Debug, Error)]
pub enum WorktreeError {
    #[error("Git repository root does not exist or is not a valid git repository: {0}")]
    RepoNotFound(PathBuf),

    #[error("Invalid agent ID '{0}': must be non-empty and contain only alphanumeric, '-', '_', '.' without traversal")]
    InvalidAgentId(String),

    #[error("Worktree for agent '{0}' already exists at '{1}'")]
    WorktreeAlreadyExists(String, PathBuf),

    #[error("Worktree for agent '{0}' not found at '{1}'")]
    WorktreeNotFound(String, PathBuf),

    #[error("Git command '{cmd}' failed (exit code: {exit_code:?}): {message}")]
    GitFailed {
        cmd: String,
        exit_code: Option<i32>,
        message: String,
    },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Metadata about an active agent worktree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorktreeInfo {
    pub agent_id: String,
    pub path: PathBuf,
    pub branch: String,
    pub head_commit: Option<String>,
}

/// Manages ephemeral Git worktrees for agent isolation.
#[derive(Debug, Clone)]
pub struct WorktreeManager {
    repo_root: PathBuf,
    worktrees_base: PathBuf,
}

impl WorktreeManager {
    /// Creates a new `WorktreeManager` for the specified repository root.
    pub fn new(repo_root: impl AsRef<Path>) -> Result<Self, WorktreeError> {
        let repo_root = repo_root.as_ref().to_path_buf();
        if !repo_root.exists() {
            return Err(WorktreeError::RepoNotFound(repo_root));
        }

        let git_dir = repo_root.join(".git");
        if !git_dir.exists() {
            return Err(WorktreeError::RepoNotFound(repo_root));
        }

        let worktrees_base = repo_root.join(".syntropy").join("worktrees");

        Ok(Self {
            repo_root,
            worktrees_base,
        })
    }

    /// Returns the root of the parent git repository.
    pub fn repo_root(&self) -> &Path {
        &self.repo_root
    }

    /// Returns the base directory where agent worktrees are hosted.
    pub fn worktrees_base(&self) -> &Path {
        &self.worktrees_base
    }

    /// Computes the path for an agent's worktree, verifying safety of the agent ID.
    pub fn worktree_path(&self, agent_id: &str) -> Result<PathBuf, WorktreeError> {
        validate_agent_id(agent_id)?;
        Ok(self.worktrees_base.join(agent_id))
    }

    /// Checks if a worktree already exists on disk for the specified agent.
    pub fn exists(&self, agent_id: &str) -> bool {
        if let Ok(path) = self.worktree_path(agent_id) {
            path.exists()
        } else {
            false
        }
    }

    /// Creates an ephemeral worktree for the given `agent_id` branched from `base_branch`.
    ///
    /// The worktree is created at `.syntropy/worktrees/<agent_id>` with branch
    /// `syntropy/worktree-<agent_id>`.
    pub fn create_worktree(
        &self,
        agent_id: &str,
        base_branch: &str,
    ) -> Result<PathBuf, WorktreeError> {
        validate_agent_id(agent_id)?;
        let path = self.worktree_path(agent_id)?;

        if path.exists() {
            return Err(WorktreeError::WorktreeAlreadyExists(
                agent_id.to_string(),
                path,
            ));
        }

        std::fs::create_dir_all(&self.worktrees_base)?;

        let branch_name = format!("syntropy/worktree-{}", agent_id);
        let base = if base_branch.trim().is_empty() {
            "HEAD"
        } else {
            base_branch.trim()
        };

        // git worktree add -B <branch_name> <path> <base>
        let cmd_str = format!("git worktree add -B {branch_name} {:?} {base}", path);
        let output = Command::new("git")
            .current_dir(&self.repo_root)
            .args([
                "worktree",
                "add",
                "-B",
                &branch_name,
                path.to_str().unwrap_or_default(),
                base,
            ])
            .output()
            .map_err(|e| WorktreeError::GitFailed {
                cmd: cmd_str.clone(),
                exit_code: None,
                message: e.to_string(),
            })?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let msg = if !stderr.trim().is_empty() {
                stderr
            } else {
                stdout
            };
            return Err(WorktreeError::GitFailed {
                cmd: cmd_str,
                exit_code: output.status.code(),
                message: msg.trim().to_string(),
            });
        }

        Ok(path)
    }

    /// Cleans up and deletes the ephemeral worktree for the specified `agent_id`.
    ///
    /// Removes the worktree via `git worktree remove --force`, prunes worktree
    /// references, deletes the local branch, and removes remaining artifacts.
    pub fn cleanup_worktree(&self, agent_id: &str) -> Result<(), WorktreeError> {
        validate_agent_id(agent_id)?;
        let path = self.worktree_path(agent_id)?;

        let branch_name = format!("syntropy/worktree-{}", agent_id);

        // Run git worktree remove --force <path>
        if path.exists() {
            let _ = Command::new("git")
                .current_dir(&self.repo_root)
                .args(["worktree", "remove", "--force", path.to_str().unwrap_or_default()])
                .output();
        }

        // Run git worktree prune
        let _ = Command::new("git")
            .current_dir(&self.repo_root)
            .args(["worktree", "prune"])
            .output();

        // Delete the created worktree branch
        let _ = Command::new("git")
            .current_dir(&self.repo_root)
            .args(["branch", "-D", &branch_name])
            .output();

        // Fallback: delete directory if still present
        if path.exists() {
            let _ = std::fs::remove_dir_all(&path);
        }

        Ok(())
    }

    /// Lists active worktrees managed under `.syntropy/worktrees`.
    pub fn list_worktrees(&self) -> Result<Vec<WorktreeInfo>, WorktreeError> {
        if !self.worktrees_base.exists() {
            return Ok(Vec::new());
        }

        let mut worktrees = Vec::new();
        let entries = std::fs::read_dir(&self.worktrees_base)?;

        for entry in entries.flatten() {
            if entry.path().is_dir() {
                let name = entry.file_name().to_string_lossy().to_string();
                let branch = format!("syntropy/worktree-{}", name);
                worktrees.push(WorktreeInfo {
                    agent_id: name,
                    path: entry.path(),
                    branch,
                    head_commit: None,
                });
            }
        }

        Ok(worktrees)
    }

    /// Cleans up all managed worktrees under `.syntropy/worktrees`.
    pub fn cleanup_all(&self) -> Result<(), WorktreeError> {
        let list = self.list_worktrees()?;
        for wt in list {
            let _ = self.cleanup_worktree(&wt.agent_id);
        }
        if self.worktrees_base.exists() {
            let _ = std::fs::remove_dir_all(&self.worktrees_base);
        }
        Ok(())
    }

    /// Verifies whether the agent store mount or remote backing directory is active and operational.
    ///
    /// Checks:
    /// 1. Worktree-local `.agent-store/.mounted` sentinel.
    /// 2. Environment variable `AGENT_STORE_MOUNT` override path sentinel.
    /// 3. System-wide `/agent-store/.mounted` sentinel or `/agent-store/<agent_id>` directory.
    pub fn verify_mount_backing(&self, agent_id: &str) -> Result<bool, WorktreeError> {
        validate_agent_id(agent_id)?;
        let wt_path = self.worktree_path(agent_id)?;

        // 1. Check if agent-store mount exists within worktree
        let local_sentinel = wt_path.join(".agent-store").join(".mounted");
        if local_sentinel.exists() {
            return Ok(true);
        }

        // 2. Check environment override AGENT_STORE_MOUNT
        if let Ok(env_mount) = std::env::var("AGENT_STORE_MOUNT") {
            let env_path = PathBuf::from(env_mount);
            if env_path.join(".mounted").exists() || env_path.join(agent_id).exists() {
                return Ok(true);
            }
        }

        // 3. Check system-level /agent-store mount
        let sys_mount = Path::new("/agent-store");
        if sys_mount.exists()
            && (sys_mount.join(".mounted").exists() || sys_mount.join(agent_id).exists())
        {
            return Ok(true);
        }

        Ok(false)
    }

    /// Links or associates an agent-store backing directory to the agent's worktree.
    pub fn link_agent_store(
        &self,
        agent_id: &str,
        store_path: impl AsRef<Path>,
    ) -> Result<PathBuf, WorktreeError> {
        validate_agent_id(agent_id)?;
        let wt_path = self.worktree_path(agent_id)?;
        let target = wt_path.join(".agent-store");
        let store_path = store_path.as_ref();

        if !store_path.exists() {
            return Err(WorktreeError::Io(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                format!("Backing store path does not exist: {}", store_path.display()),
            )));
        }

        std::fs::create_dir_all(&target)?;
        let sentinel = target.join(".mounted");
        std::fs::write(&sentinel, format!("linked_to={}\n", store_path.display()))?;

        Ok(target)
    }
}

/// Validates that an agent ID is safe for path traversal and filesystem use.
fn validate_agent_id(agent_id: &str) -> Result<(), WorktreeError> {
    let trimmed = agent_id.trim();
    if trimmed.is_empty() {
        return Err(WorktreeError::InvalidAgentId(agent_id.to_string()));
    }

    if trimmed.contains('/') || trimmed.contains('\\') || trimmed.contains("..") {
        return Err(WorktreeError::InvalidAgentId(agent_id.to_string()));
    }

    let is_valid_char = |c: char| c.is_alphanumeric() || c == '-' || c == '_' || c == '.';
    if !trimmed.chars().all(is_valid_char) {
        return Err(WorktreeError::InvalidAgentId(agent_id.to_string()));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_agent_id_validation() {
        assert!(validate_agent_id("agent-123").is_ok());
        assert!(validate_agent_id("uuid_550e8400-e29b-41d4-a716-446655440000").is_ok());
        assert!(validate_agent_id("agent.test_01").is_ok());

        // Attacks and invalid IDs
        assert!(validate_agent_id("../escape").is_err());
        assert!(validate_agent_id("sub/dir").is_err());
        assert!(validate_agent_id(r"sub\dir").is_err());
        assert!(validate_agent_id("").is_err());
        assert!(validate_agent_id("   ").is_err());
        assert!(validate_agent_id("agent;rm -rf /").is_err());
    }

    #[test]
    fn test_worktree_lifecycle_with_git() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_wt_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        // Initialize git repo
        let init = Command::new("git")
            .current_dir(&temp_dir)
            .args(["init"])
            .output();

        if let Ok(out) = init {
            if out.status.success() {
                // Configure user and email for commit
                let _ = Command::new("git")
                    .current_dir(&temp_dir)
                    .args(["config", "user.name", "Syntropy Test"])
                    .output();
                let _ = Command::new("git")
                    .current_dir(&temp_dir)
                    .args(["config", "user.email", "test@syntropy.dev"])
                    .output();

                // Initial commit
                let file_path = temp_dir.join("README.md");
                std::fs::write(&file_path, "# Syntropy Git Test").unwrap();
                let _ = Command::new("git")
                    .current_dir(&temp_dir)
                    .args(["add", "."])
                    .output();
                let commit = Command::new("git")
                    .current_dir(&temp_dir)
                    .args(["commit", "-m", "Initial commit"])
                    .output();

                if let Ok(c_out) = commit {
                    if c_out.status.success() {
                        let manager = WorktreeManager::new(&temp_dir).unwrap();
                        let agent_id = "test-agent-01";

                        // Create worktree
                        let wt_path = manager.create_worktree(agent_id, "HEAD").unwrap();
                        assert!(wt_path.exists());
                        assert!(manager.exists(agent_id));

                        // Edit file inside worktree
                        let wt_file = wt_path.join("README.md");
                        assert!(wt_file.exists());
                        std::fs::write(&wt_file, "# Modified in worktree").unwrap();

                        // List worktrees
                        let list = manager.list_worktrees().unwrap();
                        assert!(list.iter().any(|w| w.agent_id == agent_id));

                        // Cleanup worktree
                        assert!(manager.cleanup_worktree(agent_id).is_ok());
                        assert!(!manager.exists(agent_id));
                    }
                }
            }
        }

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_verify_mount_backing() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_wt_mount_test_{}", uuid::Uuid::new_v4()));
        let git_dir = temp_dir.join(".git");
        std::fs::create_dir_all(&git_dir).unwrap();

        let manager = WorktreeManager::new(&temp_dir).unwrap();
        let agent_id = "test-agent-fuse";

        // Without mount or link, verify returns false
        assert_eq!(manager.verify_mount_backing(agent_id).unwrap(), false);

        // Link external store directory
        let ext_store = temp_dir.join("remote_store_backing");
        std::fs::create_dir_all(&ext_store).unwrap();
        let linked = manager.link_agent_store(agent_id, &ext_store).unwrap();
        assert!(linked.exists());

        // Now verify_mount_backing should return true due to sentinel
        assert_eq!(manager.verify_mount_backing(agent_id).unwrap(), true);

        // Test invalid agent ID rejection
        assert!(manager.verify_mount_backing("../escape").is_err());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
