//! `syntropy-exec`
//!
//! Sandboxed execution engine for Syntropy agents.
//! Provides boundary containment (`WorkspaceJail`), cross-platform PTY multiplexing
//! (`PtyMultiplexer`), atomic patch application (`AtomicPatchApplicator`), and
//! ephemeral Git worktree management (`WorktreeManager`).

pub mod diff;
pub mod jail;
pub mod pty_mux;
pub mod worktree;

pub use diff::{
    compute_sha256, AtomicPatchApplicator, DiffError, LineReplacement, PatchApplyResult,
    PatchOptions,
};
pub use jail::{JailError, WorkspaceJail};
pub use pty_mux::{
    OutputChunk, PtyError, PtyMultiplexer, RingBuffer, ScreenInfo, ScreenStatus, SpawnOptions,
};
pub use worktree::{WorktreeError, WorktreeInfo, WorktreeManager};

#[cfg(test)]
mod integration_tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_jail_containment_and_traversal_attacks() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_jail_integ_{}", uuid::Uuid::new_v4()));
        let workspace = temp_dir.join("project_root");
        fs::create_dir_all(&workspace).unwrap();

        let jail = WorkspaceJail::new(&workspace).expect("Jail creation failed");

        // 1. Valid paths inside root
        let valid_file = workspace.join("src").join("main.rs");
        fs::create_dir_all(workspace.join("src")).unwrap();
        fs::write(&valid_file, "fn main() {}").unwrap();

        assert!(jail.is_contained(&valid_file));
        let resolved = jail.resolve_path("src/main.rs").unwrap();
        assert_eq!(resolved, fs::canonicalize(&valid_file).unwrap());

        // 2. Directory traversal attacks must be rejected
        let traversal_attempts = vec![
            "../secret.key",
            "../../Windows/System32",
            "../../../etc/shadow",
            "src/../../outside.txt",
            r"..\..\..\..\AppData",
        ];

        for attack in traversal_attempts {
            let res = jail.resolve_path(attack);
            assert!(
                res.is_err(),
                "Path traversal '{attack}' should have been blocked, but succeeded: {:?}",
                res
            );
        }

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_atomic_patch_replacement_guarantee() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_patch_integ_{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();

        let file_path = temp_dir.join("config.toml");
        let initial_content = "[daemon]\nenabled = false\nport = 8080\n";
        fs::write(&file_path, initial_content).unwrap();

        let sha_before = compute_sha256(initial_content.as_bytes());

        let applicator = AtomicPatchApplicator::new();
        let patch = r#"@@ -1,3 +1,3 @@
 [daemon]
-enabled = false
+enabled = true
 port = 8080
"#;

        let opts = PatchOptions::new().with_expected_sha256(&sha_before);
        let result = applicator
            .apply_patch(&file_path, patch, opts)
            .expect("Patch application failed");

        assert!(result.success);
        assert_eq!(result.lines_added, 1);
        assert_eq!(result.lines_removed, 1);

        let final_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(final_content, "[daemon]\nenabled = true\nport = 8080\n");
        assert_eq!(compute_sha256(final_content.as_bytes()), result.new_sha256);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[tokio::test]
    async fn test_pty_screen_io_lifecycle() {
        let mux = PtyMultiplexer::new();
        let screen_id = format!("integ-screen-{}", uuid::Uuid::new_v4());

        #[cfg(windows)]
        let opts = SpawnOptions::new("cmd.exe").args(["/c", "echo hello_syntropy_pty"]);
        #[cfg(not(windows))]
        let opts = SpawnOptions::new("echo").arg("hello_syntropy_pty");

        let mut rx = mux.spawn_screen(&screen_id, opts).unwrap();

        let mut collected = Vec::new();
        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(chunk) => {
                            collected.extend_from_slice(&chunk.data);
                            if chunk.is_eof {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => {
                    break;
                }
            }
        }

        let output = String::from_utf8_lossy(&collected);
        assert!(output.contains("hello_syntropy_pty"));

        let history = mux.get_history(&screen_id).unwrap();
        assert!(String::from_utf8_lossy(&history).contains("hello_syntropy_pty"));

        assert!(mux.cleanup_screen(&screen_id).is_ok());
    }
}
