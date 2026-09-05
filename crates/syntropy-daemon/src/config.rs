use std::path::{Path, PathBuf};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to read configuration file: {0}")]
    Io(#[from] std::io::Error),
    #[error("Failed to parse TOML configuration: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("Workspace root could not be determined")]
    MissingWorkspaceRoot,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    #[serde(default)]
    pub project: ProjectConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    #[serde(default)]
    pub pty: PtySettings,
    #[serde(default)]
    pub security: SecuritySettings,
    #[serde(default)]
    pub mcp: syntropy_mcp::McpConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectConfig {
    #[serde(default = "default_project_name")]
    pub name: String,
    #[serde(default = "default_version")]
    pub version: String,
    #[serde(default = "default_true")]
    pub root_jail: bool,
    #[serde(default = "default_allowed_paths")]
    pub allowed_paths: Vec<String>,
}

impl Default for ProjectConfig {
    fn default() -> Self {
        Self {
            name: default_project_name(),
            version: default_version(),
            root_jail: true,
            allowed_paths: default_allowed_paths(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default = "default_server_url")]
    pub server_url: String,
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval_secs: u64,
    #[serde(default = "default_reconnect_backoff")]
    pub reconnect_max_backoff_secs: u64,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            server_url: default_server_url(),
            heartbeat_interval_secs: default_heartbeat_interval(),
            reconnect_max_backoff_secs: default_reconnect_backoff(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PtySettings {
    #[serde(default = "default_shell")]
    pub default_shell: String,
    #[serde(default = "default_scrollback")]
    pub max_scrollback_lines: usize,
    #[serde(default = "default_replay_limit")]
    pub buffer_replay_limit: usize,
}

impl Default for PtySettings {
    fn default() -> Self {
        Self {
            default_shell: default_shell(),
            max_scrollback_lines: default_scrollback(),
            buffer_replay_limit: default_replay_limit(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecuritySettings {
    #[serde(default = "default_keystore")]
    pub keystore_provider: String,
    #[serde(default = "default_approval_mode")]
    pub approval_mode: String,
    #[serde(default = "default_true")]
    pub audit_ledger: bool,
    #[serde(default = "default_audit_db")]
    pub audit_db_path: String,
}

impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            keystore_provider: default_keystore(),
            approval_mode: default_approval_mode(),
            audit_ledger: true,
            audit_db_path: default_audit_db(),
        }
    }
}

fn default_project_name() -> String {
    "syntropy".into()
}

fn default_version() -> String {
    "0.1.0".into()
}

fn default_true() -> bool {
    true
}

fn default_allowed_paths() -> Vec<String> {
    vec![".".into()]
}

fn default_server_url() -> String {
    "http://127.0.0.1:50051".into()
}

fn default_heartbeat_interval() -> u64 {
    10
}

fn default_reconnect_backoff() -> u64 {
    30
}

fn default_shell() -> String {
    "default".into()
}

fn default_scrollback() -> usize {
    10000
}

fn default_replay_limit() -> usize {
    500
}

fn default_keystore() -> String {
    "auto".into()
}

fn default_approval_mode() -> String {
    "dual".into()
}

fn default_audit_db() -> String {
    ".syntropy/audit.db".into()
}

impl AppConfig {
    pub fn load_from_dir<P: AsRef<Path>>(dir: P) -> Result<Self, ConfigError> {
        let config_path = dir.as_ref().join(".syntropy.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let config: AppConfig = toml::from_str(&content)?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    pub fn resolve_audit_path<P: AsRef<Path>>(&self, workspace_root: P) -> PathBuf {
        let path = Path::new(&self.security.audit_db_path);
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            workspace_root.as_ref().join(path)
        }
    }
}
