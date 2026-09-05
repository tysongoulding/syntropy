use std::collections::HashMap;
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{mpsc, oneshot, RwLock};

use crate::protocol::{JsonRpcRequest, JsonRpcResponse};

fn default_true() -> bool {
    true
}

fn default_max_restart_attempts() -> u32 {
    3
}

fn default_restart_backoff_ms() -> u64 {
    500
}

#[derive(Error, Debug)]
pub enum McpError {
    #[error("Child process spawn failed: {0}")]
    ProcessSpawnFailed(String),

    #[error("Child process exited: {0}")]
    ProcessExited(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Request timed out: {0}")]
    Timeout(String),

    #[error("Circuit breaker is open: {0}")]
    CircuitBreakerOpen(String),

    #[error("Tool '{0}' is forbidden by allowlist")]
    ToolForbidden(String),

    #[error("Channel closed")]
    ChannelClosed,

    #[error("Supervisor terminated")]
    SupervisorTerminated,

    #[error("Invalid request: {0}")]
    InvalidRequest(String),

    #[error("Other error: {0}")]
    Other(String),
}

/// Configuration for an external MCP server child process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct McpServerConfig {
    pub name: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub auto_restart: bool,
    #[serde(default = "default_max_restart_attempts")]
    pub max_restart_attempts: u32,
    #[serde(default = "default_restart_backoff_ms")]
    pub restart_backoff_ms: u64,
}

impl McpServerConfig {
    pub fn new(name: impl Into<String>, command: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            command: command.into(),
            args: Vec::new(),
            env: HashMap::new(),
            cwd: None,
            auto_restart: true,
            max_restart_attempts: 3,
            restart_backoff_ms: 500,
        }
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    pub fn with_env(mut self, env: HashMap<String, String>) -> Self {
        self.env = env;
        self
    }

    pub fn with_auto_restart(mut self, auto_restart: bool, max_attempts: u32, backoff_ms: u64) -> Self {
        self.auto_restart = auto_restart;
        self.max_restart_attempts = max_attempts;
        self.restart_backoff_ms = backoff_ms;
        self
    }
}

type PendingMap = Arc<Mutex<HashMap<String, oneshot::Sender<Result<JsonRpcResponse, McpError>>>>>;

struct SupervisorInner {
    config: McpServerConfig,
    stdin_tx: RwLock<Option<mpsc::Sender<String>>>,
    pending: PendingMap,
    is_alive: AtomicBool,
    restart_count: AtomicU32,
    shutdown_requested: AtomicBool,
}

/// McpSupervisor manages the lifecycle of an external child MCP server process
/// communicating over stdio (using tokio::process::Command).
#[derive(Clone)]
pub struct McpSupervisor {
    inner: Arc<SupervisorInner>,
}

impl std::fmt::Debug for McpSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("McpSupervisor")
            .field("name", &self.inner.config.name)
            .field("is_alive", &self.is_alive())
            .field("restart_count", &self.restart_count())
            .finish()
    }
}

impl McpSupervisor {
    /// Start supervising an external MCP process according to the given configuration.
    pub async fn start(config: McpServerConfig) -> Result<Self, McpError> {
        let inner = Arc::new(SupervisorInner {
            config: config.clone(),
            stdin_tx: RwLock::new(None),
            pending: Arc::new(Mutex::new(HashMap::new())),
            is_alive: AtomicBool::new(false),
            restart_count: AtomicU32::new(0),
            shutdown_requested: AtomicBool::new(false),
        });

        let supervisor = Self { inner };
        let (ready_tx, ready_rx) = oneshot::channel();
        supervisor.run_loop(ready_tx);

        match ready_rx.await {
            Ok(Ok(())) => Ok(supervisor),
            Ok(Err(e)) => Err(e),
            Err(_) => Err(McpError::ProcessSpawnFailed("Supervisor task dropped before initialization".into())),
        }
    }

    /// Check whether the child MCP server process is currently running.
    pub fn is_alive(&self) -> bool {
        self.inner.is_alive.load(Ordering::SeqCst)
    }

    /// Returns the number of times the child process has been restarted.
    pub fn restart_count(&self) -> u32 {
        self.inner.restart_count.load(Ordering::SeqCst)
    }

    /// Send a JSON-RPC request to the child MCP server over stdin and wait for the matching response.
    pub async fn send_request(&self, mut request: JsonRpcRequest) -> Result<JsonRpcResponse, McpError> {
        if self.inner.shutdown_requested.load(Ordering::SeqCst) {
            return Err(McpError::SupervisorTerminated);
        }

        if !self.is_alive() {
            return Err(McpError::ProcessExited("Child MCP process is not running".into()));
        }

        // Ensure request has a valid id
        let id_val = request.id.clone().unwrap_or_else(|| {
            serde_json::json!(uuid::Uuid::new_v4().to_string())
        });
        request.id = Some(id_val.clone());
        let id_key = id_val.to_string();

        let (resp_tx, resp_rx) = oneshot::channel();
        {
            let mut pending = self.inner.pending.lock().map_err(|_| McpError::Other("Pending lock poisoned".into()))?;
            pending.insert(id_key.clone(), resp_tx);
        }

        let payload = match serde_json::to_string(&request) {
            Ok(s) => s + "\n",
            Err(e) => {
                let mut pending = self.inner.pending.lock().map_err(|_| McpError::Other("Pending lock poisoned".into()))?;
                pending.remove(&id_key);
                return Err(McpError::Serialization(e));
            }
        };

        let stdin_opt = self.inner.stdin_tx.read().await.clone();
        if let Some(stdin_tx) = stdin_opt {
            if stdin_tx.send(payload).await.is_err() {
                let mut pending = self.inner.pending.lock().map_err(|_| McpError::Other("Pending lock poisoned".into()))?;
                pending.remove(&id_key);
                return Err(McpError::ChannelClosed);
            }
        } else {
            let mut pending = self.inner.pending.lock().map_err(|_| McpError::Other("Pending lock poisoned".into()))?;
            pending.remove(&id_key);
            return Err(McpError::ProcessExited("Stdin channel unavailable".into()));
        }

        match resp_rx.await {
            Ok(res) => res,
            Err(_) => Err(McpError::ProcessExited("Response channel closed before receiving message".into())),
        }
    }

    /// Stop the supervisor and terminate the child process.
    pub async fn stop(&self) -> Result<(), McpError> {
        self.inner.shutdown_requested.store(true, Ordering::SeqCst);
        self.inner.is_alive.store(false, Ordering::SeqCst);

        // Close stdin channel
        {
            let mut guard = self.inner.stdin_tx.write().await;
            *guard = None;
        }

        // Drain pending requests
        let mut pending = self.inner.pending.lock().map_err(|_| McpError::Other("Pending lock poisoned".into()))?;
        for (_, sender) in pending.drain() {
            let _ = sender.send(Err(McpError::SupervisorTerminated));
        }

        Ok(())
    }

    fn spawn_process(&self, config: &McpServerConfig) -> Result<Child, McpError> {
        let mut cmd = Command::new(&config.command);
        cmd.args(&config.args)
            .envs(&config.env)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        if let Some(ref cwd) = config.cwd {
            cmd.current_dir(cwd);
        }

        cmd.spawn().map_err(|e| {
            McpError::ProcessSpawnFailed(format!("Failed to spawn '{}': {}", config.command, e))
        })
    }

    fn run_loop(&self, initial_ready: oneshot::Sender<Result<(), McpError>>) {
        let this = self.clone();

        tokio::spawn(async move {
            let mut initial_ready = Some(initial_ready);

            while !this.inner.shutdown_requested.load(Ordering::SeqCst) {
                let mut child = match this.spawn_process(&this.inner.config) {
                    Ok(c) => {
                        if let Some(ready) = initial_ready.take() {
                            let _ = ready.send(Ok(()));
                        }
                        c
                    }
                    Err(e) => {
                        if let Some(ready) = initial_ready.take() {
                            let _ = ready.send(Err(e));
                        }
                        break;
                    }
                };

                let stdin = match child.stdin.take() {
                    Some(s) => s,
                    None => break,
                };
                let stdout = match child.stdout.take() {
                    Some(s) => s,
                    None => break,
                };
                let stderr = match child.stderr.take() {
                    Some(s) => s,
                    None => break,
                };

                let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(128);
                {
                    let mut guard = this.inner.stdin_tx.write().await;
                    *guard = Some(stdin_tx);
                }
                this.inner.is_alive.store(true, Ordering::SeqCst);

                // Task: Stdin Writer
                let stdin_task = tokio::spawn(async move {
                    let mut writer = stdin;
                    while let Some(msg) = stdin_rx.recv().await {
                        if let Err(e) = writer.write_all(msg.as_bytes()).await {
                            tracing::warn!("Failed writing to child stdin: {e}");
                            break;
                        }
                        if let Err(e) = writer.flush().await {
                            tracing::warn!("Failed flushing child stdin: {e}");
                            break;
                        }
                    }
                });

                // Task: Stdout Reader & JSON-RPC dispatcher
                let pending_clone = this.inner.pending.clone();
                let stdout_task = tokio::spawn(async move {
                    let reader = BufReader::new(stdout);
                    let mut lines = reader.lines();

                    while let Ok(Some(line)) = lines.next_line().await {
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            continue;
                        }

                        if let Ok(response) = serde_json::from_str::<JsonRpcResponse>(trimmed) {
                            if let Some(ref id) = response.id {
                                let key = id.to_string();
                                let sender = {
                                    let mut p = pending_clone.lock().unwrap();
                                    p.remove(&key)
                                };
                                if let Some(sender) = sender {
                                    let _ = sender.send(Ok(response));
                                }
                            }
                        }
                    }

                    // On EOF: drain pending requests with ProcessExited
                    let mut p = pending_clone.lock().unwrap();
                    for (_, sender) in p.drain() {
                        let _ = sender.send(Err(McpError::ProcessExited("Child process stdout closed".into())));
                    }
                });

                // Task: Stderr Reader
                let name = this.inner.config.name.clone();
                let stderr_task = tokio::spawn(async move {
                    let reader = BufReader::new(stderr);
                    let mut lines = reader.lines();
                    while let Ok(Some(line)) = lines.next_line().await {
                        tracing::debug!("[MCP {} stderr] {}", name, line);
                    }
                });

                // Wait for process to exit
                let status = child.wait().await;
                this.inner.is_alive.store(false, Ordering::SeqCst);

                // Mark stdin channel closed
                {
                    let mut guard = this.inner.stdin_tx.write().await;
                    *guard = None;
                }

                // Abort reader/writer tasks
                stdin_task.abort();
                stdout_task.abort();
                stderr_task.abort();

                if this.inner.shutdown_requested.load(Ordering::SeqCst) {
                    break;
                }

                tracing::warn!(
                    "MCP server '{}' exited with status: {:?}",
                    this.inner.config.name,
                    status
                );

                // Auto-restart handling
                if this.inner.config.auto_restart {
                    let current_restarts = this.inner.restart_count.fetch_add(1, Ordering::SeqCst) + 1;
                    if current_restarts <= this.inner.config.max_restart_attempts {
                        tracing::info!(
                            "Restarting MCP server '{}' (attempt {}/{}) after {}ms backoff...",
                            this.inner.config.name,
                            current_restarts,
                            this.inner.config.max_restart_attempts,
                            this.inner.config.restart_backoff_ms
                        );

                        tokio::time::sleep(Duration::from_millis(this.inner.config.restart_backoff_ms)).await;
                    } else {
                        tracing::error!(
                            "MCP server '{}' reached max restart attempts ({})",
                            this.inner.config.name,
                            this.inner.config.max_restart_attempts
                        );
                        break;
                    }
                } else {
                    break;
                }
            }
        });
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_supervisor_spawn_invalid_command() {
        let config = McpServerConfig::new("invalid", "non_existent_binary_12345");
        let result = McpSupervisor::start(config).await;
        assert!(result.is_err());
        match result {
            Err(McpError::ProcessSpawnFailed(_)) => (),
            other => panic!("Expected ProcessSpawnFailed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn test_supervisor_lifecycle_and_restart() {
        // Run a short-lived process that exits immediately to verify restart tracking
        #[cfg(target_os = "windows")]
        let config = McpServerConfig::new("fast-exit", "cmd.exe")
            .with_args(vec!["/C".into(), "exit 0".into()])
            .with_auto_restart(true, 2, 20);

        #[cfg(not(target_os = "windows"))]
        let config = McpServerConfig::new("fast-exit", "sh")
            .with_args(vec!["-c".into(), "exit 0".into()])
            .with_auto_restart(true, 2, 20);

        let supervisor = McpSupervisor::start(config).await.unwrap();

        // Wait enough time for restarts to occur and exhaust
        tokio::time::sleep(Duration::from_millis(150)).await;

        let restarts = supervisor.restart_count();
        assert!(restarts >= 1, "Expected at least 1 restart, got {}", restarts);

        supervisor.stop().await.unwrap();
        assert!(!supervisor.is_alive());
    }

    #[tokio::test]
    async fn test_supervisor_message_passing() {
        // Echo server: reads a line of JSON request from stdin and writes matching JSON response to stdout
        #[cfg(target_os = "windows")]
        let config = McpServerConfig::new("echo-server", "powershell.exe")
            .with_args(vec![
                "-NoProfile".into(),
                "-Command".into(),
                "$input_line = [Console]::In.ReadLine(); [Console]::Out.WriteLine('{\"jsonrpc\":\"2.0\",\"id\":123,\"result\":{\"status\":\"ok\"}}')".into(),
            ])
            .with_auto_restart(false, 0, 0);

        #[cfg(not(target_os = "windows"))]
        let config = McpServerConfig::new("echo-server", "sh")
            .with_args(vec![
                "-c".into(),
                "read line; echo '{\"jsonrpc\":\"2.0\",\"id\":123,\"result\":{\"status\":\"ok\"}}'".into(),
            ])
            .with_auto_restart(false, 0, 0);

        let supervisor = McpSupervisor::start(config).await.unwrap();

        let req = JsonRpcRequest::new(Some(serde_json::json!(123)), "ping", None);
        let resp = supervisor.send_request(req).await.unwrap();

        assert!(resp.is_success());
        assert_eq!(resp.id, Some(serde_json::json!(123)));
        assert_eq!(resp.result.unwrap()["status"], "ok");

        supervisor.stop().await.unwrap();
    }
}
