//! Cross-platform virtual PTY and process multiplexer.
//!
//! Manages multiple concurrent agent screens indexed by `screen_id`, capturing
//! streaming output into broadcast channels and ring buffers, and supporting
//! input writing, terminal resizing, and process termination.

use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;
use tokio::sync::broadcast;

/// Errors returned by the PTY multiplexer.
#[derive(Debug, Error)]
pub enum PtyError {
    #[error("Screen '{0}' already exists")]
    ScreenAlreadyExists(String),

    #[error("Screen '{0}' not found")]
    ScreenNotFound(String),

    #[error("Screen session is closed or terminated")]
    SessionClosed,

    #[error("Operation unsupported: {0}")]
    Unsupported(String),

    #[error("PTY system error: {0}")]
    PtySystem(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Failed to spawn command '{command}': {source}")]
    SpawnFailed {
        command: String,
        #[source]
        source: std::io::Error,
    },
}

/// Execution status of a screen session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ScreenStatus {
    Running,
    Exited(i32),
    Terminated,
    Failed(String),
}

/// A chunk of streaming output emitted by a screen session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputChunk {
    pub session_id: String,
    pub data: Vec<u8>,
    pub is_stderr: bool,
    pub is_eof: bool,
    pub exit_code: Option<i32>,
}

/// Metadata and status for an active or completed screen.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScreenInfo {
    pub screen_id: String,
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub pty: bool,
    pub status: ScreenStatus,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub exit_code: Option<i32>,
    pub rows: u16,
    pub cols: u16,
}

/// Configuration options for spawning a screen.
#[derive(Debug, Clone)]
pub struct SpawnOptions {
    pub command: String,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
    pub pty: bool,
    pub rows: u16,
    pub cols: u16,
    pub buffer_capacity: usize,
}

impl SpawnOptions {
    /// Creates a new `SpawnOptions` with sensible defaults.
    pub fn new(command: impl Into<String>) -> Self {
        Self {
            command: command.into(),
            args: Vec::new(),
            cwd: None,
            env: HashMap::new(),
            pty: true,
            rows: 24,
            cols: 80,
            buffer_capacity: 512 * 1024, // 512 KB
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn arg(mut self, arg: impl Into<String>) -> Self {
        self.args.push(arg.into());
        self
    }

    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn env(mut self, key: impl Into<String>, val: impl Into<String>) -> Self {
        self.env.insert(key.into(), val.into());
        self
    }

    pub fn pty(mut self, pty: bool) -> Self {
        self.pty = pty;
        self
    }

    pub fn dimensions(mut self, rows: u16, cols: u16) -> Self {
        self.rows = rows;
        self.cols = cols;
        self
    }

    pub fn buffer_capacity(mut self, capacity: usize) -> Self {
        self.buffer_capacity = capacity;
        self
    }
}

/// Circular in-memory ring buffer holding recent output bytes for scrollback replay.
#[derive(Debug)]
pub struct RingBuffer {
    capacity: usize,
    buffer: VecDeque<u8>,
}

impl RingBuffer {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            capacity: cap,
            buffer: VecDeque::with_capacity(cap.min(65536)),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        if data.len() >= self.capacity {
            self.buffer.clear();
            self.buffer.extend(&data[data.len() - self.capacity..]);
            return;
        }
        let overflow = (self.buffer.len() + data.len()).saturating_sub(self.capacity);
        if overflow > 0 {
            self.buffer.drain(..overflow);
        }
        self.buffer.extend(data);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        self.buffer.iter().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }
}

/// Internal handle to an active screen session.
struct ScreenSession {
    info: Arc<RwLock<ScreenInfo>>,
    writer: Arc<Mutex<Option<Box<dyn Write + Send>>>>,
    master: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>>,
    pty_child: Arc<Mutex<Option<Box<dyn portable_pty::Child + Send + Sync>>>>,
    std_child: Arc<Mutex<Option<std::process::Child>>>,
    broadcast_tx: broadcast::Sender<OutputChunk>,
    ring_buffer: Arc<RwLock<RingBuffer>>,
}

/// Virtual PTY multiplexer managing concurrent agent screens.
#[derive(Clone)]
pub struct PtyMultiplexer {
    screens: Arc<RwLock<HashMap<String, Arc<ScreenSession>>>>,
}

impl std::fmt::Debug for PtyMultiplexer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.screens.read().map(|s| s.len()).unwrap_or(0);
        f.debug_struct("PtyMultiplexer")
            .field("screens_count", &count)
            .finish()
    }
}

impl Default for PtyMultiplexer {
    fn default() -> Self {
        Self::new()
    }
}

impl PtyMultiplexer {
    /// Creates a new `PtyMultiplexer`.
    pub fn new() -> Self {
        Self {
            screens: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Spawns a new command in a PTY or child process, returning a broadcast receiver
    /// for live output streaming.
    pub fn spawn_screen(
        &self,
        screen_id: impl Into<String>,
        opts: SpawnOptions,
    ) -> Result<broadcast::Receiver<OutputChunk>, PtyError> {
        let screen_id = screen_id.into();

        {
            let screens = self.screens.read().unwrap();
            if screens.contains_key(&screen_id) {
                return Err(PtyError::ScreenAlreadyExists(screen_id));
            }
        }

        let (broadcast_tx, broadcast_rx) = broadcast::channel(1024);
        let ring_buffer = Arc::new(RwLock::new(RingBuffer::new(opts.buffer_capacity)));

        let info = Arc::new(RwLock::new(ScreenInfo {
            screen_id: screen_id.clone(),
            command: opts.command.clone(),
            args: opts.args.clone(),
            cwd: opts.cwd.clone(),
            pty: opts.pty,
            status: ScreenStatus::Running,
            created_at: chrono::Utc::now(),
            exit_code: None,
            rows: opts.rows,
            cols: opts.cols,
        }));

        if opts.pty {
            let pty_system = native_pty_system();
            let pair = pty_system
                .openpty(PtySize {
                    rows: opts.rows,
                    cols: opts.cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| PtyError::PtySystem(e.to_string()))?;

            let mut cmd = CommandBuilder::new(&opts.command);
            cmd.args(&opts.args);
            if let Some(cwd) = &opts.cwd {
                cmd.cwd(cwd);
            }
            for (k, v) in &opts.env {
                cmd.env(k, v);
            }

            let child = pair.slave.spawn_command(cmd).map_err(|e| {
                PtyError::SpawnFailed {
                    command: opts.command.clone(),
                    source: std::io::Error::other(e.to_string()),
                }
            })?;

            drop(pair.slave);

            let writer = pair.master.take_writer().map_err(|e| {
                PtyError::PtySystem(format!("Failed to take PTY writer: {e}"))
            })?;

            let reader = pair.master.try_clone_reader().map_err(|e| {
                PtyError::PtySystem(format!("Failed to clone PTY reader: {e}"))
            })?;

            let master_arc: Arc<Mutex<Option<Box<dyn MasterPty + Send>>>> =
                Arc::new(Mutex::new(Some(pair.master)));
            let writer_arc: Arc<Mutex<Option<Box<dyn Write + Send>>>> =
                Arc::new(Mutex::new(Some(writer)));
            let child_arc = Arc::new(Mutex::new(Some(child)));

            let session = Arc::new(ScreenSession {
                info: info.clone(),
                writer: writer_arc.clone(),
                master: master_arc.clone(),
                pty_child: child_arc.clone(),
                std_child: Arc::new(Mutex::new(None)),
                broadcast_tx: broadcast_tx.clone(),
                ring_buffer: ring_buffer.clone(),
            });

            self.screens
                .write()
                .unwrap()
                .insert(screen_id.clone(), session);

            let tx = broadcast_tx;
            let ring = ring_buffer;
            let sid = screen_id.clone();
            let info_ref = info;
            let child_ref = child_arc;
            let master_ref = master_arc;

            let exit_code_holder = Arc::new(Mutex::new(None));
            let exit_code_for_reader = exit_code_holder.clone();

            // Background waiter thread to monitor process exit and drop master to signal EOF on Windows ConPTY
            let sid_wait = sid.clone();
            let child_wait = child_ref.clone();
            let master_wait = master_ref.clone();
            std::thread::Builder::new()
                .name(format!("pty-wait-{}", sid_wait))
                .spawn(move || {
                    let code = if let Some(mut child) = child_wait.lock().unwrap().take() {
                        match child.wait() {
                            Ok(status) => status.exit_code() as i32,
                            Err(_) => 0,
                        }
                    } else {
                        0
                    };
                    *exit_code_holder.lock().unwrap() = Some(code);

                    // Allow pending output bytes to flush through pseudo console
                    std::thread::sleep(std::time::Duration::from_millis(60));

                    // Dropping master triggers ClosePseudoConsole on Windows, causing reader to receive EOF
                    let _ = master_wait.lock().unwrap().take();
                })
                .map_err(PtyError::Io)?;

            // Reader thread
            std::thread::Builder::new()
                .name(format!("pty-reader-{}", sid))
                .spawn(move || {
                    let mut reader = reader;
                    let mut buf = [0u8; 4096];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let data = buf[..n].to_vec();
                                ring.write().unwrap().write(&data);
                                let chunk = OutputChunk {
                                    session_id: sid.clone(),
                                    data,
                                    is_stderr: false,
                                    is_eof: false,
                                    exit_code: None,
                                };
                                let _ = tx.send(chunk);
                            }
                            Err(_) => break,
                        }
                    }

                    // Retrieve exit code collected by waiter
                    let mut attempts = 0;
                    let exit_code = loop {
                        if let Some(code) = *exit_code_for_reader.lock().unwrap() {
                            break code;
                        }
                        attempts += 1;
                        if attempts > 50 {
                            break 0;
                        }
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    };

                    {
                        let mut inf = info_ref.write().unwrap();
                        inf.status = ScreenStatus::Exited(exit_code);
                        inf.exit_code = Some(exit_code);
                    }

                    let eof = OutputChunk {
                        session_id: sid,
                        data: Vec::new(),
                        is_stderr: false,
                        is_eof: true,
                        exit_code: Some(exit_code),
                    };
                    let _ = tx.send(eof);
                })
                .map_err(PtyError::Io)?;
        } else {
            // Non-PTY child process execution
            let mut cmd = std::process::Command::new(&opts.command);
            cmd.args(&opts.args);
            if let Some(cwd) = &opts.cwd {
                cmd.current_dir(cwd);
            }
            for (k, v) in &opts.env {
                cmd.env(k, v);
            }
            cmd.stdin(std::process::Stdio::piped());
            cmd.stdout(std::process::Stdio::piped());
            cmd.stderr(std::process::Stdio::piped());

            let mut child = cmd.spawn().map_err(|source| PtyError::SpawnFailed {
                command: opts.command.clone(),
                source,
            })?;

            let stdin = child.stdin.take().ok_or_else(|| {
                PtyError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Failed to capture child stdin",
                ))
            })?;
            let stdout = child.stdout.take().ok_or_else(|| {
                PtyError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Failed to capture child stdout",
                ))
            })?;
            let stderr = child.stderr.take().ok_or_else(|| {
                PtyError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "Failed to capture child stderr",
                ))
            })?;

            let writer_arc: Arc<Mutex<Option<Box<dyn Write + Send>>>> =
                Arc::new(Mutex::new(Some(Box::new(stdin))));
            let std_child_arc = Arc::new(Mutex::new(Some(child)));

            let session = Arc::new(ScreenSession {
                info: info.clone(),
                writer: writer_arc,
                master: Arc::new(Mutex::new(None)),
                pty_child: Arc::new(Mutex::new(None)),
                std_child: std_child_arc.clone(),
                broadcast_tx: broadcast_tx.clone(),
                ring_buffer: ring_buffer.clone(),
            });

            self.screens
                .write()
                .unwrap()
                .insert(screen_id.clone(), session);

            // Stdout reader thread
            let tx_out = broadcast_tx.clone();
            let ring_out = ring_buffer.clone();
            let sid_out = screen_id.clone();
            std::thread::Builder::new()
                .name(format!("proc-stdout-{}", screen_id))
                .spawn(move || {
                    let mut reader = stdout;
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = reader.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let data = buf[..n].to_vec();
                        ring_out.write().unwrap().write(&data);
                        let _ = tx_out.send(OutputChunk {
                            session_id: sid_out.clone(),
                            data,
                            is_stderr: false,
                            is_eof: false,
                            exit_code: None,
                        });
                    }
                })
                .map_err(PtyError::Io)?;

            // Stderr reader thread
            let tx_err = broadcast_tx.clone();
            let ring_err = ring_buffer;
            let sid_err = screen_id.clone();
            std::thread::Builder::new()
                .name(format!("proc-stderr-{}", screen_id))
                .spawn(move || {
                    let mut reader = stderr;
                    let mut buf = [0u8; 4096];
                    while let Ok(n) = reader.read(&mut buf) {
                        if n == 0 {
                            break;
                        }
                        let data = buf[..n].to_vec();
                        ring_err.write().unwrap().write(&data);
                        let _ = tx_err.send(OutputChunk {
                            session_id: sid_err.clone(),
                            data,
                            is_stderr: true,
                            is_eof: false,
                            exit_code: None,
                        });
                    }
                })
                .map_err(PtyError::Io)?;

            // Waiter thread
            let tx_final = broadcast_tx;
            let sid_final = screen_id;
            let info_final = info;
            let child_wait_ref = std_child_arc;
            std::thread::Builder::new()
                .name(format!("proc-wait-{}", sid_final))
                .spawn(move || {
                    let exit_code = if let Some(mut child) = child_wait_ref.lock().unwrap().take()
                    {
                        match child.wait() {
                            Ok(s) => s.code().unwrap_or(0),
                            Err(_) => 0,
                        }
                    } else {
                        0
                    };

                    {
                        let mut inf = info_final.write().unwrap();
                        inf.status = ScreenStatus::Exited(exit_code);
                        inf.exit_code = Some(exit_code);
                    }

                    let _ = tx_final.send(OutputChunk {
                        session_id: sid_final,
                        data: Vec::new(),
                        is_stderr: false,
                        is_eof: true,
                        exit_code: Some(exit_code),
                    });
                })
                .map_err(PtyError::Io)?;
        }

        Ok(broadcast_rx)
    }

    /// Writes raw input bytes to a screen session's standard input.
    pub fn write_input(&self, screen_id: &str, data: &[u8]) -> Result<(), PtyError> {
        let session = {
            let screens = self.screens.read().unwrap();
            screens
                .get(screen_id)
                .cloned()
                .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))?
        };

        let mut writer_guard = session.writer.lock().unwrap();
        if let Some(ref mut writer) = *writer_guard {
            writer.write_all(data)?;
            writer.flush()?;
            Ok(())
        } else {
            Err(PtyError::SessionClosed)
        }
    }

    /// Resizes the PTY dimensions for an active screen session.
    pub fn resize(&self, screen_id: &str, rows: u16, cols: u16) -> Result<(), PtyError> {
        let session = {
            let screens = self.screens.read().unwrap();
            screens
                .get(screen_id)
                .cloned()
                .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))?
        };

        let master_guard = session.master.lock().unwrap();
        if let Some(ref master) = *master_guard {
            master
                .resize(PtySize {
                    rows,
                    cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .map_err(|e| PtyError::PtySystem(e.to_string()))?;

            let mut info = session.info.write().unwrap();
            info.rows = rows;
            info.cols = cols;
            Ok(())
        } else {
            Err(PtyError::SessionClosed)
        }
    }

    /// Terminates an active screen session.
    pub fn terminate(&self, screen_id: &str) -> Result<(), PtyError> {
        let session = {
            let screens = self.screens.read().unwrap();
            screens
                .get(screen_id)
                .cloned()
                .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))?
        };

        // Close writer
        session.writer.lock().unwrap().take();

        // Close master to close PTY console
        session.master.lock().unwrap().take();

        // Terminate PTY child
        if let Some(mut child) = session.pty_child.lock().unwrap().take() {
            let _ = child.kill();
        }

        // Terminate std child
        if let Some(mut child) = session.std_child.lock().unwrap().take() {
            let _ = child.kill();
        }

        {
            let mut info = session.info.write().unwrap();
            info.status = ScreenStatus::Terminated;
        }

        Ok(())
    }

    /// Returns a list of snapshots for all registered screens.
    pub fn list_screens(&self) -> Vec<ScreenInfo> {
        let screens = self.screens.read().unwrap();
        screens
            .values()
            .map(|s| s.info.read().unwrap().clone())
            .collect()
    }

    /// Retrieves screen info for a given `screen_id`.
    pub fn get_screen_info(&self, screen_id: &str) -> Option<ScreenInfo> {
        let screens = self.screens.read().unwrap();
        screens.get(screen_id).map(|s| s.info.read().unwrap().clone())
    }

    /// Checks if a screen exists and is still currently running.
    pub fn is_active(&self, screen_id: &str) -> bool {
        let screens = self.screens.read().unwrap();
        if let Some(session) = screens.get(screen_id) {
            session.info.read().unwrap().status == ScreenStatus::Running
        } else {
            false
        }
    }

    /// Subscribes to the broadcast channel of an existing screen.
    pub fn subscribe(&self, screen_id: &str) -> Result<broadcast::Receiver<OutputChunk>, PtyError> {
        let screens = self.screens.read().unwrap();
        let session = screens
            .get(screen_id)
            .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))?;
        Ok(session.broadcast_tx.subscribe())
    }

    /// Retrieves all buffered output bytes stored in the ring buffer for a given screen.
    pub fn get_history(&self, screen_id: &str) -> Result<Vec<u8>, PtyError> {
        let screens = self.screens.read().unwrap();
        let session = screens
            .get(screen_id)
            .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))?;
        let bytes = session.ring_buffer.read().unwrap().to_bytes();
        Ok(bytes)
    }

    /// Cleans up and unregisters a screen session.
    pub fn cleanup_screen(&self, screen_id: &str) -> Result<(), PtyError> {
        let _ = self.terminate(screen_id);
        let mut screens = self.screens.write().unwrap();
        screens
            .remove(screen_id)
            .map(|_| ())
            .ok_or_else(|| PtyError::ScreenNotFound(screen_id.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ring_buffer_eviction() {
        let mut ring = RingBuffer::new(10);
        ring.write(b"12345");
        assert_eq!(ring.to_bytes(), b"12345");
        assert_eq!(ring.len(), 5);

        ring.write(b"67890");
        assert_eq!(ring.to_bytes(), b"1234567890");
        assert_eq!(ring.len(), 10);

        ring.write(b"ABC");
        assert_eq!(ring.to_bytes(), b"4567890ABC");
        assert_eq!(ring.len(), 10);

        // Huge write larger than capacity
        ring.write(b"OVERFLOWINGLARGEPAYLOAD");
        assert_eq!(ring.to_bytes(), b"RGEPAYLOAD");
        assert_eq!(ring.len(), 10);
    }

    #[tokio::test]
    async fn test_pty_screen_lifecycle() {
        let mux = PtyMultiplexer::new();
        let screen_id = format!("test-screen-{}", uuid::Uuid::new_v4());

        #[cfg(windows)]
        let opts = SpawnOptions::new("cmd.exe").args(["/c", "echo hello_syntropy"]);
        #[cfg(not(windows))]
        let opts = SpawnOptions::new("echo").arg("hello_syntropy");

        let mut rx = mux.spawn_screen(&screen_id, opts).unwrap();

        // Verify screen info
        let info = mux.get_screen_info(&screen_id).unwrap();
        assert_eq!(info.screen_id, screen_id);

        // Receive output chunks with timeout
        let mut received = Vec::new();
        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(chunk) => {
                            received.extend_from_slice(&chunk.data);
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

        let output_str = String::from_utf8_lossy(&received);
        assert!(output_str.contains("hello_syntropy"));

        // Wait briefly for exit code update
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        let final_info = mux.get_screen_info(&screen_id).unwrap();
        assert!(matches!(final_info.status, ScreenStatus::Exited(_)));

        // History query
        let history = mux.get_history(&screen_id).unwrap();
        assert!(String::from_utf8_lossy(&history).contains("hello_syntropy"));

        // Cleanup
        assert!(mux.cleanup_screen(&screen_id).is_ok());
        assert!(mux.get_screen_info(&screen_id).is_none());
    }

    #[tokio::test]
    async fn test_screen_termination() {
        let mux = PtyMultiplexer::new();
        let screen_id = format!("test-term-{}", uuid::Uuid::new_v4());

        #[cfg(windows)]
        let opts = SpawnOptions::new("cmd.exe").args(["/c", "pause"]);
        #[cfg(not(windows))]
        let opts = SpawnOptions::new("sleep").arg("60");

        let _rx = mux.spawn_screen(&screen_id, opts).unwrap();
        assert!(mux.is_active(&screen_id));

        assert!(mux.terminate(&screen_id).is_ok());
        let info = mux.get_screen_info(&screen_id).unwrap();
        assert_eq!(info.status, ScreenStatus::Terminated);

        assert!(mux.cleanup_screen(&screen_id).is_ok());
    }

    #[tokio::test]
    async fn test_non_pty_child_process_execution() {
        let mux = PtyMultiplexer::new();
        let screen_id = format!("test-nonpty-{}", uuid::Uuid::new_v4());

        #[cfg(windows)]
        let opts = SpawnOptions::new("cmd.exe")
            .args(["/c", "echo non_pty_output"])
            .pty(false);
        #[cfg(not(windows))]
        let opts = SpawnOptions::new("echo")
            .arg("non_pty_output")
            .pty(false);

        let mut rx = mux.spawn_screen(&screen_id, opts).unwrap();

        let mut output = Vec::new();
        let timeout = tokio::time::sleep(tokio::time::Duration::from_secs(5));
        tokio::pin!(timeout);

        loop {
            tokio::select! {
                res = rx.recv() => {
                    match res {
                        Ok(chunk) => {
                            output.extend_from_slice(&chunk.data);
                            if chunk.is_eof {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                _ = &mut timeout => break,
            }
        }

        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("non_pty_output"));
        assert!(mux.cleanup_screen(&screen_id).is_ok());
    }

    #[tokio::test]
    async fn test_pty_resize() {
        let mux = PtyMultiplexer::new();
        let screen_id = format!("test-resize-{}", uuid::Uuid::new_v4());

        #[cfg(windows)]
        let opts = SpawnOptions::new("cmd.exe").args(["/c", "pause"]);
        #[cfg(not(windows))]
        let opts = SpawnOptions::new("sleep").arg("60");

        let _rx = mux.spawn_screen(&screen_id, opts).unwrap();

        assert!(mux.resize(&screen_id, 40, 120).is_ok());

        let info = mux.get_screen_info(&screen_id).unwrap();
        assert_eq!(info.rows, 40);
        assert_eq!(info.cols, 120);

        assert!(mux.cleanup_screen(&screen_id).is_ok());
    }
}

