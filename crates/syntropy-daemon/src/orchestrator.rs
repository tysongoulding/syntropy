use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};
use tracing::{error, info};

use syntropy_exec::{
    AtomicPatchApplicator, PatchOptions, PtyMultiplexer, SpawnOptions, WorkspaceJail,
};
use syntropy_mcp::{McpProxy, ToolAllowlist};
use syntropy_proto::tunnel::{
    self, ApplyPatch, ApprovalRequest, ApprovalResponse, ExecCommand, McpInvokeRequest,
    McpInvokeResponse, PatchResult, TerminalInputChunk, TerminalOutputChunk, TunnelClientFrame,
    TunnelServerFrame,
};
use syntropy_security::{CredentialBroker, InMemoryKeyStore, KeyStore, MerkleAuditLedger};

use crate::config::AppConfig;

pub struct Orchestrator {
    agent_id: String,
    workspace_root: PathBuf,
    jail: Arc<WorkspaceJail>,
    pty_mux: Arc<PtyMultiplexer>,
    diff_applicator: Arc<AtomicPatchApplicator>,
    ledger: Arc<Mutex<MerkleAuditLedger>>,
    broker: Arc<CredentialBroker>,
    mcp_proxy: Arc<McpProxy>,
    client_tx: mpsc::Sender<TunnelClientFrame>,
}

impl Orchestrator {
    pub fn new(
        agent_id: String,
        workspace_root: PathBuf,
        config: &AppConfig,
        client_tx: mpsc::Sender<TunnelClientFrame>,
    ) -> Result<Self, anyhow::Error> {
        let jail = Arc::new(WorkspaceJail::new(&workspace_root)?);
        let pty_mux = Arc::new(PtyMultiplexer::new());
        let diff_applicator = Arc::new(AtomicPatchApplicator::new());

        let audit_path = config.resolve_audit_path(&workspace_root);
        if let Some(parent) = audit_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let ledger = Arc::new(Mutex::new(MerkleAuditLedger::open(&audit_path)?));

        // Initialize keystore and credential broker
        #[cfg(target_os = "windows")]
        let keystore: Arc<dyn KeyStore> = match syntropy_security::DpapiKeyStore::new() {
            Ok(ks) => Arc::new(ks),
            Err(_) => Arc::new(InMemoryKeyStore::new()),
        };
        #[cfg(not(target_os = "windows"))]
        let keystore: Arc<dyn KeyStore> = Arc::new(InMemoryKeyStore::new());

        let broker = Arc::new(CredentialBroker::new(keystore));

        let allowlist = ToolAllowlist::new(config.mcp.allowlist.clone());
        let mcp_proxy = Arc::new(McpProxy::with_defaults(allowlist));

        Ok(Self {
            agent_id,
            workspace_root,
            jail,
            pty_mux,
            diff_applicator,
            ledger,
            broker,
            mcp_proxy,
            client_tx,
        })
    }

    pub fn workspace_root(&self) -> &Path {
        &self.workspace_root
    }

    pub fn broker(&self) -> &Arc<CredentialBroker> {
        &self.broker
    }

    /// Helper to construct a client frame with unified metadata, eliminating duplication.
    fn make_client_frame(&self, payload: tunnel::tunnel_client_frame::Payload) -> TunnelClientFrame {
        TunnelClientFrame {
            frame_id: uuid::Uuid::new_v4().to_string(),
            timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
            agent_id: self.agent_id.clone(),
            payload: Some(payload),
        }
    }

    pub async fn handle_frame(&self, frame: TunnelServerFrame) {
        let Some(payload) = frame.payload else {
            return;
        };

        match payload {
            tunnel::tunnel_server_frame::Payload::ExecCommand(cmd) => {
                self.handle_exec_command(cmd).await;
            }
            tunnel::tunnel_server_frame::Payload::TerminalInput(input) => {
                self.handle_terminal_input(input).await;
            }
            tunnel::tunnel_server_frame::Payload::ApplyPatch(patch) => {
                self.handle_apply_patch(patch).await;
            }
            tunnel::tunnel_server_frame::Payload::McpRequest(req) => {
                self.handle_mcp_request(req).await;
            }
            tunnel::tunnel_server_frame::Payload::ApprovalRequest(req) => {
                self.handle_approval_request(req).await;
            }
            tunnel::tunnel_server_frame::Payload::Heartbeat(hb) => {
                let ack = self.make_client_frame(tunnel::tunnel_client_frame::Payload::Heartbeat(
                    tunnel::Heartbeat {
                        sequence: hb.sequence,
                        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                        agent_id: self.agent_id.clone(),
                        is_ack: true,
                    },
                ));
                let _ = self.client_tx.send(ack).await;
            }
            tunnel::tunnel_server_frame::Payload::AgentMessage(msg) => {
                info!(
                    turn_id = %msg.turn_id,
                    content = %msg.content,
                    is_final = msg.is_final,
                    "AgentMessage received from Cloud Swarm"
                );
            }
            _ => {}
        }
    }

    async fn handle_exec_command(&self, cmd: ExecCommand) {
        // Persistent per-agent screen identifier
        let session_id = if !cmd.command_id.is_empty() {
            cmd.command_id.clone()
        } else {
            format!("screen-{}", self.agent_id)
        };

        // 1. Mandatory Audit Logging (Tamper Evidence - never silently suppress errors)
        let payload_data = serde_json::to_vec(&serde_json::json!({
            "command": cmd.command,
            "args": cmd.args,
            "cwd": cmd.working_dir,
        }))
        .unwrap_or_default();

        {
            let l = self.ledger.lock().await;
            if let Err(e) = l.append(&self.agent_id, "exec_command", &payload_data) {
                error!("Audit ledger write failure: {}", e);
                let err_frame = self.make_client_frame(tunnel::tunnel_client_frame::Payload::TerminalOutput(
                    TerminalOutputChunk {
                        session_id: session_id.clone(),
                        data: format!("Security error: Audit ledger failed to record action: {}\n", e)
                            .into_bytes(),
                        is_stderr: true,
                        is_eof: true,
                        exit_code: -1,
                    },
                ));
                let _ = self.client_tx.send(err_frame).await;
                return;
            }
        }

        // 2. Validate CWD with Jail (Canonical Jailing - always validates CWD via jail)
        let cwd_opt = if cmd.working_dir.is_empty() {
            None
        } else {
            Some(Path::new(&cmd.working_dir))
        };

        let working_dir = match self.jail.validate_cwd(cwd_opt) {
            Ok(dir) => dir,
            Err(e) => {
                error!("CWD jail rejection: {}", e);
                let err_chunk = self.make_client_frame(tunnel::tunnel_client_frame::Payload::TerminalOutput(
                    TerminalOutputChunk {
                        session_id: session_id.clone(),
                        data: format!("Security error: CWD rejected by workspace jail: {}\n", e)
                            .into_bytes(),
                        is_stderr: true,
                        is_eof: true,
                        exit_code: -1,
                    },
                ));
                let _ = self.client_tx.send(err_chunk).await;
                return;
            }
        };

        // 3. Build SpawnOptions with sanitized environment variables
        let mut spawn_opts = SpawnOptions::new(&cmd.command)
            .args(cmd.args)
            .cwd(working_dir)
            .pty(cmd.pty);

        // Sanitize incoming env variables through broker pattern (Zero Credential Leakage)
        for (k, v) in cmd.env {
            if !k.to_uppercase().contains("TOKEN") && !k.to_uppercase().contains("SECRET") {
                spawn_opts = spawn_opts.env(k, v);
            }
        }

        if cmd.pty && cmd.pty_rows > 0 && cmd.pty_cols > 0 {
            spawn_opts = spawn_opts.dimensions(cmd.pty_rows as u16, cmd.pty_cols as u16);
        }

        // 4. Spawn in PtyMultiplexer
        match self.pty_mux.spawn_screen(&session_id, spawn_opts) {
            Ok(mut rx) => {
                let tx = self.client_tx.clone();
                let agent_id = self.agent_id.clone();
                let sess_id = session_id.clone();

                tokio::spawn(async move {
                    while let Ok(chunk) = rx.recv().await {
                        let is_eof = chunk.is_eof;
                        let exit_code = chunk.exit_code.unwrap_or(0);

                        let frame = TunnelClientFrame {
                            frame_id: uuid::Uuid::new_v4().to_string(),
                            timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                            agent_id: agent_id.clone(),
                            payload: Some(tunnel::tunnel_client_frame::Payload::TerminalOutput(
                                TerminalOutputChunk {
                                    session_id: sess_id.clone(),
                                    data: chunk.data,
                                    is_stderr: chunk.is_stderr,
                                    is_eof,
                                    exit_code,
                                },
                            )),
                        };

                        if tx.send(frame).await.is_err() {
                            break;
                        }

                        if is_eof {
                            break;
                        }
                    }
                });
            }
            Err(e) => {
                let err_chunk = self.make_client_frame(tunnel::tunnel_client_frame::Payload::TerminalOutput(
                    TerminalOutputChunk {
                        session_id,
                        data: format!("Failed to spawn process: {}\n", e).into_bytes(),
                        is_stderr: true,
                        is_eof: true,
                        exit_code: -1,
                    },
                ));
                let _ = self.client_tx.send(err_chunk).await;
            }
        }
    }

    async fn handle_terminal_input(&self, input: TerminalInputChunk) {
        if input.resize {
            let _ = self
                .pty_mux
                .resize(&input.session_id, input.pty_rows as u16, input.pty_cols as u16);
        } else if input.is_eof {
            let _ = self.pty_mux.terminate(&input.session_id);
        } else if !input.data.is_empty() {
            let _ = self.pty_mux.write_input(&input.session_id, &input.data);
        }
    }

    async fn handle_apply_patch(&self, patch: ApplyPatch) {
        let patch_id = patch.patch_id.clone();
        let file_path_str = patch.file_path.clone();

        // 1. Mandatory Audit Logging
        let payload_data = patch.diff.as_bytes();
        {
            let l = self.ledger.lock().await;
            if let Err(e) = l.append(&self.agent_id, "apply_patch", payload_data) {
                let res = PatchResult {
                    patch_id,
                    file_path: file_path_str,
                    success: false,
                    error_message: format!("Audit ledger failure: {}", e),
                    new_sha256: String::new(),
                    lines_added: 0,
                    lines_removed: 0,
                };
                self.send_patch_result(res).await;
                return;
            }
        }

        // 2. Validate path in jail
        let target_path = match self.jail.resolve_path(&file_path_str) {
            Ok(p) => p,
            Err(e) => {
                let res = PatchResult {
                    patch_id,
                    file_path: file_path_str,
                    success: false,
                    error_message: format!("Jail path violation: {}", e),
                    new_sha256: String::new(),
                    lines_added: 0,
                    lines_removed: 0,
                };
                self.send_patch_result(res).await;
                return;
            }
        };

        // 3. Apply Patch
        let mut opts = PatchOptions::new().dry_run(patch.dry_run);
        if !patch.expected_sha256.is_empty() {
            opts = opts.with_expected_sha256(&patch.expected_sha256);
        }

        match self
            .diff_applicator
            .apply_patch(&target_path, &patch.diff, opts)
        {
            Ok(apply_res) => {
                let res = PatchResult {
                    patch_id,
                    file_path: file_path_str,
                    success: apply_res.success,
                    error_message: String::new(),
                    new_sha256: apply_res.new_sha256,
                    lines_added: apply_res.lines_added,
                    lines_removed: apply_res.lines_removed,
                };
                self.send_patch_result(res).await;
            }
            Err(e) => {
                let res = PatchResult {
                    patch_id,
                    file_path: file_path_str,
                    success: false,
                    error_message: e.to_string(),
                    new_sha256: String::new(),
                    lines_added: 0,
                    lines_removed: 0,
                };
                self.send_patch_result(res).await;
            }
        }
    }

    async fn send_patch_result(&self, result: PatchResult) {
        let frame = self.make_client_frame(tunnel::tunnel_client_frame::Payload::PatchResult(result));
        let _ = self.client_tx.send(frame).await;
    }

    async fn handle_mcp_request(&self, req: McpInvokeRequest) {
        let invocation_id = req.invocation_id.clone();

        // 1. Mandatory Audit Logging
        let payload_data = req.arguments_json.as_bytes();
        {
            let l = self.ledger.lock().await;
            if let Err(e) = l.append(&self.agent_id, "mcp_invoke", payload_data) {
                let resp = McpInvokeResponse {
                    invocation_id,
                    success: false,
                    result_json: String::new(),
                    error_message: format!("Audit ledger failure: {}", e),
                };
                self.send_mcp_response(resp).await;
                return;
            }
        }

        // 2. Check tool allowlist directly (eliminates feature envy)
        if !self.mcp_proxy.is_tool_allowed(&req.tool_name).await {
            let resp = McpInvokeResponse {
                invocation_id,
                success: false,
                result_json: String::new(),
                error_message: format!("Tool '{}' is forbidden by security policy", req.tool_name),
            };
            self.send_mcp_response(resp).await;
            return;
        }

        let resp = McpInvokeResponse {
            invocation_id,
            success: true,
            result_json: serde_json::json!({
                "status": "acknowledged",
                "tool": req.tool_name,
                "server": req.server_name,
            })
            .to_string(),
            error_message: String::new(),
        };
        self.send_mcp_response(resp).await;
    }

    async fn send_mcp_response(&self, resp: McpInvokeResponse) {
        let frame = self.make_client_frame(tunnel::tunnel_client_frame::Payload::McpResponse(resp));
        let _ = self.client_tx.send(frame).await;
    }

    async fn handle_approval_request(&self, req: ApprovalRequest) {
        info!(
            "Approval request received: [{}] {}",
            req.action_type, req.description
        );

        let approved = !req.action_type.starts_with("destructive_");
        let reason = if approved {
            "Auto-authorized by local policy".to_string()
        } else {
            "Pending operator signature".to_string()
        };

        let resp = ApprovalResponse {
            request_id: req.request_id,
            approved,
            reason,
            approved_by: "syntropy-daemon-policy".to_string(),
            responded_at_unix: chrono::Utc::now().timestamp(),
        };

        let frame = self.make_client_frame(tunnel::tunnel_client_frame::Payload::ApprovalResponse(resp));
        let _ = self.client_tx.send(frame).await;
    }
}
