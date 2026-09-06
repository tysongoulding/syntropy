use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{error, info, warn};

use syntropy_exec::{AtomicPatchApplicator, PatchOptions, PtyMultiplexer, SpawnOptions, WorkspaceJail};
use syntropy_proto::tunnel::UserPrompt;
use syntropy_security::MerkleAuditLedger;
use syntropy_tunnel::{TunnelClient, TunnelConfig};

const INDEX_HTML: &str = include_str!("../ui/index.html");

#[derive(Debug, Deserialize, Serialize)]
struct ChatRequest {
    text: String,
    #[serde(default)]
    session_id: String,
    #[serde(default)]
    api_key: Option<String>,
    #[serde(default)]
    model: Option<String>,
}

#[derive(Debug, Serialize)]
struct ExecutedTool {
    #[serde(rename = "type")]
    tool_type: String,
    command: String,
    args: Vec<String>,
    output: String,
    file_path: String,
    lines_added: u32,
    lines_removed: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    screenshot_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
}

#[derive(Debug, Serialize)]
struct ChatResponse {
    session_id: String,
    agent_message: String,
    tool_calls: Vec<String>,
    tool_executions: Vec<ExecutedTool>,
    merkle_root: String,
}

#[derive(Debug, Serialize)]
struct AuditEntryView {
    id: i64,
    timestamp: String,
    agent_id: String,
    action_type: String,
    entry_hash: String,
    previous_hash: String,
}

fn is_remote_target(vnc_ip: &str) -> bool {
    if vnc_ip == "127.0.0.1" || vnc_ip == "localhost" || vnc_ip == "0.0.0.0" {
        return false;
    }
    if cfg!(target_os = "linux") && vnc_ip == "34.106.12.222" {
        return false;
    }
    true
}

/// Starts the local embedded HTTP UI server.
pub async fn start_ui_server(
    host: &str,
    port: u16,
    server_url: String,
    workspace_root: PathBuf,
    no_open: bool,
    vnc_host: Option<String>,
) -> Result<(), anyhow::Error> {
    let addr = format!("{}:{}", host, port);
    let listener = TcpListener::bind(&addr).await?;
    let local_addr = listener.local_addr()?;
    let display_url = if host == "0.0.0.0" {
        format!("http://127.0.0.1:{}", local_addr.port())
    } else {
        format!("http://{}", local_addr)
    };

    let target_vnc = vnc_host.unwrap_or_else(|| {
        if cfg!(target_os = "linux") {
            "127.0.0.1".to_string()
        } else {
            "34.106.12.222".to_string()
        }
    });

    info!("🚀 Syntropy UI server listening at {}:{}", host, port);
    println!("\n========================================================");
    println!("⚡ Syntropy Swarm UI active at: http://{}:{}", if host == "0.0.0.0" { "0.0.0.0" } else { host }, port);
    println!("🔗 Local Browser Access:        {}", display_url);
    println!("🌐 Network Access (Proxmox/LAN): http://<YOUR_IP>:{}", port);
    println!("🖥️ Remote VNC Host:            {}", target_vnc);
    println!("🔗 Connected to Cloud Gateway:   {}", server_url);
    println!("📂 Workspace root:               {:?}", workspace_root);
    println!("========================================================\n");

    if !no_open {
        #[cfg(windows)]
        let _ = std::process::Command::new("cmd")
            .args(["/c", "start", &display_url])
            .spawn();
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("open").arg(&display_url).spawn();
        #[cfg(all(not(windows), not(target_os = "macos")))]
        let _ = std::process::Command::new("xdg-open").arg(&display_url).spawn();
    }

    let shared_workspace = Arc::new(workspace_root);
    let shared_gateway = Arc::new(server_url);
    let shared_vnc = Arc::new(target_vnc);
    let shared_ledger = Arc::new(tokio::sync::Mutex::new(None));

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let ws = shared_workspace.clone();
                let gw = shared_gateway.clone();
                let vnc = shared_vnc.clone();
                let ledger = shared_ledger.clone();

                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, ws, gw, vnc, ledger).await {
                        error!("HTTP connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                warn!("TCP accept error: {}, pausing briefly", e);
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    workspace: Arc<PathBuf>,
    gateway_url: Arc<String>,
    vnc_host: Arc<String>,
    shared_ledger: Arc<tokio::sync::Mutex<Option<MerkleAuditLedger>>>,
) -> Result<(), anyhow::Error> {
    let mut data = Vec::new();
    let mut buffer = [0u8; 4096];
    let mut header_end = None;
    let mut expected_len = None;

    while data.len() < 131072 {
        let n = stream.read(&mut buffer).await?;
        if n == 0 {
            break;
        }
        data.extend_from_slice(&buffer[..n]);

        if header_end.is_none() {
            if let Some(pos) = data.windows(4).position(|w| w == b"\r\n\r\n") {
                header_end = Some(pos + 4);
                let header_str = String::from_utf8_lossy(&data[..pos]);
                for line in header_str.lines() {
                    let l_lower = line.to_lowercase();
                    if let Some(val) = l_lower.strip_prefix("content-length:") {
                        if let Ok(len) = val.trim().parse::<usize>() {
                            expected_len = Some(len);
                        }
                    }
                }
            }
        }

        if let Some(h_end) = header_end {
            let body_len = data.len() - h_end;
            if let Some(exp) = expected_len {
                if body_len >= exp {
                    break;
                }
            } else {
                break;
            }
        }
    }

    if data.is_empty() {
        return Ok(());
    }

    let (header_bytes, body_bytes) = if let Some(h_end) = header_end {
        (&data[..h_end - 4], &data[h_end..])
    } else {
        (data.as_slice(), &[][..])
    };

    let raw_headers = String::from_utf8_lossy(header_bytes);
    let mut lines = raw_headers.lines();
    let request_line = match lines.next() {
        Some(l) => l,
        None => return Ok(()),
    };

    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let path = parts.next().unwrap_or("/");
    let body = std::str::from_utf8(body_bytes).unwrap_or("");

    match (method, path) {
        ("GET", "/") | ("GET", "/index.html") => {
            let html = std::fs::read_to_string(workspace.join("crates/syntropy-cli/ui/index.html"))
                .or_else(|_| std::fs::read_to_string("crates/syntropy-cli/ui/index.html"))
                .unwrap_or_else(|_| INDEX_HTML.to_string());
            send_http_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
        }

        ("HEAD", "/") | ("HEAD", "/index.html") => {
            send_http_response(&mut stream, 200, "text/html; charset=utf-8", &[]).await?;
        }

        ("GET", "/api/status") => {
            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            if is_remote {
                let remote_url = format!("http://{}:3000/api/status", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_millis(1500)).build() {
                    if let Ok(resp) = client.get(&remote_url).send().await {
                        if resp.status().is_success() {
                            let bytes = resp.bytes().await.unwrap_or_default();
                            send_http_response(&mut stream, 200, "application/json", &bytes).await?;
                            return Ok(());
                        }
                    }
                }
            }

            let client = reqwest::Client::builder()
                .danger_accept_invalid_certs(true)
                .timeout(Duration::from_millis(800))
                .build()
                .ok();

            let (chrome_attached, desktop_active) = if let Some(ref c) = client {
                let chrome = c.get("http://127.0.0.1:9222/json/version").send().await.is_ok();
                let novnc = c.get(format!("http://{}:6080", vnc_ip)).send().await.is_ok()
                    || c.get(format!("http://{}:6081", vnc_ip)).send().await.is_ok()
                    || c.get("http://127.0.0.1:6080").send().await.is_ok()
                    || c.get("http://127.0.0.1:6081").send().await.is_ok()
                    || c.get("http://127.0.0.1:8444").send().await.is_ok();
                (chrome, novnc)
            } else {
                (false, false)
            };

            let body = json!({
                "gateway_url": gateway_url.as_str(),
                "workspace": workspace.display().to_string(),
                "os": std::env::consts::OS,
                "arch": std::env::consts::ARCH,
                "status": "online",
                "chrome_attached": chrome_attached,
                "desktop_active": desktop_active,
                "novnc_active": desktop_active,
                "kasm_active": desktop_active,
                "vnc_host": vnc_ip
            });
            send_json_response(&mut stream, 200, &body).await?;
        }

        ("POST", "/api/webrtc/offer") => {
            let resp = json!({
                "type": "answer",
                "status": "connected",
                "channel": "syntropy-screen",
                "loopback": true
            });
            send_json_response(&mut stream, 200, &resp).await?;
        }

        ("GET", "/api/audit") => {
            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            if is_remote {
                let remote_url = format!("http://{}:3000/api/audit", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_millis(2000)).build() {
                    if let Ok(resp) = client.get(&remote_url).send().await {
                        if resp.status().is_success() {
                            let bytes = resp.bytes().await.unwrap_or_default();
                            send_http_response(&mut stream, 200, "application/json", &bytes).await?;
                            return Ok(());
                        }
                    }
                }
            }

            let audit_path = workspace.join(".syntropy").join("audit.db");
            if !audit_path.exists() {
                let empty_resp = json!({
                    "total_entries": 0,
                    "verified": true,
                    "merkle_root": "Genesis",
                    "entries": []
                });
                send_json_response(&mut stream, 200, &empty_resp).await?;
                return Ok(());
            }

            let mut guard = shared_ledger.lock().await;
            if guard.is_none() {
                *guard = MerkleAuditLedger::open(&audit_path).ok();
            }

            if let Some(ref ledger) = *guard {
                let integrity = ledger.verify_integrity().unwrap_or(syntropy_security::IntegrityReport {
                    is_valid: false,
                    verified_count: 0,
                    latest_hash: None,
                    violation: None,
                });
                let root = ledger.compute_merkle_root().ok().flatten().unwrap_or_else(|| "Genesis".into());

                let entries = query_recent_audit_entries(ledger);
                let resp = json!({
                    "total_entries": integrity.verified_count,
                    "verified": integrity.is_valid,
                    "merkle_root": root,
                    "entries": entries
                });
                send_json_response(&mut stream, 200, &resp).await?;
            } else {
                let err = json!({ "error": "Failed to open audit database" });
                send_json_response(&mut stream, 500, &err).await?;
            }
        }

        ("GET", "/api/key") => {
            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            if is_remote {
                let remote_url = format!("http://{}:3000/api/key", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_millis(2000)).build() {
                    if let Ok(resp) = client.get(&remote_url).send().await {
                        if resp.status().is_success() {
                            let bytes = resp.bytes().await.unwrap_or_default();
                            send_http_response(&mut stream, 200, "application/json", &bytes).await?;
                            return Ok(());
                        }
                    }
                }
            }

            let key_opt = syntropy_orchestrator::GeminiClient::resolve_api_key();
            let model = std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-3.8-flash".to_string());
            let resp = match key_opt {
                Some(key) if !key.is_empty() => {
                    let preview = if key.len() > 8 {
                        format!("{}...{}", &key[..4], &key[key.len() - 4..])
                    } else {
                        "***".to_string()
                    };
                    json!({ "has_key": true, "preview": preview, "model": model })
                }
                _ => json!({ "has_key": false, "model": model }),
            };
            send_json_response(&mut stream, 200, &resp).await?;
        }

        ("POST", "/api/key") => {
            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            let parsed: Value = serde_json::from_str(body).unwrap_or_default();
            let raw_key = parsed.get("api_key")
                .or_else(|| parsed.get("apiKey"))
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .replace(['\r', '\n'], "");
            let model = parsed.get("model")
                .and_then(|v| v.as_str())
                .unwrap_or("gemini-3.8-flash")
                .trim();

            if is_remote {
                let remote_url = format!("http://{}:3000/api/key", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(5)).build() {
                    let _ = client.post(&remote_url).json(&parsed).send().await;
                }
            }

            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                let config_dir = std::path::Path::new(&home).join(".config").join("syntropy");
                let _ = std::fs::create_dir_all(&config_dir);
                let key_file = config_dir.join("gemini.key");
                let _ = std::fs::write(&key_file, &raw_key);
            }

            if !raw_key.is_empty() {
                std::env::set_var("GEMINI_API_KEY", &raw_key);
            }
            if !model.is_empty() {
                std::env::set_var("GEMINI_MODEL", model);
            }

            let resp = json!({ "status": "saved", "model": model });
            send_json_response(&mut stream, 200, &resp).await?;
        }

        ("POST", "/api/clear") => {
            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            if is_remote {
                let remote_url = format!("http://{}:3000/api/clear", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_millis(2000)).build() {
                    let _ = client.post(&remote_url).send().await;
                }
            }
            let resp = json!({ "status": "session_cleared" });
            send_json_response(&mut stream, 200, &resp).await?;
        }

        ("POST", "/api/chat") => {
            let req: ChatRequest = match serde_json::from_str(body) {
                Ok(r) => r,
                Err(e) => {
                    let err = json!({ "error": format!("Invalid JSON request: {}", e) });
                    send_json_response(&mut stream, 400, &err).await?;
                    return Ok(());
                }
            };

            let vnc_ip = vnc_host.as_str();
            let is_remote = is_remote_target(vnc_ip);

            if is_remote {
                let remote_url = format!("http://{}:3000/api/chat", vnc_ip);
                if let Ok(client) = reqwest::Client::builder().timeout(Duration::from_secs(60)).build() {
                    match client.post(&remote_url).json(&req).send().await {
                        Ok(resp) => {
                            let status = resp.status().as_u16();
                            let bytes = resp.bytes().await.unwrap_or_default();
                            send_http_response(&mut stream, status, "application/json", &bytes).await?;
                            return Ok(());
                        }
                        Err(e) => {
                            tracing::warn!("Failed to proxy chat to remote VNC host {}: {}, falling back to local execution", remote_url, e);
                        }
                    }
                }
            }

            match execute_turn_via_tunnel(&req, &workspace, &gateway_url).await {
                Ok(resp) => {
                    send_json_response(&mut stream, 200, &resp).await?;
                }
                Err(e) => {
                    let err = json!({ "error": format!("Turn execution error: {}", e) });
                    send_json_response(&mut stream, 502, &err).await?;
                }
            }
        }

        ("OPTIONS", _) => {
            send_http_response(&mut stream, 204, "text/plain", b"").await?;
        }

        _ => {
            send_http_response(&mut stream, 404, "text/plain", b"Not Found").await?;
        }
    }

    Ok(())
}

async fn execute_turn_via_tunnel(
    req: &ChatRequest,
    workspace: &Path,
    gateway_url: &str,
) -> Result<ChatResponse, anyhow::Error> {
    let prompt = UserPrompt {
        prompt_id: format!("prompt-{}", uuid::Uuid::new_v4()),
        text: req.text.clone(),
        session_id: if req.session_id.is_empty() {
            format!("sess-{}", uuid::Uuid::new_v4())
        } else {
            req.session_id.clone()
        },
        context_files: Default::default(),
    };

    if let Some(ref key) = req.api_key {
        let clean = key.trim().replace(['\r', '\n'], "");
        if !clean.is_empty() {
            std::env::set_var("GEMINI_API_KEY", &clean);
            if let Ok(home) = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE")) {
                let dir = std::path::Path::new(&home).join(".config").join("syntropy");
                let _ = std::fs::create_dir_all(&dir);
                let _ = std::fs::write(dir.join("gemini.key"), &clean);
            }
        }
    }
    if let Some(ref m) = req.model {
        let clean_m = m.trim().replace(['\r', '\n'], "");
        if !clean_m.is_empty() {
            std::env::set_var("GEMINI_MODEL", &clean_m);
        }
    }

    let jail = WorkspaceJail::new(workspace)?;
    let pty_mux = PtyMultiplexer::new();
    let diff_app = AtomicPatchApplicator::new();
    let audit_dir = workspace.join(".syntropy");
    let _ = std::fs::create_dir_all(&audit_dir);
    let audit_path = audit_dir.join("audit.db");
    let ledger = MerkleAuditLedger::open(&audit_path)?;

    let mut tool_executions = Vec::new();
    let mut server_frames_to_execute = Vec::new();
    let mut agent_message = String::new();
    let mut tool_calls = Vec::new();

    // 1. Try remote gateway tunnel first if available
    let tunnel_cfg = TunnelConfig::new(gateway_url, "local-ui-agent")
        .with_connect_timeout(Duration::from_millis(1500));

    match TunnelClient::connect(tunnel_cfg).await {
        Ok(mut client) => {
            let prompt_frame = syntropy_proto::tunnel::TunnelClientFrame {
                frame_id: uuid::Uuid::new_v4().to_string(),
                agent_id: "local-ui-agent".into(),
                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                payload: Some(syntropy_proto::tunnel::tunnel_client_frame::Payload::UserPrompt(prompt.clone())),
            };

            let _ = client.send(prompt_frame).await;

            let turn_timeout = tokio::time::Instant::now() + Duration::from_secs(45);
            while tokio::time::Instant::now() < turn_timeout {
                let server_frame = match tokio::time::timeout(Duration::from_secs(12), client.recv()).await {
                    Ok(Some(f)) => f,
                    Ok(None) => break,
                    Err(_) => break,
                };

                if let Some(payload) = server_frame.payload {
                    match payload {
                        syntropy_proto::tunnel::tunnel_server_frame::Payload::AgentMessage(msg) => {
                            agent_message = msg.content;
                            tool_calls = msg.tool_calls;
                            if msg.is_final {
                                break;
                            }
                        }
                        other => {
                            server_frames_to_execute.push(other);
                        }
                    }
                }
            }
        }
        Err(_) => {
            // 2. Gateway is offline -> evaluate prompt directly via in-process GeminiClient / TurnEngine
            info!("Cloud Gateway offline at {}, evaluating prompt directly with Gemini Turn Engine", gateway_url);
            let gemini = if let Some(ref key) = req.api_key {
                if !key.trim().is_empty() {
                    syntropy_orchestrator::GeminiClient::with_api_key(key.trim(), req.model.clone())
                } else {
                    syntropy_orchestrator::GeminiClient::from_env()
                }
            } else {
                syntropy_orchestrator::GeminiClient::from_env()
            };

            let engine = syntropy_orchestrator::AgentTurnEngine::new(Arc::new(gemini));
            let plan = engine.process_prompt(&prompt, "local-ui-agent").await?;

            agent_message = plan.agent_message.content;
            tool_calls = plan.agent_message.tool_calls;

            for frame in plan.server_frames_to_send {
                if let Some(p) = frame.payload {
                    match p {
                        syntropy_proto::tunnel::tunnel_server_frame::Payload::AgentMessage(_) => {}
                        other => server_frames_to_execute.push(other),
                    }
                }
            }
        }
    }

    // 3. Execute all scheduled tool frames inside the workspace jail & PTY multiplexer
    for payload in server_frames_to_execute {
        execute_tool_frame_locally(payload, &jail, &pty_mux, &diff_app, &ledger, &mut tool_executions).await?;
    }

    let merkle_root = ledger.compute_merkle_root()?.unwrap_or_else(|| "Genesis".into());

    Ok(ChatResponse {
        session_id: req.session_id.clone(),
        agent_message,
        tool_calls,
        tool_executions,
        merkle_root,
    })
}

async fn execute_tool_frame_locally(
    payload: syntropy_proto::tunnel::tunnel_server_frame::Payload,
    jail: &WorkspaceJail,
    pty_mux: &PtyMultiplexer,
    diff_app: &AtomicPatchApplicator,
    ledger: &MerkleAuditLedger,
    tool_executions: &mut Vec<ExecutedTool>,
) -> Result<(), anyhow::Error> {
    match payload {
        syntropy_proto::tunnel::tunnel_server_frame::Payload::ExecCommand(cmd) => {
            #[cfg(windows)]
            let (final_command, final_args) = {
                let full_line = if cmd.args.is_empty() {
                    cmd.command.clone()
                } else {
                    format!("{} {}", cmd.command, cmd.args.join(" "))
                };
                if full_line.contains(' ') || full_line.contains(';') || full_line.contains('&') || full_line.contains('|') || cmd.command == "ls" || cmd.command == "dir" {
                    ("cmd.exe".to_string(), vec!["/c".to_string(), full_line])
                } else {
                    (cmd.command.clone(), cmd.args.clone())
                }
            };
            #[cfg(not(windows))]
            let (final_command, final_args) = {
                let full_line = if cmd.args.is_empty() {
                    cmd.command.clone()
                } else {
                    format!("{} {}", cmd.command, cmd.args.join(" "))
                };
                if full_line.contains(' ') || full_line.contains(';') || full_line.contains('&') || full_line.contains('|') {
                    ("/bin/bash".to_string(), vec!["-c".to_string(), full_line])
                } else {
                    (cmd.command.clone(), cmd.args.clone())
                }
            };

            let cwd_path = if cmd.working_dir.is_empty() { None } else { Some(Path::new(&cmd.working_dir)) };
            let target_cwd = jail.validate_cwd(cwd_path)?;

            let mut spawn_opts = SpawnOptions::new(&final_command)
                .args(final_args.clone())
                .cwd(target_cwd)
                .pty(cmd.pty);
            if cmd.pty && cmd.pty_rows > 0 && cmd.pty_cols > 0 {
                spawn_opts = spawn_opts.dimensions(cmd.pty_rows as u16, cmd.pty_cols as u16);
            }

            let mut rx = pty_mux.spawn_screen("ui-screen", spawn_opts)?;
            let mut full_output = Vec::new();
            while let Ok(chunk) = rx.recv().await {
                full_output.extend_from_slice(&chunk.data);
                if chunk.is_eof {
                    break;
                }
            }
            ledger.append("local-ui-agent", "exec_command", &full_output)?;

            let output_str = sanitize_terminal_output(&String::from_utf8_lossy(&full_output));
            tool_executions.push(ExecutedTool {
                tool_type: "exec_command".into(),
                command: final_command,
                args: final_args,
                output: output_str,
                file_path: String::new(),
                lines_added: 0,
                lines_removed: 0,
                screenshot_base64: None,
                url: None,
                title: None,
            });
        }
        syntropy_proto::tunnel::tunnel_server_frame::Payload::ApplyPatch(patch) => {
            let target_path = jail.resolve_path(&patch.file_path)?;
            let opts = PatchOptions::new().dry_run(patch.dry_run);
            let result = diff_app.apply_patch(&target_path, &patch.diff, opts);

            let (_success, err_msg, lines_added, lines_removed) = match result {
                Ok(res) => {
                    ledger.append("local-ui-agent", "apply_patch", patch.diff.as_bytes())?;
                    (true, String::new(), res.lines_added, res.lines_removed)
                }
                Err(e) => {
                    warn!("Patch failed: {}", e);
                    (false, e.to_string(), 0, 0)
                }
            };

            tool_executions.push(ExecutedTool {
                tool_type: "apply_patch".into(),
                command: String::new(),
                args: Vec::new(),
                output: err_msg,
                file_path: patch.file_path,
                lines_added,
                lines_removed,
                screenshot_base64: None,
                url: None,
                title: None,
            });
        }
        syntropy_proto::tunnel::tunnel_server_frame::Payload::McpRequest(mcp_req)
            if mcp_req.server_name == "browser" || mcp_req.tool_name == "browser_action" =>
        {
            let action_req: crate::browser::BrowserAction = serde_json::from_str(&mcp_req.arguments_json)
                    .unwrap_or_else(|_| crate::browser::BrowserAction {
                        action: "navigate".into(),
                        url: Some("https://www.google.com".into()),
                        selector: None,
                        text: None,
                    });

                let b_res = crate::browser::execute_browser_action(9222, &action_req).await?;
                let res_json = serde_json::to_string(&b_res).unwrap_or_default();
                ledger.append("local-ui-agent", "browser_action", res_json.as_bytes())?;

                let output = if b_res.content.is_empty() {
                    b_res.error_message.clone().unwrap_or_else(|| "Browser action completed".into())
                } else {
                    b_res.content.clone()
                };

                tool_executions.push(ExecutedTool {
                    tool_type: "browser_action".into(),
                    command: format!("browser: {}", b_res.action),
                    args: vec![b_res.url.clone(), action_req.selector.unwrap_or_default()],
                    output,
                    file_path: String::new(),
                    lines_added: 0,
                    lines_removed: 0,
                    screenshot_base64: b_res.screenshot_base64,
                    url: Some(b_res.url),
                    title: Some(b_res.title),
                });
            }
        _ => {}
    }
    Ok(())
}

fn query_recent_audit_entries(ledger: &MerkleAuditLedger) -> Vec<AuditEntryView> {
    let count = ledger.count().unwrap_or(0);
    let offset = count.saturating_sub(25);
    ledger
        .get_entries(offset, 25)
        .unwrap_or_default()
        .into_iter()
        .map(|e| AuditEntryView {
            id: e.entry_id,
            timestamp: e.timestamp,
            agent_id: e.agent_id,
            action_type: e.action_type,
            entry_hash: e.entry_hash,
            previous_hash: e.previous_hash,
        })
        .collect()
}

async fn send_json_response<T: Serialize>(
    stream: &mut TcpStream,
    status: u16,
    data: &T,
) -> Result<(), anyhow::Error> {
    let json_bytes = serde_json::to_vec(data)?;
    send_http_response(stream, status, "application/json", &json_bytes).await
}

async fn send_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<(), anyhow::Error> {
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        _ => "Status",
    };

    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Headers: Content-Type\r\nConnection: close\r\n\r\n",
        status, status_text, content_type, body.len()
    );

    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

fn sanitize_terminal_output(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some(&'[') => {
                    chars.next();
                    while let Some(&next_c) = chars.peek() {
                        chars.next();
                        if next_c.is_ascii_alphabetic() || next_c == '~' {
                            break;
                        }
                    }
                }
                Some(&']') => {
                    chars.next();
                    while let Some(&next_c) = chars.peek() {
                        chars.next();
                        if next_c == '\x07' || next_c == '\n' {
                            break;
                        }
                    }
                }
                Some(_) => {
                    chars.next();
                }
                None => {}
            }
        } else if c == '\r' {
            if chars.peek() == Some(&'\n') {
                chars.next();
                out.push('\n');
            }
        } else if !c.is_control() || c == '\n' || c == '\t' {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ui_http_server_endpoints() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_ui_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&temp_dir).unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let ws = Arc::new(temp_dir.clone());
        let gw = Arc::new("http://127.0.0.1:50051".to_string());
        let vnc = Arc::new("34.106.12.222".to_string());
        let ledger = Arc::new(tokio::sync::Mutex::new(None));

        let server_task = tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                let ws_c = ws.clone();
                let gw_c = gw.clone();
                let vnc_c = vnc.clone();
                let ledger_c = ledger.clone();
                tokio::spawn(async move {
                    let _ = handle_connection(stream, ws_c, gw_c, vnc_c, ledger_c).await;
                });
            }
        });

        // 1. Test GET /
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("Syntropy Swarm"));

        // 2. Test GET /api/status
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"GET /api/status HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("http://127.0.0.1:50051"));

        // 3. Test GET /api/audit
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"GET /api/audit HTTP/1.1\r\nHost: localhost\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("total_entries"));

        // 4. Test POST /api/clear
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"POST /api/clear HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n").await.unwrap();
        let mut buf = vec![0u8; 4096];
        let n = client.read(&mut buf).await.unwrap();
        let resp = String::from_utf8_lossy(&buf[..n]);
        assert!(resp.starts_with("HTTP/1.1 200 OK"));
        assert!(resp.contains("session_cleared"));

        server_task.abort();
        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_sanitize_terminal_output() {
        let raw = "\x1b[?9001h\x1b[?1004h\x1b[?25l\x1b[2J\x1b[m\x1b[H\x1b]0;C:\\Windows\\cmd.exe\x07\x1b[?25hCargo.toml\r\nsrc/lib.rs\x1b[?9001l";
        let clean = sanitize_terminal_output(raw);
        assert_eq!(clean.trim(), "Cargo.toml\nsrc/lib.rs");
    }
}
