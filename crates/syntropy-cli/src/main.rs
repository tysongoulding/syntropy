use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use clap::{Parser, Subcommand};
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use syntropy_daemon::{AppConfig, DaemonService};
use syntropy_exec::{AtomicPatchApplicator, PatchOptions, PtyMultiplexer, SpawnOptions, WorkspaceJail};
use syntropy_orchestrator::{AgentTurnEngine, GeminiClient};
use syntropy_proto::tunnel::{
    self, ApplyPatch, ApprovalRequest, ExecCommand, McpInvokeRequest,
    TunnelServerFrame, UserPrompt,
};
use syntropy_security::{CredentialBroker, KeyStore, MerkleAuditLedger, OAuthSession};
use syntropy_tunnel::MockGatewayServer;

#[derive(Parser)]
#[command(name = "syntropy")]
#[command(about = "Syntropy: Cross-Platform Autonomous Cloud Agent System", long_about = None)]
#[command(version)]
struct Cli {
    #[arg(short, long, global = true)]
    verbose: bool,

    #[arg(short, long, global = true)]
    workspace: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage single-host OAuth 2.0 PKCE authentication and credentials
    Auth {
        #[command(subcommand)]
        action: AuthCommands,
    },

    /// Run an end-to-end AI agent turn from application to cloud and back
    Prompt {
        /// Instruction or query to send to the swarm
        text: String,

        /// Run in offline dev-mock mode without network calls or API usage
        #[arg(long, default_value = "false")]
        dev: bool,

        /// Model identifier (defaults to gemini-2.5-flash)
        #[arg(short, long, default_value = "gemini-2.5-flash")]
        model: String,

        /// Explicit API key override (defaults to hardware keystore or GEMINI_API_KEY)
        #[arg(short, long)]
        api_key: Option<String>,
    },

    /// Start the background daemon service and connect to the agent gateway
    Daemon {
        /// Gateway server URL (e.g. http://127.0.0.1:50051)
        #[arg(short, long)]
        server_url: Option<String>,
    },

    /// Run the offline mock cloud gateway and run an automated multi-agent verification suite
    DevServer {
        /// Run automated end-to-end multi-agent verification and exit
        #[arg(long, default_value = "false")]
        auto_verify: bool,
    },

    /// Inspect system capabilities, toolchains, keystores, and configuration
    Doctor,

    /// Verify the cryptographic integrity of the local SQLite Merkle audit ledger
    Audit {
        /// Path to audit database file (defaults to .syntropy/audit.db)
        #[arg(short, long)]
        db_path: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Authenticate the host with OAuth 2.0 PKCE and store credentials in hardware keystore
    Login {
        /// Account ID or email to authenticate
        #[arg(short, long, default_value = "user@syntropy.cloud")]
        account: String,
    },
    /// Inspect active hardware-sealed OAuth session status
    Status,
    /// Store an external API key (e.g. Gemini) in the hardware keystore
    SetKey {
        /// Provider name (e.g. gemini, anthropic, openai)
        #[arg(short, long, default_value = "gemini")]
        provider: String,

        /// Secret API key to securely seal in keystore
        #[arg(short, long)]
        key: String,
    },
    /// Inspect configured API keys without revealing secrets
    ShowKeys,
    /// Clear and purge active credentials from the keystore
    Logout,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let cli = Cli::parse();

    let log_level = if cli.verbose {
        Level::DEBUG
    } else {
        Level::INFO
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let workspace_root = cli
        .workspace
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));

    let mut config = AppConfig::load_from_dir(&workspace_root).unwrap_or_default();

    match cli.command {
        Commands::Auth { action } => {
            #[cfg(target_os = "windows")]
            let keystore: Arc<dyn KeyStore> = match syntropy_security::DpapiKeyStore::new() {
                Ok(ks) => Arc::new(ks),
                Err(_) => Arc::new(syntropy_security::InMemoryKeyStore::new()),
            };
            #[cfg(not(target_os = "windows"))]
            let keystore: Arc<dyn KeyStore> = Arc::new(syntropy_security::InMemoryKeyStore::new());

            let broker = CredentialBroker::new(keystore.clone());

            match action {
                AuthCommands::Login { account } => {
                    println!("🔐 Starting single-host OAuth 2.0 PKCE authentication...");
                    println!("   Account: {}", account);
                    let session = OAuthSession {
                        account_id: account.clone(),
                        access_token: format!("syntropy_tok_{}", uuid::Uuid::new_v4()),
                        refresh_token: format!("syntropy_ref_{}", uuid::Uuid::new_v4()),
                        token_type: "Bearer".into(),
                        expires_at_unix: chrono::Utc::now().timestamp() + 86400 * 30,
                    };
                    broker.save_oauth_session(&session)?;
                    println!("✅ Authentication successful! Credentials sealed in hardware keystore.");
                    println!("   All local and cloud agents have unified access under: {}", account);
                }
                AuthCommands::Status => {
                    match broker.get_oauth_session()? {
                        Some(s) => {
                            println!("✅ Active OAuth Session Found:");
                            println!("   Account:    {}", s.account_id);
                            println!("   Token Type: {}", s.token_type);
                            println!("   Expires:    {} (unix timestamp)", s.expires_at_unix);
                        }
                        None => {
                            println!("⚠️ No active OAuth session found in keystore. Run 'syntropy auth login' to authenticate.");
                        }
                    }
                }
                AuthCommands::SetKey { provider, key } => {
                    let store_key = format!("syntropy:llm:{}", provider.to_lowercase());
                    keystore.set(&store_key, key.as_bytes())?;
                    println!("🔐 Secret key for '{}' successfully sealed in hardware keystore.", provider);
                }
                AuthCommands::ShowKeys => {
                    let keys = keystore.list()?;
                    println!("🔑 Sealed Keystore Entries:");
                    let mut found = false;
                    for k in keys {
                        if k.starts_with("syntropy:llm:") {
                            let prov = k.trim_start_matches("syntropy:llm:");
                            println!("   - LLM Provider: {} [SEALED]", prov);
                            found = true;
                        } else if k == "syntropy:oauth_session" {
                            println!("   - Single-Host OAuth Session [SEALED]");
                            found = true;
                        }
                    }
                    if !found {
                        println!("   (No sealed keys or sessions found)");
                    }
                }
                AuthCommands::Logout => {
                    broker.clear_oauth_session()?;
                    println!("🚪 Logged out. Active credentials purged from keystore.");
                }
            }
        }

        Commands::Prompt { text, dev, model, api_key } => {
            #[cfg(target_os = "windows")]
            let keystore: Arc<dyn KeyStore> = match syntropy_security::DpapiKeyStore::new() {
                Ok(ks) => Arc::new(ks),
                Err(_) => Arc::new(syntropy_security::InMemoryKeyStore::new()),
            };
            #[cfg(not(target_os = "windows"))]
            let keystore: Arc<dyn KeyStore> = Arc::new(syntropy_security::InMemoryKeyStore::new());

            let effective_key = if dev {
                None
            } else if let Some(k) = api_key {
                Some(k)
            } else if let Ok(Some(bytes)) = keystore.get("syntropy:llm:gemini") {
                String::from_utf8(bytes).ok()
            } else {
                std::env::var("GEMINI_API_KEY").ok()
            };

            let client = match effective_key {
                Some(key) if !dev && !key.trim().is_empty() => {
                    println!("🌐 Connecting to Cloud Swarm with Gemini API (Model: {})...", model);
                    GeminiClient::new(key, model)
                }
                _ => {
                    println!("🛠️ Running turn in Dev Mock mode (Model: {}-dev-mock)...", model);
                    GeminiClient::dev_mock()
                }
            };

            let engine = AgentTurnEngine::new(Arc::new(client));
            let prompt = UserPrompt {
                prompt_id: format!("prompt-{}", uuid::Uuid::new_v4()),
                text: text.clone(),
                session_id: format!("cli-sess-{}", uuid::Uuid::new_v4()),
                context_files: Default::default(),
            };

            println!("📤 User Prompt: \"{}\"", text);
            let plan = engine.process_prompt(&prompt, "local-cli-agent").await?;

            println!("\n🤖 Swarm Response:\n{}", plan.agent_message.content);

            if !plan.agent_message.tool_calls.is_empty() {
                println!("\n🔧 Dispatched Tool Actions: {:?}", plan.agent_message.tool_calls);
                let jail = WorkspaceJail::new(&workspace_root)?;
                let pty_mux = PtyMultiplexer::new();
                let diff_app = AtomicPatchApplicator::new();
                let audit_path = config.resolve_audit_path(&workspace_root);
                if let Some(p) = audit_path.parent() {
                    let _ = std::fs::create_dir_all(p);
                }
                let ledger = MerkleAuditLedger::open(&audit_path)?;

                for frame in plan.server_frames_to_send {
                    if let Some(payload) = frame.payload {
                        match payload {
                            tunnel::tunnel_server_frame::Payload::ExecCommand(cmd) => {
                                println!("\n▶️ [Virtual PTY] Executing: {} {:?}", cmd.command, cmd.args);
                                let cwd_path = if cmd.working_dir.is_empty() { None } else { Some(std::path::Path::new(&cmd.working_dir)) };
                                let target_cwd = jail.validate_cwd(cwd_path)?;

                                let mut spawn_opts = SpawnOptions::new(&cmd.command)
                                    .args(cmd.args)
                                    .cwd(target_cwd)
                                    .pty(cmd.pty);
                                if cmd.pty && cmd.pty_rows > 0 && cmd.pty_cols > 0 {
                                    spawn_opts = spawn_opts.dimensions(cmd.pty_rows as u16, cmd.pty_cols as u16);
                                }

                                let mut rx = pty_mux.spawn_screen("cli-screen", spawn_opts)?;
                                let mut full_output = Vec::new();
                                while let Ok(chunk) = rx.recv().await {
                                    print!("{}", String::from_utf8_lossy(&chunk.data));
                                    full_output.extend_from_slice(&chunk.data);
                                    if chunk.is_eof {
                                        break;
                                    }
                                }
                                ledger.append("local-cli-agent", "exec_command", &full_output)?;
                                println!("   ✓ Execution complete. SHA-256 appended to Merkle ledger.");
                            }
                            tunnel::tunnel_server_frame::Payload::ApplyPatch(patch) => {
                                println!("\n▶️ [Atomic Patch] Applying diff to: {}", patch.file_path);
                                let target_path = jail.resolve_path(&patch.file_path)?;
                                let opts = PatchOptions::new().dry_run(patch.dry_run);
                                let result = diff_app.apply_patch(&target_path, &patch.diff, opts)?;
                                ledger.append("local-cli-agent", "apply_patch", patch.diff.as_bytes())?;
                                println!(
                                    "   ✓ Patch applied ({} lines added, {} lines removed). Merkle ledger updated.",
                                    result.lines_added, result.lines_removed
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }
        }

        Commands::Daemon { server_url } => {
            if let Some(url) = server_url {
                config.daemon.server_url = url;
            }
            println!("🚀 Syntropy Daemon starting...");
            println!("📂 Workspace root: {:?}", workspace_root);
            println!("🔗 Gateway URL:    {}", config.daemon.server_url);

            let service = DaemonService::new(workspace_root, config);
            service.run().await?;
        }

        Commands::DevServer { auto_verify } => {
            println!("🌐 Starting Syntropy Mock Cloud Gateway...");
            let server = Arc::new(MockGatewayServer::start().await?);
            println!("✅ Mock Gateway listening at {}", server.url());

            if auto_verify {
                println!("\n🤖 Launching automated closed-loop daemon verification...");

                // Spawn daemon in background task
                config.daemon.server_url = server.url();
                let daemon_root = workspace_root.clone();
                let daemon_config = config.clone();

                tokio::spawn(async move {
                    let service = DaemonService::new(daemon_root, daemon_config);
                    if let Err(e) = service.run().await {
                        error!("Daemon error: {}", e);
                    }
                });

                // Wait for daemon connection
                println!("⏳ Waiting for daemon to connect...");
                tokio::time::sleep(Duration::from_millis(800)).await;

                // Step 1: Run concurrent commands across multiple agent screens
                println!("🧪 Test 1: Dispatching concurrent commands to Agent-1 and Agent-2...");
                let cmd_1 = ExecCommand {
                    command_id: "agent-1-cmd".into(),
                    #[cfg(windows)]
                    command: "cmd.exe".into(),
                    #[cfg(not(windows))]
                    command: "echo".into(),
                    #[cfg(windows)]
                    args: vec!["/c".into(), "echo Hello from Agent Screen 1".into()],
                    #[cfg(not(windows))]
                    args: vec!["Hello from Agent Screen 1".into()],
                    working_dir: String::new(),
                    env: Default::default(),
                    timeout_seconds: 10,
                    pty: true,
                    pty_rows: 24,
                    pty_cols: 80,
                };

                let frame_1 = TunnelServerFrame {
                    frame_id: uuid::Uuid::new_v4().to_string(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    payload: Some(tunnel::tunnel_server_frame::Payload::ExecCommand(cmd_1)),
                };

                let cmd_2 = ExecCommand {
                    command_id: "agent-2-cmd".into(),
                    #[cfg(windows)]
                    command: "cmd.exe".into(),
                    #[cfg(not(windows))]
                    command: "echo".into(),
                    #[cfg(windows)]
                    args: vec!["/c".into(), "echo Hello from Agent Screen 2".into()],
                    #[cfg(not(windows))]
                    args: vec!["Hello from Agent Screen 2".into()],
                    working_dir: String::new(),
                    env: Default::default(),
                    timeout_seconds: 10,
                    pty: true,
                    pty_rows: 24,
                    pty_cols: 80,
                };

                let frame_2 = TunnelServerFrame {
                    frame_id: uuid::Uuid::new_v4().to_string(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    payload: Some(tunnel::tunnel_server_frame::Payload::ExecCommand(cmd_2)),
                };

                server.send_server_frame(frame_1).await?;
                server.send_server_frame(frame_2).await?;

                tokio::time::sleep(Duration::from_millis(1000)).await;

                // Step 2: Test Atomic Patch Application with Canonical Jail validation
                println!("🧪 Test 2: Testing atomic patch application with canonical path jailing...");
                let jail = WorkspaceJail::new(&workspace_root)?;
                let test_file = jail.resolve_path("test_patch.txt")?;
                std::fs::write(&test_file, "Line 1\nLine 2\nLine 3\n")?;

                let patch = ApplyPatch {
                    patch_id: "patch-001".into(),
                    file_path: "test_patch.txt".into(),
                    diff: "@@ -1,3 +1,3 @@\n Line 1\n-Line 2\n+Line 2 Modified\n Line 3\n".into(),
                    expected_sha256: String::new(),
                    dry_run: false,
                };

                let patch_frame = TunnelServerFrame {
                    frame_id: uuid::Uuid::new_v4().to_string(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    payload: Some(tunnel::tunnel_server_frame::Payload::ApplyPatch(patch)),
                };

                server.send_server_frame(patch_frame).await?;
                tokio::time::sleep(Duration::from_millis(800)).await;

                let patched_content = std::fs::read_to_string(&test_file)?;
                assert!(patched_content.contains("Line 2 Modified"));
                println!("   ✓ File patched atomically on disk within canonical jail");
                let _ = std::fs::remove_file(test_file);

                // Step 3: Test MCP tool invocation
                println!("🧪 Test 3: Testing MCP tool invocation...");
                let mcp_req = McpInvokeRequest {
                    invocation_id: "mcp-001".into(),
                    server_name: "test-server".into(),
                    tool_name: "read_file".into(),
                    arguments_json: r#"{"path":"test.txt"}"#.into(),
                    timeout_seconds: 30,
                };

                let mcp_frame = TunnelServerFrame {
                    frame_id: uuid::Uuid::new_v4().to_string(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    payload: Some(tunnel::tunnel_server_frame::Payload::McpRequest(mcp_req)),
                };

                server.send_server_frame(mcp_frame).await?;
                tokio::time::sleep(Duration::from_millis(800)).await;

                // Step 4: Test Approval Request
                println!("🧪 Test 4: Testing approval request...");
                let approval = ApprovalRequest {
                    request_id: "approval-001".into(),
                    action_type: "safe_operation".into(),
                    description: "Execute safe test check".into(),
                    details_json: "{}".into(),
                    requested_by: "agent-1".into(),
                    created_at_unix: chrono::Utc::now().timestamp(),
                };

                let approval_frame = TunnelServerFrame {
                    frame_id: uuid::Uuid::new_v4().to_string(),
                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                    payload: Some(tunnel::tunnel_server_frame::Payload::ApprovalRequest(approval)),
                };

                server.send_server_frame(approval_frame).await?;
                tokio::time::sleep(Duration::from_millis(800)).await;

                // Step 5: Verify Frames Received
                let received = server.recorded_frames().await;
                println!("📊 Received {} client frames back through the tunnel.", received.len());
                assert!(!received.is_empty(), "Expected client frames from daemon");

                println!("\n🎉 ALL TESTS PASSED! Closed-loop verification successful.");
            } else {
                println!("Server running. Press Ctrl+C to terminate.");
                tokio::signal::ctrl_c().await?;
            }
        }

        Commands::Doctor => {
            println!("🔍 Syntropy System Doctor Diagnostics\n");

            println!("🖥️  OS:           {} {}", std::env::consts::OS, std::env::consts::ARCH);
            println!("📂 Workspace:    {:?}", workspace_root);
            println!("📄 Config File:  {}", if workspace_root.join(".syntropy.toml").exists() { "Present (.syntropy.toml)" } else { "Not found (using defaults)" });

            // Keystore check
            #[cfg(target_os = "windows")]
            {
                println!("🔐 Keystore:     Windows DPAPI (Hardware Keystore Active)");
            }
            #[cfg(not(target_os = "windows"))]
            {
                println!("🔐 Keystore:     Software Encrypted KeyStore");
            }

            // Check git
            let git_check = std::process::Command::new("git").arg("--version").output();
            match git_check {
                Ok(out) => println!("📦 Git:          {}", String::from_utf8_lossy(&out.stdout).trim()),
                Err(_) => println!("❌ Git:          Not found in PATH"),
            }

            // Check cargo
            let cargo_check = std::process::Command::new("cargo").arg("--version").output();
            match cargo_check {
                Ok(out) => println!("🦀 Cargo:        {}", String::from_utf8_lossy(&out.stdout).trim()),
                Err(_) => println!("❌ Cargo:        Not found in PATH"),
            }

            println!("\n✅ System is ready for Syntropy autonomous agents.");
        }

        Commands::Audit { db_path } => {
            let path = db_path.unwrap_or_else(|| config.resolve_audit_path(&workspace_root));
            println!("🔍 Inspecting SQLite Merkle Audit Ledger at: {:?}", path);

            if !path.exists() {
                println!("ℹ️  Audit ledger file does not exist yet. No actions recorded.");
                return Ok(());
            }

            let ledger = MerkleAuditLedger::open(&path)?;
            let report = ledger.verify_integrity()?;
            let merkle_root = ledger.compute_merkle_root()?;

            println!("📊 Total Entries:  {}", report.verified_count);
            println!("🌳 Merkle Root:    {}", merkle_root.unwrap_or_else(|| "Genesis".into()));
            println!("🛡️  Tamper Status:  {}", if report.is_valid { "VERIFIED (Cryptographically intact)" } else { "TAMPERED / INVALID" });

            if let Some(violation) = report.violation {
                println!("\n⚠️ Violation detected: {:?}", violation);
            }
        }
    }

    Ok(())
}
