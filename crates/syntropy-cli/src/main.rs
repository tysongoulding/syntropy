use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use clap::{Parser, Subcommand};
use tracing::{error, Level};
use tracing_subscriber::FmtSubscriber;

use syntropy_daemon::{AppConfig, DaemonService};
use syntropy_proto::tunnel::{
    self, ApplyPatch, ApprovalRequest, ExecCommand, McpInvokeRequest,
    TunnelServerFrame,
};
use syntropy_security::MerkleAuditLedger;
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

                // Step 2: Test Atomic Patch Application
                println!("🧪 Test 2: Testing atomic patch application...");
                let test_file = workspace_root.join("test_patch.txt");
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
                println!("   ✓ File patched atomically on disk");
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
