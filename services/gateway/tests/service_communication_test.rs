use std::sync::Arc;
use std::time::Duration;

use syntropy_daemon::{AppConfig, DaemonService};
use syntropy_gateway::GatewayServerHandle;
use syntropy_proto::tunnel::{
    tunnel_client_frame, tunnel_server_frame, ExecCommand, TunnelServerFrame,
};

#[tokio::test]
async fn test_cloud_service_communicates_with_application_crates() {
    // 1. Initialize Cloud Track Service (syntropy-gateway) on ephemeral port
    let gateway = Arc::new(
        GatewayServerHandle::bind_ephemeral()
            .await
            .expect("Failed to bind ephemeral gateway"),
    );
    let gateway_url = gateway.url();

    // 2. Configure Application Track Crate (syntropy-daemon) to point at Cloud Gateway
    let temp_dir = std::env::temp_dir().join(format!("syntropy_test_{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&temp_dir).expect("Failed to create temp test dir");

    let mut config = AppConfig::default();
    config.daemon.server_url = gateway_url.clone();
    config.daemon.heartbeat_interval_secs = 1;

    let daemon_root = temp_dir.clone();
    let daemon_config = config.clone();

    let daemon_task = tokio::spawn(async move {
        let service = DaemonService::new(daemon_root, daemon_config);
        let _ = service.run().await;
    });

    // 3. Wait for Application Track daemon to connect and register in Cloud Gateway SessionRegistry
    let mut connected_agent_id = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let active = gateway.registry.active_agents().await;
        if let Some(session) = active.first() {
            connected_agent_id = Some(session.agent_id.clone());
            break;
        }
    }

    let agent_id = connected_agent_id.expect("Daemon failed to register with gateway within 5 seconds");
    assert!(agent_id.starts_with("daemon-"), "Registered agent should have daemon prefix");

    // 4. Cloud Service sends instruction (ExecCommand) to Application Crate daemon
    let cmd_frame = TunnelServerFrame {
        frame_id: uuid::Uuid::new_v4().to_string(),
        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
        payload: Some(tunnel_server_frame::Payload::ExecCommand(ExecCommand {
            command_id: "test-cloud-to-crate-cmd".into(),
            #[cfg(windows)]
            command: "cmd.exe".into(),
            #[cfg(not(windows))]
            command: "sh".into(),
            #[cfg(windows)]
            args: vec!["/c".into(), "echo SYNTHESIS_SUCCESS".into()],
            #[cfg(not(windows))]
            args: vec!["-c".into(), "echo SYNTHESIS_SUCCESS".into()],
            env: std::collections::HashMap::new(),
            working_dir: String::new(),
            timeout_seconds: 10,
            pty: true,
            pty_rows: 24,
            pty_cols: 80,
        })),
    };

    gateway
        .registry
        .send_to_agent(&agent_id, cmd_frame)
        .await
        .expect("Failed to send frame from gateway service to daemon crate");

    // 5. Cloud Service listens for output response streamed back from Application Crate
    let mut received_expected_output = false;
    let timeout = tokio::time::Instant::now() + Duration::from_secs(5);

    while tokio::time::Instant::now() < timeout {
        if let Some(client_frame) = tokio::time::timeout(Duration::from_millis(500), gateway.recv_client_frame())
            .await
            .ok()
            .flatten()
        {
            if let Some(tunnel_client_frame::Payload::TerminalOutput(output)) = client_frame.payload {
                let text = String::from_utf8_lossy(&output.data);
                if text.contains("SYNTHESIS_SUCCESS") {
                    received_expected_output = true;
                    break;
                }
            }
        }
    }

    assert!(
        received_expected_output,
        "Gateway did not receive expected execution output from daemon"
    );

    // 6. Cloud Service sends an atomic patch to Application Crate daemon
    let test_file = temp_dir.join("test_patch.txt");
    std::fs::write(&test_file, "Line 1\nLine 2\nLine 3\n").unwrap();

    let patch_frame = TunnelServerFrame {
        frame_id: uuid::Uuid::new_v4().to_string(),
        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
        payload: Some(tunnel_server_frame::Payload::ApplyPatch(
            syntropy_proto::tunnel::ApplyPatch {
                patch_id: "patch-001".into(),
                file_path: "test_patch.txt".into(),
                diff: "@@ -1,3 +1,3 @@\n Line 1\n-Line 2\n+Line 2 Modified\n Line 3\n".into(),
                expected_sha256: String::new(),
                dry_run: false,
            },
        )),
    };

    gateway
        .registry
        .send_to_agent(&agent_id, patch_frame)
        .await
        .expect("Failed to send patch frame to daemon");

    // Wait for patch result frame
    let mut received_patch_result = false;
    let patch_timeout = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < patch_timeout {
        if let Some(client_frame) = tokio::time::timeout(Duration::from_millis(500), gateway.recv_client_frame())
            .await
            .ok()
            .flatten()
        {
            if let Some(tunnel_client_frame::Payload::PatchResult(res)) = client_frame.payload {
                assert!(res.success, "Patch should succeed: {}", res.error_message);
                received_patch_result = true;
                break;
            }
        }
    }

    assert!(received_patch_result, "Gateway did not receive patch result");
    let patched_content = std::fs::read_to_string(&test_file).unwrap();
    assert!(patched_content.contains("Line 2 Modified"));

    // 7. Clean up
    daemon_task.abort();
    gateway.shutdown();
    let _ = std::fs::remove_dir_all(&temp_dir);
}
