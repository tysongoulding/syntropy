use std::collections::HashMap;
use std::time::Duration;
use syntropy_proto::tunnel::{
    tunnel_client_frame, tunnel_server_frame, ApplyPatch, ApprovalRequest, ApprovalResponse,
    ExecCommand, McpInvokeRequest, McpInvokeResponse, PatchResult, TerminalInputChunk,
    TerminalOutputChunk, TunnelClientFrame, TunnelServerFrame,
};
use syntropy_tunnel::{MockGatewayServer, TunnelClient, TunnelConfig};

#[tokio::test]
async fn test_bidirectional_frame_transmission() {
    let server = MockGatewayServer::start().await.expect("start mock server");
    let config = TunnelConfig::new(server.url(), "agent-test-1")
        .with_heartbeat_interval(None) // Disable heartbeat for deterministic frame counting
        .with_connect_timeout(Duration::from_secs(5));

    let mut client = TunnelClient::connect(config).await.expect("connect client");
    assert!(client.is_connected());

    // 1. Client -> Server: ExecCommand
    let client_frame = TunnelClientFrame {
        frame_id: "client-frame-1".into(),
        timestamp_unix_ms: 1000,
        agent_id: "agent-test-1".into(),
        payload: Some(tunnel_client_frame::Payload::ExecCommand(ExecCommand {
            command_id: "cmd-123".into(),
            command: "cargo test".into(),
            args: vec!["--all".into()],
            working_dir: "/workspace".into(),
            env: HashMap::from([("RUST_LOG".into(), "debug".into())]),
            timeout_seconds: 30,
            pty: true,
            pty_rows: 24,
            pty_cols: 80,
        })),
    };

    client.send(client_frame.clone()).await.expect("send client frame");

    let received_at_server = server
        .recv_client_frame()
        .await
        .expect("server receive frame");

    assert_eq!(received_at_server.frame_id, "client-frame-1");
    match received_at_server.payload {
        Some(tunnel_client_frame::Payload::ExecCommand(cmd)) => {
            assert_eq!(cmd.command_id, "cmd-123");
            assert_eq!(cmd.command, "cargo test");
            assert_eq!(cmd.args, vec!["--all"]);
            assert_eq!(cmd.working_dir, "/workspace");
            assert_eq!(cmd.pty, true);
        }
        other => panic!("Unexpected payload received at server: {:?}", other),
    }

    // 2. Server -> Client: TerminalInputChunk
    let server_frame = TunnelServerFrame {
        frame_id: "server-frame-1".into(),
        timestamp_unix_ms: 2000,
        payload: Some(tunnel_server_frame::Payload::TerminalInput(
            TerminalInputChunk {
                session_id: "cmd-123".into(),
                data: b"exit\n".to_vec(),
                is_eof: false,
                resize: false,
                pty_rows: 24,
                pty_cols: 80,
            },
        )),
    };

    server
        .send_server_frame(server_frame)
        .await
        .expect("server send frame");

    let received_at_client = client.recv().await.expect("client receive frame");
    assert_eq!(received_at_client.frame_id, "server-frame-1");
    match received_at_client.payload {
        Some(tunnel_server_frame::Payload::TerminalInput(input)) => {
            assert_eq!(input.session_id, "cmd-123");
            assert_eq!(input.data, b"exit\n");
        }
        other => panic!("Unexpected payload received at client: {:?}", other),
    }

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn test_heartbeat_ping_pong() {
    let server = MockGatewayServer::start().await.expect("start mock server");
    server.set_auto_heartbeat_ack(true);

    let config = TunnelConfig::new(server.url(), "agent-hb-test")
        .with_heartbeat_interval(Some(Duration::from_millis(50)))
        .with_connect_timeout(Duration::from_secs(5));

    let mut client = TunnelClient::connect(config).await.expect("connect client");

    // Wait for at least one heartbeat ack frame from server
    let timeout = Duration::from_secs(3);
    let start = std::time::Instant::now();
    let mut got_heartbeat_ack = false;

    while start.elapsed() < timeout {
        if let Ok(Some(frame)) = tokio::time::timeout(Duration::from_millis(500), client.recv()).await {
            if let Some(tunnel_server_frame::Payload::Heartbeat(hb)) = frame.payload {
                if hb.is_ack && hb.agent_id == "agent-hb-test" {
                    got_heartbeat_ack = true;
                    break;
                }
            }
        }
    }

    assert!(got_heartbeat_ack, "Client should receive heartbeat ack from mock server");

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn test_reconnect_exponential_backoff() {
    let server = MockGatewayServer::start().await.expect("start mock server");

    let config = TunnelConfig::new(server.url(), "agent-reconnect-test")
        .with_heartbeat_interval(None)
        .with_reconnect_policy(
            Duration::from_millis(50),
            Duration::from_millis(300),
            2.0,
            Some(10),
        )
        .with_connect_timeout(Duration::from_secs(5));

    let client = TunnelClient::connect(config).await.expect("initial connect");
    assert!(client.is_connected());

    // Send a frame before disconnect
    client
        .send(TunnelClientFrame {
            frame_id: "pre-disconnect-1".into(),
            timestamp_unix_ms: 100,
            agent_id: "agent-reconnect-test".into(),
            payload: None,
        })
        .await
        .expect("send frame");

    let rec = server.recv_client_frame().await.expect("recv pre-disconnect frame");
    assert_eq!(rec.frame_id, "pre-disconnect-1");

    // Trigger disconnect from server side
    server.disconnect_clients().await;

    // Wait for client to reconnect automatically
    tokio::time::sleep(Duration::from_millis(200)).await;
    let reconnected = client.wait_connected(Duration::from_secs(5)).await;
    assert!(reconnected.is_ok(), "Client should have reconnected successfully");
    assert!(client.is_connected());

    // Verify frames can still be sent across reconnected tunnel
    client
        .send(TunnelClientFrame {
            frame_id: "post-reconnect-1".into(),
            timestamp_unix_ms: 200,
            agent_id: "agent-reconnect-test".into(),
            payload: None,
        })
        .await
        .expect("send post-reconnect frame");

    let rec_post = server.recv_client_frame().await.expect("recv post-reconnect frame");
    assert_eq!(rec_post.frame_id, "post-reconnect-1");

    client.close().await;
    server.stop().await;
}

#[tokio::test]
async fn test_frame_multiplexing_all_types() {
    let server = MockGatewayServer::start().await.expect("start mock server");
    let config = TunnelConfig::new(server.url(), "agent-all-types")
        .with_heartbeat_interval(None)
        .with_connect_timeout(Duration::from_secs(5));

    let (tx, mut rx, handle) = TunnelClient::connect(config)
        .await
        .expect("connect client")
        .split();

    assert!(handle.is_connected());

    // 1. TerminalOutputChunk (Client -> Server)
    tx.send(TunnelClientFrame {
        frame_id: "output-1".into(),
        timestamp_unix_ms: 1,
        agent_id: "agent-all-types".into(),
        payload: Some(tunnel_client_frame::Payload::TerminalOutput(
            TerminalOutputChunk {
                session_id: "s1".into(),
                data: b"hello output".to_vec(),
                is_stderr: false,
                is_eof: false,
                exit_code: 0,
            },
        )),
    })
    .await
    .unwrap();

    let rec = server.recv_client_frame().await.unwrap();
    assert_eq!(rec.frame_id, "output-1");

    // 2. ApplyPatch (Server -> Client)
    server
        .send_server_frame(TunnelServerFrame {
            frame_id: "patch-1".into(),
            timestamp_unix_ms: 2,
            payload: Some(tunnel_server_frame::Payload::ApplyPatch(ApplyPatch {
                patch_id: "p1".into(),
                file_path: "src/main.rs".into(),
                diff: "--- a\n+++ b\n".into(),
                expected_sha256: "abc123hash".into(),
                dry_run: false,
            })),
        })
        .await
        .unwrap();

    let client_rec = rx.recv().await.unwrap();
    assert_eq!(client_rec.frame_id, "patch-1");

    // 3. PatchResult (Client -> Server)
    tx.send(TunnelClientFrame {
        frame_id: "patch-res-1".into(),
        timestamp_unix_ms: 3,
        agent_id: "agent-all-types".into(),
        payload: Some(tunnel_client_frame::Payload::PatchResult(PatchResult {
            patch_id: "p1".into(),
            file_path: "src/main.rs".into(),
            success: true,
            error_message: String::new(),
            new_sha256: "def456hash".into(),
            lines_added: 5,
            lines_removed: 2,
        })),
    })
    .await
    .unwrap();

    let rec = server.recv_client_frame().await.unwrap();
    assert_eq!(rec.frame_id, "patch-res-1");

    // 4. McpInvokeRequest (Server -> Client)
    server
        .send_server_frame(TunnelServerFrame {
            frame_id: "mcp-req-1".into(),
            timestamp_unix_ms: 4,
            payload: Some(tunnel_server_frame::Payload::McpRequest(McpInvokeRequest {
                invocation_id: "inv-1".into(),
                server_name: "git-mcp".into(),
                tool_name: "status".into(),
                arguments_json: "{}".into(),
                timeout_seconds: 15,
            })),
        })
        .await
        .unwrap();

    let client_rec = rx.recv().await.unwrap();
    assert_eq!(client_rec.frame_id, "mcp-req-1");

    // 5. McpInvokeResponse (Client -> Server)
    tx.send(TunnelClientFrame {
        frame_id: "mcp-res-1".into(),
        timestamp_unix_ms: 5,
        agent_id: "agent-all-types".into(),
        payload: Some(tunnel_client_frame::Payload::McpResponse(
            McpInvokeResponse {
                invocation_id: "inv-1".into(),
                success: true,
                result_json: "{\"clean\": true}".into(),
                error_message: String::new(),
            },
        )),
    })
    .await
    .unwrap();

    let rec = server.recv_client_frame().await.unwrap();
    assert_eq!(rec.frame_id, "mcp-res-1");

    // 6. ApprovalRequest (Client -> Server)
    tx.send(TunnelClientFrame {
        frame_id: "appr-req-1".into(),
        timestamp_unix_ms: 6,
        agent_id: "agent-all-types".into(),
        payload: Some(tunnel_client_frame::Payload::ApprovalRequest(
            ApprovalRequest {
                request_id: "appr-1".into(),
                action_type: "exec".into(),
                description: "Run rm -rf target".into(),
                details_json: "{}".into(),
                requested_by: "planner".into(),
                created_at_unix: 1700000000,
            },
        )),
    })
    .await
    .unwrap();

    let rec = server.recv_client_frame().await.unwrap();
    assert_eq!(rec.frame_id, "appr-req-1");

    // 7. ApprovalResponse (Server -> Client)
    server
        .send_server_frame(TunnelServerFrame {
            frame_id: "appr-res-1".into(),
            timestamp_unix_ms: 7,
            payload: Some(tunnel_server_frame::Payload::ApprovalResponse(
                ApprovalResponse {
                    request_id: "appr-1".into(),
                    approved: true,
                    reason: "Authorized by admin".into(),
                    approved_by: "admin@example.com".into(),
                    responded_at_unix: 1700000005,
                },
            )),
        })
        .await
        .unwrap();

    let client_rec = rx.recv().await.unwrap();
    assert_eq!(client_rec.frame_id, "appr-res-1");

    handle.close().await;
    server.stop().await;
}
