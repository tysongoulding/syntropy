use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status, Streaming};
use tracing::{debug, info};

use syntropy_proto::tunnel::{
    agent_tunnel_service_server::{AgentTunnelService, AgentTunnelServiceServer},
    tunnel_client_frame, tunnel_server_frame, AgentMessage, ApplyPatch, ExecCommand, Heartbeat,
    TunnelClientFrame, TunnelServerFrame,
};

use crate::error::{Result, TunnelError};

type ServerFrameSender = mpsc::Sender<std::result::Result<TunnelServerFrame, Status>>;

/// Internal service state implementing `AgentTunnelService`.
struct MockTunnelServiceImpl {
    client_frame_tx: mpsc::Sender<TunnelClientFrame>,
    recorded_frames: Arc<Mutex<Vec<TunnelClientFrame>>>,
    client_senders: Arc<Mutex<Vec<ServerFrameSender>>>,
    auto_heartbeat_ack: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
    connection_notify: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl AgentTunnelService for MockTunnelServiceImpl {
    type OpenTunnelStream = ReceiverStream<std::result::Result<TunnelServerFrame, Status>>;

    async fn open_tunnel(
        &self,
        request: Request<Streaming<TunnelClientFrame>>,
    ) -> std::result::Result<Response<Self::OpenTunnelStream>, Status> {
        let (outbound_tx, outbound_rx) = mpsc::channel(128);
        {
            let mut senders = self.client_senders.lock().await;
            senders.push(outbound_tx.clone());
        }

        self.active_connections.fetch_add(1, Ordering::SeqCst);
        self.connection_notify.notify_waiters();
        info!("MockGatewayServer: client stream opened");

        let mut in_stream = request.into_inner();
        let client_frame_tx = self.client_frame_tx.clone();
        let recorded_frames = self.recorded_frames.clone();
        let client_senders = self.client_senders.clone();
        let auto_ack = self.auto_heartbeat_ack.clone();
        let active_connections = self.active_connections.clone();
        let ack_sender = outbound_tx.clone();

        tokio::spawn(async move {
            while let Ok(Some(client_frame)) = in_stream.message().await {
                debug!(frame_id = %client_frame.frame_id, "MockGatewayServer: received client frame");

                // Record in history
                {
                    let mut rec = recorded_frames.lock().await;
                    rec.push(client_frame.clone());
                }

                // Auto-acknowledge heartbeat if enabled
                if auto_ack.load(Ordering::SeqCst) {
                    if let Some(tunnel_client_frame::Payload::Heartbeat(ref hb)) = client_frame.payload {
                        if !hb.is_ack {
                            let ack_frame = TunnelServerFrame {
                                frame_id: uuid::Uuid::new_v4().to_string(),
                                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                                payload: Some(tunnel_server_frame::Payload::Heartbeat(Heartbeat {
                                    sequence: hb.sequence,
                                    timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                                    agent_id: hb.agent_id.clone(),
                                    is_ack: true,
                                })),
                            };
                            let _ = ack_sender.send(Ok(ack_frame)).await;
                        }
                    }
                }

                // Auto-handle UserPrompt in mock mode
                if let Some(tunnel_client_frame::Payload::UserPrompt(ref prompt)) = client_frame.payload {
                    let p_lower = prompt.text.to_lowercase();
                    let prompt_text = prompt.text.clone();
                    let responder = ack_sender.clone();

                    tokio::spawn(async move {
                        if p_lower.contains("patch") || p_lower.contains("edit") {
                            let patch = ApplyPatch {
                                patch_id: format!("patch-{}", uuid::Uuid::new_v4()),
                                file_path: "mock_patch.txt".into(),
                                diff: "@@ -0,0 +1,1 @@\n+Mock patch content\n".into(),
                                expected_sha256: String::new(),
                                dry_run: false,
                            };
                            let _ = responder.send(Ok(TunnelServerFrame {
                                frame_id: uuid::Uuid::new_v4().to_string(),
                                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                                payload: Some(tunnel_server_frame::Payload::ApplyPatch(patch)),
                            })).await;
                        } else {
                            #[cfg(windows)]
                            let (cmd, args) = ("cmd.exe".to_string(), vec!["/c".to_string(), "dir".to_string()]);
                            #[cfg(not(windows))]
                            let (cmd, args) = ("sh".to_string(), vec!["-c".to_string(), "ls -la".to_string()]);

                            let exec = ExecCommand {
                                command_id: format!("cmd-{}", uuid::Uuid::new_v4()),
                                command: cmd,
                                args,
                                working_dir: String::new(),
                                env: std::collections::HashMap::new(),
                                timeout_seconds: 15,
                                pty: true,
                                pty_rows: 24,
                                pty_cols: 80,
                            };
                            let _ = responder.send(Ok(TunnelServerFrame {
                                frame_id: uuid::Uuid::new_v4().to_string(),
                                timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                                payload: Some(tunnel_server_frame::Payload::ExecCommand(exec)),
                            })).await;
                        }

                        let agent_msg = AgentMessage {
                            turn_id: format!("turn-{}", uuid::Uuid::new_v4()),
                            content: format!("Syntropy Mock Gateway: Swarm executed turn for prompt: '{}'", prompt_text),
                            tool_calls: vec!["exec_command".into()],
                            is_final: true,
                        };
                        let _ = responder.send(Ok(TunnelServerFrame {
                            frame_id: uuid::Uuid::new_v4().to_string(),
                            timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                            payload: Some(tunnel_server_frame::Payload::AgentMessage(agent_msg)),
                        })).await;
                    });
                }

                // Forward to test receiver
                let _ = client_frame_tx.send(client_frame).await;
            }

            info!("MockGatewayServer: client stream closed");
            active_connections.fetch_sub(1, Ordering::SeqCst);

            // Clean up closed senders
            let mut senders = client_senders.lock().await;
            senders.retain(|s| !s.is_closed());
        });

        Ok(Response::new(ReceiverStream::new(outbound_rx)))
    }
}

/// In-process mock gateway server implementing `AgentTunnelService`
/// for local integration testing and offline development.
pub struct MockGatewayServer {
    addr: SocketAddr,
    client_frame_rx: Arc<Mutex<mpsc::Receiver<TunnelClientFrame>>>,
    recorded_frames: Arc<Mutex<Vec<TunnelClientFrame>>>,
    client_senders: Arc<Mutex<Vec<ServerFrameSender>>>,
    auto_heartbeat_ack: Arc<AtomicBool>,
    active_connections: Arc<AtomicUsize>,
    connection_notify: Arc<tokio::sync::Notify>,
    shutdown_tx: Option<watch::Sender<bool>>,
    server_task: Option<tokio::task::JoinHandle<()>>,
}

impl MockGatewayServer {
    /// Binds an ephemeral local TCP port (`127.0.0.1:0`) and starts the mock gateway server.
    pub async fn start() -> Result<Self> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let addr = listener.local_addr()?;
        let stream = TcpListenerStream::new(listener);

        let (client_frame_tx, client_frame_rx) = mpsc::channel(256);
        let recorded_frames = Arc::new(Mutex::new(Vec::new()));
        let client_senders = Arc::new(Mutex::new(Vec::new()));
        let auto_heartbeat_ack = Arc::new(AtomicBool::new(true));
        let active_connections = Arc::new(AtomicUsize::new(0));
        let connection_notify = Arc::new(tokio::sync::Notify::new());

        let service = MockTunnelServiceImpl {
            client_frame_tx,
            recorded_frames: recorded_frames.clone(),
            client_senders: client_senders.clone(),
            auto_heartbeat_ack: auto_heartbeat_ack.clone(),
            active_connections: active_connections.clone(),
            connection_notify: connection_notify.clone(),
        };

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        let server_task = tokio::spawn(async move {
            let server = Server::builder().add_service(AgentTunnelServiceServer::new(service));
            let _ = server
                .serve_with_incoming_shutdown(stream, async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });

        info!(%addr, "MockGatewayServer listening");

        Ok(Self {
            addr,
            client_frame_rx: Arc::new(Mutex::new(client_frame_rx)),
            recorded_frames,
            client_senders,
            auto_heartbeat_ack,
            active_connections,
            connection_notify,
            shutdown_tx: Some(shutdown_tx),
            server_task: Some(server_task),
        })
    }

    /// Returns the bound socket address.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Returns the URL string (e.g. `http://127.0.0.1:12345`).
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Sends a `TunnelServerFrame` down to all connected clients.
    pub async fn send_server_frame(&self, frame: TunnelServerFrame) -> Result<()> {
        let senders = self.client_senders.lock().await;
        if senders.is_empty() {
            return Err(TunnelError::ConnectionClosed);
        }
        for sender in senders.iter() {
            let _ = sender.send(Ok(frame.clone())).await;
        }
        Ok(())
    }

    /// Receives the next frame transmitted by any connected client.
    pub async fn recv_client_frame(&self) -> Option<TunnelClientFrame> {
        self.client_frame_rx.lock().await.recv().await
    }

    /// Returns a copy of all recorded client frames received so far.
    pub async fn recorded_frames(&self) -> Vec<TunnelClientFrame> {
        self.recorded_frames.lock().await.clone()
    }

    /// Clears the recorded frames history.
    pub async fn clear_recorded_frames(&self) {
        self.recorded_frames.lock().await.clear();
    }

    /// Enables or disables automatic acknowledgment of heartbeat frames.
    pub fn set_auto_heartbeat_ack(&self, enabled: bool) {
        self.auto_heartbeat_ack.store(enabled, Ordering::SeqCst);
    }

    /// Returns the number of currently active client connections.
    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::SeqCst)
    }

    /// Waits until at least one client has connected, or timeout expires.
    pub async fn wait_for_connection(&self, timeout: Duration) -> Result<()> {
        if self.active_connections() > 0 {
            return Ok(());
        }

        let notify = self.connection_notify.clone();
        let wait_fut = async {
            loop {
                notify.notified().await;
                if self.active_connections() > 0 {
                    return Ok(());
                }
            }
        };

        tokio::time::timeout(timeout, wait_fut)
            .await
            .map_err(|_| TunnelError::Timeout(timeout))?
    }

    /// Simulates a server-side disconnect by dropping all active client streams.
    /// This causes the client's gRPC stream to receive EOF, triggering reconnection logic.
    pub async fn disconnect_clients(&self) {
        let mut senders = self.client_senders.lock().await;
        senders.clear();
        info!("MockGatewayServer: dropped all client senders (simulating disconnect)");
    }

    /// Shuts down the mock gateway server.
    pub async fn stop(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(task) = self.server_task.take() {
            let _ = task.await;
        }
        info!("MockGatewayServer stopped");
    }
}

impl Drop for MockGatewayServer {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}
