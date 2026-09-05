use std::time::Duration;
use tokio::sync::{mpsc, watch};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tracing::{debug, error, info, warn};

use syntropy_proto::tunnel::{
    agent_tunnel_service_client::AgentTunnelServiceClient,
    tunnel_client_frame, Heartbeat, TunnelClientFrame, TunnelServerFrame,
};

use crate::error::{Result, TunnelError};

/// Configuration options for the gRPC tunnel client.
#[derive(Clone, Debug)]
pub struct TunnelConfig {
    pub server_url: String,
    pub agent_id: String,
    pub auth_token: Option<String>,
    pub initial_reconnect_delay: Duration,
    pub max_reconnect_delay: Duration,
    pub backoff_factor: f64,
    pub max_reconnect_attempts: Option<usize>,
    pub heartbeat_interval: Option<Duration>,
    pub channel_capacity: usize,
    pub connect_timeout: Duration,
    pub tls_config: Option<ClientTlsConfig>,
}

impl TunnelConfig {
    pub fn new(server_url: impl Into<String>, agent_id: impl Into<String>) -> Self {
        Self {
            server_url: server_url.into(),
            agent_id: agent_id.into(),
            auth_token: None,
            initial_reconnect_delay: Duration::from_millis(500),
            max_reconnect_delay: Duration::from_secs(30),
            backoff_factor: 1.5,
            max_reconnect_attempts: None,
            heartbeat_interval: Some(Duration::from_secs(10)),
            channel_capacity: 1024,
            connect_timeout: Duration::from_secs(10),
            tls_config: None,
        }
    }

    pub fn with_auth_token(mut self, token: impl Into<String>) -> Self {
        self.auth_token = Some(token.into());
        self
    }

    pub fn with_reconnect_policy(
        mut self,
        initial: Duration,
        max: Duration,
        factor: f64,
        max_attempts: Option<usize>,
    ) -> Self {
        self.initial_reconnect_delay = initial;
        self.max_reconnect_delay = max;
        self.backoff_factor = factor;
        self.max_reconnect_attempts = max_attempts;
        self
    }

    pub fn with_heartbeat_interval(mut self, interval: Option<Duration>) -> Self {
        self.heartbeat_interval = interval;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = timeout;
        self
    }

    pub fn with_tls_config(mut self, tls: ClientTlsConfig) -> Self {
        self.tls_config = Some(tls);
        self
    }

    pub fn with_channel_capacity(mut self, capacity: usize) -> Self {
        self.channel_capacity = capacity;
        self
    }
}

/// Handle to control and monitor a running tunnel client.
pub struct TunnelHandle {
    connected_rx: watch::Receiver<bool>,
    shutdown_tx: Option<watch::Sender<bool>>,
    task_handle: Option<tokio::task::JoinHandle<()>>,
}

impl TunnelHandle {
    /// Returns true if the tunnel client is currently connected.
    pub fn is_connected(&self) -> bool {
        *self.connected_rx.borrow()
    }

    /// Waits until the tunnel client is connected or timeout expires.
    pub async fn wait_connected(&self, timeout: Duration) -> Result<()> {
        if self.is_connected() {
            return Ok(());
        }

        let mut rx = self.connected_rx.clone();
        let wait_fut = async {
            while rx.changed().await.is_ok() {
                if *rx.borrow() {
                    return Ok(());
                }
            }
            Err(TunnelError::ConnectionClosed)
        };

        tokio::time::timeout(timeout, wait_fut)
            .await
            .map_err(|_| TunnelError::Timeout(timeout))?
    }

    /// Gracefully stops the background reconnection worker and waits for it to complete.
    pub async fn close(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        if let Some(handle) = self.task_handle.take() {
            let _ = handle.await;
        }
    }
}

impl Drop for TunnelHandle {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
    }
}

/// A gRPC bi-directional tunnel client with automatic TLS configuration,
/// exponential backoff reconnection, and bi-directional frame channels.
pub struct TunnelClient {
    tx: mpsc::Sender<TunnelClientFrame>,
    rx: mpsc::Receiver<TunnelServerFrame>,
    handle: TunnelHandle,
}

impl TunnelClient {
    /// Starts the tunnel client and waits for the initial connection to be established.
    pub async fn connect(config: TunnelConfig) -> Result<Self> {
        let timeout = config.connect_timeout;
        let client = Self::start(config)?;
        client.wait_connected(timeout).await?;
        Ok(client)
    }

    /// Starts the tunnel client in the background without blocking on the initial connection.
    pub fn start(config: TunnelConfig) -> Result<Self> {
        let capacity = config.channel_capacity;
        let (outbound_tx, outbound_rx) = mpsc::channel::<TunnelClientFrame>(capacity);
        let (inbound_tx, inbound_rx) = mpsc::channel::<TunnelServerFrame>(capacity);
        let (connected_tx, connected_rx) = watch::channel(false);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);

        let task_handle = tokio::spawn(run_tunnel_worker(
            config,
            outbound_rx,
            inbound_tx,
            connected_tx,
            shutdown_rx,
        ));

        let handle = TunnelHandle {
            connected_rx,
            shutdown_tx: Some(shutdown_tx),
            task_handle: Some(task_handle),
        };

        Ok(Self {
            tx: outbound_tx,
            rx: inbound_rx,
            handle,
        })
    }

    /// Sends a client frame over the tunnel.
    /// If disconnected, frames are queued in memory up to `channel_capacity`
    /// and sent once reconnected.
    pub async fn send(&self, frame: TunnelClientFrame) -> Result<()> {
        self.tx
            .send(frame)
            .await
            .map_err(|e| TunnelError::Send(e.to_string()))
    }

    /// Attempts to send a frame without blocking.
    pub fn try_send(&self, frame: TunnelClientFrame) -> Result<()> {
        self.tx
            .try_send(frame)
            .map_err(|e| TunnelError::Send(e.to_string()))
    }

    /// Receives the next incoming server frame.
    pub async fn recv(&mut self) -> Option<TunnelServerFrame> {
        self.rx.recv().await
    }

    /// Clones the outbound sender.
    pub fn sender(&self) -> mpsc::Sender<TunnelClientFrame> {
        self.tx.clone()
    }

    /// Obtains a mutable reference to the inbound receiver.
    pub fn receiver(&mut self) -> &mut mpsc::Receiver<TunnelServerFrame> {
        &mut self.rx
    }

    /// Returns true if the client is currently connected.
    pub fn is_connected(&self) -> bool {
        self.handle.is_connected()
    }

    /// Waits until the client is connected or timeout expires.
    pub async fn wait_connected(&self, timeout: Duration) -> Result<()> {
        self.handle.wait_connected(timeout).await
    }

    /// Splits the client into sending/receiving channels and a management handle.
    pub fn split(
        self,
    ) -> (
        mpsc::Sender<TunnelClientFrame>,
        mpsc::Receiver<TunnelServerFrame>,
        TunnelHandle,
    ) {
        (self.tx, self.rx, self.handle)
    }

    /// Gracefully closes the tunnel client.
    pub async fn close(self) {
        self.handle.close().await;
    }
}

/// Worker loop managing the outbound stream and exponential backoff reconnection.
async fn run_tunnel_worker(
    config: TunnelConfig,
    mut outbound_rx: mpsc::Receiver<TunnelClientFrame>,
    inbound_tx: mpsc::Sender<TunnelServerFrame>,
    connected_tx: watch::Sender<bool>,
    mut shutdown_rx: watch::Receiver<bool>,
) {
    let mut current_delay = config.initial_reconnect_delay;
    let mut attempts: usize = 0;
    let mut pending_frame: Option<TunnelClientFrame> = None;
    let mut heartbeat_seq: i64 = 0;

    loop {
        if *shutdown_rx.borrow() {
            info!("Tunnel worker shutdown requested");
            break;
        }

        if let Some(max_attempts) = config.max_reconnect_attempts {
            if attempts >= max_attempts {
                error!(
                    attempts,
                    max_attempts, "Max reconnect attempts reached; stopping tunnel worker"
                );
                break;
            }
        }

        attempts += 1;
        debug!(
            attempt = attempts,
            url = %config.server_url,
            "Attempting to establish gRPC tunnel connection"
        );

        // 1. Establish Channel
        let channel = match create_channel(&config).await {
            Ok(ch) => ch,
            Err(err) => {
                warn!(
                    attempt = attempts,
                    error = %err,
                    delay_ms = current_delay.as_millis(),
                    "Failed to connect to gateway endpoint; backing off"
                );
                tokio::select! {
                    _ = tokio::time::sleep(current_delay) => {
                        current_delay = (current_delay.mul_f64(config.backoff_factor)).min(config.max_reconnect_delay);
                        continue;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                        continue;
                    }
                }
            }
        };

        // 2. Open bidirectional stream
        let mut grpc_client = AgentTunnelServiceClient::new(channel);
        let (conn_tx, conn_rx) = mpsc::channel::<TunnelClientFrame>(config.channel_capacity);
        let outbound_stream = ReceiverStream::new(conn_rx);

        let mut request = tonic::Request::new(outbound_stream);
        if let Some(token) = &config.auth_token {
            if let Ok(meta_val) = token.parse() {
                request.metadata_mut().insert("authorization", meta_val);
            }
        }
        if let Ok(meta_val) = config.agent_id.parse() {
            request.metadata_mut().insert("x-agent-id", meta_val);
        }

        let response = match grpc_client.open_tunnel(request).await {
            Ok(res) => res,
            Err(status) => {
                warn!(
                    attempt = attempts,
                    status = %status,
                    delay_ms = current_delay.as_millis(),
                    "OpenTunnel gRPC call rejected; backing off"
                );
                tokio::select! {
                    _ = tokio::time::sleep(current_delay) => {
                        current_delay = (current_delay.mul_f64(config.backoff_factor)).min(config.max_reconnect_delay);
                        continue;
                    }
                    _ = shutdown_rx.changed() => {
                        if *shutdown_rx.borrow() { break; }
                        continue;
                    }
                }
            }
        };

        // Connection established successfully
        info!(
            agent_id = %config.agent_id,
            url = %config.server_url,
            "Tunnel stream established successfully"
        );
        let _ = connected_tx.send(true);
        current_delay = config.initial_reconnect_delay;
        attempts = 0;

        // Transmit buffered pending frame if available
        if let Some(frame) = pending_frame.take() {
            if let Err(e) = conn_tx.send(frame).await {
                pending_frame = Some(e.0);
            }
        }

        let mut inbound_stream = response.into_inner();
        let mut heartbeat_ticker = config.heartbeat_interval.map(|interval| {
            let mut ticker = tokio::time::interval(interval);
            ticker.reset();
            ticker
        });

        let mut stream_active = true;
        while stream_active {
            tokio::select! {
                _ = shutdown_rx.changed() => {
                    if *shutdown_rx.borrow() {
                        info!("Shutdown signal received during active stream");
                        break;
                    }
                }

                // Inbound server frame
                inbound_msg = inbound_stream.message() => {
                    match inbound_msg {
                        Ok(Some(server_frame)) => {
                            if inbound_tx.send(server_frame).await.is_err() {
                                info!("Inbound receiver dropped; terminating tunnel");
                                let _ = connected_tx.send(false);
                                return;
                            }
                        }
                        Ok(None) => {
                            warn!("Server closed tunnel stream (EOF)");
                            stream_active = false;
                        }
                        Err(status) => {
                            warn!(status = %status, "Server stream error occurred");
                            stream_active = false;
                        }
                    }
                }

                // Outbound client frame from user
                outbound_msg = outbound_rx.recv() => {
                    match outbound_msg {
                        Some(client_frame) => {
                            if let Err(e) = conn_tx.send(client_frame).await {
                                warn!("Stream connection broken during send; buffering frame for reconnect");
                                pending_frame = Some(e.0);
                                stream_active = false;
                            }
                        }
                        None => {
                            info!("Outbound sender dropped by application; closing tunnel");
                            let _ = connected_tx.send(false);
                            return;
                        }
                    }
                }

                // Periodic heartbeat
                _ = async {
                    match &mut heartbeat_ticker {
                        Some(ticker) => {
                            ticker.tick().await;
                        }
                        None => {
                            futures::future::pending::<()>().await;
                        }
                    }
                } => {
                    heartbeat_seq += 1;
                    let now_ms = chrono::Utc::now().timestamp_millis();
                    let heartbeat_frame = TunnelClientFrame {
                        frame_id: uuid::Uuid::new_v4().to_string(),
                        timestamp_unix_ms: now_ms,
                        agent_id: config.agent_id.clone(),
                        payload: Some(tunnel_client_frame::Payload::Heartbeat(Heartbeat {
                            sequence: heartbeat_seq,
                            timestamp_unix_ms: now_ms,
                            agent_id: config.agent_id.clone(),
                            is_ack: false,
                        })),
                    };

                    if let Err(e) = conn_tx.send(heartbeat_frame).await {
                        warn!("Failed to send heartbeat over active stream; connection broken");
                        pending_frame = Some(e.0);
                        stream_active = false;
                    }
                }
            }
        }

        let _ = connected_tx.send(false);
        info!(
            delay_ms = current_delay.as_millis(),
            "Tunnel disconnected; waiting before reconnect attempt"
        );

        tokio::select! {
            _ = tokio::time::sleep(current_delay) => {
                current_delay = (current_delay.mul_f64(config.backoff_factor)).min(config.max_reconnect_delay);
            }
            _ = shutdown_rx.changed() => {
                if *shutdown_rx.borrow() {
                    break;
                }
            }
        }
    }

    let _ = connected_tx.send(false);
}

/// Creates a tonic Channel configured with timeouts and TLS if appropriate.
async fn create_channel(config: &TunnelConfig) -> Result<Channel> {
    let endpoint = Endpoint::from_shared(config.server_url.clone())
        .map_err(|e| TunnelError::Config(format!("Invalid server URL '{}': {}", config.server_url, e)))?
        .connect_timeout(config.connect_timeout);

    let endpoint = if let Some(ref tls) = config.tls_config {
        endpoint
            .tls_config(tls.clone())
            .map_err(TunnelError::Transport)?
    } else if config.server_url.starts_with("https://") {
        let tls = ClientTlsConfig::new().with_native_roots();
        endpoint
            .tls_config(tls)
            .map_err(TunnelError::Transport)?
    } else {
        endpoint
    };

    let channel = endpoint.connect().await?;
    Ok(channel)
}
