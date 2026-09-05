use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{mpsc, watch, Mutex};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use syntropy_proto::tunnel::agent_tunnel_service_server::AgentTunnelServiceServer;
use syntropy_proto::tunnel::TunnelClientFrame;

use crate::service::GatewayTunnelService;
use crate::session::SessionRegistry;

/// Handle for a running in-process or managed Gateway server.
pub struct GatewayServerHandle {
    pub addr: SocketAddr,
    pub registry: Arc<SessionRegistry>,
    pub client_frame_rx: Arc<Mutex<mpsc::Receiver<TunnelClientFrame>>>,
    shutdown_tx: watch::Sender<bool>,
}

impl GatewayServerHandle {
    /// Binds an ephemeral local TCP port (`127.0.0.1:0`) and starts the gateway service.
    pub async fn bind_ephemeral() -> Result<Self, anyhow::Error> {
        Self::bind("127.0.0.1:0").await
    }

    /// Binds to a specific address and starts the gateway service.
    pub async fn bind(addr_str: &str) -> Result<Self, anyhow::Error> {
        let listener = tokio::net::TcpListener::bind(addr_str).await?;
        let addr = listener.local_addr()?;
        let stream = TcpListenerStream::new(listener);

        let registry = Arc::new(SessionRegistry::new());
        let (client_frame_tx, client_frame_rx) = mpsc::channel(256);
        let service = GatewayTunnelService::new(registry.clone(), Some(client_frame_tx));

        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

        tokio::spawn(async move {
            let _ = Server::builder()
                .add_service(AgentTunnelServiceServer::new(service))
                .serve_with_incoming_shutdown(stream, async move {
                    let _ = shutdown_rx.changed().await;
                })
                .await;
        });

        Ok(Self {
            addr,
            registry,
            client_frame_rx: Arc::new(Mutex::new(client_frame_rx)),
            shutdown_tx,
        })
    }

    /// Returns the HTTP URL of the bound gateway.
    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Receives the next incoming client frame forwarded by the gateway.
    pub async fn recv_client_frame(&self) -> Option<TunnelClientFrame> {
        let mut rx = self.client_frame_rx.lock().await;
        rx.recv().await
    }

    /// Triggers graceful shutdown of the gateway server.
    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(true);
    }
}
