use std::net::SocketAddr;
use std::sync::Arc;
use clap::Parser;
use tonic::transport::Server;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use syntropy_gateway::{GatewayTunnelService, SessionRegistry};
use syntropy_proto::tunnel::agent_tunnel_service_server::AgentTunnelServiceServer;

#[derive(Parser, Debug)]
#[command(name = "syntropy-gateway")]
#[command(about = "Syntropy Edge Cloud Gateway: Ingress control plane for agent daemons")]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:50051")]
    bind: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    let addr: SocketAddr = args.bind.parse()?;
    let registry = Arc::new(SessionRegistry::new());
    let service = GatewayTunnelService::new(registry.clone(), None);

    info!("🚀 Syntropy Cloud Gateway starting on {}", addr);

    Server::builder()
        .add_service(AgentTunnelServiceServer::new(service))
        .serve(addr)
        .await?;

    Ok(())
}
