use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

use syntropy_tunnel::{TunnelClient, TunnelConfig};

use crate::config::AppConfig;
use crate::orchestrator::Orchestrator;

pub struct DaemonService {
    config: AppConfig,
    workspace_root: PathBuf,
    agent_id: String,
}

impl DaemonService {
    pub fn new(workspace_root: PathBuf, config: AppConfig) -> Self {
        let agent_id = format!("daemon-{}", uuid::Uuid::new_v4());
        Self {
            config,
            workspace_root,
            agent_id,
        }
    }

    pub async fn run(self) -> Result<(), anyhow::Error> {
        #[cfg(target_os = "linux")]
        {
            let cgroup_path = std::path::Path::new("/sys/fs/cgroup/agent/cgroup.procs");
            if cgroup_path.exists() {
                let pid = std::process::id();
                let _ = std::fs::write(cgroup_path, format!("{}\n", pid));
            }
        }

        info!("Starting Syntropy Daemon service for workspace: {:?}", self.workspace_root);
        info!("Connecting outbound tunnel to: {}", self.config.daemon.server_url);

        let tunnel_config = TunnelConfig::new(&self.config.daemon.server_url, &self.agent_id)
            .with_heartbeat_interval(Some(Duration::from_secs(self.config.daemon.heartbeat_interval_secs)))
            .with_reconnect_policy(
                Duration::from_millis(500),
                Duration::from_secs(self.config.daemon.reconnect_max_backoff_secs),
                1.5,
                None,
            );

        let mut tunnel = TunnelClient::start(tunnel_config)?;
        let client_tx = tunnel.sender();

        let orchestrator = Arc::new(Orchestrator::new(
            self.agent_id.clone(),
            self.workspace_root.clone(),
            &self.config,
            client_tx,
        )?);

        info!("Syntropy Daemon initialized and listening for gateway instructions.");

        while let Some(server_frame) = tunnel.recv().await {
            let orch = orchestrator.clone();
            tokio::spawn(async move {
                orch.handle_frame(server_frame).await;
            });
        }

        info!("Tunnel stream closed. Shutting down daemon service.");
        Ok(())
    }
}
