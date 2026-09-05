use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{mpsc, RwLock};
use tracing::{info, warn};

use syntropy_proto::tunnel::TunnelServerFrame;

type FrameSender = mpsc::Sender<Result<TunnelServerFrame, tonic::Status>>;

#[derive(Debug, Clone)]
pub struct AgentSession {
    pub agent_id: String,
    pub connected_at_unix_ms: i64,
}

#[derive(Default)]
pub struct SessionRegistry {
    sessions: Arc<RwLock<HashMap<String, (AgentSession, FrameSender)>>>,
}

impl SessionRegistry {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn register(&self, agent_id: String, sender: FrameSender) {
        let session = AgentSession {
            agent_id: agent_id.clone(),
            connected_at_unix_ms: chrono::Utc::now().timestamp_millis(),
        };
        let mut map = self.sessions.write().await;
        info!(agent_id = %agent_id, "Agent tunnel session registered in gateway");
        map.insert(agent_id, (session, sender));
    }

    pub async fn unregister(&self, agent_id: &str) {
        let mut map = self.sessions.write().await;
        if map.remove(agent_id).is_some() {
            info!(agent_id = %agent_id, "Agent tunnel session unregistered from gateway");
        }
    }

    pub async fn send_to_agent(&self, agent_id: &str, frame: TunnelServerFrame) -> Result<(), String> {
        let map = self.sessions.read().await;
        if let Some((_, sender)) = map.get(agent_id) {
            sender
                .send(Ok(frame))
                .await
                .map_err(|e| format!("Failed to send frame to agent {}: {}", agent_id, e))
        } else {
            Err(format!("Agent session not found for id: {}", agent_id))
        }
    }

    pub async fn broadcast(&self, frame: TunnelServerFrame) {
        let map = self.sessions.read().await;
        for (agent_id, (_, sender)) in map.iter() {
            if let Err(e) = sender.send(Ok(frame.clone())).await {
                warn!(agent_id = %agent_id, error = %e, "Broadcast failed to agent");
            }
        }
    }

    pub async fn active_agents(&self) -> Vec<AgentSession> {
        let map = self.sessions.read().await;
        map.values().map(|(s, _)| s.clone()).collect()
    }
}
