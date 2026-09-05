use std::collections::HashMap;
use std::sync::Arc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;

#[derive(Debug, Error)]
pub enum BlackboardError {
    #[error("Artifact not found: {0}")]
    NotFound(String),
    #[error("Permission denied: agent '{agent}' is not authorized to modify '{uri}' (owner is '{owner}')")]
    AccessDenied {
        agent: String,
        uri: String,
        owner: String,
    },
    #[error("Invalid deliverable URI: {0} (must start with blackboard://)")]
    InvalidUri(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub uri: String,
    pub author_agent: String,
    pub version: u32,
    pub content: Vec<u8>,
    pub sha256: String,
    pub created_at_unix_ms: i64,
}

#[derive(Default)]
pub struct BlackboardStore {
    artifacts: Arc<RwLock<HashMap<String, Vec<Artifact>>>>,
}

impl BlackboardStore {
    pub fn new() -> Self {
        Self {
            artifacts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Publish or update an artifact under a deterministic `blackboard://...` URI.
    pub async fn publish(
        &self,
        uri: &str,
        author_agent: &str,
        content: Vec<u8>,
    ) -> Result<Artifact, BlackboardError> {
        if !uri.starts_with("blackboard://") {
            return Err(BlackboardError::InvalidUri(uri.to_string()));
        }

        let mut hasher = Sha256::new();
        hasher.update(&content);
        let sha256 = hex::encode(hasher.finalize());

        let mut map = self.artifacts.write().await;
        let history = map.entry(uri.to_string()).or_default();

        let version = if let Some(latest) = history.last() {
            if latest.author_agent != author_agent && !author_agent.starts_with("lead_") {
                return Err(BlackboardError::AccessDenied {
                    agent: author_agent.to_string(),
                    uri: uri.to_string(),
                    owner: latest.author_agent.clone(),
                });
            }
            latest.version + 1
        } else {
            1
        };

        let artifact = Artifact {
            uri: uri.to_string(),
            author_agent: author_agent.to_string(),
            version,
            content,
            sha256,
            created_at_unix_ms: chrono::Utc::now().timestamp_millis(),
        };
        history.push(artifact.clone());
        Ok(artifact)
    }

    /// Read the latest version of an artifact by URI.
    pub async fn get_latest(&self, uri: &str) -> Result<Artifact, BlackboardError> {
        let map = self.artifacts.read().await;
        map.get(uri)
            .and_then(|h| h.last().cloned())
            .ok_or_else(|| BlackboardError::NotFound(uri.to_string()))
    }

    /// Read all active artifact URIs and versions.
    pub async fn list_manifest(&self) -> Vec<(String, u32, String)> {
        let map = self.artifacts.read().await;
        map.iter()
            .filter_map(|(uri, history)| {
                history
                    .last()
                    .map(|latest| (uri.clone(), latest.version, latest.sha256.clone()))
            })
            .collect()
    }
}
