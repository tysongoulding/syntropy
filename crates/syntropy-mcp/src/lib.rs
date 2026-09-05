//! Syntropy MCP: Model Context Protocol supervisor, tool allowlist proxy, and JSON-RPC bridge.

pub mod protocol;
pub mod proxy;
pub mod supervisor;

pub use protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, CIRCUIT_BREAKER_OPEN, INTERNAL_ERROR,
    INVALID_PARAMS, INVALID_REQUEST, METHOD_NOT_FOUND, PARSE_ERROR, REQUEST_TIMEOUT,
    TOOL_FORBIDDEN,
};

pub use proxy::{CircuitBreaker, CircuitBreakerConfig, CircuitState, McpProxy, ToolAllowlist};

pub use supervisor::{McpError, McpServerConfig, McpSupervisor};

fn default_true() -> bool {
    true
}

fn default_allowlist() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_command_timeout_secs() -> u64 {
    120
}

/// Global MCP configuration as declared in `.syntropy.toml`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct McpConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_allowlist")]
    pub allowlist: Vec<String>,
    #[serde(default = "default_command_timeout_secs")]
    pub command_timeout_secs: u64,
}

impl Default for McpConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            allowlist: default_allowlist(),
            command_timeout_secs: 120,
        }
    }
}
