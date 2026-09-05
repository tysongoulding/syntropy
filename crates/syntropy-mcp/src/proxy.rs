use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use crate::protocol::{
    JsonRpcError, JsonRpcRequest, JsonRpcResponse, CIRCUIT_BREAKER_OPEN, INVALID_PARAMS,
    PARSE_ERROR, REQUEST_TIMEOUT, TOOL_FORBIDDEN,
};
use crate::supervisor::{McpError, McpSupervisor};

/// Configurable allowlist for filtering MCP tool invocations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ToolAllowlist {
    patterns: Vec<String>,
}

impl ToolAllowlist {
    pub fn new(patterns: Vec<String>) -> Self {
        Self { patterns }
    }

    /// Allow all tools without restriction.
    pub fn allow_all() -> Self {
        Self {
            patterns: vec!["*".to_string()],
        }
    }

    /// Allow no tools by default.
    pub fn empty() -> Self {
        Self {
            patterns: Vec::new(),
        }
    }

    pub fn add_pattern(&mut self, pattern: impl Into<String>) {
        self.patterns.push(pattern.into());
    }

    pub fn remove_pattern(&mut self, pattern: &str) -> bool {
        let original_len = self.patterns.len();
        self.patterns.retain(|p| p != pattern);
        self.patterns.len() != original_len
    }

    pub fn patterns(&self) -> &[String] {
        &self.patterns
    }

    /// Check whether a specific tool name is permitted by the configured patterns.
    pub fn is_allowed(&self, tool_name: &str) -> bool {
        for pattern in &self.patterns {
            if pattern == "*" {
                return true;
            }
            if pattern == tool_name {
                return true;
            }
            if let Some(prefix) = pattern.strip_suffix('*') {
                if tool_name.starts_with(prefix) {
                    return true;
                }
            }
            if let Some(suffix) = pattern.strip_prefix('*') {
                if tool_name.ends_with(suffix) {
                    return true;
                }
            }
        }
        false
    }
}

/// Circuit state for protecting against hanging or broken MCP subprocesses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Configuration parameters for timeout circuits and failure thresholds.
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub reset_timeout: Duration,
    pub request_timeout: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 3,
            reset_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(30),
        }
    }
}

/// Circuit breaker tracking consecutive timeouts and failure states.
#[derive(Debug)]
pub struct CircuitBreaker {
    state: CircuitState,
    consecutive_failures: u32,
    failure_threshold: u32,
    reset_timeout: Duration,
    opened_at: Option<Instant>,
}

impl CircuitBreaker {
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            state: CircuitState::Closed,
            consecutive_failures: 0,
            failure_threshold: config.failure_threshold,
            reset_timeout: config.reset_timeout,
            opened_at: None,
        }
    }

    pub fn state(&self) -> CircuitState {
        self.state
    }

    pub fn consecutive_failures(&self) -> u32 {
        self.consecutive_failures
    }

    /// Determines if a request is allowed to proceed according to current circuit state.
    pub fn can_execute(&mut self) -> Result<(), McpError> {
        match self.state {
            CircuitState::Closed => Ok(()),
            CircuitState::Open => {
                if let Some(opened) = self.opened_at {
                    if opened.elapsed() >= self.reset_timeout {
                        tracing::info!("Circuit breaker transitioning from Open to HalfOpen (probing)");
                        self.state = CircuitState::HalfOpen;
                        return Ok(());
                    }
                }
                Err(McpError::CircuitBreakerOpen(
                    "Circuit breaker is open: MCP server is unresponsive".into(),
                ))
            }
            CircuitState::HalfOpen => Ok(()),
        }
    }

    pub fn record_success(&mut self) {
        if self.state != CircuitState::Closed {
            tracing::info!("Circuit breaker recovered to Closed");
        }
        self.state = CircuitState::Closed;
        self.consecutive_failures = 0;
        self.opened_at = None;
    }

    pub fn record_failure(&mut self) {
        self.consecutive_failures += 1;
        if self.state == CircuitState::HalfOpen || self.consecutive_failures >= self.failure_threshold {
            if self.state != CircuitState::Open {
                tracing::warn!(
                    "Circuit breaker tripped to Open after {} consecutive failures",
                    self.consecutive_failures
                );
            }
            self.state = CircuitState::Open;
            self.opened_at = Some(Instant::now());
        }
    }
}

/// McpProxy filters JSON-RPC calls against a configurable tool allowlist,
/// enforces timeout circuits, and forwards requests to the MCP supervisor or backend.
#[derive(Clone)]
pub struct McpProxy {
    allowlist: Arc<RwLock<ToolAllowlist>>,
    circuit_breaker: Arc<Mutex<CircuitBreaker>>,
    request_timeout: Duration,
}

impl McpProxy {
    pub fn new(
        allowlist: ToolAllowlist,
        request_timeout: Duration,
        cb_config: CircuitBreakerConfig,
    ) -> Self {
        Self {
            allowlist: Arc::new(RwLock::new(allowlist)),
            circuit_breaker: Arc::new(Mutex::new(CircuitBreaker::new(cb_config))),
            request_timeout,
        }
    }

    pub fn with_defaults(allowlist: ToolAllowlist) -> Self {
        let cb_config = CircuitBreakerConfig::default();
        Self::new(allowlist, cb_config.request_timeout, cb_config)
    }

    /// Access the underlying allowlist.
    pub fn allowlist(&self) -> Arc<RwLock<ToolAllowlist>> {
        self.allowlist.clone()
    }

    /// Check whether a JSON-RPC request is permitted by the allowlist.
    /// Returns Ok(()) if permitted, or Err(JsonRpcResponse) with an error payload if denied.
    #[allow(clippy::result_large_err)]
    pub async fn filter_request(&self, request: &JsonRpcRequest) -> Result<(), JsonRpcResponse> {
        if request.method == "tools/call" {
            let tool_name = match request.extract_tool_name() {
                Some(name) => name,
                None => {
                    return Err(JsonRpcResponse::error(
                        request.id.clone(),
                        JsonRpcError::new(INVALID_PARAMS, "Missing tool 'name' in tools/call parameters"),
                    ));
                }
            };

            let allowlist = self.allowlist.read().await;
            if !allowlist.is_allowed(tool_name) {
                return Err(JsonRpcResponse::error(
                    request.id.clone(),
                    JsonRpcError::new(
                        TOOL_FORBIDDEN,
                        format!("Tool '{tool_name}' is not permitted by allowlist"),
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Process and forward a JSON-RPC request through allowlist filtering,
    /// circuit breaker validation, and timeout protection.
    pub async fn forward_request<F, Fut>(
        &self,
        request: JsonRpcRequest,
        forwarder: F,
    ) -> Result<JsonRpcResponse, McpError>
    where
        F: FnOnce(JsonRpcRequest) -> Fut,
        Fut: std::future::Future<Output = Result<JsonRpcResponse, McpError>>,
    {
        // 1. Tool allowlist enforcement
        if let Err(forbidden_response) = self.filter_request(&request).await {
            return Ok(forbidden_response);
        }

        // 2. Circuit breaker check
        let req_id = request.id.clone();
        {
            let mut cb = self
                .circuit_breaker
                .lock()
                .map_err(|_| McpError::Other("Circuit breaker lock poisoned".into()))?;
            if cb.can_execute().is_err() {
                return Ok(JsonRpcResponse::error(
                    req_id,
                    JsonRpcError::new(
                        CIRCUIT_BREAKER_OPEN,
                        "Circuit breaker is open: MCP server is unresponsive",
                    ),
                ));
            }
        }

        // 3. Forward request with timeout circuit
        let timeout_duration = self.request_timeout;
        let fut = forwarder(request);

        match tokio::time::timeout(timeout_duration, fut).await {
            Ok(Ok(response)) => {
                let mut cb = self
                    .circuit_breaker
                    .lock()
                    .map_err(|_| McpError::Other("Circuit breaker lock poisoned".into()))?;
                cb.record_success();
                Ok(response)
            }
            Ok(Err(e)) => {
                let mut cb = self
                    .circuit_breaker
                    .lock()
                    .map_err(|_| McpError::Other("Circuit breaker lock poisoned".into()))?;
                cb.record_failure();
                Err(e)
            }
            Err(_) => {
                let mut cb = self
                    .circuit_breaker
                    .lock()
                    .map_err(|_| McpError::Other("Circuit breaker lock poisoned".into()))?;
                cb.record_failure();
                Ok(JsonRpcResponse::error(
                    req_id,
                    JsonRpcError::new(
                        REQUEST_TIMEOUT,
                        format!("Request timed out after {:?}", timeout_duration),
                    ),
                ))
            }
        }
    }

    /// Forward a structured request directly to an McpSupervisor instance.
    pub async fn handle_supervisor_request(
        &self,
        supervisor: &McpSupervisor,
        request: JsonRpcRequest,
    ) -> Result<JsonRpcResponse, McpError> {
        self.forward_request(request, |req| async move {
            supervisor.send_request(req).await
        })
        .await
    }

    /// Process a raw JSON-RPC string through the proxy and return the serialized JSON response.
    pub async fn handle_raw_json<F, Fut>(&self, raw_json: &str, forwarder: F) -> Result<String, McpError>
    where
        F: FnOnce(JsonRpcRequest) -> Fut,
        Fut: std::future::Future<Output = Result<JsonRpcResponse, McpError>>,
    {
        let request: JsonRpcRequest = match serde_json::from_str(raw_json) {
            Ok(req) => req,
            Err(e) => {
                let err_resp = JsonRpcResponse::error(
                    None,
                    JsonRpcError::new(PARSE_ERROR, format!("Parse error: {e}")),
                );
                return Ok(serde_json::to_string(&err_resp)?);
            }
        };

        let response = self.forward_request(request, forwarder).await?;
        Ok(serde_json::to_string(&response)?)
    }

    /// Process a raw JSON-RPC string directly using an McpSupervisor.
    pub async fn handle_supervisor_raw_json(
        &self,
        supervisor: &McpSupervisor,
        raw_json: &str,
    ) -> Result<String, McpError> {
        self.handle_raw_json(raw_json, |req| async move {
            supervisor.send_request(req).await
        })
        .await
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_allowlist_matching_and_wildcards() {
        let mut list = ToolAllowlist::new(vec!["fs_*".to_string(), "git:commit".to_string()]);

        assert!(list.is_allowed("fs_read"));
        assert!(list.is_allowed("fs_write"));
        assert!(list.is_allowed("git:commit"));
        assert!(!list.is_allowed("git:push"));
        assert!(!list.is_allowed("terminal_exec"));

        list.add_pattern("*");
        assert!(list.is_allowed("terminal_exec"));
    }

    #[tokio::test]
    async fn test_proxy_tool_allowlist_enforcement() {
        let allowlist = ToolAllowlist::new(vec!["read_file".to_string()]);
        let proxy = McpProxy::with_defaults(allowlist);

        // 1. Allowed tool call
        let allowed_req = JsonRpcRequest::tool_call(
            Some(serde_json::json!(1)),
            "read_file",
            serde_json::json!({"path": "foo.txt"}),
        );
        let resp = proxy
            .forward_request(allowed_req, |_| async {
                Ok(JsonRpcResponse::success(
                    Some(serde_json::json!(1)),
                    serde_json::json!({"content": "hello world"}),
                ))
            })
            .await
            .unwrap();

        assert!(resp.is_success());
        assert_eq!(
            resp.result.unwrap(),
            serde_json::json!({"content": "hello world"})
        );

        // 2. Disallowed tool call
        let blocked_req = JsonRpcRequest::tool_call(
            Some(serde_json::json!(2)),
            "delete_database",
            serde_json::json!({}),
        );
        let mut called = false;
        let blocked_resp = proxy
            .forward_request(blocked_req, |_| async {
                called = true;
                Ok(JsonRpcResponse::success(Some(serde_json::json!(2)), serde_json::json!({})))
            })
            .await
            .unwrap();

        assert!(!called, "Backend forwarder must NOT be called for blocked tools");
        assert!(blocked_resp.is_error());
        let err = blocked_resp.error.unwrap();
        assert_eq!(err.code, TOOL_FORBIDDEN);
        assert!(err.message.contains("Tool 'delete_database' is not permitted"));

        // 3. Non-tool call (e.g. tools/list or initialize) passes through
        let list_req = JsonRpcRequest::new(Some(serde_json::json!(3)), "tools/list", None);
        let list_resp = proxy
            .forward_request(list_req, |_| async {
                Ok(JsonRpcResponse::success(
                    Some(serde_json::json!(3)),
                    serde_json::json!({"tools": []}),
                ))
            })
            .await
            .unwrap();
        assert!(list_resp.is_success());
    }

    #[tokio::test]
    async fn test_proxy_timeout_circuit_and_breaker() {
        let allowlist = ToolAllowlist::allow_all();
        let cb_config = CircuitBreakerConfig {
            failure_threshold: 2,
            reset_timeout: Duration::from_millis(50),
            request_timeout: Duration::from_millis(20),
        };
        let proxy = McpProxy::new(allowlist, Duration::from_millis(20), cb_config);

        let slow_req = || JsonRpcRequest::new(Some(serde_json::json!(1)), "test/slow", None);

        // First timeout failure
        let r1 = proxy
            .forward_request(slow_req(), |_| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(JsonRpcResponse::success(None, serde_json::json!({})))
            })
            .await
            .unwrap();
        assert_eq!(r1.error.unwrap().code, REQUEST_TIMEOUT);

        // Second timeout failure -> trips circuit to Open
        let r2 = proxy
            .forward_request(slow_req(), |_| async {
                tokio::time::sleep(Duration::from_millis(50)).await;
                Ok(JsonRpcResponse::success(None, serde_json::json!({})))
            })
            .await
            .unwrap();
        assert_eq!(r2.error.unwrap().code, REQUEST_TIMEOUT);

        // Third request fails fast because circuit breaker is OPEN
        let mut executed = false;
        let r3 = proxy
            .forward_request(slow_req(), |_| async {
                executed = true;
                Ok(JsonRpcResponse::success(None, serde_json::json!({})))
            })
            .await
            .unwrap();

        assert!(!executed, "Should fail fast without executing backend");
        assert_eq!(r3.error.unwrap().code, CIRCUIT_BREAKER_OPEN);

        // Wait for reset_timeout
        tokio::time::sleep(Duration::from_millis(60)).await;

        // Next request enters HalfOpen and succeeds, recovering circuit to Closed
        let r4 = proxy
            .forward_request(slow_req(), |_| async {
                Ok(JsonRpcResponse::success(Some(serde_json::json!(1)), serde_json::json!("recovered")))
            })
            .await
            .unwrap();
        assert!(r4.is_success());
        assert_eq!(r4.result.unwrap(), "recovered");
    }

    #[tokio::test]
    async fn test_proxy_raw_json_message_passing() {
        let allowlist = ToolAllowlist::allow_all();
        let proxy = McpProxy::with_defaults(allowlist);

        let raw_req = r#"{"jsonrpc":"2.0","id":100,"method":"ping"}"#;
        let raw_resp = proxy
            .handle_raw_json(raw_req, |req| async move {
                assert_eq!(req.method, "ping");
                Ok(JsonRpcResponse::success(req.id, serde_json::json!("pong")))
            })
            .await
            .unwrap();

        let parsed: serde_json::Value = serde_json::from_str(&raw_resp).unwrap();
        assert_eq!(parsed["result"], "pong");
        assert_eq!(parsed["id"], 100);

        // Test invalid JSON string
        let invalid_raw = "{not valid json}";
        let err_resp = proxy
            .handle_raw_json(invalid_raw, |_| async { unreachable!() })
            .await
            .unwrap();
        let parsed_err: serde_json::Value = serde_json::from_str(&err_resp).unwrap();
        assert_eq!(parsed_err["error"]["code"], PARSE_ERROR);
    }
}
