use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tracing::{debug, info, warn};

/// Gemini model configuration.
#[derive(Debug, Clone)]
pub struct GeminiConfig {
    pub api_key: String,
    pub model: String,
    pub endpoint: String,
    pub is_dev_mock: bool,
}

impl Default for GeminiConfig {
    fn default() -> Self {
        Self {
            api_key: String::new(),
            model: "gemini-3.8-flash".into(),
            endpoint: "https://generativelanguage.googleapis.com/v1beta/models".into(),
            is_dev_mock: false,
        }
    }
}

/// Chat message exchanged in a conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String, // "user", "model", "system"
    pub text: String,
}

/// Extracted tool call from Gemini function calling.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GeminiToolCall {
    pub name: String,
    pub args: serde_json::Value,
}

/// Result of a Gemini turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeminiTurnResult {
    pub content: String,
    pub tool_calls: Vec<GeminiToolCall>,
    pub finish_reason: String,
    pub is_dev_mock: bool,
}

/// Gemini API Client supporting both real REST calls and offline Dev Mock mode.
#[derive(Clone)]
pub struct GeminiClient {
    config: GeminiConfig,
    http_client: Client,
}

impl GeminiClient {
    /// Initialize with given API key and model name.
    pub fn new(api_key: impl Into<String>, model: impl Into<String>) -> Self {
        let key = api_key.into();
        let is_dev_mock = key.is_empty() || key == "mock" || key == "dev";
        Self {
            config: GeminiConfig {
                api_key: key,
                model: model.into(),
                is_dev_mock,
                ..Default::default()
            },
            http_client: Client::builder().build().unwrap_or_default(),
        }
    }

    /// Construct a Dev Mock client for offline, zero-network testing.
    pub fn dev_mock() -> Self {
        Self {
            config: GeminiConfig {
                api_key: "dev_mock_key".into(),
                model: "gemini-flash-latest-dev-mock".into(),
                is_dev_mock: true,
                ..Default::default()
            },
            http_client: Client::builder().build().unwrap_or_default(),
        }
    }

    /// Create client from `GEMINI_API_KEY` environment variable, falling back to Dev Mock if absent.
    pub fn from_env() -> Self {
        let model = std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-3.8-flash".to_string());
        match std::env::var("GEMINI_API_KEY") {
            Ok(key) if !key.trim().is_empty() => {
                info!("GeminiClient: using API key from GEMINI_API_KEY environment variable (model: {})", model);
                Self::new(key.trim(), model)
            }
            _ => {
                info!("GeminiClient: no GEMINI_API_KEY found, initializing in offline Dev Mock mode");
                Self::dev_mock()
            }
        }
    }

    /// Create client with an explicit API key and optional model override.
    pub fn with_api_key(key: impl Into<String>, model: Option<String>) -> Self {
        let m = model.unwrap_or_else(|| {
            std::env::var("GEMINI_MODEL").unwrap_or_else(|_| "gemini-3.8-flash".to_string())
        });
        Self::new(key, m)
    }

    /// Returns true if running in offline Dev Mock mode.
    pub fn is_dev_mock(&self) -> bool {
        self.config.is_dev_mock
    }

    /// Returns the active model identifier.
    pub fn model(&self) -> &str {
        &self.config.model
    }

    /// Executes a reasoning and generation turn with Gemini.
    pub async fn generate_turn(
        &self,
        prompt: &str,
        system_instruction: Option<&str>,
        history: &[ChatMessage],
    ) -> Result<GeminiTurnResult, anyhow::Error> {
        if self.config.is_dev_mock {
            return self.generate_dev_mock_turn(prompt);
        }

        let url = format!(
            "{}/{}:generateContent?key={}",
            self.config.endpoint, self.config.model, self.config.api_key
        );

        let mut contents = Vec::new();
        for msg in history {
            let role = if msg.role == "assistant" { "model" } else { &msg.role };
            contents.push(json!({
                "role": role,
                "parts": [{ "text": msg.text }]
            }));
        }
        contents.push(json!({
            "role": "user",
            "parts": [{ "text": prompt }]
        }));

        let mut body = json!({
            "contents": contents,
            "tools": [{
                "functionDeclarations": [
                    {
                        "name": "exec_command",
                        "description": "Execute a shell command inside the user's isolated virtual PTY jail",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "command": { "type": "string", "description": "Binary or shell executable to run" },
                                "args": { "type": "array", "items": { "type": "string" }, "description": "Command line arguments" }
                            },
                            "required": ["command"]
                        }
                    },
                    {
                        "name": "apply_patch",
                        "description": "Apply a unified diff atomically to a repository file",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "file_path": { "type": "string", "description": "Relative path to target file" },
                                "diff": { "type": "string", "description": "Unified diff payload" }
                            },
                            "required": ["file_path", "diff"]
                        }
                    },
                    {
                        "name": "browser_action",
                        "description": "Perform web browsing, page navigation, inspection, and screenshot capture in the user's local Chrome browser via Chrome DevTools Protocol (CDP)",
                        "parameters": {
                            "type": "object",
                            "properties": {
                                "action": {
                                    "type": "string",
                                    "enum": ["navigate", "screenshot", "get_content", "click", "type", "press", "evaluate"],
                                    "description": "Action to perform: 'navigate' to load a URL, 'screenshot' to capture page image, 'get_content' to read page text, 'click' to click an element (supports CSS selector or text/label), 'type' to type text into an input/textarea/editable element, 'press' to simulate key press (e.g. 'Enter'), 'evaluate' to run arbitrary JS"
                                },
                                "url": { "type": "string", "description": "URL to navigate to (e.g. 'https://www.google.com')" },
                                "selector": { "type": "string", "description": "CSS selector or element text/label to click or type into" },
                                "text": { "type": "string", "description": "Text to type, key to press, or JavaScript to evaluate" }
                            },
                            "required": ["action"]
                        }
                    }
                ]
            }]
        });

        if let Some(sys) = system_instruction {
            body["systemInstruction"] = json!({
                "parts": [{ "text": sys }]
            });
        }

        debug!(url = %url, "Sending generateContent request to Gemini API");

        let res = self
            .http_client
            .post(&url)
            .json(&body)
            .send()
            .await?;

        if !res.status().is_success() {
            let status = res.status();
            let err_text = res.text().await.unwrap_or_else(|_| "Unknown error".into());
            warn!(status = %status, error = %err_text, "Gemini API request failed");
            return Err(anyhow::anyhow!("Gemini API error ({}): {}", status, err_text));
        }

        let json_resp: serde_json::Value = res.json().await?;
        Self::parse_gemini_response(json_resp)
    }

    /// Deterministic offline dev mock generator.
    fn generate_dev_mock_turn(&self, prompt: &str) -> Result<GeminiTurnResult, anyhow::Error> {
        let p_lower = prompt.to_lowercase();
        let mut tool_calls = Vec::new();
        let content = if p_lower.contains("list") || p_lower.contains("file") || p_lower.contains("dir") {
            #[cfg(windows)]
            let (cmd, args): (&str, Vec<String>) = ("cmd.exe", vec!["/c".to_string(), "dir".to_string()]);
            #[cfg(not(windows))]
            let (cmd, args): (&str, Vec<String>) = ("ls", vec!["-la".to_string()]);

            tool_calls.push(GeminiToolCall {
                name: "exec_command".into(),
                args: json!({
                    "command": cmd,
                    "args": args
                }),
            });
            format!("Syntropy Dev Mock: Executing workspace listing for prompt: '{}'", prompt)
        } else if p_lower.contains("patch") || p_lower.contains("edit") {
            tool_calls.push(GeminiToolCall {
                name: "apply_patch".into(),
                args: json!({
                    "file_path": "dev_patch.txt",
                    "diff": "@@ -0,0 +1,1 @@\n+Dev patch line\n"
                }),
            });
            "Syntropy Dev Mock: Applying mock patch.".into()
        } else if p_lower.contains("browse") || p_lower.contains("web") || p_lower.contains("chrome") || p_lower.contains("http") || p_lower.contains("google") {
            let target_url = if p_lower.contains("ycombinator") || p_lower.contains("hacker") {
                "https://news.ycombinator.com"
            } else if p_lower.contains("google") {
                "https://www.google.com"
            } else {
                "https://github.com"
            };

            tool_calls.push(GeminiToolCall {
                name: "browser_action".into(),
                args: json!({
                    "action": "navigate",
                    "url": target_url
                }),
            });
            format!("Syntropy Dev Mock: Navigating to '{}' via Chrome CDP.", target_url)
        } else {
            format!("Syntropy Dev Mock: Received prompt '{}'. Swarm reasoning complete.", prompt)
        };

        Ok(GeminiTurnResult {
            content,
            tool_calls,
            finish_reason: "STOP".into(),
            is_dev_mock: true,
        })
    }

    /// Parses Gemini raw JSON response into structured turn result.
    fn parse_gemini_response(val: serde_json::Value) -> Result<GeminiTurnResult, anyhow::Error> {
        let candidate = val["candidates"]
            .as_array()
            .and_then(|arr| arr.first())
            .ok_or_else(|| anyhow::anyhow!("No candidate in Gemini response: {}", val))?;

        let finish_reason = candidate["finishReason"]
            .as_str()
            .unwrap_or("STOP")
            .to_string();

        let mut text_parts = Vec::new();
        let mut tool_calls = Vec::new();

        if let Some(parts) = candidate["content"]["parts"].as_array() {
            for part in parts {
                if let Some(txt) = part["text"].as_str() {
                    text_parts.push(txt.to_string());
                }
                if let Some(fc) = part["functionCall"].as_object() {
                    let name = fc.get("name").and_then(|n| n.as_str()).unwrap_or_default().to_string();
                    let args = fc.get("args").cloned().unwrap_or(json!({}));
                    if !name.is_empty() {
                        tool_calls.push(GeminiToolCall { name, args });
                    }
                }
            }
        }

        Ok(GeminiTurnResult {
            content: text_parts.join("\n"),
            tool_calls,
            finish_reason,
            is_dev_mock: false,
        })
    }
}
