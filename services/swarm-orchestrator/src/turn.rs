use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use syntropy_proto::tunnel::{
    self, AgentMessage, ApplyPatch, ExecCommand, McpInvokeRequest, TunnelServerFrame, UserPrompt,
};
use tracing::info;

use crate::gemini::{ChatMessage, GeminiClient, GeminiTurnResult};

/// Represents the actions and messages resulting from an evaluated user prompt.
#[derive(Debug, Clone)]
pub struct TurnExecutionPlan {
    pub prompt_id: String,
    pub agent_message: AgentMessage,
    pub server_frames_to_send: Vec<TunnelServerFrame>,
    pub is_dev_mock: bool,
}

/// Turn engine executing an agent turn using Gemini.
#[derive(Clone)]
pub struct AgentTurnEngine {
    gemini: Arc<GeminiClient>,
    sessions: Arc<Mutex<HashMap<String, Vec<ChatMessage>>>>,
}

impl AgentTurnEngine {
    pub fn new(gemini: Arc<GeminiClient>) -> Self {
        Self {
            gemini,
            sessions: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Retrieve conversation history for a given session.
    pub async fn get_session_history(&self, session_id: &str) -> Vec<ChatMessage> {
        let guard = self.sessions.lock().await;
        guard.get(session_id).cloned().unwrap_or_default()
    }

    /// Clear conversation history for a session.
    pub async fn clear_session(&self, session_id: &str) {
        let mut guard = self.sessions.lock().await;
        guard.remove(session_id);
    }

    /// Process an incoming UserPrompt and generate appropriate agent messages and tool action frames.
    pub async fn process_prompt(
        &self,
        prompt: &UserPrompt,
        agent_id: &str,
    ) -> Result<TurnExecutionPlan, anyhow::Error> {
        info!(
            prompt_id = %prompt.prompt_id,
            session_id = %prompt.session_id,
            agent_id = %agent_id,
            dev_mock = self.gemini.is_dev_mock(),
            "Processing user prompt through Gemini Turn Engine"
        );

        let host_platform = if cfg!(windows) {
            "Windows (use cmd.exe /c or powershell.exe for builtins like dir, or native binaries like cargo, git)"
        } else {
            "Unix / Linux (sh, bash, ls, git, cargo)"
        };

        let system_directive = format!(
            "You are an autonomous engineering agent connected to host workspace via Syntropy.\n\
             Host Operating System: {host_platform}\n\
             Agent ID: {agent_id}\n\
             You have access to tools:\n\
             - 'exec_command': run shell commands inside the virtual PTY sandbox. On Linux X11 environments, desktop automation tools like 'xdotool' (e.g. 'DISPLAY=:1 xdotool mousemove/click/type') and 'scrot' are available.\n\
             - 'apply_patch': apply atomic diffs to files.\n\
             - 'browser_action': control Chrome over CDP. Actions: 'navigate', 'screenshot', 'get_content', 'click' (supports CSS selector or visible text/label), 'type' (types into inputs or contenteditable fields), 'press' (keyboard events e.g. 'Enter'), 'evaluate' (JavaScript).\n\
             Always formulate valid executable commands or browser actions."
        );

        let history = if !prompt.session_id.is_empty() {
            let guard = self.sessions.lock().await;
            guard.get(&prompt.session_id).cloned().unwrap_or_default()
        } else {
            Vec::new()
        };

        let result: GeminiTurnResult = self
            .gemini
            .generate_turn(&prompt.text, Some(&system_directive), &history)
            .await?;

        // Record history if session_id is present
        if !prompt.session_id.is_empty() {
            let mut guard = self.sessions.lock().await;
            let hist = guard.entry(prompt.session_id.clone()).or_default();
            hist.push(ChatMessage {
                role: "user".into(),
                text: prompt.text.clone(),
            });
            if !result.content.is_empty() {
                hist.push(ChatMessage {
                    role: "model".into(),
                    text: result.content.clone(),
                });
            }
        }

        let mut server_frames = Vec::new();
        let mut tool_names = Vec::new();

        for tc in &result.tool_calls {
            tool_names.push(tc.name.clone());

            match tc.name.as_str() {
                "exec_command" => {
                    let cmd_str = tc.args.get("command").and_then(|v| v.as_str()).unwrap_or("dir");
                    let args_list: Vec<String> = tc
                        .args
                        .get("args")
                        .and_then(|v| v.as_array())
                        .map(|arr| arr.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                        .unwrap_or_default();

                    let exec = ExecCommand {
                        command_id: format!("cmd-{}", uuid::Uuid::new_v4()),
                        command: cmd_str.to_string(),
                        args: args_list,
                        working_dir: String::new(),
                        env: Default::default(),
                        timeout_seconds: 30,
                        pty: true,
                        pty_rows: 24,
                        pty_cols: 80,
                    };

                    server_frames.push(TunnelServerFrame {
                        frame_id: uuid::Uuid::new_v4().to_string(),
                        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                        payload: Some(tunnel::tunnel_server_frame::Payload::ExecCommand(exec)),
                    });
                }
                "apply_patch" => {
                    let file_path = tc.args.get("file_path").and_then(|v| v.as_str()).unwrap_or("output.txt");
                    let diff = tc.args.get("diff").and_then(|v| v.as_str()).unwrap_or("");

                    let patch = ApplyPatch {
                        patch_id: format!("patch-{}", uuid::Uuid::new_v4()),
                        file_path: file_path.to_string(),
                        diff: diff.to_string(),
                        expected_sha256: String::new(),
                        dry_run: false,
                    };

                    server_frames.push(TunnelServerFrame {
                        frame_id: uuid::Uuid::new_v4().to_string(),
                        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                        payload: Some(tunnel::tunnel_server_frame::Payload::ApplyPatch(patch)),
                    });
                }
                "browser_action" => {
                    let mcp_req = McpInvokeRequest {
                        invocation_id: format!("browser-{}", uuid::Uuid::new_v4()),
                        server_name: "browser".to_string(),
                        tool_name: "browser_action".to_string(),
                        arguments_json: tc.args.to_string(),
                        timeout_seconds: 30,
                    };

                    server_frames.push(TunnelServerFrame {
                        frame_id: uuid::Uuid::new_v4().to_string(),
                        timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
                        payload: Some(tunnel::tunnel_server_frame::Payload::McpRequest(mcp_req)),
                    });
                }
                _ => {}
            }
        }

        let agent_message = AgentMessage {
            turn_id: format!("turn-{}", uuid::Uuid::new_v4()),
            content: result.content,
            tool_calls: tool_names,
            is_final: true,
        };

        // Always include the AgentMessage frame
        server_frames.push(TunnelServerFrame {
            frame_id: uuid::Uuid::new_v4().to_string(),
            timestamp_unix_ms: chrono::Utc::now().timestamp_millis(),
            payload: Some(tunnel::tunnel_server_frame::Payload::AgentMessage(agent_message.clone())),
        });

        Ok(TurnExecutionPlan {
            prompt_id: prompt.prompt_id.clone(),
            agent_message,
            server_frames_to_send: server_frames,
            is_dev_mock: result.is_dev_mock,
        })
    }
}
