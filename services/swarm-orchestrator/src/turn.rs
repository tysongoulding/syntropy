use std::sync::Arc;
use syntropy_proto::tunnel::{
    self, AgentMessage, ApplyPatch, ExecCommand, TunnelServerFrame, UserPrompt,
};
use tracing::info;

use crate::gemini::{GeminiClient, GeminiTurnResult};

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
}

impl AgentTurnEngine {
    pub fn new(gemini: Arc<GeminiClient>) -> Self {
        Self { gemini }
    }

    /// Process an incoming UserPrompt and generate appropriate agent messages and tool action frames.
    pub async fn process_prompt(
        &self,
        prompt: &UserPrompt,
        agent_id: &str,
    ) -> Result<TurnExecutionPlan, anyhow::Error> {
        info!(
            prompt_id = %prompt.prompt_id,
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
             You have access to tools: 'exec_command' (run commands inside the canonical virtual PTY sandbox) and 'apply_patch' (apply atomic diffs).\n\
             Always formulate valid executable commands for the host operating system."
        );

        let result: GeminiTurnResult = self
            .gemini
            .generate_turn(&prompt.text, Some(&system_directive), &[])
            .await?;

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
                _ => {}
            }
        }

        let agent_message = AgentMessage {
            turn_id: format!("turn-{}", uuid::Uuid::new_v4()),
            content: result.content,
            tool_calls: tool_names,
            is_final: server_frames.is_empty(),
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
