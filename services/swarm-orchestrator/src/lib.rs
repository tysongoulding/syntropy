pub mod blackboard;
pub mod blueprint;
pub mod gemini;
pub mod turn;
pub mod workflow;

pub use blackboard::{Artifact, BlackboardError, BlackboardStore};
pub use blueprint::{AgentTier, PersonaBlueprint};
pub use gemini::{ChatMessage, GeminiClient, GeminiConfig, GeminiToolCall, GeminiTurnResult};
pub use turn::{AgentTurnEngine, TurnExecutionPlan};
pub use workflow::{SprintPhase, SprintState, SprintWorkflow, WorkflowError};

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_blackboard_author_isolation() {
        let bb = BlackboardStore::new();

        // 1. Author publishes v1
        let art_v1 = bb
            .publish("blackboard://spec.json", "author-a", b"{\"v\": 1}".to_vec())
            .await
            .unwrap();
        assert_eq!(art_v1.version, 1);

        // 2. Different author cannot overwrite without lead permissions
        let err = bb
            .publish("blackboard://spec.json", "author-b", b"{\"v\": 2}".to_vec())
            .await;
        assert!(err.is_err(), "Non-owner should be denied");

        // 3. Same author can publish v2
        let art_v2 = bb
            .publish("blackboard://spec.json", "author-a", b"{\"v\": 2}".to_vec())
            .await
            .unwrap();
        assert_eq!(art_v2.version, 2);
    }

    #[tokio::test]
    async fn test_sprint_phase_gate_and_backtrack() {
        let bb = std::sync::Arc::new(BlackboardStore::new());
        let workflow = SprintWorkflow::new(
            "sprint-001".into(),
            "Build authentication subsystem".into(),
            bb.clone(),
        );

        assert_eq!(workflow.current_phase().await, SprintPhase::Initialization);

        workflow.start_planning().await.unwrap();
        assert_eq!(workflow.current_phase().await, SprintPhase::Planning);

        // Submit plan -> transitions to phase gate
        workflow.submit_plan(b"# Sprint Plan").await.unwrap();
        assert_eq!(
            workflow.current_phase().await,
            SprintPhase::PhaseGateAwaitingApproval
        );

        // Rejection backtracks to Planning
        workflow
            .reject_and_backtrack("Scope too broad".into())
            .await
            .unwrap();
        assert_eq!(workflow.current_phase().await, SprintPhase::Planning);

        // Resubmit and approve
        workflow.submit_plan(b"# Revised Sprint Plan").await.unwrap();
        let token = workflow.approval_token().await.unwrap();

        workflow.approve_phase_gate(&token).await.unwrap();
        assert_eq!(workflow.current_phase().await, SprintPhase::Implementation);

        // Complete implementation
        workflow
            .complete_implementation(b"{\"success\": true}")
            .await
            .unwrap();
        assert_eq!(workflow.current_phase().await, SprintPhase::Review);

        // Review passes
        workflow.finish_review(b"Tests pass", true).await.unwrap();
        assert_eq!(workflow.current_phase().await, SprintPhase::Completed);
    }

    #[tokio::test]
    async fn test_gemini_dev_mock_reasoning() {
        let client = GeminiClient::dev_mock();
        assert!(client.is_dev_mock());

        // Test listing command generation
        let res = client.generate_turn("List the files in the current repository", None, &[]).await.unwrap();
        assert!(res.is_dev_mock);
        assert_eq!(res.tool_calls.len(), 1);
        assert_eq!(res.tool_calls[0].name, "exec_command");

        // Test patch command generation
        let res_patch = client.generate_turn("Apply patch to config.json", None, &[]).await.unwrap();
        assert_eq!(res_patch.tool_calls.len(), 1);
        assert_eq!(res_patch.tool_calls[0].name, "apply_patch");
    }

    #[tokio::test]
    async fn test_gemini_turn_engine_dispatches_tool_frames() {
        let client = std::sync::Arc::new(GeminiClient::dev_mock());
        let engine = AgentTurnEngine::new(client);

        let prompt = syntropy_proto::tunnel::UserPrompt {
            prompt_id: "prompt-123".into(),
            text: "List files in directory".into(),
            session_id: "sess-abc".into(),
            context_files: Default::default(),
        };

        let plan = engine.process_prompt(&prompt, "test-agent").await.unwrap();
        assert_eq!(plan.prompt_id, "prompt-123");
        assert!(plan.is_dev_mock);
        assert!(!plan.server_frames_to_send.is_empty());
        assert_eq!(plan.agent_message.tool_calls, vec!["exec_command"]);
    }

    #[tokio::test]
    async fn test_agent_turn_engine_preserves_session_history() {
        let client = std::sync::Arc::new(GeminiClient::dev_mock());
        let engine = AgentTurnEngine::new(client);

        let p1 = syntropy_proto::tunnel::UserPrompt {
            prompt_id: "p1".into(),
            text: "Hello, this is Tyson".into(),
            session_id: "conv-1".into(),
            context_files: Default::default(),
        };
        let _ = engine.process_prompt(&p1, "agent").await.unwrap();

        let p2 = syntropy_proto::tunnel::UserPrompt {
            prompt_id: "p2".into(),
            text: "What tools do you have?".into(),
            session_id: "conv-1".into(),
            context_files: Default::default(),
        };
        let _ = engine.process_prompt(&p2, "agent").await.unwrap();

        let history = engine.get_session_history("conv-1").await;
        assert_eq!(history.len(), 4, "Should have 2 user prompts and 2 model turns recorded");
        assert_eq!(history[0].role, "user");
        assert_eq!(history[0].text, "Hello, this is Tyson");
        assert_eq!(history[1].role, "model");
        assert_eq!(history[2].role, "user");
        assert_eq!(history[2].text, "What tools do you have?");
        assert_eq!(history[3].role, "model");

        // Clearing session works
        engine.clear_session("conv-1").await;
        let cleared = engine.get_session_history("conv-1").await;
        assert!(cleared.is_empty());
    }
}

