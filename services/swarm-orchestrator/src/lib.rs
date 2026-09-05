pub mod blackboard;
pub mod blueprint;
pub mod workflow;

pub use blackboard::{Artifact, BlackboardError, BlackboardStore};
pub use blueprint::{AgentTier, PersonaBlueprint};
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
}
