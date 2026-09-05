use std::sync::Arc;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;

use crate::blackboard::{BlackboardError, BlackboardStore};

#[derive(Debug, Error)]
pub enum WorkflowError {
    #[error("Blackboard error: {0}")]
    Blackboard(#[from] BlackboardError),
    #[error("Invalid state transition: cannot transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: SprintPhase,
        to: SprintPhase,
    },
    #[error("Sprint halted at Phase Gate: {0}")]
    PhaseGateBlocked(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SprintPhase {
    Initialization,
    Planning,
    PhaseGateAwaitingApproval,
    Implementation,
    Review,
    Completed,
    Failed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SprintState {
    pub sprint_id: String,
    pub objective: String,
    pub phase: SprintPhase,
    pub approval_token: Option<String>,
    pub rejection_feedback: Option<String>,
}

pub struct SprintWorkflow {
    state: Arc<RwLock<SprintState>>,
    blackboard: Arc<BlackboardStore>,
}

impl SprintWorkflow {
    pub fn new(sprint_id: String, objective: String, blackboard: Arc<BlackboardStore>) -> Self {
        let state = SprintState {
            sprint_id,
            objective,
            phase: SprintPhase::Initialization,
            approval_token: None,
            rejection_feedback: None,
        };

        Self {
            state: Arc::new(RwLock::new(state)),
            blackboard,
        }
    }

    pub async fn current_phase(&self) -> SprintPhase {
        self.state.read().await.phase
    }

    pub async fn approval_token(&self) -> Option<String> {
        self.state.read().await.approval_token.clone()
    }

    pub async fn start_planning(&self) -> Result<(), WorkflowError> {
        let mut st = self.state.write().await;
        if st.phase != SprintPhase::Initialization {
            return Err(WorkflowError::InvalidTransition {
                from: st.phase,
                to: SprintPhase::Planning,
            });
        }
        st.phase = SprintPhase::Planning;
        Ok(())
    }

    pub async fn submit_plan(&self, plan_content: &[u8]) -> Result<(), WorkflowError> {
        self.blackboard
            .publish("blackboard://plan.md", "planner-lead", plan_content.to_vec())
            .await?;

        let mut st = self.state.write().await;
        st.phase = SprintPhase::PhaseGateAwaitingApproval;
        st.approval_token = Some(uuid::Uuid::new_v4().to_string());
        Ok(())
    }

    pub async fn approve_phase_gate(&self, token: &str) -> Result<(), WorkflowError> {
        let mut st = self.state.write().await;
        if st.phase != SprintPhase::PhaseGateAwaitingApproval {
            return Err(WorkflowError::InvalidTransition {
                from: st.phase,
                to: SprintPhase::Implementation,
            });
        }

        if let Some(ref expected) = st.approval_token {
            if expected == token {
                st.phase = SprintPhase::Implementation;
                st.approval_token = None;
                return Ok(());
            }
        }

        Err(WorkflowError::PhaseGateBlocked("Invalid approval token".into()))
    }

    pub async fn reject_and_backtrack(&self, feedback: String) -> Result<(), WorkflowError> {
        let mut st = self.state.write().await;
        st.rejection_feedback = Some(feedback);
        st.phase = SprintPhase::Planning;
        st.approval_token = None;
        Ok(())
    }

    pub async fn complete_implementation(&self, build_result: &[u8]) -> Result<(), WorkflowError> {
        self.blackboard
            .publish("blackboard://build_result.json", "code-implementer", build_result.to_vec())
            .await?;

        let mut st = self.state.write().await;
        st.phase = SprintPhase::Review;
        Ok(())
    }

    pub async fn finish_review(&self, qa_report: &[u8], success: bool) -> Result<(), WorkflowError> {
        self.blackboard
            .publish("blackboard://qa_report.md", "qa-reviewer", qa_report.to_vec())
            .await?;

        let mut st = self.state.write().await;
        st.phase = if success {
            SprintPhase::Completed
        } else {
            SprintPhase::Failed
        };
        Ok(())
    }
}
