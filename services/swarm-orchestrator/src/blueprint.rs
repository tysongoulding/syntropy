use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentTier {
    Tier1Planner,
    Tier2Architect,
    Tier3Implementer,
    Tier4Reviewer,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersonaBlueprint {
    pub id: String,
    pub name: String,
    pub tier: AgentTier,
    pub system_directive: String,
    pub input_deliverables: Vec<String>,
    pub output_deliverables: Vec<String>,
}

impl PersonaBlueprint {
    pub fn standard_federation() -> Vec<Self> {
        vec![
            Self {
                id: "planner-lead".into(),
                name: "Sprint Executive Planner".into(),
                tier: AgentTier::Tier1Planner,
                system_directive: "Analyze user objective, break into atomic work packages, identify risks, and publish blackboard://plan.md".into(),
                input_deliverables: vec![],
                output_deliverables: vec!["blackboard://plan.md".into()],
            },
            Self {
                id: "architect-lead".into(),
                name: "Systems Architect".into(),
                tier: AgentTier::Tier2Architect,
                system_directive: "Read blackboard://plan.md, formulate precise file diffs and command specifications, and publish blackboard://spec.json".into(),
                input_deliverables: vec!["blackboard://plan.md".into()],
                output_deliverables: vec!["blackboard://spec.json".into()],
            },
            Self {
                id: "code-implementer".into(),
                name: "Code Implementer".into(),
                tier: AgentTier::Tier3Implementer,
                system_directive: "Read blackboard://spec.json, apply atomic file patches, and run builds inside an isolated agent worktree".into(),
                input_deliverables: vec!["blackboard://spec.json".into()],
                output_deliverables: vec!["blackboard://build_result.json".into()],
            },
            Self {
                id: "qa-reviewer".into(),
                name: "Quality Assurance Reviewer".into(),
                tier: AgentTier::Tier4Reviewer,
                system_directive: "Execute test suites via PTY terminal screen, verify linter clean status, and publish blackboard://qa_report.md".into(),
                input_deliverables: vec!["blackboard://build_result.json".into()],
                output_deliverables: vec!["blackboard://qa_report.md".into()],
            },
        ]
    }
}
