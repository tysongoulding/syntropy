use std::sync::Arc;
use clap::Parser;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

use syntropy_orchestrator::{BlackboardStore, PersonaBlueprint, SprintWorkflow};

#[derive(Parser, Debug)]
#[command(name = "syntropy-orchestrator")]
#[command(about = "Syntropy Swarm Orchestrator: Multi-agent durable workflow engine and Blackboard store")]
struct Args {
    #[arg(short, long, default_value = "sprint-demo")]
    sprint_id: String,

    #[arg(short, long, default_value = "Autonomous Sprint Target")]
    objective: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let args = Args::parse();

    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .with_target(false)
        .compact()
        .finish();
    tracing::subscriber::set_global_default(subscriber).ok();

    info!("🚀 Syntropy Swarm Orchestrator Engine Initialized");
    info!("🎯 Objective: {}", args.objective);

    let blueprints = PersonaBlueprint::standard_federation();
    info!("👥 Active Federation Roster ({} Personas):", blueprints.len());
    for bp in &blueprints {
        info!("   - [{:?}] {}: {}", bp.tier, bp.name, bp.system_directive);
    }

    let blackboard = Arc::new(BlackboardStore::new());
    let workflow = SprintWorkflow::new(args.sprint_id, args.objective, blackboard);

    info!("🏁 Sprint workflow initialized in phase: {:?}", workflow.current_phase().await);
    Ok(())
}
