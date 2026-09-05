# Syntropy

**Cross-Platform Autonomous Cloud Agent System**

Syntropy is a local-first, cloud-orchestrated autonomous agent system. It pairs an outbound-only persistent TLS gRPC tunnel with a native headless Rust daemon running on Windows, macOS, and Linux. It delivers multi-agent concurrent workspaces, independent virtual PTY screens, zero-knowledge credential brokering, canonical path jailing, and a cryptographically verified SQLite Merkle audit ledger.

---

## 🏗️ Monorepo Organization

```text
syntropy/
├── Cargo.toml                    # Workspace manifest
├── .syntropy.toml                # Project & runtime configuration
├── crates/                       # Shared Core & Application Track
│   ├── syntropy-proto/           # Protobuf definitions & Tonic gRPC codegen
│   ├── syntropy-tunnel/          # Outbound gRPC connection manager & MockGatewayServer
│   ├── syntropy-exec/            # Virtual PTY mux (portable-pty), path jail, atomic diffs, worktrees
│   ├── syntropy-security/        # Windows DPAPI / Keystore, inverted credential broker, Merkle SQLite ledger
│   ├── syntropy-mcp/             # MCP child-process supervisor & capability allowlist proxy
│   ├── syntropy-daemon/          # Background daemon service & instruction orchestrator
│   └── syntropy-cli/             # CLI binary (`syntropy dev-server`, `syntropy daemon`, `syntropy doctor`)
└── services/                     # Cloud Track (Control Plane & Swarm Brain)
    ├── gateway/                  # Edge ingress gateway managing agent tunnels & stream multiplexing
    └── swarm-orchestrator/       # 4-tier swarm workflow engine, phase gates & Blackboard store
```

---

## ☁️ Cloud Track Subsystems

1. **Edge Ingress Gateway (`services/gateway`)**
   - Implements `AgentTunnelServiceServer` over Tonic gRPC.
   - Accepts outbound connections from local daemons without requiring open inbound ports or public IPs on client workstations.
   - `SessionRegistry`: Maps active agent connections, routing commands, patches, approvals, and terminal frames bidirectionally.

2. **Swarm Orchestrator & Blackboard Store (`services/swarm-orchestrator`)**
   - **Blackboard Store**: Content-addressed, versioned artifact repository (`blackboard://...`) with author-isolated write ACLs and SHA-256 deliverable verification.
   - **4-Tier Persona Federation**: Standard blueprints for Sprint Planner, Systems Architect, Code Implementer, and QA Reviewer.
   - **Sprint State Machine**: Coordinates phase transitions (`Planning` $\to$ `PhaseGate` $\to$ `Implementation` $\to$ `Review` $\to$ `Completed`), with phase-gate backtrack support upon human rejection.

---

## 💻 Application Track Subsystems

1. **Virtual PTY Multiplexer (`crates/syntropy-exec`)**
   - Cross-platform terminal virtualization powered by `portable-pty` with native Windows ConPTY support.
   - Spawns independent agent screens (`screen_id`), broadcast ANSI streaming, and circular in-memory ring buffers for history scrollback.

2. **Workspace Containment & Atomic Patching (`crates/syntropy-exec`)**
   - `WorkspaceJail`: Canonical path verification (`canonicalize`) preventing traversal attacks (`../`, symlinks, junctions).
   - `AtomicPatchApplicator`: Pre-commit content SHA-256 verification and shadow-swap ACID atomic replacements.
   - `WorktreeManager`: Ephemeral Git worktrees (`.syntropy/worktrees/<agent_id>`) for collision-free concurrent agent builds.

3. **Security & Cryptographic Audit (`crates/syntropy-security`)**
   - **Hardware Keystore**: Native Windows DPAPI integration and encrypted software fallbacks.
   - **Inverted Credential Broker**: Local token injection and signing so cloud agents never possess raw credentials.
   - **Merkle Audit Ledger**: Append-only SQLite ledger with SHA-256 Merkle chain verification for non-repudiation.

---

## 🚀 Quickstart & Verification

### 1. Build and Run Workspace Tests
```bash
cargo test --workspace
```
Executes all 44 unit and integration tests across both Cloud and Application tracks.

### 2. Run Closed-Loop End-to-End Testbed
```bash
cargo run -p syntropy-cli -- dev-server --auto-verify
```
Starts an in-process mock cloud gateway, connects the local daemon, and executes an automated end-to-end multi-agent test:
- Concurrent PTY command dispatch across Agent 1 & Agent 2 screens.
- Atomic file patch application.
- MCP tool invocation.
- Dual-channel signed approval handling.
- Audit ledger hash verification.

### 3. Run the Cloud Gateway
```bash
cargo run -p syntropy-gateway -- --bind 0.0.0.0:50051
```

### 4. Run the Swarm Orchestrator
```bash
cargo run -p syntropy-orchestrator -- --objective "Build auth service"
```

### 5. System Diagnostics & Audit Inspection
```bash
cargo run -p syntropy-cli -- doctor
cargo run -p syntropy-cli -- audit
```
