# Syntropy

**Cross-Platform Autonomous Cloud Agent System**

Syntropy is a local-first, cloud-orchestrated autonomous agent system. It pairs an outbound-only persistent TLS gRPC tunnel with a native headless Rust daemon running on Windows, macOS, and Linux. It delivers multi-agent concurrent workspaces, independent virtual PTY screens, zero-knowledge credential brokering, canonical path jailing, and a cryptographically verified SQLite Merkle audit ledger.

---

## 🏗️ Architecture & Crates

```text
syntropy/
├── Cargo.toml                    # Workspace manifest
├── .syntropy.toml                # Project & runtime configuration
├── crates/
│   ├── syntropy-proto/           # Protobuf definitions & Tonic gRPC codegen
│   ├── syntropy-tunnel/          # Outbound gRPC connection manager & MockGatewayServer
│   ├── syntropy-exec/            # Virtual PTY mux (portable-pty), path jail, atomic diffs, worktrees
│   ├── syntropy-security/        # Windows DPAPI / Keystore, inverted credential broker, Merkle SQLite ledger
│   ├── syntropy-mcp/             # MCP child-process supervisor & capability allowlist proxy
│   ├── syntropy-daemon/          # Background daemon service & instruction orchestrator
│   └── syntropy-cli/             # CLI binary (`syntropy dev-server`, `syntropy daemon`, `syntropy doctor`)
```

### Key Subsystems

1. **Multiplexed Outbound Tunnel (`syntropy-proto` & `syntropy-tunnel`)**
   - Outbound-only TLS gRPC stream via `AgentTunnelService.OpenTunnel`.
   - Multiplexes terminal PTY streams, unified diff patches, MCP invocations, approvals, and heartbeats over a single persistent HTTP/2 connection.
   - Zero open inbound ports required.
   - Automatic reconnect with exponential backoff and memory buffering.

2. **Execution Sandboxing & PTY Multiplexing (`syntropy-exec`)**
   - **Virtual PTY Multiplexer**: Cross-platform terminal virtualization with Windows ConPTY support via `portable-pty`. Supports concurrent agent screens (`screen_id`), bidirectional keyboard input, PTY resize, and circular in-memory ring buffers for history scrollback.
   - **Workspace Jail**: Resolves canonical symlinks (`canonicalize`) and verifies that all target paths and CWDs stay strictly within permitted project roots.
   - **Atomic Patch Applicator**: In-memory Unified Diff & Search/Replace block application with SHA-256 pre-verification and ACID shadow-file atomic swapping.
   - **Worktree Manager**: Creates and manages ephemeral Git worktrees in `.syntropy/worktrees/<agent_id>` so multiple agents work simultaneously without file clobbering.

3. **Security & Auditing (`syntropy-security` & `syntropy-mcp`)**
   - **Single Host Authentication**: Authenticate once on the host. Keys are sealed in the hardware keystore (Windows DPAPI, macOS Keychain, Linux Secret Service).
   - **Inverted Credential Broker**: Cloud agents request authenticated actions via RPC; the local daemon signs or injects tokens locally without leaking raw credentials or refresh tokens to the cloud.
   - **Merkle Audit Ledger**: Append-only SQLite database linking every command, patch, and MCP invocation in a SHA-256 Merkle chain for non-repudiation and tamper detection.
   - **Supervised MCP Proxy**: Supervised child-process MCP servers with JSON-RPC filtering, wildcard tool allowlists, and execution timeouts.

---

## 🚀 Quickstart & Verification

### 1. Build and Run Workspace Tests
```bash
cargo test --workspace
```
Runs 42 unit and integration tests across all 7 workspace crates.

### 2. Run Closed-Loop End-to-End Testbed
```bash
cargo run -p syntropy-cli -- dev-server --auto-verify
```
Starts the in-process mock cloud gateway, connects the local daemon, and executes an automated end-to-end multi-agent test:
- Concurrent PTY command dispatch across Agent 1 & Agent 2 screens.
- Atomic file patch application.
- MCP tool invocation.
- Dual-channel signed approval handling.
- Audit ledger hash verification.

### 3. System Diagnostics
```bash
cargo run -p syntropy-cli -- doctor
```

### 4. Verify Cryptographic Audit Ledger
```bash
cargo run -p syntropy-cli -- audit
```
Inspects `.syntropy/audit.db`, calculates the Merkle root hash, and verifies integrity across all recorded actions.
