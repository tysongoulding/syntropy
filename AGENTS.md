# Syntropy Agent Directives

Cross-platform autonomous cloud agent system. Dual-track Rust monorepo.

## Verification Gates

Execute after every modification before declaring work complete:

1. **Unit & Integration Suite**: `cargo test --workspace` (must pass all tests, 0 warnings).
2. **Closed-Loop End-to-End**: `cargo run -p syntropy-cli -- dev-server --auto-verify` (verifies PTY mux, atomic diffs, MCP allowlists, approvals, and SQLite Merkle ledger).
3. **Linter**: `cargo clippy --workspace -- -D warnings`.

## Architecture Layout

- `crates/`: Application Track & Shared Core
  - `syntropy-proto`: Protocol buffer contracts (`AgentTunnelService.OpenTunnel`). Single source of truth.
  - `syntropy-tunnel`: Outbound TLS gRPC connection manager & in-process mock gateway.
  - `syntropy-exec`: Virtual PTY multiplexer (`portable-pty`), canonical path jail, atomic diff applicator, git worktree manager.
  - `syntropy-security`: Windows DPAPI / software keystore, inverted credential broker, SQLite Merkle audit ledger.
  - `syntropy-mcp`: Supervised stdio/SSE child processes with tool allowlists.
  - `syntropy-daemon`: Local background host service.
  - `syntropy-cli`: Unified CLI entrypoint (`dev-server`, `daemon`, `doctor`, `audit`).
- `services/`: Cloud Track
  - `gateway`: Edge ingress gateway routing agent tunnels.
  - `swarm-orchestrator`: 4-tier swarm state machine & versioned Blackboard store (`blackboard://...`).

## Invariants

- **Outbound-Only Control**: Local daemon never opens listening ports. All control flows over `OpenTunnel` reverse stream.
- **Canonical Jailing**: All file writes and CWDs must pass `WorkspaceJail::resolve_path` and `validate_cwd`. Traversal (`../`) must fail.
- **Zero Credential Leakage**: Never transmit raw OAuth refresh tokens or private keys to cloud workers. Use inverted broker pattern.
- **Atomic Mutations**: File modifications must use `AtomicPatchApplicator` with shadow-file swapping.
- **Tamper Evidence**: All actions (exec, patch, mcp) append to `MerkleAuditLedger` with SHA-256 hash chaining.
