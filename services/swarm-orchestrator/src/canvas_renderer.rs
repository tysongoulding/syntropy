//! Server-Side Canvas & SVG DAG Renderer.
//!
//! Renders sprint plans, multi-agent dependency graphs, and Blackboard milestones
//! server-side as interactive SVG and Canvas payloads so web and mobile clients
//! can inspect swarm execution state with zero heavy client dependencies.

use std::collections::HashMap;
use serde::{Deserialize, Serialize};

use crate::blackboard::Artifact;
use crate::workflow::{SprintPhase, SprintState};

/// Node in the execution graph.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagNode {
    pub id: String,
    pub label: String,
    pub node_type: String, // "phase", "task", "agent", "artifact"
    pub status: String,    // "pending", "running", "completed", "failed", "awaiting_approval"
    pub metadata: HashMap<String, String>,
}

/// Directed edge between execution nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DagEdge {
    pub from: String,
    pub to: String,
    pub label: Option<String>,
    pub is_blocked: bool,
}

/// Complete execution DAG representation.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct DagGraph {
    pub title: String,
    pub nodes: Vec<DagNode>,
    pub edges: Vec<DagEdge>,
}

impl DagGraph {
    pub fn new(title: impl Into<String>) -> Self {
        Self {
            title: title.into(),
            nodes: Vec::new(),
            edges: Vec::new(),
        }
    }

    pub fn add_node(&mut self, node: DagNode) {
        self.nodes.push(node);
    }

    pub fn add_edge(&mut self, edge: DagEdge) {
        self.edges.push(edge);
    }

    /// Constructs a DAG graph from a `SprintState` and blackboard artifacts.
    pub fn from_sprint(state: &SprintState, artifacts: &[Artifact]) -> Self {
        let mut graph = Self::new(format!("Sprint: {} - {}", state.sprint_id, state.objective));

        let phases = [
            (SprintPhase::Initialization, "Init", "Initialize workspace & context"),
            (SprintPhase::Planning, "Planning", "Architect blueprint & task graph"),
            (SprintPhase::PhaseGateAwaitingApproval, "Phase Gate", "Human-in-the-loop approval"),
            (SprintPhase::Implementation, "Implement", "Dual-track code execution"),
            (SprintPhase::Review, "Review", "Closed-loop verification & gates"),
            (SprintPhase::Completed, "Completed", "Audit ledger sealed"),
        ];

        let mut prev_phase_id: Option<String> = None;

        for (idx, (phase, label, desc)) in phases.iter().enumerate() {
            let node_id = format!("phase_{}", idx);
            let status = if *phase == state.phase {
                "running"
            } else if (idx as i32) < phase_order(state.phase) {
                "completed"
            } else if state.phase == SprintPhase::Failed && *phase == SprintPhase::Review {
                "failed"
            } else {
                "pending"
            };

            let mut meta = HashMap::new();
            meta.insert("description".into(), (*desc).into());

            graph.add_node(DagNode {
                id: node_id.clone(),
                label: (*label).into(),
                node_type: "phase".into(),
                status: status.into(),
                metadata: meta,
            });

            if let Some(prev) = prev_phase_id {
                graph.add_edge(DagEdge {
                    from: prev,
                    to: node_id.clone(),
                    label: None,
                    is_blocked: status == "pending",
                });
            }
            prev_phase_id = Some(node_id);
        }

        // Attach blackboard artifacts
        for (i, art) in artifacts.iter().enumerate() {
            let art_node_id = format!("art_{}", i);
            let mut meta = HashMap::new();
            meta.insert("author".into(), art.author_agent.clone());
            meta.insert("version".into(), art.version.to_string());
            meta.insert("uri".into(), art.uri.clone());

            graph.add_node(DagNode {
                id: art_node_id.clone(),
                label: format!("v{}: {}", art.version, art.uri.replace("blackboard://", "")),
                node_type: "artifact".into(),
                status: "completed".into(),
                metadata: meta,
            });

            // Connect artifact to planning or implementation
            graph.add_edge(DagEdge {
                from: "phase_1".into(),
                to: art_node_id,
                label: Some(format!("v{}", art.version)),
                is_blocked: false,
            });
        }

        graph
    }

    /// Renders the DAG graph as a standalone vector SVG.
    pub fn render_svg(&self) -> String {
        let node_width = 180.0;
        let node_height = 64.0;
        let col_gap = 60.0;
        let row_gap = 80.0;

        let total_nodes = self.nodes.len().max(1);
        let cols = (total_nodes as f64).sqrt().ceil().max(3.0) as usize;
        let width = (cols as f64 * (node_width + col_gap) + 100.0).max(800.0);
        let rows = ((total_nodes as f64) / (cols as f64)).ceil() as usize + 1;
        let height = (rows as f64 * (node_height + row_gap) + 120.0).max(400.0);

        let mut positions: HashMap<String, (f64, f64)> = HashMap::new();
        for (idx, node) in self.nodes.iter().enumerate() {
            let c = idx % cols;
            let r = idx / cols;
            let x = 60.0 + (c as f64) * (node_width + col_gap);
            let y = 80.0 + (r as f64) * (node_height + row_gap);
            positions.insert(node.id.clone(), (x, y));
        }

        let mut out = String::new();
        out.push_str(&format!(
            r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {:.0} {:.0}" width="100%" height="100%" style="background-color:#0d1117;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Helvetica,Arial,sans-serif;">"##,
            width, height
        ));

        // SVG Defs: arrow marker & gradients
        out.push_str(r##"<defs>
<marker id="arrow" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
  <path d="M 0 0 L 10 5 L 0 10 z" fill="#58a6ff" />
</marker>
<marker id="arrow-blocked" viewBox="0 0 10 10" refX="10" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
  <path d="M 0 0 L 10 5 L 0 10 z" fill="#484f58" />
</marker>
<filter id="card-shadow" x="-5%" y="-5%" width="115%" height="115%">
  <feDropShadow dx="0" dy="4" stdDeviation="4" flood-color="#000000" flood-opacity="0.4" />
</filter>
</defs>"##);

        // Header
        out.push_str(&format!(
            r##"<text x="30" y="42" fill="#f0f6fc" font-size="18" font-weight="640">{}</text>"##,
            escape_xml(&self.title)
        ));

        // Edges
        for edge in &self.edges {
            if let (Some(&(x1, y1)), Some(&(x2, y2))) = (positions.get(&edge.from), positions.get(&edge.to)) {
                let start_x = x1 + node_width;
                let start_y = y1 + node_height / 2.0;
                let end_x = x2;
                let end_y = y2 + node_height / 2.0;

                let marker = if edge.is_blocked { "url(#arrow-blocked)" } else { "url(#arrow)" };
                let stroke = if edge.is_blocked { "#30363d" } else { "#58a6ff" };
                let dash = if edge.is_blocked { r#"stroke-dasharray="4,4""# } else { "" };

                // Draw smooth bezier curve
                let cx1 = start_x + (end_x - start_x) / 2.0;
                let cy1 = start_y;
                let cx2 = start_x + (end_x - start_x) / 2.0;
                let cy2 = end_y;

                out.push_str(&format!(
                    r##"<path d="M {:.1} {:.1} C {:.1} {:.1}, {:.1} {:.1}, {:.1} {:.1}" fill="none" stroke="{}" stroke-width="2" marker-end="{}" {} />"##,
                    start_x, start_y, cx1, cy1, cx2, cy2, end_x, end_y, stroke, marker, dash
                ));
            }
        }

        // Nodes
        for node in &self.nodes {
            if let Some(&(x, y)) = positions.get(&node.id) {
                let (fill, stroke, status_color) = match node.status.as_str() {
                    "completed" => ("#161b22", "#238636", "#3fb950"),
                    "running" => ("#161b22", "#1f6feb", "#58a6ff"),
                    "failed" => ("#161b22", "#da3633", "#f85149"),
                    "awaiting_approval" => ("#161b22", "#9e6a03", "#d29922"),
                    _ => ("#161b22", "#30363d", "#8b949e"),
                };

                out.push_str(&format!(
                    r##"<g id="{}" filter="url(#card-shadow)">
<rect x="{:.1}" y="{:.1}" width="{:.1}" height="{:.1}" rx="8" ry="8" fill="{}" stroke="{}" stroke-width="1.5" />
<circle cx="{:.1}" cy="{:.1}" r="5" fill="{}" />
<text x="{:.1}" y="{:.1}" fill="#f0f6fc" font-size="13" font-weight="600">{}</text>
<text x="{:.1}" y="{:.1}" fill="#8b949e" font-size="11">{}</text>
</g>"##,
                    escape_xml(&node.id),
                    x, y, node_width, node_height, fill, stroke,
                    x + 16.0, y + 22.0, status_color,
                    x + 28.0, y + 26.0, escape_xml(&node.label),
                    x + 16.0, y + 46.0, escape_xml(&node.status.to_uppercase()),
                ));
            }
        }

        out.push_str("</svg>");
        out
    }

    /// Renders an interactive HTML5 Canvas JavaScript rendering function.
    pub fn render_canvas_js(&self, canvas_id: &str) -> String {
        let nodes_json = serde_json::to_string(&self.nodes).unwrap_or_else(|_| "[]".into());
        let edges_json = serde_json::to_string(&self.edges).unwrap_or_else(|_| "[]".into());

        format!(
            r##"(function() {{
    const canvas = document.getElementById("{canvas_id}");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const nodes = {nodes_json};
    const edges = {edges_json};

    const nodeWidth = 180;
    const nodeHeight = 60;
    const cols = Math.max(3, Math.ceil(Math.sqrt(nodes.length)));

    function draw() {{
        ctx.fillStyle = "#0d1117";
        ctx.fillRect(0, 0, canvas.width, canvas.height);

        const posMap = {{}};
        nodes.forEach((node, i) => {{
            const c = i % cols;
            const r = Math.floor(i / cols);
            posMap[node.id] = {{
                x: 60 + c * (nodeWidth + 60),
                y: 80 + r * (nodeHeight + 80)
            }};
        }});

        // Draw edges
        edges.forEach(edge => {{
            const p1 = posMap[edge.from];
            const p2 = posMap[edge.to];
            if (!p1 || !p2) return;

            ctx.beginPath();
            ctx.moveTo(p1.x + nodeWidth, p1.y + nodeHeight / 2);
            ctx.bezierCurveTo(
                p1.x + nodeWidth + 30, p1.y + nodeHeight / 2,
                p2.x - 30, p2.y + nodeHeight / 2,
                p2.x, p2.y + nodeHeight / 2
            );
            ctx.strokeStyle = edge.is_blocked ? "#30363d" : "#58a6ff";
            ctx.lineWidth = 2;
            ctx.stroke();
        }});

        // Draw nodes
        nodes.forEach(node => {{
            const p = posMap[node.id];
            if (!p) return;

            ctx.fillStyle = "#161b22";
            ctx.strokeStyle = node.status === "completed" ? "#238636" : (node.status === "running" ? "#1f6feb" : "#30363d");
            ctx.lineWidth = 1.5;
            ctx.beginPath();
            ctx.roundRect(p.x, p.y, nodeWidth, nodeHeight, 8);
            ctx.fill();
            ctx.stroke();

            ctx.fillStyle = "#f0f6fc";
            ctx.font = "bold 12px sans-serif";
            ctx.fillText(node.label, p.x + 16, p.y + 24);

            ctx.fillStyle = "#8b949e";
            ctx.font = "10px sans-serif";
            ctx.fillText(node.status.toUpperCase(), p.x + 16, p.y + 44);
        }});
    }}

    draw();
}})();"##
        )
    }

    /// Renders a full standalone interactive HTML preview page.
    pub fn render_standalone_html(&self) -> String {
        let svg = self.render_svg();
        let js = self.render_canvas_js("swarmCanvas");

        format!(
            r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{}</title>
<style>
body {{ margin:0; padding:24px; background:#010409; color:#f0f6fc; font-family:sans-serif; }}
.card {{ background:#0d1117; border:1px solid #30363d; border-radius:12px; padding:20px; margin-bottom:24px; }}
h1 {{ font-size:20px; margin-top:0; }}
</style>
</head>
<body>
<div class="card">
  <h1>{}</h1>
  {}
</div>
<div class="card">
  <h1>Canvas Mode</h1>
  <canvas id="swarmCanvas" width="900" height="450" style="width:100%;max-width:900px;border-radius:8px;"></canvas>
</div>
<script>
{}
</script>
</body>
</html>"##,
            escape_xml(&self.title),
            escape_xml(&self.title),
            svg,
            js
        )
    }
}

fn phase_order(phase: SprintPhase) -> i32 {
    match phase {
        SprintPhase::Initialization => 0,
        SprintPhase::Planning => 1,
        SprintPhase::PhaseGateAwaitingApproval => 2,
        SprintPhase::Implementation => 3,
        SprintPhase::Review => 4,
        SprintPhase::Completed => 5,
        SprintPhase::Failed => 6,
    }
}

fn escape_xml(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canvas_renderer_svg_and_canvas_js() {
        let state = SprintState {
            sprint_id: "sprint-101".into(),
            objective: "Refactor Kernel".into(),
            phase: SprintPhase::Implementation,
            approval_token: Some("tok-auth-42".into()),
            rejection_feedback: None,
        };

        let artifacts = vec![Artifact {
            uri: "blackboard://specs/arch.md".into(),
            version: 1,
            author_agent: "architect-lead".into(),
            created_at_unix_ms: 1700000000000,
            sha256: "deadbeef".into(),
            content: b"# Architecture".to_vec(),
        }];

        let graph = DagGraph::from_sprint(&state, &artifacts);
        assert!(!graph.nodes.is_empty());
        assert!(!graph.edges.is_empty());

        let svg = graph.render_svg();
        assert!(svg.contains("<svg"));
        assert!(svg.contains("Refactor Kernel"));
        assert!(svg.contains("sprint-101"));
        assert!(svg.contains("marker id=\"arrow\""));
        assert!(svg.ends_with("</svg>"));

        let canvas_js = graph.render_canvas_js("testCanvas");
        assert!(canvas_js.contains("document.getElementById(\"testCanvas\")"));
        assert!(canvas_js.contains("bezierCurveTo"));

        let standalone = graph.render_standalone_html();
        assert!(standalone.contains("<!DOCTYPE html>"));
        assert!(standalone.contains("<canvas id=\"swarmCanvas\""));
    }
}