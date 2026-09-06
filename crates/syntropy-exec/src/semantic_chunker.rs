use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CodeChunk {
    pub start_line: usize,
    pub end_line: usize,
    pub symbol_name: Option<String>,
    pub content: String,
    pub estimated_tokens: usize,
}

pub struct SemanticChunker {
    pub max_tokens: usize,
    pub min_tokens: usize,
}

impl Default for SemanticChunker {
    fn default() -> Self {
        Self {
            max_tokens: 1000,
            min_tokens: 50,
        }
    }
}

impl SemanticChunker {
    pub fn new(max_tokens: usize, min_tokens: usize) -> Self {
        Self { max_tokens, min_tokens }
    }

    /// Estimates token count using standard 4 characters per token heuristic.
    pub fn estimate_tokens(text: &str) -> usize {
        text.len().div_ceil(4)
    }

    /// Chunks code into semantically coherent blocks (functions, structs, classes, modules).
    pub fn chunk(&self, content: &str) -> Vec<CodeChunk> {
        let lines: Vec<&str> = content.lines().collect();
        if lines.is_empty() {
            return Vec::new();
        }

        let mut chunks = Vec::new();
        let mut current_lines = Vec::new();
        let mut current_start = 1;
        let mut current_symbol = None;
        let mut brace_depth: i32 = 0;

        for (i, line) in lines.iter().enumerate() {
            let line_num = i + 1;
            let trimmed = line.trim();

            // Detect new top-level or significant symbol definitions
            let is_symbol_start = brace_depth == 0 && (
                trimmed.starts_with("fn ")
                || trimmed.starts_with("pub fn ")
                || trimmed.starts_with("pub async fn ")
                || trimmed.starts_with("async fn ")
                || trimmed.starts_with("impl ")
                || trimmed.starts_with("struct ")
                || trimmed.starts_with("pub struct ")
                || trimmed.starts_with("enum ")
                || trimmed.starts_with("pub enum ")
                || trimmed.starts_with("class ")
                || trimmed.starts_with("export class ")
                || trimmed.starts_with("function ")
                || trimmed.starts_with("export function ")
                || trimmed.starts_with("def ")
            );

            // If we hit a new symbol at depth 0 and we already have accumulated enough tokens, flush current
            let current_text = current_lines.join("\n");
            let tokens = Self::estimate_tokens(&current_text);

            if is_symbol_start && tokens >= self.min_tokens && !current_lines.is_empty() {
                chunks.push(CodeChunk {
                    start_line: current_start,
                    end_line: line_num - 1,
                    symbol_name: current_symbol.take(),
                    content: current_text,
                    estimated_tokens: tokens,
                });
                current_lines.clear();
                current_start = line_num;
            }

            if is_symbol_start && current_symbol.is_none() {
                current_symbol = extract_symbol_name(trimmed);
            }

            current_lines.push(*line);

            // Track brace depth
            for c in trimmed.chars() {
                if c == '{' {
                    brace_depth += 1;
                } else if c == '}' {
                    brace_depth = (brace_depth - 1).max(0);
                }
            }

            // Flush if chunk reaches max_tokens and we are at top-level
            let current_text = current_lines.join("\n");
            let tokens = Self::estimate_tokens(&current_text);
            if (tokens >= self.max_tokens && brace_depth == 0) || (tokens >= self.max_tokens * 2) {
                chunks.push(CodeChunk {
                    start_line: current_start,
                    end_line: line_num,
                    symbol_name: current_symbol.take(),
                    content: current_text,
                    estimated_tokens: tokens,
                });
                current_lines.clear();
                current_start = line_num + 1;
            }
        }

        if !current_lines.is_empty() {
            let current_text = current_lines.join("\n");
            let tokens = Self::estimate_tokens(&current_text);
            chunks.push(CodeChunk {
                start_line: current_start,
                end_line: lines.len(),
                symbol_name: current_symbol,
                content: current_text,
                estimated_tokens: tokens,
            });
        }

        chunks
    }
}

fn extract_symbol_name(line: &str) -> Option<String> {
    let words: Vec<&str> = line.split_whitespace().collect();
    for (i, word) in words.iter().enumerate() {
        if matches!(*word, "fn" | "struct" | "enum" | "class" | "function" | "def") {
            if let Some(name) = words.get(i + 1) {
                let clean = name.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                if !clean.is_empty() {
                    return Some(clean.to_string());
                }
            }
        } else if *word == "impl" {
            if let Some(name) = words.get(i + 1) {
                let clean = name.trim_matches(|c: char| !c.is_alphanumeric() && c != '_');
                if !clean.is_empty() {
                    return Some(format!("impl {}", clean));
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_chunker_respects_token_budget_and_boundaries() {
        let code = r#"
use std::collections::HashMap;

pub struct Config {
    pub name: String,
    pub timeout_secs: u64,
}

impl Config {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            timeout_secs: 30,
        }
    }
}

pub fn execute_task(task_id: &str) -> bool {
    println!("Executing task {}", task_id);
    true
}
"#;

        let chunker = SemanticChunker::new(50, 10);
        let chunks = chunker.chunk(code);

        assert!(!chunks.is_empty());
        let symbols: Vec<Option<String>> = chunks.iter().map(|c| c.symbol_name.clone()).collect();
        assert!(symbols.iter().any(|s| s.as_deref() == Some("Config")));
        assert!(symbols.iter().any(|s| s.as_deref() == Some("execute_task") || s.as_deref() == Some("impl Config")));

        for chunk in &chunks {
            assert!(chunk.start_line <= chunk.end_line);
            assert!(!chunk.content.is_empty());
        }
    }
}
