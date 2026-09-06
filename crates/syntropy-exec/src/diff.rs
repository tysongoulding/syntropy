//! Structured atomic patch application with SHA-256 pre-verification,
//! in-memory diff processing, and crash-safe atomic shadow file replacement.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use thiserror::Error;
use uuid::Uuid;

/// Errors returned during patch application.
#[derive(Debug, Error)]
pub enum DiffError {
    #[error("File not found: {0}")]
    FileNotFound(PathBuf),

    #[error("Content hash mismatch for '{file}': expected '{expected}', found '{actual}'")]
    HashMismatch {
        file: PathBuf,
        expected: String,
        actual: String,
    },

    #[error("Diff hunk context mismatch at line {line}: expected '{expected}', found '{actual}'")]
    ContextMismatch {
        line: usize,
        expected: String,
        actual: String,
    },

    #[error("Failed to parse diff or patch: {0}")]
    InvalidPatch(String),

    #[error("Line index out of bounds: line {line}, total lines {total}")]
    OutOfBounds { line: usize, total: usize },

    #[error("IO error on path '{path}': {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Options controlling patch application.
#[derive(Debug, Clone, Default)]
pub struct PatchOptions {
    pub patch_id: Option<String>,
    pub expected_sha256: Option<String>,
    pub dry_run: bool,
    pub create_parents: bool,
}

impl PatchOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_expected_sha256(mut self, sha256: impl Into<String>) -> Self {
        self.expected_sha256 = Some(sha256.into());
        self
    }

    pub fn dry_run(mut self, dry_run: bool) -> Self {
        self.dry_run = dry_run;
        self
    }

    pub fn create_parents(mut self, create: bool) -> Self {
        self.create_parents = create;
        self
    }
}

/// Result of an atomic patch application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatchApplyResult {
    pub patch_id: String,
    pub file_path: PathBuf,
    pub success: bool,
    pub lines_added: u32,
    pub lines_removed: u32,
    pub original_sha256: String,
    pub new_sha256: String,
    pub modified_content: String,
}

/// Structured single-range line replacement specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LineReplacement {
    /// 1-indexed start line
    pub start_line: usize,
    /// 1-indexed end line (inclusive)
    pub end_line: usize,
    /// Optional expected target content to verify before replacing
    pub target_content: Option<String>,
    /// The replacement string
    pub replacement_content: String,
}

/// Computes lowercase hex-encoded SHA-256 digest of byte slice.
pub fn compute_sha256(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Atomic patch applicator ensuring all disk mutations are verified and committed atomically.
#[derive(Debug, Clone, Default)]
pub struct AtomicPatchApplicator;

impl AtomicPatchApplicator {
    pub fn new() -> Self {
        Self
    }

    /// Applies a patch (unified diff or search/replace block) to a target file on disk.
    pub fn apply_patch(
        &self,
        target_path: impl AsRef<Path>,
        patch_content: &str,
        opts: PatchOptions,
    ) -> Result<PatchApplyResult, DiffError> {
        let target_path = target_path.as_ref().to_path_buf();
        let (original_content, original_sha256) = self.read_and_verify(&target_path, &opts)?;

        // Apply diff in memory
        let (modified_content, lines_added, lines_removed) =
            if patch_content.contains("<<<<<<< SEARCH") {
                self.apply_search_replace_in_memory(&original_content, patch_content)?
            } else {
                self.apply_unified_diff_in_memory(&original_content, patch_content)?
            };

        let new_sha256 = compute_sha256(modified_content.as_bytes());

        if !opts.dry_run {
            self.commit_atomically(&target_path, &modified_content, opts.create_parents)?;
        }

        Ok(PatchApplyResult {
            patch_id: opts.patch_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            file_path: target_path,
            success: true,
            lines_added,
            lines_removed,
            original_sha256,
            new_sha256,
            modified_content,
        })
    }

    /// Applies structured line replacements to a target file on disk.
    pub fn apply_line_replacements(
        &self,
        target_path: impl AsRef<Path>,
        replacements: &[LineReplacement],
        opts: PatchOptions,
    ) -> Result<PatchApplyResult, DiffError> {
        let target_path = target_path.as_ref().to_path_buf();
        let (original_content, original_sha256) = self.read_and_verify(&target_path, &opts)?;

        let (modified_content, lines_added, lines_removed) =
            self.apply_replacements_in_memory(&original_content, replacements)?;

        let new_sha256 = compute_sha256(modified_content.as_bytes());

        if !opts.dry_run {
            self.commit_atomically(&target_path, &modified_content, opts.create_parents)?;
        }

        Ok(PatchApplyResult {
            patch_id: opts.patch_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            file_path: target_path,
            success: true,
            lines_added,
            lines_removed,
            original_sha256,
            new_sha256,
            modified_content,
        })
    }

    /// Applies raw string content to a file atomically with optional hash verification.
    pub fn apply_full_content(
        &self,
        target_path: impl AsRef<Path>,
        new_content: &str,
        opts: PatchOptions,
    ) -> Result<PatchApplyResult, DiffError> {
        let target_path = target_path.as_ref().to_path_buf();
        let (original_content, original_sha256) = self.read_and_verify(&target_path, &opts)?;

        let original_lines = original_content.lines().count() as u32;
        let new_lines = new_content.lines().count() as u32;
        let lines_added = new_lines;
        let lines_removed = original_lines;

        let new_sha256 = compute_sha256(new_content.as_bytes());

        if !opts.dry_run {
            self.commit_atomically(&target_path, new_content, opts.create_parents)?;
        }

        Ok(PatchApplyResult {
            patch_id: opts.patch_id.unwrap_or_else(|| Uuid::new_v4().to_string()),
            file_path: target_path,
            success: true,
            lines_added,
            lines_removed,
            original_sha256,
            new_sha256,
            modified_content: new_content.to_string(),
        })
    }

    /// Reads target file (or returns empty if creating new file) and verifies expected SHA-256.
    fn read_and_verify(
        &self,
        path: &Path,
        opts: &PatchOptions,
    ) -> Result<(String, String), DiffError> {
        let (content, actual_sha256) = if path.exists() {
            let bytes = fs::read(path).map_err(|e| DiffError::Io {
                path: path.to_path_buf(),
                source: e,
            })?;
            let hash = compute_sha256(&bytes);
            let text = String::from_utf8_lossy(&bytes).to_string();
            (text, hash)
        } else {
            let empty_hash = compute_sha256(b"");
            (String::new(), empty_hash)
        };

        if let Some(expected) = &opts.expected_sha256 {
            let exp = expected.trim();
            if !exp.is_empty() && !actual_sha256.eq_ignore_ascii_case(exp) {
                return Err(DiffError::HashMismatch {
                    file: path.to_path_buf(),
                    expected: exp.to_string(),
                    actual: actual_sha256,
                });
            }
        }

        Ok((content, actual_sha256))
    }

    /// Atomically commits file content via shadow file write and atomic rename.
    fn commit_atomically(&self, path: &Path, content: &str, create_parents: bool) -> Result<(), DiffError> {
        let parent = path.parent().unwrap_or_else(|| Path::new("."));

        if create_parents && !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| DiffError::Io {
                path: parent.to_path_buf(),
                source: e,
            })?;
        }

        let file_name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "file".to_string());

        // Place temporary shadow file in the same parent directory to guarantee same filesystem volume
        let shadow_path = parent.join(format!(".{}.tmp-{}", file_name, Uuid::new_v4()));

        // Write shadow file
        {
            let mut shadow_file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&shadow_path)
                .map_err(|e| DiffError::Io {
                    path: shadow_path.clone(),
                    source: e,
                })?;

            shadow_file
                .write_all(content.as_bytes())
                .map_err(|e| DiffError::Io {
                    path: shadow_path.clone(),
                    source: e,
                })?;

            shadow_file.sync_all().map_err(|e| DiffError::Io {
                path: shadow_path.clone(),
                source: e,
            })?;
        }

        // Perform atomic rename
        let rename_res = fs::rename(&shadow_path, path);
        #[allow(unused_variables)]
        if let Err(err) = rename_res {
            #[cfg(windows)]
            {
                // On Windows, if destination exists and is read-only, remove read-only attribute
                if path.exists() {
                    if let Ok(metadata) = fs::metadata(path) {
                        let mut perms = metadata.permissions();
                        if perms.readonly() {
                            #[allow(clippy::permissions_set_readonly_false)]
                            perms.set_readonly(false);
                            let _ = fs::set_permissions(path, perms);
                        }
                    }
                    // Attempt removing existing file if rename was blocked
                    let _ = fs::remove_file(path);
                }
                if let Err(retry_err) = fs::rename(&shadow_path, path) {
                    let _ = fs::remove_file(&shadow_path);
                    return Err(DiffError::Io {
                        path: path.to_path_buf(),
                        source: retry_err,
                    });
                }
            }
            #[cfg(not(windows))]
            {
                let _ = fs::remove_file(&shadow_path);
                return Err(DiffError::Io {
                    path: path.to_path_buf(),
                    source: err,
                });
            }
        }

        Ok(())
    }

    /// Parses and applies a unified diff hunk series in memory.
    pub fn apply_unified_diff_in_memory(
        &self,
        original: &str,
        diff_str: &str,
    ) -> Result<(String, u32, u32), DiffError> {
        let crlf = original.contains("\r\n");
        let newline = if crlf { "\r\n" } else { "\n" };

        let orig_lines: Vec<&str> = original
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect();

        // Check if original had trailing newline
        let orig_had_trailing_newline = original.ends_with('\n');

        let mut lines_added = 0u32;
        let mut lines_removed = 0u32;
        let mut result_lines = Vec::new();

        let hunks = parse_unified_diff_hunks(diff_str)?;

        if hunks.is_empty() {
            return Err(DiffError::InvalidPatch(
                "No valid unified diff hunks found".to_string(),
            ));
        }

        let mut orig_idx = 0usize;

        for hunk in hunks {
            // Hunk old_start is 1-indexed
            let target_start = if hunk.old_start == 0 {
                0
            } else {
                hunk.old_start.saturating_sub(1)
            };

            // Copy lines up to hunk start
            while orig_idx < target_start && orig_idx < orig_lines.len() {
                result_lines.push(orig_lines[orig_idx].to_string());
                orig_idx += 1;
            }

            for line in hunk.lines {
                match line {
                    DiffLine::Context(text) => {
                        if orig_idx < orig_lines.len() {
                            let actual = orig_lines[orig_idx];
                            if actual != text {
                                return Err(DiffError::ContextMismatch {
                                    line: orig_idx + 1,
                                    expected: text,
                                    actual: actual.to_string(),
                                });
                            }
                            result_lines.push(text);
                            orig_idx += 1;
                        } else {
                            result_lines.push(text);
                        }
                    }
                    DiffLine::Deletion(text) => {
                        if orig_idx < orig_lines.len() {
                            let actual = orig_lines[orig_idx];
                            if actual != text {
                                return Err(DiffError::ContextMismatch {
                                    line: orig_idx + 1,
                                    expected: text,
                                    actual: actual.to_string(),
                                });
                            }
                            orig_idx += 1;
                        }
                        lines_removed += 1;
                    }
                    DiffLine::Addition(text) => {
                        result_lines.push(text);
                        lines_added += 1;
                    }
                }
            }
        }

        // Copy remaining lines from original
        while orig_idx < orig_lines.len() {
            // If original had empty last element due to trailing \n, don't double count if handled
            if orig_idx == orig_lines.len() - 1 && orig_lines[orig_idx].is_empty() && orig_had_trailing_newline {
                break;
            }
            result_lines.push(orig_lines[orig_idx].to_string());
            orig_idx += 1;
        }

        let mut output = result_lines.join(newline);
        if (orig_had_trailing_newline || lines_added > 0) && !output.ends_with(newline) && !output.is_empty() {
            output.push_str(newline);
        }

        Ok((output, lines_added, lines_removed))
    }

    /// Applies Search/Replace block patches in memory.
    pub fn apply_search_replace_in_memory(
        &self,
        original: &str,
        patch_str: &str,
    ) -> Result<(String, u32, u32), DiffError> {
        let mut current = original.to_string();
        let mut lines_added = 0u32;
        let mut lines_removed = 0u32;

        let blocks = parse_search_replace_blocks(patch_str)?;
        if blocks.is_empty() {
            return Err(DiffError::InvalidPatch(
                "No search/replace blocks found".to_string(),
            ));
        }

        for (search, replace) in blocks {
            if let Some(pos) = current.find(&search) {
                let removed_count = search.lines().count() as u32;
                let added_count = replace.lines().count() as u32;

                lines_removed += removed_count;
                lines_added += added_count;

                current = format!("{}{}{}", &current[..pos], replace, &current[pos + search.len()..]);
            } else {
                return Err(DiffError::ContextMismatch {
                    line: 0,
                    expected: search,
                    actual: "<search content not found in target file>".to_string(),
                });
            }
        }

        Ok((current, lines_added, lines_removed))
    }

    /// Applies structured line replacements in memory.
    pub fn apply_replacements_in_memory(
        &self,
        original: &str,
        replacements: &[LineReplacement],
    ) -> Result<(String, u32, u32), DiffError> {
        let crlf = original.contains("\r\n");
        let newline = if crlf { "\r\n" } else { "\n" };

        let orig_lines: Vec<&str> = original
            .split('\n')
            .map(|l| l.strip_suffix('\r').unwrap_or(l))
            .collect();

        let total_lines = orig_lines.len();
        let mut lines_added = 0u32;
        let mut lines_removed = 0u32;

        // Sort replacements by start line ascending
        let mut sorted = replacements.to_vec();
        sorted.sort_by_key(|r| r.start_line);

        let mut result = Vec::new();
        let mut cursor = 1usize; // 1-indexed

        for r in sorted {
            if r.start_line < cursor {
                return Err(DiffError::InvalidPatch(
                    "Overlapping line replacements are not supported".to_string(),
                ));
            }
            if r.start_line > total_lines + 1 {
                return Err(DiffError::OutOfBounds {
                    line: r.start_line,
                    total: total_lines,
                });
            }

            // Copy untouched lines
            while cursor < r.start_line {
                result.push(orig_lines[cursor - 1].to_string());
                cursor += 1;
            }

            // Count lines removed
            let end_bounded = r.end_line.min(total_lines);
            if end_bounded >= r.start_line {
                let removed = (end_bounded - r.start_line + 1) as u32;
                lines_removed += removed;

                // Check expected target content if provided
                if let Some(target) = &r.target_content {
                    let actual_slice = &orig_lines[r.start_line - 1..end_bounded];
                    let actual_joined = actual_slice.join(newline);
                    let target_norm = target.replace("\r\n", "\n");
                    let actual_norm = actual_joined.replace("\r\n", "\n");
                    if actual_norm != target_norm {
                        return Err(DiffError::ContextMismatch {
                            line: r.start_line,
                            expected: target.clone(),
                            actual: actual_joined,
                        });
                    }
                }
                cursor = end_bounded + 1;
            }

            // Add replacement lines
            if !r.replacement_content.is_empty() {
                for line in r.replacement_content.lines() {
                    result.push(line.to_string());
                    lines_added += 1;
                }
            }
        }

        // Copy remaining lines
        while cursor <= total_lines {
            if cursor == total_lines && orig_lines[cursor - 1].is_empty() && original.ends_with('\n') {
                break;
            }
            result.push(orig_lines[cursor - 1].to_string());
            cursor += 1;
        }

        let mut output = result.join(newline);
        if original.ends_with('\n') && !output.ends_with(newline) && !output.is_empty() {
            output.push_str(newline);
        }

        Ok((output, lines_added, lines_removed))
    }
}

#[derive(Debug, PartialEq)]
enum DiffLine {
    Context(String),
    Deletion(String),
    Addition(String),
}

#[derive(Debug)]
#[allow(dead_code)]
struct Hunk {
    old_start: usize,
    old_count: usize,
    new_start: usize,
    new_count: usize,
    lines: Vec<DiffLine>,
}

/// Parses unified diff hunks from a diff string.
fn parse_unified_diff_hunks(diff_str: &str) -> Result<Vec<Hunk>, DiffError> {
    let mut hunks = Vec::new();
    let mut current_hunk: Option<Hunk> = None;

    for line in diff_str.lines() {
        if line.starts_with("@@ ") {
            if let Some(hunk) = current_hunk.take() {
                hunks.push(hunk);
            }
            let (old_start, old_count, new_start, new_count) = parse_hunk_header(line)?;
            current_hunk = Some(Hunk {
                old_start,
                old_count,
                new_start,
                new_count,
                lines: Vec::new(),
            });
        } else if let Some(ref mut hunk) = current_hunk {
            if let Some(rest) = line.strip_prefix(' ') {
                hunk.lines.push(DiffLine::Context(rest.to_string()));
            } else if let Some(rest) = line.strip_prefix('-') {
                hunk.lines.push(DiffLine::Deletion(rest.to_string()));
            } else if let Some(rest) = line.strip_prefix('+') {
                hunk.lines.push(DiffLine::Addition(rest.to_string()));
            } else if line.starts_with('\\') {
                // Ignore "\ No newline at end of file" metadata
                continue;
            } else if line.starts_with("---") || line.starts_with("+++") {
                // Header line before first hunk, ignore
                continue;
            }
        }
    }

    if let Some(hunk) = current_hunk {
        hunks.push(hunk);
    }

    Ok(hunks)
}

/// Parses header like `@@ -1,3 +1,4 @@`
fn parse_hunk_header(line: &str) -> Result<(usize, usize, usize, usize), DiffError> {
    let parts: Vec<&str> = line.split("@@").collect();
    if parts.len() < 2 {
        return Err(DiffError::InvalidPatch(format!(
            "Invalid hunk header: {line}"
        )));
    }
    let middle = parts[1].trim();
    let ranges: Vec<&str> = middle.split_whitespace().collect();
    if ranges.len() < 2 {
        return Err(DiffError::InvalidPatch(format!(
            "Invalid hunk ranges in: {middle}"
        )));
    }

    let parse_range = |r: &str, prefix: char| -> Result<(usize, usize), DiffError> {
        let stripped = r.strip_prefix(prefix).ok_or_else(|| {
            DiffError::InvalidPatch(format!("Expected prefix '{prefix}' in '{r}'"))
        })?;
        if let Some((start_s, count_s)) = stripped.split_once(',') {
            let start = start_s
                .parse::<usize>()
                .map_err(|e| DiffError::InvalidPatch(e.to_string()))?;
            let count = count_s
                .parse::<usize>()
                .map_err(|e| DiffError::InvalidPatch(e.to_string()))?;
            Ok((start, count))
        } else {
            let start = stripped
                .parse::<usize>()
                .map_err(|e| DiffError::InvalidPatch(e.to_string()))?;
            Ok((start, 1))
        }
    };

    let (old_start, old_count) = parse_range(ranges[0], '-')?;
    let (new_start, new_count) = parse_range(ranges[1], '+')?;

    Ok((old_start, old_count, new_start, new_count))
}

/// Parses blocks in format:
/// <<<<<<< SEARCH
/// search text
/// =======
/// replace text
/// >>>>>>> REPLACE
fn parse_search_replace_blocks(text: &str) -> Result<Vec<(String, String)>, DiffError> {
    let mut blocks = Vec::new();
    let mut remaining = text;

    while let Some(search_start) = remaining.find("<<<<<<< SEARCH") {
        let after_start = &remaining[search_start + "<<<<<<< SEARCH".len()..];
        let after_start = after_start.strip_prefix("\r\n").unwrap_or_else(|| after_start.strip_prefix('\n').unwrap_or(after_start));

        let sep = match after_start.find("=======") {
            Some(pos) => pos,
            None => {
                return Err(DiffError::InvalidPatch(
                    "Missing '=======' separator in search/replace block".to_string(),
                ));
            }
        };

        let search_text = after_start[..sep].to_string();
        let after_sep = &after_start[sep + "=======".len()..];
        let after_sep = after_sep.strip_prefix("\r\n").unwrap_or_else(|| after_sep.strip_prefix('\n').unwrap_or(after_sep));

        let replace_end = match after_sep.find(">>>>>>> REPLACE") {
            Some(pos) => pos,
            None => {
                return Err(DiffError::InvalidPatch(
                    "Missing '>>>>>>> REPLACE' terminator in search/replace block".to_string(),
                ));
            }
        };

        let replace_text = after_sep[..replace_end].to_string();
        blocks.push((search_text, replace_text));

        remaining = &after_sep[replace_end + ">>>>>>> REPLACE".len()..];
    }

    Ok(blocks)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_unified_diff_application() {
        let applicator = AtomicPatchApplicator::new();
        let original = "fn main() {\n    println!(\"hello\");\n}\n";
        let diff = r#"--- a/main.rs
+++ b/main.rs
@@ -1,3 +1,4 @@
 fn main() {
-    println!("hello");
+    println!("hello world");
+    println!("syntropy");
 }
"#;
        let (modified, added, removed) = applicator
            .apply_unified_diff_in_memory(original, diff)
            .unwrap();

        assert_eq!(added, 2);
        assert_eq!(removed, 1);
        assert_eq!(
            modified,
            "fn main() {\n    println!(\"hello world\");\n    println!(\"syntropy\");\n}\n"
        );
    }

    #[test]
    fn test_search_replace_block_application() {
        let applicator = AtomicPatchApplicator::new();
        let original = "let a = 1;\nlet b = 2;\nlet c = 3;\n";
        let patch = r#"<<<<<<< SEARCH
let b = 2;
=======
let b = 200;
let b2 = 300;
>>>>>>> REPLACE"#;

        let (modified, added, removed) = applicator
            .apply_search_replace_in_memory(original, patch)
            .unwrap();

        assert_eq!(removed, 1);
        assert_eq!(added, 2);
        assert_eq!(
            modified,
            "let a = 1;\nlet b = 200;\nlet b2 = 300;\nlet c = 3;\n"
        );
    }

    #[test]
    fn test_atomic_file_write_and_sha_verification() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_diff_test_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test.txt");

        let original_text = "line 1\nline 2\nline 3\n";
        fs::write(&file_path, original_text).unwrap();

        let expected_hash = compute_sha256(original_text.as_bytes());

        let applicator = AtomicPatchApplicator::new();
        let diff = r#"@@ -1,3 +1,3 @@
 line 1
-line 2
+line 2_replaced
 line 3
"#;

        // Valid hash verification and atomic replace
        let opts = PatchOptions::new().with_expected_sha256(&expected_hash);
        let res = applicator.apply_patch(&file_path, diff, opts).unwrap();
        assert!(res.success);
        assert_eq!(res.lines_added, 1);
        assert_eq!(res.lines_removed, 1);

        let content_on_disk = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content_on_disk, "line 1\nline 2_replaced\nline 3\n");

        // Stale hash verification failure
        let stale_opts = PatchOptions::new().with_expected_sha256("bad_hash_value");
        let err = applicator.apply_patch(&file_path, diff, stale_opts).unwrap_err();
        assert!(matches!(err, DiffError::HashMismatch { .. }));

        // Content on disk must remain uncorrupted
        let content_after_err = fs::read_to_string(&file_path).unwrap();
        assert_eq!(content_after_err, "line 1\nline 2_replaced\nline 3\n");

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_dry_run_does_not_mutate_disk() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_diff_dry_{}", Uuid::new_v4()));
        fs::create_dir_all(&temp_dir).unwrap();
        let file_path = temp_dir.join("test_dry.txt");

        let initial = "alpha\nbeta\ngamma\n";
        fs::write(&file_path, initial).unwrap();

        let applicator = AtomicPatchApplicator::new();
        let diff = r#"@@ -1,3 +1,3 @@
 alpha
-beta
+BETA_MODIFIED
 gamma
"#;

        let opts = PatchOptions::new().dry_run(true);
        let res = applicator.apply_patch(&file_path, diff, opts).unwrap();
        assert!(res.success);
        assert_eq!(res.lines_added, 1);
        assert_eq!(res.lines_removed, 1);

        // Content on disk must still be original
        let on_disk = fs::read_to_string(&file_path).unwrap();
        assert_eq!(on_disk, initial);

        let _ = fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_apply_line_replacements() {
        let applicator = AtomicPatchApplicator::new();
        let original = "line1\nline2\nline3\nline4\n";

        let replacements = vec![
            LineReplacement {
                start_line: 2,
                end_line: 3,
                target_content: Some("line2\nline3".to_string()),
                replacement_content: "line2_new\nline3_new\nline3.5".to_string(),
            },
        ];

        let (res, added, removed) = applicator
            .apply_replacements_in_memory(original, &replacements)
            .unwrap();

        assert_eq!(removed, 2);
        assert_eq!(added, 3);
        assert_eq!(res, "line1\nline2_new\nline3_new\nline3.5\nline4\n");
    }

    #[test]
    fn test_create_parents_on_new_file() {
        let temp_dir = std::env::temp_dir().join(format!("syntropy_diff_parents_{}", Uuid::new_v4()));
        let nested_file = temp_dir.join("deep").join("nested").join("file.rs");

        let applicator = AtomicPatchApplicator::new();
        let opts = PatchOptions::new().create_parents(true);
        let res = applicator
            .apply_full_content(&nested_file, "pub fn nested() {}", opts)
            .unwrap();

        assert!(res.success);
        assert!(nested_file.exists());
        assert_eq!(fs::read_to_string(&nested_file).unwrap(), "pub fn nested() {}");

        let _ = fs::remove_dir_all(&temp_dir);
    }
}

