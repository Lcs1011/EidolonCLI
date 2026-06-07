use std::cmp::Reverse;
use std::collections::HashSet;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Instant;

use glob::Pattern;
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

/// Maximum file size that can be read (10 MB).
const MAX_READ_SIZE: u64 = 10 * 1024 * 1024;

/// Maximum file size that can be written (10 MB).
const MAX_WRITE_SIZE: usize = 10 * 1024 * 1024;

const GLOB_SEARCH_IGNORED_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    ".build",
    "target",
    "dist",
    "coverage",
];

/// Check whether a file appears to contain binary content by examining
/// the first chunk for NUL bytes.
fn is_binary_file(path: &Path) -> io::Result<bool> {
    use std::io::Read;
    let mut file = fs::File::open(path)?;
    let mut buffer = [0u8; 8192];
    let bytes_read = file.read(&mut buffer)?;
    Ok(buffer[..bytes_read].contains(&0))
}

/// Validate that a resolved path stays within the given workspace root.
/// Returns the canonical path on success, or an error if the path escapes
/// the workspace boundary (e.g. via `../` traversal or symlink).
fn normalize_windows_extended_path(path: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        let text = path.to_string_lossy();

        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }

        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }

        path.to_path_buf()
    }

    #[cfg(not(windows))]
    {
        path.to_path_buf()
    }
}

/// Validate that a resolved path stays within the given workspace root.
/// Returns success only when the normalized target path is inside the
/// normalized workspace root.
#[allow(dead_code)]
fn validate_workspace_boundary(resolved: &Path, workspace_root: &Path) -> io::Result<()> {
    let resolved = normalize_windows_extended_path(resolved);
    let workspace_root = normalize_windows_extended_path(workspace_root);

    if !resolved.starts_with(&workspace_root) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "path {} escapes workspace boundary {}",
                resolved.display(),
                workspace_root.display()
            ),
        ));
    }

    Ok(())
}

/// Text payload returned by file-reading operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TextFilePayload {
    #[serde(rename = "filePath")]
    pub file_path: String,
    pub content: String,
    #[serde(rename = "numLines")]
    pub num_lines: usize,
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "totalLines")]
    pub total_lines: usize,
}

/// Output envelope for the `read_file` tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadFileOutput {
    #[serde(rename = "type")]
    pub kind: String,
    pub file: TextFilePayload,
}

/// Structured patch hunk emitted by write and edit operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StructuredPatchHunk {
    #[serde(rename = "oldStart")]
    pub old_start: usize,
    #[serde(rename = "oldLines")]
    pub old_lines: usize,
    #[serde(rename = "newStart")]
    pub new_start: usize,
    #[serde(rename = "newLines")]
    pub new_lines: usize,
    pub lines: Vec<String>,
}

/// Output envelope for full-file write operations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriteFileOutput {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(rename = "filePath")]
    pub file_path: String,
    pub content: String,
    #[serde(rename = "structuredPatch")]
    pub structured_patch: Vec<StructuredPatchHunk>,
    #[serde(rename = "originalFile")]
    pub original_file: Option<String>,
    #[serde(rename = "gitDiff")]
    pub git_diff: Option<serde_json::Value>,
}

/// Output envelope for targeted string-replacement edits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EditFileOutput {
    #[serde(rename = "filePath")]
    pub file_path: String,
    #[serde(rename = "oldString")]
    pub old_string: String,
    #[serde(rename = "newString")]
    pub new_string: String,
    #[serde(rename = "originalFile")]
    pub original_file: String,
    #[serde(rename = "structuredPatch")]
    pub structured_patch: Vec<StructuredPatchHunk>,
    #[serde(rename = "userModified")]
    pub user_modified: bool,
    #[serde(rename = "replaceAll")]
    pub replace_all: bool,
    #[serde(rename = "gitDiff")]
    pub git_diff: Option<serde_json::Value>,
}


/// Output envelope for Markdown annotation insertions.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnnotateMarkdownOutput {
    #[serde(rename = "filePath")]
    pub file_path: String,

    pub annotation: String,

    pub anchor: Option<String>,

    pub position: String,

    #[serde(rename = "originalFile")]
    pub original_file: String,

    #[serde(rename = "structuredPatch")]
    pub structured_patch: Vec<StructuredPatchHunk>,

    #[serde(rename = "gitDiff")]
    pub git_diff: Option<String>,
}

/// Result of a glob-based filename search.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct GlobSearchOutput {
    #[serde(rename = "durationMs")]
    pub duration_ms: u128,
    #[serde(rename = "numFiles")]
    pub num_files: usize,
    pub filenames: Vec<String>,
    pub truncated: bool,
}

/// Parameters accepted by the grep-style search tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepSearchInput {
    pub pattern: String,
    pub path: Option<String>,
    pub glob: Option<String>,
    #[serde(rename = "output_mode")]
    pub output_mode: Option<String>,
    #[serde(rename = "-B")]
    pub before: Option<usize>,
    #[serde(rename = "-A")]
    pub after: Option<usize>,
    #[serde(rename = "-C")]
    pub context_short: Option<usize>,
    pub context: Option<usize>,
    #[serde(rename = "-n")]
    pub line_numbers: Option<bool>,
    #[serde(rename = "-i")]
    pub case_insensitive: Option<bool>,
    #[serde(rename = "type")]
    pub file_type: Option<String>,
    pub head_limit: Option<usize>,
    pub offset: Option<usize>,
    pub multiline: Option<bool>,
}

/// Result payload returned by the grep-style search tool.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GrepSearchOutput {
    pub mode: Option<String>,
    #[serde(rename = "numFiles")]
    pub num_files: usize,
    pub filenames: Vec<String>,
    pub content: Option<String>,
    #[serde(rename = "numLines")]
    pub num_lines: Option<usize>,
    #[serde(rename = "numMatches")]
    pub num_matches: Option<usize>,
    #[serde(rename = "appliedLimit")]
    pub applied_limit: Option<usize>,
    #[serde(rename = "appliedOffset")]
    pub applied_offset: Option<usize>,
}

/// Reads a text file and returns a line-windowed payload.
pub fn read_file(
    path: &str,
    offset: Option<usize>,
    limit: Option<usize>,
) -> io::Result<ReadFileOutput> {
    let absolute_path = normalize_path(path)?;

    // Check file size before reading
    let metadata = fs::metadata(&absolute_path)?;
    if metadata.len() > MAX_READ_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "file is too large ({} bytes, max {} bytes)",
                metadata.len(),
                MAX_READ_SIZE
            ),
        ));
    }

    // Detect binary files
    if is_binary_file(&absolute_path)? {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "file appears to be binary",
        ));
    }

    let content = fs::read_to_string(&absolute_path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start_index = offset.unwrap_or(0).min(lines.len());
    let end_index = limit.map_or(lines.len(), |limit| {
        start_index.saturating_add(limit).min(lines.len())
    });
    let selected = lines[start_index..end_index].join("\n");

    Ok(ReadFileOutput {
        kind: String::from("text"),
        file: TextFilePayload {
            file_path: absolute_path.to_string_lossy().into_owned(),
            content: selected,
            num_lines: end_index.saturating_sub(start_index),
            start_line: start_index.saturating_add(1),
            total_lines: lines.len(),
        },
    })
}

fn detect_line_ending_style(text: &str) -> &'static str {
    if text.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    }
}

fn normalize_line_endings_to(text: &str, newline: &str) -> String {
    let normalized = text.replace("\r\n", "\n").replace('\r', "\n");

    if newline == "\n" {
        normalized
    } else {
        normalized.replace('\n', newline)
    }
}

fn preserve_existing_text_style(content: &str, original: Option<&str>) -> String {
    let Some(original) = original else {
        return content.to_owned();
    };

    let newline = detect_line_ending_style(original);
    let mut styled = normalize_line_endings_to(content, newline);

    if original.starts_with('\u{feff}') && !styled.starts_with('\u{feff}') {
        styled.insert(0, '\u{feff}');
    }

    styled
}

struct NormalizedText {
    text: String,
    original_offsets: Vec<usize>,
}

fn push_mapped_char(
    normalized: &mut String,
    offsets: &mut Vec<usize>,
    ch: char,
    original_start: usize,
    original_end: usize,
) {
    let mut buffer = [0u8; 4];
    let encoded = ch.encode_utf8(&mut buffer);

    normalized.push(ch);

    for index in 1..=encoded.len() {
        if index == encoded.len() {
            offsets.push(original_end);
        } else {
            offsets.push(original_start);
        }
    }
}

fn normalize_text_with_offsets(original: &str) -> NormalizedText {
    let bytes = original.as_bytes();
    let mut normalized = String::new();
    let mut offsets = vec![0usize];

    let mut index = 0usize;
    while index < bytes.len() {
        if bytes[index] == b'\r' {
            if index + 1 < bytes.len() && bytes[index + 1] == b'\n' {
                push_mapped_char(&mut normalized, &mut offsets, '\n', index, index + 2);
                index += 2;
            } else {
                push_mapped_char(&mut normalized, &mut offsets, '\n', index, index + 1);
                index += 1;
            }
            continue;
        }

        let ch = original[index..]
            .chars()
            .next()
            .expect("valid UTF-8 text should yield a character");
        let end = index + ch.len_utf8();

        push_mapped_char(&mut normalized, &mut offsets, ch, index, end);
        index = end;
    }

    NormalizedText {
        text: normalized,
        original_offsets: offsets,
    }
}

fn replace_mapped_ranges(original: &str, ranges: &[(usize, usize)], replacement: &str) -> String {
    let mut updated = String::new();
    let mut cursor = 0usize;

    for &(start, end) in ranges {
        updated.push_str(&original[cursor..start]);
        updated.push_str(replacement);
        cursor = end;
    }

    updated.push_str(&original[cursor..]);
    updated
}

fn replace_text_preserving_style(
    original: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> io::Result<String> {
    if old_string.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "old_string must not be empty",
        ));
    }

    let replacement = normalize_line_endings_to(new_string, detect_line_ending_style(original));

    if original.contains(old_string) {
        let updated = if replace_all {
            original.replace(old_string, &replacement)
        } else {
            original.replacen(old_string, &replacement, 1)
        };

        return Ok(updated);
    }

    let normalized_original = normalize_text_with_offsets(original);
    let normalized_old = normalize_line_endings_to(old_string, "\n");

    let mut ranges = Vec::new();

    if replace_all {
        let mut search_start = 0usize;

        while let Some(relative_start) = normalized_original.text[search_start..].find(&normalized_old)
        {
            let normalized_start = search_start + relative_start;
            let normalized_end = normalized_start + normalized_old.len();

            ranges.push((
                normalized_original.original_offsets[normalized_start],
                normalized_original.original_offsets[normalized_end],
            ));

            search_start = normalized_end;
        }
    } else if let Some(normalized_start) = normalized_original.text.find(&normalized_old) {
        let normalized_end = normalized_start + normalized_old.len();

        ranges.push((
            normalized_original.original_offsets[normalized_start],
            normalized_original.original_offsets[normalized_end],
        ));
    }

    if ranges.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "old_string not found in file, including CRLF/LF-compatible matching",
        ));
    }

    Ok(replace_mapped_ranges(original, &ranges, &replacement))
}


fn is_markdown_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .map(|extension| {
            let extension = extension.to_ascii_lowercase();
            extension == "md" || extension == "markdown"
        })
        .unwrap_or(false)
}

fn escape_html_text(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn build_ai_annotation_block(annotation: &str, newline: &str) -> io::Result<String> {
    let annotation = annotation.trim();

    if annotation.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "annotation must not be empty",
        ));
    }

    let annotation = normalize_line_endings_to(annotation, "\n");

    let mut block = String::new();

    for line in annotation.lines() {
        let cleaned_line = line
            .trim()
            .trim_start_matches('>')
            .trim()
            .trim_start_matches("AI 批注：")
            .trim_start_matches("AI批注：")
            .trim_start_matches("批注：")
            .trim();

        if cleaned_line.is_empty() {
            block.push_str(newline);
        } else {
            block.push_str("<mark style=\"background:#d3f8b6;\">");
            block.push_str(&escape_html_text(cleaned_line));
            block.push_str("</mark>");
            block.push_str(newline);
        }
    }

    Ok(block)
}

fn normalize_annotation_position(
    position: Option<&str>,
    has_anchor: bool,
) -> io::Result<&'static str> {
    let position = position.unwrap_or(if has_anchor { "after" } else { "end" });

    match position {
        "before" => Ok("before"),
        "after" => Ok("after"),
        "end" => Ok("end"),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "position must be one of: before, after, end",
        )),
    }
}

fn find_unique_anchor_range(original: &str, anchor: &str) -> io::Result<(usize, usize)> {
    if anchor.trim().is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "anchor must not be empty",
        ));
    }

    let exact_matches: Vec<(usize, &str)> = original.match_indices(anchor).collect();

    if exact_matches.len() == 1 {
        let start = exact_matches[0].0;
        return Ok((start, start + anchor.len()));
    }

    if exact_matches.len() > 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "anchor matched multiple locations in the Markdown file",
        ));
    }

    let normalized_original = normalize_text_with_offsets(original);
    let normalized_anchor = normalize_line_endings_to(anchor, "\n");

    let mut ranges = Vec::new();

    for (normalized_start, _) in normalized_original.text.match_indices(&normalized_anchor) {
        let normalized_end = normalized_start + normalized_anchor.len();

        ranges.push((
            normalized_original.original_offsets[normalized_start],
            normalized_original.original_offsets[normalized_end],
        ));
    }

    ranges.sort_unstable();
    ranges.dedup();

    match ranges.len() {
        1 => Ok(ranges[0]),
        0 => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "anchor not found in Markdown file",
        )),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "anchor matched multiple locations in the Markdown file",
        )),
    }
}

fn line_start_for_index(text: &str, index: usize) -> usize {
    text[..index].rfind('\n').map_or(0, |position| position + 1)
}

fn line_end_for_index(text: &str, index: usize) -> usize {
    text[index..]
        .find('\n')
        .map_or(text.len(), |position| index + position + 1)
}

fn insert_annotation_block(
    original: &str,
    insert_at: usize,
    block: &str,
    newline: &str,
) -> String {
    let mut insertion = String::new();

    if insert_at > 0 {
        let before = &original[..insert_at];

        if before.ends_with("\r\n\r\n") || before.ends_with("\n\n") {
            // Already separated.
        } else if before.ends_with('\n') {
            insertion.push_str(newline);
        } else {
            insertion.push_str(newline);
            insertion.push_str(newline);
        }
    }

    insertion.push_str(block);

    if insert_at < original.len() && !insertion.ends_with(newline) {
        insertion.push_str(newline);
    }

    let mut updated = String::new();
    updated.push_str(&original[..insert_at]);
    updated.push_str(&insertion);
    updated.push_str(&original[insert_at..]);
    updated
}

/// Replaces a file's contents and returns patch metadata.
pub fn write_file(path: &str, content: &str) -> io::Result<WriteFileOutput> {
    if content.len() > MAX_WRITE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "content is too large ({} bytes, max {} bytes)",
                content.len(),
                MAX_WRITE_SIZE
            ),
        ));
    }

    let absolute_path = normalize_path_allow_missing(path)?;
    let original_file = fs::read_to_string(&absolute_path).ok();
    let styled_content = preserve_existing_text_style(content, original_file.as_deref());

    if styled_content.len() > MAX_WRITE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "styled content is too large ({} bytes, max {} bytes)",
                styled_content.len(),
                MAX_WRITE_SIZE
            ),
        ));
    }

    if let Some(parent) = absolute_path.parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(&absolute_path, &styled_content)?;

    Ok(WriteFileOutput {
        kind: if original_file.is_some() {
            String::from("update")
        } else {
            String::from("create")
        },
        file_path: absolute_path.to_string_lossy().into_owned(),
        content: styled_content.clone(),
        structured_patch: make_patch(original_file.as_deref().unwrap_or(""), &styled_content),
        original_file,
        git_diff: None,
    })
}

/// Performs an in-file string replacement and returns patch metadata.
pub fn edit_file(
    path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
) -> io::Result<EditFileOutput> {
    let absolute_path = normalize_path(path)?;
    let original_file = fs::read_to_string(&absolute_path)?;

    if old_string == new_string {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "old_string and new_string must differ",
        ));
    }

    let updated = replace_text_preserving_style(
        &original_file,
        old_string,
        new_string,
        replace_all,
    )?;

    fs::write(&absolute_path, &updated)?;

    Ok(EditFileOutput {
        file_path: absolute_path.to_string_lossy().into_owned(),
        old_string: old_string.to_owned(),
        new_string: new_string.to_owned(),
        original_file: original_file.clone(),
        structured_patch: make_patch(&original_file, &updated),
        user_modified: false,
        replace_all,
        git_diff: None,
    })
}

/// Inserts an AI annotation block into a Markdown file without modifying existing text.
pub fn annotate_markdown(
    path: &str,
    annotation: &str,
    anchor: Option<&str>,
    position: Option<&str>,
) -> io::Result<AnnotateMarkdownOutput> {
    let absolute_path = normalize_path(path)?;

    if !is_markdown_path(&absolute_path) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "annotate_markdown only supports .md and .markdown files",
        ));
    }

    let original_file = fs::read_to_string(&absolute_path)?;
    let newline = detect_line_ending_style(&original_file);
    let position = normalize_annotation_position(position, anchor.is_some())?;
    let annotation_block = build_ai_annotation_block(annotation, newline)?;

    let insert_at = if position == "end" {
        original_file.len()
    } else {
        let anchor = anchor.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "anchor is required when position is before or after",
            )
        })?;

        let (anchor_start, anchor_end) = find_unique_anchor_range(&original_file, anchor)?;

        match position {
            "before" => line_start_for_index(&original_file, anchor_start),
            "after" => line_end_for_index(&original_file, anchor_end),
            _ => unreachable!("position has already been normalized"),
        }
    };

    let updated = insert_annotation_block(&original_file, insert_at, &annotation_block, newline);

    if updated.len() > MAX_WRITE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "annotated file is too large ({} bytes, max {} bytes)",
                updated.len(),
                MAX_WRITE_SIZE
            ),
        ));
    }

    fs::write(&absolute_path, &updated)?;

    Ok(AnnotateMarkdownOutput {
        file_path: absolute_path.to_string_lossy().into_owned(),
        annotation: annotation.to_owned(),
        anchor: anchor.map(ToOwned::to_owned),
        position: position.to_owned(),
        original_file: original_file.clone(),
        structured_patch: make_patch(&original_file, &updated),
        git_diff: None,
    })
}


/// Expands a glob pattern and returns matching filenames.
pub fn glob_search(pattern: &str, path: Option<&str>) -> io::Result<GlobSearchOutput> {
    glob_search_impl(pattern, path, None)
}

fn glob_search_impl(
    pattern: &str,
    path: Option<&str>,
    workspace_root: Option<&Path>,
) -> io::Result<GlobSearchOutput> {
    let started = Instant::now();
    let base_dir = path
        .map(normalize_path)
        .transpose()?
        .unwrap_or(std::env::current_dir()?);
    let canonical_root = workspace_root.map(canonicalize_workspace_root);
    if let Some(root) = canonical_root.as_deref() {
        validate_workspace_boundary(&base_dir, root)?;
    }
    let search_pattern = if Path::new(pattern).is_absolute() {
        pattern.to_owned()
    } else {
        base_dir.join(pattern).to_string_lossy().into_owned()
    };

    // On Windows, `Path::to_string_lossy()` uses `\` as separator, but the
    // `glob` / `Pattern` crate treats `\` as an escape character. Normalize
    // all backslashes to forward slashes so glob patterns work correctly.
    let search_pattern = normalize_glob_pattern_text(&search_pattern);

    // The `glob` crate does not support brace expansion ({a,b,c}).
    // Expand braces into multiple patterns so patterns like
    // `Assets/**/*.{cs,uxml,uss}` work correctly.
    let expanded = expand_braces(&search_pattern);

    let mut seen = HashSet::new();
    let mut matches = Vec::new();
    for pat in &expanded {
        let compiled = Pattern::new(pat)
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        let walk_root = derive_glob_walk_root(pat);
        if let Some(root) = canonical_root.as_deref() {
            let canonical_walk_root = walk_root
                .canonicalize()
                .unwrap_or_else(|_| walk_root.clone());
            validate_workspace_boundary(&canonical_walk_root, root)?;
        }
        let entries = WalkDir::new(&walk_root)
            .into_iter()
            .filter_entry(|entry| !should_skip_glob_dir(entry));
        for entry in entries.flatten() {
            let candidate = entry.path();
            if entry.file_type().is_file()
                && compiled.matches(&normalize_glob_pattern_text(&candidate.to_string_lossy()))
                && seen.insert(candidate.to_path_buf())
            {
                if let Some(root) = canonical_root.as_deref() {
                    let canonical_candidate = candidate.canonicalize()?;
                    validate_workspace_boundary(&canonical_candidate, root)?;
                }
                matches.push(candidate.to_path_buf());
            }
        }
    }

    matches.sort_by_key(|path| {
        fs::metadata(path)
            .and_then(|metadata| metadata.modified())
            .ok()
            .map(Reverse)
    });

    let truncated = matches.len() > 100;
    let filenames = matches
        .into_iter()
        .take(100)
        .map(|path| normalize_glob_pattern_text(&path.to_string_lossy()))
        .collect::<Vec<_>>();

    Ok(GlobSearchOutput {
        duration_ms: started.elapsed().as_millis(),
        num_files: filenames.len(),
        filenames,
        truncated,
    })
}

/// Runs a regex search over workspace files with optional context lines.
pub fn grep_search(input: &GrepSearchInput) -> io::Result<GrepSearchOutput> {
    grep_search_impl(input, None)
}

fn grep_search_impl(
    input: &GrepSearchInput,
    workspace_root: Option<&Path>,
) -> io::Result<GrepSearchOutput> {
    let base_path = input
        .path
        .as_deref()
        .map(normalize_path)
        .transpose()?
        .unwrap_or(std::env::current_dir()?);
    let canonical_root = workspace_root.map(canonicalize_workspace_root);
    if let Some(root) = canonical_root.as_deref() {
        validate_workspace_boundary(&base_path, root)?;
    }

    let regex = RegexBuilder::new(&input.pattern)
        .case_insensitive(input.case_insensitive.unwrap_or(false))
        .dot_matches_new_line(input.multiline.unwrap_or(false))
        .build()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;

    let glob_filter = input
        .glob
        .as_deref()
        .map(|g| Pattern::new(&normalize_glob_pattern_text(g)))
        .transpose()
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
    let file_type = input.file_type.as_deref();
    let output_mode = input
        .output_mode
        .clone()
        .unwrap_or_else(|| String::from("files_with_matches"));
    let context = input.context.or(input.context_short).unwrap_or(0);

    let mut filenames = Vec::new();
    let mut content_lines = Vec::new();
    let mut total_matches = 0usize;

    for file_path in collect_search_files(&base_path)? {
        if let Some(root) = canonical_root.as_deref() {
            let canonical_file = file_path.canonicalize()?;
            validate_workspace_boundary(&canonical_file, root)?;
        }
        if !matches_optional_filters(&file_path, glob_filter.as_ref(), file_type) {
            continue;
        }

        let Ok(file_contents) = fs::read_to_string(&file_path) else {
            continue;
        };

        if output_mode == "count" {
            let count = regex.find_iter(&file_contents).count();
            if count > 0 {
                filenames.push(file_path.to_string_lossy().into_owned());
                total_matches += count;
            }
            continue;
        }

        let lines: Vec<&str> = file_contents.lines().collect();
        let mut matched_lines = Vec::new();
        for (index, line) in lines.iter().enumerate() {
            if regex.is_match(line) {
                total_matches += 1;
                matched_lines.push(index);
            }
        }

        if matched_lines.is_empty() {
            continue;
        }

        filenames.push(file_path.to_string_lossy().into_owned());
        if output_mode == "content" {
            for index in matched_lines {
                let start = index.saturating_sub(input.before.unwrap_or(context));
                let end = (index + input.after.unwrap_or(context) + 1).min(lines.len());
                for (current, line) in lines.iter().enumerate().take(end).skip(start) {
                    let prefix = if input.line_numbers.unwrap_or(true) {
                        format!("{}:{}:", file_path.to_string_lossy(), current + 1)
                    } else {
                        format!("{}:", file_path.to_string_lossy())
                    };
                    content_lines.push(format!("{prefix}{line}"));
                }
            }
        }
    }

    let (filenames, applied_limit, applied_offset) =
        apply_limit(filenames, input.head_limit, input.offset);
    if output_mode == "content" {
        return Ok(build_grep_content_output(
            output_mode,
            filenames,
            content_lines,
            input.head_limit,
            input.offset,
        ));
    }

    Ok(GrepSearchOutput {
        mode: Some(output_mode.clone()),
        num_files: filenames.len(),
        filenames,
        content: None,
        num_lines: None,
        num_matches: (output_mode == "count").then_some(total_matches),
        applied_limit,
        applied_offset,
    })
}

fn build_grep_content_output(
    output_mode: String,
    filenames: Vec<String>,
    content_lines: Vec<String>,
    head_limit: Option<usize>,
    offset: Option<usize>,
) -> GrepSearchOutput {
    let (lines, limit, offset) = apply_limit(content_lines, head_limit, offset);
    GrepSearchOutput {
        mode: Some(output_mode),
        num_files: filenames.len(),
        filenames,
        num_lines: Some(lines.len()),
        content: Some(lines.join("\n")),
        num_matches: None,
        applied_limit: limit,
        applied_offset: offset,
    }
}

fn canonicalize_workspace_root(workspace_root: &Path) -> PathBuf {
    let canonical = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());

    normalize_windows_extended_path(&canonical)
}

/// On Windows, `Path::to_string_lossy()` uses `\` as the path separator,
/// but the `glob` and `Pattern` crate treat `\` as an escape character.
/// This function converts all backslashes to forward slashes in a pattern.
fn normalize_glob_pattern_text(pattern: &str) -> String {
    #[cfg(not(target_os = "windows"))]
    {
        pattern.to_owned()
    }
    #[cfg(target_os = "windows")]
    {
        pattern.replace('\\', "/")
    }
}

fn should_skip_glob_dir(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| GLOB_SEARCH_IGNORED_DIRS.contains(&name))
}

fn derive_glob_walk_root(pattern: &str) -> PathBuf {
    let path = Path::new(pattern);
    let mut prefix = PathBuf::new();
    let mut saw_component = false;

    for component in path.components() {
        let text = component.as_os_str().to_string_lossy();
        if component_contains_glob(&text) {
            break;
        }
        prefix.push(component.as_os_str());
        saw_component = true;
    }

    if saw_component {
        prefix
    } else {
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    }
}

fn component_contains_glob(component: &str) -> bool {
    component.contains('*') || component.contains('?') || component.contains('[')
}

fn collect_search_files(base_path: &Path) -> io::Result<Vec<PathBuf>> {
    if base_path.is_file() {
        return Ok(vec![base_path.to_path_buf()]);
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(base_path) {
        let entry = entry.map_err(|error| io::Error::other(error.to_string()))?;
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }
    Ok(files)
}

fn matches_optional_filters(
    path: &Path,
    glob_filter: Option<&Pattern>,
    file_type: Option<&str>,
) -> bool {
    if let Some(glob_filter) = glob_filter {
        let path_string = normalize_glob_pattern_text(&path.to_string_lossy());
        if !glob_filter.matches(&path_string) && !glob_filter.matches_path(path) {
            return false;
        }
    }

    if let Some(file_type) = file_type {
        let extension = path.extension().and_then(|extension| extension.to_str());
        if extension != Some(file_type) {
            return false;
        }
    }

    true
}

fn apply_limit<T>(
    items: Vec<T>,
    limit: Option<usize>,
    offset: Option<usize>,
) -> (Vec<T>, Option<usize>, Option<usize>) {
    let offset_value = offset.unwrap_or(0);
    let mut items = items.into_iter().skip(offset_value).collect::<Vec<_>>();
    let explicit_limit = limit.unwrap_or(250);
    if explicit_limit == 0 {
        return (items, None, (offset_value > 0).then_some(offset_value));
    }

    let truncated = items.len() > explicit_limit;
    items.truncate(explicit_limit);
    (
        items,
        truncated.then_some(explicit_limit),
        (offset_value > 0).then_some(offset_value),
    )
}

fn make_patch(original: &str, updated: &str) -> Vec<StructuredPatchHunk> {
    if original == updated {
        return Vec::new();
    }

    let original_lines: Vec<&str> = original.lines().collect();
    let updated_lines: Vec<&str> = updated.lines().collect();

    let mut prefix_len = 0usize;
    while prefix_len < original_lines.len()
        && prefix_len < updated_lines.len()
        && original_lines[prefix_len] == updated_lines[prefix_len]
    {
        prefix_len += 1;
    }

    let mut original_suffix_start = original_lines.len();
    let mut updated_suffix_start = updated_lines.len();

    while original_suffix_start > prefix_len
        && updated_suffix_start > prefix_len
        && original_lines[original_suffix_start - 1] == updated_lines[updated_suffix_start - 1]
    {
        original_suffix_start -= 1;
        updated_suffix_start -= 1;
    }

    const CONTEXT_LINES: usize = 3;

    let old_hunk_start = prefix_len.saturating_sub(CONTEXT_LINES);
    let new_hunk_start = prefix_len.saturating_sub(CONTEXT_LINES);

    let old_hunk_end = original_suffix_start
        .saturating_add(CONTEXT_LINES)
        .min(original_lines.len());
    let new_hunk_end = updated_suffix_start
        .saturating_add(CONTEXT_LINES)
        .min(updated_lines.len());

    let mut lines = Vec::new();

    for line in &original_lines[old_hunk_start..prefix_len] {
        lines.push(format!(" {line}"));
    }

    for line in &original_lines[prefix_len..original_suffix_start] {
        lines.push(format!("-{line}"));
    }

    for line in &updated_lines[prefix_len..updated_suffix_start] {
        lines.push(format!("+{line}"));
    }

    for line in &original_lines[original_suffix_start..old_hunk_end] {
        lines.push(format!(" {line}"));
    }

    vec![StructuredPatchHunk {
        old_start: old_hunk_start + 1,
        old_lines: old_hunk_end.saturating_sub(old_hunk_start),
        new_start: new_hunk_start + 1,
        new_lines: new_hunk_end.saturating_sub(new_hunk_start),
        lines,
    }]
}

fn normalize_path(path: &str) -> io::Result<PathBuf> {
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()?.join(path)
    };
    candidate.canonicalize()
}

fn normalize_path_allow_missing(path: &str) -> io::Result<PathBuf> {
    let candidate = if Path::new(path).is_absolute() {
        PathBuf::from(path)
    } else {
        std::env::current_dir()?.join(path)
    };

    if let Ok(canonical) = candidate.canonicalize() {
        return Ok(canonical);
    }

    if let Some(parent) = candidate.parent() {
        let canonical_parent = parent
            .canonicalize()
            .unwrap_or_else(|_| parent.to_path_buf());
        if let Some(name) = candidate.file_name() {
            return Ok(canonical_parent.join(name));
        }
    }

    Ok(candidate)
}

/// Read a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn read_file_in_workspace(
    path: &str,
    offset: Option<usize>,
    limit: Option<usize>,
    workspace_root: &Path,
) -> io::Result<ReadFileOutput> {
    let absolute_path = normalize_path(path)?;
    let canonical_root = canonicalize_workspace_root(workspace_root);
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    read_file(path, offset, limit)
}

/// Write a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn write_file_in_workspace(
    path: &str,
    content: &str,
    workspace_root: &Path,
) -> io::Result<WriteFileOutput> {
    let absolute_path = normalize_path_allow_missing(path)?;
    let canonical_root = canonicalize_workspace_root(workspace_root);
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    write_file(path, content)
}

/// Edit a file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn edit_file_in_workspace(
    path: &str,
    old_string: &str,
    new_string: &str,
    replace_all: bool,
    workspace_root: &Path,
) -> io::Result<EditFileOutput> {
    let absolute_path = normalize_path(path)?;
    let canonical_root = canonicalize_workspace_root(workspace_root);
    validate_workspace_boundary(&absolute_path, &canonical_root)?;
    edit_file(path, old_string, new_string, replace_all)
}

/// Insert an AI annotation block into a Markdown file with workspace boundary enforcement.
#[allow(dead_code)]
pub fn annotate_markdown_in_workspace(
    path: &str,
    annotation: &str,
    anchor: Option<&str>,
    position: Option<&str>,
    workspace_root: &Path,
) -> io::Result<AnnotateMarkdownOutput> {
    let absolute_path = normalize_path(path)?;
    let canonical_root = canonicalize_workspace_root(workspace_root);

    validate_workspace_boundary(&absolute_path, &canonical_root)?;

    annotate_markdown(path, annotation, anchor, position)
}


/// Expand a glob pattern with workspace boundary enforcement.
#[allow(dead_code)]
pub fn glob_search_in_workspace(
    pattern: &str,
    path: Option<&str>,
    workspace_root: &Path,
) -> io::Result<GlobSearchOutput> {
    glob_search_impl(pattern, path, Some(workspace_root))
}

/// Search file contents with workspace boundary enforcement.
#[allow(dead_code)]
pub fn grep_search_in_workspace(
    input: &GrepSearchInput,
    workspace_root: &Path,
) -> io::Result<GrepSearchOutput> {
    grep_search_impl(input, Some(workspace_root))
}

/// Check whether a path is a symlink that resolves outside the workspace.
#[allow(dead_code)]
pub fn is_symlink_escape(path: &Path, workspace_root: &Path) -> io::Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_symlink() {
        return Ok(false);
    }
    let resolved = path.canonicalize()?;
    let canonical_root = workspace_root
        .canonicalize()
        .unwrap_or_else(|_| workspace_root.to_path_buf());
    Ok(!resolved.starts_with(&canonical_root))
}

/// Expand shell-style brace groups in a glob pattern.
///
/// Handles one level of braces: `foo.{a,b,c}` → `["foo.a", "foo.b", "foo.c"]`.
/// Nested braces are not expanded (uncommon in practice).
/// Patterns without braces pass through unchanged.
fn expand_braces(pattern: &str) -> Vec<String> {
    let Some(open) = pattern.find('{') else {
        return vec![pattern.to_owned()];
    };
    let Some(close) = pattern[open..].find('}').map(|i| open + i) else {
        // Unmatched brace — treat as literal.
        return vec![pattern.to_owned()];
    };
    let prefix = &pattern[..open];
    let suffix = &pattern[close + 1..];
    let alternatives = &pattern[open + 1..close];
    alternatives
        .split(',')
        .flat_map(|alt| expand_braces(&format!("{prefix}{alt}{suffix}")))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        component_contains_glob, derive_glob_walk_root, edit_file, expand_braces, glob_search,
        grep_search, is_symlink_escape, read_file, read_file_in_workspace, write_file,
        write_file_in_workspace, GrepSearchInput, MAX_WRITE_SIZE,
    };

    fn temp_path(name: &str) -> std::path::PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time should move forward")
            .as_nanos();
        std::env::temp_dir().join(format!("clawd-native-{name}-{unique}"))
    }

    #[test]
    fn reads_and_writes_files() {
        let path = temp_path("read-write.txt");
        let write_output = write_file(path.to_string_lossy().as_ref(), "one\ntwo\nthree")
            .expect("write should succeed");
        assert_eq!(write_output.kind, "create");

        let read_output = read_file(path.to_string_lossy().as_ref(), Some(1), Some(1))
            .expect("read should succeed");
        assert_eq!(read_output.file.content, "two");
    }

    #[test]
    fn edits_file_contents() {
        let path = temp_path("edit.txt");
        write_file(path.to_string_lossy().as_ref(), "alpha beta alpha")
            .expect("initial write should succeed");
        let output = edit_file(path.to_string_lossy().as_ref(), "alpha", "omega", true)
            .expect("edit should succeed");
        assert!(output.replace_all);
    }

    #[test]
    fn rejects_binary_files() {
        let path = temp_path("binary-test.bin");
        std::fs::write(&path, b"\x00\x01\x02\x03binary content").expect("write should succeed");
        let result = read_file(path.to_string_lossy().as_ref(), None, None);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("binary"));
    }

    #[test]
    fn rejects_oversized_writes() {
        let path = temp_path("oversize-write.txt");
        let huge = "x".repeat(MAX_WRITE_SIZE + 1);
        let result = write_file(path.to_string_lossy().as_ref(), &huge);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("too large"));
    }

    #[test]
    fn enforces_workspace_boundary() {
        let workspace = temp_path("workspace-boundary");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        let inside = workspace.join("inside.txt");
        write_file(inside.to_string_lossy().as_ref(), "safe content")
            .expect("write inside workspace should succeed");

        // Reading inside workspace should succeed
        let result =
            read_file_in_workspace(inside.to_string_lossy().as_ref(), None, None, &workspace);
        assert!(result.is_ok());

        // Reading outside workspace should fail
        let outside = temp_path("outside-boundary.txt");
        write_file(outside.to_string_lossy().as_ref(), "unsafe content")
            .expect("write outside should succeed");
        let result =
            read_file_in_workspace(outside.to_string_lossy().as_ref(), None, None, &workspace);
        assert!(result.is_err());
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("escapes workspace"));
    }

    #[test]
    fn detects_symlink_escape() {
        let workspace = temp_path("symlink-workspace");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        let outside = temp_path("symlink-target.txt");
        std::fs::write(&outside, "target content").expect("target should write");

        let link_path = workspace.join("escape-link.txt");
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&outside, &link_path).expect("symlink should create");
            assert!(is_symlink_escape(&link_path, &workspace).expect("check should succeed"));
        }

        // Non-symlink file should not be an escape
        let normal = workspace.join("normal.txt");
        std::fs::write(&normal, "normal content").expect("normal file should write");
        assert!(!is_symlink_escape(&normal, &workspace).expect("check should succeed"));
    }

    #[test]
    #[cfg(unix)]
    fn workspace_read_rejects_symlink_escape_regression_3007_class() {
        let workspace = temp_path("workspace-read-symlink-escape");
        let outside = temp_path("workspace-read-symlink-target");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        std::fs::create_dir_all(&outside).expect("outside dir should be created");
        let outside_file = outside.join("secret.txt");
        std::fs::write(&outside_file, "outside secret").expect("outside file should write");

        let link_path = workspace.join("linked-secret.txt");
        std::os::unix::fs::symlink(&outside_file, &link_path).expect("symlink should create");

        let result =
            read_file_in_workspace(link_path.to_string_lossy().as_ref(), None, None, &workspace);

        assert!(result.is_err(), "symlink escape must be rejected");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("escapes workspace"),
            "error should explain workspace escape: {error}"
        );

        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    #[cfg(unix)]
    fn workspace_write_rejects_parent_symlink_escape_regression_3007_class() {
        let workspace = temp_path("workspace-write-symlink-escape");
        let outside = temp_path("workspace-write-symlink-target");
        std::fs::create_dir_all(&workspace).expect("workspace dir should be created");
        std::fs::create_dir_all(&outside).expect("outside dir should be created");

        let link_dir = workspace.join("linked-outside");
        std::os::unix::fs::symlink(&outside, &link_dir).expect("symlink dir should create");
        let escaped_child = link_dir.join("created.txt");

        let result = write_file_in_workspace(
            escaped_child.to_string_lossy().as_ref(),
            "must not escape",
            &workspace,
        );

        assert!(result.is_err(), "parent symlink escape must be rejected");
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert!(
            error.to_string().contains("escapes workspace"),
            "error should explain workspace escape: {error}"
        );
        assert!(
            !outside.join("created.txt").exists(),
            "write should not create through an escaping symlink"
        );

        let _ = std::fs::remove_dir_all(&workspace);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn globs_and_greps_directory() {
        let dir = temp_path("search-dir");
        std::fs::create_dir_all(&dir).expect("directory should be created");
        let file = dir.join("demo.rs");
        write_file(
            file.to_string_lossy().as_ref(),
            "fn main() {\n println!(\"hello\");\n}\n",
        )
        .expect("file write should succeed");

        let globbed = glob_search("**/*.rs", Some(dir.to_string_lossy().as_ref()))
            .expect("glob should succeed");
        assert_eq!(globbed.num_files, 1);

        let grep_output = grep_search(&GrepSearchInput {
            pattern: String::from("hello"),
            path: Some(dir.to_string_lossy().into_owned()),
            glob: Some(String::from("**/*.rs")),
            output_mode: Some(String::from("content")),
            before: None,
            after: None,
            context_short: None,
            context: None,
            line_numbers: Some(true),
            case_insensitive: Some(false),
            file_type: None,
            head_limit: Some(10),
            offset: Some(0),
            multiline: Some(false),
        })
        .expect("grep should succeed");
        assert!(grep_output.content.unwrap_or_default().contains("hello"));
    }

    #[test]
    fn expand_braces_no_braces() {
        assert_eq!(expand_braces("*.rs"), vec!["*.rs"]);
    }

    #[test]
    fn expand_braces_single_group() {
        let mut result = expand_braces("Assets/**/*.{cs,uxml,uss}");
        result.sort();
        assert_eq!(
            result,
            vec!["Assets/**/*.cs", "Assets/**/*.uss", "Assets/**/*.uxml",]
        );
    }

    #[test]
    fn expand_braces_nested() {
        let mut result = expand_braces("src/{a,b}.{rs,toml}");
        result.sort();
        assert_eq!(
            result,
            vec!["src/a.rs", "src/a.toml", "src/b.rs", "src/b.toml"]
        );
    }

    #[test]
    fn expand_braces_unmatched() {
        assert_eq!(expand_braces("foo.{bar"), vec!["foo.{bar"]);
    }

    #[test]
    fn glob_search_with_braces_finds_files() {
        let dir = temp_path("glob-braces");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("a.rs"), "fn main() {}").unwrap();
        std::fs::write(dir.join("b.toml"), "[package]").unwrap();
        std::fs::write(dir.join("c.txt"), "hello").unwrap();

        let result =
            glob_search("*.{rs,toml}", Some(dir.to_str().unwrap())).expect("glob should succeed");
        assert_eq!(
            result.num_files, 2,
            "should match .rs and .toml but not .txt"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_search_skips_common_heavy_directories() {
        let dir = temp_path("glob-ignored-dirs");
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::create_dir_all(dir.join("docs")).unwrap();
        std::fs::create_dir_all(dir.join("node_modules/pkg")).unwrap();
        std::fs::create_dir_all(dir.join(".build/checkouts/pkg")).unwrap();
        std::fs::create_dir_all(dir.join("target/debug/deps")).unwrap();

        std::fs::write(dir.join("src/AGENTS.md"), "src").unwrap();
        std::fs::write(dir.join("docs/AGENTS.md"), "docs").unwrap();
        std::fs::write(dir.join("node_modules/pkg/AGENTS.md"), "node_modules").unwrap();
        std::fs::write(dir.join(".build/checkouts/pkg/AGENTS.md"), ".build").unwrap();
        std::fs::write(dir.join("target/debug/deps/AGENTS.md"), "target").unwrap();

        let result =
            glob_search("**/AGENTS.md", Some(dir.to_str().unwrap())).expect("glob should succeed");

        assert_eq!(result.num_files, 2, "ignored dirs should be pruned");
        assert!(result
            .filenames
            .iter()
            .any(|path| path.ends_with("src/AGENTS.md")));
        assert!(result
            .filenames
            .iter()
            .any(|path| path.ends_with("docs/AGENTS.md")));
        assert!(!result
            .filenames
            .iter()
            .any(|path| path.contains("node_modules")
                || path.contains(".build")
                || path.contains("/target/")));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn derive_glob_walk_root_stops_at_first_glob_component() {
        let root = derive_glob_walk_root("/tmp/demo/**/AGENTS.md");
        assert_eq!(root, PathBuf::from("/tmp/demo"));
        assert!(component_contains_glob("**"));
        assert!(component_contains_glob("*.rs"));
        assert!(!component_contains_glob("src"));
    }
}
