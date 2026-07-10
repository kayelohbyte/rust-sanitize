//! Whitespace-columns processor for fixed-header command output.
//!
//! Handles `ps aux` / `top -b` style listings that support bundles capture
//! verbatim: a header line of column names followed by rows aligned on
//! whitespace runs:
//!
//! ```text
//! USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
//! root           1  0.0  0.5 167576 11132 ?        Ss   Jun24   0:11 /sbin/init
//! jdoe        1234  2.0  1.1 981432 22208 ?        Sl   Jun24   3:02 ruby puma
//! ```
//!
//! Field rules match by **header column name** (exact or glob, like other
//! processors' key matching). Behaviour:
//!
//! - A line containing a token that matches a field rule is treated as the
//!   header: it fixes the column positions and is emitted unchanged. A later
//!   matching line re-keys the columns (repeated `top -b` iterations).
//! - Lines before the first header, and lines with fewer tokens than the
//!   header (`top` preamble, wrapped output), pass through unchanged.
//! - In data rows, the token at each matched column index is replaced via the
//!   rule's category. The final column is matched only up to its own token —
//!   trailing free-text (a `COMMAND` with arguments) is one token per rule
//!   match, so match trailing columns deliberately.
//!
//! `min_length` on the rule is the practical guard here: preamble lines that
//! happen to reach the header's token count carry short tokens (`-`, counts)
//! at the matched index, and service-account rows (`git`, `sshd`) are usually
//! shorter than real usernames.

use crate::error::Result;
use crate::processor::limits::DEFAULT_INPUT_SIZE;
use crate::processor::{
    apply_edits, check_size_and_decode, edit_token, find_matching_rule, FileTypeProfile, Processor,
    Replacement,
};
use crate::store::MappingStore;

/// Structured processor for whitespace-aligned columnar command output.
pub struct ColumnsProcessor;

/// `(start, end)` byte spans of the whitespace-separated tokens of `line`.
fn token_spans(line: &str) -> Vec<(usize, usize)> {
    let bytes = line.as_bytes();
    let mut spans = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let start = i;
        while i < bytes.len() && !bytes[i].is_ascii_whitespace() {
            i += 1;
        }
        spans.push((start, i));
    }
    spans
}

/// Column indices of header tokens that match a field rule, with the matched
/// column's name. Empty when `line` is not a header for this profile.
fn matched_header_columns(line: &str, profile: &FileTypeProfile) -> Vec<(usize, String)> {
    token_spans(line)
        .iter()
        .enumerate()
        .filter_map(|(idx, &(s, e))| {
            let name = &line[s..e];
            find_matching_rule(name, profile).map(|_| (idx, name.to_string()))
        })
        .collect()
}

/// Compute the span edits for `content`: for every data row under a detected
/// header, replace the token in each rule-matched column.
fn compute_edits(
    text: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
) -> Result<Vec<Replacement>> {
    let mut edits = Vec::new();
    // (column index, column name) pairs of the active header, plus its width.
    let mut header: Option<(Vec<(usize, String)>, usize)> = None;

    let mut line_start = 0usize;
    for line in text.split_inclusive('\n') {
        let body = line.trim_end_matches(['\n', '\r']);
        let matched = matched_header_columns(body, profile);
        if !matched.is_empty() {
            header = Some((matched, token_spans(body).len()));
            line_start += line.len();
            continue;
        }
        if let Some((columns, width)) = &header {
            let spans = token_spans(body);
            // Preamble/wrapped lines are narrower than the header; skip them.
            if spans.len() >= *width {
                for (idx, name) in columns {
                    let (s, e) = spans[*idx];
                    let value = &body[s..e];
                    if let Some(token) = edit_token(name, name, value, profile, store)? {
                        edits.push(Replacement::new(line_start + s, line_start + e, token));
                    }
                }
            }
        }
        line_start += line.len();
    }
    Ok(edits)
}

impl Processor for ColumnsProcessor {
    fn name(&self) -> &'static str {
        "columns"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "columns"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        let text = check_size_and_decode(content, "columns", DEFAULT_INPUT_SIZE)?;
        let edits = compute_edits(text, profile, store)?;
        Ok(apply_edits(content, edits))
    }

    fn process_to_edits(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Option<Vec<Replacement>>> {
        let text = check_size_and_decode(content, "columns", DEFAULT_INPUT_SIZE)?;
        Ok(Some(compute_edits(text, profile, store)?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use std::sync::Arc;

    fn store() -> MappingStore {
        MappingStore::new(Arc::new(HmacGenerator::new([42u8; 32])), None)
    }

    fn user_profile(min_length: usize) -> FileTypeProfile {
        FileTypeProfile::new(
            "columns",
            vec![FieldRule::new("USER")
                .with_category(Category::Name)
                .with_min_length(min_length)],
        )
    }

    #[test]
    fn ps_user_column_is_replaced() {
        let input = b"USER         PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n\
                      git            1  0.0  0.5 167576 11132 ?        Ss   Jun24   0:11 /sbin/init\n\
                      jdoeworth   1234  2.0  1.1 981432 22208 ?        Sl   Jun24   3:02 ruby puma\n";
        let st = store();
        let out = ColumnsProcessor
            .process(input, &user_profile(4), &st)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("jdoeworth"), "username replaced: {out}");
        assert!(out.contains("git "), "min_length keeps 'git': {out}");
        assert!(
            out.contains("USER") && out.contains("/sbin/init") && out.contains("ruby puma"),
            "header and commands preserved: {out}"
        );
    }

    #[test]
    fn top_preamble_lines_pass_through() {
        // top -b preamble reaches the header's width on some lines; the
        // min_length guard plus width check must leave it untouched.
        let input = b"top - 04:01:46 up 5 days,  3:22,  1 user,  load average: 0.10, 0.20, 0.30\n\
                      Tasks: 270 total,   1 running, 269 sleeping,   0 stopped,   0 zombie\n\
                      \n\
                      \x20   PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n\
                      \x20  1234 jdoeworth 20   0  981432  22208  11132 S   2.0   1.1   3:02.11 ruby\n";
        let st = store();
        let out = ColumnsProcessor
            .process(input, &user_profile(4), &st)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("jdoeworth"), "username replaced: {out}");
        assert!(
            out.contains("load average: 0.10, 0.20, 0.30") && out.contains("Tasks: 270 total"),
            "preamble untouched: {out}"
        );
    }

    #[test]
    fn lines_before_header_are_untouched() {
        let input = b"no header yet alice bob\nUSER PID\nalice 12\n";
        let st = store();
        let out = ColumnsProcessor
            .process(input, &user_profile(4), &st)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            out.starts_with("no header yet alice bob\n"),
            "pre-header lines pass through: {out}"
        );
        assert!(!out.contains("\nalice 12"), "data row replaced: {out}");
    }

    #[test]
    fn repeated_headers_rekey_columns() {
        // top -b -n 2: the header repeats; the second block must still match.
        let input = b"USER PID\nalice 12\nUSER PID\nbobby 34\n";
        let st = store();
        let out = ColumnsProcessor
            .process(input, &user_profile(4), &st)
            .unwrap();
        let out = String::from_utf8(out).unwrap();
        assert!(
            !out.contains("alice") && !out.contains("bobby"),
            "both blocks replaced: {out}"
        );
    }
}
