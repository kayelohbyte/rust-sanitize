//! Log context extraction — finds keyword-matching lines and captures
//! surrounding context windows for LLM-friendly log triage.
//!
//! The extractor scans sanitized output line-by-line for any configured
//! keyword (substring match). For each hit it records the matching line,
//! up to N lines of context before and after, and the 1-based line number
//! so engineers can locate the entry in the original file.
//!
//! # Example
//!
//! ```rust
//! use sanitize_engine::log_context::{LogContextConfig, extract_context};
//!
//! let log = "INFO  start\nERROR disk full\nINFO  retrying\nINFO  done";
//!
//! let config = LogContextConfig::new().with_context_lines(1);
//! let result = extract_context(log, &config);
//!
//! assert_eq!(result.match_count, 1);
//! assert_eq!(result.matches[0].line_number, 2);
//! assert_eq!(result.matches[0].keyword, "error");
//! assert_eq!(result.matches[0].before, vec!["INFO  start"]);
//! assert_eq!(result.matches[0].after,  vec!["INFO  retrying"]);
//! ```

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Defaults
// ---------------------------------------------------------------------------

/// Built-in keywords used when no custom list is provided.
pub const DEFAULT_KEYWORDS: &[&str] = &[
    "error",
    "failure",
    "warning",
    "warn",
    "fatal",
    "exception",
    "critical",
];

/// Default lines of context captured before and after each match.
pub const DEFAULT_CONTEXT_LINES: usize = 10;

/// Default cap on matches returned in a single result.
pub const DEFAULT_MAX_MATCHES: usize = 50;

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for [`extract_context`].
///
/// Built with a fluent API; all setters consume and return `Self`.
///
/// # Example
///
/// ```rust
/// use sanitize_engine::log_context::LogContextConfig;
///
/// let config = LogContextConfig::new()
///     .with_extra_keywords(["timeout", "oomkilled"])
///     .with_context_lines(15)
///     .with_max_matches(100);
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogContextConfig {
    /// Keywords to scan for. Each is matched as a substring of the line.
    pub keywords: Vec<String>,

    /// Lines of context captured before and after each match.
    pub context_lines: usize,

    /// Maximum number of matches to return before setting
    /// [`LogContextResult::truncated`].
    pub max_matches: usize,

    /// When `true`, keyword matching is case-sensitive. Default: `false`.
    pub case_sensitive: bool,
}

impl Default for LogContextConfig {
    fn default() -> Self {
        Self {
            keywords: DEFAULT_KEYWORDS.iter().map(|&s| s.to_owned()).collect(),
            context_lines: DEFAULT_CONTEXT_LINES,
            max_matches: DEFAULT_MAX_MATCHES,
            case_sensitive: false,
        }
    }
}

impl LogContextConfig {
    /// Create a config with default settings.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Merge additional keywords into the existing list without replacing defaults.
    #[must_use]
    pub fn with_extra_keywords(
        mut self,
        extra: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        self.keywords.extend(extra.into_iter().map(Into::into));
        self
    }

    /// Replace all keywords with the given list.
    #[must_use]
    pub fn with_keywords(mut self, keywords: impl IntoIterator<Item = impl Into<String>>) -> Self {
        self.keywords = keywords.into_iter().map(Into::into).collect();
        self
    }

    /// Set how many lines of context to capture around each match.
    #[must_use]
    pub fn with_context_lines(mut self, n: usize) -> Self {
        self.context_lines = n;
        self
    }

    /// Set the maximum number of matches to return.
    #[must_use]
    pub fn with_max_matches(mut self, n: usize) -> Self {
        self.max_matches = n;
        self
    }

    /// Set case-sensitivity for keyword matching.
    #[must_use]
    pub fn case_sensitive(mut self, sensitive: bool) -> Self {
        self.case_sensitive = sensitive;
        self
    }
}

// ---------------------------------------------------------------------------
// Output types
// ---------------------------------------------------------------------------

/// A single keyword match with surrounding context lines.
#[derive(Debug, Clone, Serialize)]
pub struct LogContextMatch {
    /// 1-based line number of the matching line.
    pub line_number: usize,

    /// The keyword that triggered this match (preserves original casing
    /// from the config, not the casing found in the log line).
    pub keyword: String,

    /// The matching line as-is from the (sanitized) content.
    pub line: String,

    /// Up to [`LogContextConfig::context_lines`] lines immediately before
    /// the match, in document order.
    pub before: Vec<String>,

    /// Up to [`LogContextConfig::context_lines`] lines immediately after
    /// the match, in document order.
    pub after: Vec<String>,
}

/// Output of [`extract_context`].
#[derive(Debug, Clone, Serialize)]
pub struct LogContextResult {
    /// Total number of lines in the input.
    pub total_lines: usize,

    /// Number of matches present in [`Self::matches`].
    /// When [`Self::truncated`] is `true` this equals `max_matches`
    /// and additional matches exist beyond what was returned.
    pub match_count: usize,

    /// `true` when scanning stopped early because `max_matches` was reached.
    /// The caller should increase `max_matches` or narrow the keyword list
    /// if full coverage is required.
    pub truncated: bool,

    /// The matched lines and their context windows, in document order.
    pub matches: Vec<LogContextMatch>,
}

// ---------------------------------------------------------------------------
// Core function
// ---------------------------------------------------------------------------

/// Scan `content` for keyword matches and return surrounding context windows.
///
/// Each line is checked for any configured keyword as a substring match.
/// When multiple keywords appear on the same line the first keyword in
/// [`LogContextConfig::keywords`] wins. Line numbers in the output are
/// 1-based to match standard editor and log viewer conventions.
///
/// This function is allocation-efficient: lines are collected once into a
/// `Vec<&str>` and context slices reference that vec without additional copies
/// until the final owned `String`s are built for the result.
#[must_use]
pub fn extract_context(content: &str, config: &LogContextConfig) -> LogContextResult {
    let lines: Vec<&str> = content.lines().collect();
    let total_lines = lines.len();

    // Pre-normalise keywords once. Each pair is (normalised_for_comparison, original_index).
    // We store the index so we can retrieve the original keyword string for output.
    let normalised: Vec<String> = config
        .keywords
        .iter()
        .map(|kw| {
            if config.case_sensitive {
                kw.clone()
            } else {
                kw.to_lowercase()
            }
        })
        .collect();

    let mut matches: Vec<LogContextMatch> = Vec::new();
    let mut truncated = false;

    for (i, &line) in lines.iter().enumerate() {
        if matches.len() >= config.max_matches {
            truncated = true;
            break;
        }

        // Find the index of the first matching keyword.
        let hit_idx = if config.case_sensitive {
            normalised
                .iter()
                .position(|norm| line.contains(norm.as_str()))
        } else {
            let lower = line.to_lowercase();
            normalised
                .iter()
                .position(|norm| lower.contains(norm.as_str()))
        };

        if let Some(idx) = hit_idx {
            let before_start = i.saturating_sub(config.context_lines);
            let after_end = (i + config.context_lines + 1).min(total_lines);

            matches.push(LogContextMatch {
                line_number: i + 1,
                keyword: config.keywords[idx].clone(),
                line: line.to_owned(),
                before: lines[before_start..i]
                    .iter()
                    .map(|&s| s.to_owned())
                    .collect(),
                after: lines[i + 1..after_end]
                    .iter()
                    .map(|&s| s.to_owned())
                    .collect(),
            });
        }
    }

    let match_count = matches.len();
    LogContextResult {
        total_lines,
        match_count,
        truncated,
        matches,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_log(lines: &[&str]) -> String {
        lines.join("\n")
    }

    // ---- basic matching ----

    #[test]
    fn finds_error_line() {
        let log = make_log(&["INFO start", "ERROR disk full", "INFO done"]);
        let result = extract_context(&log, &LogContextConfig::new().with_context_lines(0));
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line_number, 2);
        assert_eq!(result.matches[0].keyword, "error");
        assert_eq!(result.matches[0].line, "ERROR disk full");
    }

    #[test]
    fn case_insensitive_by_default() {
        let log = make_log(&["WARNING high load", "Warning: retry", "warn: slow"]);
        let result = extract_context(&log, &LogContextConfig::new().with_context_lines(0));
        assert_eq!(result.match_count, 3);
    }

    #[test]
    fn case_sensitive_skips_uppercase() {
        let log = make_log(&["ERROR upper", "error lower"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .case_sensitive(true)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].line, "error lower");
    }

    // ---- context windows ----

    #[test]
    fn before_and_after_lines() {
        let log = make_log(&["a", "b", "ERROR c", "d", "e"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(1);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].before, vec!["b"]);
        assert_eq!(result.matches[0].after, vec!["d"]);
    }

    #[test]
    fn context_clipped_at_file_start() {
        let log = make_log(&["ERROR first", "INFO second", "INFO third"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(5);
        let result = extract_context(&log, &config);
        assert!(result.matches[0].before.is_empty());
        assert_eq!(result.matches[0].after.len(), 2);
    }

    #[test]
    fn context_clipped_at_file_end() {
        let log = make_log(&["INFO first", "INFO second", "ERROR last"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(5);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].before.len(), 2);
        assert!(result.matches[0].after.is_empty());
    }

    #[test]
    fn context_lines_zero() {
        let log = make_log(&["a", "ERROR b", "c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert!(result.matches[0].before.is_empty());
        assert!(result.matches[0].after.is_empty());
    }

    // ---- multiple matches ----

    #[test]
    fn multiple_matches_in_order() {
        let log = make_log(&["ERROR a", "INFO b", "FATAL c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error", "fatal"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
        assert_eq!(result.matches[0].line_number, 1);
        assert_eq!(result.matches[0].keyword, "error");
        assert_eq!(result.matches[1].line_number, 3);
        assert_eq!(result.matches[1].keyword, "fatal");
    }

    #[test]
    fn first_keyword_wins_on_same_line() {
        let log = "ERROR and WARNING on same line";
        let config = LogContextConfig::new()
            .with_keywords(["error", "warning"])
            .with_context_lines(0);
        let result = extract_context(log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "error");
    }

    // ---- max_matches and truncation ----

    #[test]
    fn truncated_when_max_reached() {
        let lines: Vec<String> = (0..10).map(|i| format!("ERROR line {i}")).collect();
        let log = lines.join("\n");
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_max_matches(3)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 3);
        assert!(result.truncated);
    }

    #[test]
    fn not_truncated_under_limit() {
        let log = make_log(&["ERROR a", "INFO b", "ERROR c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_max_matches(10)
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
        assert!(!result.truncated);
    }

    // ---- extra keywords ----

    #[test]
    fn extra_keywords_merge_with_defaults() {
        let log = make_log(&["ERROR a", "OOMKILLED b"]);
        let config = LogContextConfig::new()
            .with_extra_keywords(["oomkilled"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 2);
    }

    #[test]
    fn replace_keywords_removes_defaults() {
        let log = make_log(&["ERROR a", "CUSTOM b"]);
        let config = LogContextConfig::new()
            .with_keywords(["custom"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "custom");
    }

    // ---- edge cases ----

    #[test]
    fn empty_content() {
        let result = extract_context("", &LogContextConfig::new());
        assert_eq!(result.total_lines, 0);
        assert_eq!(result.match_count, 0);
        assert!(!result.truncated);
    }

    #[test]
    fn no_matches() {
        let log = make_log(&["INFO all good", "DEBUG trace", "INFO done"]);
        let result = extract_context(&log, &LogContextConfig::new());
        assert_eq!(result.match_count, 0);
        assert!(!result.truncated);
        assert_eq!(result.total_lines, 3);
    }

    #[test]
    fn single_line_match() {
        let result = extract_context("ERROR only line", &LogContextConfig::new());
        assert_eq!(result.total_lines, 1);
        assert_eq!(result.match_count, 1);
        assert!(result.matches[0].before.is_empty());
        assert!(result.matches[0].after.is_empty());
    }

    #[test]
    fn line_numbers_are_one_based() {
        let log = make_log(&["INFO a", "INFO b", "ERROR c"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(0);
        let result = extract_context(&log, &config);
        assert_eq!(result.matches[0].line_number, 3);
    }

    #[test]
    fn keyword_original_case_preserved_in_output() {
        let log = "TIMEOUT occurred";
        let config = LogContextConfig::new()
            .with_keywords(["Timeout"])
            .with_context_lines(0);
        let result = extract_context(log, &config);
        assert_eq!(result.match_count, 1);
        assert_eq!(result.matches[0].keyword, "Timeout");
    }

    // ---- serialization ----

    #[test]
    fn result_serializes_to_json() {
        let log = make_log(&["INFO ok", "ERROR fail", "INFO ok"]);
        let config = LogContextConfig::new()
            .with_keywords(["error"])
            .with_context_lines(1);
        let result = extract_context(&log, &config);
        let json = serde_json::to_string_pretty(&result).unwrap();
        assert!(json.contains("\"line_number\": 2"));
        assert!(json.contains("\"keyword\": \"error\""));
        assert!(json.contains("\"total_lines\": 3"));
        assert!(json.contains("\"truncated\": false"));
    }
}
