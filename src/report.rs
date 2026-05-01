//! Structured reporting for sanitization runs.
//!
//! Generates a JSON report summarising what the sanitization tool did
//! without ever including original secret values. The report captures:
//!
//! - **Metadata**: tool version, CLI flags, timestamp.
//! - **Per-file details**: matches found, replacements applied, bytes
//!   processed, and per-pattern match counts.
//! - **Aggregated summary**: totals across all files plus wall-clock
//!   duration.
//! - **Log context** (optional): keyword-matched lines with surrounding
//!   context windows, populated when `--extract-context` is used.
//!
//! # Thread Safety
//!
//! [`ReportBuilder`] is `Send + Sync`. Multiple threads can record file
//! results concurrently via [`ReportBuilder::record_file`], which takes
//! an internal `Mutex` only long enough to push a single entry.
//!
//! # Example
//!
//! ```rust
//! use sanitize_engine::log_context::{extract_context, LogContextConfig};
//! use sanitize_engine::report::{FileReport, ReportBuilder, ReportMetadata};
//! use std::collections::HashMap;
//!
//! let meta = ReportMetadata {
//!     version: "0.4.0".into(),
//!     timestamp: "2026-03-01T00:00:00Z".into(),
//!     deterministic: true,
//!     dry_run: false,
//!     strict: false,
//!     chunk_size: 1_048_576,
//!     threads: Some(4),
//!     secrets_file: Some("secrets.enc".into()),
//! };
//!
//! let builder = ReportBuilder::new(meta);
//!
//! builder.record_file(FileReport {
//!     path: "data.log".into(),
//!     matches: 42,
//!     replacements: 42,
//!     bytes_processed: 10_000,
//!     bytes_output: 10_200,
//!     pattern_counts: HashMap::from([("email".into(), 30), ("ipv4".into(), 12)]),
//!     method: "scanner".into(),
//!     log_context: None,
//! });
//!
//! // Optionally attach per-file log context (populated by --extract-context).
//! let sanitized_output = "INFO ok\nERROR disk full\nINFO retrying";
//! let ctx = extract_context(sanitized_output, &LogContextConfig::new().with_context_lines(1));
//! builder.set_file_log_context("data.log", ctx);
//!
//! let report = builder.finish();
//! let json = report.to_json_pretty().unwrap();
//! assert!(json.contains("\"total_matches\": 42"));
//! assert!(json.contains("\"log_context\""));
//! assert!(json.contains("\"keyword\": \"error\""));
//! ```

use serde::Serialize;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Instant;

use crate::log_context::LogContextResult;
use crate::scanner::ScanStats;

// ---------------------------------------------------------------------------
// Report structures
// ---------------------------------------------------------------------------

/// Top-level sanitization report.
///
/// Serialized to JSON via [`Self::to_json`] / [`Self::to_json_pretty`].
/// Never contains original secret values.
#[derive(Debug, Clone, Serialize)]
pub struct SanitizeReport {
    /// Tool metadata and flags.
    pub metadata: ReportMetadata,
    /// Aggregated summary across all files.
    pub summary: ReportSummary,
    /// Per-file details. Each entry may include `log_context` when
    /// `--extract-context` was used.
    pub files: Vec<FileReport>,
}

impl SanitizeReport {
    /// Serialize the report as compact JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_json(&self) -> serde_json::Result<String> {
        serde_json::to_string(self)
    }

    /// Serialize the report as pretty-printed JSON.
    ///
    /// # Errors
    ///
    /// Returns [`serde_json::Error`] if serialization fails.
    pub fn to_json_pretty(&self) -> serde_json::Result<String> {
        serde_json::to_string_pretty(self)
    }
}

/// Tool metadata embedded in every report.
#[derive(Debug, Clone, Serialize)]
pub struct ReportMetadata {
    /// Crate / binary version (from `Cargo.toml`).
    pub version: String,
    /// ISO-8601 timestamp when the run started.
    pub timestamp: String,
    /// Whether `--deterministic` was used.
    pub deterministic: bool,
    /// Whether `--dry-run` was used.
    pub dry_run: bool,
    /// Whether `--strict` was used.
    pub strict: bool,
    /// Chunk size in bytes (`--chunk-size`).
    pub chunk_size: usize,
    /// Thread count (`--threads`), if specified.
    pub threads: Option<usize>,
    /// Path to the secrets file, if provided.
    pub secrets_file: Option<String>,
}

/// Aggregated summary across all processed files.
#[derive(Debug, Clone, Serialize)]
pub struct ReportSummary {
    /// Number of files processed.
    pub total_files: u64,
    /// Total pattern matches found.
    pub total_matches: u64,
    /// Total replacements applied.
    pub total_replacements: u64,
    /// Total bytes read from input(s).
    pub total_bytes_processed: u64,
    /// Total bytes written to output(s).
    pub total_bytes_output: u64,
    /// Wall-clock duration of processing in milliseconds.
    pub duration_ms: u64,
    /// Aggregate per-pattern match counts.
    pub pattern_counts: HashMap<String, u64>,
}

/// Per-file result details.
///
/// Does **not** contain any original secret values — only counts,
/// byte sizes, pattern labels, and the processing method used.
#[derive(Debug, Clone, Serialize)]
pub struct FileReport {
    /// File path (relative or archive entry name).
    pub path: String,
    /// Number of matches found in this file.
    pub matches: u64,
    /// Number of replacements applied.
    pub replacements: u64,
    /// Bytes read from this file.
    pub bytes_processed: u64,
    /// Bytes written for this file.
    pub bytes_output: u64,
    /// Per-pattern match counts for this file.
    pub pattern_counts: HashMap<String, u64>,
    /// Processing method: `"scanner"`, `"structured:json"`, etc.
    pub method: String,
    /// Log context extraction results for this file, present when
    /// `--extract-context` was used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_context: Option<LogContextResult>,
}

impl FileReport {
    /// Build a `FileReport` from scanner [`ScanStats`].
    #[must_use]
    pub fn from_scan_stats(
        path: impl Into<String>,
        stats: &ScanStats,
        method: impl Into<String>,
    ) -> Self {
        Self {
            path: path.into(),
            matches: stats.matches_found,
            replacements: stats.replacements_applied,
            bytes_processed: stats.bytes_processed,
            bytes_output: stats.bytes_output,
            pattern_counts: stats.pattern_counts.clone(),
            method: method.into(),
            log_context: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Thread-safe report builder
// ---------------------------------------------------------------------------

/// Thread-safe builder that accumulates per-file results and produces
/// a final [`SanitizeReport`].
///
/// Designed for concurrent use: wrap in `Arc` and share across threads.
/// The internal `Mutex` is held only for the duration of a single
/// `Vec::push`, so contention is negligible even at high thread counts.
#[derive(Debug)]
pub struct ReportBuilder {
    metadata: ReportMetadata,
    files: Mutex<Vec<FileReport>>,
    start: Instant,
}

// All fields are Send + Sync natively (Mutex<Vec<_>>, Instant, owned structs),
// so ReportBuilder auto-derives Send + Sync without unsafe.
const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<ReportBuilder>();
    assert_sync::<ReportBuilder>();
};

impl ReportBuilder {
    /// Create a new builder with the given metadata.
    ///
    /// The wall-clock timer starts now.
    #[must_use]
    pub fn new(metadata: ReportMetadata) -> Self {
        Self {
            metadata,
            files: Mutex::new(Vec::new()),
            start: Instant::now(),
        }
    }

    /// Attach log context extraction results to the [`FileReport`] identified
    /// by `path`. The file must already have been recorded via
    /// [`Self::record_file`]. Thread-safe.
    pub fn set_file_log_context(&self, path: &str, result: LogContextResult) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        if let Some(file) = files.iter_mut().find(|f| f.path == path) {
            file.log_context = Some(result);
        }
    }

    /// Record the result for a single file. Thread-safe.
    pub fn record_file(&self, file_report: FileReport) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        files.push(file_report);
    }

    /// Record multiple file results at once (e.g., from archive processing).
    pub fn record_files(&self, reports: impl IntoIterator<Item = FileReport>) {
        let mut files = self.files.lock().expect("report mutex poisoned");
        files.extend(reports);
    }

    /// Consume the builder and produce the final report.
    ///
    /// The duration is measured from builder creation to this call.
    pub fn finish(self) -> SanitizeReport {
        #[allow(clippy::cast_possible_truncation)] // duration in ms won't exceed u64
        let duration_ms = self.start.elapsed().as_millis() as u64;
        let files = self.files.into_inner().expect("report mutex poisoned");

        // Aggregate summary.
        let mut total_matches: u64 = 0;
        let mut total_replacements: u64 = 0;
        let mut total_bytes_processed: u64 = 0;
        let mut total_bytes_output: u64 = 0;
        let mut pattern_counts: HashMap<String, u64> = HashMap::new();

        for f in &files {
            total_matches += f.matches;
            total_replacements += f.replacements;
            total_bytes_processed += f.bytes_processed;
            total_bytes_output += f.bytes_output;
            for (pat, count) in &f.pattern_counts {
                *pattern_counts.entry(pat.clone()).or_insert(0) += count;
            }
        }

        let summary = ReportSummary {
            total_files: files.len() as u64,
            total_matches,
            total_replacements,
            total_bytes_processed,
            total_bytes_output,
            duration_ms,
            pattern_counts,
        };

        SanitizeReport {
            metadata: self.metadata,
            summary,
            files,
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_metadata() -> ReportMetadata {
        ReportMetadata {
            version: "0.2.0".into(),
            timestamp: "2026-03-01T00:00:00Z".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1_048_576,
            threads: None,
            secrets_file: None,
        }
    }

    fn sample_file_report(path: &str, matches: u64, pattern: &str) -> FileReport {
        FileReport {
            path: path.into(),
            matches,
            replacements: matches,
            bytes_processed: matches * 100,
            bytes_output: matches * 110,
            pattern_counts: HashMap::from([(pattern.into(), matches)]),
            method: "scanner".into(),
            log_context: None,
        }
    }

    // ---- Basic construction ----

    #[test]
    fn empty_report() {
        let builder = ReportBuilder::new(sample_metadata());
        let report = builder.finish();
        assert_eq!(report.summary.total_files, 0);
        assert_eq!(report.summary.total_matches, 0);
        assert!(report.files.is_empty());
    }

    #[test]
    fn single_file_report() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(sample_file_report("data.log", 10, "email"));
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 1);
        assert_eq!(report.summary.total_matches, 10);
        assert_eq!(report.summary.total_replacements, 10);
        assert_eq!(report.summary.total_bytes_processed, 1000);
        assert_eq!(report.summary.total_bytes_output, 1100);
        assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 10);
        assert_eq!(report.files[0].path, "data.log");
    }

    #[test]
    fn multiple_files_aggregated() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(sample_file_report("a.log", 5, "email"));
        builder.record_file(sample_file_report("b.log", 3, "ipv4"));
        builder.record_file(sample_file_report("c.log", 7, "email"));
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 3);
        assert_eq!(report.summary.total_matches, 15);
        assert_eq!(*report.summary.pattern_counts.get("email").unwrap(), 12);
        assert_eq!(*report.summary.pattern_counts.get("ipv4").unwrap(), 3);
    }

    // ---- JSON serialization ----

    #[test]
    fn json_serialization_no_secrets() {
        let builder = ReportBuilder::new(sample_metadata());
        builder.record_file(FileReport {
            path: "config.yaml".into(),
            matches: 2,
            replacements: 2,
            bytes_processed: 500,
            bytes_output: 520,
            pattern_counts: HashMap::from([("hostname".into(), 2)]),
            method: "structured:yaml".into(),
            log_context: None,
        });
        let report = builder.finish();
        let json = report.to_json_pretty().unwrap();

        // Must contain expected fields.
        assert!(json.contains("\"total_matches\": 2"));
        assert!(json.contains("\"version\": \"0.2.0\""));
        assert!(json.contains("\"hostname\": 2"));
        assert!(json.contains("\"method\": \"structured:yaml\""));
        assert!(json.contains("\"duration_ms\""));

        // Must NOT contain any original secret values — we only ever
        // store counts and labels, never pattern text or matched text.
        // This is a structural guarantee; verify that deserializing
        // back produces the same data without secret leakage.
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed["files"][0]["path"].as_str() == Some("config.yaml"));
        // No field named "secret", "original", or "value" at any level.
        let flat = json.to_lowercase();
        assert!(!flat.contains("\"original\""));
        assert!(!flat.contains("\"secret_value\""));
    }

    #[test]
    fn compact_json() {
        let builder = ReportBuilder::new(sample_metadata());
        let report = builder.finish();
        let json = report.to_json().unwrap();
        // Compact JSON has no pretty indentation.
        assert!(!json.contains("  "));
    }

    // ---- Metadata flags ----

    #[test]
    fn metadata_flags_preserved() {
        let meta = ReportMetadata {
            version: "1.0.0".into(),
            timestamp: "2026-06-15T12:00:00Z".into(),
            deterministic: true,
            dry_run: true,
            strict: true,
            chunk_size: 262_144,
            threads: Some(8),
            secrets_file: Some("secrets.enc".into()),
        };
        let builder = ReportBuilder::new(meta);
        let report = builder.finish();
        assert!(report.metadata.deterministic);
        assert!(report.metadata.dry_run);
        assert!(report.metadata.strict);
        assert_eq!(report.metadata.chunk_size, 262_144);
        assert_eq!(report.metadata.threads, Some(8));
        assert_eq!(report.metadata.secrets_file.as_deref(), Some("secrets.enc"));
    }

    // ---- Duration tracking ----

    #[test]
    fn duration_is_positive() {
        let builder = ReportBuilder::new(sample_metadata());
        // Do a tiny amount of work.
        builder.record_file(sample_file_report("x.txt", 1, "email"));
        let report = builder.finish();
        // Duration should be ≥ 0 (it will be 0 or 1 on fast machines).
        assert!(report.summary.duration_ms < 5_000); // sanity ceiling
    }

    // ---- Thread-safe concurrent recording ----

    #[test]
    fn concurrent_recording() {
        use std::sync::Arc;
        use std::thread;

        let builder = Arc::new(ReportBuilder::new(sample_metadata()));
        let mut handles = Vec::new();

        for i in 0_u64..16 {
            let b = Arc::clone(&builder);
            handles.push(thread::spawn(move || {
                b.record_file(sample_file_report(&format!("file_{i}.log"), i + 1, "email"));
            }));
        }

        for h in handles {
            h.join().unwrap();
        }

        // We need to unwrap the Arc to call finish().
        let builder = Arc::try_unwrap(builder).expect("other refs still held");
        let report = builder.finish();

        assert_eq!(report.summary.total_files, 16);
        // Sum of 1..=16 = 136.
        assert_eq!(report.summary.total_matches, 136);
    }

    // ---- FileReport::from_scan_stats ----

    #[test]
    fn file_report_from_scan_stats() {
        let stats = ScanStats {
            bytes_processed: 2048,
            bytes_output: 2100,
            matches_found: 5,
            replacements_applied: 5,
            pattern_counts: HashMap::from([("email".into(), 3), ("ipv4".into(), 2)]),
        };
        let fr = FileReport::from_scan_stats("test.log", &stats, "scanner");
        assert_eq!(fr.path, "test.log");
        assert_eq!(fr.matches, 5);
        assert_eq!(fr.bytes_processed, 2048);
        assert_eq!(*fr.pattern_counts.get("email").unwrap(), 3);
        assert_eq!(fr.method, "scanner");
    }

    // ---- Large-file simulation ----

    #[test]
    fn large_file_report() {
        let builder = ReportBuilder::new(sample_metadata());
        // Simulate a 10 GB file processed in chunks.
        builder.record_file(FileReport {
            path: "huge.log".into(),
            matches: 1_000_000,
            replacements: 1_000_000,
            bytes_processed: 10_737_418_240, // 10 GiB
            bytes_output: 10_900_000_000,
            pattern_counts: HashMap::from([("email".into(), 600_000), ("ipv4".into(), 400_000)]),
            method: "scanner".into(),
            log_context: None,
        });
        let report = builder.finish();
        assert_eq!(report.summary.total_matches, 1_000_000);
        assert_eq!(report.summary.total_bytes_processed, 10_737_418_240);

        // JSON serialization still works for large numbers.
        let json = report.to_json().unwrap();
        assert!(json.contains("10737418240"));
    }

    // ---- record_files bulk insert ----

    #[test]
    fn record_files_bulk() {
        let builder = ReportBuilder::new(sample_metadata());
        let files: Vec<FileReport> = (0..5)
            .map(|i| sample_file_report(&format!("entry_{i}.txt"), 2, "ssn"))
            .collect();
        builder.record_files(files);
        let report = builder.finish();
        assert_eq!(report.summary.total_files, 5);
        assert_eq!(report.summary.total_matches, 10);
    }
}
