//! Streaming scanner for detecting and replacing sensitive data.
//!
//! # Architecture
//!
//! The streaming scanner processes input data in configurable chunks,
//! detecting secret patterns (regex or literal) and applying one-way
//! replacements via the [`MappingStore`].
//! This design supports files of 20–100 GB+ without requiring the entire
//! content to fit in memory.
//!
//! ```text
//! ┌──────────────┐     ┌─────────────────┐     ┌──────────────────┐
//! │  Input (Read) │ ──▶ │  StreamScanner  │ ──▶ │  Output (Write)  │
//! │  (chunked)    │     │  (pattern match │     │  (sanitized)     │
//! └──────────────┘     │   + replace)    │     └──────────────────┘
//!                       └────────┬────────┘
//!                                │
//!                       ┌────────▼────────┐
//!                       │  MappingStore   │
//!                       │  (dedup cache)  │
//!                       └─────────────────┘
//! ```
//!
//! # Chunk Overlap Strategy
//!
//! To avoid missing matches that span chunk boundaries, the scanner
//! maintains an overlap window between consecutive chunks:
//!
//! 1. Read `chunk_size` bytes of new data.
//! 2. Prepend the `carry` buffer (tail of previous window).
//! 3. Scan the combined `window` for all pattern matches.
//! 4. Compute `commit_point = window.len() - overlap_size` (adjusted
//!    upward if a match straddles the boundary).
//! 5. Emit output for `window[..commit_point]` with replacements applied.
//! 6. Set `carry = window[commit_point..]` for the next iteration.
//!
//! The `overlap_size` should be ≥ the maximum expected match length to
//! guarantee no matches are missed at boundaries.
//!
//! # Thread Safety
//!
//! [`StreamScanner`] is `Send + Sync`. Multiple files can be scanned
//! concurrently using a shared `Arc<StreamScanner>`, all backed by the
//! same [`MappingStore`] for per-run dedup
//! consistency.
//!
//! # Performance
//!
//! - **Chunk-based I/O**: only `chunk_size + overlap_size` bytes in
//!   memory per active scan.
//! - **Compiled regex**: patterns are compiled once at construction and
//!   reused across all chunks and files.
//! - **Lock-free reads**: the `DashMap` inside `MappingStore` provides
//!   lock-free reads for already-seen values.
//! - **File-level parallelism**: share `Arc<StreamScanner>` across
//!   threads to scan multiple files concurrently.

use crate::category::Category;
use crate::error::{Result, SanitizeError};
use crate::store::MappingStore;
use regex::bytes::{Regex, RegexBuilder, RegexSet, RegexSetBuilder};
use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::Arc;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Default chunk size: 1 MiB.
const DEFAULT_CHUNK_SIZE: usize = 1024 * 1024;

/// Default overlap size: 4 KiB.
const DEFAULT_OVERLAP_SIZE: usize = 4096;

/// Maximum compiled regex automaton size (bytes). Prevents DoS via
/// pathologically complex user-supplied patterns.
const REGEX_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Maximum DFA cache size (bytes) per regex.
const REGEX_DFA_SIZE_LIMIT: usize = 1 << 20; // 1 MiB

/// Maximum number of patterns allowed in a single scanner (F-05 fix).
/// The `RegexSet` automaton memory scales linearly with pattern count.
/// With 1 MiB size/DFA limits per pattern, 10 000 patterns could
/// allocate up to ~20 GiB of automaton memory.  This cap prevents
/// accidental resource exhaustion.  Override via
/// [`StreamScanner::new_with_max_patterns`] if needed.
const DEFAULT_MAX_PATTERNS: usize = 10_000;

/// Configuration for the streaming scanner.
///
/// # Tuning Guide
///
/// | Workload               | `chunk_size` | `overlap_size` |
/// |------------------------|--------------|----------------|
/// | Small files (< 10 MB)  | 256 KiB      | 1 KiB          |
/// | General purpose        | 1 MiB        | 4 KiB          |
/// | Large files (> 1 GB)   | 4–8 MiB      | 8 KiB          |
/// | Memory-constrained     | 64 KiB       | 1 KiB          |
///
/// `overlap_size` should be ≥ the longest expected match. Most secret
/// patterns (API keys, emails, SSNs) are well under 256 bytes, so the
/// 4 KiB default provides ample margin.
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Size of each chunk read from the input (bytes).
    ///
    /// Larger chunks improve throughput (fewer syscalls) but use more
    /// memory. Default: 1 MiB.
    pub chunk_size: usize,

    /// Overlap between consecutive chunks (bytes).
    ///
    /// Must be ≥ the maximum expected match length. Patterns whose
    /// matches can exceed this length risk being missed at chunk
    /// boundaries. Default: 4 KiB.
    pub overlap_size: usize,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            chunk_size: DEFAULT_CHUNK_SIZE,
            overlap_size: DEFAULT_OVERLAP_SIZE,
        }
    }
}

impl ScanConfig {
    /// Create a new configuration with explicit values.
    #[must_use]
    pub fn new(chunk_size: usize, overlap_size: usize) -> Self {
        Self {
            chunk_size,
            overlap_size,
        }
    }

    /// Validate the configuration, returning an error if invalid.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if `chunk_size` is zero
    /// or `overlap_size >= chunk_size`.
    pub fn validate(&self) -> Result<()> {
        if self.chunk_size == 0 {
            return Err(SanitizeError::InvalidConfig(
                "chunk_size must be > 0".into(),
            ));
        }
        if self.overlap_size >= self.chunk_size {
            return Err(SanitizeError::InvalidConfig(
                "overlap_size must be < chunk_size".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Scan pattern
// ---------------------------------------------------------------------------

/// A pattern rule defining what to scan for and how to categorize matches.
///
/// Wraps a compiled [`regex::bytes::Regex`] with a [`Category`] for
/// replacement lookups and a human-readable label for reporting.
///
/// Both regex and literal patterns are supported. Literals are escaped
/// and compiled as regex for uniform handling.
pub struct ScanPattern {
    /// Compiled regex matcher.
    regex: Regex,
    /// Category for replacement lookups.
    category: Category,
    /// Human-readable label for reporting / stats.
    label: String,
}

impl std::fmt::Debug for ScanPattern {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScanPattern")
            .field("pattern", &self.regex.as_str())
            .field("category", &self.category)
            .field("label", &self.label)
            .finish()
    }
}

impl ScanPattern {
    /// Create a pattern from a regex string.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::PatternCompileError`] if the regex is invalid.
    ///
    /// # Examples
    ///
    /// ```
    /// use sanitize_engine::scanner::ScanPattern;
    /// use sanitize_engine::category::Category;
    ///
    /// let pat = ScanPattern::from_regex(
    ///     r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
    ///     Category::Email,
    ///     "email_address",
    /// ).unwrap();
    /// ```
    pub fn from_regex(pattern: &str, category: Category, label: impl Into<String>) -> Result<Self> {
        let regex = RegexBuilder::new(pattern)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(|e| SanitizeError::PatternCompileError(e.to_string()))?;
        Ok(Self {
            regex,
            category,
            label: label.into(),
        })
    }

    /// Create a pattern from a literal string.
    ///
    /// The literal is escaped so that regex metacharacters are matched
    /// verbatim.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::PatternCompileError`] if regex compilation fails.
    ///
    /// # Examples
    ///
    /// ```
    /// use sanitize_engine::scanner::ScanPattern;
    /// use sanitize_engine::category::Category;
    ///
    /// let pat = ScanPattern::from_literal(
    ///     "sk-proj-abc123secret",
    ///     Category::Custom("api_key".into()),
    ///     "openai_key",
    /// ).unwrap();
    /// ```
    pub fn from_literal(
        literal: &str,
        category: Category,
        label: impl Into<String>,
    ) -> Result<Self> {
        let escaped = regex::escape(literal);
        let regex = RegexBuilder::new(&escaped)
            .size_limit(REGEX_SIZE_LIMIT)
            .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
            .build()
            .map_err(|e| SanitizeError::PatternCompileError(e.to_string()))?;
        Ok(Self {
            regex,
            category,
            label: label.into(),
        })
    }

    /// The category this pattern maps to.
    #[must_use]
    pub fn category(&self) -> &Category {
        &self.category
    }

    /// The human-readable label.
    #[must_use]
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the raw regex pattern string for RegexSet construction.
    #[must_use]
    pub fn regex_pattern(&self) -> &str {
        self.regex.as_str()
    }
}

// ScanPattern is Send + Sync because:
// - regex::bytes::Regex is Send + Sync
// - Category is Send + Sync (it's an enum of primitives + CompactString)
// - String is Send + Sync

// ---------------------------------------------------------------------------
// Internal: raw match descriptor
// ---------------------------------------------------------------------------

/// A single match found during scanning (internal).
#[derive(Debug, Clone)]
struct RawMatch {
    /// Start byte offset within the scan window.
    start: usize,
    /// End byte offset (exclusive) within the scan window.
    end: usize,
    /// Index into the `StreamScanner::patterns` vector.
    pattern_idx: usize,
}

// ---------------------------------------------------------------------------
// Scan statistics
// ---------------------------------------------------------------------------

/// Statistics collected during a scan operation.
///
/// Returned by [`StreamScanner::scan_reader`] and
/// [`StreamScanner::scan_bytes`] to provide visibility into what
/// the scanner did.
#[derive(Debug, Clone, Default)]
pub struct ScanStats {
    /// Total bytes read from the input.
    pub bytes_processed: u64,
    /// Total bytes written to the output (may differ from `bytes_processed`
    /// when replacements have different lengths than the originals).
    pub bytes_output: u64,
    /// Total number of matches found across all patterns.
    pub matches_found: u64,
    /// Total number of replacements applied (always == `matches_found`
    /// in one-way mode).
    pub replacements_applied: u64,
    /// Per-pattern match counts, keyed by pattern label.
    pub pattern_counts: HashMap<String, u64>,
}

// ---------------------------------------------------------------------------
// StreamScanner
// ---------------------------------------------------------------------------

/// Streaming scanner that detects and replaces sensitive patterns.
///
/// Thread-safe: can be shared via `Arc<StreamScanner>` for concurrent
/// scanning of multiple files. Each call to [`scan_reader`](Self::scan_reader)
/// is independent and maintains its own chunking state.
///
/// # Usage
///
/// ```rust
/// use sanitize_engine::scanner::{StreamScanner, ScanPattern, ScanConfig};
/// use sanitize_engine::category::Category;
/// use sanitize_engine::generator::HmacGenerator;
/// use sanitize_engine::store::MappingStore;
/// use std::sync::Arc;
///
/// // 1. Build the replacement store.
/// let gen = Arc::new(HmacGenerator::new([42u8; 32]));
/// let store = Arc::new(MappingStore::new(gen, None));
///
/// // 2. Define patterns.
/// let patterns = vec![
///     ScanPattern::from_regex(
///         r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
///         Category::Email,
///         "email",
///     ).unwrap(),
/// ];
///
/// // 3. Create the scanner.
/// let scanner = StreamScanner::new(patterns, store, ScanConfig::default()).unwrap();
///
/// // 4. Scan.
/// let input = b"Contact alice@corp.com for details.";
/// let (output, stats) = scanner.scan_bytes(input).unwrap();
/// assert_eq!(stats.matches_found, 1);
/// assert!(!output.windows(b"alice@corp.com".len())
///     .any(|w| w == b"alice@corp.com"));
/// ```
pub struct StreamScanner {
    /// Compiled scan patterns.
    patterns: Vec<ScanPattern>,
    /// Pre-compiled set for fast multi-pattern pre-filtering.
    /// `matches()` returns which pattern indices matched, avoiding
    /// running every individual regex on each chunk (R-3 optimisation).
    regex_set: RegexSet,
    /// Thread-safe dedup replacement store.
    store: Arc<MappingStore>,
    /// Scanner configuration.
    config: ScanConfig,
}

impl StreamScanner {
    /// Create a new streaming scanner.
    ///
    /// # Arguments
    ///
    /// - `patterns` — the set of patterns to scan for.
    /// - `store` — the mapping store for dedup-consistent replacements.
    /// - `config` — chunking / overlap configuration.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if the configuration is
    /// invalid (e.g. `chunk_size == 0` or `overlap_size >= chunk_size`).
    pub fn new(
        patterns: Vec<ScanPattern>,
        store: Arc<MappingStore>,
        config: ScanConfig,
    ) -> Result<Self> {
        Self::new_with_max_patterns(patterns, store, config, DEFAULT_MAX_PATTERNS)
    }

    /// Create a new streaming scanner with a custom pattern limit.
    ///
    /// This is identical to [`new`](Self::new) but allows overriding the
    /// default pattern cap (10 000).  Use this
    /// when you have a legitimate need for more patterns and have
    /// verified that your system has enough memory for the resulting
    /// `RegexSet`.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::InvalidConfig`] if the configuration is
    /// invalid or the pattern count exceeds `max_patterns`.
    pub fn new_with_max_patterns(
        patterns: Vec<ScanPattern>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        max_patterns: usize,
    ) -> Result<Self> {
        config.validate()?;

        // F-05 fix: enforce maximum pattern count to bound RegexSet memory.
        if patterns.len() > max_patterns {
            return Err(SanitizeError::InvalidConfig(format!(
                "pattern count ({}) exceeds maximum allowed ({}) — \
                 RegexSet memory scales linearly with pattern count",
                patterns.len(),
                max_patterns
            )));
        }

        // Build a RegexSet from all pattern strings for fast pre-filtering.
        let regex_set = if patterns.is_empty() {
            RegexSetBuilder::new(Vec::<&str>::new())
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT)
                .build()
                .map_err(|e| SanitizeError::PatternCompileError(e.to_string()))?
        } else {
            let pattern_strs: Vec<&str> = patterns.iter().map(|p| p.regex_pattern()).collect();
            RegexSetBuilder::new(&pattern_strs)
                .size_limit(REGEX_SIZE_LIMIT * pattern_strs.len().max(1))
                .dfa_size_limit(REGEX_DFA_SIZE_LIMIT * pattern_strs.len().max(1))
                .build()
                .map_err(|e| SanitizeError::PatternCompileError(e.to_string()))?
        };

        Ok(Self {
            patterns,
            regex_set,
            store,
            config,
        })
    }

    /// Scan a reader and write sanitized output to a writer.
    ///
    /// Processes the input in chunks of `config.chunk_size` bytes,
    /// maintaining an overlap window of `config.overlap_size` bytes to
    /// catch matches spanning chunk boundaries. All detected matches
    /// are replaced one-way via the [`MappingStore`].
    ///
    /// # Arguments
    ///
    /// - `reader` — input source (file, network stream, `&[u8]`, …).
    /// - `writer` — output sink (file, `Vec<u8>`, …).
    ///
    /// # Returns
    ///
    /// [`ScanStats`] with counters for bytes processed, matches found, etc.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] on I/O failures or if a replacement
    /// cannot be generated (e.g. store capacity exceeded).
    pub fn scan_reader<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<ScanStats> {
        let mut stats = ScanStats::default();

        // Carry buffer: the tail of the previous window that needs
        // to be re-scanned with the next chunk.
        let mut carry: Vec<u8> = Vec::new();

        // Read buffer (reused across iterations to avoid re-allocation).
        let mut read_buf = vec![0u8; self.config.chunk_size];

        // Scan window (reused across iterations — grows to peak size then
        // stays there, avoiding per-chunk allocation).
        let mut window: Vec<u8> =
            Vec::with_capacity(self.config.chunk_size + self.config.overlap_size);

        loop {
            // Read the next chunk.
            let bytes_read = read_fully(&mut reader, &mut read_buf)?;
            let is_eof = bytes_read < read_buf.len();

            // Track only genuinely new bytes (carry was already counted).
            stats.bytes_processed += bytes_read as u64;

            if bytes_read == 0 && carry.is_empty() {
                break;
            }

            // Build the scan window: carry ++ new_data.
            // Reuse the window buffer to avoid per-chunk allocation.
            let new_data = &read_buf[..bytes_read];
            window.clear();
            window.extend_from_slice(&carry);
            window.extend_from_slice(new_data);

            if window.is_empty() {
                break;
            }

            // Find all non-overlapping matches in the window.
            let matches = self.find_matches(&window);

            // Determine the commit point — how much of the window we can
            // safely emit this iteration.
            let base_commit = if is_eof {
                window.len()
            } else {
                window.len().saturating_sub(self.config.overlap_size)
            };

            let commit_point =
                self.adjusted_commit_point(&matches, base_commit, window.len(), is_eof);

            // Select matches that fall entirely within the committed region.
            let committed_matches: Vec<&RawMatch> = matches
                .iter()
                .filter(|m| m.start < commit_point && m.end <= commit_point)
                .collect();

            // Apply replacements and write the committed output.
            let output =
                self.apply_replacements(&window[..commit_point], &committed_matches, &mut stats)?;
            writer
                .write_all(&output)
                .map_err(|e| SanitizeError::IoError(e.to_string()))?;
            stats.bytes_output += output.len() as u64;

            // Update carry for next iteration. Reuse the carry buffer
            // by copying remaining bytes down.
            if is_eof {
                carry.clear();
                break;
            }
            carry.clear();
            carry.extend_from_slice(&window[commit_point..]);
        }

        Ok(stats)
    }

    /// Convenience: scan byte slice in-memory and return sanitized output.
    ///
    /// Equivalent to `scan_reader(input, Vec::new())` but returns the
    /// output buffer directly.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`] if a replacement cannot be generated
    /// (e.g. store capacity exceeded).
    pub fn scan_bytes(&self, input: &[u8]) -> Result<(Vec<u8>, ScanStats)> {
        let mut output = Vec::with_capacity(input.len());
        let stats = self.scan_reader(input, &mut output)?;
        Ok((output, stats))
    }

    // ---- Accessors ----

    /// Access the scanner's configuration.
    #[must_use]
    pub fn config(&self) -> &ScanConfig {
        &self.config
    }

    /// Access the underlying mapping store.
    #[must_use]
    pub fn store(&self) -> &Arc<MappingStore> {
        &self.store
    }

    /// Number of patterns registered in this scanner.
    #[must_use]
    pub fn pattern_count(&self) -> usize {
        self.patterns.len()
    }

    /// Create a scanner from an encrypted secrets file.
    ///
    /// Decrypts the file in memory, parses the entries, compiles
    /// patterns, and returns the scanner ready to scan. Decrypted
    /// plaintext is scrubbed from memory after parsing.
    ///
    /// # Arguments
    ///
    /// - `encrypted_bytes` — raw bytes of the `.enc` file.
    /// - `password` — user password.
    /// - `format` — optional format override for the plaintext.
    /// - `store` — mapping store for dedup-consistent replacements.
    /// - `config` — chunking / overlap configuration.
    /// - `extra_patterns` — additional patterns to merge in.
    ///
    /// # Returns
    ///
    /// `(scanner, warnings)` where `warnings` lists entries that
    /// failed to compile (index + error).
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::SecretsError`] on decryption failure
    /// or [`SanitizeError::InvalidConfig`] on invalid scanner config.
    pub fn from_encrypted_secrets(
        encrypted_bytes: &[u8],
        password: &str,
        format: Option<crate::secrets::SecretsFormat>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        extra_patterns: Vec<ScanPattern>,
    ) -> Result<(Self, Vec<(usize, SanitizeError)>)> {
        let (mut patterns, warnings) =
            crate::secrets::load_encrypted_secrets(encrypted_bytes, password, format)?;
        patterns.extend(extra_patterns);
        let scanner = Self::new(patterns, store, config)?;
        Ok((scanner, warnings))
    }

    /// Create a scanner from a plaintext secrets file.
    ///
    /// Convenience for development / testing without encryption.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError::SecretsError`] on parse failure
    /// or [`SanitizeError::InvalidConfig`] on invalid scanner config.
    pub fn from_plaintext_secrets(
        plaintext: &[u8],
        format: Option<crate::secrets::SecretsFormat>,
        store: Arc<MappingStore>,
        config: ScanConfig,
        extra_patterns: Vec<ScanPattern>,
    ) -> Result<(Self, Vec<(usize, SanitizeError)>)> {
        let (mut patterns, warnings) = crate::secrets::load_plaintext_secrets(plaintext, format)?;
        patterns.extend(extra_patterns);
        let scanner = Self::new(patterns, store, config)?;
        Ok((scanner, warnings))
    }

    // ---- Internal helpers ----

    /// Find all non-overlapping matches across all patterns.
    ///
    /// Strategy: use the `RegexSet` for a fast check of which patterns
    /// have *any* match in the window, then run only those individual
    /// regexes for precise match positions.  This avoids running every
    /// pattern on every chunk (R-3 optimisation).
    fn find_matches(&self, window: &[u8]) -> Vec<RawMatch> {
        let mut all_matches = Vec::new();

        // Fast pre-filter: which patterns have at least one match?
        let active: Vec<usize> = self.regex_set.matches(window).into_iter().collect();

        // Only run individual regexes for patterns that matched.
        for &idx in &active {
            let pattern = &self.patterns[idx];
            for m in pattern.regex.find_iter(window) {
                all_matches.push(RawMatch {
                    start: m.start(),
                    end: m.end(),
                    pattern_idx: idx,
                });
            }
        }

        // Sort: primary by start (ascending), secondary by length
        // (descending — prefer longer matches when they start at the
        // same position).
        all_matches.sort_by(|a, b| {
            a.start
                .cmp(&b.start)
                .then_with(|| (b.end - b.start).cmp(&(a.end - a.start)))
        });

        // Greedily select non-overlapping matches.
        let mut selected = Vec::new();
        let mut last_end = 0;
        for m in all_matches {
            if m.start >= last_end {
                last_end = m.end;
                selected.push(m);
            }
        }

        selected
    }

    /// Adjust the commit point to avoid splitting a match across the
    /// commit / carry boundary.
    ///
    /// If any match straddles `base_commit` (starts before, ends after),
    /// the commit point is moved to after that match so it is emitted
    /// in full this iteration.
    #[allow(clippy::unused_self)] // keep &self for API consistency with other scanner methods
    fn adjusted_commit_point(
        &self,
        matches: &[RawMatch],
        base_commit: usize,
        window_len: usize,
        is_eof: bool,
    ) -> usize {
        if is_eof {
            return window_len;
        }

        let mut commit = base_commit;

        for m in matches {
            if m.start < commit && m.end > commit {
                // Match straddles the boundary — extend commit to include it.
                commit = m.end;
            }
        }

        // Never exceed window length.
        commit.min(window_len)
    }

    /// Build the output buffer for the committed region by splicing in
    /// replacements for every match.
    fn apply_replacements(
        &self,
        committed: &[u8],
        matches: &[&RawMatch],
        stats: &mut ScanStats,
    ) -> Result<Vec<u8>> {
        if matches.is_empty() {
            return Ok(committed.to_vec());
        }

        let mut output = Vec::with_capacity(committed.len());
        let mut last_end = 0;

        for m in matches {
            // Emit the non-matching region before this match.
            output.extend_from_slice(&committed[last_end..m.start]);

            // Extract the matched text (lossy UTF-8 for binary safety).
            let matched_bytes = &committed[m.start..m.end];
            let matched_text = String::from_utf8_lossy(matched_bytes);

            // Look up or create the one-way replacement.
            let pattern = &self.patterns[m.pattern_idx];
            let replacement = self.store.get_or_insert(&pattern.category, &matched_text)?;

            output.extend_from_slice(replacement.as_bytes());
            last_end = m.end;

            // Accumulate per-match stats.
            stats.matches_found += 1;
            stats.replacements_applied += 1;
            *stats
                .pattern_counts
                .entry(pattern.label.clone())
                .or_insert(0) += 1;
        }

        // Emit trailing non-matching region.
        output.extend_from_slice(&committed[last_end..]);

        Ok(output)
    }
}

// ---------------------------------------------------------------------------
// Send + Sync compile-time assertion
// ---------------------------------------------------------------------------

const _: fn() = || {
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<StreamScanner>();
    assert_sync::<StreamScanner>();
};

// ---------------------------------------------------------------------------
// I/O helper
// ---------------------------------------------------------------------------

/// Read up to `buf.len()` bytes from `reader`, retrying on `Interrupted`.
///
/// Returns the number of bytes actually read (< `buf.len()` only at EOF).
fn read_fully<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        match reader.read(&mut buf[total..]) {
            Ok(0) => break, // EOF
            Ok(n) => total += n,
            Err(ref e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(SanitizeError::IoError(e.to_string())),
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::HmacGenerator;

    /// Helper: build a scanner with given patterns and small chunk config.
    fn test_scanner(patterns: Vec<ScanPattern>) -> StreamScanner {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        StreamScanner::new(
            patterns,
            store,
            ScanConfig {
                chunk_size: 64,
                overlap_size: 16,
            },
        )
        .unwrap()
    }

    /// Helper: email pattern.
    fn email_pattern() -> ScanPattern {
        ScanPattern::from_regex(
            r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            Category::Email,
            "email",
        )
        .unwrap()
    }

    /// Helper: IPv4 pattern.
    fn ipv4_pattern() -> ScanPattern {
        ScanPattern::from_regex(
            r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b",
            Category::IpV4,
            "ipv4",
        )
        .unwrap()
    }

    // ---- Construction ----

    #[test]
    fn scanner_creation() {
        let scanner = test_scanner(vec![email_pattern()]);
        assert_eq!(scanner.pattern_count(), 1);
    }

    #[test]
    fn invalid_config_zero_chunk() {
        let gen = Arc::new(HmacGenerator::new([0u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let result = StreamScanner::new(vec![], store, ScanConfig::new(0, 0));
        assert!(result.is_err());
    }

    #[test]
    fn invalid_config_overlap_ge_chunk() {
        let gen = Arc::new(HmacGenerator::new([0u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let result = StreamScanner::new(vec![], store, ScanConfig::new(100, 100));
        assert!(result.is_err());
    }

    // ---- Empty / no-match cases ----

    #[test]
    fn empty_input() {
        let scanner = test_scanner(vec![email_pattern()]);
        let (output, stats) = scanner.scan_bytes(b"").unwrap();
        assert!(output.is_empty());
        assert_eq!(stats.matches_found, 0);
        assert_eq!(stats.bytes_processed, 0);
    }

    #[test]
    fn no_matches() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"There are no email addresses here.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(output, input.as_slice());
        assert_eq!(stats.matches_found, 0);
    }

    // ---- Single match ----

    #[test]
    fn single_email_replaced() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"Contact alice@corp.com for help.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        assert_eq!(stats.replacements_applied, 1);
        // Original must not appear in output.
        assert!(!output
            .windows(b"alice@corp.com".len())
            .any(|w| w == b"alice@corp.com"));
        // Replacement should contain the @ from the domain-preserving email.
        let output_str = String::from_utf8_lossy(&output);
        assert!(output_str.contains("@corp.com"));
        // Length preserved: output is same total length as input.
        assert_eq!(output.len(), input.len(), "length must be preserved");
        // Surrounding text preserved.
        assert!(output_str.starts_with("Contact "));
        assert!(output_str.ends_with(" for help."));
    }

    // ---- Multiple matches ----

    #[test]
    fn multiple_emails_replaced() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"From alice@corp.com to bob@corp.com cc admin@corp.com";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 3);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("alice@corp.com"));
        assert!(!out_str.contains("bob@corp.com"));
        assert!(!out_str.contains("admin@corp.com"));
    }

    // ---- Same secret gets same replacement ----

    #[test]
    fn same_secret_same_replacement() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"First alice@corp.com then alice@corp.com again.";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 2);
        let out_str = String::from_utf8_lossy(&output);
        // Both occurrences should be replaced with the same value.
        // With length-preserving replacements, look for the preserved domain.
        let parts: Vec<&str> = out_str.split("@corp.com").collect();
        // 3 parts = 2 occurrences of the replacement.
        assert_eq!(parts.len(), 3);
    }

    // ---- Literal pattern ----

    #[test]
    fn literal_pattern_matched() {
        let pat = ScanPattern::from_literal(
            "SECRET_API_KEY_12345",
            Category::Custom("api_key".into()),
            "api_key",
        )
        .unwrap();
        let scanner = test_scanner(vec![pat]);
        let input = b"key=SECRET_API_KEY_12345&foo=bar";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        assert!(!output
            .windows(b"SECRET_API_KEY_12345".len())
            .any(|w| w == b"SECRET_API_KEY_12345"));
    }

    // ---- Multiple pattern types ----

    #[test]
    fn multiple_pattern_types() {
        let scanner = test_scanner(vec![email_pattern(), ipv4_pattern()]);
        let input = b"Server 192.168.1.100 contact admin@server.com";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 2);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("192.168.1.100"));
        assert!(!out_str.contains("admin@server.com"));
        assert_eq!(*stats.pattern_counts.get("email").unwrap(), 1);
        assert_eq!(*stats.pattern_counts.get("ipv4").unwrap(), 1);
    }

    // ---- Chunk boundary: match spans two chunks ----

    #[test]
    fn match_at_chunk_boundary() {
        // Use a very small chunk size so the email straddles a boundary.
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = StreamScanner::new(
            vec![email_pattern()],
            store,
            ScanConfig {
                chunk_size: 20, // very small
                overlap_size: 16,
            },
        )
        .unwrap();

        // Place an email address that will definitely straddle a boundary.
        let input = b"AAAAAAAAAAAAAAAA alice@corp.com BBBBBBBBBBBBB";
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.matches_found, 1);
        let out_str = String::from_utf8_lossy(&output);
        assert!(!out_str.contains("alice@corp.com"));
        assert!(out_str.contains("@corp.com"), "domain must be preserved");
    }

    // ---- Large input requiring many chunks ----

    #[test]
    fn large_input_many_chunks() {
        let scanner = test_scanner(vec![email_pattern()]);

        // Build a ~2 KiB input with emails sprinkled in.
        let mut input = Vec::new();
        let filler = b"Lorem ipsum dolor sit amet. ";
        for i in 0..20 {
            input.extend_from_slice(filler);
            let email = format!("user{}@example.com ", i);
            input.extend_from_slice(email.as_bytes());
        }

        let (output, stats) = scanner.scan_bytes(&input).unwrap();
        assert_eq!(stats.matches_found, 20);
        let out_str = String::from_utf8_lossy(&output);
        for i in 0..20 {
            let email = format!("user{}@example.com", i);
            assert!(!out_str.contains(&email));
        }
    }

    // ---- Scan via Read/Write interface ----

    #[test]
    fn scan_reader_writer() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"hello alice@corp.com world";
        let mut output = Vec::new();
        let stats = scanner.scan_reader(&input[..], &mut output).unwrap();
        assert_eq!(stats.matches_found, 1);
        let out_str = String::from_utf8_lossy(&output);
        assert!(out_str.contains("@corp.com"), "domain must be preserved");
    }

    // ---- Pattern compile error ----

    #[test]
    fn invalid_regex_pattern() {
        let result = ScanPattern::from_regex("[invalid(", Category::Email, "bad");
        assert!(result.is_err());
    }

    // ---- Default config ----

    #[test]
    fn default_config_valid() {
        ScanConfig::default().validate().unwrap();
    }

    // ---- Config edge cases ----

    #[test]
    fn config_chunk_1_overlap_0() {
        // Extreme but valid: 1-byte chunks, no overlap.
        // Won't catch multi-byte patterns, but should not crash.
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        let store = Arc::new(MappingStore::new(gen, None));
        let scanner = StreamScanner::new(vec![], store, ScanConfig::new(1, 0)).unwrap();
        let (output, _) = scanner.scan_bytes(b"hello").unwrap();
        assert_eq!(output, b"hello");
    }

    // ---- Bytes output tracking ----

    #[test]
    fn bytes_output_preserved_on_replacement() {
        let scanner = test_scanner(vec![email_pattern()]);
        let input = b"a@b.cc"; // short email
        let (output, stats) = scanner.scan_bytes(input).unwrap();
        assert_eq!(stats.bytes_processed, input.len() as u64);
        assert_eq!(stats.bytes_output, output.len() as u64);
        // Length-preserving: output length matches input length.
        assert_eq!(output.len(), input.len());
    }
}
