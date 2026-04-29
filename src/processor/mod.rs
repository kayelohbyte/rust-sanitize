//! Structured processors for format-aware sanitization.
//!
//! # Architecture
//!
//! ```text
//! ┌──────────────────┐     ┌───────────────────┐     ┌──────────────────┐
//! │  Input bytes     │ ──▶ │ ProcessorRegistry  │ ──▶ │  Output bytes    │
//! │  (file content)  │     │ (profile matching) │     │  (sanitized)     │
//! └──────────────────┘     └────────┬───────────┘     └──────────────────┘
//!                                   │
//!                          ┌────────▼────────┐
//!                          │ dyn Processor    │
//!                          │                  │
//!                          │  KeyValue        │ ← gitlab.rb-style
//!                          │  JsonProcessor   │ ← JSON files
//!                          │  YamlProcessor   │ ← YAML files
//!                          │  XmlProcessor    │ ← XML files
//!                          │  CsvProcessor    │ ← CSV/TSV files
//!                          └────────┬────────┘
//!                                   │
//!                          ┌────────▼────────┐
//!                          │  MappingStore    │
//!                          │  (one-way dedup) │
//!                          └─────────────────┘
//! ```
//!
//! # File-Type Profiles
//!
//! A [`FileTypeProfile`] specifies which processor to use and what
//! fields/keys to sanitize. Users provide profiles to control which
//! parts of a structured file are replaced. If no profile matches,
//! the caller falls back to the streaming scanner.
//!
//! # Extensibility
//!
//! Implement the [`Processor`] trait and register it with the
//! [`ProcessorRegistry`]. The registry matches profiles to processors
//! by name and dispatches processing.

pub mod archive;
pub mod csv_proc;
pub mod env_proc;
pub mod ini_proc;
pub mod json_proc;
pub mod jsonl_proc;
pub mod key_value;
pub mod log_line;
pub mod profile;
pub mod registry;
pub mod toml_proc;
pub mod xml_proc;
pub mod yaml_proc;

// Re-export core types.
pub use profile::{FieldRule, FileTypeProfile};
pub use registry::ProcessorRegistry;

use crate::category::Category;
use crate::error::Result;
use crate::store::MappingStore;
use std::io;

// ---------------------------------------------------------------------------
// Processor trait
// ---------------------------------------------------------------------------

/// A structured processor that can sanitize a specific file format while
/// preserving its structure and formatting as much as possible.
///
/// Processors are **stateless** — all mutable state lives in the
/// [`MappingStore`] they receive. This makes processors `Send + Sync`
/// and reusable across files.
///
/// # Contract
///
/// - `name()` must return a unique, lowercase identifier (e.g. `"json"`).
/// - `can_handle()` is a fast heuristic check; it may inspect a few
///   bytes or the file extension but should not fully parse.
/// - `process()` performs the full structured sanitization. It should
///   preserve formatting/whitespace where possible and only replace
///   values in fields matched by the profile's [`FieldRule`]s.
/// - Replacements are **one-way** via the `MappingStore` — no reverse
///   mapping is produced.
pub trait Processor: Send + Sync {
    /// Unique name for this processor (e.g. `"json"`, `"yaml"`, `"key_value"`).
    fn name(&self) -> &'static str;

    /// Quick heuristic: can this processor handle the given content?
    ///
    /// Implementations may check magic bytes, file extension hints in
    /// the profile, or the first few bytes of content. This is called
    /// before `process()` and should be fast.
    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool;

    /// Process the content, replacing matched field values one-way.
    ///
    /// # Arguments
    ///
    /// - `content` — raw file bytes.
    /// - `profile` — the user-supplied profile with field rules.
    /// - `store` — the mapping store for dedup-consistent one-way replacements.
    ///
    /// # Returns
    ///
    /// The sanitized content as bytes, preserving structure/formatting
    /// where possible.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`](crate::error::SanitizeError) if parsing or replacement generation fails.
    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>>;

    /// Whether this processor supports bounded-memory streaming via
    /// [`process_stream`](Self::process_stream).
    ///
    /// Processors that return `true` here are eligible for the streaming
    /// structured path in the CLI, which opens the file as a reader instead
    /// of reading it fully into memory. The default is `false`.
    fn supports_streaming(&self) -> bool {
        false
    }

    /// Process content from a reader, writing sanitized output to a writer.
    ///
    /// The default implementation reads the entire reader into memory and
    /// delegates to [`process`](Self::process). Processors that return
    /// `true` from [`supports_streaming`](Self::supports_streaming) should
    /// override this to handle data incrementally, keeping memory usage
    /// bounded regardless of input size.
    ///
    /// # Errors
    ///
    /// Returns [`SanitizeError`](crate::error::SanitizeError) on read, parse,
    /// or write failure.
    fn process_stream(
        &self,
        reader: &mut dyn io::Read,
        writer: &mut dyn io::Write,
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<()> {
        let mut buf = Vec::new();
        io::Read::read_to_end(reader, &mut buf)?;
        let out = self.process(&buf, profile, store)?;
        io::Write::write_all(writer, &out)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Helpers shared across processors
// ---------------------------------------------------------------------------

/// Replace a value through the mapping store using a field rule's category.
pub(crate) fn replace_value(value: &str, rule: &FieldRule, store: &MappingStore) -> Result<String> {
    let category = rule
        .category
        .clone()
        .unwrap_or(Category::Custom("field".into()));
    let sanitized = store.get_or_insert(&category, value)?;
    Ok(sanitized.to_string())
}

/// Build a dot-separated key path by appending `key` to `prefix`.
///
/// Returns `key` unchanged when `prefix` is empty.
#[must_use]
pub(crate) fn build_path(prefix: &str, key: &str) -> String {
    if prefix.is_empty() {
        key.to_string()
    } else {
        format!("{}.{}", prefix, key)
    }
}

/// Check whether a single glob `pattern` matches `key_path`.
///
/// Supported patterns:
/// - `"*"` — matches anything.
/// - `"password"` — exact match.
/// - `"*.password"` — any key ending in `.password`.
/// - `"db.*"` — any key starting with `db.`.
#[must_use]
pub(crate) fn pattern_matches(pattern: &str, key_path: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if pattern == key_path {
        return true;
    }
    // Simple glob: *.suffix
    if let Some(suffix) = pattern.strip_prefix("*.") {
        if key_path == suffix
            || key_path
                .strip_suffix(suffix)
                .is_some_and(|rest| rest.ends_with('.'))
        {
            return true;
        }
    }
    // Simple glob: prefix.*
    if let Some(prefix) = pattern.strip_suffix(".*") {
        if key_path
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with('.'))
        {
            return true;
        }
    }
    false
}

/// Check whether a dotted key path matches any of the rules in a profile.
///
/// Supports exact matches and simple glob patterns:
/// - `"password"` matches `"password"` exactly.
/// - `"*.password"` matches any key ending in `.password`.
/// - `"db.*"` matches any key starting with `db.`.
#[must_use]
pub(crate) fn find_matching_rule<'a>(
    key_path: &str,
    profile: &'a FileTypeProfile,
) -> Option<&'a FieldRule> {
    profile
        .fields
        .iter()
        .find(|rule| pattern_matches(&rule.pattern, key_path))
}
