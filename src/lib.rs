//! # sanitize-engine
//!
//! Deterministic, one-way data sanitization engine.
//!
//! This crate provides the core replacement infrastructure for replacing
//! sensitive values with category-aware, deterministic substitutes.
//! Replacements are **one-way only** — there is no key file, mapping
//! table, or restore mode. It is the foundation layer consumed by
//! higher-level streaming and CLI components.
//!
//! ## Key Components
//!
//! - [`category::Category`] — Classification of sensitive values (email,
//!   IP, name, etc.) that determines replacement format.
//! - [`generator::ReplacementGenerator`] — Trait abstracting replacement
//!   strategy (HMAC-deterministic or CSPRNG-random).
//! - [`strategy::Strategy`] — Pluggable replacement strategies that can
//!   be called **directly** without any mapping table.
//! - [`store::MappingStore`] — Optional thread-safe per-run dedup cache
//!   ensuring the same input always maps to the same output within a run.
//! - [`scanner::StreamScanner`] — Streaming regex scanner with chunk +
//!   overlap for bounded-memory processing.
//!
//! ## Concurrency Model
//!
//! The `MappingStore` uses `DashMap` (shard-level locking) for the forward
//! dedup cache. All types are `Send + Sync`.
//!
//! ## Stability
//!
//! This crate is pre-1.0. The core guarantees — one-way replacement,
//! deterministic mode, and length preservation — are stable. Processor
//! heuristics, default limits, and report schema may evolve across minor
//! versions.
//!
//! ## Example: Store-Level Replacement
//!
//! ```rust
//! use sanitize_engine::category::Category;
//! use sanitize_engine::generator::HmacGenerator;
//! use sanitize_engine::store::MappingStore;
//! use std::sync::Arc;
//!
//! // Create a deterministic generator with a fixed seed.
//! let generator = Arc::new(HmacGenerator::new([42u8; 32]));
//!
//! // Create the replacement store (optional capacity limit).
//! let store = MappingStore::new(generator, None);
//!
//! // Sanitize a value (one-way).
//! let sanitized = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
//! assert!(sanitized.contains("@corp.com"));
//! assert_eq!(sanitized.len(), "alice@corp.com".len());
//!
//! // Same input → same output (per-run consistency).
//! let again = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
//! assert_eq!(sanitized, again);
//! ```
//!
//! ## Example: Streaming Scanner
//!
//! ```rust
//! use sanitize_engine::category::Category;
//! use sanitize_engine::generator::HmacGenerator;
//! use sanitize_engine::scanner::{ScanConfig, ScanPattern, StreamScanner};
//! use sanitize_engine::store::MappingStore;
//! use std::sync::Arc;
//!
//! // Build patterns.
//! let patterns = vec![
//!     ScanPattern::from_regex(r"alice@corp\.com", Category::Email, "alice_email").unwrap(),
//! ];
//!
//! // Store with deterministic generator.
//! let generator = Arc::new(HmacGenerator::new([42u8; 32]));
//! let store = Arc::new(MappingStore::new(generator, Some(1_000_000)));
//!
//! // Scanner with default chunk config.
//! let config = ScanConfig::new(1_048_576, 4096);
//! let scanner = StreamScanner::new(patterns, store, config).unwrap();
//!
//! // Scan bytes in-memory.
//! let input = b"Contact alice@corp.com for details.";
//! let (output, stats) = scanner.scan_bytes(input).unwrap();
//!
//! assert_eq!(stats.replacements_applied, 1);
//! assert_eq!(output.len(), input.len());
//! ```

// Crate-level lint configuration.
#![forbid(unsafe_code)]
#![warn(clippy::all, clippy::pedantic)]
// Allow specific pedantic lints that are too noisy for this crate.
#![allow(
    clippy::module_name_repetitions,
    clippy::missing_panics_doc,
    clippy::must_use_candidate, // We add #[must_use] manually on key APIs.
    clippy::uninlined_format_args,
    clippy::redundant_closure_for_method_calls,
    clippy::doc_markdown,
    clippy::similar_names
)]

pub mod atomic;
pub mod category;
pub mod error;
pub mod generator;
pub mod processor;
pub mod report;
pub mod scanner;
pub mod secrets;
pub mod store;
pub mod strategy;

// Re-exports for convenience.
pub use atomic::{atomic_write, AtomicFileWriter};
pub use category::Category;
pub use error::{Result, SanitizeError};
pub use generator::{HmacGenerator, RandomGenerator, ReplacementGenerator};
pub use processor::archive::{
    ArchiveFormat, ArchiveProcessor, ArchiveStats, DEFAULT_MAX_ARCHIVE_DEPTH,
};
pub use processor::{FieldRule, FileTypeProfile, Processor, ProcessorRegistry};
pub use report::{FileReport, ReportBuilder, ReportMetadata, SanitizeReport};
pub use scanner::{ScanConfig, ScanPattern, ScanStats, StreamScanner};
pub use secrets::{
    decrypt_secrets, encrypt_secrets, load_secrets_auto, looks_encrypted, SecretEntry,
    SecretsFormat,
};
pub use store::MappingStore;
pub use strategy::{
    EntropyMode, FakeIp, HmacHash, PreserveLength, RandomString, RandomUuid, Strategy,
    StrategyGenerator,
};
