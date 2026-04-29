//! Unified error types for the sanitization engine.
//!
//! All fallible operations in the crate return [`Result<T>`], which is an
//! alias for `std::result::Result<T, SanitizeError>`.
//!
//! Errors are categorised by subsystem (`IoError`, `SecretsError`,
//! `ArchiveError`, …) so callers can match on the variant to decide
//! whether to retry, skip, or abort. The [`thiserror`] derive keeps
//! display messages actionable and grep-friendly.

use thiserror::Error;

/// All errors that can occur within the sanitization engine.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SanitizeError {
    #[error("replacement store capacity exceeded: {current} mappings (limit: {limit})")]
    CapacityExceeded { current: usize, limit: usize },

    #[error("invalid seed length: expected 32 bytes, got {0}")]
    InvalidSeedLength(usize),

    #[error("I/O error: {0}")]
    IoError(String),

    #[error("parse error ({format}): {message}")]
    ParseError { format: String, message: String },

    #[error("recursion depth exceeded: {0}")]
    RecursionDepthExceeded(String),

    #[error("input too large: {size} bytes (limit: {limit})")]
    InputTooLarge { size: usize, limit: usize },

    #[error("pattern compilation error: {0}")]
    PatternCompileError(String),

    #[error("invalid configuration: {0}")]
    InvalidConfig(String),

    #[error("secrets: empty password")]
    SecretsEmptyPassword,

    #[error("secrets: encrypted file too short (corrupt or truncated)")]
    SecretsTooShort,

    #[error("secrets: decryption failed — wrong password or corrupted file")]
    SecretsDecryptFailed,

    #[error("secrets: cipher error: {0}")]
    SecretsCipherError(String),

    #[error("secrets: {format} error: {message}")]
    SecretsFormatError { format: String, message: String },

    #[error("secrets: invalid UTF-8: {0}")]
    SecretsInvalidUtf8(String),

    #[error("secrets: no password provided — file appears encrypted but --encrypted-secrets was not specified")]
    SecretsPasswordRequired,

    #[error("archive error: {0}")]
    ArchiveError(String),
}

impl From<std::io::Error> for SanitizeError {
    fn from(e: std::io::Error) -> Self {
        SanitizeError::IoError(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, SanitizeError>;
