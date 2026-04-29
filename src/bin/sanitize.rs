//! CLI entry-point for the sanitization engine.
//!
//! # Usage
//!
//! ```text
//! sanitize [OPTIONS] [INPUT]...
//! sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
//! sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
//!
//! # Read from stdin (plaintext secrets file — default):
//! cat data.log | sanitize -s secrets.yaml
//! grep "error" log.txt | sanitize -s secrets.json -o clean.log
//! ```
//!
//! # Subcommands
//!
//! - *(default)* — sanitize a file or archive
//! - `encrypt` — encrypt a plaintext secrets file
//! - `decrypt` — decrypt an encrypted secrets file back to plaintext
//!
//! # Examples
//!
//! ```text
//! # Encrypt a plaintext secrets file:
//! sanitize encrypt secrets.json secrets.json.enc --password
//!
//! # Decrypt it back (for editing):
//! sanitize decrypt secrets.json.enc secrets.json --password
//!
//! # Sanitize a log file (plaintext secrets — default):
//! sanitize data.log -s secrets.yaml
//!
//! # Write output to a file:
//! sanitize data.log -s secrets.yaml -o clean.log
//!
//! # Use an encrypted secrets file (requires --encrypted-secrets):
//! sanitize data.log -s secrets.enc --encrypted-secrets -p
//!
//! # Read from stdin with encrypted secrets:
//! grep "error" log.txt | sanitize -s secrets.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Deterministic mode with encrypted secrets:
//! sanitize data.csv -s s.enc --encrypted-secrets -p -d
//!
//! # Read password from a file (avoids process listing / env exposure):
//! sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
//!
//! # Dry-run:
//! sanitize config.yaml -s s.enc --encrypted-secrets -p -n
//!
//! # Fail CI if matches found:
//! sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
//! ```
//!
//! # One-Way Replacements
//!
//! All replacements are **one-way**. No mapping file is stored and there
//! is no restore mode. Re-running with the `--deterministic` flag and the
//! same secrets will produce identical replacements.

mod progress;
use progress::{
    with_progress_scope, ProgressContext, ProgressMode, ProgressPolicy, ProgressReporter,
    SharedProgressReporter,
};

use clap::{Parser, Subcommand};
use rayon::prelude::*;
use sanitize_engine::secrets::{
    decrypt_secrets, encrypt_secrets, entries_to_patterns, parse_secrets, serialize_secrets,
    SecretEntry, SecretsFormat,
};
use sanitize_engine::{
    atomic_write, ArchiveFilter, ArchiveFormat, ArchiveProcessor, ArchiveProgress,
    AtomicFileWriter, FileReport, HmacGenerator, MappingStore, ProcessorRegistry, RandomGenerator,
    ReplacementGenerator, ReportBuilder, ReportMetadata, ScanConfig, ScanPattern, ScanStats,
    StreamScanner, DEFAULT_MAX_ARCHIVE_DEPTH,
};
use std::collections::{HashMap, HashSet};
use std::env;
use std::ffi::OsString;
use std::fs;
use std::io::{self, BufReader, BufWriter, Cursor, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;
use tracing::{info, warn};
use zeroize::Zeroizing;

/// Maximum size (in bytes) for a structured file to be fully loaded into
/// memory for format-aware processing (F-03 fix). Files exceeding this
/// limit fall back to the streaming scanner which operates in bounded
/// memory. Configurable via `--max-structured-size`.
const DEFAULT_MAX_STRUCTURED_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// Global flag set by the SIGINT/SIGTERM handler.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Default UI refresh interval for live progress rendering.
const DEFAULT_PROGRESS_INTERVAL_MS: u64 = 200;

/// Check whether a graceful shutdown has been requested.
fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
}

#[derive(Copy, Clone)]
struct ArchiveDeps<'a> {
    scanner: &'a Arc<StreamScanner>,
    registry: &'a Arc<ProcessorRegistry>,
    store: &'a Arc<MappingStore>,
    profiles: &'a [sanitize_engine::processor::FileTypeProfile],
}

// ---------------------------------------------------------------------------
// CLI definition
// ---------------------------------------------------------------------------

/// Deterministic one-way data sanitization tool.
///
/// Scans files and archives for sensitive data described in an encrypted
/// secrets file and replaces every match with a category-aware substitute.
/// Replacements are ONE-WAY — no mapping file is stored and there is no
/// restore mode.
///
/// Use `sanitize encrypt` / `sanitize decrypt` to manage encrypted secrets
/// files, or omit the subcommand to sanitize data.
#[derive(Parser, Debug)]
#[command(
    name = "sanitize",
    version,
    about = "One-way data sanitization tool",
    long_about = "Deterministic one-way data sanitization tool.\n\n\
        Scans files and archives for sensitive data described in a secrets file \
        (plaintext by default) and replaces every match with a category-aware substitute.\n\
        Replacements are ONE-WAY — no mapping file is stored and there is no \
        restore mode.\n\n\
        Use `sanitize encrypt` / `sanitize decrypt` to manage encrypted secrets files.",
    after_help = "\
EXAMPLES:\n  \
  # Plaintext secrets file (default — no password needed):\n  \
  sanitize data.log -s secrets.yaml\n  \
  sanitize data.log -s secrets.yaml -o clean.log\n  \
  grep \"error\" log.txt | sanitize -s secrets.yaml\n\n  \
  # Encrypted secrets file (requires --encrypted-secrets):\n  \
  sanitize data.log -s s.enc --encrypted-secrets -p\n  \
  sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw\n  \
  SANITIZE_PASSWORD=hunter2 sanitize data.log -s s.enc --encrypted-secrets\n\n  \
  # Encrypt / decrypt secrets files:\n  \
  sanitize encrypt secrets.json secrets.json.enc --password\n  \
  sanitize decrypt secrets.json.enc secrets.json --password\n\n  \
  # Deterministic replacements with encrypted secrets:\n  \
  sanitize data.csv -s s.enc --encrypted-secrets -p -d"
)]
struct Cli {
    /// Subcommand: encrypt, decrypt, or omit for default sanitize mode.
    #[command(subcommand)]
    command: Option<SubCommand>,

    /// Path(s) to files or archives to sanitize. When omitted, reads
    /// from stdin. Use "-" to include stdin alongside file paths.
    #[arg(value_name = "INPUT")]
    input: Vec<PathBuf>,

    /// Output path. For a single input stream, writes to this file.
    /// For multiple inputs, this is treated as an output directory.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Path to a secrets file. Plaintext JSON / YAML / TOML files are
    /// loaded directly by default. Use `--encrypted-secrets` to decrypt
    /// an AES-256-GCM encrypted file.
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// Path to a file-type profile (JSON or YAML) defining which structured
    /// fields to sanitize. Each profile entry names a processor, file
    /// extensions, and field-path rules (e.g. `*.password`, `database.host`).
    ///
    /// When combined with --secrets-file the tool runs a structured pass
    /// (replacing named fields) followed by a scanner pass (catching any
    /// remaining secrets). Without --secrets-file only the structured pass
    /// runs.
    #[arg(long = "profile", value_name = "FILE")]
    profile: Option<PathBuf>,

    /// Trigger an interactive password prompt for decrypting the secrets
    /// file (masked input, never echoed). Requires `--encrypted-secrets`.
    /// Providing this flag without `--encrypted-secrets` is an error.
    /// For non-interactive automation use `--password-file` or the
    /// `SANITIZE_PASSWORD` environment variable instead.
    #[arg(short = 'p', long)]
    password: bool,

    /// Read the decryption password from a file. Requires `--encrypted-secrets`.
    /// The file must have permissions 0600 or 0400 (owner-only).
    /// Trailing newline is stripped.
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Treat the secrets file as AES-256-GCM encrypted and decrypt it
    /// before loading. Requires a password via `-p`, `--password-file`,
    /// or the `SANITIZE_PASSWORD` environment variable. Without this
    /// flag the file is loaded as plaintext (JSON / YAML / TOML);
    /// providing any password input without this flag is an error.
    #[arg(long)]
    encrypted_secrets: bool,

    /// Force input format, overriding file-extension detection.
    /// Required when reading from stdin with structured data.
    /// Values: text, json, yaml, xml, csv, key-value.
    #[arg(short = 'f', long, value_name = "FMT")]
    format: Option<String>,

    /// Scan and report matches without writing output.
    #[arg(short = 'n', long)]
    dry_run: bool,

    /// Exit with code 2 if any matches are found. Useful for CI
    /// pipelines that should fail when secrets are detected.
    #[arg(long)]
    fail_on_match: bool,

    /// Write a JSON report to the given path (or stderr if no path).
    /// The report includes file-level match counts, per-pattern stats,
    /// processing duration, and tool metadata. No original secret values
    /// are included.
    #[arg(short = 'r', long, value_name = "PATH")]
    report: Option<Option<PathBuf>>,

    /// Abort on the first error instead of skipping and continuing.
    #[arg(long)]
    strict: bool,

    /// Use HMAC-deterministic replacements so that identical inputs
    /// always produce identical outputs across runs (requires a stable
    /// seed derived from the secrets key).
    #[arg(short = 'd', long)]
    deterministic: bool,

    /// Process entries that appear to be binary data (default: skip).
    #[arg(long)]
    include_binary: bool,

    /// Bypass all structured processors (JSON, YAML, XML, TOML, etc.) and
    /// run only the streaming scanner on every file.
    ///
    /// Use this when you are uncertain about your field rules or want
    /// a guarantee that every byte in every file is pattern-scanned.
    /// The output is the same byte length as the input but structural
    /// formatting may differ for structured file types.
    /// Under normal operation the structured + scan double-pass handles
    /// this automatically; this flag disables the structured pass entirely.
    #[arg(long)]
    force_text: bool,

    /// Number of worker threads. When multiple input files are provided,
    /// files are processed in parallel up to this limit. For a single
    /// archive input, entries are sanitized in parallel using the same
    /// budget. Defaults to the number of logical CPUs. Capped to the
    /// system's available parallelism.
    #[arg(long, value_name = "N")]
    threads: Option<usize>,

    /// Chunk size in bytes for the streaming scanner (default: 1 MiB).
    #[arg(long, value_name = "BYTES", default_value_t = 1_048_576)]
    chunk_size: usize,

    /// Maximum number of unique replacement mappings to keep in memory.
    /// Guards against memory exhaustion when inputs contain huge numbers
    /// of unique matches.  Use 0 for unlimited (not recommended).
    #[arg(long, value_name = "N", default_value_t = 10_000_000)]
    max_mappings: usize,

    /// Maximum structured file size in bytes. Files exceeding this limit
    /// fall back to streaming scanner instead of structured processing.
    /// Prevents unbounded memory usage from large structured files (F-03 fix).
    #[arg(long, value_name = "BYTES", default_value_t = DEFAULT_MAX_STRUCTURED_FILE_SIZE)]
    max_structured_size: u64,

    /// Maximum nesting depth for recursive archive processing.
    /// Nested archives (e.g. a .tar.gz inside a .zip) are extracted and
    /// sanitized recursively up to this depth. Exceeding the limit is an
    /// error. Maximum allowed value is 10 (each level may buffer up to
    /// 256 MiB).
    #[arg(long, value_name = "N", default_value_t = DEFAULT_MAX_ARCHIVE_DEPTH)]
    max_archive_depth: u32,

    /// Log output format: "human" (default) or "json" (for SIEM ingestion).
    #[arg(long, value_name = "FMT", default_value = "human")]
    log_format: String,

    /// Progress display mode: auto (default), on, or off.
    #[arg(long, value_enum, value_name = "MODE")]
    progress: Option<ProgressMode>,

    /// Disable live progress output.
    #[arg(long)]
    no_progress: bool,

    /// Minimum interval between live progress refreshes.
    #[arg(long, value_name = "MS", default_value_t = DEFAULT_PROGRESS_INTERVAL_MS)]
    progress_interval_ms: u64,
}

impl Cli {
    fn effective_progress_mode(&self) -> ProgressMode {
        if let Some(mode) = self.progress {
            mode
        } else if self.no_progress {
            ProgressMode::Off
        } else {
            ProgressMode::Auto
        }
    }
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum SubCommand {
    /// Encrypt a plaintext secrets file for use with the sanitizer.
    ///
    /// Uses AES-256-GCM authenticated encryption with a key derived via
    /// PBKDF2-HMAC-SHA256 (600,000 iterations).
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize encrypt secrets.json secrets.json.enc --password \"my-password\"\n  \
  SANITIZE_PASSWORD=hunter2 sanitize encrypt secrets.yaml secrets.yaml.enc\n  \
  sanitize encrypt secrets.toml secrets.toml.enc  # interactive prompt")]
    Encrypt(EncryptArgs),

    /// Decrypt an encrypted secrets file back to plaintext.
    ///
    /// Useful for editing secrets before re-encrypting.
    #[command(after_help = "\
EXAMPLES:\n  \
  sanitize decrypt secrets.json.enc secrets.json --password \"my-password\"\n  \
  sanitize decrypt secrets.enc out.yaml --password-file /run/secrets/pw")]
    Decrypt(DecryptArgs),

    /// Interactive guided setup for logs-focused secrets templates.
    #[command(after_help = "\
EXAMPLES:\n  \
    sanitize guided")]
    Guided,

    /// Generate a starter secrets-template YAML file for a given use case.
    ///
    /// Templates include commented-out examples and common patterns so
    /// support engineers, sysadmins, and DevOps teams can get started
    /// quickly before sending logs or configs to an LLM.
    #[command(after_help = "\
PRESETS\n  \
  generic    Common secrets: tokens, emails, IPs, hostnames (default)\n  \
  web        Web-app logs: JWTs, sessions, emails, URLs\n  \
  k8s        Kubernetes configs: service-accounts, tokens, namespaces\n  \
  database   Database configs: passwords, connection strings, usernames\n  \
  aws        AWS: access keys, ARNs, account IDs\n\n\
EXAMPLES:\n  \
  sanitize template                     # generic → secrets.template.yaml\n  \
  sanitize template --preset web        # web-app template\n  \
  sanitize template --preset k8s -o k8s-secrets.yaml")]
    Template(TemplateArgs),
}

#[derive(Parser, Debug)]
struct EncryptArgs {
    /// Path to plaintext secrets file (.json, .yaml, .yml, .toml).
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path for encrypted output file (.enc).
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,

    /// Prompt interactively for the encryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SANITIZE_PASSWORD environment variable instead.
    #[arg(long)]
    password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Force input format (json, yaml, toml). Default: auto-detect from
    /// file extension.
    #[arg(long, value_parser = parse_format)]
    format: Option<SecretsFormat>,

    /// Parse the plaintext before encrypting and report any errors.
    /// Enabled by default; use --no-validate to skip.
    #[arg(long, overrides_with = "_no_validate", default_value_t = true)]
    validate: bool,

    /// Skip pre-encryption validation.
    #[arg(long = "no-validate", hide = true)]
    _no_validate: bool,
}

#[derive(Parser, Debug)]
struct DecryptArgs {
    /// Path to encrypted secrets file (.enc).
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path for decrypted plaintext output.
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,

    /// Prompt interactively for the decryption password. The password is
    /// never echoed. For non-interactive automation use --password-file or
    /// the SANITIZE_PASSWORD environment variable instead.
    #[arg(long)]
    password: bool,

    /// Read the password from a file (must have 0600 or 0400 permissions).
    #[arg(long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Validate decrypted content as secrets in this format (json, yaml,
    /// toml). If omitted, the raw decrypted bytes are written as-is.
    #[arg(long, value_parser = parse_format)]
    format: Option<SecretsFormat>,
}

fn parse_format(s: &str) -> Result<SecretsFormat, String> {
    match s {
        "json" => Ok(SecretsFormat::Json),
        "yaml" | "yml" => Ok(SecretsFormat::Yaml),
        "toml" => Ok(SecretsFormat::Toml),
        other => Err(format!(
            "unknown format '{}' (use json, yaml, or toml)",
            other
        )),
    }
}

#[derive(Parser, Debug)]
struct TemplateArgs {
    /// Which preset to generate.
    ///
    /// Choices: generic, web, k8s, database, aws.
    #[arg(long, short = 'p', default_value = "generic", value_name = "PRESET")]
    preset: String,

    /// Output path for the generated YAML template.
    ///
    /// Default: secrets.template.yaml
    #[arg(long, short = 'o', value_name = "FILE")]
    output: Option<PathBuf>,

    /// Overwrite the output file if it already exists.
    #[arg(long)]
    overwrite: bool,
}

fn parse_template_preset(s: &str) -> Result<TemplatePreset, String> {
    match s {
        "generic" => Ok(TemplatePreset::Generic),
        "web" => Ok(TemplatePreset::Web),
        "k8s" | "kubernetes" => Ok(TemplatePreset::K8s),
        "database" | "db" => Ok(TemplatePreset::Database),
        "aws" => Ok(TemplatePreset::Aws),
        other => Err(format!(
            "unknown preset '{}' (choices: generic, web, k8s, database, aws)",
            other
        )),
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum TemplatePreset {
    Generic,
    Web,
    K8s,
    Database,
    Aws,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum GuidedPreset {
    Balanced,
    Aggressive,
    WebApp,
    Kubernetes,
    Database,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
enum CloudProvider {
    Aws,
    Azure,
    Gcp,
}

#[derive(Clone, Debug)]
struct GuidedOptions {
    preset: GuidedPreset,
    domains: Vec<String>,
    providers: Vec<CloudProvider>,
    exclude_noise_ids: bool,
}

fn prompt_line(prompt: &str) -> Result<String, String> {
    let mut stdout = io::stdout();
    write!(stdout, "{}", prompt).map_err(|e| format!("failed to write prompt: {e}"))?;
    stdout
        .flush()
        .map_err(|e| format!("failed to flush prompt: {e}"))?;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .map_err(|e| format!("failed to read input: {e}"))?;
    Ok(input.trim().to_string())
}

fn prompt_yes_no(prompt: &str, default_yes: bool) -> Result<bool, String> {
    let suffix = if default_yes { "[Y/n]" } else { "[y/N]" };
    loop {
        let answer = prompt_line(&format!("{} {} ", prompt, suffix))?;
        if answer.is_empty() {
            return Ok(default_yes);
        }
        match answer.to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(true),
            "n" | "no" => return Ok(false),
            _ => eprintln!("Please answer 'y' or 'n'."),
        }
    }
}

fn sanitize_domain(input: &str) -> Option<String> {
    let trimmed = input.trim().trim_matches('.').to_ascii_lowercase();
    if trimmed.is_empty() {
        return None;
    }
    if !trimmed
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
    {
        return None;
    }
    Some(trimmed)
}

fn prompt_domains() -> Result<Vec<String>, String> {
    let raw = prompt_line(
        "Company domains (comma-separated, up to 3, optional; e.g. corp.internal,example.com): ",
    )?;
    if raw.trim().is_empty() {
        return Ok(vec![]);
    }

    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in raw.split(',') {
        let Some(domain) = sanitize_domain(item) else {
            return Err(format!("invalid domain value: '{}'", item.trim()));
        };
        if seen.insert(domain.clone()) {
            out.push(domain);
        }
    }

    if out.len() > 3 {
        return Err("please provide at most 3 domains".into());
    }
    Ok(out)
}

fn prompt_cloud_providers() -> Result<Vec<CloudProvider>, String> {
    eprintln!("Cloud providers in scope:");
    eprintln!("  1) AWS");
    eprintln!("  2) Azure");
    eprintln!("  3) GCP");
    eprintln!("  4) None");
    let raw = prompt_line("Select one or more (comma-separated numbers, default: 4): ")?;
    if raw.trim().is_empty() || raw.trim() == "4" {
        return Ok(vec![]);
    }

    let mut selected = Vec::new();
    let mut seen = HashSet::new();
    for token in raw.split(',').map(|s| s.trim()) {
        let provider = match token {
            "1" => CloudProvider::Aws,
            "2" => CloudProvider::Azure,
            "3" => CloudProvider::Gcp,
            "4" => continue,
            _ => return Err(format!("invalid selection: '{token}'")),
        };
        if seen.insert(provider) {
            selected.push(provider);
        }
    }
    Ok(selected)
}

fn make_regex_entry(pattern: &str, category: &str, label: &str) -> SecretEntry {
    SecretEntry {
        pattern: pattern.to_string(),
        kind: "regex".to_string(),
        category: category.to_string(),
        label: Some(label.to_string()),
    }
}

fn build_guided_entries(opts: &GuidedOptions) -> Vec<SecretEntry> {
    let mut entries = vec![
        make_regex_entry(
            r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
            "email",
            "email",
        ),
        make_regex_entry(
            r"\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b",
            "hostname",
            "hostname",
        ),
        make_regex_entry(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ipv4", "ipv4"),
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b",
            "ipv6",
            "ipv6",
        ),
        make_regex_entry(
            r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b",
            "mac_address",
            "mac_address",
        ),
        make_regex_entry(
            r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b",
            "uuid",
            "uuid",
        ),
        make_regex_entry(r"\b[a-f0-9]{12,64}\b", "container_id", "container_id"),
        make_regex_entry(
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
            "jwt",
            "jwt",
        ),
        make_regex_entry(r#"https?://[^\s"'<>]+"#, "url", "url"),
    ];

    if matches!(
        opts.preset,
        GuidedPreset::Aggressive
            | GuidedPreset::WebApp
            | GuidedPreset::Kubernetes
            | GuidedPreset::Database
    ) {
        entries.push(make_regex_entry(
            r"(?i)\b(?:bearer|token|api[_-]?key|secret)[\s:=]+[A-Za-z0-9._~+/=-]{16,}\b",
            "auth_token",
            "auth_token_context",
        ));
        entries.push(make_regex_entry(
            r"\b[A-Za-z0-9_\-]{20,}\b",
            "custom:high_entropy_token",
            "high_entropy_token",
        ));
    }

    // Web-app specific: session cookies, OAuth tokens, refresh tokens.
    if matches!(opts.preset, GuidedPreset::WebApp) {
        entries.push(make_regex_entry(
            r"(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b",
            "auth_token",
            "session_id",
        ));
        entries.push(make_regex_entry(
            r"(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}",
            "auth_token",
            "oauth_token",
        ));
    }

    // Kubernetes specific: service account tokens, namespaces, pod names.
    if matches!(opts.preset, GuidedPreset::Kubernetes) {
        entries.push(make_regex_entry(
            r"\bServiceAccountToken[:\s]+[A-Za-z0-9._~+/=-]{20,}\b",
            "auth_token",
            "k8s_service_account_token",
        ));
        entries.push(make_regex_entry(
            r"\bnamespace[:\s]+[a-z][a-z0-9-]{2,62}\b",
            "custom:k8s_namespace",
            "k8s_namespace",
        ));
    }

    // Database specific: connection strings with embedded credentials.
    if matches!(opts.preset, GuidedPreset::Database) {
        entries.push(make_regex_entry(
            r#"(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"'>]+"#,
            "url",
            "db_connection_string",
        ));
        entries.push(make_regex_entry(
            r#"(?i)(?:password|passwd|pwd)[\s:=]+[^\s"']{6,}"#,
            "custom:db_password",
            "db_password",
        ));
    }

    for domain in &opts.domains {
        let escaped = regex::escape(domain);
        entries.push(make_regex_entry(
            &format!(r"[A-Za-z0-9._%+-]+@{}", escaped),
            "email",
            &format!("email_{}", domain.replace('.', "_")),
        ));
        entries.push(make_regex_entry(
            &format!(r"\b(?:[A-Za-z0-9-]+\.)*{}\b", escaped),
            "hostname",
            &format!("host_{}", domain.replace('.', "_")),
        ));
    }

    let has_aws = opts.providers.contains(&CloudProvider::Aws);
    let has_azure = opts.providers.contains(&CloudProvider::Azure);
    let has_gcp = opts.providers.contains(&CloudProvider::Gcp);

    if has_aws {
        entries.push(make_regex_entry(
            r"\barn:aws:[^\s]+\b",
            "aws_arn",
            "aws_arn",
        ));
        entries.push(make_regex_entry(
            r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
            "auth_token",
            "aws_access_key_id",
        ));
    }
    if has_azure {
        entries.push(make_regex_entry(
            r"/subscriptions/[0-9a-fA-F-]{8,}/resourceGroups/[^\s/]+(?:/providers/[^\s]+)?",
            "azure_resource_id",
            "azure_resource_id",
        ));
    }
    if has_gcp {
        entries.push(make_regex_entry(
            r"\b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b",
            "custom:gcp_service_account",
            "gcp_service_account",
        ));
        entries.push(make_regex_entry(
            r"\bprojects/[a-z][a-z0-9-]{4,30}/[A-Za-z0-9/_-]+\b",
            "custom:gcp_resource",
            "gcp_resource",
        ));
    }

    if opts.exclude_noise_ids {
        entries.retain(|entry| entry.label.as_deref() != Some("high_entropy_token"));
    }

    entries
}

// ---------------------------------------------------------------------------
// Template subcommand
// ---------------------------------------------------------------------------

/// YAML comment header printed at the top of every generated template.
const TEMPLATE_HEADER: &str = "\
# =============================================================================
# sanitize secrets template
# =============================================================================
#
# PURPOSE
#   This file tells sanitize which patterns to detect and replace before
#   you send logs, configs, or other data to an LLM or external service.
#
# RELIABILITY FIRST
#   Every replacement preserves the original byte length so structured
#   formats (JSON, YAML, TOML, …) remain parseable after sanitization.
#   Run `sanitize --force-text` to bypass structured processing entirely.
#
# HOW TO USE
#   1. Edit this file to add your own patterns and literals.
#   2. Encrypt: sanitize encrypt this-file.yaml this-file.yaml.enc
#   3. Sanitize: sanitize input.log -s this-file.yaml.enc -o output.log
#
# FIELD REFERENCE
#   pattern   string  Required. Regex or literal to match.
#   kind      string  \"regex\" (default) or \"literal\".
#   category  string  Controls the replacement style. See docs/categories.md.
#   label     string  Optional. Human-readable name shown in reports.
#
# WARNING: REVIEW OUTPUT BEFORE SENDING TO AN LLM.
#          No automated tool catches everything — always spot-check.
# =============================================================================
";

fn template_body_generic() -> &'static str {
    r#"secrets:
  # --- Tokens & credentials ---
  - pattern: '(?i)\b(?:bearer|token|api[_-]?key|secret)[\s:=]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: auth_token_context

  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  # --- Network identifiers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ipv4

  - pattern: '\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\b'
    kind: regex
    category: ipv6
    label: ipv6

  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: hostname

  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Identifiers ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uuid

  - pattern: '\b[a-f0-9]{12,64}\b'
    kind: regex
    category: container_id
    label: container_id

  # --- Add your own literals below ---
  # - pattern: 'my-internal-hostname.corp.example.com'
  #   kind: literal
  #   category: hostname
  #   label: corp_hostname
"#
}

fn template_body_web() -> &'static str {
    r#"secrets:
  # --- JWTs and session tokens ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: jwt

  - pattern: '(?i)\bsess(?:ion)?[_-]?(?:id|token|key)[\s:=]+[A-Za-z0-9._~+/=-]{8,}\b'
    kind: regex
    category: auth_token
    label: session_id

  - pattern: '(?i)(?:refresh|access)[_-]?token[\s:=]+[A-Za-z0-9._~+/=-]{16,}'
    kind: regex
    category: auth_token
    label: oauth_token

  - pattern: '(?i)\b(?:bearer|authorization)[\s:]+[A-Za-z0-9._~+/=-]{16,}\b'
    kind: regex
    category: auth_token
    label: bearer_token

  # --- User identifiers ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: client_ip

  # --- URLs (may contain query params with tokens) ---
  - pattern: 'https?://[^\s"''<>]+'
    kind: regex
    category: url
    label: url

  # --- Add domain-specific literals ---
  # - pattern: 'users.myapp.com'
  #   kind: literal
  #   category: hostname
  #   label: app_domain
"#
}

fn template_body_k8s() -> &'static str {
    r#"secrets:
  # --- Service account tokens (base64, JWT) ---
  - pattern: '\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b'
    kind: regex
    category: jwt
    label: k8s_service_account_jwt

  - pattern: '(?i)token[\s:]+[A-Za-z0-9._~+/=-]{20,}'
    kind: regex
    category: auth_token
    label: k8s_token

  # --- Namespace and pod names ---
  - pattern: '\bnamespace[\s:]+[a-z][a-z0-9-]{2,62}\b'
    kind: regex
    category: custom:k8s_namespace
    label: k8s_namespace

  # --- IPs assigned to pods and services ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: pod_or_svc_ip

  # --- Cluster hostnames / DNS names ---
  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: k8s_dns

  # --- UUIDs (pod IDs, request IDs, etc.) ---
  - pattern: '\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b'
    kind: regex
    category: uuid
    label: uid

  # --- Docker / container image digests ---
  - pattern: '\b[a-f0-9]{64}\b'
    kind: regex
    category: container_id
    label: image_digest

  # --- Add your cluster name as a literal ---
  # - pattern: 'prod-cluster-1'
  #   kind: literal
  #   category: hostname
  #   label: cluster_name
"#
}

fn template_body_database() -> &'static str {
    r#"secrets:
  # --- Connection strings (contain embedded credentials) ---
  - pattern: '(?i)(?:postgres|mysql|mongodb|redis|amqp|jdbc:[^:]+)://[^\s"''>]+'
    kind: regex
    category: url
    label: db_connection_string

  # --- Inline passwords / secrets ---
  - pattern: '(?i)(?:password|passwd|pwd)[\s:=]+[^\s"'']{6,}'
    kind: regex
    category: custom:db_password
    label: db_password

  - pattern: '(?i)(?:user|username|login)[\s:=]+[^\s"'']{3,}'
    kind: regex
    category: name
    label: db_username

  # --- Host / IP for database servers ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: db_host_ip

  - pattern: '\b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b'
    kind: regex
    category: hostname
    label: db_hostname

  # --- TLS certificate fingerprints / hashes ---
  - pattern: '\b[a-f0-9]{40}\b'
    kind: regex
    category: container_id
    label: cert_fingerprint

  # --- Add database-specific literals ---
  # - pattern: 'prod-db.internal.example.com'
  #   kind: literal
  #   category: hostname
  #   label: prod_db_host
"#
}

fn template_body_aws() -> &'static str {
    r#"secrets:
  # --- AWS access key IDs ---
  - pattern: '\b(?:AKIA|ASIA)[A-Z0-9]{16}\b'
    kind: regex
    category: auth_token
    label: aws_access_key_id

  # --- ARNs (may reveal account IDs, resource names) ---
  - pattern: '\barn:aws:[^\s]+'
    kind: regex
    category: aws_arn
    label: aws_arn

  # --- AWS account IDs (12-digit numbers in ARNs or standalone) ---
  - pattern: '\b\d{12}\b'
    kind: regex
    category: custom:aws_account_id
    label: aws_account_id

  # --- S3 bucket names and keys in URLs ---
  - pattern: 'https://s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com/[^\s"''<>]+'
    kind: regex
    category: url
    label: s3_url

  # --- EC2 / ECS instance IDs ---
  - pattern: '\bi-[0-9a-f]{8,17}\b'
    kind: regex
    category: container_id
    label: ec2_instance_id

  # --- IPs for EC2 instances ---
  - pattern: '\b(?:\d{1,3}\.){3}\d{1,3}\b'
    kind: regex
    category: ipv4
    label: ec2_ip

  # --- Emails in IAM roles, SES, etc. ---
  - pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
    kind: regex
    category: email
    label: email

  # --- Add your AWS account ID as a literal for exact matching ---
  # - pattern: '123456789012'
  #   kind: literal
  #   category: custom:aws_account_id
  #   label: my_account_id
"#
}

fn run_template(args: &TemplateArgs) -> Result<(), (String, i32)> {
    let preset = parse_template_preset(&args.preset).map_err(|e| (e, 1))?;

    let output_path = args
        .output
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("secrets.template.{}.yaml", args.preset)));

    if output_path.exists() && !args.overwrite {
        return Err((
            format!(
                "{} already exists — use --overwrite to replace it",
                output_path.display()
            ),
            1,
        ));
    }

    let body = match preset {
        TemplatePreset::Generic => template_body_generic(),
        TemplatePreset::Web => template_body_web(),
        TemplatePreset::K8s => template_body_k8s(),
        TemplatePreset::Database => template_body_database(),
        TemplatePreset::Aws => template_body_aws(),
    };

    let mut content = String::with_capacity(TEMPLATE_HEADER.len() + body.len());
    content.push_str(TEMPLATE_HEADER);
    content.push('\n');
    content.push_str(body);

    atomic_write(&output_path, content.as_bytes())
        .map_err(|e| (format!("failed to write {}: {e}", output_path.display()), 1))?;

    eprintln!("Template written to {}", output_path.display());
    eprintln!();
    eprintln!("Next steps:");
    eprintln!(
        "  1. Edit {} to add your own patterns and remove irrelevant ones.",
        output_path.display()
    );
    eprintln!(
        "  2. Encrypt:  sanitize encrypt {} {}.enc",
        output_path.display(),
        output_path.display()
    );
    eprintln!(
        "  3. Sanitize: sanitize <input> -s {}.enc -o <output>",
        output_path.display()
    );
    eprintln!();
    eprintln!("WARNING: always review sanitized output before sending to an LLM.");

    Ok(())
}

fn normalize_guided_output_path(path: PathBuf) -> PathBuf {
    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_ascii_lowercase())
    {
        Some(ext) if ext == "yaml" || ext == "yml" => path,
        _ => path.with_extension("yaml"),
    }
}

fn prompt_confirm_password() -> Result<Zeroizing<String>, String> {
    loop {
        let pw1 = prompt_password("encryption")?;
        let pw2 = prompt_password("encryption (confirm)")?;
        if pw1 == pw2 {
            return Ok(pw1);
        }
        // pw1 and pw2 are Zeroizing<String>; both zeroed on drop here.
        eprintln!("Passwords did not match. Try again.");
    }
}

fn run_guided() -> Result<(), (String, i32)> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err((
            "guided mode requires an interactive terminal (TTY)".into(),
            1,
        ));
    }

    eprintln!("Guided setup: logs-focused secrets template");
    eprintln!("This wizard creates a starter file you can extend later.\n");

    eprintln!("Workspace type (affects which patterns are included):");
    eprintln!("  1) Generic     — tokens, emails, IPs, hostnames, UUIDs");
    eprintln!("  2) Web app     — JWTs, session cookies, emails, URLs");
    eprintln!("  3) Kubernetes  — service accounts, tokens, namespaces");
    eprintln!("  4) Database    — passwords, connection strings, usernames");
    eprintln!("  5) AWS         — access keys, ARNs, account IDs");
    let preset = loop {
        let answer = prompt_line("Select [1-5] (default: 1): ").map_err(|e| (e, 1))?;
        match answer.as_str() {
            "" | "1" => break GuidedPreset::Balanced,
            "2" => break GuidedPreset::WebApp,
            "3" => break GuidedPreset::Kubernetes,
            "4" => break GuidedPreset::Database,
            "5" => break GuidedPreset::Aggressive,
            _ => eprintln!("Please enter a number from 1 to 5."),
        }
    };

    eprintln!("\nReplacement strictness:");
    eprintln!("  1) Balanced    — replace clearly sensitive values only");
    eprintln!("  2) Aggressive  — replace high-entropy tokens too (recommended for LLMs)");
    let aggressive = loop {
        let answer = prompt_line("Select [1/2] (default: 2): ").map_err(|e| (e, 1))?;
        match answer.as_str() {
            "" | "2" => break true,
            "1" => break false,
            _ => eprintln!("Please enter 1 or 2."),
        }
    };

    let domains = prompt_domains().map_err(|e| (e, 1))?;
    let providers = prompt_cloud_providers().map_err(|e| (e, 1))?;
    let exclude_noise_ids = prompt_yes_no(
        "Exclude noisy IDs (trace_id/span_id-like high-entropy values)?",
        true,
    )
    .map_err(|e| (e, 1))?;

    let out_raw = prompt_line("Output secrets file path (YAML; default: secrets.guided.yaml): ")
        .map_err(|e| (e, 1))?;
    let requested_output_path = if out_raw.trim().is_empty() {
        PathBuf::from("secrets.guided.yaml")
    } else {
        PathBuf::from(out_raw)
    };
    let output_path = normalize_guided_output_path(requested_output_path.clone());
    if output_path != requested_output_path {
        eprintln!(
            "Guided mode writes YAML templates; using {}",
            output_path.display()
        );
    }

    let options = GuidedOptions {
        preset: if aggressive {
            match preset {
                GuidedPreset::Balanced => GuidedPreset::Aggressive,
                other => other,
            }
        } else {
            preset
        },
        domains,
        providers,
        exclude_noise_ids,
    };
    let entries = build_guided_entries(&options);

    let (_patterns, compile_warnings) = entries_to_patterns(&entries);
    if !compile_warnings.is_empty() {
        return Err((
            format!(
                "generated template had {} invalid pattern(s)",
                compile_warnings.len()
            ),
            1,
        ));
    }

    let plain = serialize_secrets(&entries, SecretsFormat::Yaml)
        .map_err(|e| (format!("failed to serialize template: {e}"), 1))?;

    if output_path.exists()
        && !prompt_yes_no(
            &format!("{} already exists. Overwrite?", output_path.display()),
            false,
        )
        .map_err(|e| (e, 1))?
    {
        return Err(("aborted by user".into(), 1));
    }

    atomic_write(&output_path, &plain)
        .map_err(|e| (format!("failed to write {}: {e}", output_path.display()), 1))?;

    eprintln!(
        "Generated {} entries at {}",
        entries.len(),
        output_path.display()
    );

    let encrypt =
        prompt_yes_no("Encrypt the generated secrets file now?", true).map_err(|e| (e, 1))?;
    let mut secrets_for_run = output_path.clone();
    let mut run_password: Option<Zeroizing<String>> = None;
    let mut run_unencrypted = true;

    if encrypt {
        let pw = prompt_confirm_password().map_err(|e| (e, 1))?;
        let encrypted = encrypt_secrets(&plain, &pw)
            .map_err(|e| (format!("failed to encrypt guided secrets file: {e}"), 1))?;
        let encrypted_path = PathBuf::from(format!("{}.enc", output_path.display()));
        atomic_write(&encrypted_path, &encrypted).map_err(|e| {
            (
                format!("failed to write {}: {e}", encrypted_path.display()),
                1,
            )
        })?;
        eprintln!("Encrypted template written to {}", encrypted_path.display());
        secrets_for_run = encrypted_path;
        run_password = Some(pw);
        run_unencrypted = false;
    }

    let run_now =
        prompt_yes_no("Run sanitize now with this secrets file?", true).map_err(|e| (e, 1))?;
    if !run_now {
        eprintln!("Next: sanitize <input> -s {}", secrets_for_run.display());
        return Ok(());
    }

    let input_raw = prompt_line("Input file path (or '-' for stdin): ").map_err(|e| (e, 1))?;
    let input = if input_raw.trim().is_empty() {
        return Err(("input file path is required to run sanitize now".into(), 1));
    } else {
        PathBuf::from(input_raw)
    };

    let out_raw =
        prompt_line("Output path (optional; blank = stdout/default): ").map_err(|e| (e, 1))?;
    let output = if out_raw.trim().is_empty() {
        None
    } else {
        Some(PathBuf::from(out_raw))
    };

    let dry_run = prompt_yes_no("Dry-run first?", true).map_err(|e| (e, 1))?;
    let deterministic =
        prompt_yes_no("Use deterministic replacements?", true).map_err(|e| (e, 1))?;

    let mut deterministic_password: Option<Zeroizing<String>> = run_password.clone();
    if deterministic && deterministic_password.is_none() {
        deterministic_password = Some(prompt_password("deterministic seed").map_err(|e| (e, 1))?);
    }

    let cli = Cli {
        command: None,
        input: vec![input],
        output,
        secrets_file: Some(secrets_for_run),
        profile: None,
        password: false,
        password_file: None,
        encrypted_secrets: !run_unencrypted,
        format: None,
        dry_run,
        fail_on_match: false,
        report: None,
        strict: false,
        deterministic,
        include_binary: false,
        force_text: false,
        threads: None,
        chunk_size: 1_048_576,
        max_mappings: 10_000_000,
        max_structured_size: DEFAULT_MAX_STRUCTURED_FILE_SIZE,
        max_archive_depth: DEFAULT_MAX_ARCHIVE_DEPTH,
        log_format: "human".to_string(),
        progress: None,
        no_progress: false,
        progress_interval_ms: DEFAULT_PROGRESS_INTERVAL_MS,
    };

    run_sanitize(cli, deterministic_password.or(run_password), HashMap::new())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve a password from multiple sources (priority order):
///   1. `--password` CLI flag
///   2. `--password-file <PATH>` (read file, check Unix permissions)
///   3. `SANITIZE_PASSWORD` environment variable
///   4. Interactive prompt via rpassword (stderr)
///
/// Returns an error only when all sources are exhausted or invalid.
fn resolve_password(
    password_flag: bool,
    cli_password_file: &Option<PathBuf>,
    interactive_label: &str,
) -> Result<Zeroizing<String>, String> {
    // 1. Explicit --password flag → interactive prompt.
    if password_flag {
        if !io::stdin().is_terminal() {
            return Err("--password requires an interactive terminal. \
                 For non-interactive use, supply the password via \
                 --password-file or the SANITIZE_PASSWORD environment variable."
                .into());
        }
        return prompt_password(interactive_label);
    }

    // 2. --password-file.
    if let Some(path) = cli_password_file {
        return read_password_file(path);
    }

    // 3. SANITIZE_PASSWORD env var.
    if let Ok(pw) = std::env::var("SANITIZE_PASSWORD") {
        if !pw.is_empty() {
            eprintln!("info: using password from SANITIZE_PASSWORD environment variable");
            return Ok(Zeroizing::new(pw));
        }
    }

    // 4. Interactive prompt.
    prompt_password(interactive_label)
}

/// Read a password from a file, enforcing strict Unix permissions.
#[cfg(unix)]
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    use nix::sys::stat::fstat;
    use std::os::unix::io::AsRawFd;

    let file = fs::File::open(path)
        .map_err(|e| format!("cannot open password file {}: {e}", path.display()))?;

    let stat = fstat(file.as_raw_fd())
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?;

    let mode = stat.st_mode & 0o777;
    if mode != 0o600 && mode != 0o400 {
        return Err(format!(
            "password file {} has permissions {:04o}; expected 0600 or 0400. \
             Fix with: chmod 600 {}",
            path.display(),
            mode,
            path.display(),
        ));
    }

    read_password_file_contents(path)
}

/// Read a password from a file (no permission checks on non-Unix platforms).
#[cfg(not(unix))]
fn read_password_file(path: &Path) -> Result<Zeroizing<String>, String> {
    eprintln!(
        "warning: password-file permission checks are only available on Unix. \
         Ensure {} is not world-readable.",
        path.display(),
    );
    read_password_file_contents(path)
}

/// Shared helper: read and trim password file contents.
fn read_password_file_contents(path: &Path) -> Result<Zeroizing<String>, String> {
    const MAX_PASSWORD_FILE_BYTES: u64 = 4096;
    let size = fs::metadata(path)
        .map_err(|e| format!("cannot stat password file {}: {e}", path.display()))?
        .len();
    if size > MAX_PASSWORD_FILE_BYTES {
        return Err(format!(
            "password file {} is too large ({size} bytes); expected ≤ {MAX_PASSWORD_FILE_BYTES} bytes",
            path.display(),
        ));
    }

    let mut contents = Zeroizing::new(
        fs::read_to_string(path)
            .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?,
    );

    // Trim a single trailing newline (common in files created by echo/printf).
    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }

    if contents.is_empty() {
        return Err(format!("password file {} is empty", path.display()));
        // contents is Zeroizing<String> — zeroed on drop.
    }

    Ok(contents)
}

/// Prompt for a password on stderr with hidden input.
fn prompt_password(label: &str) -> Result<Zeroizing<String>, String> {
    let pw = rpassword::prompt_password(format!("Enter {label} password: "))
        .map_err(|e| format!("failed to read password: {e}"))?;

    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(Zeroizing::new(pw))
}

/// Resolve password for the default sanitize mode.
fn resolve_sanitize_password(cli: &Cli) -> Result<Zeroizing<String>, String> {
    resolve_password(cli.password, &cli.password_file, "secrets decryption")
}

/// Return `true` if the first 512 bytes look like binary (contain NUL
/// bytes or a high ratio of non-UTF-8 bytes).
fn looks_binary(data: &[u8]) -> bool {
    let sample = &data[..data.len().min(512)];
    if sample.contains(&0u8) {
        return true;
    }
    let non_text = sample
        .iter()
        .filter(|&&b| b < 0x20 && b != b'\n' && b != b'\r' && b != b'\t')
        .count();
    non_text as f64 / sample.len().max(1) as f64 > 0.10
}

/// Build an `Arc<MappingStore>` with the chosen generator mode.
fn build_store(
    deterministic: bool,
    password: Option<&str>,
    max_mappings: usize,
) -> std::result::Result<Arc<MappingStore>, String> {
    let generator: Arc<dyn ReplacementGenerator> = if deterministic {
        let seed = match password {
            Some(k) => {
                use hmac::Hmac;
                use sha2::Sha256;
                use zeroize::Zeroizing;
                let mut buf = Zeroizing::new([0u8; 32]);
                let salt = b"sanitize-engine:deterministic-seed:v1";
                pbkdf2::pbkdf2::<Hmac<Sha256>>(k.as_bytes(), salt, 600_000, buf.as_mut())
                    .expect("PBKDF2 output length is valid");
                *buf
            }
            None => {
                return Err(
                    "--deterministic requires --password (or SANITIZE_PASSWORD). \
                     A deterministic seed cannot be derived without a key."
                        .into(),
                );
            }
        };
        Arc::new(HmacGenerator::new(seed))
    } else {
        Arc::new(RandomGenerator::new())
    };
    let capacity = if max_mappings == 0 {
        None
    } else {
        Some(max_mappings)
    };
    Ok(Arc::new(MappingStore::new(generator, capacity)))
}

/// Build an augmented scanner after the profile pass (Phase 1).
///
/// Re-parses the secrets file (if any) to get base patterns, then adds a
/// literal `ScanPattern` for every original value recorded in `store` during
/// Phase 1. This allows the scanner to catch those same values verbatim in
/// plain-text files processed in Phase 2.
///
/// Values shorter than 4 bytes are skipped to avoid false positives.
fn build_augmented_scanner(
    secrets_raw_bytes: Option<&[u8]>,
    password: Option<&str>,
    allow_plaintext: bool,
    store: &Arc<MappingStore>,
    scan_config: ScanConfig,
) -> std::result::Result<Arc<StreamScanner>, (String, i32)> {
    // Re-compile base patterns from the secrets file (if one was provided).
    let mut patterns: Vec<ScanPattern> = if let Some(raw) = secrets_raw_bytes {
        let ((base, _warnings), _encrypted) =
            sanitize_engine::secrets::load_secrets_auto(raw, password, None, allow_plaintext)
                .map_err(|e| {
                    (
                        format!("failed to reload secrets for augmented scanner: {e}"),
                        1,
                    )
                })?;
        base
    } else {
        vec![]
    };

    // Harvest original values recorded by the profile processor in Phase 1.
    let mut discovered = 0usize;
    for (category, original, _replacement) in store.iter() {
        let s = original.as_str();
        if s.len() < 4 {
            continue; // too short — high false-positive risk
        }
        match ScanPattern::from_literal(s, category, format!("profile-discovered:{s}")) {
            Ok(pat) => {
                patterns.push(pat);
                discovered += 1;
            }
            Err(e) => {
                warn!(value = s, error = %e, "could not compile discovered literal pattern");
            }
        }
    }

    if discovered > 0 {
        info!(
            count = discovered,
            "augmented scanner with profile-discovered literals"
        );
    }

    let scanner = StreamScanner::new(patterns, Arc::clone(store), scan_config)
        .map_err(|e| (format!("failed to create augmented scanner: {e}"), 1))?;
    Ok(Arc::new(scanner))
}

/// Build a `ScanConfig`, validating `chunk_size`.
fn build_scan_config(chunk_size: usize) -> Result<ScanConfig, String> {
    if chunk_size == 0 {
        return Err("--chunk-size must be greater than 0".into());
    }
    // Overlap = 25% of chunk, capped at 4 KiB, minimum 1 byte.
    // This replaces the previous `chunk_size.clamp(256, 4096)` which
    // returned chunk_size itself for any value in [256, 4096], making
    // overlap >= chunk_size and causing every small chunk to be rejected.
    let overlap = (chunk_size / 4).clamp(1, 4096);
    if overlap >= chunk_size {
        return Err(format!(
            "--chunk-size ({chunk_size}) is too small; must be > {overlap} bytes"
        ));
    }
    let cfg = ScanConfig::new(chunk_size, overlap);
    cfg.validate().map_err(|e| e.to_string())?;
    Ok(cfg)
}

/// Derive a default output path for archive files.
fn default_archive_output(input: &Path, fmt: ArchiveFormat) -> PathBuf {
    let stem = input
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let ext = match fmt {
        ArchiveFormat::Zip => "zip",
        ArchiveFormat::Tar => "tar",
        ArchiveFormat::TarGz => "tar.gz",
    };
    let base = if matches!(fmt, ArchiveFormat::TarGz) {
        stem.strip_suffix(".tar").unwrap_or(stem)
    } else {
        stem
    };
    input.with_file_name(format!("{base}.sanitized.{ext}"))
}

// ---------------------------------------------------------------------------
// Logging initialisation
// ---------------------------------------------------------------------------

/// Initialise the `tracing` subscriber based on the `--log-format` flag.
///
/// - `"human"` → compact human-readable on stderr.
/// - `"json"` → structured JSON on stderr (SIEM-friendly).
///
/// In both modes the default level is `INFO` and can be overridden via
/// the `SANITIZE_LOG` environment variable (e.g. `SANITIZE_LOG=debug`).
///
/// **Security**: no secret values are ever passed to tracing macros —
/// only opaque identifiers, counts, paths, and durations are logged.
fn init_logging(log_format: &str) {
    use tracing_subscriber::fmt;
    use tracing_subscriber::EnvFilter;

    let filter = EnvFilter::try_from_env("SANITIZE_LOG").unwrap_or_else(|_| EnvFilter::new("info"));

    match log_format {
        "json" => {
            let _ = fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .with_writer(io::stderr)
                .try_init();
        }
        _ => {
            let _ = fmt()
                .compact()
                .with_env_filter(filter)
                .with_target(false)
                .with_writer(io::stderr)
                .try_init();
        }
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Returns `true` when input should be read from stdin.
fn has_stdin_input(cli: &Cli) -> bool {
    cli.input.is_empty() || cli.input.iter().any(|p| p.as_os_str() == "-")
}

/// Returns file-path inputs, excluding explicit stdin markers ("-").
fn file_inputs(cli: &Cli) -> Vec<&PathBuf> {
    cli.input.iter().filter(|p| p.as_os_str() != "-").collect()
}

/// Map the `--format` value to extension-like string for structured processor
/// lookup. Returns `None` for "text" or unrecognised values.
fn format_to_ext(fmt: &str) -> Option<&str> {
    match fmt {
        "json" => Some("json"),
        "yaml" | "yml" => Some("yaml"),
        "xml" => Some("xml"),
        "csv" => Some("csv"),
        "tsv" => Some("tsv"),
        "key-value" | "key_value" | "kv" => Some("conf"),
        "toml" => Some("toml"),
        "env" => Some("env"),
        "ini" => Some("ini"),
        "log" => Some("log"),
        _ => None,
    }
}

fn default_plain_output(input: &Path) -> PathBuf {
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output");

    let output_name = if let Some((stem, ext)) = name.rsplit_once('.') {
        format!("{stem}-sanitized.{ext}")
    } else {
        format!("{name}-sanitized")
    };

    input.with_file_name(output_name)
}

fn split_name_for_suffix(name: &str) -> (String, String) {
    if let Some(stem) = name.strip_suffix(".tar.gz") {
        return (stem.to_string(), ".tar.gz".to_string());
    }
    if let Some((stem, ext)) = name.rsplit_once('.') {
        return (stem.to_string(), format!(".{ext}"));
    }
    (name.to_string(), String::new())
}

fn uniquify_output_path(path: PathBuf, used: &mut HashSet<PathBuf>) -> PathBuf {
    if !path.exists() && !used.contains(&path) {
        used.insert(path.clone());
        return path;
    }

    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("output")
        .to_string();
    let (stem, ext) = split_name_for_suffix(&name);

    let mut idx = 1usize;
    loop {
        let candidate = parent.join(format!("{stem}-{idx}{ext}"));
        if !candidate.exists() && !used.contains(&candidate) {
            used.insert(candidate.clone());
            return candidate;
        }
        idx += 1;
    }
}

enum InputTarget {
    Stdin { output: Option<PathBuf> },
    File { input: PathBuf, output: PathBuf },
}

fn plan_input_targets(cli: &Cli) -> Result<Vec<InputTarget>, String> {
    let has_implicit_stdin = cli.input.is_empty();
    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();

    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    let mut units = Vec::new();
    if has_implicit_stdin {
        units.push(InputTarget::Stdin {
            output: cli.output.clone(),
        });
        return Ok(units);
    }

    let input_count = cli.input.len();
    let multi_input = input_count > 1;
    let mut used_outputs = HashSet::new();

    let output_dir = if multi_input {
        if let Some(path) = &cli.output {
            if path.exists() && !path.is_dir() {
                return Err(format!(
                    "--output must be a directory when multiple inputs are provided: {}",
                    path.display()
                ));
            }
            if !path.exists() {
                fs::create_dir_all(path).map_err(|e| {
                    format!("failed to create output directory {}: {e}", path.display())
                })?;
            }
            Some(path.clone())
        } else {
            None
        }
    } else {
        None
    };

    for input in &cli.input {
        if input.as_os_str() == "-" {
            let stdin_output = if multi_input {
                None
            } else {
                cli.output.clone()
            };
            units.push(InputTarget::Stdin {
                output: stdin_output,
            });
            continue;
        }

        let format = ArchiveFormat::from_path(&input.to_string_lossy());
        let default_out = match format {
            Some(fmt) => default_archive_output(input, fmt),
            None => default_plain_output(input),
        };

        let planned_out = if multi_input {
            let out_name = default_out
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("output")
                .to_string();

            if let Some(dir) = &output_dir {
                uniquify_output_path(dir.join(out_name), &mut used_outputs)
            } else {
                uniquify_output_path(default_out, &mut used_outputs)
            }
        } else if let Some(out) = &cli.output {
            out.clone()
        } else {
            default_out
        };

        units.push(InputTarget::File {
            input: input.clone(),
            output: planned_out,
        });
    }

    Ok(units)
}

// ---------------------------------------------------------------------------
// Archive filter pre-parser
// ---------------------------------------------------------------------------

/// Pre-parse `--only` / `--exclude` flags that are interleaved with archive
/// paths in the raw argument list, **before** clap sees them.
///
/// Syntax:
/// ```text
/// archive.zip --only PATTERN... --exclude PATTERN... other.tar.gz --only PATTERN...
/// ```
///
/// Rules:
/// - `--only` / `--exclude` must appear **after** an archive path.  Using
///   them before any archive is a hard error.
/// - A non-flag argument appearing while collecting patterns is treated as
///   a new archive path if it matches a known archive extension **and** the
///   file exists on disk.  Otherwise it is a hard error ("non-archive path
///   cannot appear between filter flags").
/// - The `--only` / `--exclude` tokens and their value arguments are
///   **stripped** from the returned cleaned argument list; everything else
///   passes through to clap unchanged.
/// - Glob patterns are validated eagerly; invalid syntax is reported before
///   any archive is opened.
///
/// Returns `(filter_map, cleaned_args)` where `filter_map` maps each
/// archive path (as it appeared on the command line) to its
/// `(only_patterns, exclude_patterns)` pair.
#[allow(clippy::type_complexity)]
fn parse_archive_filters(
    args: &[OsString],
) -> Result<(HashMap<PathBuf, (Vec<String>, Vec<String>)>, Vec<OsString>), String> {
    #[derive(PartialEq)]
    enum State {
        Global,
        AfterArchive,
        CollectingOnly,
        CollectingExclude,
    }

    let mut state = State::Global;
    let mut current_archive: Option<PathBuf> = None;
    let mut filter_map: HashMap<PathBuf, (Vec<String>, Vec<String>)> = HashMap::new();
    let mut cleaned: Vec<OsString> = Vec::with_capacity(args.len());

    // Validate a glob pattern (patterns ending with '/' are directory
    // prefixes and require no glob validation).
    let validate_pattern = |p: &str| -> Result<(), String> {
        if !p.ends_with('/') {
            glob::Pattern::new(p).map_err(|e| format!("invalid glob pattern '{p}': {e}"))?;
        }
        Ok(())
    };

    for arg in args {
        let s = arg.to_string_lossy();

        match s.as_ref() {
            "--only" => {
                if state == State::Global {
                    return Err(
                        "--only must follow an archive path (e.g. archive.zip --only PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingOnly;
                // strip from cleaned args
            }
            "--exclude" => {
                if state == State::Global {
                    return Err(
                        "--exclude must follow an archive path (e.g. archive.zip --exclude PATTERN)"
                            .into(),
                    );
                }
                state = State::CollectingExclude;
                // strip from cleaned args
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && !s.starts_with('-') =>
            {
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() && candidate.is_file() {
                    // Transition: start a new archive group.
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                    cleaned.push(arg.clone());
                } else if candidate.is_file() {
                    // Plain file (not an archive) between filter flags — hard error.
                    return Err(format!(
                        "non-archive path '{}' cannot appear between filter flags; \
                         move it before or after the archive+filter group",
                        candidate.display()
                    ));
                } else {
                    // Treat as a pattern value (e.g. "*.json", "config/", "/logs/**").
                    // Patterns that look like paths but don't exist on disk are valid.
                    validate_pattern(&s)?;
                    let key = current_archive.as_ref().unwrap();
                    let entry = filter_map.entry(key.clone()).or_default();
                    if state == State::CollectingOnly {
                        entry.0.push(s.into_owned());
                    } else {
                        entry.1.push(s.into_owned());
                    }
                    // pattern values are NOT passed to cleaned args
                }
            }
            _ if (state == State::CollectingOnly || state == State::CollectingExclude)
                && s.starts_with('-') =>
            {
                // Another flag ends pattern collection.
                state = State::AfterArchive;
                cleaned.push(arg.clone());
            }
            _ => {
                // Regular argument in Global or AfterArchive state.
                let candidate = PathBuf::from(s.as_ref());
                if ArchiveFormat::from_path(&s).is_some() {
                    filter_map
                        .entry(candidate.clone())
                        .or_insert_with(|| (Vec::new(), Vec::new()));
                    current_archive = Some(candidate.clone());
                    state = State::AfterArchive;
                }
                cleaned.push(arg.clone());
            }
        }
    }

    Ok((filter_map, cleaned))
}

fn validate_args(cli: &Cli) -> Result<(), String> {
    if has_stdin_input(cli) && io::stdin().is_terminal() {
        return Err("stdin was requested but stdin is a terminal.\n\
             Provide file path(s) only, or pipe data into sanitize when using '-'.\n\n\
             Usage: sanitize [OPTIONS] [INPUT]...\n       \
             command | sanitize -s secrets.yaml"
            .into());
    }

    let explicit_stdin_count = cli.input.iter().filter(|p| p.as_os_str() == "-").count();
    if explicit_stdin_count > 1 {
        return Err("stdin marker '-' can be specified at most once".into());
    }

    for input in file_inputs(cli) {
        if !input.exists() {
            return Err(format!("input file not found: {}", input.display()));
        }
        if !input.is_file() {
            return Err(format!(
                "input path is not a regular file: {}",
                input.display()
            ));
        }
    }

    if let Some(ref fmt) = cli.format {
        let valid = [
            "text",
            "json",
            "yaml",
            "yml",
            "xml",
            "csv",
            "tsv",
            "key-value",
            "toml",
            "env",
            "ini",
            "log",
        ];
        if !valid.contains(&fmt.as_str()) {
            return Err(format!(
                "invalid --format '{}': must be one of: {}",
                fmt,
                valid.join(", ")
            ));
        }
    }

    if let Some(ref sf) = cli.secrets_file {
        if !sf.exists() && !cli.deterministic {
            return Err(format!("secrets file not found: {}", sf.display()));
        }
        if sf.exists() && !sf.is_file() {
            return Err(format!(
                "secrets path is not a regular file: {}",
                sf.display()
            ));
        }
    }

    build_scan_config(cli.chunk_size)?;

    if let Some(t) = cli.threads {
        if t == 0 {
            return Err("--threads must be ≥ 1".into());
        }
    }

    if cli.max_archive_depth > 10 {
        return Err(format!(
            "--max-archive-depth {} exceeds maximum of 10 (each nesting level \
             may buffer up to 256 MiB of archive data)",
            cli.max_archive_depth
        ));
    }
    if cli.max_archive_depth == 0 {
        return Err("--max-archive-depth must be ≥ 1".into());
    }

    if !matches!(cli.log_format.as_str(), "human" | "json") {
        return Err(format!(
            "invalid --log-format '{}': must be 'human' or 'json'",
            cli.log_format
        ));
    }

    if cli.progress_interval_ms == 0 {
        return Err("--progress-interval-ms must be greater than 0".into());
    }

    // Password inputs require --encrypted-secrets; reject early to avoid
    // confusing "failed to load secrets" errors later.
    let has_password_source = cli.password
        || cli.password_file.is_some()
        || std::env::var("SANITIZE_PASSWORD").is_ok_and(|v| !v.is_empty());
    if has_password_source && !cli.encrypted_secrets && !cli.deterministic {
        return Err(
            "password input (--password, --password-file, or SANITIZE_PASSWORD) \
             was provided but --encrypted-secrets is not set.\n\
             Add --encrypted-secrets to decrypt the secrets file, or remove \
             password inputs to use a plaintext file."
                .into(),
        );
    }

    Ok(())
}

/// Resolve and cap thread count to available parallelism.
fn resolve_thread_count(requested: Option<usize>) -> usize {
    let available = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    match requested {
        Some(n) => n.min(available),
        None => available,
    }
}

// ---------------------------------------------------------------------------
// Processing helpers
// ---------------------------------------------------------------------------

/// Build a scan progress callback that forwards updates to the shared reporter.
///
/// Eliminates the boilerplate of cloning the `SharedProgressReporter` and
/// constructing an identical `move` closure at every `scan_reader_with_progress`
/// call site.
fn make_scan_callback(
    progress: Option<SharedProgressReporter>,
    label: impl Into<String>,
) -> impl FnMut(&sanitize_engine::ScanProgress) {
    let label = label.into();
    move |scan_progress| {
        if let Some(reporter) = &progress {
            reporter
                .lock()
                .expect("progress reporter lock")
                .update_scan(&label, scan_progress);
        }
    }
}

// ---------------------------------------------------------------------------
// Processing
// ---------------------------------------------------------------------------

/// Process input from stdin. Returns `true` if matches were found.
#[allow(clippy::too_many_arguments)]
fn process_stdin(
    cli: &Cli,
    output_path: Option<&Path>,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
) -> Result<bool, String> {
    // Determine whether structured processing should be attempted.
    // Skipped entirely when --force-text is set.
    let structured_ext = if cli.force_text {
        None
    } else {
        cli.format.as_deref().and_then(format_to_ext)
    };

    let mut had_matches = false;

    if let Some(ext) = structured_ext {
        // Buffer stdin for structured processing (bounded by max_structured_size).
        let mut input_bytes = Vec::new();
        let limit = cli.max_structured_size;
        io::stdin()
            .take(limit + 1)
            .read_to_end(&mut input_bytes)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        if input_bytes.len() as u64 > limit {
            warn!(
                max = limit,
                "stdin exceeds --max-structured-size, falling back to streaming scanner"
            );
            // Too large — fall through to streaming below.
            // Re-combine what we read with the rest of stdin.
            let cursor = Cursor::new(input_bytes);
            let chained = cursor.chain(io::stdin().lock());
            let reader = BufReader::new(chained);
            return process_stdin_streaming(
                reader,
                output_path,
                cli,
                scanner,
                report_builder,
                progress,
            );
        }

        let store_len_before = store.len();
        let label = format!("Processing structured stdin ({ext})");
        return with_progress_scope(progress, &label, |_| {
            let structured_result = try_structured_processing(
                &input_bytes,
                &format!("stdin.{ext}"),
                registry,
                store,
                profiles,
            );

            match structured_result {
                Some(Ok(structured_bytes)) => {
                    // Double-pass: run the streaming scanner on the structured
                    // output to catch anything missed by field-rule gaps.
                    let (output_bytes, scan_stats) = scanner_fallback(scanner, &structured_bytes)?;
                    let method = format!("structured+scan:{ext}");
                    let structured_reps = store.len().saturating_sub(store_len_before) as u64;
                    let total_replacements = structured_reps + scan_stats.replacements_applied;
                    if total_replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        let stats = ScanStats {
                            matches_found: total_replacements,
                            replacements_applied: total_replacements,
                            bytes_processed: input_bytes.len() as u64,
                            bytes_output: output_bytes.len() as u64,
                            ..Default::default()
                        };
                        rb.record_file(FileReport::from_scan_stats(
                            "<stdin>".to_string(),
                            &stats,
                            method,
                        ));
                    }
                    if !cli.dry_run {
                        write_output(output_path, &output_bytes)?;
                    }
                    return Ok(had_matches);
                }
                Some(Err(e)) => {
                    if cli.strict {
                        return Err(format!("structured processing failed: {e}"));
                    }
                    warn!(error = %e, "structured processing failed, falling back to scanner");
                }
                None => {}
            }

            let (output_bytes, stats) = scanner_fallback(scanner, &input_bytes)?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    "<stdin>".to_string(),
                    &stats,
                    "scanner",
                ));
            }
            if !cli.dry_run {
                write_output(output_path, &output_bytes)?;
            }
            Ok(had_matches)
        });
    }

    // Plain text streaming from stdin.
    let reader = BufReader::new(io::stdin().lock());
    process_stdin_streaming(reader, output_path, cli, scanner, report_builder, progress)
}

/// Stream stdin through the scanner, writing to output (stdout or file).
fn process_stdin_streaming<R: io::Read>(
    reader: BufReader<R>,
    output_path: Option<&Path>,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
) -> Result<bool, String> {
    let label = if cli.dry_run {
        "Scanning stdin (dry-run)"
    } else {
        "Scanning stdin"
    };

    with_progress_scope(progress, label, |progress| {
        let mut had_matches = false;

        if cli.dry_run {
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    io::sink(),
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    "<stdin>".to_string(),
                    &stats,
                    "scanner",
                ));
            }
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            return Ok(had_matches);
        }

        if let Some(out_path) = output_path {
            let mut atomic_writer = AtomicFileWriter::new(out_path)
                .map_err(|e| format!("failed to create output: {e}"))?;

            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    &mut atomic_writer,
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;

            if is_interrupted() {
                return Err("interrupted — partial output discarded".into());
            }

            atomic_writer
                .finish()
                .map_err(|e| format!("failed to finalize output: {e}"))?;

            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    "<stdin>".to_string(),
                    &stats,
                    "scanner",
                ));
            }
        } else {
            let stdout = io::stdout();
            let writer = BufWriter::new(stdout.lock());
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    writer,
                    None,
                    make_scan_callback(progress.clone(), label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    "<stdin>".to_string(),
                    &stats,
                    "scanner",
                ));
            }
        }

        Ok(had_matches)
    })
}

/// Process a plain (non-archive) file. Returns `true` if matches were found.
#[allow(clippy::too_many_arguments)]
fn process_plain_file(
    input: &Path,
    cli: &Cli,
    output_path: Option<&Path>,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
) -> Result<bool, String> {
    // --- binary detection ---
    let mut sample = [0u8; 512];
    let sample_len = {
        let mut f = fs::File::open(input)
            .map_err(|e| format!("failed to open {}: {e}", input.display()))?;
        io::Read::read(&mut f, &mut sample)
            .map_err(|e| format!("failed to read {}: {e}", input.display()))?
    };
    if !cli.include_binary && looks_binary(&sample[..sample_len]) {
        let file_size = sample_len as u64;
        warn!(
            file = %input.display(),
            bytes = file_size,
            "skipping binary file — use --include-binary to process it"
        );
        return Ok(false);
    }

    let filename = if let Some(ref fmt) = cli.format {
        // --format overrides extension-based detection.
        format_to_ext(fmt)
            .map(|ext| format!("override.{ext}"))
            .unwrap_or_default()
    } else {
        input
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string()
    };

    let structured_ext = matches!(
        filename.rsplit('.').next().unwrap_or(""),
        "json"
            | "yaml"
            | "yml"
            | "xml"
            | "csv"
            | "tsv"
            | "rb"
            | "conf"
            | "cfg"
            | "ini"
            | "env"
            | "properties"
            | "toml"
    ) || {
        // Handle `.env` and `.env.local` style filenames where the file
        // name itself starts with `.env`.
        filename
            .rsplit('/')
            .next()
            .unwrap_or(&filename)
            .starts_with(".env")
    };

    let mut had_matches = false;

    // --- Bounded-memory scanner path for known structured extensions ---
    // Files with structured extensions (json, yaml, toml, etc.) are read
    // fully into memory (up to --max-structured-size) so the scanner can
    // operate on a contiguous buffer.  The streaming scanner path below
    // handles everything else and files that exceed the size limit.
    if structured_ext && !cli.force_text {
        let file_meta =
            fs::metadata(input).map_err(|e| format!("failed to stat {}: {e}", input.display()))?;
        let file_size = file_meta.len();

        if file_size > cli.max_structured_size {
            warn!(
                file = %input.display(),
                size = file_size,
                max = cli.max_structured_size,
                "structured file exceeds size limit, falling back to streaming scanner"
            );
        } else {
            let input_bytes =
                fs::read(input).map_err(|e| format!("failed to read {}: {e}", input.display()))?;

            // Track store size before processing to compute replacements
            // without a redundant re-scan of the input.
            let store_len_before = store.len();

            // Snapshot existing store keys so we can diff after structured
            // processing to find the literals discovered by this file.
            let store_snapshot = store.snapshot_keys();

            let label = format!("Processing structured {}", input.display());
            return with_progress_scope(progress, &label, |_| {
                let structured_result =
                    try_structured_processing(&input_bytes, &filename, registry, store, profiles);

                let (output_bytes, method, _was_structured, fallback_stats) =
                    match structured_result {
                        Some(Ok(_structured_bytes)) => {
                            // Format-preserving double-pass:
                            //   1. Structured processing already populated the store with
                            //      field-value mappings — its re-serialized output is discarded.
                            //   2. We diff the store against the pre-pass snapshot to find the
                            //      literals this file contributed.
                            //   3. A per-file scanner (base patterns + new literals) scans the
                            //      *original* bytes, preserving comments, indentation, and key order.
                            let ext = filename.rsplit('.').next().unwrap_or("unknown");
                            let per_file_scanner =
                                build_format_preserving_scanner(scanner, store, &store_snapshot)
                                    .map_err(|e| {
                                        format!("failed to build per-file scanner: {e}")
                                    })?;
                            let (scanned_bytes, scan_stats) =
                                scanner_fallback(&per_file_scanner, &input_bytes)?;
                            (
                                scanned_bytes,
                                format!("structured+scan:{ext}"),
                                true,
                                Some(scan_stats),
                            )
                        }
                        Some(Err(e)) => {
                            if cli.strict {
                                return Err(format!("structured processing failed: {e}"));
                            }
                            warn!(error = %e, "structured processing failed, falling back to scanner");
                            let (out, stats) = scanner_fallback(scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                        None => {
                            let (out, stats) = scanner_fallback(scanner, &input_bytes)?;
                            (out, "scanner".into(), false, Some(stats))
                        }
                    };

                if cli.dry_run || report_builder.is_some() || cli.fail_on_match {
                    // In both structured and scanner paths the final output comes from
                    // a streaming scan pass, so replacements_applied is accurate.
                    let _ = store_len_before; // no longer used for counting
                    let replacements = fallback_stats
                        .as_ref()
                        .map_or(0, |s| s.replacements_applied);

                    if replacements > 0 {
                        had_matches = true;
                    }
                    if let Some(rb) = report_builder {
                        let stats = ScanStats {
                            matches_found: replacements,
                            replacements_applied: replacements,
                            bytes_processed: input_bytes.len() as u64,
                            bytes_output: output_bytes.len() as u64,
                            ..Default::default()
                        };
                        rb.record_file(FileReport::from_scan_stats(
                            input.display().to_string(),
                            &stats,
                            method,
                        ));
                    }
                    if cli.dry_run {
                        info!(
                            matches = replacements,
                            replacements = replacements,
                            "dry-run complete"
                        );
                        return Ok(had_matches);
                    }
                }
                write_output(output_path, &output_bytes)?;
                Ok(had_matches)
            });
        }
    }

    // --- Streaming path ---
    let method = "scanner";

    if cli.dry_run {
        let label = format!("Scanning {} (dry-run)", input.display());
        let progress_label = label.clone();
        with_progress_scope(progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let progress_for_scan = progress.clone();
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    io::sink(),
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                )
                .map_err(|e| format!("scan error: {e}"))?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    input.display().to_string(),
                    &stats,
                    method,
                ));
            }
            info!(
                matches = stats.matches_found,
                replacements = stats.replacements_applied,
                "dry-run complete"
            );
            Ok(had_matches)
        })
    } else if let Some(out_path) = output_path {
        // Real streaming output.
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        with_progress_scope(progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let mut atomic_writer = AtomicFileWriter::new(out_path)
                .map_err(|e| format!("failed to create output: {e}"))?;

            let progress_for_scan = progress.clone();
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    &mut atomic_writer,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;

            if is_interrupted() {
                return Err("interrupted — partial output discarded".into());
            }

            atomic_writer
                .finish()
                .map_err(|e| format!("failed to finalize output: {e}"))?;

            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    input.display().to_string(),
                    &stats,
                    method,
                ));
            }
            Ok(had_matches)
        })
    } else {
        let label = format!("Scanning {}", input.display());
        let progress_label = label.clone();
        with_progress_scope(progress, &label, move |progress| {
            let reader = BufReader::new(
                fs::File::open(input)
                    .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
            );
            let stdout = io::stdout();
            let writer = BufWriter::new(stdout.lock());
            let progress_for_scan = progress.clone();
            let stats = scanner
                .scan_reader_with_progress(
                    reader,
                    writer,
                    Some(file_size(input)?),
                    make_scan_callback(progress_for_scan, &progress_label),
                )
                .map_err(|e| format!("scanner error: {e}"))?;
            if stats.matches_found > 0 {
                had_matches = true;
            }
            if let Some(rb) = report_builder {
                rb.record_file(FileReport::from_scan_stats(
                    input.display().to_string(),
                    &stats,
                    method,
                ));
            }
            Ok(had_matches)
        })
    }
}

/// Persist values discovered by structured scanning into a YAML secrets file.
///
/// Called at the end of a deterministic run so that the literal values found
/// by profile-based processors are available to future runs' streaming scanner.
///
/// - If `path` already exists: parse its entries, merge, deduplicate, rewrite.
/// - If `path` does not exist: create it with the discovered entries.
/// - Values shorter than 4 bytes are skipped (too short → high false-positive risk).
/// - Entries whose `pattern` already appears in the file are skipped.
fn save_discovered_secrets(
    store: &Arc<MappingStore>,
    path: &Path,
) -> std::result::Result<usize, String> {
    // Collect discovered (original, category) pairs from the store.
    let mut new_entries: Vec<SecretEntry> = store
        .iter()
        .filter(|(_, original, _)| original.len() >= 4)
        .map(|(category, original, _)| SecretEntry {
            pattern: original.to_string(),
            kind: "literal".into(),
            category: category.to_string(),
            label: Some("discovered".into()),
        })
        .collect();

    if new_entries.is_empty() {
        return Ok(0);
    }

    // Load existing entries to deduplicate against.
    let existing: Vec<SecretEntry> = if path.exists() {
        let raw = fs::read(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
        let text = std::str::from_utf8(&raw)
            .map_err(|_| format!("{} is not valid UTF-8", path.display()))?;
        serde_yaml_ng::from_str::<Vec<SecretEntry>>(text).unwrap_or_default()
    } else {
        vec![]
    };

    let existing_patterns: std::collections::HashSet<&str> =
        existing.iter().map(|e| e.pattern.as_str()).collect();

    new_entries.retain(|e| !existing_patterns.contains(e.pattern.as_str()));
    let added = new_entries.len();

    if added == 0 {
        return Ok(0);
    }

    // Merge and serialize.
    let mut all_entries: Vec<&SecretEntry> = existing.iter().collect();
    all_entries.extend(new_entries.iter());

    let yaml = serde_yaml_ng::to_string(&all_entries)
        .map_err(|e| format!("failed to serialize discovered secrets: {e}"))?;

    atomic_write(path, yaml.as_bytes())
        .map_err(|e| format!("failed to write {}: {e}", path.display()))?;

    Ok(added)
}

/// Load file-type profiles from a JSON or YAML file.
///
/// The file must deserialize to `Vec<FileTypeProfile>`. Format is detected
/// from the file extension; unknown extensions are tried as JSON then YAML.
fn load_profiles(path: &Path) -> Result<Vec<sanitize_engine::processor::FileTypeProfile>, String> {
    let raw =
        fs::read(path).map_err(|e| format!("failed to read profile '{}': {e}", path.display()))?;
    let text = std::str::from_utf8(&raw)
        .map_err(|_| format!("profile '{}' is not valid UTF-8", path.display()))?;
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    let profiles: Vec<sanitize_engine::processor::FileTypeProfile> = match ext {
        "json" => serde_json::from_str(text)
            .map_err(|e| format!("profile '{}': invalid JSON: {e}", path.display())),
        "yaml" | "yml" => serde_yaml_ng::from_str(text)
            .map_err(|e| format!("profile '{}': invalid YAML: {e}", path.display())),
        _ => serde_json::from_str(text)
            .or_else(|_| serde_yaml_ng::from_str(text))
            .map_err(|e| {
                format!(
                    "profile '{}': could not parse as JSON or YAML: {e}",
                    path.display()
                )
            }),
    }?;

    // Validate include/exclude globs eagerly so bad patterns are caught at startup.
    for (i, p) in profiles.iter().enumerate() {
        for pat in p.include.iter().chain(p.exclude.iter()) {
            glob::Pattern::new(pat).map_err(|e| {
                format!(
                    "profile '{}' entry {i}: invalid glob '{pat}': {e}",
                    path.display()
                )
            })?;
        }
    }

    Ok(profiles)
}

/// Attempt structured processing for a file using the provided profiles.
///
/// Finds the first profile whose extensions match `filename` and runs the
/// corresponding structured processor. Returns `None` when no profile
/// matches, falling through to the streaming scanner.
///
/// When `--profile` is not supplied `profiles` is empty and this always
/// returns `None`, routing every file through the scanner (value-based
/// replacement that preserves all formatting).
fn try_structured_processing(
    content: &[u8],
    filename: &str,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    profiles: &[sanitize_engine::processor::FileTypeProfile],
) -> Option<Result<Vec<u8>, String>> {
    let profile = profiles.iter().find(|p| p.matches_filename(filename))?;
    match registry.process(content, profile, store) {
        Ok(Some(result)) => Some(Ok(result)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// Build a per-file scanner for the format-preserving structured pass.
///
/// Diffs the store against `before_snapshot` to find literals discovered by
/// the most recent structured processor call, compiles each into a
/// `ScanPattern::from_literal`, then extends `base_scanner` with those patterns.
///
/// Values shorter than 4 bytes are skipped to keep false-positive risk low.
fn build_format_preserving_scanner(
    base_scanner: &Arc<StreamScanner>,
    store: &Arc<MappingStore>,
    before_snapshot: &std::collections::HashSet<(sanitize_engine::category::Category, String)>,
) -> Result<StreamScanner, sanitize_engine::error::SanitizeError> {
    let extra: Vec<ScanPattern> = store
        .iter()
        .filter(|(cat, orig, _)| {
            orig.len() >= 4 && !before_snapshot.contains(&(cat.clone(), orig.to_string()))
        })
        .filter_map(|(category, original, _)| {
            let s = original.to_string();
            match ScanPattern::from_literal(&s, category, format!("field:{s}")) {
                Ok(pat) => Some(pat),
                Err(e) => {
                    warn!(value = %s, error = %e, "could not compile field literal pattern");
                    None
                }
            }
        })
        .collect();

    base_scanner.with_extra_literals(extra)
}

/// Fall back to the streaming scanner for raw bytes.
fn scanner_fallback(scanner: &StreamScanner, input: &[u8]) -> Result<(Vec<u8>, ScanStats), String> {
    let (output, stats) = scanner
        .scan_bytes(input)
        .map_err(|e| format!("scanner error: {e}"))?;
    Ok((output, stats))
}

/// A `Write + Seek` sink that discards all bytes.
///
/// Used for dry-run zip processing: `ZipWriter` requires `Seek` to finalize
/// the central directory, so `io::sink()` alone is insufficient.
struct NullSeekWriter {
    pos: u64,
    len: u64,
}

impl io::Write for NullSeekWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        self.pos += n;
        if self.pos > self.len {
            self.len = self.pos;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for NullSeekWriter {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match from {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::Current(n) => {
                if n >= 0 {
                    self.pos.saturating_add(n as u64)
                } else {
                    self.pos.saturating_sub((-n) as u64)
                }
            }
            io::SeekFrom::End(n) => {
                if n >= 0 {
                    self.len.saturating_add(n as u64)
                } else {
                    self.len.saturating_sub((-n) as u64)
                }
            }
        };
        self.pos = new_pos;
        if new_pos > self.len {
            self.len = new_pos;
        }
        Ok(self.pos)
    }
}

/// Process an archive file. Returns `true` if entries were processed.
#[allow(clippy::too_many_arguments)]
fn process_archive(
    input: &Path,
    cli: &Cli,
    output_path: &Path,
    deps: ArchiveDeps<'_>,
    format: ArchiveFormat,
    filter: ArchiveFilter,
    report_builder: Option<&ReportBuilder>,
    progress: Option<&SharedProgressReporter>,
    suppress_inner_parallelism: bool,
) -> Result<bool, String> {
    let label = format!("Processing archive {}", input.display());

    with_progress_scope(progress, &label, |progress| {
        let base_proc = ArchiveProcessor::new(
            Arc::clone(deps.registry),
            Arc::clone(deps.scanner),
            Arc::clone(deps.store),
            deps.profiles.to_vec(),
        )
        .with_max_depth(cli.max_archive_depth)
        .with_force_text(cli.force_text)
        .with_filter(filter);

        // When the outer file-level loop is already running in parallel,
        // suppress per-entry parallelism to avoid oversubscribing the
        // rayon thread pool.
        let base_proc = if suppress_inner_parallelism {
            base_proc.with_parallel_threshold(usize::MAX)
        } else {
            base_proc
        };

        let archive_proc = if let Some(progress) = &progress {
            let label = label.clone();
            let progress = Arc::clone(progress);
            base_proc.with_progress_callback(Arc::new(move |archive_progress: &ArchiveProgress| {
                progress
                    .lock()
                    .unwrap()
                    .update_archive(&label, archive_progress);
            }))
        } else {
            base_proc
        };

        if cli.dry_run {
            let stats = match format {
                ArchiveFormat::Tar => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::TarGz => {
                    let reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    archive_proc
                        .process_tar_gz(reader, io::sink())
                        .map_err(|e| format!("archive error: {e}"))?
                }
                ArchiveFormat::Zip => {
                    let mut reader = BufReader::new(
                        fs::File::open(input)
                            .map_err(|e| format!("failed to open archive: {e}"))?,
                    );
                    let mut null_out = NullSeekWriter { pos: 0, len: 0 };
                    archive_proc
                        .process_zip(&mut reader, &mut null_out)
                        .map_err(|e| format!("archive error: {e}"))?
                }
            };

            if let Some(rb) = report_builder {
                record_archive_stats(rb, &stats);
            }

            info!(
                files = stats.files_processed,
                structured = stats.structured_hits,
                scanner = stats.scanner_fallback,
                "dry-run archive processing complete"
            );

            return Ok(stats.files_processed > 0);
        }

        let stats = match format {
            ArchiveFormat::Tar => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::TarGz => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_tar_gz(reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
            ArchiveFormat::Zip => {
                let mut reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut atomic_writer = AtomicFileWriter::new(output_path)
                    .map_err(|e| format!("failed to create output: {e}"))?;
                let stats = archive_proc
                    .process_zip(&mut reader, &mut atomic_writer)
                    .map_err(|e| format!("archive processing error: {e}"))?;
                if is_interrupted() {
                    return Err("interrupted — partial output discarded".into());
                }
                atomic_writer
                    .finish()
                    .map_err(|e| format!("failed to finalize output: {e}"))?;
                stats
            }
        };

        if let Some(rb) = report_builder {
            record_archive_stats(rb, &stats);
        }
        print_archive_stats(output_path, &stats);

        Ok(stats.files_processed > 0)
    })
}

fn file_size(path: &Path) -> Result<u64, String> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|e| format!("failed to stat {}: {e}", path.display()))
}

/// Convert archive stats into per-entry [`FileReport`]s and record them.
fn record_archive_stats(rb: &ReportBuilder, stats: &sanitize_engine::ArchiveStats) {
    for (path, method) in &stats.file_methods {
        if let Some(scan_stats) = stats.file_scan_stats.get(path) {
            rb.record_file(FileReport::from_scan_stats(
                path.clone(),
                scan_stats,
                method.clone(),
            ));
        } else {
            rb.record_file(FileReport {
                path: path.clone(),
                matches: 0,
                replacements: 0,
                bytes_processed: 0,
                bytes_output: 0,
                pattern_counts: std::collections::HashMap::new(),
                method: method.clone(),
            });
        }
    }

    if stats.file_methods.is_empty() {
        rb.record_file(FileReport {
            path: "(archive)".into(),
            matches: 0,
            replacements: 0,
            bytes_processed: stats.total_input_bytes,
            bytes_output: stats.total_output_bytes,
            pattern_counts: std::collections::HashMap::new(),
            method: format!(
                "archive({} files, {} structured, {} scanner)",
                stats.files_processed, stats.structured_hits, stats.scanner_fallback
            ),
        });
    }
}

fn print_archive_stats(output: &Path, stats: &sanitize_engine::ArchiveStats) {
    info!(
        files = stats.files_processed,
        structured = stats.structured_hits,
        scanner = stats.scanner_fallback,
        output = %output.display(),
        "archive processing complete"
    );
}

/// Write output bytes atomically to the given path, or stdout.
fn write_output(output_path: Option<&Path>, data: &[u8]) -> Result<(), String> {
    match output_path {
        Some(path) => {
            atomic_write(path, data)
                .map_err(|e| format!("failed to write {}: {e}", path.display()))?;
            info!(output = %path.display(), "output written");
        }
        None => {
            let stdout = io::stdout();
            let mut lock = stdout.lock();
            lock.write_all(data)
                .map_err(|e| format!("failed to write to stdout: {e}"))?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encrypt subcommand
// ---------------------------------------------------------------------------

fn run_encrypt(args: &EncryptArgs) -> Result<(), (String, i32)> {
    let validate = args.validate && !args._no_validate;

    // Resolve password.
    let password =
        resolve_password(args.password, &args.password_file, "encryption").map_err(|e| (e, 1))?;

    // Read plaintext file.
    let plaintext = fs::read(&args.input)
        .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?;

    // Determine format.
    let format = args
        .format
        .or_else(|| SecretsFormat::from_extension(args.input.to_string_lossy().as_ref()));

    // Validate (parse) before encrypting.
    if validate {
        eprint!("Validating secrets file... ");
        match parse_secrets(&plaintext, format) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("validation error: {e}"), 1));
            }
        }
    }

    // Encrypt.
    eprint!("Encrypting... ");
    let encrypted = encrypt_secrets(&plaintext, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("encryption failed: {e}"), 1)
    })?;

    // Write output atomically.
    atomic_write(&args.output, &encrypted)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        encrypted.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("To use with the sanitizer:");
    eprintln!(
        "  sanitize data.log -s {} --password",
        args.output.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Decrypt subcommand
// ---------------------------------------------------------------------------

fn run_decrypt(args: &DecryptArgs) -> Result<(), (String, i32)> {
    // Resolve password.
    let password =
        resolve_password(args.password, &args.password_file, "decryption").map_err(|e| (e, 1))?;

    // Read encrypted file.
    let encrypted = fs::read(&args.input)
        .map_err(|e| (format!("cannot read '{}': {e}", args.input.display()), 1))?;

    // Decrypt.
    eprint!("Decrypting... ");
    let plaintext = decrypt_secrets(&encrypted, &password).map_err(|e| {
        eprintln!("FAILED");
        (format!("decryption failed: {e}"), 1)
    })?;

    // Optionally validate the decrypted content.
    if let Some(fmt) = args.format {
        eprint!("Validating... ");
        match parse_secrets(&plaintext, Some(fmt)) {
            Ok(entries) => {
                eprintln!("OK ({} entries)", entries.len());
            }
            Err(e) => {
                eprintln!("FAILED");
                return Err((format!("decrypted content is not valid {:?}: {e}", fmt), 1));
            }
        }
    }

    // Write output atomically.
    atomic_write(&args.output, &plaintext)
        .map_err(|e| (format!("cannot write '{}': {e}", args.output.display()), 1))?;

    eprintln!("done");
    eprintln!(
        "Wrote {} bytes to '{}'",
        plaintext.len(),
        args.output.display()
    );
    eprintln!();
    eprintln!("Remember to re-encrypt after editing:");
    eprintln!(
        "  sanitize encrypt {} {}.enc",
        args.output.display(),
        args.output.display()
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

fn run() -> Result<(), (String, i32)> {
    // Pre-parse --only / --exclude flags that are interleaved with archive
    // paths before handing the cleaned arg list to clap.
    let raw_args: Vec<OsString> = std::env::args_os().skip(1).collect();
    let (raw_filter_map, cleaned_args) = parse_archive_filters(&raw_args).map_err(|e| (e, 1))?;

    // Compile ArchiveFilter objects eagerly so errors are reported before any
    // file I/O starts.
    let filter_map: HashMap<PathBuf, ArchiveFilter> = raw_filter_map
        .into_iter()
        .map(|(path, (only, exclude))| {
            ArchiveFilter::new(only, exclude)
                .map(|f| (path, f))
                .map_err(|e| (e, 1))
        })
        .collect::<Result<HashMap<_, _>, _>>()?;

    let cli = Cli::parse_from(std::iter::once(OsString::from("sanitize")).chain(cleaned_args));

    // --- initialise logging -------------------------------------------------
    init_logging(&cli.log_format);

    // --- dispatch subcommands -----------------------------------------------
    match &cli.command {
        Some(SubCommand::Encrypt(args)) => return run_encrypt(args),
        Some(SubCommand::Decrypt(args)) => return run_decrypt(args),
        Some(SubCommand::Guided) => return run_guided(),
        Some(SubCommand::Template(args)) => return run_template(args),
        None => {} // fall through to default sanitize mode
    }

    run_sanitize(cli, None, filter_map)
}

fn run_sanitize(
    cli: Cli,
    pre_resolved_password: Option<Zeroizing<String>>,
    filter_map: HashMap<PathBuf, ArchiveFilter>,
) -> Result<(), (String, i32)> {
    // --- install signal handler (graceful shutdown) --------------------------
    if let Err(e) = ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {e}");
    }

    // --- validate -----------------------------------------------------------
    validate_args(&cli).map_err(|e| (e, 1))?;

    let progress_mode = cli.effective_progress_mode();
    let progress_context = ProgressContext::detect(&cli.log_format);
    let progress_policy = ProgressPolicy::from_mode(progress_mode, progress_context);
    let progress_reporter = if progress_policy.live_updates || progress_policy.milestone_updates {
        Some(Arc::new(Mutex::new(ProgressReporter::new(
            progress_policy,
            progress_context.json_logs,
            cli.progress_interval_ms,
        ))))
    } else {
        None
    };

    let thread_count = resolve_thread_count(cli.threads);

    // Initialise the global rayon thread pool from the resolved thread count.
    // build_global() is a no-op if called more than once (e.g. in tests).
    let _ = rayon::ThreadPoolBuilder::new()
        .num_threads(thread_count)
        .build_global();

    info!(
        threads = thread_count,
        deterministic = cli.deterministic,
        chunk_size = cli.chunk_size,
        progress_mode = ?progress_mode,
        live_progress = progress_policy.live_updates,
        milestone_progress = progress_policy.milestone_updates,
        progress_interval_ms = cli.progress_interval_ms,
        "starting sanitization"
    );

    let effective_password: Option<Zeroizing<String>> =
        if cli.encrypted_secrets || cli.deterministic {
            if let Some(pw) = pre_resolved_password {
                Some(pw)
            } else {
                Some(resolve_sanitize_password(&cli).map_err(|e| (e, 1))?)
            }
        } else {
            None
        };
    // effective_password is Zeroizing<String> — scrubbed automatically on drop.

    // --- build core components ----------------------------------------------
    let scan_config = build_scan_config(cli.chunk_size).map_err(|e| (e, 1))?;
    let store = build_store(
        cli.deterministic,
        effective_password.as_ref().map(|s| s.as_str()),
        cli.max_mappings,
    )
    .map_err(|e| (e, 1))?;
    let registry = Arc::new(ProcessorRegistry::with_builtins());

    // --- load field-path profiles (--profile) --------------------------------
    let profiles: Vec<sanitize_engine::processor::FileTypeProfile> =
        if let Some(ref profile_path) = cli.profile {
            load_profiles(profile_path).map_err(|e| (e, 1))?
        } else {
            vec![]
        };

    if !profiles.is_empty() {
        info!(count = profiles.len(), "loaded field-path profiles");
    }

    // --- load secrets and build scanner -------------------------------------
    // Keep raw_bytes in scope so Phase 2 can re-parse and build an augmented
    // scanner that includes literals discovered during the profile pass (Phase 1).
    let secrets_raw_bytes: Option<Vec<u8>> = if let Some(ref secrets_path) = cli.secrets_file {
        if secrets_path.exists() {
            Some(fs::read(secrets_path).map_err(|e| {
                (
                    format!(
                        "failed to read secrets file {}: {e}",
                        secrets_path.display()
                    ),
                    1,
                )
            })?)
        } else if cli.deterministic {
            // File doesn't exist yet — will be created after processing.
            None
        } else {
            return Err((
                format!("secrets file not found: {}", secrets_path.display()),
                1,
            ));
        }
    } else {
        None
    };

    let scanner = if let Some(ref raw_bytes) = secrets_raw_bytes {
        let ((patterns, warnings), was_encrypted) = sanitize_engine::secrets::load_secrets_auto(
            raw_bytes,
            effective_password.as_ref().map(|s| s.as_str()),
            None,
            !cli.encrypted_secrets,
        )
        .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;

        let secrets_display = cli
            .secrets_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        if was_encrypted {
            info!(secrets_file = %secrets_display, "loaded encrypted secrets");
        } else {
            info!(secrets_file = %secrets_display, "loaded plaintext secrets (unencrypted)");
        }

        if !warnings.is_empty() {
            for (idx, err) in &warnings {
                warn!(entry = idx, error = %err, "secret entry warning");
            }
            if cli.strict {
                return Err((
                    format!(
                        "{} secret entries had errors (use without --strict to continue)",
                        warnings.len()
                    ),
                    1,
                ));
            }
        }

        let scanner = StreamScanner::new(patterns, Arc::clone(&store), scan_config.clone())
            .map_err(|e| (format!("failed to create scanner: {e}"), 1))?;

        let secrets_display = cli
            .secrets_file
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default();
        info!(
            patterns = scanner.pattern_count(),
            secrets_file = %secrets_display,
            "patterns loaded"
        );
        Arc::new(scanner)
    } else {
        warn!("no --secrets-file provided; only structured processing will apply");
        Arc::new(
            StreamScanner::new(vec![], Arc::clone(&store), scan_config.clone())
                .map_err(|e| (format!("failed to create scanner: {e}"), 1))?,
        )
    };

    // --- build report builder -----------------------------------------------
    let report_enabled = cli.report.is_some();
    let report_builder = if report_enabled {
        let timestamp = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| {
                let secs = d.as_secs();
                let (s, m, h) = (secs % 60, (secs / 60) % 60, (secs / 3600) % 24);
                let days = secs / 86400;
                format!("epoch+{days}d {:02}:{:02}:{:02}Z", h, m, s)
            })
            .unwrap_or_else(|_| "unknown".into());

        Some(ReportBuilder::new(ReportMetadata {
            version: env!("CARGO_PKG_VERSION").into(),
            timestamp,
            deterministic: cli.deterministic,
            dry_run: cli.dry_run,
            strict: cli.strict,
            chunk_size: cli.chunk_size,
            threads: cli.threads,
            secrets_file: cli.secrets_file.as_ref().map(|p| p.display().to_string()),
        }))
    } else {
        None
    };

    let input_targets = plan_input_targets(&cli).map_err(|e| (e, 1))?;

    // --- split stdin (serial) from file targets (parallel) ------------------
    // Stdin must always be processed serially to preserve stream semantics and
    // terminal UX. File targets are processed in parallel via rayon when
    // thread_count > 1 and there is more than one file target.
    let (stdin_targets, file_targets): (Vec<_>, Vec<_>) = input_targets
        .into_iter()
        .partition(|t| matches!(t, InputTarget::Stdin { .. }));

    let mut had_matches = false;

    // Process stdin targets sequentially.
    for target in stdin_targets {
        let InputTarget::Stdin { output } = target else {
            unreachable!()
        };
        let result = process_stdin(
            &cli,
            output.as_deref(),
            &scanner,
            &registry,
            &store,
            &profiles,
            report_builder.as_ref(),
            progress_reporter.as_ref(),
        )
        .map_err(|e| (e, 1))?;
        had_matches |= result;
    }

    // --- two-phase file processing ------------------------------------------
    //
    // Phase 1: process profile-matched plain files serially so that every
    //   value replaced via field-path rules is recorded in `store`.
    //
    // Phase 2: build an augmented scanner that includes those discovered
    //   literals (on top of any secrets-file patterns), then process all
    //   remaining files (archives + non-profile plain files) with it.
    //   Archives are always Phase 2 because we can't pre-partition their
    //   entries before reading them.
    let (phase1_targets, phase2_targets): (Vec<_>, Vec<_>) = if profiles.is_empty() {
        // No profiles → skip Phase 1 entirely.
        (vec![], file_targets)
    } else {
        file_targets.into_iter().partition(|t| {
            let InputTarget::File { ref input, .. } = t else {
                return false;
            };
            let name = input.to_string_lossy();
            ArchiveFormat::from_path(&name).is_none()
                && profiles.iter().any(|p| p.matches_filename(&name))
        })
    };

    // Phase 1 — serial, profile-matched plain files.
    for target in phase1_targets {
        if is_interrupted() {
            break;
        }
        let InputTarget::File { input, output } = target else {
            unreachable!()
        };
        let result = process_plain_file(
            &input,
            &cli,
            Some(output.as_path()),
            &scanner,
            &registry,
            &store,
            &profiles,
            report_builder.as_ref(),
            progress_reporter.as_ref(),
        )
        .map_err(|e| (e, 1))?;
        had_matches |= result;
    }

    // Archive discovery pre-pass: for any archive in Phase 2 that has
    // profile-matched entries, run the structured processor on those entries
    // (discarding output) so their replaced values are recorded in the store.
    // This is a second read of the archive file — correctness over speed.
    if !profiles.is_empty() {
        let discovery = ArchiveProcessor::new(
            Arc::clone(&registry),
            Arc::clone(&scanner), // scanner unused in discovery — just satisfies the API
            Arc::clone(&store),
            profiles.to_vec(),
        );
        for target in &phase2_targets {
            if is_interrupted() {
                break;
            }
            let InputTarget::File { ref input, .. } = target else {
                continue;
            };
            let input_str = input.to_string_lossy();
            let Some(fmt) = ArchiveFormat::from_path(&input_str) else {
                continue;
            };
            let file = fs::File::open(input).map_err(|e| {
                (
                    format!(
                        "failed to open {} for profile discovery: {e}",
                        input.display()
                    ),
                    1,
                )
            })?;
            match fmt {
                ArchiveFormat::Tar => discovery.discover_profiles_tar(file),
                ArchiveFormat::TarGz => discovery.discover_profiles_tar_gz(file),
                ArchiveFormat::Zip => discovery.discover_profiles_zip(file),
            }
            .map_err(|e| {
                (
                    format!("profile discovery failed for {}: {e}", input.display()),
                    1,
                )
            })?;
        }
    }

    // Build augmented scanner: base secrets patterns + literals discovered in
    // Phase 1 (plain files) and the archive discovery pre-pass above.
    let augmented_scanner = build_augmented_scanner(
        secrets_raw_bytes.as_deref(),
        effective_password.as_ref().map(|s| s.as_str()),
        !cli.encrypted_secrets,
        &store,
        scan_config,
    )?;

    // Phase 2 — parallel when multiple targets, serial otherwise.
    // Each worker gets Arc clones — all inner state is Send + Sync.
    // Results are collected and folded after all workers finish.
    let file_results: Vec<Result<bool, (String, i32)>> = if phase2_targets.len() > 1 {
        phase2_targets
            .into_par_iter()
            .map(|target| {
                if is_interrupted() {
                    return Ok(false);
                }
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    process_archive(
                        &input,
                        &cli,
                        &output,
                        ArchiveDeps {
                            scanner: &augmented_scanner,
                            registry: &registry,
                            store: &store,
                            profiles: &profiles,
                        },
                        fmt,
                        filter,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        // suppress per-entry parallelism: file-level parallelism
                        // is already consuming the thread budget.
                        true,
                    )
                    .map_err(|e| (e, 1))
                } else {
                    process_plain_file(
                        &input,
                        &cli,
                        Some(output.as_path()),
                        &augmented_scanner,
                        &registry,
                        &store,
                        &profiles,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                    )
                    .map_err(|e| (e, 1))
                }
            })
            .collect()
    } else {
        // Single Phase 2 target — run on the current thread (no rayon overhead).
        phase2_targets
            .into_iter()
            .map(|target| {
                let InputTarget::File { input, output } = target else {
                    unreachable!()
                };
                let input_str = input.to_string_lossy();
                if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
                    let filter = filter_map.get(&input).cloned().unwrap_or_default();
                    process_archive(
                        &input,
                        &cli,
                        &output,
                        ArchiveDeps {
                            scanner: &augmented_scanner,
                            registry: &registry,
                            store: &store,
                            profiles: &profiles,
                        },
                        fmt,
                        filter,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                        // single file target: archive entry parallelism is enabled.
                        false,
                    )
                    .map_err(|e| (e, 1))
                } else {
                    process_plain_file(
                        &input,
                        &cli,
                        Some(output.as_path()),
                        &augmented_scanner,
                        &registry,
                        &store,
                        &profiles,
                        report_builder.as_ref(),
                        progress_reporter.as_ref(),
                    )
                    .map_err(|e| (e, 1))
                }
            })
            .collect()
    };

    // Return the first error encountered (if any), then fold had_matches.
    for result in file_results {
        had_matches |= result?;
    }

    // --- check for interruption ---------------------------------------------
    if is_interrupted() {
        return Err(("interrupted by signal".into(), 130));
    }

    // --- persist discovered secrets (deterministic mode + profile) ----------
    // When running deterministically with a profile, save the literal values
    // found by structured scanning so future runs' scanner can match them.
    if cli.deterministic && !profiles.is_empty() {
        let save_path = cli
            .secrets_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("sanitize-discovered.yaml"));
        match save_discovered_secrets(&store, &save_path) {
            Ok(0) => {}
            Ok(n) => info!(
                path = %save_path.display(),
                added = n,
                "saved discovered literals to secrets file"
            ),
            Err(e) => warn!("could not save discovered secrets: {e}"),
        }
    }

    // --- write report -------------------------------------------------------
    if let Some(builder) = report_builder {
        let report = builder.finish();
        let json = report
            .to_json_pretty()
            .map_err(|e| (format!("failed to serialize report: {e}"), 1))?;

        match cli.report.as_ref().unwrap() {
            Some(path) if path.to_string_lossy() == "-" => {
                println!("{json}");
            }
            Some(path) => {
                atomic_write(path, json.as_bytes()).map_err(|e| {
                    (
                        format!("failed to write report to {}: {e}", path.display()),
                        1,
                    )
                })?;
                info!(report = %path.display(), "report written");
            }
            None => {
                eprintln!("{json}");
            }
        }
    }

    // --- Performance summary (bench feature) --------------------------------
    #[cfg(feature = "bench")]
    {
        let mappings = store.len();
        info!(unique_mappings = mappings, "performance summary");
    }

    // --- --fail-on-match ----------------------------------------------------
    if cli.fail_on_match && had_matches {
        return Err(("matches found (--fail-on-match)".into(), 2));
    }

    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err((msg, code)) => {
            eprintln!("error: {msg}");
            process::exit(code);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;
    use tempfile::tempdir;

    fn make_progress_context(
        stderr_is_terminal: bool,
        is_ci: bool,
        term_is_dumb: bool,
        json_logs: bool,
    ) -> ProgressContext {
        ProgressContext {
            stderr_is_terminal,
            is_ci,
            term_is_dumb,
            json_logs,
        }
    }

    /// Verify clap derive builds without panicking on debug assertions.
    #[test]
    fn cli_debug_assert_does_not_panic() {
        // clap runs internal validation on first parse attempt.
        // This catches issues like invalid required_unless_present references.
        let _ = Cli::try_parse_from(["sanitize", "input.txt"]);
    }

    #[test]
    fn cli_parses_basic_input() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_input_with_output() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "-o", "output.txt"]).unwrap();
        assert_eq!(cli.input, vec![PathBuf::from("input.txt")]);
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.txt"));
    }

    #[test]
    fn cli_parses_multiple_inputs() {
        let cli = Cli::try_parse_from(["sanitize", "test.txt", "a.json", "b.zip"]).unwrap();
        assert_eq!(
            cli.input,
            vec![
                PathBuf::from("test.txt"),
                PathBuf::from("a.json"),
                PathBuf::from("b.zip")
            ]
        );
    }

    #[test]
    fn cli_parses_output_long_flag() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--output", "out.txt"]).unwrap();
        assert_eq!(cli.output.unwrap(), PathBuf::from("out.txt"));
    }

    #[test]
    fn cli_parses_secrets_file_flag() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--secrets-file", "secrets.json"])
            .unwrap();
        assert_eq!(cli.secrets_file.unwrap(), PathBuf::from("secrets.json"));
    }

    #[test]
    fn cli_parses_short_flags() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "input.txt",
            "-s",
            "secrets.json",
            "-p",
            "-P",
            "/run/secrets/pw",
            "-o",
            "out.txt",
            "-n",
            "-d",
            "-f",
            "json",
        ])
        .unwrap();
        assert_eq!(cli.secrets_file.unwrap(), PathBuf::from("secrets.json"));
        assert!(cli.password);
        assert_eq!(cli.password_file.unwrap(), PathBuf::from("/run/secrets/pw"));
        assert_eq!(cli.output.unwrap(), PathBuf::from("out.txt"));
        assert!(cli.dry_run);
        assert!(cli.deterministic);
        assert_eq!(cli.format.unwrap(), "json");
    }

    #[test]
    fn cli_parses_dry_run() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--dry-run"]).unwrap();
        assert!(cli.dry_run);
    }

    #[test]
    fn cli_parses_progress_mode() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--progress", "on"]).unwrap();
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_no_progress_maps_to_off() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--no-progress"]).unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.effective_progress_mode(), ProgressMode::Off);
    }

    #[test]
    fn cli_explicit_progress_takes_precedence_over_no_progress() {
        let cli =
            Cli::try_parse_from(["sanitize", "input.txt", "--no-progress", "--progress", "on"])
                .unwrap();
        assert!(cli.no_progress);
        assert_eq!(cli.progress, Some(ProgressMode::On));
        assert_eq!(cli.effective_progress_mode(), ProgressMode::On);
    }

    #[test]
    fn cli_parses_progress_interval() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "--progress-interval-ms", "500"])
            .unwrap();
        assert_eq!(cli.progress_interval_ms, 500);
    }

    #[test]
    fn validate_args_rejects_zero_progress_interval() {
        let mut cli = Cli::try_parse_from(["sanitize", "input.txt"]).unwrap();
        cli.input = vec![std::env::current_dir().unwrap().join("Cargo.toml")];
        cli.progress_interval_ms = 0;
        let err = validate_args(&cli).unwrap_err();
        assert!(err.contains("--progress-interval-ms must be greater than 0"));
    }

    #[test]
    fn progress_policy_auto_disables_live_updates_for_json_logs() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, false, false, true),
        );
        assert!(!policy.live_updates);
        assert!(!policy.milestone_updates);
    }

    #[test]
    fn progress_policy_auto_disables_live_updates_in_ci() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, true, false, false),
        );
        assert!(!policy.live_updates);
        assert!(!policy.milestone_updates);
    }

    #[test]
    fn progress_policy_on_keeps_milestones_when_live_updates_are_unavailable() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::On,
            make_progress_context(false, false, false, false),
        );
        assert!(!policy.live_updates);
        assert!(policy.milestone_updates);
    }

    #[test]
    fn progress_policy_auto_enables_live_updates_in_interactive_human_mode() {
        let policy = ProgressPolicy::from_mode(
            ProgressMode::Auto,
            make_progress_context(true, false, false, false),
        );
        assert!(policy.live_updates);
        assert!(policy.milestone_updates);
    }

    #[test]
    fn cli_parses_encrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "encrypt",
            "secrets.json",
            "secrets.enc",
            "--password",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_parses_decrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "decrypt",
            "secrets.enc",
            "secrets.json",
            "--password",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_parses_guided_subcommand() {
        let cli = Cli::try_parse_from(["sanitize", "guided"]).unwrap();
        assert!(matches!(cli.command, Some(SubCommand::Guided)));
        assert!(cli.input.is_empty());
    }

    #[test]
    fn cli_no_input_no_subcommand_is_ok_at_parse_time() {
        // Clap allows it (input is Vec); we validate manually in run().
        let cli = Cli::try_parse_from(["sanitize", "--dry-run"]).unwrap();
        assert!(cli.input.is_empty());
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "input.log",
            "--output",
            "output.log",
            "--secrets-file",
            "s.enc",
            "--password",
            "--dry-run",
            "--fail-on-match",
            "--deterministic",
            "--strict",
            "--include-binary",
            "--encrypted-secrets",
            "--chunk-size",
            "4096",
            "--threads",
            "4",
            "--max-mappings",
            "500",
            "--log-format",
            "json",
            "--format",
            "yaml",
        ])
        .unwrap();
        assert!(cli.dry_run);
        assert!(cli.fail_on_match);
        assert!(cli.deterministic);
        assert!(cli.strict);
        assert!(cli.include_binary);
        assert!(cli.encrypted_secrets);
        assert_eq!(cli.chunk_size, 4096);
        assert_eq!(cli.threads, Some(4));
        assert_eq!(cli.max_mappings, 500);
        assert_eq!(cli.format.unwrap(), "yaml");
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.log"));
    }

    #[test]
    fn cli_stdin_dash_input() {
        let cli = Cli::try_parse_from(["sanitize", "-", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_stdin_no_input() {
        let cli = Cli::try_parse_from(["sanitize", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_input_not_stdin() {
        let cli = Cli::try_parse_from(["sanitize", "data.log"]).unwrap();
        assert!(!has_stdin_input(&cli));
    }

    #[test]
    fn cli_file_and_stdin_mix_is_supported() {
        let cli = Cli::try_parse_from(["sanitize", "test.txt", "-", "-s", "s.json"]).unwrap();
        assert!(has_stdin_input(&cli));
        assert_eq!(file_inputs(&cli).len(), 1);
    }

    #[test]
    fn format_to_ext_mapping() {
        assert_eq!(format_to_ext("json"), Some("json"));
        assert_eq!(format_to_ext("yaml"), Some("yaml"));
        assert_eq!(format_to_ext("xml"), Some("xml"));
        assert_eq!(format_to_ext("csv"), Some("csv"));
        assert_eq!(format_to_ext("key-value"), Some("conf"));
        assert_eq!(format_to_ext("text"), None);
        assert_eq!(format_to_ext("unknown"), None);
    }

    #[test]
    fn plan_multi_input_outputs_preserve_types() {
        let tmp = tempdir().unwrap();
        let input_dir = tmp.path().join("in");
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&input_dir).unwrap();

        let txt = input_dir.join("test.txt");
        let json = input_dir.join("a.json");
        let zip = input_dir.join("b.zip");
        fs::write(&txt, "x").unwrap();
        fs::write(&json, "{}\n").unwrap();
        fs::write(&zip, "PK\x03\x04").unwrap();

        let cli = Cli::try_parse_from([
            "sanitize",
            txt.to_str().unwrap(),
            json.to_str().unwrap(),
            zip.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .unwrap();

        let targets = plan_input_targets(&cli).unwrap();
        let mut outputs = targets
            .into_iter()
            .filter_map(|t| match t {
                InputTarget::File { output, .. } => {
                    Some(output.file_name().unwrap().to_string_lossy().to_string())
                }
                InputTarget::Stdin { .. } => None,
            })
            .collect::<Vec<_>>();
        outputs.sort();

        assert_eq!(
            outputs,
            vec![
                "a-sanitized.json".to_string(),
                "b.sanitized.zip".to_string(),
                "test-sanitized.txt".to_string(),
            ]
        );
    }

    #[test]
    fn plan_multi_input_collision_adds_numeric_suffix() {
        let tmp = tempdir().unwrap();
        let dir1 = tmp.path().join("dir1");
        let dir2 = tmp.path().join("dir2");
        let out_dir = tmp.path().join("out");
        fs::create_dir_all(&dir1).unwrap();
        fs::create_dir_all(&dir2).unwrap();

        let f1 = dir1.join("same.txt");
        let f2 = dir2.join("same.txt");
        fs::write(&f1, "x").unwrap();
        fs::write(&f2, "y").unwrap();

        let cli = Cli::try_parse_from([
            "sanitize",
            f1.to_str().unwrap(),
            f2.to_str().unwrap(),
            "--output",
            out_dir.to_str().unwrap(),
        ])
        .unwrap();

        let targets = plan_input_targets(&cli).unwrap();
        let outputs = targets
            .into_iter()
            .filter_map(|t| match t {
                InputTarget::File { output, .. } => {
                    Some(output.file_name().unwrap().to_string_lossy().to_string())
                }
                InputTarget::Stdin { .. } => None,
            })
            .collect::<Vec<_>>();

        assert!(outputs.contains(&"same-sanitized.txt".to_string()));
        assert!(outputs.contains(&"same-sanitized-1.txt".to_string()));
    }

    #[test]
    fn guided_entries_compile_balanced() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Balanced,
            domains: vec!["corp.internal".into()],
            providers: vec![CloudProvider::Aws],
            exclude_noise_ids: true,
        };

        let entries = build_guided_entries(&opts);
        let (_patterns, warnings) = entries_to_patterns(&entries);
        assert!(warnings.is_empty());
    }

    #[test]
    fn guided_entries_include_gcp_custom_when_selected() {
        let opts = GuidedOptions {
            preset: GuidedPreset::Aggressive,
            domains: vec![],
            providers: vec![CloudProvider::Gcp],
            exclude_noise_ids: false,
        };

        let entries = build_guided_entries(&opts);
        assert!(entries
            .iter()
            .any(|e| e.category == "custom:gcp_service_account"));
        assert!(entries.iter().any(|e| e.category == "custom:gcp_resource"));
    }
}
