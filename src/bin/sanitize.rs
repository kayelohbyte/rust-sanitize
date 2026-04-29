//! CLI entry-point for the sanitization engine.
//!
//! # Usage
//!
//! ```text
//! sanitize [OPTIONS] [INPUT]
//! sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
//! sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
//!
//! # Read from stdin:
//! cat data.log | sanitize -s secrets.enc -p hunter2
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
//! sanitize encrypt secrets.json secrets.json.enc --password "my-password"
//!
//! # Decrypt it back (for editing):
//! sanitize decrypt secrets.json.enc secrets.json --password "my-password"
//!
//! # Sanitize a log file:
//! sanitize data.log -s secrets.enc -p hunter2
//!
//! # Use a plaintext secrets file directly (auto-detected):
//! sanitize data.log -s secrets.json
//!
//! # Write output to a file:
//! sanitize data.log -s secrets.enc -p hunter2 -o clean.log
//!
//! # Read from stdin (pipe-friendly):
//! grep "error" log.txt | sanitize -s secrets.enc -p hunter2
//! cat data.csv | sanitize -s secrets.enc -p pw -f csv -o clean.csv
//!
//! # Deterministic mode:
//! sanitize data.csv -s s.enc -p pw -d
//!
//! # Read password from a file (avoids process listing / env exposure):
//! sanitize data.log -s s.enc -P /run/secrets/pw
//!
//! # Dry-run:
//! sanitize config.yaml -s s.enc -p pw -n
//!
//! # Fail CI if matches found:
//! sanitize config.yaml -s s.enc -p pw --fail-on-match
//! ```
//!
//! # One-Way Replacements
//!
//! All replacements are **one-way**. No mapping file is stored and there
//! is no restore mode. Re-running with the `--deterministic` flag and the
//! same secrets will produce identical replacements.

use clap::{Parser, Subcommand};
use sanitize_engine::secrets::{decrypt_secrets, encrypt_secrets, parse_secrets, SecretsFormat};
use sanitize_engine::{
    atomic_write, ArchiveFormat, ArchiveProcessor, AtomicFileWriter, FileReport, HmacGenerator,
    MappingStore, ProcessorRegistry, RandomGenerator, ReplacementGenerator, ReportBuilder,
    ReportMetadata, ScanConfig, ScanStats, StreamScanner, DEFAULT_MAX_ARCHIVE_DEPTH,
};
use std::fs;
use std::io::{self, BufReader, BufWriter, Cursor, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tracing::{info, warn};
use zeroize::Zeroize;

/// Maximum size (in bytes) for a structured file to be fully loaded into
/// memory for format-aware processing (F-03 fix). Files exceeding this
/// limit fall back to the streaming scanner which operates in bounded
/// memory. Configurable via `--max-structured-size`.
const DEFAULT_MAX_STRUCTURED_FILE_SIZE: u64 = 256 * 1024 * 1024; // 256 MiB

/// Global flag set by the SIGINT/SIGTERM handler.
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

/// Check whether a graceful shutdown has been requested.
fn is_interrupted() -> bool {
    INTERRUPTED.load(Ordering::Relaxed)
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
        Scans files and archives for sensitive data described in an encrypted \
        secrets file and replaces every match with a category-aware substitute.\n\
        Replacements are ONE-WAY — no mapping file is stored and there is no \
        restore mode.\n\n\
        Use `sanitize encrypt` / `sanitize decrypt` to manage encrypted secrets files.",
    after_help = "\
EXAMPLES:\n  \
  # Sanitize a log file, writing to stdout:\n  \
  sanitize data.log -s secrets.enc -p hunter2\n\n  \
  # Write sanitized output to a file:\n  \
  sanitize data.log -s secrets.enc -p hunter2 -o clean.log\n\n  \
  # Read from stdin (pipe-friendly):\n  \
  grep \"error\" log.txt | sanitize -s secrets.enc -p hunter2\n  \
  cat data.csv | sanitize -s secrets.enc -p pw -f csv -o clean.csv\n\n  \
  # Use a plaintext secrets file (auto-detected):\n  \
  sanitize data.log -s secrets.json\n\n  \
  # Encrypt / decrypt secrets files:\n  \
  sanitize encrypt secrets.json secrets.json.enc --password hunter2\n  \
  sanitize decrypt secrets.json.enc secrets.json --password hunter2\n\n  \
  # Deterministic replacements (reproducible across runs):\n  \
  sanitize data.csv -s s.enc -p pw -d\n\n  \
  # Read password from a file (avoids env / process listing exposure):\n  \
  sanitize data.log -s s.enc -P /run/secrets/pw"
)]
struct Cli {
    /// Subcommand: encrypt, decrypt, or omit for default sanitize mode.
    #[command(subcommand)]
    command: Option<SubCommand>,

    /// Path to the file or archive to sanitize. When omitted or set
    /// to "-", reads from stdin (plain text only; archives require a
    /// file path).
    #[arg(value_name = "INPUT")]
    input: Option<PathBuf>,

    /// Output path. Defaults to stdout for plain files and to
    /// `<input>.sanitized.<ext>` for archives.
    #[arg(short = 'o', long, value_name = "FILE")]
    output: Option<PathBuf>,

    /// Path to a secrets file. By default expects an AES-256-GCM
    /// encrypted file (.enc). Use `--unencrypted-secrets` to load a
    /// plaintext JSON / YAML / TOML file directly, or omit the flag
    /// to auto-detect.
    #[arg(short = 's', long = "secrets-file", value_name = "FILE")]
    secrets_file: Option<PathBuf>,

    /// Password for decrypting the secrets file. Falls back to
    /// --password-file, then SANITIZE_PASSWORD env var, then interactive
    /// prompt. Not required for plaintext secrets.
    #[arg(short = 'p', long)]
    password: Option<String>,

    /// Read the password from a file. The file must have permissions
    /// 0600 or 0400 (owner-only). Trailing newline is stripped.
    #[arg(short = 'P', long = "password-file", value_name = "FILE")]
    password_file: Option<PathBuf>,

    /// Treat the secrets file as plaintext (JSON / YAML / TOML) instead
    /// of expecting AES-256-GCM encryption. Skips decryption and password
    /// prompts entirely. When omitted, the engine auto-detects whether
    /// the file is encrypted or plaintext.
    #[arg(long)]
    unencrypted_secrets: bool,

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

    /// Number of worker threads (currently advisory; reserved for
    /// future parallel archive entry processing). Capped to the
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
}

#[derive(Parser, Debug)]
struct EncryptArgs {
    /// Path to plaintext secrets file (.json, .yaml, .yml, .toml).
    #[arg(value_name = "INPUT")]
    input: PathBuf,

    /// Path for encrypted output file (.enc).
    #[arg(value_name = "OUTPUT")]
    output: PathBuf,

    /// Encryption password. Falls back to --password-file, then
    /// SANITIZE_PASSWORD env var, then interactive prompt.
    #[arg(long)]
    password: Option<String>,

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

    /// Decryption password. Falls back to --password-file, then
    /// SANITIZE_PASSWORD env var, then interactive prompt.
    #[arg(long)]
    password: Option<String>,

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
    cli_password: &Option<String>,
    cli_password_file: &Option<PathBuf>,
    interactive_label: &str,
) -> Result<String, String> {
    // 1. Explicit --password flag.
    if let Some(pw) = cli_password {
        if pw.is_empty() {
            return Err("--password must not be empty".into());
        }
        eprintln!(
            "warning: --password was provided on the command line. \
             Prefer --password-file, the SANITIZE_PASSWORD environment variable, \
             or the interactive prompt to avoid exposing the password in \
             process listings and shell history."
        );
        return Ok(pw.clone());
    }

    // 2. --password-file.
    if let Some(path) = cli_password_file {
        return read_password_file(path);
    }

    // 3. SANITIZE_PASSWORD env var.
    if let Ok(pw) = std::env::var("SANITIZE_PASSWORD") {
        if !pw.is_empty() {
            eprintln!("info: using password from SANITIZE_PASSWORD environment variable");
            return Ok(pw);
        }
    }

    // 4. Interactive prompt.
    prompt_password(interactive_label)
}

/// Read a password from a file, enforcing strict Unix permissions.
#[cfg(unix)]
fn read_password_file(path: &Path) -> Result<String, String> {
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
fn read_password_file(path: &Path) -> Result<String, String> {
    eprintln!(
        "warning: password-file permission checks are only available on Unix. \
         Ensure {} is not world-readable.",
        path.display(),
    );
    read_password_file_contents(path)
}

/// Shared helper: read and trim password file contents.
fn read_password_file_contents(path: &Path) -> Result<String, String> {
    let mut contents = fs::read_to_string(path)
        .map_err(|e| format!("cannot read password file {}: {e}", path.display()))?;

    // Trim a single trailing newline (common in files created by echo/printf).
    if contents.ends_with('\n') {
        contents.pop();
        if contents.ends_with('\r') {
            contents.pop();
        }
    }

    if contents.is_empty() {
        contents.zeroize();
        return Err(format!("password file {} is empty", path.display()));
    }

    Ok(contents)
}

/// Prompt for a password on stderr with hidden input.
fn prompt_password(label: &str) -> Result<String, String> {
    let pw = rpassword::prompt_password(format!("Enter {label} password: "))
        .map_err(|e| format!("failed to read password: {e}"))?;

    if pw.is_empty() {
        return Err("password must not be empty".into());
    }
    Ok(pw)
}

/// Resolve password for the default sanitize mode.
fn resolve_sanitize_password(cli: &Cli) -> Result<String, String> {
    resolve_password(&cli.password, &cli.password_file, "secrets decryption")
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
    password: &Option<String>,
    max_mappings: usize,
) -> std::result::Result<Arc<MappingStore>, String> {
    let generator: Arc<dyn ReplacementGenerator> = if deterministic {
        let seed = match password {
            Some(ref k) => {
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

/// Build a `ScanConfig`, validating `chunk_size`.
fn build_scan_config(chunk_size: usize) -> Result<ScanConfig, String> {
    if chunk_size == 0 {
        return Err("--chunk-size must be greater than 0".into());
    }
    let overlap = chunk_size.clamp(256, 4096);
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
fn is_stdin_input(cli: &Cli) -> bool {
    match &cli.input {
        None => true,
        Some(p) => p.as_os_str() == "-",
    }
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
        _ => None,
    }
}

/// Validate CLI arguments for the default sanitize mode.
fn validate_args(cli: &Cli) -> Result<(), String> {
    if is_stdin_input(cli) {
        // stdin mode — check for incompatible options
        if io::stdin().is_terminal() {
            return Err("no input file given and stdin is a terminal.\n\
                 Provide a file path or pipe data into sanitize.\n\n\
                 Usage: sanitize [OPTIONS] [INPUT]\n       \
                 command | sanitize -s secrets.enc -p password"
                .into());
        }
    } else {
        let input = cli.input.as_ref().unwrap();
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
        if !sf.exists() {
            return Err(format!("secrets file not found: {}", sf.display()));
        }
        if !sf.is_file() {
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
// Processing
// ---------------------------------------------------------------------------

/// Process input from stdin. Returns `true` if matches were found.
fn process_stdin(
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    report_builder: Option<&ReportBuilder>,
) -> Result<bool, String> {
    // Determine whether structured processing should be attempted.
    let structured_ext = cli.format.as_deref().and_then(format_to_ext);

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
            return process_stdin_streaming(reader, cli, scanner, report_builder);
        }

        let store_len_before = store.len();
        let structured_result =
            try_structured_processing(&input_bytes, &format!("stdin.{ext}"), registry, store);

        match structured_result {
            Some(Ok(output_bytes)) => {
                let method = format!("structured:{ext}");
                let replacements = store.len().saturating_sub(store_len_before) as u64;
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
                        "<stdin>".to_string(),
                        &stats,
                        method,
                    ));
                }
                if !cli.dry_run {
                    write_output(cli, &output_bytes)?;
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

        // Structured processing not applicable or failed — scan the buffered bytes.
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
            write_output(cli, &output_bytes)?;
        }
        return Ok(had_matches);
    }

    // Plain text streaming from stdin.
    let reader = BufReader::new(io::stdin().lock());
    process_stdin_streaming(reader, cli, scanner, report_builder)
}

/// Stream stdin through the scanner, writing to output (stdout or file).
fn process_stdin_streaming<R: io::Read>(
    reader: BufReader<R>,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    report_builder: Option<&ReportBuilder>,
) -> Result<bool, String> {
    let mut had_matches = false;

    if cli.dry_run {
        let stats = scanner
            .scan_reader(reader, io::sink())
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

    if let Some(ref out_path) = cli.output {
        let mut atomic_writer =
            AtomicFileWriter::new(out_path).map_err(|e| format!("failed to create output: {e}"))?;

        let stats = scanner
            .scan_reader(reader, &mut atomic_writer)
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
        // stdout
        let stdout = io::stdout();
        let writer = BufWriter::new(stdout.lock());
        let stats = scanner
            .scan_reader(reader, writer)
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
}

/// Process a plain (non-archive) file. Returns `true` if matches were found.
fn process_plain_file(
    input: &Path,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    report_builder: Option<&ReportBuilder>,
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
        info!(file = %input.display(), "skipping binary file (use --include-binary to override)");
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
    );

    let mut had_matches = false;

    // --- Structured path ---
    if structured_ext {
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

            let structured_result =
                try_structured_processing(&input_bytes, &filename, registry, store);

            let (output_bytes, method, was_structured, fallback_stats) = match structured_result {
                Some(Ok(bytes)) => {
                    let ext = filename.rsplit('.').next().unwrap_or("unknown");
                    (bytes, format!("structured:{ext}"), true, None)
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
                // For structured processing, derive stats from the store
                // delta to avoid a redundant full re-scan.
                let replacements = if was_structured {
                    store.len().saturating_sub(store_len_before) as u64
                } else {
                    // Reuse stats from the scanner fallback pass.
                    fallback_stats
                        .as_ref()
                        .map_or(0, |s| s.replacements_applied)
                };

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
            write_output(cli, &output_bytes)?;
            return Ok(had_matches);
        }
    }

    // --- Streaming path ---
    let method = "scanner";

    if cli.dry_run {
        let reader = BufReader::new(
            fs::File::open(input)
                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
        );
        let stats = scanner
            .scan_reader(reader, io::sink())
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
        return Ok(had_matches);
    }

    // Real streaming output.
    if let Some(ref out_path) = cli.output {
        let reader = BufReader::new(
            fs::File::open(input)
                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
        );
        // Atomic output: write to temp, then rename.
        let mut atomic_writer =
            AtomicFileWriter::new(out_path).map_err(|e| format!("failed to create output: {e}"))?;

        let stats = scanner
            .scan_reader(reader, &mut atomic_writer)
            .map_err(|e| format!("scanner error: {e}"))?;

        if is_interrupted() {
            // Drop will clean up temp file.
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
    } else {
        // stdout
        let reader = BufReader::new(
            fs::File::open(input)
                .map_err(|e| format!("failed to open {}: {e}", input.display()))?,
        );
        let stdout = io::stdout();
        let writer = BufWriter::new(stdout.lock());
        let stats = scanner
            .scan_reader(reader, writer)
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
    }

    Ok(had_matches)
}

/// Attempt structured processing for a file based on its extension.
fn try_structured_processing(
    content: &[u8],
    filename: &str,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
) -> Option<Result<Vec<u8>, String>> {
    use sanitize_engine::processor::profile::FileTypeProfile;
    use sanitize_engine::processor::FieldRule;

    let ext = filename.rsplit('.').next().unwrap_or("");
    let processor_name = match ext {
        "json" => "json",
        "yaml" | "yml" => "yaml",
        "xml" => "xml",
        "csv" | "tsv" => "csv",
        "rb" | "conf" | "cfg" | "ini" | "env" | "properties" => "key_value",
        _ => return None,
    };

    let profile =
        FileTypeProfile::new(processor_name, vec![FieldRule::new("*")]).with_extension(ext);

    match registry.process(content, &profile, store) {
        Ok(Some(result)) => Some(Ok(result)),
        Ok(None) => None,
        Err(e) => Some(Err(e.to_string())),
    }
}

/// Fall back to the streaming scanner for raw bytes.
fn scanner_fallback(
    scanner: &Arc<StreamScanner>,
    input: &[u8],
) -> Result<(Vec<u8>, ScanStats), String> {
    let (output, stats) = scanner
        .scan_bytes(input)
        .map_err(|e| format!("scanner error: {e}"))?;
    Ok((output, stats))
}

/// Process an archive file. Returns `true` if entries were processed.
fn process_archive(
    input: &Path,
    cli: &Cli,
    scanner: &Arc<StreamScanner>,
    registry: &Arc<ProcessorRegistry>,
    store: &Arc<MappingStore>,
    format: ArchiveFormat,
    report_builder: Option<&ReportBuilder>,
) -> Result<bool, String> {
    let output_path = cli
        .output
        .clone()
        .unwrap_or_else(|| default_archive_output(input, format));

    let mut had_matches = false;

    if cli.dry_run {
        let archive_proc = ArchiveProcessor::new(
            Arc::clone(registry),
            Arc::clone(scanner),
            Arc::clone(store),
            vec![],
        )
        .with_max_depth(cli.max_archive_depth);

        let stats = match format {
            ArchiveFormat::Tar => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut sink = Vec::new();
                archive_proc
                    .process_tar(reader, &mut sink)
                    .map_err(|e| format!("archive error: {e}"))?
            }
            ArchiveFormat::TarGz => {
                let reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut sink = Vec::new();
                archive_proc
                    .process_tar_gz(reader, &mut sink)
                    .map_err(|e| format!("archive error: {e}"))?
            }
            ArchiveFormat::Zip => {
                let mut reader = BufReader::new(
                    fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
                );
                let mut cursor_out = Cursor::new(Vec::new());
                archive_proc
                    .process_zip(&mut reader, &mut cursor_out)
                    .map_err(|e| format!("archive error: {e}"))?
            }
        };

        if stats.files_processed > 0 {
            had_matches = true;
        }

        info!(
            files = stats.files_processed,
            structured = stats.structured_hits,
            scanner = stats.scanner_fallback,
            "dry-run archive processing complete"
        );

        if let Some(rb) = report_builder {
            record_archive_stats(rb, &stats);
        }
        return Ok(had_matches);
    }

    // Real processing.
    let archive_proc = ArchiveProcessor::new(
        Arc::clone(registry),
        Arc::clone(scanner),
        Arc::clone(store),
        vec![],
    )
    .with_max_depth(cli.max_archive_depth);

    match format {
        ArchiveFormat::Tar => {
            let reader = BufReader::new(
                fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
            );
            let mut atomic_writer = AtomicFileWriter::new(&output_path)
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
            if let Some(rb) = report_builder {
                record_archive_stats(rb, &stats);
            }
            if stats.files_processed > 0 {
                had_matches = true;
            }
            print_archive_stats(&output_path, &stats);
        }
        ArchiveFormat::TarGz => {
            let reader = BufReader::new(
                fs::File::open(input).map_err(|e| format!("failed to open input: {e}"))?,
            );
            let mut atomic_writer = AtomicFileWriter::new(&output_path)
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
            if let Some(rb) = report_builder {
                record_archive_stats(rb, &stats);
            }
            if stats.files_processed > 0 {
                had_matches = true;
            }
            print_archive_stats(&output_path, &stats);
        }
        ArchiveFormat::Zip => {
            let mut reader = BufReader::new(
                fs::File::open(input).map_err(|e| format!("failed to open archive: {e}"))?,
            );
            let mut cursor_out = Cursor::new(Vec::new());

            let stats = archive_proc
                .process_zip(&mut reader, &mut cursor_out)
                .map_err(|e| format!("archive processing error: {e}"))?;

            if is_interrupted() {
                return Err("interrupted — partial output discarded".into());
            }

            // Atomic write the zip output.
            atomic_write(&output_path, &cursor_out.into_inner())
                .map_err(|e| format!("failed to write output: {e}"))?;

            if let Some(rb) = report_builder {
                record_archive_stats(rb, &stats);
            }
            if stats.files_processed > 0 {
                had_matches = true;
            }
            print_archive_stats(&output_path, &stats);
        }
    }

    Ok(had_matches)
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
fn write_output(cli: &Cli, data: &[u8]) -> Result<(), String> {
    match &cli.output {
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
        resolve_password(&args.password, &args.password_file, "encryption").map_err(|e| (e, 1))?;

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
        "  sanitize data.log -s {} -p <password>",
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
        resolve_password(&args.password, &args.password_file, "decryption").map_err(|e| (e, 1))?;

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
    let cli = Cli::parse();

    // --- initialise logging -------------------------------------------------
    init_logging(&cli.log_format);

    // --- dispatch subcommands -----------------------------------------------
    match &cli.command {
        Some(SubCommand::Encrypt(args)) => return run_encrypt(args),
        Some(SubCommand::Decrypt(args)) => return run_decrypt(args),
        None => {} // fall through to default sanitize mode
    }

    // --- install signal handler (graceful shutdown) --------------------------
    if let Err(e) = ctrlc::set_handler(move || {
        INTERRUPTED.store(true, Ordering::SeqCst);
    }) {
        eprintln!("warning: failed to install signal handler: {e}");
    }

    // --- validate -----------------------------------------------------------
    validate_args(&cli).map_err(|e| (e, 1))?;

    let thread_count = resolve_thread_count(cli.threads);
    info!(
        threads = thread_count,
        deterministic = cli.deterministic,
        chunk_size = cli.chunk_size,
        "starting sanitization"
    );

    let effective_password = cli.password.clone();

    // --- build core components ----------------------------------------------
    let scan_config = build_scan_config(cli.chunk_size).map_err(|e| (e, 1))?;
    let store = build_store(cli.deterministic, &effective_password, cli.max_mappings)
        .map_err(|e| (e, 1))?;
    let registry = Arc::new(ProcessorRegistry::with_builtins());

    // --- load secrets and build scanner -------------------------------------
    let scanner = if let Some(ref secrets_path) = cli.secrets_file {
        let raw_bytes = fs::read(secrets_path).map_err(|e| {
            (
                format!(
                    "failed to read secrets file {}: {e}",
                    secrets_path.display()
                ),
                1,
            )
        })?;

        // Resolve password (may be None for plaintext mode).
        let password = if cli.unencrypted_secrets {
            None
        } else {
            resolve_sanitize_password(&cli).ok()
        };

        let ((patterns, warnings), was_encrypted) = sanitize_engine::secrets::load_secrets_auto(
            &raw_bytes,
            password.as_deref(),
            None,
            cli.unencrypted_secrets,
        )
        .map_err(|e| (format!("failed to load secrets: {e}"), 1))?;

        if was_encrypted {
            info!(secrets_file = %secrets_path.display(), "loaded encrypted secrets");
        } else {
            info!(secrets_file = %secrets_path.display(), "loaded plaintext secrets (unencrypted)");
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

        let scanner = StreamScanner::new(patterns, Arc::clone(&store), scan_config)
            .map_err(|e| (format!("failed to create scanner: {e}"), 1))?;

        info!(
            patterns = scanner.pattern_count(),
            secrets_file = %secrets_path.display(),
            "patterns loaded"
        );
        Arc::new(scanner)
    } else {
        warn!("no --secrets-file provided; only structured processing will apply");
        Arc::new(
            StreamScanner::new(vec![], Arc::clone(&store), scan_config)
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

    // --- detect stdin vs archive vs plain file --------------------------------
    let had_matches = if is_stdin_input(&cli) {
        process_stdin(&cli, &scanner, &registry, &store, report_builder.as_ref())
            .map_err(|e| (e, 1))?
    } else {
        let input = cli.input.as_ref().unwrap();
        let input_str = input.to_string_lossy();
        if let Some(fmt) = ArchiveFormat::from_path(&input_str) {
            process_archive(
                input,
                &cli,
                &scanner,
                &registry,
                &store,
                fmt,
                report_builder.as_ref(),
            )
            .map_err(|e| (e, 1))?
        } else {
            process_plain_file(
                input,
                &cli,
                &scanner,
                &registry,
                &store,
                report_builder.as_ref(),
            )
            .map_err(|e| (e, 1))?
        }
    };

    // --- check for interruption ---------------------------------------------
    if is_interrupted() {
        return Err(("interrupted by signal".into(), 130));
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
        assert_eq!(cli.input.unwrap(), PathBuf::from("input.txt"));
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_parses_input_with_output() {
        let cli = Cli::try_parse_from(["sanitize", "input.txt", "-o", "output.txt"]).unwrap();
        assert_eq!(cli.input.unwrap(), PathBuf::from("input.txt"));
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.txt"));
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
            "hunter2",
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
        assert_eq!(cli.password.unwrap(), "hunter2");
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
    fn cli_parses_encrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "encrypt",
            "secrets.json",
            "secrets.enc",
            "--password",
            "hunter2",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_none());
    }

    #[test]
    fn cli_parses_decrypt_subcommand() {
        let cli = Cli::try_parse_from([
            "sanitize",
            "decrypt",
            "secrets.enc",
            "secrets.json",
            "--password",
            "hunter2",
        ])
        .unwrap();
        assert!(cli.command.is_some());
        assert!(cli.input.is_none());
    }

    #[test]
    fn cli_no_input_no_subcommand_is_ok_at_parse_time() {
        // Clap allows it (input is Option); we validate manually in run().
        let cli = Cli::try_parse_from(["sanitize", "--dry-run"]).unwrap();
        assert!(cli.input.is_none());
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
            "pw",
            "--dry-run",
            "--fail-on-match",
            "--deterministic",
            "--strict",
            "--include-binary",
            "--unencrypted-secrets",
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
        assert!(cli.unencrypted_secrets);
        assert_eq!(cli.chunk_size, 4096);
        assert_eq!(cli.threads, Some(4));
        assert_eq!(cli.max_mappings, 500);
        assert_eq!(cli.format.unwrap(), "yaml");
        assert_eq!(cli.output.unwrap(), PathBuf::from("output.log"));
    }

    #[test]
    fn cli_stdin_dash_input() {
        let cli = Cli::try_parse_from(["sanitize", "-", "-s", "s.json"]).unwrap();
        assert!(is_stdin_input(&cli));
    }

    #[test]
    fn cli_stdin_no_input() {
        let cli = Cli::try_parse_from(["sanitize", "-s", "s.json"]).unwrap();
        assert!(is_stdin_input(&cli));
    }

    #[test]
    fn cli_file_input_not_stdin() {
        let cli = Cli::try_parse_from(["sanitize", "data.log"]).unwrap();
        assert!(!is_stdin_input(&cli));
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
}
