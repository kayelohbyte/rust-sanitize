# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.2.0] — 2026-03-20

### Fixed

- **CLI panic on startup** — `required_unless_present = "command"` referenced
  a clap subcommand field that is not exposed as a named argument in clap 4.5,
  causing a debug assertion panic on every invocation. Replaced with manual
  validation after parsing.
- **`--unencrypted-secrets` still prompted for password** — password resolution
  via `rpassword` was called unconditionally, even when `--unencrypted-secrets`
  was set. Now skips password resolution entirely when the flag is present.
- **`--dry-run --report` showed zero matches for archives** — `ScanStats` from
  per-entry scanning were discarded (`_scan_stats`). Added
  `file_scan_stats: HashMap<String, ScanStats>` to `ArchiveStats` and
  aggregated per-entry scan results so reports reflect actual match counts.

### Changed

- **Consolidated `encrypt-secrets` into `sanitize` subcommands.** The separate
  `encrypt-secrets` binary has been removed. Use `sanitize encrypt <IN> <OUT>`
  and `sanitize decrypt <IN> <OUT>` instead. The default sanitize mode
  (`sanitize [INPUT]`) is unchanged and requires no subcommand.
- **Unified password handling** across all modes with a single resolution
  chain: `--password` flag → `--password-file` → `SANITIZE_PASSWORD` env var
  → interactive prompt (masked via `rpassword`).
- **Removed `--secrets-key`** — use `--password` instead.
- **`OUTPUT` is now `--output` / `-o`** — Output path changed from a positional
  argument to a named flag. Usage: `sanitize data.log -s s.enc -o output.log`.
  Plain files still default to stdout; archives default to
  `<input>.sanitized.<ext>`.
- **Cross-platform support** — `nix` dependency is now Unix-only; password-file
  permission checks degrade gracefully on non-Unix platforms.

### Added

- **CLI smoke tests** — 15 unit tests in `src/bin/sanitize.rs` covering argument
  parsing, subcommand dispatch, short flags, stdin detection, and flag
  combinations. Prevents future clap derive regressions.
- **Stdin support** — When `INPUT` is omitted or set to `-`, `sanitize` reads
  from stdin. Enables Unix pipeline usage:
  `grep "error" log.txt | sanitize -s secrets.enc -p hunter2`.
  TTY detection prevents hanging when run interactively without input.
- **Short flags** — Common options now have short aliases: `-s` (secrets-file),
  `-p` (password), `-P` (password-file), `-o` (output), `-n` (dry-run),
  `-d` (deterministic), `-r` (report), `-f` (format).
- **`--format` / `-f` flag** — Force input format (`text`, `json`, `yaml`,
  `xml`, `csv`, `key-value`), overriding file-extension detection. Required
  for structured processing when reading from stdin.
- **`sanitize encrypt`** subcommand — encrypts a plaintext secrets file with
  AES-256-GCM (replaces the standalone `encrypt-secrets` binary).
- **`sanitize decrypt`** subcommand — decrypts an encrypted secrets file back
  to plaintext for editing, with optional format validation.
- **`--password <PW>`** flag — provides the password for the default
  sanitize mode. Also available in `encrypt` and `decrypt` subcommands.
- **`--password-file <PATH>`** flag — read the password from a file with
  strict Unix permissions enforcement (`0600` or `0400`). Avoids shell
  history and `/proc/<pid>/environ` exposure.
- **Interactive password prompt** — when no password is provided via flag,
  file, or env var, the user is prompted on the terminal with masked input
  (via the `rpassword` crate).

### Removed

- **`encrypt-secrets` binary** — functionality absorbed into
  `sanitize encrypt` and `sanitize decrypt`.

## [0.1.0] — 2026-03-19

### Added

- **Streaming scanner** with configurable chunk + overlap for bounded-memory
  processing of arbitrarily large files.
- **18 built-in categories**: email, name, phone, credit card, SSN, IPv4, IPv6,
  MAC address, hostname, container ID, UUID, JWT, auth token, file path,
  Windows SID, URL, AWS ARN, Azure resource ID, plus `custom:<tag>`.
- **Structured processors** for JSON, YAML, XML, CSV, and key-value formats
  that replace matched values while preserving document structure.
- **Archive support** for tar, tar.gz, and zip with entry-by-entry processing
  and metadata preservation (timestamps, permissions, uid/gid).
- **Deterministic mode** using HMAC-SHA256 seeded replacements — same seed and
  same input produce identical output across runs.
- **Random mode** (default) using CSPRNG with per-run dedup cache for
  consistency within a single run.
- **Length-preserving replacements** for all 18 built-in categories.
- **Encrypted secrets file** (AES-256-GCM with PBKDF2, 600 000 iterations) for
  storing detection patterns at rest.
- **Plaintext secrets** support with auto-detection (JSON, YAML, TOML).
- **`encrypt-secrets` CLI** (since removed — see 0.2.0) for converting
  plaintext secrets to encrypted form.
- **`sanitize` CLI** with `--dry-run`, `--fail-on-match`, `--report`,
  `--deterministic`, `--strict`, and streaming/structured processing options.
- **Regex hardening**: per-pattern automaton size limits (1 MiB), DFA size
  limits, and pattern count cap (10 000).
- **YAML alias bomb mitigation**: input size cap (64 MiB), node count cap
  (10 000 000), and recursion depth limit (128).
- **Memory bounds** for all structured processors (JSON/XML/CSV: 256 MiB;
  YAML: 64 MiB) with automatic fallback to streaming.
- **Atomic file writes** using temp-file + rename for crash safety.
- **Zeroization** of sensitive data (HMAC keys, secret entries, mapping store)
  on drop via the `zeroize` crate.
- **Graceful shutdown** on SIGINT with atomic flag.
- **JSON report output** (`--report`) with per-file and aggregate statistics.
- **Zero `unsafe` code** — entire crate uses safe Rust only.
- **290+ tests** including unit, integration, property-based (proptest), and
  4 fuzz targets.

[0.2.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.2.0
[0.1.0]: https://github.com/kayelohbyte/rust-sanitize/releases/tag/v0.1.0
