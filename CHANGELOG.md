# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.4.0] — 2026-05-01

### Added

- **`--llm [TEMPLATE]` flag** — formats sanitized output as an LLM-ready prompt and writes it to stdout instead of a file. Built-in templates: `troubleshoot` (default) and `review-config`. A custom template file path can be provided instead. Sanitized content appears in `<content name="...">` blocks followed by a Sanitization Summary and (optionally) a `<notable_events>` section when used with `--extract-context`.

- **Validation: `--llm` conflicts** — `--llm` cannot be combined with `--output` (the prompt is the output) or `--dry-run` (no sanitized content to include). A nonexistent or non-file custom template path is also rejected with a clear error.

- **Unit tests for `--llm` helpers** — `resolve_llm_template`, `format_llm_prompt` (content blocks, sanitization summary, notable events, multiple entries), and `validate_args` for all `--llm` rejection cases.

- **Integration test suite: `tests/llm_tests.rs`** — end-to-end CLI coverage for `--llm`: validation rejections, template selection, prompt structure, secret sanitization in prompt, `--extract-context` integration, and no-write guarantee.

- **Integration test suite: `tests/extract_context_tests.rs`** — CLI coverage for `--extract-context` (report JSON output, `--context-lines` 0 and non-zero), `--context-keywords`, `--context-keywords-only`, and `--strip-values` (file and stdin paths).

- **Unit tests for `--strip-values` helpers** — `strip_values_from_text` preserves keys, comments, blank lines, section headers, and pass-through lines without a delimiter.

- **Unit tests for `validate_args`** — covers `--format`, `--log-format`, `--threads 0`, `--password` without `--encrypted-secrets`, known LLM templates, and all `--llm` rejection paths.

## [0.3.0] — 2026-04-29

### Added

- **`--profile <FILE>` flag** — enables structured field-level sanitization. A profile YAML or JSON file maps file extensions to processors and field rules (e.g. replace `*.password` with `custom:password` category). Profiles are evaluated before the streaming scanner.

- **Two-phase pipeline** — when `--profile` is supplied, profile-matched files are processed first (serially) to populate the replacement store with discovered field values. The streaming scanner used for all other files is then augmented with those values as literal patterns, so the same secret found in `config.yaml` is automatically replaced in `app.log` with the same replacement.

- **Format-preserving structured pass** — the structured processor populates the store with field-value mappings, then the original file bytes are scanned with a per-file scanner containing those literals. Comments, indentation, key ordering, blank lines, and quoting style are all preserved exactly.

- **`include` / `exclude` globs on `FileTypeProfile`** — profiles can now restrict which files they apply to beyond extension matching. `include` narrows to filenames matching at least one glob; `exclude` skips matching filenames. Patterns without a path separator are matched against both the filename and the full path.

- **Discovered-value persistence** (`--deterministic` + `--profile`) — when `--deterministic` is set alongside `--profile`, values discovered by the structured pass are appended to `--secrets-file` after the run (creating the file if absent, deduplicating if it exists). Subsequent runs against unstructured files load those patterns and produce consistent replacements.

- **`--deterministic` without `--encrypted-secrets`** — `--deterministic` can now be used with a plaintext secrets file. The password (via `SANITIZE_PASSWORD`, `--password-file`, or `-p`) is used as the HMAC seed only; `--encrypted-secrets` is no longer required when using deterministic mode without an encrypted secrets file.

- **Archive structured discovery pre-pass** — archives in Phase 2 are opened once before the augmented scanner is built. Profile-matched entries inside the archive populate the store, so their values are included in the augmented scanner used for all Phase 2 processing.

- **`ScanPattern::Clone`** — `ScanPattern` now implements `Clone` (via the internally ref-counted `regex::bytes::Regex`).

- **`StreamScanner::with_extra_literals`** — builds an extended copy of a scanner with additional literal patterns appended. Used internally for per-file scanners in the structured pass.

- **`MappingStore::snapshot_keys`** — returns a `HashSet` of all current `(Category, original)` keys. Used to diff the store before and after structured processing to find newly discovered literals.

### Changed

- **Default secrets mode is now plaintext** — `sanitize` loads secrets files as
  plaintext JSON / YAML / TOML by default. Encrypted (AES-256-GCM) files now
  require the explicit `--encrypted-secrets` flag.
- **`--unencrypted-secrets` removed** — replaced by the inverse `--encrypted-secrets`
  flag. Scripts using `--unencrypted-secrets` must remove the flag (the default
  behaviour is now plaintext).
- **Password inputs require `--encrypted-secrets`** — supplying `--password`,
  `--password-file`, or the `SANITIZE_PASSWORD` environment variable without
  `--encrypted-secrets` is now a hard error with a clear message.
- **`--password` / `-p` is now interactive** — The flag no longer accepts an
  inline value. When provided, it triggers a secure interactive password prompt
  (masked input via `rpassword`, no shell history or process listing exposure).
  Passing `--password VALUE` is rejected by the parser. In non-interactive
  contexts (no TTY) the flag returns a clear error and directs users to
  `--password-file` or `SANITIZE_PASSWORD`.

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
  `export SANITIZE_PASSWORD="secret"; grep "error" log.txt | sanitize -s secrets.enc`.
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
