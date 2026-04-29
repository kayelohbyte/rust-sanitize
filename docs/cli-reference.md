# CLI Reference

## `sanitize`

```
sanitize [OPTIONS] [INPUT]
command | sanitize [OPTIONS]
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

The default mode (no subcommand) sanitizes files and archives. When `INPUT` is omitted or set to `-`, data is read from stdin (plain text only; archives require a file path). Use `encrypt` / `decrypt` subcommands to manage encrypted secrets files.

### Default Mode — Sanitize

| Flag / Argument | Short | Description |
|-----------------|-------|-------------|
| `[INPUT]` | | Path to the file or archive to sanitize. Omit or use `-` to read from stdin. |
| `-o, --output <FILE>` | `-o` | Output path. Plain files default to stdout; archives default to `<input>.sanitized.<ext>`. |
| `-s, --secrets-file <FILE>` | `-s` | Path to a secrets file — encrypted (`.enc`) or plaintext (`.json`, `.yaml`, `.toml`). Format is auto-detected. |
| `-p, --password <PW>` | `-p` | Password for decrypting the secrets file. Falls back to `--password-file`, then `SANITIZE_PASSWORD` env var, then interactive prompt. Not required for plaintext secrets. |
| `-P, --password-file <FILE>` | `-P` | Read the password from a file. The file must have permissions `0600` or `0400` (owner-only). Trailing newline is stripped. |
| `--unencrypted-secrets` | | Treat the secrets file as plaintext (skip decryption). When omitted, the engine auto-detects whether the file is encrypted or plaintext. |
| `-f, --format <FMT>` | `-f` | Force input format, overriding file-extension detection. Values: `text`, `json`, `yaml`, `xml`, `csv`, `key-value`. Required for structured processing when reading from stdin. |
| `-n, --dry-run` | `-n` | Scan and report matches without writing output. |
| `--fail-on-match` | | Exit with code 2 if any matches are found. |
| `-r, --report [PATH]` | `-r` | Write a JSON report to `PATH` (or stderr if no path given). Use `--report -` to write the report to stdout. |
| `--strict` | | Abort on the first error instead of skipping and continuing. |
| `-d, --deterministic` | `-d` | Use HMAC-deterministic replacements (reproducible across runs with the same seed). |
| `--include-binary` | | Process entries that appear to be binary data (default: skip). |
| `--threads <N>` | | Number of worker threads (currently advisory; reserved for future parallel archive processing). Capped to available parallelism. |
| `--chunk-size <BYTES>` | | Chunk size for the streaming scanner in bytes (default: `1048576` = 1 MiB). |
| `--max-mappings <N>` | | Maximum unique replacement mappings in memory (default: `10000000`). Use `0` for unlimited. |
| `--max-structured-size <BYTES>` | | Maximum structured file size in bytes before falling back to streaming (default: `268435456` = 256 MiB). |
| `--max-archive-depth <N>` | | Maximum nesting depth for recursive archive processing (default: `3`, max: `10`). Each nesting level may buffer up to 256 MiB. |
| `--log-format <FMT>` | | Log output format: `human` (default) or `json`. |
| `--progress <MODE>` | | Progress display mode: `auto`, `on`, or `off`. Default: `auto`. |
| `--no-progress` | | Alias for `--progress off`. |
| `--progress-interval-ms <MS>` | | Minimum interval between progress refreshes (default: `200`). |
| `-h, --help` | `-h` | Print help. |
| `-V, --version` | `-V` | Print version. |

Log level is controlled via the `SANITIZE_LOG` environment variable (e.g. `SANITIZE_LOG=debug`).

#### Progress Behavior

Progress output is designed to stay safe for pipelines and machine-readable logging:

- Live progress renders on `stderr` only.
- `stdout` remains reserved for sanitized payloads and explicit report output.
- In `auto` mode, live progress is disabled when `stderr` is not a TTY, when `TERM=dumb`, when `CI` is set, or when `--log-format json` is active.
- In `json` log mode, spinner frames are suppressed so logs remain parseable.
- `--progress on` forces progress reporting, but non-interactive environments fall back to milestone-style status instead of a live spinner.

Examples:

```bash
# Default behavior: spinner in interactive terminals, silent in CI/non-TTY.
sanitize large.log -s secrets.enc -p hunter2

# Force progress messages even in non-interactive environments.
sanitize large.log -s secrets.enc -p hunter2 --progress on

# Disable progress completely.
sanitize large.log -s secrets.enc -p hunter2 --no-progress

# Redirect sanitized payload and progress separately.
sanitize large.log -s secrets.enc -p hunter2 --progress on > clean.log 2> progress.log

# Keep machine-readable JSON logs clean (no spinner frames).
sanitize large.log -s secrets.enc -p hunter2 --log-format json --progress on > clean.log 2> events.jsonl
```

#### Stdin Support

When no input file is given (or input is `-`), `sanitize` reads from stdin:

```bash
# Pipe from another command:
grep "error" app.log | sanitize -s secrets.enc -p hunter2

# Read from stdin, write to a file:
cat data.csv | sanitize -s secrets.enc -p pw -f csv -o clean.csv

# Use with heredoc:
sanitize -s secrets.json <<< "my secret api-key-12345"
```

Stdin mode supports plain text streaming by default. Use `--format` / `-f` to enable structured processing (e.g., `-f json` for JSON-aware field replacement). Archive formats (tar, zip) are not supported via stdin.

#### Examples

```bash
# Sanitize a log file (output to stdout):
sanitize data.log -s secrets.enc -p hunter2

# Write output to a file:
sanitize data.log -s secrets.enc -p hunter2 -o clean.log

# Pipe from grep:
grep "error" app.log | sanitize -s secrets.enc -p hunter2

# Force progress to stderr while keeping stdout pipe-safe:
grep "error" app.log | sanitize -s secrets.enc -p hunter2 --progress on > clean.log 2> progress.log

# Structured stdin processing:
cat config.yaml | sanitize -s secrets.enc -p pw -f yaml -o clean.yaml

# Use a plaintext secrets file (auto-detected):
sanitize data.log -s secrets.json

# Deterministic mode (reproducible replacements):
sanitize data.csv -s s.enc -p pw -d

# Dry-run (scan only):
sanitize config.yaml -s s.enc -p pw -n

# Fail CI if matches found:
sanitize config.yaml -s s.enc -p pw --fail-on-match

# Read password from a file:
sanitize data.log -s s.enc -P /run/secrets/pw
```

### `sanitize encrypt`

Encrypt a plaintext secrets file for use with the sanitizer.

```
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to plaintext secrets file (`.json`, `.yaml`, `.yml`, `.toml`). |
| `<OUTPUT>` | Path for encrypted output file (`.enc`). |
| `--password <PW>` | Encryption password. Falls back to `--password-file`, then `SANITIZE_PASSWORD` env var, then interactive prompt. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--format <FMT>` | Force input format: `json`, `yaml`, or `toml` (default: auto-detect from extension). |
| `--validate` | Parse plaintext before encrypting and report errors (default). |
| `--no-validate` | Skip pre-encryption validation. |
| `-h, --help` | Print help. |

### `sanitize decrypt`

Decrypt an encrypted secrets file back to plaintext for editing.

```
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

| Flag / Argument | Description |
|-----------------|-------------|
| `<INPUT>` | Path to encrypted secrets file (`.enc`). |
| `<OUTPUT>` | Path for decrypted plaintext output. |
| `--password <PW>` | Decryption password. Falls back to `--password-file`, then `SANITIZE_PASSWORD` env var, then interactive prompt. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--format <FMT>` | Validate decrypted content as this format (`json`, `yaml`, `toml`). If omitted, raw bytes are written. |
| `-h, --help` | Print help. |

---

## Creating and Formatting a Secrets File

The secrets file defines which patterns to detect and how to categorize matches. It can be written in JSON, YAML, or TOML.

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `pattern` | Yes | — | The string to match. Interpreted as a regex or literal depending on `kind`. |
| `kind` | No | `"literal"` | `"regex"` for regular expression matching, or `"literal"` for exact string matching. |
| `category` | No | `"custom:secret"` | Controls replacement format. Built-in values: `email`, `name`, `phone`, `ipv4`, `ipv6`, `credit_card`, `ssn`, `hostname`, `mac_address`, `container_id`, `uuid`, `jwt`, `auth_token`, `file_path`, `windows_sid`, `url`, `aws_arn`, `azure_resource_id`. Use `custom:<tag>` for arbitrary categories. |
| `label` | No | Truncated `pattern` | Human-readable label for reporting and statistics. |

### JSON format

```json
[
  {
    "pattern": "alice@corp\\.com",
    "kind": "regex",
    "category": "email",
    "label": "alice_email"
  },
  {
    "pattern": "sk-proj-abc123secret",
    "kind": "literal",
    "category": "custom:api_key",
    "label": "openai_key"
  }
]
```

### YAML format

```yaml
- pattern: "alice@corp\\.com"
  kind: regex
  category: email
  label: alice_email

- pattern: "sk-proj-abc123secret"
  kind: literal
  category: "custom:api_key"
  label: openai_key
```

### TOML format

```toml
[[secrets]]
pattern = "alice@corp\\.com"
kind = "regex"
category = "email"
label = "alice_email"

[[secrets]]
pattern = "sk-proj-abc123secret"
kind = "literal"
category = "custom:api_key"
label = "openai_key"
```

> **Note on regex patterns:** When `kind` is `"regex"`, the `pattern` field is compiled as a Rust regular expression. Metacharacters (`.`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `\`, `^`, `$`, `|`) must be escaped with a backslash to match literally. When `kind` is `"literal"`, the pattern is automatically escaped before compilation — no manual escaping is needed.

All patterns from the secrets file are compiled into a single `RegexSet` for efficient multi-pattern matching. Each match triggers a one-way replacement through the `MappingStore`, formatted according to the pattern's category.

---

## Examples

**Sanitize a single file (output to stdout):**

```bash
sanitize data.log -s secrets.enc -p hunter2
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc -p pw -d
```

**Process a tar.gz archive with strict error handling:**

```bash
sanitize backup.tar.gz -s s.enc -p pw -o backup.sanitized.tar.gz --strict
```

**Dry-run — see what would be replaced without writing output:**

```bash
sanitize config.yaml -s s.enc -p pw -n
```

**Fail CI if secrets are detected:**

```bash
sanitize config.yaml -s s.enc -p pw --fail-on-match
```

**Read password from a file (avoids shell history and /proc exposure):**

```bash
sanitize data.log -s s.enc -P /run/secrets/pw
```

**Custom chunk size for memory-constrained environments:**

```bash
sanitize huge.log -s s.enc -p pw --chunk-size 262144
```

**JSON-structured logs for SIEM ingestion:**

```bash
sanitize data.log -s s.enc -p pw --log-format json
```

**Use a plaintext (unencrypted) secrets file:**

```bash
# Auto-detect — plaintext JSON/YAML/TOML is recognised automatically:
sanitize data.log -s secrets.json

# Explicit flag:
sanitize data.log -s secrets.yaml --unencrypted-secrets

# Deterministic mode with plaintext secrets:
sanitize data.csv -s secrets.json -d

# Fail CI with plaintext secrets:
sanitize config.yaml -s secrets.json --fail-on-match
```

**Encrypted secrets file workflow:**

```bash
# 1. Create a plaintext secrets file (JSON):
cat > secrets.json <<'EOF'
[
  {"pattern": "alice@corp\\.com", "kind": "regex", "category": "email", "label": "alice_email"},
  {"pattern": "sk-proj-abc123secret", "kind": "literal", "category": "custom:api_key", "label": "openai_key"}
]
EOF

# 2. Encrypt it:
sanitize encrypt secrets.json secrets.json.enc --password "my-password"

# 3. Remove the plaintext:
rm secrets.json

# 4. Use the encrypted file:
sanitize data.log -s secrets.json.enc -p "my-password"

# 5. Decrypt to edit later:
sanitize decrypt secrets.json.enc secrets.json --password "my-password"
```

> **Security note:** Prefer `-P` / `--password-file` or the `SANITIZE_PASSWORD` environment variable over `-p` / `--password` to avoid exposing the password in process listings and shell history.
