# CLI Reference

## `sanitize`

```
sanitize [OPTIONS] [INPUT]
command | sanitize [OPTIONS]
sanitize guided
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

The default mode (no subcommand) sanitizes files and archives. When `INPUT` is omitted or set to `-`, data is read from stdin (plain text only; archives require a file path). Use `encrypt` / `decrypt` subcommands to manage encrypted secrets files.

### `sanitize guided`

Interactive wizard for generating a logs-focused starter secrets template.

```
sanitize guided
```

What it does:

- Prompts for template strictness (`balanced` vs `aggressive`).
- Asks for up to 3 company domains to seed domain-specific host/email patterns.
- Asks for cloud providers (AWS, Azure, GCP) and adds provider-specific entries.
- Generates a plaintext YAML secrets file (`.yaml`).
- Optionally encrypts the generated file.
- Optionally runs sanitization immediately using the generated file.

#### Guided Flow (Step by Step)

1. Starts interactive wizard and checks for a TTY (non-interactive shells are rejected).
2. Asks for strictness profile:
   - `Balanced`: core log/network identifiers.
   - `Aggressive`: balanced set plus token-oriented patterns.
3. Prompts for company domains (comma-separated, up to 3).
4. Prompts for cloud provider scope (AWS, Azure, GCP, none).
5. Prompts for noisy-ID handling (`trace_id`/`span_id`-like high-entropy noise toggle).
6. Prompts for output path, then forces YAML output (`.yaml`).
7. Generates secrets entries and validates all regexes by compiling them before writing.
8. Writes plaintext YAML template.
9. Optionally encrypts the generated template and writes a sibling `.enc` file.
10. Optionally continues directly into a sanitize run:
   - Prompts for input path (or `-` for stdin).
   - Prompts for optional output path.
   - Prompts for dry-run choice.
   - Prompts for deterministic mode choice.

#### What Guided Picks Out to Sanitize

The guided template writes regex rules with these categories and targets.

Always included (balanced + aggressive):

- `email`: email addresses.
- `hostname`: DNS-style hostnames/FQDNs.
- `ipv4`: IPv4 addresses.
- `ipv6`: IPv6 addresses.
- `mac_address`: MAC addresses with `:` or `-` separators.
- `uuid`: RFC-like UUIDs.
- `container_id`: long lowercase hex IDs (12-64 chars).
- `jwt`: JWT-like `header.payload.signature` tokens.
- `url`: `http://` and `https://` URLs.

Aggressive-only additions:

- `auth_token`: context-keyed token matches (e.g. `bearer`, `token`, `api_key`, `secret` plus long value).
- `custom:high_entropy_token`: broad long token pattern (`[A-Za-z0-9_-]{20,}`), unless noisy-ID exclusion is enabled.

#### Balanced Profile Details

`Balanced` is intended to catch common technical identifiers in logs while minimizing broad token captures.

Balanced includes:

- `email`
- `hostname`
- `ipv4`
- `ipv6`
- `mac_address`
- `uuid`
- `container_id`
- `jwt`
- `url`
- Domain-derived `email` and `hostname` rules (if domains are provided)
- Provider-derived rules for selected clouds (AWS/Azure/GCP)

Balanced excludes:

- `auth_token_context` aggressive token-context regex
- `custom:high_entropy_token` broad token regex

In practice, `Balanced` reduces false positives in logs with many opaque IDs while still sanitizing network/resource identifiers.

#### Aggressive Profile Details

`Aggressive` is intended to maximize secret/token detection in logs where broad matching is preferred over precision.

Aggressive includes everything in `Balanced`, plus:

- `auth_token_context`: context-keyed token regex for patterns like `bearer`, `token`, `api_key`, `secret` followed by long values.
- `custom:high_entropy_token`: broad long-token regex (`[A-Za-z0-9_-]{20,}`), unless noisy-ID exclusion is enabled.

Aggressive behavior notes:

- Better coverage for API keys, bearer values, and opaque credential-like strings in unstructured logs.
- Higher false-positive risk for long identifiers that are not secrets (for example telemetry IDs, synthetic IDs, long slugs).
- If noisy-ID exclusion is enabled in guided prompts, the broad high-entropy token entry is removed to reduce alert noise.

When to choose `Aggressive`:

- Logs are highly unstructured and frequently contain ad-hoc credential formats.
- You prefer over-redaction during first pass, then tune patterns down.

When to prefer `Balanced`:

- Logs contain many non-secret high-entropy identifiers.
- You need lower false-positive rates for initial rollout.

Domain-derived additions (for each provided domain):

- `email`: domain-specific email regex (`...@<domain>`).
- `hostname`: domain-specific host regex (`*.domain.tld` style).

Cloud-provider additions:

- AWS selected:
  - `aws_arn`: ARN-like values.
  - `auth_token`: AWS access key ID shape (`AKIA`/`ASIA` + 16 chars).
- Azure selected:
  - `azure_resource_id`: subscription/resourceGroups/provider path shapes.
- GCP selected:
  - `custom:gcp_service_account`: service-account email shape.
  - `custom:gcp_resource`: `projects/<id>/...` resource-path shape.

Intentionally excluded by default (logs-first design):

- `ssn`, `phone`, `credit_card`, `name`, `file_path`.

#### Replacement Behavior for Guided Rules

- All replacements are one-way and length-preserving.
- Category controls output shape (for example `email` preserves domain; `uuid` preserves dash layout; `url` preserves URL structure).
- `custom:*` categories use the custom formatter (`__SANITIZED_<hex>__` style adjusted to input length).

#### Example Generated YAML (Guided)

Example (aggressive profile, with domains and GCP selected):

```yaml
- pattern: '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}'
  kind: regex
  category: email
  label: email

- pattern: \b(?:(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+(?:[a-zA-Z]{2,63})\b
  kind: regex
  category: hostname
  label: hostname

- pattern: \b(?:\d{1,3}\.){3}\d{1,3}\b
  kind: regex
  category: ipv4
  label: ipv4

- pattern: \beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b
  kind: regex
  category: jwt
  label: jwt

- pattern: (?i)\b(?:bearer|token|api[_-]?key|secret)[\s:=]+[A-Za-z0-9._~+/=-]{16,}\b
  kind: regex
  category: auth_token
  label: auth_token_context

- pattern: '[A-Za-z0-9._%+-]+@example\.com'
  kind: regex
  category: email
  label: email_example_com

- pattern: \b(?:[A-Za-z0-9-]+\.)*example\.com\b
  kind: regex
  category: hostname
  label: host_example_com

- pattern: \b[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com\b
  kind: regex
  category: custom:gcp_service_account
  label: gcp_service_account

- pattern: \bprojects/[a-z][a-z0-9-]{4,30}/[A-Za-z0-9/_-]+\b
  kind: regex
  category: custom:gcp_resource
  label: gcp_resource
```

Balanced profile note for this example:

- The `auth_token_context` entry above is omitted in `Balanced`.
- If noisy-ID exclusion is enabled, broad high-entropy token entries are also omitted.

Notes:

- Guided mode is intended for application/system logs and excludes common consumer-PII categories by default.
- In non-interactive environments, guided mode exits with an error because it requires a TTY.
- GCP patterns currently use `custom:gcp_*` categories (no built-in GCP formatter yet).

### Default Mode — Sanitize

| Flag / Argument | Short | Description |
|-----------------|-------|-------------|
| `[INPUT]` | | Path to the file or archive to sanitize. Omit or use `-` to read from stdin. |
| `-o, --output <FILE>` | `-o` | Output path. Plain files default to stdout; archives default to `<input>.sanitized.<ext>`. |
| `-s, --secrets-file <FILE>` | `-s` | Path to a secrets file. Plaintext (`.json`, `.yaml`, `.toml`) is loaded directly by default. Use `--encrypted-secrets` to decrypt an AES-256-GCM encrypted file. |
| `-p, --password` | `-p` | Trigger an interactive password prompt (masked input, never echoed). Requires `--encrypted-secrets`. Providing this flag without `--encrypted-secrets` is an error. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `-P, --password-file <FILE>` | `-P` | Read the decryption password from a file. Requires `--encrypted-secrets`. The file must have permissions `0600` or `0400` (owner-only). Trailing newline is stripped. |
| `--encrypted-secrets` | | Treat the secrets file as AES-256-GCM encrypted and decrypt it before loading. Requires a password via `-p`, `--password-file`, or `SANITIZE_PASSWORD`. Without this flag the file is loaded as plaintext. Providing any password input without this flag is an error. |
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
sanitize large.log -s secrets.enc --encrypted-secrets --password

# Force progress messages even in non-interactive environments.
sanitize large.log -s secrets.enc --encrypted-secrets --password --progress on

# Disable progress completely.
sanitize large.log -s secrets.enc --encrypted-secrets --password --no-progress

# Redirect sanitized payload and progress separately.
sanitize large.log -s secrets.enc --encrypted-secrets --password --progress on > clean.log 2> progress.log

# Keep machine-readable JSON logs clean (no spinner frames).
sanitize large.log -s secrets.enc --encrypted-secrets --password --log-format json --progress on > clean.log 2> events.jsonl
```

#### Stdin Support

When no input file is given (or input is `-`), `sanitize` reads from stdin:

```bash
# Pipe from grep with a plaintext secrets file:
grep "error" app.log | sanitize -s secrets.yaml

# Pipe from grep with an encrypted secrets file (use env var since stdin is a pipe):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Read from stdin, write to a file (plaintext secrets):
cat data.csv | sanitize -s secrets.yaml -f csv -o clean.csv

# Use with heredoc:
sanitize -s secrets.json <<< "my secret api-key-12345"
```

Stdin mode supports plain text streaming by default. Use `--format` / `-f` to enable structured processing (e.g., `-f json` for JSON-aware field replacement). Archive formats (tar, zip) are not supported via stdin.

#### Examples

```bash
# Sanitize a log file using a plaintext secrets file (default):
sanitize data.log -s secrets.yaml

# Write output to a file (plaintext secrets):
sanitize data.log -s secrets.yaml -o clean.log

# Pipe from grep (plaintext secrets):
grep "error" app.log | sanitize -s secrets.yaml

# Force progress to stderr while keeping stdout pipe-safe:
grep "error" app.log | sanitize -s secrets.yaml --progress on > clean.log 2> progress.log

# Structured stdin processing:
cat config.yaml | sanitize -s secrets.yaml -f yaml -o clean.yaml

# Encrypted secrets file — requires --encrypted-secrets:
sanitize data.log -s secrets.enc --encrypted-secrets --password
sanitize data.log -s secrets.enc --encrypted-secrets --password -o clean.log

# Non-interactive pipeline with encrypted secrets (env var):
export SANITIZE_PASSWORD="my-password"
grep "error" app.log | sanitize -s secrets.enc --encrypted-secrets

# Deterministic mode (reproducible replacements) with encrypted secrets:
sanitize data.csv -s s.enc --encrypted-secrets --password -d

# Dry-run (scan only):
sanitize config.yaml -s s.enc --encrypted-secrets --password -n

# Fail CI if matches found:
sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match

# Read password from a file:
sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
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
| `--password` | Prompt interactively for the encryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
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
| `--password` | Prompt interactively for the decryption password. The password is never echoed. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `--password-file <FILE>` | Read the password from a file (must have `0600` or `0400` permissions). |
| `--format <FMT>` | Validate decrypted content as this format (`json`, `yaml`, `toml`). If omitted, raw bytes are written. |
| `-h, --help` | Print help. |

---

## Creating and Formatting a Secrets File

The secrets file defines which patterns to detect and how to categorize matches.

Recommended canonical authoring format: YAML.

Compatibility formats: JSON and TOML remain fully supported for existing workflows and automation.

### Fields

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `pattern` | Yes | — | The string to match. Interpreted as a regex or literal depending on `kind`. |
| `kind` | No | `"literal"` | `"regex"` for regular expression matching, or `"literal"` for exact string matching. |
| `category` | No | `"custom:secret"` | Controls replacement format. Built-in values: `email`, `name`, `phone`, `ipv4`, `ipv6`, `credit_card`, `ssn`, `hostname`, `mac_address`, `container_id`, `uuid`, `jwt`, `auth_token`, `file_path`, `windows_sid`, `url`, `aws_arn`, `azure_resource_id`. Use `custom:<tag>` for arbitrary categories. |
| `label` | No | Truncated `pattern` | Human-readable label for reporting and statistics. |

### YAML format (canonical)

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

### JSON format (compatibility)

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

### TOML format (compatibility)

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

**Sanitize a single file (interactive password prompt):**

```bash
sanitize data.log -s secrets.enc --encrypted-secrets --password
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc --encrypted-secrets --password -d
```

**Process a tar.gz archive with strict error handling:**

```bash
sanitize backup.tar.gz -s s.enc --encrypted-secrets --password -o backup.sanitized.tar.gz --strict
```

**Dry-run — see what would be replaced without writing output:**

```bash
sanitize config.yaml -s s.enc --encrypted-secrets --password -n
```

**Fail CI if secrets are detected:**

```bash
sanitize config.yaml -s s.enc --encrypted-secrets -P /run/secrets/pw --fail-on-match
```

**Read password from a file (avoids shell history and /proc exposure):**

```bash
sanitize data.log -s s.enc --encrypted-secrets -P /run/secrets/pw
```

**Custom chunk size for memory-constrained environments:**

```bash
sanitize huge.log -s s.enc --encrypted-secrets --password --chunk-size 262144
```

**JSON-structured logs for SIEM ingestion:**

```bash
sanitize data.log -s s.enc --encrypted-secrets --password --log-format json
```

**Use a plaintext secrets file (default — no password needed):**

```bash
# Plaintext YAML/JSON/TOML is the default — just point at the file:
sanitize data.log -s secrets.yaml
sanitize data.log -s secrets.json

# Deterministic mode with plaintext secrets:
sanitize data.csv -s secrets.yaml -d

# Fail CI with plaintext secrets:
sanitize config.yaml -s secrets.yaml --fail-on-match
```

**Use an encrypted secrets file (opt-in with `--encrypted-secrets`):**

```bash
# Interactive password prompt:
sanitize data.log -s secrets.enc --encrypted-secrets --password

# Password from file (CI-friendly):
sanitize data.log -s secrets.enc --encrypted-secrets -P /run/secrets/pw

# Password from environment variable:
SANITIZE_PASSWORD=hunter2 sanitize data.log -s secrets.enc --encrypted-secrets
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
sanitize encrypt secrets.json secrets.json.enc --password

# 3. Remove the plaintext:
rm secrets.json

# 4. Use the encrypted file (interactive prompt):
sanitize data.log -s secrets.json.enc --encrypted-secrets --password

# 5. Decrypt to edit later:
sanitize decrypt secrets.json.enc secrets.json --password
```

> **Security note:** `-p` / `--password` triggers a secure interactive prompt (masked input, no shell history). All password inputs (`-p`, `-P`, `SANITIZE_PASSWORD`) require `--encrypted-secrets`. For non-interactive automation use `-P` / `--password-file` or the `SANITIZE_PASSWORD` environment variable.
