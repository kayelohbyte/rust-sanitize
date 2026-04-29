# CLI Reference

## `sanitize`

```
sanitize [OPTIONS] [INPUT]...
command | sanitize [OPTIONS]
sanitize guided
sanitize encrypt [OPTIONS] <INPUT> <OUTPUT>
sanitize decrypt [OPTIONS] <INPUT> <OUTPUT>
```

The default mode (no subcommand) sanitizes one or more files and archives. Multiple `INPUT` paths may be given in a single invocation and may mix plain files, structured files, and archives freely. When `INPUT` is omitted, data is read from stdin; use `-` to include stdin alongside file paths. Use `encrypt` / `decrypt` subcommands to manage encrypted secrets files.

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
| `[INPUT]...` | | One or more paths to sanitize. Any mix of plain files, structured files, and archives is accepted. Omit to read from stdin; use `-` to include stdin alongside file paths. `-` may appear at most once. |
| `-o, --output <FILE>` | `-o` | Output path. For a **single input stream** this is the output file path. For **multiple inputs** this is treated as an output directory (created automatically if absent); output files are written there instead. |}
| `-s, --secrets-file <FILE>` | `-s` | Path to a secrets file. Plaintext (`.json`, `.yaml`, `.toml`) is loaded directly by default. Use `--encrypted-secrets` to decrypt an AES-256-GCM encrypted file. |
| `-p, --password` | `-p` | Trigger an interactive password prompt (masked input, never echoed). Requires `--encrypted-secrets`. Providing this flag without `--encrypted-secrets` is an error. For non-interactive automation use `--password-file` or `SANITIZE_PASSWORD` instead. |
| `-P, --password-file <FILE>` | `-P` | Read the decryption password from a file. Requires `--encrypted-secrets`. The file must have permissions `0600` or `0400` (owner-only). Trailing newline is stripped. |
| `--encrypted-secrets` | | Treat the secrets file as AES-256-GCM encrypted and decrypt it before loading. Requires a password via `-p`, `--password-file`, or `SANITIZE_PASSWORD`. Without this flag the file is loaded as plaintext. Providing any password input without this flag is an error. |
| `-f, --format <FMT>` | `-f` | Force input format, overriding file-extension detection. Values: `text`, `json`, `yaml`, `xml`, `csv`, `key-value`. Required for structured processing when reading from stdin. |
| `-n, --dry-run` | `-n` | Scan and report matches without writing output. |
| `--fail-on-match` | | Exit with code 2 if any matches are found. |
| `-r, --report [PATH]` | `-r` | Write a JSON report to `PATH` (or stderr if no path given). Use `--report -` to write the report to stdout. |
| `--strict` | | Abort on the first error instead of skipping and continuing. |
| `-d, --deterministic` | `-d` | Use HMAC-deterministic replacements (reproducible across runs with the same password). Requires a password via `SANITIZE_PASSWORD`, `--password-file`, or `-p`. When combined with `--profile`, values discovered by structured scanning are saved to `--secrets-file` (creating the file if absent). |
| `--include-binary` | | Process entries that appear to be binary data (default: skip). |
| `--threads <N>` | | Number of worker threads. When multiple input files are given, files are processed in parallel up to this limit. For a single archive input, entries are sanitized in parallel using the same budget. Defaults to the number of logical CPUs. Capped to available parallelism. |
| `--chunk-size <BYTES>` | | Chunk size for the streaming scanner in bytes (default: `1048576` = 1 MiB). |
| `--max-mappings <N>` | | Maximum unique replacement mappings in memory (default: `10000000`). Use `0` for unlimited. |
| `--max-structured-size <BYTES>` | | Maximum structured file size in bytes before falling back to streaming (default: `268435456` = 256 MiB). |
| `--max-archive-depth <N>` | | Maximum nesting depth for recursive archive processing (default: `3`, max: `10`). Each nesting level may buffer up to 256 MiB. |
| `--profile <FILE>` | | Path to a file-type profile (JSON or YAML). Enables structured field-level sanitization for matched files. See [Structured Processing](structured-processing.md). |
| `--only <PATTERN>` | | Keep only archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--only` flags accumulate. Combined with `--exclude`: `--only` narrows first, then `--exclude` removes. Only affects archive inputs; ignored for plain files. |
| `--exclude <PATTERN>` | | Remove archive entries whose full path matches `PATTERN`. Must follow the archive path it applies to. Multiple `--exclude` flags accumulate. |
| `--log-format <FMT>` | | Log output format: `human` (default) or `json`. |
| `--progress <MODE>` | | Progress display mode: `auto`, `on`, or `off`. Default: `auto`. |
| `--no-progress` | | Alias for `--progress off`. |
| `--progress-interval-ms <MS>` | | Minimum interval between progress refreshes (default: `200`). |
| `-h, --help` | `-h` | Print help. |
| `-V, --version` | `-V` | Print version. |

Log level is controlled via the `SANITIZE_LOG` environment variable (e.g. `SANITIZE_LOG=debug`).

#### Archive Entry Filtering (`--only` / `--exclude`)

`--only` and `--exclude` filter which entries are written into the output archive. They must appear **after** the archive path they apply to. Patterns match the full stored entry path (e.g. `test/test.config`, not just `test.config`).

**Pattern syntax**

| Pattern | Meaning |
|---------|---------|
| `*.log` | Matches any `.log` file in the root of the archive. `*` does **not** cross `/`. |
| `**/*.log` | Matches `.log` files at any depth. `**` crosses `/`. |
| `logs/` | Directory-prefix match: keeps `logs/` itself and every entry under it. Trailing `/` is required. |
| `config/app.yaml` | Exact full-path match. |
| `??.txt` | `?` matches any single character except `/`. |
| `[abc].txt` | Character-class match for `a.txt`, `b.txt`, or `c.txt`. |

**Rules**

- `--only` and `--exclude` are **per-archive**. Use interleaved syntax to filter multiple archives independently.
- Both flags can be combined: `--only` narrows the set first, then `--exclude` removes from it.
- **Directory entries** (entries whose stored type is a directory) always pass through regardless of any filter. Only file entries are filtered.
- **Nested archives** inherit the same filter applied to their parent archive.
- `--only` / `--exclude` before any archive path on the command line is a hard error.
- A non-archive plain file appearing between `--only`/`--exclude` and their pattern values is a hard error.

**Single archive**

```bash
# Keep only entries matching test/test.config (exact full path):
sanitize archive.zip --only test/test.config -s secrets.yaml

# Keep only JSON files at any depth:
sanitize archive.zip --only '**/*.json' -s secrets.yaml

# Keep only entries under the config/ prefix:
sanitize archive.zip --only 'config/' -s secrets.yaml

# Drop all .log files:
sanitize archive.zip --exclude '*.log' -s secrets.yaml

# Keep only JSON files, then drop secrets.json:
sanitize archive.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml

# Keep only JSON files in the root (not subdirectories):
sanitize archive.zip --only '*.json' -s secrets.yaml
```

**Multiple archives — each gets its own filter**

```bash
# a.zip keeps only config/, b.tar.gz keeps only *.log files:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Mix an archive with a plain file — the plain file is not filtered:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml

# Mix stdin with an archive filter:
cat extra.log | sanitize - backup.zip --only 'logs/' -s secrets.yaml
```

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

#### Output Naming

When no `--output` is given, each input gets its own output file written next to the source:

| Input type | Default output name |
|------------|--------------------|
| Plain / structured file (`foo.txt`, `a.json`) | `<stem>-sanitized.<ext>` — e.g. `foo-sanitized.txt`, `a-sanitized.json` |
| Archive (`data.tar`, `data.tar.gz`, `archive.zip`) | `<stem>.sanitized.<ext>` — e.g. `data.sanitized.tar`, `data.sanitized.tar.gz`, `archive.sanitized.zip` |
| Stdin (no file path) | stdout |

When multiple inputs map to the same computed output name within one run, a numeric suffix is appended automatically (e.g. `same-sanitized-1.txt`, `same-sanitized-2.txt`).

When `--output <PATH>` is given:
- **Single input:** writes to that exact path.
- **Multiple inputs:** `PATH` is treated as a directory. The directory is created if absent. Output files are placed inside it using the per-input naming rules above.


#### Stdin Support

When no input path is given (or one of the paths is `-`), `sanitize` reads from stdin. `-` may be mixed freely with file paths and may appear at most once. Stdin output defaults to stdout unless `--output` is given.

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
# Sanitize a single log file (output goes to data-sanitized.log):
sanitize data.log -s secrets.yaml

# Sanitize multiple files in one command:
sanitize test.txt a.json b.zip -s secrets.yaml
# Produces: test-sanitized.txt  a-sanitized.json  b.sanitized.zip

# Send all sanitized files to a specific output directory:
sanitize test.txt a.json b.zip -s secrets.yaml -o /tmp/clean/

# Override output path for a single file:
sanitize data.log -s secrets.yaml -o clean.log

# Pipe from grep (plaintext secrets):
grep "error" app.log | sanitize -s secrets.yaml

# Mix stdin with file inputs (stdin goes to stdout, files get per-file outputs):
cat extra.txt | sanitize - data.log -s secrets.yaml

# Mix stdin with an archive (stdin sanitized to stdout; archive gets its own output file):
cat extra.log | sanitize - backup.zip -s secrets.yaml

# Archive and plain file together (each gets its own output file):
sanitize backup.zip config.yaml -s secrets.yaml
# Produces: backup.sanitized.zip  config-sanitized.yaml

# Filter archive entries — keep only files under config/:
sanitize backup.zip --only 'config/' -s secrets.yaml

# Filter by glob — keep only JSON files at any depth:
sanitize backup.zip --only '**/*.json' -s secrets.yaml

# Filter by exact full path (paths are stored as-is inside the archive):
sanitize test.zip --only test/test.config -s secrets.yaml

# Combine --only and --exclude: keep JSON, drop secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml

# Drop all log files from the output archive:
sanitize backup.zip --exclude '**/*.log' -s secrets.yaml

# Per-archive filters — each archive has independent --only / --exclude:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Plain file alongside a filtered archive:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (with only logs/ entries)

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

> **Note on regex patterns:** When `kind` is `"regex"`, the `pattern` field is compiled as a Rust regular expression. Metacharacters (`.`, `*`, `+`, `?`, `(`, `)`, `[`, `]`, `{`, `}`, `\`, `^`, `$`, `|`) must be escaped with a backslash to match literally. When `kind` is `"literal"`, the pattern is treated as exact text — no manual escaping is needed.

At runtime, literal patterns are matched by an Aho-Corasick automaton (single multi-literal scan), while regex patterns are matched via `RegexSet` pre-filtering plus per-pattern regex scans. Each match triggers a one-way replacement through the `MappingStore`, formatted according to the pattern's category.

---

## Examples

**Sanitize a single file (interactive password prompt):**

```bash
sanitize data.log -s secrets.enc --encrypted-secrets --password
```

**Structured field-level sanitization with a profile:**

```bash
# Sanitize only the password and username fields in config YAML files:
sanitize config.yaml -s secrets.yaml --profile profile.yaml

# Process a config file and log file together:
# values found in config.yaml are also replaced in app.log
sanitize config.yaml app.log --profile profile.yaml -s secrets.yaml
```

**Deterministic mode with profile (saves discovered values to secrets file):**

```bash
# First run: discovers "hunter2" as a password, appends it to secrets.yaml
SANITIZE_PASSWORD=secret sanitize config.yaml \
  --profile profile.yaml --deterministic --secrets-file secrets.yaml

# Second run against a log: "hunter2" is now in secrets.yaml and gets
# the same replacement as in the first run
SANITIZE_PASSWORD=secret sanitize app.log \
  --deterministic --secrets-file secrets.yaml
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc --encrypted-secrets --password -d
```

**Process a tar.gz archive with strict error handling:**

```bash
sanitize backup.tar.gz -s s.enc --encrypted-secrets --password -o backup.sanitized.tar.gz --strict
```

**Filter archive entries — keep only files under a specific path:**

```bash
# Exact full path (paths are stored as-is inside the archive, e.g. test/test.config):
sanitize test.zip --only test/test.config -s secrets.yaml

# Keep all JSON files at any depth (**/ crosses directory boundaries):
sanitize backup.zip --only '**/*.json' -s secrets.yaml

# Keep an entire directory subtree (trailing / = directory-prefix match):
sanitize backup.zip --only 'config/' -s secrets.yaml

# Drop all log files:
sanitize backup.zip --exclude '**/*.log' -s secrets.yaml

# Combine: keep JSON files, then drop the secrets file:
sanitize backup.zip --only '**/*.json' --exclude config/secrets.json -s secrets.yaml
```

**Per-archive filters — each archive in a multi-input command is filtered independently:**

```bash
# a.zip keeps only config/; b.tar.gz keeps only *.log files:
sanitize a.zip --only 'config/' b.tar.gz --only '**/*.log' -s secrets.yaml

# Plain file alongside a filtered archive:
sanitize report.txt backup.zip --only 'logs/' -s secrets.yaml
# Produces: report-sanitized.txt  backup.sanitized.zip (logs/ entries only)
```

**Mix stdin with file and archive inputs:**

```bash
# stdin goes to stdout; each file/archive gets its own output file:
cat extra.log | sanitize - backup.zip --only 'logs/' config.yaml -s secrets.yaml
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
