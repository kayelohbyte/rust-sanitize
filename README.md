# sanitize-engine

[![CI](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml/badge.svg)](https://github.com/kayelohbyte/rust-sanitize/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/sanitize-engine.svg)](https://crates.io/crates/sanitize-engine)
[![docs.rs](https://docs.rs/sanitize-engine/badge.svg)](https://docs.rs/sanitize-engine)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rust-1.74%2B-blue.svg)]()

Deterministic, one-way data sanitization engine and CLI tool.

`sanitize-engine` scans files and archives for sensitive data — emails, IP addresses, API keys, credentials, and other secrets — and replaces every match with a category-aware, structurally plausible substitute. Replacements are one-way within the system design: no reverse mapping is stored or recoverable from sanitized output alone. There is no restore mode.

## Intended Audience

- Security and compliance teams sanitizing production data for safe sharing.
- CI/CD pipelines that must fail when secrets leak into configuration or logs.
- Developers preparing realistic but non-sensitive test datasets.

## Core Differentiators

- **One-way only.** No mapping file, no restore mode. Forward map lives in process memory and is zeroized on drop.
- **Deterministic or random.** HMAC-SHA256 seeded mode produces identical replacements across runs; CSPRNG mode produces fresh replacements each run (still consistent within a single run via dedup cache).
- **Streaming architecture.** Processes 20–100 GB+ files in bounded memory via configurable chunk + overlap scanning.
- **Format-aware processing.** Structured processors for JSON, YAML, XML, CSV, and key-value files replace only matched field values while preserving document structure.
- **Archive support.** Tar, tar.gz, and zip archives are processed entry-by-entry with automatic format detection and metadata preservation.
- **Zero `unsafe` code.** The entire crate contains no `unsafe` blocks.

---

## Design Principles

1. **One-way only.** No reverse mappings, no restore mode. Security by elimination.
2. **Deterministic reproducibility.** Same seed + same input = same output, across machines and runs.
3. **Format-aware.** Replace values, not structure. JSON stays valid JSON; YAML stays valid YAML.
4. **Streaming-first.** Constant memory regardless of file size. Process 100 GB files on a 512 MB machine.
5. **Zero `unsafe`.** Thread safety through `DashMap` and `Arc`, not pointer arithmetic.
6. **Defence in depth.** Input size caps, regex automaton limits, depth limits, node-count caps — every parser has a budget.

---

## Quick Start

```bash
# 1. Create a plaintext secrets file:
cat > secrets.json <<'EOF'
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
EOF

# 2. Encrypt it (recommended for production):
sanitize encrypt secrets.json secrets.json.enc --password "my-password"

# 3. Remove the plaintext:
rm secrets.json

# 4. Sanitize a file (prefer env var over --password for passwords):
export SANITIZE_PASSWORD="my-password"
sanitize data.log -s secrets.json.enc -o output.log

# 5. Or write to stdout (default) and redirect:
sanitize data.log -s secrets.json.enc > output.log

# 6. CI gate — fail the build if secrets are detected:
sanitize config.yaml -s secrets.json.enc --fail-on-match
```

### Quick Start — Stdin Pipes

You can pipe data directly into `sanitize`:

```bash
# Pipe from grep:
grep "error" app.log | sanitize -s secrets.json -p hunter2

# Read from stdin, write sanitized output to a file:
cat data.csv | sanitize -s secrets.enc -p pw -f csv -o clean.csv

# Chain with other tools:
mysqldump mydb | sanitize -s secrets.enc -p pw | gzip > dump.sql.gz
```

### Quick Start — Plaintext Secrets (no encryption)

Encryption is recommended but not required. You can use a plaintext secrets file directly:

```bash
# Use a plaintext JSON/YAML/TOML secrets file (auto-detected):
sanitize data.log -s secrets.json

# Or explicitly skip encryption with --unencrypted-secrets:
sanitize data.log -s secrets.json --unencrypted-secrets

# Deterministic mode works the same way:
sanitize data.csv -s secrets.json -d
```

No password or `SANITIZE_PASSWORD` env var is needed when using plaintext secrets. Memory hygiene (zeroization of parsed entries) is preserved.

---

## Installation

### From crates.io

```bash
cargo install sanitize-engine
```

### From source

```bash
git clone https://github.com/kayelohbyte/rust-sanitize.git
cd rust-sanitize
cargo build --release
```

Binaries are placed at `target/release/sanitize`.

### As a library

```bash
cargo add sanitize-engine
```

```rust
use sanitize_engine::category::Category;
use sanitize_engine::generator::HmacGenerator;
use sanitize_engine::store::MappingStore;
use std::sync::Arc;

// Create a deterministic generator with a fixed seed.
let generator = Arc::new(HmacGenerator::new([42u8; 32]));

// Create the replacement store (optional capacity limit).
let store = MappingStore::new(generator, None);

// Sanitize a value (one-way).
let sanitized = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert!(sanitized.contains("@corp.com"));
assert_eq!(sanitized.len(), "alice@corp.com".len());

// Same input → same output (per-run consistency).
let again = store.get_or_insert(&Category::Email, "alice@corp.com").unwrap();
assert_eq!(sanitized, again);
```

### Requirements

- Rust 1.74 or later (stable toolchain)

---

## Documentation

| Document | Description |
|----------|-------------|
| [CLI Reference](docs/cli-reference.md) | Full `sanitize` command reference (including `encrypt` and `decrypt` subcommands), secrets file format, and usage examples. |
| [Structured Processing](docs/structured-processing.md) | File-type profiles, field rules, processor-specific options, and structured vs literal comparison. |
| [Supported Categories](docs/categories.md) | All 18 built-in replacement categories with strategies and examples, plus custom categories. |
| [Pluggable Strategies](docs/strategies.md) | The `Strategy` trait, 5 built-in strategies, and guide to writing custom strategies. |
| [Library API Reference](docs/api-reference.md) | Module-by-module public API tables (scanner, store, generator, strategy, processor, archive, report, atomic, secrets, error, category). |
| [Defensive Limits & Streaming](docs/defensive-limits.md) | Streaming chunking model, archive processing flow, and all defensive size/depth/count limits. |
| [Architecture](ARCHITECTURE.md) | Internal architecture, data flow diagrams, module map, concurrency model, and streaming design. |
| [Security](SECURITY.md) | Security properties, threat mitigations, encryption details, zeroization strategy, and threat model. |
| [Contributing](CONTRIBUTING.md) | Build instructions, test suite, fuzz targets, linting, and PR guidelines. |
| [Changelog](CHANGELOG.md) | Release history and version notes. |

---

## Supported Formats

| Format | Processor | Detection |
|--------|-----------|-----------|
| Plain text | `StreamScanner` (chunk + overlap) | Default fallback for all files |
| JSON | `JsonProcessor` | Profile match or `{`/`[` heuristic |
| YAML | `YamlProcessor` | Profile match or `---`/`- `/`: ` heuristic |
| XML | `XmlProcessor` | Profile match or `<?xml`/`<` heuristic |
| CSV / TSV | `CsvProcessor` | Profile match only |
| Key-value | `KeyValueProcessor` | Profile match only |
| Tar | `ArchiveProcessor` | `.tar` extension |
| Tar.gz / .tgz | `ArchiveProcessor` | `.tar.gz` / `.tgz` extension |
| Zip | `ArchiveProcessor` | `.zip` extension |

---

## Security Model

Replacements are one-way within the system design. No reverse mapping is stored or recoverable from sanitized output alone. The `MappingStore` forward map lives only in process memory, is never persisted to disk, and is zeroized on drop. There is no restore or decrypt-output mode.

Key security properties:

- **Encryption at rest** — Secrets files are encrypted with AES-256-GCM (PBKDF2-HMAC-SHA256, 600 000 iterations). Plaintext secrets are also supported.
- **Zeroization** — HMAC keys, secret entries, mapping store keys, and decrypted blobs are zeroized on drop.
- **Regex hardening** — Per-pattern automaton and DFA size limits (1 MiB each) prevent ReDoS and unbounded memory.
- **Defensive limits** — Input size caps, recursion depth limits, node-count caps, and pattern count limits bound every parser.
- **Zero `unsafe`** — Thread safety through `DashMap` and `Arc`. `Send + Sync` bounds verified at compile time.

For the full security model, threat mitigations, and out-of-scope threats, see [SECURITY.md](SECURITY.md).

---

## Examples

**Sanitize a single file:**

```bash
sanitize data.log -s secrets.enc -p hunter2
```

**Write output to a file:**

```bash
sanitize data.log -s secrets.enc -p hunter2 -o output.log
```

**Pipe from another command:**

```bash
grep "error" app.log | sanitize -s secrets.enc -p hunter2
```

**Deterministic mode (same seed → same replacements every run):**

```bash
sanitize data.csv -s s.enc -p pw -d
```

**Fail CI if secrets are detected:**

```bash
sanitize config.yaml -s s.enc -p pw --fail-on-match
```

See [docs/cli-reference.md](docs/cli-reference.md) for the complete set of examples including archive processing, stdin pipes, dry-run, plaintext secrets, and custom chunk sizes.

> **Security note:** Prefer `-P` / `--password-file` or the `SANITIZE_PASSWORD` environment variable over `-p` / `--password` to avoid exposing the password in process listings and shell history.

---

## Limitations

- **No restore.** Replacements are one-way by design. There is no undo, decrypt-output, or reverse-mapping capability.
- **Deterministic mode caveats.** Deterministic replacements require the same secrets key and the same secret values to produce identical output. Changing the secrets file or key produces entirely different replacements.
- **Structured fallback.** Files exceeding structured processor size limits silently fall back to the streaming scanner. The streaming scanner performs byte-level regex replacement and does not understand document structure — it may match inside JSON keys, XML tags, or other structural elements.
- **YAML formatting.** `serde_yaml` normalizes some whitespace during serialization. Minor formatting differences from the original are possible.
- **Zeroization scope.** Zeroization covers secrets, HMAC keys, and mapping store keys. It does not cover incidental copies the Rust compiler may create (e.g. during optimization passes). This is an inherent limitation of safe Rust zeroization.
- **Sequential archive processing.** Archive entries are processed sequentially (not in parallel) to preserve deterministic ordering.
- **Binary detection.** Entries detected as binary are skipped by default. Use `--include-binary` to override.

---

## Security Disclosure

If you discover a security vulnerability in this project, please report it responsibly. Do not open a public issue for security-sensitive findings.

Contact the maintainers via the security contact configured in the repository. If no security contact is listed, open a private security advisory through the repository hosting platform or contact the maintainers directly via the email address in `Cargo.toml` or commit history.

Include:

- Description of the vulnerability.
- Steps to reproduce.
- Potential impact assessment.

Maintainers will acknowledge receipt within 5 business days and aim to provide a fix or mitigation timeline within 30 days.

---

## Stability

This project follows [Semantic Versioning](https://semver.org/). While below
1.0, breaking changes will bump the minor version.

- **Stable guarantees:** One-way replacement, deterministic mode (same seed →
  same output), length preservation, encrypted secrets format.
- **May evolve:** CLI flag names, report JSON schema, processor heuristics,
  default limit values.

See [CHANGELOG.md](CHANGELOG.md) for release history.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for
the full text.
