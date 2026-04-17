# Structured Processing

Structured processors parse a file's format (JSON, YAML, XML, CSV, key-value), walk its data structure, and replace only the values at field paths you specify — leaving keys, comments, formatting, and unmatched values untouched. This contrasts with the streaming scanner, which treats the file as raw bytes and replaces pattern matches wherever they appear.

## How the CLI Uses Structured Processing

The CLI **automatically detects** structured files by extension (`.json`, `.yaml`, `.yml`, `.xml`) and applies a **wildcard profile** that matches all fields (`*`). This means every string value in a detected structured file is routed through the replacement engine.

> **Note:** CSV/TSV and key-value formats are **not** auto-detected by file extension like JSON, YAML, and XML. However, they **are** supported through the CLI via the `--format` / `-f` flag (e.g. `-f csv`, `-f key-value`). For programmatic use, create a `FileTypeProfile` with `processor` set to `"csv"` or `"key_value"`.

There is currently no `--profile` CLI flag to supply a custom profile with targeted field rules. To use field-specific profiles (e.g. replace only `password` fields), use the library API directly.

## File-Type Profiles

A `FileTypeProfile` tells the engine which processor to use, which file extensions to match, and which fields to sanitize.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `processor` | Yes | — | Processor name: `"key_value"`, `"json"`, `"yaml"`, `"xml"`, or `"csv"`. |
| `extensions` | No | `[]` | File extensions this profile applies to (e.g. `[".rb", ".conf"]`). Used for filename-based matching. |
| `fields` | Yes | — | Array of field rules specifying which keys/paths to sanitize. |
| `options` | No | `{}` | Free-form key-value map of processor-specific options. |

Example profile (JSON):

```json
{
  "processor": "key_value",
  "extensions": [".rb", ".conf"],
  "fields": [
    { "pattern": "*.password", "category": "custom:password" },
    { "pattern": "*.secret",   "category": "custom:secret" },
    { "pattern": "smtp_address", "category": "hostname" }
  ],
  "options": {
    "delimiter": "=",
    "comment_prefix": "#"
  }
}
```

## Field Rules

Each field rule specifies a key pattern to match and an optional category and label.

| Field | Required | Default | Description |
|-------|----------|---------|-------------|
| `pattern` | Yes | — | Key pattern to match (see pattern syntax below). |
| `category` | No | `"custom:field"` | Category for replacement generation. Accepts any built-in category (`email`, `hostname`, `ipv4`, etc.) or `custom:<tag>`. |
| `label` | No | — | Human-readable label for reporting. |

### Pattern Syntax

| Pattern | Matches | Example |
|---------|---------|---------|
| `"password"` | Exact key `password` | `password = "s3cret"` |
| `"database.password"` | Exact dotted path `database.password` | `{"database": {"password": "..."}}` |
| `"*.password"` | Any key ending in `.password`, or the key `password` itself | `db.password`, `smtp.password`, `password` |
| `"db.*"` | Any key starting with `db.` | `db.host`, `db.password`, `db.port` |
| `"*"` | Every field | Matches all keys |

Patterns are matched against the full key path. For nested structures, the path is built by joining keys with `.` (JSON/YAML), `/` (XML), or the literal key string (key-value files).

## Processor-Specific Options

Each processor accepts options via the profile's `options` map.

### Key-Value Processor (`"key_value"`)

Handles line-oriented `key = value` configuration files. Preserves blank lines, comments, indentation, and quoting style (single, double, or unquoted).

| Option | Default | Description |
|--------|---------|-------------|
| `delimiter` | `"="` | The key-value separator string. |
| `comment_prefix` | `"#"` | Lines starting with this prefix (after whitespace) are treated as comments and preserved as-is. |

**Key path convention:** The key is the literal text to the left of the delimiter (trimmed). For files like `gitlab_rails['smtp_password'] = "value"`, the field rule pattern is the full key string: `gitlab_rails['smtp_password']`.

### JSON Processor (`"json"`)

Parses JSON, walks the value tree, and replaces matched string values. Arrays are traversed transparently — a rule for `users.email` matches `email` inside every object in the `users` array.

| Option | Default | Description |
|--------|---------|-------------|
| `compact` | `"false"` | Set to `"true"` for compact (single-line) JSON output. Otherwise outputs pretty-printed JSON. |

**Key path convention:** Dot-separated paths: `database.password`, `smtp.credentials.user`. Numbers and booleans matched by a field rule are converted to strings after replacement.

### YAML Processor (`"yaml"`)

Parses YAML, walks the value tree with the same dot-separated key paths and array traversal as JSON. Minor formatting differences from the original are possible (serde_yaml normalizes some whitespace).

No processor-specific options.

**Key path convention:** Same as JSON — dot-separated paths: `database.password`.

### XML Processor (`"xml"`)

Uses streaming XML parsing to rewrite documents. Preserves document structure, attributes, and non-matched content.

No processor-specific options.

**Key path convention:** Slash-separated element paths: `database/password`. Attributes use the `element/@attr` syntax: `connection/@host`.

### CSV Processor (`"csv"`)

Parses CSV/TSV, replaces values in specified columns by header name, and writes back preserving the delimiter.

| Option | Default | Description |
|--------|---------|-------------|
| `delimiter` | `","` | Field delimiter (single ASCII character). Use `"\t"` for TSV. |
| `has_header` | `"true"` | Whether the first row is a header row. When `"true"`, field rules match by header column name. When `"false"`, field rules match by column index as a string (`"0"`, `"1"`, etc.). |

**Key path convention:** Header column names (e.g. `email`, `name`). Without headers, use column index strings (`"0"`, `"1"`).

## Structured Processing vs Literal Secrets

Both approaches produce **length-preserving, one-way replacements** through the same `MappingStore` — the same input value always gets the same replacement within a run.

| | Literal Secret (StreamScanner) | Structured Processor |
|---|---|---|
| **Targeting** | Replaces the pattern **everywhere** it appears — in values, keys, comments, logs, any byte position | Replaces only **matched field values** — keys, comments, and unmatched fields are preserved |
| **Setup** | Add an entry to the secrets file | Define a `FileTypeProfile` with field rules (library API) |
| **Format awareness** | None — treats input as raw bytes | Full — preserves JSON/YAML/XML/CSV/key-value structure |
| **Performance** | Faster — O(n) streaming with no parsing overhead | Slower — requires parsing, tree walking, and serialization |
| **Memory** | Constant — bounded by chunk size (~1 MiB) | Proportional to file size (full file loaded for parsing) |
| **File size limit** | None (streaming) | 256 MiB default (`--max-structured-size`); larger files fall back to streaming |
| **Best for** | Known secret values you want scrubbed everywhere (hostnames, tokens, emails) | Config files where you want to sanitize specific fields while leaving structure intact |

**When to use which:**

- **Use literal secrets** when you know the exact sensitive values (e.g. `test.test.co`, `sk-proj-abc123`) and want them replaced anywhere they appear, regardless of file format.
- **Use structured processing** when you have config files with known field names (e.g. `password`, `smtp_address`) and want to sanitize those fields across many files without listing every possible value.
- **Use both** for defence in depth: structured processing for known config formats + literal secrets to catch values that leak into unstructured files like logs.

## Nested Archives

The archive processor **recursively** processes nested archives (e.g. a `.tar.gz` inside a `.zip`). All supported format combinations are handled: zip-in-tar, tar-in-zip, tar.gz-in-zip, and so on.

Recursion is bounded by a configurable **maximum nesting depth** (default: 3, maximum: 10). If an archive entry at or beyond the depth limit is itself an archive, processing stops with a `RecursionDepthExceeded` error. Use the `--max-archive-depth` CLI flag to adjust this limit.

Each nesting level buffers the inner archive in memory (up to 256 MiB per level). At the default depth of 3, worst-case peak memory for nested archive buffers is ~768 MiB. The shared `MappingStore` ensures dedup consistency across all nesting levels — the same secret produces the same replacement regardless of where it appears in the hierarchy.

## Library API Example

```rust
use sanitize_engine::category::Category;
use sanitize_engine::generator::HmacGenerator;
use sanitize_engine::processor::key_value::KeyValueProcessor;
use sanitize_engine::processor::profile::{FieldRule, FileTypeProfile};
use sanitize_engine::processor::Processor;
use sanitize_engine::store::MappingStore;
use std::sync::Arc;

// Create the replacement store.
let generator = Arc::new(HmacGenerator::new([42u8; 32]));
let store = MappingStore::new(generator, None);

// Define which fields to sanitize.
let profile = FileTypeProfile::new(
    "key_value",
    vec![
        FieldRule::new("server_config")
            .with_category(Category::Hostname),
        FieldRule::new("*.password")
            .with_category(Category::Custom("password".into())),
    ],
)
.with_option("delimiter", "=")
.with_option("comment_prefix", "#");

// Process a config file.
let input = br#"# Server settings
server_config = "test.test.co"
server_port = 8080
db_password = "s3cret"
"#;

let processor = KeyValueProcessor;
let output = processor.process(input, &profile, &store).unwrap();
let result = String::from_utf8(output).unwrap();

// server_config and db_password values are replaced;
// server_port and comments are preserved.
```
