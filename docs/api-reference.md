# Library API Reference

All public types are re-exported from the crate root (`sanitize_engine::*`) for convenience. The table below summarises every module and its key exports.

## Scanner Module (`scanner`)

| Type / Function | Description |
|-----------------|-------------|
| `StreamScanner` | Streaming regex scanner. Processes input in chunks with overlap to catch boundary-straddling matches. |
| `StreamScanner::new(patterns, store, config)` | Create a scanner from a `Vec<ScanPattern>`, a `MappingStore`, and a `ScanConfig`. |
| `StreamScanner::new_with_max_patterns(patterns, store, config, max_patterns)` | Same as `new()` but with a custom pattern count limit (default: 10 000). |
| `StreamScanner::from_encrypted_secrets(bytes, password, format, store, config, extra)` | Convenience constructor that decrypts a secrets file and builds patterns. Returns `(scanner, warnings)`. |
| `StreamScanner::from_plaintext_secrets(plaintext, format, store, config, extra)` | Convenience constructor that parses a plaintext secrets file and builds patterns. Returns `(scanner, warnings)`. |
| `StreamScanner::scan_reader(reader, writer)` | Scan a `Read` stream, writing sanitized output to a `Write` stream. Returns `ScanStats`. |
| `StreamScanner::scan_bytes(input)` | Scan an in-memory byte slice. Returns `(Vec<u8>, ScanStats)`. |
| `StreamScanner::pattern_count()` | Number of compiled patterns. |
| `StreamScanner::config()` / `store()` | Accessors for the scanner's config and mapping store. |
| `ScanPattern` | A single detection pattern with category and label. |
| `ScanPattern::from_regex(pattern, category, label)` | Create from a regex string. |
| `ScanPattern::from_literal(literal, category, label)` | Create from a literal string (auto-escaped). |
| `ScanConfig` | Configuration for chunk size and overlap size. |
| `ScanConfig::new(chunk_size, overlap_size)` | Explicit construction. |
| `ScanConfig::default()` | Defaults: 1 MiB chunk, 4 KiB overlap. |
| `ScanConfig::validate()` | Validate that `chunk_size > 0` and `overlap_size < chunk_size`. |
| `ScanStats` | Results of a scan: `bytes_processed`, `bytes_output`, `matches_found`, `replacements_applied`, `pattern_counts: HashMap<String, u64>`. |

## Store Module (`store`)

| Type / Function | Description |
|-----------------|-------------|
| `MappingStore` | Thread-safe, one-way replacement cache backed by `DashMap` (64 shards). |
| `MappingStore::new(generator, capacity_limit)` | Create with a generator and optional max entries. |
| `MappingStore::with_expected_capacity(generator, capacity_limit, expected)` | Pre-allocate for an expected number of unique values. |
| `MappingStore::get_or_insert(category, original)` | Primary API: returns cached replacement or generates and caches a new one. Atomic first-writer-wins. |
| `MappingStore::forward_lookup(category, original)` | Read-only lookup without insert. |
| `MappingStore::len()` / `is_empty()` | Current entry count. |
| `MappingStore::clear()` | Zeroize and remove all entries. |
| `MappingStore::iter()` | Iterator over `(Category, original, replacement)` triples. |

## Generator Module (`generator`)

| Type / Function | Description |
|-----------------|-------------|
| `ReplacementGenerator` | Trait: `fn generate(&self, category: &Category, original: &str) -> String`. Must be `Send + Sync`. |
| `HmacGenerator` | Deterministic generator using `HMAC-SHA256(key, category_tag \|\| "\x00" \|\| original)`. Key is zeroized on drop. |
| `HmacGenerator::new(key: [u8; 32])` | Create from a 32-byte key. |
| `HmacGenerator::from_slice(bytes)` | Create from a byte slice (must be exactly 32 bytes). |
| `RandomGenerator` | Non-deterministic generator using OS CSPRNG (`thread_rng`). |
| `RandomGenerator::new()` | Create a new random generator. |

## Strategy Module (`strategy`)

| Type / Function | Description |
|-----------------|-------------|
| `Strategy` | Trait: `fn name(&self) -> &str` + `fn replace(&self, original: &str, entropy: &[u8; 32]) -> String`. Object-safe. |
| `StrategyGenerator` | Adapter: bridges `Strategy` → `ReplacementGenerator` with configurable entropy. |
| `EntropyMode` | Enum: `Deterministic { key: [u8; 32] }` or `Random`. |
| `RandomString`, `RandomUuid`, `FakeIp`, `PreserveLength`, `HmacHash` | Five built-in strategy implementations (see [Pluggable Strategies](strategies.md)). |

## Processor Module (`processor`)

| Type / Function | Description |
|-----------------|-------------|
| `Processor` | Trait: `fn name()`, `fn can_handle(content, profile)`, `fn process(content, profile, store)`. Must be `Send + Sync`. |
| `ProcessorRegistry` | Maps processor names to `Arc<dyn Processor>`. `ProcessorRegistry::with_builtins()` pre-loads all five processors. |
| `FileTypeProfile` | Associates a processor name, file extensions, field rules, and options. |
| `FieldRule` | A field pattern + optional category and label. |

## Archive Module (`processor::archive`)

| Type / Function | Description |
|-----------------|-------------|
| `ArchiveProcessor` | Processes `.tar`, `.tar.gz`, and `.zip` archives entry-by-entry. Routes entries to structured processors or the streaming scanner. Recursively processes nested archives up to a configurable depth. |
| `ArchiveProcessor::new(registry, scanner, store, profiles)` | Create from a `ProcessorRegistry`, `StreamScanner`, `MappingStore`, and file-type profiles. |
| `ArchiveProcessor::with_max_depth(depth)` | Builder method: set the maximum nesting depth for recursive archive processing (clamped to `MAX_ALLOWED_ARCHIVE_DEPTH`). |
| `ArchiveProcessor::with_parallel_threshold(threshold)` | Builder method: set the minimum file-entry count required to enable parallel entry sanitization. Default: `4`. Set to `usize::MAX` to disable entry-level parallelism (e.g. when outer file-level parallelism already saturates the thread budget). |
| `ArchiveFormat` | Enum: `Tar`, `TarGz`, `Zip`. |
| `ArchiveStats` | Processing results: `files_processed`, `entries_skipped`, `structured_hits`, `scanner_fallback`, `nested_archives`, `total_input_bytes`, `total_output_bytes`, `file_methods`, `file_scan_stats`. |
| `DEFAULT_MAX_ARCHIVE_DEPTH` | Default maximum nesting depth for recursive archive processing (`3`). |

## Report Module (`report`)

| Type / Function | Description |
|-----------------|-------------|
| `SanitizeReport` | Top-level report: `metadata`, `summary`, `files: Vec<FileReport>`. |
| `SanitizeReport::to_json()` / `to_json_pretty()` | Serialize to compact or pretty-printed JSON. |
| `ReportMetadata` | Run parameters: `version`, `timestamp`, `deterministic`, `dry_run`, `strict`, `chunk_size`, `threads`, `secrets_file`. |
| `ReportSummary` | Aggregated summary: `total_files`, `total_matches`, `total_replacements`, `total_bytes_processed`, `total_bytes_output`, `duration_ms`, `pattern_counts`. |
| `ReportBuilder` | Thread-safe report builder. `record_file()` adds entries; `finish()` computes duration and returns `SanitizeReport`. |
| `FileReport` | Per-file results: `path`, `matches`, `replacements`, byte counts, `pattern_counts`, `method` (e.g. `"scanner"`, `"structured:json"`). |

## Atomic I/O Module (`atomic`)

| Type / Function | Description |
|-----------------|-------------|
| `AtomicFileWriter` | Crash-safe file writer: writes to a temp file, calls `fsync`, then atomically renames to the destination. On drop without `finish()`, cleans up the temp file. Implements `std::io::Write`. |
| `AtomicFileWriter::new(dest)` | Create and open a temp file in the same directory as `dest`. |
| `AtomicFileWriter::finish()` | Flush, sync, and atomically rename to destination. |
| `atomic_write(dest, data)` | Convenience: write `&[u8]` atomically to a path in one call. |

## Secrets Module (`secrets`)

| Type / Function | Description |
|-----------------|-------------|
| `SecretEntry` | A single secret: `pattern`, `kind` (`"regex"` or `"literal"`), `category`, `label`. Zeroized on drop. |
| `SecretsFormat` | Enum: `Json`, `Yaml`, `Toml`. |
| `load_secrets_auto(data, password, format, force_plaintext)` | Detect encrypted vs plaintext and load secret patterns accordingly. Returns `(PatternCompileResult, was_encrypted)`. |
| `looks_encrypted(data)` | Heuristic: returns `true` if the data does not look like plaintext JSON/YAML/TOML (i.e. it's likely encrypted). |
| `encrypt_secrets(plaintext, password)` | Encrypt a byte slice with AES-256-GCM (PBKDF2 key derivation). |
| `decrypt_secrets(encrypted, password)` | Decrypt and return `Zeroizing<Vec<u8>>`. |
| `parse_secrets(content, format)` | Parse plaintext secrets into `Vec<SecretEntry>`. |
| `serialize_secrets(entries, format)` | Serialize `Vec<SecretEntry>` back to JSON, YAML, or TOML bytes. |
| `entries_to_patterns(entries)` | Convert `Vec<SecretEntry>` to `(Vec<ScanPattern>, warnings)`. Patterns that fail to compile are skipped and returned in warnings. |
| `parse_category(s)` | Parse a category string (`"email"`, `"custom:tag"`, etc.) into a `Category`. |

## Error Module (`error`)

| Type | Description |
|------|-------------|
| `SanitizeError` | Non-exhaustive error enum: `CapacityExceeded`, `InvalidSeedLength`, `IoError`, `ParseError`, `RecursionDepthExceeded`, `InputTooLarge`, `PatternCompileError`, `InvalidConfig`, `SecretsEmptyPassword`, `SecretsTooShort`, `SecretsDecryptFailed`, `SecretsCipherError(String)`, `SecretsFormatError { format, message }`, `SecretsInvalidUtf8(String)`, `SecretsPasswordRequired`, `ArchiveError`. |
| `Result<T>` | Type alias for `std::result::Result<T, SanitizeError>`. |

## Category Module (`category`)

| Type | Description |
|------|-------------|
| `Category` | Enum with 18 built-in variants (`Email`, `Name`, `Phone`, `IpV4`, `IpV6`, `CreditCard`, `Ssn`, `Hostname`, `MacAddress`, `ContainerId`, `Uuid`, `Jwt`, `AuthToken`, `FilePath`, `WindowsSid`, `Url`, `AwsArn`, `AzureResourceId`) plus `Custom(CompactString)`. |
| `Category::as_str()` | String representation (e.g. `"email"`, `"custom:tag"`). |
