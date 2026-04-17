# Architecture

> **sanitize-engine** v0.2.0 — Deterministic, one-way data sanitization.

This document describes the internal architecture of the sanitization
engine.  It is aimed at contributors and operators who need to
understand data-flow, concurrency, and security boundaries.

---

## 1. High-Level Data Flow

```
┌─────────────┐                 ┌───────────────────────┐
│  CLI args    │  ──────────▶   │    sanitize  (bin)     │
│  [INPUT]     │                │  ┌─────────────────┐   │
│  -o/--output │                │  │ Signal handler   │   │
│  -s/--secrets-│                │  │ Tracing init     │   │
│    file      │                │  │ Thread pool      │   │
└─────────────┘                 │  └────────┬────────┘   │
                                │           │            │
                      ┌─────────▼──────────────────────┐ │
                      │  Is it an archive?             │ │
                      │  (.tar / .tar.gz / .zip)       │ │
                      └──┬─────────────────┬───────────┘ │
                    YES  │                 │  NO         │
          ┌──────────────▼──────┐   ┌──────▼──────────┐  │
          │ ArchiveProcessor    │   │ StreamScanner   │  │
          │ (per-entry routing) │   │ (chunk+overlap) │  │
          └──────────┬──────────┘   └──────┬──────────┘  │
                     │                     │             │
         ┌───────────▼─────────────────────▼──────────┐  │
         │          MappingStore (DashMap)             │  │
         │  ┌──────────────┐  ┌─────────────────────┐ │  │
         │  │ ForwardMap   │  │ ReplacementGenerator │ │  │
         │  │ val → repl   │  │ (HMAC / Random)      │ │  │
         │  └──────────────┘  └─────────────────────┘ │  │
         └────────────────────────────────────────────┘  │
                                │                        │
                      ┌─────────▼──────────┐             │
                      │ AtomicFileWriter   │             │
                      │ (tmp → fsync →     │             │
                      │  rename)           │             │
                      └────────────────────┘             │
                                                         │
                      ┌─────────────────────┐            │
                      │ ReportBuilder       │            │
                      │ (JSON summary)      │            │
                      └─────────────────────┘            │
└────────────────────────────────────────────────────────┘
```

### Plain file path

1. Load encrypted secrets → decrypt with password (PBKDF2 + AES-256-GCM).
2. Build `ScanPattern` list from decrypted plain-text entries.
3. Create `StreamScanner` with chunk+overlap configuration.
4. Open input as a `Read`, open output via `AtomicFileWriter`.
5. Call `scan_reader(&mut reader, &mut writer)`.
6. Scanner reads chunks, applies regex set, calls `MappingStore::get_or_insert` for each match, writes sanitized chunks to the writer.
7. On success, `AtomicFileWriter::finish()` fsyncs + renames. On error/signal, temp file is cleaned up by `Drop`.

### Archive path

1. Detect format from extension (`.tar`, `.tar.gz`, `.zip`).
2. `ArchiveProcessor` iterates entries; for each regular file:
   - Try structured processor match (JSON / YAML / XML / CSV / KeyValue) via `ProcessorRegistry::find_processor`.
   - If matched and within `MAX_STRUCTURED_ENTRY_SIZE`, parse + walk + replace field values.
   - Otherwise fall back to `StreamScanner::scan_reader` for byte-level replacement.
3. Rebuild the archive with sanitized content and preserved metadata.

### Encrypt / Decrypt subcommands

The `sanitize encrypt` and `sanitize decrypt` subcommands handle
secrets file management. These are simple linear flows that do not
involve the scanning/replacement pipeline:

- **`sanitize encrypt <IN> <OUT>`** — reads a plaintext secrets file,
  optionally validates it, encrypts with AES-256-GCM (PBKDF2 key
  derivation), and writes the ciphertext atomically.
- **`sanitize decrypt <IN> <OUT>`** — reads an encrypted secrets file,
  decrypts, optionally validates the resulting plaintext, and writes
  atomically.

Both subcommands resolve the password through a unified chain:
`--password` flag → `--password-file` (with Unix permission enforcement)
→ `SANITIZE_PASSWORD` env var → interactive terminal prompt (masked
input via `rpassword`).

---

## 2. Module Map

| Module | Responsibility |
|--------|---------------|
| `scanner` | Streaming regex scanner with configurable chunk/overlap. Memory-bounded reads. |
| `store` | `DashMap`-backed dedup cache. `get_or_insert` is the single entry-point. Capacity-limited. |
| `generator` | `ReplacementGenerator` trait. Two impls: `HmacGenerator` (deterministic), `RandomGenerator` (CSPRNG). |
| `strategy` | Category-specific formatting (email, IPv4, phone, etc.). Pure functions, no I/O. |
| `category` | `Category` enum. Drives domain separation in HMAC and replacement format selection. |
| `secrets` | AES-256-GCM encrypted secrets file format. PBKDF2 key derivation. Zeroizes plaintext on drop. |
| `processor::*` | Format-aware processors: JSON, YAML, XML, CSV, KeyValue. Each implements `Processor` trait. |
| `processor::archive` | Tar / tar.gz / zip processing. Per-entry structured-or-scanner routing. |
| `processor::registry` | `ProcessorRegistry` — maps processor names to `Arc<dyn Processor>`. |
| `processor::profile` | `FileTypeProfile` + `FieldRule` — user-supplied rules for structured processing. |
| `report` | Thread-safe `ReportBuilder` producing a JSON summary of the sanitization run. |
| `error` | `SanitizeError` enum + `Result<T>` alias. |
| `atomic` | `AtomicFileWriter` — crash-safe output via temp + fsync + rename. |

---

## 3. Streaming Model

The scanner never holds the entire file in memory. It reads fixed-size
**chunks** (default 1 MiB) with a configurable **overlap** (default
4 KiB). The overlap ensures that a sensitive value straddling a chunk
boundary is still detected.

```
Chunk N:     [===========================|overlap|]
Chunk N+1:                         [overlap|===========================|overlap|]
```

After scanning a chunk, only the overlap window is retained; the rest
is flushed to the writer. Peak memory per file ≈ `chunk_size + overlap`.

For structured processors (JSON, YAML, …) the entry content must fit
in memory (gated by `MAX_STRUCTURED_ENTRY_SIZE`). Oversized entries
fall through to the streaming scanner.

---

## 4. Concurrency Model

- **`MappingStore`** uses `DashMap` (striped read-write locks). Multiple
  threads can call `get_or_insert` concurrently; per-shard locking keeps
  contention low.
- **All public types are `Send + Sync`.**
- The CLI caps the thread pool to `min(--threads, available_parallelism)`
  to avoid oversubscription.
- Archive entries are currently processed **sequentially** within a
  single archive to preserve ordering determinism.

---

## 5. Replacement Pipeline

```
Input value  ──▶  MappingStore::get_or_insert
                       │
                 ┌─────▼──────────┐
                 │ Already cached? │
                 └──┬──────────┬──┘
                  YES          NO
                   │            │
                   │    ┌───────▼──────────────┐
                   │    │ Strategy::generate()  │
                   │    │ (HMAC or Random seed  │
                   │    │  + category format)   │
                   │    └───────┬──────────────┘
                   │            │
                   │    ┌───────▼──────┐
                   │    │ Insert into  │
                   │    │ forward map  │
                   │    └───────┬──────┘
                   │            │
                   ▼            ▼
              Return cached replacement
```

- **HMAC mode**: `HMAC-SHA256(seed, category_tag || "\x00" || value)` →
  truncated to category-specific format. Same seed + value always
  produces the same replacement.
- **Random mode**: `OsRng` / `thread_rng()` per invocation. The dedup
  cache still ensures per-run consistency.

---

## 6. Atomic Output Safety

All file outputs go through `AtomicFileWriter`:

1. Write to `<destination>.tmp`.
2. `flush()` + `fsync()` the file descriptor.
3. `rename()` atomically over the destination.
4. If the process exits before `finish()`, `Drop` removes the temp file.

This guarantees that readers never see a partial output file after a
crash or signal interrupt.

---

## 7. Signal Handling

The CLI installs a `SIGINT` / `SIGTERM` handler via the `ctrlc` crate.
A global `AtomicBool` (`INTERRUPTED`) is set on signal. The pipeline
checks `is_interrupted()` before committing output:

- If interrupted **before** `AtomicFileWriter::finish()`, the temp file
  is cleaned up and the process exits with code 130.
- If interrupted **after** commit, the already-written output is valid.

---

## 8. Observability

Logging uses the `tracing` / `tracing-subscriber` stack:

- `--log-format human` (default): human-readable terminal output.
- `--log-format json`: structured JSON lines (machine-parseable).
- Level controlled via `SANITIZE_LOG` env var (e.g.
  `SANITIZE_LOG=debug`).
- **No secret values are ever logged.** Only file names, counts, and
  timing data appear in log output.

---

## 9. Feature Flags

| Feature | Effect |
|---------|--------|
| `bench` | Enables additional `tracing::info!` output for internal metrics (unique mapping count, etc.). Not intended for production. |

---

## 10. Build & Test

```bash
# Run all tests
cargo test

# Run with structured logging
SANITIZE_LOG=debug cargo run -- foo.txt -s secrets.enc -p pw -o foo.sanitized.txt

# Pipe from stdin
echo "sensitive data" | SANITIZE_LOG=debug cargo run -- -s secrets.enc -p pw

# Run benchmarks
cargo bench

# Run fuzz targets (requires cargo-fuzz / nightly)
cargo +nightly fuzz run fuzz_regex
cargo +nightly fuzz run fuzz_json
cargo +nightly fuzz run fuzz_yaml
cargo +nightly fuzz run fuzz_archive
```
