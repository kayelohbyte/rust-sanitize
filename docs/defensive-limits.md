# Defensive Limits & Streaming Scalability

## Streaming Architecture

### Chunking Model

The streaming scanner never holds the entire file in memory. It reads fixed-size **chunks** (default 1 MiB) with an automatically derived **overlap** window (default 4 KiB). The overlap ensures that a sensitive value straddling a chunk boundary is still detected.

The CLI derives overlap from the `--chunk-size` value: `overlap = min(chunk_size, 4096)`, clamped to a minimum of 256 bytes. The library API allows direct configuration via `ScanConfig::new(chunk_size, overlap_size)`.

```
Chunk N:     [===========================|overlap|]
Chunk N+1:                         [overlap|===========================|overlap|]
```

After scanning a chunk, only the overlap window is retained; the rest is flushed to the writer. Peak memory per file ≈ `chunk_size + overlap_size`.

### Archive Streaming

Archives (tar, tar.gz, zip) are processed **entry-by-entry**:

1. Each entry is matched against file-type profiles for structured processing.
2. If a structured processor matches and the entry is within `MAX_STRUCTURED_ENTRY_SIZE` (256 MiB), the entry is parsed and field values are replaced.
3. Otherwise the entry is piped through the streaming scanner in chunks — no full-entry buffering.
4. The archive is rebuilt with sanitized content and preserved metadata (timestamps, permissions, uid/gid).

Archive entries are processed **sequentially** to preserve ordering determinism.

### Structured File Size Caps

Files exceeding the structured processor's size limit are automatically demoted to the streaming scanner. This ensures bounded memory regardless of individual file size.

### Pattern Count Limits

The `StreamScanner` rejects pattern sets exceeding 10 000 patterns at construction time. This bounds `RegexSet` automaton memory, which scales linearly with pattern count.

### Memory Characteristics for Large Inputs

For 20–100 GB plain-text files, the streaming scanner maintains constant memory usage: `chunk_size + overlap_size + mapping store`. With the default 1 MiB chunk and 4 KiB overlap, base memory per active scan is ~1 MiB. The mapping store grows proportionally to the number of **unique** matched values (not file size).

---

## Defensive Limits

| Limit | Default Value | Configurable | Notes |
|-------|---------------|--------------|-------|
| Max structured file size | 256 MiB | `--max-structured-size` | Applies to JSON, YAML, XML, CSV, and archive entries routed to structured processors. Oversized files fall back to streaming. |
| Max pattern count | 10 000 | Compile-time (`DEFAULT_MAX_PATTERNS`) | Bounds `RegexSet` automaton memory. |
| Max mapping store entries | 10 000 000 | `--max-mappings` | Prevents unbounded heap growth. |
| Regex automaton size | 1 MiB | Compile-time (`REGEX_SIZE_LIMIT`) | Per-pattern limit. |
| Regex DFA cache size | 1 MiB | Compile-time (`REGEX_DFA_SIZE_LIMIT`) | Per-pattern limit. |
| YAML input size | 64 MiB | Compile-time (`MAX_YAML_INPUT_SIZE`) | Pre-parse rejection. |
| YAML node count | 10 000 000 | Compile-time (`MAX_YAML_NODE_COUNT`) | Post-expansion alias bomb defence. |
| YAML recursion depth | 128 | Compile-time (`MAX_YAML_DEPTH`) | Stack overflow prevention. |
| JSON input size | 256 MiB | Compile-time (`MAX_JSON_INPUT_SIZE`) | Pre-parse rejection. |
| JSON recursion depth | 128 | Compile-time (`MAX_JSON_DEPTH`) | Stack overflow prevention. |
| XML input size | 256 MiB | Compile-time (`MAX_XML_INPUT_SIZE`) | Pre-parse rejection. |
| XML element depth | 256 | Compile-time (`MAX_XML_DEPTH`) | Stack overflow prevention. |
| CSV input size | 256 MiB | Compile-time (`MAX_CSV_INPUT_SIZE`) | Pre-parse rejection. |
| Key-value input size | 256 MiB | Compile-time (`MAX_KV_INPUT_SIZE`) | Pre-parse rejection. |
| Max archive nesting depth | 3 | `--max-archive-depth` (max 10) | Prevents archive bombs and unbounded recursion. Each nesting level may buffer up to 256 MiB. |
