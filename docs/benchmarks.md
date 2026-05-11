# Benchmark Baselines

Criterion benchmarks for the two core subsystems: the streaming scanner and the replacement store.
Use these numbers to detect regressions and measure the impact of future changes.

## Running

```bash
# Full suite (~10 min):
cargo bench

# One harness only:
cargo bench --bench mapping_bench
cargo bench --bench streaming_bench

# One benchmark group by name (substring match):
cargo bench --bench streaming_bench -- scan_throughput
cargo bench --bench mapping_bench  -- lookup_existing

# Save a named baseline before a change:
cargo bench -- --save-baseline before

# Compare against it after:
cargo bench -- --save-baseline after
cargo critcmp before after   # cargo install critcmp
```

HTML reports (with flamegraph-style plots) land in `target/criterion/<group>/report/index.html`.

---

## Baseline — v0.8.0 · 2026-05-09

**Machine:** Apple M4 Pro · 14 logical CPUs · 24 GiB RAM  
**Toolchain:** rustc 1.92.0 · cargo 1.92.0  
**Profile:** `release` with `lto = "thin"`, `codegen-units = 1`, `strip = "symbols"`

### Streaming Scanner (`streaming_bench`)

#### `scan_throughput` — regex-only, default 1 MiB chunk

Synthetic input: one line per ~180 bytes containing an IPv4, an email, and a UUID.
Every line is a match, so this is a high-match-density worst case.

| Input size | Time | Throughput |
|---|---|---|
| 1 MiB | 2.89 ms | 347 MiB/s |
| 16 MiB | 46.4 ms | 345 MiB/s |
| 64 MiB | 191 ms | 335 MiB/s |

Throughput is stable across sizes — confirms the scanner is streaming (no full-file buffer).

#### `literal_scan_throughput` — Aho-Corasick only path

Synthetic input: `SECRET_KEY=`, `password=`, `api_key=`, `Bearer `, `Authorization:` literals every ~180 bytes.

| Input size | Time | Throughput |
|---|---|---|
| 1 MiB | 2.60 ms | 385 MiB/s |
| 16 MiB | 40.8 ms | 392 MiB/s |
| 64 MiB | 163 ms | 392 MiB/s |

~13% faster than the regex path — Aho-Corasick automaton avoids the RegexSet pre-filter pass.

#### `mixed_scan_throughput` — hybrid Aho-Corasick + regex

Synthetic input: `SECRET_KEY=`, `password=`, `api_key=` literals + email + IPv4 regexes every ~180 bytes.

| Input size | Time | Throughput |
|---|---|---|
| 1 MiB | 3.62 ms | 277 MiB/s |
| 16 MiB | 58.3 ms | 274 MiB/s |
| 64 MiB | 236 ms | 271 MiB/s |

~20% slower than regex-only because the hybrid path runs both the AC scan and the RegexSet scan over each chunk.

#### `chunk_size_impact` — 16 MiB input, varying chunk size

| Chunk size | Time | Throughput |
|---|---|---|
| 64 KiB | 47.0 ms | 340 MiB/s |
| 256 KiB | 45.9 ms | 348 MiB/s |
| 1 MiB (default) | 47.4 ms | 337 MiB/s |
| 4 MiB | 49.4 ms | 324 MiB/s |

256 KiB is the sweet spot on this hardware (L2/L3 cache boundary). The default 1 MiB is a safe conservative choice — large enough to amortise syscall overhead for real files, close enough to optimal.

#### `tar_processing` — entry-by-entry tar sanitization

Each entry is 64 KiB of synthetic log data (high match density).

| Entry count | Time | Throughput |
|---|---|---|
| 10 entries (640 KiB) | 1.91 ms | 331 MiB/s |
| 50 entries (3.2 MiB) | 9.71 ms | 324 MiB/s |

Throughput is close to the raw scanner — the archive rebuild overhead is small.

#### `parallel_archive_entries` — serial vs parallel entry processing

| Entries | Mode | Time | Throughput |
|---|---|---|---|
| 8 | Serial | 1.54 ms | 327 MiB/s |
| 8 | Parallel | 1.50 ms | 336 MiB/s |
| 20 | Serial | 3.78 ms | 334 MiB/s |
| 20 | Parallel | 3.79 ms | 333 MiB/s |
| 50 | Serial | 9.53 ms | 330 MiB/s |
| 50 | Parallel | 9.48 ms | 332 MiB/s |

**Note:** No parallelism benefit at these entry counts on M4 Pro. The entries are small (64 KiB each) and the scanner is already CPU-bound; thread spawn + sync overhead eats the gains. Expect parallel wins for larger entries (≥ 1 MiB each) or higher core-count machines with more headroom.

#### `parallel_multi_file` — sequential vs rayon across independent files

Each file is 1 MiB of mixed (literal + regex) data.

| File count | Mode | Time | Throughput |
|---|---|---|---|
| 2 | Sequential | 7.26 ms | 275 MiB/s |
| 2 | Parallel | 5.90 ms | 339 MiB/s (+23%) |
| 4 | Sequential | 14.5 ms | 275 MiB/s |
| 4 | Parallel | 11.1 ms | 359 MiB/s (+31%) |
| 8 | Sequential | 29.1 ms | 275 MiB/s |
| 8 | Parallel | 31.2 ms | 256 MiB/s (−7%) |

File-level parallelism helps up to 4 files on this machine. At 8 files, the thread pool is oversubscribed (14 logical CPUs shared with other processes) and the benefit disappears. In production, `--threads` should be tuned to leave headroom.

---

### Replacement Store (`mapping_bench`)

#### `insert_unique` — first-insert (slow path, HMAC generation)

All inserts go to `Category::Email`, each with a distinct value. Measures HMAC generation cost.

| Unique values | Time | Per-insert |
|---|---|---|
| 1 000 | 890 µs | 890 ns |
| 10 000 | 8.99 ms | 899 ns |
| 100 000 | 92.6 ms | 926 ns |

Per-insert cost is dominated by HMAC-SHA256 (~870 ns), not map overhead. Scales linearly.

#### `lookup_existing_10k` — cache-hit (fast path, no allocation)

Store pre-populated with 10 000 `Category::Email` entries. Repeatedly looks up existing values cycling through all 10 000 keys.

| Metric | Value |
|---|---|
| Time per lookup | **60 ns** |
| Allocation | **zero** (`ZeroizingString: Borrow<str>` avoids `to_owned()`) |

This is the hot path for log sanitization (same IP / email appearing thousands of times). At 60 ns per hit the store is not a bottleneck at any realistic match density.

#### `concurrent_8threads_10k_each` — concurrent unique inserts

8 threads each inserting 10 000 distinct values into `Category::Email` simultaneously.

| Metric | Value |
|---|---|
| Total time (80 000 unique inserts) | 29 ms |
| Per-insert (amortised, 8 threads) | 3.6 µs |

**Context:** This benchmark represents a pathological scenario — 80 000 all-unique inserts under heavy concurrency. In real log-sanitization workloads the slow path (first-insert) fires rarely relative to the fast path (cache-hit). A typical run against 1 GB of logs might produce a few hundred unique secrets, not 80 000. The number to watch for actual performance is `lookup_existing_10k`.

---

## How to Add a New Entry

When a change affects one of these subsystems, run the relevant bench, paste the new numbers below, and note what changed and why.

```
### vX.Y.Z · YYYY-MM-DD — <one-line description of change>

| Benchmark | Before | After | Delta |
|---|---|---|---|
| lookup_existing_10k | 60 ns | 55 ns | −8% |
| ... | | | |

Notes: <what you changed and why the numbers moved>
```

---

## Change Log

| Version | Date | Change | Key impact |
|---|---|---|---|
| v0.8.0 | 2026-05-09 | Baseline established | — |
| v0.8.0 | 2026-05-09 | Added `[profile.release]` LTO + codegen-units=1 | `insert_unique/100k`: −4.6%; scanner throughput unchanged (already fast) |
| v0.8.0 | 2026-05-09 | Two-level `MappingStore` + `Borrow<str>` fast path | `lookup_existing_10k`: −8%, zero allocation on cache hits |
