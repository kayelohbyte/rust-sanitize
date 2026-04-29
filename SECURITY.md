# Security Model

> **sanitize-engine** v0.2.0

This document describes the security properties, threat mitigations,
and operational constraints of the sanitization engine.

---

## 1. One-Way Guarantee

Replacements are **irreversible by design**.

- No reverse-mapping table is generated or stored.
- The `MappingStore` forward map (`original → replacement`) lives only
  in process memory and is zeroized on drop (see §5).
- There is no "restore" or "decrypt-output" mode.

---

## 2. Encryption at Rest — Secrets File

Sensitive detection patterns (regex, literals) are stored in an
AES-256-GCM encrypted secrets file.

| Parameter | Value |
|-----------|-------|
| KDF | PBKDF2-HMAC-SHA256 |
| Iterations | 600 000 |
| Salt | 32 bytes (OS CSPRNG) |
| Key length | 32 bytes (256 bits) |
| Cipher | AES-256-GCM |
| Nonce | 12 bytes (OS CSPRNG) |
| AAD | None (empty) |

The encrypted file format:

```
[32 bytes salt]
[12 bytes nonce]
[N bytes ciphertext + 16-byte GCM tag]
```

After decryption, plaintext secrets are wrapped in `zeroize::Zeroizing`
and each `SecretEntry`'s fields (`pattern`, `kind`, `category`, `label`)
implement `Zeroize` via `Drop`.

Secrets files are managed via the `sanitize encrypt` and
`sanitize decrypt` subcommands.

---

## 3. Password Handling

The password used for secrets encryption/decryption is resolved through
a priority chain designed to balance convenience with security:

| Priority | Source | Security Notes |
|----------|--------|----------------|
| 1 | `--password <PW>` flag | **Least secure** — visible in process listings and shell history. A warning is emitted when used. |
| 2 | `--password-file <PATH>` | Reads from a file. The file **must** have Unix permissions `0600` or `0400` (owner read/write or owner read-only). Other permissions are rejected with an error. |
| 3 | `SANITIZE_PASSWORD` env var | Avoids process listings but visible in `/proc/<pid>/environ` on Linux. |
| 4 | Interactive prompt | **Most secure** — masked terminal input via `rpassword`. No trace in history, env, or process listing. |

---

## 4. HMAC Determinism

When using `HmacGenerator`, replacements are derived from:

```
HMAC-SHA256(seed, category_tag || "\x00" || plaintext_value)
```

- The **seed** is a 32-byte key provided at CLI invocation. Same seed +
  same value → same replacement across runs.
- The seed is zeroized on `HmacGenerator` drop.
- Category `domain_tag()` provides domain separation so e.g. an email
  `"alice"` and a hostname `"alice"` produce different replacements.

---

## 5. Memory Bounds

The engine enforces hard caps at multiple layers to prevent resource
exhaustion:

| Limit | Value | Purpose |
|-------|-------|---------|
| Regex automaton size | 1 MiB | Prevents catastrophic backtracking / ReDoS |
| Regex DFA size | 1 MiB | Caps DFA memory during matching |
| Max patterns | 10 000 (default) | Bounds total compiled regex memory |
| Mapping store capacity | Configurable | Prevents unbounded map growth |
| YAML input size | 64 MiB | Stops alias-bomb expansion |
| YAML node count | 10 000 000 | Caps post-expansion node count |
| YAML recursion depth | 128 | Prevents stack overflow |
| XML input size | 256 MiB | Bounds memory for DOM parse |
| XML element depth | 256 | Prevents stack overflow |
| CSV input size | 256 MiB | Bounds memory for full parse |
| Structured archive entry | 256 MiB | Oversized entries fall to streaming scanner |
| Scanner chunk size | Configurable (default 1 MiB) | Peak memory ≈ chunk + overlap |

---

## 6. Zeroization

Sensitive data is scrubbed from memory on drop:

| Type | What is zeroized | Mechanism |
|------|-----------------|-----------|
| `HmacGenerator` | 32-byte HMAC key | `Zeroize` trait on `Drop` |
| `SecretEntry` | pattern, kind, category, label strings | `Zeroize` trait on `Drop` |
| `MappingStore` | All original-value keys in forward map | Custom `Drop` iterates + zeroizes |
| Decrypted secrets | Full plaintext JSON blob | `zeroize::Zeroizing<Vec<u8>>` |

> **Note:** Zeroization is best-effort on safe Rust. The compiler may
> copy values before they are scrubbed. Using `zeroize` with its
> `volatile` write semantics minimizes but does not eliminate this risk.

---

## 7. No Unsafe Code

The crate contains **zero** `unsafe` blocks. Thread safety is achieved
through `DashMap` (shard-level locking) and `Arc`. `Send + Sync` bounds
are verified with compile-time assertions.

---

## 8. Out of Scope

The following threats are outside the tool's design boundary:

- **Compromised runtime environment.** If the host OS or runtime is
  compromised, an attacker can read process memory directly.
- **Memory scraping during execution.** Sensitive values exist in
  process memory between decryption and zeroization.
- **Kernel-level or hypervisor adversaries.** The tool operates in user
  space and cannot defend against privileged code.
- **Side-channel attacks.** HMAC computation and regex matching are not
  constant-time with respect to input contents.
- **Deterministic seed brute-force.** In `--deterministic` mode, an
  adversary who knows the seed can compute HMAC for any candidate and
  compare against replacements in the output.

---

## 9. Responsible Disclosure

If you discover a security vulnerability, please report it privately
via GitHub Security Advisories or email the maintainers directly.
Do not open a public issue for security vulnerabilities.

**Response timeline:**
- Acknowledgement within 48 hours.
- Initial assessment within 5 business days.
- Fix or mitigation within 30 days for confirmed issues.

---

## 10. YAML Alias Bomb Mitigation

YAML anchors/aliases can cause exponential expansion:

```yaml
a: &x "boom"
b: [*x, *x, *x, *x, *x, *x, *x, *x]  # 8× expansion
c: [*b, *b, *b, *b, *b, *b, *b, *b]  # 64× expansion
```

The `YamlProcessor` defends against this with three layers:

1. **Input size cap** — reject inputs > 64 MiB before parsing.
2. **Node count cap** — after `serde_yaml` deserialization (which
   expands aliases), count nodes and reject if > 10 000 000.
3. **Recursion depth cap** — reject documents deeper than 128 levels.

---

## 11. Archive Decompression Bomb Mitigation

Malicious archives can contain entries that expand to many times their
compressed size (zip bombs, tar bombs, nested archives). The
`ArchiveProcessor` defends against this:

1. **Entry size cap** — individual entries larger than 256 MiB are
   diverted to the streaming scanner (which processes in bounded chunks)
   rather than being buffered in memory for structured processing.
2. **Nesting depth cap** — recursive archive processing (archives inside
   archives) is limited to a default depth of 3 and a hard maximum of
   10. Exceeding the limit returns `RecursionDepthExceeded`.
3. **Entry-by-entry processing** — archives are never fully decompressed
   into memory. Each entry is processed independently, so peak memory is
   proportional to the largest single entry (structured path) or
   `chunk_size + overlap_size` (streaming scanner path).

---

## 12. Signal Safety

`SIGINT` / `SIGTERM` set a global `AtomicBool`. The pipeline checks
this flag before committing output. If interrupted:

- `AtomicFileWriter` drops the temp file (no partial output).
- Exit code is 130 (standard UNIX convention for SIGINT).

---

## 13. Logging Hygiene

The tracing layer **never** logs:

- Secret patterns or their plaintext values.
- Decryption keys, passwords, or HMAC seeds.
- Contents of sensitive fields.

Only metadata is logged: file paths, byte counts, entry counts, timing,
and error descriptions.

---

## 14. Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| ReDoS via malicious patterns | Regex size + DFA limits (1 MiB each) |
| YAML alias bomb | Input size + node count + depth caps |
| XML billion-laughs | Input size + element depth limits |
| Unbounded memory from large files | Streaming scanner (chunk + overlap) |
| Partial output after crash | Atomic file writes (tmp → fsync → rename) |
| Secret leakage in logs | No secret values in tracing output |
| Plaintext lingering in memory | Zeroize on Drop for keys, secrets, mappings |
| Reverse-engineering replacements | One-way only; no mapping table persisted |
| Thread oversubscription | CLI caps threads to `available_parallelism()` |
