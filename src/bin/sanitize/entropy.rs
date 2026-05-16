use sanitize_engine::secrets::{parse_category, SecretEntry};
use sanitize_engine::{Category, MappingStore, ScanStats, StreamScanner};
use std::io;
use std::sync::Arc;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum EntropyCharset {
    Alphanumeric,
    Base64,
    Hex,
    Any,
}

impl EntropyCharset {
    fn from_str(s: &str) -> Self {
        match s {
            "base64" => Self::Base64,
            "hex" => Self::Hex,
            "any" => Self::Any,
            _ => Self::Alphanumeric,
        }
    }

    pub(crate) fn matches_all(&self, token: &[u8]) -> bool {
        token.iter().all(|&b| match self {
            Self::Alphanumeric => b.is_ascii_alphanumeric(),
            Self::Base64 => b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
            Self::Hex => b.is_ascii_hexdigit(),
            Self::Any => b.is_ascii_graphic(),
        })
    }
}

/// Configuration for one entropy-detection pass. Produced from `kind: entropy`
/// secrets-file entries and from the `--entropy-threshold` CLI flag.
#[derive(Debug, Clone)]
pub(crate) struct EntropyConfig {
    pub(crate) min_length: usize,
    pub(crate) max_length: usize,
    pub(crate) threshold: f64,
    pub(crate) charset: EntropyCharset,
    pub(crate) label: String,
    pub(crate) category: Category,
}

impl Default for EntropyConfig {
    fn default() -> Self {
        Self {
            min_length: 20,
            max_length: 200,
            threshold: 4.5,
            charset: EntropyCharset::Alphanumeric,
            label: "high_entropy_token".into(),
            category: Category::AuthToken,
        }
    }
}

fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

/// Build `EntropyConfig`s from `kind: entropy` entries in the secrets file.
pub(crate) fn entropy_configs_from_entries(entries: &[SecretEntry]) -> Vec<EntropyConfig> {
    entries
        .iter()
        .filter(|e| e.kind == "entropy")
        .map(|e| EntropyConfig {
            min_length: e.min_length.unwrap_or(20),
            max_length: e.max_length.unwrap_or(200),
            threshold: e.threshold.unwrap_or(4.5),
            charset: EntropyCharset::from_str(e.charset.as_deref().unwrap_or("alphanumeric")),
            label: e
                .label
                .clone()
                .unwrap_or_else(|| "high_entropy_token".into()),
            category: parse_category(&e.category),
        })
        .collect()
}

/// Byte values that delimit tokens for entropy analysis.
const ENTROPY_DELIMITERS: &[u8] = b" \t\n\r\"'`=:,;()[]{}|<>@#\\/^~!?&%$*";

/// Scan `input` for high-entropy tokens and replace them using `store`.
/// Returns `(output_bytes, match_count)`.
///
/// Runs AFTER the main scanner so tokens already replaced (now placeholders)
/// won't double-fire — placeholders have low entropy by design.
pub(crate) fn entropy_scan_bytes(
    input: &[u8],
    configs: &[EntropyConfig],
    store: &Arc<MappingStore>,
) -> (Vec<u8>, u64) {
    if configs.is_empty() || input.is_empty() {
        return (input.to_vec(), 0);
    }

    let mut output = Vec::with_capacity(input.len());
    let mut matches: u64 = 0;
    let mut pos = 0;

    while pos < input.len() {
        let token_start = pos;
        let token_end = input[pos..]
            .iter()
            .position(|b| ENTROPY_DELIMITERS.contains(b))
            .map(|p| pos + p)
            .unwrap_or(input.len());

        let token = &input[token_start..token_end];

        let replaced = if !token.is_empty() {
            let hit = configs.iter().find(|cfg| {
                token.len() >= cfg.min_length
                    && token.len() <= cfg.max_length
                    && cfg.charset.matches_all(token)
                    && shannon_entropy(token) >= cfg.threshold
            });

            if let Some(cfg) = hit {
                if let Ok(token_str) = std::str::from_utf8(token) {
                    if let Ok(replacement) = store.get_or_insert(&cfg.category, token_str) {
                        output.extend_from_slice(replacement.as_bytes());
                    } else {
                        output.extend_from_slice(token);
                    }
                    matches += 1;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };

        if !replaced {
            output.extend_from_slice(token);
        }

        if token_end < input.len() {
            output.push(input[token_end]);
            pos = token_end + 1;
        } else {
            pos = token_end;
        }
    }

    (output, matches)
}

pub(crate) fn scanner_fallback(
    scanner: &StreamScanner,
    input: &[u8],
) -> Result<(Vec<u8>, ScanStats), String> {
    scanner
        .scan_bytes(input)
        .map_err(|e| format!("scanner error: {e}"))
}

/// A `Write + Seek` sink that discards all bytes.
///
/// Used for dry-run zip processing: `ZipWriter` requires `Seek` to finalize
/// the central directory, so `io::sink()` alone is insufficient.
pub(crate) struct NullSeekWriter {
    pub(crate) pos: u64,
    pub(crate) len: u64,
}

impl io::Write for NullSeekWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = buf.len() as u64;
        self.pos += n;
        if self.pos > self.len {
            self.len = self.pos;
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl io::Seek for NullSeekWriter {
    fn seek(&mut self, from: io::SeekFrom) -> io::Result<u64> {
        let new_pos: u64 = match from {
            io::SeekFrom::Start(n) => n,
            io::SeekFrom::Current(n) => {
                if n >= 0 {
                    self.pos.saturating_add(n as u64)
                } else {
                    self.pos.saturating_sub((-n) as u64)
                }
            }
            io::SeekFrom::End(n) => {
                if n >= 0 {
                    self.len.saturating_add(n as u64)
                } else {
                    self.len.saturating_sub((-n) as u64)
                }
            }
        };
        self.pos = new_pos;
        if new_pos > self.len {
            self.len = new_pos;
        }
        Ok(self.pos)
    }
}
