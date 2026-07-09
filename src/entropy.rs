//! Shannon-entropy token detection.
//!
//! Splits input on token delimiters and replaces tokens whose per-character
//! Shannon entropy meets a configured threshold. Runs AFTER pattern scanning
//! so already-replaced values (now placeholders) won't double-fire —
//! placeholders have low entropy by design.
//!
//! Configs come from `kind: entropy` secrets-file entries or the CLI's
//! `--entropy-threshold` flag, and are applied both by the CLI's dispatch
//! layer for directly-processed files and by
//! [`ArchiveProcessor`](crate::ArchiveProcessor) for archive entries.

use crate::category::Category;
use crate::scanner::ScanStats;
use crate::store::MappingStore;
use std::collections::HashMap;

/// Character set an entropy candidate token must consist of exclusively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntropyCharset {
    Alphanumeric,
    Base64,
    Hex,
    Any,
}

impl EntropyCharset {
    /// Parse a charset name (`"base64"`, `"hex"`, `"any"`); anything else
    /// falls back to `Alphanumeric`, the default.
    #[must_use]
    pub fn parse(s: &str) -> Self {
        match s {
            "base64" => Self::Base64,
            "hex" => Self::Hex,
            "any" => Self::Any,
            _ => Self::Alphanumeric,
        }
    }

    /// Human-readable charset name for reports and calibration output.
    #[must_use]
    pub fn describe(&self) -> &'static str {
        match self {
            Self::Alphanumeric => "alphanumeric",
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Any => "any printable",
        }
    }

    /// Whether every byte of `token` belongs to this charset.
    #[must_use]
    pub fn matches_all(&self, token: &[u8]) -> bool {
        token.iter().all(|&b| match self {
            Self::Alphanumeric => b.is_ascii_alphanumeric(),
            Self::Base64 => b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=',
            Self::Hex => b.is_ascii_hexdigit(),
            Self::Any => b.is_ascii_graphic(),
        })
    }
}

/// Configuration for one entropy-detection pass.
#[derive(Debug, Clone)]
pub struct EntropyConfig {
    /// Minimum token length to consider (default: 20).
    pub min_length: usize,
    /// Maximum token length to consider (default: 200).
    pub max_length: usize,
    /// Shannon entropy threshold in bits per character (default: 4.5).
    pub threshold: f64,
    /// Character set the token must consist of exclusively.
    pub charset: EntropyCharset,
    /// Label used in reports and summaries.
    pub label: String,
    /// Replacement category for matched tokens.
    pub category: Category,
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

/// Byte values that delimit tokens for entropy analysis.
pub const ENTROPY_DELIMITERS: &[u8] = b" \t\n\r\"'`=:,;()[]{}|<>@#\\/^~!?&%$*";

/// Shannon entropy of `data` in bits per byte.
#[must_use]
#[allow(clippy::cast_precision_loss)] // token lengths are far below 2^52
pub fn shannon_entropy(data: &[u8]) -> f64 {
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
            let p = f64::from(c) / len;
            -p * p.log2()
        })
        .sum()
}

/// Scan `input` for high-entropy tokens and replace them using `store`.
/// Returns `(output_bytes, per_label_counts)`.
#[must_use]
pub fn entropy_scan_bytes(
    input: &[u8],
    configs: &[EntropyConfig],
    store: &MappingStore,
) -> (Vec<u8>, HashMap<String, u64>) {
    if configs.is_empty() || input.is_empty() {
        return (input.to_vec(), HashMap::new());
    }

    let mut output = Vec::with_capacity(input.len());
    let mut label_counts: HashMap<String, u64> = HashMap::new();
    let mut pos = 0;

    while pos < input.len() {
        let token_start = pos;
        let token_end = input[pos..]
            .iter()
            .position(|b| ENTROPY_DELIMITERS.contains(b))
            .map_or(input.len(), |p| pos + p);

        let token = &input[token_start..token_end];

        let replaced = if token.is_empty() {
            false
        } else {
            let hit = configs.iter().find(|cfg| {
                token.len() >= cfg.min_length
                    && token.len() <= cfg.max_length
                    && cfg.charset.matches_all(token)
                    && shannon_entropy(token) >= cfg.threshold
            });

            if let (Some(cfg), Ok(token_str)) = (hit, std::str::from_utf8(token)) {
                if let Ok(replacement) = store.get_or_insert(&cfg.category, token_str) {
                    output.extend_from_slice(replacement.as_bytes());
                } else {
                    output.extend_from_slice(token);
                }
                *label_counts.entry(cfg.label.clone()).or_insert(0) += 1;
                true
            } else {
                false
            }
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

    (output, label_counts)
}

/// Merge per-label entropy replacement counts into `stats`.
pub fn merge_entropy_counts(
    stats: &mut ScanStats,
    label_counts: impl IntoIterator<Item = (String, u64)>,
) {
    let mut total = 0u64;
    for (label, count) in label_counts {
        total += count;
        *stats.pattern_counts.entry(label).or_insert(0) += count;
    }
    stats.matches_found += total;
    stats.replacements_applied += total;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generator::HmacGenerator;
    use std::sync::Arc;

    fn store() -> MappingStore {
        MappingStore::new(Arc::new(HmacGenerator::new([9u8; 32])), None)
    }

    #[test]
    fn replaces_high_entropy_token_and_keeps_prose() {
        let cfg = EntropyConfig {
            min_length: 40,
            charset: EntropyCharset::Base64,
            ..Default::default()
        };
        let input = b"secret FLwnxzdPdfIwcrav7PpjWEoYEc55HAcl2Aad0w8rfSsUvYoJHOlqlngm5UzH1zKJ here";
        let (out, counts) = entropy_scan_bytes(input, &[cfg], &store());
        let out = String::from_utf8(out).unwrap();
        assert!(!out.contains("FLwnxzdPdfIw"), "token replaced: {out}");
        assert!(out.starts_with("secret ") && out.ends_with(" here"));
        assert_eq!(counts["high_entropy_token"], 1);
    }

    #[test]
    fn low_entropy_and_short_tokens_pass_through() {
        let cfg = EntropyConfig::default();
        let input = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa short words";
        let (out, counts) = entropy_scan_bytes(input, &[cfg], &store());
        assert_eq!(out, input.to_vec());
        assert!(counts.is_empty());
    }

    #[test]
    fn empty_configs_are_a_noop() {
        let input = b"anything at all";
        let (out, counts) = entropy_scan_bytes(input, &[], &store());
        assert_eq!(out, input.to_vec());
        assert!(counts.is_empty());
    }
}
