//! YAML structured processor.
//!
//! Parses YAML input, walks the value tree, replaces matched field
//! values, and serializes back. Structure is preserved but minor
//! formatting differences are possible (serde_yaml normalizes some
//! whitespace).
//!
//! Key paths use the same dot-separated convention as the JSON processor.

use crate::error::{Result, SanitizeError};
use crate::processor::{find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;
use serde_yaml_ng::Value;

/// Maximum recursion depth for walking YAML value trees.
const MAX_YAML_DEPTH: usize = 128;

/// Maximum allowed size (in bytes) for raw YAML input.
/// Guards against alias/anchor bombs that expand exponentially (R-4 / F-04 / F-06 fix).
const MAX_YAML_INPUT_SIZE: usize = 64 * 1024 * 1024; // 64 MiB

/// Maximum number of distinct YAML nodes after alias expansion.
/// serde_yaml expands aliases into values during deserialization;
/// this limit caps the total node count to prevent exponential
/// growth from alias bombs (F-06 fix).
const MAX_YAML_NODE_COUNT: usize = 10_000_000;

/// Structured processor for YAML files.
pub struct YamlProcessor;

impl Processor for YamlProcessor {
    fn name(&self) -> &'static str {
        "yaml"
    }

    fn can_handle(&self, content: &[u8], profile: &FileTypeProfile) -> bool {
        if profile.processor == "yaml" {
            return true;
        }
        // Heuristic: starts with `---` or a YAML-ish key: value.
        let text = String::from_utf8_lossy(content);
        let trimmed = text.trim_start();
        trimmed.starts_with("---") || trimmed.starts_with("- ") || trimmed.contains(": ")
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        // Guard against alias bombs: reject inputs above MAX_YAML_INPUT_SIZE.
        if content.len() > MAX_YAML_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: MAX_YAML_INPUT_SIZE,
            });
        }

        let text = std::str::from_utf8(content).map_err(|e| SanitizeError::ParseError {
            format: "YAML".into(),
            message: format!("invalid UTF-8: {}", e),
        })?;

        let mut value: Value =
            serde_yaml_ng::from_str(text).map_err(|e| SanitizeError::ParseError {
                format: "YAML".into(),
                message: format!("YAML parse error: {}", e),
            })?;

        // F-06 fix: count total nodes in the deserialized tree to detect
        // alias bombs. After expansion, aliased subtrees become
        // independent copies in memory, so the node count reflects the
        // true memory footprint.
        let node_count = count_yaml_nodes(&value);
        if node_count > MAX_YAML_NODE_COUNT {
            return Err(SanitizeError::InputTooLarge {
                size: node_count,
                limit: MAX_YAML_NODE_COUNT,
            });
        }

        walk_yaml(&mut value, "", profile, store, 0)?;

        let output = serde_yaml_ng::to_string(&value)
            .map_err(|e| SanitizeError::IoError(format!("YAML serialize error: {}", e)))?;

        Ok(output.into_bytes())
    }
}

/// Count the total number of nodes in a YAML value tree (F-06 fix).
/// Used to detect alias bombs that produce a small source document
/// but expand to millions of nodes after alias resolution.
fn count_yaml_nodes(value: &Value) -> usize {
    count_yaml_nodes_inner(value, 0)
}

/// Inner recursive counter with depth guard to prevent stack overflow
/// on deeply nested YAML before `walk_yaml`'s depth check is reached.
fn count_yaml_nodes_inner(value: &Value, depth: usize) -> usize {
    if depth > MAX_YAML_DEPTH {
        return 1; // Stop counting deeper; walk_yaml will catch depth violations
    }
    match value {
        Value::Mapping(map) => {
            1 + map
                .iter()
                .map(|(k, v)| {
                    count_yaml_nodes_inner(k, depth + 1) + count_yaml_nodes_inner(v, depth + 1)
                })
                .sum::<usize>()
        }
        Value::Sequence(seq) => {
            1 + seq
                .iter()
                .map(|v| count_yaml_nodes_inner(v, depth + 1))
                .sum::<usize>()
        }
        Value::Tagged(tagged) => 1 + count_yaml_nodes_inner(&tagged.value, depth + 1),
        _ => 1, // Null, Bool, Number, String
    }
}

/// Recursively walk a YAML value, replacing matched fields.
fn walk_yaml(
    value: &mut Value,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
) -> Result<()> {
    if depth > MAX_YAML_DEPTH {
        return Err(SanitizeError::RecursionDepthExceeded(format!(
            "YAML recursion depth exceeds limit of {MAX_YAML_DEPTH}"
        )));
    }
    match value {
        Value::Mapping(map) => {
            let keys: Vec<Value> = map.keys().cloned().collect();
            for key in keys {
                let key_str = yaml_key_to_string(&key);
                let path = if prefix.is_empty() {
                    key_str.clone()
                } else {
                    format!("{}.{}", prefix, key_str)
                };

                if let Some(v) = map.get_mut(&key) {
                    match v {
                        Value::String(s) => {
                            if let Some(rule) = find_matching_rule(&path, profile) {
                                *s = replace_value(s, rule, store)?;
                            }
                        }
                        Value::Number(_) | Value::Bool(_) => {
                            if let Some(rule) = find_matching_rule(&path, profile) {
                                let repr = yaml_scalar_to_string(v);
                                let replaced = replace_value(&repr, rule, store)?;
                                *v = Value::String(replaced);
                            }
                        }
                        Value::Mapping(_) | Value::Sequence(_) => {
                            walk_yaml(v, &path, profile, store, depth + 1)?;
                        }
                        Value::Null | Value::Tagged(_) => {}
                    }
                }
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                walk_yaml(item, prefix, profile, store, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn yaml_key_to_string(key: &Value) -> String {
    match key {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => format!("{:?}", key),
    }
}

fn yaml_scalar_to_string(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Number(n) => n.to_string(),
        Value::Bool(b) => b.to_string(),
        _ => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::category::Category;
    use crate::generator::HmacGenerator;
    use crate::processor::profile::FieldRule;
    use std::sync::Arc;

    fn make_store() -> MappingStore {
        let gen = Arc::new(HmacGenerator::new([42u8; 32]));
        MappingStore::new(gen, None)
    }

    #[test]
    fn basic_yaml_replacement() {
        let store = make_store();
        let proc = YamlProcessor;

        let content = b"database:\n  host: db.corp.com\n  password: s3cret\nport: 5432\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![
                FieldRule::new("database.password").with_category(Category::Custom("pw".into())),
                FieldRule::new("database.host").with_category(Category::Hostname),
            ],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("s3cret"));
        assert!(!out.contains("db.corp.com"));
        // port should be preserved
        assert!(out.contains("5432"));
    }

    #[test]
    fn yaml_sequence_traversal() {
        let store = make_store();
        let proc = YamlProcessor;

        let content = b"users:\n  - email: a@b.com\n  - email: c@d.com\n";
        let profile = FileTypeProfile::new(
            "yaml",
            vec![FieldRule::new("users.email").with_category(Category::Email)],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("a@b.com"));
        assert!(!out.contains("c@d.com"));
    }
}
