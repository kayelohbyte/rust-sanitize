//! TOML structured processor.
//!
//! Parses TOML input, walks the value tree, replaces matched field
//! values, and serializes back to TOML preserving structure.
//!
//! # Key Paths
//!
//! Nested keys use the same dot-separated convention as the JSON processor:
//! `database.password`, `server.credentials.token`.
//!
//! Array elements are traversed transparently — a rule for `servers.host`
//! matches the `host` field inside every table in the `servers` array.
//!
//! # Non-String Scalars
//!
//! When a FieldRule matches an integer, float, boolean, or datetime value,
//! that value is converted to a string replacement. This changes the TOML
//! type for that key but keeps the file syntactically valid. Use specific
//! field rules (e.g. `"database.password"`) rather than `"*"` if you want
//! to avoid replacing non-sensitive numeric values.

use crate::error::{Result, SanitizeError};
use crate::processor::{build_path, find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;
use toml::Value;

/// Maximum recursion depth for walking TOML value trees.
const MAX_TOML_DEPTH: usize = 128;

/// Maximum allowed input size (bytes) for TOML processing.
const MAX_TOML_INPUT_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

/// Structured processor for TOML configuration files.
pub struct TomlProcessor;

impl Processor for TomlProcessor {
    fn name(&self) -> &'static str {
        "toml"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "toml"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        if content.len() > MAX_TOML_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: MAX_TOML_INPUT_SIZE,
            });
        }

        let text = std::str::from_utf8(content).map_err(|e| SanitizeError::ParseError {
            format: "TOML".into(),
            message: format!("invalid UTF-8: {}", e),
        })?;

        let mut value: Value = toml::from_str(text).map_err(|e| SanitizeError::ParseError {
            format: "TOML".into(),
            message: format!("TOML parse error: {}", e),
        })?;

        walk_toml(&mut value, "", profile, store, 0)?;

        let output = toml::to_string_pretty(&value)
            .map_err(|e| SanitizeError::IoError(format!("TOML serialize error: {}", e)))?;

        Ok(output.into_bytes())
    }
}

/// Recursively walk a TOML value tree, replacing matched field values.
fn walk_toml(
    value: &mut Value,
    prefix: &str,
    profile: &FileTypeProfile,
    store: &MappingStore,
    depth: usize,
) -> Result<()> {
    if depth > MAX_TOML_DEPTH {
        return Err(SanitizeError::RecursionDepthExceeded(format!(
            "TOML recursion depth exceeds limit of {MAX_TOML_DEPTH}"
        )));
    }
    match value {
        Value::Table(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for key in keys {
                let path = build_path(prefix, &key);
                if let Some(v) = map.get_mut(&key) {
                    match v {
                        Value::String(s) => {
                            if let Some(rule) = find_matching_rule(&path, profile) {
                                *s = replace_value(s, rule, store)?;
                            }
                        }
                        // Non-string scalars: convert to string replacement when matched.
                        // This preserves TOML syntax validity while sanitizing the value.
                        Value::Integer(_)
                        | Value::Float(_)
                        | Value::Boolean(_)
                        | Value::Datetime(_) => {
                            if let Some(rule) = find_matching_rule(&path, profile) {
                                let repr = v.to_string();
                                let replaced = replace_value(&repr, rule, store)?;
                                *v = Value::String(replaced);
                            }
                        }
                        Value::Table(_) | Value::Array(_) => {
                            walk_toml(v, &path, profile, store, depth + 1)?;
                        }
                    }
                }
            }
        }
        Value::Array(arr) => {
            for item in arr.iter_mut() {
                walk_toml(item, prefix, profile, store, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
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
    fn basic_toml_replacement() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = br#"[database]
host = "db.corp.com"
password = "s3cret"
port = 5432

[smtp]
user = "admin@corp.com"
"#;
        let profile = FileTypeProfile::new(
            "toml",
            vec![
                FieldRule::new("database.password"),
                FieldRule::new("smtp.user").with_category(Category::Email),
            ],
        );
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        // Password replaced, host and port preserved.
        assert!(!text.contains("s3cret"));
        assert!(text.contains("db.corp.com"));
        assert!(text.contains("5432"));
        // Email replaced.
        assert!(!text.contains("admin@corp.com"));
    }

    #[test]
    fn wildcard_replaces_all_strings() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"api_key = \"secret\"\ndb_url = \"postgres://user:pass@host/db\"\n";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("*")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("secret"));
        assert!(!text.contains("postgres://user:pass@host/db"));
    }

    #[test]
    fn invalid_toml_returns_parse_error() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"this is not valid toml [[[";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("*")]);
        let result = proc.process(content, &profile, &store);
        assert!(result.is_err());
    }

    #[test]
    fn deeply_nested_toml() {
        let store = make_store();
        let proc = TomlProcessor;
        let content = b"[a.b.c]\nkey = \"value\"\n";
        let profile = FileTypeProfile::new("toml", vec![FieldRule::new("a.b.c.key")]);
        let output = proc.process(content, &profile, &store).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(!text.contains("value"));
    }
}
