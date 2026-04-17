//! Key-value processor for `gitlab.rb`-style configuration files.
//!
//! Handles files with lines of the form:
//!
//! ```text
//! key = "value"
//! key = 'value'
//! key = value
//! # comment lines are preserved
//! ```
//!
//! The delimiter, comment prefix, and quoting style are configurable
//! via the profile's `options` map.
//!
//! # Profile Options
//!
//! | Key              | Default | Description                                  |
//! |------------------|---------|----------------------------------------------|
//! | `delimiter`      | `"="`   | The key-value separator.                     |
//! | `comment_prefix` | `"#"`   | Lines starting with this (after whitespace)  |
//! |                  |         | are treated as comments and preserved as-is. |
//!
//! # Formatting Preservation
//!
//! - Blank lines, comment lines, and indentation are preserved verbatim.
//! - The original quoting style (single, double, or unquoted) is kept.
//! - Whitespace around the delimiter is preserved where possible.

use crate::error::{Result, SanitizeError};
use crate::processor::{find_matching_rule, replace_value, FileTypeProfile, Processor};
use crate::store::MappingStore;

/// Maximum allowed input size (bytes) for key-value processing.
const MAX_KV_INPUT_SIZE: usize = 256 * 1024 * 1024; // 256 MiB

/// Structured processor for key = value configuration files.
pub struct KeyValueProcessor;

impl Processor for KeyValueProcessor {
    fn name(&self) -> &'static str {
        "key_value"
    }

    fn can_handle(&self, _content: &[u8], profile: &FileTypeProfile) -> bool {
        profile.processor == "key_value"
    }

    fn process(
        &self,
        content: &[u8],
        profile: &FileTypeProfile,
        store: &MappingStore,
    ) -> Result<Vec<u8>> {
        if content.len() > MAX_KV_INPUT_SIZE {
            return Err(SanitizeError::InputTooLarge {
                size: content.len(),
                limit: MAX_KV_INPUT_SIZE,
            });
        }

        let text = String::from_utf8_lossy(content);
        let delimiter = profile.options.get("delimiter").map_or("=", |s| s.as_str());
        let comment_prefix = profile
            .options
            .get("comment_prefix")
            .map_or("#", |s| s.as_str());

        let mut output = String::with_capacity(text.len());

        for line in text.split('\n') {
            let trimmed = line.trim();

            // Preserve blank lines.
            if trimmed.is_empty() {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Preserve comment lines.
            if trimmed.starts_with(comment_prefix) {
                output.push_str(line);
                output.push('\n');
                continue;
            }

            // Try to split on delimiter.
            if let Some(delim_pos) = line.find(delimiter) {
                let raw_key = &line[..delim_pos];
                let after_delim = &line[delim_pos + delimiter.len()..];

                let key = raw_key.trim();

                // Check if this key matches any field rule.
                if let Some(rule) = find_matching_rule(key, profile) {
                    // Determine leading whitespace on the value side.
                    let value_leading_ws: &str = {
                        let trimmed_start = after_delim.trim_start();
                        &after_delim[..after_delim.len() - trimmed_start.len()]
                    };
                    let raw_value = after_delim.trim();

                    // Detect quoting.
                    let (quote_char, inner_value) = detect_quotes(raw_value);

                    // Replace the inner value.
                    let replaced = replace_value(inner_value, rule, store)?;

                    // Reconstruct the line preserving formatting.
                    output.push_str(raw_key);
                    output.push_str(delimiter);
                    output.push_str(value_leading_ws);
                    if let Some(q) = quote_char {
                        output.push(q);
                        output.push_str(&replaced);
                        output.push(q);
                    } else {
                        output.push_str(&replaced);
                    }
                    output.push('\n');
                } else {
                    // Key not matched; preserve line as-is.
                    output.push_str(line);
                    output.push('\n');
                }
            } else {
                // No delimiter found; preserve line as-is.
                output.push_str(line);
                output.push('\n');
            }
        }

        // Remove the trailing newline we added if the original didn't end with one.
        if !text.ends_with('\n') && output.ends_with('\n') {
            output.pop();
        }

        Ok(output.into_bytes())
    }
}

/// Detect surrounding quotes and return `(quote_char, inner_value)`.
fn detect_quotes(value: &str) -> (Option<char>, &str) {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return (Some(first as char), &value[1..value.len() - 1]);
        }
    }
    (None, value)
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
    fn basic_key_value_replacement() {
        let store = make_store();
        let proc = KeyValueProcessor;

        let content = br#"# GitLab configuration file
gitlab_rails['smtp_password'] = "super_secret_123"
gitlab_rails['smtp_address'] = "smtp.corp.com"
gitlab_rails['db_pool'] = 10
"#;

        let profile = FileTypeProfile::new(
            "key_value",
            vec![
                FieldRule::new("gitlab_rails['smtp_password']")
                    .with_category(Category::Custom("password".into())),
                FieldRule::new("gitlab_rails['smtp_address']").with_category(Category::Hostname),
            ],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        // Comment preserved.
        assert!(out.contains("# GitLab configuration file"));
        // Secrets replaced.
        assert!(!out.contains("super_secret_123"));
        assert!(!out.contains("smtp.corp.com"));
        // Unmatched key preserved.
        assert!(out.contains("gitlab_rails['db_pool'] = 10"));
        // Quoting preserved.
        assert!(out.contains('"'));
    }

    #[test]
    fn preserves_blank_lines_and_comments() {
        let store = make_store();
        let proc = KeyValueProcessor;

        let content = b"# Header comment\n\nkey = value\n\n# Footer\n";
        let profile = FileTypeProfile::new(
            "key_value",
            vec![FieldRule::new("key").with_category(Category::Custom("test".into()))],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(out.starts_with("# Header comment\n\n"));
        assert!(out.contains("\n\n# Footer\n"));
        assert!(!out.contains("= value"));
    }

    #[test]
    fn glob_pattern_matching() {
        let store = make_store();
        let proc = KeyValueProcessor;

        let content = b"db.password = secret1\ndb.host = myhost\napp.name = test\n";
        let profile = FileTypeProfile::new(
            "key_value",
            vec![FieldRule::new("db.*").with_category(Category::Custom("db".into()))],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();

        assert!(!out.contains("secret1"));
        assert!(!out.contains("myhost"));
        assert!(out.contains("app.name = test"));
    }

    #[test]
    fn deterministic_replacement() {
        let store = make_store();
        let proc = KeyValueProcessor;

        let content = b"key1 = secret\nkey2 = secret\n";
        let profile = FileTypeProfile::new(
            "key_value",
            vec![
                FieldRule::new("key1").with_category(Category::Custom("test".into())),
                FieldRule::new("key2").with_category(Category::Custom("test".into())),
            ],
        );

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        let lines: Vec<&str> = out.lines().collect();

        // Same original + same category → same replacement.
        let val1 = lines[0].split(" = ").nth(1).unwrap();
        let val2 = lines[1].split(" = ").nth(1).unwrap();
        assert_eq!(val1, val2);
    }

    #[test]
    fn custom_delimiter() {
        let store = make_store();
        let proc = KeyValueProcessor;

        let content = b"key: value\n";
        let profile = FileTypeProfile::new(
            "key_value",
            vec![FieldRule::new("key").with_category(Category::Custom("test".into()))],
        )
        .with_option("delimiter", ":");

        let result = proc.process(content, &profile, &store).unwrap();
        let out = String::from_utf8(result).unwrap();
        assert!(!out.contains("value"));
        assert!(out.contains("key:"));
    }
}
