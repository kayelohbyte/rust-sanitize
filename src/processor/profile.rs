//! File-type profiles for structured processors.
//!
//! A [`FileTypeProfile`] tells the processing pipeline which processor
//! to use and which fields/keys within the file should be sanitized.

use crate::category::Category;
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// FieldRule
// ---------------------------------------------------------------------------

/// A rule describing a single field/key to sanitize.
///
/// # Pattern Syntax
///
/// - Exact key: `"password"`, `"db_host"`.
/// - Dotted path: `"database.password"`, `"smtp.user"`.
/// - Glob suffix: `"*.password"` — matches any key ending in `.password`.
/// - Glob prefix: `"db.*"` — matches any key starting with `db.`.
/// - Wildcard: `"*"` — matches every field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldRule {
    /// Key pattern to match (see Pattern Syntax above).
    pub pattern: String,

    /// Category for replacement generation. Defaults to `Custom("field")`
    /// if not specified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<Category>,

    /// Optional human-readable label for reporting.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl FieldRule {
    /// Create a new field rule with just a pattern.
    #[must_use]
    pub fn new(pattern: impl Into<String>) -> Self {
        Self {
            pattern: pattern.into(),
            category: None,
            label: None,
        }
    }

    /// Set the category for this rule.
    #[must_use]
    pub fn with_category(mut self, category: Category) -> Self {
        self.category = Some(category);
        self
    }

    /// Set the label for this rule.
    #[must_use]
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = Some(label.into());
        self
    }
}

// ---------------------------------------------------------------------------
// FileTypeProfile
// ---------------------------------------------------------------------------

/// Specifies which processor to use and what fields to sanitize.
///
/// # Example (serialized as JSON)
///
/// ```json
/// {
///   "processor": "key_value",
///   "extensions": [".rb", ".conf"],
///   "fields": [
///     { "pattern": "*.password", "category": "custom:password" },
///     { "pattern": "*.secret",   "category": "custom:secret"   },
///     { "pattern": "smtp_address", "category": "hostname" }
///   ],
///   "options": {
///     "delimiter": "=",
///     "comment_prefix": "#"
///   }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileTypeProfile {
    /// Name of the processor to use (e.g. `"key_value"`, `"json"`).
    pub processor: String,

    /// File extensions this profile applies to (e.g. `[".rb", ".conf"]`).
    #[serde(default)]
    pub extensions: Vec<String>,

    /// Field rules: which keys/paths to sanitize.
    pub fields: Vec<FieldRule>,

    /// Free-form options passed to the processor (e.g. delimiter, comment chars).
    #[serde(default)]
    pub options: std::collections::HashMap<String, String>,
}

impl FileTypeProfile {
    /// Create a minimal profile for a given processor.
    #[must_use]
    pub fn new(processor: impl Into<String>, fields: Vec<FieldRule>) -> Self {
        Self {
            processor: processor.into(),
            extensions: Vec::new(),
            fields,
            options: std::collections::HashMap::new(),
        }
    }

    /// Add an extension to this profile.
    #[must_use]
    pub fn with_extension(mut self, ext: impl Into<String>) -> Self {
        self.extensions.push(ext.into());
        self
    }

    /// Add a free-form option.
    #[must_use]
    pub fn with_option(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.options.insert(key.into(), value.into());
        self
    }

    /// Check whether a filename matches this profile's extensions.
    ///
    /// Returns `false` if the profile has no extensions.
    ///
    /// # Examples
    ///
    /// ```
    /// use sanitize_engine::processor::profile::FieldRule;
    /// use sanitize_engine::processor::profile::FileTypeProfile;
    ///
    /// let profile = FileTypeProfile::new("json", vec![])
    ///     .with_extension(".json")
    ///     .with_extension(".jsonc");
    ///
    /// assert!(profile.matches_filename("config.json"));
    /// assert!(profile.matches_filename("deep/path/app.jsonc"));
    /// assert!(!profile.matches_filename("config.yml"));
    /// assert!(!FileTypeProfile::new("json", vec![]).matches_filename("any.json"));
    /// ```
    pub fn matches_filename(&self, filename: &str) -> bool {
        if self.extensions.is_empty() {
            return false;
        }
        self.extensions
            .iter()
            .any(|ext| filename.ends_with(ext.as_str()))
    }
}

// ---------------------------------------------------------------------------
// Serde support for Category (as string)
// ---------------------------------------------------------------------------

impl Serialize for Category {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Category {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "email" => Category::Email,
            "name" => Category::Name,
            "phone" => Category::Phone,
            "ipv4" => Category::IpV4,
            "ipv6" => Category::IpV6,
            "credit_card" => Category::CreditCard,
            "ssn" => Category::Ssn,
            "hostname" => Category::Hostname,
            "mac_address" => Category::MacAddress,
            "container_id" => Category::ContainerId,
            "uuid" => Category::Uuid,
            "jwt" => Category::Jwt,
            "auth_token" => Category::AuthToken,
            "file_path" => Category::FilePath,
            "windows_sid" => Category::WindowsSid,
            "url" => Category::Url,
            "aws_arn" => Category::AwsArn,
            "azure_resource_id" => Category::AzureResourceId,
            other => {
                let tag = other.strip_prefix("custom:").unwrap_or(other);
                Category::Custom(tag.into())
            }
        })
    }
}
