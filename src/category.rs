//! Data category types for classifying sensitive values.
//!
//! Each sensitive value detected belongs to a `Category`, which determines
//! the format of its replacement. For example, emails are replaced with
//! syntactically valid emails, IPv4 addresses with valid IPv4 addresses, etc.

use compact_str::CompactString;
use std::borrow::Cow;
use std::fmt;

/// Classification of a sensitive data value. Determines the replacement format.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Category {
    // ── PII ────────────────────────────────────────────────────────────
    /// Email addresses → preserve domain, hex username
    Email,
    /// Person names → synthetic name from hash-indexed table
    Name,
    /// Phone numbers → format-preserving numeric replacement
    Phone,
    /// Credit card numbers → format-preserving numeric replacement (fails Luhn)
    CreditCard,
    /// Social Security Numbers → `000-<hash>`-formatted replacement
    Ssn,

    // ── Network & Infrastructure ───────────────────────────────────────
    /// IPv4 addresses → preserve dots, replace digit groups
    IpV4,
    /// IPv6 addresses → preserve colons/`::`, replace hex digits
    IpV6,
    /// MAC addresses → preserve `:` or `-` separators, replace hex digits
    MacAddress,
    /// Hostname / FQDN → preserve domain suffix, hex prefix
    Hostname,
    /// Docker / container hex IDs → replace hex digits
    ContainerId,

    // ── Application & Identity ─────────────────────────────────────────
    /// UUIDs → preserve `-` dashes, replace hex digits
    Uuid,
    /// JSON Web Tokens → preserve `.` separators, replace base64url chars
    Jwt,
    /// Opaque auth tokens / API keys / bearer tokens
    AuthToken,

    // ── System & OS ────────────────────────────────────────────────────
    /// File paths → preserve `/`, `\`, and extension; replace segment content
    FilePath,
    /// Windows Security Identifiers → preserve `S-` prefix and `-` separators
    WindowsSid,

    // ── Web ────────────────────────────────────────────────────────────
    /// URLs → preserve scheme and structural chars (`://`, `/`, `?`, `=`, `&`)
    Url,

    // ── Cloud ──────────────────────────────────────────────────────────
    /// AWS ARNs → preserve `:` and `/` separators, replace content segments
    AwsArn,
    /// Azure Resource IDs → preserve `/` structure and well-known segment names
    AzureResourceId,

    // ── Catch-all ──────────────────────────────────────────────────────
    /// Arbitrary / user-defined category
    Custom(CompactString),
}

impl fmt::Display for Category {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Category::Custom(name) => write!(f, "custom:{name}"),
            other => f.write_str(other.as_str()),
        }
    }
}

impl Category {
    /// Return the canonical string representation for this category.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Category::Email => "email",
            Category::Name => "name",
            Category::Phone => "phone",
            Category::CreditCard => "credit_card",
            Category::Ssn => "ssn",
            Category::IpV4 => "ipv4",
            Category::IpV6 => "ipv6",
            Category::MacAddress => "mac_address",
            Category::Hostname => "hostname",
            Category::ContainerId => "container_id",
            Category::Uuid => "uuid",
            Category::Jwt => "jwt",
            Category::AuthToken => "auth_token",
            Category::FilePath => "file_path",
            Category::WindowsSid => "windows_sid",
            Category::Url => "url",
            Category::AwsArn => "aws_arn",
            Category::AzureResourceId => "azure_resource_id",
            Category::Custom(name) => name.as_str(),
        }
    }

    /// Return a collision-safe key for HMAC domain separation.
    ///
    /// For `Custom` categories this includes the `custom:` prefix so that
    /// `Custom("email")` cannot collide with the built-in `Email` tag.
    /// Returns `Borrowed` for all built-in variants (zero allocation) and
    /// `Owned` only for `Custom` (one allocation per HMAC call).
    #[must_use]
    pub fn domain_tag_hmac(&self) -> Cow<'_, str> {
        match self {
            Category::Custom(name) => Cow::Owned(format!("custom:{name}")),
            other => Cow::Borrowed(other.as_str()),
        }
    }
}
