//! LLM prompt formatting — template resolution and prompt assembly.
//!
//! Provides the built-in prompt templates and the helpers needed to build a
//! structured LLM prompt from sanitized content and an optional sanitization
//! report.
//!
//! # Built-in templates
//!
//! | Name | Use case |
//! |------|----------|
//! | `"troubleshoot"` | Incident triage — root cause, event sequence, remediation |
//! | `"review-config"` | Config review — misconfigurations, security concerns, best practices |
//!
//! A filesystem path can be supplied instead of a name; the file's raw content
//! is used as-is (no substitution is applied to custom templates).
//!
//! # Example
//!
//! ```rust
//! use sanitize_engine::llm::{format_llm_prompt, LlmEntry};
//!
//! let entries: Vec<LlmEntry> = vec![
//!     ("app.log".to_string(), b"INFO start\nERROR disk full\n".to_vec()),
//! ];
//! let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
//! assert!(prompt.contains("Root cause"));
//! assert!(prompt.contains("<content name=\"app.log\">"));
//! ```

use crate::report::SanitizeReport;
use std::fmt::Write as FmtWrite;
use std::fs;

/// A single content entry for the LLM prompt: `(label, sanitized_bytes)`.
pub type LlmEntry = (String, Vec<u8>);

/// Preamble injected into every built-in template, explaining the sanitization
/// model to the LLM so it does not attempt to recover original values.
pub const PROMPT_PREAMBLE: &str = "\
Sensitive values in the content below have been sanitized:
- Structured fields (passwords, tokens, API keys) appear as __SANITIZED-<hash>__
- Typed values (emails, IPs, hostnames, etc.) are replaced with realistic-looking
  substitutes of the same format and length

In all cases the same original value always maps to the same replacement within
a run, so relationships and patterns in the data are preserved. Do not attempt
to recover original values. When referencing specific values in your response,
use the sanitized forms as shown.
";

/// Built-in template for incident troubleshooting.
pub const TEMPLATE_TROUBLESHOOT: &str = "\
You are troubleshooting an incident based on sanitized output.

{preamble}
Analyze the following and provide:
1. Root cause of any errors or failures
2. The sequence of events that led to the issue
3. Specific remediation steps

";

/// Built-in template for configuration review.
pub const TEMPLATE_REVIEW_CONFIG: &str = "\
You are reviewing a sanitized configuration file.

{preamble}
Review the following and identify:
1. Misconfigurations or invalid settings
2. Security concerns (exposed services, weak settings, overly permissive rules)
3. Best practice violations or missing required fields

";

/// Resolve a template name or path to its instruction text.
///
/// Accepts `"troubleshoot"`, `"review-config"` (built-in templates with the
/// preamble embedded), or an arbitrary filesystem path whose raw content is
/// returned unchanged.
///
/// # Errors
///
/// Returns an error string if a custom path cannot be read from disk.
pub fn resolve_llm_template(template_name: &str) -> Result<String, String> {
    match template_name {
        "troubleshoot" => Ok(TEMPLATE_TROUBLESHOOT.replace("{preamble}", PROMPT_PREAMBLE)),
        "review-config" => Ok(TEMPLATE_REVIEW_CONFIG.replace("{preamble}", PROMPT_PREAMBLE)),
        path => fs::read_to_string(path)
            .map_err(|e| format!("failed to read LLM template '{}': {e}", path)),
    }
}

/// Build a complete LLM prompt from a template, content entries, and an
/// optional sanitization report.
///
/// The prompt structure is:
/// 1. Template instructions (with preamble embedded for built-ins)
/// 2. `## Sanitization Summary` — file count and total replacements (when `report` is `Some`)
/// 3. One `<content name="…">…</content>` block per entry
/// 4. `<notable_events>…</notable_events>` — keyword-matched log lines with
///    surrounding context (only when the report contains log context with hits)
///
/// # Errors
///
/// Returns an error string if the template cannot be resolved.
pub fn format_llm_prompt(
    template_name: &str,
    entries: &[LlmEntry],
    report: Option<&SanitizeReport>,
) -> Result<String, String> {
    let mut out = resolve_llm_template(template_name)?;

    if let Some(r) = report {
        let total_replacements: u64 = r.files.iter().map(|f| f.replacements).sum();
        write!(
            out,
            "## Sanitization Summary\n\
             - Files processed: {}\n\
             - Total replacements: {total_replacements}\n\n",
            r.files.len()
        )
        .unwrap();
    }

    for (label, bytes) in entries {
        let content = String::from_utf8_lossy(bytes);
        write!(
            out,
            "<content name=\"{}\">\n{}\n</content>\n\n",
            label, content
        )
        .unwrap();
    }

    if let Some(r) = report {
        let notable: Vec<_> = r
            .files
            .iter()
            .filter_map(|f| f.log_context.as_ref().map(|ctx| (&f.path, ctx)))
            .filter(|(_, ctx)| ctx.match_count > 0)
            .collect();

        if !notable.is_empty() {
            out.push_str("<notable_events>\n");
            let mut any_truncated = false;
            for (path, ctx) in &notable {
                writeln!(out, "# {path}").unwrap();
                for m in &ctx.matches {
                    for line in &m.before {
                        writeln!(out, "  {line}").unwrap();
                    }
                    writeln!(out, ">>> [{}] {}", m.keyword, m.line).unwrap();
                    for line in &m.after {
                        writeln!(out, "  {line}").unwrap();
                    }
                    out.push('\n');
                }
                if ctx.truncated {
                    any_truncated = true;
                }
            }
            if any_truncated {
                out.push_str(
                    "(notable events truncated — use --context-lines or --report for full context)\n",
                );
            }
            out.push_str("</notable_events>\n");
        }
    }

    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_context::{extract_context, LogContextConfig};
    use crate::report::{FileReport, ReportBuilder, ReportMetadata};
    use crate::scanner::ScanStats;
    use std::fs;
    use tempfile::tempdir;

    fn make_test_report(replacements: u64) -> SanitizeReport {
        let builder = ReportBuilder::new(ReportMetadata {
            version: "0.0.0".into(),
            timestamp: "test".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1024,
            threads: None,
            secrets_file: None,
        });
        builder.record_file(FileReport::from_scan_stats(
            "test.log",
            &ScanStats {
                matches_found: replacements,
                replacements_applied: replacements,
                ..Default::default()
            },
            "scanner",
        ));
        builder.finish()
    }

    #[test]
    fn troubleshoot_embeds_preamble_and_instructions() {
        let t = resolve_llm_template("troubleshoot").unwrap();
        assert!(t.contains("sanitized"), "preamble should be embedded");
        assert!(
            t.contains("Root cause"),
            "should request root cause analysis"
        );
        assert!(
            t.contains("remediation"),
            "should request remediation steps"
        );
    }

    #[test]
    fn review_config_embeds_preamble_and_instructions() {
        let t = resolve_llm_template("review-config").unwrap();
        assert!(t.contains("sanitized"), "preamble should be embedded");
        assert!(
            t.contains("Misconfigurations"),
            "should request misconfiguration review"
        );
        assert!(
            t.contains("Security concerns"),
            "should request security review"
        );
    }

    #[test]
    fn nonexistent_path_returns_error() {
        let err = resolve_llm_template("/nonexistent/template.txt").unwrap_err();
        assert!(err.contains("failed to read"), "got: {err}");
    }

    #[test]
    fn custom_file_returns_raw_content() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("custom.txt");
        fs::write(&p, "MY CUSTOM INSTRUCTIONS\n").unwrap();
        let t = resolve_llm_template(p.to_str().unwrap()).unwrap();
        assert_eq!(t, "MY CUSTOM INSTRUCTIONS\n");
    }

    #[test]
    fn prompt_includes_content_block() {
        let entries = vec![("app.log".to_string(), b"sanitized line\n".to_vec())];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        assert!(
            prompt.contains("<content name=\"app.log\">"),
            "got:\n{prompt}"
        );
        assert!(prompt.contains("sanitized line"), "got:\n{prompt}");
        assert!(prompt.contains("</content>"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_includes_sanitization_summary() {
        let report = make_test_report(7);
        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(prompt.contains("## Sanitization Summary"), "got:\n{prompt}");
        assert!(prompt.contains("Files processed: 1"), "got:\n{prompt}");
        assert!(prompt.contains("Total replacements: 7"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_includes_notable_events_when_present() {
        let builder = ReportBuilder::new(ReportMetadata {
            version: "0.0.0".into(),
            timestamp: "test".into(),
            deterministic: false,
            dry_run: false,
            strict: false,
            chunk_size: 1024,
            threads: None,
            secrets_file: None,
        });
        builder.record_file(FileReport::from_scan_stats(
            "app.log",
            &ScanStats::default(),
            "scanner",
        ));
        let ctx = extract_context(
            "INFO start\nERROR disk full\nINFO done",
            &LogContextConfig::new().with_context_lines(1),
        );
        builder.set_file_log_context("app.log", ctx);
        let report = builder.finish();

        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(prompt.contains("<notable_events>"), "got:\n{prompt}");
        assert!(prompt.contains("# app.log"), "got:\n{prompt}");
        assert!(prompt.contains(">>> [error]"), "got:\n{prompt}");
        assert!(prompt.contains("ERROR disk full"), "got:\n{prompt}");
        assert!(prompt.contains("</notable_events>"), "got:\n{prompt}");
    }

    #[test]
    fn prompt_omits_notable_events_when_no_matches() {
        let report = make_test_report(0);
        let entries: Vec<LlmEntry> = vec![];
        let prompt = format_llm_prompt("troubleshoot", &entries, Some(&report)).unwrap();
        assert!(
            !prompt.contains("<notable_events>"),
            "should omit section when no keyword matches"
        );
    }

    #[test]
    fn prompt_multiple_content_blocks_in_order() {
        let entries = vec![
            ("first.log".to_string(), b"first content".to_vec()),
            ("second.log".to_string(), b"second content".to_vec()),
        ];
        let prompt = format_llm_prompt("troubleshoot", &entries, None).unwrap();
        let first_pos = prompt.find("first.log").unwrap();
        let second_pos = prompt.find("second.log").unwrap();
        assert!(
            first_pos < second_pos,
            "entries should appear in insertion order"
        );
    }
}
