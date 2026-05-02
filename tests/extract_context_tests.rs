//! Integration tests for `--extract-context`, `--context-keywords`,
//! `--context-keywords-only`, and `--strip-values`.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

fn empty_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, "[]").unwrap();
    p
}

// ---------------------------------------------------------------------------
// --extract-context via --report
// ---------------------------------------------------------------------------

#[test]
fn extract_context_appears_in_report_json() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let input = dir.path().join("app.log");
    fs::write(&input, "INFO start\nERROR disk full\nINFO retrying\n").unwrap();
    let report_path = dir.path().join("report.json");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--report",
            report_path.to_str().unwrap(),
            "--extract-context",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(report_path.exists(), "report file was not created");

    let report = fs::read_to_string(&report_path).unwrap();
    assert!(
        report.contains("log_context"),
        "report missing log_context field"
    );
    assert!(
        report.contains("ERROR disk full") || report.contains("disk full"),
        "error line should appear in log_context"
    );
}

#[test]
fn extract_context_respects_context_lines_zero() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let input = dir.path().join("app.log");
    fs::write(&input, "INFO before\nERROR exploded\nINFO after\n").unwrap();
    let report_path = dir.path().join("report.json");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--report",
            report_path.to_str().unwrap(),
            "--extract-context",
            "--context-lines",
            "0",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(out.status.success());
    let report = fs::read_to_string(&report_path).unwrap();
    // With 0 context lines, "before" and "after" lines should not appear in the match context.
    assert!(report.contains("ERROR exploded") || report.contains("exploded"));
    // The "before"/"after" arrays in the JSON should be empty (no surrounding context captured).
    assert!(
        report.contains("\"before\":[]") || report.contains("\"before\": []"),
        "expected empty before context at context_lines=0, report: {report}"
    );
}

#[test]
fn extract_context_respects_context_lines_nonzero() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let input = dir.path().join("app.log");
    fs::write(
        &input,
        "INFO start\nINFO preparing\nERROR exploded\nINFO cleanup\nINFO end\n",
    )
    .unwrap();
    let report_path = dir.path().join("report.json");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--report",
            report_path.to_str().unwrap(),
            "--extract-context",
            "--context-lines",
            "2",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(out.status.success());
    let report = fs::read_to_string(&report_path).unwrap();
    // With 2 context lines we should capture "INFO preparing" (before) and "INFO cleanup" (after).
    assert!(
        report.contains("INFO preparing"),
        "expected 'INFO preparing' in context, got: {report}"
    );
    assert!(
        report.contains("INFO cleanup"),
        "expected 'INFO cleanup' in context, got: {report}"
    );
}

// ---------------------------------------------------------------------------
// --context-keywords
// ---------------------------------------------------------------------------

#[test]
fn extract_context_custom_keywords_are_matched() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let input = dir.path().join("app.log");
    fs::write(
        &input,
        "INFO start\nWARN connection timeout reached\nINFO end\n",
    )
    .unwrap();
    let report_path = dir.path().join("report.json");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--report",
            report_path.to_str().unwrap(),
            "--extract-context",
            "--context-keywords",
            "timeout",
            "--context-lines",
            "0",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(out.status.success());
    let report = fs::read_to_string(&report_path).unwrap();
    assert!(
        report.contains("timeout"),
        "custom keyword 'timeout' should produce a match, got: {report}"
    );
}

#[test]
fn extract_context_keywords_only_replaces_defaults() {
    let dir = tempdir().unwrap();
    let s = empty_secrets(dir.path());
    let input = dir.path().join("app.log");
    // "error" is a default keyword; "oomkilled" is our custom-only keyword.
    fs::write(&input, "ERROR default match\nINFO oomkilled custom match\n").unwrap();
    let report_path = dir.path().join("report.json");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "-s",
            s.to_str().unwrap(),
            "--report",
            report_path.to_str().unwrap(),
            "--extract-context",
            "--context-keywords",
            "oomkilled",
            "--context-keywords-only",
            "--context-lines",
            "0",
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(out.status.success());
    let report = fs::read_to_string(&report_path).unwrap();

    // "oomkilled" line must be captured.
    assert!(
        report.contains("oomkilled"),
        "custom keyword should produce a match, got: {report}"
    );

    // The match count should be 1: "ERROR default match" must NOT match because
    // --context-keywords-only replaced the defaults.
    let match_count_one =
        report.contains("\"match_count\":1") || report.contains("\"match_count\": 1");
    assert!(
        match_count_one,
        "default 'error' keyword should be suppressed by --context-keywords-only, got: {report}"
    );
}

// ---------------------------------------------------------------------------
// --strip-values (file input)
// ---------------------------------------------------------------------------

#[test]
fn strip_values_removes_values_from_file() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("config.cfg");
    fs::write(&input, "host = localhost\nport = 5432\npassword = s3cr3t\n").unwrap();
    let output_path = dir.path().join("out.cfg");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--strip-values",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("host"), "key should be preserved");
    assert!(content.contains("port"), "key should be preserved");
    assert!(content.contains("password"), "key should be preserved");
    assert!(!content.contains("localhost"), "value should be stripped");
    assert!(!content.contains("5432"), "value should be stripped");
    assert!(!content.contains("s3cr3t"), "value should be stripped");
}

#[test]
fn strip_values_preserves_comments_and_blank_lines_in_file() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("config.cfg");
    fs::write(&input, "# database settings\n\nhost = localhost\n").unwrap();
    let output_path = dir.path().join("out.cfg");

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input.to_str().unwrap(),
            "--strip-values",
            "-o",
            output_path.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(out.status.success());
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(
        content.contains("# database settings"),
        "comment should be preserved"
    );
    // Blank line should be preserved (two newlines around the blank line section).
    assert!(
        content.contains("\n\n") || content.lines().count() >= 3,
        "blank line should be preserved"
    );
    assert!(!content.contains("localhost"), "value should be stripped");
}

// ---------------------------------------------------------------------------
// --strip-values (stdin with explicit output file)
// ---------------------------------------------------------------------------

#[test]
fn strip_values_stdin_to_output_file() {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("stripped.cfg");

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(["-", "--strip-values", "-o", output_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SANITIZE_LOG", "error")
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"host = localhost\nport = 5432\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(content.contains("host"), "key should be preserved");
    assert!(content.contains("port"), "key should be preserved");
    assert!(!content.contains("localhost"), "value should be stripped");
    assert!(!content.contains("5432"), "value should be stripped");
}

#[test]
fn strip_values_section_headers_preserved_stdin() {
    let dir = tempdir().unwrap();
    let output_path = dir.path().join("stripped.cfg");

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(["-", "--strip-values", "-o", output_path.to_str().unwrap()])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SANITIZE_LOG", "error")
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"[database]\nhost = localhost\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();

    assert!(out.status.success());
    let content = fs::read_to_string(&output_path).unwrap();
    assert!(
        content.contains("[database]"),
        "section header should be preserved"
    );
    assert!(!content.contains("localhost"), "value should be stripped");
}
