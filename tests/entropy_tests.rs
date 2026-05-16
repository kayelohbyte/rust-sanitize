//! Integration tests for the `--entropy-threshold` CLI flag.
//!
//! Covers:
//! - High-entropy tokens are replaced at a moderate threshold
//! - Threshold of 0.0 causes nearly all tokens to be replaced
//! - A very high threshold passes tokens through unchanged
//! - Entropy detection works when reading from stdin
//! - The JSON report reflects entropy-triggered match counts

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run sanitize with the given args, writing stdin from `input`.
fn run_stdin(args: &[&str], input: &[u8]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .env("SANITIZE_LOG", "error")
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}

/// Write a minimal secrets file that matches nothing.
fn write_empty_secrets(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(&p, "[]").unwrap();
    p
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn entropy_threshold_replaces_high_entropy_token() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path());
    let input_file = dir.path().join("input.txt");
    let out_file = dir.path().join("out.txt");

    // AKIAIOSFODNN7EXAMPLE is an AWS-key-format token with high Shannon entropy.
    // "hello" is a very low-entropy English word.
    fs::write(&input_file, b"hello AKIAIOSFODNN7EXAMPLE\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_file.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--entropy-threshold",
            "3.5",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&out_file).unwrap();
    assert!(
        !content.contains("AKIAIOSFODNN7EXAMPLE"),
        "high-entropy token should be replaced; got:\n{content}"
    );
    assert!(
        content.contains("hello"),
        "low-entropy word should pass through; got:\n{content}"
    );
}

#[test]
fn entropy_threshold_zero_replaces_everything_with_entropy() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path());
    let input_file = dir.path().join("input.txt");
    let out_file = dir.path().join("out.txt");

    // The entropy detector requires tokens of 20–200 alphanumeric characters.
    // Use a 20-character all-lowercase token: even at threshold 0.0 it has
    // non-zero entropy (bits per char > 0), so it will be caught.
    // "aaaaaaaaaaaaaaaaaaaaa" has entropy 0.0 but "abcdefghijklmnopqrst"
    // has positive entropy and is exactly 20 chars.
    fs::write(&input_file, b"token=abcdefghijklmnopqrst\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_file.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--entropy-threshold",
            "0.0",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&out_file).unwrap();
    assert!(
        !content.contains("abcdefghijklmnopqrst"),
        "20-char token should be replaced at threshold 0.0; got:\n{content}"
    );
}

#[test]
fn entropy_threshold_high_value_passes_everything_through() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path());
    let input_file = dir.path().join("input.txt");
    let out_file = dir.path().join("out.txt");

    // With an extremely high threshold (7.9 bits/char), the tool should not
    // flag sk-abc123 via entropy detection, and the empty secrets file won't
    // match it either, so it passes through unchanged.
    fs::write(&input_file, b"token=sk-abc123\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_file.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--entropy-threshold",
            "7.9",
            "-o",
            out_file.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&out_file).unwrap();
    assert!(
        content.contains("sk-abc123"),
        "token should survive a very high entropy threshold; got:\n{content}"
    );
}

#[test]
fn entropy_threshold_works_on_stdin() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path());
    let out_file = dir.path().join("out.txt");

    // Feed a high-entropy token via stdin using "-" as the input path.
    let out = run_stdin(
        &[
            "-",
            "-s",
            secrets.to_str().unwrap(),
            "--entropy-threshold",
            "3.5",
            "-o",
            out_file.to_str().unwrap(),
        ],
        b"AKIAIOSFODNN7EXAMPLE\n",
    );

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    let content = fs::read_to_string(&out_file).unwrap();
    assert!(
        !content.contains("AKIAIOSFODNN7EXAMPLE"),
        "high-entropy token piped via stdin should be replaced; got:\n{content}"
    );
}

#[test]
fn entropy_report_counts_entropy_matches() {
    let dir = tempdir().unwrap();
    let secrets = write_empty_secrets(dir.path());
    let input_file = dir.path().join("input.txt");
    let out_file = dir.path().join("out.txt");
    let report_file = dir.path().join("report.json");

    fs::write(&input_file, b"AKIAIOSFODNN7EXAMPLE\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_file.to_str().unwrap(),
            "-s",
            secrets.to_str().unwrap(),
            "--entropy-threshold",
            "3.5",
            "-o",
            out_file.to_str().unwrap(),
            "--report",
            report_file.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );

    assert!(
        report_file.exists(),
        "report file should be created at {}",
        report_file.display()
    );

    let report_content = fs::read_to_string(&report_file).unwrap();
    let report: serde_json::Value = serde_json::from_str(&report_content)
        .unwrap_or_else(|e| panic!("report is not valid JSON: {e}\ncontent:\n{report_content}"));

    // The report must record at least one match for the high-entropy token.
    let total_matches = report["summary"]["total_matches"].as_u64().unwrap_or(0);
    assert!(
        total_matches >= 1,
        "expected at least 1 match in report summary, got {total_matches};\nreport:\n{report_content}"
    );
}
