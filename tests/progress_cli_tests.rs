//! Integration tests for CLI progress behavior in redirected (non-TTY) runs.

use std::fs;
use std::io::Write;
use std::process::Command;
use tempfile::tempdir;

fn write_test_inputs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
    let dir = tempdir().unwrap();
    let input_path = dir.path().join("input.log");
    let secrets_path = dir.path().join("secrets.json");

    fs::write(&input_path, "prefix SUPERSECRET suffix\n").unwrap();
    fs::write(
        &secrets_path,
        r#"[
  {
    "pattern": "SUPERSECRET",
    "kind": "literal",
    "category": "custom:token",
    "label": "token"
  }
]"#,
    )
    .unwrap();

    (dir, input_path, secrets_path)
}

#[test]
fn forced_progress_uses_stderr_and_keeps_stdout_payload_clean() {
    let (_dir, input_path, secrets_path) = write_test_inputs();

    let output = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&input_path)
        .arg("-s")
        .arg(&secrets_path)
        .arg("--unencrypted-secrets")
        .arg("--progress")
        .arg("on")
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "sanitize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Sanitized payload should be on stdout.
    assert!(!stdout.contains("SUPERSECRET"));
    assert!(stdout.contains("prefix"));
    assert!(stdout.contains("suffix"));

    // Progress/status should be emitted on stderr only.
    assert!(stderr.contains("Scanning"));
    assert!(stderr.contains("done"));
    assert!(!stdout.contains("Scanning"));
    assert!(!stdout.contains("done"));
}

#[test]
fn auto_progress_is_silent_in_non_tty_mode() {
    let (_dir, input_path, secrets_path) = write_test_inputs();

    let output = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&input_path)
        .arg("-s")
        .arg(&secrets_path)
        .arg("--unencrypted-secrets")
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "sanitize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stdout.contains("SUPERSECRET"));
    assert!(
        stderr.trim().is_empty(),
        "expected no progress output in auto/non-TTY mode, got: {stderr}"
    );
}

#[test]
fn stdin_pipeline_forced_progress_keeps_stdout_clean() {
    let (_dir, _input_path, secrets_path) = write_test_inputs();

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg("-")
        .arg("-s")
        .arg(&secrets_path)
        .arg("--unencrypted-secrets")
        .arg("--progress")
        .arg("on")
        .env("SANITIZE_LOG", "error")
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"prefix SUPERSECRET suffix\n").unwrap();
    }

    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "sanitize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(!stdout.contains("SUPERSECRET"));
    assert!(stdout.contains("prefix"));
    assert!(stdout.contains("suffix"));

    assert!(stderr.contains("Scanning stdin"));
    assert!(stderr.contains("done"));
    assert!(!stdout.contains("Scanning stdin"));
    assert!(!stdout.contains("done"));
}
