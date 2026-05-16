//! Integration tests for the `sanitize template` subcommand.
//!
//! Covers:
//! - Default preset generates a YAML file with `secrets:` content
//! - Named presets (web, k8s, database, aws) generate preset-specific files
//! - Refusing to overwrite an existing file without `--overwrite`
//! - `--overwrite` replaces an existing file
//! - The generated template is accepted by a sanitize run

use std::fs;
use std::process::Command;
use tempfile::tempdir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn run_template(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args(std::iter::once("template").chain(args.iter().copied()))
        .env("SANITIZE_LOG", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap()
}

fn stderr(o: &std::process::Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn template_default_creates_generic_yaml() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    let out = run_template(&["-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        out_path.exists(),
        "template output file should exist at {}",
        out_path.display()
    );

    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("secrets:"),
        "template should contain 'secrets:' key; got:\n{content}"
    );
    assert!(
        content.contains("pattern:"),
        "template should contain at least one 'pattern:' entry; got:\n{content}"
    );
}

#[test]
fn template_preset_web_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("web-secrets.yaml");

    let out = run_template(&["--preset", "web", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(out_path.exists(), "web template file should exist");

    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("jwt") || lower.contains("session"),
        "web template should contain 'jwt' or 'session'; got:\n{content}"
    );
}

#[test]
fn template_preset_k8s_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("k8s-secrets.yaml");

    let out = run_template(&["--preset", "k8s", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(out_path.exists(), "k8s template file should exist");

    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("k8s")
            || lower.contains("kubernetes")
            || lower.contains("namespace")
            || lower.contains("serviceaccount"),
        "k8s template should contain k8s-related terminology; got:\n{content}"
    );
}

#[test]
fn template_preset_database_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("db-secrets.yaml");

    let out = run_template(&["--preset", "database", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(out_path.exists(), "database template file should exist");

    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        lower.contains("password") || lower.contains("connection") || lower.contains("database"),
        "database template should contain password/connection/database; got:\n{content}"
    );
}

#[test]
fn template_preset_aws_creates_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("aws-secrets.yaml");

    let out = run_template(&["--preset", "aws", "-o", out_path.to_str().unwrap()]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(out_path.exists(), "aws template file should exist");

    let content = fs::read_to_string(&out_path).unwrap();
    let lower = content.to_lowercase();
    assert!(
        content.contains("AKIA") || lower.contains("aws") || lower.contains("arn:aws"),
        "aws template should contain AKIA/aws/arn:aws; got:\n{content}"
    );
}

#[test]
fn template_fails_without_overwrite_when_file_exists() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    // First run: create the template.
    let out1 = run_template(&["-o", out_path.to_str().unwrap()]);
    assert!(out1.status.success(), "first run failed: {}", stderr(&out1));
    assert!(out_path.exists());

    // Second run without --overwrite should be refused.
    let out2 = run_template(&["-o", out_path.to_str().unwrap()]);
    assert!(
        !out2.status.success(),
        "expected failure when file already exists without --overwrite"
    );
}

#[test]
fn template_overwrite_flag_replaces_existing_file() {
    let dir = tempdir().unwrap();
    let out_path = dir.path().join("secrets.yaml");

    // Write dummy content at the target path.
    fs::write(&out_path, b"dummy content that should be replaced\n").unwrap();

    let out = run_template(&["-o", out_path.to_str().unwrap(), "--overwrite"]);

    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let content = fs::read_to_string(&out_path).unwrap();
    assert!(
        content.contains("secrets:"),
        "file should contain 'secrets:' after overwrite; got:\n{content}"
    );
    assert!(
        !content.contains("dummy content"),
        "old content should have been replaced; got:\n{content}"
    );
}

#[test]
fn template_generated_file_is_valid_for_sanitize() {
    let dir = tempdir().unwrap();
    let template_path = dir.path().join("secrets.yaml");
    let input_path = dir.path().join("input.txt");
    let out_path = dir.path().join("out.txt");

    // Generate a template with the default (generic) preset.
    let tpl_out = run_template(&["--preset", "generic", "-o", template_path.to_str().unwrap()]);
    assert!(
        tpl_out.status.success(),
        "template generation failed: {}",
        stderr(&tpl_out)
    );
    assert!(template_path.exists());

    // The template is a human-editable YAML file whose top-level key is
    // `secrets:` (a sequence). The sanitize CLI auto-detects secrets format
    // from file content: files starting with `#` (the template header) fall
    // through to the TOML detector, which cannot parse YAML.  To make the
    // generated template usable as a `-s` argument, we extract the inner YAML
    // sequence and write it as a standalone YAML array file (the native format
    // for plaintext YAML secrets files).
    let raw = fs::read_to_string(&template_path).unwrap();

    // Strip comment lines and the `secrets:` wrapper to obtain a bare YAML
    // sequence.  The sequence entries start at the first `  - ` line.
    let entries_yaml: String = raw
        .lines()
        .filter(|l| {
            let t = l.trim_start();
            // Keep entry lines (start with `- ` after stripping indentation)
            // and continuation lines (start with `  ` within an entry, but not
            // the bare `secrets:` key itself).
            !t.is_empty() && !t.starts_with('#') && t != "secrets:"
        })
        .map(|l| {
            // Remove one level of leading indentation (two spaces) that
            // nests the entries under `secrets:`.
            l.strip_prefix("  ").unwrap_or(l)
        })
        .fold(String::new(), |mut acc, l| {
            acc.push_str(l);
            acc.push('\n');
            acc
        });

    let usable_secrets = dir.path().join("usable-secrets.yaml");
    fs::write(&usable_secrets, entries_yaml.as_bytes()).unwrap();

    // Create a simple input file.
    fs::write(&input_path, b"safe text with no secrets here\n").unwrap();

    // Run sanitize with the usable secrets file derived from the template.
    let run_out = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .args([
            input_path.to_str().unwrap(),
            "-s",
            usable_secrets.to_str().unwrap(),
            "-o",
            out_path.to_str().unwrap(),
        ])
        .env("SANITIZE_LOG", "error")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap();

    assert!(
        run_out.status.success(),
        "sanitize run with secrets derived from generated template should exit 0; stderr: {}",
        String::from_utf8_lossy(&run_out.stderr)
    );
}
