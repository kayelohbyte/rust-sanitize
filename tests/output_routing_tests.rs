//! Regression tests for output routing: `-o -` stdout sentinel and
//! `-o <file>` / `-o <dir>` explicit paths.

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn secrets_json(dir: &std::path::Path) -> std::path::PathBuf {
    let p = dir.join("secrets.json");
    fs::write(
        &p,
        r#"[{"pattern":"SUPERSECRET","kind":"literal","category":"custom:token","label":"tok"}]"#,
    )
    .unwrap();
    p
}

// ---------------------------------------------------------------------------
// -o - (stdout sentinel)
// ---------------------------------------------------------------------------

/// `sanitize <file> -o -` must write sanitized content to stdout, not to a
/// file named `-` in the working directory.
#[test]
fn dash_o_dash_writes_to_stdout_not_a_file() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.log");
    let secrets = secrets_json(dir.path());
    fs::write(&input, "token: SUPERSECRET\n").unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&input)
        .arg("-s")
        .arg(&secrets)
        .arg("-o")
        .arg("-")
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "sanitize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    // Sanitized content must appear on stdout.
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("SUPERSECRET"),
        "raw secret must not appear on stdout"
    );
    assert!(stdout.contains("token:"), "non-secret content must be present");

    // No literal file named `-` must be created.
    assert!(
        !dir.path().join("-").exists(),
        "a file named '-' must not be created"
    );
}

/// Structured input (JSON) with `-o -` must also write to stdout.
#[test]
fn dash_o_dash_works_with_structured_json() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("config.json");
    let secrets = secrets_json(dir.path());
    fs::write(&input, r#"{"token":"SUPERSECRET","host":"example.com"}"#).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&input)
        .arg("-s")
        .arg(&secrets)
        .arg("-o")
        .arg("-")
        .env("SANITIZE_LOG", "error")
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("SUPERSECRET"));
    assert!(stdout.contains("example.com"));
    assert!(!dir.path().join("-").exists());
}

/// Stdin input with `-o -` must write sanitized content to stdout.
#[test]
fn stdin_with_dash_o_dash_writes_to_stdout() {
    use std::io::Write;
    use std::process::Stdio;

    let dir = tempdir().unwrap();
    let secrets = secrets_json(dir.path());

    let mut child = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg("-")
        .arg("-s")
        .arg(&secrets)
        .arg("-o")
        .arg("-")
        .env("SANITIZE_LOG", "error")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"key=SUPERSECRET\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("SUPERSECRET"));
    assert!(stdout.contains("key="));
}

// ---------------------------------------------------------------------------
// -o <file> explicit output path
// ---------------------------------------------------------------------------

/// `sanitize <file> -o <explicit-path>` must write to that exact path.
#[test]
fn explicit_output_file_is_written() {
    let dir = tempdir().unwrap();
    let input = dir.path().join("input.log");
    let out = dir.path().join("clean.log");
    let secrets = secrets_json(dir.path());
    fs::write(&input, "token: SUPERSECRET\n").unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&input)
        .arg("-s")
        .arg(&secrets)
        .arg("-o")
        .arg(&out)
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success());
    assert!(out.exists(), "explicit output file must be created");
    let content = fs::read_to_string(&out).unwrap();
    assert!(!content.contains("SUPERSECRET"));
}

// ---------------------------------------------------------------------------
// -o <dir> output directory
// ---------------------------------------------------------------------------

/// Multiple inputs + `-o <dir>` must write each output into the directory.
#[test]
fn output_dir_receives_all_sanitized_files() {
    let dir = tempdir().unwrap();
    let in1 = dir.path().join("a.log");
    let in2 = dir.path().join("b.log");
    let out_dir = dir.path().join("sanitized");
    let secrets = secrets_json(dir.path());
    fs::write(&in1, "token: SUPERSECRET\n").unwrap();
    fs::write(&in2, "pass: SUPERSECRET\n").unwrap();
    fs::create_dir(&out_dir).unwrap();

    let status = Command::new(env!("CARGO_BIN_EXE_sanitize"))
        .arg(&in1)
        .arg(&in2)
        .arg("-s")
        .arg(&secrets)
        .arg("-o")
        .arg(&out_dir)
        .env("SANITIZE_LOG", "error")
        .status()
        .unwrap();

    assert!(status.success());
    let a_out = out_dir.join("a-sanitized.log");
    let b_out = out_dir.join("b-sanitized.log");
    assert!(a_out.exists());
    assert!(b_out.exists());
    assert!(!fs::read_to_string(&a_out).unwrap().contains("SUPERSECRET"));
    assert!(!fs::read_to_string(&b_out).unwrap().contains("SUPERSECRET"));
}
