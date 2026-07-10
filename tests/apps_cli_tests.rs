//! Integration tests for `scour-secrets apps` subcommands: list, update, dir.
//!
//! Apps are plain YAML directories managed by the user; the CLI surface is
//! list (default), `update` (refresh local copies of built-in bundles from
//! the binary), and `dir` (print the apps directory path).

use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn run_with_apps_dir(args: &[&str], apps_dir: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_scour-secrets"))
        .args(args)
        .env("SCOUR_SECRETS_LOG", "error")
        .env("SCOUR_SECRETS_APPS_DIR", apps_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .unwrap()
}

fn stdout(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stdout).unwrap().trim()
}

fn stderr(o: &std::process::Output) -> &str {
    std::str::from_utf8(&o.stderr).unwrap().trim()
}

fn write_profile(dir: &std::path::Path, filename: &str) {
    fs::write(
        dir.join(filename),
        b"# Test app profile\n- processor: yaml\n  extensions: [\".yaml\"]\n  fields:\n    - pattern: \"*.password\"\n      category: \"custom:password\"\n",
    )
    .unwrap();
}

// ---------------------------------------------------------------------------
// apps list
// ---------------------------------------------------------------------------

#[test]
fn apps_list_shows_builtins() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(&["apps"], dir.path().to_str().unwrap());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(s.contains("gitlab"), "expected gitlab in: {s}");
    assert!(s.contains("nginx"), "expected nginx in: {s}");
    assert!(s.contains("postgresql"), "expected postgresql in: {s}");
}

#[test]
fn apps_list_shows_user_defined_app() {
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("myapp");
    fs::create_dir_all(&app_dir).unwrap();
    write_profile(&app_dir, "profile.yaml");

    let out = run_with_apps_dir(&["apps"], dir.path().to_str().unwrap());
    assert!(out.status.success());
    let s = stdout(&out);
    assert!(s.contains("myapp"), "expected myapp in: {s}");
}

/// A local copy of a built-in whose profile.yaml differs from the shipped
/// bundle is flagged in the list output.
#[test]
fn apps_list_marks_stale_local_copy() {
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("gitlab");
    fs::create_dir_all(&app_dir).unwrap();
    write_profile(&app_dir, "profile.yaml"); // differs from shipped

    let out = run_with_apps_dir(&["apps"], dir.path().to_str().unwrap());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let s = stdout(&out);
    assert!(
        s.contains("update available"),
        "expected staleness marker in: {s}"
    );
}

// ---------------------------------------------------------------------------
// apps dir
// ---------------------------------------------------------------------------

#[test]
fn apps_dir_prints_path() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(&["apps", "dir"], dir.path().to_str().unwrap());
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains(dir.path().to_str().unwrap()),
        "got: {}",
        stdout(&out)
    );
}

// ---------------------------------------------------------------------------
// apps update
// ---------------------------------------------------------------------------

#[test]
fn apps_update_requires_names_or_all() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(&["apps", "update"], dir.path().to_str().unwrap());
    assert!(!out.status.success(), "expected non-zero exit");
    assert!(
        stderr(&out).contains("--all"),
        "expected usage hint; got: {}",
        stderr(&out)
    );
}

/// User-defined apps have no shipped counterpart to update from.
#[test]
fn apps_update_rejects_user_defined_app() {
    let dir = tempdir().unwrap();
    let app_dir = dir.path().join("myapp");
    fs::create_dir_all(&app_dir).unwrap();
    write_profile(&app_dir, "profile.yaml");

    let out = run_with_apps_dir(
        &["apps", "update", "myapp", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(!out.status.success(), "expected non-zero exit");
    assert!(
        stderr(&out).contains("not a built-in"),
        "got: {}",
        stderr(&out)
    );
}

/// `apps update <name> --yes` with no local copy materializes a fresh one.
#[test]
fn apps_update_materializes_missing_copy() {
    let dir = tempdir().unwrap();
    let out = run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(dir.path().join("gitlab/profile.yaml").is_file());
    assert!(dir.path().join("gitlab/secrets.yaml").is_file());
    assert!(
        stdout(&out).contains("installed local copy"),
        "got: {}",
        stdout(&out)
    );
}

/// A freshly materialized copy is up to date; a second update is a no-op.
#[test]
fn apps_update_up_to_date_is_noop() {
    let dir = tempdir().unwrap();
    run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    let out = run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("up to date"), "got: {}", stdout(&out));
}

/// Without --yes a stale copy produces a dry-run summary and non-zero exit;
/// the files are not touched.
#[test]
fn apps_update_dry_run_without_yes() {
    let dir = tempdir().unwrap();
    run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    let profile = dir.path().join("gitlab/profile.yaml");
    write_profile(profile.parent().unwrap(), "profile.yaml");
    let modified = fs::read(&profile).unwrap();

    let out = run_with_apps_dir(&["apps", "update", "gitlab"], dir.path().to_str().unwrap());
    assert!(!out.status.success(), "dry run must exit non-zero");
    assert!(
        stdout(&out).contains("would replace"),
        "got: {}",
        stdout(&out)
    );
    assert_eq!(
        fs::read(&profile).unwrap(),
        modified,
        "dry run must not modify files"
    );
}

/// With --yes a stale profile.yaml is replaced with the shipped version.
#[test]
fn apps_update_replaces_stale_profile() {
    let dir = tempdir().unwrap();
    run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    let profile = dir.path().join("gitlab/profile.yaml");
    let shipped = fs::read(&profile).unwrap();
    write_profile(profile.parent().unwrap(), "profile.yaml");

    let out = run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert_eq!(
        fs::read(&profile).unwrap(),
        shipped,
        "profile.yaml must match the shipped bundle after update"
    );
}

/// secrets.yaml is a union update: locally added entries (e.g. discovered
/// literals from the structured handoff) survive, and shipped entries missing
/// locally are appended.
#[test]
fn apps_update_preserves_local_secrets_and_appends_shipped() {
    let dir = tempdir().unwrap();
    run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    let secrets = dir.path().join("gitlab/secrets.yaml");

    // Replace the local secrets with a single user/discovered entry, dropping
    // every shipped one.
    fs::write(
        &secrets,
        "- pattern: \"discovered-hostname.corp\"\n  kind: literal\n  category: hostname\n  label: discovered\n",
    )
    .unwrap();

    let out = run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(stdout(&out).contains("appended"), "got: {}", stdout(&out));

    let content = fs::read_to_string(&secrets).unwrap();
    assert!(
        content.contains("discovered-hostname.corp"),
        "local entry must survive the update; got:\n{content}"
    );
    assert!(
        content.contains("glpat-"),
        "shipped entries must be appended; got:\n{content}"
    );
}

/// `--all` refreshes only apps with an existing local copy.
#[test]
fn apps_update_all_touches_existing_copies_only() {
    let dir = tempdir().unwrap();
    run_with_apps_dir(
        &["apps", "update", "gitlab", "--yes"],
        dir.path().to_str().unwrap(),
    );

    let out = run_with_apps_dir(
        &["apps", "update", "--all", "--yes"],
        dir.path().to_str().unwrap(),
    );
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    assert!(
        stdout(&out).contains("gitlab: up to date"),
        "got: {}",
        stdout(&out)
    );
    assert!(
        !dir.path().join("nginx").exists(),
        "--all must not materialize apps that were never used"
    );
}
