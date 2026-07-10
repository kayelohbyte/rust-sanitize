use crate::cli_args::{AppsArgs, AppsSubCommand, AppsUpdateArgs};
use scour_secrets::atomic_write_private;
use scour_secrets::processor::FileTypeProfile;
use scour_secrets::secrets::{
    looks_encrypted, parse_secrets, serialize_secrets, SecretEntry, SecretsFormat,
};
use std::fs;
use std::path::{Path, PathBuf};

// ---------------------------------------------------------------------------
// Built-in app bundles
// ---------------------------------------------------------------------------
//
// Each app ships embedded in the binary from  apps/<name>/
//   secrets.yaml  — Vec<SecretEntry>  (optional; omit when the app has none)
//   profile.yaml  — Vec<FileTypeProfile> (optional)
//
// On first `--app <name>` use the bundle is materialized into the apps
// directory (SCOUR_SECRETS_APPS_DIR, falling back to
// ~/.config/scour-secrets/apps — XDG-compatible) and from then on the files
// there are the single source of truth for the app: users edit them in place,
// the structured handoff appends discovered literals to the app's
// secrets.yaml, and `scour-secrets apps update` refreshes them from the
// binary. User-defined apps follow the same two-file convention in the same
// directory.
//
// The first YAML comment line (# ...) in either file is shown as the
// description in  `scour-secrets apps`.

/// Compiled content loaded from an app bundle directory.
pub(crate) struct AppBundle {
    pub(crate) secrets: Vec<SecretEntry>,
    pub(crate) profiles: Vec<FileTypeProfile>,
}

pub(crate) struct BuiltinApp {
    pub(crate) name: &'static str,
    pub(crate) description: &'static str,
    /// `Vec<SecretEntry>` YAML; None when the app has no unique secrets patterns.
    pub(crate) secrets_yaml: Option<&'static str>,
    /// `Vec<FileTypeProfile>` YAML; None when the app has no profile rules.
    pub(crate) profile_yaml: Option<&'static str>,
}

pub(crate) const BUILTIN_APPS: &[BuiltinApp] = &[
    BuiltinApp {
        name: "ansible",
        description: "Ansible — group_vars, host_vars, vault credentials",
        secrets_yaml: Some(include_str!("../../../apps/ansible/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/ansible/profile.yaml")),
    },
    BuiltinApp {
        name: "aws-cli",
        description: "AWS CLI — ~/.aws/credentials, ~/.aws/config access keys",
        secrets_yaml: Some(include_str!("../../../apps/aws-cli/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/aws-cli/profile.yaml")),
    },
    BuiltinApp {
        name: "circleci",
        description: "CircleCI — .circleci/config.yml job/step environment variables, docker auth",
        secrets_yaml: Some(include_str!("../../../apps/circleci/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/circleci/profile.yaml")),
    },
    BuiltinApp {
        name: "datadog",
        description: "Datadog Agent — datadog.yaml API keys, proxy credentials, SNMP auth, cluster agent tokens",
        secrets_yaml: Some(include_str!("../../../apps/datadog/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/datadog/profile.yaml")),
    },
    BuiltinApp {
        name: "dataiku",
        description: "Dataiku DSS — diagnosis bundle: connection creds, user password hashes, DB server keys, LDAP/SSO settings, license, API keys",
        secrets_yaml: Some(include_str!("../../../apps/dataiku/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/dataiku/profile.yaml")),
    },
    BuiltinApp {
        name: "django",
        description: "Django — .env files, SECRET_KEY, database credentials, third-party API keys",
        secrets_yaml: Some(include_str!("../../../apps/django/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/django/profile.yaml")),
    },
    BuiltinApp {
        name: "docker-compose",
        description: "Docker Compose — compose.yml environment variables, image credentials",
        secrets_yaml: Some(include_str!("../../../apps/docker-compose/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/docker-compose/profile.yaml")),
    },
    BuiltinApp {
        name: "elasticsearch",
        description: "Elasticsearch — elasticsearch.yml, Kibana/Logstash credentials",
        secrets_yaml: Some(include_str!("../../../apps/elasticsearch/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/elasticsearch/profile.yaml")),
    },
    BuiltinApp {
        name: "fstab",
        description: "fstab — /etc/fstab CIFS/SMB credentials, NFS and iSCSI server addresses",
        secrets_yaml: Some(include_str!("../../../apps/fstab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/fstab/profile.yaml")),
    },
    BuiltinApp {
        name: "github-actions",
        description: "GitHub Actions — workflow env vars, step inputs, container registry credentials",
        secrets_yaml: Some(include_str!("../../../apps/github-actions/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/github-actions/profile.yaml")),
    },
    BuiltinApp {
        name: "gitlab",
        description: "GitLab — gitlab.rb, .gitlab-ci.yml, Helm values, GitLabSOS/kubeSOS support bundles",
        secrets_yaml: Some(include_str!("../../../apps/gitlab/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/gitlab/profile.yaml")),
    },
    BuiltinApp {
        name: "grafana",
        description: "Grafana — grafana.ini admin credentials, provisioning datasource secrets",
        secrets_yaml: Some(include_str!("../../../apps/grafana/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/grafana/profile.yaml")),
    },
    BuiltinApp {
        name: "bruno",
        description: "Bruno — .bru collections and OpenCollection YAML (Bruno 3.0+) credentials",
        secrets_yaml: Some(include_str!("../../../apps/bruno/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/bruno/profile.yaml")),
    },
    BuiltinApp {
        name: "har",
        description: "HAR (HTTP Archive) — browser-captured request/response traffic, auth headers, cookies",
        secrets_yaml: Some(include_str!("../../../apps/har/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/har/profile.yaml")),
    },
    BuiltinApp {
        name: "insomnia",
        description: "Insomnia — workspace exports, request auth, environment variables",
        secrets_yaml: Some(include_str!("../../../apps/insomnia/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/insomnia/profile.yaml")),
    },
    BuiltinApp {
        name: "heroku",
        description: "Heroku — app.json env values, add-on credentials (Postgres, Redis, SendGrid, Mailgun, Cloudinary…)",
        secrets_yaml: Some(include_str!("../../../apps/heroku/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/heroku/profile.yaml")),
    },
    BuiltinApp {
        name: "kubernetes",
        description: "Kubernetes — kubeconfig credentials, Secret manifests, Helm values",
        secrets_yaml: Some(include_str!("../../../apps/kubernetes/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/kubernetes/profile.yaml")),
    },
    BuiltinApp {
        name: "laravel",
        description: "Laravel — .env files, APP_KEY, Pusher, Passport, Stripe secrets",
        secrets_yaml: Some(include_str!("../../../apps/laravel/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/laravel/profile.yaml")),
    },
    BuiltinApp {
        name: "mongodb",
        description: "MongoDB — mongod.conf TLS passwords, .env connection strings",
        secrets_yaml: Some(include_str!("../../../apps/mongodb/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/mongodb/profile.yaml")),
    },
    BuiltinApp {
        name: "mysql",
        description: "MySQL / MariaDB — my.cnf credentials, .env DATABASE_URL",
        secrets_yaml: Some(include_str!("../../../apps/mysql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/mysql/profile.yaml")),
    },
    BuiltinApp {
        name: "postman",
        description: "Postman — collection credentials, environment variables, auth configs",
        secrets_yaml: Some(include_str!("../../../apps/postman/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/postman/profile.yaml")),
    },
    BuiltinApp {
        name: "nginx",
        description: "Nginx — nginx.conf virtual hosts, proxy upstreams, access/error logs",
        secrets_yaml: Some(include_str!("../../../apps/nginx/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/nginx/profile.yaml")),
    },
    BuiltinApp {
        name: "postgresql",
        description: "PostgreSQL — postgresql.conf, connection strings, pg logs",
        secrets_yaml: Some(include_str!("../../../apps/postgresql/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/postgresql/profile.yaml")),
    },
    BuiltinApp {
        name: "rails",
        description: "Ruby on Rails — database.yml, .env, config/secrets.yml",
        secrets_yaml: Some(include_str!("../../../apps/rails/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/rails/profile.yaml")),
    },
    BuiltinApp {
        name: "redis",
        description: "Redis — redis.conf requirepass/masterauth, .env credentials",
        secrets_yaml: Some(include_str!("../../../apps/redis/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/redis/profile.yaml")),
    },
    BuiltinApp {
        name: "splunk",
        description: "Splunk — outputs.conf, inputs.conf, authentication.conf credentials",
        secrets_yaml: Some(include_str!("../../../apps/splunk/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/splunk/profile.yaml")),
    },
    BuiltinApp {
        name: "spring-boot",
        description:
            "Spring Boot — application.yml, application.properties, datasource credentials",
        secrets_yaml: Some(include_str!("../../../apps/spring-boot/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/spring-boot/profile.yaml")),
    },
    BuiltinApp {
        name: "terraform",
        description: "Terraform — *.tfvars variable files, terraform.tfstate sensitive outputs",
        secrets_yaml: Some(include_str!("../../../apps/terraform/secrets.yaml")),
        profile_yaml: Some(include_str!("../../../apps/terraform/profile.yaml")),
    },
];

/// Return a sorted list of all built-in app names.
pub(crate) fn builtin_app_names() -> Vec<&'static str> {
    BUILTIN_APPS.iter().map(|a| a.name).collect()
}

/// Resolve the user-defined apps directory.
///
/// Checks `SCOUR_SECRETS_APPS_DIR` first, then falls back to
/// `~/.config/scour-secrets/apps` (XDG base directory convention).
pub(crate) fn user_apps_dir() -> Option<PathBuf> {
    if let Ok(dir) = std::env::var("SCOUR_SECRETS_APPS_DIR") {
        if !dir.is_empty() {
            return Some(PathBuf::from(dir));
        }
    }
    Some(crate::hooks::sanitize_config_dir().join("apps"))
}

/// Parse a YAML file as `T`, returning a clear error on failure.
fn parse_yaml_file<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_yaml_ng::from_str(&content)
        .map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

/// Read the first `# description` comment line from a YAML file, if present.
fn read_app_description(app_dir: &Path) -> String {
    for filename in &["secrets.yaml", "profile.yaml"] {
        let path = app_dir.join(filename);
        if let Ok(content) = fs::read_to_string(&path) {
            if let Some(line) = content.lines().next() {
                if let Some(rest) = line.strip_prefix('#') {
                    let desc = rest.trim().to_string();
                    if !desc.is_empty() {
                        return desc;
                    }
                }
            }
        }
    }
    String::new()
}

/// Ensure a local user copy of a built-in app bundle exists.
///
/// Called automatically when `--app <name>` is used. If the user app directory
/// for `name` does not yet exist, both `profile.yaml` and `secrets.yaml` are
/// copied from the built-in bundle so that:
///
/// - The profile and secrets files are editable without running `scour-secrets apps edit`.
/// - Discovered literal values from the profile pass can be persisted back into
///   `secrets.yaml` by subsequent runs.
///
/// Returns the path to the user `secrets.yaml` on success, or `None` when the
/// app is not a built-in or the directory could not be created.
///
/// If the directory already exists this is a no-op; existing customisations are
/// never overwritten.
pub(crate) fn ensure_user_app_copy(name: &str) -> Option<PathBuf> {
    let apps_dir = user_apps_dir()?;
    let app_dir = apps_dir.join(name);

    // Already provisioned — return the secrets file path (may or may not exist yet).
    if app_dir.is_dir() {
        return Some(app_dir.join("secrets.yaml"));
    }

    // Only provision built-in apps; custom apps have no source to copy from.
    let entry = BUILTIN_APPS.iter().find(|a| a.name == name)?;

    if let Err(e) = fs::create_dir_all(&app_dir) {
        eprintln!(
            "warning: could not create app directory {}: {e}",
            app_dir.display()
        );
        return None;
    }

    let mut ok = true;

    if let Some(yaml) = entry.profile_yaml {
        let dst = app_dir.join("profile.yaml");
        if let Err(e) = fs::write(&dst, yaml) {
            eprintln!("warning: could not write {}: {e}", dst.display());
            ok = false;
        }
    }

    if let Some(yaml) = entry.secrets_yaml {
        let dst = app_dir.join("secrets.yaml");
        if let Err(e) = fs::write(&dst, yaml) {
            eprintln!("warning: could not write {}: {e}", dst.display());
            ok = false;
        }
    }

    if !ok {
        let _ = fs::remove_dir_all(&app_dir);
        return None;
    }

    Some(app_dir.join("secrets.yaml"))
}

/// Load an app bundle by name.
///
/// Resolution order:
///   1. User apps directory (`SCOUR_SECRETS_APPS_DIR` or `~/.config/scour-secrets/apps/<name>/`)
///   2. Built-in apps embedded in the binary
pub(crate) fn load_app_bundle(name: &str) -> Result<AppBundle, String> {
    // 1. User-defined app takes precedence over built-in.
    if let Some(apps_dir) = user_apps_dir() {
        let app_dir = apps_dir.join(name);
        if app_dir.is_dir() {
            let secrets_path = app_dir.join("secrets.yaml");
            let profile_path = app_dir.join("profile.yaml");

            let secrets: Vec<SecretEntry> = if secrets_path.exists() {
                parse_yaml_file(&secrets_path)?
            } else {
                vec![]
            };
            let profiles: Vec<FileTypeProfile> = if profile_path.exists() {
                parse_yaml_file(&profile_path)?
            } else {
                vec![]
            };
            return Ok(AppBundle { secrets, profiles });
        }
    }

    // 2. Built-in app.
    let entry = BUILTIN_APPS
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| {
            format!(
                "unknown app '{}'. Built-in apps: {}. \
                 Add a custom app at $SCOUR_SECRETS_APPS_DIR/{} (secrets.yaml / profile.yaml).",
                name,
                builtin_app_names().join(", "),
                name,
            )
        })?;

    let secrets: Vec<SecretEntry> = match entry.secrets_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in secrets for '{}': {e}", name))?,
        None => vec![],
    };
    let profiles: Vec<FileTypeProfile> = match entry.profile_yaml {
        Some(yaml) => serde_yaml_ng::from_str(yaml)
            .map_err(|e| format!("failed to parse built-in profile for '{}': {e}", name))?,
        None => vec![],
    };

    Ok(AppBundle { secrets, profiles })
}

pub(crate) fn validate_app_name(name: &str) -> Result<(), String> {
    if name.is_empty() {
        return Err("app name cannot be empty".into());
    }
    if !name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
    {
        return Err(format!(
            "app name '{name}' must start with a letter or digit"
        ));
    }
    if let Some(bad) = name
        .chars()
        .find(|c| !c.is_ascii_alphanumeric() && *c != '-' && *c != '_')
    {
        return Err(format!(
            "app name '{name}' contains invalid character '{bad}'; \
             only letters, digits, hyphens, and underscores are allowed"
        ));
    }
    Ok(())
}

pub(crate) fn run_apps(args: &AppsArgs) -> Result<(), (String, i32)> {
    match &args.command {
        None => run_apps_list(),
        Some(AppsSubCommand::Update(a)) => run_apps_update(a),
        Some(AppsSubCommand::Dir) => run_apps_dir(),
    }
}

fn run_apps_list() -> Result<(), (String, i32)> {
    let overridden: std::collections::HashSet<String> = user_apps_dir()
        .filter(|d| d.is_dir())
        .map(|d| {
            fs::read_dir(&d)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| e.file_name().to_string_lossy().to_string())
                        .collect()
                })
                .unwrap_or_default()
        })
        .unwrap_or_default();

    println!("Built-in app bundles (use with --app <name>):\n");
    for app in BUILTIN_APPS {
        if overridden.contains(app.name) {
            let marker = if app_update_available(app.name) {
                " (local copy — update available: scour-secrets apps update)"
            } else {
                " (local copy)"
            };
            println!("  {:<18} {}{}", app.name, app.description, marker);
        } else {
            println!("  {:<18} {}", app.name, app.description);
        }
    }

    let apps_dir = user_apps_dir();
    let dir_display = apps_dir
        .as_ref()
        .map(|d| d.display().to_string())
        .unwrap_or_else(|| "~/.config/scour-secrets/apps".into());

    if let Some(ref dir) = apps_dir {
        if dir.is_dir() {
            // Materialized copies of built-ins are listed above with a
            // "(local copy)" marker — only genuinely user-defined apps here.
            let mut user_apps: Vec<(String, String)> = fs::read_dir(dir)
                .map(|entries| {
                    entries
                        .flatten()
                        .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                        .map(|e| {
                            let name = e.file_name().to_string_lossy().to_string();
                            let desc = read_app_description(&e.path());
                            (name, desc)
                        })
                        .filter(|(name, _)| !BUILTIN_APPS.iter().any(|a| a.name == name))
                        .collect()
                })
                .unwrap_or_default();
            user_apps.sort_by(|a, b| a.0.cmp(&b.0));

            if !user_apps.is_empty() {
                println!("\nUser-defined apps (from {dir_display}):\n");
                for (name, desc) in &user_apps {
                    if desc.is_empty() {
                        println!("  {name}");
                    } else {
                        println!("  {:<18} {}", name, desc);
                    }
                }
            }
        }
    }

    println!("\nCombine multiple apps:  scour-secrets file.zip --app gitlab,nginx,postgresql");
    println!("Refresh local copies:   scour-secrets apps update [<name>...|--all]");
    println!("Apps directory:         scour-secrets apps dir");
    println!("\nApps are plain YAML (profile.yaml + secrets.yaml) in the apps directory —");
    println!("create, edit, or delete them there directly. Layout: docs/cli-reference.md;");
    println!("YAML format: docs/structured-processing.md.");
    Ok(())
}

/// True when `name` is a built-in app with a materialized local copy whose
/// `profile.yaml` differs from the embedded one — either a newer bundle
/// shipped with this binary, or the user customized the copy. The check is
/// deliberately limited to `profile.yaml`: the app's `secrets.yaml` is
/// mutated by the structured handoff on every run, so its content can never
/// signal staleness.
pub(crate) fn app_update_available(name: &str) -> bool {
    let Some(entry) = BUILTIN_APPS.iter().find(|a| a.name == name) else {
        return false;
    };
    let Some(embedded) = entry.profile_yaml else {
        return false;
    };
    let Some(apps_dir) = user_apps_dir() else {
        return false;
    };
    let app_dir = apps_dir.join(name);
    if !app_dir.is_dir() {
        return false;
    }
    match fs::read(app_dir.join("profile.yaml")) {
        Ok(local) => local != embedded.as_bytes(),
        // Local copy exists but its profile.yaml is missing: stale.
        Err(_) => true,
    }
}

/// Canonical identity for a secrets entry: the serde round-trip of the parsed
/// entry, so shipped and local entries compare after identical normalization
/// (comments and formatting never participate).
fn entry_identity(entry: &SecretEntry) -> String {
    serde_yaml_ng::to_string(entry).unwrap_or_default()
}

/// Refresh materialized copies of built-in app bundles.
///
/// Per app: `profile.yaml` is replaced with the embedded version when it
/// differs; for `secrets.yaml` the shipped entries missing from the local
/// file are appended, so discovered literals and user-added entries are
/// preserved (entries the user deleted from the shipped set do reappear).
/// An app with no local copy yet is materialized fresh.
fn run_apps_update(args: &AppsUpdateArgs) -> Result<(), (String, i32)> {
    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".to_string(),
            1,
        )
    })?;

    let names: Vec<String> = if args.all {
        // --all refreshes existing local copies only; apps never used have no
        // copy to update (the embedded bundle is current by definition).
        BUILTIN_APPS
            .iter()
            .map(|a| a.name.to_string())
            .filter(|n| apps_dir.join(n).is_dir())
            .collect()
    } else if args.names.is_empty() {
        return Err((
            "specify one or more app names, or --all to refresh every local copy".into(),
            1,
        ));
    } else {
        args.names.clone()
    };

    if names.is_empty() {
        println!("No local app copies to update in {}", apps_dir.display());
        return Ok(());
    }

    let mut pending = 0usize;

    for name in &names {
        validate_app_name(name).map_err(|e| (e, 1))?;
        let Some(entry) = BUILTIN_APPS.iter().find(|a| a.name == name.as_str()) else {
            return Err((
                format!(
                    "'{name}' is not a built-in app — user-defined apps are managed \
                     directly in {} (edit or delete the files there)",
                    apps_dir.display()
                ),
                1,
            ));
        };

        let app_dir = apps_dir.join(name);

        // No local copy yet: materialize a fresh one.
        if !app_dir.is_dir() {
            if !args.yes {
                println!(
                    "{name}: no local copy — would install one at {}",
                    app_dir.display()
                );
                pending += 1;
                continue;
            }
            fs::create_dir_all(&app_dir)
                .map_err(|e| (format!("failed to create {}: {e}", app_dir.display()), 1))?;
            if let Some(yaml) = entry.profile_yaml {
                fs::write(app_dir.join("profile.yaml"), yaml)
                    .map_err(|e| (format!("failed to write profile.yaml: {e}"), 1))?;
            }
            if let Some(yaml) = entry.secrets_yaml {
                fs::write(app_dir.join("secrets.yaml"), yaml)
                    .map_err(|e| (format!("failed to write secrets.yaml: {e}"), 1))?;
            }
            println!("{name}: installed local copy at {}", app_dir.display());
            continue;
        }

        // profile.yaml: full replacement when it differs from the embedded one.
        let profile_stale = app_update_available(name);

        // secrets.yaml: union-append shipped entries the local file lacks.
        // Skipped (with a warning) when the local file is encrypted.
        let secrets_path = app_dir.join("secrets.yaml");
        let mut missing: Vec<SecretEntry> = Vec::new();
        let mut local_entries: Vec<SecretEntry> = Vec::new();
        let mut secrets_skipped = false;
        if let Some(shipped_yaml) = entry.secrets_yaml {
            let local_raw = fs::read(&secrets_path).unwrap_or_default();
            if looks_encrypted(&local_raw) {
                eprintln!(
                    "warning: {} is encrypted — secrets entries not updated",
                    secrets_path.display()
                );
                secrets_skipped = true;
            } else {
                local_entries = if local_raw.is_empty() {
                    vec![]
                } else {
                    parse_secrets(&local_raw, None).map_err(|e| {
                        (
                            format!("failed to parse {}: {e}", secrets_path.display()),
                            1,
                        )
                    })?
                };
                let shipped: Vec<SecretEntry> =
                    serde_yaml_ng::from_str(shipped_yaml).map_err(|e| {
                        (
                            format!("failed to parse built-in secrets for '{name}': {e}"),
                            1,
                        )
                    })?;
                let have: std::collections::HashSet<String> =
                    local_entries.iter().map(entry_identity).collect();
                missing = shipped
                    .into_iter()
                    .filter(|e| !have.contains(&entry_identity(e)))
                    .collect();
            }
        }

        if !profile_stale && missing.is_empty() {
            println!("{name}: up to date");
            continue;
        }

        if !args.yes {
            if profile_stale {
                println!(
                    "{name}: profile.yaml differs from the shipped version — would replace it"
                );
            }
            if !missing.is_empty() {
                println!(
                    "{name}: would append {} shipped secrets entr{} missing locally",
                    missing.len(),
                    if missing.len() == 1 { "y" } else { "ies" }
                );
            }
            pending += 1;
            continue;
        }

        if profile_stale {
            if let Some(yaml) = entry.profile_yaml {
                fs::write(app_dir.join("profile.yaml"), yaml)
                    .map_err(|e| (format!("failed to write profile.yaml: {e}"), 1))?;
                println!("{name}: profile.yaml updated");
            }
        }
        if !missing.is_empty() && !secrets_skipped {
            let added = missing.len();
            local_entries.extend(missing);
            let serialized = serialize_secrets(&local_entries, SecretsFormat::Yaml)
                .map_err(|e| (format!("failed to serialize secrets: {e}"), 1))?;
            atomic_write_private(&secrets_path, &serialized).map_err(|e| {
                (
                    format!("failed to write {}: {e}", secrets_path.display()),
                    1,
                )
            })?;
            println!(
                "{name}: appended {added} shipped secrets entr{}",
                if added == 1 { "y" } else { "ies" }
            );
        }
    }

    if pending > 0 {
        return Err((
            format!(
                "{pending} app{} pending — re-run with --yes to apply. \
                 Local customizations to profile.yaml are overwritten; \
                 secrets.yaml entries (including discovered literals) are preserved.",
                if pending == 1 { "" } else { "s" }
            ),
            1,
        ));
    }

    Ok(())
}

fn run_apps_dir() -> Result<(), (String, i32)> {
    let apps_dir = user_apps_dir().ok_or_else(|| {
        (
            "cannot determine user apps directory: HOME is not set".into(),
            1,
        )
    })?;

    println!("{}", apps_dir.display());

    if !apps_dir.exists() {
        eprintln!(
            "note: directory does not exist yet — it will be created automatically by `scour-secrets apps add`"
        );
    }

    Ok(())
}
