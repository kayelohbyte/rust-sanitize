#!/bin/sh
# Installs the optional pre-push hook that mirrors the CI checks
# (fmt, clippy, tests, doc build) so failures surface before pushing.
#
# Usage: ./scripts/setup-hooks.sh [--force]

set -e

cd "$(git rev-parse --show-toplevel)"

hook=.git/hooks/pre-push

if [ -e "$hook" ] && [ "${1:-}" != "--force" ]; then
    echo "error: $hook already exists — rerun with --force to overwrite" >&2
    exit 1
fi

cat > "$hook" <<'EOF'
#!/bin/sh
# Mirrors the CI checks that run on every push.
# Skip for one push:  SCOUR_SKIP_PUSH=1 git push ...

[ "${SCOUR_SKIP_PUSH:-0}" = "1" ] && exit 0

set -e

cd "$(git rev-parse --show-toplevel)"

echo "--- pre-push: fmt ---"
cargo fmt --all -- --check

echo "--- pre-push: clippy ---"
cargo clippy --all-targets -- -D warnings

echo "--- pre-push: test ---"
cargo test

echo "--- pre-push: doc ---"
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --quiet

echo "--- pre-push: all checks passed ---"
EOF

chmod +x "$hook"
echo "Installed $hook"
