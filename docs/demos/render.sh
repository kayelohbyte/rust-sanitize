#!/usr/bin/env bash
# Regenerate every demo recording: VHS GIFs (docs/demos/out/*.gif) and
# asciinema casts (docs/demos/out/*.cast). Run from anywhere.
#
#   docs/demos/render.sh            # uses target/release/sanitize
#   SANITIZE_BIN=/path/to/sanitize docs/demos/render.sh
#
# Requires: vhs, asciinema, ffmpeg, ttyd, jq on PATH.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
cd "$REPO"

export SANITIZE_BIN="${SANITIZE_BIN:-$REPO/target/release/sanitize}"
if [[ ! -x "$SANITIZE_BIN" ]]; then
  echo "error: sanitize binary not found at $SANITIZE_BIN" >&2
  echo "       build it first:  cargo build --release" >&2
  exit 1
fi

for tool in vhs asciinema; do
  command -v "$tool" >/dev/null || { echo "error: $tool not on PATH" >&2; exit 1; }
done

echo "Using sanitize: $SANITIZE_BIN"

# --- VHS GIFs ---
for tape in docs/demos/tapes/*.tape; do
  echo ">> vhs $tape"
  vhs "$tape"
done

# --- asciinema casts ---
for drv in docs/demos/drivers/[0-9]*.sh; do
  name="$(basename "$drv" .sh)"
  echo ">> asciinema $name"
  asciinema rec --overwrite --headless --window-size 120x32 \
    --title "rust-sanitize — ${name#[0-9][0-9]-}" \
    -c "bash $drv" "docs/demos/out/$name.cast"
done

echo "Done. Output in docs/demos/out/"
