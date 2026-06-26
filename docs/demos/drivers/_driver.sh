#!/usr/bin/env bash
# Shared helpers for the asciinema demo drivers.
#
# Each driver sources this file, which prepares the hermetic work dir and
# defines two helpers:
#   note "<text>"  — print a dim comment line (narration)
#   run  "<cmd>"   — print the command as if typed (selectable text in the
#                    asciinema player), pause, then run it
#
# The command text is printed verbatim, so viewers can copy it straight out of
# the player — the reason we record casts in addition to the VHS GIFs.

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../lib.sh
source "$HERE/../lib.sh"
prepare_workdir >/dev/null

_PROMPT='\033[1;32m$\033[0m '   # bold green $

note() {
  printf '\033[2m%s\033[0m\n' "$*"
  sleep 0.7
}

run() {
  printf '%b%s\n' "$_PROMPT" "$1"
  sleep 0.7
  eval "$1"
  printf '\n'
  sleep 1.4
}
