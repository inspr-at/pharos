#!/usr/bin/env bash
# The calendar v2 display settings are read at build time from an in-repo copy
# of the doctrine data file (PHAROS-264, INSPR-414). CI and Nix builds do not
# always check out the doctrine submodule, so the copy is what the binary
# embeds. This reviewed pin identifies the exact published upstream bytes.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

# inspr-modules v0.10.0; the helper invoked below is vendored unchanged from
# scripts/check-calendar-version-display-pin.sh at the same revision.
pinned_doctrine_revision=a45fe06250ff5ca3ae5b31d26b4cd16c982ce402
pinned_display_size=863
pinned_display_sha256=2fdc8b4f6fcaf71cf3a7c8333e63c0f61bae32ebb8bd334eef0e3f67c59725e0

scripts/check-calendar-version-display-pin.sh \
  contracts/inspr-calendar-version-display/calendar-version-display.json \
  "$pinned_display_size" \
  "$pinned_display_sha256" \
  "$pinned_doctrine_revision" \
  doctrine
