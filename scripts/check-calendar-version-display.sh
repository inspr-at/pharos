#!/usr/bin/env bash
# The calendar v2 display weights are read at build time from an in-repo copy
# of the doctrine data file (PHAROS-261, INSPR-400). CI and Nix builds do not
# check out the doctrine submodule, so the copy is what the binary embeds; this
# check pins the copy to the exact bytes published by inspr-modules and, when
# the submodule is present, proves both files are identical.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
copy="$repo_root/contracts/inspr-calendar-version-display/calendar-version-display.json"
upstream="$repo_root/doctrine/lib/calendar-version-display.json"
if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
else
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
fi
# inspr-modules v0.9.0 (1ee78a780ce14d78cb3447706283e10378f457c7), lib/calendar-version-display.json
expected_bytes=846
expected_sha=2909e7839aba2325b343fd150e9794a059ddacbde29c9d45d10639190a6ebbb2
actual_bytes=$(wc -c <"$copy" | tr -d ' ')
actual_sha=$(sha256_file "$copy")
if [[ "$actual_bytes" != "$expected_bytes" || "$actual_sha" != "$expected_sha" ]]; then
  printf 'error: vendored calendar-version-display.json drifted from the pinned inspr-modules bytes\n' >&2
  exit 1
fi
if [[ -f "$upstream" ]]; then
  cmp -s "$copy" "$upstream" || {
    printf 'error: vendored calendar-version-display.json differs from doctrine/lib/calendar-version-display.json; re-copy and re-pin\n' >&2
    exit 1
  }
  printf 'calendar-version-display: copy matches pinned bytes and the doctrine submodule\n'
else
  printf 'calendar-version-display: copy matches pinned bytes (doctrine submodule not checked out)\n'
fi
