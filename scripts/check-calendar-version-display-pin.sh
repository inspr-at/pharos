#!/usr/bin/env bash
# Verify an offline, consumer-owned copy of the calendar display data without
# fetching doctrine. Run from the consuming repository root.
set -euo pipefail

fail() {
  printf 'calendar-version-display-pin: %s\n' "$*" >&2
  exit 1
}

if [[ "$#" -lt 4 || "$#" -gt 5 ]]; then
  printf 'usage: check-calendar-version-display-pin.sh COPY SIZE SHA256 DOCTRINE_REVISION [DOCTRINE_PATH]\n' >&2
  exit 2
fi

copy_path=$1
expected_size=$2
expected_sha256=$3
expected_revision=$4
doctrine_path=${5:-doctrine}

case "$copy_path" in
  ""|/*|.|..|../*|*/../*|*/..) fail 'COPY must be an in-repository relative path' ;;
esac
case "$doctrine_path" in
  ""|/*|.|..|../*|*/../*|*/..) fail 'DOCTRINE_PATH must be an in-repository relative path' ;;
esac
case "$expected_size" in
  ""|*[!0-9]*) fail 'SIZE must be a decimal byte count' ;;
esac
[[ "$expected_size" -gt 0 ]] || fail 'SIZE must be greater than zero'
[[ ${#expected_sha256} -eq 64 ]] \
  || fail 'SHA256 must be exactly 64 lowercase hexadecimal characters'
case "$expected_sha256" in
  *[!0-9a-f]*) fail 'SHA256 must be exactly 64 lowercase hexadecimal characters' ;;
esac
if [[ ${#expected_revision} -ne 40 && ${#expected_revision} -ne 64 ]]; then
  fail 'DOCTRINE_REVISION must be a full 40- or 64-character Git object ID'
fi
case "$expected_revision" in
  *[!0-9a-f]*) fail 'DOCTRINE_REVISION must be a lowercase hexadecimal Git object ID' ;;
esac

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) \
  || fail 'run this check inside the consuming Git repository'
[[ "$PWD" == "$repo_root" ]] \
  || fail 'run this check from the consuming repository root'

[[ -f "$copy_path" && ! -L "$copy_path" ]] \
  || fail "$copy_path is not a regular in-repository file"
git ls-files --error-unmatch -- "$copy_path" >/dev/null 2>&1 \
  || fail "$copy_path is not tracked by the consuming repository"

actual_size=$(wc -c < "$copy_path" | tr -d '[:space:]')
[[ "$actual_size" == "$expected_size" ]] \
  || fail "$copy_path has $actual_size bytes; expected $expected_size"

if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum -- "$copy_path" | awk '{print $1}')
elif command -v shasum >/dev/null 2>&1; then
  actual_sha256=$(shasum -a 256 -- "$copy_path" | awk '{print $1}')
else
  fail 'neither sha256sum nor shasum is available'
fi
[[ "$actual_sha256" == "$expected_sha256" ]] \
  || fail "$copy_path SHA256 does not match its pinned digest"

if [[ -e "$doctrine_path/.git" ]]; then
  git -C "$doctrine_path" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || fail "$doctrine_path is present but is not a verifiable Git checkout"
  doctrine_revision=$(git -C "$doctrine_path" rev-parse --verify HEAD 2>/dev/null) \
    || fail "$doctrine_path is initialized but HEAD cannot be resolved"
  [[ "$doctrine_revision" == "$expected_revision" ]] \
    || fail "$doctrine_path is at $doctrine_revision; expected $expected_revision"

  doctrine_source="$doctrine_path/lib/calendar-version-display.json"
  [[ -f "$doctrine_source" && ! -L "$doctrine_source" ]] \
    || fail "$doctrine_path is initialized but its display data is unavailable"
  cmp -s "$copy_path" "$doctrine_source" \
    || fail "$copy_path differs from the initialized doctrine source"
  printf 'calendar-version-display-pin: ok (pinned bytes and initialized doctrine agree)\n'
else
  if [[ -e "$doctrine_path/lib/calendar-version-display.json" ]]; then
    fail "$doctrine_path is present but is not a verifiable Git checkout"
  fi
  printf 'calendar-version-display-pin: ok (pinned bytes; doctrine checkout absent)\n'
fi
