#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
fixture_root="$repo_root/contracts/paimos-external-stage-v1"

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
  sha256_stream() { sha256sum | awk '{print $1}'; }
else
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
  sha256_stream() { shasum -a 256 | awk '{print $1}'; }
fi

check_file() {
  local name=$1
  local expected_bytes=$2
  local expected_sha=$3
  local actual_bytes actual_sha
  actual_bytes=$(wc -c <"$fixture_root/$name" | tr -d ' ')
  actual_sha=$(sha256_file "$fixture_root/$name")
  if [[ "$actual_bytes" != "$expected_bytes" || "$actual_sha" != "$expected_sha" ]]; then
    printf 'error: pinned Paimos fixture drifted: %s\n' "$name" >&2
    exit 1
  fi
}

check_file dependency-janus-v1.json 1115 52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b
check_file owner-pharos-v1.json 1504 8ab2ab9df3f5e12cf225a83d77129bdcab14241bc2a5ab03505811a556e016fc

set_sha=$(
  {
    printf 'paimos.external-stage.fixtures.v1\0'
    for name in dependency-janus-v1.json owner-pharos-v1.json; do
      printf '%s\0' "$name"
      command cat "$fixture_root/$name"
      printf '\0'
    done
  } | sha256_stream
)
if [[ "$set_sha" != 0318f4025902c9d5dd790384950cc9daebb16e02e79a4a90ce7dddc673e68bed ]]; then
  printf 'error: pinned Paimos fixture-set digest drifted\n' >&2
  exit 1
fi

manifest_sha=$(sha256_file "$fixture_root/manifest-v1.json")
if [[ "$manifest_sha" != 6aaad204b9e086e49eb0c7c10681ae334819c8d06faf621c68df16bde9ecef87 ]]; then
  printf 'error: pinned Paimos manifest drifted\n' >&2
  exit 1
fi

printf 'paimos_delivery_contract=ok release=v5.11.0 commit=e5f4c86bc061775c853d5847e8fb8bb7e3a31c34 schema_major=1 fixture_set_sha256=%s\n' "$set_sha"
