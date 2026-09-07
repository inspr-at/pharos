#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
owner_root="$repo_root/contracts/paimos-external-stage-v2"
dependency_root="$repo_root/contracts/paimos-external-stage-v1"

if command -v sha256sum >/dev/null 2>&1; then
  sha256_file() { sha256sum "$1" | awk '{print $1}'; }
  sha256_stream() { sha256sum | awk '{print $1}'; }
else
  sha256_file() { shasum -a 256 "$1" | awk '{print $1}'; }
  sha256_stream() { shasum -a 256 | awk '{print $1}'; }
fi

check_file() {
  local root=$1
  local name=$2
  local expected_bytes=$3
  local expected_sha=$4
  local actual_bytes actual_sha
  actual_bytes=$(wc -c <"$root/$name" | tr -d ' ')
  actual_sha=$(sha256_file "$root/$name")
  if [[ "$actual_bytes" != "$expected_bytes" || "$actual_sha" != "$expected_sha" ]]; then
    printf 'error: pinned Paimos fixture drifted: %s\n' "$name" >&2
    exit 1
  fi
}

# Owner v2 is the Pharos reporter pin. Janus v1 stays a separate dependency fixture.
check_file "$owner_root" owner-pharos-v2.json 3868 99abbf90592ff319b4e00319bc8bb5141572e6dc66cfcf074d781358c36954a9
check_file "$owner_root" external-stage-v2.schema.json 10292 57b2ceaebc2991f89b9adb4de713c2c760c40f521ee8bde8cd67dfb5559ae33a
check_file "$dependency_root" dependency-janus-v1.json 1115 52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b

owner_sha=$(
  {
    printf 'paimos.external-stage.fixtures.v2\0'
    printf 'owner-pharos-v2.json\0'
    command cat "$owner_root/owner-pharos-v2.json"
    printf '\0'
  } | sha256_stream
)
if [[ "$owner_sha" != 6bba9613230c6ea728db58ffea5533399caed19e6d56a8d78ef19d0fde20be8a ]]; then
  printf 'error: pinned Paimos owner v2 fixture-set digest drifted\n' >&2
  exit 1
fi

manifest_sha=$(sha256_file "$owner_root/manifest-v2.json")
if [[ "$manifest_sha" != 9f7c57503d2a883d548e41714ba8c37c5049a6e6a3e3fb0add6f460cfc7199ef ]]; then
  printf 'error: pinned Paimos v2 manifest drifted\n' >&2
  exit 1
fi

janus_set_sha=$(
  {
    printf 'paimos.external-stage.fixtures.v1\0'
    printf 'dependency-janus-v1.json\0'
    command cat "$dependency_root/dependency-janus-v1.json"
    printf '\0'
  } | sha256_stream
)
if [[ "$janus_set_sha" == "$owner_sha" ]]; then
  printf 'error: Janus dependency fixture must stay distinct from the owner v2 pin\n' >&2
  exit 1
fi

printf 'paimos_delivery_contract=ok release=v26.09.05 commit=bb3b874f22a14fbe3879b1b575f33d55a001312d schema_major=2 fixture_set_sha256=%s janus_dependency_sha256=%s\n' "$owner_sha" "$(sha256_file "$dependency_root/dependency-janus-v1.json")"
