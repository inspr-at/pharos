#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
owner_root="$repo_root/contracts/paimos-external-stage-v2"
dependency_root="$repo_root/contracts/paimos-external-stage-v1"
launch_root="$repo_root/contracts/paimos-external-stage-launch-admission-v1"

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
check_file "$owner_root" owner-pharos-v2.json 5780 e63cc10020b706a07af969e5dab0052894c2dcbc338c53e7bf6327a7a92baf2b
check_file "$owner_root" external-stage-v2.schema.json 10380 9e9140bb7fbf4b46caf53ab9576be8ff99b208dcb4a10b8512f0d69959190ed0
check_file "$dependency_root" dependency-janus-v1.json 1115 52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b
check_file "$launch_root" external-stage-launch-admission-v1.schema.json 6738 6c7ac4984affdd0ead93091cf02b9c522b83ca5fdc56ab81c80507e547f7a066
check_file "$launch_root" candidate.json 909 4eed040a5bef85899994c30751bb37ec135f81d42e5ff58a764cf51a87f0775b
check_file "$launch_root" admission.json 1707 00a564686330328c119f645f5ea9e16e1fab1569b76092b0822b773c8e84b248
check_file "$launch_root" consume.json 157 014ced0d247386e30267b0c129c4c7d8abcc3e3987841c966a05ed0cc336159c
check_file "$launch_root" receipt.json 348 bd57a2ae684af37a6d43f1888a402189aa48089f733ffb7ef73b40c2a9f3da01
check_file "$launch_root" manifest-v1.json 997 2ec32fbf844d83d112a140532923af05b2292007b268974162e487f5f95a3b2d

owner_sha=$(
  {
    printf 'paimos.external-stage.fixtures.v2\0'
    printf 'owner-pharos-v2.json\0'
    command cat "$owner_root/owner-pharos-v2.json"
    printf '\0'
  } | sha256_stream
)
if [[ "$owner_sha" != fb68cb9990bfcdfe4168f9780c412327d357ecd4181a6b24499352c7858be5f6 ]]; then
  printf 'error: pinned Paimos owner v2 fixture-set digest drifted\n' >&2
  exit 1
fi

manifest_sha=$(sha256_file "$owner_root/manifest-v2.json")
if [[ "$manifest_sha" != 3982cff68d4b41ebe82bf8bc709f530abf2a5aa3019c43d4c6fefdec77e15e18 ]]; then
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

printf 'paimos_delivery_contract=ok release=v260909151030.0.0 commit=c656912e28c7da208148f4f940991c228f0bf71a schema_major=2 fixture_set_sha256=%s janus_dependency_sha256=%s launch_schema_major=1 launch_source_candidate_commit=90e34fa0d5dc9b6e59b62a9021138706cd73af84 launch_release_pin=required\n' "$owner_sha" "$(sha256_file "$dependency_root/dependency-janus-v1.json")"
