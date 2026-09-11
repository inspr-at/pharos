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
check_file "$launch_root" external-stage-launch-admission-v1.schema.json 6759 3b15130cddc9461d038f06332f066220274c265bfd15a3d2aaa636b8b229415c
check_file "$launch_root" candidate.json 909 4eed040a5bef85899994c30751bb37ec135f81d42e5ff58a764cf51a87f0775b
check_file "$launch_root" admission.json 1707 00a564686330328c119f645f5ea9e16e1fab1569b76092b0822b773c8e84b248
check_file "$launch_root" consume.json 157 014ced0d247386e30267b0c129c4c7d8abcc3e3987841c966a05ed0cc336159c
check_file "$launch_root" receipt.json 348 bd57a2ae684af37a6d43f1888a402189aa48089f733ffb7ef73b40c2a9f3da01
check_file "$launch_root" manifest-v1.json 1186 bdf0866f0afb362eefec4187f66b38ef17c00edc2f64b3fcea2da60fd4c531dd

launch_commit=b3e4634af72fa2d1fec51b3d8ca8b7ced2e95270
launch_release=v260911172741.0.0
launch_artifact_status=published-admitted
launch_image=ghcr.io/inspr-at/paimos
launch_image_index_digest=sha256:3143fe79fb72ba1f1ef8fef4380e2ca5285ee011058d6f4f3e9e3da10e9d2155
if ! jq -e \
  --arg commit "$launch_commit" \
  --arg release "$launch_release" \
  --arg artifact_status "$launch_artifact_status" \
  --arg image "$launch_image" \
  --arg image_index_digest "$launch_image_index_digest" \
  '.source_status == "released"
    and .artifact_status == $artifact_status
    and .paimos_source_commit == $commit
    and .paimos_integration_commit == $commit
    and .paimos_release == $release
    and .paimos_image == $image
    and .paimos_image_index_digest == $image_index_digest
    and .schema_sha256 == "3b15130cddc9461d038f06332f066220274c265bfd15a3d2aaa636b8b229415c"' \
  "$launch_root/manifest-v1.json" >/dev/null; then
  printf 'error: launch-admission release draft identity drifted\n' >&2
  exit 1
fi

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

printf 'paimos_delivery_contract=ok release=v260909151030.0.0 commit=c656912e28c7da208148f4f940991c228f0bf71a schema_major=2 fixture_set_sha256=%s janus_dependency_sha256=%s launch_schema_major=1 launch_source_status=released launch_commit=%s launch_release=%s launch_artifact_status=%s launch_image=%s launch_image_index_digest=%s\n' "$owner_sha" "$(sha256_file "$dependency_root/dependency-janus-v1.json")" "$launch_commit" "$launch_release" "$launch_artifact_status" "$launch_image" "$launch_image_index_digest"
