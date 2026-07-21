#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
pharos_root="$(cd -- "$script_dir/.." && pwd -P)"
janus_root="${1:-}"

if [[ -z "$janus_root" ]]; then
  printf 'usage: %s /path/to/janus\n' "$0" >&2
  exit 2
fi
janus_root="$(cd -- "$janus_root" && pwd -P)"

pharos_fixture="$pharos_root/contracts/pharos-beacon-token-generation-v2.json"
janus_fixture="$janus_root/contracts/pharos-beacon-token-generation-v2.json"
[[ -f "$pharos_fixture" && -f "$janus_fixture" ]] || {
  printf 'shared Janus/Pharos contract fixture is missing\n' >&2
  exit 1
}

cmp --silent "$pharos_fixture" "$janus_fixture" || {
  printf 'Janus producer and Pharos consumer fixtures differ\n' >&2
  exit 1
}

cargo test \
  --manifest-path "$janus_root/Cargo.toml" \
  --locked \
  -p janus-executor \
  shared_contract_fixture_is_a_valid_producer_generation
cargo test \
  --manifest-path "$pharos_root/Cargo.toml" \
  --locked \
  -p pharosd \
  shared_janus_producer_fixture_is_consumer_compatible
