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

# PHAROS-195: the managed setup-intent handoff is a second Janus/Pharos pairing
# with no shared fixture to compare. Its bounds live as constants on both sides,
# so a Janus release could silently move them. Assert them here instead.
pharos_intents="$pharos_root/crates/pharosd/src/managed_setup_intents.rs"
janus_intents="$janus_root/go-envelope/managed_setup_intents.go"
janus_witness="$janus_root/go-envelope/auth_witness.go"
for file in "$pharos_intents" "$janus_intents" "$janus_witness"; do
  [[ -f "$file" ]] || {
    printf 'setup-intent pairing source is missing: %s\n' "$file" >&2
    exit 1
  }
done

# Every extraction fails closed: an unreadable constant is a contract change.
# The substitution is delimited with | because some patterns contain /.
extract() { # file, regex with one capture group, human name
  local value
  value="$(sed -nE "s|.*$2.*|\1|p" "$1" | head -n 1)"
  [[ -n "$value" ]] || {
    printf 'setup-intent pairing: could not read %s from %s\n' "$3" "$1" >&2
    exit 1
  }
  printf '%s' "$value"
}

compare() { # name, pharos value, janus value
  [[ "$2" == "$3" ]] || {
    printf 'setup-intent pairing drifted: %s is %s in Pharos and %s in Janus\n' \
      "$1" "$2" "$3" >&2
    exit 1
  }
}

pharos_signed_schema="$(extract "$pharos_intents" 'SIGNED_INTENT_SCHEMA: &str = "([^"]+)";' 'SIGNED_INTENT_SCHEMA')"
pharos_setup_schema="$(extract "$pharos_intents" 'SETUP_INTENT_SCHEMA: &str = "([^"]+)";' 'SETUP_INTENT_SCHEMA')"
pharos_delivery_schema="$(extract "$pharos_intents" 'DELIVERY_SCHEMA: &str = "([^"]+)";' 'DELIVERY_SCHEMA')"
pharos_domain="$(extract "$pharos_intents" 'SIGNATURE_DOMAIN: &\[u8\] = b"([^"]+)";' 'SIGNATURE_DOMAIN')"
pharos_version="$(extract "$pharos_intents" 'CONTRACT_VERSION: u16 = ([0-9]+);' 'CONTRACT_VERSION')"
pharos_intent_minutes="$(extract "$pharos_intents" 'INTENT_TTL_SECS: i64 = ([0-9]+) \* 60;' 'INTENT_TTL_SECS')"
pharos_stepup_minutes="$(extract "$pharos_intents" 'JANUS_STEP_UP_TTL_SECS: i64 = ([0-9]+) \* 60;' 'JANUS_STEP_UP_TTL_SECS')"

janus_signed_schema="$(extract "$janus_intents" 'managedSignedIntentSchema[[:space:]]+= "([^"]+)"' 'managedSignedIntentSchema')"
janus_setup_schema="$(extract "$janus_intents" 'managedSetupIntentSchema[[:space:]]+= "([^"]+)"' 'managedSetupIntentSchema')"
janus_delivery_schema="$(extract "$janus_intents" 'managedIntentDenialSchema[[:space:]]+= "([^"]+)"' 'managedIntentDenialSchema')"
janus_domain="$(extract "$janus_intents" 'managedIntentSignatureDomain[[:space:]]+= "([^"]+)"' 'managedIntentSignatureDomain')"
janus_version="$(extract "$janus_intents" 'managedIntentContractVersion[[:space:]]+= ([0-9]+)' 'managedIntentContractVersion')"
janus_intent_minutes="$(extract "$janus_intents" 'managedIntentMaxTTLSeconds = int64\(([0-9]+) \* time\.Minute / time\.Second\)' 'managedIntentMaxTTLSeconds')"
janus_stepup_minutes="$(extract "$janus_witness" 'authenticatedBrowserCaptureFreshness = ([0-9]+) \* time\.Minute' 'authenticatedBrowserCaptureFreshness')"

compare 'signed intent schema' "$pharos_signed_schema" "$janus_signed_schema"
compare 'setup intent schema' "$pharos_setup_schema" "$janus_setup_schema"
compare 'delivery/denial schema' "$pharos_delivery_schema" "$janus_delivery_schema"
compare 'signature domain' "$pharos_domain" "$janus_domain"
compare 'contract version' "$pharos_version" "$janus_version"

# Pharos must never issue an intent Janus would reject as over-long, and its
# recorded step-up window must match the one Janus actually enforces.
if ((pharos_intent_minutes > janus_intent_minutes)); then
  printf 'setup-intent pairing drifted: Pharos issues %s-minute intents but Janus rejects above %s minutes\n' \
    "$pharos_intent_minutes" "$janus_intent_minutes" >&2
  exit 1
fi
compare 'passwordless step-up window (minutes)' "$pharos_stepup_minutes" "$janus_stepup_minutes"

printf 'janus_contract=ok intent_ttl_minutes=%s step_up_minutes=%s contract_version=%s\n' \
  "$pharos_intent_minutes" "$pharos_stepup_minutes" "$pharos_version"
