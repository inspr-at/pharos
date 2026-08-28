#!/usr/bin/env bash
set -euo pipefail

# These runtime classifications come from the action metadata at each immutable
# commit. A pin bump must review action.yml/action.yaml and update this inventory.
readonly NODE24_ACTIONS=(
  "Swatinem/rust-cache@6323deb102c322ba6fcbdcafc7e3dddab59af2b6"        # v2.9.2
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"           # v7.0.1
  "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020"         # v7.0.0
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a"    # v7.0.1
  "anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610"        # v0.24.0
  "docker/build-push-action@53b7df96c91f9c12dcc8a07bcb9ccacbed38856a"   # v7.3.0
  "docker/login-action@dbcb813823bdd20940b903addbd779551569679f"        # v4.6.0
  "docker/metadata-action@dc802804100637a589fabce1cb79ff13a1411302"     # v6.2.0
  "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803df7f5f0e" # v4.3.0
)

readonly NON_JAVASCRIPT_ACTIONS=(
  # v0.36.0 is composite. Its immutable setup-trivy v0.2.6 and cache v5.0.5
  # dependencies pin only Node 24 cache/checkout actions transitively.
  "aquasecurity/trivy-action@ed142fd0673e97e23eac54620cfb913e5ce36c25"
  "cachix/install-nix-action@630ae543ea3a38a9a4166f03376c02c50f408342" # v31.11.0, composite
  "dtolnay/rust-toolchain@4cda84d5c5c54efe2404f9d843567869ab1699d4"    # stable, composite
  "sigstore/cosign-installer@398d4b0eeef1380460a10c8013a76f728fb906ac" # v3.9.1, composite
)

check_workflows() {
  local workflow_dir="$1"
  local actual expected ref

  if [[ ! -d "$workflow_dir" ]]; then
    echo "error: workflow directory does not exist: $workflow_dir" >&2
    return 1
  fi

  actual="$({
    while IFS= read -r workflow; do
      sed -nE 's/^[[:space:]-]*uses:[[:space:]]*([^[:space:]#]+).*/\1/p' "$workflow"
    done < <(find "$workflow_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) | LC_ALL=C sort)
  } | LC_ALL=C sort -u)"

  if [[ -z "$actual" ]]; then
    echo "error: no GitHub Actions references found in $workflow_dir" >&2
    return 1
  fi

  while IFS= read -r ref; do
    if [[ ! "$ref" =~ ^[-_.A-Za-z0-9]+/[-_.A-Za-z0-9]+(/[-_.A-Za-z0-9]+)*@[0-9a-f]{40}$ ]]; then
      echo "error: GitHub Action is not pinned to an immutable 40-character commit: $ref" >&2
      return 1
    fi
  done <<<"$actual"

  expected="$(printf '%s\n' "${NODE24_ACTIONS[@]}" "${NON_JAVASCRIPT_ACTIONS[@]}" | LC_ALL=C sort -u)"
  if ! diff -u <(printf '%s\n' "$expected") <(printf '%s\n' "$actual"); then
    echo "error: workflow action inventory changed; review upstream runtime metadata and update the assurance list" >&2
    return 1
  fi
}

prepare_case() {
  local source_dir="$1"
  local case_dir="$2"
  local workflow

  mkdir -p "$case_dir"
  while IFS= read -r workflow; do
    cp "$workflow" "$case_dir/$(basename "$workflow")"
  done < <(find "$source_dir" -type f \( -name '*.yml' -o -name '*.yaml' \) | LC_ALL=C sort)
}

expect_failure() {
  local case_dir="$1"
  local label="$2"
  if check_workflows "$case_dir" >/dev/null 2>&1; then
    echo "error: self-test accepted $label" >&2
    return 1
  fi
}

self_test() {
  local workflow_dir="$1"
  local test_root case_dir
  test_root="$(mktemp -d)"

  cleanup() {
    find "$test_root" -type f -delete 2>/dev/null || true
    find "$test_root" -depth -type d -exec rmdir '{}' \; 2>/dev/null || true
  }
  trap cleanup EXIT

  check_workflows "$workflow_dir"

  case_dir="$test_root/mutable"
  prepare_case "$workflow_dir" "$case_dir"
  perl -pi -e 's/3d3c42e5aac5ba805825da76410c181273ba90b1/v7/g' "$case_dir"/*
  expect_failure "$case_dir" "a mutable action tag"

  case_dir="$test_root/legacy"
  prepare_case "$workflow_dir" "$case_dir"
  perl -pi -e 's/3d3c42e5aac5ba805825da76410c181273ba90b1/11d5960a326750d5838078e36cf38b85af677262/g' "$case_dir"/*
  expect_failure "$case_dir" "a reviewed action rolled back to its Node 20 release"

  case_dir="$test_root/unknown"
  prepare_case "$workflow_dir" "$case_dir"
  printf '\n      - uses: example/unknown-action@0000000000000000000000000000000000000000\n' >>"$case_dir/ci.yml"
  expect_failure "$case_dir" "an unreviewed pinned action"

  case_dir="$test_root/missing"
  prepare_case "$workflow_dir" "$case_dir"
  perl -ni -e 'print unless /actions\/setup-node@/' "$case_dir"/*
  expect_failure "$case_dir" "a silently removed reviewed action"

  echo "GitHub Actions Node runtime assurance self-test: ok"
  trap - EXIT
  cleanup
}

workflow_dir=".github/workflows"
case "${1:-}" in
  "")
    check_workflows "$workflow_dir"
    echo "GitHub Actions Node runtime assurance: ok"
    ;;
  --self-test)
    self_test "$workflow_dir"
    ;;
  --workflows)
    if [[ -z "${2:-}" || -n "${3:-}" ]]; then
      echo "usage: $0 [--self-test | --workflows DIR]" >&2
      exit 2
    fi
    check_workflows "$2"
    echo "GitHub Actions Node runtime assurance: ok"
    ;;
  *)
    echo "usage: $0 [--self-test | --workflows DIR]" >&2
    exit 2
    ;;
esac
