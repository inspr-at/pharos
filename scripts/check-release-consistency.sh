#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

version=$(tr -d '\r\n' <VERSION)
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  printf 'error: VERSION must contain one x.y.z semantic version\n' >&2
  exit 1
fi

cargo_version=$(
  awk '
    /^\[workspace\.package\]$/ { in_workspace_package = 1; next }
    /^\[/ { in_workspace_package = 0 }
    in_workspace_package && /^version[[:space:]]*=/ {
      value = $0
      sub(/^[^=]*=[[:space:]]*"/, "", value)
      sub(/"[[:space:]]*$/, "", value)
      print value
      exit
    }
  ' Cargo.toml
)
if [[ "$cargo_version" != "$version" ]]; then
  printf 'error: Cargo workspace version does not match VERSION\n' >&2
  exit 1
fi

if ! grep -Fq "## ${version} - " docs/CHANGELOG.md; then
  printf 'error: changelog has no dated heading for VERSION\n' >&2
  exit 1
fi

if ! grep -Fq "version-${version}-" README.md; then
  printf 'error: README version badge does not match VERSION\n' >&2
  exit 1
fi

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  expected_tag="v${version}"
  if [[ "${GITHUB_REF_NAME:-}" != "$expected_tag" ]]; then
    printf 'error: release tag does not match VERSION\n' >&2
    exit 1
  fi
  if [[ "$(git cat-file -t "refs/tags/${expected_tag}" 2>/dev/null || true)" != "tag" ]]; then
    printf 'error: semantic releases require an annotated Git tag\n' >&2
    exit 1
  fi
fi

printf 'release_consistency=ok version=%s\n' "$version"
