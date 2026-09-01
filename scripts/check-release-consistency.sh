#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

python3 -m unittest tests/test_release_version.py
python3 scripts/release_version.py check

version=$(jq -er '.version' RELEASE.json)

if [[ "${GITHUB_REF_TYPE:-}" == "tag" ]]; then
  expected_tag="v${version}"
  if [[ "${GITHUB_REF_NAME:-}" != "$expected_tag" ]]; then
    printf 'error: release tag does not match RELEASE.json\n' >&2
    exit 1
  fi
  if [[ "$(git cat-file -t "refs/tags/${expected_tag}" 2>/dev/null || true)" != "tag" ]]; then
    printf 'error: calendar releases require an annotated Git tag\n' >&2
    exit 1
  fi
fi
