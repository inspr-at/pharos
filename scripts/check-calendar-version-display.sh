#!/usr/bin/env bash
# Verify the complete, build-time-only INSPR Calendar renderer closure.
set -euo pipefail
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 "$repo_root/scripts/check-calendar-version-display.py" "$repo_root"
