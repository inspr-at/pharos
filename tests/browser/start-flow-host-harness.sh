#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../" && pwd)"
PHAROS_PID=""
LAUNCHER_PID=""

terminate_pid() {
  local pid="$1"
  if [[ -z "$pid" ]]; then
    return 0
  fi
  if ! kill -0 "$pid" 2>/dev/null; then
    return 0
  fi
  kill -TERM "$pid" 2>/dev/null || true
  local waited=0
  while kill -0 "$pid" 2>/dev/null && (( waited < 50 )); do
    sleep 0.1
    waited=$((waited + 1))
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
}

PHAROS_ADDR="${PHAROS_ADDR:-127.0.0.1:${PHAROS_BROWSER_INTERNAL_PORT:-18091}}"
export PHAROS_ADDR
export PHAROS_PUBLIC_ADDR="${PHAROS_PUBLIC_ADDR:-$PHAROS_ADDR}"

cleanup() {
  status=$?
  terminate_pid "$PHAROS_PID"
  terminate_pid "$LAUNCHER_PID"
  exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -z "${PHAROS_BROWSER_INTERNAL_PORT:-}" ]]; then
  echo "PHAROS_BROWSER_INTERNAL_PORT is required" >&2
  exit 1
fi

node "$ROOT/tests/browser/flow-host/harness-launcher.mjs" &
LAUNCHER_PID=$!
wait "$LAUNCHER_PID"
