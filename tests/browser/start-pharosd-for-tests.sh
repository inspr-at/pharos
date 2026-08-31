#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../../" && pwd)"
PHAROS_PID=""
MOCK_PID=""

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

PHAROS_ADDR="${PHAROS_ADDR:-127.0.0.1:18081}"
export PHAROS_ADDR
export PHAROS_PUBLIC_ADDR="${PHAROS_PUBLIC_ADDR:-$PHAROS_ADDR}"

if [[ -z "${PHAROS_BROWSER_HARNESS_ENV_FILE:-}" ]]; then
  echo "PHAROS_BROWSER_HARNESS_ENV_FILE is required" >&2
  exit 1
fi
export PHAROS_BROWSER_HARNESS_ENV_FILE

if [[ "${PHAROS_BROWSER_INTERNAL:-}" == "1" ]]; then
  unset PHAROS_BROWSER_RUN_DIR
fi

cleanup() {
  status=$?
  if [[ -n "${PHAROS_PID:-}" ]]; then
    terminate_pid "$PHAROS_PID"
  fi
  if [[ -n "${MOCK_PID:-}" ]]; then
    terminate_pid "$MOCK_PID"
  fi
  if [[ -n "${PHAROS_BROWSER_RUN_DIR:-}" && -d "$PHAROS_BROWSER_RUN_DIR" ]]; then
    node "$ROOT/tests/browser/delete-owned-run-dir.mjs" "$PHAROS_BROWSER_RUN_DIR" 2>/dev/null || true
  fi
  if [[ "${PHAROS_BROWSER_HARNESS_OWNED_SESSION:-}" == "1" && -n "${PHAROS_BROWSER_HARNESS_ENV_FILE:-}" ]]; then
    node "$ROOT/tests/browser/delete-owned-session-file.mjs" "$PHAROS_BROWSER_HARNESS_ENV_FILE" 2>/dev/null || true
  fi
  exit "$status"
}
trap cleanup EXIT INT TERM

if [[ -z "${PHAROS_BROWSER_RUN_DIR:-}" ]]; then
  PHAROS_BROWSER_RUN_DIR="$(node "$ROOT/tests/browser/allocate-owned-run-dir.mjs")"
fi
export PHAROS_BROWSER_RUN_DIR
node "$ROOT/tests/browser/validate-run-dir.mjs" --require-owned --path "$PHAROS_BROWSER_RUN_DIR"

if [[ -z "${PHAROS_BROWSER_DISPATCH_PORT:-}" ]]; then
  PHAROS_BROWSER_DISPATCH_PORT="$(
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
  )"
fi
export PHAROS_BROWSER_DISPATCH_PORT

node "$ROOT/tests/browser/prepare-run-dir.mjs"
node "$ROOT/tests/browser/write-harness-session.mjs"

node "$ROOT/tests/browser/mock-github-dispatch.mjs" &
MOCK_PID=$!

if [[ -z "${PHAROS_MANIFEST_PATHS:-}" ]]; then
  PHAROS_MANIFEST_PATHS="$(cat "$PHAROS_BROWSER_RUN_DIR/manifest-paths")"
fi
export PHAROS_MANIFEST_PATHS
export PHAROS_MANAGED_SERVICE_MANIFEST_PATHS="${PHAROS_MANAGED_SERVICE_MANIFEST_PATHS:-contracts/managed-service-declarations-v1.json}"
export PHAROS_MACHINE_OPERATOR_TOKEN_HASH_DIR="$PHAROS_BROWSER_RUN_DIR/machine-operator"
export PHAROS_BEACON_TOKEN_HASH_DIR="$PHAROS_BROWSER_RUN_DIR/beacon-token"
export PHAROS_BEACON_TOKEN_MODE=dual
export PHAROS_REQUIRE_BEACON_TOKEN=false
export PHAROS_RETIREMENT_OWNER_HOST=browser-retirement-owner
export PHAROS_NIXCFG_DISPATCH_ENABLED=true
export PHAROS_SYSTEM_UPDATE_DISPATCH_ENABLED=true
export PHAROS_HOST_REMOVAL_DISPATCH_ENABLED=true
export PHAROS_NIXCFG_DISPATCH_TOKEN_FILE="$PHAROS_BROWSER_RUN_DIR/dispatch-token"
export PHAROS_NIXCFG_DISPATCH_API_BASE="http://127.0.0.1:${PHAROS_BROWSER_DISPATCH_PORT}"
export PHAROS_ALLOW_OPEN=true
export RUST_LOG="${RUST_LOG:-warn}"

node "$ROOT/tests/browser/validate-harness-env.mjs"

"$ROOT/target/debug/pharosd" &
PHAROS_PID=$!
wait "$PHAROS_PID"
