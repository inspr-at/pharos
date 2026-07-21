#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: bootstrap-pharos-nixos-anywhere.sh --flake REF#HOST --target USER@HOST --token-file PATH --known-hosts PATH [options]

Runs a reviewed nixos-anywhere install and copies the beacon token through
--extra-files. The raw token is never placed in command arguments or Nix code.

Required:
  --flake REF#HOST       NixOS configuration accepted by nixos-anywhere.
  --target USER@HOST     Existing SSH target to replace with NixOS.
  --token-file PATH      Private file containing only the raw beacon token.
  --known-hosts PATH     Pinned SSH known_hosts file.

Options:
  --identity PATH        Private SSH identity file.
  --port NUMBER          SSH port (default: 22).
  --nixos-anywhere PATH  nixos-anywhere executable (default: PATH lookup).
  --verify-timeout SEC   Wait for pharos-beacon after install (default: 300).
  --dry-run              Validate the handoff without building or changing a host.
EOF
}

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

private_mode() {
  local path="$1" mode
  if mode=$(stat -c '%a' "$path" 2>/dev/null); then
    :
  elif mode=$(stat -f '%Lp' "$path" 2>/dev/null); then
    :
  else
    return 1
  fi
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (((8#$mode & 077) == 0))
}

not_writable_by_others() {
  local path="$1" mode
  if mode=$(stat -c '%a' "$path" 2>/dev/null); then
    :
  elif mode=$(stat -f '%Lp' "$path" 2>/dev/null); then
    :
  else
    return 1
  fi
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || return 1
  (((8#$mode & 022) == 0))
}

flake=""
target=""
token_file=""
known_hosts=""
identity=""
port=22
nixos_anywhere="nixos-anywhere"
verify_timeout=300
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --flake)
      flake="${2:-}"
      shift 2
      ;;
    --flake=*)
      flake="${1#--flake=}"
      shift
      ;;
    --target)
      target="${2:-}"
      shift 2
      ;;
    --target=*)
      target="${1#--target=}"
      shift
      ;;
    --token-file)
      token_file="${2:-}"
      shift 2
      ;;
    --token-file=*)
      token_file="${1#--token-file=}"
      shift
      ;;
    --known-hosts)
      known_hosts="${2:-}"
      shift 2
      ;;
    --known-hosts=*)
      known_hosts="${1#--known-hosts=}"
      shift
      ;;
    --identity)
      identity="${2:-}"
      shift 2
      ;;
    --identity=*)
      identity="${1#--identity=}"
      shift
      ;;
    --port)
      port="${2:-}"
      shift 2
      ;;
    --port=*)
      port="${1#--port=}"
      shift
      ;;
    --nixos-anywhere)
      nixos_anywhere="${2:-}"
      shift 2
      ;;
    --nixos-anywhere=*)
      nixos_anywhere="${1#--nixos-anywhere=}"
      shift
      ;;
    --verify-timeout)
      verify_timeout="${2:-}"
      shift 2
      ;;
    --verify-timeout=*)
      verify_timeout="${1#--verify-timeout=}"
      shift
      ;;
    --dry-run)
      dry_run=1
      shift
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *) die "unknown option: $1" ;;
  esac
done

[[ -n "$flake" && "$flake" == *#* ]] || die "--flake must include #HOST"
[[ "$flake" != *$'\n'* && "$flake" != *$'\r'* ]] || die "--flake contains a newline"
case "$flake" in
  *[Tt][Oo][Kk][Ee][Nn]=* | *[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]=* | *[Bb][Ee][Aa][Rr][Ee][Rr]' '*)
    die "--flake must not contain credential material"
    ;;
esac
[[ "$target" =~ ^[A-Za-z0-9_][A-Za-z0-9._-]*@[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
  die "--target must be USER@HOST using plain hostname characters"
[[ "$port" =~ ^[0-9]+$ && "$port" -ge 1 && "$port" -le 65535 ]] ||
  die "--port must be between 1 and 65535"
[[ "$verify_timeout" =~ ^[0-9]+$ && "$verify_timeout" -ge 30 && "$verify_timeout" -le 1800 ]] ||
  die "--verify-timeout must be between 30 and 1800 seconds"
[[ -f "$token_file" && -r "$token_file" && -s "$token_file" ]] ||
  die "--token-file must be a readable non-empty regular file"
private_mode "$token_file" || die "--token-file must not be group/world accessible"
token_contents="$(<"$token_file")"
[[ -n "$token_contents" && ${#token_contents} -le 512 ]] ||
  die "--token-file does not contain one usable token"
[[ "$token_contents" != *$'\n'* && "$token_contents" != *$'\r'* && "$token_contents" != *[[:space:]]* ]] ||
  die "--token-file must contain one token without whitespace"
unset token_contents
[[ -f "$known_hosts" && -r "$known_hosts" && -s "$known_hosts" ]] ||
  die "--known-hosts must be a readable non-empty regular file"
not_writable_by_others "$known_hosts" || die "--known-hosts must not be group/world writable"
if [[ -n "$identity" ]]; then
  [[ -f "$identity" && -r "$identity" ]] || die "--identity must be a readable regular file"
  private_mode "$identity" || die "--identity must not be group/world accessible"
fi

if [[ "$dry_run" -eq 1 ]]; then
  printf 'nixos_bootstrap_dry_run=ok\n'
  printf 'token_transport=extra-files\n'
  printf 'host_key_policy=strict-preserved\n'
  exit 0
fi

[[ "$(uname -s)" == "Linux" ]] || die "run the NixOS bootstrap from a Linux host"
need_cmd "$nixos_anywhere"
need_cmd ssh
need_cmd install
need_cmd mktemp

state_home="${XDG_STATE_HOME:-$HOME/.local/state}"
log_dir="$state_home/pharos/bootstrap"
install -d -m 0700 "$log_dir"
safe_host="${target##*@}"
stamp="$(date -u +%Y%m%dT%H%M%SZ)"
log_file="$log_dir/${safe_host}-${stamp}.log"
: >"$log_file"
chmod 0600 "$log_file"

runtime_base="${XDG_RUNTIME_DIR:-/tmp}"
extra_root="$(mktemp -d "$runtime_base/pharos-nixos-anywhere.XXXXXX")"
chmod 0700 "$extra_root"
# shellcheck disable=SC2329 # invoked by the EXIT trap below
cleanup() {
  if [[ -d "$extra_root" ]]; then
    find "$extra_root" -type f -exec chmod u+w '{}' + 2>/dev/null || true
    find "$extra_root" -type f -delete 2>/dev/null || true
    find "$extra_root" -depth -type d -exec rmdir '{}' \; 2>/dev/null || true
  fi
}
trap cleanup EXIT

install -d -m 0700 "$extra_root/etc/pharos"
install -m 0600 "$token_file" "$extra_root/etc/pharos/pharos-beacon.token"

ssh_options=(
  "BatchMode=yes"
  "PasswordAuthentication=no"
  "KbdInteractiveAuthentication=no"
  "StrictHostKeyChecking=yes"
  "UserKnownHostsFile=$known_hosts"
  "ConnectTimeout=10"
  "ServerAliveInterval=5"
  "ServerAliveCountMax=3"
)
nixos_args=(
  --flake "$flake"
  --target-host "$target"
  --ssh-port "$port"
  --copy-host-keys
  --extra-files "$extra_root"
)
for option in "${ssh_options[@]}"; do
  nixos_args+=(--ssh-option "$option")
done
if [[ -n "$identity" ]]; then
  nixos_args+=(-i "$identity")
fi

if ! "$nixos_anywhere" "${nixos_args[@]}" >"$log_file" 2>&1; then
  printf 'nixos_bootstrap=failed\n' >&2
  printf 'private_log=%s\n' "$log_file" >&2
  exit 1
fi

ssh_args=(
  -o BatchMode=yes
  -o PasswordAuthentication=no
  -o KbdInteractiveAuthentication=no
  -o StrictHostKeyChecking=yes
  -o "UserKnownHostsFile=$known_hosts"
  -o ConnectTimeout=10
  -o ServerAliveInterval=5
  -o ServerAliveCountMax=3
  -p "$port"
)
if [[ -n "$identity" ]]; then
  ssh_args+=(-o IdentitiesOnly=yes -i "$identity")
fi

deadline=$((SECONDS + verify_timeout))
while ((SECONDS < deadline)); do
  if ssh "${ssh_args[@]}" "$target" 'systemctl is-active --quiet pharos-beacon.service' \
    >/dev/null 2>&1; then
    printf 'nixos_bootstrap=ok\n'
    printf 'beacon_service=active\n'
    printf 'private_log=%s\n' "$log_file"
    exit 0
  fi
  sleep 5
done

printf 'nixos_bootstrap=installed_but_unverified\n' >&2
printf 'private_log=%s\n' "$log_file" >&2
exit 1
