#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: install-pharos-beacon-systemd.sh --binary PATH|--binary-url URL --pharos-url URL --token-env PATH|--token-file PATH [options]

Installs pharos-beacon as a native systemd service on non-Nix Linux hosts.
The token env/file must already exist unless --allow-legacy is set for the
temporary PHAROS-37 rollout window.
Host settings are stored privately in /var/lib/pharos-beacon.

Options:
  --binary PATH          Local pharos-beacon binary to install.
  --binary-url URL       Download from an exact HTTPS URL; redirects are refused.
  --binary-sha256 HEX    Required SHA-256 for every --binary-url download.
  --token-env PATH       Runtime env file containing PHAROS_TOKEN=...
  --token-file PATH      Runtime file containing only the raw token.
  --allow-legacy         Allow install without token env file.
  --pharos-url URL       Required pharosd HTTP(S) base URL.
  --host NAME            Reported host name (default: hostname -s).
  --role ROLE            Reported host role (default: server).
  --interval SECONDS     Heartbeat interval (default: 60).
  --nixcfg-dir PATH      Optional nixcfg checkout path for freshness.
  --user NAME            Service user/group (default: pharos-beacon).
  --prefix PATH          Install prefix (default: /usr/local).
  --no-start             Install and enable, but do not start now.
  --dry-run              Validate inputs and print planned files.
EOF
}

die() {
  echo "error: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required"
}

validate_no_newline() {
  local name="$1" value="$2"
  [[ "$value" != *$'\n'* ]] || die "$name must not contain a newline"
}

validate_owned_regular_file() {
  local path="$1" forbidden_mode="$2" label="$3"
  [[ -f "$path" && -r "$path" && ! -L "$path" ]] ||
    die "$label must be a readable regular file, not a symlink"
  local owner mode current_uid
  owner="$(stat -c '%u' -- "$path")" || die "could not inspect $label owner"
  mode="$(stat -c '%a' -- "$path")" || die "could not inspect $label mode"
  current_uid="$(id -u)"
  [[ "$owner" = "0" || "$owner" = "$current_uid" ]] ||
    die "$label has an unexpected owner"
  [[ "$mode" =~ ^[0-7]{3,4}$ ]] || die "$label mode is invalid"
  (((8#$mode & forbidden_mode) == 0)) || die "$label permissions are too broad"
}

systemd_quote() {
  local value="$1"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  printf '"%s"' "$value"
}

binary=""
binary_url=""
binary_sha256=""
token_env=""
token_file=""
allow_legacy=0
pharos_url="${PHAROS_URL:-}"
host="${PHAROS_HOSTNAME:-$(hostname -s 2>/dev/null || hostname)}"
role="${PHAROS_ROLE:-server}"
interval="${PHAROS_INTERVAL:-60}"
nixcfg_dir="${NIXCFG_DIR:-}"
service_user="pharos-beacon"
prefix="/usr/local"
start_now=1
dry_run=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --binary)
      binary="${2:-}"
      shift 2
      ;;
    --binary=*)
      binary="${1#--binary=}"
      shift
      ;;
    --binary-url)
      binary_url="${2:-}"
      shift 2
      ;;
    --binary-url=*)
      binary_url="${1#--binary-url=}"
      shift
      ;;
    --binary-sha256)
      binary_sha256="${2:-}"
      shift 2
      ;;
    --binary-sha256=*)
      binary_sha256="${1#--binary-sha256=}"
      shift
      ;;
    --token-env)
      token_env="${2:-}"
      shift 2
      ;;
    --token-env=*)
      token_env="${1#--token-env=}"
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
    --allow-legacy)
      allow_legacy=1
      shift
      ;;
    --pharos-url)
      pharos_url="${2:-}"
      shift 2
      ;;
    --pharos-url=*)
      pharos_url="${1#--pharos-url=}"
      shift
      ;;
    --host)
      host="${2:-}"
      shift 2
      ;;
    --host=*)
      host="${1#--host=}"
      shift
      ;;
    --role)
      role="${2:-}"
      shift 2
      ;;
    --role=*)
      role="${1#--role=}"
      shift
      ;;
    --interval)
      interval="${2:-}"
      shift 2
      ;;
    --interval=*)
      interval="${1#--interval=}"
      shift
      ;;
    --nixcfg-dir)
      nixcfg_dir="${2:-}"
      shift 2
      ;;
    --nixcfg-dir=*)
      nixcfg_dir="${1#--nixcfg-dir=}"
      shift
      ;;
    --user)
      service_user="${2:-}"
      shift 2
      ;;
    --user=*)
      service_user="${1#--user=}"
      shift
      ;;
    --prefix)
      prefix="${2:-}"
      shift 2
      ;;
    --prefix=*)
      prefix="${1#--prefix=}"
      shift
      ;;
    --no-start)
      start_now=0
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
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ -n "$binary" || -n "$binary_url" ]] || die "set --binary or --binary-url"
[[ -z "$binary" || -z "$binary_url" ]] || die "set only one of --binary or --binary-url"
[[ -n "$pharos_url" ]] || die "set --pharos-url or PHAROS_URL"
[[ -z "$binary_url" || "$binary_url" = https://* ]] || die "--binary-url must use https"
[[ -z "$binary_url" || "$binary_sha256" =~ ^[0-9a-f]{64}$ ]] ||
  die "--binary-url requires --binary-sha256 with 64 lowercase hex characters"
[[ -n "$binary_url" || -z "$binary_sha256" ]] || die "--binary-sha256 requires --binary-url"
[[ "$interval" =~ ^[0-9]+$ && "$interval" -ge 10 && "$interval" -le 3600 ]] || die "--interval must be between 10 and 3600 seconds"
[[ "$host" =~ ^[A-Za-z0-9._-]+$ ]] || die "--host contains unsupported characters"
[[ "$service_user" =~ ^[A-Za-z_][A-Za-z0-9_-]*[$]?$ ]] || die "--user contains unsupported characters"
[[ "$prefix" = /* ]] || die "--prefix must be absolute"
[[ -z "$token_env" || "$token_env" = /* ]] || die "--token-env must be absolute"
[[ -z "$token_file" || "$token_file" = /* ]] || die "--token-file must be absolute"
[[ -z "$token_env" || -z "$token_file" ]] || die "set only one of --token-env or --token-file"
[[ -z "$nixcfg_dir" || "$nixcfg_dir" = /* ]] || die "--nixcfg-dir must be absolute"

validate_no_newline "PHAROS_URL" "$pharos_url"
validate_no_newline "PHAROS_HOSTNAME" "$host"
validate_no_newline "PHAROS_ROLE" "$role"
validate_no_newline "NIXCFG_DIR" "$nixcfg_dir"
validate_no_newline "binary URL" "$binary_url"

need_cmd stat
if [[ -n "$token_env" ]]; then
  validate_owned_regular_file "$token_env" "$((8#7077))" "token environment file"
fi
if [[ -n "$token_file" ]]; then
  validate_owned_regular_file "$token_file" "$((8#7077))" "token file"
fi
if [[ -z "$token_env" && -z "$token_file" && "$allow_legacy" -ne 1 ]]; then
  die "set --token-env, --token-file, or explicitly pass --allow-legacy"
fi
if [[ -n "$binary" ]]; then
  validate_owned_regular_file "$binary" "$((8#7022))" "beacon binary"
  [[ -x "$binary" ]] || die "binary is not executable: $binary"
fi

service_path="/etc/systemd/system/pharos-beacon.service"
install_path="$prefix/bin/pharos-beacon"
tmp_binary=""

cleanup() {
  if [[ -n "$tmp_binary" && -f "$tmp_binary" ]]; then
    rm -f -- "$tmp_binary"
  fi
}
trap cleanup EXIT

service_contents() {
  cat <<EOF
[Unit]
Description=Pharos host status beacon
Wants=network-online.target
After=network-online.target

[Service]
Type=notify
NotifyAccess=main
WatchdogSec=$((interval * 3))s
User=$service_user
Group=$service_user
Environment=PHAROS_URL=$(systemd_quote "$pharos_url")
Environment=PHAROS_INTERVAL=$interval
Environment=PHAROS_HOSTNAME=$(systemd_quote "$host")
Environment=PHAROS_ROLE=$(systemd_quote "$role")
Environment=PHAROS_PREFERENCES_FILE="/var/lib/pharos-beacon/host-preferences.json"
EOF
  if [[ -n "$nixcfg_dir" ]]; then
    echo "Environment=NIXCFG_DIR=$(systemd_quote "$nixcfg_dir")"
  fi
  if [[ -n "$token_env" ]]; then
    echo "EnvironmentFile=$token_env"
  fi
  if [[ -n "$token_file" ]]; then
    echo "Environment=PHAROS_TOKEN_FILE=$(systemd_quote "$token_file")"
  fi
  cat <<EOF
ExecStart=$install_path
Restart=always
RestartSec=10s
StateDirectory=pharos-beacon
StateDirectoryMode=0700
UMask=0077
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectClock=true
ProtectControlGroups=true
ProtectHome=read-only
ProtectKernelLogs=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
EOF
}

if [[ "$dry_run" -eq 1 ]]; then
  echo "install_path=$install_path"
  echo "service_path=$service_path"
  echo "start_now=$start_now"
  service_contents
  exit 0
fi

[[ "$(id -u)" -eq 0 ]] || die "run as root"
need_cmd install
need_cmd systemctl

if ! getent group "$service_user" >/dev/null 2>&1; then
  groupadd --system "$service_user"
fi
if ! id "$service_user" >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$service_user" "$service_user"
fi

install -d -m 0755 "$prefix/bin"
if [[ -n "$binary_url" ]]; then
  need_cmd curl
  need_cmd sha256sum
  tmp_binary="$(mktemp)"
  http_status="$(curl --proto '=https' --tlsv1.2 --silent --show-error \
    --output "$tmp_binary" --write-out '%{http_code}' "$binary_url")" ||
    die "binary download failed"
  [[ "$http_status" =~ ^2[0-9][0-9]$ ]] || die "binary download returned a non-success response"
  printf '%s  %s\n' "$binary_sha256" "$tmp_binary" | sha256sum -c - >/dev/null ||
    die "binary checksum verification failed"
  chmod 0755 "$tmp_binary"
  install -m 0755 "$tmp_binary" "$install_path"
else
  install -m 0755 "$binary" "$install_path"
fi

install -d -m 0755 /etc/systemd/system
service_contents >"$service_path"
chmod 0644 "$service_path"

systemctl daemon-reload
systemctl enable pharos-beacon.service >/dev/null
if [[ "$start_now" -eq 1 ]]; then
  systemctl restart pharos-beacon.service
fi

echo "pharos-beacon installed"
