#!/usr/bin/env bash
set -euo pipefail

# PHAROS-188: execute the exact production formatter against a real Docker
# container. A missing/renamed template field must fail CI instead of turning
# every Compose host into a permanent coarse "discovery failed" observation.
readonly compose_format='{{.Label "com.docker.compose.project"}}	{{.Label "com.docker.compose.service"}}	{{.Label "com.docker.compose.oneoff"}}	{{.State}}	{{.Status}}'
readonly image="pharos-compose-contract-$PPID-$$"
readonly container="pharos-compose-contract-$PPID-$$"

cleanup() {
  docker container rm --force "$container" >/dev/null 2>&1 || true
  docker image rm --force "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf 'FROM scratch\nCMD ["/pharos-contract-placeholder"]\n' |
  docker build --quiet --tag "$image" - >/dev/null
docker container create \
  --name "$container" \
  --label com.docker.compose.project=contract-project \
  --label com.docker.compose.service=contract-service \
  --label com.docker.compose.oneoff=False \
  "$image" >/dev/null

actual="$(docker container ls \
  --all \
  --filter label=com.docker.compose.project=contract-project \
  --filter label=com.docker.compose.service=contract-service \
  --format "$compose_format")"
expected="$(printf 'contract-project\tcontract-service\tFalse\tcreated\tCreated')"
test "$actual" = "$expected"

echo "Compose observation Docker formatter contract: ok"
