#!/usr/bin/env bash
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo"

echo "==> managed-service secret contracts"
cargo test -p pharos-core --locked managed_

echo "==> managed-service operation recovery"
cargo test -p pharosd --locked managed_service_operations::tests::

echo "==> managed-service signed intent boundary"
cargo test -p pharosd --locked managed_setup_intents::tests::

echo "==> managed-service UI minimization"
cargo test -p pharosd --locked managed_service_ui::tests::

echo "==> managed-service HTTP and manifest boundary"
cargo test -p pharosd --locked tests::managed_setup_
cargo test -p pharosd --locked manifests::tests::managed_service

echo "ok: Pharos managed-service secret assurance passed"
