# syntax=docker/dockerfile:1.20.0@sha256:26147acbda4f14c5add9946e2fd2ed543fc402884fd75146bd342a7f6271dc1d
# Multi-stage build. Ships pharosd, pharos-beacon, and the read-only pharos CLI.
# Full (non-slim) toolchain: pharosd's OIDC stack pulls ring (rustls), which
# needs a C compiler. The runtime image stays slim — ring links statically and
# rustls uses bundled roots, so no system OpenSSL at build or runtime.

FROM rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS build
ARG GIT_COMMIT=dev
WORKDIR /src
COPY . .
RUN GIT_COMMIT="${GIT_COMMIT}" cargo build --release --locked -p pharosd -p pharos-beacon -p pharos-cli \
    && strip target/release/pharosd target/release/pharos-beacon target/release/pharos

FROM debian:bookworm-slim@sha256:7b140f374b289a7c2befc338f42ebe6441b7ea838a042bbd5acbfca6ec875818
ARG DEBIAN_SNAPSHOT=20260713T000000Z
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
# git: the beacon shells out to it for commits-behind (rev-list HEAD..@{u}).
# restic: optional PHAROS_BACKUP_MODE=restic collector; no credentials are
# baked into the image.
# openssh-client: pharosd can run read-only existing-host preflight and
# convergence-marker probes when the runtime has non-interactive SSH access.
# iputils-ping: the fixed appliance-presence signal used before testing SSH.
# The Debian image and package indexes share one immutable snapshot date. HTTP
# transport is safe here because apt verifies Debian's signed Release metadata
# and package hashes.
RUN printf '%s\n' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm bookworm-updates' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      '' \
      'Types: deb' \
      "URIs: http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT}" \
      'Suites: bookworm-security' \
      'Components: main' \
      'Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg' \
      'Check-Valid-Until: no' \
      > /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates iputils-ping openssh-client restic \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 pharos
# /data owned by pharos so a named volume mounted here inherits writable
# ownership (PHAROS_DB persistence — set PHAROS_DB=/data/pharos.json).
RUN install -d -o pharos -g pharos /data
COPY --from=build /src/target/release/pharosd /usr/local/bin/pharosd
COPY --from=build /src/target/release/pharos-beacon /usr/local/bin/pharos-beacon
COPY --from=build /src/target/release/pharos /usr/local/bin/pharos
COPY --from=build /src/LICENSE /usr/share/licenses/pharos/LICENSE
COPY --chmod=0755 scripts/install-pharos-beacon-systemd.sh /usr/local/share/pharos/install-pharos-beacon-systemd.sh
USER pharos
ENV PHAROS_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080
# Role-aware container probe (PHAROS-203/204). The image is shared by two
# roles: `pharosd` (default entrypoint) and `pharos-beacon`. A beacon always
# carries PHAROS_URL, so that selects its own report-freshness check; anything
# else gets the daemon readiness probe, which refuses to guess a bind address
# and prints its reason. Both verdicts land in `docker inspect .State.Health`.
HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
    CMD if [ -n "${PHAROS_URL:-}" ]; then \
        exec /usr/local/bin/pharos-beacon healthcheck; \
    else \
        exec /usr/local/bin/pharosd healthcheck; \
    fi
ENTRYPOINT ["/usr/local/bin/pharosd"]
