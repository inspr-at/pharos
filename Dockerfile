# syntax=docker/dockerfile:1
# Multi-stage build. Ships BOTH binaries: pharosd (the server) + pharos-beacon
# (the agent, so it can be extracted onto hosts: docker cp ...).
# Full (non-slim) toolchain: pharosd's OIDC stack pulls ring (rustls), which
# needs a C compiler. The runtime image stays slim — ring links statically and
# rustls uses bundled roots, so no system OpenSSL at build or runtime.

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pharosd -p pharos-beacon \
    && strip target/release/pharosd target/release/pharos-beacon

FROM debian:bookworm-slim
# git: the beacon shells out to it for commits-behind (rev-list HEAD..@{u}).
# restic: optional PHAROS_BACKUP_MODE=restic collector; no credentials are
# baked into the image.
# openssh-client: pharosd can run read-only existing-host preflight probes when
# the runtime has non-interactive SSH access configured.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates openssh-client restic \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 pharos
# /data owned by pharos so a named volume mounted here inherits writable
# ownership (PHAROS_DB persistence — set PHAROS_DB=/data/pharos.json).
RUN install -d -o pharos -g pharos /data
COPY --from=build /src/target/release/pharosd /usr/local/bin/pharosd
COPY --from=build /src/target/release/pharos-beacon /usr/local/bin/pharos-beacon
USER pharos
ENV PHAROS_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pharosd"]
