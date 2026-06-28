# syntax=docker/dockerfile:1
# Multi-stage build. No native deps (no TLS/openssl/sqlite C), so slim works.
# Ships BOTH binaries: pharosd (the server) + pharos-beacon (the agent, so it
# can be extracted onto hosts: docker cp <ctr>:/usr/local/bin/pharos-beacon ...).

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pharosd -p pharos-beacon \
    && strip target/release/pharosd target/release/pharos-beacon

FROM debian:bookworm-slim
# git: the beacon shells out to it for commits-behind (rev-list HEAD..@{u}).
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --uid 10001 pharos
COPY --from=build /src/target/release/pharosd /usr/local/bin/pharosd
COPY --from=build /src/target/release/pharos-beacon /usr/local/bin/pharos-beacon
USER pharos
ENV PHAROS_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pharosd"]
