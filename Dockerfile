# syntax=docker/dockerfile:1
# Multi-stage build for pharosd. No native deps (no openssl), so slim works.

FROM rust:1-slim-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p pharosd \
    && strip target/release/pharosd

FROM debian:bookworm-slim
RUN useradd --system --uid 10001 pharos
COPY --from=build /src/target/release/pharosd /usr/local/bin/pharosd
USER pharos
ENV PHAROS_ADDR=0.0.0.0:8080 \
    RUST_LOG=info
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/pharosd"]
