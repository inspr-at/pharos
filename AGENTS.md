# Pharos — Agent Doctrine Overlay

This file contains the Pharos-specific delta. Universal INSPR doctrine lives
in `../inspr-modules`; load the relevant domain pack before specialized work.

## Project identity

- **Trust context**: INSPR (published FOSS under `inspr-at`).
- **PPM project**: Pharos, key `PHAROS`, numeric id `17`.
- Use `paimos` for Knowledge, backlog, ticket status, and time tracking.
- Reference `PHAROS-<number>` in branches, commits, pull requests, and reports.

## Repository boundaries

- Pharos owns fleet observation, operator-facing lifecycle state, and guarded
  workflows. nixcfg owns declarative host configuration; Janus owns secrets,
  credentials, and privileged authorization.
- Keep browser, logs, durable state, tests, Git, and PPM value-free: never put
  raw tokens, credentials, private keys, secret contents, or credential-bearing
  URLs into them.
- Durable architecture and operational knowledge belongs in PPM Knowledge.
  Local documentation is limited to the standard repository files described by
  doctrine.

## Local validation

- Rust: `cargo test --workspace`, `cargo clippy --workspace --all-targets -- -D warnings`,
  and `cargo fmt --all -- --check`.
- Browser tests: `npm run test:browser`.
- Release consistency: `scripts/check-release-consistency.sh`.
