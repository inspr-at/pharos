# Pharos 🔦

Minimal fleet management + host access for the INSPR/DSC fleet — the lean,
INSPR-native successor to FleetCom. Planning lives in PPM project **PHAROS**.

## MVP scope (v1)

1. **Auth** — Zitadel OIDC login (PHAROS-4).
2. **Onboarding / host registration** — `inspr onboard` registers a host,
   receives a per-host beacon token, and deploys `pharos-beacon` (PHAROS-6/7/8).
3. **Nix host freshness** — a human one-liner TL;DR per host of what it is
   "missing": `flake.lock 12d old · 3 commits behind nixcfg` (PHAROS-15).

Everything else (per-host authz, command channel, alerting, drag, …) is
explicitly deferred. See PPM PHAROS-1 and the `guideline/pharos-architecture`
+ `guideline/pharos-ui` knowledge entries.

## Stack (ADR-001 / ADR-002, in PHAROS-2)

Rust, aligned with the Janus workspace. axum + sqlx/SQLite backend; **Leptos**
UI (shares `pharos-core` types end-to-end); tokens via Janus crates.

## Workspace

| Crate | What |
| --- | --- |
| `pharos-core` | shared types (host, report, nix-freshness TL;DR, liveness) — used by server **and** agent so the schema can't drift |
| `pharosd` | the server: host registry, JSON API, dashboard |
| `pharos-beacon` | per-host agent (self-register + report) |

## Develop

Toolchain comes from `devenv` (no global rustup) — `direnv allow`, then:

```bash
cargo run -p pharosd      # http://127.0.0.1:8080  (/, /healthz, /version, /hosts.json)
cargo test --all
cargo clippy --all-targets -- -D warnings
```

## Beacon tokens

`POST /register` is the local MVP token issuer. Set
`PHAROS_REGISTRATION_TOKEN`, then call it with `Authorization: Bearer ...`.
The response returns the raw per-host token once; pharosd stores only its
SHA-256 hash.

```bash
PHAROS_REGISTRATION_TOKEN=dev cargo run -p pharosd

curl -sS -H 'Authorization: Bearer dev' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ares","role":"NixOS Host","is_nix":true,"heartbeat_interval_secs":60}' \
  http://127.0.0.1:8080/register
```

`pharos-beacon` sends that token as `PHAROS_TOKEN`. `POST /report` requires a
valid token for registered hosts. Set `PHAROS_REQUIRE_BEACON_TOKEN=1` to reject
legacy unregistered reports; by default that becomes true when
`PHAROS_REGISTRATION_TOKEN` is configured.
