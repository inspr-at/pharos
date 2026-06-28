# Pharos 🔦

Minimal fleet management + host access for the INSPR/DSC fleet — the lean,
INSPR-native successor to FleetCom. Planning lives in PPM project **PHAROS**.

## MVP scope (v1)

1. **Auth** — Zitadel OIDC login (PHAROS-4).
2. **Onboarding / host registration** — `inspr onboard` registers a host and
   deploys `pharos-beacon`, which self-registers on first report (PHAROS-6/7).
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

> **Status: scaffold (PHAROS-2).** The dashboard at `/` is a static preview of
> the intended design (rounded cards, accessible status, the dsc0 lighthouse)
> over **sample data**. The real Leptos UI (PHAROS-10), SQLite store
> (PHAROS-3/9), auth (PHAROS-4), and Janus tokens (PHAROS-8) are next.
