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

## Current shipped shape

Rust, aligned with the Janus workspace, but the live v1 is deliberately smaller
than the long-term ADR target:

- `pharosd`: axum server with an in-memory store and optional JSON persistence
  (`PHAROS_DB`). sqlx/SQLite remains a PHAROS-3 durability decision, not the
  current deployed store.
- UI: server-rendered HTML plus a small vanilla-JS bridge over stable JSON APIs.
  Leptos remains the ADR direction if the dashboard grows beyond this thin
  surface; it is not required for the accepted July 2026 v1 dashboard.
- Auth: Zitadel OIDC for human routes when OIDC env is configured. Local/dev is
  open when those env vars are absent. `PHAROS_ALLOWED_OPERATORS` can then
  restrict authenticated users to explicit Pharos operators.
- Machine auth: local MVP bearer tokens via `/register` + `PHAROS_TOKEN`.
  Janus Forge/Warden migration remains later.

## Planned direction (ADR-001 / ADR-002, in PHAROS-2)

Keep the Rust workspace and shared `pharos-core` contracts. Move storage to
SQLite only if JSON persistence stops being enough for the fleet. Move the UI to
Leptos only if the operator surface grows enough to justify a frontend build.
Move token issuance/rotation to Janus once the local MVP token flow is proven.

## Workspace

| Crate | What |
| --- | --- |
| `pharos-core` | shared types (host, report, nix-freshness TL;DR, liveness) — used by server **and** agent so the schema can't drift |
| `pharosd` | the server: host registry, JSON persistence, JSON APIs, dashboard, Agora |
| `pharos-beacon` | per-host agent (Nix freshness + heartbeat report) |

## Develop

Toolchain comes from `devenv` (no global rustup) — `direnv allow`, then:

```bash
cargo run -p pharosd      # http://127.0.0.1:8080  (/, /healthz, /version, /hosts.json, /agora)
cargo test --all
cargo clippy --all-targets -- -D warnings
```

`PHAROS_MANIFEST_PATHS` may point to one or more nixcfg-generated v1 host
manifests, separated by `:` or `,`. pharosd serves them at
`/declared-hosts.json` with runtime state overlaid separately from the declared
manifest. Agora uses the same manifest data for per-host settings proposals.

```bash
PHAROS_MANIFEST_PATHS=/etc/hostdash-config/hsb8.json cargo run -p pharosd
```

### Local Docker Compose

`docker-compose.yml` is a local smoke topology, not the production deployment.
It builds `pharosd:local`, persists `/data/pharos.json` in a local Docker
volume, binds only `127.0.0.1:8080`, and keeps OIDC/operator policy off unless
you export the relevant env vars yourself. Production compose remains in
`nixcfg` under `hosts/csb1/docker/docker-compose.yml`.

```bash
docker compose up --build pharosd
docker compose --profile beacon up --build
```

The optional `pharos-beacon` profile reports to the local `pharosd` service.
For strict-token local tests, register a host and provide `PHAROS_TOKEN` from an
untracked local environment; never commit token values.

### Native NixOS beacon

The flake exports a package and NixOS module for replacing the interim Docker
beacon with a native systemd service:

```nix
{
  inputs.pharos.url = "github:markus-barta/pharos";
  inputs.pharos.inputs.nixpkgs.follows = "nixpkgs";
}
```

```nix
{
  imports = [ inputs.pharos.nixosModules.pharos-beacon ];

  services.pharos-beacon = {
    enable = true;
    tokenEnvironmentFile = "/run/agenix/pharos-beacon-env";
    nixcfgDir = "/home/mba/Code/nixcfg";
  };
}
```

`tokenEnvironmentFile` must contain `PHAROS_TOKEN=...` and should be produced by
agenix or another runtime secret source. During the temporary PHAROS-37 rollout,
`allowLegacyReports = true` can run the service without a token, but that should
not be used for final production enforcement.

### Portable non-Nix beacon

Non-Nix Linux hosts can install the beacon as a native systemd service without
Docker:

```bash
sudo ./scripts/install-pharos-beacon-systemd.sh \
  --binary ./pharos-beacon \
  --token-env /etc/pharos/pharos-beacon.env \
  --host ares
```

The installer also accepts `--binary-url` for a prebuilt binary. It never creates
or prints token values; the env file must already exist and contain
`PHAROS_TOKEN=...`, unless `--allow-legacy` is passed for the temporary PHAROS-37
rollout window.

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

Production is still rolling toward strict token-only report ingestion. Do not
enable strict mode until every deployed beacon has a per-host `PHAROS_TOKEN` and
the persisted host state has token hashes for those hosts.

## Operator authorization

When OIDC is enabled, set `PHAROS_ALLOWED_OPERATORS` to a comma- or
space-separated allowlist. Entries match normalized OIDC subject,
`preferred_username`, or email claims collected from the ID token/UserInfo.

```bash
PHAROS_ALLOWED_OPERATORS=markus cargo run -p pharosd
```

If OIDC is configured and the allowlist is absent, Pharos keeps compatibility
mode and allows all authenticated users. Production should set the allowlist
explicitly before adding broader operator access or sensitive controls.

## Route boundaries

- Human routes: `/`, `/hosts.json`, `/agora`, and Agora proposal APIs are gated
  by OIDC and the Pharos operator policy when auth is configured.
- Public/machine routes: `/healthz`, `/version`, `/assets/*`, `/auth/*`,
  `/declared-hosts.json`, `/register`, and `/report`.
- `/declared-hosts.json` is declaration plus runtime overlay; the manifest stays
  declarative and Pharos does not write runtime state back into it.
