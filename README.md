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

## Release Versioning

`VERSION` is the visible product version and must match the Cargo workspace
version. `pharosd` embeds that version at build time and reports it from
`/version` together with the build commit. The dashboard sidebar shows the same
version and links to the release history rendered from `docs/CHANGELOG.md`.

Before every production deploy:

1. Bump `VERSION` using semver.
2. Keep the Cargo workspace version in sync.
3. Add the newest entry to `docs/CHANGELOG.md` in operator-facing language.
4. Do not deploy a changed product with an unchanged visible version.

`PHAROS_MANIFEST_PATHS` may point to one or more nixcfg-generated v1 host
manifests, separated by `:` or `,`. pharosd serves them at
`/declared-hosts.json` with runtime state overlaid separately from the declared
manifest. Agora uses the same manifest data for per-host settings proposals.

```bash
PHAROS_MANIFEST_PATHS=/etc/hostdash-config/hsb8.json cargo run -p pharosd
```

### Declarative Nix host settings

Agora can request the fixed `inspr.pharos.host-preferences.v1` preference set
through nixcfg's guarded `pharos-host-settings.yml` workflow. This integration
is off by default. The current production exception uses a dedicated classic
GitHub PAT with no configured expiration and only the top-level `repo` scope.
GitHub requires that broad scope to dispatch a workflow in a private repository
with a classic PAT, so never reuse this credential for interactive Git, pull
requests, merges, or another service. Replace it with Janus-brokered GitHub App
installation tokens when JANUS-275 lands:

```bash
export PHAROS_NIXCFG_DISPATCH_ENABLED=1
export PHAROS_NIXCFG_DISPATCH_TOKEN_FILE=/run/pharos/nixcfg-dispatch-token
export PHAROS_HOST_PREFERENCES_PATH=/nixcfg/modules/pharos-host-preferences.json
# Enable only after the fixed review-only removal workflow is installed.
export PHAROS_HOST_REMOVAL_DISPATCH_ENABLED=1
# Machine identity that owns target-local Janus credential retirement.
export PHAROS_RETIREMENT_OWNER_HOST=csb1
```

Mount the token as a private, read-only runtime file; never place its value in
Compose, an environment variable, logs, or the host store. pharosd calls only
the fixed workflow-dispatch endpoint. The workflow's scoped `GITHUB_TOKEN` owns
validation, commit, pull request, checks, and ordinary merge; pharosd has no git
or merge logic. Treat the classic PAT as a temporary, explicitly reviewed
privilege exception even though Pharos deliberately uses only the narrow API
operation.

Mount nixcfg's complete host-preference registry read-only at
`PHAROS_HOST_PREFERENCES_PATH`. Pharos validates the exact registry contract
and treats it as declared state; a loaded host manifest remains the fallback
when no registry entry exists. The registry never becomes applied state by
itself.

An accepted dispatch means only that the request reached GitHub. It does not
mean the workflow merged or that a host rebuilt. Fleet therefore keeps three
states separate: requested operator intent, the declaration currently loaded
from the nixcfg-generated manifest, and the last preference set reported by
the beacon. A declared change remains **change waiting** until the host's own
later rebuild applies it and the beacon reports the matching value. Pharos does
not trigger that rebuild or any fleet-wide deployment.

Host removal uses the same narrow dispatch credential but a separate opt-in
workflow. Local-token runtime-only hosts are retired directly in Pharos. A
Janus-managed host must have a declared retirement path and remains visibly
pending while nixcfg prepares a review-only cleanup proposal. After that
declaration is reviewed, merged, and applied, the configured retirement owner
claims a separate machine-authenticated lease and runs only the reviewed Janus
retirement intent. Pharos completes the workflow only after both declaration
cleanup and a value-free owner result pass. A stopped owner run requires an
operator retry; it is never silently replayed. The current owner cannot retire
itself until ownership moves to another host.

Pharos records whether the old host was destroyed, left unmanaged, or rebuilt;
rebuilt hosts must name a different successor that is already onboarded. No
removal action deletes a server, provider resource, disk, service, or
application data. `/agent/retirements/claim` and
`/agent/retirements/{id}/result` accept only the configured owner's existing
per-host machine identity. A compromised target host therefore cannot approve
or complete its own credential retirement.

After a NixOS generation owns the declaration, point the beacon at that
generation's registry with
`PHAROS_PREFERENCES_FILE=/etc/pharos/host-preferences.json` (or the NixOS module
option below). The beacon validates the complete fixed schema, selects only its
own hostname, and keeps its last valid value if a later read is missing or
malformed. Unknown fields are rejected; the file cannot carry commands.

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

### Self-Host Docker Compose

`docker-compose.selfhost.yml` is the reusable self-host control-plane template.
It runs the released GHCR image, persists `/data/pharos.json`, requires OIDC for
human routes, requires an operator allowlist, and keeps beacon ingestion
strict-token gated from first start. Keep all runtime values in your shell, host
secret manager, or orchestrator. Do not commit a populated env file.

Minimum first-run values:

```bash
export PHAROS_OIDC_ISSUER=https://issuer.example
export PHAROS_OIDC_CLIENT_ID=pharos
export PHAROS_OIDC_REDIRECT_URI=https://pharos.example/auth/callback
export PHAROS_ALLOWED_OPERATORS=alice
read -rsp 'Pharos registration token: ' PHAROS_REGISTRATION_TOKEN; echo
export PHAROS_REGISTRATION_TOKEN
export PHAROS_BIND=127.0.0.1:8080
docker compose -f docker-compose.selfhost.yml config
docker compose -f docker-compose.selfhost.yml up -d
```

Put a reverse proxy or tailnet endpoint in front of `PHAROS_BIND`; expose only
HTTPS to users. The registration token is only for initial beacon registration.
After moving to Janus sidecars, set `PHAROS_BEACON_TOKEN_MODE=janus` and provide
the private hash sidecar mount/env from your secret-rendering system.

Hetzner Cloud creation is also off by default. Prepare an existing SSH public
key and a reviewed firewall in the Hetzner project, mount the API token as a
private runtime file, then set:

```bash
export PHAROS_HCLOUD_EXECUTE=1
export PHAROS_HCLOUD_API_TOKEN_FILE=/run/pharos/hcloud-token
export PHAROS_HCLOUD_SSH_KEY_REF=pharos-bootstrap-key
export PHAROS_HCLOUD_FIREWALL_REF=pharos-bootstrap-firewall
```

Pharos resolves both named resources before the create call and attaches their
numeric provider IDs to the server request. If the token, public key, or
firewall is unavailable, setup fails before creating a server. Keep the token
mount in a private Compose override or orchestrator secret; never place the raw
value in Compose, an env file, or the setup UI.

Before the first heartbeat, the tracked setup can be reopened from its fleet
card. **Recovery options** can remove only that job's single persisted Hetzner
server after explicit confirmation. The same operation is available as
`POST /setup/provisioning-jobs/{id}/cleanup` with `{"confirm":true}`. A proven
delete or provider `404` becomes an idempotent rolled-back outcome; network,
unexpected success, and error responses remain `cleanup-needed` so an operator
can verify the provider console before retrying. The API token is never returned
in job or cleanup responses.

Existing-host native systemd execution is deliberately off by default. The
assistant still provides a reviewable manual handoff without it. To enable the
executor, mount a private SSH identity and a pinned `known_hosts` file
read-only, then set:

```bash
export PHAROS_EXISTING_HOST_EXECUTE=1
export PHAROS_EXISTING_HOST_PHAROS_URL=https://pharos.example
export PHAROS_EXISTING_HOST_IDENTITY_FILE=/run/pharos/ssh/id
export PHAROS_EXISTING_HOST_KNOWN_HOSTS_FILE=/run/pharos/ssh/known_hosts
```

The executor refuses unknown host keys, password/interactive SSH, an existing
target token file, or an unreadable runtime reference. It transfers the bundled
beacon and installer first, then sends the newly issued beacon token only over
SSH stdin into a root-owned `0600` env file. Local/dual token mode supports this
direct handoff; Janus-only mode fails closed until a Janus credential broker is
configured. Do not put private SSH material in the Compose file or repository.

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
    tokenFile = "/etc/pharos/pharos-beacon.token";
    nixcfgDir = "/home/mba/Code/nixcfg";
    preferencesFile = "/etc/pharos/host-preferences.json";
  };
}
```

For first installation onto an existing machine, run the helper from a Linux
host with Nix and `nixos-anywhere` installed:

```bash
scripts/bootstrap-pharos-nixos-anywhere.sh \
  --flake /path/to/nixcfg#host-name \
  --target root@host-name \
  --token-file /private/runtime/pharos-beacon.token \
  --known-hosts /private/runtime/known_hosts \
  --identity /private/runtime/id_ed25519
```

The helper validates private-file permissions and strict SSH trust, preserves
the target host keys, copies the token with `nixos-anywhere --extra-files`, and
waits for `pharos-beacon.service`. The raw token is not a command argument and
never enters Nix evaluation or the Nix store. The module loads the root-only
source file through a per-service systemd credential, so the unprivileged
beacon can read its private copy without weakening the source permissions. The
target configuration must import `nixosModules.pharos-beacon` and use the shown
first-bootstrap token path.
After the first heartbeat, migrate that file to an agenix- or Janus-managed
runtime path and update `tokenFile` declaratively.

`tokenEnvironmentFile` remains supported when a root-owned env file containing
`PHAROS_TOKEN=...` is more practical. `allowLegacyReports = true` exists only
for controlled migrations and must not be used with strict production report
ingestion.

### Portable non-Nix beacon

Non-Nix Linux hosts can install the beacon as a native systemd service without
Docker:

```bash
sudo ./scripts/install-pharos-beacon-systemd.sh \
  --binary ./pharos-beacon \
  --token-file /etc/pharos/pharos-beacon.token \
  --host ares
```

The installer also accepts `--binary-url` for a prebuilt binary. It never creates
or prints token values; the token file or env file must already exist unless
`--allow-legacy` is passed for the temporary PHAROS-37 rollout window.

## Beacon tokens

`POST /register` is the local MVP token issuer. Set
`PHAROS_REGISTRATION_TOKEN`, then call it with `Authorization: Bearer ...`.
The response returns the raw per-host token once; pharosd stores only its
SHA-256 hash. Keep this path for development and migration only.

```bash
PHAROS_REGISTRATION_TOKEN=dev cargo run -p pharosd

curl -sS -H 'Authorization: Bearer dev' \
  -H 'Content-Type: application/json' \
  -d '{"name":"ares","role":"NixOS Host","is_nix":true,"heartbeat_interval_secs":60}' \
  http://127.0.0.1:8080/register
```

`pharos-beacon` sends that token as `PHAROS_TOKEN`, or reads it from
`PHAROS_TOKEN_FILE` when configured. For Janus-managed issuance, set
`PHAROS_BEACON_TOKEN_MODE=janus` and provide
`PHAROS_BEACON_TOKEN_HASH_FILE` pointing at a private Janus/Forge-produced JSON
file. For per-host sidecars, use `PHAROS_BEACON_TOKEN_HASH_FILES` as a
comma-separated list or `PHAROS_BEACON_TOKEN_HASH_DIR` to read every non-hidden
`.json` regular file in a private directory. Those files contain host names and
SHA-256 token hashes only; pharosd never needs the raw beacon token. `dual` mode
accepts both the local persisted hashes and Janus hash files during migration.
In `janus` mode, local `/register` is disabled unless
`PHAROS_ALLOW_LOCAL_REGISTER=1` is set explicitly.

The hash file contract is:

```json
{
  "schema": "inspr.pharos.beacon-token-hashes.v1",
  "hosts": [
    { "name": "ares", "token_sha256": "<64 lowercase hex chars>" }
  ]
}
```

When
`PHAROS_REQUIRE_BEACON_TOKEN=0`, `/report` accepts legacy reports without a
bearer token even if the host already has a stored token hash, while still
rejecting an explicitly wrong bearer token. Set
`PHAROS_REQUIRE_BEACON_TOKEN=1` to reject reports that do not present a valid
per-host token; by default that becomes true when `PHAROS_REGISTRATION_TOKEN`
is configured or a Janus hash file is configured.

Production uses strict token-only report ingestion. Before enabling the same
policy in another deployment, ensure every beacon has a per-host token and
pharosd has either persisted local hashes or a Janus-managed hash file for those
hosts.

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
  `/declared-hosts.json`, `/register`, `/report`, `/agent/actions/*`, and
  `/agent/retirements/*`.
- `/declared-hosts.json` is declaration plus runtime overlay; the manifest stays
  declarative and Pharos does not write runtime state back into it.
