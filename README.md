# Pharos

**Fleet clarity before fleet control.**

[![CI](https://github.com/inspr-at/pharos/actions/workflows/ci.yml/badge.svg)](https://github.com/inspr-at/pharos/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-0.1.84-d79b2b)](docs/CHANGELOG.md)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-0b8178)](LICENSE)

Pharos is a compact, self-hosted fleet control plane for people and automation.
It turns scattered heartbeats, host declarations, backup facts and guarded
operations into one legible operating picture.

It is deliberately not a generic remote shell. Pharos separates what a host
reported, what configuration declares, what an operator requested and what an
executor proved. That separation is the product.

[Product site](https://pharos.inspr.at) ·
[Source](https://github.com/inspr-at/pharos) ·
[Changelog](docs/CHANGELOG.md) ·
[INSPR](https://www.inspr.at)

## Why Pharos exists

A fleet becomes difficult before it becomes large. Five machines can already
mean five different answers to basic questions:

- Is the host alive, or did the dashboard simply stop hearing from it?
- Is a NixOS host running what its declaration says?
- Did the latest backup succeed, and when?
- Is a pending restart expected or forgotten?
- Was a change requested, reviewed, applied and verified, or merely clicked?
- Which system is allowed to hold a provider credential?

Most dashboards flatten these questions into a green or red dot. Pharos keeps
their sources and meanings visible.

| State | Meaning | Source |
| --- | --- | --- |
| **Observed** | What a host or bounded probe reported | `pharos-beacon`, server receive time, optional probes |
| **Declared** | What should exist | Read-only host manifests and the nixcfg preference registry |
| **Requested** | What an operator asked to change | Persisted Pharos workflow state |
| **Executed** | What a bounded agent or provider operation attempted | Leased action result |
| **Verified** | What fresh evidence confirms after the action | New heartbeat, kernel, service and backup evidence |

That model prevents a merged declaration from masquerading as a deployed
system, and prevents a successful API request from masquerading as a completed
operation.

## What ships in v0.1.53

| Area | Current capability |
| --- | --- |
| **Fleet** | Grid and list views, search, sorting, host liveness, heartbeat history, Nix freshness, kernel posture and service observations |
| **Map** | Optional host location and reachability signals without turning location into a control channel |
| **Backups** | Per-host backup posture from beacon observations, including protected, stale, failed and unreported states |
| **Alerts and activity** | Actionable fleet attention, value-free workflow history and optional outbound silent-heartbeat notifications |
| **Host settings** | Color, server/workstation kind and alert preferences with requested, declared and applied state shown separately |
| **Onboarding** | Existing-host preflight, native beacon or NixOS handoff, first-heartbeat tracking and explicit backup/location decisions |
| **Providers** | English/German Hetzner portal guidance with Fish-safe commands and exact destination paths, read-only provider checks, exact paid-plan review, attended authorization, single-use creation and ownership-checked cleanup |
| **Guarded actions** | Fixed review/apply/restart, fleet-update proposal and host-retirement workflows with leases, confirmation and recovery evidence |
| **Access** | OIDC Authorization Code + PKCE for people; scoped machine-operator credentials for read-only clients; independent per-host bearer authentication for beacons |

The UI is server-rendered HTML with a focused vanilla-JavaScript interaction
layer. There is no separate frontend build or client framework.

## Architecture

```text
                                  read-only declarations
                             ┌────────────────────────────┐
                             │ nixcfg manifests/preferences│
                             └──────────────┬─────────────┘
                                            │
  browser ── OIDC + PKCE ─┐                 ▼
                           │        ┌─────────────────┐
  pharos-beacon ─ report ──┼───────▶│    pharosd      │
                           │        │ Axum + SSR + API │
  target agent ◀─ lease ───┤        └────────┬────────┘
               ─ result ──▶│                 │
                           │                 ▼
  Janus token generation ──┘        durable JSON snapshots
                                            │ fixed, opt-in calls
                                            ▼
                              nixcfg / Hetzner Cloud
```

### Workspace

| Crate | Responsibility |
| --- | --- |
| `pharos-core` | Versioned host, report, liveness, preferences, provisioning and manifest contracts shared by server and agent |
| `pharosd` | Fleet store, OIDC guard, machine APIs, server-rendered dashboard, provider connections and guarded workflows |
| `pharos-beacon` | Small per-host reporter for heartbeat, generation-proven Nix freshness, kernel, backup, location and bounded service observations |
| `pharos-cli` | Read-only `pharos` operator CLI for health/version, hosts, declarations, beacon last-seen, proofs and provisioning jobs |

The shared Rust contracts matter: server and beacon cannot silently drift onto
different report schemas. The current report contract is
`inspr.pharos.host-report.v5`; the local onboarding envelope is
`inspr.pharos.host-registration.v1`. Both require explicit schema/version
fields and reject extensions. Reports are limited to 64 KiB, heartbeat cadence
is 10–3600 seconds, and all identities, freshness values, and observation text
are bounded before persistence or alerting.

Nix freshness is tied to the active NixOS generation, not inferred from a mutable
checkout. A strict value-free evidence document identifies the exact nixcfg
revision, SHA-256 of the evaluated `flake.lock`, resolved primary nixpkgs
revision, last-modified timestamp, and channel. The beacon accepts checkout lock
context only when its digest and primary node exactly match that evidence.

The beacon fetches the configured authoritative nixcfg branch into an isolated
writable reference repository; `/nixcfg` remains read-only. Exact ancestry
distinguishes current, behind with a proven commit count, ahead, and diverged.
Fetch, timeout, parse, missing-object, evidence, or consistency failure produces
unknown and never falls back to a local upstream-tracking ref. The locked
nixpkgs revision is separately compared with the bounded `git-revision`
published for its declared channel. For the official NixOS source, Pharos reads
the HTTPS channel document and permits only its single documented redirect to
`releases.nixos.org`; the response is size-bounded and must contain exactly one
full lowercase Git object ID. Custom Git remotes retain the exact fail-closed
Git comparison. Age is context only: Pharos claims current only when the active
generation, authoritative nixcfg revision, and nixpkgs channel revision all
match exactly.

The control plane still applies the release calendar, so an end-of-life channel
outranks revision age. Another root nixpkgs-family input may be shown separately
as neutral lock-maintenance context only when the checkout lock matches the
generation digest; transitive inputs remain excluded and secondary context never
changes host patch posture.

For an ordered fleet rollout, the control plane accepts the current report
contract and exactly its immediate predecessor. Deploy the new control plane
first, verify readiness and old-beacon reports, then roll the beacons. Unknown,
older, or mismatched schema/version pairs still fail closed; this bounded
compatibility window prevents a release from aging otherwise healthy hosts to
Down while avoiding an open-ended legacy protocol surface.

### Persistence

`pharosd` keeps working state in memory and persists it when `PHAROS_DB` points
to a JSON file. Provisioning, provider, guarded-action and retirement state use
derived JSON sidecars beside that file. Most read-only/local use remains
available without persistence, but paid provider review, authorization,
creation, reconciliation, and cleanup fail closed unless the provisioning-job
sidecar is configured and valid. `PHAROS_PROVISIONING_JOBS_DB` can name that
sidecar explicitly when `PHAROS_DB` is not used. Paid job snapshots use a
checksummed, store-bound envelope and an adjacent `.initialized` marker; back
up and restore both together. If an initialized snapshot disappears or is
replaced by a bare/partial JSON list, paid actions stay disabled.

This is intentionally a small-fleet design:

- one `pharosd` process is the expected writer;
- there is no SQL database, clustering or multi-node consensus;
- OIDC sessions and in-flight login state are memory-only;
- a restart requires users to sign in again;
- the data volume still needs ordinary host-level backup.

Heartbeat history is bounded to the latest 24 hours and at most 3,000 samples
per host. Liveness is stamped by the server when a report arrives; an agent
cannot declare itself recently seen.

## Quick start

### Docker

The fastest useful local run starts the server and a development beacon:

```bash
docker compose --profile beacon up --build
```

Then open:

- Dashboard: <http://127.0.0.1:8080>
- Health: <http://127.0.0.1:8080/healthz>
- Build metadata: <http://127.0.0.1:8080/version>

The local Compose topology binds only to loopback, stores data in a Docker
volume and intentionally leaves OIDC and strict beacon authentication off. It
is a smoke environment, not a production template.

### Native development

The repository includes a `devenv` environment:

```bash
devenv shell
PHAROS_ALLOW_OPEN=true cargo run -p pharosd
```

In another shell, send one local report:

```bash
PHAROS_URL=http://127.0.0.1:8080 \
PHAROS_HOSTNAME=local-dev \
PHAROS_ROLE="Development host" \
cargo run -p pharos-beacon
```

Set `PHAROS_INTERVAL=60` to keep the beacon running (valid range: 10–3600
seconds). Without it, the beacon reports once and exits. HTTP and HTTPS are
supported; credentials, query strings and fragments are rejected in
`PHAROS_URL`.

## Self-hosting baseline

[`docker-compose.selfhost.yml`](docker-compose.selfhost.yml) is the reusable
control-plane template. It requires OIDC, an operator allowlist and strict
machine authentication from first start.

```bash
export PHAROS_OIDC_ISSUER=https://issuer.example
export PHAROS_OIDC_CLIENT_ID=pharos
export PHAROS_OIDC_REDIRECT_URI=https://pharos.example/auth/callback
export PHAROS_ALLOWED_OPERATORS=email:alice@example.com
export PHAROS_BIND=127.0.0.1:8080

export PHAROS_REGISTRATION_TOKEN_FILE=/run/secrets/pharos-registration-token

docker compose -f docker-compose.selfhost.yml config
docker compose -f docker-compose.selfhost.yml up -d
```

Mount the secret-manager-owned registration-token file read-only at that exact
container path with a private Compose override. The file path, not the token,
is placed in the process environment. In Janus token mode, leave both the
direct and file-backed registration-token variables unset.

Put an HTTPS reverse proxy or a private tailnet endpoint in front of
`PHAROS_BIND`. For durable operation, supply runtime values through your host
secret manager or orchestrator rather than a committed environment file.

The OIDC client is public and uses PKCE, so it has no client secret. Login state
is browser-bound and expires after ten minutes; in-flight logins and sessions
have hard count and creation-rate bounds. Session cookies use the `__Host-`
prefix, and logout is a CSRF-protected POST. Expired, replayed, restarted or
superseded login flows fail closed into a no-store recovery page with one fresh
sign-in action. Only validated local, non-authentication return paths survive a
recovery; temporary provider transport failures remain distinct from OAuth
rejection, malformed responses and token-verification failures.

`PHAROS_ALLOWED_OPERATORS` grants full fleet access to explicit authorization
identifiers. Prefer `operator-ref:<sha256>`, the value-free reference Pharos
derives from the immutable OIDC issuer and subject. `verified-email-ref:<sha256>`
is a domain-separated, value-free migration reference that Pharos derives only
when the signed OIDC claims say `email_verified=true`. Literal
`email:<address>` remains supported for migration but exposes that address to
the runtime configuration. Usernames and unprefixed emails are rejected at
startup. `PHAROS_ACCESS_POLICY_FILE` uses the same identifier forms for scoped
grants.

If OIDC variables are absent, startup fails unless `PHAROS_ALLOW_OPEN=true`
is set and the effective public address is loopback. Containerized development
can declare its loopback-only published boundary with `PHAROS_PUBLIC_ADDR`;
production deployments must use OIDC instead.

## Trust model

Pharos assumes infrastructure state is useful only when its authority is
understandable.

### 1. Human and machine routes are separate

Dashboard and operator APIs are behind the OIDC guard when configured.
Registration, reports and target-agent routes use bearer credentials instead
of browser sessions. Liveness (`/healthz`), readiness (`/readyz`), metrics,
version and authentication endpoints remain public.

### 2. Machine credentials are purpose-specific

Machine-operator credentials are separate from registration and beacon tokens.
Janus projects only scoped SHA-256 verifiers to pharosd; clients read their raw
credential from `PHAROS_OPERATOR_TOKEN_FILE`. `fleet:read` can inspect guarded
fleet JSON and job evidence. `fleet:write` additionally reaches existing write
handlers, which still require `X-Pharos-Action: 1` and every workflow-specific
review, enablement and attended-authorization gate.

Beacon identity remains per host.

Local registration returns a raw beacon token exactly once and stores only its
SHA-256 hash. Report verification uses constant-time comparison.

| `PHAROS_BEACON_TOKEN_MODE` | Accepted token source |
| --- | --- |
| `local` | Hashes persisted by local `/register` |
| `dual` | Local hashes or the active Janus v2 generation during migration |
| `janus` | The active Janus v2 generation only; strict report auth and disabled local registration are enforced at startup |

Unknown mode values reject startup. Janus mode also rejects a local registration
credential and requires one readable, non-empty v2 generation root. The retired
v1 per-file variables fail startup. Pharos reads the small atomic `current`
pointer for every authorization check and reparses the bounded immutable
generation only when that pointer changes, so revocation is immediate without
rescanning unrelated files. `/readyz` and `/metrics` expose value-free status,
generation id and last successful load time.

`PHAROS_REQUIRE_BEACON_TOKEN=1` is the production posture. The self-host
template sets it explicitly.

### 3. Secret values stay out of product state

Janus integration gives `pharosd` host names and token hashes, not raw beacon
tokens. Provider credentials are read from private runtime files when an
executor is enabled. They are not serialized into jobs, returned to the
browser or written into the host store.

The Janus provider-setup link carries value-free metadata only. Pharos is not a
general secret manager. A signed setup intent lasts at most fifteen minutes so
page review can precede one complete five-minute Janus passkey step-up. The
browser still receives only an opaque reference; Janus independently caps the
outer lifetime, keeps the passkey proof at five minutes, and consumes the exact
intent once before reading any value bytes.

### 4. Automation is narrow and off by default

Provider creation, existing-host execution and nixcfg dispatch each require
explicit runtime enablement and complete trust inputs. Missing tokens, SSH
identity, pinned host keys, reviewed firewalls, backup evidence or fresh
post-action observations stop the workflow.

Host-action state contains no credentials, arbitrary commands, Nix store paths
or command output. Target agents can claim only a fixed phase of a persisted
workflow for a bounded lease.

The optional Paimos delivery-stage adapter is reporter-only. Its owner-written
local intent file fixes the Paimos origin, handoff IDs, host, one of the two
compiled workflows (`deploy-production` or `verify-production`), symbolic
environment, exact artifact tuple and existing guarded `UpdateRestart` binding.
Paimos supplies none of those authority-bearing selectors, and no Paimos field
can become a command, path, callback, host selector or arbitrary workflow.

Every external call requires the registered API key and the handoff's separate
32-byte credential from different owner-only, current-user-owned, single-link
files. Before a mutation, Pharos durably stores the exact safe JSON request and
an idempotency key derived from handoff ID, sequence and request digest. The
journal also stores a domain-separated digest of the canonical Paimos origin
and every non-secret owner-intent selector, so a crash replay is rejected if
the destination, workflow, environment, host, artifact or guarded action
binding changed. An unchanged intent replays the
exact bytes after a crash or ambiguous response; credential rotation does not
change request identity. The adapter emits only sequence 1 `accepted` followed
by sequence 2 `succeeded` or `failed`—never `active` or a heartbeat.

Deployment success requires an already operator-confirmed `UpdateRestart` to
finish and a newer fresh beacon to report Nix generation evidence whose source
revision and `flake.lock` digest match the locally configured commit and
artifact digest. Verification uses a separate handoff and remains unreported
until another fresh beacon arrives after Paimos received deployment, with the
identical host, environment and artifact tuple. Wrong artifact, wrong
environment, stale, missing or pre-deployment evidence fails closed.

### 5. Requested is never presented as applied

Nix host settings become declared only after the configured nixcfg artifact is
loaded. They become applied only after a later beacon reports the same value.
Non-Nix hosts may receive their own bounded preferences document in the report
response; the beacon validates it and replaces its private file atomically.

### 6. Destructive scope stays explicit

Removing a host from Pharos revokes reports and records retirement state. It
does not delete a server, disk, service or application data. The one exception
is an explicitly confirmed cleanup endpoint for the single Hetzner server
recorded by an incomplete provisioning job. Uncertain provider responses remain
visible for operator review.

Declarative cleanup and credential retirement are independent stages, because a
declared manifest and a Janus-issued beacon credential come from separate
sources. A removal runs whichever stages apply, the dialog names them before
confirmation, and the host stays durably visible as a pending removal until
every applicable stage completes.

### 7. The browser boundary is deny-by-default

Every response carries anti-framing, MIME-sniffing, referrer, permissions,
transport and cross-origin hardening headers. Rendered HTML receives a fresh
cryptographic CSP nonce; scripts may run only from the Pharos origin or with
that response nonce, script attributes are denied, and objects/frames/base-URI
injection are disabled. The current server-rendered UI still uses bounded
inline style attributes, so `style-src-attr 'unsafe-inline'` is the documented
temporary exception; inline script is not allowed.

Leaflet 1.9.4 and D3 7.9.0 are pinned, vendored with their upstream licenses,
embedded in `pharosd`, and served from versioned same-origin asset paths. Map
tiles deliberately remain external CARTO `light_all` requests: the tile host
can observe the browser IP address and requested viewport/tile coordinates,
but receives no Pharos credentials, host payload, or HTTP referrer. Deployments
whose policy forbids that metadata disclosure should block the CARTO tile host;
the inventory/site view and map labels continue to work without the basemap.

| Vendored file | SHA-256 |
| --- | --- |
| `leaflet-1.9.4/leaflet.css` | `337bfca5cabd03b39815b2700febe2b3b7edf55921c59cd49f88ecb328212303` |
| `leaflet-1.9.4/leaflet.js` | `db49d009c841f5ca34a888c96511ae936fd9f5533e90d8b2c4d57596f4e5641a` |
| `d3-7.9.0/d3.min.js` | `f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539` |

## Beacons

### Native NixOS service

The flake exports `nixosModules.pharos-beacon`:

```nix
{
  inputs.pharos.url = "github:inspr-at/pharos";
  inputs.pharos.inputs.nixpkgs.follows = "nixpkgs";
}
```

```nix
{
  imports = [ inputs.pharos.nixosModules.pharos-beacon ];

  services.pharos-beacon = {
    enable = true;
    url = "https://pharos.example";
    tokenFile = "/run/secrets/pharos-beacon-token";
    nixcfgDir = "/etc/nixos";
    preferencesFile = "/etc/pharos/host-preferences.json";
  };
}
```

The module loads `tokenFile` through a systemd credential, runs the beacon as
an unprivileged service and hardens its filesystem view. The service uses
systemd readiness/watchdog notifications; only a successful report refreshes
the watchdog. Set `allowLegacyReports = true` only for a controlled migration.

### Portable Linux service

For a non-Nix Linux host:

```bash
sudo ./scripts/install-pharos-beacon-systemd.sh \
  --binary ./pharos-beacon \
  --token-file /etc/pharos/pharos-beacon.token \
  --pharos-url https://pharos.example \
  --host example-host
```

The installer expects token material to exist already. It does not generate or
print credentials. The service keeps mutable preferences in its private state
directory and reports them on the next heartbeat.

Every request has explicit connect, read, write and overall deadlines shorter
than its reporting cadence. Failed recurring reports retry with capped
exponential backoff and jitter. Command collectors drain output concurrently,
retain only bounded output, and kill their process group at the execution
deadline.

### What a beacon reports

Collectors are explicit and bounded:

- host identity, role and heartbeat interval;
- Nix `flake.lock` age and commits behind the configured checkout;
- running versus current kernel posture;
- optional backup observations from Restic, a status file or a configured
  bounded command;
- optional location from static configuration, a bounded command or an
  operator-enabled IP service;
- bounded service observations and report round-trip timing;
- currently applied host preferences.

Unknown or malformed contract fields fail validation. A missing observation is
shown as unknown rather than guessed.

## Guarded operations

Pharos can coordinate changes without becoming a free-form command bus.

### Host update and restart

The current workflow persists:

1. operator intent;
2. target-local review and preflight;
3. the exact review result;
4. attended confirmation;
5. a leased apply/restart phase;
6. fresh system, kernel, service and heartbeat verification;
7. typed failure or recovery evidence.

Review failures can be retried explicitly. Failures after confirmation require
recovery; Pharos does not silently replay a switch or reboot.

### Declarative settings and fleet proposals

The nixcfg integration dispatches fixed GitHub Actions workflows. Pharos has no
Git implementation and cannot merge or deploy a host. A dispatch acceptance
means only that GitHub received the request.

Enable it only after mounting a dedicated runtime credential and reviewing the
target workflow:

```bash
export PHAROS_NIXCFG_DISPATCH_ENABLED=1
export PHAROS_NIXCFG_DISPATCH_TOKEN_FILE=/run/pharos/nixcfg-dispatch-token
export PHAROS_HOST_PREFERENCES_PATH=/manifests/host-preferences.json
```

The current classic-PAT path is a temporary integration boundary. A scoped
GitHub App or Janus-brokered installation token is the intended replacement.

### Hetzner Cloud

Hetzner creation is disabled unless every prerequisite is supplied:

```bash
export PHAROS_HCLOUD_EXECUTE=1
export PHAROS_HCLOUD_API_TOKEN_FILE=/run/pharos/hcloud-token
export PHAROS_HCLOUD_PROJECT_LABEL=personal-lab
# Optional: 60–1800 seconds; defaults to 900 (15 minutes).
export PHAROS_HCLOUD_APPROVAL_TTL_SECS=900
export PHAROS_HCLOUD_SSH_KEY_REF=pharos-bootstrap-key
export PHAROS_HCLOUD_FIREWALL_REF=pharos-bootstrap-firewall
```

`PHAROS_HCLOUD_PROJECT_LABEL` is a safe, non-secret name shown during review;
the API token remains the authority for the actual provider project. Pharos
persists only a domain-separated credential fingerprint alongside the
value-free review, exact prices, and expiry; the raw token is never persisted
or returned. It requires a separate authenticated authorization and enables
**Create** only while that bounded authorization and credential binding are
current. The default authorization window is 15 minutes and cannot be
configured above 30 minutes.

Immediately before creation, Pharos rechecks the current catalog, price,
project server count, SSH key, and firewall. The former direct `apply=true`
path is rejected: paid creation must follow persisted review → authorize →
**Create**. A valid durable provisioning-job sidecar is mandatory, and an
unresolved create attempt reserves the provider project across restarts so a
new review cannot race an uncertain result. The SSH key and firewall must
already exist in the provider project. Each provider operation pins one token
snapshot and disables HTTP redirects. Current Hetzner server responses expose
the location directly; Pharos also accepts the legacy nested datacenter
location when the two facts do not conflict, so uncertain creation can be
reconciled without weakening the exact reviewed-location check. After a
legitimate token rotation,
reconciliation and cleanup can recover only from an exact visible ownership
match; an empty inventory under a different credential is never accepted as
proof that the original server is absent.

netcup, AWS, Google Cloud and Oracle Cloud currently use guided import paths.
Pharos does not claim ordering, billing or free-tier guarantees for them.

## Selected HTTP surface

The full UI and internal JSON routes are implementation interfaces, not a
promised third-party API. The important boundaries are:

| Route | Boundary |
| --- | --- |
| `GET /healthz`, `GET /version` | Public health and build metadata |
| `POST /register` | Strict versioned registration contract plus deployment bootstrap token; issues one per-host token |
| `POST /report` | Strict 64 KiB beacon v5/v4 contract and per-host bearer token |
| `GET /hosts.json`, `GET /declared-hosts.json`, `GET /proof/{host}` | OIDC/access-policy or scoped machine-operator guarded fleet views |
| `POST /host-need-intents` | Stores a typed need and creates only the existing immutable Hetzner plan review; authorization and create remain separate |
| `POST /setup/existing-host/preflight` | Guarded read-only onboarding facts |
| `/host-actions/...` | OIDC/operator guarded workflow requests |
| `/agent/actions/...`, `/agent/retirements/...` | Machine-authenticated fixed leases and value-free results |

## Configuration map

### Server

| Variable | Purpose |
| --- | --- |
| `PHAROS_ADDR` | Listen address, default `127.0.0.1:8080` |
| `PHAROS_PUBLIC_ADDR` | Optional effective public bind used to validate explicit loopback-only open mode behind a local container port mapping |
| `PHAROS_ALLOW_OPEN` | Explicitly allow unauthenticated human routes; valid only for a loopback public address |
| `PHAROS_DB` | JSON host-store path; enables derived persistent sidecars and is required for paid provider actions unless their sidecar is set explicitly |
| `PHAROS_PAIMOS_DELIVERY_CONFIG_FILE` | Optional owner-only reporter intent document; requires `PHAROS_DB` for the derived exact-replay journal and keeps API-key and per-handoff secret values in separate referenced owner-only files |
| `PHAROS_PROVISIONING_JOBS_DB` | Optional explicit provisioning-job sidecar path; required for paid provider actions when `PHAROS_DB` is unset |
| `PHAROS_OIDC_ISSUER` | OIDC discovery issuer |
| `PHAROS_OIDC_CLIENT_ID` | Public OIDC client identifier |
| `PHAROS_OIDC_REDIRECT_URI` | Exact callback URI |
| `PHAROS_ALLOWED_OPERATORS` | Comma/space-separated `operator-ref:<sha256>`, `verified-email-ref:<sha256>`, or `email:<verified-address>` full-fleet identities |
| `PHAROS_ACCESS_POLICY_FILE` | Optional scoped policy using the same strict OIDC authorization identifiers |
| `PHAROS_JANUS_PROJECTION_ROOT` | Capability-named Janus projection root; Pharos resolves `pharos-beacon-token` and `pharos-machine-operator` beneath it |
| `PHAROS_MACHINE_OPERATOR_TOKEN_HASH_DIR` | Migration-compatible direct root for the scoped machine-operator hash-dir v2 (`current` plus immutable `generation-{id}.json` documents using schema `inspr.pharos.machine-operator-token-generation.v2`); cannot be combined with the capability root |
| `PHAROS_REGISTRATION_TOKEN` / `PHAROS_REGISTRATION_TOKEN_FILE` | Bootstrap authorization for local registration; the file form wins and is preferred |
| `PHAROS_REQUIRE_BEACON_TOKEN` | Require a valid machine token on every report |
| `PHAROS_BEACON_TOKEN_MODE` | `local`, `dual` or `janus` |
| `PHAROS_BEACON_TOKEN_HASH_DIR` | Private Janus v2 token-generation root containing `current` and immutable generation files |
| `PHAROS_MANIFEST_PATHS` | Read-only declared-host manifests |
| `PHAROS_HOST_PREFERENCES_PATH` | Read-only declared preference registry |
| `PHAROS_ALERT_WEBHOOK_URL` | Optional HTTP(S) or Telegram alert target; enables durable host-down and backup Stale/Failed incidents, escalation and recovery delivery with redirects disabled |
| `PHAROS_ALERT_DB` | Optional explicit durable incident/outbox path; derived beside `PHAROS_DB` when unset and required when alert delivery is configured |
| `PHAROS_ALERT_CHECK_SECS` | Durable alert sweep interval, minimum 5 seconds |
| `PHAROS_ALERT_WEBHOOK_TIMEOUT_SECS` | Per-request alert delivery timeout, minimum 1 second |

### Beacon

| Variable | Purpose |
| --- | --- |
| `PHAROS_URL` | Validated HTTP(S) base URL of `pharosd`; userinfo, query strings and fragments are rejected |
| `PHAROS_INTERVAL` | Recurring report interval from 10–3600 seconds; unset means report once |
| `PHAROS_HOSTNAME`, `PHAROS_ROLE` | Explicit reported identity |
| `PHAROS_TOKEN` / `PHAROS_TOKEN_FILE` | Per-host bearer credential; the file form wins and is preferred |
| `NIXCFG_DIR` | Read-only checkout used as a Git object source; lock context is accepted only when its digest matches the active generation |
| `PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE` | Strict generation-owned deployment evidence; missing or malformed evidence renders freshness unverified |
| `PHAROS_NIXCFG_REMOTE_URL` | Credential-free HTTPS Git repository used as authoritative nixcfg source |
| `PHAROS_NIXCFG_REMOTE_REF` | Exact `refs/heads/*` authoritative nixcfg branch |
| `PHAROS_NIXPKGS_REMOTE_URL` | Credential-free HTTPS nixpkgs Git repository; the official NixOS/nixpkgs remote uses the bounded official channel publication, while custom remotes use exact fail-closed Git comparison |
| `PHAROS_NIXPKGS_CHANNEL_BASE_URL` | Optional credential-free HTTPS base for bounded `<channel>/git-revision` documents; overrides the automatic official channel base |
| `PHAROS_PREFERENCES_FILE` | Declared or private applied-preferences file |
| `PHAROS_BACKUP_MODE` | `auto`, `off`, `restic`, `status-file` or `command` |
| `PHAROS_LOCATION_MODE` | `off`, `env`, `ip-api` or `command` |

### Read-only CLI

Set `PHAROS_URL` and `PHAROS_OPERATOR_TOKEN_FILE`, then use `pharos hosts`,
`pharos declared status`, `pharos beacon last-seen [HOST]`, `pharos proof HOST`
or `pharos job ID`. `pharos health` and `pharos version` use the intentionally
public service endpoints. The CLI has no write command and never calls
`/agent/*`.

See the committed Compose files and NixOS module for the complete wiring.

The Paimos adapter config uses schema
`inspr.pharos.paimos-delivery-adapter.v1`. It requires a credential-free HTTPS
origin, `poll_interval_secs` from 5–3600,
`verification_freshness_secs` from 30–900, one `api_key_file`, and 1–128 strict
intents. A deployment intent has `stage: "deployment"`,
`workflow: "deploy-production"` and `update_restart_job_id`; a verification
intent has `stage: "verification"`, `workflow: "verify-production"` and
`deployment_handoff_id`. Both carry locally selected `handoff_id`,
`handoff_secret_file`, `host`, `environment`, and an artifact containing a
bounded version, `sha256:` digest and lowercase 40- or 64-hex commit digest.
Unknown fields, unsafe origins, mismatched deployment/verification pairs and
shared credential files reject startup. The bundled contract verifier is
`scripts/check-paimos-delivery-contract.sh`.

The in-process conformance harness injects its loopback URL directly into a
test-only configuration value; the production config parser never accepts
cleartext HTTP.

For both token pairs, a non-empty `_FILE` variable takes precedence over the
direct value. Pharos removes one trailing LF or CRLF from the file and preserves
all other bytes. A configured file that is unreadable, invalid UTF-8, or empty
fails startup; Pharos never falls back to the direct value after a file error.

When alert delivery is enabled, pharosd fails startup unless the incident and
outbox state has a durable path. Delivery is at least once: every event carries
a stable `event_id` and HTTP `Idempotency-Key`, while failed attempts remain in
the outbox with bounded exponential backoff and jitter. `/readyz` fails when the
supervised worker stops or becomes stale; `pharos_alert_*` metrics expose worker
health, restarts, the pending backlog, and delivery outcomes. Backup incidents
are independent per host and observation ID, honor the applied Backup warnings
preference, escalate after the same 15-minute and 60-minute windows as host
incidents, and emit recovery only after the posture returns to Healthy.

## Project status

Pharos is an active early release at **v0.1.72**. It is already used as a real
fleet dashboard and guarded operations layer, but its limits are part of its
interface.

Good fit today:

- a small, self-hosted Linux or NixOS fleet;
- one control-plane instance;
- operators who value explicit evidence over broad automation;
- environments that can provide OIDC, private runtime files and HTTPS;
- gradual adoption, beginning with read-only fleet visibility.

Not provided today:

- multi-node high availability or a transactional SQL store;
- a multi-tenant SaaS control plane;
- arbitrary remote shell or general command execution;
- automatic reconciliation of every declared change;
- broad cloud-provider lifecycle management;
- a replacement for a secret manager, backup engine or infrastructure source
  of truth.

Provider APIs, SSH execution, nixcfg dispatch, alert delivery and target agents
are external dependencies. Their availability and permissions affect the
corresponding workflow. Pharos records that uncertainty instead of treating it
as success.

## Development

Run the same core checks as CI:

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo deny check
```

Additional checks cover the NixOS module, native systemd installer,
`nixos-anywhere` handoff and self-host Compose contract.

The visible version in [`VERSION`](VERSION), the Cargo workspace version and
the latest entry in [`docs/CHANGELOG.md`](docs/CHANGELOG.md) must stay aligned.
`pharosd` exposes the version and build commit at `/version`.

## License

Pharos is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE), expressed as
`AGPL-3.0-only`.

The AGPL protects the availability of source for modified network deployments.
Third-party dependencies and embedded third-party assets retain their own
licenses.
