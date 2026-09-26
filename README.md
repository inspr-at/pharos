# Pharos

**Fleet clarity before fleet control.**

[![CI](https://github.com/inspr-at/pharos/actions/workflows/ci.yml/badge.svg)](https://github.com/inspr-at/pharos/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-260925163010.0.0-d79b2b)](docs/CHANGELOG.md)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-0b8178)](LICENSE)

Pharos is a compact, self-hosted fleet control plane for people and automation.
It turns server onboarding, scattered heartbeats, host declarations, backup
evidence and guarded deployment into one legible operating picture.

It is deliberately not a generic remote shell. Pharos separates what a host
reported, what configuration declares, what an operator requested and what an
executor proved. That separation is the product.

[Product site](https://pharos.inspr.at/) ·
[Deutsch](https://pharos.inspr.at/de/) ·
[Source](https://github.com/inspr-at/pharos) ·
[Changelog](docs/CHANGELOG.md) ·
[INSPR](https://www.inspr.at)

Pharos is part of the open INSPR product family and is authored and published
by [Markus Barta](https://github.com/markus-barta). Augmentoring's professional
services deploy and operate Pharos; Augmentoring is not the product owner.

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

| State         | Meaning                                              | Source                                                      |
| ------------- | ---------------------------------------------------- | ----------------------------------------------------------- |
| **Observed**  | What a host or bounded probe reported                | `pharos-beacon`, server receive time, optional probes       |
| **Declared**  | What should exist                                    | Read-only host manifests and the nixcfg preference registry |
| **Requested** | What an operator asked to change                     | Persisted Pharos workflow state                             |
| **Executed**  | What a bounded agent or provider operation attempted | Leased action result                                        |
| **Verified**  | What fresh evidence confirms after the action        | New heartbeat, kernel, service and backup evidence          |

That model prevents a merged declaration from masquerading as a deployed
system, and prevents a successful API request from masquerading as a completed
operation.

## What ships in v260922141211.0.0

| Area                    | Current capability                                                                                                                                                                                                       |
| ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| **Fleet**               | Grid and list views, search, sorting, and host liveness on the existing shell. The seven navigation entries and lighthouse artwork stay. A host name opens the workspace; Quick preview is separate. One moving heartbeat age line per card and row; detailed history in Quick preview. The percentage is heartbeat delivery, not uptime |
| **Map**                 | Optional host location and reachability signals without turning location into a control channel                                                                                                                          |
| **Backups**             | Independent daily-backup and selective-restore facts. Overdue restore is strictly more than 30 days after the last successful test. Unknown evidence stays unknown. Disabled backup is not an exemption. The server uses the 36-hour daily stale default. No selective-restore producer ships here |
| **Alerts and activity** | Actionable fleet attention, value-free workflow history and optional outbound silent-heartbeat notifications                                                                                                             |
| **Host settings**       | Durable per-host workspace for color, server/workstation kind and alert preferences, with requested, declared and applied state shown separately. Quiet lifecycle copy is “No pending changes”. Fleet heartbeat grace defaults to 15 seconds after cadence                                |
| **Onboarding**          | Existing-host preflight, native beacon or NixOS handoff, first-heartbeat tracking and explicit backup/location decisions                                                                                                 |
| **Providers**           | English/German Hetzner portal guidance with Fish-safe commands and exact destination paths, read-only provider checks, exact paid-plan review, attended authorization, single-use creation and ownership-checked cleanup |
| **Guarded actions**     | Fixed review/apply/restart, fleet-update, host-retirement and managed-service workflows with durable next-action ownership, idempotent handoffs, leases, confirmation and recovery evidence                              |
| **Access**              | OIDC Authorization Code + PKCE for people; scoped machine-operator credentials for read-only clients; independent per-host bearer authentication for beacons                                                             |

The UI is server-rendered HTML with a focused vanilla-JavaScript interaction
layer. There is no separate frontend build or client framework.

The fleet shell is unchanged: seven entries (Fleet, Map, Alerts, Backups,
Services, Activity, Settings) and the lighthouse artwork. A host name opens
that host's workspace at `/hosts/{name}`. **Quick preview** is a separate
control.

The health badge aggregates problem reasons. Daily backup and selective
restore stay independent, so a current daily success remains current when
restore is overdue, and overdue restore still marks overall health. A
successful selective restore is a test that restored at least one file. For
the host, that success is current until it is strictly more than 30 days old. Unknown or
missing evidence stays unknown and is not shown as healthy. A disabled backup
is not an exemption and does not make restore unnecessary. The server's daily
projection uses the existing 36-hour stale default: a recorded success
strictly older than 36 hours is stale, and a success time more than two
seconds in the future is not treated as fresh. Repository checks, snapshot
existence, and similar observations are not a successful selective restore.
No producer of that restore ships with Pharos; NIX-562 tracks it. Since
host-report v7 the validation record keeps the last successful restore
(`last_success_at`) apart from the latest attempt, so a later failed attempt
renders as failed while the success that drives the 30-day clock stays
recorded, and a later stale or unknown attempt keeps the restore out of green, and `restored_files` is the evidence: a restore without at least one
restored file is not observed as a success. One successfully restored file per
host satisfies this check; it does not
require one file from every repository. This posture does not establish
full-system recoverability.

A quiet lifecycle says **No pending changes**. That means no pending work, not
that packages are fresh. A channel-tip difference alone is not a deployable
update.

Fleet heartbeat grace defaults to 15 seconds after the reported cadence. A
host override is optional: omitted or null inherits the fleet value, and zero
is a valid override. **Use fleet default** clears the override in one click
on the draft. Declared, requested, and applied settings stay distinct; the
live clock follows the grace the beacon has applied. Stale and down remain
twice and five times the cadence. Publishing a populated host override is
safe only after every reader of the shared preferences registry has been
upgraded.

Cards and list rows show one moving heartbeat age line. Its marker advances
from the last observed report and resets on a new report; stale snapshots
stop live motion. Reduced-motion preferences disable interpolation and
arrival flashes while the displayed age remains current. Detailed heartbeat
history and timing policy are in Quick preview. The percentage is heartbeat
delivery, not host or service uptime, and partial retention is qualified.

Host cards use consistent typography, spacing and centered health marks.
Quick preview shows health, daily backup and selective restore immediately,
then keeps those facts synchronized while switching hosts or refreshing.
Document freeze and resume events suspend and recover the refresh clock;
physical Chrome window-focus recovery still needs separate live verification.

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

| Crate           | Responsibility                                                                                                                    |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `pharos-core`   | Versioned host, report, liveness, preferences, provisioning and manifest contracts shared by server and agent                     |
| `pharosd`       | Fleet store, OIDC guard, machine APIs, server-rendered dashboard, provider connections and guarded workflows                      |
| `pharos-beacon` | Small per-host reporter for heartbeat, generation-proven Nix freshness, kernel, backup, location and bounded service observations |
| `pharos-cli`    | Read-only `pharos` operator CLI for health/version, hosts, declarations, beacon last-seen, proofs and provisioning jobs           |

The shared Rust contracts matter: server and beacon cannot silently drift onto
different report schemas. The current report contract is
`inspr.pharos.host-report.v7`; the control plane still accepts predecessor
`v6`, `v5` and `v4` reports, and refuses v7 selective-restore history on them. The local onboarding envelope is
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
match exactly. A channel-tip difference alone is not a deployable update.

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
per host. Those samples are a time axis, separate from the current arrival
indicator. The percentage measures heartbeat delivery, not host or service
uptime, and partial retention is qualified. Liveness is stamped by the server
when a report arrives; an agent cannot declare itself recently seen.

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

### Container health

`pharosd` and `pharos-beacon` ship in one image, so the image `HEALTHCHECK`
is role-aware: a container with `PHAROS_URL` set is a beacon and runs
`pharos-beacon healthcheck`; any other container runs `pharosd healthcheck`.
Each verdict prints its reason, visible with
`docker inspect --format '{{json .State.Health}}' <container>`.

| Role            | Healthy means                                                                                                                       | Unhealthy reasons                                                                                                                                                              |
| --------------- | ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `pharosd`       | `GET /readyz` on the loopback side of `PHAROS_ADDR` answered 200                                                                    | `PHAROS_ADDR` unset or not a socket address (the probe never guesses `127.0.0.1:8080`), unreachable, non-200 status                                                            |
| `pharos-beacon` | The beacon can write its report state where it is configured and the last successful report is at most three `PHAROS_INTERVAL`s old | `PHAROS_INTERVAL` unset (one-shot beacon), report state location not writable, report state missing, unreadable or invalid, no successful report yet, clock skew, report stale |

The beacon records its last successful report in
`/tmp/pharos-beacon-health-v1` (`PHAROS_BEACON_HEALTH_FILE` overrides the
path); a read-only container needs a writable tmpfs there. Every probe first
proves it can perform the same atomic write the beacon uses: it creates a
temporary file next to the marker, hard-links the existing marker to a
sibling name and renames the temporary over that link, so immutable flags,
deny-delete ACLs, sticky-directory ownership or a filesystem without hard
links that would refuse replacing the marker refuse the probe too, while the
marker itself is never written or moved. The marker is only ever opened
without following symlinks; a symlink, directory or device at that path is
invalid state and is never followed. Writes and probes take a shared lock
(`.<marker>.lock`, the one artifact that stays), so a probe never recovers or
replaces anything while a refresh is in flight; under it, probe and write
artifacts use fixed sibling names (`.<marker>.tmp`, `.<marker>.probe-tmp`,
`.<marker>.probe-link`) that each run removes first, so a run killed by the
healthcheck timeout leaves at most one file per name, and a write temporary
that cannot be removed makes the probe unhealthy because no refresh could
land. A marker the beacon cannot replace is never trusted, however recent it
reads. The marker also records which beacon process wrote it (pid and kernel
process start time) and is trusted only while that exact process is running:
state left by a previous run never becomes healthy merely because an obstacle
to resetting it clears, a crashed beacon is unhealthy at the next probe, and
only a successful report by the current process restores health (on Linux
the token includes the kernel boot id, which must be the canonical lowercase
UUID the kernel writes; anything else, or an unreadable boot id, is refused). The state is reset at startup under the same lock: the beacon takes
it, notes which file the marker name points at, attempts the reset, and if
that fails unlinks only that exact file (it never writes into an existing
file); if the lock cannot be taken, nothing is touched. Deployments that disabled
the inherited check (`--no-healthcheck`, Compose `healthcheck: disable: true`)
as a workaround can remove that override.

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

The OIDC client is public and uses PKCE, so it has no client secret. Provider
requests require HTTPS, verify certificates and refuse redirects. Login state
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

Read-only people keep the observation surfaces they were granted. Guarded
surfaces name the required **Fleet manager** role, identify the **Pharos
administrator** as the access owner, and offer one GET-only access-request
path. `PHAROS_ACCESS_REQUEST_URL` may send that click to a credential-free
HTTPS help destination (or a local absolute path); when it is unset, Pharos
offers a value-free request users can copy into their normal help channel.
Viewer requests are still rejected by every mutation handler even if browser
markup is bypassed.

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

| `PHAROS_BEACON_TOKEN_MODE` | Accepted token source                                                                                           |
| -------------------------- | --------------------------------------------------------------------------------------------------------------- |
| `local`                    | Hashes persisted by local `/register`                                                                           |
| `dual`                     | Local hashes or the active Janus v2 generation during migration                                                 |
| `janus`                    | The active Janus v2 generation only; strict report auth and disabled local registration are enforced at startup |

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

The optional Paimos delivery-stage adapter reports owner evidence and, after a
durable local accept, creates exactly one guarded `UpdateRestart` review or
attaches an explicitly configured matching job. Adapter-v2 and adapter-v3
intents without `delegated_launch` never confirm, agent-claim or dispatch that
job. Its owner-written local intent file fixes the Paimos
origin, handoff IDs, host, one of the two compiled workflows
(`deploy-production` or `verify-production`), symbolic environment, exact
artifact tuple and optional existing guarded `UpdateRestart` binding. Paimos
supplies none of those authority-bearing selectors, and no Paimos field can
become a command, path, callback, host selector or arbitrary workflow. An
unrelated active job on the same host is not adopted.

When a later Paimos execution follows an adapter-owned review that failed
before confirmation, the adapter creates a new deterministic review linked by
`retry_of`. It does so only when the durable prior operation has the same host,
workflow, environment, artifact and plan and is the immediately
preceding execution. The fresh execution's own predecessor remains independently
bound and may change with its new execution and authority lineage. Foreign
failures, ambiguous history, changed plans and failures after confirmation
remain unavailable; the new review still requires the normal agent review and
human confirmation.

Every external call requires the registered API key and the handoff's separate
32-byte credential from different owner-only, current-user-owned, single-link
files. Before a mutation, Pharos durably stores the exact safe JSON request and
an idempotency key derived from handoff ID, sequence and request digest. The
journal also stores a domain-separated digest of the canonical Paimos origin
and every non-secret owner-intent selector, plus a deterministic operation
identity for the created or attached job, so a crash replay is rejected if the
destination, workflow, environment, host, artifact, authority epoch or guarded
action binding changed. An unchanged intent replays the exact bytes after a
crash or ambiguous response; credential rotation does not change request
identity. The adapter emits only sequence 1 `accepted` followed by sequence 2
`succeeded` or `failed`—never `active` or a heartbeat.

Config v3 may opt one deployment intent into `delegated_launch` with only an
owner-selected `target_ref`; the workflow remains compiled as
`deploy-production`, and host, environment, artifact, paths and credentials
still come from their existing closed local fields. Only that exact intent's
`AwaitingConfirmation` job with a complete ready host-agent plan can submit a
one-shot launch candidate. Pharos separately hashes the complete reviewed plan
and all public pull commitments—including the Paimos plan, predecessor and
context digests that transitively bind the private attempt and plan revision—
then journals exact candidate and consume bytes before sending them. It accepts
only an exact, live, one-launch admission, re-pulls and rechecks the unchanged
job and plan immediately before consume, and persists the immutable consumed
receipt before recording a Pharos-sourced confirmation on that same job.
Consume is the point of no return. A consumed receipt may complete that one
pending transition after a crash; it
never creates or confirms another job and never claims, redispatches or executes
an already queued or terminal job. Pause, revocation, expiry, target drift,
credential rotation or any reflected/unknown response fails closed.

Deployment success requires an operator-confirmed owned `UpdateRestart` to
finish and a newer fresh beacon to report a measured running-container identity
whose immutable image **config ID** matches the locally configured artifact
digest. This collector does not measure OCI index or manifest digests; those
expectations fail closed instead of being coerced. Nix generation evidence and
`flake.lock` digest are not that identity. An operator JSON file is not a
measurement: a digest-bound release envelope may supply the release tuple only
when it names the same config ID the running container actually has, and the
observation time is taken from the measurement clock. Missing, stopped,
replaced, stale, mismatched, predated, wrong-environment or wrong-digest-class
observations fail closed. Verification uses a separate handoff and remains
unreported until Paimos received deployment and a later observation of the same
host, environment, artifact and lineage arrives. Human attended confirmation
remains the default; automatic progression exists only through the explicit
local v3 selection plus a consumed Paimos admission rooted in prior human
review. Live host proof still requires operator-configured container
allowlisting plus a completed guarded apply—this repository does not claim that
proof from fixtures.

### Aeon delivery adapter

`PHAROS_AEON_DELIVERY_CONFIG_FILE` selects an owner-only Aeon delivery
adapter (`inspr.pharos.aeon-delivery-adapter.v1`). It requires `PHAROS_DB`.
The journal is `{PHAROS_DB}.aeon-delivery-journal.json`. The classic Paimos
adapter is unchanged and stays on its own config. If both delivery config
variables are set, pharosd refuses to start: one delivery owner per process.

The document names the HTTPS Aeon origin, a bearer-token file, an optional CA
bundle, the poll and freshness windows, and closed intents. Each intent fixes
the handoff, project node, release node, operation (`deploy` or `verify`),
one compiled workflow (`deploy-production` or `verify-production`), environment,
host, and artifact. A verify intent names a distinct deploy intent with the
same host, environment, and artifact. No Aeon field becomes a command, path,
or host selector.

A deploy intent binds one guarded `UpdateRestart` review and requires
`delegated_launch`, whose `target_ref` is that intent's artifact digest.
A ready review posts `launch_readiness`, checks a one-use
admission — including a binding digest recomputed locally — consumes that
admission, and only then confirms the same job. Deployment evidence follows a
fresh config-class beacon, a failed or cancelled job, or a terminal launch
block while the job is still awaiting confirmation. A failed result uses
one of Aeon's blocker codes (`dependency_pending`, `dependency_failed`,
`reporter_stale`, `external_waiting`, `policy_refused`). The precise Pharos
reason stays in the journal and is not sent as the code: Aeon rejects any
other result field. An expired admission journals `admission_expired` and,
while the handoff is still current, posts a failed result (`policy_refused`
once the admission is consumed, `external_waiting` when a fresh attempt is
still possible) so the handoff closes. After the handoff itself is stale,
that block stays in the journal and no result is posted. Verification evidence
requires `plan_digest` to equal the deploy binding plan digest and
`predecessor_digest` to equal the dependency seal recomputed from the journaled
deploy result. Epochs are per release, stage, and operation. Every mutation
is journaled as exact request bytes before it is sent. After a crash, admit
and consume are replayed with the journaled Idempotency-Key. An exact replay
returns the stored admission or receipt, and a conflicting replay stays
unresolved without changing the host. The bearer token stays in its referenced
file and is not written to the journal. The adapter does nothing until the
config variable is set.

`live_roundtrip_against_aeon` is an ignored test that drives this adapter
against a live HTTPS Aeon origin. It runs only when `PHAROS_AEON_LIVE_ORIGIN`
is set and `PHAROS_AEON_LIVE_ACK=disposable`, reads the bearer token from
`PHAROS_AEON_LIVE_KEY_FILE` with the production reader, and writes a value-free
JSON report to `PHAROS_AEON_LIVE_REPORT`. Before any write it reads the journey
and the handoff, requires `PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY` to equal the
journey `project_key`, refuses `project_key` `PHAROS` and any tenant other than
`inspr`, and refuses a handoff whose `release_node_id` is not
`PHAROS_AEON_LIVE_RELEASE_NODE_ID`. It prints the project key, node key, and
release number first. A response that reflects the bearer token is withheld
from the trace and the report. It does not run in CI.

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

Leaflet 1.9.4, D3 7.9.0, MapLibre GL JS 5.24.0 and its Leaflet binding 0.1.3
are pinned, vendored with their upstream licenses, embedded in `pharosd`, and
served from versioned same-origin asset paths. The MapLibre CSP build uses a
same-origin worker; external JavaScript, blob workers and `unsafe-eval` remain
disallowed. Leaflet retains the map controls, viewport persistence and D3 host
labels; MapLibre renders only the light vector basemap beneath them.

The basemap uses [OpenFreeMap Positron](https://openfreemap.org/quick_start/),
with OpenMapTiles and OpenStreetMap attribution. No account, API key or manual
credential issuance/rotation is needed. Styles, tiles, sprites and glyphs are
fetched from `https://tiles.openfreemap.org` only after the operator activates
the contextual **Load external basemap** control. The one-time choice is not
stored. Before that action, the same-origin Leaflet map, D3 host labels and
location list work without a third-party request. The provider can observe the
browser IP and requested viewport/tile coordinates, but receives no Pharos
credentials, host payload or HTTP referrer. Both the page and the worker restrict
basemap requests to that origin. Tile/provider failures, unavailable WebGL, or
a failed renderer download leave the site list, D3 labels and Leaflet controls
available, with a retry control. OpenFreeMap is an external service without an
SLA; this is not an offline map.

PHAROS-280 chose this source to preserve worldwide street detail without adding
tile storage and refresh operations to every deployment. A self-hosted Protomaps
extract would remove that dependency, but also needs an explicitly bounded
region/detail level, archive distribution and refresh, HTTP range serving,
and local styles/fonts/sprites. A Europe-only archive would leave other fleet
locations without coverage. OSM standard public tiles require a Referer, which
conflicts with Pharos's `no-referrer` policy; Esri's anonymously reachable raster
endpoint was not selected because anonymous access alone does not establish
permission to use it. See the [Protomaps download guidance](https://docs.protomaps.com/basemaps/downloads)
and [OSMF tile policy](https://operations.osmfoundation.org/policies/tiles/).

| Vendored file               | SHA-256                                                            |
| --------------------------- | ------------------------------------------------------------------ |
| `leaflet-1.9.4/leaflet.css` | `337bfca5cabd03b39815b2700febe2b3b7edf55921c59cd49f88ecb328212303` |
| `leaflet-1.9.4/leaflet.js`  | `db49d009c841f5ca34a888c96511ae936fd9f5533e90d8b2c4d57596f4e5641a` |
| `d3-7.9.0/d3.min.js`        | `f2094bbf6141b359722c4fe454eb6c4b0f0e42cc10cc7af921fc158fceb86539` |
| `maplibre-gl-5.24.0/maplibre-gl.css` | `ab1e70d59ec40465bae7e7030da2f3ccf28133fd502e62bd598eefbadfd7a732` |
| `maplibre-gl-5.24.0/maplibre-gl-csp.js` | `a1f1847bac64aa00acbf80fbb79b2c5af24d8eecaaa5e2ad14080fab81f1de95` |
| `maplibre-gl-5.24.0/maplibre-gl-csp-worker.js` | `f950e7b15c49c8b9c7bb52136df2a2df2f6f03b83b8927774573fc98b067f7f0` |
| `maplibre-gl-leaflet-0.1.3/leaflet-maplibre-gl.js` | `1c33367962e7755c1a16d1f85658fdc96b5baa36f81adfca9493174cd1b526ce` |

### Browser privacy and device storage

Pharos does not include analytics, advertising, social plugins, remote fonts,
or cross-site tracking. Application scripts, styles, fonts, images, video and
data requests are same-origin on first paint. There is no page-wide cookie
banner: the only optional external runtime service, OpenFreeMap, is disabled
until the map's contextual load-once action. Adding product analytics later
requires a separate review; self-hosted builds must ship it disabled, without a
persistent identifier, and with any consent component disabled until an optional
integration actually needs it.

Pharos sets these host-only cookies for the requested sign-in service:

| Cookie | Trigger and purpose | Lifetime and scope | Classification |
| --- | --- | --- | --- |
| `__Host-pharos_flow` | Starting OIDC login; binds the callback to the initiating browser and safe local return path | 10 minutes; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` | Strictly necessary authentication/security state |
| `__Host-pharos_session` | Successful OIDC callback; authenticates the browser session | 8 hours; `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, no `Domain` | Strictly necessary authentication state |
| `__Host-pharos_logout_csrf` | Successful OIDC callback; binds the logout POST to the browser session | 8 hours; `Secure`, script-readable, `SameSite=Strict`, `Path=/`, no `Domain` | Strictly necessary CSRF protection |

Older releases wrote `pharos_sort`, `pharos_view`, `pharos_search`,
`pharos_live_filter`, and `pharos_signal_window` cookies for one year. The
current UI expires those legacy cookies and keeps view, sort, status-filter and
signal-window state in the current URL; search text is no longer persisted.

The UI uses no `sessionStorage`. It writes the following first-party
`localStorage` preferences only after the operator changes the corresponding
control. Each record carries its own 180-day expiry and is removed when expired
or malformed: `pharos_freeform_order_v1`, `pharos.sidebar.still.v1`,
`pharos-provider-guide-language`, `pharos.map.viewport.v1`,
`pharos.map.mode.v1`, and `pharos.map.labelDensity.v1`. These records contain
only the requested card order, motion/language choice, or map view; no generated
visitor identifier is stored.

The configured identity provider may set its own session, security or language
cookies on its own origin during the top-level sign-in journey. Their names,
recipients and lifetimes depend on the operator-selected provider and are not
controlled by Pharos; deployments must list those provider-specific operations
in their privacy information. Reverse proxies or other operator-added browser
services require the same deployment inventory. For GDPR purposes the deployer
remains responsible for documenting its lawful basis, recipients, retention and
transfers; the classifications above address Pharos's technical device access,
not a deployment-specific legal certification.

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

The module builds its default package with the consumer's `pkgs`. You can also
set `package = inputs.pharos.packages.${pkgs.stdenv.hostPlatform.system}.pharos-beacon` explicitly.
Both forms support `nix flake check --no-build` without first archiving the
Pharos input or creating the runtime token file. Package evaluation reads release
metadata and `Cargo.lock` from the original source tree; filtering the build
source does not require materialising it to read those files. `src` overrides
remain authoritative: `cleanSource`/`cleanSourceWith` expose their original tree
for metadata reads, while a plain source path supplies both metadata and contents.

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
- Compose services discovered through a fixed, local Docker query. Replica
  failures are warnings, missing healthchecks stay unknown, and probe failure
  is reported separately from service failure;
- optional backup observations from Restic, a status file or a configured
  bounded command;
- optional location from static configuration, a bounded command or an
  operator-enabled IP service;
- bounded service observations and report round-trip timing;
- currently applied host preferences.

Unknown or malformed contract fields fail validation. A missing observation is
shown as unknown rather than guessed.

Service observation deliberately uses discovery, not the declared-host
manifest: the useful signal is what Compose actually has, including stopped
replicas. It groups containers by Compose project and service, ignores one-off
jobs, sorts groups deterministically, and reserves the final available report
slot for an overflow warning. The probe asks Docker only for Compose
project/service/one-off labels, lifecycle state and bounded status. It derives
only the fixed healthy, unhealthy, starting, or no-healthcheck states; raw
status, inspect documents, environment, mounts, ports and probe payloads are
never reported. The local beacon user still needs permission to connect
to the Docker socket;
granting Docker-group access is root-equivalent and therefore remains an
explicit host-operator decision. The collector interface is runtime-specific,
so a future systemd collector can add fixed unit-state discovery without
changing the report contract or creating a general inspection channel.

### Declared HTTP health observations

Hosts without Compose discovery can still expose service health without a
Docker socket. When `PHAROS_HTTP_PROBES_PATH` names a reviewed
`inspr.pharos.http-probes.v1` registry, each entry binds one exact manifest
host and service to a credential-free HTTP(S) URL, expected status, optional
body marker, interval and timeout. Startup rejects unknown hosts or services,
duplicate bindings, unknown fields, credential-bearing URLs and values outside
the documented bounds. The synthetic shape is in
`contracts/http-probes-v1.json`.

Pharos checks every declaration on its own 10–3600 second cadence. Redirects
and retries are disabled, each request has its declared 100–10000 millisecond
deadline, and marker matching reads at most 64 KiB. The response body and
marker are never retained, logged or projected. Status surfaces expose only a
coarse pass, status mismatch, marker mismatch, timeout or transport result;
results older than three declared intervals become stale. Existing manifest
TCP probes remain the fallback for services without a declared HTTP probe.

### Appliance convergence observations

Appliance-tier hosts deliberately run no beacon and hold no Pharos secret.
When `PHAROS_APPLIANCE_PROBES_PATH` names a reviewed registry using
`inspr.pharos.appliance-probes.v1`, `pharosd` makes only two fixed network
checks: one ICMP presence probe and one TCP connection to the declared SSH
port. Targets are used for those calls only and are never returned in the API,
logs, observations or durable debounce state.

Every registry host must already have a Pharos host record and be declared
`kind: workstation` through the existing PHAROS-109 preference contract;
startup rejects missing records or server-kind declarations. Record creation
and real-host acceptance remain owned by OPS-19. Once validated, an ICMP-down
appliance is recorded as `powered off as expected` and creates no heartbeat
alert. ICMP-up with SSH closed remains non-alerting boot grace until the
declared 2–10 consecutive-sample threshold is reached; it then becomes the
distinct warning
`un-converged: online but SSH is unavailable`. SSH recovery resets the durable
counter. Pharos only detects and reports this state—it never tries to enable
SSH, run a bootstrap, install an agent or otherwise remediate the appliance.

If the existing-host strict SSH boundary has both an owner-controlled identity
file and a pinned `known_hosts` file, Pharos also runs one fixed read-only
marker command after SSH becomes reachable. The marker is at the registry's
validated absolute path and contains exactly:

```text
<build-id> <RFC3339 timestamp>
```

The response is limited to 256 ASCII bytes; only a 1–64 byte
`[A-Za-z0-9._-]` build identifier and a valid RFC3339 timestamp are surfaced.
Missing, malformed, oversized or unavailable markers are named coarsely, and
raw SSH output is never logged or stored. The registry contains no credential;
the committed `contracts/appliance-probes-v1.json` is a synthetic shape
fixture. `PHAROS_DB` is required so the debounce counter survives restarts.

## Guarded operations

Pharos can coordinate changes without becoming a free-form command bus.

### Host update and restart

When nothing is pending, the lifecycle chip says **No pending changes**. That
is workflow idle copy, not a statement that Nix packages are current. A
nixpkgs channel tip that differs from the deployed revision does not, by
itself, make an update deployable. An update is deployable when the host is
behind the authoritative nixcfg revision by at least one commit. Declared
preference drift and a kernel that needs a restart stay actionable on their
own.

The current workflow persists a typed `update`, `apply_declared`, or
`restart_only` intent. Existing records without an intent remain `update`;
`restart_only` is reserved and is not offered in the first UI. A declared
preference or kernel drift can start `apply_declared` only for a reporting Nix
host whose manifest requires Janus. It uses the same fresh-backup and attended
confirmation gates as an update, and skips the restart step when the reviewed
plan says no restart is required. One update/restart workflow holds the fleet
lock at a time; other eligible hosts name the blocking host instead of issuing
a request that would be rejected. The target-agent lease deliberately remains
the deployed v1 six-field `PHAROS-126` envelope; intent and `PHAROS-216`
provenance stay in Pharos's durable job, events and summary.

Each workflow persists:

1. operator intent;
2. start and last-evidence times, the next automatic check, and a rounded
   expected range;
3. deterministic overdue and escalation boundaries with an effect-bound,
   same-run idempotency key;
4. target-local review and preflight;
5. the exact review result;
6. attended confirmation;
7. a leased apply/restart phase;
8. fresh system, kernel, service and heartbeat verification;
9. typed failure, recovery, cancellation, or terminal evidence.

Review failures can be retried explicitly. Failures after confirmation require
recovery; Pharos does not silently replay a switch or reboot. Automatic
reconciliation resumes after a Pharos restart, while terminal and withdrawn
runs retain their receipt and expose no next action to poll.

### Declarative settings and fleet proposals

Fleet Settings → **Fleet freshness** stores the default nixpkgs warning
threshold in days (30 initially; whole numbers 1–3650). It is saved atomically
beside `PHAROS_DB` as `<database filename>.fleet-settings.json`, survives
restarts, and applies to the next page or fleet refresh without restarting
pharosd. Ephemeral installations without `PHAROS_DB` cannot save this setting.

In a host's **Alert preferences**, an optional **nixpkgs warning threshold**
uses the existing guarded host-settings request and apply workflow. Empty
means inherit the fleet default. The shared `inspr.pharos.host-preferences.v1`
registry carries it as `hosts.<host>.alerts.nixpkgs_warn_after_days`; it is
omitted when unset. The effective limit is the reported host override, then
the saved fleet default, then 30 days. Requested or declared overrides become
effective after the beacon reports them as applied.

The `nixpkgs differs from <channel>` attention reason, amber card fault and
sort weight require an exact `different` comparison **and** deployed nixpkgs
age **greater than** the effective limit. Age is whole days computed from
generation-owned `nixpkgs_last_modified` on the server clock; equality stays
quiet. Missing generation evidence remains unverified; an unknown age cannot
prove staleness. EOL channels, missing comparisons, nixcfg drift, and alert
suppression retain their separate rules. Detail views can still report the
revision difference neutrally below the limit. Map attention and the
freshness entries in Alerts/Activity use the same threshold. That age warning
stays independent of deployability. `has_proven_deployable_update` is true
only when nixcfg is behind by at least one commit. A channel-tip difference
alone is not a deployable update. The beacon's coarse `nix-freshness`
service observation remains factual and is excluded from service attention
counts because the server's dedicated freshness policy owns that signal.

Fleet Settings stores heartbeat grace beside the nixpkgs threshold: extra
whole seconds after the reported cadence, default 15, range 0 through 3600.
The host field is `alerts.heartbeat_grace_secs` on the same
`inspr.pharos.host-preferences.v1` registry. Omit it, or send null, to
inherit. Zero is serialized when it is the override; sending the fleet number
does not mean inherit. **Use fleet default** clears the override in the draft
in one click and does not itself move the live clock. The clock uses applied
preferences, the value the beacon last reported. The fleet setting has no
inherit: saving 15 is how the fleet default returns to 15. Stale and down
stay at twice and five times the cadence. The nixcfg workflow accepts an
optional `heartbeat_grace_secs` input (NIX-561). Empty or omitted inherits.
Zero is an override only when it is the value sent. A populated host override
is still withheld until every beacon that reads the shared registry has been
upgraded.

Rollout: upgrade pharosd and **every beacon reading the registry before
publishing any override**. Old binaries reject unknown preference fields,
including fields belonging to another host in a shared registry. With the
field omitted, old/new preferences and the existing report versions remain
compatible; populating it before the readers upgrade is not safe. The nixcfg
workflow accepts optional `nixpkgs_warn_after_days` (a string integer 1–3650;
empty or omitted removes that override) and optional `heartbeat_grace_secs`
(NIX-561; empty or omitted removes that override). Pharos omits a field when
inheriting. A populated override still waits until every registry reader
accepts that field. For rollback to
old binaries, first remove overrides from declarations and reports, drain
pending preference requests/workflows, and verify value-free persisted state
contains no new preference field. The fleet settings sidecar itself is ignored
by older pharosd versions.

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

| Route                                                              | Boundary                                                                                                                  |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------- |
| `GET /healthz`, `GET /version`                                     | Public health and build metadata                                                                                          |
| `POST /register`                                                   | Strict versioned registration contract plus deployment bootstrap token; issues one per-host token                         |
| `POST /report`                                                     | Strict 64 KiB beacon v7/v6/v5/v4 contract and per-host bearer token                                                          |
| `GET /hosts.json`, `GET /declared-hosts.json`, `GET /proof/{host}` | OIDC/access-policy or scoped machine-operator guarded fleet views                                                         |
| `POST /host-need-intents`                                          | Stores a typed need and creates only the existing immutable Hetzner plan review; authorization and create remain separate |
| `POST /setup/existing-host/preflight`                              | Guarded read-only onboarding facts                                                                                        |
| `/host-actions/...`                                                | OIDC/operator guarded workflow requests                                                                                   |
| `/agent/actions/...`, `/agent/retirements/...`                     | Machine-authenticated fixed leases and value-free results                                                                 |

## Configuration map

### Flow host

Optional bounded `@inspr/flow-shell` integration is enabled when `PHAROS_FLOW_CONFIG_FILE`
points at a JSON document using schema `inspr.pharos.flow-host-config.v1`. The config
file and the referenced Paimos API key file must both be owner-readable only (`0600`,
matching uid, parent directory `0700`). Each binding maps one Paimos project to Pharos
host names and `operator-ref` values that may use the shell. `paimos_origin` is the
server-side projection URL and may include Paimos's own public base path; the
API key file stays off the browser. Optional `paimos_public_url` is the
browser navigation address when that public URL differs from the server-side
origin (for example a same-origin `/paimos` mount).

Schema `inspr.pharos.flow-host-config.v2` (PHAROS-313) selects the Aeon
successor instead: `upstream` is `aeon`, `aeon_origin` (and optional
`aeon_public_url`) replace the Paimos URLs, `tenant_slug` names the Aeon tenant,
and each binding carries the project's `project_node_id` (UUID) and route
`project_key` instead of a numeric id and opaque ref. The server reads
`GET /api/projects/{project_node_id}/journey` with the scoped key
(`journey.read`), refuses any response whose `project_node_id`, `project_key`
or `tenant_slug` differ from the configuration, refuses a journey whose
revision moved backwards, and projects stage, next action and launch readiness
onto the shell. Browser navigation goes to `/p/{project_key}?view=journey`
(plus `stage=` only when Aeon returned one) and nothing else. A v1 and a v2
document never mix; the classic path is unchanged. The key file is materialized
by the operator (see nixcfg agent secrets); a hand-placed file does not survive
a Home Manager switch.

Optional `PHAROS_PUBLIC_BASE_PATH` (empty default) serves the same binary under
a configured prefix such as `/pharos` without changing cookie names, `__Host-`
flags (`Secure`, `Path=/`, no `Domain`), or per-app operator/project
verification. `PHAROS_PUBLIC_ORIGIN` is scheme+host separately. The edge must
forward the same public path. There is no HTML rewriter, iframe gateway,
shared session, or forwarded-user trust. Register the OIDC callback as origin
plus base path plus `/auth/callback` (origin-root when the base path is empty).

For local harnesses against loopback Paimos, set `PHAROS_FLOW_ALLOW_LOOPBACK_ORIGIN=true`
when **both** `PHAROS_ADDR` and `PHAROS_PUBLIC_ADDR` are loopback. Cleartext HTTP is
rejected by default and does not change the PHAROS-206 delivery adapter's production
HTTPS-only boundary. Store Flow config and API key files under an operator-owned
`0700` directory (for example `/var/lib/pharos/flow-host/`), not under shared
`/run/secrets` parents that are typically root-owned `0755`.

### Server

| Variable                                                       | Purpose                                                                                                                                                                                                                                                |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `PHAROS_ADDR`                                                  | Listen address, default `127.0.0.1:8080`                                                                                                                                                                                                               |
| `PHAROS_PUBLIC_ADDR`                                           | Optional effective public bind used to validate explicit loopback-only open mode behind a local container port mapping                                                                                                                                 |
| `PHAROS_PUBLIC_ORIGIN`                                         | Optional scheme+host of the customer address; never includes a path. When set, `PHAROS_OIDC_REDIRECT_URI` must match this origin                                                                                                                       |
| `PHAROS_PUBLIC_BASE_PATH`                                      | Optional native public mount (`""` standalone root, or `/pharos` / `/ops/pharos` when sharing one customer origin). Canonical ASCII `[A-Za-z0-9_-]+` segments, no trailing slash. Empty default keeps today's root routes. Same binary, runtime config |
| `PHAROS_ALLOW_OPEN`                                            | Explicitly allow unauthenticated human routes; valid only for a loopback public address                                                                                                                                                                |
| `PHAROS_DB`                                                    | JSON host-store path; enables derived persistent sidecars and is required for paid provider actions unless their sidecar is set explicitly                                                                                                             |
| `PHAROS_PAIMOS_DELIVERY_CONFIG_FILE`                           | Optional owner-only reporter intent document; requires `PHAROS_DB` for the derived exact-replay journal and keeps API-key and per-handoff secret values in separate referenced owner-only files                                                        |
| `PHAROS_AEON_DELIVERY_CONFIG_FILE`                             | Optional owner-only Aeon delivery intent document; requires `PHAROS_DB` for its journal. pharosd refuses to start when `PHAROS_PAIMOS_DELIVERY_CONFIG_FILE` is also set                                                                                    |
| `PHAROS_FLOW_CONFIG_FILE`                                      | Optional owner-only Flow host config (`inspr.pharos.flow-host-config.v1`) enabling bounded `@inspr/flow-shell` projection and guarded Review/Start navigation                                                                                          |
| `PHAROS_FLOW_ALLOW_LOOPBACK_ORIGIN`                            | When `true` or `1`, allow cleartext loopback Paimos origins only while **both** `PHAROS_ADDR` and `PHAROS_PUBLIC_ADDR` are loopback; for local harnesses only                                                                                           |
| `PHAROS_PROVISIONING_JOBS_DB`                                  | Optional explicit provisioning-job sidecar path; required for paid provider actions when `PHAROS_DB` is unset                                                                                                                                          |
| `PHAROS_OIDC_ISSUER`                                           | HTTPS OIDC discovery issuer                                                                                                                                                                                                                             |
| `PHAROS_OIDC_CLIENT_ID`                                        | Public OIDC client identifier                                                                                                                                                                                                                          |
| `PHAROS_OIDC_REDIRECT_URI`                                     | Exact callback URI                                                                                                                                                                                                                                     |
| `PHAROS_OIDC_CA_FILE`                                          | Optional owner-selected read-only PEM CA bundle for OIDC discovery/token requests; regular file, one link, up to 256 KiB, certificate blocks only, no group/other write. Absent keeps bundled WebPKI roots. The path must be a protected container mount, and trust remains scoped to this OIDC client. |
| `PHAROS_ALLOWED_OPERATORS`                                     | Comma/space-separated `operator-ref:<sha256>`, `verified-email-ref:<sha256>`, or `email:<verified-address>` full-fleet identities                                                                                                                      |
| `PHAROS_ACCESS_POLICY_FILE`                                    | Optional scoped policy using the same strict OIDC authorization identifiers                                                                                                                                                                            |
| `PHAROS_ACCESS_REQUEST_URL`                                    | Optional credential-free HTTPS help destination or local absolute path for the read-only user's GET-only **Request access** action                                                                                                                     |
| `PHAROS_JANUS_PROJECTION_ROOT`                                 | Capability-named Janus projection root; Pharos resolves `pharos-beacon-token` and `pharos-machine-operator` beneath it                                                                                                                                 |
| `PHAROS_MACHINE_OPERATOR_TOKEN_HASH_DIR`                       | Migration-compatible direct root for the scoped machine-operator hash-dir v2 (`current` plus immutable `generation-{id}.json` documents using schema `inspr.pharos.machine-operator-token-generation.v2`); cannot be combined with the capability root |
| `PHAROS_REGISTRATION_TOKEN` / `PHAROS_REGISTRATION_TOKEN_FILE` | Bootstrap authorization for local registration; the file form wins and is preferred                                                                                                                                                                    |
| `PHAROS_REQUIRE_BEACON_TOKEN`                                  | Require a valid machine token on every report                                                                                                                                                                                                          |
| `PHAROS_BEACON_TOKEN_MODE`                                     | `local`, `dual` or `janus`                                                                                                                                                                                                                             |
| `PHAROS_BEACON_TOKEN_HASH_DIR`                                 | Private Janus v2 token-generation root containing `current` and immutable generation files                                                                                                                                                             |
| `PHAROS_MANIFEST_PATHS`                                        | Read-only declared-host manifests                                                                                                                                                                                                                      |
| `PHAROS_HOST_PREFERENCES_PATH`                                 | Read-only declared preference registry                                                                                                                                                                                                                 |
| `PHAROS_HTTP_PROBES_PATH`                                      | Optional owner-controlled `inspr.pharos.http-probes.v1` registry binding exact manifest services to bounded HTTP(S) health checks                                                                                                                      |
| `PHAROS_APPLIANCE_PROBES_PATH`                                 | Optional owner-controlled `inspr.pharos.appliance-probes.v1` registry for fixed ICMP/SSH convergence observations; requires `PHAROS_DB`                                                                                                                |
| `PHAROS_EXISTING_HOST_KNOWN_HOSTS_FILE`                        | Owner-controlled pinned SSH host-key file used by existing-host and optional appliance marker reads                                                                                                                                                    |
| `PHAROS_EXISTING_HOST_IDENTITY_FILE`                           | Owner-controlled SSH identity path; required with the pinned host-key file before appliance marker reads are attempted                                                                                                                                 |
| `PHAROS_ALERT_WEBHOOK_URL`                                     | Optional HTTP(S) or Telegram alert target; enables durable host-down and backup Stale/Failed incidents, escalation and recovery delivery with redirects disabled                                                                                       |
| `PHAROS_ALERT_DB`                                              | Optional explicit durable incident/outbox path; derived beside `PHAROS_DB` when unset and required when alert delivery is configured                                                                                                                   |
| `PHAROS_ALERT_CHECK_SECS`                                      | Durable alert sweep interval, minimum 5 seconds                                                                                                                                                                                                        |
| `PHAROS_ALERT_WEBHOOK_TIMEOUT_SECS`                            | Per-request alert delivery timeout, minimum 1 second                                                                                                                                                                                                   |

### Beacon

| Variable                                   | Purpose                                                                                                                                                                                  |
| ------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PHAROS_URL`                               | Validated HTTP(S) base URL of `pharosd`; userinfo, query strings and fragments are rejected                                                                                              |
| `PHAROS_INTERVAL`                          | Recurring report interval from 10–3600 seconds; unset means report once                                                                                                                  |
| `PHAROS_HOSTNAME`, `PHAROS_ROLE`           | Explicit reported identity                                                                                                                                                               |
| `PHAROS_TOKEN` / `PHAROS_TOKEN_FILE`       | Per-host bearer credential; the file form wins and is preferred                                                                                                                          |
| `NIXCFG_DIR`                               | Read-only checkout used as a Git object source; lock context is accepted only when its digest matches the active generation                                                              |
| `PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE`      | Strict generation-owned Nix evidence; missing or malformed evidence renders freshness unverified. This is not a released-software digest.                                                 |
| `PHAROS_DEPLOYED_ARTIFACT_CONTAINER`       | Exact locally allowlisted running container name or id for collector `allowlisted-running-container`; missing, stopped, replaced or invalid identifiers omit deployed-artifact evidence |
| `PHAROS_DEPLOYED_ARTIFACT_RELEASE_ENVELOPE_FILE` | Optional regular, non-symlink, non-world-writable envelope bound to the measured OCI config digest; it cannot supply observation time or prove a different running image            |
| `PHAROS_NIXCFG_REMOTE_URL`                 | Credential-free HTTPS Git repository used as authoritative nixcfg source                                                                                                                 |
| `PHAROS_NIXCFG_REMOTE_REF`                 | Exact `refs/heads/*` authoritative nixcfg branch                                                                                                                                         |
| `PHAROS_NIXPKGS_REMOTE_URL`                | Credential-free HTTPS nixpkgs Git repository; the official NixOS/nixpkgs remote uses the bounded official channel publication, while custom remotes use exact fail-closed Git comparison |
| `PHAROS_NIXPKGS_CHANNEL_BASE_URL`          | Optional credential-free HTTPS base for bounded `<channel>/git-revision` documents; overrides the automatic official channel base                                                        |
| `PHAROS_PREFERENCES_FILE`                  | Declared or private applied-preferences file                                                                                                                                             |
| `PHAROS_BACKUP_MODE`                       | `auto`, `off`, `restic`, `status-file` or `command`                                                                                                                                      |
| `PHAROS_SERVICE_OBSERVATION_MODE`          | `auto` (default), `off` or `compose`; auto stays silent when the local Docker socket is absent, while an indicated but inaccessible or failed local probe reports unknown                |
| `PHAROS_SERVICE_OBSERVATION_INTERVAL_SECS` | Compose discovery cadence, 60–3600 seconds (default 300); cached coarse observations are carried on faster heartbeats and failed probes retry after at most 60 seconds                   |
| `PHAROS_DOCKER_SOCKET`                     | Absolute local Docker Unix socket path (default `/var/run/docker.sock`); remote Docker endpoints are never used                                                                          |
| `PHAROS_LOCATION_MODE`                     | `off`, `env`, `ip-api` or `command`                                                                                                                                                      |

### Read-only CLI

Set `PHAROS_URL` and `PHAROS_OPERATOR_TOKEN_FILE`, then use `pharos hosts`,
`pharos declared status`, `pharos beacon last-seen [HOST]`, `pharos proof HOST`
or `pharos job ID`. `pharos health` and `pharos version` use the intentionally
public service endpoints. The CLI has no write command and never calls
`/agent/*`.

See the committed Compose files and NixOS module for the complete wiring.

The Paimos adapter accepts an optional top-level `"paimos_ca_file":"…"` in
both `inspr.pharos.paimos-delivery-adapter.v2` and v3. When absent, the existing
bundled WebPKI roots remain unchanged. When present, the path must identify a
mounted, owner-selected regular file with current-user ownership, no group or
world permissions, one link, at most 256 KiB, and 1–32 PEM `CERTIFICATE`
blocks with no keys or other content. Those roots are added only to this
adapter's client; certificate chain, hostname and time checks remain enabled,
redirects remain disabled, and
requests remain confined to the exact configured HTTPS origin. The v3 schema
additionally permits only the optional deployment field
`"delegated_launch":{"target_ref":"sha256:…"}`; its absence preserves the
attended behavior. The adapter requires a credential-free HTTPS origin,
`poll_interval_secs` from 5–3600,
`verification_freshness_secs` from 30–900, one `api_key_file`, and 1–128 strict
intents. A deployment intent has `stage: "deployment"`,
`workflow: "deploy-production"` and either omits `update_restart_job_id` to
create one deterministic guarded review or sets it to an explicitly selected
matching job; a verification intent has `stage: "verification"`,
`workflow: "verify-production"` and `deployment_handoff_id`. Both carry locally
selected `handoff_id`, `handoff_secret_file`, `host`, `environment`, and a v2
artifact containing explicit `version_scheme` (`legacy`, `inspr-calendar-v1` or
`inspr-calendar-v2`),
a bounded version, release channel and sequence, `sha256:` digest, lowercase
40- or 64-hex commit digest, and release-manifest coordinate plus digest.
Calendar strings are accepted only as calendar dates of their declared scheme
(v1 `yy.mm.dd[.hh.mm.ss]`, v2 UTC `YYMMDDhhmmss.0.0`). Unknown fields, unsafe
origins, mismatched deployment/verification pairs and shared credential files
reject startup. The bundled contract verifier is
`scripts/check-paimos-delivery-contract.sh`. Janus remains a separate v1
dependency fixture and is never the deployment owner. Paimos still owns
CreateHandoff as a producer follow-up; this adapter does not create handoffs.
The bundled launch-admission v1 schema and four fixtures are pinned byte-exact
to Paimos's protected release merge
`b3e4634af72fa2d1fec51b3d8ca8b7ced2e95270`, whose tree matches approved
release source `f3592475`, for release `v260911172741.0.0`. That immutable tag
is published and admitted at OCI index digest
`sha256:3143fe79fb72ba1f1ef8fef4380e2ca5285ee011058d6f4f3e9e3da10e9d2155`,
with verified signature, SBOM attestations and provenance. This exact supply-chain
pin does not by itself claim that the artifact has been deployed or observed at
runtime.

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

Pharos is an active early release at **v260922141211.0.0**. It is already used as a real
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
  of truth;
- a selective file-restore producer (NIX-562 tracks that work);
- a per-repository restore requirement, or full-system recoverability from
  backup posture.

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

`python3 scripts/check-nix-consumer.py` evaluates external consumers for both
Linux architectures, with the default and exported beacon packages. Each case
uses an empty Nix store and fetcher cache, a source file deliberately removed by
filtering, and a nonexistent runtime token path. It asserts that the filtered
source paths stay absent, then evaluates NixOS configurations without building
them. CI also builds and tests the beacon on aarch64-darwin.

Browser QA runs with `npm run test:browser`. Playwright keeps transient traces,
failure screenshots and videos under `test-results/`, while reviewed visual
baselines live under `tests/browser/__screenshots__/`. Use the harness output
paths for ad-hoc evidence and synthetic fixture data only. Cargo's ignored
`target/` directory is disposable build cache: never park tests or fleet
captures there, and never commit captured infrastructure data as a fixture.

Flow host integration QA runs with `npm run test:flow-host`. That command builds
`pharosd`, starts the OIDC and Paimos loopback harness, and exercises the
shipped bootstrap boundary in Chromium.

[`RELEASE.json`](RELEASE.json) is the single authoritative release coordinate.
It records the canonical INSPR Calendar Version v2 coordinate (the UTC
reservation second as `YYMMDDhhmmss.0.0`, itself valid SemVer), the
stable-channel sequence, the two-step migration anchor (legacy → calendar v1 →
calendar v2), the exact legacy rollback authority and the Cargo SemVer mapping,
which is the identity for v2 coordinates. The
consistency gate keeps Cargo, Nix, the changelog and release workflow aligned.
The release-history dialog omits the changelog's Unreleased section, including
any pending notes. Release rows show a muted relative age, calculated from the
recorded UTC release date, with the exact date available on hover. This also
applies to legacy versions; historical changelog dates remain unchanged. The
aligned metadata row includes a release-details download with a hint describing
the JSON artifact versions and checksums.

Development commits may descend from the current annotated release tag while
preserving its release metadata. Publication still requires that exact tag at
HEAD; changing a published coordinate requires a new release reservation.
Each release first validates an untagged digest-only OCI candidate, then signs
an exact release-set containing both immutable image coordinates and the real
OCI signature, provenance and SBOM digests before admitting final tags. Its
source-lock digest hashes, in order, the exact bytes of `Cargo.lock`,
`devenv.lock`, `flake.lock`, and `package-lock.json` under the domain
`inspr.pharos.source-lock-set.v1`.
`pharosd` exposes both the canonical identity and compatibility mapping at
`/version`.

The sidebar and release history render calendar v2 coordinates through the
build-time-only INSPR Calendar display bundle in
`crates/pharosd/assets/vendor/calendar-version-display`. The bundle is pinned
to source `317f872bc061576fc0b45d274d3a22f69bcd4c8a`; its manifest, configuration,
scheme labels, renderer, interaction helper, AutoAnimate library and license are verified
offline by `scripts/check-calendar-version-display.sh` and again by the Rust
build. The server-rendered canonical coordinate remains visible if JavaScript
is unavailable, and `/version` remains the machine interface.
The release-history scheme label comes from the bundle's `schemes.json`
(`INSPR-VER2` for `inspr-calendar-v2`). Unknown schemes fail the build; machine
scheme identifiers remain unchanged.

### Live UI harness

The family runner, `node scripts/family-live-ui.mjs APP`, reuses the same
request, redirect, Chromium target, screenshot, password and TOTP guards. `APP`
is one of `aithema`, `paimos`, `pharos`, or `janus`; each run stays on that app's
fixed `https://flow.inspr.at/APP/` mount and the real `auth.inspr.at` login.
A successful OIDC callback and the app's signed-in shell are both required.
Every application mutation is blocked, including server-side drafts. Pharos
requires the approved Fleet manager grant; its runner permits inspection only.
Janus requires JANUS-476's exclusive `flow_viewer` role and an exact sandbox
binding, with no core viewer, auditor or operator role. It captures the dedicated
Flow landing page, shell state and static assets. Its unique restricted-page
marker is required before screenshots; an ordinary vault dashboard is refused.
The server role denies catalog, posture, audit, setup and secret-use routes;
the harness additionally blocks requests to those routes.

From a clean checkout, run `npm ci --ignore-scripts` and install Chromium with
`npx playwright install chromium`. The dedicated identity must already have its
reviewed per-app access and enrolled authenticator. Keep its source file at
`~/.inspr/secrets/agents/INSPR-UXQA.env`, owned by the current user with mode
`0600`, containing `INSPR_UXQA_USERNAME`, `INSPR_UXQA_PASSWORD`, and
`INSPR_UXQA_TOTP_SECRET`. Provision it privately; never paste its contents or
values into command arguments. Run in a shell with tracing disabled:

```sh
bash -c '( set -a; source "$HOME/.inspr/secrets/agents/INSPR-UXQA.env"; node scripts/family-live-ui.mjs paimos; result=$?; set +a; exit "$result" )'
```

The runner captures those three values, removes them from the child-process
environment before starting Chromium, and retains no browser session on disk.
Protected-file input is also supported through `INSPR_UXQA_USERNAME_FILE`,
`INSPR_UXQA_PASSWORD_FILE`, and `INSPR_UXQA_TOTP_SECRET_FILE`; do not mix modes.
No client secret, bearer shortcut, dev login, or per-run human OTP is used.
The unchanged Pharos-only runner below continues to accept its own file inputs.

Evidence is created in a new private directory at
`~/.inspr/runtime/inspr-uxqa/APP/UTC-STAMP/`: `evidence.json` uses
`inspr.uxqa.live-ui-evidence.v1`, with named routes, classification, status,
viewport and screenshot filenames. Observed password and TOTP submission are
recorded independently; an OIDC callback never implies MFA was submitted.
Both desktop `1440×1000` and mobile-size `390×844` landing captures are required
for success. These are Chromium viewports, not mobile-device emulation. Pharos also captures its
list view. Optional non-sensitive `INSPR_UXQA_PROJECT_REF` adds the already
provisioned sandbox route (`project:ID` for Aithema, numeric ID for Paimos);
it grants no server access. Set this per command for Aithema/Paimos only, never
in the shared credential file; omit it for Janus and Pharos.
A failed login, denied role, missing shell, or refused screenshot exits nonzero
and is recorded as a blocker, never a health-check success. Screenshots and
evidence are owner-only; symlinked paths and nonempty output directories are
refused. Do not enable debugging, traces, HAR/video, proxying, or storage-state
exports. Run `node --test tests/family-live-ui.test.mjs` for the policy tests and
`node tests/family-live-ui-browser-proof.mjs` for the synthetic Chromium
viewport/screenshot proof. The identity's allowed projects, rotation date, and manual canonical
credential-store instructions belong in its INSPR Knowledge runbook.

`node scripts/live-ui.mjs inventory` and `node scripts/live-ui.mjs draft` are
the only commands. Arguments are those two words. The runner opens one
headless Chromium context against the personal Pharos UI and signs in through
the normal OIDC Authorization Code + PKCE redirect at `GET /pharos/auth/login`.
It does not add a login bypass. The signed-in account's server role stays
Fleet manager. Blocking a request here is a runner restriction, not server
RBAC.

Approved application origins are `https://pharos.barta.cm` and
`https://flow.inspr.at`, and only under `/pharos`. Paths for other
applications on `https://flow.inspr.at` are denied. The only login-provider
origin is `https://auth.inspr.at`. Every other origin is denied, including
`https://pharos.agm.ng`. HTTP and IP hosts are denied. Origins and the base
path are fixed; environment overrides are refused. Credentials are typed only
on the login-provider origin.

The primary-frame route denies the initial load of a popup or an iframe.
Separately, the main page checks each redirect hop at request stage before
that hop is sent, including a hop that keeps POST. A flat loopback debugger
session closes every additional page, worker, and shared worker before that
runtime executes. Pausing a runtime is not a network guard: an ordinary
permitted worker-script GET can still reach the server. If the raw debugger
or the main-page request guard is lost, the runner closes the contexts and
the browser through a separate browser connection and keeps the guards and
secrets until that browser has closed. An authentication challenge is
cancelled and is not answered with a username or password.

Application methods other than `GET` and `HEAD` are denied, including
settings apply, host actions, restart, remove, provider purchase and cleanup,
logout, and server-side drafts. `POST /agora/requests/host-preferences.json`
persists a settings workflow, so it is not a client draft. The server
mutation allowlist is empty. Machine routes such as `/report`, `/register`,
`/agent`, and `/metrics` are denied. External map tiles stay unloaded.
`draft` fills ordinary page fields and does not send an application mutation.
A host settings draft may name `/pharos/hosts/{name}?section=settings`. That fill
is still DOM-only. Its screenshot is `host-NN-settings-draft.png`, separate
from the inventory shot, and the confirm sheet is counted rather than accepted.
Host workspace pages come from `/hosts.json`, workspace links, and fleet
`data-host` attributes. A declared-only configuration record is not turned
into a workspace URL. A linked or observed host that the server denies stays
a denied route, as does a denied application page.

After an authenticated inventory, one Fleet manager session also runs
`scripts/live-ui-inspect.mjs` on the same guarded page. It keeps `?view=list`
and host `?section=backups`, `?section=activity`, and `?section=settings`, and
it screenshots those through the existing guarded shot. For one representative
host it opens Exact times, Quick preview, and the Actions menu, then closes
each without activating Review, Confirm, Save, or a menu item. A host grace
edit and Use fleet default stay in the page; a reload checks that the saved
value did not change. Fleet freshness is scrolled into view and not saved.
Missing controls on an older release are `not-supported`. Channel-only update
review stays `unobservable` from this one host. Focus evidence dispatches
synthetic blur and focus while the document stays visible, waits one fleet
poll, and records `productionWindowSwitchReproduced` as false. It is not a
physical Chrome window switch. Denied map tiles are a harness limit. Fleet
search text in `q` is not stored. A viewer session records `not-manager` and
does not click. Evidence is `clientInspection` inside the existing
`evidence.json`. This repository does not launch that browser from the unit
test.

On the login provider, `GET` and `HEAD` stay on the existing read prefixes
and still deny console, management, admin, system, and debug paths. `POST`
is allowed only for the exact paths `/ui/login/loginname` and
`/ui/login/password`. Reset, init, revoke, token, enrollment, registration,
recovery, and new-password posts are denied, including
`/ui/login/password/reset`, `/ui/login/password/init`, `/oauth/v2/revoke`,
`/oauth/v2/token`, `/ui/v2/login/password`, and `POST /v2/sessions`. A body
field that asks for one of those actions is denied even on an exact login
path. A visible reset, new-password, recovery, enrollment, or registration
submit is not filled. A forgot-password link beside a current-password form
is not that form. An optional passkey or security-key link is not
`mfa-required`. A visible one-time-code field or a passwordless WebAuthn
challenge stops as `mfa-required`. Without the optional TOTP seed file
below, it is not submitted.

The issuer's MFA enrollment prompt is account setup, not a verification
challenge. It is recognized from visible provider choices
(`input[type=radio][name=provider]`) with a submit control, and only when
the page has no password, one-time-code, or WebAuthn challenge field. A
submit control named `skip` with value `true` marks that prompt optional;
the class is the same when that control is absent. The runner does not
choose a provider, click Skip, or submit the prompt. It returns before
inventory with class `account-setup-required` (exit 5), types no credential
into the prompt, and takes no screenshot. Finish that enrollment in a
private browser session before this inspection. Copy that merely mentions
multi-factor authentication, without those provider controls, stays
`mfa-required`. The request allowlist is unchanged.

By default a TOTP prompt also stops as `mfa-required`. The runner does not
ask for a code and does not read a password manager. One-time enrollment of
the dedicated account is done separately. After that, later headless logins
can be unattended.

`PHAROS_LIVE_UI_TOTP_SECRET_FILE` is an optional absolute path to one Base32
TOTP seed. It uses the same ownership rules as the password file. The value
is a path. A raw seed, a current code, or an `otpauth` URI in the
environment or the arguments is refused. The seed stays in the Node process.
It is not typed into the page and it is not sent on the network. When the
current top-level document on `https://auth.inspr.at` is the TOTP form that
posts to `/ui/login/mfa/verify` with `mfaType` `0`, the runner generates one
six-digit code in memory (SHA-1, 30-second step) and submits it once. If
that code is about to expire, the runner waits at most five seconds and
generates the next code instead. It then clears the field. A wrong code, a
second submit, a different MFA form, or a lost guard stops the run. There
is no retry and no per-run interaction. SMS and email verification
(`/ui/login/mfa/otp/verify`), provider switching, enrollment, reset, and
recovery stay denied. The unconditional login posts remain
`/ui/login/loginname` and `/ui/login/password`. The seed file does not
change saved credentials, enrollment, or the server role.

Screenshots stay refused for a code or MFA form.

After repeated safe percent-decoding, any substring of the username or
password denies the request, including a short secret inside a larger path
segment. Verdicts, navigation errors, and evidence use `path-category` or
`[redacted]`. Evidence records method, path, and reason, and omits the raw
URL, query, userinfo, fragment, and post body. Screenshots are taken only
after classification `authenticated`, and never for a credential form, the
login provider, or an `/auth/` path. Before the shot, the runner scans the
full visible text, title, and input values for the whole password, including
punctuation. A hidden input that contains the password refuses the shot. The
label word Password does not. Username text is not treated as the password.

The context is memory-only: headless Chromium, no persistent profile, no
saved session, no trace, and no video. Username and password come from
owner-only files outside this repository. Do not put those values in
arguments, the environment, URLs, screenshots, traces, or stored sessions.

| Name | Contract |
| --- | --- |
| `PHAROS_LIVE_UI_USERNAME_FILE` | Absolute path to one login name. Mode `0600`, parent directory mode `0700`, no symlink, outside this repository |
| `PHAROS_LIVE_UI_PASSWORD_FILE` | Absolute path to one password, same ownership rules |
| `PHAROS_LIVE_UI_TOTP_SECRET_FILE` | Optional absolute path to one Base32 TOTP seed, same ownership rules. Unattended MFA. Never put the seed or a code in this variable |
| `PHAROS_LIVE_UI_OUTPUT_DIR` | Absolute directory, mode `0700`, outside this repository. Receives `evidence.json` (`inspr.pharos.live-ui-evidence.v1`) and authenticated screenshots |
| `PHAROS_LIVE_UI_DRAFT_FILE` | Required for `draft`. Same ownership rules. JSON `{"path":"/pharos/...","fields":[{"selector":"...","value":"..."}]}` |

`PHAROS_LIVE_UI_USERNAME`, `PHAROS_LIVE_UI_PASSWORD`, a raw TOTP seed or code,
an `otpauth` URI, origin, issuer,
base-path, and URL overrides, `DEBUG`, `PWDEBUG`, proxy variables, and
`NODE_TLS_REJECT_UNAUTHORIZED=0` are refused. Classes are `authenticated`
(exit 0), `broken-ui` or `refused` (exit 1), `auth-required` (exit 2),
`mfa-required` (exit 3), `policy-denied` (exit 4), and
`account-setup-required` (exit 5). Stdout also reports
`server-role=unchanged`.

`node --test tests/live-ui-guard.test.mjs`,
`node --test tests/live-ui-totp.test.mjs`, and
`node --test tests/live-ui-inspect.test.mjs` cover the guard and the
inspection planner. The CI check job runs them beside
`tests/fleet-refresh.test.mjs`, on the same Node runtime and without
Playwright. It is not part of `npm run test:browser`. The operator
supplies the account and the files above when the session runs. This
repository does not store them.

Login v2 session posts, including `POST /ui/v2/login/password` and
`POST /v2/sessions`, stay denied. A browser `POST /oauth/v2/token` stays
denied; Pharos exchanges the authorization code on the server. If the live
issuer needs one of those posts, the run fails closed. A password that is a
substring of an ordinary path or of the username label fails closed. Hosts
that the page does not name are not visited.

## Contributing

### Developer Certificate of Origin

New contributions use the unmodified [Developer Certificate of Origin 1.1](DCO).
A `Signed-off-by: Name <email>` trailer records that you have the right to submit
the contribution under the project licence. It is not a cryptographic signature
or a guarantee of correctness. Use the same identity as the commit author;
a GitHub-associated noreply address is fine. Sign-offs remain in public history.
This applies to maintainers and outside contributors alike, from adoption onward;
existing history is not rewritten. After reading the DCO, create each new commit
with `git commit -s` using your own name and GitHub-associated email.

Fork the repository, create a branch from the current upstream `main`, implement
and test your change, then push to your fork and open a pull request to `main`.
Describe the change, its purpose, tests, and any limitations. Contributors need
no write access to this repository. The maintainer reviews agent findings and
decides whether to merge; passing checks never grants an agent merge authority.

The required `dco` check validates every commit introduced by a PR, including
merge commits on the contributor branch. An empty or incomplete range fails.
Local checks require Python 3 and full Git history; deepen a shallow checkout
with `git fetch --unshallow` first. When merging upstream updates into your
branch, use `git merge --signoff upstream/main` after fetching upstream.
It reads real Git trailers, so a sign-off quoted in prose does not count.
Missing sign-offs must be supplied by the contributor, not invented by a reviewer
or agent. Do not rewrite shared history to repair them without explicit agreement.

Bots are not exempt. Dependabot's native `Signed-off-by` service address is
accepted for its exact GitHub author identity; other bots use their own matching
author/sign-off identity. This checks declarations, not account authenticity.
For agent-assisted work, the human contributor must understand and authorize
their DCO declaration; the agent must not invent identities or sign for others.

GitHub web commits require sign-off. For squash merges, retain the original
commit messages and move their existing sign-off declarations into the final
trailer block; an indented or quoted sign-off is not a trailer. Check that the
final author still has a matching declaration. Never invent a contributor's
sign-off. Use a regular merge when combining authors would obscure provenance.
Release and deployment remain maintainer-controlled. Existing review and CI
requirements still apply; DCO introduces no second-maintainer requirement.

## License

Copyright © 2026 [Markus Barta](https://github.com/markus-barta).

Pharos is licensed under the
[GNU Affero General Public License v3.0 only](LICENSE), expressed as
`AGPL-3.0-only`.

The AGPL protects the availability of source for modified network deployments.
Third-party dependencies and embedded third-party assets retain their own
licenses.
