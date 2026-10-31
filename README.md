# Pharos

**Which hosts are patched, which are not, and what is due.**

[![CI](https://github.com/inspr-at/pharos/actions/workflows/ci.yml/badge.svg)](https://github.com/inspr-at/pharos/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-261022144327.0.0-d79b2b)](docs/CHANGELOG.md)
[![License](https://img.shields.io/badge/license-AGPL--3.0--only-0b8178)](LICENSE)

Pharos is a small, self-hosted, read-only fleet view. Beacons report what each
host runs; Pharos shows it behind login. Pharos reports state and never changes
a host: configuration management does the work, and Pharos confirms when it is
done.

[Product site](https://pharos.inspr.at/) ·
[Deutsch](https://pharos.inspr.at/de/) ·
[Source](https://github.com/inspr-at/pharos) ·
[Changelog](docs/CHANGELOG.md) ·
[INSPR](https://www.inspr.at)

Pharos is part of the open INSPR product family and is authored and published
by [Markus Barta](https://github.com/markus-barta). Augmentoring's professional
services deploy and operate Pharos; Augmentoring is not the product owner.

Pharos 2 is being built on this branch line. The last release of the earlier,
larger product is tag `v261022144327.0.0`, which stays the reference and the
rollback for everything removed here.

## Workspace

| Crate           | Purpose                                                       |
| --------------- | ------------------------------------------------------------- |
| `pharosd`       | Server: beacon ingestion, login, the Fleet page and its data  |
| `pharos-beacon` | Host agent that collects bounded facts and reports them       |
| `pharos-cli`    | Read-only command line client                                 |
| `pharos-core`   | Shared report, registration and manifest contracts            |

State is one JSON store at `PHAROS_DB`, written atomically. Without it, pharosd
runs in memory.

## Quick start

```bash
docker compose up --build
```

Then open <http://127.0.0.1:8080>. Health is at `/healthz` and build metadata
at `/version`. This Compose file binds to loopback, keeps data in a Docker
volume and leaves login off, so it is a smoke environment only.
`docker-compose.selfhost.yml` is the production template.

For native development, use the `devenv` environment and switch registration on
with a token file:

```bash
devenv shell
umask 077
printf 'local-dev-only\n' >"$TMPDIR/pharos-registration-token"
PHAROS_ALLOW_OPEN=true \
PHAROS_ALLOW_LOCAL_REGISTER=true \
PHAROS_REGISTRATION_TOKEN_FILE="$TMPDIR/pharos-registration-token" \
cargo run -p pharosd
```

In another shell, register the host and send one report:

```bash
token=$(curl -sS -H 'Authorization: Bearer local-dev-only' \
  -H 'Content-Type: application/json' \
  -d '{"schema":"inspr.pharos.host-registration.v1","version":1,"name":"local-dev","role":"development","is_nix":false,"heartbeat_interval_secs":60}' \
  http://127.0.0.1:8080/register | jq -r .token)
PHAROS_URL=http://127.0.0.1:8080 \
PHAROS_TOKEN="$token" \
PHAROS_HOSTNAME=local-dev \
PHAROS_ROLE="Development host" \
cargo run -p pharos-beacon
```

Set `PHAROS_INTERVAL=60` to keep the beacon running (valid range: 10–3600
seconds). Without it, the beacon reports once and exits.

## HTTP surface

| Route                                     | Access       | Purpose                                 |
| ----------------------------------------- | ------------ | --------------------------------------- |
| `GET /`                                   | Login        | Fleet page                              |
| `GET /hosts.json`                         | Login        | Fleet data, filtered by access grant    |
| `POST /report`                            | Beacon token | Beacon report                           |
| `POST /register`                          | Bootstrap    | Off by default; issue or rotate a token |
| `GET /healthz`, `/readyz`, `/version`     | Public       | Health and build metadata               |
| `/auth/*`                                 | Public       | OIDC login, recovery and logout         |

With `PHAROS_PUBLIC_BASE_PATH`, browser routes live under that prefix. Machine
routes answer both there and at the origin root.

## Configuration

| Variable                                                       | Purpose                                                                         |
| -------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| `PHAROS_ADDR`                                                  | Listen address, default `127.0.0.1:8080`                                        |
| `PHAROS_PUBLIC_ADDR`                                           | Effective public bind, used to validate loopback-only open mode                 |
| `PHAROS_PUBLIC_ORIGIN`                                         | Scheme and host of the public address; `PHAROS_OIDC_REDIRECT_URI` must match it |
| `PHAROS_PUBLIC_BASE_PATH`                                      | Optional public mount such as `/pharos`                                         |
| `PHAROS_DB`                                                    | JSON host store path                                                            |
| `PHAROS_FLEET_DATA_FILE`                                       | Fleet data file, re-read on change and never written. Mount its directory read-only, because a single-file bind keeps the old file across an atomic rename |
| `PHAROS_ALLOW_OPEN`                                            | Allow human routes without login; valid only on a loopback public address       |
| `PHAROS_OIDC_ISSUER`, `_CLIENT_ID`, `_REDIRECT_URI`            | OIDC login, all or none                                                         |
| `PHAROS_OIDC_CA_FILE`                                          | Optional read-only PEM CA bundle for OIDC requests                              |
| `PHAROS_ALLOWED_OPERATORS`                                     | `operator-ref:<sha256>`, `verified-email-ref:<sha256>` or `email:<address>`     |
| `PHAROS_ACCESS_POLICY_FILE`                                    | Optional per-identifier host scopes                                             |
| `PHAROS_ALLOW_LOCAL_REGISTER`                                  | `true` switches on `POST /register`, otherwise it answers 410; needs the file   |
| `PHAROS_REGISTRATION_TOKEN_FILE`                               | Bootstrap token for `POST /register`; read only when registration is on         |
| `PHAROS_REQUIRE_BEACON_TOKEN`                                  | Optional; tokens are always required, and `false` refuses startup               |
| `PHAROS_BEACON_TOKEN_MODE`                                     | Optional; only `local` is valid, and anything else refuses startup              |
| `PHAROS_MANIFEST_PATHS`                                        | Read-only declared-host manifests                                               |
| `PHAROS_HTTP_PROBES_PATH`                                      | Optional `inspr.pharos.http-probes.v1` registry                                 |
| `PHAROS_HOST_PROBES_PATH`                                      | Optional `inspr.pharos.host-probes.v1` registry; requires `PHAROS_DB`           |

Startup fails closed: partial OIDC settings or open mode on a non-loopback
address stop the server.

## Trust model

- Human and machine routes are separate. A bearer credential is refused on
  human routes and never falls back to a cookie or open mode.
- Every report needs a beacon token. Tokens are stored only as SHA-256 hashes and
  compared in constant time. A wrong token, no token or an unknown host gets 401.
- Registration is off by default. The store is the only copy of the hashes, so
  back it up. [RUNBOOK.md](RUNBOOK.md) covers adding a host, rotating a token and
  recovering a lost store.
- `/hosts.json` is built from named fields, so the stored hash cannot reach it.
- Pharos never stores or returns raw tokens, private keys, secret contents or
  credential-bearing URLs.
- HTML responses carry a per-response nonce CSP. Assets are local; the page
  contacts no third party.

## Beacons

The flake exports `nixosModules.pharos-beacon`:

```nix
{
  imports = [ inputs.pharos.nixosModules.pharos-beacon ];

  services.pharos-beacon = {
    enable = true;
    url = "https://pharos.example";
    tokenFile = "/run/secrets/pharos-beacon-token";
    nixcfgDir = "/etc/nixos";
  };
}
```

The module loads `tokenFile` through a systemd credential, runs the beacon as
an unprivileged service and hardens its filesystem view. For a non-Nix Linux
host, use `scripts/install-pharos-beacon-systemd.sh`. It expects the token
to exist already and never generates or prints credentials.

Collectors are explicit and bounded: host identity, Nix `flake.lock` age and
commits behind, running versus current kernel, Compose service state, optional
backup observations and report round-trip timing. Unknown fields fail
validation, and a missing observation stays unknown.

## Beaconless probes

Hosts without a beacon can still report reachability. `PHAROS_HTTP_PROBES_PATH`
binds a manifest service to a credential-free URL with an expected status and
optional body marker; `contracts/http-probes-v1.json` shows the shape.
`PHAROS_HOST_PROBES_PATH` runs one ICMP check and one TCP connection per host, with
no credential; `contracts/host-probes-v1.json` shows the shape. The last time a host
answered is kept in `<PHAROS_DB>.host-probes.json` and survives a restart. A
configured registry that is missing, invalid, a symlink, or writable by group or
others refuses startup. Probes return reachability and coarse results, never
response bodies, and targets are never returned in the API. Ping needs no capability
in the image: on a bridge network Docker allows it, and on a host network the host's
`net.ipv4.ping_group_range` decides. A check that cannot run says nothing about the
host.

## Development

```bash
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all --locked
cargo deny check
npm ci --ignore-scripts && npm run test:browser
scripts/check-release-consistency.sh
```

`npm run test:browser` builds `pharosd` and runs it on a free loopback port with
a throwaway store. Use synthetic fixture data only, and never commit captured
infrastructure data.

[`RELEASE.json`](RELEASE.json) is the single authoritative release coordinate;
the consistency gate keeps Cargo, Nix, the changelog and the release workflow
aligned. Publication requires an exact annotated tag at HEAD. The version label
renders through the build-time INSPR Calendar display bundle in
`crates/pharosd/assets/vendor/calendar-version-display`, verified offline by
`scripts/check-calendar-version-display.sh` and by the Rust build.

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
