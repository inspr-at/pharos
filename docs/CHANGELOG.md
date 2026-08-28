# Pharos Changelog

## Unreleased

- Fail closed on beacon container health when the report marker cannot be replaced: `pharos-beacon healthcheck` proves the beacon's atomic temp+rename write is possible (directory writable and the existing marker replaceable despite immutable flags, ACLs or sticky ownership, probed through a hard link so the marker is never touched, with fixed-name artifacts that every run recovers) before trusting a recent marker, names the path and reason otherwise, never follows a symlink at the marker path, a failed startup reset only unlinks the previous marker, never writing into it, writes and probes share a marker lock so a blocked write temporary is detected instead of raced, and the marker names the beacon process that wrote it so state from a previous run is never healthy again once its obstacle clears (PHAROS-203).

## 0.1.90 - 2026-08-28

- Make container health diagnosable and truthful for both image roles: `pharosd healthcheck` refuses to guess the bind address when `PHAROS_ADDR` is unset and reports the failing target or HTTP status, `pharos-beacon healthcheck` states why the beacon is unhealthy (one-shot mode, missing or invalid report state, no successful report yet, clock skew, stale age against the interval), and `PHAROS_BEACON_HEALTH_FILE` relocates the beacon's report state; deployments can drop `--no-healthcheck` workarounds (PHAROS-203).

## 0.1.89 - 2026-08-27

- Keep host setting edits local until an explicit review and confirmation creates exactly one saved SettingsChange request, with clean draft discard and clear requested consequences (PHAROS-225).
- Follow a confirmed SettingsChange live through recorded host evidence, advancing the truth ladder only from matching reports and stopping polling once the workflow is terminal (PHAROS-226).
- Make the shared container healthcheck role-aware: `pharosd` keeps its readiness probe while `pharos-beacon` becomes healthy after a successful report and unhealthy when reporting goes stale (PHAROS-204).

## 0.1.88 - 2026-08-27

- Show one truthful lifecycle control for each host, backed by a server-computed priority projection that keeps simultaneous and recovered workflows visible (PHAROS-214, PHAROS-219).
- Anchor the Fleet host Actions menu to the invoking card across desktop and mobile refreshes (PHAROS-220).
- Terminalize successful system-update proposals, deduplicate dispatch, and make uncertain guarded handoffs explicitly recoverable (PHAROS-217).
- Add a fact-based Observed / Declared / Requested / Executed / Verified ladder, explicit next-action consequences, and SettingsChange withdrawal that preserves any open nixcfg proposal (PHAROS-215).

## 0.1.87 - 2026-08-24

- Fleet freshness chip row clips inside the card and fades at the right edge (PHAROS-211).

## 0.1.86 - 2026-08-23

- Fleet host cards show deployed / nixcfg / nixpkgs as three one-line chips that share the card width, with a right-edge fade (PHAROS-211).

## 0.1.85 - 2026-08-23

- Fleet grid host cards no longer overlap (clip heartbeat stage, contain card layout, align grid items to start). PHAROS-211.

## 0.1.84 - 2026-08-22

- Bind Paimos crash replay to the exact current owner intent and canonical origin, rejecting configuration drift before any network access while preserving credential rotation.
- Keep cleartext loopback transport test-only and require exactly one canonical response media type, no content encoding, and exact HTTP status-to-duplicate receipt semantics.
- Disable every reqwest transparent response decoder, retain identity-only negotiation, and prove gzip, Brotli, zstd, and deflate refusal over the real client path with feature-unified CI.

## 0.1.83 - 2026-08-22

- Add the opt-in, reporter-only Paimos external-stage adapter pinned to schema major 1, Paimos v5.11.0, certified commit `e5f4c86bc061775c853d5847e8fb8bb7e3a31c34`, and the exact released owner/dependency fixture bytes.
- Require separate owner-only API-key and per-handoff credential files, journal exact requests before sending, and replay with idempotency derived only from handoff, sequence, and request digest.
- Report deployment only from an existing completed guarded `UpdateRestart` plus matching later Nix-generation evidence, and report verification only from a separate handoff after a still-later fresh beacon for the identical locally configured artifact and environment.
- Bind ambiguous crash replay to the exact current owner intent, keep cleartext loopback transport test-only, and require singleton JSON media, no content encoding, and exact duplicate/status semantics.

## 0.1.82 - 2026-08-20

- Independent machine-operator credential verifier using SHA-256 bearer tokens instead of OIDC. Invalid or unavailable bearer credentials fail closed (401/503) without falling back to cookie authentication or open mode.
- Typed `HostNeedIntent` resource via `POST /host-need-intents` creates Hetzner paid-plan review records (`apply: false`). No PPM webhook integration.
- Capability-named Janus projection roots for `pharos-beacon-token` and `pharos-machine-operator` credentials, both using hash-dir v2 format (`generation-{id}.json`).
- Read-only `pharos` CLI gated by `PHAROS_OPERATOR_TOKEN_FILE` environment variable. No agent endpoints (`/agent/*`).

## 0.1.81 - 2026-08-10

- Resolve the official NixOS channel tip from its bounded HTTPS `git-revision` publication instead of downloading GitHub's complete nixpkgs ref advertisement, eliminating host-speed-dependent comparison timeouts.
- Accept only a size-bounded exact lowercase Git object ID over HTTPS and allow only the official channel-to-release redirect; every network, redirect, size, or parse failure remains explicitly unknown.
- Keep exact fail-closed Git comparison for explicitly configured custom nixpkgs remotes and expose an optional channel-publication base for controlled deployments.

## 0.1.80 - 2026-08-10

- Tie Nix freshness to strict active-generation evidence containing the exact nixcfg revision, flake.lock SHA-256, and resolved nixpkgs revision instead of trusting a mutable checkout.
- Compare the deployed revision with a freshly fetched authoritative branch in an isolated writable reference repository, distinguishing current, behind, ahead, diverged, and unknown; a failed fetch never reuses a stale tracking ref.
- Compare the locked nixpkgs revision with the exact current tip of its declared channel. Lock age remains context, while only exact revision equality can claim current.
- Move the host report contract to `inspr.pharos.host-report.v5`, keeping v4 as the accepted predecessor; predecessor or incomplete evidence renders unverified rather than up to date.

## 0.1.79 - 2026-08-10

- Report the stalest other root nixpkgs-family input by name, age, and channel as neutral lock-maintenance context while keeping transitive inputs excluded and the system nixpkgs as the sole source of host patch posture.
- Move the host report contract to `inspr.pharos.host-report.v4`, keeping v3 as the accepted predecessor for the control-plane-first rollout and rejecting v2.

## 0.1.78 - 2026-08-10

- Load local registration and beacon credentials from read-only runtime files with `_FILE` precedence, remove exactly one trailing line ending, and fail startup on a missing, invalid or empty file instead of falling back to an environment value.
- Move the self-host and NixOS integration paths to file-backed registration so credential values no longer need to enter the service environment.

## 0.1.77 - 2026-08-08

- Request the nixcfg retirement proposal whenever a removal must retire a credential, not only when it must remove a declaration, so removing a Janus-managed host that nixcfg does not declare no longer revokes reporting and then strands with the credential live.
- Fail such a removal closed when the proposal cannot be requested, and stop offering it in Fleet, instead of starting a removal that can never complete.
- Report a stuck credential retirement as a missing declared retirement intent rather than an invalid contract, since retrying cannot change it.

## 0.1.76 - 2026-08-08

- Report the age and channel of the nixpkgs a host is actually built from, rather than the oldest input whose name resembles nixpkgs, so an unreferenced or transitive stale input no longer reads as a patching gap on an otherwise current host.

## 0.1.75 - 2026-08-08

- Report the age of the oldest nixpkgs input and the release channel it tracks, so a frozen nixpkgs no longer reads as fresh because some other flake input moved recently.
- Flag an end-of-life NixOS release channel as a distinct signal that outranks any age number, classified by the control plane so a newly expired release needs no fleet-wide beacon roll.
- Move the host report contract to `inspr.pharos.host-report.v3`, keeping v2 as the accepted predecessor; deploy the control plane before rolling beacons.

## 0.1.74 - 2026-08-08

- Announce a completed host-removal reconciliation once instead of on every reconciliation pass, so a durable retirement record no longer emits a steady operational log line after its removal has finished.

## 0.1.73 - 2026-08-08

- Allow removal of a Janus-managed host that has no declared manifest, which previously dead-ended on a conflict because declarative cleanup and credential retirement were treated as one stage.
- Keep a retired host durably visible until every applicable removal stage completes, so an outstanding credential retirement can no longer be hidden behind an apparently finished removal.
- Name declarative cleanup and credential retirement separately in the removal dialog before confirmation, replacing the registration-only scope previously shown for undeclared managed hosts.

## 0.1.72 - 2026-08-04

- Replace dead-end OIDC callback failures with a branded, accessible one-action recovery flow that clears obsolete browser state and preserves only validated local return destinations.
- Handle expired, replayed, wrong-browser, concurrent-tab, and post-restart login state deterministically without redirect loops or replaying non-idempotent requests.
- Classify token exchange failures into value-free transport, provider, malformed-response, and verification categories with appropriate `503`, `502`, and `401` responses.

## 0.1.71 - 2026-08-04

- Complete logout with a POST-redirect-GET response so browsers reach the GET-only signed-out page without replaying the logout form, while preserving CSRF validation, session removal, and cookie expiry.

## 0.1.70 - 2026-08-04

- Polish Fleet host-card lifecycle states with consistent “Change requested”, “Ready to apply”, “Restart required”, and quiet “Up to date” indicators.
- Align each lifecycle indicator to the combined width of the two fixed Nix freshness cells and their gap, remove duplicate freshness attention, and place the host actions menu before backup status.

## 0.1.69 - 2026-08-04

- Route per-backup Stale and Failed posture transitions through the durable alert incident/outbox pipeline, including preference suppression, stable deduplication, escalation, Telegram delivery, recovery, and in-place migration of existing host-down alert state.

## 0.1.68 - 2026-08-04

- Polish Fleet host cards by moving settings into the actions menu, reducing backup posture to a color-aware ghost control, and compacting freshness, timestamps, availability, and heartbeat-window controls without changing list view.
- Add accessible hover, focus, and reduced-motion behavior for icon-backed flake.lock age and commits-behind facts while preserving their structure during live refreshes.

## 0.1.67 - 2026-07-30

- Give the opaque, signed managed-service setup intent a bounded fifteen-minute outer window so page review and one complete five-minute Janus passkey step-up no longer share the same deadline; exact target/user binding, cancellation, expiry, and single-use consumption remain unchanged.

## 0.1.66 - 2026-07-29

- Align the managed NixOS bootstrap lease with the reviewed executor's two-hour hard runtime so a legitimate long-running install does not become an ambiguous recovery solely because its one-hour lease elapsed.

## 0.1.65 - 2026-07-29

- Reconcile an ambiguous Hetzner server deletion with bounded read-only inventory checks after exactly one destructive request, without automatically replaying the provider operation.
- Recover a lost cleanup response from durable job state and refresh Fleet automatically once terminal removal is confirmed, including delayed identity retirement.

## 0.1.64 - 2026-07-27

- Let an authenticated operator request fresh exact-generation health evidence when delivery and reload completed but verification ended in a safe failure.
- Reopen only the existing operation's verification phase: require the current declaration, reject newer work or incomplete delivery, and never create, rotate, transport, or reveal another secret.
- Replace the misleading fresh-setup action with a focused “Recheck recovered service” path, preserving strict value-free responses, durable idempotency, and host-scoped verification leases.

## 0.1.63 - 2026-07-25

- Let a safely failed or rolled-back first managed-secret setup start a fresh passkey-confirmed attempt instead of leaving the operator on a disabled dead-end control.
- Explain that the failed value was never activated, keep technical evidence optional, and preserve the no-reveal/value-free browser boundary.
- Point source, CI, package, and Nix metadata at the transferred `inspr-at/pharos` repository.

## 0.1.62 - 2026-07-24

- Add the managed-service secret CRUD control plane: declaration-locked service and slot selection, signed single-use Janus handoffs, value-free operation leases, exact host execution, health-confirmed activation, replacement rollback, and recoverable removal quarantine.
- Ship a focused, accessible Services UX that offers generated or one-time imported values without reveal, copy, or secret-shaped evidence; keep future consumer types subtle and managed services first.
- Add closed release assurance for the cross-repository Pharos, Janus, and host-agent contract, including real desktop/mobile Chromium coverage and fail-closed adversarial paths.

## 0.1.61 - 2026-07-23

- Reconcile an uncertain managed bootstrap through an explicit read-only lease that proves the exact job credential and installation artifacts are absent before allowing the existing server to retry.
- Keep uncertain, failed, expired, and ambiguous evidence fail-closed; prevent cleanup while reconciliation is active; and guide operators through the safe recovery state without replaying installation work.

## 0.1.60 - 2026-07-23

- Honor the kebab-case managed provisioning state contract in the setup assistant, expose SSH host-key attestation and accurate installation guidance, keep identity-retirement polling active, and fail closed on unknown states.
- Load deterministic value-free managed-service secret-slot declarations from nixcfg, reject malformed, ambiguous, cross-host, or stale declarations for mutation, and expose declaration/load status separately from Janus-owned delivery and observed health.
- Issue short-lived Ed25519-signed managed-service setup intents, keep browser handoffs opaque, authenticate Janus retrieval, bind cancellation to the initiating OIDC principal, and durably close delivery/cancellation races.
- Add a focused Services view for declared managed-service secret slots, with locked targets, one value-free setup action, plain lifecycle/progress language, safe offline and declaration-error recovery, and a Janus handoff that never asks Pharos for a source or value.

## 0.1.59 - 2026-07-23

- Reconcile current Hetzner server responses through their top-level location while retaining the legacy nested datacenter fallback, sharing one exact fact matcher across creation and uncertain-result recovery, and rejecting missing or conflicting location evidence without replaying paid work.

## 0.1.58 - 2026-07-22

- Carry a reviewed Hetzner paid plan through durable creation, SSH host-key attestation, a leased NixOS bootstrap, and the first authenticated heartbeat without automatically replaying uncertain work.
- Bind every job to one managed executor and Janus credential reference, and require exact ownership plus credential retirement for destructive recovery.
- Continue the in-app server assistant through verification and installation while keeping provider execution and executor readiness behind independent activation gates.

## 0.1.57 - 2026-07-22

- Keep the immediately preceding host-report contract valid during a control-plane-first rolling upgrade, reject mismatched or older schema/version pairs, and enforce that bounded compatibility window in the release contract tests.

## 0.1.56 - 2026-07-21

- Pin the release signer to cosign v2.5.2, the version checksum-bootstrapped by the reviewed installer action, instead of requesting an incompatible v3 release whose assets use a different verification format.

## 0.1.55 - 2026-07-21

- Keep BuildKit's signed OCI provenance and SBOM attestations for private-repository releases, verify both before signing, and verify the keyless image signature before admitting the release.
- Remove the unsupported duplicate GitHub attestation API call, which rejects user-owned private repositories after the image has already passed its build, vulnerability scan, and SBOM gates.

## 0.1.54 - 2026-07-21

- Make report, alert, provider, and workflow persistence crash-safe and fail closed with bounded reads, checksummed durable sidecars, serialized mutation, startup validation, and explicit delivery supervision.
- Split startup, routing, alerting, provisioning, Janus authentication, and UI rendering into reviewable modules, and move the static interface into separately testable assets without changing route authorization boundaries.
- Consume Janus beacon verifier generations as immutable snapshots, reject invalid pointers, schemas, digests, permissions, and partial updates, and enforce producer/consumer compatibility against one byte-identical fixture in CI.
- Add a signed in-process OIDC authorization-code/PKCE end-to-end test, strict browser security-header coverage, report-contract property tests, and real-browser accessibility, focus, responsive, alignment, and visual-regression checks.
- Pin the Rust and Node toolchains, GitHub Actions, container bases, dependency workaround, and outbound provider behavior; publish vulnerability-scanned images with SPDX SBOM, provenance, and keyless signatures.
- Enforce warning-free Rust, dependency policy, shell lint/format, 80% line coverage, Nix package builds, hardened self-host container posture, and Linux arm64 image smoke coverage in the release path.

## 0.1.53 - 2026-07-21

- Make Fleet foreground recovery atomic: stop client-side heartbeat projection, supersede stale requests, apply one authoritative host snapshot, and only then restart the clock.
- Stop trusting suspended background timers, expose a clear synchronizing or out-of-date state, and preserve last-known host states when synchronization fails.
- Reconcile Fleet counters, cards, rows, timestamps, and heartbeat history from the same snapshot, with executable lifecycle regressions for suspension, rapid refocus, request replacement, and failure handling.

## 0.1.52 - 2026-07-21

- Format provider-plan monthly prices with the browser locale, the catalog currency symbol, and exactly two decimal places.
- Present a completed connection awaiting installation activation as an amber attention gate instead of a red provider failure, while keeping paid execution disabled.

## 0.1.51 - 2026-07-21

- Treat a verified provider connection as complete independently from the installation's paid-execution switch, while keeping managed creation locked until explicitly enabled.
- Hand the completed provider guide to the server assistant and explain the remaining installation-level activation gate instead of looping back to another connection test.
- Keep incomplete provider help expanded, automatically collapse it after every setup check is green, and preserve manual expand/collapse access.
- Vertically center every numbered provider-assistant circle with one shared system-font and line-height rule.

## 0.1.50 - 2026-07-21

- Preserve valid human-readable Hetzner SSH-key and firewall names, including names containing characters such as `@`, when building provider dropdowns.
- Explain that the SSH-key dropdown is sourced from public-key names returned by the current Hetzner project and never reads or uploads private key material.
- Keep numbered setup tasks on one grid-aligned column and describe changing public addresses generically as dynamic IPs.

## 0.1.49 - 2026-07-20

- Make the Hetzner firewall assistant branch explicitly between a static bootstrap executor, a dynamic-IP connection, and a Tailscale end state before showing firewall-creation steps.
- Treat a dynamic `/32` as temporary attended access that must be refreshed immediately before later paid creation and bootstrap, while keeping SSH keys mandatory under CGNAT.
- Prevent Tailscale `100.x` addresses from being presented as public Hetzner sources, document the current public-SSH bootstrap boundary, and require verified tailnet access before removing public SSH.

## 0.1.48 - 2026-07-20

- Turn the Hetzner firewall assistant into a literal English/German walkthrough of the current form, including how to remove the default Any IPv4, Any IPv6, and optional ICMP entries.
- Explain TCP, SSH port 22, and the single-address `/32` boundary in beginner language, with an exact ready check before firewall creation.
- Keep the macOS source range in the local clipboard with Fish-safe execution and explicitly prevent operators from sharing the real address in chat, tickets, or logs.

## 0.1.47 - 2026-07-20

- Add an English/German Hetzner portal-label switch with localized official documentation links and safe project-selector links for every provider setup destination.
- Run every macOS and Linux terminal snippet through an explicit Bash boundary so the copied commands work unchanged from Fish, Zsh, or Bash.
- Correct firewall navigation to the standalone Firewalls item in the left Cloud menu and call out that it is not under Security.

## 0.1.46 - 2026-07-20

- Replace the abstract Hetzner prerequisite text with a four-stage setup assistant that opens at the first missing API, SSH-key, firewall, or Pharos-selection task.
- Give beginners exact Hetzner click paths and separate macOS and Linux key-pair commands while copying only static safe commands and never accepting a token, private key, passphrase, or source address.
- Detect existing provider resources, keep official reference links and installation-specific secure handoff, explain the firewall source lookup and no-billing finish check, and retain full viewer and responsive behavior.

## 0.1.45 - 2026-07-20

- Materialize the pushed annotated tag object inside the release checkout before enforcing the semantic-release gate, preserving immutable tags while allowing a verified release to publish.

## 0.1.44 - 2026-07-20

- Add a generic in-product guide below Hetzner Cloud settings for creating a project-scoped Read & Write API token, preparing a Linux-executor SSH key, and defining a least-privilege bootstrap firewall.
- Link to current official Hetzner instructions, route managers to each installation's secure credential workflow, and explain how to refresh empty location, key, or firewall choices without placing secrets in Pharos.
- Cover manager and viewer access, responsive presentation, prerequisite ordering, installation-neutral wording, and secret-safe boundaries with focused regressions.

## 0.1.43 - 2026-07-18

- Keep the authenticated read-only Hetzner Cloud connection test available while managed execution is disabled, without exposing Add server or paid-review actions.
- Make current `PHAROS_HCLOUD_EXECUTE=0` state fail closed even when fresh evidence was recorded while execution was enabled, and cover the read-only requests and disabled gate with focused regressions.

## 0.1.42 - 2026-07-18

- Persist an exact, secret-free Hetzner Cloud plan with server name, current gross prices, hard caps, project and resource selectors, a non-secret credential binding, ownership labels, a one-server maximum, and a short expiry before any paid action is available.
- Require the authenticated operator to authorize that exact digest in a separate attended step, then revalidate live credentials, catalog facts, image, SSH key, firewall, prices, complete project inventory, and the bound server facts immediately before one single-use create request.
- Require a checksummed, store-bound durable job sidecar, reserve the project across restart while any attempt is unresolved, pin one no-retry/no-redirect credential snapshot per provider operation, reconcile uncertain results without replay, and allow separately confirmed cleanup only with exact ownership evidence, including safe recovery after credential or operator rotation.

## 0.1.41 - 2026-07-15

- Animate the sidebar lighthouse with a compact, silent native video while preserving the existing still image as the loading and playback fallback.
- Add one browser-local Still sidebar image switch under Settings; motion remains the default and the preference survives navigation and refreshes.
- Avoid hidden work by skipping motion on compact layouts, reduced-motion or data-saving connections, pausing it in background tabs, and serving a 329 KB versioned asset with no audio stream.

## 0.1.40 - 2026-07-15

- Add a reduced Hetzner Cloud connection screen with only API connection, SSH key, and firewall checks; region and provider choices stay behind Connection details until they need attention.
- Test the provider through read-only official API calls, keep the token in the Janus and agenix file boundary, persist only safe evidence, and block creation when connection or catalog evidence is stale.
- Load current locations, available server plans, and project prices into Add server instead of relying on a fixed plan, then validate the exact choice again before the separate paid-creation confirmation.

## 0.1.39 - 2026-07-15

- Add one reduced Provider connections screen under Settings, with a compact managed-or-guided status and one clear next action for Hetzner Cloud, netcup, AWS, Google Cloud, and Oracle Cloud.
- Open secure Hetzner setup through Janus using value-free metadata only, and keep provider credentials out of Pharos pages, browser state, responses, and deployment files.
- Send an interrupted Add server flow to the exact provider setup page and return to the same step, while keeping unsupported or eligibility-dependent providers on honest two-step guided paths.

## 0.1.38 - 2026-07-14

- Apply color, host type, and alert choices on native non-Nix hosts through the heartbeat they already send, with no inbound listener or additional operator setup.
- Keep the selected values in private host-owned service state and confirm them only after the host reports the applied settings on its next heartbeat.
- Reuse the exact narrow Nix host-settings schema, reject commands and unknown fields, and preserve the last valid local settings when a response is malformed, mismatched, oversized, or cannot be written safely.

## 0.1.37 - 2026-07-14

- Open Add server with only two obvious choices: create a new server or connect one that already exists, using centered Pharos-style icon controls on desktop and mobile.
- Present one decision per step with predictable Back navigation, while keeping provider templates, connection facts, and technical checks out of sight until that path needs them.
- Preserve guarded provider readiness, existing-host preflight, explicit confirmation, setup progress, and recovery behavior without the previous lifecycle chips, duplicated footer controls, or all-at-once form.

## 0.1.36 - 2026-07-14

- Treat a Workstation host type as an explicit expected-offline policy: Fleet and Map retain the true Down state while Alerts, Activity, and outbound silent-heartbeat notifications omit that expected outage.
- Keep Server behavior unchanged, preserve the existing manual Down-alert preference, and continue surfacing backup, Nix freshness, kernel, and service warnings independently of host type.
- Explain the automatic Workstation policy in Host Settings with a disabled Down-alert control while preserving the user's manual preference for a future switch back to Server.

## 0.1.35 - 2026-07-14

- Keep declared-host removal pending until both the reviewed nixcfg declaration and the Janus-owned host credential are retired; removing a manifest alone no longer reports success.
- Add a separate machine-authenticated retirement-owner lease that can execute only an already approved host retirement, never return credential material, and cannot retire its own owner host.
- Show credential retirement as a persisted checklist gate with waiting, running, action-required, retry, and complete states while preserving typed failure evidence and the original operator intent.

## 0.1.34 - 2026-07-13

- Keep the running workflow step visibly active with a low-frequency stepped indicator that avoids continuous full-dialog compositing and honors reduced-motion preferences.
- Use one replaceable timer and one abortable request for Fleet and Host Settings workflow polling, with bounded retry delays and cleanup on close or navigation.
- Pause workflow polling and animation while hidden or offline, then refresh once immediately when the page becomes visible, focused, or connected again.

## 0.1.33 - 2026-07-13

- Add safe run, host, timing, duration, and execution-location metadata to the shared persisted checklist used by settings, update review, apply/restart, removal, and recovery workflows.
- Allow operators to cancel an update review only before attended confirmation, persist the cancellation, release host and fleet gates, and reject late target-agent results without authorizing a live change.
- Link guarded-action Activity rows to their exact saved workflow, reopen the same run after refresh, and expose the single running step with accessible busy and current-step semantics.

## 0.1.32 - 2026-07-13

- Preserve the exact guarded-action lease phase across Pharos restarts and lease expiry so post-reboot verification can never be replayed as a second apply.
- Allow only one poller to claim a resumed action, reject inconsistent persisted lease state, and retain typed timeout plus original apply-failure evidence through store reloads.

## 0.1.31 - 2026-07-13

- Persist a typed, value-free failure gate for guarded host actions so recovery shows the exact verification stage that stopped without exposing command output, machine paths, or opaque identifiers.
- Distinguish recovery of the exact reviewed system from verification of a newer trusted deployment while preserving the original failure and preventing a second switch or restart.
- Show a lightweight activity indicator only on the checklist step that is currently running, expose its busy state to assistive technology, and honor reduced-motion preferences.

## 0.1.30 - 2026-07-13

- Add one persisted, plain-language execution checklist for host settings, fleet update proposals, guarded update/restart, host removal, and recovery, with clear waiting, confirmation, action-required, completed, stopped, and recovered states.
- Keep technical evidence in a sanitized Advanced history that excludes credentials, machine paths, opaque identifiers, and command output while preserving operator, host-agent, heartbeat, and Pharos audit events.
- Reconcile post-confirmation failures in the original run using fresh live and current-kernel evidence; the target-local recovery branch verifies the existing result and never requests a second switch or reboot.
- Record workflows before external dispatch so nixcfg rejection remains visible at the exact failed step, and pause expensive Fleet heartbeat work while dialogs or background tabs are inactive.
- Resolve each workflow type from its newest run so a successful retry or recovery supersedes older failure state, and use the same workflow identity for accurate Activity labels.

## 0.1.29 - 2026-07-13

- Ask what happened to a host before removal and record whether it was destroyed, left unmanaged, or rebuilt with an already onboarded successor.
- Keep runtime-only removal local while declaratively managed hosts require a fixed, review-only nixcfg cleanup request; operating system type alone never implies nixcfg ownership.
- Revoke reports through a durable retirement record, expose lifecycle intent in Activity and the fleet API, and migrate older removal records conservatively to unmanaged without exposing credential material.

## 0.1.28 - 2026-07-12

- Let operators retry the latest failed pre-change host review from the existing action dialog after its cause is corrected, while preserving the failed attempt and linking the new review to it.
- Keep retries fail-closed: only review failures before confirmation are retryable; failures after confirmation require manual recovery and cannot silently start another live change.
- Make each host's latest guarded attempt control the fleet gate, validate retry relationships in durable state, and prevent bypassing a recorded failure with an unrelated new review.

## 0.1.27 - 2026-07-12

- Add one shared, accessible per-host Actions menu to Fleet cards and rows, with pending-change review, safe technical details, and contextual controls that appear only when their guarded backend is prepared.
- Add review-only fleet update dispatch, target-local update/restart jobs with exact leased phases and attended confirmation, and typed host removal that revokes reports without deleting the server or its data.
- Persist guarded actions and retired-host tombstones transactionally, expose sanitized progress in Fleet and Activity, and fail closed when authorization, backup, validation, persistence, or fresh post-restart kernel evidence is missing.

## 0.1.26 - 2026-07-12

- Rebuild Fleet's list mode as a compact six-column counterpart to the grid cards, with shared host identity, attention, freshness, heartbeat signal, Backup, and Settings components.
- Keep rows at a stable scanning height while Backup and Settings disclose labels on hover or focus, and replace wrapped last-seen sentences with compact values that still reveal historic heartbeat detail.
- Preserve sorting, search, summary filters, signal-window controls, setup/onboarding rows, live refresh, and narrow-screen use with horizontal overflow contained inside the list surface.

## 0.1.25 - 2026-07-12

- Keep the oldest visible heartbeat centered four pixels inside the timeline so the pulse fade always begins inside the card and retains its requested four-pixel lead-in, including full-window histories.

## 0.1.24 - 2026-07-12

- Keep Backup and Settings as centered icon-only host-card actions at rest, with smooth label disclosure on hover and keyboard focus while preserving state tint and pending-change affordances.
- Keep the Settings glyph stable when a change is waiting, remove the duplicate pending marker, and make the single plain-language waiting line open the correct host settings directly.
- Start the heartbeat pulse inside the visible history, just before its oldest mark, and emphasize the segment leading to the current heartbeat without clipping the card.

## 0.1.23 - 2026-07-11

- Add a versioned, sanitized kernel-posture report that compares the running kernel with the current NixOS generation without transmitting store paths or opaque identifiers.
- Show only actionable pending-restart state in Fleet, with a plain-language running-versus-ready disclosure and one warning in Alerts and Activity.
- Fail missing, malformed, inaccessible, or ambiguous kernel observations safely to unknown, cover the native NixOS path in KVM, and never reboot a host automatically.

## 0.1.22 - 2026-07-10

- Load nixcfg's exact all-host preference registry as the authoritative declared-settings layer, with generated host manifests as fallback.
- Show registry-only declarations for every permitted host in Fleet and Agora while keeping beacon reports as the sole source of applied state.
- Keep the merge-to-host-rebuild boundary explicit: reading a merged declaration never triggers or implies deployment.

## 0.1.21 - 2026-07-10

- Dispatch Nix host color, host type, and alert preferences through nixcfg's fixed guarded workflow using an opt-in, file-only Actions credential; Pharos never writes git or deploys a host.
- Keep requested, declared, and beacon-applied settings separate in the Fleet API and UI, with a compact change-waiting state that never presents a pending color as live.
- Let the beacon validate and report its host's applied preferences from the shared `inspr.pharos.host-preferences.v1` registry while rejecting unknown fields and retaining its last valid state on read failures.
- Add the NixOS preference-file option and KVM coverage for the complete declared-file-to-beacon-to-Pharos report path.

## 0.1.20 - 2026-07-10

- Move each host's backup posture into a compact, clickable Fleet header chip beside Host settings, with distinct protected, unreported, stale, and failed shield states.
- Open Backups already filtered, highlighted, and scrolled to the selected host while preserving the existing detailed backup rendering in Fleet list view.
- Keep backup chips synchronized with live host reports without reloading the Fleet page.

## 0.1.19 - 2026-07-10

- Replace the dense Agora mini-app with shared Pharos navigation, one host selector, one color task, and collapsed declarative details that also work on narrow screens.
- Add host-owned color and alert preference requests with explicit pending-versus-applied state; monitoring changes only after the host reports the applied preference.
- Let applied host preferences mute down, backup, or Nix-freshness attention in Fleet, Alerts, and Activity while keeping a visible muted marker on Fleet cards and rows.
- Keep Fleet mute markers synchronized through the existing background refresh without exposing pending requests or credential material.

## 0.1.18 - 2026-07-10

- Move release history into a body-level portal above Fleet cards, map controls, tables, and every other page surface.
- Initialize release history from the shared sidebar on every route, with working close-button, backdrop, Escape, focus restoration, and scroll locking behavior.

## 0.1.17 - 2026-07-10

- Add an auth-guarded, explicitly confirmed cleanup endpoint that can delete only the single validated Hetzner server persisted on an eligible setup job.
- Persist proven deletion as an idempotent, rollback-compatible terminal outcome while uncertain provider results remain cleanup-needed with safe recovery guidance.
- Replace the provider-created result with the imagegen-designed focused flow: one primary setup action, collapsed recovery options, confirmation-gated deletion, and clear deleted state.
- Keep pending and cleanup-needed setup jobs reopenable from fleet cards and rows after a browser restart.

## 0.1.16 - 2026-07-10

- Deliver NixOS beacon token files through a per-service systemd credential so the root-only source remains protected while the unprivileged beacon can authenticate.
- Add a KVM-backed NixOS integration check that performs runtime registration and waits for a real authenticated first heartbeat in Pharos.
- Keep test-only Nix files out of the Rust package source closure so integration fixture changes reuse unchanged application packages.

## 0.1.15 - 2026-07-10

- Reworked new-server review into a focused, imagegen-designed summary with server, setup, and post-setup intent visible while technical provider details stay collapsed.
- Added safe provider-readiness feedback without returning API tokens, resource names, private key material, or other runtime secret references to the browser.
- Resolve the configured Hetzner SSH public key and reviewed firewall before server creation, attach their provider IDs to the create request, and fail before create when either prerequisite is missing.
- Route manual/free-tier provider choices into existing-host import instead of submitting an unsupported provider create job.
- Documented the runtime-file credential, existing public-key, and pre-reviewed firewall requirements for self-host operators.

## 0.1.14 - 2026-07-10

- Persist the created Hetzner server, provider location, and validated public SSH destination on the tracked setup job.
- Add a protected NixOS bootstrap handoff that keeps beacon credentials out of job data, command arguments, and Nix evaluation.
- Replace the completed provider form with a focused server-created screen that leads from creation through Pharos install to the first heartbeat.
- Fail closed on unsupported provider inputs and require cleanup review when a server exists but no usable public IPv4 address is returned.

## 0.1.13 - 2026-07-10

- Added a guarded Linux-side `nixos-anywhere` helper for the existing-host NixOS path, using strict SSH trust, preserved host keys, and post-install service verification.
- Passed the one-time beacon token through a private `--extra-files` tree instead of command arguments or Nix evaluation, keeping it out of the Nix store.
- Linked NixOS setup jobs to the concrete helper and first-bootstrap token path, with a follow-up migration to agenix or Janus after the first heartbeat.
- Added a CI dry-run contract for the helper and refreshed the README to reflect production strict-token ingestion.

## 0.1.12 - 2026-07-10

- Added an opt-in, fail-closed native systemd executor for existing-host onboarding after successful SSH/preflight review.
- Kept raw beacon credentials out of process arguments, persisted jobs, and logs: the one-time value travels only over SSH stdin into a root-owned runtime env file.
- Refused unknown SSH host keys, missing runtime references, unsupported routes/architectures, and implicit token-file rotation before changing a target.
- Required a heartbeat at or after the current wait state so old host data cannot falsely complete a new onboarding job; a valid heartbeat can resolve an uncertain install result.
- Bundled the portable systemd installer in the released container and documented the advanced self-host executor contract while leaving it disabled by default.

## 0.1.11 - 2026-07-10

- Added a separate self-host Docker Compose template for running the released Pharos image outside the Markus-owned nixcfg deployment.
- Documented the minimum self-host runtime environment, OIDC/operator gate, strict beacon token gate, and first-run config validation.
- Kept committed self-host config value-free: runtime tokens and tenant-specific values stay in the operator environment or secret manager.

## 0.1.10 - 2026-07-10

- Added access intent to setup jobs so new-host and existing-host onboarding record who should see the host after first heartbeat.
- Exposed access policy choices in the setup assistant alongside backup and location intent.
- Render setup access intent on pending setup cards and include it in setup search text.

## 0.1.9 - 2026-07-10

- Fail closed before automated existing-host handoff unless SSH plus required preflight checks are verified.
- Keep failed existing-host preflight context on the tracked job so operators can see why no handoff was recorded.
- Added tests for missing and failed preflight blockers before native or NixOS bootstrap handoff.

## 0.1.8 - 2026-07-10

- Persist existing-host setup context on tracked jobs: SSH route, selected bootstrap method, preflight summary/checks, and non-secret verification steps.
- Require a non-secret SSH target before recording automated existing-host bootstrap handoffs.
- Render the saved existing-host context in the setup assistant job status so operators can see what Pharos is waiting for without exposing tokens.

## 0.1.7 - 2026-07-09

- Reconcile tracked setup jobs after the first runtime heartbeat: jobs move to backup-pending when backup work remains, or complete when the selected backup policy does not block onboarding.
- Complete backup-pending jobs once Pharos receives backup observation evidence from the runtime host.
- Keep setup job polling and Alerts/Activity aligned with the persisted job state instead of hiding first-heartbeat jobs without closing them.

## 0.1.6 - 2026-07-09

- Added a real Hetzner Cloud create executor behind setup jobs, gated by explicit runtime config and complete create inputs.
- Persisted safe provider progress: provisioning, bootstrapping handoff, waiting for heartbeat, and cleanup-needed recovery when provider state is uncertain.
- Extended the new-host assistant to send host, location, server type, image, and SSH key reference without collecting provider credentials in the UI.

## 0.1.5 - 2026-07-09

- Changed existing-host NixOS/native bootstrap jobs from generic failed executor state to an explicit runtime-credential handoff.
- Kept Janus/dev-local beacon credential creation outside the UI response: no raw tokens, token files, env contents, or hashes are rendered by setup jobs.
- Existing-host jobs now remain visible while waiting for the first heartbeat after approved credential handoff and beacon start.

## 0.1.4 - 2026-07-09

- Added Oracle Always Free and Google Cloud free-tier lab import templates.
- Kept lab VMs provider-neutral: create externally, verify pricing/limits/capacity at runtime, then import through existing-host onboarding.
- Avoided promising permanently free capacity or collecting cloud credentials for lab templates.

## 0.1.3 - 2026-07-09

- Added an explicit Netcup manual-import setup template.
- Kept Netcup server creation, billing, rescue/ISO, snapshot, and SSH preparation as external operator steps.
- Linked Netcup to the existing-host import/bootstrap contract without introducing provider credentials or unsupported automated ordering.

## 0.1.2 - 2026-07-09

- Made existing-host onboarding collect SSH user and heartbeat cadence explicitly.
- Hardened preflight parsing so pasted `user@host:port` SSH targets probe the host correctly.
- Persisted non-default heartbeat cadence into tracked setup jobs and handoff text.

## 0.1.1 - 2026-07-09

- Added read-only existing-host backup signal detection during setup preflight.
- Surface detected backup tools as setup evidence so operators can choose managed-elsewhere, Pharos enrollment, or deferred backup handling deliberately.
- Kept backup facts sanitized: no command output, credentials, repository paths, or raw runtime values are stored or shown.

## 0.1.0 - 2026-07-09

- Added a visible dashboard version badge and release-history dialog.
- Added build-time version and Git commit reporting through `/version`.
- Documented the release discipline: bump `VERSION` and update this changelog before every production deploy.
- Kept the operator-facing dashboard behavior unchanged while making deployed builds easier to identify.

## 0.0.1 - 2026-07-08

- Shipped the Pharos fleet dashboard baseline with OIDC-gated operator routes.
- Added host cards, map, alerts, backups, activity, Agora host settings, and heartbeat history.
- Added beacon token enforcement migration support, including local, dual, and Janus sidecar modes.
