# Pharos Changelog

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
