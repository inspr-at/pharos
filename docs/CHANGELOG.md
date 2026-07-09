# Pharos Changelog

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
