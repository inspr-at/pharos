//! pharosd — the Pharos server.
//!
//! Routes: `/healthz`, `/version`, `POST /register` (token issuance, PHAROS-8),
//! `POST /report` (beacon ingestion, PHAROS-9), `/hosts.json`, and the host
//! dashboard at `/`. Hosts live in a small store (in-memory + optional JSON
//! persistence; sqlx+SQLite is PHAROS-3). The
//! dashboard is a static server render previewing the design (rounded cards,
//! accessible SVG status, the self-host lighthouse); the interactive Leptos UI
//! is PHAROS-10.

mod agora;
mod auth;
mod icons;
mod manifests;
mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::{
    liveness, BackupObservation, BackupPostureState, BackupSetupIntent, BootstrapMethod,
    ExistingHostBootstrapOption, ExistingHostPreflightCheck, ExistingHostPreflightFacts,
    ExistingHostPreflightReport, ExistingHostPreflightRequest, ExistingHostPreflightSummary, Host,
    HostLocation, HostLocationSource, HostManifest, HostRegistration, HostRegistrationResponse,
    HostReport, Liveness, LocationSetupIntent, ManifestLocationMode, ManifestProbePolicy,
    ManifestService, ManifestStatusSource, NixFreshness, PreflightCheckState,
    ProvisioningBackupProposal, ProvisioningBackupProposalKind, ProvisioningBackupSecretFile,
    ProvisioningHandoff, ProvisioningJob, ProvisioningJobState, ProvisioningProgressEntry,
    ProvisioningSetupIntent, SecretOwner, ServiceObservation, ServiceObservationState, SshRoute,
    EXISTING_HOST_PREFLIGHT_SCHEMA, EXISTING_HOST_PREFLIGHT_VERSION, HOST_MANIFEST_SCHEMA,
    HOST_MANIFEST_VERSION, PROVISIONING_JOB_SCHEMA, PROVISIONING_JOB_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, MissedTickBehavior};
use url::Url;

use crate::auth::{Auth, AuthState};
use crate::manifests::{ManifestLoadIssue, ManifestRegistry};
use crate::store::Store;

const SERVER_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const EXISTING_HOST_SSH_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const ALERT_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const ALERT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    provisioning_jobs: Arc<ProvisioningJobStore>,
    manifests: Arc<ManifestRegistry>,
    auth: AuthState,
    beacon_auth: BeaconAuth,
    provider_runtime: ProviderRuntimeConfig,
}

impl FromRef<AppState> for Arc<Store> {
    fn from_ref(s: &AppState) -> Self {
        s.store.clone()
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

impl FromRef<AppState> for Arc<ManifestRegistry> {
    fn from_ref(s: &AppState) -> Self {
        s.manifests.clone()
    }
}

struct ProvisioningJobStore {
    path: Option<PathBuf>,
    jobs: RwLock<BTreeMap<String, ProvisioningJob>>,
    counter: AtomicU64,
}

impl ProvisioningJobStore {
    fn new(path: Option<PathBuf>) -> Self {
        let jobs = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice::<Vec<ProvisioningJob>>(&bytes).ok())
            .map(|jobs| {
                jobs.into_iter()
                    .filter(|job| job.validate_contract().is_ok())
                    .map(|job| (job.id.clone(), job))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            path,
            jobs: RwLock::new(jobs),
            counter: AtomicU64::new(1),
        }
    }

    fn start(
        &self,
        request: &ProvisioningJobStartRequest,
        now: i64,
        provider_runtime: &ProviderRuntimeConfig,
    ) -> Result<ProvisioningJob, ProvisioningJobStartError> {
        if !valid_setup_provider(&request.provider) {
            return Err(ProvisioningJobStartError::UnsupportedProvider);
        }
        if !valid_setup_template(&request.provider, &request.template) {
            return Err(ProvisioningJobStartError::UnsupportedTemplate);
        }
        let id = format!(
            "setup-{now}-{}",
            self.counter.fetch_add(1, Ordering::Relaxed)
        );
        let (state, progress) = provisioning_job_progress(request, provider_runtime, now);
        let handoff = provisioning_job_handoff(request);
        let setup_intent = provisioning_setup_intent(request);
        let backup_proposal = provisioning_backup_proposal(request);
        let host_name = request
            .host_name
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let role = request
            .role
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let job = ProvisioningJob {
            schema: PROVISIONING_JOB_SCHEMA.to_string(),
            version: PROVISIONING_JOB_VERSION,
            id,
            provider: request.provider.to_string(),
            template: request.template.to_string(),
            host_name,
            role,
            is_nix: request.is_nix,
            heartbeat_interval_secs: request.heartbeat_interval_secs.filter(|value| *value > 0),
            state,
            created_at: now,
            updated_at: now,
            handoff,
            setup_intent,
            backup_proposal,
            progress,
        };
        job.validate_contract()
            .map_err(|_| ProvisioningJobStartError::InvalidJob)?;
        {
            let mut jobs = self.jobs.write().expect("provisioning job store lock");
            jobs.insert(job.id.clone(), job.clone());
        }
        self.persist();
        Ok(job)
    }

    fn get(&self, id: &str) -> Option<ProvisioningJob> {
        self.jobs
            .read()
            .expect("provisioning job store lock")
            .get(id)
            .cloned()
    }

    fn list(&self) -> Vec<ProvisioningJob> {
        self.jobs
            .read()
            .expect("provisioning job store lock")
            .values()
            .cloned()
            .collect()
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let snapshot: Vec<ProvisioningJob> = self
            .jobs
            .read()
            .expect("provisioning job store lock")
            .values()
            .cloned()
            .collect();
        let Ok(json) = serde_json::to_vec_pretty(&snapshot) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(path, json) {
            tracing::warn!(
                "failed to persist provisioning jobs to {}: {e}",
                path.display()
            );
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ProvisioningJobStartRequest {
    provider: String,
    template: String,
    #[serde(default)]
    apply: bool,
    #[serde(default)]
    host_name: Option<String>,
    #[serde(default)]
    role: Option<String>,
    #[serde(default)]
    is_nix: Option<bool>,
    #[serde(default)]
    heartbeat_interval_secs: Option<u64>,
    #[serde(default)]
    backup_intent: Option<BackupSetupIntent>,
    #[serde(default)]
    location_intent: Option<LocationSetupIntent>,
    #[serde(default)]
    location: Option<String>,
    #[serde(default)]
    server_type: Option<String>,
    #[serde(default)]
    image: Option<String>,
    #[serde(default)]
    ssh_key_ref: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct ProviderRuntimeConfig {
    hetzner_cloud: HetznerCloudRuntimeConfig,
}

impl ProviderRuntimeConfig {
    fn from_env() -> Self {
        Self {
            hetzner_cloud: HetznerCloudRuntimeConfig::from_env(),
        }
    }
}

#[derive(Clone, Debug, Default)]
struct HetznerCloudRuntimeConfig {
    credential_source: Option<ProviderCredentialSource>,
    execute_enabled: bool,
}

impl HetznerCloudRuntimeConfig {
    fn from_env() -> Self {
        let credential_source = env_nonempty("PHAROS_HCLOUD_API_TOKEN_FILE")
            .map(|_| ProviderCredentialSource::File)
            .or_else(|| {
                env_nonempty("PHAROS_HCLOUD_API_TOKEN")
                    .map(|_| ProviderCredentialSource::Environment)
            });
        let execute_enabled = env_nonempty("PHAROS_HCLOUD_EXECUTE")
            .and_then(|value| parse_bool(&value))
            .unwrap_or(false);
        Self {
            credential_source,
            execute_enabled,
        }
    }

    fn is_configured(&self) -> bool {
        self.credential_source.is_some()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProviderCredentialSource {
    Environment,
    File,
}

fn provisioning_job_progress(
    request: &ProvisioningJobStartRequest,
    provider_runtime: &ProviderRuntimeConfig,
    now: i64,
) -> (ProvisioningJobState, Vec<ProvisioningProgressEntry>) {
    let mut progress = vec![ProvisioningProgressEntry {
        state: ProvisioningJobState::Planning,
        message: "Plan accepted; tracked job created.".to_string(),
        observed_at: now,
    }];

    match request.provider.as_str() {
        "hetzner-cloud" => {
            let hetzner = &provider_runtime.hetzner_cloud;
            if !hetzner.is_configured() {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor is not configured; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if !request.apply {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor requires explicit apply confirmation; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if !hetzner.execute_enabled {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor is configured but live execution is disabled; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            if missing_hetzner_create_inputs(request) {
                progress.push(ProvisioningProgressEntry {
                    state: ProvisioningJobState::Failed,
                    message: "Hetzner Cloud executor needs host, location, server type, image, and SSH key reference before create/apply; no provider resources were created.".to_string(),
                    observed_at: now,
                });
                return (ProvisioningJobState::Failed, progress);
            }
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Provisioning,
                message: "Hetzner Cloud create/apply is gated for the next executor slice; no provider resources were created.".to_string(),
                observed_at: now,
            });
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Failed,
                message: "Provider apply is not active in this build; retry after PHAROS-97 executor apply is enabled.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::Failed, progress)
        }
        "manual-import" => {
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Failed,
                message: "Manual import is routed to the existing-host flow; no provider resources were created.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::Failed, progress)
        }
        "existing-host" => existing_host_job_progress(request, now, progress),
        _ => (ProvisioningJobState::Failed, progress),
    }
}

fn existing_host_job_progress(
    request: &ProvisioningJobStartRequest,
    now: i64,
    mut progress: Vec<ProvisioningProgressEntry>,
) -> (ProvisioningJobState, Vec<ProvisioningProgressEntry>) {
    if request
        .host_name
        .as_deref()
        .is_none_or(|host_name| host_name.trim().is_empty())
    {
        progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Failed,
            message: "Existing-host setup needs a host name; no token files or host services were changed.".to_string(),
            observed_at: now,
        });
        return (ProvisioningJobState::Failed, progress);
    }
    if !request.apply {
        progress.push(ProvisioningProgressEntry {
            state: ProvisioningJobState::Failed,
            message: "Existing-host setup needs explicit confirmation; no token files or host services were changed.".to_string(),
            observed_at: now,
        });
        return (ProvisioningJobState::Failed, progress);
    }

    match request.template.as_str() {
        "manual-deferred" => {
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Bootstrapping,
                message: "Manual existing-host path recorded; no automated host changes were made."
                    .to_string(),
                observed_at: now,
            });
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::WaitingForHeartbeat,
                message: "Waiting for file/env-file beacon handoff and first heartbeat; keep existing token files unchanged unless rotation is explicit.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::WaitingForHeartbeat, progress)
        }
        "nixos-anywhere" | "native-systemd" => {
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Bootstrapping,
                message: "Automated existing-host apply was requested; no token files or host services were changed by this build.".to_string(),
                observed_at: now,
            });
            progress.push(ProvisioningProgressEntry {
                state: ProvisioningJobState::Failed,
                message: "Automated existing-host apply is not active yet; use manual/deferred handoff or retry after the executor slice.".to_string(),
                observed_at: now,
            });
            (ProvisioningJobState::Failed, progress)
        }
        _ => (ProvisioningJobState::Failed, progress),
    }
}

fn provisioning_job_handoff(request: &ProvisioningJobStartRequest) -> Option<ProvisioningHandoff> {
    if request.provider != "existing-host" {
        return None;
    }
    let method = match request.template.as_str() {
        "nixos-anywhere" => BootstrapMethod::NixosAnywhere,
        "native-systemd" => BootstrapMethod::NativeSystemd,
        "manual-deferred" => BootstrapMethod::Manual,
        _ => return None,
    };
    let interval = request.heartbeat_interval_secs.unwrap_or(60).max(1);
    let backup_steps = backup_enrollment_steps(request, method);
    match method {
        BootstrapMethod::NixosAnywhere => {
            let mut next_steps = vec![
                "Prepare the target flake/module so services.pharos-beacon reads a runtime credential file.".to_string(),
                "Run the NixOS bootstrap only after SSH, privilege, disk, and rollback checks pass.".to_string(),
                "Wait for the first heartbeat before marking onboarding complete.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method,
                status: "executor-pending".to_string(),
                title: "NixOS bootstrap handoff".to_string(),
                summary: "Declarative bootstrap is selected; automated apply stays disabled until the executor can stream credentials without exposing them.".to_string(),
                token_policy: "Beacon credentials must be installed through a runtime file or secret manager reference, never as a command-line value.".to_string(),
                secret_target: Some("/run/agenix/pharos-beacon-token".to_string()),
                command_ref: Some("nixos-anywhere plus services.pharos-beacon".to_string()),
                next_steps,
            })
        }
        BootstrapMethod::NativeSystemd => {
            let mut next_steps = vec![
                "Create the env file through an approved secret channel before starting the service.".to_string(),
                format!(
                    "Run the native installer with the selected host, role, and {interval}s heartbeat interval."
                ),
                "Start pharos-beacon and wait for the first heartbeat before marking onboarding complete.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method,
                status: "executor-pending".to_string(),
                title: "Native systemd beacon handoff".to_string(),
                summary: "Portable beacon install is selected; automated apply stays disabled until Pharos can write the env file over a safe channel.".to_string(),
                token_policy: "Beacon credentials belong in a root-owned env file or token file and must not be pasted into shell history.".to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.env".to_string()),
                command_ref: Some("scripts/install-pharos-beacon-systemd.sh".to_string()),
                next_steps,
            })
        }
        BootstrapMethod::Manual | BootstrapMethod::Deferred => {
            let mut next_steps = vec![
                "Install or enable pharos-beacon using the appropriate NixOS or native systemd path.".to_string(),
                format!("Configure the beacon to report with a {interval}s heartbeat interval."),
                "Confirm the first heartbeat appears in Pharos, then continue backup and location decisions.".to_string(),
            ];
            next_steps.extend(backup_steps);
            Some(ProvisioningHandoff {
                method: BootstrapMethod::Manual,
                status: "manual-handoff".to_string(),
                title: "Manual beacon handoff".to_string(),
                summary: "No automated host changes were made; Pharos is waiting for the operator-managed beacon install.".to_string(),
                token_policy: "Use a file or env-file secret handoff; never place the beacon credential in command arguments, chat, PPM, or logs.".to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.env".to_string()),
                command_ref: Some("scripts/install-pharos-beacon-systemd.sh or nixosModules.pharos-beacon".to_string()),
                next_steps,
            })
        }
    }
}

fn backup_enrollment_steps(
    request: &ProvisioningJobStartRequest,
    method: BootstrapMethod,
) -> Vec<String> {
    let intent = request.backup_intent.unwrap_or(BackupSetupIntent::Deferred);
    let nix_path = request
        .is_nix
        .unwrap_or(matches!(method, BootstrapMethod::NixosAnywhere));
    match intent {
        BackupSetupIntent::Required => {
            let mut steps = vec![
                "Backup required: keep onboarding open after first heartbeat until Pharos observes a first successful backup or a concrete failure.".to_string(),
            ];
            if nix_path {
                steps.push("For NixOS, prepare a declarative backup module proposal that reads repository and password material from agenix or Janus-rendered runtime files; do not embed secret values in Nix options or the Nix store.".to_string());
            } else {
                steps.push("For non-Nix hosts, install or observe a native backup job through a runtime secret file, then let pharos-beacon report sanitized backup evidence.".to_string());
            }
            steps
        }
        BackupSetupIntent::Optional => vec![
            "Backup optional: offer enrollment after first heartbeat, but allow onboarding to finish if the operator explicitly defers protection.".to_string(),
        ],
        BackupSetupIntent::External => vec![
            "Backups managed elsewhere: keep Pharos read-only and observe external backup evidence when the beacon can detect it.".to_string(),
        ],
        BackupSetupIntent::EnrollLater => vec![
            "Backup enrollment later: create a backup-pending follow-up after first heartbeat and do not block beacon onboarding.".to_string(),
        ],
        BackupSetupIntent::Absent => vec![
            "No backups requested: record the host as intentionally unprotected until the operator changes backup intent.".to_string(),
        ],
        BackupSetupIntent::Deferred => vec![
            "Backup decision pending: ask for backup intent again before considering onboarding complete.".to_string(),
        ],
    }
}

fn provisioning_setup_intent(
    request: &ProvisioningJobStartRequest,
) -> Option<ProvisioningSetupIntent> {
    Some(ProvisioningSetupIntent {
        backup: request.backup_intent.unwrap_or(BackupSetupIntent::Deferred),
        location: request.location_intent.unwrap_or(LocationSetupIntent::Auto),
    })
}

fn provisioning_backup_proposal(
    request: &ProvisioningJobStartRequest,
) -> Option<ProvisioningBackupProposal> {
    let intent = request.backup_intent.unwrap_or(BackupSetupIntent::Deferred);
    if !matches!(
        intent,
        BackupSetupIntent::Required | BackupSetupIntent::Optional | BackupSetupIntent::EnrollLater
    ) {
        return None;
    }

    let nix_path = request.is_nix.unwrap_or_else(|| {
        request.provider == "hetzner-cloud" || request.template == "nixos-anywhere"
    });
    if !nix_path {
        return None;
    }

    let host_slug = request
        .host_name
        .as_deref()
        .map(secret_ref_slug)
        .filter(|slug| !slug.is_empty())
        .unwrap_or_else(|| "pharos-host".to_string());
    let repository_file = format!("/run/agenix/{host_slug}-restic-repository");
    let password_file = format!("/run/agenix/{host_slug}-restic-password");
    let nix_module = format!(
        r#"{{
  config,
  lib,
  ...
}}:

{{
  services.pharos-beacon.extraEnvironment = {{
    PHAROS_BACKUP_MODE = "restic";
    PHAROS_BACKUP_ID = "restic-main";
    PHAROS_BACKUP_LABEL = "Restic backup";
    PHAROS_BACKUP_TARGET_LABEL = "off-box repository";
    PHAROS_BACKUP_SCHEDULE = "daily";
    PHAROS_BACKUP_STALE_AFTER_SECS = "129600";
    RESTIC_REPOSITORY_FILE = "{repository_file}";
    RESTIC_PASSWORD_FILE = "{password_file}";
  }};

  systemd.services.pharos-beacon.serviceConfig.ReadOnlyPaths = [
    "{repository_file}"
    "{password_file}"
  ];
}}
"#
    );

    Some(ProvisioningBackupProposal {
        kind: ProvisioningBackupProposalKind::NixosResticBeaconObservation,
        title: "NixOS restic backup proposal".to_string(),
        summary: "Declarative beacon backup observation using runtime agenix files for repository and password material.".to_string(),
        module_attribute: "services.pharos-beacon.extraEnvironment".to_string(),
        nix_module,
        secret_files: vec![
            ProvisioningBackupSecretFile {
                key: "restic-repository-file".to_string(),
                owner: SecretOwner::Agenix,
                path: repository_file,
                purpose: "Restic repository location, stored outside the Nix store.".to_string(),
            },
            ProvisioningBackupSecretFile {
                key: "restic-password-file".to_string(),
                owner: SecretOwner::Agenix,
                path: password_file,
                purpose: "Restic repository password, readable only by pharos-beacon.".to_string(),
            },
        ],
        next_steps: vec![
            "Create or reference the agenix files before deployment.".to_string(),
            "Review the NixOS module snippet in nixcfg and keep raw values out of Nix options.".to_string(),
            "Deploy the host, wait for the first heartbeat, then verify first backup evidence in Pharos.".to_string(),
        ],
    })
}

fn secret_ref_slug(value: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;
    for ch in value.trim().chars() {
        let next = if ch.is_ascii_alphanumeric() {
            last_dash = false;
            Some(ch.to_ascii_lowercase())
        } else if !last_dash {
            last_dash = true;
            Some('-')
        } else {
            None
        };
        if let Some(next) = next {
            out.push(next);
        }
    }
    out.trim_matches('-').to_string()
}

fn missing_hetzner_create_inputs(request: &ProvisioningJobStartRequest) -> bool {
    [
        request.host_name.as_deref(),
        request.location.as_deref(),
        request.server_type.as_deref(),
        request.image.as_deref(),
        request.ssh_key_ref.as_deref(),
    ]
    .iter()
    .any(|value| value.is_none_or(|value| value.trim().is_empty()))
}

#[derive(Debug, PartialEq, Eq)]
enum ProvisioningJobStartError {
    UnsupportedProvider,
    UnsupportedTemplate,
    InvalidJob,
}

impl std::fmt::Display for ProvisioningJobStartError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedProvider => write!(f, "unsupported setup provider"),
            Self::UnsupportedTemplate => write!(f, "unsupported setup template"),
            Self::InvalidJob => write!(f, "provisioning job contract failed validation"),
        }
    }
}

fn valid_setup_provider(provider: &str) -> bool {
    matches!(
        provider,
        "hetzner-cloud" | "manual-import" | "existing-host"
    )
}

fn valid_setup_template(provider: &str, template: &str) -> bool {
    matches!(
        (provider, template),
        ("hetzner-cloud", "hetzner-small-nixos")
            | ("hetzner-cloud", "hetzner-lab")
            | ("hetzner-cloud", "bring-own-plan")
            | ("manual-import", "manual-import")
            | ("existing-host", "nixos-anywhere")
            | ("existing-host", "native-systemd")
            | ("existing-host", "manual-deferred")
    )
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlan {
    schema: &'static str,
    version: u16,
    provider: &'static str,
    template: &'static str,
    strategy: &'static str,
    approach: &'static str,
    summary: &'static str,
    docs: Vec<SetupProviderPlanDoc>,
    resources: Vec<SetupProviderPlanResource>,
    steps: Vec<SetupProviderPlanStep>,
    secret_boundary: Vec<SetupProviderPlanSecretBoundary>,
    handoffs: Vec<SetupProviderPlanHandoff>,
    runtime_checks: Vec<&'static str>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlanDoc {
    label: &'static str,
    url: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlanResource {
    key: &'static str,
    kind: &'static str,
    required: bool,
    api: &'static str,
    detail: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlanStep {
    key: &'static str,
    title: &'static str,
    detail: &'static str,
    status: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlanSecretBoundary {
    key: &'static str,
    source: &'static str,
    rule: &'static str,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SetupProviderPlanHandoff {
    key: &'static str,
    target: &'static str,
    detail: &'static str,
}

fn setup_provider_plan(
    provider: &str,
    template: &str,
) -> Result<SetupProviderPlan, ProvisioningJobStartError> {
    if !valid_setup_provider(provider) {
        return Err(ProvisioningJobStartError::UnsupportedProvider);
    }
    if !valid_setup_template(provider, template) {
        return Err(ProvisioningJobStartError::UnsupportedTemplate);
    }
    match (provider, template) {
        ("hetzner-cloud", "hetzner-small-nixos")
        | ("hetzner-cloud", "hetzner-lab")
        | ("hetzner-cloud", "bring-own-plan") => Ok(hetzner_cloud_setup_plan(template)),
        ("manual-import", "manual-import") => Ok(manual_import_setup_plan()),
        _ => Err(ProvisioningJobStartError::UnsupportedTemplate),
    }
}

fn hetzner_cloud_setup_plan(template: &str) -> SetupProviderPlan {
    SetupProviderPlan {
        schema: "inspr.pharos.setup-provider-plan.v1",
        version: 1,
        provider: "hetzner-cloud",
        template: match template {
            "hetzner-lab" => "hetzner-lab",
            "bring-own-plan" => "bring-own-plan",
            _ => "hetzner-small-nixos",
        },
        strategy: "hcloud-api-plus-nixos-anywhere",
        approach: "Use direct Hetzner Cloud API execution for live jobs; keep the hcloud Terraform/OpenTofu provider as the plan-compatible reference, not as a required state backend.",
        summary: "Plan Hetzner Cloud resources through the Cloud API, then bootstrap NixOS with nixos-anywhere before waiting for the first beacon heartbeat.",
        docs: vec![
            SetupProviderPlanDoc {
                label: "Hetzner Cloud API reference",
                url: "https://docs.hetzner.cloud/reference/cloud",
            },
            SetupProviderPlanDoc {
                label: "Hetzner Cloud API getting started",
                url: "https://docs.hetzner.cloud/",
            },
            SetupProviderPlanDoc {
                label: "Hetzner Cloud Terraform provider",
                url: "https://registry.terraform.io/providers/hetznercloud/hcloud/latest/docs",
            },
            SetupProviderPlanDoc {
                label: "nixos-anywhere quickstart",
                url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
            },
        ],
        resources: vec![
            SetupProviderPlanResource {
                key: "server",
                kind: "hetzner-cloud-server",
                required: true,
                api: "GET /server_types, GET /locations, GET /images, POST /servers",
                detail: "Select server type, location, and bootstrap-capable base image at plan time, then create the server only after operator confirmation.",
            },
            SetupProviderPlanResource {
                key: "ssh_key",
                kind: "hetzner-cloud-ssh-key",
                required: true,
                api: "GET /ssh_keys, POST /ssh_keys",
                detail: "Attach or create an SSH public key only; private key material stays outside provider state and outside Pharos job records.",
            },
            SetupProviderPlanResource {
                key: "firewall",
                kind: "hetzner-cloud-firewall",
                required: true,
                api: "GET /firewalls, POST /firewalls, POST /firewalls/{id}/actions/apply_to_resources",
                detail: "Apply a minimal firewall profile for SSH/bootstrap and Pharos beacon egress; rules are visible in the review plan before creation.",
            },
            SetupProviderPlanResource {
                key: "volume",
                kind: "hetzner-cloud-volume",
                required: false,
                api: "GET /volumes, POST /volumes",
                detail: "Optional data volume; availability, size, attachment, and cost are verified at plan time before inclusion.",
            },
            SetupProviderPlanResource {
                key: "backup_or_snapshot",
                kind: "hetzner-cloud-backup-snapshot",
                required: false,
                api: "GET /pricing, POST /servers/{id}/actions/create_image",
                detail: "Optional provider backup or initial snapshot handoff; pricing and support are runtime checks, not hardcoded promises.",
            },
        ],
        steps: vec![
            SetupProviderPlanStep {
                key: "provider_resources",
                title: "Provider resources",
                detail: "Plan or create the server, SSH public key attachment, labels, and a minimal firewall through Hetzner Cloud API calls.",
                status: "planned",
            },
            SetupProviderPlanStep {
                key: "runtime_verify",
                title: "Runtime verification",
                detail: "Fetch server types, images, locations, and prices at plan time; do not hardcode price or availability promises.",
                status: "required",
            },
            SetupProviderPlanStep {
                key: "bootstrap",
                title: "NixOS bootstrap",
                detail: "Boot a runtime-verified Linux base with SSH access, then run nixos-anywhere from a Pharos/nixcfg flake profile.",
                status: "planned",
            },
            SetupProviderPlanStep {
                key: "beacon_handoff",
                title: "Beacon handoff",
                detail: "Install pharos-beacon using a token file or secret reference; raw tokens never appear in job progress, logs, or URLs.",
                status: "protected",
            },
            SetupProviderPlanStep {
                key: "observable_finish",
                title: "Observable finish",
                detail: "Wait for the first valid heartbeat, then mark backup enrollment and location source as complete or explicitly pending.",
                status: "waiting",
            },
        ],
        secret_boundary: vec![
            SetupProviderPlanSecretBoundary {
                key: "provider_api_token",
                source: "runtime secret reference",
                rule: "Use only for the provider executor call; never serialize into plan JSON, PPM notes, logs, progress messages, URLs, or OpenTofu state.",
            },
            SetupProviderPlanSecretBoundary {
                key: "ssh_private_key",
                source: "operator or agent runtime",
                rule: "Only public keys may be sent to Hetzner Cloud; private key material must stay in the runtime secret store.",
            },
            SetupProviderPlanSecretBoundary {
                key: "pharos_registration_and_beacon",
                source: "Pharos/Janus handoff",
                rule: "Registration and per-host beacon values are one-time or secret-store handoffs; job output may show refs and states only.",
            },
        ],
        handoffs: vec![
            SetupProviderPlanHandoff {
                key: "provider_executor",
                target: "PHAROS-97",
                detail: "Consumes this plan contract to call Hetzner Cloud and persist safe resource identifiers plus cleanup guidance.",
            },
            SetupProviderPlanHandoff {
                key: "nixos_bootstrap",
                target: "nixos-anywhere",
                detail: "Runs against the freshly reachable server using a reviewed flake profile and generated hardware facts.",
            },
            SetupProviderPlanHandoff {
                key: "beacon_token",
                target: "Pharos/Janus",
                detail: "Installs pharos-beacon with a token file or managed secret ref, then waits for first heartbeat before live state.",
            },
            SetupProviderPlanHandoff {
                key: "backup_location",
                target: "PHAROS-83/86",
                detail: "Leaves backup enrollment and location source as explicit pending work when they are not completed during provisioning.",
            },
        ],
        runtime_checks: vec![
            "server_type availability",
            "location availability",
            "image/base OS availability",
            "current provider price",
            "SSH key and firewall compatibility",
            "backup/snapshot option availability",
        ],
    }
}

fn manual_import_setup_plan() -> SetupProviderPlan {
    SetupProviderPlan {
        schema: "inspr.pharos.setup-provider-plan.v1",
        version: 1,
        provider: "manual-import",
        template: "manual-import",
        strategy: "operator-managed-import",
        approach: "Keep provider creation external; Pharos plans the import/bootstrap checks and records only safe runtime observations.",
        summary: "Keep provider creation outside Pharos, then import and bootstrap the already-created host.",
        docs: vec![SetupProviderPlanDoc {
            label: "nixos-anywhere quickstart",
            url: "https://github.com/nix-community/nixos-anywhere/blob/main/docs/quickstart.md",
        }],
        resources: vec![
            SetupProviderPlanResource {
                key: "existing_server",
                kind: "operator-owned-server",
                required: true,
                api: "external",
                detail: "Operator supplies an already-created host and SSH route; Pharos does not create provider resources for this path.",
            },
            SetupProviderPlanResource {
                key: "ssh_access",
                kind: "ssh-route",
                required: true,
                api: "preflight",
                detail: "Verify reachability and privilege level before bootstrap; private keys remain outside Pharos records.",
            },
        ],
        steps: vec![
            SetupProviderPlanStep {
                key: "provider_resources",
                title: "Provider resources",
                detail: "Operator creates or keeps the server with the external provider; Pharos stores no provider credentials for this path.",
                status: "external",
            },
            SetupProviderPlanStep {
                key: "bootstrap",
                title: "Bootstrap",
                detail: "Run existing-host preflight, then choose NixOS, portable beacon, or manual/deferred bootstrap.",
                status: "handoff",
            },
            SetupProviderPlanStep {
                key: "observable_finish",
                title: "Observable finish",
                detail: "Wait for first heartbeat and record backup/location decisions explicitly.",
                status: "waiting",
            },
        ],
        secret_boundary: vec![
            SetupProviderPlanSecretBoundary {
                key: "ssh_private_key",
                source: "operator runtime",
                rule: "Use only for preflight/bootstrap; never serialize private key material into Pharos job state.",
            },
            SetupProviderPlanSecretBoundary {
                key: "pharos_registration_and_beacon",
                source: "Pharos/Janus handoff",
                rule: "Registration and beacon values stay in runtime secret handling; UI and progress text show states only.",
            },
        ],
        handoffs: vec![
            SetupProviderPlanHandoff {
                key: "existing_host_preflight",
                target: "PHAROS-84/85",
                detail: "Chooses SSH/bootstrap method and validates the host before installing or configuring the beacon.",
            },
            SetupProviderPlanHandoff {
                key: "backup_location",
                target: "PHAROS-86",
                detail: "Records backup and location setup decisions after the imported host reports.",
            },
        ],
        runtime_checks: vec![
            "SSH reachability",
            "OS/bootstrap capability",
            "Pharos endpoint reachability",
        ],
    }
}

fn provisioning_jobs_path(host_store_path: Option<&Path>) -> Option<PathBuf> {
    if let Ok(path) = std::env::var("PHAROS_PROVISIONING_JOBS_DB") {
        let path = path.trim();
        if !path.is_empty() {
            return Some(PathBuf::from(path));
        }
    }
    host_store_path.map(derived_provisioning_jobs_path)
}

fn derived_provisioning_jobs_path(host_store_path: &Path) -> PathBuf {
    let file_name = host_store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("pharos.json");
    host_store_path.with_file_name(format!("{file_name}.provisioning-jobs.json"))
}

#[derive(Clone)]
struct BeaconAuth {
    registration_token: Option<String>,
    require_report_token: bool,
    report_token_mode: BeaconTokenMode,
    janus_token_hash_sources: Vec<JanusTokenHashSource>,
    local_register_enabled: bool,
}

impl BeaconAuth {
    fn from_env() -> Self {
        let registration_token = env_nonempty("PHAROS_REGISTRATION_TOKEN");
        let janus_token_hash_sources = janus_token_hash_sources_from_env();
        let report_token_mode = env_nonempty("PHAROS_BEACON_TOKEN_MODE")
            .and_then(|s| parse_beacon_token_mode(&s))
            .unwrap_or({
                if !janus_token_hash_sources.is_empty() {
                    BeaconTokenMode::Dual
                } else {
                    BeaconTokenMode::Local
                }
            });
        let require_report_token = std::env::var("PHAROS_REQUIRE_BEACON_TOKEN")
            .ok()
            .and_then(|s| parse_bool(&s))
            .unwrap_or(
                registration_token.is_some()
                    || !janus_token_hash_sources.is_empty()
                    || report_token_mode == BeaconTokenMode::Janus,
            );
        let local_register_enabled = std::env::var("PHAROS_ALLOW_LOCAL_REGISTER")
            .ok()
            .and_then(|s| parse_bool(&s))
            .unwrap_or(report_token_mode != BeaconTokenMode::Janus);
        Self {
            registration_token,
            require_report_token,
            report_token_mode,
            janus_token_hash_sources,
            local_register_enabled,
        }
    }

    fn registration_status(&self, headers: &HeaderMap) -> RegistrationAuth {
        if !self.local_register_enabled {
            return RegistrationAuth::Disabled;
        }
        let Some(expected) = &self.registration_token else {
            return RegistrationAuth::NotConfigured;
        };
        match bearer_token(headers) {
            Some(actual) if constant_time_eq(actual, expected) => RegistrationAuth::Allowed,
            _ => RegistrationAuth::Denied,
        }
    }

    fn report_token_status(&self, store: &Store, host: &str, token: &str) -> ReportTokenAuth {
        let expected_hash = token_hash(token);
        match self.report_token_mode {
            BeaconTokenMode::Local => {
                if local_token_matches(store, host, &expected_hash) {
                    ReportTokenAuth::Allowed
                } else {
                    ReportTokenAuth::Denied
                }
            }
            BeaconTokenMode::Dual => {
                if local_token_matches(store, host, &expected_hash) {
                    return ReportTokenAuth::Allowed;
                }
                match self.janus_token_matches(host, &expected_hash) {
                    Ok(true) => ReportTokenAuth::Allowed,
                    Ok(false) => ReportTokenAuth::Denied,
                    Err(err) => ReportTokenAuth::Unavailable(err),
                }
            }
            BeaconTokenMode::Janus => match self.janus_token_matches(host, &expected_hash) {
                Ok(true) => ReportTokenAuth::Allowed,
                Ok(false) => ReportTokenAuth::Denied,
                Err(err) => ReportTokenAuth::Unavailable(err),
            },
        }
    }

    fn janus_token_matches(
        &self,
        host: &str,
        expected_hash: &str,
    ) -> Result<bool, JanusTokenHashError> {
        let hashes = load_janus_token_hashes(&self.janus_token_hash_sources)?;
        Ok(hashes
            .get(host)
            .is_some_and(|stored| constant_time_eq(stored, expected_hash)))
    }
}

#[derive(Clone)]
enum JanusTokenHashSource {
    File(PathBuf),
    Dir(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BeaconTokenMode {
    Local,
    Dual,
    Janus,
}

enum RegistrationAuth {
    Allowed,
    Denied,
    Disabled,
    NotConfigured,
}

enum ReportTokenAuth {
    Allowed,
    Denied,
    Unavailable(JanusTokenHashError),
}

#[derive(Clone)]
struct AlertNotifier {
    webhook_url: Option<String>,
    client: reqwest::Client,
    notified_down_hosts: Arc<Mutex<BTreeSet<String>>>,
    check_interval: Duration,
}

impl AlertNotifier {
    fn from_env() -> Self {
        let webhook_url = alert_webhook_url(
            std::env::var("PHAROS_ALERT_WEBHOOK_URL").ok(),
            std::env::var("WATCHTOWER_NOTIFICATION_URL").ok(),
            std::env::var("PHAROS_ALERT_WEBHOOK_ENV_FILE").ok(),
        );
        let check_interval = std::env::var("PHAROS_ALERT_CHECK_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 5)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_CHECK_INTERVAL);
        let timeout = std::env::var("PHAROS_ALERT_WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 1)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_WEBHOOK_TIMEOUT);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            webhook_url,
            client,
            notified_down_hosts: Arc::new(Mutex::new(BTreeSet::new())),
            check_interval,
        }
    }

    fn enabled(&self) -> bool {
        self.webhook_url.is_some()
    }

    async fn check_store(&self, store: &Store, now: i64) {
        let alerts = silent_beacon_alerts(&store.list(), now);
        let down_hosts = alerts
            .iter()
            .map(|alert| alert.host.clone())
            .collect::<BTreeSet<_>>();
        let candidates = {
            let mut notified = self
                .notified_down_hosts
                .lock()
                .expect("alert notifier mutex poisoned");
            notified.retain(|host| down_hosts.contains(host));
            alerts
                .into_iter()
                .filter(|alert| !notified.contains(&alert.host))
                .collect::<Vec<_>>()
        };

        for alert in candidates {
            if self.send(&alert).await {
                self.notified_down_hosts
                    .lock()
                    .expect("alert notifier mutex poisoned")
                    .insert(alert.host.clone());
            }
        }
    }

    async fn send(&self, alert: &SilentBeaconAlert) -> bool {
        let Some(url) = self.webhook_url.as_deref() else {
            return false;
        };
        let Ok(parsed_url) = Url::parse(url) else {
            tracing::warn!(host = %alert.host, "silent beacon alert target URL is invalid");
            return false;
        };
        match parsed_url.scheme() {
            "http" | "https" => self.send_http_alert(url, alert).await,
            "telegram" => self.send_telegram_alert(&parsed_url, alert).await,
            _ => {
                tracing::warn!(
                    host = %alert.host,
                    scheme = %parsed_url.scheme(),
                    "silent beacon alert target URL scheme is unsupported"
                );
                false
            }
        }
    }

    async fn send_http_alert(&self, url: &str, alert: &SilentBeaconAlert) -> bool {
        match self.client.post(url).json(alert).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::warn!(
                    host = %alert.host,
                    age_seconds = alert.age_seconds,
                    "silent beacon alert notification sent"
                );
                true
            }
            Ok(response) => {
                tracing::warn!(
                    host = %alert.host,
                    status = %response.status(),
                    "silent beacon alert webhook returned non-success"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    host = %alert.host,
                    "silent beacon alert webhook request failed"
                );
                false
            }
        }
    }

    async fn send_telegram_alert(&self, url: &Url, alert: &SilentBeaconAlert) -> bool {
        let Some(target) = TelegramAlertTarget::from_url(url) else {
            tracing::warn!(host = %alert.host, "silent beacon Telegram alert target is invalid");
            return false;
        };
        let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", target.token);
        let text = telegram_alert_text(alert);
        let mut sent_all = true;

        for chat_id in target.chats {
            let payload = json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true,
            });
            match self.client.post(&endpoint).json(&payload).send().await {
                Ok(response) if response.status().is_success() => {
                    tracing::warn!(
                        host = %alert.host,
                        age_seconds = alert.age_seconds,
                        "silent beacon Telegram alert notification sent"
                    );
                }
                Ok(response) => {
                    tracing::warn!(
                        host = %alert.host,
                        status = %response.status(),
                        "silent beacon Telegram alert returned non-success"
                    );
                    sent_all = false;
                }
                Err(_) => {
                    tracing::warn!(
                        host = %alert.host,
                        "silent beacon Telegram alert request failed"
                    );
                    sent_all = false;
                }
            }
        }

        sent_all
    }
}

fn spawn_alert_loop(state: AppState, notifier: AlertNotifier) {
    if !notifier.enabled() {
        tracing::info!("silent beacon alert webhook not configured; notifications disabled");
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(notifier.check_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            notifier.check_store(&state.store, now_unix()).await;
        }
    });
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SilentBeaconAlert {
    schema: &'static str,
    level: &'static str,
    kind: &'static str,
    host: String,
    role: String,
    last_seen: i64,
    age_seconds: i64,
    heartbeat_interval_secs: u64,
    as_of: i64,
    summary: String,
    next_action: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct TelegramAlertTarget {
    token: String,
    chats: Vec<String>,
}

impl TelegramAlertTarget {
    fn from_url(url: &Url) -> Option<Self> {
        if url.scheme() != "telegram" {
            return None;
        }
        let username = url.username();
        if username.is_empty() {
            return None;
        }
        let token = match url.password() {
            Some(password) if !password.is_empty() => format!("{username}:{password}"),
            _ => username.to_string(),
        };
        let chats = url
            .query_pairs()
            .find_map(|(key, value)| {
                if key == "chats" || key == "channels" {
                    Some(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|chat| !chat.is_empty())
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
            .filter(|chats| !chats.is_empty())?;

        Some(Self { token, chats })
    }
}

fn telegram_alert_text(alert: &SilentBeaconAlert) -> String {
    format!(
        "Pharos critical alert\nHost: {}\nProblem: {}\nAge: {}\nNext: {}",
        alert.host,
        alert.summary,
        duration_label(alert.age_seconds),
        alert.next_action
    )
}

fn silent_beacon_alerts(hosts: &[Host], now: i64) -> Vec<SilentBeaconAlert> {
    let mut alerts = hosts
        .iter()
        .filter_map(|host| {
            let last_seen = host.last_seen?;
            if liveness(host.last_seen, host.heartbeat_interval_secs, now) != Liveness::Down {
                return None;
            }
            let age_seconds = now.saturating_sub(last_seen);
            let interval = host.heartbeat_interval_secs.unwrap_or(60);
            Some(SilentBeaconAlert {
                schema: "inspr.pharos.alert.v1",
                level: "critical",
                kind: "silent_heartbeat",
                host: host.name.clone(),
                role: host.role.clone(),
                last_seen,
                age_seconds,
                heartbeat_interval_secs: interval,
                as_of: now,
                summary: format!(
                    "{} has not reported to Pharos for {}.",
                    host.name,
                    duration_label(age_seconds)
                ),
                next_action: "Check host power, network, and pharos-beacon.",
            })
        })
        .collect::<Vec<_>>();
    alerts.sort_by(|left, right| left.host.cmp(&right.host));
    alerts
}

fn non_empty_env_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn alert_webhook_url(
    pharos_url: Option<String>,
    watchtower_url: Option<String>,
    env_file: Option<String>,
) -> Option<String> {
    pharos_url
        .as_deref()
        .and_then(non_empty_env_value)
        .or_else(|| watchtower_url.as_deref().and_then(non_empty_env_value))
        .or_else(|| {
            env_file
                .as_deref()
                .and_then(alert_webhook_url_from_env_file)
        })
}

fn alert_webhook_url_from_env_file(path: &str) -> Option<String> {
    let path = non_empty_env_value(path)?;
    let contents = fs::read_to_string(path).ok()?;
    env_file_value(&contents, "WATCHTOWER_NOTIFICATION_URL")
        .as_deref()
        .and_then(non_empty_env_value)
}

fn env_file_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(unquote_env_value(value.trim()).to_string())
    })
}

fn unquote_env_value(value: &str) -> &str {
    if value.len() < 2 {
        return value;
    }
    let bytes = value.as_bytes();
    let quoted = (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'');
    if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

const FLEET_HORIZON_PNG: &[u8] = include_bytes!("../assets/fleet-horizon.png");
const SIDEBAR_LIGHTHOUSE_PNG: &[u8] = include_bytes!("../assets/sidebar-lighthouse.png");
const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="5" fill="#f7fbfc"/><path d="M10.5 5 12 2.5 13.5 5" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><rect x="10" y="5" width="4" height="3" rx=".5" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 8 8.6 20M14 8l1.4 12M9.2 13.5h5.6M7 20h10M6 22h12M16.6 6.4l2.4-1M7.4 6.4l-2.4-1" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--card:#ffffff;--card-soft:rgba(255,255,255,.82);--accent:#1f7fb5;--sea:#159e99;--sun:#d69b31;--live:#25845f;--stale:#b26a00;--down:#bf3a35;--wait:#8997a3;--side:232px}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%);min-height:100vh;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-3;background:radial-gradient(circle at 86% 5%,rgba(214,155,49,.16),transparent 12rem),radial-gradient(circle at 18% 28%,rgba(21,158,153,.08),transparent 18rem),linear-gradient(180deg,rgba(255,255,255,.94),rgba(239,249,250,.82));pointer-events:none}
.app-shell{min-height:100vh;display:grid;grid-template-columns:var(--side) minmax(0,1fr)}
.sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:24px;padding:30px 18px 18px;border-right:1px solid rgba(211,225,233,.78);background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(247,252,253,.82));box-shadow:12px 0 38px rgba(45,75,95,.05);overflow:hidden}
.sidebar:before{content:"";position:absolute;left:-18%;right:-20%;bottom:-10%;height:66%;background:url('/assets/sidebar-lighthouse.png') left bottom/118% auto no-repeat;opacity:.78;pointer-events:none;-webkit-mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%);mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%)}
.side-brand,.side-nav,.side-foot{position:relative;z-index:1}.side-brand{display:flex;align-items:center;gap:13px;padding:0 12px}.side-mark{display:grid;place-items:center;width:36px;height:50px;color:var(--sun)}.side-mark .ico{width:31px;height:31px}.side-logo{font-family:Georgia,"Times New Roman",serif;font-size:22px;letter-spacing:.18em;color:#14304b;text-transform:uppercase}
.side-nav{display:grid;gap:7px}.side-link{display:grid;grid-template-columns:23px minmax(0,1fr) auto;align-items:center;gap:11px;min-height:46px;padding:0 13px;border-radius:7px;color:#294761;text-decoration:none;font-weight:520}.side-link[aria-current="page"]{background:rgba(223,241,249,.76);color:#0f4f80}.side-link .ico{width:18px;height:18px}.side-badge{display:grid;place-items:center;min-width:24px;height:24px;border-radius:999px;background:#ffe7bb;color:#9a5b00;font-size:12px;font-weight:700}
.side-foot{margin-top:auto;display:flex;align-items:center;justify-content:space-between;gap:9px;min-height:48px;padding:7px 8px 7px 11px;border:1px solid rgba(211,225,233,.70);border-radius:999px;background:linear-gradient(180deg,rgba(255,255,255,.78),rgba(247,252,253,.62));box-shadow:0 10px 26px rgba(45,75,95,.12);-webkit-backdrop-filter:blur(10px) saturate(1.08);backdrop-filter:blur(10px) saturate(1.08);color:#294761;font-size:13px}.side-user{min-width:0;display:flex;align-items:center;gap:9px;font-weight:650;text-shadow:0 1px 0 rgba(255,255,255,.76)}.side-user:before{content:"";flex:0 0 auto;width:24px;height:24px;border-radius:50%;border:1px solid rgba(214,155,49,.38);background:radial-gradient(circle,#fff 0 33%,rgba(214,155,49,.18) 36%,transparent 68%)}.side-user span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.side-logout{display:grid;place-items:center;flex:0 0 auto;width:30px;height:30px;border-radius:50%;color:#4c6780;text-decoration:none}.side-logout:hover{background:rgba(223,241,249,.78);color:#0f4f80}.side-logout .ico{width:16px;height:16px}
main{width:min(1280px,100%);margin:0;padding:34px 34px 56px}
.ico{width:16px;height:16px;display:inline-block;vertical-align:middle;flex:0 0 auto}
.top{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:22px;min-height:118px;margin:-10px 0 20px;padding:10px 0 18px;overflow:hidden}
.top-art{position:absolute;inset:0;z-index:0;opacity:.84;pointer-events:none;--edge-fade-x:30%;--edge-fade-y:20%;-webkit-mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade-x),#000 calc(100% - var(--edge-fade-x)),transparent 100%);mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade-x),#000 calc(100% - var(--edge-fade-x)),transparent 100%)}
.top-art:before{content:"";position:absolute;inset:0;background:url('/assets/fleet-horizon.png') center center/100% auto no-repeat;-webkit-mask-image:linear-gradient(to bottom,transparent 0,#000 var(--edge-fade-y),#000 calc(100% - var(--edge-fade-y)),transparent 100%);mask-image:linear-gradient(to bottom,transparent 0,#000 var(--edge-fade-y),#000 calc(100% - var(--edge-fade-y)),transparent 100%)}
.top>:not(.top-art){position:relative;z-index:1}.top-art{z-index:0}.brand{display:flex;align-items:center;gap:12px;margin:0 0 4px}
.brand h1{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:31px;line-height:1.05;font-weight:500;letter-spacing:0;color:#12304b}
.fleet{display:flex;align-items:center;gap:10px;margin:8px 0 0;color:var(--muted);font-size:14px}
.wave{width:44px;height:10px;color:var(--sea);opacity:.78}
.asof{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:22px}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 18px}
.metric{appearance:none;position:relative;min-width:0;display:grid;grid-template-columns:50px minmax(0,1fr);align-items:center;column-gap:12px;text-align:left;background:rgba(255,255,255,.82);border:1px solid rgba(210,226,234,.78);border-radius:8px;padding:14px 16px;box-shadow:0 12px 30px rgba(54,88,108,.06);backdrop-filter:blur(10px);cursor:pointer}
.metric:before{content:"";grid-row:1/3;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--metric-color,var(--wait)) 14%,white);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--metric-color,var(--wait)) 20%,transparent)}
.metric b{display:block;font-family:Georgia,"Times New Roman",serif;font-size:29px;line-height:1;font-weight:500;color:var(--ink)}
.metric span{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.metric.live{--metric-color:var(--sea)}.metric.stale{--metric-color:var(--sun)}.metric.down{--metric-color:var(--down)}
.metric.live{border-color:rgba(37,132,95,.22)}.metric.stale{border-color:rgba(178,106,0,.24)}.metric.down{border-color:rgba(191,58,53,.24)}
.metric:hover,.metric[aria-pressed="true"]{border-color:color-mix(in srgb,var(--metric-color,var(--accent)) 38%,rgba(210,226,234,.78));box-shadow:0 14px 32px rgba(54,88,108,.08),0 0 0 3px color-mix(in srgb,var(--metric-color,var(--accent)) 9%,transparent);transform:translateY(-1px)}
.metric:focus-visible{outline:2px solid color-mix(in srgb,var(--metric-color,var(--accent)) 38%,transparent);outline-offset:3px}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 18px;padding:9px;background:rgba(255,255,255,.72);border:1px solid rgba(210,226,234,.78);border-radius:8px;box-shadow:0 12px 30px rgba(54,88,108,.05);backdrop-filter:blur(10px)}
.toolbar-left,.toolbar-right{display:flex;align-items:center;gap:10px;min-width:0}
.seg{display:inline-flex;align-items:center;padding:3px;border:1px solid rgba(210,226,234,.86);border-radius:7px;background:rgba(244,250,251,.76)}
.seg button{appearance:none;border:0;background:transparent;color:var(--muted);display:grid;place-items:center;width:30px;height:28px;border-radius:6px;cursor:pointer}
.seg button[aria-pressed="true"]{background:#fff;color:var(--accent);box-shadow:0 1px 5px rgba(45,75,95,.12)}
.seg .ico{width:16px;height:16px}
.arrange{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;white-space:nowrap}
.arrange select{appearance:none;border:0;background:transparent;color:var(--ink);font:inherit;font-weight:600;outline:none;padding-right:2px;cursor:pointer}
.search{position:relative;min-width:210px;color:var(--muted)}
.search .ico{position:absolute;left:10px;top:50%;width:15px;height:15px;transform:translateY(-50%)}
.search input{width:100%;height:34px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:13px;padding:0 10px 0 32px;outline:none}
.search input:focus{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:18px}
.card{--state:var(--wait);position:relative;min-height:264px;display:flex;flex-direction:column;background:rgba(255,255,255,.88);border:1px solid rgba(211,225,233,.86);border-radius:8px;padding:15px 16px 14px;box-shadow:0 14px 32px rgba(45,75,95,.08);overflow:hidden}
.card:before{content:"";position:absolute;left:16px;right:16px;top:58px;height:1px;background:linear-gradient(90deg,transparent,rgba(31,127,181,.16),transparent);pointer-events:none}
.onboard-tile{appearance:none;position:relative;min-height:264px;display:flex;flex-direction:column;align-items:flex-start;justify-content:space-between;gap:18px;padding:18px;border:1px dashed rgba(214,155,49,.48);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.82),rgba(240,250,250,.74));box-shadow:0 14px 32px rgba(45,75,95,.05),inset 0 0 0 1px rgba(255,255,255,.52);color:var(--ink);text-align:left;cursor:pointer;overflow:hidden}
.onboard-tile:before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 72% 22%,rgba(214,155,49,.12),transparent 34%),linear-gradient(160deg,transparent 48%,rgba(21,158,153,.08));pointer-events:none}
.onboard-tile>*{position:relative;z-index:1}.onboard-tile:hover,.onboard-tile:focus-visible{border-style:solid;border-color:rgba(214,155,49,.64);box-shadow:0 18px 38px rgba(45,75,95,.09),0 0 0 4px rgba(214,155,49,.08);outline:0;transform:translateY(-1px)}
.onboard-mark{display:grid;place-items:center;width:42px;height:42px;border:1px solid rgba(214,155,49,.30);border-radius:50%;background:rgba(255,255,255,.78);color:var(--sun);box-shadow:0 0 0 8px rgba(214,155,49,.06)}.onboard-mark .ico{width:20px;height:20px}
.onboard-copy strong{display:block;margin:0 0 4px;font-size:18px;line-height:1.15;color:var(--ink)}.onboard-copy span{display:block;color:var(--muted);font-size:13px}
.onboard-foot{display:flex;align-items:center;gap:8px;color:#0f4f80;font-size:12px;font-weight:760}.onboard-foot:after{content:"";width:24px;height:1px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.60),transparent)}
[data-live="live"]{--state:var(--live)}[data-live="stale"]{--state:var(--stale)}[data-live="down"]{--state:var(--down)}[data-live="awaiting_first_heartbeat"]{--state:var(--wait)}
.card.light{border-color:rgba(214,155,49,.28);box-shadow:0 14px 32px rgba(45,75,95,.08),inset 0 0 0 1px rgba(214,155,49,.08)}
.pharos-mark{position:absolute;right:10px;top:7px;z-index:0;display:grid;place-items:center;width:58px;height:58px;color:rgba(214,155,49,.14);pointer-events:none}
.pharos-mark .ico{width:50px;height:50px;stroke-width:1.35}
.card-head{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
.card-actions{position:relative;z-index:2;display:flex;align-items:center;gap:5px;flex:0 0 auto}
.host{display:flex;align-items:center;gap:9px;min-width:0}
.nix{display:grid;place-items:center;width:30px;height:30px;border:1px solid rgba(102,121,139,.18);border-radius:50%;color:var(--accent);background:rgba(241,248,250,.72);transition:border-color .2s ease,box-shadow .2s ease}
.card.has-settings .nix,.list tr.has-settings .nix{border-width:2px;border-color:var(--host-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--host-color) 13%,transparent),0 0 17px color-mix(in srgb,var(--host-color) 18%,transparent);background:linear-gradient(180deg,rgba(255,255,255,.92),color-mix(in srgb,var(--host-color) 8%,#f5fbfc))}
.name{font-weight:650;font-size:16px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.role{font-size:12px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.signal{--signal-color:var(--wait);display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:52px;min-height:24px;color:var(--signal-color);font-size:13px;font-weight:720;white-space:nowrap;text-align:center}
.signal[data-signal-level="good"]{--signal-color:var(--live)}.signal[data-signal-level="warn"]{--signal-color:var(--stale)}.signal[data-signal-level="down"]{--signal-color:var(--down)}.signal[data-signal-level="wait"]{--signal-color:var(--wait)}
.signal-window{appearance:none;border:0;background:transparent;color:var(--muted);font:inherit;font-size:11px;font-weight:700;padding:0 1px;cursor:pointer}
.signal-window:hover{color:var(--ink);text-decoration:underline;text-underline-offset:2px}.signal-window:focus-visible{outline:2px solid color-mix(in srgb,var(--signal-color) 34%,transparent);outline-offset:2px;border-radius:4px}
.signal-orb{width:12px;height:12px;border-radius:50%;background:radial-gradient(circle,#fff 0 28%,var(--signal-color) 33% 63%,transparent 66%);box-shadow:0 0 0 4px color-mix(in srgb,var(--signal-color) 12%,transparent),0 0 12px color-mix(in srgb,var(--signal-color) 18%,transparent);opacity:.92}
.status-pill{display:inline-flex;align-items:center;gap:6px;min-height:25px;max-width:150px;flex-shrink:0;padding:4px 9px;border-radius:999px;border:1px solid color-mix(in srgb,var(--state) 24%,transparent);background:color-mix(in srgb,var(--state) 10%,white);color:var(--state);font-size:12px;white-space:nowrap}
.status-pill .ico{width:14px;height:14px}.word{color:inherit;overflow:hidden;text-overflow:ellipsis}
.state-icon{display:none}[data-live="live"] .state-icon.live,[data-live="stale"] .state-icon.stale,[data-live="down"] .state-icon.down,[data-live="awaiting_first_heartbeat"] .state-icon.awaiting{display:inline-block}
.reason{--reason-color:var(--muted);display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;gap:8px;min-height:22px;margin:-2px 0 10px;color:var(--muted);font-size:12px;line-height:1.25}
.reason:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--reason-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--reason-color) 12%,transparent)}
.reason.ok{--reason-color:var(--live)}.reason.warn{--reason-color:var(--stale)}.reason.down{--reason-color:var(--down)}.reason.wait{--reason-color:var(--wait)}.reason.self{--reason-color:var(--sun)}
.reason span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fresh{min-height:52px;margin:4px 0 11px;font-size:13px;line-height:1.45;color:var(--ink)}
.fresh-row{display:grid;grid-template-columns:1fr auto;align-items:center;gap:10px;min-height:23px;border-bottom:1px solid rgba(214,226,234,.58)}
.fresh-row:last-child{border-bottom:0}
.fresh-row span{color:var(--muted);font-size:12px}
.fresh-row strong{font-size:12px;font-weight:650;color:var(--ink)}
.fresh-row strong.ok{color:var(--live)}.fresh-row strong.warn{color:var(--stale)}.fresh-row strong.na{color:var(--wait)}
.backup-mini{--backup-color:var(--wait);display:grid;grid-template-columns:8px minmax(0,1fr);align-items:center;column-gap:8px;min-height:32px;margin:-1px 0 10px;padding:7px 8px;border:1px solid color-mix(in srgb,var(--backup-color) 20%,rgba(210,226,234,.82));border-radius:7px;background:linear-gradient(135deg,rgba(255,255,255,.78),color-mix(in srgb,var(--backup-color) 6%,white));color:var(--ink)}
.backup-mini:before{content:"";grid-row:1/3;width:8px;height:8px;border-radius:50%;background:var(--backup-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--backup-color) 10%,transparent)}
.backup-mini strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.15;color:var(--ink)}
.backup-mini span{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:11px;line-height:1.2}
.backup-mini.clear{--backup-color:var(--live)}.backup-mini.warning{--backup-color:var(--stale)}.backup-mini.critical{--backup-color:var(--down)}.backup-mini.watch{--backup-color:var(--wait)}
.backup-list{min-width:150px;margin:0}
.backup-list span{font-size:11px}
.backup-list strong{font-size:12px}
.protection-onboard{--protect-color:var(--wait);display:grid;grid-template-columns:8px minmax(0,1fr);align-items:center;column-gap:8px;min-height:30px;margin:-3px 0 10px;padding:7px 8px;border:1px solid color-mix(in srgb,var(--protect-color) 18%,rgba(210,226,234,.82));border-radius:7px;background:linear-gradient(135deg,rgba(255,255,255,.76),color-mix(in srgb,var(--protect-color) 5%,white));color:var(--ink)}
.protection-onboard:before{content:"";grid-row:1/3;width:8px;height:8px;border-radius:50%;background:var(--protect-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--protect-color) 10%,transparent)}
.protection-onboard strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.15;color:var(--ink)}
.protection-onboard span{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:11px;line-height:1.2}
.protection-onboard.clear{--protect-color:var(--live)}.protection-onboard.warning{--protect-color:var(--stale)}.protection-onboard.critical{--protect-color:var(--down)}.protection-onboard.watch{--protect-color:var(--wait)}
.protection-list{min-width:150px;margin:6px 0 0}
.setup-card{border-color:rgba(214,155,49,.34);background:linear-gradient(135deg,rgba(255,255,255,.90),rgba(247,252,253,.82));box-shadow:0 14px 32px rgba(45,75,95,.08),inset 0 0 0 1px rgba(214,155,49,.08)}
.setup-card[data-setup-level="warning"]{border-color:rgba(178,106,0,.32)}
.setup-card .nix{color:var(--sun);border-color:rgba(214,155,49,.24);box-shadow:0 0 0 5px rgba(214,155,49,.06)}
.setup-intent{display:flex;flex-wrap:wrap;gap:6px;margin:0 0 10px}
.setup-chip{display:inline-flex;align-items:center;min-height:25px;max-width:100%;padding:4px 8px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font-size:11px;font-weight:720;white-space:nowrap}
.setup-chip.backup{border-color:rgba(214,155,49,.28);background:rgba(255,246,228,.72);color:#9a5b00}
.setup-chip.location{border-color:rgba(103,177,196,.30);background:rgba(223,241,249,.62);color:#0f4f80}
.setup-detail{min-height:40px;margin:2px 0 10px;color:var(--muted);font-size:12px;line-height:1.35}
.setup-action{display:inline-flex;align-items:center;justify-content:center;min-height:30px;padding:6px 10px;border:1px solid rgba(21,48,75,.88);border-radius:7px;background:#12304b;color:#fff;text-decoration:none;font-size:12px;font-weight:760;box-shadow:0 8px 18px rgba(18,48,75,.12)}
.setup-action:hover,.setup-action:focus-visible{background:#0f2941;box-shadow:0 10px 22px rgba(18,48,75,.16);outline:0}
.setup-row td{border-color:rgba(214,155,49,.30);background:linear-gradient(135deg,rgba(255,255,255,.90),rgba(247,252,253,.78))}
.setup-row[data-setup-level="warning"] td{border-color:rgba(178,106,0,.32)}
.meta{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:auto;border-top:1px solid rgba(214,226,234,.72);padding-top:10px;font-size:11px;color:var(--muted)}
.meta strong{font-weight:600;color:var(--ink)}
.card-tools{display:flex;align-items:center;justify-content:center;min-height:25px;margin-top:5px}
.drag-handle{appearance:none;display:none;place-items:center;width:25px;height:25px;margin:0;border:0;border-radius:50%;background:transparent;color:var(--muted);cursor:grab}
main[data-arrange="freeform"] .drag-handle{display:grid}
.drag-handle:hover,.drag-handle:focus-visible{background:rgba(223,241,249,.78);color:var(--accent);box-shadow:0 7px 16px rgba(45,75,95,.08);outline:0}
.drag-handle:active{cursor:grabbing}
.drag-handle .ico{width:13px;height:13px}
.card[data-dragging="true"]{z-index:20;transform:scale(1.015);box-shadow:0 20px 44px rgba(45,75,95,.18);cursor:grabbing}
.grid[data-freeform-dragging="true"] .card:not([data-dragging]){transition:transform .12s ease,box-shadow .12s ease}
.settings-card{display:inline-grid;place-items:center;width:25px;height:25px;margin:0;border:0;border-radius:50%;background:transparent;color:var(--accent);text-decoration:none;box-shadow:none}
.settings-card:hover{background:rgba(223,241,249,.78);box-shadow:0 7px 16px rgba(45,75,95,.08);transform:translateY(-1px)}
.settings-card.unavailable{--host-color:#aebac3;color:var(--muted);opacity:.72;box-shadow:none}
.settings-card.unavailable:hover{background:rgba(241,247,250,.92);box-shadow:0 7px 16px rgba(45,75,95,.05);opacity:1}
.settings-card.unavailable .settings-icon{color:var(--muted)}
.settings-icon{display:grid;place-items:center;width:25px;height:25px;border:1px solid rgba(210,226,234,.76);border-radius:50%;background:rgba(255,255,255,.58);color:inherit}
.settings-icon .ico{width:13px;height:13px}
.settings-copy,.settings-swatch{display:none}
.beat{--beat-color:var(--state);--now-x:0%;--expect-x:64%;--stale-x:82%;--fill-color:var(--sea);--expect-fill:0deg;--expect-alpha:.55;--target-ring:3px;--late-alpha:.3;margin-top:10px;color:var(--beat-color)}
.beat-stage{position:relative;height:50px;overflow:visible}
.beat-floor{position:absolute;left:0;right:0;top:21px;height:4px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.16) 0 var(--expect-x),rgba(214,155,49,.16) var(--expect-x) var(--stale-x),rgba(191,58,53,.12) var(--stale-x) 100%);box-shadow:inset 0 0 0 1px rgba(137,151,163,.18)}
.beat-fill{position:absolute;left:0;top:22px;width:var(--now-x);height:2px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.18),var(--fill-color));transition:background-color .2s ease}
.beat-now{position:absolute;left:var(--now-x);top:23px;z-index:8;width:13px;height:13px;border-radius:50%;background:radial-gradient(circle,#fff 0 29%,var(--fill-color) 32% 62%,transparent 64%);box-shadow:0 0 0 5px color-mix(in srgb,var(--fill-color) 12%,transparent),0 0 14px color-mix(in srgb,var(--fill-color) 26%,transparent);transform:translate(-50%,-50%);pointer-events:none}
.beat-current{position:absolute;top:22px;left:calc(var(--now-x) - 22%);width:22%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--fill-color) 34%,transparent),transparent);animation:tide 2.8s linear infinite;opacity:.8}
.beat-marks{position:absolute;inset:0}
.beat-mark{--mark-color:var(--sea);position:absolute;left:var(--mark-x);top:23px;z-index:4;width:6px;height:6px;border-radius:50%;background:var(--mark-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--mark-color) 10%,transparent);opacity:.82;transform:translate(-50%,-50%);cursor:help}
.beat-mark[data-history-level="late"]{--mark-color:var(--sun)}.beat-mark[data-history-level="stale"]{--mark-color:var(--stale)}.beat-mark[data-history-level="down"]{--mark-color:var(--down)}.beat-mark[data-history-level="first"]{--mark-color:var(--wait)}
.beat-mark:hover,.beat-mark:focus-visible{opacity:1;box-shadow:0 0 0 5px color-mix(in srgb,var(--mark-color) 18%,transparent),0 0 14px color-mix(in srgb,var(--mark-color) 24%,transparent);outline:0}
.beat[data-count="0"] .beat-mark{display:none}
.beat-threshold{position:absolute;top:15px;bottom:15px;width:1px;background:rgba(137,151,163,.25)}
.beat-threshold.expected{left:var(--expect-x)}.beat-threshold.stale{left:var(--stale-x)}
.beat-hit{position:absolute;left:var(--hit-x,0%);top:23px;z-index:9;width:9px;height:9px;border-radius:50%;background:currentColor;opacity:0;transform:translate(-50%,-50%) scale(.7);pointer-events:none}
.beat[data-flash="true"] .beat-hit{animation:beat-hit .9s ease-out}
.beat-zones{position:absolute;left:0;right:0;bottom:0;color:var(--muted);font-size:10px}
.beat-zones span{position:absolute;bottom:0;white-space:nowrap}.beat-zones span:first-child{left:0}.beat-zones span:nth-child(2){left:var(--expect-x);transform:translateX(-50%)}.beat-zones span:nth-child(3){right:0;color:var(--stale)}
.beat[data-beat="late"]{--beat-color:var(--stale)}.beat[data-beat="stale"]{--beat-color:var(--stale)}.beat[data-beat="down"]{--beat-color:var(--down)}.beat[data-beat="waiting"]{--beat-color:var(--wait)}.beat[data-beat="lit"]{--beat-color:var(--sun)}
@keyframes beat-hit{0%{opacity:.9;transform:translate(-50%,-50%) scale(.55);box-shadow:0 0 0 0 color-mix(in srgb,currentColor 28%,transparent)}100%{opacity:0;transform:translate(-50%,-50%) scale(2.4);box-shadow:0 0 0 12px transparent}}
@keyframes tide{from{transform:translateX(-16%)}to{transform:translateX(42%)}}
.list-wrap{display:none}
main[data-view="list"] .grid{display:none}
main[data-view="list"] .list-wrap{display:block}
.list{width:100%;border-collapse:separate;border-spacing:0 8px}
.list th{padding:0 12px 6px;text-align:left;color:var(--muted);font-size:11px;font-weight:600}
.list td{padding:12px;background:rgba(255,255,255,.88);border-top:1px solid rgba(211,225,233,.86);border-bottom:1px solid rgba(211,225,233,.86);vertical-align:middle}
.list td:first-child{border-left:1px solid rgba(211,225,233,.86);border-radius:8px 0 0 8px}
.list td:last-child{border-right:1px solid rgba(211,225,233,.86);border-radius:0 8px 8px 0}
.list tr.light td{border-color:rgba(214,155,49,.34)}
.list .host{min-width:210px}.list .reason{min-width:150px;margin:0}.list .fresh{min-height:0;margin:0;white-space:nowrap}.list .fresh-row{min-height:20px}.list .status-pill{max-width:120px}.list .beat{width:230px;margin:0}.list .card-tools{margin:0}.list .settings-card{margin:0}.list .settings-icon{width:25px;height:25px}
.list tr.onboard-row td{border:1px dashed rgba(214,155,49,.42);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.86),rgba(240,250,250,.72));box-shadow:0 10px 24px rgba(45,75,95,.05)}
.onboard-row button{appearance:none;width:100%;display:flex;align-items:center;gap:12px;border:0;background:transparent;color:var(--ink);font:inherit;text-align:left;cursor:pointer}.onboard-row button:hover strong,.onboard-row button:focus-visible strong{color:#0f4f80}.onboard-row button:focus-visible{outline:0}
.onboard-row .onboard-mark{width:32px;height:32px;box-shadow:0 0 0 6px rgba(214,155,49,.05)}.onboard-row .onboard-mark .ico{width:16px;height:16px}.onboard-row strong{display:block;font-size:13px}.onboard-row span:last-child{display:block;color:var(--muted);font-size:12px}
.ops-main{width:min(1280px,100%)}
.ops-summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:10px;margin:0 0 18px}
.ops-metric{--metric-color:var(--wait);appearance:none;width:100%;display:grid;grid-template-columns:50px minmax(0,1fr);align-items:center;column-gap:12px;min-height:78px;padding:14px 16px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.82);box-shadow:0 12px 30px rgba(54,88,108,.06);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);text-align:left;cursor:pointer}
.ops-metric:before{content:"";grid-row:1/3;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--metric-color) 14%,white);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--metric-color) 20%,transparent)}
.ops-metric b{display:block;font-family:Georgia,"Times New Roman",serif;font-size:28px;line-height:1;font-weight:500;color:var(--ink)}
.ops-metric span{display:block;color:var(--muted);font-size:12px;margin-top:2px}
.ops-metric:hover,.ops-metric:focus-visible{border-color:color-mix(in srgb,var(--metric-color) 38%,rgba(210,226,234,.86));box-shadow:0 16px 34px rgba(54,88,108,.09),0 0 0 3px color-mix(in srgb,var(--metric-color) 9%,transparent);outline:0}
.ops-metric[aria-pressed="true"]{border-color:color-mix(in srgb,var(--metric-color) 46%,rgba(210,226,234,.86));background:linear-gradient(135deg,rgba(255,255,255,.94),color-mix(in srgb,var(--metric-color) 8%,white));box-shadow:0 16px 34px rgba(54,88,108,.10),0 0 0 3px color-mix(in srgb,var(--metric-color) 12%,transparent)}
.ops-metric.critical{--metric-color:var(--down);border-color:rgba(191,58,53,.24)}.ops-metric.warning{--metric-color:var(--stale);border-color:rgba(178,106,0,.24)}.ops-metric.watch{--metric-color:var(--sun);border-color:rgba(214,155,49,.24)}.ops-metric.clear,.ops-metric.info,.ops-metric.recovery{--metric-color:var(--live);border-color:rgba(37,132,95,.22)}
.ops-toolbar{margin-bottom:18px}
.ops-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:start}
.ops-panel,.ops-side-panel{border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 16px 38px rgba(54,88,108,.08);overflow:hidden}
.ops-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:17px 18px;border-bottom:1px solid rgba(214,226,234,.72);background:rgba(251,253,254,.74)}
.ops-panel-head h2,.ops-side-panel h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;letter-spacing:0;color:#12304b}
.ops-panel-head p,.ops-side-panel p{margin:3px 0 0;color:var(--muted);font-size:12px}
.ops-count{display:inline-flex;align-items:center;justify-content:center;min-width:30px;height:27px;border-radius:999px;background:rgba(223,241,249,.78);color:#0f4f80;font-size:12px;font-weight:760}
.alert-list,.activity-list{display:grid}
.alert-row,.activity-row{--row-color:var(--wait);position:relative;display:grid;gap:12px;align-items:center;min-width:0;border-bottom:1px solid rgba(214,226,234,.66);background:rgba(255,255,255,.72);color:var(--ink)}
.alert-row:last-child,.activity-row:last-child{border-bottom:0}
.alert-row{grid-template-columns:minmax(116px,.58fr) auto minmax(180px,1.25fr) minmax(66px,.36fr) minmax(74px,.42fr) minmax(124px,.7fr);gap:10px;padding:13px 16px}
.activity-row{grid-template-columns:86px minmax(110px,.55fr) 92px minmax(260px,1.5fr) 94px;align-items:start;padding:14px 16px}
.alert-row.critical,.activity-row.critical{--row-color:var(--down)}.alert-row.warning,.activity-row.warning{--row-color:var(--stale)}.alert-row.watch,.activity-row.watch{--row-color:var(--sun)}.alert-row.clear,.activity-row.clear,.activity-row.recovery{--row-color:var(--live)}.activity-row.info{--row-color:var(--accent)}
.alert-host,.activity-host{display:flex;align-items:center;gap:9px;min-width:0}
.alert-dot,.activity-dot{flex:0 0 auto;width:9px;height:9px;border-radius:50%;background:var(--row-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--row-color) 12%,transparent)}
.alert-host strong,.activity-host strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.alert-host span:last-child,.activity-host span:last-child{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:11px}
.alert-status{display:flex;flex-wrap:wrap;align-items:center;gap:6px;min-width:0}
.alert-repeat{display:inline-flex;align-items:center;min-height:23px;padding:3px 8px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font-size:11px;font-weight:720}
.severity{display:inline-flex;align-items:center;justify-content:center;width:max-content;min-height:25px;padding:4px 9px;border:1px solid color-mix(in srgb,var(--row-color) 25%,transparent);border-radius:999px;background:color-mix(in srgb,var(--row-color) 9%,white);color:var(--row-color);font-size:11px;font-weight:760;text-transform:lowercase}
.alert-issue strong,.activity-copy strong{display:block;color:var(--ink);font-size:13px}
.alert-issue p,.activity-copy p{margin:2px 0 0;color:var(--muted);font-size:12px;line-height:1.35}
.ops-source,.ops-time{color:var(--muted);font-size:12px}.ops-time{white-space:nowrap}
.next-action{min-width:0;color:#0f4f80;font-size:12px;font-weight:720;line-height:1.35;overflow-wrap:anywhere}
.ops-side-panel{display:grid;gap:14px;padding:16px}
.posture-ring{--posture-color:var(--live);appearance:none;position:relative;display:grid;place-items:center;width:126px;height:126px;margin:2px auto 4px;border:0;border-radius:50%;background:conic-gradient(var(--posture-color) var(--posture-fill),rgba(214,226,234,.72) 0);box-shadow:0 0 0 10px color-mix(in srgb,var(--posture-color) 8%,transparent);cursor:pointer;text-align:center}
.posture-ring:before{content:"";position:absolute;inset:18px;border-radius:50%;background:#fff;box-shadow:inset 0 0 0 1px rgba(210,226,234,.72)}
.posture-ring:hover,.posture-ring:focus-visible{box-shadow:0 0 0 10px color-mix(in srgb,var(--posture-color) 11%,transparent),0 12px 28px rgba(45,75,95,.10);outline:0}
.posture-ring strong{position:relative;font-family:Georgia,"Times New Roman",serif;font-size:27px;font-weight:500;color:var(--ink)}
.posture-ring span{position:relative;color:var(--muted);font-size:11px}
.posture-list,.activity-filters{display:flex;flex-wrap:wrap;gap:7px}
.posture-chip,.activity-filter{appearance:none;display:inline-flex;align-items:center;gap:6px;min-height:28px;padding:5px 9px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font:inherit;font-size:12px;font-weight:650;cursor:pointer}
.posture-chip:before,.activity-filter:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--chip-color,var(--wait));box-shadow:0 0 0 3px color-mix(in srgb,var(--chip-color,var(--wait)) 10%,transparent)}
.posture-chip.critical,.activity-filter.critical{--chip-color:var(--down)}.posture-chip.warning,.activity-filter.warning{--chip-color:var(--stale)}.posture-chip.watch,.activity-filter.watch{--chip-color:var(--sun)}.posture-chip.clear,.activity-filter.clear,.activity-filter.recovery{--chip-color:var(--live)}.posture-chip.info,.activity-filter.info{--chip-color:var(--accent)}
.posture-chip:hover,.posture-chip:focus-visible,.activity-filter:hover,.activity-filter:focus-visible{border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.58);outline:0}
.posture-chip[aria-pressed="true"],.activity-filter[aria-pressed="true"]{color:#0f4f80;border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.76)}
.ops-action{display:inline-flex;align-items:center;justify-content:center;min-height:36px;padding:8px 12px;border:1px solid rgba(103,177,196,.42);border-radius:7px;background:rgba(223,241,249,.72);color:#0f4f80;text-decoration:none;font-size:12px;font-weight:760;box-shadow:0 8px 20px rgba(45,75,95,.07)}
.ops-action:hover,.ops-action:focus-visible{background:rgba(207,235,244,.92);box-shadow:0 10px 24px rgba(45,75,95,.10);outline:0}
.ops-empty{padding:34px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(239,249,250,.78));box-shadow:0 16px 38px rgba(54,88,108,.08)}
.ops-empty h2{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:25px;font-weight:500}.ops-empty p{margin:0;color:var(--muted)}
.ops-note{padding:11px 13px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(247,252,253,.78);color:var(--muted);font-size:12px}
.ops-filter-empty{display:none;margin:0;padding:22px;border-top:1px solid rgba(214,226,234,.66);color:var(--muted);font-size:13px;background:rgba(255,255,255,.64)}
.ops-filter-empty[data-visible="true"]{display:block}
.backup-page .ops-panel{overflow:auto}
.backup-list-full{display:grid;min-width:920px}
.backup-row{--row-color:var(--wait);display:grid;grid-template-columns:minmax(150px,.9fr) 104px minmax(190px,1.15fr) minmax(96px,.58fr) minmax(92px,.52fr) minmax(132px,.72fr) minmax(120px,.68fr);gap:12px;align-items:center;padding:14px 16px;border-bottom:1px solid rgba(214,226,234,.66);background:rgba(255,255,255,.72)}
.backup-row:last-child{border-bottom:0}
.backup-row.critical{--row-color:var(--down)}.backup-row.warning{--row-color:var(--stale)}.backup-row.watch{--row-color:var(--wait)}.backup-row.clear{--row-color:var(--live)}
.backup-host{display:grid;grid-template-columns:9px minmax(0,1fr);align-items:center;gap:8px;min-width:0}
.backup-host:before{content:"";width:9px;height:9px;border-radius:50%;background:var(--row-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--row-color) 12%,transparent)}
.backup-host strong,.backup-issue strong,.backup-field strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink);font-size:13px}
.backup-host span,.backup-issue p,.backup-field span{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:11px;line-height:1.3}
.backup-state{display:flex;flex-wrap:wrap;align-items:center;gap:6px}
.backup-count{display:inline-flex;align-items:center;min-height:22px;padding:0 7px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font-size:11px;font-weight:720}
.backup-issue{min-width:0}
.backup-issue p{font-size:12px;white-space:normal}
.backup-field{min-width:0}
[hidden]{display:none!important}
.empty-state,.lone-state{position:relative;overflow:hidden;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(239,249,250,.78));box-shadow:0 16px 38px rgba(54,88,108,.08)}
.empty-state{min-height:430px;margin-top:18px;padding:36px;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(240px,.95fr);align-items:center;gap:30px}
.empty-state:before,.lone-state:before{content:"";position:absolute;inset:auto -8% -30% -8%;height:50%;background:repeating-linear-gradient(178deg,rgba(31,127,181,.12) 0 1px,transparent 1px 28px);opacity:.72;pointer-events:none}
.empty-copy{position:relative;max-width:440px}
.empty-kicker,.lone-kicker{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--sun);font-weight:700}
.empty-copy h2{margin:8px 0 9px;font-size:30px;line-height:1.12;letter-spacing:0}
.empty-copy p,.lone-copy p{margin:0;color:var(--muted);font-size:14px}
.empty-visual{position:relative;min-height:285px;display:grid;place-items:center;color:var(--sun)}
.empty-sun{position:absolute;right:14%;top:8%;width:66px;height:66px;border-radius:50%;background:radial-gradient(circle,#fff 0 34%,rgba(214,155,49,.26) 36% 58%,transparent 60%);box-shadow:0 0 0 12px rgba(214,155,49,.06),0 0 42px rgba(214,155,49,.20)}
.empty-line{position:absolute;left:7%;right:7%;top:57%;height:2px;border-radius:999px;background:linear-gradient(90deg,transparent,rgba(21,158,153,.42),rgba(214,155,49,.46),transparent)}
.empty-line:after{content:"";position:absolute;left:0;top:50%;width:26%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,var(--sea),transparent);animation:tide 3.2s linear infinite;transform:translateY(-50%)}
.empty-lighthouse{position:relative;display:grid;place-items:center;width:150px;height:150px;border-radius:50%;background:radial-gradient(circle,rgba(214,155,49,.18),rgba(255,255,255,.66) 54%,transparent 70%);color:var(--sun)}
.empty-lighthouse .ico{width:68px;height:68px}
.empty-await{position:absolute;left:50%;bottom:16%;transform:translateX(-50%);font-size:11px;color:var(--muted);white-space:nowrap}
.lone-state{margin-top:14px;padding:17px 18px;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:16px}
.lone-mark{position:relative;display:grid;place-items:center;width:46px;height:46px;border-radius:50%;border:1px solid rgba(214,155,49,.28);background:rgba(255,255,255,.74);color:var(--sun)}
.lone-mark .ico{width:24px;height:24px}
.lone-copy{position:relative;min-width:0}.lone-copy strong{display:block;font-size:15px}.lone-copy p{font-size:12px}
.onboard-primary{appearance:none;position:relative;display:inline-flex;align-items:center;justify-content:center;gap:9px;min-height:38px;margin-top:18px;padding:0 14px;border:1px solid rgba(103,177,196,.42);border-radius:7px;background:rgba(223,241,249,.74);color:#0f4f80;text-decoration:none;font:inherit;font-size:13px;font-weight:760;box-shadow:0 8px 20px rgba(45,75,95,.07);cursor:pointer}.onboard-primary:hover,.onboard-primary:focus-visible{background:rgba(207,235,244,.92);box-shadow:0 10px 24px rgba(45,75,95,.10);outline:0}.onboard-primary .ico{width:15px;height:15px}
.lone-state .onboard-primary{margin:0}
.assistant-overlay{position:fixed;inset:0;z-index:5000;display:grid;place-items:center;padding:24px;overflow:auto;background:rgba(20,43,63,.20);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px)}
.assistant-sheet{width:min(760px,100%);max-height:calc(100vh - 48px);border:1px solid rgba(210,226,234,.92);border-radius:8px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(247,252,253,.94));box-shadow:0 28px 70px rgba(31,61,82,.22);overflow:auto}
.assistant-head{display:flex;align-items:flex-start;justify-content:space-between;gap:18px;padding:20px 22px 16px;border-bottom:1px solid rgba(214,226,234,.72)}.assistant-head h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:27px;font-weight:500;color:#12304b}.assistant-head p{margin:5px 0 0;color:var(--muted);font-size:13px}
.assistant-close{appearance:none;display:grid;place-items:center;min-width:34px;height:34px;border:1px solid rgba(210,226,234,.86);border-radius:50%;background:#fff;color:var(--muted);font:inherit;font-size:12px;font-weight:760;cursor:pointer}.assistant-close:hover,.assistant-close:focus-visible{background:rgba(223,241,249,.72);color:#0f4f80;outline:0}
.assistant-body{display:grid;gap:13px;padding:18px 22px 22px}.assistant-paths{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.assistant-path{appearance:none;display:grid;gap:11px;min-height:150px;padding:15px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.78);color:var(--ink);font:inherit;text-align:left;cursor:pointer;box-shadow:0 12px 28px rgba(45,75,95,.06)}.assistant-path:hover,.assistant-path:focus-visible{border-color:rgba(103,177,196,.52);box-shadow:0 16px 34px rgba(45,75,95,.09),0 0 0 3px rgba(103,177,196,.09);outline:0}.assistant-path[aria-pressed="true"]{border-color:rgba(21,158,153,.68);background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(232,248,248,.76));box-shadow:0 16px 34px rgba(45,75,95,.09),0 0 0 3px rgba(21,158,153,.10)}.assistant-path .onboard-mark{width:34px;height:34px;box-shadow:0 0 0 6px rgba(214,155,49,.05)}.assistant-path[aria-pressed="true"] .onboard-mark{border-color:rgba(21,158,153,.34);color:var(--sea);box-shadow:0 0 0 7px rgba(21,158,153,.08)}.assistant-path strong{display:block;font-size:16px;color:var(--ink)}.assistant-path span{display:block;color:var(--muted);font-size:12px;line-height:1.4}
.assistant-provider-step{display:none;gap:12px}.assistant-overlay[data-assistant-selected-path="new"] .assistant-provider-step{display:grid}.assistant-step-head{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-top:1px}.assistant-step-head strong{font-size:13px;color:var(--ink)}.assistant-step-head span{font-size:11px;color:var(--muted)}.assistant-providers{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.assistant-provider{appearance:none;display:grid;gap:8px;padding:13px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.78);color:var(--ink);font:inherit;text-align:left;cursor:pointer}.assistant-provider:hover,.assistant-provider:focus-visible,.assistant-template:hover,.assistant-template:focus-visible{border-color:rgba(103,177,196,.52);box-shadow:0 0 0 3px rgba(103,177,196,.09);outline:0}.assistant-provider[aria-pressed="true"]{border-color:rgba(21,158,153,.64);background:linear-gradient(135deg,rgba(255,255,255,.96),rgba(232,248,248,.72));box-shadow:0 0 0 3px rgba(21,158,153,.09)}.assistant-provider-title{display:flex;align-items:center;justify-content:space-between;gap:10px}.assistant-provider-title strong{font-size:15px}.assistant-badge{display:inline-flex;align-items:center;min-height:22px;padding:0 8px;border:1px solid rgba(214,155,49,.28);border-radius:999px;background:rgba(255,246,228,.76);color:#9a5b00;font-size:11px;font-weight:760}.assistant-provider p{margin:0;color:var(--muted);font-size:12px;line-height:1.4}.assistant-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:7px}.assistant-facts span{min-width:0;padding:7px 8px;border:1px solid rgba(214,226,234,.66);border-radius:7px;background:rgba(247,252,253,.76);font-size:11px;color:var(--muted)}.assistant-facts b{display:block;margin-bottom:2px;color:var(--ink);font-size:11px}.assistant-templates{display:grid;gap:8px}.assistant-template{appearance:none;display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:12px;min-height:62px;padding:11px 12px;border:1px solid rgba(210,226,234,.82);border-radius:8px;background:rgba(255,255,255,.74);color:var(--ink);font:inherit;text-align:left;cursor:pointer}.assistant-template[hidden]{display:none}.assistant-template[aria-pressed="true"]{border-color:rgba(21,158,153,.62);background:rgba(233,249,248,.74);box-shadow:0 0 0 3px rgba(21,158,153,.08)}.assistant-template strong{display:block;font-size:13px}.assistant-template span{display:block;margin-top:2px;color:var(--muted);font-size:11px;line-height:1.35}.assistant-template em{font-style:normal;color:var(--sun);font-size:11px;font-weight:760;white-space:nowrap}
.assistant-existing-step{display:none;gap:12px}.assistant-overlay[data-assistant-selected-path="existing"] .assistant-existing-step{display:grid}.assistant-preflight-form{display:grid;grid-template-columns:1fr .85fr 1fr 1.25fr .8fr auto;gap:10px;align-items:end;padding:13px;border:1px solid rgba(210,226,234,.82);border-radius:8px;background:rgba(255,255,255,.78)}.assistant-preflight-form label,.assistant-preflight-facts label{display:grid;gap:5px;min-width:0}.assistant-preflight-form label span,.assistant-preflight-facts label span{color:var(--muted);font-size:11px;font-weight:650}.assistant-preflight-form input,.assistant-preflight-form select,.assistant-preflight-facts input,.assistant-preflight-facts select{width:100%;height:36px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:13px;padding:0 10px;outline:0}.assistant-preflight-form input:focus,.assistant-preflight-form select:focus,.assistant-preflight-facts input:focus,.assistant-preflight-facts select:focus{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}.assistant-preflight-details{grid-column:1/-1;border:1px solid rgba(214,226,234,.66);border-radius:7px;background:rgba(247,252,253,.74);padding:8px 10px}.assistant-preflight-details summary{cursor:pointer;color:#0f4f80;font-size:12px;font-weight:760}.assistant-preflight-facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:9px;margin-top:10px}.assistant-check{min-height:36px;padding:0 13px;border:1px solid rgba(21,48,75,.88);border-radius:7px;background:#12304b;color:#fff;font:inherit;font-size:12px;font-weight:760;white-space:nowrap;cursor:pointer}.assistant-check:disabled{border-color:rgba(210,226,234,.88);background:rgba(238,244,247,.88);color:#93a1ad}.assistant-preflight-result{display:grid;gap:10px;padding:13px;border:1px solid rgba(210,226,234,.82);border-radius:8px;background:rgba(247,252,253,.78)}.assistant-result-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.assistant-result-head strong{font-size:14px;color:var(--ink)}.assistant-result-head span{max-width:430px;color:var(--muted);font-size:12px;line-height:1.35;text-align:right}.assistant-checks{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}.assistant-check-row{--check-color:var(--wait);display:grid;grid-template-columns:10px minmax(0,1fr);gap:8px;align-items:start;min-height:42px;padding:8px 9px;border:1px solid rgba(214,226,234,.70);border-radius:7px;background:rgba(255,255,255,.72)}.assistant-check-row:before{content:"";width:8px;height:8px;margin-top:4px;border-radius:50%;background:var(--check-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--check-color) 10%,transparent)}.assistant-check-row[data-state="pass"]{--check-color:var(--live)}.assistant-check-row[data-state="warn"]{--check-color:var(--stale)}.assistant-check-row[data-state="fail"]{--check-color:var(--down)}.assistant-check-row strong{display:block;font-size:12px;color:var(--ink)}.assistant-check-row span{display:block;margin-top:1px;color:var(--muted);font-size:11px;line-height:1.35}.assistant-bootstrap{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:8px}.assistant-bootstrap-option{--option-color:var(--wait);appearance:none;display:block;width:100%;min-height:72px;padding:10px;border:1px solid rgba(214,226,234,.74);border-radius:7px;background:rgba(255,255,255,.74);color:var(--ink);font:inherit;text-align:left;opacity:.72}.assistant-bootstrap-option[data-available="true"]{--option-color:var(--sea);opacity:1;border-color:rgba(21,158,153,.26);background:rgba(233,249,248,.62);cursor:pointer}.assistant-bootstrap-option[data-selected="true"]{border-color:rgba(21,158,153,.58);box-shadow:0 0 0 3px rgba(21,158,153,.10),0 10px 22px rgba(45,75,95,.08)}.assistant-bootstrap-option:disabled{cursor:not-allowed}.assistant-bootstrap-option strong{display:block;color:var(--ink);font-size:12px}.assistant-bootstrap-option span{display:block;margin-top:3px;color:var(--muted);font-size:11px;line-height:1.35}.assistant-bootstrap-option:before{content:"";display:block;width:8px;height:8px;margin-bottom:7px;border-radius:50%;background:var(--option-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--option-color) 10%,transparent)}
.assistant-plan{display:none;gap:10px;padding:12px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(247,252,253,.70)}.assistant-overlay[data-assistant-stage="plan"] .assistant-plan{display:grid}.assistant-plan-head{display:flex;justify-content:space-between;align-items:end;gap:12px}.assistant-plan-head strong{font-size:15px}.assistant-plan-head span{font-size:12px;color:var(--muted)}.assistant-plan-list{display:grid;gap:7px}.assistant-plan-row{display:grid;grid-template-columns:minmax(0,1fr) auto;gap:10px;align-items:center;min-height:42px;padding:8px 10px;border:1px solid rgba(214,226,234,.68);border-radius:7px;background:rgba(255,255,255,.74)}.assistant-plan-row strong{display:block;font-size:12px}.assistant-plan-row span{display:block;color:var(--muted);font-size:11px}.assistant-plan-chip{display:inline-flex;align-items:center;min-height:22px;padding:0 8px;border-radius:999px;border:1px solid rgba(210,226,234,.88);background:#fff;color:var(--muted);font-size:11px;font-weight:760}.assistant-plan-chip[data-kind="protected"]{border-color:rgba(21,158,153,.24);background:rgba(233,249,248,.72);color:var(--live)}.assistant-plan-chip[data-kind="later"]{border-color:rgba(214,155,49,.28);background:rgba(255,246,228,.70);color:#9a5b00}.assistant-setup-intent{display:none;gap:9px;padding:10px;border:1px solid rgba(214,226,234,.70);border-radius:8px;background:rgba(255,255,255,.76)}.assistant-overlay[data-assistant-stage="plan"] .assistant-setup-intent{display:grid}.assistant-choice-group{display:grid;gap:7px}.assistant-choice-group strong{font-size:12px;color:var(--ink)}.assistant-choice-options{display:flex;flex-wrap:wrap;gap:6px}.assistant-choice{position:relative;display:inline-flex;align-items:center;min-height:30px;padding:0 10px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font-size:12px;font-weight:760;cursor:pointer}.assistant-choice:hover{border-color:rgba(103,177,196,.48);color:#0f4f80}.assistant-choice input{position:absolute;opacity:0;pointer-events:none}.assistant-choice:has(input:checked){border-color:rgba(21,158,153,.42);background:rgba(233,249,248,.72);color:var(--live);box-shadow:0 0 0 3px rgba(21,158,153,.08)}.assistant-intent-note{display:flex;flex-wrap:wrap;gap:6px;color:var(--muted);font-size:11px}.assistant-intent-note span{display:inline-flex;align-items:center;min-height:22px;padding:0 8px;border-radius:999px;border:1px solid rgba(214,226,234,.72);background:rgba(247,252,253,.76)}.assistant-confirm{display:grid;grid-template-columns:auto minmax(0,1fr) auto;align-items:center;gap:10px;padding:10px;border:1px solid rgba(214,226,234,.72);border-radius:7px;background:rgba(255,255,255,.78);font-size:12px;color:var(--ink)}.assistant-confirm input{width:16px;height:16px;accent-color:var(--sea)}.assistant-start{min-height:34px;padding:0 12px;border:1px solid rgba(21,48,75,.88);border-radius:7px;background:#12304b;color:#fff;font:inherit;font-size:12px;font-weight:760}.assistant-start:disabled{border-color:rgba(210,226,234,.88);background:rgba(238,244,247,.88);color:#93a1ad}.assistant-progress{display:flex;flex-wrap:wrap;gap:6px}.assistant-progress span{display:inline-flex;align-items:center;min-height:22px;padding:0 8px;border:1px solid rgba(210,226,234,.70);border-radius:999px;background:rgba(255,255,255,.72);color:var(--muted);font-size:11px}.assistant-progress span[data-risk="fail"]{border-color:rgba(198,40,40,.22);background:rgba(255,236,236,.62);color:#a23a3a}.assistant-progress span[data-risk="ok"]{border-color:rgba(21,158,153,.22);background:rgba(233,249,248,.62);color:var(--live)}
.assistant-plan-field{display:grid;gap:5px;padding:10px;border:1px solid rgba(214,226,234,.70);border-radius:8px;background:rgba(255,255,255,.76)}.assistant-plan-field span{color:var(--muted);font-size:11px;font-weight:650}.assistant-plan-field input{width:100%;height:36px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:13px;padding:0 10px;outline:0}.assistant-plan-field input:focus{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}
.assistant-job{display:grid;gap:2px;padding:9px 10px;border:1px solid rgba(210,226,234,.76);border-radius:7px;background:rgba(255,255,255,.78)}.assistant-job[hidden]{display:none}.assistant-job strong{font-size:12px;color:var(--ink)}.assistant-job span{font-size:11px;color:var(--muted);line-height:1.4}.assistant-progress span[data-active="true"]{border-color:rgba(21,158,153,.42);background:rgba(233,249,248,.82);color:var(--live);box-shadow:0 0 0 3px rgba(21,158,153,.08)}.assistant-progress span[data-active="true"][data-risk="fail"]{border-color:rgba(198,40,40,.34);background:rgba(255,236,236,.82);color:#a23a3a;box-shadow:0 0 0 3px rgba(198,40,40,.07)}
.assistant-next{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:14px;margin-top:2px;padding:14px 15px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(247,252,253,.82);color:var(--ink)}.assistant-next strong{display:block;font-size:14px}.assistant-next span{display:block;margin-top:2px;color:var(--muted);font-size:12px}.assistant-next button{min-width:112px;min-height:40px;border:1px solid rgba(210,226,234,.88);border-radius:7px;background:rgba(238,244,247,.88);color:#93a1ad;font:inherit;font-size:13px;font-weight:760}
.assistant-next button:not(:disabled){border-color:rgba(21,48,75,.88);background:#12304b;color:#fff;cursor:pointer;box-shadow:0 10px 22px rgba(18,48,75,.14)}
body[data-assistant-open="true"]{overflow:hidden}
@media (max-width:640px){.assistant-overlay{padding:14px}.assistant-paths,.assistant-providers,.assistant-preflight-form,.assistant-preflight-facts,.assistant-checks,.assistant-bootstrap{grid-template-columns:1fr}.assistant-head{padding:18px}.assistant-body{padding:16px 18px 18px}.assistant-facts{grid-template-columns:1fr}.assistant-template{grid-template-columns:1fr}.assistant-template em{white-space:normal}.assistant-result-head{display:grid}.assistant-result-head span{text-align:left}}
.map-main{width:min(1380px,100%)}
.map-main[data-map-view="maximized"]{width:100%}
.map-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:18px;align-items:stretch}
.map-panel,.site-panel{border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.84);box-shadow:0 16px 38px rgba(54,88,108,.08);overflow:hidden}
.map-panel{position:relative;display:flex;min-height:560px}
.fleet-map{flex:1 1 auto;height:100%;min-height:560px;background:linear-gradient(135deg,#f7fbfc,#edf6f7)}
.map-layout[data-mode="maximized"]{grid-template-columns:minmax(0,1fr)}
.map-layout[data-mode="maximized"] .site-panel{display:none}
.map-layout[data-mode="maximized"] .map-panel{height:calc(100vh - 258px);min-height:640px}
.map-panel:fullscreen{width:100vw;height:100vh;min-height:100vh;border:0;border-radius:0;background:#f7fbfc}
.map-panel:fullscreen .fleet-map{min-height:100vh}
.map-panel:-webkit-full-screen{width:100vw;height:100vh;min-height:100vh;border:0;border-radius:0;background:#f7fbfc}
.map-panel:-webkit-full-screen .fleet-map{min-height:100vh}
.map-mode-controls{position:absolute;right:12px;top:12px;z-index:1001;display:flex;align-items:center;gap:4px;padding:4px;border:1px solid rgba(210,226,234,.94);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 12px 28px rgba(45,75,95,.14);-webkit-backdrop-filter:blur(10px) saturate(1.06);backdrop-filter:blur(10px) saturate(1.06)}
.map-mode-control{display:grid;place-items:center;width:34px;height:34px;border:1px solid transparent;border-radius:6px;background:transparent;color:#44637f;cursor:pointer}
.map-mode-control:hover{border-color:rgba(173,205,220,.72);background:rgba(223,241,249,.56);color:#17304a}
.map-mode-control[aria-pressed="true"]{border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.82);color:#187fb9;box-shadow:0 0 0 3px rgba(103,177,196,.10)}
.map-mode-control .ico{width:17px;height:17px}
.map-density-control{margin-left:5px;border-left:1px solid rgba(210,226,234,.86)}
.map-panel:fullscreen .map-mode-controls,.map-panel:-webkit-full-screen .map-mode-controls{right:14px;top:14px}
.map-fallback{display:none;position:absolute;inset:0;place-items:center;padding:28px;text-align:center;color:var(--muted);background:rgba(255,255,255,.82);z-index:2}
.map-fallback strong{display:block;color:var(--ink);font-size:18px}
.map-loading{position:absolute;inset:0;z-index:900;display:grid;place-items:center;padding:26px;pointer-events:none;background:linear-gradient(135deg,rgba(255,255,255,.82),rgba(239,249,250,.54))}
.map-panel[data-loading="false"] .map-loading{display:none;opacity:0;visibility:hidden}
.map-load-card{width:min(420px,calc(100% - 40px));padding:18px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 16px 38px rgba(54,88,108,.12);-webkit-backdrop-filter:blur(10px) saturate(1.06);backdrop-filter:blur(10px) saturate(1.06)}
.map-load-card strong{display:block;margin-bottom:5px;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;color:var(--ink)}
.map-load-card p{margin:0;color:var(--muted);font-size:12px}
.map-load-rail{position:relative;height:6px;margin-top:14px;overflow:hidden;border-radius:999px;background:rgba(214,226,234,.68)}
.map-load-rail:after{content:"";position:absolute;inset:0;width:38%;border-radius:999px;background:linear-gradient(90deg,transparent,rgba(21,158,153,.68),transparent);animation:mapShimmer 1.2s linear infinite}
.fleet-map:before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 22% 42%,rgba(21,158,153,.10),transparent 20%),radial-gradient(circle at 72% 38%,rgba(214,155,49,.10),transparent 18%),linear-gradient(135deg,#f7fbfc,#edf6f7);opacity:0;transition:opacity .18s ease}
.map-panel[data-loading="true"] .fleet-map{position:relative}
.map-panel[data-loading="true"] .fleet-map:before{opacity:1}
.site-loading,.site-error{display:grid;gap:8px;padding:11px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.74)}
.site-skel-line{height:11px;border-radius:999px;background:linear-gradient(90deg,rgba(222,234,240,.58),rgba(247,252,253,.96),rgba(222,234,240,.58));background-size:220% 100%;animation:siteShimmer 1.4s linear infinite}
.site-skel-line.short{width:46%}.site-skel-line.medium{width:68%}.site-skel-line.long{width:86%}
.site-error strong{font-size:13px;color:var(--ink)}.site-error span{color:var(--muted);font-size:12px}
@keyframes mapShimmer{from{transform:translateX(-100%)}to{transform:translateX(265%)}}
@keyframes siteShimmer{from{background-position:120% 0}to{background-position:-120% 0}}
.site-panel{padding:16px;display:flex;flex-direction:column;gap:14px}
.site-panel h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;letter-spacing:0}
.site-panel p{margin:0;color:var(--muted);font-size:12px}
.site-list{display:grid;gap:9px;overflow:auto;padding-right:2px}
.site-item{display:grid;gap:8px;padding:11px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.74)}
.site-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
.site-head strong{font-size:13px}
.site-count{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:22px;border-radius:999px;background:rgba(223,241,249,.78);color:#0f4f80;font-size:12px;font-weight:700}
.site-hosts{display:flex;flex-wrap:wrap;gap:6px}
.site-host{--host-state:var(--wait);display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;column-gap:6px;min-height:42px;padding:5px 8px;border:1px solid color-mix(in srgb,var(--host-state) 22%,transparent);border-radius:8px;background:color-mix(in srgb,var(--host-state) 8%,white);color:var(--ink);font-size:12px;text-decoration:none}
.site-host:before{content:"";grid-row:1/4;width:7px;height:7px;border-radius:50%;background:var(--host-state);box-shadow:0 0 0 4px color-mix(in srgb,var(--host-state) 12%,transparent)}
.site-host-name{line-height:1.1;font-weight:650;white-space:nowrap}
.site-host-signals{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px}
.site-host-ping{line-height:1.1;font-size:10px;color:var(--muted);white-space:nowrap}
.site-host-ping[data-probe-level="good"]{color:var(--live)}.site-host-ping[data-probe-level="warn"]{color:var(--stale)}.site-host-ping[data-probe-level="down"]{color:var(--down)}.site-host-ping[data-policy="blocked"]{color:var(--muted)}
.site-host-source{display:inline-flex;align-items:center;gap:4px;margin-left:auto;padding:2px 6px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:rgba(255,255,255,.78);color:#546b80;font-size:10px;line-height:1.1;white-space:nowrap}
.site-host-source:before{content:"";width:5px;height:5px;border-radius:50%;background:#8aa0b2;box-shadow:0 0 0 3px rgba(138,160,178,.10)}
.site-host-source[data-location-source="declared"]:before{background:#2d87bf}.site-host-source[data-location-source="wifi"]:before,.site-host-source[data-location-source="ip"]:before{background:var(--live)}.site-host-source[data-location-source="provider"]:before{background:var(--sea)}.site-host-source[data-location-source="fallback"]:before{background:var(--sun)}
.map-note{margin-top:auto;padding-top:8px;border-top:1px solid rgba(214,226,234,.72);color:var(--muted);font-size:11px}
.leaflet-container{height:100%;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink)}
.leaflet-control-zoom a{color:var(--ink)!important}
.map-label-layer{position:absolute;inset:0;z-index:650;pointer-events:none;overflow:hidden}
.map-links{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.map-link{fill:none;stroke:rgba(21,158,153,.36);stroke-width:1.15;opacity:.72;vector-effect:non-scaling-stroke}
.map-link[data-inbound-level="warn"]{stroke:rgba(214,155,49,.38)}.map-link[data-inbound-level="down"]{stroke:rgba(191,58,53,.30);stroke-dasharray:4 7}.map-link[data-outbound-policy="blocked"]{stroke:rgba(137,151,163,.34);stroke-dasharray:3 6;opacity:.42}
.map-packet{r:3;opacity:.78}.map-packet.inbound{fill:var(--sea)}.map-packet.outbound{fill:var(--accent)}.map-packet[data-level="warn"]{fill:var(--sun)}.map-packet[data-level="down"]{fill:var(--down)}.map-packet[data-policy="blocked"]{fill:var(--wait);opacity:.38}
.map-leaders{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.map-leaders line{stroke:#7a8c9c;stroke-width:1.2;stroke-dasharray:2 4;opacity:.52;vector-effect:non-scaling-stroke}
.map-anchor{--node-color:var(--wait);position:absolute;width:12px;height:12px;border-radius:50%;background:radial-gradient(circle,#fff 0 27%,var(--node-color) 33% 68%,transparent 70%);box-shadow:0 0 0 5px color-mix(in srgb,var(--node-color) 11%,transparent),0 6px 12px rgba(45,75,95,.14);transform:translate(-50%,-50%);pointer-events:none}
.map-anchor.live,.map-node.live{--node-color:var(--live)}.map-anchor.stale,.map-node.stale{--node-color:var(--stale)}.map-anchor.down,.map-node.down{--node-color:var(--down)}.map-anchor.awaiting_first_heartbeat,.map-node.awaiting_first_heartbeat{--node-color:var(--wait)}
.map-node{--node-color:var(--wait);position:absolute;display:grid;grid-template-columns:9px minmax(0,1fr);column-gap:7px;align-items:start;min-width:106px;max-width:154px;padding:6px 8px 7px 7px;border:1px solid color-mix(in srgb,var(--node-color) 30%,rgba(210,226,234,.92));border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 10px 22px rgba(45,75,95,.14),0 0 0 4px color-mix(in srgb,var(--node-color) 7%,transparent);-webkit-backdrop-filter:blur(8px) saturate(1.05);backdrop-filter:blur(8px) saturate(1.05);color:var(--ink);text-decoration:none;pointer-events:auto}
.map-node:hover{box-shadow:0 14px 28px rgba(45,75,95,.18),0 0 0 5px color-mix(in srgb,var(--node-color) 12%,transparent);transform:translateY(-1px)}
.map-status-dot{grid-row:1/4;width:9px;height:9px;margin-top:4px;border-radius:50%;background:var(--node-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--node-color) 13%,transparent)}
.map-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.15;font-weight:760;color:#17304a}
.map-signals{grid-column:2;display:grid;gap:2px;margin-top:2px}
.map-ping{display:flex;align-items:center;gap:4px;font-size:10px;line-height:1.15;color:var(--muted);white-space:nowrap}
.map-ping:before{content:attr(data-dir);width:17px;color:var(--muted);font-weight:700;text-transform:uppercase;font-size:8px;letter-spacing:.03em}
.map-ping[data-probe-level="good"]{color:var(--live)}.map-ping[data-probe-level="warn"]{color:var(--stale)}.map-ping[data-probe-level="down"]{color:var(--down)}.map-ping[data-policy="blocked"]{color:var(--muted)}
.map-source{grid-column:2;justify-self:start;display:inline-flex;align-items:center;gap:4px;margin-top:4px;padding:2px 6px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:rgba(255,255,255,.76);color:#546b80;font-size:10px;line-height:1.1;white-space:nowrap}
.map-source:before{content:"";width:5px;height:5px;border-radius:50%;background:#8aa0b2;box-shadow:0 0 0 3px rgba(138,160,178,.10)}
.map-source[data-location-source="declared"]:before{background:#2d87bf}.map-source[data-location-source="wifi"]:before,.map-source[data-location-source="ip"]:before{background:var(--live)}.map-source[data-location-source="provider"]:before{background:var(--sea)}.map-source[data-location-source="fallback"]:before{background:var(--sun)}
.map-panel[data-label-density="compact"] .map-node{grid-template-columns:8px max-content;align-items:center;min-width:0;max-width:132px;padding:5px 8px 5px 7px}
.map-panel[data-label-density="compact"] .map-status-dot{grid-row:auto;margin-top:0;width:8px;height:8px}
.map-panel[data-label-density="compact"] .map-name{font-size:12px}
.map-panel[data-label-density="compact"] .map-signals,.map-panel[data-label-density="compact"] .map-source{display:none}
@media (max-width:900px){.app-shell{display:block}.sidebar{position:relative;height:auto;min-height:0;display:grid;grid-template-columns:1fr;gap:14px;padding:18px;border-right:0;border-bottom:1px solid rgba(211,225,233,.78)}.sidebar:before{display:none}.side-brand{padding:0}.side-nav{grid-template-columns:repeat(3,minmax(0,1fr))}.side-link{min-height:38px;padding:0 10px}.side-foot{display:none}main{padding:28px 18px 42px}.top{display:block;min-height:112px}.asof{padding-top:10px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.toolbar{align-items:stretch;flex-direction:column}.toolbar-left,.toolbar-right{justify-content:space-between}.search{min-width:0;width:100%}.grid{grid-template-columns:1fr}.list-wrap{overflow-x:auto}.list{min-width:1050px}}
@media (max-width:1100px){.map-layout{grid-template-columns:1fr}.site-panel{display:block}.site-list{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:12px}.map-note{margin-top:12px}.map-layout[data-mode="maximized"] .site-panel{display:none}}
@media (max-width:1100px){.ops-layout{grid-template-columns:1fr}.alert-row{grid-template-columns:1fr 92px}.alert-issue{grid-column:1/-1}.ops-source,.ops-time,.next-action{font-size:11px}.activity-row{grid-template-columns:78px minmax(0,1fr)}.activity-host,.activity-copy,.activity-row .severity,.activity-row .ops-source{grid-column:2}.ops-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:720px){.empty-state{grid-template-columns:1fr;min-height:0;padding:24px}.empty-copy h2{font-size:24px}.empty-visual{min-height:210px;order:-1}.lone-state{grid-template-columns:auto 1fr}.lone-state .onboard-primary{grid-column:1/-1;width:100%}.map-panel{min-height:420px}.fleet-map{min-height:420px}.map-mode-controls{top:10px;right:10px}.ops-summary{grid-template-columns:1fr}.alert-row{grid-template-columns:1fr}.activity-row{grid-template-columns:1fr}.activity-host,.activity-copy,.activity-row .severity,.activity-row .ops-source{grid-column:auto}}
@media (prefers-reduced-motion:reduce){.beat-current,.beat[data-flash="true"] .beat-hit{animation:none}}
</style></head><body><div class="app-shell">"#;

const FOOT: &str = r#"</div><script>
const words={live:'live',stale:'stale',down:'down',awaiting_first_heartbeat:'awaiting'};
const HISTORY_DOTS=12;
const EXPECT_X=64;
const STALE_X=82;
const HISTORY_STEP=EXPECT_X/HISTORY_DOTS;
const SIGNAL_WINDOWS=[{key:'10m',label:'10m',secs:10*60},{key:'1h',label:'1h',secs:60*60},{key:'24h',label:'24h',secs:24*60*60}];
let signalWindow=SIGNAL_WINDOWS[0];
let activeSearch='';
let activeLiveFilter='all';
function dur(s){s=Math.max(0,s);if(s<10)return s.toFixed(1)+'s';s=Math.ceil(s);return s<60?s+'s':Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s'}
function clock(t){return new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
const ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(v){return String(v ?? '').replace(/[&<>"']/g,ch=>ESC[ch])}
function cookie(name){return document.cookie.split('; ').find(v=>v.startsWith(name+'='))?.split('=').slice(1).join('=')||''}
function setCookie(name,value){document.cookie=name+'='+encodeURIComponent(value)+'; path=/; max-age=31536000; SameSite=Lax'}
function hostSurfaces(name){return Array.from(document.querySelectorAll('[data-host-surface="runtime"]')).filter(el=>el.dataset.host===name)}
function parseBeats(v){return String(v||'').split(',').map(Number).filter(Number.isFinite).filter(n=>n>0)}
function signalWindowByKey(key){return SIGNAL_WINDOWS.find(w=>w.key===key)||SIGNAL_WINDOWS[0]}
function historyWindowMeta(samples,windowDef){
  if(samples.length<2)return {start:0,latest:0,span:1,candidates:[]};
  const latest=samples[samples.length-1];
  const start=Math.max(latest-windowDef.secs,samples[0]);
  const span=Math.max(1,latest-start);
  const candidates=samples.map((stamp,index)=>({stamp,index})).filter(item=>item.index>0&&item.stamp>=start&&item.stamp<=latest);
  return {start,latest,span,candidates};
}
function visibleHistory(samples,windowDef){
  const meta=historyWindowMeta(samples,windowDef);
  if(meta.candidates.length<=HISTORY_DOTS)return {...meta,visible:meta.candidates};
  const buckets=Array(HISTORY_DOTS).fill(null);
  for(const item of meta.candidates){
    const bucket=Math.min(HISTORY_DOTS-1,Math.max(0,Math.floor(((item.stamp-meta.start)/meta.span)*HISTORY_DOTS)));
    buckets[bucket]=item;
  }
  return {...meta,visible:buckets.filter(Boolean)};
}
function historyInfo(beats,index,interval){
  const stamp=beats[index];
  const previous=index>0?beats[index-1]:null;
  if(previous==null)return {level:'first',label:'first heartbeat',detail:'at '+clock(stamp)};
  const gap=Math.max(0,stamp-previous);
  if(gap<=interval)return {level:'ok',label:'on cadence',detail:dur(gap)+' after previous · '+clock(stamp)};
  if(gap<=interval*2)return {level:'late',label:'late heartbeat',detail:dur(gap)+' after previous · '+clock(stamp)};
  if(gap<=interval*5)return {level:'stale',label:'stale gap recovered',detail:dur(gap)+' after previous · '+clock(stamp)};
  return {level:'down',label:'offline gap recovered',detail:dur(gap)+' after previous · '+clock(stamp)};
}
function freshRow(label,value,klass){return '<div class="fresh-row"><span>'+esc(label)+'</span><strong class="'+klass+'">'+esc(value)+'</strong></div>'}
function freshValue(v,zero){
  const n=Number(v);
  if(v==null||!Number.isFinite(n))return {value:'unknown',klass:'na'};
  if(n===0)return {value:zero,klass:'ok'};
  return {value:String(n),klass:'warn'};
}
function freshHtml(f){
  if(!f||f.applicable===false)return freshRow('Flake.lock age','n/a','na')+freshRow('Commits behind','n/a','na');
  const age=freshValue(f.flake_lock_age_days,'fresh');
  const commits=freshValue(f.commits_behind,'0');
  if(age.klass==='warn')age.value=age.value+'d';
  return freshRow('Flake.lock age',age.value,age.klass)+freshRow('Commits behind',commits.value,commits.klass);
}
function freshnessAttention(f){
  if(!f||f.applicable===false)return null;
  const age=Number(f.flake_lock_age_days);
  const commits=Number(f.commits_behind);
  const hasAge=f.flake_lock_age_days!=null&&Number.isFinite(age);
  const hasCommits=f.commits_behind!=null&&Number.isFinite(commits);
  const ageWarn=hasAge&&age>0;
  const commitsWarn=hasCommits&&commits>0;
  if(ageWarn&&commitsWarn)return {label:'nix drift: '+age+'d · '+commits+' commits',level:'warn',rank:3};
  if(ageWarn)return {label:'flake.lock '+age+'d',level:'warn',rank:3};
  if(commitsWarn)return {label:commits+' commits behind',level:'warn',rank:3};
  if(!hasAge||!hasCommits)return {label:'freshness unknown',level:'wait',rank:3};
  return null;
}
function attentionFor(live,f){
  if(live==='down')return {label:'silent heartbeat',level:'down',rank:0};
  if(live==='stale')return {label:'stale heartbeat',level:'warn',rank:1};
  if(live==='awaiting_first_heartbeat')return {label:'awaiting first beat',level:'wait',rank:2};
  return freshnessAttention(f)||{label:'all clear',level:'ok',rank:4};
}
const BACKUP_RANK={failed:0,missing:1,stale:2,warning:3,unknown:4,'not-configured':5,healthy:6};
const BACKUP_LEVEL={failed:'critical',missing:'critical',stale:'warning',warning:'warning',unknown:'watch','not-configured':'watch',healthy:'clear'};
const BACKUP_LABEL={failed:'Backup failed',missing:'Backup missing',stale:'Backup stale',warning:'Review backup',unknown:'Backup pending','not-configured':'No backup',healthy:'Protected'};
function backupRunLabel(state){
  return ({succeeded:'succeeded',failed:'failed',running:'running',unknown:'unknown'})[state]||String(state||'unknown');
}
function backupDetail(obs,now){
  if(!obs)return 'No backup signal yet';
  if(obs.state==='healthy'&&Number.isFinite(Number(obs.last_success_at)))return 'last success '+dur(now-Number(obs.last_success_at))+' ago';
  if(Number.isFinite(Number(obs.last_attempt_at))&&obs.last_attempt_state)return backupRunLabel(obs.last_attempt_state)+' · '+dur(now-Number(obs.last_attempt_at))+' ago';
  return String(obs.summary||'backup status reported');
}
function backupInfo(host,now){
  const observations=Array.isArray(host.backup_observations)?host.backup_observations:[];
  if(!observations.length)return {state:'unknown',level:'watch',label:'Not observed',detail:'No backup signal yet',search:'',total:0};
  const primary=[...observations].sort((a,b)=>(BACKUP_RANK[a.state]??4)-(BACKUP_RANK[b.state]??4))[0];
  const state=primary.state||'unknown';
  const label=BACKUP_LABEL[state]||'Backup pending';
  const detail=backupDetail(primary,now);
  const last=Number.isFinite(Number(primary.last_success_at))?dur(now-Number(primary.last_success_at))+' ago':'not yet';
  const schedule=String(primary.schedule||'not declared');
  const target=String(primary.target_label||'not declared');
  return {state,level:BACKUP_LEVEL[state]||'watch',label,detail,total:observations.length,search:[label,detail,last,schedule,target].join(' ')};
}
function updateBackup(surface,info){
  const el=surface.querySelector('[data-backup-state]');
  if(!el)return;
  const list=el.classList.contains('backup-list');
  el.className='backup-mini'+(list?' backup-list':'')+' '+info.level;
  el.dataset.backupState=info.state;
  el.title='Backup: '+info.label+' - '+info.detail;
  const label=el.querySelector('strong');
  const detail=el.querySelector('span');
  if(label)label.textContent=info.label;
  if(detail)detail.textContent=info.detail;
}
function setReason(surface,reason){
  const el=surface.querySelector('[data-reason]');
  if(!el)return;
  el.className='reason '+reason.level;
  const text=el.querySelector('span');
  if(text)text.textContent=reason.label;
}
function markHtml(beats,interval,windowDef=signalWindow){
  const kept=Array.from(new Set(beats)).sort((a,b)=>a-b);
  if(kept.length<2)return '';
  const cadence=Math.max(1,Number(interval)||60);
  const newestX=EXPECT_X-HISTORY_STEP;
  const view=visibleHistory(kept,windowDef);
  return view.visible.map(item=>{
    const x=((item.stamp-view.start)/view.span)*newestX;
    const info=historyInfo(kept,item.index,cadence);
    const title=info.label+' · '+info.detail;
    return '<span class="beat-mark" tabindex="0" data-history-level="'+esc(info.level)+'" data-history-label="'+esc(info.label)+'" data-history-detail="'+esc(info.detail)+'" title="'+esc(title)+'" aria-label="'+esc(title)+'" style="--mark-x:'+x.toFixed(1)+'%"></span>';
  }).join('');
}
function signalInfo(beats,last,interval,now,windowDef=signalWindow){
  const cadence=Math.max(1,Number(interval)||60);
  const samples=Array.from(new Set(beats.concat(Number.isFinite(last)&&last>0?[last]:[]))).filter(Number.isFinite).filter(n=>n>0).sort((a,b)=>a-b);
  if(!samples.length)return {text:'new',level:'wait',window:windowDef.label,title:'Signal over '+windowDef.label+': waiting for first heartbeat'};
  const requestedStart=now-windowDef.secs;
  const retainedStart=Math.max(requestedStart,samples[0]);
  const span=Math.max(cadence,Math.min(windowDef.secs,now-retainedStart));
  const expected=Math.max(1,Math.ceil(span/cadence));
  const received=samples.filter(stamp=>stamp>=retainedStart&&stamp<=now).length;
  let longestGap=Math.max(0,Math.min(now-samples[samples.length-1],span));
  let previous=retainedStart;
  for(const stamp of samples){
    if(stamp<retainedStart||stamp>now)continue;
    longestGap=Math.max(longestGap,stamp-previous);
    previous=stamp;
  }
  longestGap=Math.max(longestGap,now-previous);
  const percent=Math.max(0,Math.min(100,Math.round((received/expected)*100)));
  const level=percent>=95?'good':percent>=75?'warn':'down';
  const coverage=retainedStart>requestedStart?' · retained '+dur(span):'';
  return {text:percent+'%',level,window:windowDef.label,title:'Signal over '+windowDef.label+': '+received+' of '+expected+' expected heartbeats received · longest gap '+dur(longestGap)+coverage};
}
function updateSignal(surface,info){
  const signal=surface?.querySelector('[data-signal]');
  if(!signal)return;
  signal.dataset.signalLevel=info.level;
  signal.dataset.signalWindowKey=info.window;
  signal.title=info.title;
  signal.setAttribute('aria-label',info.title);
  const text=signal.querySelector('[data-signal-percent]');
  if(text)text.textContent=info.text;
  const windowLabel=signal.querySelector('[data-signal-window]');
  if(windowLabel){
    const next=SIGNAL_WINDOWS[(SIGNAL_WINDOWS.findIndex(w=>w.label===info.window)+1)%SIGNAL_WINDOWS.length]||SIGNAL_WINDOWS[0];
    windowLabel.textContent=info.window;
    windowLabel.title=info.title+'; click for '+next.label;
    windowLabel.setAttribute('aria-label',info.title+'; click for '+next.label);
  }
}
function setHistoryHint(mark,show){
  const card=mark.closest('.card');
  if(!card)return;
  const seen=card.querySelector('[data-seen]');
  const asof=card.querySelector('[data-card-asof]');
  if(!seen||!asof)return;
  if(show){
    card.dataset.historyHint='true';
    seen.textContent=mark.dataset.historyLabel||'historic heartbeat';
    asof.textContent=mark.dataset.historyDetail||'';
  }else{
    delete card.dataset.historyHint;
    seen.textContent=seen.dataset.defaultText||seen.textContent;
    asof.textContent=asof.dataset.defaultText||asof.textContent;
  }
}
function bindHistoryHints(root=document){
  root.querySelectorAll('.beat-mark').forEach(mark=>{
    if(mark.dataset.hintBound==='true')return;
    mark.dataset.hintBound='true';
    mark.addEventListener('mouseenter',()=>setHistoryHint(mark,true));
    mark.addEventListener('mouseleave',()=>setHistoryHint(mark,false));
    mark.addEventListener('focus',()=>setHistoryHint(mark,true));
    mark.addEventListener('blur',()=>setHistoryHint(mark,false));
  });
}
function setBeatHistory(beat,beats,interval){
  const all=Array.from(new Set(beats)).sort((a,b)=>a-b);
  const view=visibleHistory(all,signalWindow);
  const kept=view.visible.map(item=>item.stamp);
  const cadence=Math.max(1,Number(interval)||Number(beat.dataset.interval)||60);
  beat.dataset.signalBeats=all.join(',');
  beat.dataset.beats=kept.join(',');
  beat.dataset.count=String(kept.length);
  beat.dataset.historyWindow=signalWindow.label;
  const windowLabel=beat.querySelector('[data-history-window-label]');
  if(windowLabel)windowLabel.textContent=signalWindow.label;
  const marks=beat.querySelector('.beat-marks');
  if(marks){
    marks.innerHTML=markHtml(all,cadence,signalWindow);
    bindHistoryHints(marks);
  }
}
function flashBeat(beat){
  beat.dataset.flash='true';
  window.setTimeout(()=>{delete beat.dataset.flash},950);
}
function heartbeatX(age,interval){
  if(age<=interval)return (age/interval)*EXPECT_X;
  if(age<=interval*2)return EXPECT_X+((age-interval)/interval)*(STALE_X-EXPECT_X);
  if(age<=interval*5)return STALE_X+((age-interval*2)/(interval*3))*(100-STALE_X);
  return 100;
}
function updateBeatClock(beat,now){
  const last=Number(beat.dataset.last);
  const interval=Math.max(1,Number(beat.dataset.interval)||60);
  const surface=beat.closest('[data-host]');
  if(!Number.isFinite(last)||last<=0){
    beat.style.setProperty('--expect-alpha','.22');
    beat.style.setProperty('--now-x','0%');
    beat.style.setProperty('--fill-color','var(--wait)');
    beat.style.setProperty('--expect-fill','0deg');
    beat.style.setProperty('--target-ring','3px');
    beat.style.setProperty('--late-alpha','.3');
    beat.dataset.beat='waiting';
    updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats),last,interval,now));
    return;
  }
  const age=Math.max(0,now-last);
  const expect=Math.max(0,Math.min(1,age/interval));
  const x=heartbeatX(age,interval);
  beat.style.setProperty('--now-x',x.toFixed(2)+'%');
  beat.style.setProperty('--expect-alpha',(.34+expect*.45).toFixed(3));
  beat.style.setProperty('--expect-fill',(expect*360).toFixed(1)+'deg');
  beat.style.setProperty('--target-ring',(3+expect*5).toFixed(1)+'px');
  if(age<=interval){
    beat.style.setProperty('--fill-color',beat.dataset.self==='true'?'var(--sun)':'var(--sea)');
    beat.dataset.beat=beat.dataset.self==='true'?'lit':'tracking';
  }else if(age<=interval*2){
    beat.style.setProperty('--fill-color','var(--sun)');
    beat.style.setProperty('--expect-alpha','.79');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='late';
  }else if(age<=interval*5){
    beat.style.setProperty('--fill-color','var(--stale)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='stale';
  }else{
    beat.style.setProperty('--fill-color','var(--down)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='down';
  }
  updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats||beat.dataset.beats),last,interval,now));
}
function frame(){
  const now=Date.now()/1000;
  document.querySelectorAll('.beat').forEach(beat=>{
    updateBeatClock(beat,now);
  });
  requestAnimationFrame(frame);
}
function setSeen(card,last,now){
  const seen=card.querySelector('[data-seen]');
  if(!seen)return;
  const text=last==null?'never seen':'last seen '+dur(now-last)+' ago';
  seen.dataset.defaultText=text;
  if(card.dataset.historyHint!=='true')seen.textContent=text;
}
function setCardAsOf(card,now){
  const asof=card.querySelector('[data-card-asof]');
  if(!asof)return;
  const text='as of '+clock(now);
  asof.dataset.defaultText=text;
  if(card.dataset.historyHint!=='true')asof.textContent=text;
}
function sevFor(live){return live==='down'?0:live==='stale'?1:live==='awaiting_first_heartbeat'?2:3}
function cmp(a,b,mode){
  if(mode==='name')return a.dataset.sortName.localeCompare(b.dataset.sortName);
  if(mode==='last')return Number(b.dataset.last||0)-Number(a.dataset.last||0)||a.dataset.sortName.localeCompare(b.dataset.sortName);
  return Number(a.dataset.sev)-Number(b.dataset.sev)||a.dataset.sortName.localeCompare(b.dataset.sortName);
}
const FREEFORM_ORDER_KEY='pharos_freeform_order_v1';
function readFreeformOrder(){
  try{
    const parsed=JSON.parse(window.localStorage.getItem(FREEFORM_ORDER_KEY)||'[]');
    return Array.isArray(parsed)?parsed.filter(v=>typeof v==='string'&&v):[];
  }catch(_){return []}
}
function writeFreeformOrder(){
  const grid=document.querySelector('[data-grid]');
  if(!grid)return;
  try{
    const order=Array.from(grid.querySelectorAll('.card')).map(el=>el.dataset.host).filter(Boolean);
    window.localStorage.setItem(FREEFORM_ORDER_KEY,JSON.stringify(order));
  }catch(_){}
}
function clearFreeformOrder(){
  try{window.localStorage.removeItem(FREEFORM_ORDER_KEY)}catch(_){}
}
function sortByFreeformOrder(items,order){
  const index=new Map(order.map((name,idx)=>[name,idx]));
  return items.sort((a,b)=>{
    const ai=index.has(a.dataset.host)?index.get(a.dataset.host):Number.MAX_SAFE_INTEGER;
    const bi=index.has(b.dataset.host)?index.get(b.dataset.host):Number.MAX_SAFE_INTEGER;
    return ai-bi||a.dataset.sortName.localeCompare(b.dataset.sortName);
  });
}
function keepOnboardAffordanceLast(){
  const grid=document.querySelector('[data-grid]');
  const tile=document.querySelector('[data-onboard-tile]');
  if(grid&&tile)grid.appendChild(tile);
}
function applyFreeformOrder(){
  const grid=document.querySelector('[data-grid]');
  const body=document.querySelector('[data-list-body]');
  const order=readFreeformOrder();
  if(!order.length){
    writeFreeformOrder();
    keepOnboardAffordanceLast();
    return;
  }
  if(grid)sortByFreeformOrder(Array.from(grid.querySelectorAll('.card')),order).forEach(el=>grid.appendChild(el));
  if(body)sortByFreeformOrder(Array.from(body.querySelectorAll('tr')),order).forEach(el=>body.appendChild(el));
  keepOnboardAffordanceLast();
}
function setArrangeMode(mode){
  const main=document.querySelector('main');
  if(main)main.dataset.arrange=mode;
}
function applySort(mode,write=true){
  mode=['attention','name','last','freeform'].includes(mode)?mode:'attention';
  const grid=document.querySelector('[data-grid]');
  const body=document.querySelector('[data-list-body]');
  setArrangeMode(mode);
  if(mode==='freeform'){
    applyFreeformOrder();
  }else{
    if(write)clearFreeformOrder();
    if(grid)Array.from(grid.querySelectorAll('.card')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>grid.appendChild(el));
    if(body)Array.from(body.querySelectorAll('tr')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>body.appendChild(el));
  }
  keepOnboardAffordanceLast();
  const select=document.querySelector('[data-sort]');
  if(select)select.value=mode;
  if(write)setCookie('pharos_sort',mode);
}
function applyView(view,write=true){
  view=view==='list'?'list':'grid';
  const main=document.querySelector('main');
  if(main)main.dataset.view=view;
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.setAttribute('aria-pressed',String(btn.dataset.viewButton===view)));
  if(write)setCookie('pharos_view',view);
}
function hostMatchesSurface(el,q,live){
  const text=q===''||String(el.dataset.search||'').includes(q);
  const state=live==='all'||el.dataset.live===live;
  return text&&state;
}
function updateGroupVisibility(){
  document.querySelectorAll('.site-item').forEach(site=>{
    const visible=Array.from(site.querySelectorAll('.site-host')).some(host=>!host.hidden);
    site.hidden=!visible;
  });
}
function updateSummaryFilterButtons(){
  document.querySelectorAll('[data-live-filter]').forEach(btn=>{
    const active=btn.dataset.liveFilter===activeLiveFilter;
    btn.setAttribute('aria-pressed',active?'true':'false');
  });
}
function applySurfaceFilters(write=true){
  const q=activeSearch.trim().toLowerCase();
  document.querySelectorAll('[data-host]').forEach(el=>{
    if(el.dataset.mapLayer==='managed')return;
    el.hidden=!hostMatchesSurface(el,q,activeLiveFilter);
  });
  updateGroupVisibility();
  if(typeof window.pharosMapApplyFilter==='function')window.pharosMapApplyFilter(q,activeLiveFilter);
  updateSummaryFilterButtons();
  if(write){
    setCookie('pharos_search',activeSearch);
    setCookie('pharos_live_filter',activeLiveFilter);
  }
}
function applyFilter(query,write=true){
  activeSearch=query;
  const input=document.querySelector('[data-search]');
  if(input&&input.value!==query)input.value=query;
  applySurfaceFilters(write);
}
function applyLiveFilter(filter,write=true){
  activeLiveFilter=['all','live','stale','down','awaiting_first_heartbeat'].includes(filter)?filter:'all';
  applySurfaceFilters(write);
}
function applySignalWindow(key,write=true){
  signalWindow=signalWindowByKey(key);
  document.querySelectorAll('.beat').forEach(beat=>{
    const surface=beat.closest('[data-host]');
    const last=Number(beat.dataset.last);
    const interval=Math.max(1,Number(beat.dataset.interval)||60);
    setBeatHistory(beat,parseBeats(beat.dataset.signalBeats||beat.dataset.beats),interval);
    updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats||beat.dataset.beats),last,interval,Date.now()/1000,signalWindow));
  });
  if(write)setCookie('pharos_signal_window',signalWindow.key);
}
function cycleSignalWindow(){
  const idx=SIGNAL_WINDOWS.findIndex(w=>w.key===signalWindow.key);
  applySignalWindow(SIGNAL_WINDOWS[(idx+1)%SIGNAL_WINDOWS.length].key);
  updateUrlState();
}
function freeformTarget(grid,x,y){
  let best=null;
  let bestDistance=Infinity;
  let bestAfter=false;
  grid.querySelectorAll('.card:not([data-dragging]):not([hidden])').forEach(card=>{
    const box=card.getBoundingClientRect();
    const cx=box.left+box.width/2;
    const cy=box.top+box.height/2;
    const distance=Math.hypot(x-cx,(y-cy)*1.35);
    if(distance<bestDistance){
      best=card;
      bestDistance=distance;
      bestAfter=y>cy||Math.abs(y-cy)<box.height*.42&&x>cx;
    }
  });
  return {card:best,after:bestAfter};
}
function bindFreeformDrag(){
  const grid=document.querySelector('[data-grid]');
  if(!grid||grid.dataset.freeformBound==='true')return;
  grid.dataset.freeformBound='true';
  let drag=null;
  function finish(){
    if(!drag)return;
    delete drag.card.dataset.dragging;
    drag.card.style.zIndex='';
    delete grid.dataset.freeformDragging;
    writeFreeformOrder();
    applyFreeformOrder();
    drag=null;
  }
  grid.addEventListener('pointerdown',event=>{
    const handle=event.target.closest('[data-drag-handle]');
    if(!handle||!grid.contains(handle))return;
    if(document.querySelector('main')?.dataset.arrange!=='freeform')return;
    if(event.button!==0)return;
    const card=handle.closest('.card');
    if(!card)return;
    event.preventDefault();
    handle.setPointerCapture?.(event.pointerId);
    drag={card,pointerId:event.pointerId};
    card.dataset.dragging='true';
    card.style.zIndex='20';
    grid.dataset.freeformDragging='true';
  });
  grid.addEventListener('pointermove',event=>{
    if(!drag||event.pointerId!==drag.pointerId)return;
    event.preventDefault();
    const target=freeformTarget(grid,event.clientX,event.clientY);
    if(!target.card){
      grid.appendChild(drag.card);
      return;
    }
    const before=target.after?target.card.nextSibling:target.card;
    if(before!==drag.card)grid.insertBefore(drag.card,before);
  });
  grid.addEventListener('pointerup',event=>{if(drag&&event.pointerId===drag.pointerId)finish()});
  grid.addEventListener('pointercancel',event=>{if(drag&&event.pointerId===drag.pointerId)finish()});
  window.addEventListener('blur',finish);
}
const ASSISTANT_SETUP_PARAM='setup';
const ASSISTANT_PATH_PARAM='setup_path';
const ASSISTANT_PROVIDER_PARAM='setup_provider';
const ASSISTANT_TEMPLATE_PARAM='setup_template';
const ASSISTANT_STAGE_PARAM='setup_stage';
const ASSISTANT_TEMPLATE_PROVIDERS={
  'hetzner-small-nixos':'hetzner-cloud',
  'hetzner-lab':'hetzner-cloud',
  'bring-own-plan':'hetzner-cloud',
  'manual-import':'manual-import',
  'nixos-anywhere':'existing-host',
  'native-systemd':'existing-host',
  'manual-deferred':'existing-host'
};
function assistantPath(path){
  return ['new','existing'].includes(path)?path:'';
}
function assistantProvider(provider){
  return ['hetzner-cloud','manual-import','existing-host'].includes(provider)?provider:'';
}
function assistantTemplate(template){
  return Object.prototype.hasOwnProperty.call(ASSISTANT_TEMPLATE_PROVIDERS,template)?template:'';
}
function assistantStage(stage){
  return stage==='plan'?'plan':'';
}
function assistantState(overlay){
  return {
    path: assistantPath(overlay?.dataset.assistantSelectedPath||''),
    provider: assistantProvider(overlay?.dataset.assistantSelectedProvider||''),
    template: assistantTemplate(overlay?.dataset.assistantSelectedTemplate||''),
    stage: assistantStage(overlay?.dataset.assistantStage||'')
  };
}
function writeAssistantUrl(open,path='',provider='',template='',stage=''){
  const params=new URLSearchParams(location.search);
  if(open){
    params.set(ASSISTANT_SETUP_PARAM,'add-server');
    const safePath=assistantPath(path);
    if(safePath)params.set(ASSISTANT_PATH_PARAM,safePath);
    else params.delete(ASSISTANT_PATH_PARAM);
    const safeProvider=safePath==='new'?assistantProvider(provider):'';
    const safeTemplate=safePath==='new'?assistantTemplate(template):'';
    if(safeProvider)params.set(ASSISTANT_PROVIDER_PARAM,safeProvider);
    else params.delete(ASSISTANT_PROVIDER_PARAM);
    if(safeTemplate&&ASSISTANT_TEMPLATE_PROVIDERS[safeTemplate]===safeProvider)params.set(ASSISTANT_TEMPLATE_PARAM,safeTemplate);
    else params.delete(ASSISTANT_TEMPLATE_PARAM);
    const safeStage=safeTemplate?assistantStage(stage):'';
    if(safeStage)params.set(ASSISTANT_STAGE_PARAM,safeStage);
    else params.delete(ASSISTANT_STAGE_PARAM);
  }else{
    params.delete(ASSISTANT_SETUP_PARAM);
    params.delete(ASSISTANT_PATH_PARAM);
    params.delete(ASSISTANT_PROVIDER_PARAM);
    params.delete(ASSISTANT_TEMPLATE_PARAM);
    params.delete(ASSISTANT_STAGE_PARAM);
  }
  const query=params.toString();
  history.replaceState(null,'',location.pathname+(query?'?'+query:''));
}
function syncAssistantNext(overlay){
  const {path,provider,template,stage}=assistantState(overlay);
  const title=overlay.querySelector('[data-assistant-next-title]');
  const copy=overlay.querySelector('[data-assistant-next-copy]');
  const button=overlay.querySelector('[data-assistant-continue]');
  if(button){
    button.disabled=true;
    button.textContent='Continue';
  }
  if(path==='new'){
    if(template&&stage==='plan'){
      if(title)title.textContent='Review plan';
      if(copy)copy.textContent='Confirm only after the plan looks right. No resources or tokens are created by viewing this plan.';
    }else if(template){
      const selected=[...overlay.querySelectorAll('[data-assistant-template]')].find(btn=>btn.dataset.assistantTemplate===template);
      if(title)title.textContent='Template selected';
      if(copy)copy.textContent=selected?.dataset.assistantNext||'Next: review the provisioning plan before anything is created.';
      if(button)button.disabled=false;
    }else if(provider){
      if(title)title.textContent='Choose a template';
      if(copy)copy.textContent='Pick a starting point. No credentials, resources, or host records have been created.';
    }else{
      if(title)title.textContent='Choose a provider';
      if(copy)copy.textContent='Hetzner is the polished path. Manual and Netcup-style hosts route through import.';
    }
  }else if(path==='existing'){
    const result=overlay.querySelector('[data-preflight-result]');
    const summary=overlay.querySelector('[data-preflight-summary]');
    if(stage==='plan'){
      if(title)title.textContent='Protection and place';
      if(copy)copy.textContent=`${currentSetupIntentSummary(overlay)} These choices are setup intent only; no runtime facts or secrets are stored here.`;
    }else{
      if(title)title.textContent=result&&!result.hidden?(summary?.textContent||'Preflight complete'):'Check existing server';
      if(copy)copy.textContent=result&&!result.hidden?'Choose a bootstrap path only after the read-only checks look right.':'Enter the server name and SSH address, then run a read-only preflight. No tokens or host records are created.';
    }
  }else{
    if(title)title.textContent='Next step';
    if(copy)copy.textContent='Choose a path to preview the next step. No changes have been started.';
  }
}
function provisioningJobTerminal(state){
  return ['complete','failed','cleanup-needed'].includes(state||'');
}
function provisioningJobLabel(state){
  return String(state||'pending').replace(/-/g,' ');
}
function latestProvisioningMessage(job){
  const progress=Array.isArray(job?.progress)?job.progress:[];
  const latest=progress[progress.length-1];
  return latest?.message||'Tracked setup job is waiting for progress.';
}
function provisioningHandoffMessage(job){
  const handoff=job?.handoff;
  if(!handoff)return '';
  const parts=[
    handoff.title||'Bootstrap handoff',
    handoff.summary||'',
    handoff.token_policy||'',
    handoff.secret_target?`Target: ${handoff.secret_target}.`:'',
    handoff.command_ref?`Use: ${handoff.command_ref}.`:'',
    ...(Array.isArray(handoff.next_steps)?handoff.next_steps:[])
  ];
  return parts.filter(Boolean).join(' ');
}
const BACKUP_INTENT_COPY={
  'required':['backup required','observe existing jobs or queue Pharos enrollment'],
  'optional':['backup optional','offer enrollment, but do not block onboarding'],
  'external':['managed elsewhere','observe external backup evidence when available'],
  'enroll-later':['enroll later','queue backup enrollment after first heartbeat'],
  'absent':['no backups','record that backups are intentionally absent'],
  'deferred':['backup decision pending','ask again before marking onboarding complete']
};
const LOCATION_INTENT_COPY={
  'auto':['auto location','use runtime auto-detection when the beacon reports'],
  'manual':['manual location','collect declared coordinates outside runtime facts'],
  'site-fallback':['site fallback','use provider or site fallback when runtime is missing'],
  'hidden':['hidden location','keep host coordinates hidden']
};
function setupIntentChoice(overlay,name,fallback){
  return overlay.querySelector(`input[name="${name}"]:checked`)?.value||fallback;
}
function setupIntentSummary(backup,location){
  const backupCopy=BACKUP_INTENT_COPY[backup]||BACKUP_INTENT_COPY.deferred;
  const locationCopy=LOCATION_INTENT_COPY[location]||LOCATION_INTENT_COPY.auto;
  return `Backups: ${backupCopy[0]}. Location: ${locationCopy[0]}.`;
}
function setupIntentDetail(backup,location){
  const backupCopy=BACKUP_INTENT_COPY[backup]||BACKUP_INTENT_COPY.deferred;
  const locationCopy=LOCATION_INTENT_COPY[location]||LOCATION_INTENT_COPY.auto;
  return `Next: ${backupCopy[1]}; ${locationCopy[1]}.`;
}
function currentSetupIntentSummary(overlay){
  return setupIntentSummary(
    setupIntentChoice(overlay,'backup_intent','deferred'),
    setupIntentChoice(overlay,'location_intent','auto')
  );
}
function provisioningIntentMessage(job){
  const intent=job?.setup_intent;
  if(!intent)return '';
  return `Setup intent recorded. ${setupIntentSummary(intent.backup,intent.location)} ${setupIntentDetail(intent.backup,intent.location)}`;
}
function provisioningBackupProposalMessage(job){
  const proposal=job?.backup_proposal;
  if(!proposal)return '';
  const files=Array.isArray(proposal.secret_files)?proposal.secret_files:[];
  const fileCopy=files.map(file=>`${file.key||'runtime file'} at ${file.path||'runtime path'}`).join('; ');
  const next=Array.isArray(proposal.next_steps)?proposal.next_steps.join(' '):'';
  return [`Backup proposal: ${proposal.title||'declarative backup proposal'}.`,proposal.summary||'',fileCopy?`Runtime files: ${fileCopy}.`:'',next].filter(Boolean).join(' ');
}
function renderProvisioningJob(overlay,job){
  if(!overlay||!job)return;
  overlay.dataset.assistantJobId=job.id||'';
  const title=overlay.querySelector('[data-assistant-next-title]');
  const copy=overlay.querySelector('[data-assistant-next-copy]');
  const jobBox=overlay.querySelector('[data-assistant-job]');
  const jobTitle=overlay.querySelector('[data-assistant-job-title]');
  const jobMessage=overlay.querySelector('[data-assistant-job-message]');
  const label=provisioningJobLabel(job.state);
  const message=latestProvisioningMessage(job);
  const handoff=provisioningHandoffMessage(job);
  const setupIntent=provisioningIntentMessage(job);
  const backupProposal=provisioningBackupProposalMessage(job);
  const fullMessage=[handoff||message,setupIntent,backupProposal].filter(Boolean).join(' ');
  if(title)title.textContent=job.state==='failed'?'Setup did not start':`Setup ${label}`;
  if(copy)copy.textContent=fullMessage;
  if(jobBox){
    jobBox.hidden=false;
    jobBox.scrollIntoView({block:'nearest'});
  }
  if(jobTitle)jobTitle.textContent=`Tracked job: ${label}`;
  if(jobMessage)jobMessage.textContent=[message,handoff,setupIntent,backupProposal].filter(Boolean).join(' ');
  overlay.querySelectorAll('[data-progress-state]').forEach(step=>{
    step.dataset.active=String(step.dataset.progressState===job.state);
  });
}
function preflightBoolValue(overlay,name){
  const value=overlay.querySelector(`[data-preflight-fact="${name}"]`)?.value||'';
  if(value==='true')return true;
  if(value==='false')return false;
  return undefined;
}
function existingHostRole(overlay){
  return (overlay.querySelector('[data-preflight-role]')?.value||'server').trim()||'server';
}
function existingHostType(overlay){
  return overlay.querySelector('[data-preflight-host-type]')?.value||'';
}
function existingHostIsNix(overlay){
  const type=existingHostType(overlay);
  if(type==='nixos')return true;
  if(type==='linux-beacon')return false;
  return undefined;
}
function existingPreflightRequest(overlay){
  const hostName=(overlay.querySelector('[data-preflight-host-name]')?.value||'').trim();
  const hostType=existingHostType(overlay);
  const route=overlay.querySelector('[data-preflight-route]')?.value||'tailnet';
  const sshHost=(overlay.querySelector('[data-preflight-ssh-host]')?.value||'').trim();
  const admin=overlay.querySelector('[data-preflight-admin]')?.value||'';
  const os=overlay.querySelector('[data-preflight-os]')?.value||'';
  const diskRaw=(overlay.querySelector('[data-preflight-disk]')?.value||'').trim();
  const facts={};
  const sshAuthenticated=preflightBoolValue(overlay,'ssh_authenticated');
  const nixAvailable=preflightBoolValue(overlay,'nix_available');
  const pharosReachable=preflightBoolValue(overlay,'pharos_reachable');
  if(hostType==='nixos'){facts.os_family='nixos';facts.nixos=true;facts.nix_available=true}
  else if(hostType==='linux-beacon'){facts.os_family='linux';facts.nixos=false}
  if(sshAuthenticated!==undefined)facts.ssh_authenticated=sshAuthenticated;
  if(nixAvailable!==undefined)facts.nix_available=nixAvailable;
  if(pharosReachable!==undefined)facts.pharos_reachable=pharosReachable;
  if(admin==='root'){facts.root=true;facts.sudo=false}
  else if(admin==='sudo'){facts.root=false;facts.sudo=true}
  else if(admin==='none'){facts.root=false;facts.sudo=false}
  if(os==='nixos'){facts.os_family='nixos';facts.nixos=true;facts.nix_available=true}
  else if(os==='linux'){facts.os_family='linux';facts.nixos=false}
  else if(os==='other'){facts.os_family='other';facts.nixos=false}
  if(diskRaw){
    const disk=Number(diskRaw);
    if(Number.isFinite(disk)&&disk>=0)facts.free_disk_gib=Math.floor(disk);
  }
  return {
    host_name:hostName,
    ssh:{
      route,
      host:route==='none'?undefined:sshHost||undefined
    },
    facts,
    pharos_url:location.origin
  };
}
function preflightStateTitle(state){
  return String(state||'unknown').replace(/-/g,' ');
}
function selectExistingBootstrap(overlay,option,button){
  overlay.dataset.existingBootstrapMethod=option.method||'';
  overlay.querySelectorAll('[data-bootstrap-option]').forEach(item=>{
    item.dataset.selected=String(item===button);
  });
  const title=overlay.querySelector('[data-assistant-next-title]');
  const copy=overlay.querySelector('[data-assistant-next-copy]');
  const continueButton=overlay.querySelector('[data-assistant-continue]');
  if(title)title.textContent=`Review: ${option.label||preflightStateTitle(option.method)}`;
  const parts=[
    option.message||'Review this path before applying changes.',
    Array.isArray(option.changes)?option.changes.join(' '):'',
    option.token_handoff||'',
    option.existing_token_policy||'',
    option.next_state?`Next: ${option.next_state}.`:''
  ].filter(Boolean);
  if(copy)copy.textContent=parts.join(' ');
  if(continueButton){
    continueButton.disabled=false;
    continueButton.textContent='Record path';
  }
}
function existingBootstrapTemplate(method){
  if(method==='nixos-anywhere')return 'nixos-anywhere';
  if(method==='native-systemd')return 'native-systemd';
  if(method==='manual')return 'manual-deferred';
  if(method==='deferred')return 'manual-deferred';
  return '';
}
function renderExistingPreflight(overlay,preflight){
  const box=overlay.querySelector('[data-preflight-result]');
  const summary=overlay.querySelector('[data-preflight-summary]');
  const message=overlay.querySelector('[data-preflight-message]');
  const checks=overlay.querySelector('[data-preflight-checks]');
  const bootstrap=overlay.querySelector('[data-preflight-bootstrap]');
  if(!box||!preflight)return;
  box.hidden=false;
  overlay.dataset.existingBootstrapMethod='';
  if(summary)summary.textContent=preflight.summary?.label||'Preflight';
  if(message)message.textContent=preflight.summary?.message||preflight.next_action||'Review checks before continuing.';
  if(checks){
    checks.replaceChildren();
    (Array.isArray(preflight.checks)?preflight.checks:[]).forEach(check=>{
      const row=document.createElement('div');
      row.className='assistant-check-row';
      row.dataset.state=check.state||'unknown';
      const copy=document.createElement('div');
      const title=document.createElement('strong');
      title.textContent=check.label||preflightStateTitle(check.key);
      const text=document.createElement('span');
      text.textContent=check.message||preflightStateTitle(check.state);
      copy.append(title,text);
      row.append(copy);
      checks.append(row);
    });
  }
  if(bootstrap){
    bootstrap.replaceChildren();
    const options=Array.isArray(preflight.bootstrap_options)?preflight.bootstrap_options:[];
    options.forEach(option=>{
      const row=document.createElement('button');
      row.type='button';
      row.className='assistant-bootstrap-option';
      row.dataset.bootstrapOption=option.method||'';
      row.dataset.available=String(Boolean(option.available));
      row.disabled=!option.available;
      const title=document.createElement('strong');
      title.textContent=option.label||preflightStateTitle(option.method);
      const text=document.createElement('span');
      text.textContent=option.message||'Review this path before applying changes.';
      const detail=document.createElement('span');
      const changes=Array.isArray(option.changes)?option.changes:[];
      const detailParts=[
        changes.join(' '),
        option.token_handoff||'',
        option.existing_token_policy||'',
        option.next_state?`Next: ${option.next_state}.`:''
      ].filter(Boolean);
      detail.textContent=detailParts.join(' ');
      row.append(title,text);
      if(detail.textContent)row.append(detail);
      row.addEventListener('click',()=>selectExistingBootstrap(overlay,option,row));
      bootstrap.append(row);
    });
    bootstrap.hidden=options.length===0;
  }
  syncAssistantNext(overlay);
}
async function runExistingPreflight(overlay,button){
  const request=existingPreflightRequest(overlay);
  if(!request.host_name)throw new Error('Enter a server name first.');
  if(request.ssh.route!=='none'&&!request.ssh.host)throw new Error('Enter an SSH address or choose Manual.');
  if(button){
    button.disabled=true;
    button.textContent='Checking';
  }
  const result=overlay.querySelector('[data-preflight-result]');
  const summary=overlay.querySelector('[data-preflight-summary]');
  const message=overlay.querySelector('[data-preflight-message]');
  if(result)result.hidden=false;
  if(summary)summary.textContent='Checking server';
  if(message)message.textContent='Running read-only checks from Pharos.';
  const response=await fetch('/setup/existing-host/preflight',{
    method:'POST',
    headers:{'content-type':'application/json','accept':'application/json'},
    body:JSON.stringify(request),
    cache:'no-store'
  });
  const payload=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(payload.error||'preflight could not be completed');
  renderExistingPreflight(overlay,payload.preflight);
}
async function fetchProvisioningJob(id){
  const response=await fetch(`/setup/provisioning-jobs/${encodeURIComponent(id)}`,{
    headers:{'accept':'application/json'},
    cache:'no-store'
  });
  const payload=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(payload.error||'setup job could not be loaded');
  return payload.job;
}
function scheduleProvisioningPoll(overlay,id){
  if(!id)return;
  window.clearTimeout(window.pharosAssistantJobTimer);
  window.pharosAssistantJobTimer=window.setTimeout(async()=>{
    try{
      const job=await fetchProvisioningJob(id);
      renderProvisioningJob(overlay,job);
      if(!provisioningJobTerminal(job?.state))scheduleProvisioningPoll(overlay,id);
    }catch(error){
      const copy=overlay.querySelector('[data-assistant-next-copy]');
      if(copy)copy.textContent=error.message||'setup job could not be refreshed';
    }
  },1500);
}
async function startProvisioningJob(overlay,start){
  const state=assistantState(overlay);
  const body={provider:state.provider,template:state.template};
  body.backup_intent=setupIntentChoice(overlay,'backup_intent','deferred');
  body.location_intent=setupIntentChoice(overlay,'location_intent','auto');
  if(state.path==='new'){
    const hostName=(overlay.querySelector('[data-new-host-name]')?.value||'').trim();
    if(!hostName)throw new Error('Enter a server name first.');
    body.host_name=hostName;
    body.role='server';
    body.is_nix=state.provider==='hetzner-cloud';
    body.heartbeat_interval_secs=60;
  }else if(state.path==='existing'){
    const hostName=(overlay.querySelector('[data-preflight-host-name]')?.value||'').trim();
    const template=existingBootstrapTemplate(overlay.dataset.existingBootstrapMethod||'');
    if(!hostName)throw new Error('Enter a server name first.');
    if(!template)throw new Error('Choose a bootstrap path first.');
    body.provider='existing-host';
    body.template=template;
    body.host_name=hostName;
    body.role=existingHostRole(overlay);
    const isNix=existingHostIsNix(overlay);
    if(isNix!==undefined)body.is_nix=isNix;
    body.heartbeat_interval_secs=60;
    body.apply=true;
  }
  start.textContent='Starting setup';
  start.disabled=true;
  const response=await fetch('/setup/provisioning-jobs',{
    method:'POST',
    headers:{'content-type':'application/json','accept':'application/json'},
    body:JSON.stringify(body),
    cache:'no-store'
  });
  const payload=await response.json().catch(()=>({}));
  if(!response.ok)throw new Error(payload.error||'setup job could not be started');
  renderProvisioningJob(overlay,payload.job);
  start.textContent='Setup job recorded';
  if(payload.job?.id&&!provisioningJobTerminal(payload.job.state))scheduleProvisioningPoll(overlay,payload.job.id);
}
function setAssistantTemplate(template,write=true){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  const provider=assistantProvider(overlay.dataset.assistantSelectedProvider||'');
  const safeTemplate=assistantTemplate(template);
  const nextTemplate=safeTemplate&&ASSISTANT_TEMPLATE_PROVIDERS[safeTemplate]===provider?safeTemplate:'';
  overlay.dataset.assistantSelectedTemplate=nextTemplate;
  if(!nextTemplate)overlay.dataset.assistantStage='';
  overlay.querySelectorAll('[data-assistant-template]').forEach(btn=>{
    const visible=!btn.hidden&&btn.dataset.assistantTemplateProvider===provider;
    btn.setAttribute('aria-pressed',String(visible&&btn.dataset.assistantTemplate===nextTemplate));
  });
  syncAssistantNext(overlay);
  if(write){
    const state=assistantState(overlay);
    writeAssistantUrl(!overlay.hidden,state.path,state.provider,state.template,state.stage);
  }
}
function setAssistantProvider(provider,write=true){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  const safeProvider=assistantProvider(provider);
  overlay.dataset.assistantSelectedProvider=safeProvider;
  overlay.querySelectorAll('[data-assistant-provider]').forEach(btn=>{
    btn.setAttribute('aria-pressed',String(btn.dataset.assistantProvider===safeProvider));
  });
  overlay.querySelectorAll('[data-assistant-template]').forEach(btn=>{
    btn.hidden=!(safeProvider&&btn.dataset.assistantTemplateProvider===safeProvider);
  });
  if(ASSISTANT_TEMPLATE_PROVIDERS[assistantTemplate(overlay.dataset.assistantSelectedTemplate||'')]!==safeProvider){
    setAssistantTemplate('',false);
  }else{
    setAssistantTemplate(overlay.dataset.assistantSelectedTemplate,false);
  }
  syncAssistantNext(overlay);
  if(write){
    const state=assistantState(overlay);
    writeAssistantUrl(!overlay.hidden,state.path,state.provider,state.template,state.stage);
  }
}
function setAssistantPath(path,write=true){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  const safePath=assistantPath(path);
  const previousPath=assistantPath(overlay.dataset.assistantSelectedPath||'');
  overlay.dataset.assistantSelectedPath=safePath;
  if(safePath!==previousPath){
    overlay.dataset.assistantStage='';
    overlay.dataset.existingBootstrapMethod='';
  }
  overlay.querySelectorAll('[data-assistant-path]').forEach(btn=>{
    btn.setAttribute('aria-pressed',String(btn.dataset.assistantPath===safePath));
  });
  if(safePath==='new'){
    setAssistantProvider(assistantProvider(overlay.dataset.assistantSelectedProvider||'')||'hetzner-cloud',false);
  }else if(safePath==='existing'){
    setAssistantProvider('',false);
    setAssistantTemplate('',false);
  }else{
    setAssistantProvider('',false);
    setAssistantTemplate('',false);
  }
  syncAssistantNext(overlay);
  if(write){
    const state=assistantState(overlay);
    writeAssistantUrl(!overlay.hidden,state.path,state.provider,state.template,state.stage);
  }
}
function setAssistantOpen(open,write=true){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  overlay.hidden=!open;
  document.body.dataset.assistantOpen=open?'true':'false';
  if(!open)setAssistantPath('',false);
  if(write){
    const state=assistantState(overlay);
    writeAssistantUrl(open,state.path,state.provider,state.template,state.stage);
  }
  if(open)overlay.querySelector('[data-assistant-close]')?.focus();
}
function restoreAssistantFromUrl(){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  const params=new URLSearchParams(location.search);
  const open=params.get(ASSISTANT_SETUP_PARAM)==='add-server';
  setAssistantOpen(open,false);
  if(!open){
    setAssistantPath('',false);
    return;
  }
  const path=assistantPath(params.get(ASSISTANT_PATH_PARAM));
  setAssistantPath(path,false);
  if(path==='new'){
    setAssistantProvider(assistantProvider(params.get(ASSISTANT_PROVIDER_PARAM))||'hetzner-cloud',false);
    setAssistantTemplate(params.get(ASSISTANT_TEMPLATE_PARAM),false);
    overlay.dataset.assistantStage=assistantStage(params.get(ASSISTANT_STAGE_PARAM));
    syncAssistantNext(overlay);
  }
}
function initSetupAssistant(){
  const overlay=document.querySelector('[data-setup-assistant]');
  if(!overlay)return;
  document.querySelectorAll('[data-onboard-open]').forEach(btn=>btn.addEventListener('click',()=>setAssistantOpen(true)));
  overlay.querySelectorAll('[data-assistant-close]').forEach(btn=>btn.addEventListener('click',()=>setAssistantOpen(false)));
  overlay.addEventListener('click',event=>{if(event.target===overlay)setAssistantOpen(false)});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&!overlay.hidden)setAssistantOpen(false)});
  overlay.querySelectorAll('[data-assistant-path]').forEach(btn=>btn.addEventListener('click',()=>setAssistantPath(btn.dataset.assistantPath)));
  overlay.querySelectorAll('[data-assistant-provider]').forEach(btn=>btn.addEventListener('click',()=>setAssistantProvider(btn.dataset.assistantProvider)));
  overlay.querySelectorAll('[data-assistant-template]').forEach(btn=>btn.addEventListener('click',()=>setAssistantTemplate(btn.dataset.assistantTemplate)));
  overlay.querySelector('[data-preflight-form]')?.addEventListener('submit',async event=>{
    event.preventDefault();
    const button=overlay.querySelector('[data-preflight-check]');
    const summary=overlay.querySelector('[data-preflight-summary]');
    const message=overlay.querySelector('[data-preflight-message]');
    try{
      await runExistingPreflight(overlay,button);
    }catch(error){
      const result=overlay.querySelector('[data-preflight-result]');
      if(result)result.hidden=false;
      if(summary)summary.textContent='Preflight could not run';
      if(message)message.textContent=error.message||'Check the server details and try again.';
      syncAssistantNext(overlay);
    }finally{
      if(button){
        button.disabled=false;
        button.textContent='Check server';
      }
    }
  });
  overlay.querySelector('[data-assistant-confirm]')?.addEventListener('change',event=>{
    const start=overlay.querySelector('[data-assistant-start]');
    if(start)start.disabled=!event.currentTarget.checked;
  });
  overlay.querySelectorAll('input[name="backup_intent"],input[name="location_intent"]').forEach(input=>{
    input.addEventListener('change',()=>syncAssistantNext(overlay));
  });
  overlay.querySelector('[data-assistant-start]')?.addEventListener('click',async event=>{
    if(event.currentTarget.disabled)return;
    const start=event.currentTarget;
    const title=overlay.querySelector('[data-assistant-next-title]');
    const copy=overlay.querySelector('[data-assistant-next-copy]');
    try{
      await startProvisioningJob(overlay,start);
    }catch(error){
      start.textContent='Start setup';
      start.disabled=false;
      if(title)title.textContent='Setup could not start';
      if(copy)copy.textContent=error.message||'The setup job could not be created.';
    }
  });
  overlay.querySelector('[data-assistant-continue]')?.addEventListener('click',event=>{
    if(event.currentTarget.disabled)return;
    overlay.dataset.assistantStage='plan';
    if(assistantState(overlay).path==='existing'){
      const start=overlay.querySelector('[data-assistant-start]');
      const confirm=overlay.querySelector('[data-assistant-confirm]');
      if(confirm)confirm.checked=true;
      if(start){
        start.disabled=false;
        start.textContent='Record setup path';
      }
    }
    const state=assistantState(overlay);
    writeAssistantUrl(!overlay.hidden,state.path,state.provider,state.template,state.stage);
    syncAssistantNext(overlay);
  });
  window.addEventListener('popstate',restoreAssistantFromUrl);
  restoreAssistantFromUrl();
}
function updateUrlState(){
  const main=document.querySelector('main');
  const sort=document.querySelector('[data-sort]')?.value||'attention';
  const params=new URLSearchParams(location.search);
  params.set('view',main?.dataset.view||'grid');
  params.set('sort',sort);
  params.set('filter',activeLiveFilter);
  params.set('signal',signalWindow.key);
  const url=location.pathname+'?'+params.toString();
  history.replaceState(null,'',url);
}
function initControls(){
  const params=new URLSearchParams(location.search);
  const view=params.get('view')||decodeURIComponent(cookie('pharos_view'))||'grid';
  const sort=params.get('sort')||decodeURIComponent(cookie('pharos_sort'))||'attention';
  const search=decodeURIComponent(cookie('pharos_search'));
  const liveFilter=params.get('filter')||decodeURIComponent(cookie('pharos_live_filter'))||'all';
  const selectedSignalWindow=params.get('signal')||decodeURIComponent(cookie('pharos_signal_window'))||SIGNAL_WINDOWS[0].key;
  applyView(view,false);
  applySort(sort,false);
  applyFilter(search,false);
  applyLiveFilter(liveFilter,false);
  applySignalWindow(selectedSignalWindow,false);
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.addEventListener('click',()=>{applyView(btn.dataset.viewButton);updateUrlState()}));
  document.querySelector('[data-sort]')?.addEventListener('change',e=>{applySort(e.target.value);updateUrlState()});
  document.querySelector('[data-search]')?.addEventListener('input',e=>applyFilter(e.target.value));
  document.querySelectorAll('[data-live-filter]').forEach(btn=>btn.addEventListener('click',()=>{applyLiveFilter(btn.dataset.liveFilter);updateUrlState()}));
  document.querySelectorAll('[data-signal-window]').forEach(btn=>btn.addEventListener('click',cycleSignalWindow));
  bindFreeformDrag();
  initSetupAssistant();
}
const REFRESH_MS=10000;
const HIDDEN_REFRESH_MS=60000;
const FETCH_TIMEOUT_MS=9000;
let refreshTimer=null;
let refreshPromise=null;
let refreshAbort=null;
let refreshStartedAt=0;
let refreshGeneration=0;
function clearRefreshTimer(){
  if(refreshTimer!=null){
    clearTimeout(refreshTimer);
    refreshTimer=null;
  }
}
function nextRefreshDelay(){
  return document.hidden?HIDDEN_REFRESH_MS:REFRESH_MS;
}
function scheduleRefresh(delay=nextRefreshDelay()){
  clearRefreshTimer();
  refreshTimer=setTimeout(()=>refresh('timer'),delay);
}
async function refresh(reason='manual'){
  clearRefreshTimer();
  if(refreshPromise)return refreshPromise;
  const controller=new AbortController();
  const generation=++refreshGeneration;
  refreshAbort=controller;
  refreshStartedAt=Date.now();
  const timeout=setTimeout(()=>controller.abort(),FETCH_TIMEOUT_MS);
  refreshPromise=(async()=>{
  try{
    const res=await fetch('/hosts.json?refresh='+Date.now(),{headers:{Accept:'application/json'},cache:'no-store',credentials:'same-origin',signal:controller.signal});
    if(!res.ok)return;
    const data=await res.json();
    if(generation!==refreshGeneration)return;
    const now=Number(data.as_of)||Math.floor(Date.now()/1000);
    const asof=document.querySelector('[data-as-of]');
    if(asof)asof.textContent='as of '+clock(now);
    for(const h of data.hosts||[]){
      const surfaces=hostSurfaces(h.name);
      for(const card of surfaces){
        const live=h.liveness;
        card.dataset.live=live;
        const attention=h.attention||attentionFor(h.liveness,h.freshness);
        const backup=backupInfo(h,now);
        card.dataset.sev=String(attention.rank ?? sevFor(live));
        card.dataset.last=h.last_seen ?? 0;
        card.dataset.search=(String(h.name||'')+' '+String(h.role||'')+' '+String(h.freshness_tldr||'')+' '+String(attention.label||'')+' '+String(backup.search||'')).toLowerCase().trim();
        const word=card.querySelector('[data-status-word]');
        if(word)word.textContent=words[h.liveness]||h.liveness;
        setReason(card,attention);
        const fresh=card.querySelector('[data-fresh]');
        if(fresh)fresh.innerHTML=freshHtml(h.freshness);
        updateBackup(card,backup);
        setSeen(card,h.last_seen,now);
        setCardAsOf(card,now);
        const beat=card.querySelector('.beat');
        if(beat){
          const previous=Number(beat.dataset.last);
          const last=h.last_seen == null ? NaN : Number(h.last_seen);
          const interval=h.heartbeat_interval_secs || 60;
          const incoming=Array.isArray(h.heartbeat_log)?h.heartbeat_log.map(Number).filter(Number.isFinite):[];
          const beats=incoming.length?incoming:(Number.isFinite(last)?[last]:[]);
          beat.dataset.interval=interval;
          setBeatHistory(beat,beats,interval);
          updateSignal(card,signalInfo(beats,last,interval,now));
          if(beat.dataset.ready==='true'&&Number.isFinite(previous)&&Number.isFinite(last)&&last>previous){
            beat.style.setProperty('--hit-x',heartbeatX(Math.max(0,last-previous),Math.max(1,Number(interval)||60)).toFixed(2)+'%');
            flashBeat(beat);
          }
          beat.dataset.ready='true';
          beat.dataset.last=Number.isFinite(last)?String(last):'';
          beat.dataset.nextAt=Number.isFinite(last)?String(last+interval):'';
        }
      }
    }
    applySort(document.querySelector('[data-sort]')?.value||'attention',false);
    applySurfaceFilters(false);
  }catch(_){}
  finally{
    clearTimeout(timeout);
    if(generation===refreshGeneration){
      if(refreshAbort===controller)refreshAbort=null;
      refreshPromise=null;
      scheduleRefresh();
    }
  }
  })();
  return refreshPromise;
}
function resumeRefresh(reason){
  if(document.hidden){
    scheduleRefresh(HIDDEN_REFRESH_MS);
    return;
  }
  if(refreshPromise&&refreshAbort&&Date.now()-refreshStartedAt>FETCH_TIMEOUT_MS){
    refreshAbort.abort();
    refreshGeneration++;
    refreshAbort=null;
    refreshPromise=null;
  }
  refresh(reason);
}
document.addEventListener('visibilitychange',()=>resumeRefresh('visible'));
window.addEventListener('focus',()=>resumeRefresh('focus'));
window.addEventListener('pageshow',()=>resumeRefresh('pageshow'));
window.addEventListener('online',()=>resumeRefresh('online'));
document.querySelectorAll('[data-seen],[data-card-asof]').forEach(el=>{el.dataset.defaultText=el.textContent});
document.querySelectorAll('.beat').forEach(beat=>{setBeatHistory(beat,parseBeats(beat.dataset.signalBeats||beat.dataset.beats),Number(beat.dataset.interval)||60);beat.dataset.ready='true'});
initControls();
requestAnimationFrame(frame);
scheduleRefresh(3000);
</script></body></html>"#;

const HEARTBEAT_HISTORY_DOTS: usize = 12;
const HEARTBEAT_EXPECT_X: f64 = 64.0;
const HEARTBEAT_STALE_X: f64 = 82.0;
const SIGNAL_DEFAULT_WINDOW_LABEL: &str = "10m";
const SIGNAL_DEFAULT_WINDOW_SECS: i64 = 10 * 60;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The host pharosd itself runs on — gets the lighthouse treatment (PHAROS-10).
fn self_host() -> String {
    std::env::var("PHAROS_SELF").unwrap_or_else(|_| "csb1".into())
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_beacon_token_mode(value: &str) -> Option<BeaconTokenMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" | "mvp" => Some(BeaconTokenMode::Local),
        "dual" | "migration" => Some(BeaconTokenMode::Dual),
        "janus" | "forge" | "warden" => Some(BeaconTokenMode::Janus),
        _ => None,
    }
}

fn janus_token_hash_sources_from_env() -> Vec<JanusTokenHashSource> {
    let mut sources = Vec::new();
    if let Some(value) = env_nonempty("PHAROS_BEACON_TOKEN_HASH_FILES") {
        sources.extend(
            parse_path_list(&value)
                .into_iter()
                .map(JanusTokenHashSource::File),
        );
    }
    for name in [
        "PHAROS_BEACON_TOKEN_HASH_FILE",
        "PHAROS_JANUS_BEACON_TOKEN_HASH_FILE",
    ] {
        if let Some(path) = env_nonempty(name) {
            sources.push(JanusTokenHashSource::File(PathBuf::from(path)));
        }
    }
    if let Some(path) = env_nonempty("PHAROS_BEACON_TOKEN_HASH_DIR") {
        sources.push(JanusTokenHashSource::Dir(PathBuf::from(path)));
    }
    sources
}

fn parse_path_list(value: &str) -> Vec<PathBuf> {
    value
        .split(',')
        .filter_map(|path| {
            let path = path.trim();
            if path.is_empty() {
                None
            } else {
                Some(PathBuf::from(path))
            }
        })
        .collect()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..len {
        diff |=
            usize::from(left.get(idx).copied().unwrap_or(0) ^ right.get(idx).copied().unwrap_or(0));
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn local_token_matches(store: &Store, host: &str, expected_hash: &str) -> bool {
    store
        .token_hash_for(host)
        .is_some_and(|stored| constant_time_eq(&stored, expected_hash))
}

fn new_beacon_token() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("pharos_{}", hex(&bytes)))
}

const JANUS_BEACON_TOKEN_HASH_SCHEMA: &str = "inspr.pharos.beacon-token-hashes.v1";

#[derive(Debug, Deserialize)]
struct JanusTokenHashFile {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    hosts: Vec<JanusTokenHashHost>,
    #[serde(default)]
    tokens: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct JanusTokenHashHost {
    name: String,
    #[serde(alias = "tokenHash", alias = "token_hash", alias = "sha256")]
    token_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
enum JanusTokenHashError {
    NotConfigured,
    Read,
    Parse,
    UnsupportedSchema,
    EmptyHost,
    InvalidHash,
    DuplicateHost,
}

impl std::fmt::Display for JanusTokenHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "janus token hash file is not configured"),
            Self::Read => write!(f, "janus token hash source could not be read"),
            Self::Parse => write!(f, "janus token hash file could not be parsed"),
            Self::UnsupportedSchema => write!(f, "janus token hash file schema is unsupported"),
            Self::EmptyHost => write!(f, "janus token hash file contains an empty host"),
            Self::InvalidHash => write!(f, "janus token hash file contains an invalid hash"),
            Self::DuplicateHost => write!(f, "janus token hash file contains a duplicate host"),
        }
    }
}

fn load_janus_token_hashes(
    sources: &[JanusTokenHashSource],
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    if sources.is_empty() {
        return Err(JanusTokenHashError::NotConfigured);
    }
    let mut hashes = BTreeMap::new();
    for source in sources {
        match source {
            JanusTokenHashSource::File(path) => {
                merge_janus_token_hashes(&mut hashes, load_janus_token_hash_file(path)?)?;
            }
            JanusTokenHashSource::Dir(path) => {
                for path in janus_token_hash_dir_files(path)? {
                    merge_janus_token_hashes(&mut hashes, load_janus_token_hash_file(&path)?)?;
                }
            }
        }
    }
    if hashes.is_empty() {
        return Err(JanusTokenHashError::NotConfigured);
    }
    Ok(hashes)
}

fn janus_token_hash_dir_files(path: &Path) -> Result<Vec<PathBuf>, JanusTokenHashError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| JanusTokenHashError::Read)? {
        let entry = entry.map_err(|_| JanusTokenHashError::Read)?;
        let metadata = entry.metadata().map_err(|_| JanusTokenHashError::Read)?;
        if !metadata.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(JanusTokenHashError::Read);
        };
        if file_name.starts_with('.') {
            continue;
        }
        let is_json = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        if is_json {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn merge_janus_token_hashes(
    target: &mut BTreeMap<String, String>,
    next: BTreeMap<String, String>,
) -> Result<(), JanusTokenHashError> {
    for (host, hash) in next {
        if target.insert(host.clone(), hash).is_some() {
            return Err(JanusTokenHashError::DuplicateHost);
        }
    }
    Ok(())
}

fn load_janus_token_hash_file(
    path: &Path,
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    let contents = fs::read_to_string(path).map_err(|_| JanusTokenHashError::Read)?;
    parse_janus_token_hashes(&contents)
}

fn parse_janus_token_hashes(
    contents: &str,
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    let payload: JanusTokenHashFile =
        serde_json::from_str(contents).map_err(|_| JanusTokenHashError::Parse)?;
    if let Some(schema) = payload.schema.as_deref() {
        if schema != JANUS_BEACON_TOKEN_HASH_SCHEMA {
            return Err(JanusTokenHashError::UnsupportedSchema);
        }
    }

    let mut hashes = BTreeMap::new();
    for (host, hash) in payload.tokens.into_iter().chain(
        payload
            .hosts
            .into_iter()
            .map(|host| (host.name, host.token_sha256)),
    ) {
        let host = host.trim().to_string();
        let hash = hash.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(JanusTokenHashError::EmptyHost);
        }
        if !is_sha256_hex(&hash) {
            return Err(JanusTokenHashError::InvalidHash);
        }
        if hashes.insert(host.clone(), hash).is_some() {
            return Err(JanusTokenHashError::DuplicateHost);
        }
    }
    Ok(hashes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "name": "pharosd", "version": env!("CARGO_PKG_VERSION") }))
}

#[derive(Debug, Deserialize)]
struct SetupProviderPlanQuery {
    provider: String,
    template: String,
}

async fn setup_provider_plan_json(
    Query(query): Query<SetupProviderPlanQuery>,
) -> impl IntoResponse {
    match setup_provider_plan(&query.provider, &query.template) {
        Ok(plan) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "plan": plan })),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error.to_string() })),
        ),
    }
}

async fn create_provisioning_job(
    State(state): State<AppState>,
    Json(request): Json<ProvisioningJobStartRequest>,
) -> impl IntoResponse {
    match state
        .provisioning_jobs
        .start(&request, now_unix(), &state.provider_runtime)
    {
        Ok(job) => (
            StatusCode::CREATED,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        Err(error) => (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error.to_string() })),
        ),
    }
}

async fn provisioning_job_json(
    State(state): State<AppState>,
    AxumPath(id): AxumPath<String>,
) -> impl IntoResponse {
    match state.provisioning_jobs.get(&id) {
        Some(job) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "job": job })),
        ),
        None => (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "provisioning job not found" })),
        ),
    }
}

async fn existing_host_preflight_json(
    Json(request): Json<ExistingHostPreflightRequest>,
) -> impl IntoResponse {
    if let Err(error) = request.validate_contract() {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": error })),
        );
    }
    let report = existing_host_preflight_report(&request, now_unix()).await;
    match report.validate_contract() {
        Ok(()) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({ "preflight": report })),
        ),
        Err(error) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            no_store_headers(),
            Json(json!({ "error": error })),
        ),
    }
}

async fn existing_host_preflight_report(
    request: &ExistingHostPreflightRequest,
    now: i64,
) -> ExistingHostPreflightReport {
    let mut checks = Vec::new();
    let facts = if needs_existing_host_ssh_fact_probe(&request.facts) {
        merge_preflight_facts(
            request.facts.clone(),
            existing_host_ssh_fact_probe(request).await,
        )
    } else {
        request.facts.clone()
    };
    let ssh_tcp_state = match preflight_ssh_endpoint(request) {
        Some((host, port)) => {
            let started = Instant::now();
            match timeout(
                SERVER_PROBE_TIMEOUT,
                TcpStream::connect((host.as_str(), port)),
            )
            .await
            {
                Ok(Ok(_)) => {
                    let elapsed_ms = started.elapsed().as_millis().max(1);
                    PreflightCheckState::Pass.with_message(format!(
                        "SSH port is reachable from Pharos in {elapsed_ms} ms."
                    ))
                }
                Ok(Err(_)) => PreflightCheckState::Fail
                    .with_message("Pharos cannot open the SSH port for this host.".to_string()),
                Err(_) => PreflightCheckState::Fail
                    .with_message("Pharos timed out while checking the SSH port.".to_string()),
            }
        }
        None => PreflightCheckState::Unknown
            .with_message("Add an SSH target before automated bootstrap is offered.".to_string()),
    };
    checks.push(preflight_check(
        "ssh-reachability",
        "SSH reachability",
        ssh_tcp_state.0,
        ssh_tcp_state.1,
    ));
    checks.push(preflight_bool_check(
        "ssh-authentication",
        "SSH authentication",
        facts.ssh_authenticated,
        "SSH authentication has been verified.",
        "SSH authentication failed or is not available.",
        "Verify SSH login without sending any password or key material to Pharos.",
    ));
    checks.push(privilege_check(&facts));
    checks.push(os_family_check(&facts));
    checks.push(nix_capability_check(&facts));
    checks.push(disk_check(&facts));
    checks.push(preflight_bool_check(
        "pharos-reachability",
        "Host can reach Pharos",
        facts.pharos_reachable,
        "The host can reach the Pharos report endpoint.",
        "The host cannot reach Pharos yet.",
        "Confirm outbound HTTPS from the host to Pharos before registering a beacon.",
    ));

    let bootstrap_options = bootstrap_options(&facts, &checks);
    let summary = preflight_summary(&checks);
    let next_action = preflight_next_action(&summary, &bootstrap_options).to_string();
    ExistingHostPreflightReport {
        schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
        version: EXISTING_HOST_PREFLIGHT_VERSION,
        host_name: request.host_name.trim().to_string(),
        checked_at: now,
        summary,
        checks,
        bootstrap_options,
        next_action,
    }
}

fn preflight_ssh_endpoint(request: &ExistingHostPreflightRequest) -> Option<(String, u16)> {
    if matches!(request.ssh.route, SshRoute::None | SshRoute::Unknown) {
        return None;
    }
    request
        .ssh
        .host
        .as_deref()
        .and_then(|host| split_probe_host_port(host, request.ssh.port.unwrap_or(22)))
}

fn needs_existing_host_ssh_fact_probe(facts: &ExistingHostPreflightFacts) -> bool {
    facts.ssh_authenticated.is_none()
        || facts.root.is_none()
        || facts.sudo.is_none()
        || facts.os_family.is_none()
        || facts.nixos.is_none()
        || facts.nix_available.is_none()
        || facts.free_disk_gib.is_none()
        || facts.pharos_reachable.is_none()
}

async fn existing_host_ssh_fact_probe(
    request: &ExistingHostPreflightRequest,
) -> ExistingHostPreflightFacts {
    let Some((host, port)) = preflight_ssh_endpoint(request) else {
        return ExistingHostPreflightFacts::default();
    };
    let user = request.ssh.user.clone();
    let pharos_url = request.pharos_url.clone();
    match timeout(
        EXISTING_HOST_SSH_PROBE_TIMEOUT,
        tokio::task::spawn_blocking(move || {
            run_existing_host_ssh_probe(host, port, user, pharos_url)
        }),
    )
    .await
    {
        Ok(Ok(facts)) => facts,
        _ => ExistingHostPreflightFacts {
            ssh_authenticated: Some(false),
            ..ExistingHostPreflightFacts::default()
        },
    }
}

fn run_existing_host_ssh_probe(
    host: String,
    port: u16,
    user: Option<String>,
    pharos_url: Option<String>,
) -> ExistingHostPreflightFacts {
    let target = match user
        .as_deref()
        .map(str::trim)
        .filter(|user| !user.is_empty())
    {
        Some(user) => format!("{user}@{host}"),
        None => host,
    };
    let mut remote = String::new();
    if let Some(url) = pharos_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
    {
        remote.push_str("PHAROS_PREFLIGHT_URL=");
        remote.push_str(&shell_single_quote(url));
        remote.push_str("; export PHAROS_PREFLIGHT_URL; ");
    }
    remote.push_str("sh -c ");
    remote.push_str(&shell_single_quote(EXISTING_HOST_SSH_PROBE_SCRIPT));

    let output = Command::new("ssh")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("ConnectTimeout=4")
        .arg("-o")
        .arg("ServerAliveInterval=2")
        .arg("-o")
        .arg("ServerAliveCountMax=1")
        .arg("-p")
        .arg(port.to_string())
        .arg(target)
        .arg(remote)
        .output();

    match output {
        Ok(output) if output.status.success() => {
            parse_existing_host_ssh_probe_stdout(&output.stdout)
        }
        Ok(_) => ExistingHostPreflightFacts {
            ssh_authenticated: Some(false),
            ..ExistingHostPreflightFacts::default()
        },
        Err(_) => ExistingHostPreflightFacts::default(),
    }
}

const EXISTING_HOST_SSH_PROBE_SCRIPT: &str = r#"uid=$(id -u 2>/dev/null || printf unknown)
case "$uid" in
  0) root=true ;;
  *) root=false ;;
esac
if command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1; then
  sudo=true
else
  sudo=false
fi
if [ -r /etc/os-release ]; then
  os=$(. /etc/os-release >/dev/null 2>&1; printf '%s' "${ID:-linux}")
else
  os=$(uname -s 2>/dev/null || printf unknown)
fi
if [ -e /etc/NIXOS ]; then nixos=true; else nixos=false; fi
if command -v nix >/dev/null 2>&1; then nix=true; else nix=false; fi
disk=$(df -Pk / 2>/dev/null | awk 'NR==2 { printf "%d", $4 / 1048576 }')
case "$disk" in ''|*[!0-9]*) disk=0 ;; esac
pharos=unknown
if [ -n "${PHAROS_PREFLIGHT_URL:-}" ]; then
  if command -v curl >/dev/null 2>&1; then
    if curl -fsS --max-time 4 "${PHAROS_PREFLIGHT_URL%/}/healthz" >/dev/null 2>&1; then pharos=true; else pharos=false; fi
  elif command -v wget >/dev/null 2>&1; then
    if wget -q -T 4 -O /dev/null "${PHAROS_PREFLIGHT_URL%/}/healthz" >/dev/null 2>&1; then pharos=true; else pharos=false; fi
  fi
fi
printf 'ssh_authenticated=true\n'
printf 'root=%s\n' "$root"
printf 'sudo=%s\n' "$sudo"
printf 'os_family=%s\n' "$os"
printf 'nixos=%s\n' "$nixos"
printf 'nix_available=%s\n' "$nix"
printf 'free_disk_gib=%s\n' "$disk"
printf 'pharos_reachable=%s\n' "$pharos"
"#;

fn parse_existing_host_ssh_probe_stdout(stdout: &[u8]) -> ExistingHostPreflightFacts {
    let mut facts = ExistingHostPreflightFacts::default();
    let text = String::from_utf8_lossy(stdout);
    for line in text.lines().take(32) {
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let value = value.trim();
        match key.trim() {
            "ssh_authenticated" => facts.ssh_authenticated = parse_probe_bool(value),
            "root" => facts.root = parse_probe_bool(value),
            "sudo" => facts.sudo = parse_probe_bool(value),
            "os_family" => facts.os_family = sanitize_probe_text(value),
            "nixos" => facts.nixos = parse_probe_bool(value),
            "nix_available" => facts.nix_available = parse_probe_bool(value),
            "free_disk_gib" => facts.free_disk_gib = value.parse::<u32>().ok(),
            "pharos_reachable" => facts.pharos_reachable = parse_probe_bool(value),
            _ => {}
        }
    }
    facts
}

fn parse_probe_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "1" | "yes" => Some(true),
        "false" | "0" | "no" => Some(false),
        _ => None,
    }
}

fn sanitize_probe_text(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 80
        || value.contains('\n')
        || value.contains('\r')
        || value.to_ascii_lowercase().contains("token=")
        || value.to_ascii_lowercase().contains("bearer ")
    {
        return None;
    }
    Some(value.to_string())
}

fn merge_preflight_facts(
    mut base: ExistingHostPreflightFacts,
    probe: ExistingHostPreflightFacts,
) -> ExistingHostPreflightFacts {
    base.ssh_authenticated = base.ssh_authenticated.or(probe.ssh_authenticated);
    base.root = base.root.or(probe.root);
    base.sudo = base.sudo.or(probe.sudo);
    base.os_family = base.os_family.or(probe.os_family);
    base.nixos = base.nixos.or(probe.nixos);
    base.nix_available = base.nix_available.or(probe.nix_available);
    base.free_disk_gib = base.free_disk_gib.or(probe.free_disk_gib);
    base.pharos_reachable = base.pharos_reachable.or(probe.pharos_reachable);
    base
}

fn shell_single_quote(value: &str) -> String {
    let mut quoted = String::from("'");
    for ch in value.chars() {
        if ch == '\'' {
            quoted.push_str("'\"'\"'");
        } else {
            quoted.push(ch);
        }
    }
    quoted.push('\'');
    quoted
}

fn preflight_check(
    key: &str,
    label: &str,
    state: PreflightCheckState,
    message: String,
) -> ExistingHostPreflightCheck {
    ExistingHostPreflightCheck {
        key: key.to_string(),
        label: label.to_string(),
        state,
        message,
    }
}

trait PreflightStateMessage {
    fn with_message(self, message: String) -> (PreflightCheckState, String);
}

impl PreflightStateMessage for PreflightCheckState {
    fn with_message(self, message: String) -> (PreflightCheckState, String) {
        (self, message)
    }
}

fn preflight_bool_check(
    key: &str,
    label: &str,
    value: Option<bool>,
    pass: &str,
    fail: &str,
    unknown: &str,
) -> ExistingHostPreflightCheck {
    match value {
        Some(true) => preflight_check(key, label, PreflightCheckState::Pass, pass.to_string()),
        Some(false) => preflight_check(key, label, PreflightCheckState::Fail, fail.to_string()),
        None => preflight_check(
            key,
            label,
            PreflightCheckState::Unknown,
            unknown.to_string(),
        ),
    }
}

fn privilege_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    match (facts.root, facts.sudo) {
        (Some(true), _) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Pass,
            "Root access is available for bootstrap.".to_string(),
        ),
        (_, Some(true)) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Pass,
            "The SSH user can elevate with sudo.".to_string(),
        ),
        (Some(false), Some(false)) => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Fail,
            "Automated bootstrap needs root or sudo access.".to_string(),
        ),
        _ => preflight_check(
            "privilege",
            "Privilege model",
            PreflightCheckState::Unknown,
            "Verify root or sudo capability before choosing an automated path.".to_string(),
        ),
    }
}

fn os_family_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    let Some(os) = facts.os_family.as_deref().map(str::trim) else {
        return preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Unknown,
            "Identify the host operating system before bootstrap.".to_string(),
        );
    };
    let lowered = os.to_ascii_lowercase();
    if lowered.contains("linux") || lowered.contains("nixos") {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Pass,
            format!("{os} is a supported existing-host target."),
        )
    } else if lowered.contains("darwin")
        || lowered.contains("macos")
        || lowered.contains("windows")
        || lowered.contains("bsd")
    {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Fail,
            format!("{os} is not supported by the automated existing-host bootstrap path."),
        )
    } else {
        preflight_check(
            "os-family",
            "Operating system",
            PreflightCheckState::Warn,
            format!("{os} needs manual review before automated bootstrap."),
        )
    }
}

fn nix_capability_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    match (facts.nixos, facts.nix_available) {
        (Some(true), _) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Pass,
            "NixOS is already detected.".to_string(),
        ),
        (Some(false), Some(true)) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Warn,
            "Nix is available, but the host is not confirmed as NixOS.".to_string(),
        ),
        (Some(false), Some(false)) => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Warn,
            "Nix is not detected; use native beacon or manual bootstrap unless converting the host.".to_string(),
        ),
        _ => preflight_check(
            "nix-capability",
            "Nix capability",
            PreflightCheckState::Unknown,
            "Check whether the host is NixOS or can run the portable beacon.".to_string(),
        ),
    }
}

fn disk_check(facts: &ExistingHostPreflightFacts) -> ExistingHostPreflightCheck {
    match facts.free_disk_gib {
        Some(gib) if gib >= 8 => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Pass,
            format!("{gib} GiB free is enough for setup checks."),
        ),
        Some(gib) if gib >= 4 => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Warn,
            format!("{gib} GiB free is tight; review before bootstrap."),
        ),
        Some(gib) => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Fail,
            format!("{gib} GiB free is too little for a safe bootstrap."),
        ),
        None => preflight_check(
            "disk-space",
            "Disk headroom",
            PreflightCheckState::Unknown,
            "Check free disk space before installing or converting the host.".to_string(),
        ),
    }
}

fn bootstrap_options(
    facts: &ExistingHostPreflightFacts,
    checks: &[ExistingHostPreflightCheck],
) -> Vec<ExistingHostBootstrapOption> {
    let ssh_reachable = check_passed(checks, "ssh-reachability");
    let auth_ok = facts.ssh_authenticated == Some(true);
    let privilege_ok = facts.root == Some(true) || facts.sudo == Some(true);
    let disk_ok = !check_failed(checks, "disk-space");
    let os_supported = check_passed(checks, "os-family") || facts.os_family.is_none();
    let linuxish = facts
        .os_family
        .as_deref()
        .map(|os| {
            let os = os.to_ascii_lowercase();
            os.contains("linux") || os.contains("nixos")
        })
        .unwrap_or(false);
    let automated_ready = ssh_reachable && auth_ok && privilege_ok && disk_ok && os_supported;
    vec![
        ExistingHostBootstrapOption {
            method: BootstrapMethod::NixosAnywhere,
            label: "NixOS / declarative".to_string(),
            available: automated_ready && linuxish,
            message: if automated_ready && linuxish {
                "Use this when the host should be managed declaratively.".to_string()
            } else {
                "Needs reachable SSH, authentication, privilege, Linux/NixOS facts, and enough disk."
                    .to_string()
            },
            changes: vec![
                "Review and apply a declarative NixOS bootstrap.".to_string(),
                "Install or update pharos-beacon through managed system configuration.".to_string(),
            ],
            token_handoff: Some(
                "Beacon token handoff uses a managed file or env-file, never a command-line argument."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "Existing beacon token files are rotation-sensitive and must be reviewed before replacement."
                    .to_string(),
            ),
            next_state: Some("awaiting-first-heartbeat after setup starts".to_string()),
        },
        ExistingHostBootstrapOption {
            method: BootstrapMethod::NativeSystemd,
            label: "Native beacon".to_string(),
            available: automated_ready && linuxish,
            message: if automated_ready && linuxish {
                "Use this when the host should keep its current OS and only report to Pharos."
                    .to_string()
            } else {
                "Needs verified Linux SSH access with root or sudo.".to_string()
            },
            changes: vec![
                "Install the portable pharos-beacon service on the existing OS.".to_string(),
                "Create a least-surprise service environment file for beacon configuration.".to_string(),
            ],
            token_handoff: Some(
                "Beacon token handoff uses a local env-file path owned by the service user."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "Existing token files are rotation-sensitive and preserved until explicit rotation is confirmed.".to_string(),
            ),
            next_state: Some("awaiting-first-heartbeat after setup starts".to_string()),
        },
        ExistingHostBootstrapOption {
            method: BootstrapMethod::Manual,
            label: "Manual / deferred".to_string(),
            available: true,
            message:
                "Always available; the operator completes setup without automated host changes."
                    .to_string(),
            changes: vec![
                "No automated host changes are made by Pharos.".to_string(),
                "Show manual instructions and wait for the first heartbeat.".to_string(),
            ],
            token_handoff: Some(
                "Token handoff stays file/env-file based; do not paste raw tokens into shell history."
                    .to_string(),
            ),
            existing_token_policy: Some(
                "If a token already exists, treat it as rotation-sensitive state.".to_string(),
            ),
            next_state: Some("manual setup or awaiting-first-heartbeat".to_string()),
        },
    ]
}

fn check_passed(checks: &[ExistingHostPreflightCheck], key: &str) -> bool {
    checks
        .iter()
        .any(|check| check.key == key && check.state == PreflightCheckState::Pass)
}

fn check_failed(checks: &[ExistingHostPreflightCheck], key: &str) -> bool {
    checks
        .iter()
        .any(|check| check.key == key && check.state == PreflightCheckState::Fail)
}

fn preflight_summary(checks: &[ExistingHostPreflightCheck]) -> ExistingHostPreflightSummary {
    if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Fail)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Fail,
            label: "Needs attention".to_string(),
            message: "Fix failed checks before registering a beacon token.".to_string(),
        }
    } else if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Unknown)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Unknown,
            label: "Needs details".to_string(),
            message: "Collect the missing read-only facts before automated bootstrap.".to_string(),
        }
    } else if checks
        .iter()
        .any(|check| check.state == PreflightCheckState::Warn)
    {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Warn,
            label: "Review first".to_string(),
            message: "Bootstrap may be possible, but one check needs operator review.".to_string(),
        }
    } else {
        ExistingHostPreflightSummary {
            state: PreflightCheckState::Pass,
            label: "Ready".to_string(),
            message: "Choose a bootstrap method; no token has been registered yet.".to_string(),
        }
    }
}

fn preflight_next_action(
    summary: &ExistingHostPreflightSummary,
    options: &[ExistingHostBootstrapOption],
) -> &'static str {
    match summary.state {
        PreflightCheckState::Fail => "Fix failed checks, then run preflight again.",
        PreflightCheckState::Unknown => {
            "Collect SSH, privilege, OS, disk, and host-to-Pharos facts."
        }
        PreflightCheckState::Warn => "Review warnings, then choose a bootstrap method.",
        PreflightCheckState::Pass => {
            if options
                .iter()
                .any(|option| option.available && option.method != BootstrapMethod::Manual)
            {
                "Choose NixOS/declarative or native beacon bootstrap."
            } else {
                "Use manual/deferred setup or collect more automation facts."
            }
        }
    }
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rep): Json<HostReport>,
) -> StatusCode {
    if let Err(error) = rep.validate_contract() {
        tracing::warn!(
            host = %rep.name,
            schema = %rep.schema,
            version = rep.version,
            error = %error,
            "report rejected: invalid report contract"
        );
        return StatusCode::BAD_REQUEST;
    }
    if let Some(token) = bearer_token(&headers) {
        match state
            .beacon_auth
            .report_token_status(&state.store, &rep.name, token)
        {
            ReportTokenAuth::Allowed => {}
            ReportTokenAuth::Denied => {
                tracing::warn!(host = %rep.name, "report rejected: invalid bearer token");
                return StatusCode::UNAUTHORIZED;
            }
            ReportTokenAuth::Unavailable(err) => {
                tracing::error!(
                    host = %rep.name,
                    error = %err,
                    "report rejected: beacon token verifier unavailable"
                );
                return StatusCode::SERVICE_UNAVAILABLE;
            }
        }
    } else if state.beacon_auth.require_report_token {
        tracing::warn!(host = %rep.name, "report rejected: missing bearer token");
        return StatusCode::UNAUTHORIZED;
    } else {
        tracing::warn!(
            host = %rep.name,
            "accepting legacy unauthenticated report; migrate this host to PHAROS_TOKEN before enabling strict report auth"
        );
    }
    tracing::info!(host = %rep.name, "report received");
    state.store.record(rep, now_unix());
    StatusCode::NO_CONTENT
}

/// Local host registration for MVP onboarding (PHAROS-8/7). Protected by a
/// deployment-local bootstrap token; the returned beacon token is shown once.
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<HostRegistration>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.beacon_auth.registration_status(&headers) {
        RegistrationAuth::Allowed => {}
        RegistrationAuth::Disabled => {
            return (
                StatusCode::GONE,
                Json(json!({
                    "error": "local registration disabled; use Janus-managed beacon token issuance"
                })),
            );
        }
        RegistrationAuth::Denied => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "registration token invalid" })),
            );
        }
        RegistrationAuth::NotConfigured => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "PHAROS_REGISTRATION_TOKEN not configured" })),
            );
        }
    }

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("failed to generate beacon token: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "token generation failed" })),
            );
        }
    };
    let response = HostRegistrationResponse {
        name: registration.name.clone(),
        token: token.clone(),
    };
    let host = state.store.register(registration, token_hash(&token));
    tracing::info!(host = %host.name, "beacon token issued");
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(response).expect("registration response serializes")),
    )
}

async fn hosts_json(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let runtime_hosts = state.store.list();
    no_store_json(hosts_payload(
        runtime_hosts,
        state.manifests.manifests(),
        now,
    ))
}

fn hosts_payload(
    runtime_hosts: Vec<Host>,
    manifests: &[HostManifest],
    now: i64,
) -> serde_json::Value {
    let manifests = manifest_by_host(manifests);
    let hosts: Vec<_> = runtime_hosts
        .into_iter()
        .map(|h| {
            let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
            let freshness_tldr = h.freshness.tldr();
            let attention = attention_reason(live, &h.freshness, &h.service_observations);
            let location = resolve_host_location(
                Some(&h),
                manifests.get(h.name.as_str()).copied(),
                &h.name,
                now,
            );
            json!({
                "name": h.name,
                "role": h.role,
                "is_nix": h.is_nix,
                "report_version": h.report_version,
                "last_seen": h.last_seen,
                "heartbeat_log": h.heartbeat_log,
                "heartbeat_interval_secs": h.heartbeat_interval_secs,
                "inbound_rtt": h.inbound_rtt,
                "liveness": live,
                "location": location_payload(&location),
                "freshness": h.freshness,
                "freshness_tldr": freshness_tldr,
                "service_observations": h.service_observations,
                "service_observations_summary": service_observations_summary(&h.service_observations),
                "backup_observations": h.backup_observations,
                "backup_observations_summary": backup_observations_summary(&h.backup_observations),
                "attention": {
                    "label": attention.label,
                    "level": attention.level,
                    "rank": attention.rank,
                },
            })
        })
        .collect();
    json!({ "as_of": now, "hosts": hosts })
}

async fn declared_hosts_json(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let runtime_hosts = state.store.list();
    let server_probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_json(declared_hosts_payload(
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &runtime_hosts,
        &server_probes,
        now,
    ))
}

fn declared_hosts_payload(
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    runtime_hosts: &[Host],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    now: i64,
) -> serde_json::Value {
    let runtime_by_name: BTreeMap<&str, &Host> = runtime_hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let declared_hosts: Vec<_> = manifests
        .iter()
        .map(|manifest| {
            let runtime = runtime_by_name
                .get(manifest.host.name.as_str())
                .copied()
                .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
            let probes = server_probes
                .get(manifest.host.name.as_str())
                .or_else(|| server_probes.get(manifest.slug.as_str()))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            json!({
                "name": &manifest.host.name,
                "slug": &manifest.slug,
                "declared": manifest,
                "runtime": runtime_overlay(runtime, manifest, probes, now),
            })
        })
        .collect();

    json!({
        "schema": "inspr.pharos.declared-hosts.v1",
        "manifest_schema": HOST_MANIFEST_SCHEMA,
        "manifest_version": HOST_MANIFEST_VERSION,
        "as_of": now,
        "declared_hosts": declared_hosts,
        "load_errors": load_errors,
    })
}

fn runtime_overlay(
    host: Option<&Host>,
    manifest: &HostManifest,
    server_probes: &[ServerProbeObservation],
    now: i64,
) -> serde_json::Value {
    let location = resolve_host_location(host, Some(manifest), &manifest.host.name, now);
    let Some(host) = host else {
        return json!({
            "state": "pending",
            "liveness": Liveness::AwaitingFirstHeartbeat,
            "last_seen": null,
            "heartbeat_log": [],
            "heartbeat_interval_secs": null,
            "inbound_rtt": null,
            "location": location_payload(&location),
            "freshness": null,
            "freshness_tldr": null,
            "service_observations": [],
            "service_observations_summary": service_observations_summary(&[]),
            "backup_observations": [],
            "backup_observations_summary": backup_observations_summary(&[]),
            "server_probes": server_probes,
            "server_probes_summary": server_probe_summary(server_probes),
        });
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    json!({
        "state": "observed",
        "report_version": host.report_version,
        "last_seen": host.last_seen,
        "heartbeat_log": host.heartbeat_log,
        "heartbeat_interval_secs": host.heartbeat_interval_secs,
        "inbound_rtt": host.inbound_rtt,
        "liveness": live,
        "location": location_payload(&location),
        "freshness": host.freshness,
        "freshness_tldr": host.freshness.tldr(),
        "service_observations": host.service_observations,
        "service_observations_summary": service_observations_summary(&host.service_observations),
        "backup_observations": host.backup_observations,
        "backup_observations_summary": backup_observations_summary(&host.backup_observations),
        "server_probes": server_probes,
        "server_probes_summary": server_probe_summary(server_probes),
    })
}

fn no_store_headers() -> [(header::HeaderName, &'static str); 3] {
    [
        (
            header::CACHE_CONTROL,
            "no-store, no-cache, max-age=0, must-revalidate",
        ),
        (header::PRAGMA, "no-cache"),
        (header::EXPIRES, "0"),
    ]
}

fn no_store_html(body: String) -> impl IntoResponse {
    (no_store_headers(), Html(body))
}

fn no_store_json(value: serde_json::Value) -> impl IntoResponse {
    (no_store_headers(), Json(value))
}

async fn home(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    let jobs = state.provisioning_jobs.list();
    no_store_html(render_home(
        RuntimeSnapshot {
            hosts: &hosts,
            jobs: &jobs,
        },
        &self_host(),
        now_unix(),
        state.manifests.manifests(),
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
        true,
    ))
}

async fn map_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    no_store_html(render_map(
        &hosts,
        &self_host(),
        now_unix(),
        &user_label,
        state.auth.is_some(),
    ))
}

async fn map_data_json(State(state): State<AppState>) -> impl IntoResponse {
    let hosts = state.store.list();
    let now = now_unix();
    let probes = map_connectivity_probes(&hosts, state.manifests.manifests()).await;
    let payload = map_data_payload(
        &hosts,
        &self_host(),
        now,
        state.manifests.manifests(),
        &probes,
    );
    no_store_json(serde_json::to_value(payload).expect("map data serializes"))
}

async fn alerts_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    let jobs = state.provisioning_jobs.list();
    let now = now_unix();
    let probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_html(render_alerts(
        RuntimeSnapshot {
            hosts: &hosts,
            jobs: &jobs,
        },
        &self_host(),
        now,
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &probes,
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
    ))
}

async fn activity_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    let jobs = state.provisioning_jobs.list();
    let now = now_unix();
    let probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_html(render_activity(
        RuntimeSnapshot {
            hosts: &hosts,
            jobs: &jobs,
        },
        &self_host(),
        now,
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &probes,
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
    ))
}

async fn backups_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    no_store_html(render_backups(
        &state.store.list(),
        now_unix(),
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
    ))
}

async fn fleet_horizon_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        FLEET_HORIZON_PNG,
    )
}

async fn sidebar_lighthouse_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SIDEBAR_LIGHTHOUSE_PNG,
    )
}

async fn favicon_svg() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn url_query_escape(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn manifest_palette_color(manifests: &[HostManifest]) -> BTreeMap<String, String> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        let Some(color) = manifest.palette.as_ref().and_then(|palette| {
            palette
                .accent
                .clone()
                .or_else(|| palette.gradient.get("primary").cloned())
        }) else {
            continue;
        };
        by_host.insert(manifest.host.name.clone(), color.clone());
        by_host.insert(manifest.slug.clone(), color);
    }
    by_host
}

fn freshness_row(label: &str, value: &str, class: &str) -> String {
    format!(
        r#"<div class="fresh-row"><span>{}</span><strong class="{}">{}</strong></div>"#,
        html_escape(label),
        html_escape(class),
        html_escape(value)
    )
}

fn freshness_value(value: Option<u32>, zero_label: &str) -> (String, &'static str) {
    match value {
        Some(0) => (zero_label.to_string(), "ok"),
        Some(v) => (v.to_string(), "warn"),
        None => ("unknown".to_string(), "na"),
    }
}

fn freshness_markup(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return format!(
            "{}{}",
            freshness_row("Flake.lock age", "n/a", "na"),
            freshness_row("Commits behind", "n/a", "na")
        );
    }

    let (mut age, age_class) = freshness_value(freshness.flake_lock_age_days, "fresh");
    if age_class == "warn" {
        age.push('d');
    }
    let (commits, commits_class) = freshness_value(freshness.commits_behind, "0");
    format!(
        "{}{}",
        freshness_row("Flake.lock age", &age, age_class),
        freshness_row("Commits behind", &commits, commits_class)
    )
}

struct AttentionReason {
    label: String,
    level: &'static str,
    rank: u8,
}

fn self_attention_reason() -> AttentionReason {
    AttentionReason {
        label: "Pharos host".to_string(),
        level: "self",
        rank: 4,
    }
}

fn freshness_attention_reason(freshness: &NixFreshness) -> Option<AttentionReason> {
    if !freshness.applicable {
        return None;
    }

    let age_warn = freshness.flake_lock_age_days.filter(|d| *d > 0);
    let commits_warn = freshness.commits_behind.filter(|c| *c > 0);
    let label = match (age_warn, commits_warn) {
        (Some(days), Some(commits)) => format!("nix drift: {days}d · {commits} commits"),
        (Some(days), None) => format!("flake.lock {days}d"),
        (None, Some(commits)) => format!("{commits} commits behind"),
        (None, None) => {
            if freshness.flake_lock_age_days.is_none() || freshness.commits_behind.is_none() {
                "freshness unknown".to_string()
            } else {
                return None;
            }
        }
    };

    Some(AttentionReason {
        label,
        level: if age_warn.is_some() || commits_warn.is_some() {
            "warn"
        } else {
            "wait"
        },
        rank: 3,
    })
}

fn service_observation_attention_reason(
    observations: &[ServiceObservation],
) -> Option<AttentionReason> {
    if observations.is_empty() {
        return None;
    }

    let warnings = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Warning)
        .count();
    if warnings > 0 {
        return Some(AttentionReason {
            label: format!(
                "{warnings} service warning{}",
                if warnings == 1 { "" } else { "s" }
            ),
            level: "warn",
            rank: 3,
        });
    }

    let stale = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Stale)
        .count();
    if stale > 0 {
        return Some(AttentionReason {
            label: format!("{stale} service stale{}", if stale == 1 { "" } else { "s" }),
            level: "warn",
            rank: 3,
        });
    }

    let unknown = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Unknown)
        .count();
    if unknown > 0 {
        return Some(AttentionReason {
            label: format!("{unknown} service unknown"),
            level: "wait",
            rank: 3,
        });
    }

    None
}

fn service_observations_summary(observations: &[ServiceObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => warning += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let label = if observations.is_empty() {
        "not observed".to_string()
    } else if warning > 0 {
        format!("{warning} warning{}", if warning == 1 { "" } else { "s" })
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "healthy".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

fn backup_observations_summary(observations: &[BackupObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut failed = 0;
    let mut unknown = 0;
    let mut missing = 0;
    let mut not_configured = 0;
    for observation in observations {
        match observation.state {
            BackupPostureState::Healthy => healthy += 1,
            BackupPostureState::Warning => warning += 1,
            BackupPostureState::Stale => stale += 1,
            BackupPostureState::Failed => failed += 1,
            BackupPostureState::Unknown => unknown += 1,
            BackupPostureState::Missing => missing += 1,
            BackupPostureState::NotConfigured => not_configured += 1,
        }
    }
    let (state, label) = if observations.is_empty() {
        ("unknown", "not observed".to_string())
    } else if failed > 0 {
        ("failed", format!("{failed} failed"))
    } else if missing > 0 {
        ("missing", format!("{missing} missing"))
    } else if stale > 0 {
        ("stale", format!("{stale} stale"))
    } else if warning > 0 {
        (
            "warning",
            format!("{warning} warning{}", if warning == 1 { "" } else { "s" }),
        )
    } else if unknown > 0 {
        ("unknown", format!("{unknown} unknown"))
    } else if not_configured > 0 {
        ("not-configured", format!("{not_configured} not configured"))
    } else {
        ("healthy", "healthy".to_string())
    };
    json!({
        "state": state,
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "failed": failed,
        "unknown": unknown,
        "missing": missing,
        "not_configured": not_configured,
        "total": observations.len(),
    })
}

#[derive(Debug, Clone)]
struct BackupUiSummary {
    state: &'static str,
    level: &'static str,
    label: String,
    detail: String,
    last_success: String,
    schedule: String,
    target: String,
    validation: String,
    total: usize,
    rank: usize,
}

fn backup_posture_rank(state: BackupPostureState) -> usize {
    match state {
        BackupPostureState::Failed => 0,
        BackupPostureState::Missing => 1,
        BackupPostureState::Stale => 2,
        BackupPostureState::Warning => 3,
        BackupPostureState::Unknown => 4,
        BackupPostureState::NotConfigured => 5,
        BackupPostureState::Healthy => 6,
    }
}

fn backup_level(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Failed | BackupPostureState::Missing => "critical",
        BackupPostureState::Stale | BackupPostureState::Warning => "warning",
        BackupPostureState::Unknown | BackupPostureState::NotConfigured => "watch",
        BackupPostureState::Healthy => "clear",
    }
}

fn backup_state_key(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Healthy => "healthy",
        BackupPostureState::Warning => "warning",
        BackupPostureState::Stale => "stale",
        BackupPostureState::Failed => "failed",
        BackupPostureState::Unknown => "unknown",
        BackupPostureState::Missing => "missing",
        BackupPostureState::NotConfigured => "not-configured",
    }
}

fn backup_state_label(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Healthy => "Protected",
        BackupPostureState::Warning => "Review backup",
        BackupPostureState::Stale => "Backup stale",
        BackupPostureState::Failed => "Backup failed",
        BackupPostureState::Unknown => "Backup pending",
        BackupPostureState::Missing => "Backup missing",
        BackupPostureState::NotConfigured => "No backup",
    }
}

fn backup_run_label(state: pharos_core::BackupRunState) -> &'static str {
    match state {
        pharos_core::BackupRunState::Succeeded => "succeeded",
        pharos_core::BackupRunState::Failed => "failed",
        pharos_core::BackupRunState::Running => "running",
        pharos_core::BackupRunState::Unknown => "unknown",
    }
}

fn backup_validation_state_label(state: pharos_core::BackupValidationState) -> &'static str {
    match state {
        pharos_core::BackupValidationState::Passed => "passed",
        pharos_core::BackupValidationState::Failed => "failed",
        pharos_core::BackupValidationState::Stale => "stale",
        pharos_core::BackupValidationState::Unknown => "unknown",
    }
}

fn backup_validation_level_label(level: pharos_core::BackupValidationLevel) -> &'static str {
    match level {
        pharos_core::BackupValidationLevel::SnapshotExists => "snapshot",
        pharos_core::BackupValidationLevel::RepositoryCheck => "repo check",
        pharos_core::BackupValidationLevel::MountList => "mount/list",
        pharos_core::BackupValidationLevel::RestoreSample => "restore sample",
        pharos_core::BackupValidationLevel::DiffHash => "diff/hash",
        pharos_core::BackupValidationLevel::OperatorTest => "operator test",
    }
}

fn backup_last_success_label(observation: &BackupObservation, now: i64) -> String {
    observation
        .last_success_at
        .map(|timestamp| format!("{} ago", duration_label(now - timestamp)))
        .unwrap_or_else(|| "not yet".to_string())
}

fn backup_validation_label(observation: &BackupObservation, now: i64) -> String {
    if let Some(restore) = &observation.restore_validation {
        let label = restore
            .evidence_label
            .as_deref()
            .unwrap_or_else(|| backup_validation_level_label(restore.level));
        return restore
            .checked_at
            .map(|timestamp| {
                format!(
                    "{} {} · {} ago",
                    label,
                    backup_validation_state_label(restore.state),
                    duration_label(now - timestamp)
                )
            })
            .unwrap_or_else(|| {
                format!("{} {}", label, backup_validation_state_label(restore.state))
            });
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_check_at, observation.last_check_state)
    {
        return format!(
            "check {} · {} ago",
            backup_validation_state_label(state),
            duration_label(now - timestamp)
        );
    }

    "not checked".to_string()
}

fn backup_attempt_detail(observation: &BackupObservation, now: i64) -> String {
    if observation.state == BackupPostureState::Healthy {
        return observation
            .last_success_at
            .map(|timestamp| format!("last success {} ago", duration_label(now - timestamp)))
            .unwrap_or_else(|| observation.summary.clone());
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_attempt_at, observation.last_attempt_state)
    {
        return format!(
            "{} · {} ago",
            backup_run_label(state),
            duration_label(now - timestamp)
        );
    }

    observation.summary.clone()
}

fn backup_ui_summary(observations: &[BackupObservation], now: i64) -> BackupUiSummary {
    let Some(primary) = observations
        .iter()
        .min_by_key(|observation| backup_posture_rank(observation.state))
    else {
        return BackupUiSummary {
            state: "unknown",
            level: "watch",
            label: "Not observed".to_string(),
            detail: "No backup signal yet".to_string(),
            last_success: "not observed".to_string(),
            schedule: "not declared".to_string(),
            target: "not declared".to_string(),
            validation: "not checked".to_string(),
            total: 0,
            rank: backup_posture_rank(BackupPostureState::Unknown),
        };
    };

    BackupUiSummary {
        state: backup_state_key(primary.state),
        level: backup_level(primary.state),
        label: backup_state_label(primary.state).to_string(),
        detail: backup_attempt_detail(primary, now),
        last_success: backup_last_success_label(primary, now),
        schedule: primary
            .schedule
            .clone()
            .unwrap_or_else(|| "not declared".to_string()),
        target: primary
            .target_label
            .clone()
            .unwrap_or_else(|| "not declared".to_string()),
        validation: backup_validation_label(primary, now),
        total: observations.len(),
        rank: backup_posture_rank(primary.state),
    }
}

fn backup_card_markup(summary: &BackupUiSummary, extra_class: &str) -> String {
    let extra_class = if extra_class.is_empty() {
        String::new()
    } else {
        format!(" {}", html_escape(extra_class))
    };
    format!(
        r#"<div class="backup-mini{extra_class} {level}" data-backup-state="{state}" title="{title}"><strong>{label}</strong><span>{detail}</span></div>"#,
        extra_class = extra_class,
        level = html_escape(summary.level),
        state = html_escape(summary.state),
        title = html_escape(&format!("Backup: {} - {}", summary.label, summary.detail)),
        label = html_escape(&summary.label),
        detail = html_escape(&summary.detail)
    )
}

fn backup_search_text(summary: &BackupUiSummary) -> Option<String> {
    (summary.total > 0).then(|| {
        format!(
            "{} {} {} {} {} {}",
            summary.label,
            summary.detail,
            summary.last_success,
            summary.schedule,
            summary.target,
            summary.validation
        )
    })
}

const FIRST_BACKUP_PENDING_GRACE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
struct ProtectionOnboardingStatus {
    state: &'static str,
    level: &'static str,
    label: String,
    detail: String,
    sort_time: i64,
}

impl ProtectionOnboardingStatus {
    fn search_text(&self) -> String {
        format!("{} {} {}", self.state, self.label, self.detail)
    }
}

fn protection_setup_job_for_host<'a>(
    host_name: &str,
    jobs: &'a [ProvisioningJob],
) -> Option<&'a ProvisioningJob> {
    jobs.iter()
        .filter(|job| {
            !matches!(
                job.state,
                ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded
            ) && provisioning_job_host_name(job).is_some_and(|name| name == host_name)
        })
        .max_by_key(|job| job.updated_at)
}

fn first_runtime_seen_at(host: &Host, job: &ProvisioningJob) -> i64 {
    host.heartbeat_log
        .iter()
        .copied()
        .filter(|stamp| *stamp >= job.created_at)
        .min()
        .or(host.last_seen)
        .unwrap_or(job.updated_at)
}

fn backup_observation_success_at(observation: &BackupObservation) -> Option<i64> {
    if observation.state == BackupPostureState::Healthy
        || observation.last_attempt_state == Some(pharos_core::BackupRunState::Succeeded)
        || observation.last_success_at.is_some()
    {
        return observation
            .last_success_at
            .or(observation.last_attempt_at)
            .or(observation.last_check_at);
    }
    None
}

fn protection_onboarding_status(
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) -> Option<ProtectionOnboardingStatus> {
    let job = protection_setup_job_for_host(&host.name, jobs)?;
    let intent = provisioning_job_setup_intent(job);
    let first_seen = first_runtime_seen_at(host, job);

    if let Some(failed) = host.backup_observations.iter().find(|observation| {
        matches!(
            observation.state,
            BackupPostureState::Failed | BackupPostureState::Missing
        ) || observation.last_attempt_state == Some(pharos_core::BackupRunState::Failed)
    }) {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-failed",
            level: "critical",
            label: "First backup failed".to_string(),
            detail: failed.summary.clone(),
            sort_time: failed
                .last_attempt_at
                .or(failed.last_check_at)
                .unwrap_or(now),
        });
    }

    if let Some(review) = host.backup_observations.iter().find(|observation| {
        matches!(
            observation.state,
            BackupPostureState::Stale | BackupPostureState::Warning
        )
    }) {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-review",
            level: "warning",
            label: "First backup needs review".to_string(),
            detail: review.summary.clone(),
            sort_time: backup_sort_time(host, review, now),
        });
    }

    if let Some(success_at) = host
        .backup_observations
        .iter()
        .filter_map(backup_observation_success_at)
        .max()
    {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-succeeded",
            level: "clear",
            label: "First backup succeeded".to_string(),
            detail: format!(
                "Successful backup observed {} ago",
                duration_label(now - success_at)
            ),
            sort_time: success_at,
        });
    }

    match intent.backup {
        BackupSetupIntent::Required => {
            let age = now.saturating_sub(first_seen);
            if age > FIRST_BACKUP_PENDING_GRACE_SECS {
                Some(ProtectionOnboardingStatus {
                    state: "first-backup-overdue",
                    level: "warning",
                    label: "First backup overdue".to_string(),
                    detail: format!(
                        "No successful backup after {} from first heartbeat",
                        duration_label(FIRST_BACKUP_PENDING_GRACE_SECS)
                    ),
                    sort_time: first_seen + FIRST_BACKUP_PENDING_GRACE_SECS,
                })
            } else {
                Some(ProtectionOnboardingStatus {
                    state: "first-backup-pending",
                    level: "watch",
                    label: "First backup pending".to_string(),
                    detail: "First heartbeat seen; waiting for backup evidence".to_string(),
                    sort_time: first_seen,
                })
            }
        }
        BackupSetupIntent::Optional => Some(ProtectionOnboardingStatus {
            state: "backup-optional",
            level: "clear",
            label: "Backup optional".to_string(),
            detail: "Not required to finish onboarding".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::External => Some(ProtectionOnboardingStatus {
            state: "backup-external",
            level: "watch",
            label: "Managed elsewhere".to_string(),
            detail: "External evidence will appear when detected".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::EnrollLater => Some(ProtectionOnboardingStatus {
            state: "backup-enroll-later",
            level: "watch",
            label: "Backup enrollment queued".to_string(),
            detail: "Follow up after onboarding is stable".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::Absent => Some(ProtectionOnboardingStatus {
            state: "backup-absent",
            level: "clear",
            label: "Backups intentionally absent".to_string(),
            detail: "Host is recorded as intentionally unprotected".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::Deferred => Some(ProtectionOnboardingStatus {
            state: "backup-deferred",
            level: "watch",
            label: "Backup decision pending".to_string(),
            detail: "Ask again before closing onboarding".to_string(),
            sort_time: job.updated_at,
        }),
    }
}

fn protection_onboarding_markup(status: &ProtectionOnboardingStatus, extra_class: &str) -> String {
    let extra_class = if extra_class.is_empty() {
        String::new()
    } else {
        format!(" {}", html_escape(extra_class))
    };
    format!(
        r#"<div class="protection-onboard{extra_class} {level}" data-protection-state="{state}" title="{title}"><strong>{label}</strong><span>{detail}</span></div>"#,
        extra_class = extra_class,
        level = html_escape(status.level),
        state = html_escape(status.state),
        title = html_escape(&format!(
            "Protection onboarding: {} - {}",
            status.label, status.detail
        )),
        label = html_escape(&status.label),
        detail = html_escape(&status.detail)
    )
}

fn protection_onboarding_alert(
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) -> Option<AlertItem> {
    let status = protection_onboarding_status(host, jobs, now)?;
    if status.level == "clear" {
        return None;
    }
    let action = match status.state {
        "first-backup-overdue" => "Inspect backup enrollment and run or observe the first backup.",
        "first-backup-failed" => "Fix the backup job, then confirm the next successful run.",
        "first-backup-review" => "Review backup evidence before closing onboarding.",
        "first-backup-pending" => "Keep onboarding open until the first backup is observed.",
        "backup-deferred" => "Choose whether this host should be protected.",
        "backup-enroll-later" => "Schedule or start backup enrollment after the host is stable.",
        "backup-external" => "Confirm external backup evidence can be observed when available.",
        _ => "Review protection onboarding.",
    };
    Some(AlertItem {
        level: status.level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: status.label,
        detail: status.detail,
        source: "setup",
        seen: format!("as of {}", clock_label(now)),
        next_action: action.to_string(),
        sort_time: status.sort_time,
    })
}

fn push_protection_onboarding_activity(
    events: &mut Vec<ActivityEvent>,
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) {
    let Some(status) = protection_onboarding_status(host, jobs, now) else {
        return;
    };
    let level = match status.level {
        "clear" => "recovery",
        level => level,
    };
    events.push(ActivityEvent::new(
        status.sort_time,
        host.name.clone(),
        level,
        "setup",
        status.label,
        status.detail,
        "setup",
    ));
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ServerProbeObservation {
    id: String,
    service: String,
    source: &'static str,
    policy: &'static str,
    kind: &'static str,
    target: Option<String>,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    client_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
}

async fn server_probe_overlays(
    manifests: &[HostManifest],
    now: i64,
) -> BTreeMap<String, Vec<ServerProbeObservation>> {
    let mut overlays = BTreeMap::new();
    for manifest in manifests {
        let mut observations = Vec::new();
        for service in &manifest.services {
            if should_server_probe(service) {
                observations.push(server_probe_service(service, now).await);
            }
        }
        if !observations.is_empty() {
            overlays.insert(manifest.host.name.clone(), observations);
        }
    }
    overlays
}

async fn server_probe_service(service: &ManifestService, now: i64) -> ServerProbeObservation {
    let Some(raw_url) = server_probe_url(service) else {
        return server_probe_observation(
            service,
            None,
            ServiceObservationState::Unknown,
            None,
            "no server-probe URL declared".to_string(),
            now,
        );
    };

    let url = match Url::parse(&raw_url) {
        Ok(url) => url,
        Err(_) => {
            return server_probe_observation(
                service,
                Some(raw_url),
                ServiceObservationState::Unknown,
                None,
                "server-probe URL is invalid".to_string(),
                now,
            );
        }
    };
    let target = sanitized_probe_target(&url);

    if !matches!(url.scheme(), "http" | "https") {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server probe supports http/https targets only".to_string(),
            now,
        );
    }

    let Some(host) = url.host_str() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no host".to_string(),
            now,
        );
    };
    let Some(port) = url.port_or_known_default() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no port".to_string(),
            now,
        );
    };

    match timeout(SERVER_PROBE_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Healthy,
            Some(true),
            format!("server can reach {host}:{port}"),
            now,
        ),
        Ok(Err(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server cannot reach {host}:{port}"),
            now,
        ),
        Err(_) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server probe timed out for {host}:{port}"),
            now,
        ),
    }
}

fn server_probe_observation(
    service: &ManifestService,
    target: Option<String>,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
) -> ServerProbeObservation {
    ServerProbeObservation {
        id: service_probe_id(service),
        service: service.name.clone(),
        source: "server",
        policy: "pharos-runtime",
        kind: "tcp-connect",
        target,
        state,
        server_reachable,
        client_reachable: None,
        summary,
        checked_at,
    }
}

fn should_server_probe(service: &ManifestService) -> bool {
    explicit_server_probe_policy_opt(service.probe.as_ref())
        || (service.status_policy.source == ManifestStatusSource::PharosRuntime
            && !service.passive
            && server_probe_url(service).is_some())
}

fn explicit_server_probe_policy_opt(policy: Option<&ManifestProbePolicy>) -> bool {
    policy.is_some_and(explicit_server_probe_policy)
}

fn explicit_server_probe_policy(policy: &ManifestProbePolicy) -> bool {
    match policy {
        ManifestProbePolicy::Named(name) => matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "server" | "server-probe" | "pharos" | "pharos-runtime"
        ),
        ManifestProbePolicy::Enabled(_) => false,
    }
}

fn server_probe_url(service: &ManifestService) -> Option<String> {
    ["tailnet", "lanHostname", "lanIp"]
        .into_iter()
        .find_map(|key| service.urls.get(key).filter(|url| !url.is_empty()).cloned())
        .or_else(|| service.url.as_ref().filter(|url| !url.is_empty()).cloned())
}

fn sanitized_probe_target(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    format!("{}://{host}{port}{path}", url.scheme())
}

fn server_probe_summary(observations: &[ServerProbeObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => warning += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let label = if observations.is_empty() {
        "not probed".to_string()
    } else if warning > 0 {
        format!("{warning} unreachable")
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "server reachable".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

fn service_probe_id(service: &ManifestService) -> String {
    let mut id = String::new();
    for ch in service.name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            id.push(ch);
        } else if !id.ends_with('-') {
            id.push('-');
        }
    }
    id.trim_matches('-').to_string()
}

fn attention_reason(
    live: Liveness,
    freshness: &NixFreshness,
    observations: &[ServiceObservation],
) -> AttentionReason {
    match live {
        Liveness::Down => AttentionReason {
            label: "silent heartbeat".to_string(),
            level: "down",
            rank: 0,
        },
        Liveness::Stale => AttentionReason {
            label: "stale heartbeat".to_string(),
            level: "warn",
            rank: 1,
        },
        Liveness::AwaitingFirstHeartbeat => AttentionReason {
            label: "awaiting first beat".to_string(),
            level: "wait",
            rank: 2,
        },
        Liveness::Live => freshness_attention_reason(freshness)
            .or_else(|| service_observation_attention_reason(observations))
            .unwrap_or_else(|| AttentionReason {
                label: "all clear".to_string(),
                level: "ok",
                rank: 4,
            }),
    }
}

fn reason_markup(reason: &AttentionReason) -> String {
    format!(
        r#"<div class="reason {}" data-reason><span>{}</span></div>"#,
        html_escape(reason.level),
        html_escape(&reason.label)
    )
}

fn live_key(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "live",
        Liveness::Stale => "stale",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "awaiting_first_heartbeat",
    }
}

fn icon_with_class(svg: &str, class: &str) -> String {
    svg.replacen("class=\"ico\"", &format!("class=\"ico {class}\""), 1)
}

fn status_icon_stack() -> String {
    format!(
        "{}{}{}{}",
        icon_with_class(icons::status_svg(Liveness::Live), "state-icon live"),
        icon_with_class(icons::status_svg(Liveness::Stale), "state-icon stale"),
        icon_with_class(icons::status_svg(Liveness::Down), "state-icon down"),
        icon_with_class(
            icons::status_svg(Liveness::AwaitingFirstHeartbeat),
            "state-icon awaiting"
        )
    )
}

fn duration_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn clock_label(timestamp: i64) -> String {
    let seconds = timestamp.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn summary_cards(hosts: &[Host], _self_name: &str, now: i64) -> String {
    let total = hosts.len();
    let mut live = 0;
    let mut stale = 0;
    let mut down = 0;
    for h in hosts {
        let live_state = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        match live_state {
            Liveness::Live => live += 1,
            Liveness::Stale => stale += 1,
            Liveness::Down => down += 1,
            Liveness::AwaitingFirstHeartbeat => {}
        }
    }
    format!(
        r#"<section class="summary" aria-label="host summary"><button class="metric" type="button" data-live-filter="all" aria-pressed="true"><b>{total}</b><span>All hosts</span></button><button class="metric live" type="button" data-live-filter="live" aria-pressed="false"><b>{live}</b><span>Live</span></button><button class="metric stale" type="button" data-live-filter="stale" aria-pressed="false"><b>{stale}</b><span>Stale</span></button><button class="metric down" type="button" data-live-filter="down" aria-pressed="false"><b>{down}</b><span>Down</span></button></section>"#
    )
}

fn sidebar_user_label(auth: &AuthState, headers: &HeaderMap) -> String {
    auth.as_ref()
        .and_then(|auth| auth.current_user(headers))
        .map(|user| user.display_name)
        .unwrap_or_else(|| {
            if auth.is_some() {
                "signed in".to_string()
            } else {
                "local access".to_string()
            }
        })
}

fn sidebar(user_label: &str, logout_enabled: bool, active: &str) -> String {
    let logout = if logout_enabled {
        format!(
            r#"<a class="side-logout" href="/auth/logout" title="Log out of Pharos" aria-label="Log out of Pharos">{}</a>"#,
            icons::LOG_OUT
        )
    } else {
        String::new()
    };
    let fleet_current = if active == "fleet" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let map_current = if active == "map" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let alerts_current = if active == "alerts" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let backups_current = if active == "backups" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let activity_current = if active == "activity" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let settings_current = if active == "settings" {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r##"<aside class="sidebar" aria-label="primary navigation"><div class="side-brand"><span class="side-mark">{lighthouse}</span><span class="side-logo">PHAROS</span></div><nav class="side-nav"><a class="side-link" href="/"{fleet_current}>{fleet}<span>Fleet</span></a><a class="side-link" href="/map"{map_current}>{map}<span>Map</span></a><a class="side-link" href="/alerts"{alerts_current}>{alerts}<span>Alerts</span></a><a class="side-link" href="/backups"{backups_current}>{backups}<span>Backups</span></a><a class="side-link" href="/activity"{activity_current}>{activity}<span>Activity</span></a><a class="side-link" href="/agora"{settings_current}>{settings}<span>Settings</span></a></nav><div class="side-foot"><span class="side-user" title="{user_title}"><span>{user_label}</span></span>{logout}</div></aside>"##,
        lighthouse = icons::LIGHTHOUSE,
        fleet = icons::GRID,
        map = icons::SERVER,
        alerts = icons::status_svg(Liveness::Stale),
        backups = icons::SHIELD_CHECK,
        activity = icons::LIST,
        settings = icons::SLIDERS,
        fleet_current = fleet_current,
        map_current = map_current,
        alerts_current = alerts_current,
        backups_current = backups_current,
        activity_current = activity_current,
        settings_current = settings_current,
        user_label = html_escape(user_label),
        user_title = html_escape(user_label),
        logout = logout
    )
}

fn page_header(title: &str, subtitle: &str, now: i64) -> String {
    format!(
        r#"<div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>{title}</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">{subtitle}</p></div><div class="asof" data-as-of>as of {as_of}</div></div>"#,
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        as_of = clock_label(now)
    )
}

fn header(now: i64) -> String {
    page_header("Fleet", "All hosts at a glance", now)
}

#[derive(Debug, Clone, Copy)]
struct ShellContext<'a> {
    user_label: &'a str,
    logout_enabled: bool,
}

#[derive(Debug, Clone, Copy)]
struct RuntimeSnapshot<'a> {
    hosts: &'a [Host],
    jobs: &'a [ProvisioningJob],
}

fn search_box(placeholder: &str) -> String {
    format!(
        r#"<label class="search">{search}<input data-search type="search" autocomplete="off" placeholder="{placeholder}"></label>"#,
        search = icons::SEARCH,
        placeholder = html_escape(placeholder)
    )
}

fn toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="fleet controls"><div class="toolbar-left"><div class="seg" role="group" aria-label="view"><button type="button" data-view-button="grid" aria-pressed="true" title="Grid view">{grid}</button><button type="button" data-view-button="list" aria-pressed="false" title="List view">{list}</button></div><label class="arrange">Arrange by <select data-sort aria-label="arrange by"><option value="attention">Needs attention</option><option value="name">Name</option><option value="last">Last change</option><option value="freeform">Freeform</option></select></label></div><div class="toolbar-right">{search}</div></section>"#,
        grid = icons::GRID,
        list = icons::LIST,
        search = search_box("Search hosts...")
    )
}

fn map_toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="map controls"><div class="toolbar-left"><span class="arrange">All servers stay visible unless filtered</span></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

fn onboard_primary(label: &str) -> String {
    format!(
        r#"<button class="onboard-primary" type="button" data-onboard-open>{icon}<span>{label}</span></button>"#,
        icon = icons::PLUS,
        label = html_escape(label)
    )
}

fn onboard_tile() -> String {
    format!(
        r#"<button class="onboard-tile" type="button" data-onboard-open data-onboard-tile aria-label="Add server"><span class="onboard-mark">{icon}</span><span class="onboard-copy"><strong>Add server</strong><span>Provision or onboard</span></span><span class="onboard-foot">Open setup assistant</span></button>"#,
        icon = icons::PLUS
    )
}

fn onboard_row() -> String {
    format!(
        r#"<tr class="onboard-row" data-sev="9" data-sort-name="zzzz-onboard" data-last="0"><td colspan="7"><button type="button" data-onboard-open aria-label="Add server"><span class="onboard-mark">{icon}</span><span><strong>Add server</strong><span>Provision a new host or onboard an existing one.</span></span></button></td></tr>"#,
        icon = icons::PLUS
    )
}

fn setup_assistant() -> String {
    format!(
        r#"<section class="assistant-overlay" data-setup-assistant hidden aria-label="setup assistant"><div class="assistant-sheet" role="dialog" aria-modal="true" aria-labelledby="setup-assistant-title"><header class="assistant-head"><div><h2 id="setup-assistant-title">Add a server</h2><p>Choose what you want to add. Nothing changes until you confirm.</p></div><button class="assistant-close" type="button" data-assistant-close>Close</button></header><div class="assistant-body"><div class="assistant-paths"><button class="assistant-path" type="button" data-assistant-path="new" aria-pressed="false"><span class="onboard-mark">{plus}</span><span><strong>New server</strong><span>Provision a server from a provider template.</span></span></button><button class="assistant-path" type="button" data-assistant-path="existing" aria-pressed="false"><span class="onboard-mark">{server}</span><span><strong>Existing server</strong><span>Onboard a server you already control.</span></span></button></div><div class="assistant-provider-step" data-assistant-provider-step><div class="assistant-step-head"><strong>New server</strong><span>Choose where this server starts.</span></div><div class="assistant-providers"><button class="assistant-provider" type="button" data-assistant-provider="hetzner-cloud" aria-pressed="false"><span class="assistant-provider-title"><strong>Hetzner Cloud</strong><span class="assistant-badge">Recommended</span></span><p>Best supported path for a fresh Pharos-managed server.</p><span class="assistant-facts"><span><b>Credentials needed</b>API token later</span><span><b>Cost</b>Paid cloud</span><span><b>Bootstrap</b>NixOS ready</span></span></button><button class="assistant-provider" type="button" data-assistant-provider="manual-import" aria-pressed="false"><span class="assistant-provider-title"><strong>Manual / existing provider</strong></span><p>Use this for Netcup or any provider that is not safely automated yet.</p><span class="assistant-facts"><span><b>Credentials needed</b>SSH later</span><span><b>Cost</b>Your provider</span><span><b>Bootstrap</b>Import path</span></span></button></div><div class="assistant-step-head"><strong>Template</strong><span>No provider resources are created here.</span></div><div class="assistant-templates" aria-label="server templates"><button class="assistant-template" type="button" data-assistant-template-provider="hetzner-cloud" data-assistant-template="hetzner-small-nixos" data-assistant-next="Next: review a Hetzner Cloud plan for a small NixOS server. No resources have been created." aria-pressed="false"><span><strong>Small NixOS server</strong><span>Low monthly cost, automatic NixOS bootstrap, good first production default.</span></span><em>low cost</em></button><button class="assistant-template" type="button" data-assistant-template-provider="hetzner-cloud" data-assistant-template="hetzner-lab" data-assistant-next="Next: review a lab-style plan and confirm current pricing before creating anything." aria-pressed="false"><span><strong>Lab / free-tier style</strong><span>Smallest practical shape. Pricing and availability must be checked at plan time.</span></span><em>check cost</em></button><button class="assistant-template" type="button" data-assistant-template-provider="hetzner-cloud" data-assistant-template="bring-own-plan" data-assistant-next="Next: choose exact provider size, region, and image before creating anything." aria-pressed="false"><span><strong>Bring your own plan</strong><span>Use when you already know the size, region, and bootstrap profile you want.</span></span><em>custom</em></button><button class="assistant-template" type="button" data-assistant-template-provider="manual-import" data-assistant-template="manual-import" data-assistant-next="Next: switch to existing-host import. Netcup is not treated as fully automated yet." aria-pressed="false" hidden><span><strong>Manual import handoff</strong><span>For Netcup and other providers, prepare SSH/import instead of automated provisioning.</span></span><em>import</em></button></div></div><div class="assistant-existing-step" data-assistant-existing-step><div class="assistant-step-head"><strong>Add existing server</strong><span>Read-only check first.</span></div><form class="assistant-preflight-form" data-preflight-form><label><span>Server name</span><input data-preflight-host-name autocomplete="off" placeholder="hsb8"></label><label><span>SSH address</span><input data-preflight-ssh-host autocomplete="off" placeholder="host or host:22"></label><label><span>Connection</span><select data-preflight-route><option value="tailnet">Tailnet</option><option value="direct">Direct</option><option value="bastion">Bastion</option><option value="none">Manual</option></select></label><details class="assistant-preflight-details"><summary>Known facts</summary><div class="assistant-preflight-facts"><label><span>Login works</span><select data-preflight-fact="ssh_authenticated"><option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option></select></label><label><span>Admin access</span><select data-preflight-admin><option value="">Unknown</option><option value="sudo">sudo</option><option value="root">root</option><option value="none">No</option></select></label><label><span>Operating system</span><select data-preflight-os><option value="">Unknown</option><option value="linux">Linux</option><option value="nixos">NixOS</option><option value="other">Other</option></select></label><label><span>Nix available</span><select data-preflight-fact="nix_available"><option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option></select></label><label><span>Disk free</span><input data-preflight-disk type="number" min="0" step="1" inputmode="numeric" placeholder="GiB"></label><label><span>Can reach Pharos</span><select data-preflight-fact="pharos_reachable"><option value="">Unknown</option><option value="true">Yes</option><option value="false">No</option></select></label></div></details><button class="assistant-check" type="submit" data-preflight-check>Check server</button></form><div class="assistant-preflight-result" data-preflight-result hidden><div class="assistant-result-head"><strong data-preflight-summary>Preflight</strong><span data-preflight-message>Waiting for checks.</span></div><div class="assistant-checks" data-preflight-checks></div><div class="assistant-bootstrap" data-preflight-bootstrap hidden></div></div></div><div class="assistant-plan" data-assistant-plan><div class="assistant-plan-head"><strong>Review plan</strong><span>Nothing is created until you start setup.</span></div><div class="assistant-plan-list"><div class="assistant-plan-row"><span><strong>Provider resources</strong><span>Prepare server, SSH key, firewall, and selected region.</span></span><em class="assistant-plan-chip">planned</em></div><div class="assistant-plan-row"><span><strong>SSH and bootstrap</strong><span>Prepare NixOS bootstrap path without exposing private key material.</span></span><em class="assistant-plan-chip">planned</em></div><div class="assistant-plan-row"><span><strong>Beacon registration</strong><span>Create only a safe handoff; raw tokens are never shown.</span></span><em class="assistant-plan-chip" data-kind="protected">protected</em></div><div class="assistant-plan-row"><span><strong>First heartbeat</strong><span>Wait until the new host reports before marking it live.</span></span><em class="assistant-plan-chip">waiting</em></div><div class="assistant-plan-row"><span><strong>Backup and location</strong><span>Hand off backup enrollment and site/location setup after first contact.</span></span><em class="assistant-plan-chip" data-kind="later">later</em></div></div><label class="assistant-confirm"><input type="checkbox" data-assistant-confirm><span>I understand this may create provider resources.</span><button class="assistant-start" type="button" data-assistant-start disabled>Start setup</button></label><div class="assistant-job" data-assistant-job hidden><strong data-assistant-job-title>Tracked job</strong><span data-assistant-job-message>Waiting for setup.</span></div><div class="assistant-progress" aria-label="provisioning progress states"><span data-progress-state="planning">planning</span><span data-progress-state="provisioning">provisioning</span><span data-progress-state="bootstrapping">bootstrapping</span><span data-progress-state="waiting-for-heartbeat">waiting for heartbeat</span><span data-progress-state="backup-pending">backup pending</span><span data-progress-state="complete" data-risk="ok">complete</span><span data-progress-state="failed" data-risk="fail">failed</span><span data-progress-state="cleanup-needed" data-risk="fail">cleanup needed</span></div></div><div class="assistant-next" data-assistant-next><div><strong data-assistant-next-title>Next step</strong><span data-assistant-next-copy>Choose a path to preview the next step. No changes have been started.</span></div><button type="button" data-assistant-continue disabled>Continue</button></div></div></div></section>"#,
        plus = icons::PLUS,
        server = icons::SERVER
    )
    .replace(
        r#"<div class="assistant-plan-list">"#,
        r#"<label class="assistant-plan-field"><span>Server name</span><input data-new-host-name autocomplete="off" placeholder="lab-01"></label><div class="assistant-plan-list">"#,
    )
    .replace(
        r#"<form class="assistant-preflight-form" data-preflight-form><label><span>Server name</span><input data-preflight-host-name autocomplete="off" placeholder="hsb8"></label><label><span>SSH address</span><input data-preflight-ssh-host autocomplete="off" placeholder="host or host:22"></label><label><span>Connection</span><select data-preflight-route><option value="tailnet">Tailnet</option><option value="direct">Direct</option><option value="bastion">Bastion</option><option value="none">Manual</option></select></label>"#,
        r#"<form class="assistant-preflight-form" data-preflight-form><label><span>Server name</span><input data-preflight-host-name autocomplete="off" placeholder="hsb8"></label><label><span>Role</span><input data-preflight-role autocomplete="off" placeholder="server"></label><label><span>Host type</span><select data-preflight-host-type><option value="">Decide after check</option><option value="nixos">NixOS</option><option value="linux-beacon">Linux beacon</option></select></label><label><span>SSH address</span><input data-preflight-ssh-host autocomplete="off" placeholder="host or host:22"></label><label><span>Connection</span><select data-preflight-route><option value="tailnet">Tailnet</option><option value="direct">Direct</option><option value="bastion">Bastion</option><option value="none">Manual</option></select></label>"#,
    )
    .replace(
        r#"</div></div><label class="assistant-confirm">"#,
        r#"</div><div class="assistant-setup-intent" data-existing-setup-intent><div class="assistant-plan-head"><strong>Protection and place</strong><span>Saved as setup intent.</span></div><div class="assistant-choice-group"><strong>Backups</strong><div class="assistant-choice-options" role="radiogroup" aria-label="backup setup intent"><label class="assistant-choice"><input type="radio" name="backup_intent" value="required">Required</label><label class="assistant-choice"><input type="radio" name="backup_intent" value="optional">Optional</label><label class="assistant-choice"><input type="radio" name="backup_intent" value="external">Managed elsewhere</label><label class="assistant-choice"><input type="radio" name="backup_intent" value="enroll-later">Enroll later</label><label class="assistant-choice"><input type="radio" name="backup_intent" value="absent">None</label><label class="assistant-choice"><input type="radio" name="backup_intent" value="deferred" checked>Decide later</label></div></div><div class="assistant-choice-group"><strong>Location</strong><div class="assistant-choice-options" role="radiogroup" aria-label="location setup intent"><label class="assistant-choice"><input type="radio" name="location_intent" value="auto" checked>Auto</label><label class="assistant-choice"><input type="radio" name="location_intent" value="manual">Manual</label><label class="assistant-choice"><input type="radio" name="location_intent" value="site-fallback">Site fallback</label><label class="assistant-choice"><input type="radio" name="location_intent" value="hidden">Hidden</label></div></div><div class="assistant-intent-note"><span>No secrets stored</span><span>Runtime facts stay separate</span></div></div></div><label class="assistant-confirm">"#,
    )
}

fn empty_state(can_onboard: bool) -> String {
    let action = if can_onboard {
        onboard_primary("Add first server")
    } else {
        String::new()
    };
    format!(
        r#"<section class="empty-state" aria-label="first run"><div class="empty-copy"><span class="empty-kicker">first light</span><h2>Waiting for the first host</h2><p>Register a host and Pharos will hold it in the grey awaiting state until the first real heartbeat arrives.</p>{action}</div><div class="empty-visual" aria-hidden="true"><span class="empty-sun"></span><span class="empty-line"></span><span class="empty-lighthouse">{lighthouse}</span><span class="empty-await">awaiting first heartbeat</span></div></section>"#,
        action = action,
        lighthouse = icons::LIGHTHOUSE
    )
}

fn lone_host_state(can_onboard: bool) -> String {
    let action = if can_onboard {
        onboard_primary("Add server")
    } else {
        String::new()
    };
    format!(
        r#"<aside class="lone-state" aria-label="lone host state"><span class="lone-mark">{lighthouse}</span><div class="lone-copy"><span class="lone-kicker">one light</span><strong>First host is on the map</strong><p>The fleet view is ready for the next onboarded machine.</p></div>{action}</aside>"#,
        lighthouse = icons::LIGHTHOUSE,
        action = action
    )
}

fn provisioning_job_host_name(job: &ProvisioningJob) -> Option<&str> {
    job.host_name
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
}

fn provisioning_job_role(job: &ProvisioningJob) -> &str {
    job.role
        .as_deref()
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .unwrap_or("server")
}

fn provisioning_job_visible_in_fleet(job: &ProvisioningJob) -> bool {
    matches!(
        job.state,
        ProvisioningJobState::Planning
            | ProvisioningJobState::Provisioning
            | ProvisioningJobState::Bootstrapping
            | ProvisioningJobState::WaitingForHeartbeat
            | ProvisioningJobState::BackupPending
    )
}

fn first_heartbeat_timeout_secs(job: &ProvisioningJob) -> i64 {
    let interval = i64::try_from(job.heartbeat_interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    (interval * 5).clamp(300, 1800)
}

fn provisioning_job_first_heartbeat_overdue(job: &ProvisioningJob, now: i64) -> bool {
    job.state == ProvisioningJobState::WaitingForHeartbeat
        && now.saturating_sub(job.updated_at) > first_heartbeat_timeout_secs(job)
}

fn provisioning_job_fleet_status(
    job: &ProvisioningJob,
    now: i64,
) -> (&'static str, &'static str, &'static str, u8, String) {
    if provisioning_job_first_heartbeat_overdue(job, now) {
        return (
            "stale",
            "warning",
            "warn",
            1,
            "first heartbeat overdue".to_string(),
        );
    }

    match job.state {
        ProvisioningJobState::Planning
        | ProvisioningJobState::Provisioning
        | ProvisioningJobState::Bootstrapping => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            format!("setup {}", job.state.label()),
        ),
        ProvisioningJobState::WaitingForHeartbeat => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            "waiting for first heartbeat".to_string(),
        ),
        ProvisioningJobState::BackupPending => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            "backup pending".to_string(),
        ),
        ProvisioningJobState::Complete => ("live", "clear", "ok", 4, "setup complete".to_string()),
        ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded => {
            ("down", "critical", "down", 0, job.state.label().to_string())
        }
    }
}

fn provisioning_job_setup_intent(job: &ProvisioningJob) -> ProvisioningSetupIntent {
    job.setup_intent.clone().unwrap_or(ProvisioningSetupIntent {
        backup: BackupSetupIntent::Deferred,
        location: LocationSetupIntent::Auto,
    })
}

fn provisioning_job_latest_message(job: &ProvisioningJob) -> String {
    job.progress
        .last()
        .map(|entry| entry.message.clone())
        .unwrap_or_else(|| "Setup job is waiting for progress.".to_string())
}

fn setup_intent_markup(intent: &ProvisioningSetupIntent) -> String {
    format!(
        r#"<div class="setup-intent"><span class="setup-chip backup">{backup}</span><span class="setup-chip location">{location}</span></div>"#,
        backup = html_escape(intent.backup_label()),
        location = html_escape(intent.location_label())
    )
}

fn setup_intent_search_text(intent: &ProvisioningSetupIntent) -> String {
    format!(
        "{} {} {} {}",
        intent.backup_label(),
        intent.backup_next_action(),
        intent.location_label(),
        intent.location_next_action()
    )
}

fn pending_setup_jobs<'a>(hosts: &[Host], jobs: &'a [ProvisioningJob]) -> Vec<&'a ProvisioningJob> {
    let runtime_names: BTreeSet<&str> = hosts.iter().map(|host| host.name.as_str()).collect();
    let mut latest_by_host: BTreeMap<&str, &ProvisioningJob> = BTreeMap::new();
    for job in jobs {
        let Some(host_name) = provisioning_job_host_name(job) else {
            continue;
        };
        if runtime_names.contains(host_name) || !provisioning_job_visible_in_fleet(job) {
            continue;
        }
        let replace = latest_by_host
            .get(host_name)
            .is_none_or(|existing| job.updated_at >= existing.updated_at);
        if replace {
            latest_by_host.insert(host_name, job);
        }
    }
    let mut jobs: Vec<&ProvisioningJob> = latest_by_host.into_values().collect();
    jobs.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| provisioning_job_host_name(left).cmp(&provisioning_job_host_name(right)))
    });
    jobs
}

fn render_setup_card(job: &ProvisioningJob, now: i64) -> String {
    let Some(raw_name) = provisioning_job_host_name(job) else {
        return String::new();
    };
    let name = html_escape(raw_name);
    let role = html_escape(provisioning_job_role(job));
    let is_nix = job.is_nix.unwrap_or(false);
    let host_icon = if is_nix {
        icons::SNOWFLAKE
    } else {
        icons::SERVER
    };
    let (live_key, level, reason_level, sev, reason) = provisioning_job_fleet_status(job, now);
    let intent = provisioning_job_setup_intent(job);
    let intent_markup = setup_intent_markup(&intent);
    let search = html_escape(&format!(
        "{} {} setup provisioning {} {} {}",
        raw_name.to_lowercase(),
        provisioning_job_role(job).to_lowercase(),
        reason.to_lowercase(),
        job.state.label(),
        setup_intent_search_text(&intent).to_lowercase()
    ));
    let detail = if provisioning_job_first_heartbeat_overdue(job, now) {
        format!(
            "No first heartbeat after {}. Check beacon install, network, and host power.",
            duration_label(now.saturating_sub(job.updated_at))
        )
    } else {
        provisioning_job_latest_message(job)
    };
    let started = format!("setup started {} ago", duration_label(now - job.created_at));
    format!(
        r#"<article class="card setup-card" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{updated_at}" data-search="{search}" data-host-surface="setup" data-setup-level="{level}"><header class="card-head"><div class="host"><span class="nix">{host_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div><div class="card-actions"><a class="settings-card" href="/?setup=add-server" title="Continue setup for {name}" aria-label="Continue setup for {name}"><span class="settings-icon">{settings}</span></a></div></header><div class="reason {reason_level}" data-reason><span>{reason}</span></div>{intent_markup}<div class="setup-detail">{detail}</div><div class="meta"><span>{started}</span><span>as of {as_of}</span></div><div class="card-tools"><a class="setup-action" href="/?setup=add-server">Continue setup</a></div></article>"#,
        sort_name = html_escape(&raw_name.to_lowercase()),
        updated_at = job.updated_at,
        settings = icons::SLIDERS,
        reason = html_escape(&reason),
        detail = html_escape(&detail),
        started = html_escape(&started),
        as_of = clock_label(now)
    )
}

fn render_setup_row(job: &ProvisioningJob, now: i64) -> String {
    let Some(raw_name) = provisioning_job_host_name(job) else {
        return String::new();
    };
    let name = html_escape(raw_name);
    let role = html_escape(provisioning_job_role(job));
    let is_nix = job.is_nix.unwrap_or(false);
    let host_icon = if is_nix {
        icons::SNOWFLAKE
    } else {
        icons::SERVER
    };
    let (live_key, level, reason_level, sev, reason) = provisioning_job_fleet_status(job, now);
    let intent = provisioning_job_setup_intent(job);
    let search = html_escape(&format!(
        "{} {} setup provisioning {} {} {}",
        raw_name.to_lowercase(),
        provisioning_job_role(job).to_lowercase(),
        reason.to_lowercase(),
        job.state.label(),
        setup_intent_search_text(&intent).to_lowercase()
    ));
    let started = format!("setup started {} ago", duration_label(now - job.created_at));
    let status_icon = status_icon_stack();
    format!(
        r#"<tr class="setup-row" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{updated_at}" data-search="{search}" data-host-surface="setup" data-setup-level="{level}"><td><div class="host"><span class="nix">{host_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div></td><td><span class="status-pill" aria-label="status: {reason}">{status_icon}<span class="word" data-status-word>{reason}</span></span></td><td><div class="reason {reason_level}" data-reason><span>{reason}</span></div></td><td><span class="setup-chip backup">{backup}</span></td><td><span class="setup-chip location">{location}</span></td><td><span>{started}</span></td><td><span>{job_state}</span></td><td><a class="setup-action" href="/?setup=add-server">Continue</a></td></tr>"#,
        sort_name = html_escape(&raw_name.to_lowercase()),
        updated_at = job.updated_at,
        reason = html_escape(&reason),
        backup = html_escape(intent.backup_label()),
        location = html_escape(intent.location_label()),
        started = html_escape(&started),
        job_state = html_escape(job.state.label())
    )
}

fn heartbeat_samples(log: &[i64], last_seen: Option<i64>) -> Vec<i64> {
    let mut samples = log.to_vec();
    if samples.is_empty() {
        if let Some(last) = last_seen {
            samples.push(last);
        }
    }
    samples.sort_unstable();
    samples.dedup();
    samples
}

struct HeartbeatSignal {
    text: String,
    level: &'static str,
    window: &'static str,
    title: String,
}

fn heartbeat_signal(
    log: &[i64],
    last_seen: Option<i64>,
    interval: i64,
    now: i64,
    window_label: &'static str,
    window_secs: i64,
) -> HeartbeatSignal {
    let samples = heartbeat_samples(log, last_seen);
    if samples.is_empty() {
        return HeartbeatSignal {
            text: "new".to_string(),
            level: "wait",
            window: window_label,
            title: format!("Signal over {window_label}: waiting for first heartbeat"),
        };
    };

    let interval = interval.max(1);
    let window_secs = window_secs.max(interval);
    let requested_start = now - window_secs;
    let retained_start = samples
        .first()
        .copied()
        .map(|oldest| oldest.max(requested_start))
        .unwrap_or(requested_start);
    let span = (now - retained_start).max(interval).min(window_secs);
    let expected = ((span + interval - 1) / interval).max(1) as usize;
    let received = samples
        .iter()
        .filter(|stamp| **stamp >= retained_start && **stamp <= now)
        .count();
    let mut previous = retained_start;
    let mut longest_gap = samples
        .last()
        .copied()
        .map(|latest| (now - latest).max(0).min(span))
        .unwrap_or(span);
    for stamp in samples
        .iter()
        .copied()
        .filter(|stamp| *stamp >= retained_start && *stamp <= now)
    {
        longest_gap = longest_gap.max(stamp - previous);
        previous = stamp;
    }
    longest_gap = longest_gap.max(now - previous);

    let percent = (((received * 100) + (expected / 2)) / expected).min(100);
    let level = if percent >= 95 {
        "good"
    } else if percent >= 75 {
        "warn"
    } else {
        "down"
    };
    HeartbeatSignal {
        text: format!("{percent}%"),
        level,
        window: window_label,
        title: format!(
            "Signal over {window_label}: {received} of {expected} expected heartbeats received · longest gap {}{}",
            duration_label(longest_gap),
            if retained_start > requested_start {
                format!(" · retained {}", duration_label(span))
            } else {
                String::new()
            }
        ),
    }
}

fn signal_markup(signal: &HeartbeatSignal) -> String {
    let title = html_escape(&signal.title);
    format!(
        r#"<span class="signal" data-signal data-signal-level="{level}" data-signal-window-key="{window}" title="{title}" aria-label="{title}"><span data-signal-percent>{text}</span><span class="signal-orb" aria-hidden="true"></span><button class="signal-window" type="button" data-signal-window title="{title}">{window}</button></span>"#,
        level = html_escape(signal.level),
        text = html_escape(&signal.text),
        window = html_escape(signal.window),
    )
}

fn head_with_extra(extra: &str) -> String {
    HEAD.replacen("</style></head>", &format!("</style>{extra}</head>"), 1)
}

const LOCATION_STALE_AFTER_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq)]
struct SiteLocation {
    id: String,
    label: String,
    region: String,
    lat: f64,
    lon: f64,
    source: HostLocationSource,
    mode: &'static str,
    state: &'static str,
    stale: bool,
    manual_override: bool,
    observed_at: Option<i64>,
    accuracy_meters: Option<f64>,
    precision_meters: Option<f64>,
}

impl SiteLocation {
    fn from_site(site: &str, source: HostLocationSource) -> Self {
        let (id, label, region, lat, lon) = match site {
            "cloud" | "cloud-de" => ("cloud-de", "Cloud", "Germany", 50.1109, 8.6821),
            "home" | "home-at" => ("home-at", "Home", "Austria", 48.2082, 16.3738),
            "ww87" | "parents-home" => ("ww87", "Parents' home", "Austria", 48.32, 15.92),
            "parents-in-law" => ("parents-in-law", "Parents-in-law", "Austria", 48.13, 15.18),
            "dsc" | "dsc0" | "dsc-us" | "hillsboro-or" => {
                ("dsc-us", "DSC", "Hillsboro, OR, US", 45.5229, -122.9898)
            }
            _ => ("unknown", "Unknown site", "Not declared", 46.8, 8.2),
        };
        Self {
            id: id.to_string(),
            label: label.to_string(),
            region: region.to_string(),
            lat,
            lon,
            source,
            mode: "auto",
            state: if id == "unknown" { "unknown" } else { "known" },
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }

    fn from_host_location(
        location: &HostLocation,
        fallback_label: impl Into<String>,
        fallback_region: impl Into<String>,
        mode: &'static str,
        state: &'static str,
        now: i64,
    ) -> Self {
        let stale = location_stale(location, now);
        let label = location
            .label
            .clone()
            .unwrap_or_else(|| fallback_label.into());
        let region = fallback_region.into();
        let id = format!(
            "{}:{:.4},{:.4}",
            location_source_key(location.source),
            location.latitude,
            location.longitude
        );
        Self {
            id,
            label,
            region,
            lat: location.latitude,
            lon: location.longitude,
            source: location.source,
            mode,
            state: if stale { "stale" } else { state },
            stale,
            manual_override: location.manual_override,
            observed_at: location.observed_at,
            accuracy_meters: location.accuracy_meters,
            precision_meters: location.precision_meters,
        }
    }

    fn hidden() -> Self {
        Self {
            id: "hidden".to_string(),
            label: "Location hidden".to_string(),
            region: "Not shown".to_string(),
            lat: 46.8,
            lon: 8.2,
            source: HostLocationSource::Unknown,
            mode: "hidden",
            state: "hidden",
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapProbeTarget {
    endpoint: Option<(String, u16)>,
    kind: &'static str,
    policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct MapSignal {
    label: String,
    level: &'static str,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
struct MapHost {
    name: String,
    role: String,
    live: &'static str,
    status: &'static str,
    attention: String,
    search: String,
    site_id: String,
    site_label: String,
    region: String,
    lat: f64,
    lon: f64,
    location_source: &'static str,
    location_state: &'static str,
    location_stale: bool,
    location_manual_override: bool,
    location: serde_json::Value,
    is_pharos: bool,
    inbound_label: String,
    inbound_level: &'static str,
    inbound_title: String,
    outbound_label: String,
    outbound_level: &'static str,
    outbound_title: String,
    outbound_policy: &'static str,
    settings_href: String,
}

#[derive(Debug, Clone, Serialize)]
struct MapDataPayload {
    schema: &'static str,
    as_of: i64,
    hosts: Vec<MapHost>,
}

fn site_location(site: &str) -> SiteLocation {
    SiteLocation::from_site(site, HostLocationSource::Provider)
}

fn fallback_site_location(host: &str) -> SiteLocation {
    SiteLocation::from_site(fallback_site_for_host(host), HostLocationSource::Fallback)
}

fn location_source_key(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

fn location_source_label(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi | HostLocationSource::Ip => "auto",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

fn location_stale(location: &HostLocation, now: i64) -> bool {
    if location.stale {
        return true;
    }
    location
        .observed_at
        .is_some_and(|observed| now.saturating_sub(observed) > LOCATION_STALE_AFTER_SECS)
}

fn location_payload(location: &SiteLocation) -> serde_json::Value {
    json!({
        "latitude": location.lat,
        "longitude": location.lon,
        "source": location_source_key(location.source),
        "mode": location.mode,
        "state": location.state,
        "stale": location.stale,
        "manual_override": location.manual_override,
        "observed_at": location.observed_at,
        "accuracy_meters": location.accuracy_meters,
        "precision_meters": location.precision_meters,
        "label": location.label,
        "region": location.region,
        "site_id": location.id,
    })
}

fn resolve_host_location(
    host: Option<&Host>,
    manifest: Option<&HostManifest>,
    host_name: &str,
    now: i64,
) -> SiteLocation {
    let mode = manifest
        .map(|manifest| manifest.host.location_mode)
        .unwrap_or_default();
    if mode == ManifestLocationMode::Hidden {
        return SiteLocation::hidden();
    }

    let provider = manifest
        .and_then(|manifest| {
            manifest
                .host
                .site
                .as_deref()
                .filter(|site| !site.trim().is_empty())
        })
        .map(site_location);

    let declared_location = manifest.and_then(|manifest| manifest.host.location.as_ref());

    if let Some(location) = declared_location.filter(|location| {
        mode == ManifestLocationMode::DeclaredOverride
            || (mode == ManifestLocationMode::Auto && location.manual_override)
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-override",
            "declared",
            now,
        );
    }

    if let Some(location) = host.and_then(|host| host.location.as_ref()) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "observed",
            "observed",
            now,
        );
    }

    if let Some(location) = declared_location.filter(|_| {
        matches!(
            mode,
            ManifestLocationMode::DeclaredFallback | ManifestLocationMode::Auto
        )
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-fallback",
            "declared",
            now,
        );
    }

    provider.unwrap_or_else(|| fallback_site_location(host_name))
}

fn fallback_site_for_host(host: &str) -> &'static str {
    match host {
        "csb0" | "csb1" => "cloud-de",
        "hsb0" | "hsb1" | "gpc0" => "home-at",
        "hsb8" => "ww87",
        "hsb9" => "parents-in-law",
        "dsc0" => "dsc-us",
        _ => "unknown",
    }
}

fn manifest_by_host(manifests: &[HostManifest]) -> BTreeMap<&str, &HostManifest> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        by_host.insert(manifest.host.name.as_str(), manifest);
        by_host.insert(manifest.slug.as_str(), manifest);
    }
    by_host
}

fn split_probe_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(trimmed) {
        let host = url.host_str()?.trim().to_string();
        if host.is_empty() {
            return None;
        }
        return Some((host, url.port_or_known_default().unwrap_or(default_port)));
    }
    let target = trimmed
        .trim_start_matches("//")
        .split('/')
        .next()
        .unwrap_or(trimmed)
        .trim();
    if target.is_empty() {
        return None;
    }
    if let Some((host, port)) = target.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
    }
    Some((target.to_string(), default_port))
}

fn normalize_outbound_policy(policy: &str) -> Option<&'static str> {
    match policy.trim().to_ascii_lowercase().as_str() {
        "expected" | "reachable" | "allow" | "allowed" | "required" => Some("expected"),
        "blocked" | "deny" | "denied" | "intentional-block" | "intentional_block" => {
            Some("blocked")
        }
        "unknown" | "probe" | "best-effort" | "best_effort" => Some("unknown"),
        _ => None,
    }
}

fn manifest_outbound_policy(host: &str, manifests: &[HostManifest]) -> Option<&'static str> {
    let manifests = manifest_by_host(manifests);
    let manifest = manifests.get(host)?;
    [
        "pharosOutbound",
        "pharosOutboundPolicy",
        "pharosConnectivity",
    ]
    .into_iter()
    .find_map(|key| manifest.host.access.get(key))
    .and_then(|value| normalize_outbound_policy(value))
}

fn outbound_policy_for_host(host: &Host, manifests: &[HostManifest]) -> &'static str {
    manifest_outbound_policy(&host.name, manifests).unwrap_or("unknown")
}

fn map_probe_target(host: &Host, manifests: &[HostManifest]) -> MapProbeTarget {
    let policy = outbound_policy_for_host(host, manifests);
    if policy == "blocked" {
        return MapProbeTarget {
            endpoint: None,
            kind: "tailnet ssh",
            policy,
        };
    }
    let manifests = manifest_by_host(manifests);
    if let Some(manifest) = manifests.get(host.name.as_str()) {
        if let Some(tailnet) = manifest.host.tailnet_hostname() {
            if let Some((host, port)) = split_probe_host_port(tailnet, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "tailnet ssh",
                    policy,
                };
            }
        }
        if let Some(lan) = manifest.host.lan_hostname() {
            if let Some((host, port)) = split_probe_host_port(lan, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
        if let Some(ip) = manifest.host.lan_ip() {
            if let Some((host, port)) = split_probe_host_port(ip, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
    }
    MapProbeTarget {
        endpoint: Some((format!("{}.ts.barta.cm", host.name), 2222)),
        kind: "tailnet ssh",
        policy,
    }
}

fn default_map_signal() -> MapSignal {
    MapSignal {
        label: "checking".to_string(),
        level: "wait",
        title: "Pharos reachability check is pending".to_string(),
        policy: None,
    }
}

async fn map_connectivity_probe(target: MapProbeTarget) -> MapSignal {
    let Some((host, port)) = target.endpoint else {
        return MapSignal {
            label: if target.policy == "blocked" {
                "blocked".to_string()
            } else {
                "unknown".to_string()
            },
            level: "wait",
            title: if target.policy == "blocked" {
                "Outbound access from Pharos is blocked by policy".to_string()
            } else {
                "No outbound probe endpoint declared".to_string()
            },
            policy: Some(target.policy),
        };
    };
    let started = Instant::now();
    match timeout(
        SERVER_PROBE_TIMEOUT,
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => {
            let elapsed_ms = started.elapsed().as_millis().max(1);
            MapSignal {
                label: format!("{elapsed_ms} ms"),
                level: "good",
                title: format!(
                    "Pharos {kind} check to {host}:{port} reachable in {elapsed_ms} ms",
                    kind = target.kind,
                    host = host,
                    port = port
                ),
                policy: Some(target.policy),
            }
        }
        Ok(Err(_)) => MapSignal {
            label: "no route".to_string(),
            level: if target.policy == "expected" {
                "down"
            } else {
                "warn"
            },
            title: format!(
                "Pharos {kind} check to {host}:{port} failed",
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
        Err(_) => MapSignal {
            label: "timeout".to_string(),
            level: "warn",
            title: format!(
                "Pharos {kind} check to {host}:{port} timed out after {} ms",
                SERVER_PROBE_TIMEOUT.as_millis(),
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
    }
}

async fn map_connectivity_probes(
    hosts: &[Host],
    manifests: &[HostManifest],
) -> BTreeMap<String, MapSignal> {
    let mut jobs = JoinSet::new();
    for host in hosts {
        let name = host.name.clone();
        let target = map_probe_target(host, manifests);
        jobs.spawn(async move { (name, map_connectivity_probe(target).await) });
    }
    let mut probes = BTreeMap::new();
    while let Some(result) = jobs.join_next().await {
        if let Ok((name, probe)) = result {
            probes.insert(name, probe);
        }
    }
    probes
}

fn map_inbound_signal(host: &Host, is_pharos: bool, now: i64) -> MapSignal {
    if is_pharos {
        return MapSignal {
            label: "local".to_string(),
            level: "good",
            title: "Pharos is the local control host".to_string(),
            policy: None,
        };
    }
    if let Some(rtt) = host.inbound_rtt {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        let level = match live {
            Liveness::Live => {
                if rtt.millis <= 500 {
                    "good"
                } else {
                    "warn"
                }
            }
            Liveness::Stale => "warn",
            Liveness::Down => "down",
            Liveness::AwaitingFirstHeartbeat => "wait",
        };
        let observed_age = (now - rtt.observed_at).max(0);
        return MapSignal {
            label: format!("{} ms", rtt.millis),
            level,
            title: format!(
                "Host-to-Pharos report submit RTT from {} was {} ms, observed {} ago",
                host.name,
                rtt.millis,
                duration_label(observed_age)
            ),
            policy: None,
        };
    }
    let Some(last_seen) = host.last_seen else {
        return MapSignal {
            label: "waiting".to_string(),
            level: "wait",
            title: "No heartbeat from this host has reached Pharos yet".to_string(),
            policy: None,
        };
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    let level = match live {
        Liveness::Live => "good",
        Liveness::Stale => "warn",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "wait",
    };
    let age = (now - last_seen).max(0);
    MapSignal {
        label: format!("beat {}", duration_label(age)),
        level,
        title: format!(
            "No measured inbound RTT yet; last heartbeat from {} reached Pharos {} ago",
            host.name,
            duration_label(age)
        ),
        policy: None,
    }
}

fn map_hosts(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
) -> Vec<MapHost> {
    let manifests = manifest_by_host(manifests);
    let mut mapped = hosts
        .iter()
        .map(|host| {
            let is_pharos = host.name == self_name;
            let mut live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
            if is_pharos {
                live = Liveness::Live;
            }
            let (_color, status) = live.badge();
            let attention = if host.name == self_name {
                self_attention_reason()
            } else {
                attention_reason(live, &host.freshness, &host.service_observations)
            };
            let site = resolve_host_location(
                Some(host),
                manifests.get(host.name.as_str()).copied(),
                &host.name,
                now,
            );
            let inbound = map_inbound_signal(host, is_pharos, now);
            let outbound = probes
                .get(&host.name)
                .cloned()
                .unwrap_or_else(default_map_signal);
            let search = format!(
                "{} {} {} {} {} {} {} {} {} {}",
                host.name,
                host.role,
                status,
                attention.label,
                site.label,
                site.region,
                location_source_key(site.source),
                location_source_label(site.source),
                inbound.label,
                outbound.label
            )
            .to_lowercase();
            let location = location_payload(&site);
            MapHost {
                name: host.name.clone(),
                role: host.role.clone(),
                live: live_key(live),
                status,
                attention: attention.label,
                search,
                site_id: site.id,
                site_label: site.label,
                region: site.region,
                lat: site.lat,
                lon: site.lon,
                location_source: location_source_key(site.source),
                location_state: site.state,
                location_stale: site.stale,
                location_manual_override: site.manual_override,
                location,
                is_pharos,
                inbound_label: inbound.label,
                inbound_level: inbound.level,
                inbound_title: inbound.title,
                outbound_label: outbound.label,
                outbound_level: outbound.level,
                outbound_title: outbound.title,
                outbound_policy: outbound.policy.unwrap_or("unknown"),
                settings_href: format!("/agora?host={}", url_query_escape(&host.name)),
            }
        })
        .collect::<Vec<_>>();
    mapped.sort_by(|a, b| {
        a.site_label
            .cmp(&b.site_label)
            .then_with(|| a.name.cmp(&b.name))
    });
    mapped
}

fn map_data_payload(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
) -> MapDataPayload {
    MapDataPayload {
        schema: "inspr.pharos.map-data.v1",
        as_of: now,
        hosts: map_hosts(hosts, self_name, now, manifests, probes),
    }
}

#[derive(Debug, Clone)]
struct AlertItem {
    level: &'static str,
    host: String,
    role: String,
    issue: String,
    detail: String,
    source: &'static str,
    seen: String,
    next_action: String,
    sort_time: i64,
}

#[derive(Debug, Clone)]
struct AlertGroup {
    level: &'static str,
    hosts: Vec<(String, String)>,
    issue: String,
    detail: String,
    source: &'static str,
    seen: String,
    next_action: String,
    sort_time: i64,
    count: usize,
}

#[derive(Debug, Clone)]
struct ActivityEvent {
    timestamp: i64,
    host: String,
    level: &'static str,
    kind: &'static str,
    title: String,
    detail: String,
    source: &'static str,
}

impl ActivityEvent {
    fn new(
        timestamp: i64,
        host: impl Into<String>,
        level: &'static str,
        kind: &'static str,
        title: impl Into<String>,
        detail: impl Into<String>,
        source: &'static str,
    ) -> Self {
        Self {
            timestamp,
            host: host.into(),
            level,
            kind,
            title: title.into(),
            detail: detail.into(),
            source,
        }
    }
}

fn level_rank(level: &str) -> usize {
    match level {
        "critical" => 0,
        "warning" => 1,
        "watch" => 2,
        "recovery" => 3,
        "info" => 4,
        "clear" => 5,
        _ => 6,
    }
}

fn level_label(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "warning" => "warning",
        "watch" => "watch",
        "recovery" => "recovery",
        "info" => "info",
        "clear" => "clear",
        _ => "info",
    }
}

fn seen_label(last_seen: Option<i64>, now: i64) -> String {
    match last_seen {
        Some(seen) => format!("{} ago", duration_label(now - seen)),
        None => "never".to_string(),
    }
}

fn freshness_alert(freshness: &NixFreshness) -> Option<(&'static str, String, String)> {
    if !freshness.applicable {
        return None;
    }

    let age = freshness.flake_lock_age_days;
    let commits = freshness.commits_behind;
    if age.is_none() || commits.is_none() {
        return Some((
            "watch",
            "Freshness is only partially observed".to_string(),
            "Confirm the beacon can read nixcfg freshness.".to_string(),
        ));
    }

    let days = age.unwrap_or(0);
    let behind = commits.unwrap_or(0);
    if behind > 0 || days >= 30 {
        return Some((
            "warning",
            freshness.tldr(),
            "Review nixcfg, then update or deploy when safe.".to_string(),
        ));
    }
    if days > 0 {
        return Some((
            "watch",
            freshness.tldr(),
            "Consider a normal flake update during the next maintenance window.".to_string(),
        ));
    }
    None
}

fn service_alert(host: &Host, observation: &ServiceObservation, now: i64) -> Option<AlertItem> {
    if is_nix_freshness_observation(observation) {
        return None;
    }

    let (level, action) = match observation.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning => ("warning", "Inspect the service on the host."),
        ServiceObservationState::Stale => ("warning", "Verify the service is still reporting."),
        ServiceObservationState::Unknown => {
            ("watch", "Confirm whether this service should report state.")
        }
    };
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!("{}: {}", observation.label, observation.state.label()),
        detail: observation.summary.clone(),
        source: "service",
        seen: seen_label(host.last_seen, now),
        next_action: action.to_string(),
        sort_time: host.last_seen.unwrap_or(now),
    })
}

fn backup_sort_time(host: &Host, observation: &BackupObservation, now: i64) -> i64 {
    observation
        .last_attempt_at
        .or(observation.last_success_at)
        .or(observation.last_check_at)
        .or(host.last_seen)
        .unwrap_or(now)
}

fn backup_alert(host: &Host, observation: &BackupObservation, now: i64) -> Option<AlertItem> {
    let (level, action) = match observation.state {
        BackupPostureState::Healthy => return None,
        BackupPostureState::Failed => (
            "critical",
            "Inspect the backup job, fix the failure, then confirm the next successful run.",
        ),
        BackupPostureState::Missing => (
            "critical",
            "Restore or declare the expected backup job for this host.",
        ),
        BackupPostureState::Stale => (
            "warning",
            "Confirm the backup schedule, runner, and latest successful snapshot.",
        ),
        BackupPostureState::Warning => (
            "warning",
            "Review backup evidence and schedule before the next maintenance window.",
        ),
        BackupPostureState::Unknown => (
            "watch",
            "Confirm the backup collector can observe this job.",
        ),
        BackupPostureState::NotConfigured => (
            "watch",
            "Decide whether this host should be protected or intentionally unprotected.",
        ),
    };
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!(
            "{}: {}",
            observation.label,
            backup_state_label(observation.state)
        ),
        detail: observation.summary.clone(),
        source: "backup",
        seen: format!(
            "{} ago",
            duration_label((now - backup_sort_time(host, observation, now)).max(0))
        ),
        next_action: action.to_string(),
        sort_time: backup_sort_time(host, observation, now),
    })
}

fn backup_validation_alert(
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) -> Option<AlertItem> {
    let restore = observation.restore_validation.as_ref();
    let (state, checked_at, label, detail) = if let Some(restore) = restore {
        (
            restore.state,
            restore.checked_at,
            restore
                .evidence_label
                .as_deref()
                .unwrap_or_else(|| backup_validation_level_label(restore.level))
                .to_string(),
            restore
                .summary
                .clone()
                .unwrap_or_else(|| backup_validation_label(observation, now)),
        )
    } else {
        let state = observation.last_check_state?;
        (
            state,
            observation.last_check_at,
            "backup check".to_string(),
            backup_validation_label(observation, now),
        )
    };

    let (level, issue, action) = match state {
        pharos_core::BackupValidationState::Failed => (
            "critical",
            "Restore validation failed",
            "Inspect validation evidence and run a clean restore or repository check.",
        ),
        pharos_core::BackupValidationState::Stale => (
            "warning",
            "Restore validation overdue",
            "Run a restore validation or repository check and let Pharos observe it.",
        ),
        pharos_core::BackupValidationState::Passed
        | pharos_core::BackupValidationState::Unknown => return None,
    };

    let sort_time = checked_at.unwrap_or_else(|| backup_sort_time(host, observation, now));
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!("{}: {}", observation.label, issue),
        detail: label + " - " + &detail,
        source: "backup",
        seen: format!("{} ago", duration_label((now - sort_time).max(0))),
        next_action: action.to_string(),
        sort_time,
    })
}

fn is_nix_freshness_observation(observation: &ServiceObservation) -> bool {
    observation.id == "nix-freshness" || observation.label.eq_ignore_ascii_case("Nix freshness")
}

fn probe_alert(host: &str, role: &str, probe: &ServerProbeObservation) -> Option<AlertItem> {
    let (level, action) = match probe.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning => (
            "warning",
            "Check the service route, firewall, or probe target.",
        ),
        ServiceObservationState::Stale => ("warning", "Re-check the service probe path."),
        ServiceObservationState::Unknown => ("watch", "Complete the service probe declaration."),
    };
    Some(AlertItem {
        level,
        host: host.to_string(),
        role: role.to_string(),
        issue: format!("{} probe {}", probe.service, probe.state.label()),
        detail: probe.summary.clone(),
        source: "probe",
        seen: format!("as of {}", clock_label(probe.checked_at)),
        next_action: action.to_string(),
        sort_time: probe.checked_at,
    })
}

fn provisioning_job_alert(
    job: &ProvisioningJob,
    runtime_names: &BTreeSet<&str>,
    now: i64,
) -> Option<AlertItem> {
    let host = provisioning_job_host_name(job)?;
    if runtime_names.contains(host) && !matches!(job.state, ProvisioningJobState::BackupPending) {
        return None;
    }

    let latest = provisioning_job_latest_message(job);
    let (level, issue, detail, action) = match job.state {
        ProvisioningJobState::Planning
        | ProvisioningJobState::Provisioning
        | ProvisioningJobState::Bootstrapping => (
            "watch",
            "Setup in progress",
            latest,
            "Continue setup and wait for the first valid beacon heartbeat.",
        ),
        ProvisioningJobState::WaitingForHeartbeat => {
            if provisioning_job_first_heartbeat_overdue(job, now) {
                (
                    "warning",
                    "First heartbeat overdue",
                    format!(
                        "No first heartbeat after {}.",
                        duration_label(now.saturating_sub(job.updated_at))
                    ),
                    "Check beacon install, network, and host power.",
                )
            } else {
                (
                    "watch",
                    "Waiting for first heartbeat",
                    latest,
                    "Finish the beacon handoff and keep onboarding open.",
                )
            }
        }
        ProvisioningJobState::BackupPending => (
            "watch",
            "Backup enrollment pending",
            latest,
            "Record backup posture or wait for the first backup observation.",
        ),
        ProvisioningJobState::Failed => (
            "critical",
            "Setup failed",
            latest,
            "Open the setup assistant, correct the blocker, and retry.",
        ),
        ProvisioningJobState::CleanupNeeded => (
            "critical",
            "Setup cleanup needed",
            latest,
            "Review provider state before retrying or removing the job.",
        ),
        ProvisioningJobState::Complete => return None,
    };

    Some(AlertItem {
        level,
        host: host.to_string(),
        role: provisioning_job_role(job).to_string(),
        issue: issue.to_string(),
        detail,
        source: "setup",
        seen: format!("as of {}", clock_label(job.updated_at)),
        next_action: action.to_string(),
        sort_time: job.updated_at,
    })
}

fn alert_items(
    hosts: &[Host],
    jobs: &[ProvisioningJob],
    _self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
) -> Vec<AlertItem> {
    let mut alerts = Vec::new();
    let runtime_by_name: BTreeMap<&str, &Host> = hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let runtime_names: BTreeSet<&str> = runtime_by_name.keys().copied().collect();
    let manifest_roles: BTreeMap<&str, &str> = manifests
        .iter()
        .map(|manifest| {
            (
                manifest.host.name.as_str(),
                manifest.host.role.as_deref().unwrap_or("declared host"),
            )
        })
        .collect();

    for issue in load_errors {
        alerts.push(AlertItem {
            level: "critical",
            host: "Pharos".to_string(),
            role: "manifest loader".to_string(),
            issue: "Declared host manifest failed to load".to_string(),
            detail: format!("{} - {}", issue.path, issue.error),
            source: "config",
            seen: format!("as of {}", clock_label(now)),
            next_action: "Fix the manifest and restart or reload Pharos.".to_string(),
            sort_time: now,
        });
    }

    for manifest in manifests {
        let runtime = runtime_by_name
            .get(manifest.host.name.as_str())
            .copied()
            .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
        if runtime.is_none() {
            alerts.push(AlertItem {
                level: "watch",
                host: manifest.host.name.clone(),
                role: manifest
                    .host
                    .role
                    .clone()
                    .unwrap_or_else(|| "declared host".to_string()),
                issue: "Declared host has not reported yet".to_string(),
                detail:
                    "The host exists in declared metadata, but no runtime heartbeat is present."
                        .to_string(),
                source: "config",
                seen: "never".to_string(),
                next_action: "Install or start pharos-beacon, or remove stale metadata."
                    .to_string(),
                sort_time: now,
            });
        }
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        match live {
            Liveness::Down => alerts.push(AlertItem {
                level: "critical",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "No heartbeat received".to_string(),
                detail: "Pharos has not received a report within the allowed heartbeat window."
                    .to_string(),
                source: "heartbeat",
                seen: seen_label(host.last_seen, now),
                next_action: "Check host power, network, and pharos-beacon.".to_string(),
                sort_time: host.last_seen.unwrap_or(now),
            }),
            Liveness::Stale => alerts.push(AlertItem {
                level: "warning",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Heartbeat is late".to_string(),
                detail: "The host checked in later than its normal cadence.".to_string(),
                source: "heartbeat",
                seen: seen_label(host.last_seen, now),
                next_action: "Verify pharos-beacon and recent host load.".to_string(),
                sort_time: host.last_seen.unwrap_or(now),
            }),
            Liveness::AwaitingFirstHeartbeat => alerts.push(AlertItem {
                level: "watch",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Waiting for first heartbeat".to_string(),
                detail: "The host is registered but has not sent a first report.".to_string(),
                source: "heartbeat",
                seen: "never".to_string(),
                next_action: "Finish onboarding or confirm the host should exist.".to_string(),
                sort_time: now,
            }),
            Liveness::Live => {}
        }

        if let Some((level, issue, action)) = freshness_alert(&host.freshness) {
            alerts.push(AlertItem {
                level,
                host: host.name.clone(),
                role: host.role.clone(),
                issue,
                detail: "Nix freshness differs from the preferred declared state.".to_string(),
                source: "freshness",
                seen: seen_label(host.last_seen, now),
                next_action: action,
                sort_time: host.last_seen.unwrap_or(now),
            });
        }

        for observation in &host.service_observations {
            if let Some(alert) = service_alert(host, observation, now) {
                alerts.push(alert);
            }
        }

        for observation in &host.backup_observations {
            if let Some(alert) = backup_alert(host, observation, now) {
                alerts.push(alert);
            }
            if let Some(alert) = backup_validation_alert(host, observation, now) {
                alerts.push(alert);
            }
        }

        if let Some(alert) = protection_onboarding_alert(host, jobs, now) {
            alerts.push(alert);
        }
    }

    for job in jobs {
        if let Some(alert) = provisioning_job_alert(job, &runtime_names, now) {
            alerts.push(alert);
        }
    }

    for (host, probes) in server_probes {
        let role = runtime_by_name
            .get(host.as_str())
            .map(|host| host.role.as_str())
            .or_else(|| manifest_roles.get(host.as_str()).copied())
            .unwrap_or("declared service");
        for probe in probes {
            if let Some(alert) = probe_alert(host, role, probe) {
                alerts.push(alert);
            }
        }
    }

    alerts.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.source.cmp(right.source))
    });
    alerts
}

fn alert_counts(alerts: &[AlertItem], hosts: &[Host]) -> (usize, usize, usize, usize) {
    let critical = alerts
        .iter()
        .filter(|alert| alert.level == "critical")
        .count();
    let warning = alerts
        .iter()
        .filter(|alert| alert.level == "warning")
        .count();
    let watch = alerts.iter().filter(|alert| alert.level == "watch").count();
    let affected: std::collections::BTreeSet<&str> = alerts
        .iter()
        .filter(|alert| alert.host != "Pharos")
        .map(|alert| alert.host.as_str())
        .collect();
    let clear = hosts.len().saturating_sub(affected.len());
    (critical, warning, watch, clear)
}

fn alert_groups(alerts: &[AlertItem]) -> Vec<AlertGroup> {
    let mut groups: Vec<AlertGroup> = Vec::new();

    for alert in alerts {
        if let Some(group) = groups.iter_mut().find(|group| {
            group.level == alert.level
                && group.source == alert.source
                && group.issue == alert.issue
                && group.detail == alert.detail
                && group.next_action == alert.next_action
        }) {
            group.count += 1;
            if !group.hosts.iter().any(|(host, _)| host == &alert.host) {
                group.hosts.push((alert.host.clone(), alert.role.clone()));
            }
            if alert.sort_time >= group.sort_time {
                group.sort_time = alert.sort_time;
                group.seen = alert.seen.clone();
            }
        } else {
            groups.push(AlertGroup {
                level: alert.level,
                hosts: vec![(alert.host.clone(), alert.role.clone())],
                issue: alert.issue.clone(),
                detail: alert.detail.clone(),
                source: alert.source,
                seen: alert.seen.clone(),
                next_action: alert.next_action.clone(),
                sort_time: alert.sort_time,
                count: 1,
            });
        }
    }

    for group in &mut groups {
        group.hosts.sort_by(|left, right| left.0.cmp(&right.0));
    }
    groups.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.issue.cmp(&right.issue))
            .then_with(|| left.source.cmp(right.source))
    });
    groups
}

fn ops_summary_metrics(alerts: &[AlertItem], hosts: &[Host]) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    format!(
        r#"<section class="ops-summary" aria-label="alert summary"><button class="ops-metric critical" type="button" data-ops-filter="critical" aria-pressed="false"><b>{critical}</b><span>critical</span></button><button class="ops-metric warning" type="button" data-ops-filter="warning" aria-pressed="false"><b>{warning}</b><span>warning</span></button><button class="ops-metric watch" type="button" data-ops-filter="watch" aria-pressed="false"><b>{watch}</b><span>watch</span></button><button class="ops-metric clear" type="button" data-ops-filter="clear" aria-pressed="false"><b>{clear}</b><span>clear</span></button></section>"#
    )
}

fn alert_group_host_label(group: &AlertGroup) -> (String, String) {
    if group.hosts.len() == 1 {
        return group.hosts[0].clone();
    }

    let mut names = group
        .hosts
        .iter()
        .take(3)
        .map(|(host, _)| host.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if group.hosts.len() > 3 {
        names.push_str(&format!(" +{} more", group.hosts.len() - 3));
    }
    (format!("{} hosts", group.hosts.len()), names)
}

fn alert_group_host_search(group: &AlertGroup) -> String {
    let mut parts = Vec::new();
    for (host, role) in &group.hosts {
        parts.push(host.as_str());
        parts.push(role.as_str());
    }
    parts.push(group.issue.as_str());
    parts.push(group.detail.as_str());
    parts.push(group.source);
    parts.join(" ").to_lowercase()
}

fn render_alert_row(group: &AlertGroup) -> String {
    let (host_label, host_detail) = alert_group_host_label(group);
    let repeat = if group.count > 1 {
        format!(
            r#"<span class="alert-repeat">{count} alerts</span>"#,
            count = group.count
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="alert-row {level}" data-ops-row data-ops-level="{level}" data-ops-kind="{source}" data-host-search="{host_search}"><div class="alert-host"><span class="alert-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{role}</span></div></div><div class="alert-status"><span class="severity">{level_label}</span>{repeat}</div><div class="alert-issue"><strong>{issue}</strong><p>{detail}</p></div><span class="ops-source">{source}</span><span class="ops-time">{seen}</span><span class="next-action">{next_action}</span></article>"#,
        level = html_escape(group.level),
        level_label = level_label(group.level),
        repeat = repeat,
        host = html_escape(&host_label),
        role = html_escape(&host_detail),
        issue = html_escape(&group.issue),
        detail = html_escape(&group.detail),
        source = html_escape(group.source),
        seen = html_escape(&group.seen),
        next_action = html_escape(&group.next_action),
        host_search = html_escape(&alert_group_host_search(group))
    )
}

fn render_alert_rows(groups: &[AlertGroup]) -> String {
    if groups.is_empty() {
        return r#"<section class="ops-empty"><h2>All clear</h2><p>No host, backup, freshness, service, probe, or manifest alert needs attention right now.</p></section>"#.to_string();
    }
    groups.iter().map(render_alert_row).collect()
}

fn posture_panel(alerts: &[AlertItem], hosts: &[Host]) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    let total_alerts = alerts.len().max(1);
    let (posture_label, posture_color, posture_count, posture_filter) = if critical > 0 {
        ("critical", "var(--down)", critical, "critical")
    } else if warning > 0 {
        ("warning", "var(--stale)", warning, "warning")
    } else if watch > 0 {
        ("watch", "var(--sun)", watch, "watch")
    } else {
        ("clear", "var(--live)", clear, "clear")
    };
    let posture_fill = if alerts.is_empty() {
        100
    } else {
        ((posture_count * 100) / total_alerts).clamp(8, 100)
    };
    format!(
        r#"<aside class="ops-side-panel" aria-label="operations posture"><div><h2>Operations posture</h2><p>Most important work first.</p></div><button class="posture-ring" type="button" data-ops-filter="{posture_filter}" aria-pressed="false" style="--posture-fill:{posture_fill}%;--posture-color:{posture_color}"><div><strong>{posture_count}</strong><span>{posture_label}</span></div></button><div class="posture-list"><button class="posture-chip critical" type="button" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="posture-chip warning" type="button" data-ops-filter="warning" aria-pressed="false">warning {warning}</button><button class="posture-chip watch" type="button" data-ops-filter="watch" aria-pressed="false">watch {watch}</button><button class="posture-chip clear" type="button" data-ops-filter="clear" aria-pressed="false">clear {clear}</button><button class="posture-chip info" type="button" data-ops-filter="all" aria-pressed="true">show all</button></div><div class="ops-note">Repeated alerts are grouped. Use the host search and severity controls to focus the queue.</div><a class="ops-action" href="/map">View on map</a></aside>"#
    )
}

fn render_alerts(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    let alerts = alert_items(
        runtime.hosts,
        runtime.jobs,
        self_name,
        now,
        manifests,
        load_errors,
        server_probes,
    );
    let groups = alert_groups(&alerts);
    let rows = render_alert_rows(&groups);
    format!(
        r#"{HEAD}{sidebar}<main class="ops-main" data-ops-page="alerts">{header}{summary}{toolbar}<section class="ops-layout"><section class="ops-panel" aria-label="attention queue"><header class="ops-panel-head"><div><h2>Needs attention</h2><p>Plain-language queue from heartbeat, backup, freshness, service, probe, and config state.</p></div><span class="ops-count">{count}</span></header><div class="alert-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching alerts.</section></section>{posture}</section></main>{script}</div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "alerts"),
        header = page_header("Alerts", "Needs attention", now),
        summary = ops_summary_metrics(&alerts, runtime.hosts),
        toolbar = ops_toolbar(),
        count = alerts.len(),
        posture = posture_panel(&alerts, runtime.hosts),
        script = ops_script()
    )
}

fn ops_toolbar() -> String {
    format!(
        r#"<section class="toolbar ops-toolbar" aria-label="operations filters"><div class="toolbar-left"><button class="activity-filter info" type="button" data-ops-filter="all" aria-pressed="true">Show all</button></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

fn backup_summary_metrics(hosts: &[Host], now: i64) -> String {
    let mut protected = 0;
    let mut review = 0;
    let mut failed = 0;
    let mut unknown = 0;

    for host in hosts {
        match backup_ui_summary(&host.backup_observations, now).level {
            "clear" => protected += 1,
            "warning" => review += 1,
            "critical" => failed += 1,
            _ => unknown += 1,
        }
    }

    format!(
        r#"<section class="ops-summary backup-summary" aria-label="backup summary"><button class="ops-metric clear" type="button" data-ops-filter="clear" aria-pressed="false"><b>{protected}</b><span>Protected</span></button><button class="ops-metric warning" type="button" data-ops-filter="warning" aria-pressed="false"><b>{review}</b><span>Review</span></button><button class="ops-metric critical" type="button" data-ops-filter="critical" aria-pressed="false"><b>{failed}</b><span>Failed or missing</span></button><button class="ops-metric watch" type="button" data-ops-filter="watch" aria-pressed="false"><b>{unknown}</b><span>Unknown</span></button></section>"#
    )
}

fn render_backup_rows(hosts: &[Host], now: i64) -> String {
    if hosts.is_empty() {
        return r#"<section class="ops-empty"><h2>No hosts yet</h2><p>Once hosts report, Pharos will show backup posture here.</p></section>"#.to_string();
    }

    let mut rows: Vec<(&Host, BackupUiSummary)> = hosts
        .iter()
        .map(|host| (host, backup_ui_summary(&host.backup_observations, now)))
        .collect();
    rows.sort_by(|(left_host, left), (right_host, right)| {
        left.rank
            .cmp(&right.rank)
            .then_with(|| left_host.name.cmp(&right_host.name))
    });

    rows.into_iter()
        .map(|(host, backup)| {
            let count = if backup.total > 1 {
                format!(
                    r#"<span class="backup-count">{count} jobs</span>"#,
                    count = backup.total
                )
            } else {
                String::new()
            };
            let search = html_escape(
                &format!(
                    "{} {} {} {} {} {} {} {}",
                    host.name,
                    host.role,
                    backup.label,
                    backup.detail,
                    backup.last_success,
                    backup.schedule,
                    backup.target,
                    backup.validation
                )
                .to_lowercase(),
            );
            format!(
                r#"<article class="backup-row {level}" data-ops-row data-ops-level="{level}" data-host-search="{search}"><div class="backup-host"><div><strong>{host}</strong><span>{role}</span></div></div><div class="backup-state"><span class="severity">{label}</span>{count}</div><div class="backup-issue"><strong>{detail}</strong><p>{state}</p></div><div class="backup-field"><span>Last success</span><strong>{last_success}</strong></div><div class="backup-field"><span>Schedule</span><strong>{schedule}</strong></div><div class="backup-field"><span>Target</span><strong>{target}</strong></div><div class="backup-field"><span>Validation</span><strong>{validation}</strong></div></article>"#,
                level = html_escape(backup.level),
                search = search,
                host = html_escape(&host.name),
                role = html_escape(&host.role),
                label = html_escape(&backup.label),
                count = count,
                detail = html_escape(&backup.detail),
                state = html_escape(backup.state),
                last_success = html_escape(&backup.last_success),
                schedule = html_escape(&backup.schedule),
                target = html_escape(&backup.target),
                validation = html_escape(&backup.validation)
            )
        })
        .collect()
}

fn render_backups(hosts: &[Host], now: i64, shell: ShellContext<'_>) -> String {
    let rows = render_backup_rows(hosts, now);
    format!(
        r#"{HEAD}{sidebar}<main class="ops-main backup-page" data-ops-page="backups">{header}{summary}{toolbar}<section class="ops-panel" aria-label="backup posture"><header class="ops-panel-head"><div><h2>Backup posture</h2><p>Sanitized runtime evidence from backup jobs. No logs, paths, repositories, or credentials are shown.</p></div><span class="ops-count">{count}</span></header><div class="backup-list-full">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching backup rows.</section></section><div class="ops-note" style="margin-top:14px">A protected state means the latest reported backup source is healthy. Restore validation is tracked separately from last backup success when evidence exists.</div></main>{script}</div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "backups"),
        header = page_header("Backups", "Protection at a glance", now),
        summary = backup_summary_metrics(hosts, now),
        toolbar = ops_toolbar(),
        count = hosts.len(),
        rows = rows,
        script = ops_script()
    )
}

fn ops_script() -> &'static str {
    r#"<script>
document.querySelectorAll('[data-ops-page]').forEach(root=>{
  const search=root.querySelector('[data-search]');
  const rows=[...root.querySelectorAll('[data-ops-row]')];
  const empty=root.querySelector('[data-ops-empty]');
  let active='all';
  function setFilter(filter){
    active=filter||'all';
    root.querySelectorAll('[data-ops-filter]').forEach(button=>{
      button.setAttribute('aria-pressed',String((button.dataset.opsFilter||'all')===active));
    });
    apply();
  }
  function apply(){
    const query=(search?.value||'').trim().toLowerCase();
    let visible=0;
    rows.forEach(row=>{
      const filterOk=active==='all'||row.dataset.opsLevel===active||row.dataset.opsKind===active;
      const haystack=(row.dataset.hostSearch||row.textContent||'').toLowerCase();
      const searchOk=!query||haystack.includes(query);
      const show=filterOk&&searchOk;
      row.hidden=!show;
      if(show)visible++;
    });
    if(empty)empty.dataset.visible=String(visible===0&&rows.length>0);
  }
  root.querySelectorAll('[data-ops-filter]').forEach(button=>{
    button.addEventListener('click',()=>setFilter(button.dataset.opsFilter||'all'));
  });
  search?.addEventListener('input',apply);
  setFilter('all');
});
</script>"#
}

fn backup_engine_label(engine: pharos_core::BackupEngine) -> &'static str {
    match engine {
        pharos_core::BackupEngine::Restic => "Restic",
        pharos_core::BackupEngine::Borg => "Borg",
        pharos_core::BackupEngine::Kopia => "Kopia",
        pharos_core::BackupEngine::ProviderSnapshot => "provider snapshot",
        pharos_core::BackupEngine::Other => "backup",
        pharos_core::BackupEngine::Unknown => "backup",
    }
}

fn backup_activity_level(state: BackupPostureState) -> &'static str {
    match backup_level(state) {
        "clear" => "info",
        level => level,
    }
}

fn backup_activity_detail(observation: &BackupObservation) -> String {
    let mut parts = vec![backup_engine_label(observation.engine).to_string()];
    if let Some(schedule) = &observation.schedule {
        parts.push(format!("schedule {}", schedule));
    }
    if let Some(target) = &observation.target_label {
        parts.push(format!("target {}", target));
    }
    parts.join(" · ")
}

fn push_backup_activity_events(
    events: &mut Vec<ActivityEvent>,
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) {
    let observed_at = backup_sort_time(host, observation, now);
    events.push(ActivityEvent::new(
        host.last_seen.unwrap_or(observed_at),
        host.name.clone(),
        "info",
        "backup",
        "Backup source observed",
        backup_activity_detail(observation),
        "backup",
    ));

    if let Some(timestamp) = observation.last_success_at {
        events.push(ActivityEvent::new(
            timestamp,
            host.name.clone(),
            "info",
            "backup",
            format!("{} succeeded", observation.label),
            backup_activity_detail(observation),
            "backup",
        ));
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_attempt_at, observation.last_attempt_state)
    {
        match state {
            pharos_core::BackupRunState::Succeeded => {}
            pharos_core::BackupRunState::Failed => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "critical",
                "backup",
                format!("{} failed", observation.label),
                observation.summary.clone(),
                "backup",
            )),
            pharos_core::BackupRunState::Running => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "watch",
                "backup",
                format!("{} running", observation.label),
                observation.summary.clone(),
                "backup",
            )),
            pharos_core::BackupRunState::Unknown => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "watch",
                "backup",
                format!("{} state unknown", observation.label),
                observation.summary.clone(),
                "backup",
            )),
        }
    }

    if observation.state != BackupPostureState::Healthy {
        events.push(ActivityEvent::new(
            observed_at,
            host.name.clone(),
            backup_activity_level(observation.state),
            "backup",
            format!(
                "{}: {}",
                observation.label,
                backup_state_label(observation.state)
            ),
            observation.summary.clone(),
            "backup",
        ));
    }

    if let Some(restore) = &observation.restore_validation {
        let level = match restore.state {
            pharos_core::BackupValidationState::Passed => "info",
            pharos_core::BackupValidationState::Failed => "critical",
            pharos_core::BackupValidationState::Stale => "warning",
            pharos_core::BackupValidationState::Unknown => "watch",
        };
        let checked_at = restore.checked_at.unwrap_or(observed_at);
        let label = restore
            .evidence_label
            .as_deref()
            .unwrap_or_else(|| backup_validation_level_label(restore.level));
        events.push(ActivityEvent::new(
            checked_at,
            host.name.clone(),
            level,
            "backup",
            format!(
                "{} validation {}",
                observation.label,
                backup_validation_state_label(restore.state)
            ),
            format!(
                "{} - {}",
                label,
                restore
                    .summary
                    .clone()
                    .unwrap_or_else(|| backup_validation_label(observation, now))
            ),
            "backup",
        ));
    } else if let (Some(timestamp), Some(state)) =
        (observation.last_check_at, observation.last_check_state)
    {
        let level = match state {
            pharos_core::BackupValidationState::Passed => "info",
            pharos_core::BackupValidationState::Failed => "critical",
            pharos_core::BackupValidationState::Stale => "warning",
            pharos_core::BackupValidationState::Unknown => "watch",
        };
        events.push(ActivityEvent::new(
            timestamp,
            host.name.clone(),
            level,
            "backup",
            format!(
                "{} validation {}",
                observation.label,
                backup_validation_state_label(state)
            ),
            backup_validation_label(observation, now),
            "backup",
        ));
    }
}

fn activity_events(
    hosts: &[Host],
    jobs: &[ProvisioningJob],
    _self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
) -> Vec<ActivityEvent> {
    let mut events = Vec::new();
    let runtime_names: BTreeSet<&str> = hosts.iter().map(|host| host.name.as_str()).collect();

    for issue in load_errors {
        events.push(ActivityEvent::new(
            now,
            "Pharos",
            "critical",
            "config",
            "Manifest load failed",
            format!("{} - {}", issue.path, issue.error),
            "config",
        ));
    }

    for manifest in manifests {
        events.push(ActivityEvent::new(
            now,
            manifest.host.name.clone(),
            "info",
            "config",
            "Declared host manifest loaded",
            format!("{} declared services", manifest.services.len()),
            "config",
        ));
    }

    for job in jobs {
        let Some(host) = provisioning_job_host_name(job) else {
            continue;
        };
        if provisioning_job_first_heartbeat_overdue(job, now) && !runtime_names.contains(host) {
            events.push(ActivityEvent::new(
                now,
                host.to_string(),
                "warning",
                "setup",
                "First heartbeat overdue",
                format!(
                    "No first heartbeat after {}.",
                    duration_label(now.saturating_sub(job.updated_at))
                ),
                "setup",
            ));
        }
        for entry in &job.progress {
            let level = match entry.state {
                ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded => "critical",
                ProvisioningJobState::WaitingForHeartbeat
                | ProvisioningJobState::BackupPending
                | ProvisioningJobState::Planning
                | ProvisioningJobState::Provisioning
                | ProvisioningJobState::Bootstrapping => "watch",
                ProvisioningJobState::Complete => "recovery",
            };
            events.push(ActivityEvent::new(
                entry.observed_at,
                host.to_string(),
                level,
                "setup",
                format!("Setup {}", entry.state.label()),
                entry.message.clone(),
                "setup",
            ));
        }
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        match live {
            Liveness::Down => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "critical",
                "heartbeat",
                "No heartbeat received",
                format!("Last report was {}", seen_label(host.last_seen, now)),
                "heartbeat",
            )),
            Liveness::Stale => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "warning",
                "heartbeat",
                "Heartbeat lateness detected",
                format!("Last report was {}", seen_label(host.last_seen, now)),
                "heartbeat",
            )),
            Liveness::AwaitingFirstHeartbeat => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "watch",
                "heartbeat",
                "Awaiting first heartbeat",
                "Host exists but has not reported yet.",
                "heartbeat",
            )),
            Liveness::Live => {}
        }

        let samples = heartbeat_samples(&host.heartbeat_log, host.last_seen);
        for stamp in samples.iter().rev().take(4) {
            events.push(ActivityEvent::new(
                *stamp,
                host.name.clone(),
                "info",
                "heartbeat",
                "Heartbeat received",
                format!("{} checked in at {}", host.name, clock_label(*stamp)),
                "heartbeat",
            ));
        }

        if let Some((level, issue, _action)) = freshness_alert(&host.freshness) {
            events.push(ActivityEvent::new(
                host.last_seen.unwrap_or(now),
                host.name.clone(),
                level,
                "freshness",
                "Freshness drift detected",
                issue,
                "freshness",
            ));
        }

        for observation in &host.service_observations {
            if is_nix_freshness_observation(observation) {
                continue;
            }

            if observation.state == ServiceObservationState::Healthy {
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    "info",
                    "service",
                    format!("{} is healthy", observation.label),
                    observation.summary.clone(),
                    "service",
                ));
            } else {
                let level = match observation.state {
                    ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                    ServiceObservationState::Unknown => "watch",
                    ServiceObservationState::Healthy => "info",
                };
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    level,
                    "service",
                    format!("{} {}", observation.label, observation.state.label()),
                    observation.summary.clone(),
                    "service",
                ));
            }
        }

        for observation in &host.backup_observations {
            push_backup_activity_events(&mut events, host, observation, now);
        }

        push_protection_onboarding_activity(&mut events, host, jobs, now);
    }

    for (host, probes) in server_probes {
        for probe in probes {
            let level = match probe.state {
                ServiceObservationState::Healthy => "info",
                ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                ServiceObservationState::Unknown => "watch",
            };
            events.push(ActivityEvent::new(
                probe.checked_at,
                host.clone(),
                level,
                "service",
                format!("{} probe {}", probe.service, probe.state.label()),
                probe.summary.clone(),
                "probe",
            ));
        }
    }

    events.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| level_rank(left.level).cmp(&level_rank(right.level)))
            .then_with(|| left.host.cmp(&right.host))
    });
    events
}

fn activity_source_count(events: &[ActivityEvent], kind: &str) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

fn activity_summary_metrics(events: &[ActivityEvent]) -> String {
    let heartbeat = activity_source_count(events, "heartbeat");
    let freshness = activity_source_count(events, "freshness");
    let service = activity_source_count(events, "service");
    let backup = activity_source_count(events, "backup");
    let setup = activity_source_count(events, "setup");
    format!(
        r#"<section class="ops-summary" aria-label="activity summary"><button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true"><b>{total}</b><span>all events</span></button><button class="ops-metric clear" type="button" data-ops-filter="heartbeat" aria-pressed="false"><b>{heartbeat}</b><span>heartbeat</span></button><button class="ops-metric watch" type="button" data-ops-filter="setup" aria-pressed="false"><b>{setup}</b><span>setup</span></button><button class="ops-metric watch" type="button" data-ops-filter="freshness" aria-pressed="false"><b>{freshness}</b><span>freshness</span></button><button class="ops-metric warning" type="button" data-ops-filter="service" aria-pressed="false"><b>{service}</b><span>service</span></button><button class="ops-metric recovery" type="button" data-ops-filter="backup" aria-pressed="false"><b>{backup}</b><span>backup</span></button></section>"#,
        total = events.len()
    )
}

fn activity_filter_bar(events: &[ActivityEvent]) -> String {
    let config = activity_source_count(events, "config");
    let setup = activity_source_count(events, "setup");
    let critical = events
        .iter()
        .filter(|event| event.level == "critical")
        .count();
    let warning = events
        .iter()
        .filter(|event| event.level == "warning")
        .count();
    format!(
        r#"<div class="activity-filters" role="group" aria-label="activity filters"><button class="activity-filter info" type="button" data-activity-filter="all" data-ops-filter="all" aria-pressed="true">All events {total}</button><button class="activity-filter clear" type="button" data-activity-filter="heartbeat" data-ops-filter="heartbeat" aria-pressed="false">Heartbeat {heartbeat}</button><button class="activity-filter watch" type="button" data-activity-filter="setup" data-ops-filter="setup" aria-pressed="false">Setup {setup}</button><button class="activity-filter watch" type="button" data-activity-filter="freshness" data-ops-filter="freshness" aria-pressed="false">Freshness {freshness}</button><button class="activity-filter warning" type="button" data-activity-filter="service" data-ops-filter="service" aria-pressed="false">Service {service}</button><button class="activity-filter recovery" type="button" data-activity-filter="backup" data-ops-filter="backup" aria-pressed="false">Backup {backup}</button><button class="activity-filter info" type="button" data-activity-filter="config" data-ops-filter="config" aria-pressed="false">Config {config}</button><button class="activity-filter critical" type="button" data-activity-filter="critical" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="activity-filter warning" type="button" data-activity-filter="warning" data-ops-filter="warning" aria-pressed="false">warning {warning}</button></div>"#,
        total = events.len(),
        heartbeat = activity_source_count(events, "heartbeat"),
        freshness = activity_source_count(events, "freshness"),
        service = activity_source_count(events, "service"),
        backup = activity_source_count(events, "backup"),
    )
}

fn render_activity_row(event: &ActivityEvent) -> String {
    format!(
        r#"<article class="activity-row {level}" data-ops-row data-activity-kind="{kind}" data-activity-level="{level}" data-ops-kind="{kind}" data-ops-level="{level}" data-host-search="{host_search}"><span class="ops-time">{time}</span><div class="activity-host"><span class="activity-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{kind}</span></div></div><span class="severity">{level_label}</span><div class="activity-copy"><strong>{title}</strong><p>{detail}</p></div><span class="ops-source">{source}</span></article>"#,
        level = html_escape(event.level),
        kind = html_escape(event.kind),
        time = html_escape(&clock_label(event.timestamp)),
        host = html_escape(&event.host),
        level_label = level_label(event.level),
        title = html_escape(&event.title),
        detail = html_escape(&event.detail),
        source = html_escape(event.source),
        host_search = html_escape(
            &format!(
                "{} {} {} {} {}",
                event.host, event.kind, event.title, event.detail, event.source
            )
            .to_lowercase(),
        )
    )
}

fn activity_rows(events: &[ActivityEvent]) -> String {
    if events.is_empty() {
        return r#"<section class="ops-empty"><h2>No activity yet</h2><p>Once hosts report, Pharos will show heartbeats, backup changes, freshness changes, service observations, and config events here.</p></section>"#.to_string();
    }
    events.iter().take(80).map(render_activity_row).collect()
}

fn activity_script() -> &'static str {
    ops_script()
}

fn render_activity(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    let events = activity_events(
        runtime.hosts,
        runtime.jobs,
        self_name,
        now,
        manifests,
        load_errors,
        server_probes,
    );
    let rows = activity_rows(&events);
    format!(
        r#"{HEAD}{sidebar}<main class="ops-main" data-ops-page="activity">{header}{summary}{toolbar}<section class="ops-panel" aria-label="operational timeline"><header class="ops-panel-head"><div><h2>Operational timeline</h2><p>Reverse chronological history from heartbeat, backup, freshness, service, and config signals.</p></div><span class="ops-count">{count}</span></header><div style="padding:14px 16px;border-bottom:1px solid rgba(214,226,234,.72)">{filters}</div><div class="activity-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching activity.</section></section><div class="ops-note" style="margin-top:14px">Activity is derived from current retained Pharos state. It is not an audit log yet; it shows the recent operational picture Pharos can prove now.</div></main>{script}</div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "activity"),
        header = page_header("Activity", "Operational timeline", now),
        summary = activity_summary_metrics(&events),
        toolbar = ops_toolbar(),
        count = events.len(),
        filters = activity_filter_bar(&events),
        script = activity_script()
    )
}

fn render_map(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    user_label: &str,
    logout_enabled: bool,
) -> String {
    let summary = summary_cards(hosts, self_name, now);
    let toolbar = map_toolbar();
    let map_script = r#"<script>
const MAP_DATA_URL='/map/data.json';
const MAP_LEAFLET_CSS='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
const MAP_LEAFLET_JS='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
const MAP_D3_JS='https://unpkg.com/d3@7.9.0/dist/d3.min.js';
let MAP_HOSTS=[];
let applyMapFilterNow=null;
let pendingMapFilter={q:'',live:'all'};
function escapeHtml(value){return String(value).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function stateVar(live){return live==='awaiting_first_heartbeat'?'wait':live}
function locationSourceLabel(source){
  switch(source){
    case 'wifi':
    case 'ip':
      return 'auto';
    case 'declared':
      return 'declared';
    case 'provider':
      return 'provider';
    case 'fallback':
      return 'fallback';
    default:
      return 'unknown';
  }
}
function locationSourceTitle(host){
  const label=locationSourceLabel(host.location_source);
  const stale=host.location_stale?'stale ':'';
  const state=host.location_state&&host.location_state!=='observed'?' · '+host.location_state:'';
  return stale+label+' location'+state;
}
function loadStylesheet(href){
  if(document.querySelector('link[href="'+href+'"]'))return Promise.resolve();
  return new Promise((resolve,reject)=>{
    const tag=document.createElement('link');
    tag.rel='stylesheet';
    tag.href=href;
    tag.onload=resolve;
    tag.onerror=()=>reject(new Error('stylesheet failed'));
    document.head.appendChild(tag);
  });
}
function loadScript(src,ready){
  if(ready&&ready())return Promise.resolve();
  if(document.querySelector('script[src="'+src+'"]')){
    return new Promise(resolve=>{
      const check=()=>ready&&ready()?resolve():setTimeout(check,30);
      check();
    });
  }
  return new Promise((resolve,reject)=>{
    const tag=document.createElement('script');
    tag.src=src;
    tag.async=true;
    tag.onload=resolve;
    tag.onerror=()=>reject(new Error('script failed'));
    document.head.appendChild(tag);
  });
}
async function loadMapAssets(){
  await loadStylesheet(MAP_LEAFLET_CSS);
  await loadScript(MAP_LEAFLET_JS,()=>Boolean(window.L));
  await loadScript(MAP_D3_JS,()=>Boolean(window.d3));
}
async function loadMapData(){
  const res=await fetch(MAP_DATA_URL+'?refresh='+Date.now(),{headers:{Accept:'application/json'},cache:'no-store',credentials:'same-origin'});
  if(!res.ok)throw new Error('map data failed');
  const data=await res.json();
  if(!data||!Array.isArray(data.hosts))throw new Error('map data malformed');
  return data;
}
function setMapLoading(state,message){
  const panel=document.getElementById('map-panel');
  const sitePanel=document.querySelector('[data-site-panel]');
  const note=document.querySelector('[data-map-note]');
  const text=document.querySelector('[data-map-status-message]');
  if(panel)panel.dataset.loading=state==='loading'?'true':'false';
  if(panel)panel.dataset.mapState=state;
  if(sitePanel)sitePanel.dataset.loading=state==='loading'?'true':'false';
  if(note&&message)note.textContent=message;
  if(text&&message)text.textContent=message;
}
function siteSkeleton(){
  return '<div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line long"></span><span class="site-skel-line medium"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line medium"></span><span class="site-skel-line long"></span><span class="site-skel-line short"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line medium"></span><span class="site-skel-line long"></span></div>';
}
function siteError(message){
  return '<div class="site-error"><strong>Locations unavailable</strong><span>'+escapeHtml(message||'Map data could not be loaded. Try refreshing this view.')+'</span></div>';
}
function siteHostHtml(host){
  const style='--host-state:var(--'+escapeHtml(stateVar(host.live))+')';
  const sourceLabel=locationSourceLabel(host.location_source);
  const sourceTitle=locationSourceTitle(host);
  return '<a class="site-host" href="'+escapeHtml(host.settings_href)+'" data-host="'+escapeHtml(host.name)+'" data-live="'+escapeHtml(host.live)+'" data-search="'+escapeHtml(host.search||'')+'" style="'+style+'" title="'+escapeHtml(host.name+': '+host.attention+'; '+sourceTitle+'; '+host.inbound_title+'; '+host.outbound_title)+'"><span class="site-host-name">'+escapeHtml(host.name)+'</span><span class="site-host-signals"><span class="site-host-ping" data-probe-level="'+escapeHtml(host.inbound_level)+'">in '+escapeHtml(host.inbound_label)+'</span><span class="site-host-ping" data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">out '+escapeHtml(host.outbound_label)+'</span><span class="site-host-source" data-location-source="'+escapeHtml(host.location_source)+'" data-location-state="'+escapeHtml(host.location_state)+'" title="'+escapeHtml(sourceTitle)+'">'+escapeHtml(sourceLabel)+'</span></span></a>';
}
function renderSiteList(hosts){
  const target=document.querySelector('[data-site-list]');
  if(!target)return;
  if(!hosts.length){
    target.innerHTML='<div class="site-error"><strong>No mapped hosts</strong><span>Pharos has no host locations to show yet.</span></div>';
    return;
  }
  const bySite=new Map();
  hosts.forEach(host=>{
    const key=host.site_id||'unknown';
    if(!bySite.has(key))bySite.set(key,[]);
    bySite.get(key).push(host);
  });
  const sections=Array.from(bySite.values()).sort((a,b)=>String(a[0].site_label).localeCompare(String(b[0].site_label))).map(siteHosts=>{
    siteHosts.sort((a,b)=>String(a.name).localeCompare(String(b.name)));
    const first=siteHosts[0];
    return '<section class="site-item"><div class="site-head"><div><strong>'+escapeHtml(first.site_label)+'</strong><p>'+escapeHtml(first.region)+'</p></div><span class="site-count">'+siteHosts.length+'</span></div><div class="site-hosts">'+siteHosts.map(siteHostHtml).join('')+'</div></section>';
  });
  target.innerHTML=sections.join('');
}
function nodeHtml(host){const sourceLabel=locationSourceLabel(host.location_source);const sourceTitle=locationSourceTitle(host);return '<span class="map-status-dot" aria-hidden="true"></span><span class="map-name">'+escapeHtml(host.name)+'</span><span class="map-signals"><span class="map-ping" data-dir="in" data-probe-level="'+escapeHtml(host.inbound_level)+'">'+escapeHtml(host.inbound_label)+'</span><span class="map-ping" data-dir="out" data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">'+escapeHtml(host.outbound_label)+'</span></span><span class="map-source" data-location-source="'+escapeHtml(host.location_source)+'" data-location-state="'+escapeHtml(host.location_state)+'" title="'+escapeHtml(sourceTitle)+'">'+escapeHtml(sourceLabel)+'</span>'}
function groupOffsets(hosts){
  const groups=new Map();
  hosts.forEach(host=>{
    const key=Number(host.lat).toFixed(4)+','+Number(host.lon).toFixed(4);
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(host.name);
  });
  return groups;
}
function seedOffset(index,count){
  if(count<=1)return {x:34,y:-28};
  const angle=(-Math.PI/2)+(index/count)*Math.PI*2;
  const radius=42+Math.min(count,6)*6;
  return {x:Math.cos(angle)*radius,y:Math.sin(angle)*radius};
}
function clamp(value,min,max){return Math.max(min,Math.min(max,value))}
function forceBounds(nodes,width,height){
  return function(){
    for(const d of nodes){
      d.x=clamp(d.x,d.w/2+8,width-d.w/2-8);
      d.y=clamp(d.y,d.h/2+8,height-d.h/2-8);
    }
  }
}
function svgEl(name){return document.createElementNS('http://www.w3.org/2000/svg',name)}
function curvePath(a,b){
  const dx=b.ax-a.ax;
  const dy=b.ay-a.ay;
  const mx=(a.ax+b.ax)/2;
  const my=(a.ay+b.ay)/2;
  const len=Math.max(1,Math.hypot(dx,dy));
  const bend=Math.min(70,Math.max(18,len*.12));
  const cx=mx+(-dy/len)*bend;
  const cy=my+(dx/len)*bend;
  return 'M '+a.ax.toFixed(1)+' '+a.ay.toFixed(1)+' Q '+cx.toFixed(1)+' '+cy.toFixed(1)+' '+b.ax.toFixed(1)+' '+b.ay.toFixed(1);
}
function addPacket(path,id,dir,level,policy,reverse){
  const circle=svgEl('circle');
  circle.setAttribute('r','3');
  circle.classList.add('map-packet',dir);
  circle.dataset.level=level;
  circle.dataset.policy=policy||'unknown';
  const motion=svgEl('animateMotion');
  motion.setAttribute('dur',dir==='inbound'?'3.6s':'2.8s');
  motion.setAttribute('repeatCount','indefinite');
  motion.setAttribute('calcMode','linear');
  if(reverse){
    motion.setAttribute('keyPoints','1;0');
    motion.setAttribute('keyTimes','0;1');
  }
  const mpath=svgEl('mpath');
  mpath.setAttribute('href','#'+id);
  motion.appendChild(mpath);
  circle.appendChild(motion);
  path.parentNode.appendChild(circle);
  return circle;
}
function mapHostMatches(host,q,live){return (q===''||String(host.search||'').includes(q))&&(live==='all'||host.live===live)}
function buildLabels(map,el){
  const layer=document.createElement('div');
  layer.className='map-label-layer';
  const links=svgEl('svg');
  links.classList.add('map-links');
  const leaders=svgEl('svg');
  leaders.classList.add('map-leaders');
  layer.appendChild(links);
  layer.appendChild(leaders);
  el.appendChild(layer);
  const groups=groupOffsets(MAP_HOSTS);
  const seen=new Map();
  const nodes=MAP_HOSTS.map((host,idx)=>{
    const key=Number(host.lat).toFixed(4)+','+Number(host.lon).toFixed(4);
    const groupIndex=seen.get(key)||0;
    seen.set(key,groupIndex+1);
    const anchor=document.createElement('span');
    anchor.className='map-anchor '+escapeHtml(host.live);
    const link=document.createElement('a');
    link.className='map-node '+escapeHtml(host.live);
    link.href=host.settings_href;
    link.dataset.host=host.name;
    link.dataset.live=host.live;
    link.dataset.search=host.search||'';
    link.dataset.mapLayer='managed';
    link.innerHTML=nodeHtml(host);
    link.title=host.name+': '+host.status+'; '+locationSourceTitle(host)+'; '+host.inbound_title+'; '+host.outbound_title;
    link.setAttribute('aria-label',host.name+', '+host.status+', '+locationSourceTitle(host)+', inbound '+host.inbound_label+', outbound '+host.outbound_label);
    const line=svgEl('line');
    leaders.appendChild(line);
    layer.appendChild(anchor);
    layer.appendChild(link);
    return {host,idx,anchor,link,line,groupIndex,groupCount:(groups.get(key)||[]).length,visible:true,w:100,h:38,r:58,x:0,y:0,ax:0,ay:0};
  });
  const pharosNode=nodes.find(node=>node.host.is_pharos)||nodes[0];
  const linksByHost=nodes.filter(node=>node!==pharosNode).map((node,idx)=>{
    const path=svgEl('path');
    const id='map-link-'+idx;
    path.id=id;
    path.classList.add('map-link');
    path.dataset.inboundLevel=node.host.inbound_level;
    path.dataset.outboundLevel=node.host.outbound_level;
    path.dataset.outboundPolicy=node.host.outbound_policy;
    links.appendChild(path);
    const packets=[];
    if(node.host.inbound_level!=='wait')packets.push(addPacket(path,id,'inbound',node.host.inbound_level,node.host.outbound_policy,true));
    if(node.host.outbound_level==='good')packets.push(addPacket(path,id,'outbound',node.host.outbound_level,node.host.outbound_policy,false));
    return {node,path,packets};
  });
  let scheduled=false;
  function layout(){
    scheduled=false;
    const width=el.clientWidth||800;
    const height=el.clientHeight||520;
    links.setAttribute('viewBox','0 0 '+width+' '+height);
    leaders.setAttribute('viewBox','0 0 '+width+' '+height);
    const visibleNodes=nodes.filter(node=>node.visible!==false);
    nodes.filter(node=>node.visible===false).forEach(node=>{
      node.anchor.hidden=true;
      node.link.hidden=true;
      node.line.style.opacity='0';
    });
    visibleNodes.forEach(node=>{
      const point=map.latLngToContainerPoint([node.host.lat,node.host.lon]);
      const offset=seedOffset(node.groupIndex,node.groupCount);
      node.ax=point.x;
      node.ay=point.y;
      node.anchor.hidden=false;
      node.link.hidden=false;
      node.anchor.style.left=point.x+'px';
      node.anchor.style.top=point.y+'px';
      node.link.style.transform='translate(-1000px,-1000px)';
      const rect=node.link.getBoundingClientRect();
      node.w=rect.width||110;
      node.h=rect.height||54;
      node.r=Math.sqrt(node.w*node.w+node.h*node.h)/2+10;
      node.x=clamp(point.x+offset.x,node.w/2+8,width-node.w/2-8);
      node.y=clamp(point.y+offset.y,node.h/2+8,height-node.h/2-8);
    });
    if(window.d3&&d3.forceSimulation){
      const simulation=d3.forceSimulation(visibleNodes)
        .force('x',d3.forceX(d=>d.ax+seedOffset(d.groupIndex,d.groupCount).x).strength(.18))
        .force('y',d3.forceY(d=>d.ay+seedOffset(d.groupIndex,d.groupCount).y).strength(.18))
        .force('collide',d3.forceCollide(d=>d.r).strength(1))
        .force('bounds',forceBounds(visibleNodes,width,height))
        .stop();
      for(let i=0;i<90;i++)simulation.tick();
    }
    visibleNodes.forEach(node=>{
      node.x=clamp(node.x,node.w/2+8,width-node.w/2-8);
      node.y=clamp(node.y,node.h/2+8,height-node.h/2-8);
      const left=node.x-node.w/2;
      const top=node.y-node.h/2;
      node.link.style.transform='translate('+left.toFixed(1)+'px,'+top.toFixed(1)+'px)';
      const distance=Math.hypot(node.x-node.ax,node.y-node.ay);
      node.line.setAttribute('x1',node.ax);
      node.line.setAttribute('y1',node.ay);
      node.line.setAttribute('x2',node.x);
      node.line.setAttribute('y2',node.y);
      node.line.style.opacity=distance>22?'.55':'0';
    });
    if(pharosNode){
      linksByHost.forEach(link=>{
        const visible=pharosNode.visible!==false&&link.node.visible!==false;
        link.path.style.display=visible?'':'none';
        link.packets.forEach(packet=>{packet.style.display=visible?'':'none'});
        if(!visible)return;
        link.path.setAttribute('d',curvePath(pharosNode,link.node));
      });
    }
  }
  function scheduleLayout(){
    if(scheduled)return;
    scheduled=true;
    requestAnimationFrame(layout);
  }
  map.on('move zoom moveend zoomend resize viewreset',scheduleLayout);
  window.addEventListener('resize',scheduleLayout);
  applyMapFilterNow=(q='',live='all')=>{
    nodes.forEach(node=>{
      node.visible=mapHostMatches(node.host,q,live);
    });
    scheduleLayout();
  };
  window.pharosMapApplyFilter=(q='',live='all')=>{
    pendingMapFilter={q,live};
    applyMapFilterNow(q,live);
  };
  applyMapFilterNow(pendingMapFilter.q,pendingMapFilter.live);
  scheduleLayout();
  return scheduleLayout;
}
function fullscreenElement(){return document.fullscreenElement||document.webkitFullscreenElement||null}
function requestFullscreen(el){
  if(el.requestFullscreen)return el.requestFullscreen();
  if(el.webkitRequestFullscreen)return el.webkitRequestFullscreen();
  return Promise.reject(new Error('Fullscreen is not supported'));
}
function exitFullscreen(){
  if(document.exitFullscreen)return document.exitFullscreen();
  if(document.webkitExitFullscreen)return document.webkitExitFullscreen();
  return Promise.resolve();
}
const MAP_VIEWPORT_STORAGE='pharos.map.viewport.v1';
const MAP_MODE_STORAGE='pharos.map.mode.v1';
const MAP_LABEL_DENSITY_STORAGE='pharos.map.labelDensity.v1';
function storageGet(key){try{return window.localStorage.getItem(key)}catch(_){return null}}
function storageSet(key,value){try{window.localStorage.setItem(key,value)}catch(_){}}
function storedMapMode(){
  const value=storageGet(MAP_MODE_STORAGE);
  return value==='maximized'?'maximized':'standard';
}
function storeMapMode(mode){
  storageSet(MAP_MODE_STORAGE,mode==='standard'?'standard':'maximized');
}
function storedMapLabelDensity(){
  return storageGet(MAP_LABEL_DENSITY_STORAGE)==='compact'?'compact':'normal';
}
function storeMapLabelDensity(density){
  storageSet(MAP_LABEL_DENSITY_STORAGE,density==='compact'?'compact':'normal');
}
function storedViewport(){
  try{
    const raw=storageGet(MAP_VIEWPORT_STORAGE);
    if(!raw)return null;
    const parsed=JSON.parse(raw);
    const lat=Number(parsed.lat);
    const lon=Number(parsed.lon);
    const zoom=Number(parsed.zoom);
    if(!Number.isFinite(lat)||!Number.isFinite(lon)||!Number.isFinite(zoom))return null;
    if(lat<-90||lat>90||lon<-180||lon>180||zoom<0||zoom>20)return null;
    return {lat,lon,zoom};
  }catch(_){
    return null;
  }
}
function storeViewport(map){
  const center=map.getCenter();
  storageSet(MAP_VIEWPORT_STORAGE,JSON.stringify({
    lat:Number(center.lat.toFixed(5)),
    lon:Number(center.lng.toFixed(5)),
    zoom:map.getZoom()
  }));
}
function setupMapModes(map,el,relayout){
  const panel=document.getElementById('map-panel');
  const layout=document.querySelector('[data-map-layout]');
  const main=document.querySelector('[data-map-view]');
  const buttons=Array.from(document.querySelectorAll('[data-map-mode-button]'));
  const densityButton=document.querySelector('[data-map-density-button]');
  if(!panel||!layout||!main||!buttons.length)return;
  let mode='standard';
  let beforeFullscreen='standard';
  function resizeSoon(){
    const run=()=>{map.invalidateSize();relayout&&relayout()};
    requestAnimationFrame(run);
    window.setTimeout(run,90);
    window.setTimeout(run,260);
  }
  function setPressed(next){
    buttons.forEach(button=>{
      const active=button.dataset.mapModeButton===next;
      button.setAttribute('aria-pressed',active?'true':'false');
    });
  }
  function commit(next){
    mode=next;
    panel.dataset.mode=next;
    layout.dataset.mode=next==='fullscreen'?'maximized':next;
    main.dataset.mapView=next==='standard'?'standard':'maximized';
    setPressed(next);
    storeMapMode(next);
    resizeSoon();
  }
  function setMode(next){
    if(next==='fullscreen'){
      beforeFullscreen=mode==='fullscreen'?'standard':mode;
      commit('fullscreen');
      requestFullscreen(panel).catch(()=>commit('maximized'));
      return;
    }
    if(fullscreenElement()===panel){
      exitFullscreen().catch(()=>{});
    }
    commit(next);
  }
  buttons.forEach(button=>{
    button.addEventListener('click',()=>setMode(button.dataset.mapModeButton||'standard'));
  });
  function setDensity(next){
    const density=next==='compact'?'compact':'normal';
    panel.dataset.labelDensity=density;
    if(densityButton)densityButton.setAttribute('aria-pressed',density==='compact'?'true':'false');
    storeMapLabelDensity(density);
    resizeSoon();
  }
  densityButton?.addEventListener('click',()=>{
    setDensity(panel.dataset.labelDensity==='compact'?'normal':'compact');
  });
  function onFullscreenChange(){
    if(fullscreenElement()===panel){
      commit('fullscreen');
    }else if(mode==='fullscreen'){
      commit(beforeFullscreen||'standard');
    }else{
      resizeSoon();
    }
  }
  document.addEventListener('fullscreenchange',onFullscreenChange);
  document.addEventListener('webkitfullscreenchange',onFullscreenChange);
  commit(storedMapMode());
  setDensity(storedMapLabelDensity());
}
function initMap(){
  const el=document.getElementById('fleet-map');
  if(!el||!window.L){document.querySelector('[data-map-fallback]')?.style.setProperty('display','grid');return}
  const map=L.map(el,{worldCopyJump:true,scrollWheelZoom:true,zoomControl:false});
  L.control.zoom({position:'topleft'}).addTo(map);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:20,attribution:'&copy; OpenStreetMap contributors &copy; CARTO'}).addTo(map);
  const bounds=MAP_HOSTS.map(host=>[host.lat,host.lon]);
  const saved=storedViewport();
  if(saved){map.setView([saved.lat,saved.lon],saved.zoom)}
  else if(bounds.length===1){map.setView(bounds[0],5)}
  else if(bounds.length){map.fitBounds(bounds,{padding:[64,64],maxZoom:5})}
  else{map.setView([20,0],2)}
  const relayout=buildLabels(map,el);
  setupMapModes(map,el,relayout);
  map.on('moveend zoomend',()=>storeViewport(map));
  storeViewport(map);
}
window.pharosMapApplyFilter=(q='',live='all')=>{
  pendingMapFilter={q,live};
  if(applyMapFilterNow)applyMapFilterNow(q,live);
};
async function bootMap(){
  setMapLoading('loading','Loading server locations and reachability checks.');
  const target=document.querySelector('[data-site-list]');
  if(target)target.innerHTML=siteSkeleton();
  try{
    const [data]=await Promise.all([loadMapData(),loadMapAssets()]);
    MAP_HOSTS=data.hosts;
    renderSiteList(MAP_HOSTS);
    initMap();
    setMapLoading('ready','All servers stay visible; labels are separated by D3 force layout with leader lines.');
    if(typeof applySurfaceFilters==='function')applySurfaceFilters(false);
    else window.pharosMapApplyFilter(pendingMapFilter.q,pendingMapFilter.live);
  }catch(error){
    setMapLoading('error','Map data is temporarily unavailable. The rest of Pharos remains usable.');
    const fallback=document.querySelector('[data-map-fallback]');
    if(fallback)fallback.style.display='grid';
    const target=document.querySelector('[data-site-list]');
    if(target)target.innerHTML=siteError(error&&error.message);
  }
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootMap,{once:true});
else bootMap();
</script>"#;
    format!(
        r#"{HEAD}{sidebar}<main class="map-main" data-map-view="standard"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>Map</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">Server locations</p></div><div class="asof" data-as-of>as of {as_of}</div></div>{summary}{toolbar}<section class="map-layout" data-map-layout data-mode="standard"><div id="map-panel" class="map-panel" data-mode="standard" data-label-density="normal" data-loading="true" data-map-state="loading"><div class="map-mode-controls" role="group" aria-label="Map layout"><button class="map-mode-control" type="button" data-map-mode-button="standard" aria-label="Standard layout" aria-pressed="true" title="Standard layout">{standard_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="maximized" aria-label="Maximize to window" aria-pressed="false" title="Maximize to window">{maximize_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="fullscreen" aria-label="Fullscreen" aria-pressed="false" title="Fullscreen">{fullscreen_icon}</button><button class="map-mode-control map-density-control" type="button" data-map-density-button aria-label="Compact server labels" aria-pressed="false" title="Compact server labels">{compact_icon}</button></div><div id="fleet-map" class="fleet-map" aria-label="world map with server locations"></div><div class="map-loading" data-map-loading><div class="map-load-card"><strong>Preparing map</strong><p data-map-status-message>Loading server locations and reachability checks.</p><span class="map-load-rail" aria-hidden="true"></span></div></div><div class="map-fallback" data-map-fallback><div><strong>Map unavailable</strong><p>The location list remains available when data can be loaded.</p></div></div></div><aside class="site-panel" aria-label="server locations" data-site-panel data-loading="true"><div><h2>Locations</h2><p>Approximate site-level coordinates.</p></div><div class="site-list" data-site-list><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line long"></span><span class="site-skel-line medium"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line medium"></span><span class="site-skel-line long"></span><span class="site-skel-line short"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line medium"></span><span class="site-skel-line long"></span></div></div><div class="map-note" data-map-note>Loading server locations and reachability checks.</div></aside></section></main>{map_script}{FOOT}"#,
        sidebar = sidebar(user_label, logout_enabled, "map"),
        as_of = clock_label(now),
        summary = summary,
        toolbar = toolbar,
        standard_icon = icons::PANEL_RIGHT,
        maximize_icon = icons::MAXIMIZE_2,
        fullscreen_icon = icons::FULLSCREEN,
        compact_icon = icons::LIST,
    )
}

struct HeartbeatHistoryView {
    start: i64,
    span: i64,
    visible: Vec<usize>,
}

fn heartbeat_history_view(log: &[i64], window_secs: i64) -> HeartbeatHistoryView {
    if log.len() < 2 {
        return HeartbeatHistoryView {
            start: 0,
            span: 1,
            visible: Vec::new(),
        };
    }

    let latest = log[log.len() - 1];
    let start = log[0].max(latest - window_secs.max(1));
    let span = (latest - start).max(1);
    let candidates = log
        .iter()
        .enumerate()
        .filter_map(|(idx, stamp)| {
            if idx > 0 && *stamp >= start && *stamp <= latest {
                Some(idx)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if candidates.len() <= HEARTBEAT_HISTORY_DOTS {
        return HeartbeatHistoryView {
            start,
            span,
            visible: candidates,
        };
    }

    let mut buckets = vec![None; HEARTBEAT_HISTORY_DOTS];
    for idx in candidates {
        let raw_bucket = (((log[idx] - start) as f64 / span as f64) * HEARTBEAT_HISTORY_DOTS as f64)
            .floor() as usize;
        let bucket = raw_bucket.min(HEARTBEAT_HISTORY_DOTS - 1);
        buckets[bucket] = Some(idx);
    }

    HeartbeatHistoryView {
        start,
        span,
        visible: buckets.into_iter().flatten().collect(),
    }
}

fn heartbeat_visible_log(log: &[i64], window_secs: i64) -> Vec<i64> {
    let view = heartbeat_history_view(log, window_secs);
    view.visible.into_iter().map(|idx| log[idx]).collect()
}

fn heartbeat_history(log: &[i64], idx: usize, interval: i64) -> (&'static str, String, String) {
    let stamp = log[idx];
    let Some(previous) = idx.checked_sub(1).and_then(|previous| log.get(previous)) else {
        return (
            "first",
            "first heartbeat".to_string(),
            format!("at {}", clock_label(stamp)),
        );
    };
    let gap = (stamp - previous).max(0);
    let interval = interval.max(1);
    let (level, label) = if gap <= interval {
        ("ok", "on cadence")
    } else if gap <= interval * 2 {
        ("late", "late heartbeat")
    } else if gap <= interval * 5 {
        ("stale", "stale gap recovered")
    } else {
        ("down", "offline gap recovered")
    };
    (
        level,
        label.to_string(),
        format!(
            "{} after previous · {}",
            duration_label(gap),
            clock_label(stamp)
        ),
    )
}

fn heartbeat_marks(log: &[i64], interval: i64, window_secs: i64) -> String {
    if log.len() < 2 {
        return String::new();
    }

    let interval = interval.max(1);
    let step = HEARTBEAT_EXPECT_X / HEARTBEAT_HISTORY_DOTS.max(1) as f64;
    let newest_x = HEARTBEAT_EXPECT_X - step;
    let view = heartbeat_history_view(log, window_secs);
    let mut marks = String::new();
    for idx in view.visible {
        let x = (((log[idx] - view.start).max(0) as f64 / view.span as f64) * newest_x)
            .clamp(0.0, newest_x);
        let (level, label, detail) = heartbeat_history(log, idx, interval);
        let title = format!("{label} · {detail}");
        marks.push_str(&format!(
            r#"<span class="beat-mark" tabindex="0" data-history-level="{level}" data-history-label="{label}" data-history-detail="{detail}" title="{title}" aria-label="{title}" style="--mark-x:{x:.1}%"></span>"#,
            level = html_escape(level),
            label = html_escape(&label),
            detail = html_escape(&detail),
            title = html_escape(&title)
        ));
    }
    marks
}

fn heartbeat_x(age: i64, interval: i64) -> f64 {
    let age = age.max(0) as f64;
    let interval = interval.max(1) as f64;
    if age <= interval {
        return (age / interval) * HEARTBEAT_EXPECT_X;
    }
    if age <= interval * 2.0 {
        return HEARTBEAT_EXPECT_X + ((age - interval) / interval) * 18.0;
    }
    if age <= interval * 5.0 {
        return HEARTBEAT_STALE_X + ((age - interval * 2.0) / (interval * 3.0)) * 18.0;
    }
    100.0
}

fn heartbeat_card(
    last_seen: Option<i64>,
    heartbeat_log: &[i64],
    interval_secs: Option<u64>,
    now: i64,
    is_self: bool,
) -> String {
    let interval = i64::try_from(interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    let all_beats = heartbeat_samples(heartbeat_log, last_seen);
    let visible_beats = heartbeat_visible_log(&all_beats, SIGNAL_DEFAULT_WINDOW_SECS);
    let beats_attr = visible_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let signal_beats_attr = all_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let marks = heartbeat_marks(&all_beats, interval, SIGNAL_DEFAULT_WINDOW_SECS);
    let (last_attr, next_at_attr, beat_state, now_x, fill_color, expect_fill, target_ring) =
        match last_seen {
            Some(last) => {
                let age = (now - last).max(0);
                let progress = (age as f64 / interval as f64).clamp(0.0, 1.0);
                if age <= interval {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        if is_self { "lit" } else { "tracking" },
                        heartbeat_x(age, interval),
                        if is_self { "var(--sun)" } else { "var(--sea)" },
                        progress * 360.0,
                        3.0 + progress * 5.0,
                    )
                } else if age <= interval * 2 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "late",
                        heartbeat_x(age, interval),
                        "var(--sun)",
                        360.0,
                        8.0,
                    )
                } else if age <= interval * 5 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "stale",
                        heartbeat_x(age, interval),
                        "var(--stale)",
                        360.0,
                        8.0,
                    )
                } else {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "down",
                        100.0,
                        "var(--down)",
                        360.0,
                        8.0,
                    )
                }
            }
            None => (
                "".to_string(),
                "".to_string(),
                "waiting",
                0.0,
                "var(--wait)",
                0.0,
                3.0,
            ),
        };
    let self_attr = if is_self { r#" data-self="true""# } else { "" };
    format!(
        r#"<div class="beat" data-beat="{beat_state}" data-count="{count}" data-last="{last_attr}" data-interval="{interval}" data-next-at="{next_at_attr}" data-beats="{beats_attr}" data-signal-beats="{signal_beats_attr}" data-history-window="{history_window}" style="--now-x:{now_x:.2}%;--fill-color:{fill_color};--expect-fill:{expect_fill:.1}deg;--target-ring:{target_ring:.1}px"{self_attr}><div class="beat-stage" aria-label="heartbeat timeline"><span class="beat-floor"></span><span class="beat-fill"></span><span class="beat-current"></span><span class="beat-marks">{marks}</span><span class="beat-threshold expected"></span><span class="beat-threshold stale"></span><span class="beat-now"></span><span class="beat-hit"></span><span class="beat-zones"><span data-history-window-label>{history_window}</span><span>expected</span><span>late</span></span></div></div>"#,
        count = visible_beats.len(),
        history_window = html_escape(SIGNAL_DEFAULT_WINDOW_LABEL)
    )
}

fn render_home(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    shell: ShellContext<'_>,
    can_onboard: bool,
) -> String {
    let hosts = runtime.hosts;
    let setup_jobs = pending_setup_jobs(runtime.hosts, runtime.jobs);
    if runtime.hosts.is_empty() && setup_jobs.is_empty() {
        let assistant = if can_onboard {
            setup_assistant()
        } else {
            String::new()
        };
        return format!(
            "{HEAD}{sidebar}<main>{header}{empty}</main>{assistant}{FOOT}",
            sidebar = sidebar(shell.user_label, shell.logout_enabled, "fleet"),
            header = header(now),
            empty = empty_state(can_onboard),
            assistant = assistant
        );
    }

    let palette_colors = manifest_palette_color(manifests);
    let mut sorted: Vec<&Host> = hosts.iter().collect();
    sorted.sort_by_key(|h| {
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let rank = attention_reason(live, &h.freshness, &h.service_observations).rank;
        (rank, h.name.clone())
    });

    let mut cards = String::new();
    let mut rows = String::new();
    for h in sorted {
        let is_self = h.name == self_name;
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let (_color, word) = live.badge();
        let nix_icon = if h.is_nix {
            icons::SNOWFLAKE
        } else {
            icons::SERVER
        };
        let name = html_escape(&h.name);
        let role = html_escape(&h.role);
        let fresh_tldr = h.freshness.tldr();
        let fresh = freshness_markup(&h.freshness);
        let attention = attention_reason(live, &h.freshness, &h.service_observations);
        let reason = reason_markup(&attention);
        let backup = backup_ui_summary(&h.backup_observations, now);
        let backup_card = backup_card_markup(&backup, "");
        let backup_list = backup_card_markup(&backup, "backup-list");
        let protection = protection_onboarding_status(h, runtime.jobs, now);
        let protection_card = protection
            .as_ref()
            .map(|status| protection_onboarding_markup(status, ""))
            .unwrap_or_default();
        let protection_list = protection
            .as_ref()
            .map(|status| protection_onboarding_markup(status, "protection-list"))
            .unwrap_or_default();
        let mut search_parts = vec![format!(
            "{} {} {} {}",
            h.name.to_lowercase(),
            h.role.to_lowercase(),
            fresh_tldr.to_lowercase(),
            attention.label.to_lowercase()
        )];
        if let Some(backup_text) = backup_search_text(&backup) {
            search_parts.push(backup_text.to_lowercase());
        }
        if let Some(status) = &protection {
            search_parts.push(status.search_text().to_lowercase());
        }
        let search = html_escape(&search_parts.join(" "));
        let sort_name = html_escape(&h.name.to_lowercase());
        let last_sort = h.last_seen.unwrap_or(0);
        let sev = attention.rank;
        let seen = match h.last_seen {
            Some(t) => format!("last seen {} ago", duration_label(now - t)),
            None => "never seen".to_string(),
        };
        let light_cls = if is_self { " light" } else { "" };
        let self_attr = if is_self { r#" data-self="true""# } else { "" };
        let beam = if is_self {
            format!(
                r#"<span class="pharos-mark" aria-hidden="true">{}</span>"#,
                icons::LIGHTHOUSE
            )
        } else {
            String::new()
        };
        let settings_href = html_escape(&format!("/agora?host={}", url_query_escape(&h.name)));
        let settings_color = palette_colors.get(&h.name).map(|color| html_escape(color));
        let settings_cls = if settings_color.is_some() {
            " has-settings"
        } else {
            ""
        };
        let host_color_style = settings_color
            .as_ref()
            .map(|color| format!(r#" style="--host-color:{color}""#))
            .unwrap_or_default();
        let settings_action = if settings_color.is_some() {
            format!(
                r#"<a class="settings-card" href="{settings_href}" title="Open color settings for {name}" aria-label="Open color settings for {name}"><span class="settings-icon">{icon}</span></a>"#,
                icon = icons::SLIDERS
            )
        } else {
            format!(
                r#"<a class="settings-card unavailable" href="{settings_href}" title="Prepare color settings for {name}" aria-label="Prepare color settings for {name}"><span class="settings-icon">{icon}</span></a>"#,
                icon = icons::SLIDERS
            )
        };
        let drag_action = format!(
            r#"<button class="drag-handle" type="button" data-drag-handle title="Move {name}" aria-label="Move {name}">{icon}</button>"#,
            icon = icons::GRIP
        );
        let status_word = word;
        let status_icon = status_icon_stack();
        let heartbeat = heartbeat_card(
            h.last_seen,
            &h.heartbeat_log,
            h.heartbeat_interval_secs,
            now,
            is_self,
        );
        let interval = i64::try_from(h.heartbeat_interval_secs.unwrap_or(60))
            .unwrap_or(60)
            .max(1);
        let signal = signal_markup(&heartbeat_signal(
            &h.heartbeat_log,
            h.last_seen,
            interval,
            now,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        ));
        let row_cls = format!("{light_cls}{settings_cls}").trim().to_string();
        cards.push_str(&format!(
            r#"<article class="card{light_cls}{settings_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime"{self_attr}{host_color_style}>{beam}<header class="card-head"><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div><div class="card-actions">{drag_action}{settings_action}</div></header>{reason}<div class="fresh" data-fresh>{fresh}</div>{backup_card}{protection_card}<div class="meta"><span data-seen>{seen}</span><span data-card-asof>as of {as_of}</span></div>{heartbeat}<div class="card-tools">{signal}</div></article>"#,
            live_key = live_key(live),
            as_of = clock_label(now)
        ));
        rows.push_str(&format!(
            r#"<tr class="{row_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime"{self_attr}{host_color_style}><td><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div></td><td><span class="status-pill" aria-label="status: {status_word}">{status_icon}<span class="word" data-status-word>{status_word}</span></span></td><td>{reason}</td><td>{backup_list}{protection_list}</td><td><div class="fresh" data-fresh>{fresh}</div></td><td><span data-seen>{seen}</span></td><td>{heartbeat}</td><td>{settings_action}</td></tr>"#,
            live_key = live_key(live),
        ));
    }
    for job in setup_jobs {
        cards.push_str(&render_setup_card(job, now));
        rows.push_str(&render_setup_row(job, now));
    }

    let lone = if hosts.len() == 1 {
        lone_host_state(can_onboard)
    } else {
        String::new()
    };
    if can_onboard {
        cards.push_str(&onboard_tile());
        rows.push_str(&onboard_row());
    }
    let assistant = if can_onboard {
        setup_assistant()
    } else {
        String::new()
    };

    format!(
        "{HEAD}{sidebar}<main data-view=\"grid\">{header}{summary}{toolbar}<div class=\"grid\" data-grid>{cards}</div><section class=\"list-wrap\"><table class=\"list\"><thead><tr><th>Host</th><th>Status</th><th>Attention</th><th>Backup</th><th>Freshness</th><th>Last seen</th><th>Heartbeat</th><th>Actions</th></tr></thead><tbody data-list-body>{rows}</tbody></table></section>{lone}</main>{assistant}{FOOT}",
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "fleet"),
        header = header(now),
        summary = summary_cards(hosts, self_name, now),
        toolbar = toolbar(),
        assistant = assistant
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let host_store_path = std::env::var("PHAROS_DB").ok().map(PathBuf::from);
    let provisioning_job_store_path = provisioning_jobs_path(host_store_path.as_deref());
    let store = Arc::new(Store::new(host_store_path));
    let provisioning_jobs = Arc::new(ProvisioningJobStore::new(provisioning_job_store_path));
    let manifests = Arc::new(ManifestRegistry::from_env());
    let auth = Auth::from_env().await;
    let beacon_auth = BeaconAuth::from_env();
    let provider_runtime = ProviderRuntimeConfig::from_env();
    let alert_notifier = AlertNotifier::from_env();
    let state = AppState {
        store,
        provisioning_jobs,
        manifests,
        auth,
        beacon_auth,
        provider_runtime,
    };
    spawn_alert_loop(state.clone(), alert_notifier);

    let app = Router::new()
        // Human routes — gated by OIDC when configured (open otherwise).
        .route("/", get(home))
        .route("/map", get(map_page))
        .route("/map/data.json", get(map_data_json))
        .route("/alerts", get(alerts_page))
        .route("/backups", get(backups_page))
        .route("/activity", get(activity_page))
        .route("/agora", get(agora::page))
        .route(
            "/agora/proposals/host-palette.json",
            get(agora::palette_proposal),
        )
        .route(
            "/agora/proposals/host-location.json",
            get(agora::location_proposal),
        )
        .route("/hosts.json", get(hosts_json))
        .route("/setup/provider-plan.json", get(setup_provider_plan_json))
        .route("/setup/provisioning-jobs", post(create_provisioning_job))
        .route("/setup/provisioning-jobs/{id}", get(provisioning_job_json))
        .route(
            "/setup/existing-host/preflight",
            post(existing_host_preflight_json),
        )
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        // Machine/public routes: beacon ingestion, local registration, health,
        // version, declared manifests, and the auth flow.
        .route("/declared-hosts.json", get(declared_hosts_json))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/favicon.svg", get(favicon_svg))
        .route("/assets/fleet-horizon.png", get(fleet_horizon_asset))
        .route(
            "/assets/sidebar-lighthouse.png",
            get(sidebar_lighthouse_asset),
        )
        .route("/register", post(register))
        .route("/report", post(report))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", get(auth::logout))
        .route("/auth/logged-out", get(auth::logged_out))
        .with_state(state);

    let addr = std::env::var("PHAROS_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind PHAROS_ADDR");
    tracing::info!(
        "pharosd v{} listening on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backup_observation(state: BackupPostureState) -> BackupObservation {
        BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: pharos_core::BackupEngine::Restic,
            state,
            configured: pharos_core::BackupConfiguredState::Enabled,
            summary: "last backup succeeded".to_string(),
            target_label: Some("off-box repository".to_string()),
            repository_id: Some("restic-main-repository".to_string()),
            schedule: Some("hourly".to_string()),
            next_run_at: None,
            last_attempt_at: Some(1_700_000_000),
            last_attempt_state: Some(pharos_core::BackupRunState::Succeeded),
            last_success_at: Some(1_700_000_000),
            snapshot_count: Some(3),
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: Some(1_700_000_100),
            last_check_state: Some(pharos_core::BackupValidationState::Passed),
            restore_validation: Some(pharos_core::BackupValidationObservation {
                level: pharos_core::BackupValidationLevel::RepositoryCheck,
                state: pharos_core::BackupValidationState::Passed,
                checked_at: Some(1_700_000_100),
                evidence_label: Some("repo check".to_string()),
                summary: None,
            }),
        }
    }

    fn setup_job(
        host_name: &str,
        state: ProvisioningJobState,
        created_at: i64,
        updated_at: i64,
        setup_intent: ProvisioningSetupIntent,
    ) -> ProvisioningJob {
        ProvisioningJob {
            schema: PROVISIONING_JOB_SCHEMA.to_string(),
            version: PROVISIONING_JOB_VERSION,
            id: format!("setup-{created_at}-test"),
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            host_name: Some(host_name.to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            state,
            created_at,
            updated_at,
            handoff: None,
            setup_intent: Some(setup_intent),
            backup_proposal: None,
            progress: vec![ProvisioningProgressEntry {
                state,
                message: match state {
                    ProvisioningJobState::WaitingForHeartbeat => {
                        "Waiting for file/env-file beacon handoff and first heartbeat."
                    }
                    ProvisioningJobState::Failed => {
                        "Setup could not continue; no host services were changed."
                    }
                    ProvisioningJobState::BackupPending => {
                        "First heartbeat seen; waiting for backup posture."
                    }
                    _ => "Setup progress recorded.",
                }
                .to_string(),
                observed_at: updated_at,
            }],
        }
    }

    fn host_with_backups(
        name: &str,
        last_seen: i64,
        backup_observations: Vec<BackupObservation>,
    ) -> Host {
        Host {
            name: name.to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(last_seen),
            heartbeat_log: vec![last_seen],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness::default(),
            service_observations: vec![],
            backup_observations,
        }
    }

    fn runtime<'a>(hosts: &'a [Host], jobs: &'a [ProvisioningJob]) -> RuntimeSnapshot<'a> {
        RuntimeSnapshot { hosts, jobs }
    }

    fn shell(user_label: &str, logout_enabled: bool) -> ShellContext<'_> {
        ShellContext {
            user_label,
            logout_enabled,
        }
    }

    #[tokio::test]
    async fn favicon_serves_pharos_lighthouse_svg() {
        let response = favicon_svg().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("favicon body");
        let svg = std::str::from_utf8(&body).expect("favicon is utf8 svg");
        assert!(svg.contains(r#"<svg xmlns="http://www.w3.org/2000/svg""#));
        assert!(svg.contains(r##"stroke="#d69b31""##));
        assert!(svg.contains(r#"M10.5 5 12 2.5 13.5 5"#));
    }

    #[tokio::test]
    async fn existing_host_preflight_keeps_unknowns_read_only() {
        let request = ExistingHostPreflightRequest {
            schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
            version: EXISTING_HOST_PREFLIGHT_VERSION,
            host_name: "legacy-1".to_string(),
            ssh: pharos_core::SshAccessIntent {
                route: SshRoute::None,
                user: None,
                host: None,
                port: None,
            },
            facts: ExistingHostPreflightFacts::default(),
            pharos_url: None,
        };

        let report = existing_host_preflight_report(&request, 1_700_000_000).await;

        report.validate_contract().expect("report contract valid");
        assert_eq!(report.summary.state, PreflightCheckState::Unknown);
        assert_eq!(
            report.next_action,
            "Collect SSH, privilege, OS, disk, and host-to-Pharos facts."
        );
        assert!(report.checks.iter().any(|check| {
            check.key == "ssh-reachability" && check.state == PreflightCheckState::Unknown
        }));
        assert!(report
            .bootstrap_options
            .iter()
            .any(|option| option.method == BootstrapMethod::Manual && option.available));
        assert!(!serde_json::to_string(&report)
            .expect("report serializes")
            .to_ascii_lowercase()
            .contains("token="));
    }

    #[tokio::test]
    async fn existing_host_preflight_offers_automated_paths_when_ready() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test listener");
        let port = listener.local_addr().expect("listener addr").port();
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });
        let request = ExistingHostPreflightRequest {
            schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
            version: EXISTING_HOST_PREFLIGHT_VERSION,
            host_name: "legacy-2".to_string(),
            ssh: pharos_core::SshAccessIntent {
                route: SshRoute::Direct,
                user: Some("mba".to_string()),
                host: Some("127.0.0.1".to_string()),
                port: Some(port),
            },
            facts: ExistingHostPreflightFacts {
                ssh_authenticated: Some(true),
                root: Some(false),
                sudo: Some(true),
                os_family: Some("linux".to_string()),
                nixos: Some(true),
                nix_available: Some(true),
                free_disk_gib: Some(16),
                pharos_reachable: Some(true),
            },
            pharos_url: Some("https://pharos.barta.cm/report".to_string()),
        };

        let report = existing_host_preflight_report(&request, 1_700_000_001).await;
        let _ = accept.await;

        report.validate_contract().expect("report contract valid");
        assert_eq!(report.summary.state, PreflightCheckState::Pass);
        assert_eq!(
            report.next_action,
            "Choose NixOS/declarative or native beacon bootstrap."
        );
        assert!(report
            .bootstrap_options
            .iter()
            .any(|option| { option.method == BootstrapMethod::NixosAnywhere && option.available }));
        let native = report
            .bootstrap_options
            .iter()
            .find(|option| option.method == BootstrapMethod::NativeSystemd)
            .expect("native beacon option");
        assert!(native.available);
        assert!(native
            .token_handoff
            .as_deref()
            .is_some_and(|handoff| handoff.contains("env-file")));
        assert!(native
            .existing_token_policy
            .as_deref()
            .is_some_and(|policy| policy.contains("rotation-sensitive")));
    }

    #[test]
    fn existing_host_ssh_probe_output_is_sanitized_facts() {
        let facts = parse_existing_host_ssh_probe_stdout(
            b"ssh_authenticated=true\nroot=false\nsudo=true\nos_family=ubuntu\nnixos=false\nnix_available=true\nfree_disk_gib=42\npharos_reachable=true\nignored=value\n",
        );

        assert_eq!(facts.ssh_authenticated, Some(true));
        assert_eq!(facts.root, Some(false));
        assert_eq!(facts.sudo, Some(true));
        assert_eq!(facts.os_family.as_deref(), Some("ubuntu"));
        assert_eq!(facts.nixos, Some(false));
        assert_eq!(facts.nix_available, Some(true));
        assert_eq!(facts.free_disk_gib, Some(42));
        assert_eq!(facts.pharos_reachable, Some(true));
    }

    #[test]
    fn existing_host_probe_does_not_override_operator_facts() {
        let base = ExistingHostPreflightFacts {
            ssh_authenticated: Some(true),
            root: None,
            sudo: Some(false),
            os_family: None,
            nixos: None,
            nix_available: None,
            free_disk_gib: None,
            pharos_reachable: None,
        };
        let probe = ExistingHostPreflightFacts {
            ssh_authenticated: Some(false),
            root: Some(false),
            sudo: Some(true),
            os_family: Some("linux".to_string()),
            nixos: Some(false),
            nix_available: Some(true),
            free_disk_gib: Some(12),
            pharos_reachable: Some(true),
        };

        let merged = merge_preflight_facts(base, probe);

        assert_eq!(merged.ssh_authenticated, Some(true));
        assert_eq!(merged.sudo, Some(false));
        assert_eq!(merged.root, Some(false));
        assert_eq!(merged.os_family.as_deref(), Some("linux"));
        assert_eq!(merged.free_disk_gib, Some(12));
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(
            shell_single_quote("https://pharos.example/a'b"),
            "'https://pharos.example/a'\"'\"'b'"
        );
    }

    #[test]
    fn render_home_includes_lighthouse_and_heartbeat_markup() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "hades".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(879),
                heartbeat_log: vec![760, 819, 879],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "poseidon".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
                backup_observations: vec![],
            },
        ];

        let html = render_home(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains(r#"<section class="toolbar""#));
        assert!(html.contains(r#"data-view-button="list""#));
        assert!(html.contains(r#"<option value="freeform">Freeform</option>"#));
        assert!(html.contains("pharos_freeform_order_v1"));
        assert!(html.contains("bindFreeformDrag();"));
        assert!(html.contains(r#"data-drag-handle title="Move poseidon""#));
        assert!(html.contains(r#"<table class="list">"#));
        assert!(
            html.contains(r#"<span class="side-user" title="markus"><span>markus</span></span>"#)
        );
        assert!(html.contains(r#"href="/" aria-current="page""#));
        assert!(html.contains(r#"href="/map""#));
        assert!(html.contains(r#"href="/backups""#));
        assert!(html.contains(r#"href="/auth/logout""#));
        assert!(html.contains(r#"aria-label="Log out of Pharos""#));
        assert!(!html.contains(">mba<"));
        assert!(html.contains("cache:'no-store'"));
        assert!(html.contains("'/hosts.json?refresh='+Date.now()"));
        assert!(html.contains("credentials:'same-origin'"));
        assert!(html.contains("let refreshGeneration=0;"));
        assert!(html.contains("generation!==refreshGeneration"));
        assert!(html.contains("refreshGeneration++;"));
        assert!(html.contains("document.addEventListener('visibilitychange'"));
        assert!(html.contains("window.addEventListener('focus'"));
        assert!(html.contains("window.addEventListener('pageshow'"));
        assert!(html.contains("window.addEventListener('online'"));
        assert!(html.contains("scheduleRefresh(3000);"));
        assert!(!html.contains("setInterval(refresh,10000)"));
        assert!(html.contains(r#"data-host="csb1" data-live="live""#));
        assert!(html.contains(r#"data-self="true""#));
        assert!(html.contains(r#"class="pharos-mark""#));
        assert!(!html.contains("the light is lit"));
        assert!(html.contains(r#"<th>Attention</th>"#));
        assert!(html.contains(r#"<th>Backup</th>"#));
        assert!(html.contains(r#"<th>Actions</th>"#));
        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(!html.contains("No settings yet"));
        assert!(!html.contains("Not set up yet"));
        assert!(!html.contains("control light"));
        assert!(!html.contains("expected beat"));
        assert!(html.contains(r#"class="signal" data-signal data-signal-level="good""#));
        assert!(html.contains(r#"<span data-signal-percent>100%</span>"#));
        assert!(html.contains(
            r#"<span data-signal-percent>100%</span><span class="signal-orb" aria-hidden="true"></span><button class="signal-window""#
        ));
        assert!(html.contains(r#"<button class="signal-window" type="button" data-signal-window"#));
        assert!(html.contains(r#"data-signal-window-key="10m""#));
        assert!(html.contains(r#"data-beats="910,970""#));
        assert!(html.contains(r#"data-signal-beats="850,910,970""#));
        assert!(html.contains(r#"data-history-window="10m""#));
        assert!(html.contains(r#"<span data-history-window-label>10m</span>"#));
        assert!(
            !html.contains(r#"<span class="beat-mark" tabindex="0" data-history-level="first""#)
        );
        assert!(html.contains(r#"data-history-level="ok""#));
        assert!(html.contains(r#"data-history-label="on cadence""#));
        assert!(html.contains(r#"--mark-x:29.3%""#));
        assert!(html.contains(r#"--mark-x:58.7%""#));
        assert!(!html.contains(r#"--mark-x:64.0%""#));
        assert!(html.contains("Flake.lock age"));
        assert!(html.contains(r#"<strong class="warn">1d</strong>"#));
        assert!(html.contains("Commits behind"));
        assert!(html.contains(r#"<strong class="warn">3</strong>"#));
        assert!(html.contains("beat-fill"));
        assert!(html.contains("beat-now"));
        assert!(html.contains("beat-current"));
        assert!(html.contains("beat-zones"));
        assert!(html.contains("nix drift: 1d"));
        assert!(html.contains("3 commits"));
        assert!(html.contains(r#"data-search="poseidon nixos host flake.lock 1d old · 3 commits behind nixcfg nix drift: 1d · 3 commits""#));
        assert!(html.contains(r#"data-host="poseidon" data-live="live" data-sev="3""#));
        assert!(html.contains(r#"data-host="hades" data-live="stale""#));
        assert!(html.contains(r#"data-sev="1""#));
        assert!(html.contains("state-icon stale"));
    }

    #[test]
    fn render_home_surfaces_backup_posture_in_grid_and_list() {
        let host = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1_700_000_100),
            heartbeat_log: vec![1_700_000_040, 1_700_000_100],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
        };

        let html = render_home(
            runtime(&[host], &[]),
            "csb1",
            1_700_000_120,
            &[],
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"data-backup-state="healthy""#));
        assert!(html.contains(">Protected<"));
        assert!(html.contains("last success 2m 00s ago"));
        assert!(html.contains(r#"class="backup-mini backup-list clear""#));
        assert!(html.contains("off-box repository"));
        assert!(!html.contains("restic-main-repository"));
    }

    #[test]
    fn render_backups_shows_first_class_backup_page() {
        let host = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1_700_000_100),
            heartbeat_log: vec![1_700_000_040, 1_700_000_100],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
        };

        let html = render_backups(
            &[host],
            1_700_000_120,
            ShellContext {
                user_label: "markus",
                logout_enabled: true,
            },
        );

        assert!(html.contains(r#"<h1>Backups</h1>"#));
        assert!(html.contains(r#"href="/backups" aria-current="page""#));
        assert!(html.contains(r#"data-ops-page="backups""#));
        assert!(html.contains(r#"data-ops-filter="clear""#));
        assert!(html.contains(r#"class="backup-row clear""#));
        assert!(html.contains("Last success"));
        assert!(html.contains("Schedule"));
        assert!(html.contains("Target"));
        assert!(html.contains("Validation"));
        assert!(html.contains("repo check passed"));
        assert!(html.contains("off-box repository"));
        assert!(!html.contains("restic-main-repository"));
    }

    #[test]
    fn backup_page_search_includes_restore_validation_evidence() {
        let mut observation = backup_observation(BackupPostureState::Healthy);
        observation.restore_validation = Some(pharos_core::BackupValidationObservation {
            level: pharos_core::BackupValidationLevel::RestoreSample,
            state: pharos_core::BackupValidationState::Stale,
            checked_at: Some(1_700_000_050),
            evidence_label: Some("restore sample".to_string()),
            summary: Some("restore drill overdue".to_string()),
        });
        let host = host_with_backups("athena", 1_700_000_100, vec![observation]);

        let html = render_backups(
            &[host],
            1_700_000_120,
            ShellContext {
                user_label: "markus",
                logout_enabled: true,
            },
        );
        let row_search = html
            .split("data-host-search=\"")
            .nth(1)
            .expect("backup row search haystack")
            .split('"')
            .next()
            .expect("backup row search value");

        assert!(html.contains("Last success"));
        assert!(html.contains("Validation"));
        assert!(html.contains("restore sample stale"));
        assert!(row_search.contains("restore sample stale"));
    }

    #[test]
    fn validation_alerts_are_separate_from_successful_backup_alerts() {
        let mut observation = backup_observation(BackupPostureState::Healthy);
        observation.restore_validation = Some(pharos_core::BackupValidationObservation {
            level: pharos_core::BackupValidationLevel::RestoreSample,
            state: pharos_core::BackupValidationState::Failed,
            checked_at: Some(1_700_000_050),
            evidence_label: Some("restore sample".to_string()),
            summary: Some("restore sample failed".to_string()),
        });
        let host = host_with_backups("csb1", 1_700_000_100, vec![]);

        assert!(backup_alert(&host, &observation, 1_700_000_120).is_none());
        let alert = backup_validation_alert(&host, &observation, 1_700_000_120)
            .expect("failed validation alert");

        assert_eq!(alert.level, "critical");
        assert_eq!(alert.source, "backup");
        assert_eq!(alert.issue, "Restic main: Restore validation failed");
        assert!(alert.detail.contains("restore sample"));
        assert!(alert.next_action.contains("validation evidence"));
    }

    #[test]
    fn repository_check_state_can_raise_validation_overdue_alert() {
        let mut observation = backup_observation(BackupPostureState::Healthy);
        observation.restore_validation = None;
        observation.last_check_at = Some(1_700_000_050);
        observation.last_check_state = Some(pharos_core::BackupValidationState::Stale);
        let host = host_with_backups("csb1", 1_700_000_100, vec![]);

        assert!(backup_alert(&host, &observation, 1_700_000_120).is_none());
        let alert = backup_validation_alert(&host, &observation, 1_700_000_120)
            .expect("stale repository check alert");

        assert_eq!(alert.level, "warning");
        assert_eq!(alert.issue, "Restic main: Restore validation overdue");
        assert!(alert.detail.contains("backup check"));
        assert!(alert.next_action.contains("restore validation"));
    }

    #[test]
    fn hosts_payload_exposes_backup_runtime_overlay() {
        let host = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("not-rendered-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
        };

        let payload = hosts_payload(vec![host], &[], 1000);

        assert_eq!(payload["as_of"], 1000);
        assert_eq!(
            payload["hosts"][0]["backup_observations"][0]["id"],
            "restic-main"
        );
        assert_eq!(
            payload["hosts"][0]["backup_observations"][0]["restore_validation"]["level"],
            "repository-check"
        );
        assert_eq!(
            payload["hosts"][0]["backup_observations_summary"]["state"],
            "healthy"
        );
        assert_eq!(
            payload["hosts"][0]["backup_observations_summary"]["label"],
            "healthy"
        );
        assert_eq!(
            payload["hosts"][0]["backup_observations_summary"]["total"],
            1
        );
        assert!(!payload.to_string().contains("not-rendered-token-hash"));
    }

    #[test]
    fn render_alerts_derives_actionable_attention_queue() {
        let mut failed_backup = backup_observation(BackupPostureState::Failed);
        failed_backup.summary = "backup command failed".to_string();
        failed_backup.last_attempt_at = Some(940);
        failed_backup.last_attempt_state = Some(pharos_core::BackupRunState::Failed);
        failed_backup.last_success_at = None;
        failed_backup.restore_validation = None;

        let mut stale_validation = backup_observation(BackupPostureState::Healthy);
        stale_validation.restore_validation = Some(pharos_core::BackupValidationObservation {
            level: pharos_core::BackupValidationLevel::RestoreSample,
            state: pharos_core::BackupValidationState::Stale,
            checked_at: Some(900),
            evidence_label: Some("restore sample".to_string()),
            summary: Some("restore drill is overdue".to_string()),
        });

        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "control".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
                backup_observations: vec![failed_backup],
            },
            Host {
                name: "poseidon".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: Some("not-rendered-token-hash".to_string()),
                last_seen: Some(500),
                heartbeat_log: vec![380, 440, 500],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
                backup_observations: vec![stale_validation],
            },
            Host {
                name: "athena".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(2),
                    commits_behind: Some(3),
                },
                service_observations: vec![
                    ServiceObservation::nix_freshness(&NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(2),
                        commits_behind: Some(3),
                    }),
                    ServiceObservation {
                        id: "nginx".to_string(),
                        label: "nginx".to_string(),
                        state: ServiceObservationState::Warning,
                        summary: "response is slow".to_string(),
                    },
                ],
                backup_observations: vec![],
            },
            Host {
                name: "hermes".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(2),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
                backup_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8", "role": "parents home" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let load_error = ManifestLoadIssue {
            path: "/etc/pharos/hosts/broken.json".to_string(),
            error: "failed to parse manifest JSON".to_string(),
        };
        let mut probes = BTreeMap::new();
        probes.insert(
            "hsb8".to_string(),
            vec![ServerProbeObservation {
                id: "home-assistant".to_string(),
                service: "Home Assistant".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("http://hsb8.lan:8123/".to_string()),
                state: ServiceObservationState::Warning,
                server_reachable: Some(false),
                client_reachable: None,
                summary: "server probe timed out".to_string(),
                checked_at: 995,
            }],
        );

        let html = render_alerts(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            &[manifest],
            &[load_error],
            &probes,
            shell("markus", true),
        );

        assert!(html.contains(r#"href="/alerts" aria-current="page""#));
        assert!(html.contains(r#"<h1>Alerts</h1>"#));
        assert!(html.contains("Needs attention"));
        assert!(html.contains("Declared host manifest failed to load"));
        assert!(html.contains("No heartbeat received"));
        assert!(html.contains("Check host power, network, and pharos-beacon."));
        assert!(html.contains("3 commits behind nixcfg"));
        assert!(html.contains(r#"<span class="alert-repeat">2 alerts</span>"#));
        assert!(html.contains("athena, hermes"));
        assert!(html.contains("nginx: warning"));
        assert!(html.contains("Restic main: Backup failed"));
        assert!(html.contains("backup command failed"));
        assert!(html.contains("Inspect the backup job"));
        assert!(html.contains("Restic main: Restore validation overdue"));
        assert!(html.contains("restore sample - restore drill is overdue"));
        assert!(html.contains(r#"data-ops-kind="backup""#));
        assert!(!html.contains("Nix freshness: warning"));
        assert!(html.contains("Home Assistant probe warning"));
        assert!(html.contains("Install or start pharos-beacon"));
        assert!(html.contains("Operations posture"));
        assert!(html.contains(r#"class="ops-action" href="/map">View on map</a>"#));
        assert!(html.contains(
            r#"<button class="ops-metric critical" type="button" data-ops-filter="critical""#
        ));
        assert!(html.contains(r#"data-ops-filter="warning""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-host-search="athena server hermes server"#));
        assert!(html.contains(r#"class="posture-ring" type="button" data-ops-filter="critical""#));
        assert!(html.contains(r#"<strong>3</strong><span>critical</span>"#));
        assert!(html.contains("Repeated alerts are grouped."));
        assert!(html.contains("const filterOk=active==='all'"));
        assert!(!html.contains("restic-main-repository"));
        assert!(!html.contains("not-rendered-token-hash"));
    }

    #[test]
    fn render_activity_derives_operational_timeline() {
        let mut healthy_backup = backup_observation(BackupPostureState::Healthy);
        healthy_backup.last_attempt_at = Some(940);
        healthy_backup.last_success_at = Some(940);
        healthy_backup.last_check_at = Some(950);
        healthy_backup.restore_validation = Some(pharos_core::BackupValidationObservation {
            level: pharos_core::BackupValidationLevel::RepositoryCheck,
            state: pharos_core::BackupValidationState::Passed,
            checked_at: Some(950),
            evidence_label: Some("repo check".to_string()),
            summary: Some("repository check passed".to_string()),
        });

        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "control".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(1000),
                heartbeat_log: vec![880, 940, 1000],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(0),
                    commits_behind: Some(0),
                },
                service_observations: vec![],
                backup_observations: vec![healthy_backup],
            },
            Host {
                name: "athena".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: Some("not-rendered-token-hash".to_string()),
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(4),
                    commits_behind: Some(1),
                },
                service_observations: vec![
                    ServiceObservation::nix_freshness(&NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(4),
                        commits_behind: Some(1),
                    }),
                    ServiceObservation {
                        id: "ssh".to_string(),
                        label: "ssh".to_string(),
                        state: ServiceObservationState::Healthy,
                        summary: "accepting connections".to_string(),
                    },
                    ServiceObservation {
                        id: "nginx".to_string(),
                        label: "nginx".to_string(),
                        state: ServiceObservationState::Warning,
                        summary: "response is slow".to_string(),
                    },
                ],
                backup_observations: vec![],
            },
            Host {
                name: "hades".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(760),
                heartbeat_log: vec![640, 700, 760],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
                backup_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "athena",
            "host": { "name": "athena", "role": "server" },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [{ "wing": "ops", "name": "ssh" }],
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let mut probes = BTreeMap::new();
        probes.insert(
            "athena".to_string(),
            vec![ServerProbeObservation {
                id: "ssh".to_string(),
                service: "ssh".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("tcp://athena:22".to_string()),
                state: ServiceObservationState::Healthy,
                server_reachable: Some(true),
                client_reachable: None,
                summary: "server can reach ssh".to_string(),
                checked_at: 990,
            }],
        );

        let html = render_activity(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            &[manifest],
            &[],
            &probes,
            shell("markus", true),
        );

        assert!(html.contains(r#"href="/activity" aria-current="page""#));
        assert!(html.contains(r#"<h1>Activity</h1>"#));
        assert!(html.contains("Operational timeline"));
        assert!(!html.contains("Control light observed"));
        assert!(html.contains("Heartbeat received"));
        assert!(html.contains("Heartbeat lateness detected"));
        assert!(html.contains("Freshness drift detected"));
        assert!(html.contains("ssh is healthy"));
        assert!(html.contains("nginx warning"));
        assert!(html.contains("Backup source observed"));
        assert!(html.contains("Restic main succeeded"));
        assert!(html.contains("Restic main validation passed"));
        assert!(html.contains("repository check passed"));
        assert!(!html.contains("Nix freshness warning"));
        assert!(html.contains("ssh probe healthy"));
        assert!(html.contains("Declared host manifest loaded"));
        assert!(html.contains(r#"data-activity-filter="heartbeat""#));
        assert!(html.contains(r#"data-activity-filter="backup""#));
        assert!(html.contains(r#"data-ops-filter="backup""#));
        assert!(html.contains(r#"data-ops-filter="heartbeat""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-host-search="athena freshness freshness drift detected"#));
        assert!(html.contains(r#"<button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true""#));
        assert!(html.contains(r#"data-activity-filter="critical""#));
        assert!(html.contains("const filterOk=active==='all'"));
        assert!(html.contains("Activity is derived from current retained Pharos state."));
        assert!(!html.contains("restic-main-repository"));
        assert!(!html.contains("not-rendered-token-hash"));
    }

    #[test]
    fn render_home_sorts_self_host_like_any_other_host() {
        fn host(name: &str) -> Host {
            Host {
                name: name.to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(990),
                heartbeat_log: vec![930, 990],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness {
                    applicable: false,
                    ..Default::default()
                },
                service_observations: vec![],
                backup_observations: vec![],
            }
        }

        let html = render_home(
            runtime(&[host("csb1"), host("csb0")], &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        let csb0 = html.find(r#"data-host="csb0""#).expect("csb0 rendered");
        let csb1 = html.find(r#"data-host="csb1""#).expect("csb1 rendered");

        assert!(csb0 < csb1, "self host must not be pinned ahead of csb0");
        assert!(html.contains(r#"<span class="pharos-mark" aria-hidden="true">"#));
        assert!(!html.contains("control light"));
        assert!(!html.contains("the light is lit"));
        assert!(!html.contains("dataset.self==='true')-Number"));
    }

    #[test]
    fn render_map_uses_visible_labels_and_site_level_locations() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "csb0".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: Some(pharos_core::InboundRttObservation {
                    millis: 12,
                    observed_at: 990,
                }),
                location: Some(HostLocation {
                    latitude: 50.1109,
                    longitude: 8.6821,
                    source: HostLocationSource::Wifi,
                    accuracy_meters: Some(1000.0),
                    precision_meters: Some(25_000.0),
                    observed_at: Some(990),
                    stale: false,
                    manual_override: false,
                    label: Some("Runtime wifi".to_string()),
                }),
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "hsb8".to_string(),
                role: "parents' home".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "dsc0".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            },
            Host {
                name: "new-host".to_string(),
                role: "new server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: None,
                heartbeat_log: vec![],
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8", "site": "ww87" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let probes = BTreeMap::from([
            (
                "csb1".to_string(),
                MapSignal {
                    label: "4 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 4 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "csb0".to_string(),
                MapSignal {
                    label: "8 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 8 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "hsb8".to_string(),
                MapSignal {
                    label: "blocked".to_string(),
                    level: "wait",
                    title: "Outbound access from Pharos is blocked by policy".to_string(),
                    policy: Some("blocked"),
                },
            ),
            (
                "dsc0".to_string(),
                MapSignal {
                    label: "139 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 139 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "new-host".to_string(),
                MapSignal {
                    label: "timeout".to_string(),
                    level: "warn",
                    title: "Pharos tailnet ssh check timed out".to_string(),
                    policy: Some("unknown"),
                },
            ),
        ]);

        let manifests = vec![manifest];
        let html = render_map(&hosts, "csb1", 1000, "markus", true);
        let payload = map_data_payload(&hosts, "csb1", 1000, &manifests, &probes);
        let data_json = serde_json::to_string(&payload).expect("map payload serializes");

        let leaflet_css = html.find("leaflet@1.9.4/dist/leaflet.css").unwrap();
        let body = html.find("</head><body>").unwrap();
        assert!(leaflet_css > body);
        assert!(html.contains(r#"href="/map" aria-current="page""#));
        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains("const MAP_DATA_URL='/map/data.json'"));
        assert!(html.contains("fetch(MAP_DATA_URL+'?refresh='"));
        assert!(html.contains("loadMapAssets()"));
        assert!(html.contains("data-map-loading"));
        assert!(html.contains("data-map-state=\"loading\""));
        assert!(html.contains("Preparing map"));
        assert!(html.contains("site-skel-line"));
        assert!(html.contains("Loading server locations and reachability checks."));
        assert!(html.contains("let MAP_HOSTS=[]"));
        assert!(!html.contains("const MAP_HOSTS=["));
        assert!(html.contains("d3@7.9.0"));
        assert!(html.contains("d3.forceSimulation"));
        assert!(html.contains("d3.forceCollide"));
        assert!(html.contains("renderSiteList(MAP_HOSTS)"));
        assert!(html.contains("function locationSourceLabel(source)"));
        assert!(html.contains("class=\"site-host-source\""));
        assert!(html.contains("class=\"map-source\""));
        assert!(html.contains("data-location-source"));
        assert!(html.contains("buildLabels(map,el)"));
        assert!(html.contains("basemaps.cartocdn.com/light_all"));
        assert!(html.contains("map.on('move zoom moveend zoomend resize viewreset'"));
        assert!(html.contains("classList.add('map-links')"));
        assert!(html.contains("animateMotion"));
        assert!(html.contains("const MAP_VIEWPORT_STORAGE='pharos.map.viewport.v1'"));
        assert!(html.contains("const MAP_MODE_STORAGE='pharos.map.mode.v1'"));
        assert!(html.contains("storedViewport()"));
        assert!(html.contains("storeViewport(map)"));
        assert!(html.contains("map.on('moveend zoomend',()=>storeViewport(map))"));
        assert!(html.contains("scrollWheelZoom:true"));
        assert!(html.contains("L.control.zoom({position:'topleft'})"));
        assert!(html.contains(r#"data-map-view="standard""#));
        assert!(html.contains(r#"data-map-layout data-mode="standard""#));
        assert!(html.contains(r#"id="map-panel" class="map-panel""#));
        assert!(html.contains(r#"data-map-mode-button="standard""#));
        assert!(html.contains(r#"data-map-mode-button="maximized""#));
        assert!(html.contains(r#"data-map-mode-button="fullscreen""#));
        assert!(html.contains(r#"data-map-density-button"#));
        assert!(html.contains("const MAP_LABEL_DENSITY_STORAGE='pharos.map.labelDensity.v1'"));
        assert!(html.contains("window.pharosMapApplyFilter"));
        assert!(html.contains("dataset.mapLayer='managed'"));
        assert!(html.contains(r#"class="toolbar" aria-label="map controls""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-live-filter="all""#));
        assert!(html.contains(r#"data-live-filter="live""#));
        assert!(html.contains("requestFullscreen(panel)"));
        assert!(html.contains("map.invalidateSize()"));
        assert!(html.contains(".fleet-map{flex:1 1 auto;height:100%;min-height:560px"));
        assert!(html.contains(".map-mode-controls{position:absolute;right:12px;top:12px"));
        assert!(html.contains(r#".map-panel[data-label-density="compact"] .map-node"#));
        assert!(html.contains("data-dir=\"in\""));
        assert!(html.contains("data-dir=\"out\""));
        assert!(!html.contains("markercluster"));
        assert!(!html.contains("L.markerClusterGroup"));
        assert!(!html.contains(r#""site_id":"cloud-de""#));
        assert!(!html.contains(r#""lon":-122.9898"#));
        assert!(html.contains(r#"data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">out "#));
        assert!(html.contains(r#"data-host="'+escapeHtml(host.name)+'" data-live="'+escapeHtml(host.live)+'" data-search="'+escapeHtml(host.search||'')+'" "#));
        assert!(html.contains(r#"<b>5</b><span>All hosts</span>"#));
        assert!(html.contains(r#"<b>4</b><span>Live</span>"#));
        assert!(html.contains("Approximate site-level coordinates."));
        assert!(html.contains("All servers stay visible"));

        assert!(data_json.contains(r#""schema":"inspr.pharos.map-data.v1""#));
        assert!(data_json.contains(r#""site_id":"cloud-de""#));
        assert!(data_json.contains(r#""site_id":"wifi:50.1109,8.6821""#));
        assert!(data_json.contains(r#""site_id":"ww87""#));
        assert!(data_json.contains(r#""site_id":"dsc-us""#));
        assert!(data_json.contains(r#""site_id":"unknown""#));
        assert!(data_json.contains(r#""lon":-122.9898"#));
        assert!(data_json.contains(r#""location_source":"provider""#));
        assert!(data_json.contains(r#""location_source":"wifi""#));
        assert!(data_json.contains(r#""location_source":"fallback""#));
        assert!(data_json.contains(r#""source":"provider""#));
        assert!(data_json.contains(r#""source":"wifi""#));
        assert!(data_json.contains(r#""source":"fallback""#));
        assert!(data_json.contains("Hillsboro, OR, US"));
        assert!(data_json.contains(r#""inbound_label":"12 ms""#));
        assert!(data_json
            .contains(r#""inbound_title":"Host-to-Pharos report submit RTT from csb0 was 12 ms"#));
        assert!(data_json.contains(r#""inbound_label":"beat 30s""#));
        assert!(data_json.contains(r#""outbound_label":"blocked""#));
        assert!(data_json.contains(r#""outbound_policy":"blocked""#));
        assert!(data_json.contains(r#""search":"csb1 server live"#));
        assert!(payload.hosts.iter().any(|host| host.name == "hsb8"
            && host.live == "live"
            && host.outbound_label == "blocked"
            && host.outbound_policy == "blocked"));
        assert!(payload.hosts.iter().any(|host| host.name == "csb0"
            && host.location_source == "wifi"
            && host.location_state == "observed"
            && host.inbound_label == "12 ms"
            && host.search.contains("auto")));
        assert!(payload.hosts.iter().any(|host| host.name == "new-host"
            && host.live == "awaiting_first_heartbeat"
            && host.outbound_label == "timeout"
            && host.outbound_level == "warn"
            && host.search.contains("fallback")));
    }

    #[test]
    fn host_location_resolution_defines_precedence_and_stale_state() {
        fn location(
            latitude: f64,
            longitude: f64,
            source: HostLocationSource,
            observed_at: Option<i64>,
            manual_override: bool,
            label: &str,
        ) -> HostLocation {
            HostLocation {
                latitude,
                longitude,
                source,
                accuracy_meters: Some(1000.0),
                precision_meters: None,
                observed_at,
                stale: false,
                manual_override,
                label: Some(label.to_string()),
            }
        }

        let mut host = Host {
            name: "dsc0".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1000),
            heartbeat_log: vec![940, 1000],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: Some(location(
                50.1109,
                8.6821,
                HostLocationSource::Wifi,
                Some(995),
                false,
                "Runtime wifi",
            )),
            freshness: NixFreshness::default(),
            service_observations: vec![],
            backup_observations: vec![],
        };
        let mut manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "dsc0",
            "host": {
                "name": "dsc0",
                "site": "dsc-us",
                "location": {
                    "latitude": 45.5229,
                    "longitude": -122.9898,
                    "source": "declared",
                    "manual_override": true,
                    "label": "Declared DSC"
                }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let declared = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared.source, HostLocationSource::Declared);
        assert_eq!(declared.label, "Declared DSC");
        assert!(declared.manual_override);

        manifest.host.location.as_mut().unwrap().manual_override = false;
        manifest.host.location_mode = ManifestLocationMode::DeclaredOverride;
        let declared_mode = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared_mode.source, HostLocationSource::Declared);
        assert_eq!(declared_mode.mode, "declared-override");
        assert_eq!(declared_mode.label, "Declared DSC");

        manifest.host.location_mode = ManifestLocationMode::DeclaredFallback;
        let runtime = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(runtime.source, HostLocationSource::Wifi);
        assert_eq!(runtime.label, "Runtime wifi");
        assert_eq!(runtime.state, "observed");

        host.location.as_mut().unwrap().observed_at = Some(1000 - LOCATION_STALE_AFTER_SECS - 1);
        let stale = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(stale.source, HostLocationSource::Wifi);
        assert_eq!(stale.state, "stale");
        assert!(stale.stale);

        host.location = None;
        let declared_fallback = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared_fallback.source, HostLocationSource::Declared);
        assert_eq!(declared_fallback.mode, "declared-fallback");

        manifest.host.location_mode = ManifestLocationMode::Hidden;
        let hidden = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(hidden.source, HostLocationSource::Unknown);
        assert_eq!(hidden.mode, "hidden");
        assert_eq!(hidden.state, "hidden");
        assert_eq!(hidden.id, "hidden");

        manifest.host.location_mode = ManifestLocationMode::Auto;
        manifest.host.location = None;
        let provider = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(provider.source, HostLocationSource::Provider);
        assert_eq!(provider.id, "dsc-us");

        manifest.host.site = None;
        let fallback = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(fallback.source, HostLocationSource::Fallback);
        assert_eq!(fallback.id, "dsc-us");

        let unknown = resolve_host_location(None, None, "new-host", 1000);
        assert_eq!(unknown.source, HostLocationSource::Fallback);
        assert_eq!(unknown.state, "unknown");
        assert_eq!(unknown.id, "unknown");
    }

    #[test]
    fn declared_hosts_payload_exposes_sanitized_location_overlay() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "athena",
            "host": {
                "name": "athena",
                "site": "home-at"
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let runtime = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("not-rendered-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: Some(HostLocation {
                latitude: 48.2082,
                longitude: 16.3738,
                source: HostLocationSource::Wifi,
                accuracy_meters: Some(1500.0),
                precision_meters: None,
                observed_at: Some(970),
                stale: false,
                manual_override: false,
                label: Some("Vienna area".to_string()),
            }),
            freshness: NixFreshness::default(),
            service_observations: vec![],
            backup_observations: vec![],
        };

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            std::slice::from_ref(&runtime),
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["source"],
            "wifi"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["label"],
            "Vienna area"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["manual_override"],
            false
        );
        assert!(!payload.to_string().contains("not-rendered-token-hash"));
    }

    #[test]
    fn silent_beacon_alerts_only_previous_hosts_that_are_down() {
        fn host(name: &str, last_seen: Option<i64>) -> Host {
            Host {
                name: name.to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen,
                heartbeat_log: last_seen.into_iter().collect(),
                heartbeat_interval_secs: Some(60),
                inbound_rtt: None,
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
                backup_observations: vec![],
            }
        }

        let alerts = silent_beacon_alerts(
            &[
                host("live", Some(950)),
                host("stale", Some(800)),
                host("down", Some(600)),
                host("awaiting", None),
            ],
            1000,
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].host, "down");
        assert_eq!(alerts[0].kind, "silent_heartbeat");
        assert_eq!(alerts[0].age_seconds, 400);
        assert_eq!(alerts[0].heartbeat_interval_secs, 60);
        assert!(alerts[0].summary.contains("has not reported"));
    }

    #[test]
    fn alert_webhook_prefers_pharos_specific_url() {
        let selected = alert_webhook_url(
            Some(" https://pharos-alert.example/hook ".to_string()),
            Some("https://watchtower.example/hook".to_string()),
            Some("/no/read/needed".to_string()),
        );

        assert_eq!(
            selected.as_deref(),
            Some("https://pharos-alert.example/hook")
        );
    }

    #[test]
    fn alert_webhook_reuses_watchtower_url_when_pharos_url_is_blank() {
        let selected = alert_webhook_url(
            Some("   ".to_string()),
            Some(" https://watchtower.example/hook ".to_string()),
            Some("/no/read/needed".to_string()),
        );

        assert_eq!(selected.as_deref(), Some("https://watchtower.example/hook"));
    }

    #[test]
    fn alert_webhook_can_read_watchtower_url_from_env_file() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pharos-alert-env-{}-{}.env",
            std::process::id(),
            now_unix()
        ));
        fs::write(
            &path,
            r#"
# ignored
WATCHTOWER_HTTP_API_TOKEN=not-selected
export WATCHTOWER_NOTIFICATION_URL="https://watchtower.example/hook"
"#,
        )
        .expect("write test env file");

        let selected = alert_webhook_url(None, None, Some(path.display().to_string()));
        let _ = fs::remove_file(path);

        assert_eq!(selected.as_deref(), Some("https://watchtower.example/hook"));
    }

    #[test]
    fn telegram_alert_target_parses_shoutrrr_url() {
        let url =
            Url::parse("telegram://123456:abcDEF@telegram?chats=-100111222333,444555").unwrap();
        let target = TelegramAlertTarget::from_url(&url).expect("telegram target");

        assert_eq!(target.token, "123456:abcDEF");
        assert_eq!(target.chats, vec!["-100111222333", "444555"]);
    }

    #[test]
    fn telegram_alert_text_is_plain_and_actionable() {
        let alert = SilentBeaconAlert {
            schema: "inspr.pharos.alert.v1",
            level: "critical",
            kind: "silent_heartbeat",
            host: "gpc0".to_string(),
            role: "server".to_string(),
            last_seen: 100,
            age_seconds: 360,
            heartbeat_interval_secs: 60,
            as_of: 460,
            summary: "gpc0 has not reported for 6m 00s.".to_string(),
            next_action: "Check host power, network, and pharos-beacon.",
        };

        let text = telegram_alert_text(&alert);

        assert!(text.contains("Pharos critical alert"));
        assert!(text.contains("Host: gpc0"));
        assert!(text.contains("Check host power"));
    }

    #[test]
    fn heartbeat_history_uses_outcome_slots_before_expected_marker() {
        let marks = heartbeat_marks(&[100, 160, 220, 340], 60, SIGNAL_DEFAULT_WINDOW_SECS);

        assert!(!marks.contains(r#"data-history-level="first""#));
        assert!(marks.contains(r#"data-history-level="ok""#));
        assert!(marks.contains(r#"data-history-level="late""#));
        assert!(marks.contains(r#"--mark-x:14.7%""#));
        assert!(marks.contains(r#"--mark-x:29.3%""#));
        assert!(marks.contains(r#"--mark-x:58.7%""#));
        assert!(!marks.contains(r#"--mark-x:64.0%""#));
    }

    #[test]
    fn first_heartbeat_without_previous_sample_has_no_history_dot() {
        assert!(heartbeat_marks(&[100], 60, SIGNAL_DEFAULT_WINDOW_SECS).is_empty());
    }

    #[test]
    fn heartbeat_history_window_changes_visible_samples() {
        let log = (0..=20).map(|idx| idx * 60).collect::<Vec<_>>();

        let ten_minutes = heartbeat_visible_log(&log, 10 * 60);
        let hour = heartbeat_visible_log(&log, 60 * 60);

        assert_eq!(ten_minutes.len(), 11);
        assert_eq!(ten_minutes.first(), Some(&600));
        assert_eq!(ten_minutes.last(), Some(&1200));
        assert_eq!(hour.len(), HEARTBEAT_HISTORY_DOTS);
        assert_ne!(hour, ten_minutes);
        assert_eq!(hour.last(), Some(&1200));
    }

    #[test]
    fn heartbeat_signal_scores_expected_intervals_not_dots() {
        let steady = heartbeat_signal(
            &[100, 160, 220, 280, 340, 400, 460, 520, 580],
            Some(580),
            60,
            588,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(steady.text, "100%");
        assert_eq!(steady.level, "good");
        assert_eq!(steady.window, "10m");

        let overdue = heartbeat_signal(
            &[100, 160, 220, 280, 340, 400, 460, 520, 580],
            Some(580),
            60,
            645,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(overdue.text, "90%");
        assert_eq!(overdue.level, "warn");

        let recovered_gap = heartbeat_signal(
            &[100, 160, 220, 460],
            Some(460),
            60,
            468,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(recovered_gap.text, "57%");
        assert_eq!(recovered_gap.level, "down");
    }

    #[test]
    fn heartbeat_signal_can_score_longer_windows() {
        let sparse = heartbeat_signal(&[0, 60, 120, 3600], Some(3600), 60, 3600, "1h", 3600);

        assert_eq!(sparse.text, "7%");
        assert_eq!(sparse.level, "down");
        assert_eq!(sparse.window, "1h");
        assert!(sparse.title.contains("longest gap"));
    }

    #[test]
    fn render_home_marks_declared_host_settings_as_available() {
        let host = Host {
            name: "poseidon".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(970),
            heartbeat_log: vec![850, 910, 970],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![],
        };
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "poseidon",
            "host": { "name": "poseidon" },
            "palette": {
                "name": "custom-poseidon",
                "accent": "#48b8a8",
                "gradient": { "primary": "#48b8a8" }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let html = render_home(
            runtime(&[host], &[]),
            "csb1",
            1000,
            &[manifest],
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(html.contains(r#"class="card has-settings""#));
        assert!(html.contains(r#"aria-label="Open color settings for poseidon""#));
        assert!(html.contains(r#"<div class="card-actions"><button class="drag-handle" type="button" data-drag-handle title="Move poseidon" aria-label="Move poseidon""#));
        assert!(html.contains(r#"<div class="card-tools"><span class="signal" data-signal"#));
        assert!(html.contains(r#"style="--host-color:#48b8a8""#));
        assert!(!html.contains("Color and access"));
        assert!(!html.contains(r#"class="settings-swatch""#));
    }

    #[test]
    fn render_home_has_deliberate_empty_and_lone_host_states() {
        let empty = render_home(
            runtime(&[], &[]),
            "csb1",
            1000,
            &[],
            shell("local access", false),
            true,
        );
        assert!(empty.contains(r#"<section class="empty-state""#));
        assert!(empty.contains("Waiting for the first host"));
        assert!(empty.contains("Add first server"));
        assert!(empty.contains("Add a server"));
        assert!(empty.contains("setup_path"));
        assert!(empty.contains("setup_provider"));
        assert!(empty.contains("setup_template"));
        assert!(empty.contains("setup_stage"));
        assert!(empty.contains("Hetzner Cloud"));
        assert!(empty.contains("Manual / existing provider"));
        assert!(empty.contains("Add existing server"));
        assert!(empty.contains(r#"data-preflight-form"#));
        assert!(empty.contains(r#"data-preflight-host-name"#));
        assert!(empty.contains(r#"data-preflight-role"#));
        assert!(empty.contains(r#"data-preflight-host-type"#));
        assert!(empty.contains(r#"data-preflight-ssh-host"#));
        assert!(empty.contains(r#"data-preflight-result"#));
        assert!(empty.contains(r#"data-preflight-bootstrap"#));
        assert!(empty.contains("Known facts"));
        assert!(empty.contains("Check server"));
        assert!(empty.contains("Small NixOS server"));
        assert!(empty.contains("Lab / free-tier style"));
        assert!(empty.contains("Bring your own plan"));
        assert!(empty.contains("Netcup"));
        assert!(empty.contains("data-assistant-template=\"hetzner-small-nixos\""));
        assert!(empty.contains("No provider resources are created here."));
        assert!(empty.contains("Review plan"));
        assert!(empty.contains("Provider resources"));
        assert!(empty.contains("SSH and bootstrap"));
        assert!(empty.contains("Beacon registration"));
        assert!(empty.contains("First heartbeat"));
        assert!(empty.contains("Backup and location"));
        assert!(empty.contains(r#"data-existing-setup-intent"#));
        assert!(empty.contains("Protection and place"));
        assert!(empty.contains(r#"name="backup_intent" value="optional""#));
        assert!(empty.contains(r#"name="backup_intent" value="external""#));
        assert!(empty.contains(r#"name="location_intent" value="site-fallback""#));
        assert!(empty.contains("No secrets stored"));
        assert!(empty.contains("I understand this may create provider resources."));
        assert!(empty.contains("data-assistant-job"));
        assert!(empty.contains("data-progress-state=\"failed\""));
        assert!(empty.contains("cleanup needed"));
        assert!(empty.contains(r#"data-assistant-next-title"#));
        assert!(empty.contains(r#"aria-pressed="false""#));
        assert!(empty.contains("awaiting first heartbeat"));

        let host = Host {
            name: "ares".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("hash".to_string()),
            last_seen: None,
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![],
        };
        let lone = render_home(
            runtime(&[host], &[]),
            "csb1",
            1000,
            &[],
            shell("local access", false),
            true,
        );
        assert!(lone.contains(r#"<aside class="lone-state""#));
        assert!(lone.contains("First host is on the map"));
        assert!(lone.contains(r#"data-onboard-tile"#));
        assert!(lone.contains(r#"<tr class="onboard-row""#));
        assert!(lone.contains(r#"data-live="awaiting_first_heartbeat""#));
    }

    #[test]
    fn render_home_shows_pending_setup_job_before_first_heartbeat() {
        let job = setup_job(
            "lab-01",
            ProvisioningJobState::WaitingForHeartbeat,
            1_000,
            1_000,
            ProvisioningSetupIntent {
                backup: BackupSetupIntent::Required,
                location: LocationSetupIntent::Manual,
            },
        );

        let html = render_home(
            runtime(&[], &[job]),
            "csb1",
            1_120,
            &[],
            shell("local access", false),
            true,
        );

        assert!(!html.contains("Waiting for the first host"));
        assert!(html.contains(r#"class="card setup-card""#));
        assert!(html.contains("lab-01"));
        assert!(html.contains("waiting for first heartbeat"));
        assert!(html.contains("backup required"));
        assert!(html.contains("manual location"));
        assert!(html.contains("Continue setup"));
        assert!(html.contains(r#"data-host-surface="setup""#));
        assert!(html.contains(r#"<tr class="setup-row""#));
    }

    #[test]
    fn render_home_hides_setup_job_once_runtime_host_exists() {
        let job = setup_job(
            "lab-01",
            ProvisioningJobState::WaitingForHeartbeat,
            1_000,
            1_000,
            ProvisioningSetupIntent {
                backup: BackupSetupIntent::Required,
                location: LocationSetupIntent::Auto,
            },
        );
        let host = host_with_backups("lab-01", 1_110, vec![]);

        let html = render_home(
            runtime(&[host], &[job]),
            "csb1",
            1_120,
            &[],
            shell("local access", false),
            true,
        );

        assert!(html.contains(r#"data-host-surface="runtime""#));
        assert!(!html.contains(r#"class="card setup-card""#));
        assert!(!html.contains(r#"<tr class="setup-row""#));
        assert!(html.contains(r#"data-protection-state="first-backup-pending""#));
        assert!(html.contains("First backup pending"));
    }

    #[test]
    fn first_backup_onboarding_states_are_visible() {
        let now = 100_000;
        let intent = ProvisioningSetupIntent {
            backup: BackupSetupIntent::Required,
            location: LocationSetupIntent::Auto,
        };
        let pending_job = setup_job(
            "lab-pending",
            ProvisioningJobState::WaitingForHeartbeat,
            now - 120,
            now - 120,
            intent.clone(),
        );
        let overdue_job = setup_job(
            "lab-overdue",
            ProvisioningJobState::WaitingForHeartbeat,
            2_000,
            2_000,
            intent.clone(),
        );
        let failed_job = setup_job(
            "lab-failed",
            ProvisioningJobState::WaitingForHeartbeat,
            3_000,
            3_000,
            intent.clone(),
        );
        let succeeded_job = setup_job(
            "lab-succeeded",
            ProvisioningJobState::WaitingForHeartbeat,
            4_000,
            4_000,
            intent,
        );

        let mut failed_backup = backup_observation(BackupPostureState::Failed);
        failed_backup.summary = "first backup attempt failed".to_string();
        failed_backup.last_success_at = None;
        failed_backup.last_attempt_at = Some(3_080);
        failed_backup.last_attempt_state = Some(pharos_core::BackupRunState::Failed);

        let mut succeeded_backup = backup_observation(BackupPostureState::Healthy);
        succeeded_backup.last_success_at = Some(4_090);
        succeeded_backup.last_attempt_at = Some(4_090);
        succeeded_backup.last_attempt_state = Some(pharos_core::BackupRunState::Succeeded);

        let hosts = vec![
            host_with_backups("lab-pending", now - 60, vec![]),
            host_with_backups("lab-overdue", 2_060, vec![]),
            host_with_backups("lab-failed", 3_060, vec![failed_backup]),
            host_with_backups("lab-succeeded", 4_060, vec![succeeded_backup]),
        ];
        let jobs = vec![pending_job, overdue_job, failed_job, succeeded_job];

        let html = render_home(
            runtime(&hosts, &jobs),
            "csb1",
            now,
            &[],
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"data-protection-state="first-backup-pending""#));
        assert!(html.contains(r#"data-protection-state="first-backup-overdue""#));
        assert!(html.contains(r#"data-protection-state="first-backup-failed""#));
        assert!(html.contains(r#"data-protection-state="first-backup-succeeded""#));
        assert!(html.contains("First backup pending"));
        assert!(html.contains("First backup overdue"));
        assert!(html.contains("First backup failed"));
        assert!(html.contains("First backup succeeded"));

        let probes = BTreeMap::new();
        let alerts = render_alerts(
            runtime(&hosts, &jobs),
            "csb1",
            now,
            &[],
            &[],
            &probes,
            shell("markus", true),
        );
        assert!(alerts.contains("First backup overdue"));
        assert!(alerts.contains("First backup failed"));
        assert!(!alerts.contains("First backup succeeded"));

        let activity = render_activity(
            runtime(&hosts, &jobs),
            "csb1",
            now,
            &[],
            &[],
            &probes,
            shell("markus", true),
        );
        assert!(activity.contains("First backup pending"));
        assert!(activity.contains("First backup overdue"));
        assert!(activity.contains("First backup failed"));
        assert!(activity.contains("First backup succeeded"));
    }

    #[test]
    fn alerts_and_activity_include_setup_overdue_and_failure_states() {
        let overdue = setup_job(
            "lab-01",
            ProvisioningJobState::WaitingForHeartbeat,
            1_000,
            1_000,
            ProvisioningSetupIntent {
                backup: BackupSetupIntent::Required,
                location: LocationSetupIntent::Auto,
            },
        );
        let failed = setup_job(
            "lab-02",
            ProvisioningJobState::Failed,
            1_050,
            1_060,
            ProvisioningSetupIntent {
                backup: BackupSetupIntent::Optional,
                location: LocationSetupIntent::SiteFallback,
            },
        );
        let jobs = vec![overdue, failed];
        let probes = BTreeMap::new();

        let alerts = render_alerts(
            runtime(&[], &jobs),
            "csb1",
            1_400,
            &[],
            &[],
            &probes,
            shell("markus", true),
        );
        assert!(alerts.contains("First heartbeat overdue"));
        assert!(alerts.contains("Setup failed"));
        assert!(alerts.contains(r#"data-ops-filter="warning""#));

        let activity = render_activity(
            runtime(&[], &jobs),
            "csb1",
            1_400,
            &[],
            &[],
            &probes,
            shell("markus", true),
        );
        assert!(activity.contains(r#"data-activity-filter="setup""#));
        assert!(activity.contains("First heartbeat overdue"));
        assert!(activity.contains("Setup failed"));
    }

    #[test]
    fn render_home_hides_onboarding_when_not_allowed() {
        let host = Host {
            name: "ares".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(940),
            heartbeat_log: vec![880, 940],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![],
        };

        let html = render_home(
            runtime(&[host], &[]),
            "csb1",
            1000,
            &[],
            shell("reader", true),
            false,
        );

        assert!(!html.contains(r#"<button class="onboard-tile""#));
        assert!(!html.contains("Add server"));
        assert!(!html.contains(r#"<section class="assistant-overlay""#));
        assert!(!html.contains(r#"<tr class="onboard-row""#));
    }

    #[test]
    fn declared_hosts_payload_keeps_declared_and_runtime_state_separate() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "access": {
                    "lanHostname": "hsb8.lan",
                    "lanIp": "192.168.1.100",
                    "tailnet": "hsb8"
                }
            },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [
                {
                    "wing": "ops",
                    "name": "pharos-beacon",
                    "passive": true,
                    "statusPolicy": { "source": "pharos-runtime" }
                }
            ],
            "policy": {
                "declaredOnly": true,
                "runtimeStateOwner": "pharos",
                "privilegedActions": { "mode": "none", "janusRequired": false }
            }
        }))
        .expect("manifest parses");
        let runtime = Host {
            name: "hsb8".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
            },
            service_observations: vec![ServiceObservation::nix_freshness(&NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
            })],
            backup_observations: vec![backup_observation(BackupPostureState::Warning)],
        };

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            std::slice::from_ref(&runtime),
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(payload["schema"], "inspr.pharos.declared-hosts.v1");
        assert_eq!(
            payload["declared_hosts"][0]["declared"]["services"][0]["statusPolicy"]["source"],
            "pharos-runtime"
        );
        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "observed");
        assert_eq!(payload["declared_hosts"][0]["runtime"]["liveness"], "live");
        assert!(payload["declared_hosts"][0]["runtime"]["token_hash"].is_null());
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes_summary"]["label"],
            "not probed"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["backup_observations"][0]["id"],
            "restic-main"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["backup_observations_summary"]["state"],
            "warning"
        );
        assert!(payload["declared_hosts"][0]["declared"]
            .get("backup_observations")
            .is_none());
        assert!(!payload.to_string().contains("stored-token-hash"));
    }

    #[test]
    fn declared_hosts_payload_adds_server_probe_runtime_overlay() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8" },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [
                {
                    "wing": "ops",
                    "name": "Home Assistant",
                    "url": "http://hsb8.lan:8123/",
                    "statusPolicy": { "source": "pharos-runtime" }
                }
            ],
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let mut probes = BTreeMap::new();
        probes.insert(
            "hsb8".to_string(),
            vec![ServerProbeObservation {
                id: "home-assistant".to_string(),
                service: "Home Assistant".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("http://hsb8.lan:8123/".to_string()),
                state: ServiceObservationState::Healthy,
                server_reachable: Some(true),
                client_reachable: None,
                summary: "server can reach hsb8.lan:8123".to_string(),
                checked_at: 1000,
            }],
        );

        let payload =
            declared_hosts_payload(std::slice::from_ref(&manifest), &[], &[], &probes, 1000);

        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["state"],
            "healthy"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["server_reachable"],
            true
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["client_reachable"],
            serde_json::Value::Null
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes_summary"]["label"],
            "server reachable"
        );
        assert!(payload["declared_hosts"][0]["declared"]["services"][0]
            .get("server_probes")
            .is_none());
    }

    #[test]
    fn declared_hosts_payload_marks_missing_runtime_as_pending() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "new-host",
            "host": { "name": "new-host" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            &[],
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "pending");
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["liveness"],
            "awaiting_first_heartbeat"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["backup_observations_summary"]["state"],
            "unknown"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["backup_observations_summary"]["total"],
            0
        );
    }

    #[test]
    fn server_probe_policy_is_explicitly_declared() {
        let hostdash_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Client probe",
            "url": "http://example.test/",
            "probe": true,
            "statusPolicy": { "source": "hostdash-probe" }
        }))
        .expect("service parses");
        assert!(!should_server_probe(&hostdash_service));

        let pharos_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Server probe",
            "url": "http://example.test/",
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");
        assert!(should_server_probe(&pharos_service));

        let named_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Named server probe",
            "url": "http://example.test/",
            "probe": "server"
        }))
        .expect("service parses");
        assert!(should_server_probe(&named_service));

        let passive_runtime_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Beacon observation",
            "passive": true,
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");
        assert!(!should_server_probe(&passive_runtime_service));
    }

    #[test]
    fn sanitized_probe_target_drops_userinfo_query_and_fragment() {
        let url = Url::parse("https://user:secret@example.test:8443/path?token=secret#frag")
            .expect("valid URL");

        assert_eq!(
            sanitized_probe_target(&url),
            "https://example.test:8443/path"
        );
    }

    #[test]
    fn provisioning_job_store_persists_safe_backend_failure() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pharos-provisioning-jobs-{}-{}.json",
            std::process::id(),
            nanos
        ));
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let request = ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            apply: false,
            host_name: None,
            role: None,
            is_nix: None,
            heartbeat_interval_secs: None,
            backup_intent: None,
            location_intent: None,
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_000, &runtime)
            .expect("supported plan starts a tracked job");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert_eq!(job.progress.len(), 2);
        assert_eq!(job.progress[0].state, ProvisioningJobState::Planning);
        assert_eq!(job.progress[1].state, ProvisioningJobState::Failed);
        assert!(job.progress[1]
            .message
            .contains("no provider resources were created"));
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::Deferred);
        assert_eq!(setup_intent.location, LocationSetupIntent::Auto);
        let unsupported = ProvisioningJobStartRequest {
            template: "manual-import".to_string(),
            ..request.clone()
        };
        assert!(store.start(&unsupported, 1, &runtime).is_err());

        let reloaded = ProvisioningJobStore::new(Some(path.clone()));
        let persisted = reloaded.get(&job.id).expect("job persisted");
        assert_eq!(persisted, job);
        let contents = std::fs::read_to_string(&path).expect("persisted json is readable");
        assert!(contents.contains(PROVISIONING_JOB_SCHEMA));
        assert!(!contents.to_ascii_lowercase().contains("bearer "));
        assert!(!contents.to_ascii_lowercase().contains("token="));

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hetzner_executor_gate_persists_precise_safe_failures() {
        let store = ProvisioningJobStore::new(None);
        let mut request = ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            apply: false,
            host_name: None,
            role: None,
            is_nix: None,
            heartbeat_interval_secs: None,
            backup_intent: None,
            location_intent: None,
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File),
                execute_enabled: false,
            },
        };

        let job = store
            .start(&request, 1_700_000_001, &runtime)
            .expect("configured backend still creates recoverable job");
        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert!(job.progress[1]
            .message
            .contains("explicit apply confirmation"));

        request.apply = true;
        let disabled = store
            .start(&request, 1_700_000_002, &runtime)
            .expect("disabled execution records safe failure");
        assert!(disabled.progress[1]
            .message
            .contains("live execution is disabled"));

        let enabled = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::Environment),
                execute_enabled: true,
            },
        };
        let missing_inputs = store
            .start(&request, 1_700_000_003, &enabled)
            .expect("missing inputs record safe failure");
        assert!(missing_inputs.progress[1]
            .message
            .contains("needs host, location, server type, image, and SSH key reference"));

        request.host_name = Some("hcloud-lab-1".to_string());
        request.location = Some("fsn1".to_string());
        request.server_type = Some("cx22".to_string());
        request.image = Some("debian-12".to_string());
        request.ssh_key_ref = Some("janus:pharos/ssh/hcloud-lab-1".to_string());
        let gated = store
            .start(&request, 1_700_000_004, &enabled)
            .expect("fully shaped request reaches provider gate");
        assert_eq!(gated.state, ProvisioningJobState::Failed);
        assert_eq!(gated.progress[1].state, ProvisioningJobState::Provisioning);
        assert!(gated.progress[1]
            .message
            .contains("no provider resources were created"));
        let json = serde_json::to_string(&gated).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn provider_setup_job_persists_backup_intent_without_provider_apply() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            apply: false,
            host_name: Some("hcloud-lab-2".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Optional),
            location_intent: Some(LocationSetupIntent::Manual),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_004, &runtime)
            .expect("provider job stores setup intent even when execution is gated");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::Optional);
        assert_eq!(setup_intent.backup_label(), "backup optional");
        assert_eq!(
            setup_intent.backup_next_action(),
            "offer enrollment, but do not block onboarding"
        );
        assert_eq!(setup_intent.location, LocationSetupIntent::Manual);
        let proposal = job.backup_proposal.as_ref().expect("backup proposal");
        assert_eq!(
            proposal.kind,
            ProvisioningBackupProposalKind::NixosResticBeaconObservation
        );
        assert!(proposal
            .nix_module
            .contains(r#"RESTIC_REPOSITORY_FILE = "/run/agenix/hcloud-lab-2-restic-repository""#));
        assert!(proposal
            .nix_module
            .contains(r#"RESTIC_PASSWORD_FILE = "/run/agenix/hcloud-lab-2-restic-password""#));
        assert!(proposal
            .secret_files
            .iter()
            .any(|file| file.path == "/run/agenix/hcloud-lab-2-restic-repository"));
        assert!(proposal
            .secret_files
            .iter()
            .any(|file| file.path == "/run/agenix/hcloud-lab-2-restic-password"));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn existing_host_manual_path_waits_for_heartbeat_without_secrets() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_name: Some("legacy-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::External),
            location_intent: Some(LocationSetupIntent::SiteFallback),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_005, &runtime)
            .expect("manual existing-host path records setup state");

        assert_eq!(job.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(job.host_name.as_deref(), Some("legacy-1"));
        assert_eq!(job.role.as_deref(), Some("server"));
        assert_eq!(job.is_nix, Some(false));
        assert_eq!(job.heartbeat_interval_secs, Some(60));
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::External);
        assert_eq!(setup_intent.location, LocationSetupIntent::SiteFallback);
        assert!(job.backup_proposal.is_none());
        assert_eq!(setup_intent.backup_label(), "managed elsewhere");
        assert_eq!(setup_intent.location_label(), "site fallback");
        let handoff = job.handoff.as_ref().expect("manual handoff");
        assert_eq!(handoff.method, BootstrapMethod::Manual);
        assert_eq!(handoff.status, "manual-handoff");
        assert!(handoff
            .token_policy
            .contains("never place the beacon credential"));
        assert_eq!(
            handoff.secret_target.as_deref(),
            Some("/etc/pharos/pharos-beacon.env")
        );
        assert!(handoff
            .next_steps
            .iter()
            .any(|step| step.contains("Backups managed elsewhere")));
        assert_eq!(
            job.progress.last().expect("progress entry").state,
            ProvisioningJobState::WaitingForHeartbeat
        );
        assert!(job
            .progress
            .last()
            .expect("progress entry")
            .message
            .contains("first heartbeat"));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn existing_host_automated_path_fails_closed_until_executor_exists() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "native-systemd".to_string(),
            apply: true,
            host_name: Some("legacy-2".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::EnrollLater),
            location_intent: Some(LocationSetupIntent::Auto),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_006, &runtime)
            .expect("automated existing-host path records safe failure");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert_eq!(job.host_name.as_deref(), Some("legacy-2"));
        assert_eq!(job.role.as_deref(), Some("server"));
        assert_eq!(job.is_nix, Some(false));
        assert_eq!(job.heartbeat_interval_secs, Some(60));
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::EnrollLater);
        assert_eq!(setup_intent.location, LocationSetupIntent::Auto);
        let handoff = job.handoff.as_ref().expect("native handoff");
        assert_eq!(handoff.method, BootstrapMethod::NativeSystemd);
        assert_eq!(handoff.status, "executor-pending");
        assert!(handoff
            .command_ref
            .as_deref()
            .is_some_and(|value| value.contains("install-pharos-beacon-systemd")));
        assert!(handoff
            .next_steps
            .iter()
            .any(|step| step.contains("Backup enrollment later")));
        assert!(job.backup_proposal.is_none());
        assert_eq!(
            job.progress.last().expect("progress entry").state,
            ProvisioningJobState::Failed
        );
        assert!(job
            .progress
            .last()
            .expect("progress entry")
            .message
            .contains("Automated existing-host apply is not active yet"));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn nixos_existing_host_handoff_proposes_secret_safe_backup_config() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "nixos-anywhere".to_string(),
            apply: true,
            host_name: Some("nix-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Required),
            location_intent: Some(LocationSetupIntent::Auto),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_007, &runtime)
            .expect("nixos existing-host handoff records setup state");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::Required);
        let handoff = job.handoff.as_ref().expect("nixos handoff");
        assert_eq!(handoff.method, BootstrapMethod::NixosAnywhere);
        assert!(handoff
            .next_steps
            .iter()
            .any(|step| step.contains("declarative backup module proposal")));
        assert!(handoff.next_steps.iter().any(
            |step| step.contains("do not embed secret values in Nix options or the Nix store")
        ));
        let proposal = job.backup_proposal.as_ref().expect("backup proposal");
        assert_eq!(
            proposal.kind,
            ProvisioningBackupProposalKind::NixosResticBeaconObservation
        );
        assert_eq!(
            proposal.module_attribute,
            "services.pharos-beacon.extraEnvironment"
        );
        assert!(proposal.nix_module.contains("PHAROS_BACKUP_MODE"));
        assert!(proposal.nix_module.contains("RESTIC_REPOSITORY_FILE"));
        assert!(proposal.nix_module.contains("RESTIC_PASSWORD_FILE"));
        assert!(proposal
            .nix_module
            .contains("/run/agenix/nix-1-restic-repository"));
        assert!(proposal
            .next_steps
            .iter()
            .any(|step| step.contains("Create or reference the agenix files")));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        assert!(!json.contains("PHAROS_TOKEN ="));
    }

    #[test]
    fn hetzner_setup_plan_selects_api_and_nixos_anywhere_path() {
        let plan = setup_provider_plan("hetzner-cloud", "hetzner-small-nixos")
            .expect("hetzner template has a plan");

        assert_eq!(plan.strategy, "hcloud-api-plus-nixos-anywhere");
        assert_eq!(plan.provider, "hetzner-cloud");
        assert_eq!(plan.template, "hetzner-small-nixos");
        assert!(plan.approach.contains("direct Hetzner Cloud API"));
        assert!(plan
            .docs
            .iter()
            .any(|doc| doc.url == "https://docs.hetzner.cloud/reference/cloud"));
        assert!(plan
            .docs
            .iter()
            .any(|doc| doc.url.contains("nixos-anywhere")));
        assert!(plan
            .resources
            .iter()
            .any(|resource| resource.key == "server"
                && resource.required
                && resource.api.contains("POST /servers")));
        assert!(plan
            .resources
            .iter()
            .any(|resource| resource.key == "firewall" && resource.required));
        assert!(plan
            .resources
            .iter()
            .any(|resource| resource.key == "volume" && !resource.required));
        assert!(plan.runtime_checks.contains(&"current provider price"));
        assert!(plan
            .steps
            .iter()
            .any(|step| step.key == "beacon_handoff" && step.status == "protected"));
        assert!(plan
            .secret_boundary
            .iter()
            .any(|boundary| boundary.key == "provider_api_token"
                && boundary.rule.contains("never serialize")));
        assert!(plan
            .handoffs
            .iter()
            .any(|handoff| handoff.key == "provider_executor" && handoff.target == "PHAROS-97"));
        let json = serde_json::to_string(&plan).expect("plan serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        assert_eq!(
            setup_provider_plan("hetzner-cloud", "manual-import").err(),
            Some(ProvisioningJobStartError::UnsupportedTemplate)
        );
    }

    fn report_test_state(require_report_token: bool) -> AppState {
        report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token,
            report_token_mode: BeaconTokenMode::Local,
            janus_token_hash_sources: vec![],
            local_register_enabled: true,
        })
    }

    fn report_test_state_with_auth(beacon_auth: BeaconAuth) -> AppState {
        AppState {
            store: Arc::new(Store::new(None)),
            provisioning_jobs: Arc::new(ProvisioningJobStore::new(None)),
            manifests: Arc::new(ManifestRegistry::default()),
            auth: None,
            beacon_auth,
            provider_runtime: ProviderRuntimeConfig::default(),
        }
    }

    fn janus_hash_file(host: &str, token: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pharos-janus-token-hashes-{}-{}.json",
            std::process::id(),
            nanos
        ));
        let payload = json!({
            "schema": JANUS_BEACON_TOKEN_HASH_SCHEMA,
            "hosts": [
                {
                    "name": host,
                    "token_sha256": token_hash(token)
                }
            ]
        });
        std::fs::write(&path, serde_json::to_string(&payload).unwrap()).expect("write hash file");
        path
    }

    fn janus_hash_dir(entries: &[(&str, &str)]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "pharos-janus-token-hash-dir-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir(&dir).expect("create hash dir");
        for (host, token) in entries {
            let path = dir.join(format!("{host}.json"));
            let payload = json!({
                "schema": JANUS_BEACON_TOKEN_HASH_SCHEMA,
                "hosts": [
                    {
                        "name": host,
                        "token_sha256": token_hash(token)
                    }
                ]
            });
            std::fs::write(&path, serde_json::to_string(&payload).unwrap())
                .expect("write hash file");
        }
        dir
    }

    fn test_report(host: &str) -> HostReport {
        HostReport {
            schema: pharos_core::HOST_REPORT_SCHEMA.to_string(),
            version: pharos_core::HOST_REPORT_VERSION,
            name: host.to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![],
            inbound_rtt_ms: None,
            location: None,
        }
    }

    fn register_test_token(state: &AppState, host: &str, token: &str) {
        state.store.register(
            HostRegistration {
                name: host.to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            },
            token_hash(token),
        );
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("valid bearer header"),
        );
        headers
    }

    #[tokio::test]
    async fn report_accepts_registered_host_without_token_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state.clone()),
            HeaderMap::new(),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state
            .store
            .list()
            .into_iter()
            .find(|host| host.name == "ares")
            .and_then(|host| host.last_seen)
            .is_some());
    }

    #[tokio::test]
    async fn report_accepts_valid_token_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("valid-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_rejects_invalid_token_even_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("wrong-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_rejects_missing_token_when_strict_enabled() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "valid-token");

        let status = report(State(state), HeaderMap::new(), Json(test_report("ares"))).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_accepts_valid_token_when_strict_enabled() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("valid-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_accepts_janus_hash_file_token_without_local_registration() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: false,
        });

        let status = report(
            State(state.clone()),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!state.store.has_token("ares"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_rejects_local_token_when_janus_mode_is_enabled() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: false,
        });
        register_test_token(&state, "ares", "local-token");

        let status = report(
            State(state),
            bearer_headers("local-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_accepts_local_or_janus_token_in_dual_mode() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Dual,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: true,
        });
        register_test_token(&state, "athena", "local-token");

        let janus_status = report(
            State(state.clone()),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;
        let local_status = report(
            State(state),
            bearer_headers("local-token"),
            Json(test_report("athena")),
        )
        .await;

        assert_eq!(janus_status, StatusCode::NO_CONTENT);
        assert_eq!(local_status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_accepts_janus_hash_sidecar_directory() {
        let dir = janus_hash_dir(&[("ares", "ares-token"), ("athena", "athena-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::Dir(dir.clone())],
            local_register_enabled: false,
        });

        let ares_status = report(
            State(state.clone()),
            bearer_headers("ares-token"),
            Json(test_report("ares")),
        )
        .await;
        let athena_status = report(
            State(state),
            bearer_headers("athena-token"),
            Json(test_report("athena")),
        )
        .await;

        assert_eq!(ares_status, StatusCode::NO_CONTENT);
        assert_eq!(athena_status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn report_ignores_janus_hash_sidecar_directory_temp_files() {
        let dir = janus_hash_dir(&[("ares", "ares-token")]);
        std::fs::write(dir.join(".ares.json.123.tmp"), "not-json").expect("write temp sidecar");
        std::fs::write(dir.join("README.txt"), "not-json").expect("write ignored text file");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::Dir(dir.clone())],
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("ares-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn report_fails_closed_when_janus_hash_file_is_unavailable() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(PathBuf::from(
                "/no/such/pharos-token-hashes.json",
            ))],
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn local_register_is_disabled_by_default_in_janus_mode() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap".to_string()),
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(PathBuf::from(
                "/run/janus/pharos-token-hashes.json",
            ))],
            local_register_enabled: false,
        });

        let (status, Json(payload)) = register(
            State(state),
            bearer_headers("bootstrap"),
            Json(HostRegistration {
                name: "ares".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            payload["error"],
            "local registration disabled; use Janus-managed beacon token issuance"
        );
    }

    #[test]
    fn janus_token_hash_contract_rejects_secret_shaped_or_invalid_hashes() {
        let err = parse_janus_token_hashes(
            r#"{
                "schema": "inspr.pharos.beacon-token-hashes.v1",
                "tokens": { "ares": "pharos_not_a_hash" }
            }"#,
        )
        .expect_err("invalid hash is rejected");

        assert_eq!(err, JanusTokenHashError::InvalidHash);
    }

    #[tokio::test]
    async fn server_probe_service_reports_reachable_tcp_target() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Local Test",
            "url": format!("http://{addr}/"),
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");

        let observation = server_probe_service(&service, 1000).await;

        assert_eq!(observation.state, ServiceObservationState::Healthy);
        assert_eq!(observation.server_reachable, Some(true));
        assert_eq!(observation.client_reachable, None);
        assert_eq!(observation.kind, "tcp-connect");
    }
}
