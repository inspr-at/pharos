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
mod alerting;
mod alerts;
mod appliance_probes;
mod auth;
mod durable_file;
mod host_actions;
mod icons;
mod janus_auth;
mod janus_projections;
mod managed_service_operations;
mod managed_service_ui;
mod managed_setup_intents;
mod manifests;
mod next_action;
mod nixcfg_dispatch;
mod paimos_delivery;
mod provider_connections;
mod provisioning;
mod routes;
mod startup;
mod store;
mod ui;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(unix)]
use std::os::unix::process::CommandExt;

use axum::extract::{DefaultBodyLimit, FromRef, Path as AxumPath, Query, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::{
    liveness,
    managed_operations::{
        ManagedOperationClaimV1, ManagedOperationReadyV1, ManagedOperationResultV1,
        MAX_MANAGED_OPERATION_REQUEST_BYTES,
    },
    managed_services::{
        ManagedBindingState, ManagedServiceManifestV1, MANAGED_SERVICE_MANIFEST_SCHEMA,
        MANAGED_SERVICE_MANIFEST_VERSION,
    },
    AccessSetupIntent, BackupObservation, BackupPostureState, BackupSetupIntent, BootstrapMethod,
    ExistingHostBootstrapOption, ExistingHostPreflightCheck, ExistingHostPreflightFacts,
    ExistingHostPreflightReport, ExistingHostPreflightRequest, ExistingHostPreflightSummary,
    ExistingHostSetupContext, GitRevisionRelation, Host, HostKind, HostLocation,
    HostLocationSource, HostManifest, HostNeedIntent, HostPreferences, HostRegistration,
    HostRegistrationResponse, HostReport, HostReportResponse, KernelPosture, KernelPostureState,
    Liveness, LocationSetupIntent, ManifestLocationMode, ManifestProbePolicy, ManifestService,
    ManifestStatusSource, NixFreshness, NixpkgsRevisionRelation, PreflightCheckState,
    PrivilegedActionMode, ProvisioningBackupProposal, ProvisioningBackupProposalKind,
    ProvisioningBackupSecretFile, ProvisioningHandoff, ProvisioningJob, ProvisioningJobState,
    ProvisioningManagedFailure, ProvisioningManagedIdentity, ProvisioningManagedIdentityState,
    ProvisioningPaidAuthorization, ProvisioningPaidExecution, ProvisioningProgressEntry,
    ProvisioningProviderResource, ProvisioningReviewedPaidPlan, ProvisioningSetupIntent,
    ProvisioningTerminalOutcome, SecretOwner, ServiceObservation, ServiceObservationState,
    SshAccessIntent, SshRoute, EXISTING_HOST_PREFLIGHT_SCHEMA, EXISTING_HOST_PREFLIGHT_VERSION,
    HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION, MAX_HOST_REGISTRATION_BYTES,
    MAX_HOST_REPORT_BYTES, PROVISIONING_JOB_SCHEMA, PROVISIONING_JOB_VERSION,
};
#[cfg(test)]
use pharos_core::{NixDeploymentEvidence, NixcfgGitComparison, NixpkgsGitComparison};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, MissedTickBehavior};
use url::Url;

use crate::alerting::*;
use crate::alerts::{AlertEvent, AlertStore, AlertWorkerHealth};
use crate::appliance_probes::{spawn_appliance_probe_loop, ApplianceProbeRuntime};
use crate::auth::{access_for_headers, AccessGrant, Auth, AuthConfig, AuthState};
#[cfg(test)]
use crate::host_actions::host_lifecycle;
use crate::host_actions::{
    active_update_restart_for_host, blocking_update_for_host, host_lifecycle_with_apply,
    host_preferences_state, linked_settings_apply, most_relevant_host_action,
    withdrawable_settings_change_for_host, AgentActionOutcome, AgentActionResultRequest,
    HostActionEventSource, HostActionJob, HostActionState, HostActionStore, HostActionStoreError,
    HostLifecycle, HostLifecycleSlot, HostPreferencesState, HostRemovalPlan,
    HostRetirementDisposition, HostSettingsContext, HostWorkflowKind, HostWorkflowSummary,
    RetiredHost, RetiredHostStore, RetirementAgentResultRequest, SystemUpdateProposalBegin,
    UpdateRestartIntent,
};
use crate::janus_auth::{JanusTokenHashError, JanusTokenReadiness, JanusTokenStore};
use crate::janus_projections::{capability_root_from_env, JanusCapability};
use crate::managed_service_operations::{
    ManagedOperationPhase, ManagedOperationStoreError, ManagedServiceOperationStore,
};
use crate::managed_setup_intents::*;
use crate::manifests::{ManifestLoadIssue, ManifestRegistry};
use crate::nixcfg_dispatch::{NixcfgDispatch, NixcfgDispatchError};
use crate::provider_connections::{
    compare_gross_prices, evidence_is_fresh, safe_hcloud_api_base, test_hetzner_connection,
    HetznerConnectionAttempt, HetznerConnectionCode, HetznerConnectionPreferences,
    HetznerConnectionTestResult, HetznerTestConfig, ProviderConnectionStore,
};
#[cfg(test)]
use crate::provider_connections::{
    HetznerCatalog, HetznerLocation, HetznerServerType, HetznerServerTypeLocation,
};
use crate::provisioning::*;
use crate::routes::build_router;
use crate::startup::*;
use crate::store::Store;
use crate::ui::*;

const SERVER_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const EXISTING_HOST_SSH_PROBE_TIMEOUT: Duration = Duration::from_secs(8);
const EXISTING_HOST_SSH_TOTAL_TIMEOUT: Duration = Duration::from_secs(120);
const SETTINGS_APPLY_UNAVAILABLE_REASON: &str =
    "Guarded apply is not prepared for this host because target-local Janus actions are not enabled.";
/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    provisioning_jobs: Arc<ProvisioningJobStore>,
    manifests: Arc<ManifestRegistry>,
    managed_setup_intents: Option<Arc<ManagedSetupIntentStore>>,
    managed_service_operations: Arc<ManagedServiceOperationStore>,
    auth: AuthState,
    beacon_auth: BeaconAuth,
    provider_runtime: ProviderRuntimeConfig,
    provider_connections: Arc<ProviderConnectionStore>,
    paid_create_lock: Arc<tokio::sync::Mutex<()>>,
    settings_change_lock: Arc<tokio::sync::Mutex<()>>,
    nixcfg_dispatch: NixcfgDispatch,
    retirement_owner: RetirementOwnerAuth,
    host_actions: Arc<HostActionStore>,
    retired_hosts: Arc<RetiredHostStore>,
    alert_health: AlertWorkerHealth,
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

#[derive(Clone)]
struct BeaconAuth {
    registration_token: Option<String>,
    require_report_token: bool,
    report_token_mode: BeaconTokenMode,
    janus_tokens: Option<JanusTokenStore>,
    local_register_enabled: bool,
}

impl BeaconAuth {
    fn from_env() -> Result<Self, String> {
        let registration_token =
            pharos_core::secret_input::optional_secret("PHAROS_REGISTRATION_TOKEN")
                .map_err(|error| error.to_string())?;
        let janus_tokens = janus_token_generation_root_from_env()?
            .map(JanusTokenStore::load)
            .transpose()
            .map_err(|error| {
                format!("Janus token generation failed startup validation: {error}")
            })?;
        let report_token_mode = match env_nonempty("PHAROS_BEACON_TOKEN_MODE") {
            Some(value) => parse_beacon_token_mode(&value)?,
            None => {
                if janus_tokens.is_some() {
                    BeaconTokenMode::Dual
                } else {
                    BeaconTokenMode::Local
                }
            }
        };
        let require_report_token = env_bool("PHAROS_REQUIRE_BEACON_TOKEN")?.unwrap_or(
            registration_token.is_some()
                || janus_tokens.is_some()
                || report_token_mode == BeaconTokenMode::Janus,
        );
        let local_register_enabled = env_bool("PHAROS_ALLOW_LOCAL_REGISTER")?
            .unwrap_or(report_token_mode != BeaconTokenMode::Janus);

        Self::validated(
            registration_token,
            require_report_token,
            report_token_mode,
            janus_tokens,
            local_register_enabled,
        )
    }

    fn validated(
        registration_token: Option<String>,
        require_report_token: bool,
        report_token_mode: BeaconTokenMode,
        janus_tokens: Option<JanusTokenStore>,
        local_register_enabled: bool,
    ) -> Result<Self, String> {
        if report_token_mode == BeaconTokenMode::Janus {
            if !require_report_token {
                return Err(
                    "PHAROS_BEACON_TOKEN_MODE=janus requires PHAROS_REQUIRE_BEACON_TOKEN=true"
                        .to_string(),
                );
            }
            if local_register_enabled {
                return Err(
                    "PHAROS_BEACON_TOKEN_MODE=janus requires PHAROS_ALLOW_LOCAL_REGISTER=false"
                        .to_string(),
                );
            }
            if registration_token.is_some() {
                return Err(
                    "PHAROS_REGISTRATION_TOKEN and PHAROS_REGISTRATION_TOKEN_FILE must be absent when PHAROS_BEACON_TOKEN_MODE=janus"
                        .to_string(),
                );
            }
            if janus_tokens.is_none() {
                return Err(
                    "PHAROS_BEACON_TOKEN_MODE=janus requires a Janus token generation root"
                        .to_string(),
                );
            }
        }

        Ok(Self {
            registration_token,
            require_report_token,
            report_token_mode,
            janus_tokens,
            local_register_enabled,
        })
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

    fn managed_agent_token_status(&self, host_ref: &str, token: &str) -> ReportTokenAuth {
        let Some(janus_tokens) = self.janus_tokens.as_ref() else {
            return ReportTokenAuth::Unavailable(JanusTokenHashError::NotConfigured);
        };
        let expected_hash = token_hash(token);
        match janus_tokens.token_matches(host_ref, &expected_hash) {
            Ok(true) => ReportTokenAuth::Allowed,
            Ok(false) => ReportTokenAuth::Denied,
            Err(error) => ReportTokenAuth::Unavailable(error),
        }
    }

    fn janus_token_matches(
        &self,
        host: &str,
        expected_hash: &str,
    ) -> Result<bool, JanusTokenHashError> {
        self.janus_tokens
            .as_ref()
            .ok_or(JanusTokenHashError::NotConfigured)?
            .token_matches(host, expected_hash)
    }

    fn janus_manages_host(&self, host: &str) -> Result<bool, JanusTokenHashError> {
        if self.report_token_mode == BeaconTokenMode::Local {
            return Ok(false);
        }
        self.janus_tokens
            .as_ref()
            .ok_or(JanusTokenHashError::NotConfigured)?
            .manages_host(host)
    }

    fn janus_readiness(&self) -> Option<JanusTokenReadiness> {
        self.janus_tokens
            .as_ref()
            .map(JanusTokenStore::refresh_readiness)
    }
}

#[derive(Clone, Default)]
struct RetirementOwnerAuth {
    owner_host: Option<String>,
}

impl RetirementOwnerAuth {
    fn from_env() -> Self {
        let owner_host = env_nonempty("PHAROS_RETIREMENT_OWNER_HOST");
        if let Some(host) = owner_host.as_deref() {
            assert!(
                valid_action_host_name(host),
                "PHAROS_RETIREMENT_OWNER_HOST must be a valid host name"
            );
            tracing::info!(owner = %host, "Pharos retirement owner enabled");
        }
        Self { owner_host }
    }

    fn configured(&self) -> bool {
        self.owner_host.is_some()
    }

    fn is_owner(&self, host: &str) -> bool {
        self.owner_host.as_deref() == Some(host)
    }
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

fn env_bool(name: &str) -> Result<Option<bool>, String> {
    let Some(value) = env_nonempty(name) else {
        return Ok(None);
    };
    parse_bool(&value)
        .map(Some)
        .ok_or_else(|| format!("{name} must be one of true/false, 1/0, yes/no, or on/off"))
}

fn parse_beacon_token_mode(value: &str) -> Result<BeaconTokenMode, String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" | "mvp" => Ok(BeaconTokenMode::Local),
        "dual" | "migration" => Ok(BeaconTokenMode::Dual),
        "janus" | "forge" | "warden" => Ok(BeaconTokenMode::Janus),
        _ => Err(format!(
            "unknown PHAROS_BEACON_TOKEN_MODE value {value:?}; expected local, dual, or janus"
        )),
    }
}

fn janus_token_generation_root_from_env() -> Result<Option<PathBuf>, String> {
    for name in [
        "PHAROS_BEACON_TOKEN_HASH_FILES",
        "PHAROS_BEACON_TOKEN_HASH_FILE",
        "PHAROS_JANUS_BEACON_TOKEN_HASH_FILE",
    ] {
        if env_nonempty(name).is_some() {
            return Err(format!(
                "{name} uses the retired v1 per-file contract; configure PHAROS_BEACON_TOKEN_HASH_DIR with a v2 generation root"
            ));
        }
    }
    capability_root_from_env(
        JanusCapability::PharosBeaconToken,
        Some("PHAROS_BEACON_TOKEN_HASH_DIR"),
    )
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

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SystemUpdateActionRequest {
    host: String,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateRestartActionRequest {
    #[serde(default)]
    intent: UpdateRestartIntent,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmHostActionRequest {
    confirmation: String,
    attended: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemoveHostActionRequest {
    confirmation: String,
    disposition: HostRetirementDisposition,
    #[serde(default)]
    successor: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfirmHostNameRequest {
    confirmation: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentActionClaimRequest {
    host: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RetirementAgentClaimRequest {
    owner: String,
}

fn action_request_header(headers: &HeaderMap) -> bool {
    headers
        .get("X-Pharos-Action")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == "1")
}

fn system_update_uncertainty_acknowledgement(headers: &HeaderMap) -> Option<&str> {
    headers
        .get("X-Pharos-Acknowledge-Uncertainty")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

pub(crate) fn action_actor(auth: &AuthState, headers: &HeaderMap) -> String {
    let raw = sidebar_user_label(auth, headers);
    let actor: String = raw
        .trim()
        .chars()
        .filter(|character| !character.is_control())
        .take(160)
        .collect();
    if actor.is_empty() {
        "operator".to_string()
    } else {
        actor
    }
}

fn action_error(status: StatusCode, message: &str) -> (StatusCode, Json<serde_json::Value>) {
    (status, Json(json!({ "error": message })))
}

fn action_message(job: &HostActionJob) -> Cow<'static, str> {
    if job.workflow_kind() == host_actions::HostWorkflowKind::SettingsChange {
        let outcome_uncertain = job
            .events
            .iter()
            .any(|event| event.kind == host_actions::HostActionEventKind::DispatchOutcomeUncertain);
        let uncertainty_acknowledged = job.events.iter().any(|event| {
            event.kind == host_actions::HostActionEventKind::DispatchUncertaintyAcknowledged
        });
        return Cow::Borrowed(match job.state {
            HostActionState::Succeeded => "The host reported the requested settings.",
            HostActionState::Cancelled => {
                "The pending settings request was withdrawn. An open nixcfg proposal was not changed."
            }
            HostActionState::Failed if outcome_uncertain && uncertainty_acknowledged => {
                "The operator recorded that nixcfg was checked. A fresh settings request may now be submitted deliberately."
            }
            HostActionState::Failed if outcome_uncertain => {
                "Pharos could not confirm whether nixcfg received the settings request. Verify nixcfg before allowing another request."
            }
            HostActionState::Failed => "The settings request stopped and was recorded.",
            _ => "The settings request is saved and waiting for the host.",
        });
    }
    if job.workflow_kind() == host_actions::HostWorkflowKind::SystemUpdateProposal {
        let outcome_uncertain = job
            .events
            .iter()
            .any(|event| event.kind == host_actions::HostActionEventKind::DispatchOutcomeUncertain);
        return Cow::Borrowed(match job.state {
            HostActionState::Succeeded => {
                "Pharos handed the update review request to nixcfg. Repository checks and review continue outside Pharos. No host was deployed or verified from Pharos."
            }
            HostActionState::Failed if outcome_uncertain => {
                "Pharos could not confirm whether nixcfg received this review request. Verify nixcfg before starting another fleet-wide proposal. No host change was deployed or verified from Pharos."
            }
            HostActionState::Failed => {
                "The system update review request stopped and was recorded. No host change was authorized from Pharos."
            }
            HostActionState::ProposalRequested => {
                "Pharos is recording the fleet-wide update review request. No host has changed."
            }
            _ => "The system update review workflow is recorded.",
        });
    }
    if job.workflow_kind() == host_actions::HostWorkflowKind::RemoveHost {
        let outcome_uncertain = job
            .events
            .iter()
            .any(|event| event.kind == host_actions::HostActionEventKind::DispatchOutcomeUncertain);
        let uncertainty_acknowledged = job.events.iter().any(|event| {
            event.kind == host_actions::HostActionEventKind::DispatchUncertaintyAcknowledged
        });
        return match job.state {
            HostActionState::ProposalRequested => Cow::Borrowed(
                "The retirement intent is saved while Pharos finishes the guarded handoff.",
            ),
            HostActionState::RemovalPending => Cow::Owned(job.summary().workflow.guidance),
            HostActionState::Succeeded => {
                Cow::Borrowed("The host retirement completed and was recorded.")
            }
            HostActionState::Failed if outcome_uncertain && uncertainty_acknowledged => {
                Cow::Borrowed(
                    "The operator recorded that nixcfg was checked. Reporting remains active, and a fresh removal request may now be started deliberately.",
                )
            }
            HostActionState::Failed if outcome_uncertain => Cow::Borrowed(
                "Pharos could not confirm whether nixcfg received the removal request. Reporting access remains active; verify nixcfg before allowing another request.",
            ),
            HostActionState::Failed => {
                Cow::Borrowed("The removal request stopped safely and remains recorded.")
            }
            _ => Cow::Borrowed("The host retirement workflow is recorded."),
        };
    }
    if job.recovery_started_at.is_some() {
        return match job.state {
            HostActionState::Applying => {
                Cow::Borrowed("The target-local recovery checks are running.")
            }
            HostActionState::Rebooting => {
                Cow::Borrowed("Recovery checks are queued for the target-local agent.")
            }
            HostActionState::Succeeded => {
                Cow::Borrowed("Current host evidence passed and the workflow was recovered.")
            }
            HostActionState::Failed => Cow::Owned(job.summary().workflow.guidance),
            _ => Cow::Borrowed("The recovery branch is recorded."),
        };
    }
    Cow::Borrowed(match job.state {
        HostActionState::ProposalRequested => {
            "Update review requested. No branch has been merged and no host has changed."
        }
        HostActionState::QueuedReview => "Guarded host review queued. No live change has started.",
        HostActionState::Reviewing => "The host is preparing a read-only review.",
        HostActionState::AwaitingConfirmation => {
            "Review passed. Explicit attended confirmation is still required."
        }
        HostActionState::QueuedApply => "Confirmed and waiting for the target-local agent.",
        HostActionState::Applying => "The target-local Janus workflow is running.",
        HostActionState::Rebooting => "The host is restarting; Pharos is waiting for verification.",
        HostActionState::RemovalPending => {
            "Beacon access is revoked; declarative removal is waiting for review and apply."
        }
        HostActionState::Succeeded => "The guarded action completed and was recorded.",
        HostActionState::Cancelled => {
            "The review was cancelled before any live change and remains recorded."
        }
        HostActionState::Failed if job.recoverable() => {
            "The live workflow stopped. Reconcile this saved run with current host evidence before continuing."
        }
        HostActionState::Failed => "The guarded action stopped safely and remains recorded.",
    })
}

fn action_response(
    status: StatusCode,
    job: &HostActionJob,
) -> (StatusCode, Json<serde_json::Value>) {
    let message = action_message(job);
    action_response_with_message(status, job, message.as_ref())
}

fn action_response_with_message(
    status: StatusCode,
    job: &HostActionJob,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let summary = job.summary();
    let workflow_html = host_workflow_markup(&summary.workflow);
    (
        status,
        Json(json!({
            "message": message,
            "job": summary,
            "workflow_html": workflow_html,
        })),
    )
}

fn action_response_with_host_settings_context(
    status: StatusCode,
    job: &HostActionJob,
    settings: HostSettingsContext<'_>,
) -> (StatusCode, Json<serde_json::Value>) {
    let summary = job.summary_with_host_settings_context(settings);
    let message = match summary
        .workflow
        .primary_action
        .as_ref()
        .map(|action| action.kind)
    {
        Some(host_actions::HostWorkflowActionKind::Continue) => Cow::Borrowed(
            "Pharos has the exact saved settings, but no durable repository receipt. Choose Continue request to send them through the reviewed nixcfg workflow.",
        ),
        Some(host_actions::HostWorkflowActionKind::Restart) => Cow::Borrowed(
            "The exact saved settings are no longer available. Clear this request and start over.",
        ),
        Some(host_actions::HostWorkflowActionKind::ApplyDeclared) => Cow::Owned(format!(
            "The declaration is ready. Apply it on {} through the guarded deployment workflow.",
            job.host
        )),
        _ => action_message(job),
    };
    let workflow_html = host_workflow_markup(&summary.workflow);
    (
        status,
        Json(json!({
            "message": message,
            "job": summary,
            "workflow_html": workflow_html,
        })),
    )
}

fn action_response_with_settings_context_and_message(
    status: StatusCode,
    job: &HostActionJob,
    declared_preferences: Option<&HostPreferences>,
    pending_preferences: Option<&HostPreferences>,
    legacy_nix_host: bool,
    message: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    let summary = job.summary_with_settings_context(
        declared_preferences,
        pending_preferences,
        legacy_nix_host,
    );
    let workflow_html = host_workflow_markup(&summary.workflow);
    (
        status,
        Json(json!({
            "message": message,
            "job": summary,
            "workflow_html": workflow_html,
        })),
    )
}

pub(crate) fn host_workflow_markup(workflow: &HostWorkflowSummary) -> String {
    let ladder = workflow
        .ladder
        .iter()
        .map(|fact| {
            let at = fact
                .at
                .map(|at| format!(" <time>{}</time>", html_escape(&clock_label(at))))
                .unwrap_or_default();
            format!(
                r#"<li data-ladder-key="{key}" data-ladder-state="{state}"><span class="host-workflow-ladder-marker" aria-hidden="true"></span><span><strong>{label}</strong><small>{fact}{at}</small></span></li>"#,
                key = html_escape(fact.key),
                state = html_escape(fact.state),
                label = html_escape(fact.label),
                fact = html_escape(&fact.fact),
                at = at,
            )
        })
        .collect::<String>();
    let next_action = workflow
        .primary_action
        .as_ref()
        .filter(|action| action.kind == host_actions::HostWorkflowActionKind::Refresh)
        .map(|action| {
            format!(
                r#"<button class="host-action-dialog-button primary" type="button" data-host-action-refresh>{}</button>"#,
                html_escape(&action.label)
            )
        })
        .unwrap_or_default();
    let next = format!(
        r#"<section class="host-workflow-next" aria-labelledby="host-workflow-next-title"><span>Next</span><div><h3 id="host-workflow-next-title">{title}</h3><p>{consequence}</p>{next_action}<dl><dt>Where</dt><dd>{location}</dd><dt>Will not</dt><dd>{boundary}</dd></dl></div></section>"#,
        title = html_escape(&workflow.next.title),
        consequence = html_escape(&workflow.next.consequence),
        next_action = next_action,
        location = html_escape(&workflow.next.location),
        boundary = html_escape(&workflow.next.boundary),
    );
    let mut groups = String::new();
    let mut current_group = "";
    for (index, step) in workflow.steps.iter().enumerate() {
        let current = workflow.current_step.as_deref() == Some(step.key.as_str());
        let waiting_for_evidence = workflow.kind == host_actions::HostWorkflowKind::SettingsChange
            && current
            && step.state.key() == "waiting";
        let state_label = workflow_step_presentation_label(workflow, step);
        let location_label = step.location.label(&workflow.host);
        let current_attribute = if current {
            r#" aria-current="step""#
        } else {
            ""
        };
        let location = if current {
            format!("<small>on {}</small>", html_escape(&location_label))
        } else {
            String::new()
        };
        let state_aria = if current {
            format!("{state_label} on {location_label}")
        } else {
            state_label.to_string()
        };
        if step.group != current_group {
            if !current_group.is_empty() {
                groups.push_str("</div></section>");
            }
            current_group = &step.group;
            groups.push_str(&format!(
                r#"<section class="host-workflow-group" aria-label="{group}"><h3>{group}</h3><div class="host-workflow-steps" role="list">"#,
                group = html_escape(current_group)
            ));
        }
        groups.push_str(&format!(
            r#"<div class="host-workflow-step" role="listitem" data-step-state="{state}" data-current="{current}" data-waiting-for-evidence="{waiting_for_evidence}" aria-busy="{busy}"{current_attribute}><span class="host-workflow-marker" aria-hidden="true"></span><span class="host-workflow-step-copy"><strong>{number}. {label}</strong><span>{detail}</span></span><span class="host-workflow-step-state" aria-label="{state_aria}"><span>{state_label}</span>{location}</span></div>"#,
            state = step.state.key(),
            current = current,
            waiting_for_evidence = waiting_for_evidence,
            busy = step.state.key() == "running" || waiting_for_evidence,
            current_attribute = current_attribute,
            number = index + 1,
            label = html_escape(&step.label),
            detail = html_escape(&step.detail),
            state_label = state_label,
            state_aria = html_escape(&state_aria),
            location = location,
        ));
    }
    if !current_group.is_empty() {
        groups.push_str("</div></section>");
    }

    let workflow_evidence = workflow
        .evidence
        .iter()
        .map(|fact| {
            format!(
                "<dt>{}</dt><dd>{}</dd>",
                html_escape(&fact.label),
                html_escape(&fact.value)
            )
        })
        .collect::<String>();
    let linked_evidence = workflow
        .linked_run_id
        .as_ref()
        .map_or_else(String::new, |id| {
            let state = workflow
                .linked_run_state
                .map(|state| state.key().replace('_', " "))
                .unwrap_or_else(|| "recorded".to_string());
            format!(
                "<dt>Guarded apply run</dt><dd>{}</dd><dt>Guarded apply state</dt><dd>{}</dd>",
                html_escape(id),
                html_escape(&state),
            )
        });
    let evidence = format!(
        "<dt>Run ID</dt><dd>{run_id}</dd><dt>Host</dt><dd>{host}</dd><dt>Started</dt><dd>{created}</dd><dt>Last update</dt><dd>{updated}</dd><dt>Recorded span</dt><dd>{duration}</dd>{linked_evidence}{workflow_evidence}",
        run_id = html_escape(&workflow.run_id),
        host = html_escape(&workflow.host),
        created = html_escape(&clock_label(workflow.created_at)),
        updated = html_escape(&clock_label(workflow.updated_at)),
        duration = html_escape(&duration_label(workflow.recorded_duration_secs)),
        linked_evidence = linked_evidence,
    );
    let events = workflow
        .events
        .iter()
        .rev()
        .map(|event| {
            let source = match event.source {
                HostActionEventSource::Operator => "operator",
                HostActionEventSource::HostAgent => "host agent",
                HostActionEventSource::RetirementAgent => "retirement owner",
                HostActionEventSource::Beacon => "heartbeat",
                HostActionEventSource::Pharos => "Pharos",
            };
            let actor = event
                .actor
                .as_deref()
                .map(|actor| format!(" · {}", html_escape(actor)))
                .unwrap_or_default();
            format!(
                r#"<li><time>{}</time><span><strong>{}</strong><small>{source}{actor}</small></span></li>"#,
                clock_label(event.at),
                html_escape(&event.label),
            )
        })
        .collect::<String>();
    let current_location = workflow
        .current_location
        .map(|location| location.label(&workflow.host));
    let current_status = workflow
        .current_step
        .as_deref()
        .and_then(|key| workflow.steps.iter().find(|step| step.key == key))
        .map(|step| workflow_step_state_label(step.state.key()))
        .unwrap_or(&workflow.status_label);
    let current_location = current_location
        .map(|location| format!(" on {}", html_escape(&location)))
        .unwrap_or_default();
    format!(
        r#"<section class="host-workflow-summary" data-workflow-kind="{kind}" data-workflow-status="{status}"><ol class="host-workflow-ladder" aria-label="Run truth: observed, declared, requested, executed, verified">{ladder}</ol><div class="host-workflow-meta"><span>Started <time>{created}</time></span><span><strong>{current_status}</strong>{current_location}</span></div>{next}{groups}<details class="host-workflow-advanced"><summary>Advanced details</summary><div><p>Sanitized plan evidence and workflow history. Credentials, secret values, paths, hashes, and command output are excluded.</p><dl class="host-workflow-evidence" aria-label="Sanitized workflow evidence">{evidence}</dl><ol>{events}</ol></div></details><p class="host-workflow-persisted">This run is saved and resumes after refresh or restart.</p></section>"#,
        kind = workflow_kind_key(workflow.kind),
        status = html_escape(&workflow.status_label),
        ladder = ladder,
        created = html_escape(&clock_label(workflow.created_at)),
        current_status = html_escape(current_status),
        next = next,
    )
}

fn workflow_kind_key(kind: host_actions::HostWorkflowKind) -> &'static str {
    match kind {
        host_actions::HostWorkflowKind::SettingsChange => "settings_change",
        host_actions::HostWorkflowKind::SystemUpdateProposal => "system_update_proposal",
        host_actions::HostWorkflowKind::UpdateRestart => "update_restart",
        host_actions::HostWorkflowKind::RemoveHost => "remove_host",
    }
}

fn workflow_step_state_label(state: &str) -> &'static str {
    match state {
        "queued" => "queued",
        "running" => "in progress",
        "waiting" => "waiting",
        "confirmation_required" => "confirmation required",
        "action_required" => "action required",
        "passed" => "complete",
        "failed" => "stopped",
        "skipped" => "not required",
        "recovered" => "recovered",
        "cancelled" => "cancelled",
        _ => "recorded",
    }
}

fn workflow_step_presentation_label(
    workflow: &host_actions::HostWorkflowSummary,
    step: &host_actions::HostWorkflowStep,
) -> &'static str {
    if workflow.kind == host_actions::HostWorkflowKind::SystemUpdateProposal
        && step.state.key() == "skipped"
    {
        match workflow.status_label.as_str() {
            "review handed to nixcfg" => match step.key.as_str() {
                "validate" | "review" => "continues in nixcfg",
                "deploy" => "not deployed",
                _ => workflow_step_state_label(step.state.key()),
            },
            "dispatch outcome uncertain" => match step.key.as_str() {
                "validate" | "review" => "not confirmed",
                "deploy" => "not deployed",
                _ => workflow_step_state_label(step.state.key()),
            },
            "update review stopped" => match step.key.as_str() {
                "validate" | "review" => "not attempted",
                "deploy" => "not deployed",
                _ => workflow_step_state_label(step.state.key()),
            },
            _ => workflow_step_state_label(step.state.key()),
        }
    } else {
        workflow_step_state_label(step.state.key())
    }
}

fn host_is_declared(state: &AppState, host: &str) -> bool {
    state
        .manifests
        .manifests()
        .iter()
        .any(|manifest| manifest.host.name == host || manifest.slug == host)
        || state.manifests.declared_preferences_for(host).is_some()
}

fn host_needs_declaration_cleanup(state: &AppState, host: &str) -> bool {
    host_is_declared(state, host)
}

fn host_janus_actions_ready(state: &AppState, host: &str) -> bool {
    let declared_ready = state.manifests.manifests().iter().any(|manifest| {
        (manifest.host.name == host || manifest.slug == host)
            && manifest.policy.privileged_actions.mode == PrivilegedActionMode::Janus
            && manifest.policy.privileged_actions.janus_required
    });
    declared_ready && state.beacon_auth.janus_manages_host(host).unwrap_or(false)
}

fn update_restart_target_error(
    state: &AppState,
    host: &str,
    intent: UpdateRestartIntent,
) -> Option<(StatusCode, &'static str)> {
    let Some(runtime) = state.store.get(host) else {
        return Some((StatusCode::NOT_FOUND, "Host is not reporting to Pharos"));
    };
    if !runtime.is_nix {
        return Some((
            StatusCode::CONFLICT,
            "Guarded system updates are available only for Nix hosts",
        ));
    }
    if !host_janus_actions_ready(state, host) {
        return Some((
            StatusCode::CONFLICT,
            "This host is not prepared for target-local Janus actions yet",
        ));
    }
    match intent {
        UpdateRestartIntent::Update => {
            if kernel_reboot_required(runtime.kernel.as_ref()).is_none()
                && !runtime.freshness.has_proven_deployable_update()
            {
                return Some((
                    StatusCode::CONFLICT,
                    "No pending system update or restart is currently reported for this host",
                ));
            }
        }
        UpdateRestartIntent::ApplyDeclared => {
            let preferences = host_preferences_state(
                &runtime.preferences,
                state.manifests.declared_preferences_for(host),
                runtime.requested_preferences.as_ref(),
            );
            if preferences != HostPreferencesState::DeclaredNotApplied
                && kernel_reboot_required(runtime.kernel.as_ref()).is_none()
            {
                return Some((
                    StatusCode::CONFLICT,
                    "No declared preference or kernel drift is ready to apply for this host",
                ));
            }
        }
        UpdateRestartIntent::RestartOnly => {
            return Some((
                StatusCode::CONFLICT,
                "Restart-only workflows are not available in this release",
            ));
        }
    }
    None
}

fn system_update_action_response_for_existing_replacement(
    workflow: &HostActionJob,
) -> (StatusCode, Json<serde_json::Value>) {
    if host_actions::system_update_dispatch_handed_off(workflow) {
        return action_response(StatusCode::ACCEPTED, workflow);
    }
    if workflow.state == HostActionState::Failed {
        if workflow
            .events
            .iter()
            .any(|event| event.kind == host_actions::HostActionEventKind::DispatchOutcomeUncertain)
        {
            return action_response_with_message(
                StatusCode::CONFLICT,
                workflow,
                "Pharos could not confirm whether nixcfg received the review request. Verify nixcfg before retrying.",
            );
        }
        return action_response_with_message(
            StatusCode::BAD_GATEWAY,
            workflow,
            "The repository workflow rejected the review request; no host change was authorized",
        );
    }
    action_response(StatusCode::ACCEPTED, workflow)
}

async fn request_system_update(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<SystemUpdateActionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    let host = request.host.trim();
    if !action_request_header(&headers) || !access.can_manage_fleet() || !access.allows_host(host) {
        return action_error(
            StatusCode::FORBIDDEN,
            "Fleet update review access is not granted",
        );
    }
    let Some(runtime) = state.store.get(host) else {
        return action_error(StatusCode::NOT_FOUND, "Host is not reporting to Pharos");
    };
    if !runtime.is_nix {
        return action_error(
            StatusCode::CONFLICT,
            "System update proposals are available only for declared Nix hosts",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    let now = now_unix();
    let acknowledge_uncertainty =
        system_update_uncertainty_acknowledgement(&headers).map(str::to_string);
    if let Some(id) = acknowledge_uncertainty.as_deref() {
        if !host_actions::system_update_uncertainty_acknowledgement_id_valid(id) {
            return action_error(
                StatusCode::BAD_REQUEST,
                "The uncertainty acknowledgement reference is invalid",
            );
        }
    }
    let begin = match state.host_actions.begin_system_update_proposal(
        host,
        &actor,
        now,
        acknowledge_uncertainty.as_deref(),
    ) {
        Ok(begin) => begin,
        Err(HostActionStoreError::InvalidJob) => {
            return action_error(
                StatusCode::BAD_REQUEST,
                "The uncertainty acknowledgement reference is invalid",
            );
        }
        Err(HostActionStoreError::NotFound) => {
            return action_error(
                StatusCode::BAD_REQUEST,
                "The uncertainty acknowledgement reference was not found",
            );
        }
        Err(HostActionStoreError::WrongHost) => {
            return action_error(
                StatusCode::FORBIDDEN,
                "The uncertainty acknowledgement does not belong to this host",
            );
        }
        Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job)) => {
            return action_response_with_message(
                StatusCode::CONFLICT,
                &job,
                "Pharos could not confirm the prior repository dispatch. Review the saved workflow, verify nixcfg, then acknowledge the uncertainty before starting another fleet-wide request.",
            );
        }
        Err(HostActionStoreError::ActiveSystemUpdateProposal(job)) => {
            return action_response_with_message(
                StatusCode::CONFLICT,
                &job,
                "A fleet-wide system update review is already open. Open the saved workflow before starting another request.",
            );
        }
        Err(_) => {
            return action_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The update review checklist could not be recorded",
            );
        }
    };
    if let SystemUpdateProposalBegin::Existing(workflow) = &begin {
        return system_update_action_response_for_existing_replacement(workflow);
    }
    let workflow = match begin {
        SystemUpdateProposalBegin::New(job) => job,
        SystemUpdateProposalBegin::Existing(_) => {
            unreachable!("existing replacements handled above")
        }
    };
    if let Err(error) = state
        .nixcfg_dispatch
        .dispatch_system_update_with_key(host, &workflow.id)
        .await
    {
        let failed = match error {
            NixcfgDispatchError::OutcomeUncertain => state
                .host_actions
                .fail_system_update_proposal_uncertain(&workflow.id, now_unix())
                .unwrap_or(workflow),
            _ => state
                .host_actions
                .fail_system_update_proposal(&workflow.id, now_unix())
                .unwrap_or(workflow),
        };
        return action_response_with_message(
            if error.is_outcome_uncertain() {
                StatusCode::CONFLICT
            } else {
                StatusCode::BAD_GATEWAY
            },
            &failed,
            error.system_update_message(),
        );
    }
    let submitted = match state.host_actions.mark_dispatch_submitted_with_request_id(
        &workflow.id,
        &workflow.id,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => state
            .host_actions
            .get(&workflow.id)
            .unwrap_or_else(|| workflow.clone()),
        Err(_) => {
            let uncertain = state
                .host_actions
                .fail_system_update_proposal_uncertain(&workflow.id, now_unix())
                .ok()
                .or_else(|| state.host_actions.get(&workflow.id))
                .unwrap_or_else(|| workflow.clone());
            return action_response_with_message(
                StatusCode::CONFLICT,
                &uncertain,
                "The update request was sent, but Pharos could not record the repository handoff. Verify nixcfg before any retry.",
            );
        }
    };
    tracing::info!(host = %host, actor = %actor, ticket = "PHAROS-125", "system update review handed to nixcfg");
    action_response(StatusCode::ACCEPTED, &submitted)
}

async fn request_update_restart_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(host): AxumPath<String>,
    Json(request): Json<UpdateRestartActionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() || !access.allows_host(&host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded host action access is not granted",
        );
    }
    if let Some((status, message)) = update_restart_target_error(&state, &host, request.intent) {
        return action_error(status, message);
    }
    let actor = action_actor(&state.auth, &headers);
    match state.host_actions.create_update_review_with_intent(
        &host,
        &actor,
        request.intent,
        now_unix(),
    ) {
        Ok(job) => {
            tracing::info!(host = %host, actor = %actor, intent = request.intent.key(), ticket = %job.ticket, "guarded host review queued");
            action_response(StatusCode::ACCEPTED, &job)
        }
        Err(HostActionStoreError::ActiveJob) => action_error(
            StatusCode::CONFLICT,
            "A guarded update workflow is already active for this host",
        ),
        Err(HostActionStoreError::FailedJobRequiresRetry) => action_error(
            StatusCode::CONFLICT,
            "The latest guarded review failed; retry that recorded attempt",
        ),
        Err(HostActionStoreError::BlockedByFleetGate) => {
            let jobs = state.host_actions.list();
            let message = blocking_update_for_host(&jobs, &host).map_or_else(
                || "Another host update workflow must finish or be resolved first".to_string(),
                |blocker| {
                    format!(
                        "{} holds the fleet update lock; finish or resolve that workflow first",
                        blocker.host
                    )
                },
            );
            action_error(StatusCode::CONFLICT, &message)
        }
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The guarded review could not be recorded",
        ),
    }
}

async fn apply_declared_settings_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let _settings_change_guard = state.settings_change_lock.lock().await;
    let Some(settings) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Settings request was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&settings.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded settings apply access is not granted",
        );
    }
    if settings.workflow_kind() != HostWorkflowKind::SettingsChange {
        return action_error(StatusCode::CONFLICT, "This run is not a settings request");
    }
    let declared = state.manifests.declared_preferences_for(&settings.host);
    if settings.requested_preferences().is_none() || settings.requested_preferences() != declared {
        return action_error(
            StatusCode::CONFLICT,
            "The loaded nixcfg declaration does not exactly match this saved settings request",
        );
    }
    if let Some((status, message)) =
        update_restart_target_error(&state, &settings.host, UpdateRestartIntent::ApplyDeclared)
    {
        return action_error(status, message);
    }
    let actor = action_actor(&state.auth, &headers);
    let linked = match state.host_actions.begin_settings_apply_review(
        &id,
        &settings.host,
        &actor,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => {
            let jobs = state.host_actions.list();
            match linked_settings_apply(&jobs, &id).cloned() {
                Some(job) => job,
                None => {
                    return action_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "The guarded review was saved but could not be reloaded",
                    )
                }
            }
        }
        Err(HostActionStoreError::ActiveJob) => {
            return action_error(
                StatusCode::CONFLICT,
                "A guarded update workflow is already active for this host",
            )
        }
        Err(HostActionStoreError::FailedJobRequiresRetry) => {
            return action_error(
                StatusCode::CONFLICT,
                "The latest guarded review failed; retry that recorded attempt",
            )
        }
        Err(HostActionStoreError::BlockedByFleetGate) => {
            let jobs = state.host_actions.list();
            let message = blocking_update_for_host(&jobs, &settings.host).map_or_else(
                || "Another guarded host workflow must finish first".to_string(),
                |blocker| {
                    format!(
                        "{} holds the fleet update lock; finish or resolve that workflow first",
                        blocker.host
                    )
                },
            );
            return action_error(StatusCode::CONFLICT, &message);
        }
        Err(HostActionStoreError::WrongHost) => {
            return action_error(
                StatusCode::FORBIDDEN,
                "Settings request belongs to another host",
            )
        }
        Err(HostActionStoreError::NotFound) => {
            return action_error(StatusCode::NOT_FOUND, "Settings request was not found")
        }
        Err(HostActionStoreError::InvalidTransition) => {
            return action_error(
                StatusCode::CONFLICT,
                "The repository handoff is not durably accepted and ready to apply",
            )
        }
        Err(_) => {
            return action_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The guarded settings review could not be recorded",
            )
        }
    };
    tracing::info!(host = %settings.host, actor = %actor, settings_run = %id, guarded_run = %linked.id, ticket = "PHAROS-241", "guarded declared settings review linked");
    let runtime_host = state.store.get(&settings.host);
    let jobs = state.host_actions.list();
    let linked_apply = linked_settings_apply(&jobs, &id);
    action_response_with_host_settings_context(
        StatusCode::ACCEPTED,
        &settings,
        HostSettingsContext {
            declared_preferences: declared,
            pending_preferences: runtime_host
                .as_ref()
                .and_then(|host| host.requested_preferences.as_ref()),
            legacy_nix_host: runtime_host.as_ref().is_some_and(|host| host.is_nix),
            apply_declared_ready: true,
            apply_declared_unavailable_reason: None,
            linked_apply,
            apply_blocked_by: None,
        },
    )
}

async fn retry_update_restart_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded host action access is not granted",
        );
    }
    if let Some((status, message)) =
        update_restart_target_error(&state, &existing.host, existing.update_restart_intent())
    {
        return action_error(status, message);
    }
    let actor = action_actor(&state.auth, &headers);
    match state
        .host_actions
        .retry_update_review(&id, &existing.host, &actor, now_unix())
    {
        Ok(job) => {
            tracing::info!(host = %job.host, actor = %actor, ticket = "PHAROS-126", "failed guarded host review retried");
            action_response(StatusCode::ACCEPTED, &job)
        }
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "Only the latest pre-confirmation review failure can be retried",
        ),
        Err(HostActionStoreError::ActiveJob) => action_error(
            StatusCode::CONFLICT,
            "A guarded update workflow is already active for this host",
        ),
        Err(HostActionStoreError::BlockedByFleetGate) => {
            let jobs = state.host_actions.list();
            let message = blocking_update_for_host(&jobs, &existing.host).map_or_else(
                || "Another host update workflow must finish or be resolved first".to_string(),
                |blocker| {
                    format!(
                        "{} holds the fleet update lock; finish or resolve that workflow first",
                        blocker.host
                    )
                },
            );
            action_error(StatusCode::CONFLICT, &message)
        }
        Err(HostActionStoreError::NotFound) => {
            action_error(StatusCode::NOT_FOUND, "Guarded action was not found")
        }
        Err(HostActionStoreError::WrongHost) => action_error(
            StatusCode::FORBIDDEN,
            "Guarded action does not belong to this host",
        ),
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The guarded retry could not be recorded",
        ),
    }
}

async fn cancel_update_restart_review(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded host action access is not granted",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    match state.host_actions.cancel_update_review(
        &id,
        &existing.host,
        &actor,
        now_unix(),
    ) {
        Ok(job) => {
            tracing::info!(host = %job.host, actor = %actor, ticket = "PHAROS-129", "guarded host review cancelled before live change");
            action_response(StatusCode::OK, &job)
        }
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "This review can no longer be cancelled because the live gate has started or the run is already complete",
        ),
        Err(HostActionStoreError::WrongHost) => action_error(
            StatusCode::FORBIDDEN,
            "Guarded action does not belong to this host",
        ),
        Err(HostActionStoreError::NotFound) => {
            action_error(StatusCode::NOT_FOUND, "Guarded action was not found")
        }
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The safe cancellation could not be recorded",
        ),
    }
}

async fn withdraw_settings_change(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(preview) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Settings change was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_agora() || !access.allows_host(&preview.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Settings change access is not granted",
        );
    }
    // A withdrawal must run wholly before a settings submission begins or
    // after its handoff and pending write have both completed.
    let _settings_change_guard = state.settings_change_lock.lock().await;
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Settings change was not found");
    };
    if !existing.can_withdraw() {
        return action_error(
            StatusCode::CONFLICT,
            "Only a non-terminal settings change can be withdrawn",
        );
    }
    let Some(host_before) = state.store.get(&existing.host) else {
        return action_error(
            StatusCode::CONFLICT,
            "The settings change host is not in the fleet store",
        );
    };
    let previous_preferences = host_before.requested_preferences.clone();
    if let Err(error) = state.store.clear_requested_preferences(&existing.host) {
        tracing::error!(host = %existing.host, error = %error, "pending host settings could not be cleared for withdrawal");
        return action_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "The pending settings request could not be cleared",
        );
    }

    let actor = action_actor(&state.auth, &headers);
    let withdrawn = match state.host_actions.withdraw_settings_change(
        &id,
        &existing.host,
        &actor,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => {
            let Some(job) = state
                .host_actions
                .get(&id)
                .filter(|job| job.state == HostActionState::Cancelled)
            else {
                return action_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The withdrawal was persisted but could not be reloaded",
                );
            };
            job
        }
        Err(error) => {
            let workflow_still_withdrawable = state
                .host_actions
                .get(&id)
                .is_some_and(|job| job.can_withdraw());
            if let Some(preferences) = previous_preferences.filter(|_| workflow_still_withdrawable)
            {
                if let Err(restore_error) =
                    state.store.request_preferences(&existing.host, preferences)
                {
                    tracing::error!(host = %existing.host, error = %restore_error, "pending settings request could not be restored after withdrawal failure");
                }
            }
            let (status, message) = match error {
                HostActionStoreError::InvalidTransition => (
                    StatusCode::CONFLICT,
                    "Only a non-terminal settings change can be withdrawn",
                ),
                HostActionStoreError::WrongHost => (
                    StatusCode::FORBIDDEN,
                    "Settings change does not belong to this host",
                ),
                HostActionStoreError::NotFound => {
                    (StatusCode::NOT_FOUND, "Settings change was not found")
                }
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The settings change withdrawal could not be recorded",
                ),
            };
            return action_error(status, message);
        }
    };
    tracing::info!(host = %withdrawn.host, actor = %actor, ticket = "PHAROS-215", "pending settings request withdrawn without changing nixcfg");
    action_response_with_message(
        StatusCode::OK,
        &withdrawn,
        "Clears the pending request. An open nixcfg proposal stays open there.",
    )
}

async fn recover_update_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded recovery access is not granted",
        );
    }
    let Some(runtime) = state.store.get(&existing.host) else {
        return action_error(
            StatusCode::CONFLICT,
            "The host is not reporting; inspect it before starting recovery checks",
        );
    };
    if liveness(
        runtime.last_seen,
        runtime.heartbeat_interval_secs,
        now_unix(),
    ) != Liveness::Live
    {
        return action_error(
            StatusCode::CONFLICT,
            "Wait for a fresh live heartbeat before starting recovery checks",
        );
    }
    if !runtime
        .kernel
        .as_ref()
        .is_some_and(|kernel| kernel.state == KernelPostureState::Current)
    {
        return action_error(
            StatusCode::CONFLICT,
            "The host has not reported the expected current kernel",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    match state
        .host_actions
        .queue_recovery(&id, &existing.host, &actor, now_unix())
    {
        Ok(job) => {
            tracing::info!(host = %job.host, actor = %actor, ticket = "PHAROS-131", "guarded host workflow recovery queued");
            action_response(StatusCode::ACCEPTED, &job)
        }
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "Only the latest failed post-confirmation workflow can enter recovery",
        ),
        Err(HostActionStoreError::BlockedByFleetGate) => action_error(
            StatusCode::CONFLICT,
            "Resolve the earlier host workflow before starting this recovery",
        ),
        Err(HostActionStoreError::WrongHost) => action_error(
            StatusCode::FORBIDDEN,
            "Guarded action does not belong to this host",
        ),
        Err(HostActionStoreError::NotFound) => {
            action_error(StatusCode::NOT_FOUND, "Guarded action was not found")
        }
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The recovery branch could not be recorded",
        ),
    }
}

async fn host_action_job_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(job) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora() || !access.allows_host(&job.host) {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded action access is not granted",
        );
    }
    let runtime_host = state.store.get(&job.host);
    let jobs = state.host_actions.list();
    let linked_apply = (job.workflow_kind() == HostWorkflowKind::SettingsChange)
        .then(|| linked_settings_apply(&jobs, &job.id))
        .flatten();
    let blocker = blocking_update_for_host(&jobs, &job.host);
    let declared_preferences = state.manifests.declared_preferences_for(&job.host);
    let apply_declared_ready = runtime_host.as_ref().is_some_and(|host| {
        host.is_nix
            && host_janus_actions_ready(&state, &job.host)
            && (host_preferences_state(
                &host.preferences,
                declared_preferences,
                host.requested_preferences.as_ref(),
            ) == HostPreferencesState::DeclaredNotApplied
                || kernel_reboot_required(host.kernel.as_ref()).is_some())
    });
    action_response_with_host_settings_context(
        StatusCode::OK,
        &job,
        HostSettingsContext {
            declared_preferences,
            pending_preferences: runtime_host
                .as_ref()
                .and_then(|host| host.requested_preferences.as_ref()),
            legacy_nix_host: runtime_host.as_ref().is_some_and(|host| host.is_nix),
            apply_declared_ready,
            apply_declared_unavailable_reason: (!apply_declared_ready)
                .then_some(SETTINGS_APPLY_UNAVAILABLE_REASON),
            linked_apply,
            apply_blocked_by: blocker.map(|job| job.host.as_str()),
        },
    )
}

async fn acknowledge_dispatch_uncertainty(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    let workflow_allowed = match existing.workflow_kind() {
        host_actions::HostWorkflowKind::SettingsChange => access.can_agora(),
        host_actions::HostWorkflowKind::RemoveHost => access.can_manage_fleet(),
        _ => false,
    };
    if !action_request_header(&headers) || !workflow_allowed || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Dispatch uncertainty acknowledgement access is not granted",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    match state
        .host_actions
        .acknowledge_dispatch_uncertainty(&id, &actor, now_unix())
    {
        Ok(job) => action_response_with_message(
            StatusCode::OK,
            &job,
            "The nixcfg verification was recorded. A fresh request may now be started deliberately.",
        ),
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "Only an uncertain settings or removal dispatch can be acknowledged",
        ),
        Err(HostActionStoreError::NotFound) => {
            action_error(StatusCode::NOT_FOUND, "Guarded action was not found")
        }
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The dispatch uncertainty acknowledgement could not be recorded",
        ),
    }
}

async fn continue_legacy_settings_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(preview) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Settings change was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_agora() || !access.allows_host(&preview.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Settings continuation access is not granted",
        );
    }

    // The old flow dispatched before it persisted a repository receipt. Keep
    // continuation, withdrawal, and fresh submission in one total order so a
    // double click cannot send twice or resurrect a cancelled request.
    let _settings_change_guard = state.settings_change_lock.lock().await;
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Settings change was not found");
    };
    if !existing.can_continue_legacy_settings() {
        return action_error(
            StatusCode::CONFLICT,
            "Only an accepted older settings request without a saved repository receipt can continue",
        );
    }
    let Some(runtime_host) = state.store.get(&existing.host) else {
        return action_error(
            StatusCode::CONFLICT,
            "The host is no longer in the fleet store; clear this request and start over",
        );
    };
    if !runtime_host.is_nix {
        return action_error(
            StatusCode::CONFLICT,
            "Only a Nix host settings request can continue through nixcfg",
        );
    }
    let Some(preferences) = runtime_host.requested_preferences.clone() else {
        return action_error(
            StatusCode::CONFLICT,
            "The exact settings are no longer recoverable; clear this request and start over",
        );
    };
    let declared_preferences = state.manifests.declared_preferences_for(&existing.host);
    if declared_preferences == Some(&preferences) {
        return action_response_with_settings_context_and_message(
            StatusCode::OK,
            &existing,
            declared_preferences,
            Some(&preferences),
            true,
            "The loaded nixcfg declaration already contains these settings. Deploy the host, then check again.",
        );
    }

    let recorded = match state.host_actions.prepare_legacy_settings_continuation(
        &existing.id,
        &preferences,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => {
            let Some(job) = state.host_actions.get(&existing.id).filter(|job| {
                job.requested_preferences() == Some(&preferences) && !job.dispatch_submitted()
            }) else {
                return action_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "The recovered settings were persisted but could not be reloaded safely",
                );
            };
            job
        }
        Err(_) => {
            return action_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "The recovered settings could not be saved before repository handoff",
            );
        }
    };

    let recorded = match state
        .host_actions
        .prepare_repository_dispatch(&existing.id, &existing.id)
    {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => {
            state.host_actions.get(&existing.id).unwrap_or(recorded)
        }
        Err(_) => {
            return action_response_with_message(
                StatusCode::SERVICE_UNAVAILABLE,
                &recorded,
                "The recovered dispatch coordinate could not be saved before repository handoff",
            );
        }
    };

    let request_id = match state
        .nixcfg_dispatch
        .dispatch_settings_with_key(&existing.host, &preferences, &existing.id)
        .await
    {
        Ok(request_id) => request_id,
        Err(error) => {
            let failed = match error {
                NixcfgDispatchError::OutcomeUncertain => state
                    .host_actions
                    .fail_settings_change_uncertain(&existing.id, now_unix())
                    .ok(),
                _ => state
                    .host_actions
                    .fail_settings_change(&existing.id, now_unix())
                    .ok(),
            }
            .or_else(|| state.host_actions.get(&existing.id))
            .unwrap_or(recorded);
            let status = match &error {
                NixcfgDispatchError::Disabled | NixcfgDispatchError::CredentialUnavailable => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                NixcfgDispatchError::InvalidHost
                | NixcfgDispatchError::InvalidPreferences
                | NixcfgDispatchError::InvalidRemovalIntent => StatusCode::BAD_REQUEST,
                NixcfgDispatchError::OutcomeUncertain => StatusCode::CONFLICT,
                NixcfgDispatchError::Rejected(_) => StatusCode::BAD_GATEWAY,
            };
            return action_response_with_message(status, &failed, error.safe_message());
        }
    };

    let submitted = match state.host_actions.mark_settings_dispatch_submitted(
        &existing.id,
        &request_id,
        now_unix(),
    ) {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => state
            .host_actions
            .get(&existing.id)
            .unwrap_or_else(|| recorded.clone()),
        Err(_) => {
            let uncertain = state
                .host_actions
                .fail_settings_change_uncertain(&existing.id, now_unix())
                .ok()
                .or_else(|| state.host_actions.get(&existing.id))
                .unwrap_or(recorded);
            return action_response_with_message(
                StatusCode::CONFLICT,
                &uncertain,
                "nixcfg may have accepted the recovered request, but Pharos could not save that receipt. Verify nixcfg before any retry.",
            );
        }
    };

    tracing::info!(
        host = %submitted.host,
        ticket = "PHAROS-240",
        "legacy settings request continued through nixcfg"
    );
    action_response_with_settings_context_and_message(
        StatusCode::ACCEPTED,
        &submitted,
        declared_preferences,
        Some(&preferences),
        true,
        "The recovered settings were sent to the reviewed nixcfg workflow. Deployment and matching host evidence are still required.",
    )
}

async fn reconcile_accepted_dispatch(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(preview) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    let workflow_allowed = match preview.workflow_kind() {
        host_actions::HostWorkflowKind::SettingsChange => access.can_agora(),
        host_actions::HostWorkflowKind::RemoveHost => access.can_manage_fleet(),
        _ => false,
    };
    if !action_request_header(&headers) || !workflow_allowed || !access.allows_host(&preview.host) {
        return action_error(
            StatusCode::FORBIDDEN,
            "Accepted dispatch reconciliation access is not granted",
        );
    }
    // Settings reconciliation writes the same pending preference slot as a
    // fresh submission. Order it with withdrawal, then reload the workflow so
    // a queued reconciliation cannot act on a run that was just cancelled.
    let _settings_change_guard =
        if preview.workflow_kind() == host_actions::HostWorkflowKind::SettingsChange {
            Some(state.settings_change_lock.lock().await)
        } else {
            None
        };
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    if existing.state != HostActionState::ProposalRequested
        || !existing.dispatch_submitted()
        || existing.accepted_dispatch_reconciled()
    {
        return action_error(
            StatusCode::CONFLICT,
            "Only a saved, accepted repository handoff can be reconciled locally",
        );
    }

    match existing.workflow_kind() {
        host_actions::HostWorkflowKind::SettingsChange => {
            let Some(preferences) = existing.requested_preferences().cloned() else {
                return action_error(
                    StatusCode::CONFLICT,
                    "The accepted settings handoff has no saved local recovery payload",
                );
            };
            let host = match state.store.request_preferences(&existing.host, preferences) {
                Ok(host) => host,
                Err(error) => {
                    return action_response_with_message(
                        StatusCode::SERVICE_UNAVAILABLE,
                        &existing,
                        &format!(
                            "The repository handoff remains accepted, but the local settings save still failed: {}",
                            error.safe_message()
                        ),
                    );
                }
            };
            let accepted = match state
                .host_actions
                .accept_settings_change(&existing.id, now_unix())
            {
                Ok(job) => job,
                Err(HostActionStoreError::PersistenceCommitted) => state
                    .host_actions
                    .get(&existing.id)
                    .unwrap_or_else(|| existing.clone()),
                Err(_) => {
                    return action_response_with_message(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &existing,
                        "The local settings save succeeded, but its checklist still needs reconciliation",
                    );
                }
            };
            let job = if host.requested_preferences.is_none() {
                match state
                    .host_actions
                    .complete_settings_change(&host.name, now_unix())
                {
                    Ok(Some(job)) => job,
                    Ok(None) => accepted,
                    Err(HostActionStoreError::PersistenceCommitted) => {
                        state.host_actions.get(&existing.id).unwrap_or(accepted)
                    }
                    Err(_) => {
                        return action_response_with_message(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            &accepted,
                            "The local settings save succeeded, but completion still needs reconciliation",
                        );
                    }
                }
            } else {
                accepted
            };
            action_response_with_message(
                StatusCode::OK,
                &job,
                "The accepted repository handoff was reconciled locally without a second dispatch.",
            )
        }
        host_actions::HostWorkflowKind::RemoveHost => {
            let Some(plan) = existing.removal_plan.clone() else {
                return action_error(StatusCode::CONFLICT, "The removal plan is unavailable");
            };
            if !plan.declaration_pending && !plan.credential_retirement_required {
                return action_error(
                    StatusCode::CONFLICT,
                    "This removal did not require a repository handoff",
                );
            }
            if !state.retired_hosts.is_retired(&existing.host) {
                match state.retired_hosts.retire(RetiredHost {
                    host: existing.host.clone(),
                    requested_by: existing.requested_by.clone(),
                    removal_job_id: existing.id.clone(),
                    disposition: plan.disposition,
                    successor: plan.successor.clone(),
                    declaration_pending: plan.declaration_pending,
                    retired_at: now_unix(),
                }) {
                    Ok(()) | Err(HostActionStoreError::PersistenceCommitted) => {}
                    Err(_) => {
                        return action_response_with_message(
                            StatusCode::SERVICE_UNAVAILABLE,
                            &existing,
                            "The repository handoff remains accepted, but the local retirement save still failed",
                        );
                    }
                }
            }
            let job = match state
                .host_actions
                .mark_removal_access_revoked(&existing.id, now_unix())
            {
                Ok(job) => job,
                Err(HostActionStoreError::PersistenceCommitted) => {
                    state.host_actions.get(&existing.id).unwrap_or(existing)
                }
                Err(_) => {
                    return action_response_with_message(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        &existing,
                        "The retirement save succeeded, but its checklist still needs reconciliation",
                    );
                }
            };
            action_response_with_message(
                StatusCode::ACCEPTED,
                &job,
                "The accepted repository handoff was reconciled locally without a second dispatch.",
            )
        }
        _ => action_error(
            StatusCode::CONFLICT,
            "This workflow has no accepted local handoff to reconcile",
        ),
    }
}

async fn confirm_update_restart(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ConfirmHostActionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Guarded action was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Guarded host action access is not granted",
        );
    }
    if request.confirmation != existing.host || !request.attended {
        return action_error(
            StatusCode::BAD_REQUEST,
            "Type the exact host name and confirm that the host is attended",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    match state
        .host_actions
        .confirm_update(&id, &existing.host, &actor, now_unix())
    {
        Ok(job) => {
            tracing::info!(host = %job.host, ticket = "PHAROS-126", "guarded host update confirmed");
            action_response(StatusCode::ACCEPTED, &job)
        }
        Err(HostActionStoreError::ReviewFailed) => action_error(
            StatusCode::CONFLICT,
            "Backup and validation gates have not all passed",
        ),
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "This workflow is not waiting for confirmation",
        ),
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The confirmation could not be recorded",
        ),
    }
}

async fn request_host_removal(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(host): AxumPath<String>,
    Json(request): Json<RemoveHostActionRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() || !access.allows_host(&host)
    {
        return action_error(StatusCode::FORBIDDEN, "Host removal access is not granted");
    }
    if request.confirmation != host {
        return action_error(
            StatusCode::BAD_REQUEST,
            "Type the exact host name to confirm",
        );
    }
    if state.retired_hosts.is_retired(&host) {
        return action_error(StatusCode::CONFLICT, "This host is already being removed");
    }
    if state.store.get(&host).is_none() && !host_is_declared(&state, &host) {
        return action_error(StatusCode::NOT_FOUND, "Host is not managed by Pharos");
    }
    let successor = request
        .successor
        .as_deref()
        .map(str::trim)
        .filter(|successor| !successor.is_empty())
        .map(str::to_string);
    let declaration_pending = host_needs_declaration_cleanup(&state, &host);
    let credential_retirement_required = match state.beacon_auth.janus_manages_host(&host) {
        Ok(required) => required,
        Err(_) => {
            return action_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Janus credential ownership could not be verified",
            );
        }
    };
    if credential_retirement_required && !state.retirement_owner.configured() {
        return action_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "A retirement owner must be configured before removing this host",
        );
    }
    if state.retirement_owner.is_owner(&host) {
        return action_error(
            StatusCode::CONFLICT,
            "Move retirement ownership to another host before removing this owner",
        );
    }
    // PHAROS-194: a Janus-issued credential and a declared manifest come from
    // independent sources, so a managed host can legitimately be undeclared.
    // Such a removal still runs the full credential retirement checklist; it is
    // the declarative cleanup that is not required.
    let removal_plan = HostRemovalPlan {
        disposition: request.disposition,
        successor,
        declaration_pending,
        credential_retirement_required,
    };
    if !removal_plan.validate(&host) {
        return action_error(
            StatusCode::BAD_REQUEST,
            "Choose what happened to the host; rebuilt hosts require a different valid successor",
        );
    }
    if let Some(successor) = removal_plan.successor.as_deref() {
        if state.retired_hosts.is_retired(successor) {
            return action_error(
                StatusCode::CONFLICT,
                "The successor is retired and cannot take over this host",
            );
        }
        if state.store.get(successor).is_none() && !host_is_declared(&state, successor) {
            return action_error(
                StatusCode::CONFLICT,
                "Onboard the successor in Pharos before recording this replacement",
            );
        }
    }
    let actor = action_actor(&state.auth, &headers);
    let now = now_unix();
    let mut workflow =
        match state
            .host_actions
            .begin_removal(&host, &actor, removal_plan.clone(), now)
        {
            Ok(job) => job,
            Err(HostActionStoreError::ActiveJob) => {
                if let Some(current) = state.host_actions.latest_removal_for_host(&host) {
                    return action_response_with_message(
                        StatusCode::CONFLICT,
                        &current,
                        "A removal workflow is already active for this host",
                    );
                }
                return action_error(
                    StatusCode::CONFLICT,
                    "A removal workflow is already active for this host",
                );
            }
            Err(HostActionStoreError::PersistenceCommitted) => {
                match state.host_actions.latest_removal_for_host(&host) {
                    Some(job) => job,
                    None => {
                        return action_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "The removal workflow could not be recorded",
                        );
                    }
                }
            }
            Err(_) => {
                return action_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "The removal workflow could not be recorded",
                );
            }
        };
    // PHAROS-197: the proposal is what records the retirement intent the
    // retirement agent reads, so it is needed whenever a credential must be
    // retired, not only when a declaration must be removed. Without it an
    // undeclared Janus-managed host revokes reporting and then strands, failing
    // credential retirement on every attempt with its credential still live.
    let repository_dispatch_required = declaration_pending || credential_retirement_required;
    if repository_dispatch_required {
        workflow = match state
            .host_actions
            .prepare_repository_dispatch(&workflow.id, &workflow.id)
        {
            Ok(job) => job,
            Err(HostActionStoreError::PersistenceCommitted) => state
                .host_actions
                .get(&workflow.id)
                .unwrap_or_else(|| workflow.clone()),
            Err(_) => {
                let failed = state
                    .host_actions
                    .fail_removal(&workflow.id, now_unix())
                    .ok()
                    .unwrap_or(workflow);
                return action_response_with_message(
                    StatusCode::SERVICE_UNAVAILABLE,
                    &failed,
                    "The removal dispatch coordinate could not be saved before repository dispatch",
                );
            }
        };
        if let Err(error) = state
            .nixcfg_dispatch
            .dispatch_host_removal_with_key(
                &host,
                removal_plan.disposition.key(),
                removal_plan.successor.as_deref(),
                credential_retirement_required,
                &workflow.id,
            )
            .await
        {
            let failed = match error {
                NixcfgDispatchError::OutcomeUncertain => state
                    .host_actions
                    .fail_removal_uncertain(&workflow.id, now_unix())
                    .unwrap_or(workflow),
                _ => state
                    .host_actions
                    .fail_removal(&workflow.id, now_unix())
                    .unwrap_or(workflow),
            };
            return action_response_with_message(
                if error.is_outcome_uncertain() {
                    StatusCode::CONFLICT
                } else {
                    StatusCode::BAD_GATEWAY
                },
                &failed,
                error.host_removal_message(),
            );
        }
        workflow = match state.host_actions.mark_dispatch_submitted_with_request_id(
            &workflow.id,
            &workflow.id,
            now_unix(),
        ) {
            Ok(job) => job,
            Err(HostActionStoreError::PersistenceCommitted) => state
                .host_actions
                .get(&workflow.id)
                .unwrap_or_else(|| workflow.clone()),
            Err(_) => {
                let uncertain = state
                    .host_actions
                    .fail_removal_uncertain(&workflow.id, now_unix())
                    .ok()
                    .or_else(|| state.host_actions.get(&workflow.id))
                    .unwrap_or_else(|| workflow.clone());
                return action_response_with_message(
                    StatusCode::CONFLICT,
                    &uncertain,
                    "nixcfg accepted the removal request, but Pharos could not save that handoff. Verify nixcfg before any retry.",
                );
            }
        };
    }
    let retirement_record = state.retired_hosts.retire(RetiredHost {
        host: host.clone(),
        requested_by: actor.clone(),
        removal_job_id: workflow.id.clone(),
        disposition: removal_plan.disposition,
        successor: removal_plan.successor.clone(),
        declaration_pending,
        retired_at: now,
    });
    if !matches!(
        retirement_record,
        Ok(()) | Err(HostActionStoreError::PersistenceCommitted)
    ) {
        if repository_dispatch_required {
            return action_response_with_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                &workflow,
                "nixcfg accepted the removal request, but the local retirement record could not be persisted. Reporting access remains active; do not resend the request.",
            );
        }
        let failed = state
            .host_actions
            .fail_removal(&workflow.id, now_unix())
            .unwrap_or(workflow);
        return action_response_with_message(
            StatusCode::INTERNAL_SERVER_ERROR,
            &failed,
            "Beacon revocation could not be persisted",
        );
    }
    let job = match state
        .host_actions
        .mark_removal_access_revoked(&workflow.id, now_unix())
    {
        Ok(job) => job,
        Err(HostActionStoreError::PersistenceCommitted) => {
            state.host_actions.get(&workflow.id).unwrap_or(workflow)
        }
        Err(_) => {
            let current = state.host_actions.get(&workflow.id).unwrap_or(workflow);
            return action_response_with_message(
                StatusCode::INTERNAL_SERVER_ERROR,
                &current,
                "Beacon access was revoked, but the saved checklist still needs reconciliation",
            );
        }
    };
    // PHAROS-194: keep the host durably visible while any part of the removal is
    // still outstanding. Dropping it here while credential retirement is pending
    // would hide an unfinished workflow behind an apparently completed removal.
    if !declaration_pending && !credential_retirement_required {
        if let Err(error) = state.store.remove(&host) {
            tracing::error!(host = %host, error = %error, "retired host could not be removed from the durable fleet store");
            return action_response_with_message(
                StatusCode::SERVICE_UNAVAILABLE,
                &job,
                "Beacon access is revoked, but durable fleet cleanup must be retried",
            );
        }
    }
    tracing::info!(host = %host, actor = %actor, declaration_pending, credential_retirement_required, disposition = ?removal_plan.disposition, successor = ?removal_plan.successor, ticket = "PHAROS-127", "host removal requested and beacon access revoked");
    action_response(StatusCode::ACCEPTED, &job)
}

async fn retry_host_retirement(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let Some(existing) = state.host_actions.get(&id) else {
        return action_error(StatusCode::NOT_FOUND, "Host retirement was not found");
    };
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers)
        || !access.can_manage_fleet()
        || !access.allows_host(&existing.host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Host retirement recovery access is not granted",
        );
    }
    if !state.retired_hosts.is_retired(&existing.host) {
        return action_error(
            StatusCode::CONFLICT,
            "The host no longer has a pending retirement record",
        );
    }
    let actor = action_actor(&state.auth, &headers);
    match state.host_actions.retry_retirement(&id, &actor, now_unix()) {
        Ok(job) => action_response(StatusCode::ACCEPTED, &job),
        Err(HostActionStoreError::InvalidTransition) => action_error(
            StatusCode::CONFLICT,
            "Credential retirement is not waiting for an operator retry",
        ),
        Err(HostActionStoreError::NotFound) => {
            action_error(StatusCode::NOT_FOUND, "Host retirement was not found")
        }
        Err(_) => action_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "The credential retirement retry could not be recorded",
        ),
    }
}

async fn allow_host_reonboarding(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(host): AxumPath<String>,
    Json(request): Json<ConfirmHostNameRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() || !access.allows_host(&host)
    {
        return action_error(
            StatusCode::FORBIDDEN,
            "Host re-onboarding access is not granted",
        );
    }
    if request.confirmation != host {
        return action_error(
            StatusCode::BAD_REQUEST,
            "Type the exact host name to confirm",
        );
    }
    match state.retired_hosts.clear(&host) {
        Ok(true) | Err(HostActionStoreError::PersistenceCommitted) => {}
        Ok(false) => return action_error(StatusCode::NOT_FOUND, "Host is not retired"),
        Err(_) => {
            return action_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The re-onboarding approval could not be durably recorded",
            );
        }
    }
    tracing::info!(host = %host, actor = %action_actor(&state.auth, &headers), ticket = "PHAROS-127", "host re-onboarding allowed");
    (
        StatusCode::OK,
        Json(json!({
            "message": "Retirement cleared. Re-onboarding still requires a valid managed beacon credential."
        })),
    )
}

/// Returns how many removals newly reached a terminal state on this pass.
/// Callers ignore it; tests use it to prove the pass is idempotent.
fn reconcile_completed_removals(state: &AppState, now: i64) -> usize {
    let mut transitions = 0usize;
    for retired in state.retired_hosts.list() {
        if state
            .host_actions
            .mark_removal_access_revoked(&retired.removal_job_id, now)
            .is_err()
        {
            tracing::warn!(host = %retired.host, ticket = "PHAROS-127", "retired host checklist reconciliation could not be persisted");
            continue;
        }
        if retired.declaration_pending && host_is_declared(state, &retired.host) {
            continue;
        }
        if state
            .host_actions
            .mark_removal_declaration_completed(&retired.removal_job_id, now)
            .is_err()
        {
            tracing::warn!(host = %retired.host, ticket = "PHAROS-127", "declarative removal completion could not be persisted");
            continue;
        }
        // PHAROS-194: complete the checklist before dropping the durable record.
        // A Janus-managed host can have no declaration left to remove while its
        // credential retirement is still outstanding, and removing it here would
        // hide that unfinished work behind an apparently completed removal.
        let (completed, transitioned) = match state
            .host_actions
            .complete_removal(&retired.removal_job_id, now)
        {
            Ok(Some(_)) => (true, true),
            // Already terminal from an earlier pass whose durable cleanup failed.
            // Retry that cleanup, but do not re-announce a finished transition:
            // retirement records are durable, so this branch repeats forever.
            Ok(None) => (
                state
                    .host_actions
                    .get(&retired.removal_job_id)
                    .is_some_and(|job| job.state == HostActionState::Succeeded),
                false,
            ),
            Err(_) => {
                tracing::warn!(host = %retired.host, ticket = "PHAROS-127", "declarative host removal reconciliation could not be persisted");
                continue;
            }
        };
        if !completed {
            continue;
        }
        if let Err(error) = state.store.remove(&retired.host) {
            tracing::warn!(host = %retired.host, error = %error, ticket = "PHAROS-163", "declarative host removal could not be persisted");
            continue;
        }
        if transitioned {
            transitions += 1;
            tracing::info!(host = %retired.host, ticket = "PHAROS-127", "declarative host removal reconciled");
        }
    }
    transitions
}

/// Advance durable owner handoffs from value-free local evidence.
///
/// This pass is intentionally idempotent: it never dispatches a repository
/// workflow or replays a live host action. It repairs accepted local receipts,
/// observes already-matching host state, and lets the existing removal
/// reconciler finish recorded retirement gates.
async fn reconcile_saved_next_actions(state: &AppState, now: i64) -> usize {
    let mut transitions = 0usize;
    {
        // This is the same transaction boundary used by fresh submissions,
        // continuations, and withdrawals. Candidate IDs are only hints; every
        // decision below reloads the exact run while the boundary is held.
        let _settings_change_guard = state.settings_change_lock.lock().await;
        let _ = state.host_actions.reconcile_orphaned_host_dispatches(now);
        let candidate_ids: Vec<_> = state
            .host_actions
            .list()
            .into_iter()
            .filter(|job| job.workflow_kind() == HostWorkflowKind::SettingsChange)
            .map(|job| job.id)
            .collect();
        for id in candidate_ids {
            let Some(job) = state.host_actions.get(&id).filter(|job| {
                job.workflow_kind() == HostWorkflowKind::SettingsChange && !job.state.is_terminal()
            }) else {
                continue;
            };
            let Some(requested) = job.requested_preferences().cloned() else {
                continue;
            };
            if job.dispatch_submitted()
                && !job.accepted_dispatch_reconciled()
                && state
                    .store
                    .request_preferences(&job.host, requested)
                    .is_ok()
                && state.host_actions.accept_settings_change(&id, now).is_ok()
            {
                transitions += 1;
            }

            let Some(current) = state.host_actions.get(&id).filter(|job| {
                job.workflow_kind() == HostWorkflowKind::SettingsChange && !job.state.is_terminal()
            }) else {
                continue;
            };
            let Some(requested) = current.requested_preferences() else {
                continue;
            };
            let Some(host) = state.store.get(&current.host) else {
                continue;
            };
            if host.preferences == *requested
                && state
                    .host_actions
                    .complete_settings_change_run(&id, now)
                    .is_ok()
            {
                transitions += 1;
            }
        }
    }
    transitions + reconcile_completed_removals(state, now)
}

fn spawn_next_action_loop(state: AppState) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(15));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            let advanced = reconcile_saved_next_actions(&state, now_unix()).await;
            if advanced > 0 {
                tracing::info!(
                    advanced,
                    ticket = "PHAROS-245",
                    "saved next actions reconciled"
                );
            }
        }
    });
}

fn agent_authorized(state: &AppState, headers: &HeaderMap, host: &str) -> Result<(), StatusCode> {
    if state.retired_hosts.is_retired(host) {
        return Err(StatusCode::GONE);
    }
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    match state
        .beacon_auth
        .report_token_status(&state.store, host, token)
    {
        ReportTokenAuth::Allowed => Ok(()),
        ReportTokenAuth::Denied => Err(StatusCode::UNAUTHORIZED),
        ReportTokenAuth::Unavailable(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn managed_agent_authorized(
    state: &AppState,
    headers: &HeaderMap,
    host_ref: &str,
) -> Result<(), StatusCode> {
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    match state
        .beacon_auth
        .managed_agent_token_status(host_ref, token)
    {
        ReportTokenAuth::Allowed => Ok(()),
        ReportTokenAuth::Denied => Err(StatusCode::UNAUTHORIZED),
        ReportTokenAuth::Unavailable(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn retirement_owner_authorized(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
) -> Result<(), StatusCode> {
    if !state.retirement_owner.is_owner(owner) {
        return Err(StatusCode::FORBIDDEN);
    }
    if state.retired_hosts.is_retired(owner) {
        return Err(StatusCode::GONE);
    }
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    match state
        .beacon_auth
        .report_token_status(&state.store, owner, token)
    {
        ReportTokenAuth::Allowed => Ok(()),
        ReportTokenAuth::Denied => Err(StatusCode::UNAUTHORIZED),
        ReportTokenAuth::Unavailable(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

fn provisioning_owner_authorized(
    state: &AppState,
    headers: &HeaderMap,
    owner: &str,
) -> Result<(), StatusCode> {
    if !state.provider_runtime.managed_provisioning.is_owner(owner) {
        return Err(StatusCode::FORBIDDEN);
    }
    if state.retired_hosts.is_retired(owner) {
        return Err(StatusCode::GONE);
    }
    let token = bearer_token(headers).ok_or(StatusCode::UNAUTHORIZED)?;
    match state
        .beacon_auth
        .report_token_status(&state.store, owner, token)
    {
        ReportTokenAuth::Allowed => Ok(()),
        ReportTokenAuth::Denied => Err(StatusCode::UNAUTHORIZED),
        ReportTokenAuth::Unavailable(_) => Err(StatusCode::SERVICE_UNAVAILABLE),
    }
}

async fn claim_managed_provisioning_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProvisioningAgentClaimRequest>,
) -> axum::response::Response {
    let owner = request.owner.trim().to_string();
    if !valid_action_host_name(&owner) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = provisioning_owner_authorized(&state, &headers, &owner) {
        return status.into_response();
    }
    match state
        .provisioning_jobs
        .claim_managed_provisioning(&owner, now_unix())
    {
        Ok(Some(lease)) => (StatusCode::OK, Json(lease)).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(ProvisioningAgentStoreError::Persistence) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

async fn record_managed_provisioning_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<ProvisioningAgentResultRequest>,
) -> axum::response::Response {
    let owner = request.owner.trim().to_string();
    if !valid_action_host_name(&owner) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = provisioning_owner_authorized(&state, &headers, &owner) {
        return status.into_response();
    }
    let action = request.action;
    let outcome = request.outcome;
    let job =
        match state
            .provisioning_jobs
            .record_managed_provisioning_result(&id, &request, now_unix())
        {
            Ok(job) => job,
            Err(ProvisioningAgentStoreError::NotFound) => {
                return StatusCode::NOT_FOUND.into_response()
            }
            Err(ProvisioningAgentStoreError::WrongOwner) => {
                return StatusCode::FORBIDDEN.into_response();
            }
            Err(ProvisioningAgentStoreError::Persistence) => {
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
            Err(_) => return StatusCode::CONFLICT.into_response(),
        };
    if action == ProvisioningAgentAction::Retire && outcome == ProvisioningAgentOutcome::Succeeded {
        let Some(host) = job.host_name.as_deref() else {
            return StatusCode::CONFLICT.into_response();
        };
        let owned_runtime = job
            .managed_identity
            .as_ref()
            .is_some_and(|identity| identity.first_heartbeat_at.is_some());
        if owned_runtime {
            if host_is_declared(&state, host) {
                tracing::error!(host = %host, ticket = "PHAROS-176", "job-owned cleanup refused to remove declared host state");
                return StatusCode::CONFLICT.into_response();
            }
            if let Err(error) = state.store.remove(host) {
                tracing::error!(host = %host, error = %error, ticket = "PHAROS-176", "job-owned runtime host cleanup could not be persisted");
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
        if let Err(error) = state
            .provisioning_jobs
            .complete_managed_retirement(&id, now_unix())
        {
            return match error {
                ProvisioningAgentStoreError::Persistence => {
                    StatusCode::SERVICE_UNAVAILABLE.into_response()
                }
                _ => StatusCode::CONFLICT.into_response(),
            };
        }
    }
    StatusCode::NO_CONTENT.into_response()
}

async fn claim_retirement_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<RetirementAgentClaimRequest>,
) -> axum::response::Response {
    let owner = request.owner.trim().to_string();
    if !valid_action_host_name(&owner) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = retirement_owner_authorized(&state, &headers, &owner) {
        return status.into_response();
    }
    let _ = reconcile_completed_removals(&state, now_unix());
    match state.host_actions.claim_retirement(&owner, now_unix()) {
        Ok(Some(lease)) => (StatusCode::OK, Json(lease)).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn record_retirement_action_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<RetirementAgentResultRequest>,
) -> axum::response::Response {
    let owner = request.owner.trim().to_string();
    let host = request.host.trim().to_string();
    if !valid_action_host_name(&owner) || !valid_action_host_name(&host) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = retirement_owner_authorized(&state, &headers, &owner) {
        return status.into_response();
    }
    if !state.retired_hosts.is_retired(&host) {
        return StatusCode::CONFLICT.into_response();
    }
    match state
        .host_actions
        .record_retirement_result(&id, &request, now_unix())
    {
        Ok(job) => {
            if job.state == HostActionState::Succeeded {
                if let Err(error) = state.store.remove(&host) {
                    tracing::error!(host = %host, error = %error, "completed retirement could not be removed from the durable fleet store");
                    return StatusCode::SERVICE_UNAVAILABLE.into_response();
                }
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Err(HostActionStoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(HostActionStoreError::WrongHost) => StatusCode::FORBIDDEN.into_response(),
        Err(HostActionStoreError::InvalidJob | HostActionStoreError::InvalidTransition) => {
            StatusCode::CONFLICT.into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn claim_host_action(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AgentActionClaimRequest>,
) -> axum::response::Response {
    let host = request.host.trim().to_string();
    if !valid_action_host_name(&host) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = agent_authorized(&state, &headers, &host) {
        return status.into_response();
    }
    match state.host_actions.claim(&host, now_unix()) {
        Ok(Some(lease)) => (StatusCode::OK, Json(lease)).into_response(),
        Ok(None) => StatusCode::NO_CONTENT.into_response(),
        Err(HostActionStoreError::BlockedByFleetGate) => (
            StatusCode::CONFLICT,
            Json(
                json!({ "error": "Another host update workflow must finish or be resolved first" }),
            ),
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn record_host_action_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
    Json(request): Json<AgentActionResultRequest>,
) -> axum::response::Response {
    let host = request.host.trim().to_string();
    if !valid_action_host_name(&host) {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = agent_authorized(&state, &headers, &host) {
        return status.into_response();
    }
    let Some(job) = state.host_actions.get(&id) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if job.host != host {
        return StatusCode::FORBIDDEN.into_response();
    }
    if request.outcome == AgentActionOutcome::Succeeded
        && matches!(
            request.phase,
            host_actions::AgentActionPhase::Apply | host_actions::AgentActionPhase::Resume
        )
    {
        let runtime_verified = state.store.get(&host).is_some_and(|runtime| {
            runtime.last_seen.is_some_and(|seen| {
                seen >= job.confirmed_at.unwrap_or(job.created_at)
                    && runtime
                        .kernel
                        .as_ref()
                        .is_some_and(|kernel| kernel.state == KernelPostureState::Current)
            })
        });
        if !runtime_verified {
            return (
                StatusCode::CONFLICT,
                Json(json!({ "error": "Waiting for a fresh heartbeat with the expected kernel" })),
            )
                .into_response();
        }
    }
    match state
        .host_actions
        .record_agent_result(&id, &host, request, now_unix())
    {
        Ok(job) => action_response(StatusCode::OK, &job).into_response(),
        Err(HostActionStoreError::InvalidJob) => StatusCode::UNPROCESSABLE_ENTITY.into_response(),
        Err(HostActionStoreError::InvalidTransition) => StatusCode::CONFLICT.into_response(),
        Err(HostActionStoreError::WrongHost) => StatusCode::FORBIDDEN.into_response(),
        Err(HostActionStoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

fn valid_action_host_name(host: &str) -> bool {
    let bytes = host.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz(State(state): State<AppState>) -> Response {
    let readiness = state.beacon_auth.janus_readiness();
    let machine_operator_ready = state.auth.machine_readiness();
    let alert_worker = state.alert_health.snapshot(now_unix());
    let ready = readiness.as_ref().is_none_or(|status| status.ready)
        && machine_operator_ready.is_none_or(|ready| ready)
        && alert_worker.ready;
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        no_store_headers(),
        Json(json!({
            "ready": ready,
            "janus_sidecar": readiness,
            "machine_operator": machine_operator_ready.map(|ready| json!({
                "capability": JanusCapability::PharosMachineOperator.as_str(),
                "ready": ready,
                "value_returned": false,
            })),
            "alert_worker": alert_worker,
        })),
    )
        .into_response()
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let readiness = state.beacon_auth.janus_readiness();
    let mut body = String::from(
        "# HELP pharos_janus_sidecar_ready Whether the active Janus credential generation is usable.\n\
# TYPE pharos_janus_sidecar_ready gauge\n",
    );
    match readiness {
        Some(readiness) => {
            body.push_str(&format!(
                "pharos_janus_sidecar_ready {}\n",
                usize::from(readiness.ready)
            ));
            body.push_str(
                "# HELP pharos_janus_sidecar_hosts Hosts in the active Janus credential generation.\n\
# TYPE pharos_janus_sidecar_hosts gauge\n",
            );
            body.push_str(&format!(
                "pharos_janus_sidecar_hosts {}\n",
                readiness.host_count
            ));
            if let Some(generation) = readiness.generation {
                body.push_str(
                    "# HELP pharos_janus_sidecar_generation_info Active immutable Janus credential generation.\n\
# TYPE pharos_janus_sidecar_generation_info gauge\n",
                );
                body.push_str(&format!(
                    "pharos_janus_sidecar_generation_info{{generation=\"{generation}\"}} 1\n"
                ));
            }
            if let Some(last_success) = readiness.last_success_unix {
                body.push_str(
                    "# HELP pharos_janus_sidecar_last_success_unixtime Last successful Janus generation load.\n\
# TYPE pharos_janus_sidecar_last_success_unixtime gauge\n",
                );
                body.push_str(&format!(
                    "pharos_janus_sidecar_last_success_unixtime {last_success}\n"
                ));
            }
        }
        None => body.push_str("pharos_janus_sidecar_ready 1\n"),
    }
    let alerts = state.alert_health.snapshot(now_unix());
    body.push_str(
        "# HELP pharos_alert_worker_ready Whether the configured alert worker is running and completing durable sweeps.\n\
# TYPE pharos_alert_worker_ready gauge\n",
    );
    body.push_str(&format!(
        "pharos_alert_worker_ready {}\n",
        usize::from(alerts.ready)
    ));
    body.push_str(
        "# HELP pharos_alert_outbox_pending Durable alert events awaiting delivery.\n\
# TYPE pharos_alert_outbox_pending gauge\n",
    );
    body.push_str(&format!(
        "pharos_alert_outbox_pending {}\n",
        alerts.pending_events
    ));
    body.push_str(
        "# HELP pharos_alert_deliveries_total Durable alert events marked delivered.\n\
# TYPE pharos_alert_deliveries_total counter\n",
    );
    body.push_str(&format!(
        "pharos_alert_deliveries_total {}\n",
        alerts.deliveries_total
    ));
    body.push_str(
        "# HELP pharos_alert_delivery_failures_total Alert delivery attempts that remain pending.\n\
# TYPE pharos_alert_delivery_failures_total counter\n",
    );
    body.push_str(&format!(
        "pharos_alert_delivery_failures_total {}\n",
        alerts.delivery_failures_total
    ));
    body.push_str(
        "# HELP pharos_alert_worker_restarts_total Unexpected alert-worker exits supervised and restarted.\n\
# TYPE pharos_alert_worker_restarts_total counter\n",
    );
    body.push_str(&format!(
        "pharos_alert_worker_restarts_total {}\n",
        alerts.restarts_total
    ));
    if let Some(last_success) = alerts.last_success_unix {
        body.push_str(
            "# HELP pharos_alert_worker_last_success_unixtime Last successful durable alert sweep.\n\
# TYPE pharos_alert_worker_last_success_unixtime gauge\n",
        );
        body.push_str(&format!(
            "pharos_alert_worker_last_success_unixtime {last_success}\n"
        ));
    }
    (
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "name": "pharosd",
        "version": APP_VERSION,
        "git_commit": GIT_COMMIT,
        "display_version": release_label()
    }))
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rep): Json<HostReport>,
) -> Response {
    if state.retired_hosts.is_retired(&rep.name) {
        tracing::warn!(host = %rep.name, "report rejected: host retired from Pharos");
        return StatusCode::GONE.into_response();
    }
    if let Err(error) = rep.validate_contract() {
        tracing::warn!(error = %error, "report rejected: invalid report contract");
        return StatusCode::BAD_REQUEST.into_response();
    }
    if rep
        .service_observations
        .iter()
        .any(appliance_probes::is_appliance_observation)
    {
        tracing::warn!(host = %rep.name, "report rejected: reserved server observation");
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Some(token) = bearer_token(&headers) {
        match state
            .beacon_auth
            .report_token_status(&state.store, &rep.name, token)
        {
            ReportTokenAuth::Allowed => {}
            ReportTokenAuth::Denied => {
                tracing::warn!(host = %rep.name, "report rejected: invalid bearer token");
                return StatusCode::UNAUTHORIZED.into_response();
            }
            ReportTokenAuth::Unavailable(err) => {
                tracing::error!(
                    host = %rep.name,
                    error = %err,
                    "report rejected: beacon token verifier unavailable"
                );
                return StatusCode::SERVICE_UNAVAILABLE.into_response();
            }
        }
    } else if state.beacon_auth.require_report_token {
        tracing::warn!(host = %rep.name, "report rejected: missing bearer token");
        return StatusCode::UNAUTHORIZED.into_response();
    } else {
        tracing::warn!(
            host = %rep.name,
            "accepting legacy unauthenticated report; migrate this host to PHAROS_TOKEN before enabling strict report auth"
        );
    }
    tracing::info!(host = %rep.name, "report received");
    let host_name = rep.name.clone();
    let requested_preferences = state
        .store
        .get(&host_name)
        .and_then(|host| host.requested_preferences);
    let settings_applied = requested_preferences
        .as_ref()
        .is_some_and(|requested| requested == &rep.preferences);
    let pending_preferences = (!rep.is_nix)
        .then(|| requested_preferences.clone())
        .flatten()
        .filter(|requested| requested != &rep.preferences);
    if let Some(observation) = rep
        .service_observations
        .iter()
        .find(|observation| observation.id == "host-preferences")
    {
        tracing::warn!(
            host = %host_name,
            state = observation.state.label(),
            "host settings application reported attention"
        );
    }
    let now = now_unix();
    if let Err(error) = state.store.record(rep, now) {
        tracing::error!(host = %host_name, error = %error, "report could not be durably recorded");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    if let Some(host) = state.store.get(&host_name) {
        reconcile_provisioning_jobs_with_runtime(&state.provisioning_jobs, &[host], now);
    }
    if settings_applied {
        match state.host_actions.complete_settings_change(&host_name, now) {
            Ok(Some(_)) => {
                tracing::info!(host = %host_name, ticket = "PHAROS-239", "host settings workflow completed");
            }
            Ok(None) => {}
            Err(_) => {
                tracing::warn!(host = %host_name, ticket = "PHAROS-239", "host settings applied but workflow completion could not be persisted");
            }
        }
    }
    let Some(preferences) = pending_preferences else {
        return StatusCode::NO_CONTENT.into_response();
    };
    match HostReportResponse::pending(&host_name, preferences) {
        Ok(response) => (StatusCode::OK, Json(response)).into_response(),
        Err(error) => {
            tracing::error!(
                host = %host_name,
                error = %error,
                "pending host settings response could not be constructed"
            );
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Local host registration for MVP onboarding (PHAROS-8/7). Protected by a
/// deployment-local bootstrap token; the returned beacon token is shown once.
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<HostRegistration>,
) -> Response {
    if let Err(error) = registration.validate_contract() {
        tracing::warn!(error = %error, "registration rejected: invalid contract");
        return register_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid registration contract" }),
        );
    }
    if state.retired_hosts.is_retired(&registration.name) {
        return register_response(
            StatusCode::CONFLICT,
            json!({
                "error": "host was removed; clear the retirement through explicit re-onboarding first"
            }),
        );
    }
    match state.beacon_auth.registration_status(&headers) {
        RegistrationAuth::Allowed => {}
        RegistrationAuth::Disabled => {
            return register_response(
                StatusCode::GONE,
                json!({
                    "error": "local registration disabled; use Janus-managed beacon token issuance"
                }),
            );
        }
        RegistrationAuth::Denied => {
            return register_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "registration token invalid" }),
            );
        }
        RegistrationAuth::NotConfigured => {
            return register_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": "PHAROS_REGISTRATION_TOKEN not configured" }),
            );
        }
    }

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("failed to generate beacon token: {err}");
            return register_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "token generation failed" }),
            );
        }
    };
    let response = HostRegistrationResponse {
        name: registration.name.clone(),
        token: token.clone(),
    };
    let host = match state.store.register(registration, token_hash(&token)) {
        Ok(host) => host,
        Err(error) => {
            tracing::error!(error = %error, "registration could not be durably recorded");
            return register_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": "registration could not be durably recorded" }),
            );
        }
    };
    tracing::info!(host = %host.name, "beacon token issued");
    register_response(
        StatusCode::CREATED,
        serde_json::to_value(response).expect("registration response serializes"),
    )
}

fn register_response(status: StatusCode, payload: serde_json::Value) -> Response {
    (status, no_store_headers(), Json(payload)).into_response()
}

async fn hosts_json(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let now = now_unix();
    let access = access_for_headers(&state.auth, &headers);
    let runtime_hosts = filter_hosts_by_access(state.store.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let declared_preferences =
        filter_declared_preferences_by_access(state.manifests.declared_preferences(), &access);
    let action_jobs: Vec<_> = state
        .host_actions
        .list()
        .into_iter()
        .filter(|job| access.allows_host(&job.host))
        .collect();
    let janus_action_hosts: BTreeSet<String> = runtime_hosts
        .iter()
        .filter(|host| host_janus_actions_ready(&state, &host.name))
        .map(|host| host.name.clone())
        .collect();
    let mut payload = hosts_payload(
        runtime_hosts,
        &manifests,
        &declared_preferences,
        &action_jobs,
        Some(&janus_action_hosts),
        now,
    );
    if let Some(hosts) = payload
        .get_mut("hosts")
        .and_then(|hosts| hosts.as_array_mut())
    {
        for host in hosts {
            let Some(name) = host
                .get("name")
                .and_then(|name| name.as_str())
                .map(str::to_string)
            else {
                continue;
            };
            if let Some(retired) = state.retired_hosts.get(&name) {
                // PHAROS-194: a pending removal can be waiting on declarative
                // cleanup, credential retirement, or both. Name which one.
                let credential_retirement_pending = state
                    .host_actions
                    .get(&retired.removal_job_id)
                    .is_some_and(|job| {
                        job.state != HostActionState::Succeeded
                            && job
                                .removal_plan
                                .as_ref()
                                .is_some_and(|plan| plan.credential_retirement_required)
                    });
                host["retirement"] = json!({
                    "pending": true,
                    "disposition": retired.disposition,
                    "successor": retired.successor,
                    "declaration_pending": retired.declaration_pending,
                    "credential_retirement_pending": credential_retirement_pending,
                    "retired_at": retired.retired_at,
                });
            }
        }
    }
    no_store_json(payload)
}

fn hosts_payload(
    runtime_hosts: Vec<Host>,
    manifests: &[HostManifest],
    declared_preferences: &BTreeMap<String, HostPreferences>,
    action_jobs: &[HostActionJob],
    janus_action_hosts: Option<&BTreeSet<String>>,
    now: i64,
) -> serde_json::Value {
    let manifests = manifest_by_host(manifests);
    let hosts: Vec<_> = runtime_hosts
        .into_iter()
        .map(|h| {
            let manifest = manifests.get(h.name.as_str()).copied();
            let declared_preferences = declared_preferences
                .get(&h.name)
                .cloned()
                .or_else(|| manifest.map(|manifest| manifest.host.preferences.clone()));
            let preferences_state = host_preferences_state(
                &h.preferences,
                declared_preferences.as_ref(),
                h.requested_preferences.as_ref(),
            );
            let action = most_relevant_host_action(action_jobs, &h.name);
            let apply_declared_ready = h.is_nix
                && janus_action_hosts.is_some_and(|hosts| hosts.contains(&h.name))
                && manifest.is_some_and(|manifest| {
                    manifest.policy.privileged_actions.mode == PrivilegedActionMode::Janus
                        && manifest.policy.privileged_actions.janus_required
                });
            let normal_update_ready = apply_declared_ready
                && (kernel_reboot_required(h.kernel.as_ref()).is_some()
                    || h.freshness.has_proven_deployable_update());
            let linked_apply = action
                .filter(|job| job.workflow_kind() == HostWorkflowKind::SettingsChange)
                .and_then(|job| linked_settings_apply(action_jobs, &job.id));
            let apply_blocker = (preferences_state == HostPreferencesState::DeclaredNotApplied)
                .then(|| blocking_update_for_host(action_jobs, &h.name))
                .flatten();
            let settings_context = HostSettingsContext {
                declared_preferences: declared_preferences.as_ref(),
                pending_preferences: h.requested_preferences.as_ref(),
                legacy_nix_host: h.is_nix,
                apply_declared_ready: apply_declared_ready
                    && (preferences_state == HostPreferencesState::DeclaredNotApplied
                        || kernel_reboot_required(h.kernel.as_ref()).is_some()),
                apply_declared_unavailable_reason: (!apply_declared_ready)
                    .then_some(SETTINGS_APPLY_UNAVAILABLE_REASON),
                linked_apply,
                apply_blocked_by: apply_blocker.map(|job| job.host.as_str()),
            };
            let lifecycle = host_lifecycle_with_apply(
                action_jobs,
                &h.name,
                preferences_state,
                kernel_reboot_required(h.kernel.as_ref()).is_some(),
                apply_declared_ready,
                normal_update_ready,
                settings_context,
            );
            let action_summary = action.map(|action| {
                action.summary_with_host_settings_context(settings_context)
            });
            let withdrawable_settings_change =
                withdrawable_settings_change_for_host(action_jobs, &h.name);
            let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
            let freshness_tldr = h.freshness.tldr();
            let attention = attention_reason(
                live,
                &h.freshness,
                h.kernel.as_ref(),
                &h.service_observations,
                &h.preferences,
            );
            let location = resolve_host_location(
                Some(&h),
                manifest,
                &h.name,
                now,
            );
            let mut host = json!({
                "name": h.name,
                "role": h.role,
                "is_nix": h.is_nix,
                "preferences": h.preferences,
                "declared_preferences": declared_preferences,
                "requested_preferences": h.requested_preferences,
                "preferences_state": preferences_state.key(),
                "report_version": h.report_version,
                "last_seen": h.last_seen,
                "heartbeat_log": h.heartbeat_log,
                "heartbeat_interval_secs": h.heartbeat_interval_secs,
                "inbound_rtt": h.inbound_rtt,
                "liveness": live,
                "location": location_payload(&location),
                "freshness": h.freshness,
                "freshness_tldr": freshness_tldr,
                "kernel": h.kernel,
                "service_observations": h.service_observations,
                "service_observations_summary": service_observations_summary(&h.service_observations),
                "backup_observations": h.backup_observations,
                "backup_observations_summary": backup_observations_summary(&h.backup_observations),
                "lifecycle": lifecycle,
                "update_restart_active": active_update_restart_for_host(action_jobs, &h.name).is_some(),
                "settings_change_withdraw_run_id": withdrawable_settings_change.map(|job| &job.id),
                "attention": {
                    "label": attention.label,
                    "level": attention.level,
                    "rank": attention.rank,
                },
            });
            if let Some(action_summary) = action_summary {
                host["host_action"] =
                    serde_json::to_value(action_summary).expect("host action summary serializes");
            }
            host
        })
        .collect();
    json!({ "as_of": now, "hosts": hosts })
}

async fn declared_hosts_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let now = now_unix();
    let access = access_for_headers(&state.auth, &headers);
    let runtime_hosts = filter_hosts_by_access(state.store.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let load_errors: &[ManifestLoadIssue] = if access.can_agora() {
        state.manifests.load_errors()
    } else {
        &[]
    };
    let server_probes = server_probe_overlays(&manifests, now).await;
    no_store_json(declared_hosts_payload(
        &manifests,
        load_errors,
        &runtime_hosts,
        &server_probes,
        now,
    ))
}

async fn host_proof_json(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(host): AxumPath<String>,
) -> Response {
    let access = access_for_headers(&state.auth, &headers);
    if !valid_action_host_name(&host) || !access.allows_host(&host) {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Host proof access is not granted" })),
        )
            .into_response();
    }
    let runtime = state.store.get(&host);
    let declared = host_is_declared(&state, &host);
    let job = state
        .provisioning_jobs
        .list()
        .into_iter()
        .filter(|job| provisioning_job_host_name(job) == Some(host.as_str()))
        .max_by_key(|job| (job.updated_at, job.created_at));
    if runtime.is_none() && !declared && job.is_none() {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Json(json!({ "error": "Host proof was not found" })),
        )
            .into_response();
    }
    let last_seen = runtime.as_ref().and_then(|host| host.last_seen);
    let liveness = runtime
        .as_ref()
        .map(|host| liveness(host.last_seen, host.heartbeat_interval_secs, now_unix()));
    let verified = last_seen.is_some()
        && job.as_ref().is_none_or(|job| {
            job.terminal_outcome == Some(ProvisioningTerminalOutcome::Provisioned)
        });
    (
        StatusCode::OK,
        no_store_headers(),
        Json(json!({
            "schema": "inspr.pharos.host-proof.v1",
            "version": 1,
            "host": host,
            "declared": declared,
            "reporting": runtime.is_some(),
            "last_seen": last_seen,
            "liveness": liveness,
            "verified": verified,
            "provisioning": job.as_ref().map(|job| json!({
                "job_id": job.id,
                "state": job.state,
                "terminal_outcome": job.terminal_outcome,
                "host_need_intent_ref": job.host_need_intent.as_ref().map(|intent| &intent.intent_ref),
                "reason_ref": job.host_need_intent.as_ref().map(|intent| &intent.reason_ref),
            })),
            "janus": state.beacon_auth.janus_readiness().map(|readiness| json!({
                "capability": JanusCapability::PharosBeaconToken.as_str(),
                "ready": readiness.ready,
                "generation": readiness.generation,
                "host_count": readiness.host_count,
            })),
            "value_returned": false,
        })),
    )
        .into_response()
}

async fn managed_service_declarations_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> (
    StatusCode,
    [(header::HeaderName, &'static str); 3],
    Json<serde_json::Value>,
) {
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Managed-service declaration access is not granted" })),
        );
    }
    (
        StatusCode::OK,
        no_store_headers(),
        Json(managed_service_declarations_payload(
            state.manifests.managed_service_manifests(),
            state.manifests.managed_service_load_errors(),
            &state.managed_service_operations,
            now_unix(),
        )),
    )
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreateManagedSetupIntentRequest {
    operation_kind: ManagedOperationKind,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
}

async fn create_managed_setup_intent(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<CreateManagedSetupIntentRequest>,
) -> Response {
    if !action_request_header(&headers) {
        return managed_intent_denial(IntentReason::InvalidRequest);
    }
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora() {
        return managed_intent_denial(IntentReason::Forbidden);
    }
    let Some(user) = state.auth.human_user(&headers) else {
        return managed_intent_denial(IntentReason::AuthenticationRequired);
    };
    let Some(store) = state.managed_setup_intents.as_ref() else {
        return managed_intent_denial(IntentReason::Disabled);
    };
    let slot_policy = match current_managed_slot(
        &state.manifests,
        &state.managed_service_operations,
        &request,
        now_unix(),
    ) {
        Ok(policy) => policy,
        Err(reason) => return managed_intent_denial(reason),
    };
    match store.issue(IssueIntent {
        operation_kind: request.operation_kind,
        allowed_sources: slot_policy.allowed_sources,
        host_ref: request.host_ref,
        service_ref: request.service_ref,
        slot_ref: request.slot_ref,
        human_session_ref: user.managed_human_session_ref,
        declaration_fingerprint: slot_policy.declaration_fingerprint,
        now_unix_secs: now_unix(),
    }) {
        Ok(issued) => (
            StatusCode::CREATED,
            no_store_headers(),
            Json(json!({
                "schema": DELIVERY_SCHEMA,
                "schema_version": CONTRACT_VERSION,
                "intent_ref": issued.intent_ref,
                "continue_url": issued.continue_url,
                "expires_at_unix_secs": issued.expires_at_unix_secs,
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(reason) => managed_intent_denial(reason),
    }
}

async fn cancel_managed_setup_intent(
    State(state): State<AppState>,
    AxumPath(intent_ref): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if !action_request_header(&headers) {
        return managed_intent_denial(IntentReason::InvalidRequest);
    }
    let Some(user) = state.auth.human_user(&headers) else {
        return managed_intent_denial(IntentReason::AuthenticationRequired);
    };
    let Some(store) = state.managed_setup_intents.as_ref() else {
        return managed_intent_denial(IntentReason::Disabled);
    };
    match store.cancel(&intent_ref, &user.managed_human_session_ref, now_unix()) {
        Ok(()) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "schema": DELIVERY_SCHEMA,
                "schema_version": CONTRACT_VERSION,
                "intent_ref": intent_ref,
                "outcome": "cancelled",
                "reason_code": "managed_intent_cancelled",
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(reason) => managed_intent_denial(reason),
    }
}

async fn retry_managed_service_verification(
    State(state): State<AppState>,
    AxumPath(operation_ref): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    if !action_request_header(&headers) {
        return managed_verification_retry_denial(
            StatusCode::BAD_REQUEST,
            "managed_verification_retry_invalid_request",
        );
    }
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora() {
        return managed_verification_retry_denial(
            StatusCode::FORBIDDEN,
            "managed_verification_retry_forbidden",
        );
    }
    if state.auth.human_user(&headers).is_none() {
        return managed_verification_retry_denial(
            StatusCode::UNAUTHORIZED,
            "managed_verification_retry_authentication_required",
        );
    }
    let now = now_unix();
    let operation = match state.managed_service_operations.get(&operation_ref, now) {
        Ok(operation) => operation,
        Err(error) => return managed_operation_denial(error),
    };
    if state
        .manifests
        .managed_secret_slot_for_mutation(
            &operation.host_ref,
            &operation.service_ref,
            &operation.slot_ref,
            &operation.declaration_fingerprint,
        )
        .is_err()
    {
        return managed_operation_denial(ManagedOperationStoreError::DeclarationDrift);
    }
    match state.managed_service_operations.retry(&operation_ref, now) {
        Ok(operation) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "schema": "inspr.pharos.managed-service-operation-status.v1",
                "schema_version": 1,
                "operation": operation,
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(error) => managed_operation_denial(error),
    }
}

fn managed_verification_retry_denial(status: StatusCode, reason_code: &'static str) -> Response {
    (
        status,
        no_store_headers(),
        Json(json!({
            "schema": "inspr.pharos.managed-service-operation-status.v1",
            "schema_version": 1,
            "outcome": "denied",
            "reason_code": reason_code,
            "value_returned": false,
        })),
    )
        .into_response()
}

async fn retrieve_managed_setup_intent(
    State(state): State<AppState>,
    AxumPath(intent_ref): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(store) = state.managed_setup_intents.as_ref() else {
        return managed_intent_denial(IntentReason::Disabled);
    };
    let token = bearer_token(&headers).unwrap_or_default();
    match store.retrieve(&intent_ref, token, now_unix()) {
        Ok(envelope) => (StatusCode::OK, no_store_headers(), Json(envelope)).into_response(),
        Err(reason) => managed_intent_denial(reason),
    }
}

async fn register_managed_service_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManagedOperationReadyV1>,
) -> Response {
    let Some(intent_store) = state.managed_setup_intents.as_ref() else {
        return managed_operation_denial(ManagedOperationStoreError::PersistenceUnavailable);
    };
    let token = bearer_token(&headers).unwrap_or_default();
    if !intent_store.system_authorized(token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if request.validate_contract().is_err() {
        return managed_operation_denial(ManagedOperationStoreError::InvalidRequest);
    }
    let slot = match state.manifests.managed_secret_slot_for_mutation(
        &request.host_ref,
        &request.service_ref,
        &request.slot_ref,
        &request.declaration_fingerprint,
    ) {
        Ok(slot) => slot,
        Err(_) => {
            return managed_operation_denial(ManagedOperationStoreError::DeclarationDrift);
        }
    };
    match state
        .managed_service_operations
        .register(&request, slot, now_unix())
    {
        Ok(operation) => (
            StatusCode::CREATED,
            no_store_headers(),
            Json(json!({
                "schema": "inspr.pharos.managed-service-operation-status.v1",
                "schema_version": 1,
                "operation": operation,
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(error) => managed_operation_denial(error),
    }
}

async fn retrieve_managed_service_operation(
    State(state): State<AppState>,
    AxumPath(operation_ref): AxumPath<String>,
    headers: HeaderMap,
) -> Response {
    let Some(intent_store) = state.managed_setup_intents.as_ref() else {
        return managed_operation_denial(ManagedOperationStoreError::PersistenceUnavailable);
    };
    let token = bearer_token(&headers).unwrap_or_default();
    if !intent_store.system_authorized(token) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match state
        .managed_service_operations
        .get(&operation_ref, now_unix())
    {
        Ok(operation) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "schema": "inspr.pharos.managed-service-operation-status.v1",
                "schema_version": 1,
                "operation": operation,
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(error) => managed_operation_denial(error),
    }
}

async fn claim_managed_service_operation(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ManagedOperationClaimV1>,
) -> Response {
    if request.validate_contract().is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = managed_agent_authorized(&state, &headers, &request.host_ref) {
        return status.into_response();
    }
    match state
        .managed_service_operations
        .claim(&request.host_ref, now_unix())
    {
        Ok(Some(lease)) => (StatusCode::OK, no_store_headers(), Json(lease)).into_response(),
        Ok(None) => (StatusCode::NO_CONTENT, no_store_headers()).into_response(),
        Err(ManagedOperationStoreError::PersistenceUnavailable) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::CONFLICT.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManagedOperationHostStatusQuery {
    host_ref: String,
}

async fn retrieve_managed_service_operation_for_host(
    State(state): State<AppState>,
    AxumPath(operation_ref): AxumPath<String>,
    Query(query): Query<ManagedOperationHostStatusQuery>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = managed_agent_authorized(&state, &headers, &query.host_ref) {
        return status.into_response();
    }
    match state
        .managed_service_operations
        .get(&operation_ref, now_unix())
    {
        Ok(operation) if operation.host_ref == query.host_ref => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "schema": "inspr.pharos.managed-service-operation-status.v1",
                "schema_version": 1,
                "operation": operation,
                "value_returned": false,
            })),
        )
            .into_response(),
        Ok(_) => StatusCode::FORBIDDEN.into_response(),
        Err(ManagedOperationStoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ManagedOperationStoreError::PersistenceUnavailable) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn record_managed_service_operation_result(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(operation_ref): AxumPath<String>,
    Json(request): Json<ManagedOperationResultV1>,
) -> Response {
    if request.validate_contract().is_err() || request.operation_ref != operation_ref {
        return StatusCode::BAD_REQUEST.into_response();
    }
    if let Err(status) = managed_agent_authorized(&state, &headers, &request.host_ref) {
        return status.into_response();
    }
    match state
        .managed_service_operations
        .record_result(&request, now_unix())
    {
        Ok(operation) => (
            StatusCode::OK,
            no_store_headers(),
            Json(json!({
                "schema": "inspr.pharos.managed-service-operation-status.v1",
                "schema_version": 1,
                "operation": operation,
                "value_returned": false,
            })),
        )
            .into_response(),
        Err(ManagedOperationStoreError::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(ManagedOperationStoreError::WrongHost) => StatusCode::FORBIDDEN.into_response(),
        Err(ManagedOperationStoreError::PersistenceUnavailable) => {
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
        Err(
            ManagedOperationStoreError::LeaseExpired
            | ManagedOperationStoreError::InvalidEvidence
            | ManagedOperationStoreError::Conflict,
        ) => StatusCode::CONFLICT.into_response(),
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

fn managed_operation_denial(error: ManagedOperationStoreError) -> Response {
    let (status, reason_code) = match error {
        ManagedOperationStoreError::InvalidRequest => {
            (StatusCode::BAD_REQUEST, "managed_operation_invalid_request")
        }
        ManagedOperationStoreError::DeclarationDrift => {
            (StatusCode::CONFLICT, "managed_operation_declaration_drift")
        }
        ManagedOperationStoreError::GenerationDowngrade => (
            StatusCode::CONFLICT,
            "managed_operation_generation_downgrade",
        ),
        ManagedOperationStoreError::Conflict => {
            (StatusCode::CONFLICT, "managed_operation_conflict")
        }
        ManagedOperationStoreError::NotFound => {
            (StatusCode::NOT_FOUND, "managed_operation_unknown")
        }
        ManagedOperationStoreError::WrongHost => {
            (StatusCode::FORBIDDEN, "managed_operation_wrong_host")
        }
        ManagedOperationStoreError::LeaseExpired => {
            (StatusCode::CONFLICT, "managed_operation_lease_expired")
        }
        ManagedOperationStoreError::InvalidEvidence => {
            (StatusCode::CONFLICT, "managed_operation_health_invalid")
        }
        ManagedOperationStoreError::PersistenceUnavailable => (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed_operation_persistence_unavailable",
        ),
        ManagedOperationStoreError::Capacity => (
            StatusCode::SERVICE_UNAVAILABLE,
            "managed_operation_capacity",
        ),
    };
    (
        status,
        no_store_headers(),
        Json(json!({
            "schema": "inspr.pharos.managed-service-operation-status.v1",
            "schema_version": 1,
            "outcome": "denied",
            "reason_code": reason_code,
            "value_returned": false,
        })),
    )
        .into_response()
}

fn current_managed_slot(
    manifests: &ManifestRegistry,
    operations: &ManagedServiceOperationStore,
    request: &CreateManagedSetupIntentRequest,
    now: i64,
) -> Result<ManagedSlotIntentPolicy, IntentReason> {
    if !manifests.managed_service_load_errors().is_empty() {
        return Err(IntentReason::DeclarationUnavailable);
    }
    let manifest = manifests
        .managed_service_manifests()
        .iter()
        .find(|manifest| manifest.host_ref == request.host_ref)
        .ok_or(IntentReason::DeclarationDrift)?;
    let service = manifest
        .services
        .iter()
        .find(|service| service.service_ref == request.service_ref)
        .ok_or(IntentReason::DeclarationDrift)?;
    let slot = service
        .slots
        .iter()
        .find(|slot| slot.slot_ref == request.slot_ref)
        .ok_or(IntentReason::DeclarationDrift)?;
    let latest = operations.latest_for_slot(
        &request.host_ref,
        &request.service_ref,
        &request.slot_ref,
        now,
    );
    match request.operation_kind {
        ManagedOperationKind::Create => {
            if slot.binding_state != ManagedBindingState::Required {
                return Err(IntentReason::BindingDetached);
            }
            if latest.as_ref().is_some_and(|operation| {
                !matches!(
                    operation.phase,
                    ManagedOperationPhase::Failed | ManagedOperationPhase::Superseded
                )
            }) {
                return Err(IntentReason::OperationConflict);
            }
        }
        ManagedOperationKind::Replace => {
            if slot.binding_state != ManagedBindingState::Required {
                return Err(IntentReason::BindingDetached);
            }
            match latest.as_ref() {
                Some(operation)
                    if operation.declaration_fingerprint == manifest.declaration_fingerprint
                        && (operation.phase == ManagedOperationPhase::Active
                            || operation.phase == ManagedOperationPhase::RolledBack
                                && operation.rollback.is_some()) => {}
                Some(operation) if !operation.phase.terminal() => {
                    return Err(IntentReason::OperationConflict);
                }
                _ => return Err(IntentReason::ActiveGenerationRequired),
            }
        }
        ManagedOperationKind::Remove => {
            if slot.binding_state != ManagedBindingState::Detached || slot.detach.is_none() {
                return Err(IntentReason::BindingDetachRequired);
            }
            match latest.as_ref() {
                Some(operation)
                    if operation.phase == ManagedOperationPhase::Active
                        || operation.phase == ManagedOperationPhase::RolledBack
                            && operation.rollback.is_some() => {}
                Some(operation) if !operation.phase.terminal() => {
                    return Err(IntentReason::OperationConflict);
                }
                _ => return Err(IntentReason::ActiveGenerationRequired),
            }
        }
    }
    let allowed_sources = if request.operation_kind == ManagedOperationKind::Remove {
        Vec::new()
    } else {
        slot.allowed_sources
            .iter()
            .map(|source| match source {
                pharos_core::managed_services::ManagedSecretSource::Generated => {
                    ManagedSecretSource::Generated
                }
                pharos_core::managed_services::ManagedSecretSource::Import => {
                    ManagedSecretSource::Import
                }
            })
            .collect()
    };
    // The declaration admits both operations, but Pharos signs Replace only
    // for a current, healthy generation (or a proven healthy rollback). Janus
    // independently rechecks value custody and the exact declaration binding.
    Ok(ManagedSlotIntentPolicy {
        declaration_fingerprint: manifest.declaration_fingerprint.clone(),
        allowed_sources,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ManagedSlotIntentPolicy {
    declaration_fingerprint: String,
    allowed_sources: Vec<ManagedSecretSource>,
}

fn managed_intent_denial(reason: IntentReason) -> Response {
    let status = match reason {
        IntentReason::AuthenticationRequired | IntentReason::UnauthorizedSystem => {
            StatusCode::UNAUTHORIZED
        }
        IntentReason::Forbidden => StatusCode::FORBIDDEN,
        IntentReason::InvalidRequest => StatusCode::BAD_REQUEST,
        IntentReason::OperationConflict
        | IntentReason::ActiveGenerationRequired
        | IntentReason::BindingDetachRequired
        | IntentReason::BindingDetached => StatusCode::CONFLICT,
        IntentReason::Unknown => StatusCode::NOT_FOUND,
        IntentReason::Expired | IntentReason::Cancelled | IntentReason::WrongUser => {
            StatusCode::GONE
        }
        IntentReason::DeclarationDrift | IntentReason::AlreadyDelivered => StatusCode::CONFLICT,
        IntentReason::Disabled
        | IntentReason::DeclarationUnavailable
        | IntentReason::Capacity
        | IntentReason::PersistenceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
    };
    tracing::warn!(reason_code = reason.code(), "managed setup intent denied");
    (
        status,
        no_store_headers(),
        Json(json!({
            "schema": DELIVERY_SCHEMA,
            "schema_version": CONTRACT_VERSION,
            "outcome": "denied",
            "reason_code": reason.code(),
            "value_returned": false,
        })),
    )
        .into_response()
}

fn managed_service_declarations_payload(
    manifests: &[ManagedServiceManifestV1],
    load_errors: &[ManifestLoadIssue],
    operations: &ManagedServiceOperationStore,
    now: i64,
) -> serde_json::Value {
    let mutation_block = if !load_errors.is_empty() {
        Some("registry_invalid")
    } else if manifests.is_empty() {
        Some("no_declarations")
    } else {
        None
    };
    let declarations: Vec<_> = manifests
        .iter()
        .map(|manifest| {
            let operation_status: Vec<_> = operations
                .for_host(&manifest.host_ref, now)
                .into_iter()
                .filter(|operation| {
                    operation.declaration_fingerprint == manifest.declaration_fingerprint
                })
                .collect();
            let observed_health: Vec<_> = operation_status
                .iter()
                .filter_map(|operation| operation.health.as_ref())
                .collect();
            json!({
                "declared": manifest,
                "runtime": {
                    "delivery_owner": "janus",
                    "operations": operation_status,
                    "observed_health": observed_health,
                },
            })
        })
        .collect();
    json!({
        "schema": "inspr.pharos.managed-service-declaration-status.v1",
        "declaration_schema": MANAGED_SERVICE_MANIFEST_SCHEMA,
        "declaration_version": MANAGED_SERVICE_MANIFEST_VERSION,
        "mutation_ready": mutation_block.is_none(),
        "mutation_block": mutation_block,
        "declarations": declarations,
        "load_errors": load_errors,
    })
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
            "kernel": null,
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
        "kernel": host.kernel,
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

const MAX_RENDERED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

async fn security_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
    let auth_response = request.uri().path().starts_with("/auth/");
    let mut response = secure_response(next.run(request).await).await;
    if auth_response {
        for (name, value) in no_store_headers() {
            response
                .headers_mut()
                .insert(name, axum::http::HeaderValue::from_static(value));
        }
    }
    response
}

async fn secure_response(response: Response) -> Response {
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));

    let nonce = if is_html {
        match content_security_nonce() {
            Ok(nonce) => Some(nonce),
            Err(()) => {
                return security_policy_failure_response();
            }
        }
    } else {
        None
    };

    let mut response = if let Some(nonce) = nonce.as_deref() {
        let (mut parts, body) = response.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_RENDERED_RESPONSE_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => return security_policy_failure_response(),
        };
        let html = match String::from_utf8(bytes.to_vec()) {
            Ok(html) => html,
            Err(_) => return security_policy_failure_response(),
        };
        let script_open = format!(r#"<script nonce="{nonce}""#);
        let style_open = format!(r#"<style nonce="{nonce}""#);
        let html = html
            .replace("<script", &script_open)
            .replace("<style", &style_open);
        parts.headers.remove(header::CONTENT_LENGTH);
        Response::from_parts(parts, axum::body::Body::from(html))
    } else {
        response
    };

    apply_security_headers(response.headers_mut(), nonce.as_deref());
    response
}

fn content_security_nonce() -> Result<String, ()> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| ())?;
    let mut nonce = String::with_capacity(random.len() * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(nonce, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(nonce)
}

fn apply_security_headers(headers: &mut HeaderMap, nonce: Option<&str>) {
    use axum::http::{HeaderName, HeaderValue};

    let csp = nonce.map_or_else(
        || "default-src 'none'; base-uri 'none'; frame-ancestors 'none'".to_string(),
        |nonce| {
            format!(
                "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'nonce-{nonce}'; script-src-attr 'none'; style-src 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data: https://*.basemaps.cartocdn.com; connect-src 'self'; font-src 'self'; media-src 'self'; frame-src 'none'; worker-src 'none'; manifest-src 'self'"
            )
        },
    );
    let csp = HeaderValue::from_str(&csp).expect("generated CSP is a valid header");
    headers.insert(HeaderName::from_static("content-security-policy"), csp);
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
}

fn security_policy_failure_response() -> Response {
    let mut response = (
        StatusCode::INTERNAL_SERVER_ERROR,
        "response security policy unavailable",
    )
        .into_response();
    apply_security_headers(response.headers_mut(), None);
    response
}

fn no_store_html(body: String) -> impl IntoResponse {
    (no_store_headers(), Html(body))
}

fn no_store_json(value: serde_json::Value) -> impl IntoResponse {
    (no_store_headers(), Json(value))
}

fn filter_hosts_by_access(hosts: Vec<Host>, access: &AccessGrant) -> Vec<Host> {
    hosts
        .into_iter()
        .filter(|host| access.allows_host(&host.name))
        .collect()
}

fn filter_manifests_by_access(
    manifests: &[HostManifest],
    access: &AccessGrant,
) -> Vec<HostManifest> {
    manifests
        .iter()
        .filter(|manifest| {
            access.allows_host(&manifest.host.name) || access.allows_host(&manifest.slug)
        })
        .cloned()
        .collect()
}

fn filter_declared_preferences_by_access(
    preferences: &BTreeMap<String, HostPreferences>,
    access: &AccessGrant,
) -> BTreeMap<String, HostPreferences> {
    preferences
        .iter()
        .filter(|(host, _)| access.allows_host(host))
        .map(|(host, preferences)| (host.clone(), preferences.clone()))
        .collect()
}

fn filter_jobs_by_access(jobs: Vec<ProvisioningJob>, access: &AccessGrant) -> Vec<ProvisioningJob> {
    jobs.into_iter()
        .filter(|job| {
            provisioning_job_host_name(job)
                .map(|host| access.allows_host(host))
                .unwrap_or_else(|| access.can_agora())
        })
        .collect()
}

#[derive(Debug, Default, Deserialize)]
struct ProviderSettingsQuery {
    #[serde(default, rename = "return")]
    return_path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderDisconnectRequest {
    confirm: bool,
}

fn unavailable_hetzner_test_result(
    runtime: &HetznerCloudRuntimeConfig,
    now: i64,
) -> HetznerConnectionTestResult {
    HetznerConnectionTestResult {
        attempt: HetznerConnectionAttempt {
            tested_at: now,
            code: HetznerConnectionCode::CredentialUnavailable,
            api_access: false,
            credential_boundary_ready: runtime.credential_boundary_ready(),
            execution_enabled: runtime.execute_enabled,
            ssh_key_ready: false,
            firewall_ready: false,
            default_location_ready: false,
            catalog_ready: false,
        },
        catalog: None,
    }
}

async fn run_hetzner_connection_test(
    state: &AppState,
    now: i64,
) -> Result<(), provider_connections::ProviderConnectionStoreError> {
    run_hetzner_connection_test_for(state, now, None, None).await
}

async fn run_hetzner_connection_test_for(
    state: &AppState,
    now: i64,
    ssh_key_override: Option<&str>,
    location_override: Option<&str>,
) -> Result<(), provider_connections::ProviderConnectionStoreError> {
    let runtime = effective_hetzner_runtime(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
    );
    let result = match runtime.api_token() {
        Ok(token) => {
            test_hetzner_connection(
                HetznerTestConfig {
                    api_base_url: &runtime.api_base_url,
                    request_timeout: runtime.request_timeout,
                    token: &token,
                    credential_boundary_ready: runtime.credential_boundary_ready(),
                    execution_enabled: runtime.execute_enabled,
                    ssh_key_ref: ssh_key_override.or(runtime.default_ssh_key_ref.as_deref()),
                    firewall_ref: runtime.firewall_ref.as_deref(),
                    default_location: location_override.or(runtime.default_location.as_deref()),
                },
                now,
            )
            .await
        }
        Err(_) => unavailable_hetzner_test_result(&runtime, now),
    };
    state.provider_connections.record_test(result)
}

fn hetzner_connection_response(state: &AppState, now: i64) -> Json<serde_json::Value> {
    let readiness = hetzner_runtime_readiness(
        &state.provider_runtime.hetzner_cloud,
        &state.provider_connections,
        now,
    );
    let catalog = state.provider_connections.catalog();
    Json(json!({
        "readiness": readiness,
        "catalog": catalog.map(|catalog| json!({
            "refreshed_at": catalog.refreshed_at,
            "currency": catalog.currency,
            "locations": catalog.locations.len(),
            "server_types": catalog.server_types.len(),
            "ssh_keys": catalog.ssh_keys.len(),
            "firewalls": catalog.firewalls.len(),
        })),
    }))
}

async fn test_hetzner_provider_connection(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Provider connection access is not granted" })),
        );
    }
    let now = now_unix();
    if let Err(error) = run_hetzner_connection_test(&state, now).await {
        tracing::error!(error = %error, "provider test result could not be durably recorded");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(json!({ "error": "Provider state could not be durably recorded" })),
        );
    }
    (
        StatusCode::OK,
        no_store_headers(),
        hetzner_connection_response(&state, now),
    )
}

async fn update_hetzner_provider_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(preferences): Json<HetznerConnectionPreferences>,
) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Provider connection access is not granted" })),
        );
    }
    let now = now_unix();
    if let Err(error) = state.provider_connections.update_preferences(
        preferences,
        now,
        state.provider_runtime.hetzner_cloud.evidence_ttl_secs,
    ) {
        let status = if error == provider_connections::HetznerPreferenceError::PersistenceFailed {
            StatusCode::SERVICE_UNAVAILABLE
        } else {
            StatusCode::CONFLICT
        };
        return (
            status,
            no_store_headers(),
            Json(json!({ "error": error.safe_message() })),
        );
    }
    if let Err(error) = run_hetzner_connection_test(&state, now).await {
        tracing::error!(error = %error, "provider retest result could not be durably recorded");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(json!({ "error": "Provider state could not be durably recorded" })),
        );
    }
    (
        StatusCode::OK,
        no_store_headers(),
        hetzner_connection_response(&state, now),
    )
}

async fn disconnect_hetzner_provider(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<ProviderDisconnectRequest>,
) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    if !action_request_header(&headers) || !access.can_manage_fleet() {
        return (
            StatusCode::FORBIDDEN,
            no_store_headers(),
            Json(json!({ "error": "Provider connection access is not granted" })),
        );
    }
    if !request.confirm {
        return (
            StatusCode::BAD_REQUEST,
            no_store_headers(),
            Json(json!({ "error": "Confirm provider disconnection first" })),
        );
    }
    let now = now_unix();
    if let Err(error) = state.provider_connections.disconnect(now) {
        tracing::error!(error = %error, "provider disconnection could not be durably recorded");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Json(json!({ "error": "Provider disconnection could not be durably recorded" })),
        );
    }
    (
        StatusCode::OK,
        no_store_headers(),
        hetzner_connection_response(&state, now),
    )
}

#[tokio::main]
async fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("healthcheck")) {
        // Container probe (PHAROS-203): every verdict carries its reason so
        // `docker inspect --format '{{json .State.Health}}'` is diagnosable.
        match container_healthcheck().await {
            Ok(detail) => {
                println!("pharosd healthcheck: {detail}");
                std::process::exit(0);
            }
            Err(reason) => {
                eprintln!("pharosd healthcheck: {reason}");
                std::process::exit(1);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let startup = StartupConfig::from_env()
        .unwrap_or_else(|err| panic!("invalid Pharos startup configuration: {err}"));
    let host_store_path = std::env::var("PHAROS_DB").ok().map(PathBuf::from);
    let managed_setup_intent_store_path =
        ManagedSetupIntentStore::path_for(host_store_path.as_deref());
    let managed_service_operation_store_path =
        ManagedServiceOperationStore::path_for(host_store_path.as_deref());
    let provisioning_job_store_path = provisioning_jobs_path(host_store_path.as_deref());
    let host_action_store_path = HostActionStore::path_for(host_store_path.as_deref());
    let retired_host_store_path = RetiredHostStore::path_for(host_store_path.as_deref());
    let provider_connection_store_path =
        ProviderConnectionStore::path_for(host_store_path.as_deref());
    let alert_store_path = AlertStore::path_for(host_store_path.as_deref());
    let store = Arc::new(
        Store::new(host_store_path.clone())
            .unwrap_or_else(|error| panic!("host store startup failed: {error}")),
    );
    let provisioning_jobs = Arc::new(ProvisioningJobStore::new(provisioning_job_store_path));
    let host_actions = Arc::new(HostActionStore::new(host_action_store_path));
    let retired_hosts = Arc::new(RetiredHostStore::new(retired_host_store_path));
    let provider_connections = Arc::new(
        ProviderConnectionStore::new(provider_connection_store_path)
            .unwrap_or_else(|error| panic!("provider connection store startup failed: {error}")),
    );
    let alert_store = Arc::new(
        AlertStore::new(alert_store_path)
            .unwrap_or_else(|error| panic!("alert store startup failed: {error}")),
    );
    let manifests = Arc::new(ManifestRegistry::from_env());
    let managed_setup_intents = match ManagedSetupIntentConfig::from_env()
        .unwrap_or_else(|error| panic!("managed setup intent startup failed: {error}"))
    {
        None => None,
        Some(config) => {
            let path = managed_setup_intent_store_path.unwrap_or_else(|| {
                panic!("managed setup intents require PHAROS_DB for durable single-use state")
            });
            Some(Arc::new(
                ManagedSetupIntentStore::new(path, config).unwrap_or_else(|error| {
                    panic!("managed setup intent store startup failed: {error}")
                }),
            ))
        }
    };
    let managed_service_operations = Arc::new(
        ManagedServiceOperationStore::new(managed_service_operation_store_path)
            .unwrap_or_else(|error| panic!("managed service operation startup failed: {error}")),
    );
    let auth = Auth::from_config(startup.auth)
        .await
        .unwrap_or_else(|err| panic!("Pharos authentication startup failed: {err}"));
    let beacon_auth = startup.beacon_auth;
    let provider_runtime = ProviderRuntimeConfig::from_env();
    let appliance_probes = ApplianceProbeRuntime::from_env(
        host_store_path.as_deref(),
        provider_runtime.existing_host.clone(),
    )
    .unwrap_or_else(|error| panic!("appliance probe startup failed: {error}"));
    if let Some(runtime) = appliance_probes.as_ref() {
        runtime
            .validate_host_records(&store, &manifests)
            .unwrap_or_else(|error| panic!("appliance probe startup failed: {error}"));
    }
    let appliance_probes = appliance_probes.map(Arc::new);
    store
        .replace_server_observations(appliance_probes::APPLIANCE_OBSERVATION_ID, &BTreeMap::new())
        .unwrap_or_else(|error| panic!("stale appliance observation cleanup failed: {error}"));
    let nixcfg_dispatch = NixcfgDispatch::from_env();
    let retirement_owner = RetirementOwnerAuth::from_env();
    let alert_notifier = AlertNotifier::from_env(alert_store)
        .unwrap_or_else(|error| panic!("alert notifier startup failed: {error}"));
    let alert_health = alert_notifier.health.clone();
    let paimos_delivery = paimos_delivery::PaimosDeliveryAdapter::from_env(
        host_store_path.as_deref(),
        Arc::clone(&store),
        Arc::clone(&host_actions),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    let state = AppState {
        store,
        provisioning_jobs,
        manifests,
        managed_setup_intents,
        managed_service_operations,
        auth,
        beacon_auth,
        provider_runtime,
        provider_connections,
        paid_create_lock: Arc::new(tokio::sync::Mutex::new(())),
        settings_change_lock: Arc::new(tokio::sync::Mutex::new(())),
        nixcfg_dispatch,
        retirement_owner,
        host_actions,
        retired_hosts,
        alert_health,
    };
    let _ = reconcile_saved_next_actions(&state, now_unix()).await;
    spawn_next_action_loop(state.clone());
    spawn_alert_loop(state.clone(), alert_notifier);
    if let Some(runtime) = appliance_probes {
        spawn_appliance_probe_loop(runtime, Arc::clone(&state.store));
    }
    if let Some(adapter) = paimos_delivery {
        adapter.spawn();
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(startup.addr)
        .await
        .expect("bind PHAROS_ADDR");
    tracing::info!(
        "pharosd v{} listening on http://{}",
        env!("CARGO_PKG_VERSION"),
        startup.addr
    );
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn proven_freshness(
        channel: &str,
        git_relation: GitRevisionRelation,
        commits_behind: Option<u32>,
        nixpkgs_relation: NixpkgsRevisionRelation,
    ) -> NixFreshness {
        let deployed_revision = "1".repeat(40);
        let nixpkgs_revision = "2".repeat(40);
        NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind,
            nixpkgs_age_days: Some(0),
            nixpkgs_channel: Some(channel.to_string()),
            secondary_nixpkgs: None,
            deployment_evidence: Some(NixDeploymentEvidence {
                schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
                version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
                source_revision: deployed_revision.clone(),
                flake_lock_sha256: "3".repeat(64),
                nixpkgs_revision: nixpkgs_revision.clone(),
                nixpkgs_last_modified: 1_700_000_000,
                nixpkgs_channel: channel.to_string(),
            }),
            nixcfg_comparison: Some(NixcfgGitComparison {
                upstream_revision: if git_relation == GitRevisionRelation::Current {
                    deployed_revision
                } else {
                    "4".repeat(40)
                },
                relation: git_relation,
                commits_behind,
            }),
            nixpkgs_comparison: Some(NixpkgsGitComparison {
                upstream_revision: if nixpkgs_relation == NixpkgsRevisionRelation::Current {
                    nixpkgs_revision
                } else {
                    "5".repeat(40)
                },
                relation: nixpkgs_relation,
            }),
        }
    }

    async fn json_response(response: Response) -> (StatusCode, HeaderMap, serde_json::Value) {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body is bounded");
        let payload = serde_json::from_slice(&bytes).expect("response body is JSON");
        (status, headers, payload)
    }

    #[derive(Clone, Debug)]
    struct RecordedSshCall {
        command: String,
        stdin: Vec<u8>,
    }

    struct FakeExistingHostSshRunner {
        readiness: &'static str,
        calls: Mutex<Vec<RecordedSshCall>>,
    }

    impl FakeExistingHostSshRunner {
        fn new(readiness: &'static str) -> Self {
            Self {
                readiness,
                calls: Mutex::new(Vec::new()),
            }
        }

        fn calls(&self) -> Vec<RecordedSshCall> {
            self.calls.lock().expect("fake runner lock").clone()
        }
    }

    impl ExistingHostSshRunner for FakeExistingHostSshRunner {
        fn run(
            &self,
            _config: &ExistingHostRuntimeConfig,
            _spec: &NativeSystemdBootstrapSpec,
            remote_command: &str,
            stdin: Option<&[u8]>,
        ) -> Result<Vec<u8>, ExistingHostExecutionError> {
            self.calls
                .lock()
                .expect("fake runner lock")
                .push(RecordedSshCall {
                    command: remote_command.to_string(),
                    stdin: stdin.unwrap_or_default().to_vec(),
                });
            if remote_command.contains("mktemp -d") {
                return Ok(b"/tmp/pharos-bootstrap.test123\n".to_vec());
            }
            if remote_command == REMOTE_NATIVE_SYSTEMD_READINESS {
                return Ok(self.readiness.as_bytes().to_vec());
            }
            Ok(Vec::new())
        }
    }

    fn test_existing_host_runtime() -> (ExistingHostRuntimeConfig, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "pharos-existing-runtime-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("test runtime dir");
        let known_hosts_file = dir.join("known_hosts");
        let beacon_binary_path = dir.join("pharos-beacon");
        let installer_path = dir.join("installer.sh");
        std::fs::write(&known_hosts_file, b"test-host-key\n").expect("known hosts");
        std::fs::write(&beacon_binary_path, b"test-beacon-binary").expect("beacon binary");
        std::fs::write(&installer_path, b"#!/bin/sh\nexit 0\n").expect("installer");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;

            std::fs::set_permissions(&known_hosts_file, std::fs::Permissions::from_mode(0o600))
                .expect("known-hosts permissions");
            std::fs::set_permissions(&beacon_binary_path, std::fs::Permissions::from_mode(0o700))
                .expect("beacon permissions");
            std::fs::set_permissions(&installer_path, std::fs::Permissions::from_mode(0o700))
                .expect("installer permissions");
        }
        (
            ExistingHostRuntimeConfig {
                execute_enabled: true,
                identity_file: None,
                known_hosts_file: Some(known_hosts_file),
                beacon_binary_path,
                installer_path,
                pharos_url: Some("https://pharos.example".to_string()),
            },
            dir,
        )
    }

    fn cleanup_test_existing_host_runtime(config: &ExistingHostRuntimeConfig, dir: &Path) {
        if let Some(path) = &config.known_hosts_file {
            let _ = std::fs::remove_file(path);
        }
        let _ = std::fs::remove_file(&config.beacon_binary_path);
        let _ = std::fs::remove_file(&config.installer_path);
        let _ = std::fs::remove_dir(dir);
    }

    fn test_native_bootstrap_spec() -> NativeSystemdBootstrapSpec {
        NativeSystemdBootstrapSpec {
            host_name: "legacy-test".to_string(),
            role: "server".to_string(),
            interval: 60,
            target: "root@legacy-test".to_string(),
            port: 22,
        }
    }

    fn test_ready_arch() -> &'static str {
        match std::env::consts::ARCH {
            "x86_64" => "ready:x86_64",
            "aarch64" => "ready:aarch64",
            _ => "ready:unknown",
        }
    }

    #[tokio::test]
    async fn version_endpoint_reports_embedded_build_metadata() {
        let Json(payload) = version().await;

        assert_eq!(payload["name"], "pharosd");
        assert_eq!(payload["version"], APP_VERSION);
        assert_eq!(payload["display_version"], release_label());
        assert_eq!(payload["git_commit"], GIT_COMMIT);
    }

    #[test]
    fn container_healthcheck_targets_the_bound_port_over_loopback() {
        assert_eq!(
            container_healthcheck_url("0.0.0.0:8080".parse().unwrap()),
            "http://127.0.0.1:8080/readyz"
        );
        assert_eq!(
            container_healthcheck_url("[::]:9090".parse().unwrap()),
            "http://[::1]:9090/readyz"
        );
    }

    #[test]
    fn sidebar_exposes_root_portaled_release_history_dialog() {
        let html = sidebar("markus", true, "fleet");

        assert!(html.contains(r#"data-sidebar-still="true""#));
        assert!(html.contains(r#"data-sidebar-motion"#));
        assert!(html.contains(r#"data-src="/assets/sidebar-lighthouse-motion-v1.mp4""#));
        assert!(html.contains(r#"muted loop playsinline preload="none""#));
        assert!(html.contains("pharos.sidebar.still.v1"));
        assert!(html.contains("prefers-reduced-motion: reduce"));
        assert!(html.contains("connection?.saveData===true"));
        assert!(html.contains("visibilitychange"));
        assert!(html.contains("video.removeAttribute('src')"));
        assert!(html.contains("error?.name==='AbortError'"));
        let hidden_guard = html
            .find("if(document.hidden)return")
            .expect("hidden guard exists");
        let attach_source = html
            .find("video.setAttribute('src',video.dataset.src)")
            .expect("dynamic source attachment exists");
        assert!(hidden_guard < attach_source);
        assert!(html.contains(r#"class="side-version""#));
        assert!(html.contains(&release_label()));
        assert!(html.contains("Release history"));
        assert!(html.contains("Pharos Changelog"));
        assert!(html.contains("0.1.0 - 2026-07-09"));
        assert!(html.contains("document.body.appendChild(modal)"));
        assert!(html.contains("modal.dataset.releasePortal='body'"));
        assert!(html.contains("event.key==='Escape'"));
        assert!(html.contains("opener.focus()"));
        assert!(HEAD.contains(".release-overlay{position:fixed;inset:0;z-index:6000"));

        let sidebar_end = html.find("</aside>").expect("sidebar closes");
        let dialog_start = html
            .find(r#"<section class="release-overlay""#)
            .expect("release dialog exists");
        assert!(sidebar_end < dialog_start);
    }

    #[test]
    fn changelog_renderer_escapes_operator_text() {
        let html = changelog_html();

        assert!(html.contains("<h3>0.1.0 - 2026-07-09</h3>"));
        assert!(html.contains("<li>Added a visible dashboard version badge"));
        assert!(!html.contains("<script"));
    }

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
            host_need_intent: None,
            existing_host_context: None,
            state,
            terminal_outcome: None,
            created_at,
            updated_at,
            handoff: None,
            setup_intent: Some(setup_intent),
            backup_proposal: None,
            reviewed_plan: None,
            paid_authorization: None,
            paid_execution: None,
            managed_identity: None,
            provider_resources: vec![],
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

    fn test_preflight_check(
        key: &str,
        label: &str,
        state: PreflightCheckState,
        message: &str,
    ) -> ExistingHostPreflightCheck {
        ExistingHostPreflightCheck {
            key: key.to_string(),
            label: label.to_string(),
            state,
            message: message.to_string(),
        }
    }

    fn ready_existing_host_preflight_checks() -> Vec<ExistingHostPreflightCheck> {
        vec![
            test_preflight_check(
                "ssh-reachability",
                "SSH reachability",
                PreflightCheckState::Pass,
                "SSH port is reachable from Pharos.",
            ),
            test_preflight_check(
                "ssh-authentication",
                "SSH authentication",
                PreflightCheckState::Pass,
                "SSH authentication has been verified.",
            ),
            test_preflight_check(
                "privilege",
                "Privilege model",
                PreflightCheckState::Pass,
                "Root access is available for bootstrap.",
            ),
            test_preflight_check(
                "os-family",
                "Operating system",
                PreflightCheckState::Pass,
                "linux is a supported existing-host target.",
            ),
            test_preflight_check(
                "disk-space",
                "Disk headroom",
                PreflightCheckState::Pass,
                "16 GiB free is enough for setup checks.",
            ),
            test_preflight_check(
                "pharos-reachability",
                "Host can reach Pharos",
                PreflightCheckState::Pass,
                "The host can reach the Pharos report endpoint.",
            ),
            test_preflight_check(
                "backup-observation",
                "Backup signal",
                PreflightCheckState::Warn,
                "No existing backup job was detected during read-only preflight.",
            ),
        ]
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
            kernel: None,
            service_observations: vec![],
            backup_observations,
            preferences: Default::default(),
            requested_preferences: None,
        }
    }

    fn reboot_required_kernel(observed_at: i64) -> KernelPosture {
        KernelPosture::observed(
            true,
            Some("6.18.26".to_string()),
            Some("7.0.14".to_string()),
            observed_at,
        )
    }

    fn runtime<'a>(hosts: &'a [Host], jobs: &'a [ProvisioningJob]) -> RuntimeSnapshot<'a> {
        RuntimeSnapshot {
            hosts,
            jobs,
            action_jobs: &[],
            declared_preferences: None,
            janus_managed_hosts: None,
        }
    }

    fn rendered_card<'a>(html: &'a str, host: &str) -> &'a str {
        let host_marker = format!(r#"data-host="{host}""#);
        let host_at = html.find(&host_marker).expect("host card rendered");
        let start = html[..host_at]
            .rfind(r#"<article class="card"#)
            .expect("host card starts");
        let end = html[host_at..]
            .find("</article>")
            .map(|end| host_at + end + "</article>".len())
            .expect("host card closes");
        &html[start..end]
    }

    fn shell(user_label: &str, logout_enabled: bool) -> ShellContext<'_> {
        ShellContext {
            user_label,
            logout_enabled,
        }
    }

    fn test_manifest(name: &str, janus_ready: bool) -> HostManifest {
        serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": name,
            "host": { "name": name },
            "wings": [],
            "services": [],
            "policy": {
                "declaredOnly": true,
                "runtimeStateOwner": "pharos",
                "privilegedActions": {
                    "mode": if janus_ready { "janus" } else { "none" },
                    "janusRequired": janus_ready
                }
            }
        }))
        .expect("test manifest parses")
    }

    #[test]
    fn access_grants_filter_hosts_and_render_safe_empty_state() {
        let hosts = vec![
            host_with_backups("csb1", 1_000, vec![]),
            host_with_backups("hsb8", 1_000, vec![]),
        ];
        let limited = AccessGrant::limited(["hsb8"], false);
        let filtered = filter_hosts_by_access(hosts, &limited);

        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "hsb8");

        let html = render_no_access_page(
            "Fleet",
            "All hosts at a glance",
            shell("new-user", true),
            "fleet",
        );
        assert!(html.contains("No access yet"));
        assert!(html.contains("Your login works"));
        assert!(html.contains(r#"action="/auth/logout" method="post""#));
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
    async fn sidebar_motion_serves_a_small_versioned_mp4() {
        let response = sidebar_lighthouse_motion_asset().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "video/mp4"
        );
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("sidebar motion body");
        assert!(!body.is_empty());
        assert!(body.len() < 500_000);
    }

    #[tokio::test]
    async fn vendored_map_assets_are_versioned_and_same_origin() {
        let leaflet = leaflet_js_asset().await.into_response();
        assert_eq!(leaflet.status(), StatusCode::OK);
        assert_eq!(
            leaflet.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            leaflet.headers().get(header::CACHE_CONTROL).unwrap(),
            "public, max-age=31536000, immutable"
        );
        let leaflet = axum::body::to_bytes(leaflet.into_body(), usize::MAX)
            .await
            .expect("vendored Leaflet body");
        assert!(leaflet.starts_with(b"/* @preserve"));

        let d3 = d3_js_asset().await.into_response();
        let d3 = axum::body::to_bytes(d3.into_body(), usize::MAX)
            .await
            .expect("vendored D3 body");
        assert!(d3.starts_with(b"// https://d3js.org"));

        assert_eq!(
            leaflet_image_asset(AxumPath("not-vendored.png".to_string()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    #[tokio::test]
    async fn rendered_html_receives_nonce_csp_and_browser_security_headers() {
        let response = secure_response(
            Html("<html><head><style>body{color:black}</style></head><body><script>window.ok=true</script></body></html>")
                .into_response(),
        )
        .await;
        let headers = response.headers().clone();
        let csp = headers
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .expect("CSP header");
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|tail| tail.split('\'').next())
            .expect("CSP nonce");

        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("strict-transport-security"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src-attr 'none'"));
        assert!(csp.contains("img-src 'self' data: https://*.basemaps.cartocdn.com"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("secured HTML body");
        let body = std::str::from_utf8(&body).expect("secured HTML is UTF-8");
        assert!(body.contains(&format!(r#"<style nonce="{nonce}">"#)));
        assert!(body.contains(&format!(r#"<script nonce="{nonce}">"#)));
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
                backup_tools: vec!["restic".to_string(), "systemd-timer".to_string()],
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
        assert!(report.checks.iter().any(|check| {
            check.key == "backup-observation"
                && check.state == PreflightCheckState::Pass
                && check.message.contains("restic")
        }));
    }

    #[test]
    fn existing_host_ssh_probe_output_is_sanitized_facts() {
        let facts = parse_existing_host_ssh_probe_stdout(
            b"ssh_authenticated=true\nroot=false\nsudo=true\nos_family=ubuntu\nnixos=false\nnix_available=true\nfree_disk_gib=42\npharos_reachable=true\nbackup_tools=restic,systemd-timer,bad/tool,restic\nignored=value\n",
        );

        assert_eq!(facts.ssh_authenticated, Some(true));
        assert_eq!(facts.root, Some(false));
        assert_eq!(facts.sudo, Some(true));
        assert_eq!(facts.os_family.as_deref(), Some("ubuntu"));
        assert_eq!(facts.nixos, Some(false));
        assert_eq!(facts.nix_available, Some(true));
        assert_eq!(facts.free_disk_gib, Some(42));
        assert_eq!(facts.pharos_reachable, Some(true));
        assert_eq!(facts.backup_tools, vec!["restic", "systemd-timer"]);
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
            backup_tools: vec!["restic".to_string()],
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
            backup_tools: vec!["systemd-timer".to_string()],
        };

        let merged = merge_preflight_facts(base, probe);

        assert_eq!(merged.ssh_authenticated, Some(true));
        assert_eq!(merged.sudo, Some(false));
        assert_eq!(merged.root, Some(false));
        assert_eq!(merged.os_family.as_deref(), Some("linux"));
        assert_eq!(merged.free_disk_gib, Some(12));
        assert_eq!(merged.backup_tools, vec!["restic"]);
    }

    #[test]
    fn shell_single_quote_escapes_embedded_quotes() {
        assert_eq!(
            shell_single_quote("https://pharos.example/a'b"),
            "'https://pharos.example/a'\"'\"'b'"
        );
    }

    #[test]
    fn split_probe_host_port_strips_pasted_ssh_user() {
        assert_eq!(
            split_probe_host_port("root@example.test:2222", 22),
            Some(("example.test".to_string(), 2222))
        );
        assert_eq!(
            split_probe_host_port("ssh://root@example.test:2200", 22),
            Some(("example.test".to_string(), 2200))
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                freshness: proven_freshness(
                    "nixos-unstable",
                    GitRevisionRelation::Behind,
                    Some(3),
                    NixpkgsRevisionRelation::Current,
                ),
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                freshness: proven_freshness(
                    "nixos-unstable",
                    GitRevisionRelation::Behind,
                    Some(3),
                    NixpkgsRevisionRelation::Current,
                ),
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
        assert!(html.contains(r#"action="/auth/logout" method="post""#));
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
        assert!(html.contains(r#"<col class="heartbeat-col">"#));
        assert!(html.contains(r#"<th scope="col">Attention</th>"#));
        assert!(html.contains(r#"<th scope="col">Actions</th>"#));
        assert!(!html.contains("status-pill"));
        assert!(!html.contains(r#"<th scope="col">Backup</th>"#));
        assert!(html.contains(r#"class="list-heartbeat""#));
        assert!(html.contains(r#"data-seen data-seen-compact"#));
        assert!(html.contains(r#"class="list-actions""#));
        assert!(html.contains("seen.hasAttribute('data-seen-compact')"));
        assert!(html.contains(r#"href="/hosts/poseidon""#));
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
        assert!(
            html.contains(r#"<div class="availability-head"><span class="signal availability""#)
        );
        assert!(html.contains(
            r#"<button class="beat-window" type="button" data-signal-window data-history-window-label"#
        ));
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
        assert!(html.contains("nixpkgs lock (nixos-unstable)"));
        assert!(html.contains(r#"data-fresh-kind="nixcfg-drift" tabindex="0""#));
        assert!(html.contains(r#"<strong class="warn" data-fresh-value>3 commits behind</strong>"#));
        assert!(html.contains(r#"data-deployed-revision=""#));
        assert!(html.contains(r#"data-nixcfg-revision=""#));
        assert!(html.contains(r#"data-nixpkgs-revision=""#));
        assert!(html.contains(r#"data-seen data-seen-card>Seen 30s ago</span>"#));
        assert!(html.contains(r#"data-card-asof data-card-asof-compact>00:16</span>"#));
        assert!(html.contains("beat-fill"));
        assert!(html.contains("beat-now"));
        assert!(html.contains("beat-current"));
        assert!(html.contains(r#"--history-start-x:29.3%"#));
        assert!(html.contains("beat-zones"));
        assert!(HEAD.contains("left:max(0px,calc(var(--pulse-left) - 4px))"));
        assert!(HEAD.contains("left:clamp(4px,var(--mark-x),calc(100% - 4px))"));
        assert!(HEAD.contains("top:21px;z-index:6;height:4px"));
        assert!(HEAD.contains(
            "@keyframes tide{from{background-position:100% 0}to{background-position:0 0}}"
        ));
        assert!(html.contains("3 commits behind nixcfg"));
        assert!(html.contains("3 commits"));
        assert!(html.contains("data-search=\"poseidon nixos host 3 commits behind nixcfg"));
        assert!(html.contains(r#"data-host="poseidon" data-live="live" data-sev="3""#));
        assert!(html.contains(r#"data-host="hades" data-live="stale""#));
        assert!(html.contains(r#"data-sev="1""#));
        assert!(!html.contains(r#"<th scope="col">Status</th>"#));
    }

    #[test]
    fn fleet_foreground_recovery_is_atomic_and_failure_visible() {
        let hosts = vec![host_with_backups("alpha", 970, vec![])];
        let html = render_home(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );

        assert!(html.contains(
            r#"<main data-view="grid" data-fleet-sync-state="current" data-fleet-snapshot-at="1000">"#
        ));
        for state in ["all", "live", "stale", "down"] {
            assert!(html.contains(&format!(r#"data-summary-count="{state}""#)));
        }
        assert!(html.contains("function updateFleetSummary(hosts)"));
        assert!(html.contains("updateFleetSummary(hosts);"));
        assert!(html.contains("Data out of date \\u00b7 "));
        assert!(html.contains("res.redirected||!contentType.includes('application/json')"));
        assert!(html.contains("window.addEventListener('blur',suspendFleet)"));
        assert!(html.contains(
            "if(!fleetMain()||document.hidden||(typeof document.hasFocus==='function'&&!document.hasFocus()))return;"
        ));
        assert!(html.contains("if(options.force===true&&refreshPromise)abandonRefresh();"));
        assert!(html.contains("if(generation!==refreshGeneration)return false;"));
        assert!(html.contains("if(!fleetMembershipMatches(hosts))"));
        assert!(html.contains("window.location.reload();"));
        assert!(!html.contains("HIDDEN_REFRESH_MS"));

        let recovery = html
            .find("function recoverFleet(reason='foreground')")
            .expect("foreground recovery exists");
        let recovery = &html[recovery..];
        let stop = recovery.find("stopBeatClock();").expect("clock stops");
        let syncing = recovery
            .find("setFleetSyncState('syncing');")
            .expect("syncing state is visible");
        let request = recovery
            .find("refresh(reason,{force:true,recovery:true})")
            .expect("authoritative recovery refresh exists");
        assert!(stop < syncing && syncing < request);

        let refresh = html
            .find("async function refresh(reason='manual',options={})")
            .expect("refresh exists");
        let refresh = &html[refresh..];
        let apply = refresh
            .find("if(!applyFleetSnapshot(data))return false;")
            .expect("snapshot applies");
        let current = refresh
            .find("setFleetSyncState('current');")
            .expect("current state follows apply");
        let resume = refresh
            .find("resumeBeatClock();")
            .expect("clock resumes after apply");
        assert!(apply < current && current < resume);
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
            preferences: Default::default(),
            requested_preferences: None,
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
        assert_eq!(
            html.matches(r#"data-backup-state="healthy" data-backup-level="clear""#)
                .count(),
            2
        );
        assert!(html.contains(
            r#"aria-label="Backup for athena: Protected, last success 2m 00s ago" hidden>"#
        ));
        assert!(html.contains(r#"href="/backups?host=athena""#));
        assert!(html.contains(r#"data-backup-level="clear" data-backup-glyph="check""#));
        assert!(
            html.contains(r#"aria-label="Backup for athena: Protected, last success 2m 00s ago""#)
        );
        assert!(!html.contains(r#"class="backup-mini backup-list clear""#));
        assert!(
            html.contains(r#"<div class="list-actions"><a class="header-chip backup-chip clear""#)
        );
        assert!(html.contains("off-box repository"));
        assert!(!html.contains("restic-main-repository"));
    }

    #[test]
    fn backup_chip_maps_posture_to_distinct_glyphs() {
        let cases = [
            (BackupPostureState::Healthy, "clear", "check"),
            (BackupPostureState::Unknown, "watch", "question"),
            (BackupPostureState::Stale, "warning", "alert"),
            (BackupPostureState::Failed, "critical", "x"),
        ];

        for (state, level, glyph) in cases {
            let summary = backup_ui_summary(&[backup_observation(state)], 1_700_000_120);
            let html = backup_chip_markup(&summary, "athena");
            assert!(html.contains(&format!(r#"class="header-chip backup-chip {level}""#)));
            assert!(html.contains(&format!(r#"data-backup-glyph="{glyph}""#)));
            assert!(html.contains(r#"href="/backups?host=athena""#));
            assert!(html.contains(
                r#"<span class="header-chip-label" aria-hidden="true">Backup</span></a>"#
            ));
        }
        let healthy_html = backup_chip_markup(
            &backup_ui_summary(
                &[backup_observation(BackupPostureState::Healthy)],
                1_700_000_120,
            ),
            "athena",
        );
        assert!(healthy_html.contains(r#"data-backup-state="healthy""#));
        assert!(healthy_html.contains(" hidden>"));
        let failed_html = backup_chip_markup(
            &backup_ui_summary(
                &[backup_observation(BackupPostureState::Failed)],
                1_700_000_120,
            ),
            "athena",
        );
        assert!(!failed_html.contains(" hidden>"));
    }

    #[test]
    fn fleet_header_chips_expand_while_fault_rail_uses_full_width() {
        assert!(HEAD.contains(".header-chip{position:relative;appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:0;width:25px;height:25px"));
        assert!(HEAD.contains(".header-chip:hover,.header-chip:focus-visible{width:86px"));
        assert!(HEAD.contains(".header-chip-label{display:block;max-width:0;opacity:0"));
        assert!(HEAD.contains(".header-chip:hover .header-chip-label,.header-chip:focus-visible .header-chip-label{max-width:58px;opacity:1"));
        assert!(HEAD.contains(".backup-chip[hidden]{display:none}"));
        assert!(!HEAD.contains(
            ".card .backup-chip:not(:hover):not(:focus-visible){border-color:transparent;background:transparent;box-shadow:none}"
        ));
        assert!(HEAD.contains(
            ".host-actions-trigger{color:#4c6780;border-color:rgba(188,211,222,.92);background:rgba(255,255,255,.88)"
        ));
        assert!(HEAD.contains(
            ".card .fresh{position:relative;display:flex;align-items:center;width:100%;min-width:0"
        ));
        assert!(HEAD.contains("flex:0 0 auto;width:max-content"));
        assert!(HEAD.contains(".card .fresh-row-label{display:none}"));
        assert!(HEAD.contains(".card .fresh-row-label,.card .fresh-row strong{transition:none}"));
        assert!(FOOT
            .contains("matchMedia?.('(prefers-reduced-motion: reduce)').matches?'auto':'smooth'"));
    }

    #[test]
    fn fleet_card_header_actions_visible_backup_omitted_when_healthy() {
        let healthy = {
            let mut host = host_with_backups("healthy-header", 970, vec![]);
            host.backup_observations = vec![backup_observation(BackupPostureState::Healthy)];
            host
        };
        let failed = {
            let mut host = host_with_backups("failed-header", 970, vec![]);
            host.backup_observations = vec![backup_observation(BackupPostureState::Failed)];
            host.requested_preferences = Some(HostPreferences {
                accent: Some("#48b8a8".to_string()),
                ..Default::default()
            });
            host
        };
        let html = render_home_with_capabilities(
            runtime(&[healthy, failed], &[]),
            "csb1",
            1_700_000_120,
            &[],
            shell("markus", true),
            FleetCapabilities {
                can_onboard: true,
                can_manage_fleet: true,
                system_update_available: true,
                host_removal_available: true,
            },
        );

        assert_eq!(
            html.matches(r#"class="header-chip host-actions-trigger""#)
                .count(),
            4
        );
        assert_eq!(
            html.matches(r#"class="header-chip backup-chip clear""#)
                .count(),
            2
        );
        assert_eq!(
            html.matches(r#"class="header-chip backup-chip critical""#)
                .count(),
            2
        );
        assert!(html.contains(
            r#"aria-label="Backup for healthy-header: Protected, last success 2m 00s ago" hidden>"#
        ));
        let failed_card = rendered_card(&html, "failed-header");
        let failed_chip = failed_card
            .split_once(r#"class="header-chip backup-chip critical""#)
            .map(|(_, tail)| tail.split_once('>').map_or(tail, |(tag, _)| tag))
            .expect("failed backup chip rendered");
        assert!(!failed_chip.contains(" hidden"));
        assert_eq!(
            html.matches(
                r#"class="host-action-dot" data-host-action-dot aria-hidden="true"></span>"#
            )
            .count(),
            2
        );
    }

    #[test]
    fn fleet_host_actions_share_contextual_grid_and_list_markup() {
        let mut host = host_with_backups("hsb8", 1_700_000_100, vec![]);
        host.kernel = Some(reboot_required_kernel(1_700_000_100));
        host.requested_preferences = Some(HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        });
        let manifests = vec![test_manifest("hsb8", true)];
        let html = render_home_with_capabilities(
            runtime(&[host], &[]),
            "csb1",
            1_700_000_120,
            &manifests,
            shell("markus", true),
            FleetCapabilities {
                can_onboard: true,
                can_manage_fleet: true,
                system_update_available: true,
                host_removal_available: true,
            },
        );

        assert_eq!(
            html.matches(r#"class="header-chip host-actions-trigger""#)
                .count(),
            2
        );
        assert!(html.contains(r#"id="host-actions-hsb8-card" role="menu""#));
        assert!(html.contains(r#"id="host-actions-hsb8-row" role="menu""#));
        assert_eq!(
            html.matches(r#"data-host-action="host-settings" data-settings-state="#)
                .count(),
            1
        );
        assert!(!html.contains(r#"data-host-action="review-pending""#));
        assert_eq!(
            html.matches(
                r#"<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="system-update""#
            )
            .count(),
            2
        );
        assert_eq!(
            html.matches(
                r#"<button class="host-action-item restart" type="button" role="menuitem" tabindex="-1" data-host-action="update-restart""#
            )
            .count(),
            2
        );
        assert_eq!(
            html.matches(
                r#"<button class="host-action-item remove" type="button" role="menuitem" tabindex="-1" data-host-action="remove""#
            )
            .count(),
            2
        );
        assert_eq!(
            html.matches(r#"<section class="host-action-overlay""#)
                .count(),
            1
        );
        assert!(html.contains("Privileged changes always open a review first"));
        assert!(html.contains("function initHostActions()"));
        assert!(html.contains("event.key==='ArrowDown'"));
        assert!(html.contains("event.key==='Escape'"));
        assert!(html.contains("X-Pharos-Action"));
        assert!(html.contains("workflow.primary_action"));
        assert!(html.contains(
            "'/host-actions/jobs/'+encodeURIComponent(hostActionContext.jobId)+'/recover'"
        ));
        assert!(html.contains("new AbortController()"));
        assert!(html.contains("if(!response.ok&&!payload.job)"));
        assert!(html.contains("document.addEventListener('visibilitychange'"));
        assert!(html.contains(
            "const savedRunLoading=!!lifecycleRunId&&(action==='workflow'||action==='update-restart')"
        ));
        assert!(html.contains("hostActionContext.jobId=lifecycleRunId"));
        assert!(html.contains("hostActionContext.stage='loading'"));
        assert!(html.contains("if(primary){primary.hidden=true;primary.disabled=true}"));
        assert!(html.contains("if(savedRunLoading)pollHostActionJob(lifecycleRunId,true)"));
        assert!(html.contains("if(hostActionContext.stage==='loading')return"));
        assert!(!html.contains("const storedMatches=action==='workflow'"));
        assert!(html.contains("chip.dataset.lifecycleInvoke"));
        assert!(html.contains("chip.dataset.lifecycleRunId"));
        assert!(html.contains(r#"data-host-remove-disposition"#));
        assert!(html.contains("It no longer exists"));
        assert!(html.contains("It still exists; stop managing it"));
        assert!(html.contains("It was replaced by another host"));
        assert!(html.contains(r#"data-host-remove-successor-input"#));
        assert!(html.contains("Onboard the successor in Pharos first"));
        assert!(html.contains(
            "'/host-actions/jobs/'+encodeURIComponent(hostActionContext.jobId)+'/retry'"
        ));
        assert!(html.contains(
            "'/host-actions/jobs/'+encodeURIComponent(hostActionContext.jobId)+'/cancel'"
        ));
        assert!(html.contains("'/host-actions/jobs/'+encodeURIComponent(runId)+'/withdraw'"));
        assert!(html.contains(
            "openHostActionDialog('workflow',root,root.querySelector('[data-host-actions-trigger]'));"
        ));
        assert!(!html.contains("openHostActionDialog('workflow',root,actionItem,runId)"));
        assert!(html.contains("Withdraw change request"));
        assert!(
            html.contains("Clears the pending request. An open nixcfg proposal stays open there.")
        );
        assert!(html.contains(r#"data-host-action-cancel hidden"#));
        assert!(html.contains(
            r#"data-host-action-primary>Continue</button><button class="host-action-dialog-button" type="button" data-host-action-cancel hidden>Cancel run</button><button class="host-action-dialog-button" type="button" data-host-action-close>Close</button>"#
        ));
        assert!(html.contains("openRequestedWorkflow()"));
        assert!(html.contains(
            "openHostActionDialog('workflow',root,root.querySelector('[data-host-actions-trigger]'),workflowId)"
        ));
    }

    #[test]
    fn host_action_dialog_uses_one_suspendable_poll_lifecycle() {
        assert!(FOOT.contains("function pauseHostActionPoll()"));
        assert!(FOOT.contains("function stopHostActionPoll()"));
        assert!(FOOT.contains("if(hostActionPoll.terminal)return;"));
        assert!(FOOT.contains("hostActionPoll.terminal=!active;"));
        assert!(FOOT.contains("Watching for recorded host evidence"));
        assert!(FOOT.contains("function scheduleHostActionPoll(id,delay=2000)"));
        assert!(FOOT.contains("hostActionPoll.timer=null;\n    pollHostActionJob(id,false);"));
        assert!(FOOT.contains("if(document.hidden){pauseHostActionPoll();return}"));
        assert!(FOOT.contains(
            "window.addEventListener('focus',()=>{\n    if(hostActionContext?.jobId)scheduleHostActionPoll(hostActionContext.jobId,0);"
        ));
        assert!(
            FOOT.contains("window.addEventListener('offline',()=>{\n    pauseHostActionPoll();")
        );
        assert!(FOOT.contains("window.addEventListener('pagehide',stopHostActionPoll)"));
        assert!(FOOT.contains("stopHostActionPoll();\n  closeHostActions(root);"));
        assert!(FOOT.contains("stopHostActionPoll();\n  if(overlay.hidden)return;"));
        assert!(!FOOT.contains("setInterval("));
        assert!(HEAD.contains("animation-duration:3.2s;animation-timing-function:steps(4,end)"));
        assert!(HEAD.contains(r#"data-waiting-for-evidence="true""#));
        assert!(HEAD.contains(r#"data-workflow-live="true""#));
    }

    #[test]
    fn workflow_markup_shows_safe_run_metadata_and_excludes_sensitive_evidence() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 1_700_000_100)
            .expect("workflow created");
        store
            .claim("hsb8", 1_700_000_101)
            .expect("workflow claim")
            .expect("review lease");
        let running_html = host_workflow_markup(
            &store
                .get(&job.id)
                .expect("running workflow")
                .summary()
                .workflow,
        );
        assert!(running_html.contains(
            r#"data-step-state="running" data-current="true" data-waiting-for-evidence="false" aria-busy="true""#
        ));
        assert!(running_html.contains(r#"aria-current="step""#));
        assert!(running_html.contains("<small>on hsb8</small>"));
        assert!(running_html.contains(r#"role="listitem""#));
        assert!(running_html.contains(
            r#"aria-label="Run truth: observed, declared, requested, executed, verified""#
        ));
        for label in ["Observed", "Declared", "Requested", "Executed", "Verified"] {
            assert!(running_html.contains(&format!("<strong>{label}</strong>")));
        }
        assert!(running_html.contains(r#"class="host-workflow-next""#));
        assert!(running_html.contains("<dt>Where</dt>"));
        assert!(running_html.contains("<dt>Will not</dt>"));
        assert_eq!(running_html.matches(r#"aria-busy="true""#).count(), 1);
        assert!(HEAD.contains("@keyframes host-workflow-spin"));
        assert!(HEAD.contains(
            ".host-workflow-step[data-waiting-for-evidence=\"true\"] .host-workflow-marker:before"
        ));
        let reviewed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: host_actions::AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(host_actions::HostActionPlan {
                        changed_file_count: 3,
                        changed_areas: vec!["automation".to_string(), "nixcfg".to_string()],
                        all_host_eval_passed: true,
                        target_build_passed: true,
                        backup_ready: true,
                        running_kernel: Some("7.0.13".to_string()),
                        expected_kernel: Some("7.0.14".to_string()),
                        restart_required: true,
                    }),
                    result: None,
                },
                1_700_000_102,
            )
            .expect("review evidence recorded");
        let html = host_workflow_markup(&reviewed.summary().workflow);

        assert!(html.contains("Sanitized plan evidence and workflow history"));
        assert!(html.contains("Changed files"));
        assert!(html.contains("automation, nixcfg"));
        assert!(html.contains("7.0.13"));
        assert!(html.contains("7.0.14"));
        assert!(html.contains("command output are excluded"));
        assert!(html.contains("This run is saved and resumes after refresh or restart"));
        assert!(html.contains("Run ID"));
        assert!(html.contains(&job.id));
        assert!(html.contains("Recorded span"));
        assert!(!html.contains("/nix/store/"));
    }

    #[test]
    fn settings_workflow_markup_marks_only_the_evidence_wait_as_live() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_settings_change("hsb8", "markus", 1_700_000_200)
            .expect("settings workflow created");
        store
            .mark_dispatch_submitted(&job.id, 1_700_000_201)
            .expect("repository handoff recorded");
        let waiting = store
            .accept_settings_change(&job.id, 1_700_000_202)
            .expect("settings request accepted");
        let waiting_html = host_workflow_markup(&waiting.summary().workflow);
        assert!(waiting_html.contains(
            r#"data-step-state="waiting" data-current="true" data-waiting-for-evidence="true" aria-busy="true""#
        ));
        assert!(!waiting_html.contains("data-host-action-refresh"));
        assert!(waiting_html.contains(r#"data-ladder-key="verified" data-ladder-state="pending""#));

        let completed = store
            .complete_settings_change("hsb8", 1_700_000_203)
            .expect("settings completion persisted")
            .expect("settings workflow completed");
        let completed_html = host_workflow_markup(&completed.summary().workflow);
        assert!(!completed_html.contains(r#"data-waiting-for-evidence="true""#));
        assert!(!completed_html.contains("data-host-action-refresh"));
        assert!(
            completed_html.contains(r#"data-ladder-key="verified" data-ladder-state="complete""#)
        );
    }

    #[test]
    fn fleet_host_actions_fail_closed_without_fleet_or_janus_capability() {
        let mut host = host_with_backups("hsb8", 1_700_000_100, vec![]);
        host.kernel = Some(reboot_required_kernel(1_700_000_100));
        let manifest = test_manifest("hsb8", false);
        let backup = backup_ui_summary(&host.backup_observations, 1_700_000_120);
        let markup = host_actions_markup(
            &host,
            HostActionRenderContext {
                manifest: Some(&manifest),
                declared: true,
                credential_retirement_required: false,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: false,
                    system_update_available: true,
                    host_removal_available: true,
                },
                action_jobs: &[],
            },
            None,
            &host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, true),
        );

        assert!(markup.contains(r#"data-can-manage="false""#));
        assert!(markup.contains(r#"data-host-action="system-update" hidden"#));
        assert!(markup.contains(r#"data-host-action="update-restart" hidden"#));
        assert!(markup.contains(r#"data-host-action="remove" hidden"#));
        assert!(markup.contains(r#"data-host-action="technical""#));

        let runtime_only_markup = host_actions_markup(
            &host,
            HostActionRenderContext {
                manifest: None,
                declared: false,
                credential_retirement_required: false,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: false,
                    host_removal_available: false,
                },
                action_jobs: &[],
            },
            None,
            &host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, true),
        );
        assert!(runtime_only_markup.contains(r#"data-host-action="remove"><svg"#));
        assert!(runtime_only_markup.contains(r#"data-declared="false""#));
        assert!(runtime_only_markup.contains(r#"data-credential-retirement="false""#));

        // PHAROS-194: an undeclared host can still be Janus-managed, and the
        // removal dialog needs that fact before the operator confirms.
        let janus_managed_markup = host_actions_markup(
            &host,
            HostActionRenderContext {
                manifest: None,
                declared: false,
                credential_retirement_required: true,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: false,
                    host_removal_available: false,
                },
                action_jobs: &[],
            },
            None,
            &host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, true),
        );
        assert!(janus_managed_markup.contains(r#"data-declared="false""#));
        assert!(janus_managed_markup.contains(r#"data-credential-retirement="true""#));
        // PHAROS-197: this removal must record a retirement intent through the
        // nixcfg proposal, so without that dispatch it is not offered at all
        // rather than offered and then refused.
        assert!(janus_managed_markup.contains(r#"data-host-action="remove" hidden"#));

        let janus_managed_ready = host_actions_markup(
            &host,
            HostActionRenderContext {
                manifest: None,
                declared: false,
                credential_retirement_required: true,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: false,
                    host_removal_available: true,
                },
                action_jobs: &[],
            },
            None,
            &host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, true),
        );
        assert!(janus_managed_ready.contains(r#"data-host-action="remove"><svg"#));

        let mut pending_update = host_with_backups("hsb8", 1_700_000_100, vec![]);
        pending_update.freshness = proven_freshness(
            "nixos-unstable",
            GitRevisionRelation::Behind,
            Some(2),
            NixpkgsRevisionRelation::Current,
        );
        pending_update.kernel = Some(KernelPosture::observed(
            true,
            Some("7.0.14".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_100,
        ));
        let ready_manifest = test_manifest("hsb8", true);
        let pending_markup = host_actions_markup(
            &pending_update,
            HostActionRenderContext {
                manifest: Some(&ready_manifest),
                declared: true,
                credential_retirement_required: false,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: true,
                    host_removal_available: true,
                },
                action_jobs: &[],
            },
            None,
            &host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, false),
        );
        assert!(pending_markup.contains(r#"data-update-pending="true""#));
        assert!(pending_markup.contains(r#"data-host-action="update-restart"><svg"#));

        let store = HostActionStore::new(None);
        let update_job = store
            .create_update_review("hsb8", "markus", 1_700_000_110)
            .expect("active update restart");
        let action_jobs = store.list();
        let active_markup = host_actions_markup(
            &pending_update,
            HostActionRenderContext {
                manifest: Some(&ready_manifest),
                declared: true,
                credential_retirement_required: false,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: true,
                    host_removal_available: true,
                },
                action_jobs: &action_jobs,
            },
            Some(&update_job),
            &host_lifecycle(&action_jobs, "hsb8", HostPreferencesState::Applied, false),
        );
        assert!(active_markup.contains(r#"data-host-action="update-restart" hidden"#));
        assert!(active_markup.contains(r#"data-update-restart-active="true""#));
        assert!(!active_markup.contains("Continue update workflow"));
        assert!(!FOOT.contains("Continue update workflow"));
    }

    #[test]
    fn fleet_host_actions_keep_independent_controls_when_removal_masks_host_action() {
        let mut pending_update = host_with_backups("hsb8", 1_700_000_100, vec![]);
        pending_update.freshness = proven_freshness(
            "nixos-unstable",
            GitRevisionRelation::Behind,
            Some(2),
            NixpkgsRevisionRelation::Current,
        );
        pending_update.kernel = Some(KernelPosture::observed(
            true,
            Some("7.0.14".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_100,
        ));
        let ready_manifest = test_manifest("hsb8", true);
        let backup = backup_ui_summary(&pending_update.backup_observations, 1_700_000_120);
        let store = HostActionStore::new(None);
        let update_job = store
            .create_update_review("hsb8", "markus", 1_700_000_110)
            .expect("active update restart");
        let settings_job = store
            .begin_settings_change("hsb8", "markus", 1_700_000_115)
            .expect("active settings change");
        let removal_job = store
            .begin_removal(
                "hsb8",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Unmanaged,
                    successor: None,
                    declaration_pending: false,
                    credential_retirement_required: false,
                },
                1_700_000_120,
            )
            .expect("active removal");
        let action_jobs = store.list();
        let masked_action = most_relevant_host_action(&action_jobs, "hsb8").expect("removal wins");
        assert_eq!(masked_action.id, removal_job.id);
        assert_ne!(masked_action.id, update_job.id);
        let lifecycle = host_lifecycle(&action_jobs, "hsb8", HostPreferencesState::Applied, false);
        assert_eq!(lifecycle.slot, HostLifecycleSlot::RemoveHost);
        assert_eq!(lifecycle.run_id.as_deref(), Some(removal_job.id.as_str()));
        assert!(active_update_restart_for_host(&action_jobs, "hsb8").is_some());

        let markup = host_actions_markup(
            &pending_update,
            HostActionRenderContext {
                manifest: Some(&ready_manifest),
                declared: true,
                credential_retirement_required: false,
                settings_state: HostPreferencesState::Applied,
                settings_href: "/agora?host=hsb8",
                backup: &backup,
                surface: "card",
                capabilities: FleetCapabilities {
                    can_onboard: true,
                    can_manage_fleet: true,
                    system_update_available: true,
                    host_removal_available: true,
                },
                action_jobs: &action_jobs,
            },
            Some(masked_action),
            &lifecycle,
        );
        assert!(markup.contains(r#"data-update-restart-active="true""#));
        assert!(markup.contains(r#"data-host-action="update-restart" hidden"#));
        assert!(markup.contains(&format!(r#"data-lifecycle-run-id="{}""#, settings_job.id)));
        assert!(markup.contains("Withdraw change request"));
        assert!(!markup.contains("Continue update workflow"));

        let payload = hosts_payload(
            vec![pending_update],
            &[ready_manifest],
            &BTreeMap::new(),
            &action_jobs,
            None,
            1_700_000_130,
        );
        let emitted = payload["hosts"][0].as_object().expect("host object");
        assert_eq!(emitted["update_restart_active"], true);
        assert_eq!(emitted["settings_change_withdraw_run_id"], settings_job.id);
        assert_eq!(emitted["lifecycle"]["slot"], "remove_host");
        assert_eq!(emitted["host_action"]["workflow"]["kind"], "remove_host");
        assert_eq!(emitted["lifecycle"]["run_id"], removal_job.id);
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
            preferences: Default::default(),
            requested_preferences: None,
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
        assert!(html.contains(
            r#"class="backup-row clear" data-ops-row data-ops-level="clear" data-host="athena""#
        ));
        assert!(html.contains("new URLSearchParams(window.location.search).get('host')"));
        assert!(html.contains("target.scrollIntoView({block:'center',behavior:'smooth'})"));
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![backup_observation(BackupPostureState::Healthy)],
            preferences: Default::default(),
            requested_preferences: None,
        };

        let payload = hosts_payload(vec![host], &[], &BTreeMap::new(), &[], None, 1000);

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
    fn hosts_json_payload_emits_one_complete_lifecycle_for_every_host() {
        let quiet = host_with_backups("quiet", 970, vec![]);
        let ready = host_with_backups("ready", 970, vec![]);
        let mut failed = host_with_backups("failed-settings", 970, vec![]);
        failed.requested_preferences = Some(HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        });
        let mut kernel = host_with_backups("kernel-drift", 970, vec![]);
        kernel.kernel = Some(reboot_required_kernel(965));

        let actions = HostActionStore::new(None);
        let settings_run = actions
            .begin_settings_change("failed-settings", "markus", 900)
            .expect("settings run created");
        actions
            .fail_settings_change(&settings_run.id, 901)
            .expect("settings run failed");
        let action_jobs = actions.list();
        let declarations = BTreeMap::from([(
            "ready".to_string(),
            HostPreferences {
                accent: Some("#9868d0".to_string()),
                ..Default::default()
            },
        )]);

        let payload = hosts_payload(
            vec![quiet, ready, failed, kernel],
            &[],
            &declarations,
            &action_jobs,
            None,
            1000,
        );
        let hosts = payload["hosts"].as_array().expect("hosts array");
        assert_eq!(hosts.len(), 4);
        for host in hosts {
            let lifecycle = host
                .get("lifecycle")
                .and_then(serde_json::Value::as_object)
                .expect("every host has a lifecycle object");
            for field in [
                "slot",
                "label",
                "level",
                "invoke",
                "run_id",
                "detail",
                "blocked_by",
            ] {
                assert!(
                    lifecycle.contains_key(field),
                    "{} lifecycle misses {field}",
                    host["name"]
                );
            }
        }

        let by_name = |name: &str| {
            hosts
                .iter()
                .find(|host| host["name"] == name)
                .expect("named host")
        };
        assert_eq!(by_name("quiet")["lifecycle"]["slot"], "quiet");
        assert_eq!(by_name("ready")["lifecycle"]["label"], "Ready to apply");
        assert_eq!(by_name("kernel-drift")["lifecycle"]["slot"], "kernel_drift");
        let failed = by_name("failed-settings");
        assert_eq!(failed["lifecycle"]["slot"], "settings_change");
        assert_eq!(failed["lifecycle"]["run_id"], settings_run.id);
        assert_ne!(failed["lifecycle"]["label"], "Change requested");
        assert!(failed["lifecycle"]["primary_action"].is_null());
        assert_eq!(failed["host_action"]["workflow"]["kind"], "settings_change");
    }

    #[test]
    fn hosts_payload_lifecycle_run_id_differs_from_legacy_host_action() {
        let store = HostActionStore::new(None);
        let mut cancelled_settings = store
            .begin_settings_change("diverge-host", "markus", 100)
            .expect("settings workflow created");
        cancelled_settings.state = HostActionState::Cancelled;
        cancelled_settings.updated_at = 101;
        let proposal = store
            .begin_system_update_proposal("diverge-host", "markus", 200, None)
            .expect("system update proposal created")
            .job()
            .clone();
        let action_jobs = vec![cancelled_settings, proposal];
        let host = host_with_backups("diverge-host", 970, vec![]);
        let payload = hosts_payload(vec![host], &[], &BTreeMap::new(), &action_jobs, None, 1000);
        let emitted = payload["hosts"][0].as_object().expect("host object");
        let lifecycle = emitted["lifecycle"].as_object().expect("lifecycle object");
        let host_action = emitted["host_action"]
            .as_object()
            .expect("host_action object");
        assert_eq!(lifecycle["slot"], "settings_change");
        assert_eq!(lifecycle["run_id"], action_jobs[0].id);
        assert_eq!(host_action["id"], action_jobs[1].id);
        assert_ne!(lifecycle["run_id"], host_action["id"]);
    }

    #[test]
    fn fleet_render_hides_kernel_drift_when_update_restart_wins_lifecycle() {
        let store = HostActionStore::new(None);
        let settings = store
            .begin_settings_change("hsb8", "markus", 100)
            .expect("settings workflow created");
        store
            .fail_settings_change(&settings.id, 101)
            .expect("settings workflow failed");
        store
            .create_update_review("hsb8", "markus", 200)
            .expect("update restart review created");
        let mut host = host_with_backups("hsb8", 970, vec![]);
        host.kernel = Some(reboot_required_kernel(965));
        let action_jobs = store.list();
        let html = render_home(
            RuntimeSnapshot {
                hosts: std::slice::from_ref(&host),
                jobs: &[],
                action_jobs: &action_jobs,
                declared_preferences: None,
                janus_managed_hosts: None,
            },
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(html.contains("review queued"));
        assert!(html.contains(r#"data-lifecycle-invoke="update_restart""#));
        assert!(!html.contains(r#"<div class="kernel-slot" data-kernel-slot"#));
    }

    #[test]
    fn hosts_payload_and_fleet_expose_only_actionable_kernel_posture() {
        let mut staged = host_with_backups("csb0", 970, vec![]);
        staged.kernel = Some(reboot_required_kernel(965));

        let payload = hosts_payload(vec![staged.clone()], &[], &BTreeMap::new(), &[], None, 1000);
        assert_eq!(payload["hosts"][0]["kernel"]["state"], "reboot_required");
        assert_eq!(payload["hosts"][0]["kernel"]["running_version"], "6.18.26");
        assert_eq!(payload["hosts"][0]["kernel"]["expected_version"], "7.0.14");
        assert_eq!(payload["hosts"][0]["attention"]["label"], "restart needed");
        assert_eq!(payload["hosts"][0]["attention"]["rank"], 2);

        let html = render_home(
            runtime(&[staged], &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(html.contains(r#"data-host-lifecycle-chip"#));
        assert!(html.contains(r#"data-lifecycle-slot="kernel_drift""#));
        assert!(html.contains(r#"<span data-host-lifecycle-chip-copy>Restart required</span>"#));
        assert!(!html.contains("Continue: planned restart"));
        assert!(html.contains("restart required restart needed kernel reboot required"));

        let mut current = host_with_backups("hsb0", 970, vec![]);
        current.kernel = Some(KernelPosture::observed(
            true,
            Some("7.0.14".to_string()),
            Some("7.0.14".to_string()),
            965,
        ));
        let current_html = render_home(
            runtime(&[current], &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(current_html.contains(r#"data-host-lifecycle-chip-copy>Up to date</span>"#));
        assert!(!current_html.contains(r#"<div class="kernel-slot" data-kernel-slot"#));
    }

    #[test]
    fn pending_kernel_restart_is_one_warning_and_one_activity_event() {
        let mut host = host_with_backups("csb0", 970, vec![]);
        host.kernel = Some(reboot_required_kernel(965));
        let hosts = [host];
        let probes = BTreeMap::new();

        let alerts = alert_items(&hosts, &[], "csb1", 1000, &[], &[], &probes);
        let kernel_alerts = alerts
            .iter()
            .filter(|alert| alert.source == "kernel")
            .collect::<Vec<_>>();
        assert_eq!(kernel_alerts.len(), 1);
        assert_eq!(kernel_alerts[0].level, "warning");
        assert_eq!(kernel_alerts[0].issue, "Restart needed");
        assert!(!alerts.iter().any(|alert| {
            alert.host == "csb0" && alert.source == "heartbeat" && alert.level == "critical"
        }));

        let events = activity_events(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &probes,
                action_jobs: &[],
            },
        );
        let kernel_events = events
            .iter()
            .filter(|event| event.source == "kernel")
            .collect::<Vec<_>>();
        assert_eq!(kernel_events.len(), 1);
        assert_eq!(kernel_events[0].level, "warning");
        assert_eq!(kernel_events[0].title, "Restart needed");
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![failed_backup],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![stale_validation],
                preferences: Default::default(),
                requested_preferences: None,
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
                freshness: proven_freshness(
                    "nixos-unstable",
                    GitRevisionRelation::Behind,
                    Some(3),
                    NixpkgsRevisionRelation::Current,
                ),
                kernel: None,
                service_observations: vec![
                    ServiceObservation::nix_freshness(&proven_freshness(
                        "nixos-unstable",
                        GitRevisionRelation::Behind,
                        Some(3),
                        NixpkgsRevisionRelation::Current,
                    )),
                    ServiceObservation {
                        id: "nginx".to_string(),
                        label: "nginx".to_string(),
                        state: ServiceObservationState::Warning,
                        summary: "response is slow".to_string(),
                    },
                ],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                freshness: proven_freshness(
                    "nixos-unstable",
                    GitRevisionRelation::Behind,
                    Some(3),
                    NixpkgsRevisionRelation::Current,
                ),
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
            std::slice::from_ref(&manifest),
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
                    nixpkgs_age_days: None,
                    nixpkgs_channel: None,
                    secondary_nixpkgs: None,
                    deployment_evidence: None,
                    nixcfg_comparison: None,
                    nixpkgs_comparison: None,
                },
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![healthy_backup],
                preferences: Default::default(),
                requested_preferences: None,
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
                    nixpkgs_age_days: None,
                    nixpkgs_channel: None,
                    secondary_nixpkgs: None,
                    deployment_evidence: None,
                    nixcfg_comparison: None,
                    nixpkgs_comparison: None,
                },
                kernel: None,
                service_observations: vec![
                    ServiceObservation::nix_freshness(&NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(4),
                        commits_behind: Some(1),
                        nixpkgs_age_days: None,
                        nixpkgs_channel: None,
                        secondary_nixpkgs: None,
                        deployment_evidence: None,
                        nixcfg_comparison: None,
                        nixpkgs_comparison: None,
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
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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

        let action = HostActionStore::new(None)
            .create_system_update_proposal(
                "update-review-athena-995".to_string(),
                "athena",
                "markus",
                995,
            )
            .expect("safe action event");
        let html = render_activity_with_actions(
            runtime(&hosts, &[]),
            "csb1",
            1000,
            ActivitySources {
                manifests: std::slice::from_ref(&manifest),
                load_errors: &[],
                server_probes: &probes,
                action_jobs: &[action],
            },
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
        assert!(html.contains(r#"data-activity-filter="action""#));
        assert!(html.contains("System update review requested"));
        assert!(html.contains("PHAROS-125"));
        assert!(html.contains("requested by markus"));
        assert!(html.contains(r#"href="/?host=athena&amp;workflow=update-review-athena-995""#));
        assert!(html.contains(r#"aria-label="Open saved workflow for athena""#));
        assert!(html.contains(r#"data-ops-filter="backup""#));
        assert!(html.contains(r#"data-ops-filter="heartbeat""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-host-search="athena freshness freshness drift detected"#));
        assert!(html.contains(r#"<button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true""#));
        assert!(html.contains(r#"data-activity-filter="critical""#));
        assert!(html.contains("const filterOk=active==='all'"));
        assert!(html.contains("Guarded action requests and results are persisted."));
        assert!(html.contains("Other operational events are derived"));
        assert!(!html.contains("restic-main-repository"));
        assert!(!html.contains("not-rendered-token-hash"));
    }

    #[test]
    fn removal_activity_records_lifecycle_intent_without_secret_material() {
        let actions = HostActionStore::new(None);
        actions
            .create_removal(
                "gpc0",
                "markus",
                None,
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: Some("stm2607".to_string()),
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                1_000,
            )
            .expect("removal action recorded");
        let action_jobs = actions.list();
        let events = activity_events(
            runtime(&[], &[]),
            "csb1",
            1_000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &action_jobs,
            },
        );

        let event = events
            .iter()
            .find(|event| event.host == "gpc0" && event.kind == "action")
            .expect("removal activity present");
        assert!(event.detail.contains("Disposition: rebuilt"));
        assert!(event.detail.contains("successor stm2607"));
        assert!(event.detail.contains("nixcfg cleanup pending"));
        assert!(!event.detail.to_ascii_lowercase().contains("token"));
        assert!(!event.detail.to_ascii_lowercase().contains("secret"));
    }

    #[test]
    fn settings_activity_uses_the_workflow_kind_not_the_storage_compatibility_kind() {
        let actions = HostActionStore::new(None);
        actions
            .begin_settings_change("athena", "markus", 1_000)
            .expect("settings workflow recorded");
        let action_jobs = actions.list();
        let events = activity_events(
            runtime(&[], &[]),
            "csb1",
            1_000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &action_jobs,
            },
        );

        let event = events
            .iter()
            .find(|event| event.host == "athena" && event.kind == "action")
            .expect("settings activity present");
        assert_eq!(event.title, "Host settings change waiting");
        assert!(!event.title.contains("System update"));
    }

    #[test]
    fn applied_alert_preferences_filter_monitoring_and_pending_requests_do_not() {
        let mut failed_backup = backup_observation(BackupPostureState::Failed);
        failed_backup.summary = "backup command failed".to_string();
        failed_backup.last_attempt_at = Some(900);
        failed_backup.last_attempt_state = Some(pharos_core::BackupRunState::Failed);
        failed_backup.last_success_at = None;
        failed_backup.restore_validation = None;
        let suppressed = HostPreferences {
            alerts: pharos_core::HostAlertPreferences {
                suppress_down: true,
                suppress_backup: true,
                suppress_nix_freshness: true,
            },
            ..Default::default()
        };
        let mut host = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(500),
            heartbeat_log: vec![380, 440, 500],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(31),
                commits_behind: Some(2),
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
            },
            kernel: None,
            service_observations: vec![ServiceObservation {
                id: "nginx".to_string(),
                label: "nginx".to_string(),
                state: ServiceObservationState::Warning,
                summary: "response is slow".to_string(),
            }],
            backup_observations: vec![failed_backup],
            preferences: suppressed.clone(),
            requested_preferences: None,
        };

        let alerts = alert_items(
            &[host.clone()],
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(alerts.iter().any(|alert| alert.issue == "nginx: warning"));
        assert!(!alerts.iter().any(|alert| alert.source == "heartbeat"));
        assert!(!alerts.iter().any(|alert| alert.source == "freshness"));
        assert!(!alerts.iter().any(|alert| alert.source == "backup"));

        let events = activity_events(
            runtime(std::slice::from_ref(&host), &[]),
            "csb1",
            1000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[],
            },
        );
        assert!(events.iter().any(|event| event.title == "nginx warning"));
        assert!(!events
            .iter()
            .any(|event| event.title == "No heartbeat received"));
        assert!(!events.iter().any(|event| event.kind == "freshness"));
        assert!(!events.iter().any(|event| event.kind == "backup"));

        let fleet = render_home(
            runtime(std::slice::from_ref(&host), &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(fleet.contains("down, backup, Nix freshness muted"));
        assert!(fleet.contains(r#"class="mute-note""#));
        let applied_payload =
            hosts_payload(vec![host.clone()], &[], &BTreeMap::new(), &[], None, 1000);
        assert_eq!(
            applied_payload["hosts"][0]["preferences"]["alerts"]["suppress_down"],
            true
        );
        assert!(applied_payload["hosts"][0]["requested_preferences"].is_null());
        assert!(applied_payload["hosts"][0]["declared_preferences"].is_null());
        assert_eq!(applied_payload["hosts"][0]["preferences_state"], "applied");

        host.preferences = HostPreferences::default();
        host.requested_preferences = Some(suppressed);
        let pending_alerts = alert_items(
            &[host.clone()],
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(pending_alerts
            .iter()
            .any(|alert| alert.source == "heartbeat"));
        assert!(pending_alerts
            .iter()
            .any(|alert| alert.source == "freshness"));
        assert!(pending_alerts.iter().any(|alert| alert.source == "backup"));

        let pending_fleet = render_home(
            runtime(std::slice::from_ref(&host), &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(pending_fleet.contains(r#"class="mute-note" data-mute-note title="" hidden"#));
        assert!(!pending_fleet.contains("down, backup, Nix freshness muted"));
        let pending_payload = hosts_payload(vec![host], &[], &BTreeMap::new(), &[], None, 1000);
        assert_eq!(
            pending_payload["hosts"][0]["preferences"]["alerts"]["suppress_down"],
            false
        );
        assert_eq!(
            pending_payload["hosts"][0]["requested_preferences"]["alerts"]["suppress_down"],
            true
        );
        assert_eq!(
            pending_payload["hosts"][0]["preferences_state"],
            "request_pending"
        );
    }

    #[test]
    fn workstation_down_state_remains_visible_without_creating_down_alerts() {
        let mut workstation = host_with_backups("stm2607", 500, vec![]);
        workstation.preferences.kind = HostKind::Workstation;

        let alerts = alert_items(
            std::slice::from_ref(&workstation),
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(!alerts.iter().any(|alert| alert.source == "heartbeat"));

        let events = activity_events(
            runtime(std::slice::from_ref(&workstation), &[]),
            "csb1",
            1000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[],
            },
        );
        assert!(!events
            .iter()
            .any(|event| event.title == "No heartbeat received"));

        let payload = hosts_payload(
            vec![workstation.clone()],
            &[],
            &BTreeMap::new(),
            &[],
            None,
            1000,
        );
        assert_eq!(payload["hosts"][0]["liveness"], "down");
        assert_eq!(
            payload["hosts"][0]["attention"]["label"],
            "offline as expected"
        );
        assert_eq!(payload["hosts"][0]["attention"]["level"], "ok");

        let fleet = render_home(
            runtime(std::slice::from_ref(&workstation), &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(fleet.contains(r#"data-host="stm2607" data-live="down""#));
        assert!(fleet.contains("offline as expected"));
        assert!(fleet.contains("down alerts off for workstation"));

        let map = map_hosts(
            std::slice::from_ref(&workstation),
            "csb1",
            1000,
            &[],
            &BTreeMap::new(),
        );
        assert_eq!(map[0].live, "down");
        assert_eq!(map[0].attention, "offline as expected");
        let alert_store = AlertStore::new(None).expect("in-memory alert store starts");
        alert_store
            .reconcile_hosts(std::slice::from_ref(&workstation), 1000)
            .expect("workstation alert state reconciles");
        assert_eq!(alert_store.pending_count(), 0);

        workstation.service_observations = vec![ServiceObservation {
            id: "nginx".to_string(),
            label: "nginx".to_string(),
            state: ServiceObservationState::Warning,
            summary: "response is slow".to_string(),
        }];
        let service_alerts = alert_items(
            std::slice::from_ref(&workstation),
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(service_alerts
            .iter()
            .any(|alert| alert.issue == "nginx: warning"));
        assert!(!service_alerts
            .iter()
            .any(|alert| alert.source == "heartbeat"));

        let server = host_with_backups("always-on", 500, vec![]);
        let server_alerts = alert_items(
            std::slice::from_ref(&server),
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(server_alerts
            .iter()
            .any(|alert| alert.source == "heartbeat"));
    }

    #[test]
    fn appliance_probe_owns_liveness_without_false_boot_or_offline_alerts() {
        let mut appliance = host_with_backups("appliance-test", 500, vec![]);
        appliance.last_seen = None;
        appliance.heartbeat_log.clear();
        appliance.heartbeat_interval_secs = None;
        // Beacon-less records retain the runtime default. Startup separately
        // proves that this server-owned observation is backed by a declared
        // workstation preference before it can reach these projections.
        assert_eq!(appliance.preferences.kind, HostKind::Server);
        appliance.service_observations = vec![ServiceObservation {
            id: appliance_probes::APPLIANCE_OBSERVATION_ID.to_string(),
            label: "Appliance convergence".to_string(),
            state: ServiceObservationState::Healthy,
            summary: "powered off as expected".to_string(),
        }];

        let offline_alerts = alert_items(
            std::slice::from_ref(&appliance),
            &[],
            "csb1",
            1000,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(offline_alerts.is_empty());
        let offline_attention = attention_reason(
            Liveness::AwaitingFirstHeartbeat,
            &appliance.freshness,
            None,
            &appliance.service_observations,
            &appliance.preferences,
        );
        assert_eq!(offline_attention.label, "offline as expected");
        assert_eq!(offline_attention.level, "ok");
        let offline_activity = activity_events(
            runtime(std::slice::from_ref(&appliance), &[]),
            "csb1",
            1000,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[],
            },
        );
        assert!(!offline_activity
            .iter()
            .any(|event| matches!(event.kind, "heartbeat" | "service")));

        appliance.service_observations[0].state = ServiceObservationState::Unknown;
        appliance.service_observations[0].summary =
            "online; allowing SSH startup (1 of 3)".to_string();
        let grace_alerts = alert_items(
            std::slice::from_ref(&appliance),
            &[],
            "csb1",
            1001,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert!(grace_alerts.is_empty());
        let grace_attention = attention_reason(
            Liveness::AwaitingFirstHeartbeat,
            &appliance.freshness,
            None,
            &appliance.service_observations,
            &appliance.preferences,
        );
        assert_eq!(grace_attention.label, "starting normally");
        assert_eq!(grace_attention.level, "ok");
        let grace_activity = activity_events(
            runtime(std::slice::from_ref(&appliance), &[]),
            "csb1",
            1001,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[],
            },
        );
        assert!(!grace_activity
            .iter()
            .any(|event| matches!(event.kind, "heartbeat" | "service")));

        appliance.service_observations[0].state = ServiceObservationState::Warning;
        appliance.service_observations[0].summary =
            "un-converged: online but SSH is unavailable".to_string();
        let unconverged_alerts = alert_items(
            std::slice::from_ref(&appliance),
            &[],
            "csb1",
            1002,
            &[],
            &[],
            &BTreeMap::new(),
        );
        assert_eq!(unconverged_alerts.len(), 1);
        assert_eq!(unconverged_alerts[0].source, "service");
        assert!(unconverged_alerts[0].detail.starts_with("un-converged:"));
        assert!(unconverged_alerts[0]
            .next_action
            .contains("will not remediate"));
        assert!(!unconverged_alerts
            .iter()
            .any(|alert| alert.source == "heartbeat"));
        let unconverged_activity = activity_events(
            runtime(std::slice::from_ref(&appliance), &[]),
            "csb1",
            1002,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[],
            },
        );
        assert!(!unconverged_activity
            .iter()
            .any(|event| event.kind == "heartbeat"));
        let unconverged_event = unconverged_activity
            .iter()
            .find(|event| event.kind == "service")
            .expect("un-converged service activity is present");
        assert!(unconverged_event.detail.starts_with("un-converged:"));
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
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

        let leaflet_css = html
            .find("/assets/vendor/leaflet-1.9.4/leaflet.css")
            .unwrap();
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
        assert!(html.contains("/assets/vendor/d3-7.9.0/d3.min.js"));
        assert!(html.contains("/assets/vendor/leaflet-1.9.4/leaflet.js"));
        assert!(!html.contains(&["unpkg", ".com"].concat()));
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
        assert!(html.contains(r#"<b data-summary-count="all">5</b><span>All hosts</span>"#));
        assert!(html.contains(r#"<b data-summary-count="live">4</b><span>Live</span>"#));
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
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
    fn alert_incidents_only_open_for_previous_unsuppressed_down_hosts() {
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
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                preferences: Default::default(),
                requested_preferences: None,
            }
        }

        let mut manually_muted = host("manually-muted", Some(600));
        manually_muted.preferences.alerts.suppress_down = true;
        let mut workstation = host("workstation", Some(600));
        workstation.preferences.kind = HostKind::Workstation;
        let outbox = AlertStore::new(None).expect("in-memory alert store starts");
        outbox
            .reconcile_hosts(
                &[
                    host("live", Some(950)),
                    host("stale", Some(800)),
                    host("down", Some(600)),
                    host("awaiting", None),
                    manually_muted,
                    workstation,
                ],
                1000,
            )
            .expect("incidents reconcile");

        assert_eq!(outbox.pending_count(), 1);
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

    #[tokio::test]
    async fn alert_webhook_refuses_redirects_and_sends_idempotency_key() {
        use std::net::TcpListener;
        use std::sync::mpsc;

        let redirect_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let redirect_address = redirect_listener.local_addr().unwrap();
        let sink_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let sink_address = sink_listener.local_addr().unwrap();
        let (request_sender, request_receiver) = mpsc::sync_channel(1);
        let redirect_server = std::thread::spawn(move || {
            let (mut stream, _) = redirect_listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut request = Vec::new();
            let mut chunk = [0_u8; 2_048];
            loop {
                let read = stream.read(&mut chunk).unwrap_or(0);
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&chunk[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            request_sender.send(request).unwrap();
            write!(
                stream,
                "HTTP/1.1 302 Found\r\nLocation: http://{sink_address}/sink\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
        });
        let outbox = Arc::new(AlertStore::new(None).unwrap());
        let notifier = AlertNotifier {
            webhook_url: Some(format!("http://{redirect_address}/hook")),
            client: reqwest::Client::builder()
                .timeout(Duration::from_millis(250))
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            outbox,
            health: AlertWorkerHealth::new(true, now_unix(), 60),
            check_interval: Duration::from_secs(60),
        };
        let event = AlertEvent {
            schema: "inspr.pharos.alert-event.v1".to_string(),
            event_id: "alert-event-fixture".to_string(),
            incident_id: "alert-incident-fixture".to_string(),
            kind: crate::alerts::AlertEventKind::Down,
            sequence: 0,
            level: "critical".to_string(),
            host: "gpc0".to_string(),
            role: "server".to_string(),
            last_seen: 100,
            age_seconds: 360,
            heartbeat_interval_secs: 60,
            occurred_at: 460,
            summary: "gpc0 has not reported for 6m 00s.".to_string(),
            next_action: "Check host power, network, and pharos-beacon.".to_string(),
        };

        assert!(!notifier.send(&event).await);
        redirect_server.join().unwrap();
        let request = String::from_utf8(request_receiver.recv().unwrap()).unwrap();
        assert!(request
            .to_ascii_lowercase()
            .contains("idempotency-key: alert-event-fixture"));
        sink_listener.set_nonblocking(true).unwrap();
        assert!(matches!(
            sink_listener.accept(),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock
        ));
    }

    #[tokio::test]
    async fn alert_worker_supervisor_restarts_a_failed_child() {
        let health = AlertWorkerHealth::new(true, now_unix(), 60);
        let spawn_count = Arc::new(AtomicU64::new(0));
        let factory_count = spawn_count.clone();
        let supervisor_health = health.clone();
        let supervisor = tokio::spawn(supervise_alert_worker(
            supervisor_health,
            Duration::from_millis(1),
            move || {
                let attempt = factory_count.fetch_add(1, Ordering::AcqRel);
                tokio::spawn(async move {
                    if attempt == 0 {
                        panic!("injected alert worker failure");
                    }
                })
            },
        ));

        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if health.snapshot(now_unix()).restarts_total >= 2 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor restarts failed alert workers");

        assert!(spawn_count.load(Ordering::Acquire) >= 2);
        supervisor.abort();
        let _ = supervisor.await;
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
        let alert = AlertEvent {
            schema: "inspr.pharos.alert-event.v1".to_string(),
            event_id: "alert-event-fixture".to_string(),
            incident_id: "alert-incident-fixture".to_string(),
            level: "critical".to_string(),
            kind: crate::alerts::AlertEventKind::Down,
            sequence: 0,
            host: "gpc0".to_string(),
            role: "server".to_string(),
            last_seen: 100,
            age_seconds: 360,
            heartbeat_interval_secs: 60,
            occurred_at: 460,
            summary: "gpc0 has not reported for 6m 00s.".to_string(),
            next_action: "Check host power, network, and pharos-beacon.".to_string(),
        };

        let text = telegram_alert_text(&alert);

        assert!(text.contains("Pharos critical alert"));
        assert!(text.contains("Host: gpc0"));
        assert!(text.contains("Check host power"));
        assert!(text.contains("alert-event-fixture"));
    }

    #[test]
    fn heartbeat_history_uses_outcome_slots_before_expected_marker() {
        let (marks, history_start_x) =
            heartbeat_marks(&[100, 160, 220, 340], 60, SIGNAL_DEFAULT_WINDOW_SECS);

        assert!((history_start_x - 14.7).abs() < 0.1);
        assert!(!marks.contains(r#"data-history-level="first""#));
        assert!(marks.contains(r#"data-history-level="ok""#));
        assert!(marks.contains(r#"data-history-level="late""#));
        assert!(marks.contains(r#"--mark-x:14.7%""#));
        assert!(marks.contains(r#"--mark-x:29.3%""#));
        assert!(marks.contains(r#"--mark-x:58.7%""#));
        assert!(!marks.contains(r#"--mark-x:64.0%""#));
        assert!(marks.contains(r#"class="beat-mark" role="img" tabindex="0""#));
        assert!(FOOT.contains(r#"class="beat-mark" role="img" tabindex="0""#));
    }

    #[test]
    fn first_heartbeat_without_previous_sample_has_no_history_dot() {
        let (marks, history_start_x) = heartbeat_marks(&[100], 60, SIGNAL_DEFAULT_WINDOW_SECS);
        assert!(marks.is_empty());
        assert_eq!(history_start_x, 0.0);
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
        let mut host = Host {
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
        };
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "poseidon",
            "host": {
                "name": "poseidon",
                "preferences": {
                    "accent": "#48b8a8",
                    "kind": "server",
                    "alerts": {
                        "suppress_down": false,
                        "suppress_backup": false,
                        "suppress_nix_freshness": false
                    }
                }
            },
            "palette": {
                "name": "custom-poseidon",
                "accent": "#48b8a8",
                "gradient": { "primary": "#48b8a8" }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let html = render_home(
            runtime(std::slice::from_ref(&host), &[]),
            "csb1",
            1000,
            std::slice::from_ref(&manifest),
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"href="/hosts/poseidon""#));
        assert!(!html.contains(r#"class="card has-settings""#));
        assert!(html.contains(r#"data-settings-state="declared_not_applied""#));
        assert!(html.contains(r#"aria-label="Ready to apply""#));
        assert!(html.contains(r#"style="--pending-color:#48b8a8""#));
        assert_eq!(
            html.matches(
                r#"<a class="header-chip settings-card" data-settings-state="declared_not_applied""#
            )
            .count(),
            1
        );
        assert!(html.contains(
            r#"data-host-action="host-settings" data-settings-state="declared_not_applied" href="/hosts/poseidon""#
        ));
        assert!(html.contains(
            r#"<span class="header-chip-label" aria-hidden="true">Settings</span><span class="settings-swatch" aria-hidden="true"></span></a>"#
        ));
        assert!(html.contains(
            r#"<button class="settings-wait-note host-lifecycle-chip" type="button" data-host-lifecycle-chip data-settings-state="declared_not_applied" data-lifecycle-slot="prefs_drift" data-lifecycle-level="info" data-lifecycle-invoke="host_settings""#
        ));
        assert!(
            html.contains(r#"<span data-host-lifecycle-chip-copy>Ready to apply</span></button>"#)
        );
        assert!(!html.contains(r#"class="settings-wait-icon""#));
        assert!(!html.contains(r#"--host-color:#48b8a8""#));
        assert!(html.contains(r#"<div class="card-actions"><button class="drag-handle" type="button" data-drag-handle title="Move poseidon" aria-label="Move poseidon""#));
        assert!(html.contains(
            r#"<div class="availability-head"><span class="signal availability" data-signal"#
        ));
        assert!(!html.contains(r#"<div class="card-tools"><span class="signal" data-signal"#));
        assert!(!html.contains("Color and access"));

        host.preferences.accent = Some("#48b8a8".to_string());
        let applied = render_home(
            runtime(&[host], &[]),
            "csb1",
            1000,
            std::slice::from_ref(&manifest),
            shell("markus", true),
            true,
        );
        assert!(applied.contains(r#"class="card has-settings""#));
        assert!(applied.contains(
            r#"data-settings-state="applied" data-lifecycle-slot="quiet" data-lifecycle-level="clear" data-lifecycle-invoke="host_settings""#
        ));
        assert!(
            applied.contains(r#"<span data-host-lifecycle-chip-copy>Up to date</span></button>"#)
        );
        assert!(applied.contains(r#"style="--host-color:#48b8a8""#));
        assert!(!applied.contains(r#"aria-label="Ready to apply""#));
    }

    #[test]
    fn fleet_card_aligns_lifecycle_and_freshness_without_duplicate_attention() {
        let mut drift = host_with_backups("drift", 970, vec![]);
        drift.freshness = proven_freshness(
            "nixos-unstable",
            GitRevisionRelation::Current,
            Some(0),
            NixpkgsRevisionRelation::Different,
        );
        let drift_html = render_home(
            runtime(&[drift], &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(drift_html.contains(
            r#"<div class="reason warn" data-reason hidden><span>nixpkgs differs from nixos-unstable</span></div>"#
        ));
        assert!(drift_html.contains(
            r#"data-fresh-kind="nixpkgs-drift" tabindex="0" title="nixpkgs: nixpkgs differs from nixos-unstable" aria-label="nixpkgs: nixpkgs differs from nixos-unstable""#
        ));

        let mut lifecycle = host_with_backups("lifecycle", 970, vec![]);
        lifecycle.requested_preferences = Some(HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        });
        lifecycle.kernel = Some(reboot_required_kernel(965));
        let lifecycle_html = render_home(
            runtime(&[lifecycle], &[]),
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );
        assert!(lifecycle_html.contains(r#"<div class="card-maintenance">"#));
        assert!(lifecycle_html
            .contains(r#"<span data-host-lifecycle-chip-copy>Change requested</span></button>"#));
        assert!(!lifecycle_html.contains(r#"<span data-host-lifecycle-chip-copy>Continue:"#));
        assert!(!lifecycle_html.contains(r#"<div class="kernel-slot" data-kernel-slot"#));
        assert!(
            HEAD.contains(".card-maintenance .host-lifecycle-chip{width:var(--lifecycle-width)")
        );
        assert!(HEAD.contains(".card .fresh-row-compact{position:relative;display:flex"));
        assert!(HEAD.contains("width:max-content"));

        let card_start = lifecycle_html
            .find(r#"<article class="card"#)
            .expect("runtime card rendered");
        let card_end = lifecycle_html[card_start..]
            .find("</article>")
            .map(|end| card_start + end)
            .expect("runtime card closes");
        let card = &lifecycle_html[card_start..card_end];
        let menu = card
            .find("data-host-actions")
            .expect("actions menu rendered");
        let backup = card.find("backup-chip").expect("backup control rendered");
        assert!(menu < backup, "ellipsis menu must precede backup control");
    }

    #[test]
    fn server_rendered_lifecycle_preserves_existing_click_targets() {
        let prefs = host_with_backups("prefs-target", 970, vec![]);
        let mut run = host_with_backups("run-target", 970, vec![]);
        run.requested_preferences = Some(HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        });
        let mut kernel = host_with_backups("kernel-target", 970, vec![]);
        kernel.kernel = Some(reboot_required_kernel(965));
        let hosts = [prefs, run, kernel];
        let declarations = BTreeMap::from([(
            "prefs-target".to_string(),
            HostPreferences {
                accent: Some("#9868d0".to_string()),
                ..Default::default()
            },
        )]);
        let actions = HostActionStore::new(None);
        let settings_run = actions
            .begin_settings_change("run-target", "markus", 900)
            .expect("settings run created");
        actions
            .fail_settings_change(&settings_run.id, 901)
            .expect("settings run failed");
        let action_jobs = actions.list();

        let html = render_home(
            RuntimeSnapshot {
                hosts: &hosts,
                jobs: &[],
                action_jobs: &action_jobs,
                declared_preferences: Some(&declarations),
                janus_managed_hosts: None,
            },
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );

        let prefs_card = rendered_card(&html, "prefs-target");
        assert!(prefs_card.contains(
            r#"<button class="settings-wait-note host-lifecycle-chip" type="button" data-host-lifecycle-chip data-settings-state="declared_not_applied" data-lifecycle-slot="prefs_drift" data-lifecycle-level="info" data-lifecycle-invoke="host_settings""#
        ));
        assert!(prefs_card
            .contains(r#"<span data-host-lifecycle-chip-copy>Ready to apply</span></button>"#));
        assert!(!prefs_card.contains("data-settings-note"));

        let run_card = rendered_card(&html, "run-target");
        assert!(run_card.contains("data-host-lifecycle-chip"));
        assert!(run_card.contains(r#"data-lifecycle-slot="settings_change""#));
        assert!(run_card.contains(r#"data-lifecycle-invoke="workflow""#));
        assert!(run_card.contains(&format!(r#"data-lifecycle-run-id="{}"#, settings_run.id)));
        assert!(run_card.contains(
            r#"<span data-host-lifecycle-chip-copy>settings request stopped</span></button>"#
        ));
        assert!(run_card.contains(r#"data-host-action="lifecycle-continue""#));
        assert!(!run_card.contains("Continue: Run recovery checks"));
        assert!(run_card.contains(&format!(
            r#"data-action-job-id="{}" data-action-kind="settings_change" data-action-state="failed""#,
            settings_run.id
        )));
        assert!(!run_card.contains("Change requested"));
        assert!(run_card.contains(r#"type="button" data-host-lifecycle-chip"#));

        let read_only_html = render_home(
            RuntimeSnapshot {
                hosts: &hosts,
                jobs: &[],
                action_jobs: &action_jobs,
                declared_preferences: Some(&declarations),
                janus_managed_hosts: None,
            },
            "csb1",
            1000,
            &[],
            shell("viewer", true),
            false,
        );
        let read_only_run = rendered_card(&read_only_html, "run-target");
        assert!(read_only_run.contains("data-host-lifecycle-chip"));
        assert!(read_only_run.contains("disabled"));
        assert!(read_only_run.contains("aria-disabled=\"true\""));
        assert!(!read_only_run.contains("data-host-actions"));
        let read_only_prefs = rendered_card(&read_only_html, "prefs-target");
        assert!(read_only_prefs.contains("data-host-lifecycle-chip"));
        assert!(read_only_prefs.contains("disabled"));

        let kernel_card = rendered_card(&html, "kernel-target");
        assert!(kernel_card.contains(
            r#"data-lifecycle-slot="kernel_drift" data-lifecycle-level="warning" data-lifecycle-invoke="kernel_details""#
        ));
        assert!(kernel_card
            .contains(r#"<span data-host-lifecycle-chip-copy>Restart required</span></button>"#));
        assert!(!kernel_card.contains(r#"<span data-host-lifecycle-chip-copy>Continue:"#));
        assert!(!kernel_card.contains(r#"<div class="kernel-slot" data-kernel-slot"#));

        assert!(FOOT.contains("event.target.closest('[data-host-lifecycle-chip]')"));
        assert!(FOOT.contains("chip.dataset.lifecycleInvoke"));
        assert!(FOOT.contains("chip.dataset.lifecycleRunId"));
        assert!(FOOT.contains("openHostLifecycleSheet"));
        assert!(FOOT.contains("dialog.dataset.drift"));
    }

    #[test]
    fn registry_only_declaration_is_not_rendered_as_applied() {
        let host = host_with_backups("gpc0", 970, vec![]);
        let declared = HostPreferences {
            accent: Some("#9868d0".to_string()),
            kind: pharos_core::HostKind::Workstation,
            alerts: Default::default(),
        };
        let declarations = BTreeMap::from([("gpc0".to_string(), declared.clone())]);
        let hosts = [host.clone()];
        let html = render_home(
            RuntimeSnapshot {
                hosts: &hosts,
                jobs: &[],
                action_jobs: &[],
                declared_preferences: Some(&declarations),
                janus_managed_hosts: None,
            },
            "csb1",
            1000,
            &[],
            shell("markus", true),
            true,
        );

        assert!(html.contains(r#"data-settings-state="declared_not_applied""#));
        assert!(html.contains(r#"style="--pending-color:#9868d0""#));
        assert!(!html.contains(r#"--host-color:#9868d0""#));

        let payload = hosts_payload(vec![host], &[], &declarations, &[], None, 1000);
        assert_eq!(payload["hosts"][0]["declared_preferences"], json!(declared));
        assert_eq!(
            payload["hosts"][0]["preferences_state"],
            "declared_not_applied"
        );
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
        assert!(empty.contains("What would you like to add?"));
        assert!(empty.contains("setup_path"));
        assert!(empty.contains("setup_provider"));
        assert!(empty.contains("setup_template"));
        assert!(empty.contains("setup_stage"));
        assert!(empty.contains(r#"data-assistant-stage="choose""#));
        assert_eq!(empty.matches(r#"data-assistant-path=""#).count(), 2);
        assert!(empty.contains(r#"data-assistant-path="new""#));
        assert!(empty.contains(r#"data-assistant-path="existing""#));
        assert!(empty.contains("New server"));
        assert!(empty.contains("Create a new server"));
        assert!(empty.contains("Existing server"));
        assert!(empty.contains("Connect a server you already have"));
        assert!(empty.contains(r#"data-assistant-step="choose""#));
        assert!(empty.contains(r#"data-assistant-step="template""#));
        assert!(empty.contains(r#"data-assistant-step="existing""#));
        assert!(empty.contains(r#"data-assistant-step="bootstrap""#));
        assert!(empty.contains(r#"data-assistant-step="plan""#));
        assert!(empty.contains(r#"data-assistant-step="job""#));
        assert!(empty.contains(r#"data-assistant-step-back"#));
        assert!(empty.contains("Small server"));
        assert!(empty.contains("Recommended for most uses"));
        assert!(empty.contains("Lab server"));
        assert!(empty.contains("Custom server"));
        assert!(empty.contains("Choose size and region during review"));
        assert!(empty.contains(r#"data-new-host-name"#));
        assert!(empty.contains(r#"data-new-role"#));
        assert!(empty.contains(r#"data-new-location"#));
        assert!(empty.contains(r#"data-new-server-type"#));
        assert!(empty.contains(r#"data-new-image"#));
        assert!(empty.contains(r#"data-new-ssh-key"#));
        assert!(empty.contains(r#"data-preflight-form"#));
        assert!(empty.contains(r#"data-preflight-host-name"#));
        assert!(empty.contains(r#"data-preflight-role"#));
        assert!(empty.contains(r#"data-preflight-host-type"#));
        assert!(empty.contains(r#"data-preflight-heartbeat"#));
        assert!(empty.contains(r#"data-preflight-ssh-user"#));
        assert!(empty.contains(r#"data-preflight-ssh-host"#));
        assert!(empty.contains(r#"data-preflight-result"#));
        assert!(empty.contains(r#"data-preflight-bootstrap"#));
        assert!(empty.contains("Advanced"));
        assert!(empty.contains("Technical checks"));
        assert!(empty.contains("Check server"));
        assert!(empty.contains("data-assistant-template=\"hetzner-small-nixos\""));
        assert!(empty.contains("data-assistant-template=\"netcup-manual-import\""));
        assert!(empty.contains("data-assistant-template=\"oracle-always-free-lab\""));
        assert!(empty.contains("data-assistant-template=\"gcp-free-tier-lab\""));
        assert!(empty.contains(r#"data-assistant-review"#));
        assert!(empty.contains(r#"data-review-provider"#));
        assert!(empty.contains(r#"data-review-server"#));
        assert!(empty.contains(r#"data-review-setup"#));
        assert!(empty.contains(r#"data-review-after"#));
        assert!(empty.contains(r#"data-provider-readiness"#));
        assert!(HEAD.contains(
            r#".assistant-provider-readiness[data-state="attention"] i{background:var(--stale)"#
        ));
        assert!(empty.contains("new Intl.NumberFormat(undefined,{style:'currency'"));
        assert!(empty.contains("minimumFractionDigits:2,maximumFractionDigits:2"));
        assert!(empty.contains("providerMoneyLabel(availability.monthly_gross,currency)"));
        assert!(empty.contains("activationRequired?'attention':'blocked'"));
        assert!(empty.contains(r#"data-provider-plan-resources"#));
        assert!(empty.contains(r#"data-existing-setup-intent"#));
        assert!(empty.contains(r#"name="backup_intent" value="optional""#));
        assert!(empty.contains(r#"name="backup_intent" value="external""#));
        assert!(empty.contains(r#"name="location_intent" value="site-fallback""#));
        assert!(empty.contains(r#"name="access_intent" value="operator-only""#));
        assert!(empty.contains(r#"name="access_intent" value="limited-users""#));
        assert!(!empty.contains("I understand this creates a paid cloud server."));
        assert!(empty.contains("Review paid plan"));
        assert!(empty.contains(r#"<dl class="assistant-paid-policy" data-paid-policy"#));
        for selector in [
            "data-paid-server-name",
            "data-paid-provider-project",
            "data-paid-region",
            "data-paid-server-type",
            "data-paid-catalog-refreshed",
            "data-paid-image",
            "data-paid-price-hourly",
            "data-paid-price-monthly",
            "data-paid-cap-hourly",
            "data-paid-cap-monthly",
            "data-paid-max-active",
            "data-paid-expiry",
            "data-paid-confirmed-at",
            "data-paid-execution-state",
            "data-paid-ssh-key",
            "data-paid-firewall",
            "data-paid-operations",
            "data-paid-labels",
            "data-paid-cleanup",
            "data-paid-next-step",
        ] {
            assert!(
                empty.contains(selector),
                "missing paid policy selector {selector}"
            );
        }
        assert!(empty.contains("Review and authorization do not create a server or start billing."));
        assert!(empty.contains("Continue authorized create"));
        assert!(empty.contains("Check provider result"));
        assert!(empty.contains("Create result unknown"));
        assert!(empty.contains(r#"data-assistant-paid-stage="claimed""#));
        assert!(empty.contains("executionState!=='claimed'"));
        assert!(empty.contains("paid_execution?.state==='failed-closed'"));
        assert!(empty.contains("assistantPaidActionPending"));
        assert!(empty.contains("!expired&&!claimed&&!reconciling"));
        assert!(empty.contains("focusTarget?.setAttribute('tabindex','-1')"));
        assert!(empty.contains("!focusable.includes(document.activeElement)"));
        assert!(empty.contains("body.apply=false"));
        assert!(empty.contains("X-Pharos-Action"));
        assert!(empty.contains("/confirm"));
        assert!(empty.contains("/create"));
        assert!(empty.contains("data-assistant-job"));
        assert!(empty.contains(r#"data-assistant-created"#));
        assert!(empty.contains("Server created"));
        assert!(empty.contains("Ready for setup"));
        assert!(empty.contains("Continue setup"));
        assert!(empty.contains("Do this later"));
        assert!(empty.contains("Recovery options"));
        assert!(empty.contains("Delete this server"));
        assert!(empty.contains(r#"data-created-delete-confirm"#));
        assert!(empty.contains(r#"data-created-delete"#));
        assert!(empty.contains(r#"data-created-delete-status"#));
        assert!(empty.contains(r#"data-created-resource"#));
        assert!(empty.contains(r#"data-created-ssh"#));
        assert!(!empty.contains(r#"data-assistant-continue"#));
        assert!(!empty.contains(r#"data-assistant-next-title"#));
        assert!(!empty.contains(r#"<li data-progress-state=""#));
        assert!(!empty.contains("Choose what you want to add. Nothing changes until you confirm."));
        assert!(!empty.contains("Manual / existing provider"));
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
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
                access: AccessSetupIntent::LimitedUsers,
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
        assert!(html.contains("limited users"));
        assert!(html.contains("Continue setup"));
        assert!(html.contains(r#"setup=add-server&amp;setup_job=setup-1000-test"#));
        assert!(html.contains(r#"data-host-surface="setup""#));
        assert!(html.contains(r#"<tr class="setup-row""#));
        assert!(html.contains(r#"class="list-setup-intent""#));
        assert!(html.contains(r#"class="list-setup-state""#));
        assert!(html.contains(r#"colspan="6""#));
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
                access: AccessSetupIntent::OperatorOnly,
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
            access: AccessSetupIntent::OperatorOnly,
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
                access: AccessSetupIntent::OperatorOnly,
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
                access: AccessSetupIntent::AllOperators,
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
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
        assert!(
            !html.contains(r#"<button class="onboard-primary" type="button" data-onboard-open>"#)
        );
        assert!(!html.contains(r#"<section class="assistant-overlay""#));
        assert!(!html.contains(r#"<tr class="onboard-row""#));
    }

    #[test]
    fn managed_service_status_keeps_declaration_delivery_and_health_separate() {
        let manifest: ManagedServiceManifestV1 = serde_json::from_str(include_str!(
            "../../../contracts/managed-service-declarations-v1.json"
        ))
        .unwrap();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let payload = managed_service_declarations_payload(
            std::slice::from_ref(&manifest),
            &[],
            &operations,
            1_800_000_000,
        );

        assert_eq!(
            payload["schema"],
            "inspr.pharos.managed-service-declaration-status.v1"
        );
        assert_eq!(payload["mutation_ready"], true);
        assert!(payload["mutation_block"].is_null());
        assert_eq!(payload["declarations"][0]["declared"], json!(manifest));
        assert_eq!(
            payload["declarations"][0]["runtime"],
            json!({
                "delivery_owner": "janus",
                "operations": [],
                "observed_health": [],
            })
        );

        let issue = ManifestLoadIssue {
            path: "/managed-services/bad.json".to_string(),
            error: "managed-service manifest JSON is invalid".to_string(),
        };
        let blocked =
            managed_service_declarations_payload(&[], &[issue], &operations, 1_800_000_000);
        assert_eq!(blocked["mutation_ready"], false);
        assert_eq!(blocked["mutation_block"], "registry_invalid");
        assert_eq!(blocked["load_errors"].as_array().unwrap().len(), 1);
    }

    fn managed_setup_request() -> CreateManagedSetupIntentRequest {
        CreateManagedSetupIntentRequest {
            operation_kind: ManagedOperationKind::Create,
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
        }
    }

    #[tokio::test]
    async fn managed_setup_human_handlers_require_action_header_and_oidc_session() {
        let state = report_test_state(false);
        let response = create_managed_setup_intent(
            State(state.clone()),
            HeaderMap::new(),
            Json(managed_setup_request()),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(payload["reason_code"], IntentReason::InvalidRequest.code());

        let mut action_headers = HeaderMap::new();
        action_headers.insert("X-Pharos-Action", "1".parse().unwrap());
        let response = create_managed_setup_intent(
            State(state.clone()),
            action_headers.clone(),
            Json(managed_setup_request()),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            payload["reason_code"],
            IntentReason::AuthenticationRequired.code()
        );

        let response = retry_managed_service_verification(
            State(state.clone()),
            AxumPath("op_retry_verify01".to_string()),
            HeaderMap::new(),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(
            payload["reason_code"],
            "managed_verification_retry_invalid_request"
        );
        assert_eq!(payload["value_returned"], false);

        let response = retry_managed_service_verification(
            State(state.clone()),
            AxumPath("op_retry_verify01".to_string()),
            action_headers.clone(),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            payload["reason_code"],
            "managed_verification_retry_authentication_required"
        );
        assert_eq!(payload["value_returned"], false);

        let response = cancel_managed_setup_intent(
            State(state),
            AxumPath("intent_0f92b78c3d16".to_string()),
            action_headers,
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            payload["reason_code"],
            IntentReason::AuthenticationRequired.code()
        );
    }

    #[tokio::test]
    async fn managed_setup_machine_handler_requires_bearer_and_returns_exact_envelope() {
        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "pharos-managed-handler-{}-{sequence}.json",
            std::process::id()
        ));
        let token = "m".repeat(32);
        let store = Arc::new(
            ManagedSetupIntentStore::new(
                path.clone(),
                ManagedSetupIntentConfig::for_test([14; 32], "key_handler0001", &token),
            )
            .unwrap(),
        );
        let issued = store
            .issue(IssueIntent {
                operation_kind: ManagedOperationKind::Create,
                allowed_sources: vec![ManagedSecretSource::Generated, ManagedSecretSource::Import],
                host_ref: "host_58f36c72a91e".to_string(),
                service_ref: "svc_0bca8d31f7e2".to_string(),
                slot_ref: "slot_49c0e8a17d63".to_string(),
                human_session_ref: "hsn_489e126a70bf".to_string(),
                declaration_fingerprint:
                    "decl_d962b7d42f75d59e53bf94ee39ee3ec467bf507e99178c17f05b3c8205c82a2a"
                        .to_string(),
                now_unix_secs: now_unix(),
            })
            .unwrap();
        let mut state = report_test_state(false);
        state.managed_setup_intents = Some(store);

        let response = retrieve_managed_setup_intent(
            State(state.clone()),
            AxumPath(issued.intent_ref.clone()),
            HeaderMap::new(),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(
            payload["reason_code"],
            IntentReason::UnauthorizedSystem.code()
        );

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().unwrap(),
        );
        let response =
            retrieve_managed_setup_intent(State(state), AxumPath(issued.intent_ref), headers).await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["schema"], SIGNED_INTENT_SCHEMA);
        assert_eq!(payload["key_id"], "key_handler0001");
        assert!(payload.get("reason_code").is_none());
        let _ = fs::remove_file(path);
    }

    #[tokio::test]
    async fn managed_operation_handlers_bind_internal_and_host_ref_credentials() {
        use pharos_core::managed_operations::{
            ManagedOperationAgentOutcome, ManagedOperationKind, ManagedOperationReason,
            MANAGED_OPERATION_CLAIM_SCHEMA, MANAGED_OPERATION_CONTRACT_VERSION,
            MANAGED_OPERATION_READY_SCHEMA, MANAGED_OPERATION_RESULT_SCHEMA,
        };

        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let intent_path = std::env::temp_dir().join(format!(
            "pharos-managed-operation-handler-{}-{sequence}.json",
            std::process::id()
        ));
        let internal_token = "i".repeat(32);
        let agent_token = "agent-token-for-managed-operation";
        let ordinary_host_token = "ordinary-host-beacon-token";
        let host_ref = "host_58f36c72a91e";
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/managed-service-declarations-v1.json");
        let (janus_root, janus_tokens) =
            janus_test_store(&[("csb1", ordinary_host_token), (host_ref, agent_token)]);
        let mut state = report_test_state(false);
        state.manifests = Arc::new(ManifestRegistry::from_all_sources(
            Vec::new(),
            None,
            vec![fixture],
        ));
        state.managed_setup_intents = Some(Arc::new(
            ManagedSetupIntentStore::new(
                intent_path.clone(),
                ManagedSetupIntentConfig::for_test([15; 32], "key_operation0001", &internal_token),
            )
            .unwrap(),
        ));
        state.beacon_auth = BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Dual,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        };
        let ready = ManagedOperationReadyV1 {
            schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            operation_ref: "op_10000001".to_string(),
            operation_kind: ManagedOperationKind::Create,
            host_ref: host_ref.to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint:
                "decl_d962b7d42f75d59e53bf94ee39ee3ec467bf507e99178c17f05b3c8205c82a2a".to_string(),
            generation: 1,
            purge_not_before_unix_secs: None,
            value_returned: false,
        };

        let unauthorized = register_managed_service_operation(
            State(state.clone()),
            HeaderMap::new(),
            Json(ready.clone()),
        )
        .await;
        assert_eq!(unauthorized.status(), StatusCode::UNAUTHORIZED);

        let mut drifted = ready.clone();
        drifted.declaration_fingerprint = format!("decl_{}", "a".repeat(64));
        let response = register_managed_service_operation(
            State(state.clone()),
            bearer_headers(&internal_token),
            Json(drifted),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(
            payload["reason_code"],
            "managed_operation_declaration_drift"
        );

        let response = register_managed_service_operation(
            State(state.clone()),
            bearer_headers(&internal_token),
            Json(ready),
        )
        .await;
        let (status, headers, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::CREATED);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, max-age=0, must-revalidate")
        );
        assert_eq!(payload["operation"]["phase"], "install_pending");
        assert_eq!(payload["value_returned"], false);

        let response = retrieve_managed_service_operation(
            State(state.clone()),
            AxumPath("op_10000001".to_string()),
            HeaderMap::new(),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = retrieve_managed_service_operation(
            State(state.clone()),
            AxumPath("op_10000001".to_string()),
            bearer_headers(&internal_token),
        )
        .await;
        let (status, headers, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|value| value.to_str().ok()),
            Some("no-store, no-cache, max-age=0, must-revalidate")
        );
        assert_eq!(payload["operation"]["operation_ref"], "op_10000001");
        assert_eq!(payload["operation"]["phase"], "install_pending");
        assert_eq!(payload["value_returned"], false);

        let response = retrieve_managed_service_operation_for_host(
            State(state.clone()),
            AxumPath("op_10000001".to_string()),
            Query(ManagedOperationHostStatusQuery {
                host_ref: host_ref.to_string(),
            }),
            bearer_headers(ordinary_host_token),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        let response = retrieve_managed_service_operation_for_host(
            State(state.clone()),
            AxumPath("op_10000001".to_string()),
            Query(ManagedOperationHostStatusQuery {
                host_ref: host_ref.to_string(),
            }),
            bearer_headers(agent_token),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["operation"]["operation_ref"], "op_10000001");
        assert_eq!(payload["operation"]["host_ref"], host_ref);
        assert_eq!(payload["value_returned"], false);

        let claim = ManagedOperationClaimV1 {
            schema: MANAGED_OPERATION_CLAIM_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            host_ref: host_ref.to_string(),
        };
        let wrong_identity = claim_managed_service_operation(
            State(state.clone()),
            bearer_headers(ordinary_host_token),
            Json(claim.clone()),
        )
        .await;
        assert_eq!(wrong_identity.status(), StatusCode::UNAUTHORIZED);

        let response = claim_managed_service_operation(
            State(state.clone()),
            bearer_headers(agent_token),
            Json(claim),
        )
        .await;
        let (status, headers, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, max-age=0, must-revalidate")
        );
        let lease: pharos_core::managed_operations::ManagedOperationLeaseV1 =
            serde_json::from_value(payload.clone()).unwrap();
        assert_eq!(lease.host_ref, host_ref);
        assert!(!lease.value_returned);

        let result = ManagedOperationResultV1 {
            schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: lease.lease_ref,
            operation_ref: lease.operation_ref.clone(),
            host_ref: host_ref.to_string(),
            phase: lease.phase,
            outcome: ManagedOperationAgentOutcome::Succeeded,
            reason_code: ManagedOperationReason::PhaseSucceeded,
            generation: lease.generation,
            health_evidence: None,
            rollback_evidence: None,
            removal_evidence: None,
            value_returned: false,
        };
        let response = record_managed_service_operation_result(
            State(state),
            bearer_headers(agent_token),
            AxumPath(lease.operation_ref),
            Json(result),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["operation"]["phase"], "reload_pending");
        let raw = serde_json::to_string(&payload).unwrap();
        for forbidden in [
            "secret_value",
            "ciphertext",
            "private_key",
            "permit",
            "runtime_path",
            "command",
            "stdout",
            "stderr",
        ] {
            assert!(!raw.contains(forbidden), "response exposed {forbidden}");
        }

        let _ = fs::remove_file(intent_path);
        let _ = fs::remove_dir_all(janus_root);
    }

    #[test]
    fn managed_setup_declaration_resolution_binds_source_policy_and_fails_closed() {
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/managed-service-declarations-v1.json");
        let registry = ManifestRegistry::from_all_sources(Vec::new(), None, vec![fixture]);
        let request = managed_setup_request();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let policy = current_managed_slot(&registry, &operations, &request, 1_800_000_000).unwrap();
        assert_eq!(
            policy.declaration_fingerprint,
            "decl_d962b7d42f75d59e53bf94ee39ee3ec467bf507e99178c17f05b3c8205c82a2a"
        );
        assert_eq!(
            policy.allowed_sources,
            vec![ManagedSecretSource::Generated, ManagedSecretSource::Import]
        );

        let missing_registry = ManifestRegistry::from_all_sources(
            Vec::new(),
            None,
            vec![PathBuf::from("/definitely/missing/managed-service.json")],
        );
        assert_eq!(
            current_managed_slot(&missing_registry, &operations, &request, 1_800_000_000),
            Err(IntentReason::DeclarationUnavailable)
        );
        let mut drifted = request;
        drifted.slot_ref = "slot_unknown0000".to_string();
        assert_eq!(
            current_managed_slot(&registry, &operations, &drifted, 1_800_000_000),
            Err(IntentReason::DeclarationDrift)
        );
    }

    #[test]
    fn replacement_intent_requires_one_healthy_generation_and_rejects_overlap() {
        use pharos_core::managed_operations::{
            ManagedHealthEvidenceV1, ManagedOperationAgentOutcome,
            ManagedOperationKind as AgentOperationKind, ManagedOperationReason, ManagedProbeState,
            ManagedProcessState, MANAGED_OPERATION_CONTRACT_VERSION,
            MANAGED_OPERATION_READY_SCHEMA, MANAGED_OPERATION_RESULT_SCHEMA,
        };

        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../contracts/managed-service-declarations-v1.json");
        let registry = ManifestRegistry::from_all_sources(Vec::new(), None, vec![fixture]);
        let manifest = &registry.managed_service_manifests()[0];
        let service = &manifest.services[0];
        let slot = &service.slots[0];
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let now = 1_800_000_000;
        let ready = ManagedOperationReadyV1 {
            schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            operation_ref: "op_policycreate01".to_string(),
            operation_kind: AgentOperationKind::Create,
            host_ref: manifest.host_ref.clone(),
            service_ref: service.service_ref.clone(),
            slot_ref: slot.slot_ref.clone(),
            declaration_fingerprint: manifest.declaration_fingerprint.clone(),
            generation: 1,
            purge_not_before_unix_secs: None,
            value_returned: false,
        };
        operations.register(&ready, slot, now).unwrap();
        for completed_at in [now + 2, now + 4] {
            let lease = operations
                .claim(&manifest.host_ref, completed_at - 1)
                .unwrap()
                .unwrap();
            operations
                .record_result(
                    &ManagedOperationResultV1 {
                        schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
                        schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
                        lease_ref: lease.lease_ref,
                        operation_ref: lease.operation_ref,
                        host_ref: lease.host_ref,
                        phase: lease.phase,
                        outcome: ManagedOperationAgentOutcome::Succeeded,
                        reason_code: ManagedOperationReason::PhaseSucceeded,
                        generation: lease.generation,
                        health_evidence: None,
                        rollback_evidence: None,
                        removal_evidence: None,
                        value_returned: false,
                    },
                    completed_at,
                )
                .unwrap();
        }
        let verify = operations
            .claim(&manifest.host_ref, now + 5)
            .unwrap()
            .unwrap();
        operations
            .record_result(
                &ManagedOperationResultV1 {
                    schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
                    schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
                    lease_ref: verify.lease_ref,
                    operation_ref: verify.operation_ref,
                    host_ref: verify.host_ref,
                    phase: verify.phase,
                    outcome: ManagedOperationAgentOutcome::Succeeded,
                    reason_code: ManagedOperationReason::PhaseSucceeded,
                    generation: verify.generation,
                    health_evidence: Some(ManagedHealthEvidenceV1 {
                        generation: 1,
                        materialized: true,
                        process_state: ManagedProcessState::Running,
                        probe_state: ManagedProbeState::Healthy,
                        heartbeat_observed_at_unix_secs: now + 5,
                        process_observed_at_unix_secs: now + 5,
                        probe_observed_at_unix_secs: now + 5,
                    }),
                    rollback_evidence: None,
                    removal_evidence: None,
                    value_returned: false,
                },
                now + 6,
            )
            .unwrap();

        let mut remove = managed_setup_request();
        remove.operation_kind = ManagedOperationKind::Remove;
        assert_eq!(
            current_managed_slot(&registry, &operations, &remove, now + 7),
            Err(IntentReason::BindingDetachRequired)
        );
        let detached_path = std::env::temp_dir().join(format!(
            "pharos-managed-service-detached-{}-{now}.json",
            std::process::id()
        ));
        let mut detached_manifest = manifest.clone();
        detached_manifest.services[0].slots[0].binding_state = ManagedBindingState::Detached;
        detached_manifest.services[0].slots[0]
            .allowed_sources
            .clear();
        detached_manifest.declaration_fingerprint = detached_manifest
            .computed_declaration_fingerprint()
            .unwrap();
        fs::write(
            &detached_path,
            serde_json::to_vec_pretty(&detached_manifest).unwrap(),
        )
        .unwrap();
        let detached_registry =
            ManifestRegistry::from_all_sources(Vec::new(), None, vec![detached_path.clone()]);
        let removal_policy =
            current_managed_slot(&detached_registry, &operations, &remove, now + 7).unwrap();
        assert!(removal_policy.allowed_sources.is_empty());
        assert_eq!(
            removal_policy.declaration_fingerprint,
            detached_manifest.declaration_fingerprint
        );
        fs::remove_file(detached_path).unwrap();

        let mut replacement = managed_setup_request();
        replacement.operation_kind = ManagedOperationKind::Replace;
        assert!(current_managed_slot(&registry, &operations, &replacement, now + 7).is_ok());
        assert_eq!(
            current_managed_slot(&registry, &operations, &managed_setup_request(), now + 7),
            Err(IntentReason::OperationConflict)
        );

        let mut replacing = ready;
        replacing.operation_ref = "op_policyreplace1".to_string();
        replacing.operation_kind = AgentOperationKind::Replace;
        replacing.generation = 2;
        operations.register(&replacing, slot, now + 8).unwrap();
        assert_eq!(
            current_managed_slot(&registry, &operations, &replacement, now + 9),
            Err(IntentReason::OperationConflict)
        );
    }

    #[tokio::test]
    async fn managed_setup_denial_statuses_are_stable_and_value_free() {
        for (reason, expected) in [
            (IntentReason::Forbidden, StatusCode::FORBIDDEN),
            (IntentReason::DeclarationDrift, StatusCode::CONFLICT),
            (IntentReason::AlreadyDelivered, StatusCode::CONFLICT),
            (IntentReason::Unknown, StatusCode::NOT_FOUND),
            (IntentReason::Expired, StatusCode::GONE),
            (
                IntentReason::PersistenceUnavailable,
                StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let (status, _, payload) = json_response(managed_intent_denial(reason)).await;
            assert_eq!(status, expected);
            assert_eq!(payload["reason_code"], reason.code());
            assert_eq!(payload["value_returned"], false);
            let encoded = payload.to_string();
            assert!(!encoded.contains("host_"));
            assert!(!encoded.contains("slot_"));
            assert!(!encoded.contains("password"));
        }
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
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
            },
            kernel: None,
            service_observations: vec![ServiceObservation::nix_freshness(&NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
            })],
            backup_observations: vec![backup_observation(BackupPostureState::Warning)],
            preferences: Default::default(),
            requested_preferences: None,
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
            host_need_intent: None,
            host_name: None,
            role: None,
            is_nix: None,
            heartbeat_interval_secs: None,
            backup_intent: None,
            location_intent: None,
            access_intent: None,
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
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
    fn hetzner_direct_apply_fails_without_execution_claim() {
        let path = provisioning_store_test_path("direct-apply-rejection");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let request = hcloud_apply_request("hcloud-direct-apply");
        let runtime = test_hcloud_store_runtime();

        let job = store
            .start(&request, 1_700_000_001, &runtime)
            .expect("direct apply is recorded as a safe terminal job");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert!(job.reviewed_plan.is_none());
        assert!(job.paid_authorization.is_none());
        assert!(job.paid_execution.is_none());
        assert!(job.provider_resources.is_empty());
        assert!(!should_run_hetzner_executor(&request, &job));
        assert!(job
            .progress
            .last()
            .expect("direct-apply rejection progress")
            .message
            .contains("Direct Hetzner Cloud apply is not accepted"));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn paid_review_endpoint_rejects_direct_apply_and_open_auth_before_provider_access() {
        let direct = create_provisioning_job(
            State(report_test_state(false)),
            HeaderMap::new(),
            Json(hcloud_apply_request("hcloud-direct-endpoint")),
        )
        .await
        .into_response();
        assert_eq!(direct.status(), StatusCode::BAD_REQUEST);

        let mut action_headers = HeaderMap::new();
        action_headers.insert("X-Pharos-Action", "1".parse().expect("valid header"));
        let open_auth = create_provisioning_job(
            State(report_test_state(false)),
            action_headers,
            Json(hcloud_review_request("hcloud-open-auth")),
        )
        .await
        .into_response();
        assert_eq!(open_auth.status(), StatusCode::SERVICE_UNAVAILABLE);

        let missing_action = create_provisioning_job(
            State(report_test_state(false)),
            HeaderMap::new(),
            Json(hcloud_review_request("hcloud-no-action")),
        )
        .await
        .into_response();
        assert_eq!(missing_action.status(), StatusCode::FORBIDDEN);
    }

    #[derive(Clone, Debug)]
    struct RecordedHcloudRequest {
        method: String,
        path: String,
        body: String,
    }

    async fn hcloud_mock_server(
        server_status: &str,
        server_body: &'static str,
        firewall_available: bool,
    ) -> (String, Arc<Mutex<Vec<RecordedHcloudRequest>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind hcloud mock");
        let addr = listener.local_addr().expect("mock address");
        let server_status = server_status.to_string();
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            for _ in 0..4 {
                let Ok(Ok((mut stream, _))) =
                    timeout(Duration::from_secs(2), listener.accept()).await
                else {
                    break;
                };
                let mut buf = vec![0; 8192];
                let size = stream.read(&mut buf).await.expect("read hcloud request");
                let request = String::from_utf8_lossy(&buf[..size]);
                let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
                let mut request_line = head.lines().next().unwrap_or_default().split_whitespace();
                let method = request_line.next().unwrap_or_default().to_string();
                let path = request_line.next().unwrap_or_default().to_string();
                recorded
                    .lock()
                    .expect("hcloud request lock")
                    .push(RecordedHcloudRequest {
                        method,
                        path: path.clone(),
                        body: body.to_string(),
                    });
                let (status, response_body) = if path.starts_with("/images?") {
                    ("200 OK", r#"{"images":[{"id":77,"name":"debian-12"}]}"#)
                } else if path.starts_with("/ssh_keys?") {
                    (
                        "200 OK",
                        r#"{"ssh_keys":[{"id":101,"name":"pharos-bootstrap-key"}]}"#,
                    )
                } else if path.starts_with("/firewalls?") {
                    if firewall_available {
                        (
                            "200 OK",
                            r#"{"firewalls":[{"id":202,"name":"pharos-bootstrap-firewall"}]}"#,
                        )
                    } else {
                        ("200 OK", r#"{"firewalls":[]}"#)
                    }
                } else {
                    (server_status.as_str(), server_body)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{response_body}",
                    response_body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write hcloud response");
            }
        });
        (format!("http://{addr}"), requests)
    }

    async fn hcloud_cleanup_mock_server(
        inventory_body: String,
        delete_status: &'static str,
        delete_body: &'static str,
    ) -> (String, Arc<Mutex<Vec<RecordedHcloudRequest>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind cleanup mock");
        let addr = listener.local_addr().expect("cleanup mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            for _ in 0..5 {
                let Ok(Ok((mut stream, _))) =
                    timeout(Duration::from_secs(2), listener.accept()).await
                else {
                    break;
                };
                let mut buf = vec![0; 8192];
                let size = stream.read(&mut buf).await.expect("read cleanup request");
                let request = String::from_utf8_lossy(&buf[..size]);
                let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
                let mut request_line = head.lines().next().unwrap_or_default().split_whitespace();
                let method = request_line.next().unwrap_or_default().to_string();
                let path = request_line.next().unwrap_or_default().to_string();
                recorded
                    .lock()
                    .expect("cleanup request lock")
                    .push(RecordedHcloudRequest {
                        method: method.clone(),
                        path: path.clone(),
                        body: body.to_string(),
                    });
                let (status, response_body) = if method == "GET" && path.starts_with("/servers?") {
                    ("200 OK", inventory_body.as_str())
                } else if method == "DELETE" && path.starts_with("/servers/") {
                    (delete_status, delete_body)
                } else {
                    ("404 Not Found", r#"{"error":"unexpected"}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{response_body}",
                    response_body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write cleanup response");
            }
        });
        (format!("http://{addr}"), requests)
    }

    async fn hcloud_cleanup_reconciliation_mock_server(
        inventory_before_delete: String,
        inventories_after_delete: Vec<String>,
        delete_status: &'static str,
        delete_body: &'static str,
    ) -> (String, Arc<Mutex<Vec<RecordedHcloudRequest>>>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        assert!(!inventories_after_delete.is_empty());
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind cleanup reconciliation mock");
        let addr = listener.local_addr().expect("cleanup mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            let mut delete_observed = false;
            let mut post_delete_read = 0_usize;
            for _ in 0..inventories_after_delete.len().saturating_add(2) {
                let Ok(Ok((mut stream, _))) =
                    timeout(Duration::from_secs(2), listener.accept()).await
                else {
                    break;
                };
                let mut buf = vec![0; 8192];
                let size = stream
                    .read(&mut buf)
                    .await
                    .expect("read cleanup reconciliation request");
                let request = String::from_utf8_lossy(&buf[..size]);
                let (head, body) = request.split_once("\r\n\r\n").unwrap_or((&request, ""));
                let mut request_line = head.lines().next().unwrap_or_default().split_whitespace();
                let method = request_line.next().unwrap_or_default().to_string();
                let path = request_line.next().unwrap_or_default().to_string();
                recorded
                    .lock()
                    .expect("cleanup reconciliation request lock")
                    .push(RecordedHcloudRequest {
                        method: method.clone(),
                        path: path.clone(),
                        body: body.to_string(),
                    });
                let (status, response_body) = if method == "GET" && path.starts_with("/servers?") {
                    if delete_observed {
                        let index =
                            post_delete_read.min(inventories_after_delete.len().saturating_sub(1));
                        post_delete_read = post_delete_read.saturating_add(1);
                        ("200 OK", inventories_after_delete[index].as_str())
                    } else {
                        ("200 OK", inventory_before_delete.as_str())
                    }
                } else if method == "DELETE" && path.starts_with("/servers/") {
                    delete_observed = true;
                    (delete_status, delete_body)
                } else {
                    ("404 Not Found", r#"{"error":"unexpected"}"#)
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{response_body}",
                    response_body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write cleanup reconciliation response");
            }
        });
        (format!("http://{addr}"), requests)
    }

    fn hcloud_apply_request(host_name: &str) -> ProvisioningJobStartRequest {
        ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some(host_name.to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::EnrollLater),
            location_intent: Some(LocationSetupIntent::SiteFallback),
            access_intent: Some(AccessSetupIntent::LimitedUsers),
            location: Some("fsn1".to_string()),
            server_type: Some("cx22".to_string()),
            image: Some("debian-12".to_string()),
            ssh_key_ref: Some("pharos-bootstrap-key".to_string()),
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        }
    }

    fn hcloud_review_request(host_name: &str) -> ProvisioningJobStartRequest {
        ProvisioningJobStartRequest {
            apply: false,
            host_need_intent: None,
            ..hcloud_apply_request(host_name)
        }
    }

    fn test_hcloud_store_runtime() -> ProviderRuntimeConfig {
        ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File(PathBuf::from(
                    "/run/secrets/pharos-hcloud-token",
                ))),
                execute_enabled: true,
                firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
                default_location: Some("fsn1".to_string()),
                project_label: Some("test-project".to_string()),
                approval_ttl_secs: 15 * 60,
                ..HetznerCloudRuntimeConfig::default()
            },
            ..ProviderRuntimeConfig::default()
        }
    }

    fn test_reviewed_paid_plan(job: &ProvisioningJob) -> ProvisioningReviewedPaidPlan {
        let mut reviewed = ProvisioningReviewedPaidPlan {
            provider_project: "test-project".to_string(),
            credential_binding_sha256: hetzner_credential_binding("test-hcloud-token"),
            server_name: job.host_name.clone().expect("reviewed server name"),
            location: "fsn1".to_string(),
            location_label: "Falkenstein (fsn1)".to_string(),
            server_type: "cx22".to_string(),
            server_type_label: "CX22 - 2 vCPU / 4 GB".to_string(),
            image: "debian-12".to_string(),
            price_currency: "EUR".to_string(),
            price_hourly_gross: "0.0060".to_string(),
            price_monthly_gross: "3.4900".to_string(),
            max_hourly_gross: "0.0060".to_string(),
            max_monthly_gross: "3.4900".to_string(),
            observed_active_servers: 0,
            max_active_servers: 1,
            catalog_refreshed_at: job.created_at,
            expires_at: job.created_at + 15 * 60,
            ssh_key_ref: "pharos-bootstrap-key".to_string(),
            firewall_ref: "pharos-bootstrap-firewall".to_string(),
            managed_executor_owner: None,
            managed_credential_ref: None,
            required_labels: paid_required_labels(&job.id, "test-project"),
            allowed_operations: vec!["create-server".to_string(), "delete-server".to_string()],
            cleanup_policy: "No silent retry or automatic deletion; separately confirm cleanup."
                .to_string(),
            plan_sha256: "0".repeat(64),
        };
        reviewed.plan_sha256 = reviewed_paid_plan_digest(&reviewed);
        reviewed
            .validate_contract()
            .expect("reviewed paid plan fixture is valid");
        reviewed
    }

    fn start_hcloud_review_job(
        store: &ProvisioningJobStore,
        host_name: &str,
        created_at: i64,
    ) -> ProvisioningJob {
        let request = hcloud_review_request(host_name);
        let job = store
            .start(&request, created_at, &test_hcloud_store_runtime())
            .expect("review job starts");
        assert_eq!(job.state, ProvisioningJobState::Planning);
        job
    }

    fn test_paid_resource(host_name: &str, provider_id: &str) -> ProvisioningProviderResource {
        ProvisioningProviderResource {
            provider: "hetzner-cloud".to_string(),
            kind: "server".to_string(),
            provider_id: provider_id.to_string(),
            name: host_name.to_string(),
            state: "created".to_string(),
            location: Some("fsn1".to_string()),
            ssh: Some(SshAccessIntent {
                route: SshRoute::Direct,
                user: Some("root".to_string()),
                host: Some("192.0.2.42".to_string()),
                port: Some(22),
            }),
        }
    }

    fn managed_hcloud_created_job(
        store: &ProvisioningJobStore,
        host_name: &str,
        provider_id: &str,
        created_at: i64,
    ) -> ProvisioningJob {
        let job = start_hcloud_review_job(store, host_name, created_at);
        let mut reviewed = test_reviewed_paid_plan(&job);
        reviewed.managed_executor_owner = Some("csb1".to_string());
        reviewed.managed_credential_ref = Some(format!("sec_{}", "d".repeat(20)));
        reviewed.plan_sha256 = reviewed_paid_plan_digest(&reviewed);
        let digest = reviewed.plan_sha256.clone();
        let operator_ref = "b".repeat(64);
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("managed review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &digest,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("managed review confirms");
        store
            .claim_paid_execution(&job.id, &digest, &operator_ref, created_at + 3)
            .expect("managed provider execution claims");
        store
            .mark_paid_request_started(&job.id, &digest, created_at + 4)
            .expect("managed provider request starts");
        let resource = test_paid_resource(host_name, provider_id);
        let handoff = hetzner_bootstrap_handoff(&resource).expect("managed handoff");
        store
            .complete_paid_create(
                &job.id,
                &digest,
                resource,
                Some(handoff),
                false,
                created_at + 5,
            )
            .expect("managed provider result persists")
    }

    fn provisioning_store_test_path(label: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pharos-{label}-{}-{nanos}-{sequence}.json",
            std::process::id()
        ))
    }

    fn remove_provisioning_store_test_files(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(provisioning_job_store_marker_path(path));
    }

    struct TestHcloudFiles {
        token_path: PathBuf,
        jobs_path: PathBuf,
    }

    impl AsRef<Path> for TestHcloudFiles {
        fn as_ref(&self) -> &Path {
            &self.token_path
        }
    }

    impl Drop for TestHcloudFiles {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.token_path);
            remove_provisioning_store_test_files(&self.jobs_path);
        }
    }

    fn test_hcloud_state(api_base_url: String) -> (AppState, TestHcloudFiles) {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let token_path = std::env::temp_dir().join(format!(
            "pharos-hcloud-test-token-{}-{}-{}",
            std::process::id(),
            nanos,
            sequence
        ));
        std::fs::write(&token_path, "test-hcloud-token").expect("write test token");
        let jobs_path = token_path.with_extension("provisioning-jobs.json");
        let mut state = report_test_state(false);
        state.provisioning_jobs = Arc::new(ProvisioningJobStore::new(Some(jobs_path.clone())));
        state.provider_runtime = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File(token_path.clone())),
                execute_enabled: true,
                default_ssh_key_ref: None,
                firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
                default_location: Some("fsn1".to_string()),
                api_base_url,
                request_timeout: Duration::from_secs(2),
                evidence_ttl_secs: 60 * 60,
                project_label: Some("test-project".to_string()),
                approval_ttl_secs: 15 * 60,
            },
            ..ProviderRuntimeConfig::default()
        };
        (
            state,
            TestHcloudFiles {
                token_path,
                jobs_path,
            },
        )
    }

    #[tokio::test]
    async fn paid_create_payload_uses_only_the_persisted_plan_and_ownership_labels() {
        let response_body = r#"{"server":{"id":4242,"name":"hcloud-paid-test","labels":{"managed-by":"pharos","pharos-setup":"tracked-job","pharos-owner":"75c84d20a0aa90c5","pharos-job":"setup-1700000000-1","pharos-attempt":"setup-1700000000-1-1"},"server_type":{"name":"cx22"},"image":{"name":"debian-12"},"location":{"id":1,"name":"fsn1","city":"Falkenstein","country":"DE","network_zone":"eu-central"},"public_net":{"ipv4":{"ip":"192.0.2.42"}}}}"#;
        let (api, requests) = hcloud_mock_server("201 Created", response_body, true).await;
        let (state, token_path) = test_hcloud_state(api);
        let job =
            start_hcloud_review_job(&state.provisioning_jobs, "hcloud-paid-test", 1_700_000_000);
        let reviewed = test_reviewed_paid_plan(&job);
        let digest = reviewed.plan_sha256.clone();
        let reviewed_job = state
            .provisioning_jobs
            .attach_paid_review(&job.id, reviewed.clone(), 1_700_000_001)
            .expect("review attaches");
        state
            .provisioning_jobs
            .confirm_paid_review(
                &job.id,
                &digest,
                &"a".repeat(64),
                "Test Operator",
                1_700_000_002,
            )
            .expect("review confirms");
        state
            .provisioning_jobs
            .claim_paid_execution(&job.id, &digest, &"a".repeat(64), 1_700_000_003)
            .expect("execution claims");
        let _started = state
            .provisioning_jobs
            .mark_paid_request_started(&job.id, &digest, 1_700_000_004)
            .expect("request marker persists");

        let mut create_plan = reviewed_job.reviewed_plan.clone().expect("reviewed plan");
        create_plan.expires_at = now_unix() + 60;
        let operation =
            HetznerOperationContext::resolve(state.provider_runtime.hetzner_cloud.clone())
                .expect("operation credential resolves");
        let prerequisites = resolve_hetzner_create_prerequisites(&create_plan, &operation)
            .await
            .expect("mock prerequisites resolve");
        let server = send_hetzner_create(&create_plan, prerequisites, &operation)
            .await
            .expect("mock provider creates server");
        assert_eq!(server.id, 4242);

        let recorded = requests.lock().expect("hcloud requests");
        assert_eq!(recorded.len(), 4);
        assert!(recorded[0].path.starts_with("/images?"));
        assert!(recorded[1].path.starts_with("/ssh_keys?"));
        assert!(recorded[2].path.starts_with("/firewalls?"));
        assert_eq!(recorded[3].method, "POST");
        assert_eq!(recorded[3].path, "/servers");
        let payload: serde_json::Value =
            serde_json::from_str(&recorded[3].body).expect("create payload is JSON");
        assert_eq!(payload["name"], "hcloud-paid-test");
        assert_eq!(payload["server_type"], reviewed.server_type);
        assert_eq!(payload["image"], reviewed.image);
        assert_eq!(payload["location"], reviewed.location);
        for (key, value) in &reviewed.required_labels {
            assert_eq!(payload["labels"][key], value.as_str());
        }
        let body = recorded[3].body.to_ascii_lowercase();
        assert!(!body.contains("test-hcloud-token"));
        assert!(!body.contains("bearer "));
        drop(recorded);
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn paid_create_response_accepts_compatible_locations_and_rejects_unsafe_facts() {
        let path = provisioning_store_test_path("paid-create-location-compat");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-location-compat", 1_700_000_025);
        let reviewed = test_reviewed_paid_plan(&job);
        let legacy = json!({
            "id": 4242,
            "name": reviewed.server_name,
            "labels": reviewed.required_labels,
            "server_type": {"name": reviewed.server_type},
            "image": {"name": reviewed.image},
            "datacenter": {"location": {"name": reviewed.location}}
        });
        let server: HetznerCreatedServer =
            serde_json::from_value(legacy.clone()).expect("legacy create response parses");
        assert!(server.matches_reviewed_plan(&reviewed));

        let mut current_and_legacy = legacy.clone();
        current_and_legacy["location"] = json!({"name": reviewed.location});
        let server: HetznerCreatedServer = serde_json::from_value(current_and_legacy)
            .expect("compatible current and legacy create response parses");
        assert!(server.matches_reviewed_plan(&reviewed));

        let mut conflicting = legacy.clone();
        conflicting["location"] = json!({"name": "nbg1"});
        let server: HetznerCreatedServer =
            serde_json::from_value(conflicting).expect("conflicting create response parses");
        assert!(!server.matches_reviewed_plan(&reviewed));

        let mut incomplete = legacy;
        incomplete
            .as_object_mut()
            .expect("server object")
            .remove("datacenter");
        let server: HetznerCreatedServer =
            serde_json::from_value(incomplete).expect("incomplete create response parses");
        assert!(!server.matches_reviewed_plan(&reviewed));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_reconciliation_requires_all_reviewed_server_facts() {
        let path = provisioning_store_test_path("paid-reconciliation-facts");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-reconcile-facts", 1_700_000_050);
        let reviewed = test_reviewed_paid_plan(&job);
        let exact = json!({
            "id": 4242,
            "name": reviewed.server_name,
            "labels": reviewed.required_labels,
            "server_type": {"name": reviewed.server_type},
            "image": {"name": reviewed.image},
            "location": {
                "id": 1,
                "name": reviewed.location,
                "city": "Falkenstein",
                "country": "DE",
                "network_zone": "eu-central"
            }
        });
        let server: HetznerListedServer =
            serde_json::from_value(exact.clone()).expect("exact inventory server parses");
        assert!(server.matches_reviewed_plan(&reviewed));

        for (pointer, replacement) in [
            ("/server_type/name", json!("cx32")),
            ("/image/name", json!("unexpected-image")),
            ("/location/name", json!("nbg1")),
        ] {
            let mut changed = exact.clone();
            *changed
                .pointer_mut(pointer)
                .expect("reviewed fact pointer exists") = replacement;
            let server: HetznerListedServer =
                serde_json::from_value(changed).expect("changed inventory server parses");
            assert!(!server.matches_reviewed_plan(&reviewed));
        }

        let mut legacy = exact.clone();
        legacy
            .as_object_mut()
            .expect("server object")
            .remove("location");
        legacy["datacenter"] = json!({"location": {"name": reviewed.location}});
        let server: HetznerListedServer =
            serde_json::from_value(legacy).expect("legacy inventory server parses");
        assert!(server.matches_reviewed_plan(&reviewed));

        let mut conflicting = exact.clone();
        conflicting["datacenter"] = json!({"location": {"name": "nbg1"}});
        let server: HetznerListedServer =
            serde_json::from_value(conflicting).expect("conflicting inventory server parses");
        assert!(!server.matches_reviewed_plan(&reviewed));

        let mut incomplete = exact;
        incomplete
            .as_object_mut()
            .expect("server object")
            .remove("location");
        let server: HetznerListedServer =
            serde_json::from_value(incomplete).expect("incomplete inventory server parses");
        assert!(!server.matches_reviewed_plan(&reviewed));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn paid_cleanup_rejects_live_ownership_mismatch_without_delete() {
        let inventory = r#"{"servers":[{"id":4242,"name":"hcloud-owned-test","labels":{"managed-by":"someone-else"}}],"meta":{"pagination":{"page":1,"next_page":null,"last_page":1,"total_entries":1}}}"#;
        let (api, requests) = hcloud_mock_server("200 OK", inventory, true).await;
        let (state, token_path) = test_hcloud_state(api);
        let created_at = 1_700_000_000;
        let job =
            start_hcloud_review_job(&state.provisioning_jobs, "hcloud-owned-test", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let digest = reviewed.plan_sha256.clone();
        state
            .provisioning_jobs
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("review attaches");
        state
            .provisioning_jobs
            .confirm_paid_review(
                &job.id,
                &digest,
                &"a".repeat(64),
                "Test Operator",
                created_at + 2,
            )
            .expect("review confirms");
        state
            .provisioning_jobs
            .claim_paid_execution(&job.id, &digest, &"a".repeat(64), created_at + 3)
            .expect("execution claims");
        state
            .provisioning_jobs
            .mark_paid_request_started(&job.id, &digest, created_at + 4)
            .expect("request starts");
        let resource = test_paid_resource("hcloud-owned-test", "4242");
        let handoff = hetzner_bootstrap_handoff(&resource).expect("handoff");
        let created = state
            .provisioning_jobs
            .complete_paid_create(
                &job.id,
                &digest,
                resource,
                Some(handoff),
                false,
                created_at + 5,
            )
            .expect("create persists");

        let failure = execute_hetzner_cleanup_job(&state, created)
            .await
            .expect_err("mismatched labels stop cleanup");
        assert_eq!(failure.error, ProvisioningCleanupError::OwnershipMismatch);
        let recorded = requests.lock().expect("hcloud requests");
        assert_eq!(recorded.len(), 1);
        assert_eq!(recorded[0].method, "GET");
        assert!(recorded[0].path.starts_with("/servers?"));
        assert!(!recorded.iter().any(|request| request.method == "DELETE"));
        drop(recorded);
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn legacy_numeric_provider_resource_cannot_bypass_paid_ownership() {
        let (api, requests) = hcloud_mock_server("204 No Content", "", true).await;
        let (state, token_path) = test_hcloud_state(api);
        let mut legacy = state
            .provisioning_jobs
            .start(
                &hcloud_apply_request("hcloud-legacy-cleanup"),
                1_700_000_010,
                &state.provider_runtime,
            )
            .expect("legacy-shaped job fixture persists");
        let resource = test_paid_resource("hcloud-legacy-cleanup", "4241");
        legacy.state = ProvisioningJobState::WaitingForHeartbeat;
        legacy.updated_at = 1_700_000_011;
        legacy.provider_resources = vec![resource.clone()];
        legacy.handoff = hetzner_bootstrap_handoff(&resource);

        let failure = execute_hetzner_cleanup_job(&state, legacy)
            .await
            .expect_err("legacy numeric ID has no Phase 1 ownership envelope");
        assert_eq!(failure.error, ProvisioningCleanupError::OwnershipMismatch);
        assert!(requests.lock().expect("hcloud requests").is_empty());
        let _ = std::fs::remove_file(token_path);
    }

    fn tracked_hcloud_cleanup_job(state: &AppState, provider_id: &str) -> ProvisioningJob {
        let request = hcloud_review_request("hcloud-cleanup-test");
        let job = state
            .provisioning_jobs
            .start(&request, 1_700_000_020, &state.provider_runtime)
            .expect("tracked Hetzner job starts");
        let reviewed = test_reviewed_paid_plan(&job);
        let digest = reviewed.plan_sha256.clone();
        state
            .provisioning_jobs
            .attach_paid_review(&job.id, reviewed, 1_700_000_021)
            .expect("cleanup review attaches");
        state
            .provisioning_jobs
            .confirm_paid_review(
                &job.id,
                &digest,
                &"a".repeat(64),
                "Test Operator",
                1_700_000_022,
            )
            .expect("cleanup review confirms");
        state
            .provisioning_jobs
            .claim_paid_execution(&job.id, &digest, &"a".repeat(64), 1_700_000_023)
            .expect("cleanup execution claims");
        state
            .provisioning_jobs
            .mark_paid_request_started(&job.id, &digest, 1_700_000_024)
            .expect("cleanup create boundary persists");
        let resource = ProvisioningProviderResource {
            provider: "hetzner-cloud".to_string(),
            kind: "server".to_string(),
            provider_id: provider_id.to_string(),
            name: "hcloud-cleanup-test".to_string(),
            state: "created".to_string(),
            location: Some("fsn1".to_string()),
            ssh: Some(SshAccessIntent {
                route: SshRoute::Direct,
                user: Some("root".to_string()),
                host: Some("192.0.2.42".to_string()),
                port: Some(22),
            }),
        };
        let handoff = hetzner_bootstrap_handoff(&resource).expect("bootstrap handoff");
        state
            .provisioning_jobs
            .complete_paid_create(
                &job.id,
                &digest,
                resource,
                Some(handoff),
                false,
                1_700_000_025,
            )
            .expect("tracked resource persisted")
    }

    fn owned_cleanup_inventory(provider_id: &str) -> String {
        json!({
            "servers": [{
                "id": provider_id.parse::<u64>().expect("numeric provider id"),
                "name": "hcloud-cleanup-test",
                "labels": paid_required_labels("setup-1700000020-1", "test-project")
            }],
            "meta": {"pagination": {
                "page": 1,
                "next_page": null,
                "last_page": 1,
                "total_entries": 1
            }}
        })
        .to_string()
    }

    #[tokio::test]
    async fn hetzner_cleanup_deletes_once_and_replays_without_provider_request() {
        let (api, requests) =
            hcloud_cleanup_mock_server(owned_cleanup_inventory("4242"), "204 No Content", "").await;
        let (state, token_path) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4242");

        let (deleted, already_absent) = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect("cleanup succeeds");
        assert!(!already_absent);
        assert_eq!(deleted.state, ProvisioningJobState::Complete);
        assert_eq!(
            deleted.terminal_outcome,
            Some(ProvisioningTerminalOutcome::RolledBack)
        );
        let resource = deleted
            .provider_resources
            .first()
            .expect("deleted resource remains tracked");
        assert_eq!(resource.state, "deleted");
        assert!(resource.ssh.is_none());
        assert_eq!(
            deleted
                .handoff
                .as_ref()
                .map(|handoff| handoff.status.as_str()),
            Some("provider-resource-deleted")
        );
        {
            let recorded = requests.lock().expect("hcloud requests");
            assert_eq!(recorded.len(), 2);
            assert_eq!(recorded[0].method, "GET");
            assert!(recorded[0].path.starts_with("/servers?"));
            assert_eq!(recorded[1].method, "DELETE");
            assert_eq!(recorded[1].path, "/servers/4242");
            assert!(recorded[1].body.is_empty());
        }

        let (replayed, replay_already_absent) =
            execute_hetzner_cleanup_job(&state, deleted.clone())
                .await
                .expect("cleanup replay is idempotent");
        assert!(replay_already_absent);
        assert_eq!(replayed, deleted);
        assert_eq!(requests.lock().expect("hcloud requests").len(), 2);

        let json = serde_json::to_string(&deleted).expect("cleanup job serializes");
        assert!(!json.contains("test-hcloud-token"));
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn hetzner_cleanup_accepts_provider_already_absent() {
        let (api, requests) =
            hcloud_cleanup_mock_server(
                r#"{"servers":[],"meta":{"pagination":{"page":1,"next_page":null,"last_page":1,"total_entries":0}}}"#.to_string(),
                "204 No Content",
                "",
            )
            .await;
        let (state, token_path) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4243");

        let (deleted, already_absent) = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect("provider absence is a proven cleanup result");
        assert!(already_absent);
        assert_eq!(deleted.state, ProvisioningJobState::Complete);
        assert_eq!(deleted.provider_resources[0].state, "deleted");
        assert_eq!(requests.lock().expect("hcloud requests").len(), 1);
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn hetzner_cleanup_reconciles_absence_after_ambiguous_delete_response() {
        let empty_inventory = r#"{"servers":[],"meta":{"pagination":{"page":1,"next_page":null,"last_page":1,"total_entries":0}}}"#.to_string();
        let owned_inventory = owned_cleanup_inventory("4253");
        let (api, requests) = hcloud_cleanup_reconciliation_mock_server(
            owned_inventory.clone(),
            vec![owned_inventory, empty_inventory],
            "500 Internal Server Error",
            r#"{"error":"result-lost"}"#,
        )
        .await;
        let (state, token_path) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4253");

        let (deleted, already_absent) = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect("read-only reconciliation proves ambiguous cleanup");

        assert!(!already_absent);
        assert_eq!(deleted.state, ProvisioningJobState::Complete);
        assert_eq!(
            deleted.terminal_outcome,
            Some(ProvisioningTerminalOutcome::RolledBack)
        );
        assert_eq!(deleted.provider_resources[0].state, "deleted");
        let recorded = requests.lock().expect("hcloud requests");
        assert_eq!(
            recorded
                .iter()
                .map(|request| request.method.as_str())
                .collect::<Vec<_>>(),
            vec!["GET", "DELETE", "GET", "GET"]
        );
        assert_eq!(
            recorded
                .iter()
                .filter(|request| request.method == "DELETE")
                .count(),
            1
        );
        drop(recorded);
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn hetzner_cleanup_rejects_incomplete_inventory_as_absence_proof() {
        for inventory in [r#"{}"#, r#"{"servers":[]}"#] {
            let (api, requests) =
                hcloud_cleanup_mock_server(inventory.to_string(), "204 No Content", "").await;
            let (state, token_path) = test_hcloud_state(api);
            let job = tracked_hcloud_cleanup_job(&state, "4249");

            let failure = execute_hetzner_cleanup_job(&state, job)
                .await
                .expect_err("partial inventory cannot prove provider absence");
            assert_eq!(failure.error, ProvisioningCleanupError::ProviderUnavailable);
            let recorded = requests.lock().expect("hcloud requests");
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].method, "GET");
            assert!(!recorded.iter().any(|request| request.method == "DELETE"));
            drop(recorded);
            let _ = std::fs::remove_file(token_path);
        }
    }

    #[tokio::test]
    async fn rotated_credential_cleanup_requires_visible_ownership_proof() {
        let (api, requests) =
            hcloud_cleanup_mock_server(owned_cleanup_inventory("4251"), "204 No Content", "").await;
        let (state, files) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4251");
        std::fs::write(files.as_ref(), "rotated-test-hcloud-token")
            .expect("rotate credential fixture");

        let (deleted, already_absent) = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect("exact visible ownership permits cleanup after rotation");
        assert!(!already_absent);
        assert_eq!(deleted.provider_resources[0].state, "deleted");
        assert_eq!(requests.lock().expect("hcloud requests").len(), 2);
        drop(files);

        let empty_inventory = r#"{"servers":[],"meta":{"pagination":{"page":1,"next_page":null,"last_page":1,"total_entries":0}}}"#;
        let (api, requests) =
            hcloud_cleanup_mock_server(empty_inventory.to_string(), "204 No Content", "").await;
        let (state, files) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4252");
        std::fs::write(files.as_ref(), "rotated-test-hcloud-token")
            .expect("rotate credential fixture");

        let failure = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect_err("rotated credential cannot prove absence in the original project");
        assert_eq!(failure.error, ProvisioningCleanupError::ProviderUnavailable);
        let recorded = requests.lock().expect("hcloud requests");
        assert_eq!(recorded.len(), 1);
        assert!(!recorded.iter().any(|request| request.method == "DELETE"));
    }

    #[tokio::test]
    async fn hetzner_cleanup_uncertain_results_remain_recoverable() {
        for (status, body) in [
            ("500 Internal Server Error", r#"{"error":"temporary"}"#),
            ("200 OK", r#"{"unexpected":true}"#),
        ] {
            let (api, requests) =
                hcloud_cleanup_mock_server(owned_cleanup_inventory("4244"), status, body).await;
            let (state, token_path) = test_hcloud_state(api);
            let job = tracked_hcloud_cleanup_job(&state, "4244");
            let failure = execute_hetzner_cleanup_job(&state, job)
                .await
                .expect_err("uncertain response fails closed");

            assert_eq!(failure.error, ProvisioningCleanupError::ProviderUncertain);
            let persisted = failure.job.expect("cleanup-needed job returned");
            assert_eq!(persisted.state, ProvisioningJobState::CleanupNeeded);
            assert_eq!(persisted.provider_resources[0].state, "created");
            assert!(persisted
                .progress
                .last()
                .expect("safe recovery progress")
                .message
                .contains("deletion was not proven"));
            let recorded = requests.lock().expect("hcloud requests");
            assert_eq!(recorded.len(), 5);
            assert_eq!(
                recorded
                    .iter()
                    .filter(|request| request.method == "DELETE")
                    .count(),
                1
            );
            let json = serde_json::to_string(&persisted).expect("job serializes");
            assert!(!json.contains("test-hcloud-token"));
            assert!(!json.to_ascii_lowercase().contains("bearer "));
            assert!(!json.to_ascii_lowercase().contains("token="));
            let _ = std::fs::remove_file(token_path);
        }

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("reserve unavailable provider address");
        let address = listener.local_addr().expect("provider address");
        drop(listener);
        let (state, token_path) = test_hcloud_state(format!("http://{address}"));
        let job = tracked_hcloud_cleanup_job(&state, "4245");
        let failure = execute_hetzner_cleanup_job(&state, job)
            .await
            .expect_err("network uncertainty fails closed");
        assert_eq!(failure.error, ProvisioningCleanupError::ProviderUnavailable);
        assert_eq!(
            failure.job.expect("persisted job").state,
            ProvisioningJobState::WaitingForHeartbeat
        );
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn hetzner_cleanup_rejects_ambiguous_or_disabled_jobs_without_request() {
        let (api, requests) = hcloud_mock_server("204 No Content", "", true).await;
        let (mut state, token_path) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4246");
        state.provider_runtime.hetzner_cloud.execute_enabled = false;
        let disabled = execute_hetzner_cleanup_job(&state, job.clone())
            .await
            .expect_err("disabled runtime fails closed");
        assert_eq!(disabled.error, ProvisioningCleanupError::RuntimeDisabled);
        assert!(requests.lock().expect("hcloud requests").is_empty());

        state.provider_runtime.hetzner_cloud.execute_enabled = true;
        let second = ProvisioningProviderResource {
            provider_id: "4248".to_string(),
            name: "unexpected-second-server".to_string(),
            ..job.provider_resources[0].clone()
        };
        let mut ambiguous = job.clone();
        ambiguous.provider_resources.push(second);
        let failure = execute_hetzner_cleanup_job(&state, ambiguous)
            .await
            .expect_err("ambiguous resources fail closed");
        assert_eq!(failure.error, ProvisioningCleanupError::ResourceAmbiguous);
        assert!(requests.lock().expect("hcloud requests").is_empty());

        let mut invalid = job.clone();
        invalid.provider_resources[0].provider_id = "not-a-number".to_string();
        let failure = execute_hetzner_cleanup_job(&state, invalid)
            .await
            .expect_err("non-numeric provider id fails closed");
        assert_eq!(failure.error, ProvisioningCleanupError::ResourceInvalid);

        let mut unproven_deleted = job;
        unproven_deleted.provider_resources[0].state = "deleted".to_string();
        let failure = execute_hetzner_cleanup_job(&state, unproven_deleted)
            .await
            .expect_err("unproven deleted state fails closed");
        assert_eq!(failure.error, ProvisioningCleanupError::ResourceInvalid);
        assert!(requests.lock().expect("hcloud requests").is_empty());
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn cleanup_endpoint_requires_explicit_confirmation() {
        let state = report_test_state(false);
        let response = cleanup_provisioning_job(
            State(state),
            HeaderMap::new(),
            AxumPath("missing-job".to_string()),
            Json(ProvisioningCleanupRequest { confirm: false }),
        )
        .await
        .into_response();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn cleanup_endpoint_rejects_open_mode_before_provider_delete() {
        let (api, requests) = hcloud_mock_server("204 No Content", "", true).await;
        let (state, token_path) = test_hcloud_state(api);
        let job = tracked_hcloud_cleanup_job(&state, "4250");
        let response = cleanup_provisioning_job(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(job.id.clone()),
            Json(ProvisioningCleanupRequest { confirm: true }),
        )
        .await
        .into_response();

        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let persisted = state
            .provisioning_jobs
            .get(&job.id)
            .expect("cleanup endpoint persists job");
        assert_eq!(persisted.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(persisted.terminal_outcome, None);
        assert_eq!(persisted.provider_resources[0].state, "created");
        assert!(requests.lock().expect("hcloud requests").is_empty());
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn paid_plan_can_attach_confirm_claim_start_and_complete() {
        let path = provisioning_store_test_path("paid-success");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_000_100;
        let job = start_hcloud_review_job(&store, "hcloud-paid-success", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let operator_ref = "b".repeat(64);

        let attached = store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("exact review attaches");
        assert_eq!(
            attached
                .reviewed_plan
                .as_ref()
                .map(|plan| plan.plan_sha256.as_str()),
            Some(plan_sha256.as_str())
        );

        let confirmed = store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("exact review confirms");
        assert_eq!(
            confirmed
                .paid_authorization
                .as_ref()
                .map(|authorization| authorization.operator_ref.as_str()),
            Some(operator_ref.as_str())
        );

        let claimed = store
            .claim_paid_execution(&job.id, &plan_sha256, &operator_ref, created_at + 3)
            .expect("authorized execution claims");
        assert_eq!(claimed.state, ProvisioningJobState::Provisioning);
        assert_eq!(
            claimed
                .paid_execution
                .as_ref()
                .map(|execution| execution.state.as_str()),
            Some("claimed")
        );

        let started = store
            .mark_paid_request_started(&job.id, &plan_sha256, created_at + 4)
            .expect("provider request marker persists");
        assert_eq!(
            started
                .paid_execution
                .as_ref()
                .and_then(|execution| execution.provider_request_started_at),
            Some(created_at + 4)
        );

        let resource = test_paid_resource("hcloud-paid-success", "4242");
        let handoff = hetzner_bootstrap_handoff(&resource).expect("bootstrap handoff");
        let complete = store
            .complete_paid_create(
                &job.id,
                &plan_sha256,
                resource,
                Some(handoff),
                false,
                created_at + 5,
            )
            .expect("known provider result completes");

        assert_eq!(complete.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(complete.provider_resources[0].provider_id, "4242");
        assert_eq!(
            complete
                .paid_execution
                .as_ref()
                .map(|execution| (execution.state.as_str(), execution.provider_id.as_deref())),
            Some(("created", Some("4242")))
        );
        assert_eq!(store.get(&job.id), Some(complete));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn managed_bootstrap_requires_attested_host_key_and_one_bounded_claim() {
        let path = provisioning_store_test_path("managed-bootstrap-claim");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_010_000;
        let job = managed_hcloud_created_job(&store, "managed-bootstrap-test", "5101", created_at);
        let identity = job.managed_identity.as_ref().expect("managed identity");
        assert_eq!(
            identity.state,
            ProvisioningManagedIdentityState::AwaitingHostKey
        );
        assert_eq!(identity.credential_ready_at, None);
        assert_eq!(
            store.claim_managed_provisioning("csb1", created_at + 6),
            Ok(None)
        );
        assert_eq!(
            store.attest_managed_host_key(
                &job.id,
                "not-a-fingerprint",
                &"a".repeat(64),
                created_at + 7,
            ),
            Err(ProvisioningAgentStoreError::InvalidContract)
        );
        let fingerprint = format!("SHA256:{}", "A".repeat(43));
        let attested = store
            .attest_managed_host_key(&job.id, &fingerprint, &"a".repeat(64), created_at + 8)
            .expect("public fingerprint attests");
        assert_eq!(
            attested.managed_identity.as_ref().map(|value| value.state),
            Some(ProvisioningManagedIdentityState::Ready)
        );
        let lease = store
            .claim_managed_provisioning("csb1", created_at + 9)
            .expect("claim persists")
            .expect("bootstrap lease");
        assert_eq!(lease.action, ProvisioningAgentAction::Bootstrap);
        assert_eq!(
            lease.host_key_fingerprint.as_deref(),
            Some(fingerprint.as_str())
        );
        assert_eq!(lease.lease_until - (created_at + 9), 2 * 60 * 60);
        assert_eq!(
            store.claim_managed_provisioning("csb1", created_at + 10),
            Ok(None)
        );
        let json = serde_json::to_string(&lease).expect("lease serializes");
        assert!(!json.to_ascii_lowercase().contains("private"));
        assert!(!json.to_ascii_lowercase().contains("bearer"));
        remove_provisioning_store_test_files(&path);
    }

    #[test]
    fn managed_bootstrap_known_failure_retries_but_expired_claim_never_replays() {
        let path = provisioning_store_test_path("managed-bootstrap-retry");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_020_000;
        let job = managed_hcloud_created_job(&store, "managed-retry-test", "5102", created_at);
        let fingerprint = format!("SHA256:{}", "B".repeat(43));
        store
            .attest_managed_host_key(&job.id, &fingerprint, &"a".repeat(64), created_at + 6)
            .expect("fingerprint attests");
        store
            .claim_managed_provisioning("csb1", created_at + 7)
            .expect("claim persists")
            .expect("bootstrap lease");
        let failed = store
            .record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-retry-test".to_string(),
                    action: ProvisioningAgentAction::Bootstrap,
                    outcome: ProvisioningAgentOutcome::Failed,
                    credential_created: false,
                    reason: Some(ProvisioningManagedFailure::SshUnreachable),
                },
                created_at + 8,
            )
            .expect("known failure persists");
        assert_eq!(failed.state, ProvisioningJobState::CleanupNeeded);
        assert_eq!(
            failed.managed_identity.as_ref().map(|value| value.state),
            Some(ProvisioningManagedIdentityState::RetryRequired)
        );
        store
            .retry_managed_bootstrap(&job.id, created_at + 9)
            .expect("attended bounded retry queues");
        store
            .claim_managed_provisioning("csb1", created_at + 10)
            .expect("retry claim persists")
            .expect("retry bootstrap lease");
        assert_eq!(
            store.claim_managed_provisioning("csb1", created_at + 10 + 2 * 60 * 60,),
            Ok(None)
        );
        let uncertain = store.get(&job.id).expect("uncertain job remains");
        assert_eq!(uncertain.state, ProvisioningJobState::CleanupNeeded);
        assert_eq!(
            uncertain.managed_identity.as_ref().map(|value| value.state),
            Some(ProvisioningManagedIdentityState::Uncertain)
        );
        assert_eq!(
            store.retry_managed_bootstrap(&job.id, created_at + 20_000),
            Err(ProvisioningAgentStoreError::InvalidTransition)
        );
        let reconciliation = store
            .queue_managed_bootstrap_reconciliation(&job.id, created_at + 20_001)
            .expect("attended read-only reconciliation queues");
        assert_eq!(
            reconciliation
                .managed_identity
                .as_ref()
                .map(|value| value.state),
            Some(ProvisioningManagedIdentityState::ReconciliationPending)
        );
        let reconciliation_lease = store
            .claim_managed_provisioning("csb1", created_at + 20_002)
            .expect("reconciliation claim persists")
            .expect("reconciliation lease");
        assert_eq!(
            reconciliation_lease.action,
            ProvisioningAgentAction::ReconcileBootstrap
        );
        assert_eq!(
            store
                .get(&job.id)
                .and_then(|value| value.managed_identity)
                .and_then(|value| value.last_failure),
            Some(ProvisioningManagedFailure::UncertainExecution)
        );
        assert_eq!(
            store.record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-retry-test".to_string(),
                    action: ProvisioningAgentAction::ReconcileBootstrap,
                    outcome: ProvisioningAgentOutcome::Succeeded,
                    credential_created: true,
                    reason: None,
                },
                created_at + 20_003,
            ),
            Err(ProvisioningAgentStoreError::InvalidContract)
        );
        let reconciled = store
            .record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-retry-test".to_string(),
                    action: ProvisioningAgentAction::ReconcileBootstrap,
                    outcome: ProvisioningAgentOutcome::Succeeded,
                    credential_created: false,
                    reason: None,
                },
                created_at + 20_003,
            )
            .expect("read-only reconciliation result persists");
        assert_eq!(reconciled.state, ProvisioningJobState::CleanupNeeded);
        assert_eq!(
            reconciled
                .managed_identity
                .as_ref()
                .map(|value| value.state),
            Some(ProvisioningManagedIdentityState::RetryRequired)
        );
        assert_eq!(
            reconciled
                .managed_identity
                .as_ref()
                .and_then(|value| value.last_failure),
            Some(ProvisioningManagedFailure::UncertainExecution)
        );
        store
            .retry_managed_bootstrap(&job.id, created_at + 20_004)
            .expect("reconciled bootstrap queues one bounded retry");
        remove_provisioning_store_test_files(&path);
    }

    #[test]
    fn managed_bootstrap_reconciliation_expiry_stays_fail_closed() {
        let path = provisioning_store_test_path("managed-bootstrap-reconciliation-expiry");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_025_000;
        let job =
            managed_hcloud_created_job(&store, "managed-reconcile-expiry", "5104", created_at);
        let fingerprint = format!("SHA256:{}", "C".repeat(43));
        store
            .attest_managed_host_key(&job.id, &fingerprint, &"a".repeat(64), created_at + 6)
            .expect("fingerprint attests");
        store
            .claim_managed_provisioning("csb1", created_at + 7)
            .expect("bootstrap claim persists")
            .expect("bootstrap lease");
        store
            .record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-reconcile-expiry".to_string(),
                    action: ProvisioningAgentAction::Bootstrap,
                    outcome: ProvisioningAgentOutcome::Uncertain,
                    credential_created: false,
                    reason: Some(ProvisioningManagedFailure::UncertainExecution),
                },
                created_at + 8,
            )
            .expect("uncertain result persists");
        store
            .queue_managed_bootstrap_reconciliation(&job.id, created_at + 9)
            .expect("reconciliation queues");
        store
            .claim_managed_provisioning("csb1", created_at + 10)
            .expect("reconciliation claim persists")
            .expect("reconciliation lease");
        assert_eq!(
            store.claim_managed_provisioning("csb1", created_at + 10 + 2 * 60 * 60,),
            Ok(None)
        );
        let expired = store.get(&job.id).expect("expired reconciliation remains");
        assert_eq!(expired.state, ProvisioningJobState::CleanupNeeded);
        assert_eq!(
            expired.managed_identity.as_ref().map(|value| (
                value.state,
                value.lease_until,
                value.last_failure
            )),
            Some((
                ProvisioningManagedIdentityState::Uncertain,
                None,
                Some(ProvisioningManagedFailure::UncertainExecution),
            ))
        );
        assert_eq!(
            store.retry_managed_bootstrap(&job.id, created_at + 4_000),
            Err(ProvisioningAgentStoreError::InvalidTransition)
        );
        remove_provisioning_store_test_files(&path);
    }

    #[tokio::test]
    async fn managed_cleanup_retires_exact_identity_before_terminal_rollback() {
        let inventory = json!({
            "servers": [{
                "id": 5103,
                "name": "managed-cleanup-test",
                "labels": paid_required_labels("setup-1700030000-1", "test-project")
            }],
            "meta": {"pagination": {
                "page": 1,
                "next_page": null,
                "last_page": 1,
                "total_entries": 1
            }}
        })
        .to_string();
        let (api, requests) = hcloud_cleanup_mock_server(inventory, "204 No Content", "").await;
        let (state, _files) = test_hcloud_state(api);
        let created_at = 1_700_030_000;
        let job = managed_hcloud_created_job(
            &state.provisioning_jobs,
            "managed-cleanup-test",
            "5103",
            created_at,
        );
        let fingerprint = format!("SHA256:{}", "C".repeat(43));
        state
            .provisioning_jobs
            .attest_managed_host_key(&job.id, &fingerprint, &"a".repeat(64), created_at + 6)
            .expect("fingerprint attests");
        state
            .provisioning_jobs
            .claim_managed_provisioning("csb1", created_at + 7)
            .expect("bootstrap claim persists")
            .expect("bootstrap lease");
        state
            .provisioning_jobs
            .record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-cleanup-test".to_string(),
                    action: ProvisioningAgentAction::Bootstrap,
                    outcome: ProvisioningAgentOutcome::Succeeded,
                    credential_created: true,
                    reason: None,
                },
                created_at + 8,
            )
            .expect("bootstrap completion persists");
        state
            .provisioning_jobs
            .record_managed_first_heartbeat(
                &job.id,
                ProvisioningJobState::Complete,
                "Authenticated ownership proof recorded.",
                created_at + 9,
                created_at + 9,
            )
            .expect("first authenticated heartbeat binds ownership");

        let current = state
            .provisioning_jobs
            .get(&job.id)
            .expect("managed job remains");
        let (deleted, already_absent) = execute_hetzner_cleanup_job(&state, current)
            .await
            .expect("provider deletion is proven");
        assert!(!already_absent);
        assert_eq!(deleted.state, ProvisioningJobState::CleanupNeeded);
        assert_eq!(deleted.provider_resources[0].state, "deleted");
        assert_eq!(
            deleted.managed_identity.as_ref().map(|value| value.state),
            Some(ProvisioningManagedIdentityState::RetirementPending)
        );
        let (idempotent, already_absent) = execute_hetzner_cleanup_job(&state, deleted.clone())
            .await
            .expect("deleted cleanup is idempotent");
        assert!(already_absent);
        assert_eq!(idempotent, deleted);

        let retirement = state
            .provisioning_jobs
            .claim_managed_provisioning("csb1", created_at + 10)
            .expect("retirement claim persists")
            .expect("retirement lease");
        assert_eq!(retirement.action, ProvisioningAgentAction::Retire);
        state
            .provisioning_jobs
            .record_managed_provisioning_result(
                &job.id,
                &ProvisioningAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "managed-cleanup-test".to_string(),
                    action: ProvisioningAgentAction::Retire,
                    outcome: ProvisioningAgentOutcome::Succeeded,
                    credential_created: false,
                    reason: None,
                },
                created_at + 11,
            )
            .expect("exact credential retirement persists");
        let complete = state
            .provisioning_jobs
            .complete_managed_retirement(&job.id, created_at + 12)
            .expect("managed cleanup finishes");
        assert_eq!(complete.state, ProvisioningJobState::Complete);
        assert_eq!(
            complete.terminal_outcome,
            Some(ProvisioningTerminalOutcome::RolledBack)
        );
        assert_eq!(requests.lock().expect("provider requests").len(), 2);
    }

    #[test]
    fn an_already_started_paid_request_can_reconcile_after_authorization_expiry() {
        let path = provisioning_store_test_path("paid-expired-reconcile");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_000_500;
        let job = start_hcloud_review_job(&store, "hcloud-paid-reconcile", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let expires_at = reviewed.expires_at;
        let operator_ref = "b".repeat(64);
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("review confirms");
        store
            .claim_paid_execution(&job.id, &plan_sha256, &operator_ref, created_at + 3)
            .expect("execution claims");
        store
            .mark_paid_request_started(&job.id, &plan_sha256, created_at + 4)
            .expect("request marker persists");
        store
            .fail_paid_execution(
                &job.id,
                &plan_sha256,
                true,
                "Provider response was uncertain; reconcile by labels.".to_string(),
                created_at + 5,
            )
            .expect("uncertain result persists");

        let resource = test_paid_resource("hcloud-paid-reconcile", "4343");
        let handoff = hetzner_bootstrap_handoff(&resource).expect("bootstrap handoff");
        let reconciled = store
            .complete_paid_create(
                &job.id,
                &plan_sha256,
                resource,
                Some(handoff),
                true,
                expires_at + 100,
            )
            .expect("read-only reconciliation remains possible after expiry");
        assert_eq!(reconciled.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(
            reconciled
                .paid_execution
                .as_ref()
                .map(|execution| execution.state.as_str()),
            Some("reconciled")
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn another_fleet_operator_can_reconcile_but_cannot_send_the_claimed_request() {
        let path = provisioning_store_test_path("paid-recovery-operator");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_000_800;
        let job = start_hcloud_review_job(&store, "hcloud-operator-recovery", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let authorizing_operator = "b".repeat(64);
        let recovery_operator = "c".repeat(64);
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &authorizing_operator,
                "authorizing@example.test",
                created_at + 2,
            )
            .expect("review confirms");
        let claimed = store
            .claim_paid_execution(&job.id, &plan_sha256, &authorizing_operator, created_at + 3)
            .expect("execution claims");
        assert_eq!(
            validate_paid_job_binding(&claimed, &plan_sha256, &recovery_operator),
            Err(ProvisioningPaidStoreError::OperatorMismatch)
        );

        store
            .mark_paid_request_started(&job.id, &plan_sha256, created_at + 4)
            .expect("provider request boundary persists");
        let uncertain = store
            .fail_paid_execution(
                &job.id,
                &plan_sha256,
                true,
                "Provider result is uncertain; reconcile without replay.".to_string(),
                created_at + 5,
            )
            .expect("uncertain result persists");
        validate_paid_job_binding(&uncertain, &plan_sha256, &recovery_operator)
            .expect("another fully privileged operator may perform read-only recovery");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_plan_rejects_tampered_hash_expiry_and_wrong_operator() {
        let path = provisioning_store_test_path("paid-rejections");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_001_100;
        let job = start_hcloud_review_job(&store, "hcloud-paid-reject", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let expires_at = reviewed.expires_at;
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("exact review attaches");

        assert_eq!(
            store.confirm_paid_review(
                &job.id,
                &"f".repeat(64),
                &"b".repeat(64),
                "operator@example.test",
                created_at + 2,
            ),
            Err(ProvisioningPaidStoreError::PlanMismatch)
        );
        assert_eq!(
            store.confirm_paid_review(
                &job.id,
                &plan_sha256,
                &"b".repeat(64),
                "operator@example.test",
                expires_at,
            ),
            Err(ProvisioningPaidStoreError::Expired)
        );

        let operator_ref = "b".repeat(64);
        store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &operator_ref,
                "operator@example.test",
                created_at + 3,
            )
            .expect("valid operator confirms before expiry");
        assert_eq!(
            store.confirm_paid_review(
                &job.id,
                &plan_sha256,
                &"c".repeat(64),
                "different@example.test",
                created_at + 4,
            ),
            Err(ProvisioningPaidStoreError::OperatorMismatch)
        );
        let wrong_operator_claim =
            store.claim_paid_execution(&job.id, &plan_sha256, &"c".repeat(64), created_at + 4);
        assert_eq!(
            wrong_operator_claim,
            Err(ProvisioningPaidStoreError::OperatorMismatch)
        );
        assert!(store
            .get(&job.id)
            .expect("rejected plan remains stored")
            .paid_execution
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_actions_require_a_valid_durable_snapshot() {
        let memory_only = ProvisioningJobStore::new(None);
        assert!(!memory_only.durable_ready());
        assert_eq!(
            memory_only.start(
                &hcloud_review_request("hcloud-memory-only"),
                1_700_001_500,
                &test_hcloud_store_runtime(),
            ),
            Err(ProvisioningJobStartError::PersistenceFailed)
        );

        let malformed_path = provisioning_store_test_path("paid-malformed-snapshot");
        std::fs::write(&malformed_path, b"{not-json").expect("write malformed snapshot");
        let malformed = ProvisioningJobStore::new(Some(malformed_path.clone()));
        assert!(!malformed.durable_ready());
        assert_eq!(
            malformed.start(
                &hcloud_review_request("hcloud-malformed-store"),
                1_700_001_501,
                &test_hcloud_store_runtime(),
            ),
            Err(ProvisioningJobStartError::PersistenceFailed)
        );
        let _ = std::fs::remove_file(malformed_path);

        let tampered_path = provisioning_store_test_path("paid-tampered-snapshot");
        let store = ProvisioningJobStore::new(Some(tampered_path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-tampered-store", 1_700_001_600);
        let reviewed = test_reviewed_paid_plan(&job);
        store
            .attach_paid_review(&job.id, reviewed, 1_700_001_601)
            .expect("valid review persists");
        let mut snapshot: serde_json::Value = serde_json::from_slice(
            &std::fs::read(&tampered_path).expect("read persisted snapshot"),
        )
        .expect("snapshot JSON");
        snapshot["jobs"][0]["reviewed_plan"]["server_name"] = json!("changed-after-review");
        std::fs::write(
            &tampered_path,
            serde_json::to_vec_pretty(&snapshot).expect("encode tampered snapshot"),
        )
        .expect("write tampered snapshot");
        let tampered = ProvisioningJobStore::new(Some(tampered_path.clone()));
        assert!(!tampered.durable_ready());
        assert!(tampered.list().is_empty());
        remove_provisioning_store_test_files(&tampered_path);

        let replaced_path = provisioning_store_test_path("paid-replaced-snapshot");
        let store = ProvisioningJobStore::new(Some(replaced_path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-replaced-store", 1_700_001_700);
        let reviewed = test_reviewed_paid_plan(&job);
        store
            .attach_paid_review(&job.id, reviewed, 1_700_001_701)
            .expect("valid review persists");
        drop(store);
        std::fs::write(&replaced_path, b"[]").expect("replace snapshot with valid empty JSON");
        let replaced = ProvisioningJobStore::new(Some(replaced_path.clone()));
        assert!(!replaced.durable_ready());
        assert!(replaced.list().is_empty());
        remove_provisioning_store_test_files(&replaced_path);

        let missing_path = provisioning_store_test_path("paid-missing-after-init");
        let initialized = ProvisioningJobStore::new(Some(missing_path.clone()));
        assert!(initialized.durable_ready());
        drop(initialized);
        std::fs::remove_file(&missing_path).expect("remove initialized snapshot");
        let missing = ProvisioningJobStore::new(Some(missing_path.clone()));
        assert!(!missing.durable_ready());
        remove_provisioning_store_test_files(&missing_path);
    }

    #[test]
    fn unresolved_paid_attempt_reserves_the_project_across_reload() {
        let path = provisioning_store_test_path("paid-project-reservation");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let operator_ref = "b".repeat(64);

        let first = start_hcloud_review_job(&store, "hcloud-first-attempt", 1_700_001_700);
        let first_plan = test_reviewed_paid_plan(&first);
        let first_digest = first_plan.plan_sha256.clone();
        store
            .attach_paid_review(&first.id, first_plan, 1_700_001_701)
            .expect("first review attaches");
        store
            .confirm_paid_review(
                &first.id,
                &first_digest,
                &operator_ref,
                "operator@example.test",
                1_700_001_702,
            )
            .expect("first review confirms");

        let second = start_hcloud_review_job(&store, "hcloud-second-attempt", 1_700_001_703);
        let second_plan = test_reviewed_paid_plan(&second);
        let second_digest = second_plan.plan_sha256.clone();
        store
            .attach_paid_review(&second.id, second_plan, 1_700_001_704)
            .expect("second review can exist before either claim");
        store
            .confirm_paid_review(
                &second.id,
                &second_digest,
                &operator_ref,
                "operator@example.test",
                1_700_001_705,
            )
            .expect("second review confirms");

        store
            .claim_paid_execution(&first.id, &first_digest, &operator_ref, 1_700_001_706)
            .expect("first attempt claims project");
        store
            .mark_paid_request_started(&first.id, &first_digest, 1_700_001_707)
            .expect("first request boundary persists");
        store
            .fail_paid_execution(
                &first.id,
                &first_digest,
                true,
                "Provider result is uncertain; do not replay.".to_string(),
                1_700_001_708,
            )
            .expect("uncertain reservation persists");

        let reloaded = ProvisioningJobStore::new(Some(path.clone()));
        assert!(reloaded.durable_ready());
        assert!(reloaded.paid_project_blocked(None));
        assert_eq!(
            reloaded
                .claim_paid_execution(&second.id, &second_digest, &operator_ref, 1_700_001_709,),
            Err(ProvisioningPaidStoreError::ProjectBusy)
        );
        assert!(reloaded
            .get(&second.id)
            .expect("second review remains")
            .paid_execution
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn malformed_successful_create_response_remains_uncertain() {
        let response_body = r#"{"server":{"id":0,"name":"hcloud-partial-success","labels":{"managed-by":"pharos","pharos-setup":"tracked-job","pharos-owner":"75c84d20a0aa90c5","pharos-job":"setup-1700001800-1","pharos-attempt":"setup-1700001800-1-1"}}}"#;
        let (api, requests) = hcloud_mock_server("201 Created", response_body, true).await;
        let (state, token_path) = test_hcloud_state(api);
        let job = start_hcloud_review_job(
            &state.provisioning_jobs,
            "hcloud-partial-success",
            1_700_001_800,
        );
        let mut plan = test_reviewed_paid_plan(&job);
        plan.expires_at = now_unix() + 60;
        let operation =
            HetznerOperationContext::resolve(state.provider_runtime.hetzner_cloud.clone())
                .expect("operation credential resolves");
        let prerequisites = resolve_hetzner_create_prerequisites(&plan, &operation)
            .await
            .expect("prerequisites resolve");
        let error = send_hetzner_create(&plan, prerequisites, &operation)
            .await
            .expect_err("zero provider identity is not a successful create");
        assert!(error.resource_state_uncertain());
        assert_eq!(requests.lock().expect("hcloud requests").len(), 4);
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn request_start_boundary_rechecks_authorization_expiry() {
        let path = provisioning_store_test_path("paid-boundary-expiry");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let created_at = 1_700_001_900;
        let job = start_hcloud_review_job(&store, "hcloud-expiry-boundary", created_at);
        let plan = test_reviewed_paid_plan(&job);
        let digest = plan.plan_sha256.clone();
        let expires_at = plan.expires_at;
        let operator_ref = "b".repeat(64);
        store
            .attach_paid_review(&job.id, plan, created_at + 1)
            .expect("review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &digest,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("review confirms");
        store
            .claim_paid_execution(&job.id, &digest, &operator_ref, expires_at - 1)
            .expect("claim before expiry persists");
        assert_eq!(
            store.mark_paid_request_started(&job.id, &digest, expires_at),
            Err(ProvisioningPaidStoreError::Expired)
        );
        assert_eq!(
            store
                .get(&job.id)
                .and_then(|job| job.paid_execution)
                .map(|execution| execution.state),
            Some("claimed".to_string())
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_claim_and_request_started_marker_survive_reload() {
        let path = provisioning_store_test_path("paid-reload");
        let created_at = 1_700_002_100;
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-paid-reload", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let operator_ref = "b".repeat(64);
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("exact review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("exact review confirms");
        store
            .claim_paid_execution(&job.id, &plan_sha256, &operator_ref, created_at + 3)
            .expect("execution claim persists");
        drop(store);

        let reloaded = ProvisioningJobStore::new(Some(path.clone()));
        let claimed = reloaded.get(&job.id).expect("claimed job reloads");
        assert_eq!(
            claimed
                .paid_execution
                .as_ref()
                .map(|execution| execution.state.as_str()),
            Some("claimed")
        );
        assert!(claimed
            .paid_execution
            .as_ref()
            .expect("claim")
            .provider_request_started_at
            .is_none());
        reloaded
            .mark_paid_request_started(&job.id, &plan_sha256, created_at + 4)
            .expect("request-started marker persists");
        drop(reloaded);

        let reloaded = ProvisioningJobStore::new(Some(path.clone()));
        let started = reloaded.get(&job.id).expect("started job reloads");
        assert_eq!(
            started
                .paid_execution
                .as_ref()
                .map(|execution| execution.state.as_str()),
            Some("request-started")
        );
        assert_eq!(
            started
                .paid_execution
                .as_ref()
                .and_then(|execution| execution.provider_request_started_at),
            Some(created_at + 4)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn paid_claim_rolls_back_when_persistence_fails() {
        let obstruction = provisioning_store_test_path("paid-persistence-obstruction");
        std::fs::create_dir_all(&obstruction).expect("test store directory");
        let path = obstruction.join("jobs.json");
        let created_at = 1_700_003_100;
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let job = start_hcloud_review_job(&store, "hcloud-paid-persist", created_at);
        let reviewed = test_reviewed_paid_plan(&job);
        let plan_sha256 = reviewed.plan_sha256.clone();
        let operator_ref = "b".repeat(64);
        store
            .attach_paid_review(&job.id, reviewed, created_at + 1)
            .expect("exact review attaches");
        store
            .confirm_paid_review(
                &job.id,
                &plan_sha256,
                &operator_ref,
                "operator@example.test",
                created_at + 2,
            )
            .expect("exact review confirms");

        std::fs::remove_file(&path).expect("remove persisted snapshot");
        std::fs::remove_file(provisioning_job_store_marker_path(&path))
            .expect("remove persistence marker");
        std::fs::remove_dir(&obstruction).expect("remove store directory");
        std::fs::write(&obstruction, b"not a directory").expect("obstruct persistence path");

        assert_eq!(
            store.claim_paid_execution(&job.id, &plan_sha256, &operator_ref, created_at + 3),
            Err(ProvisioningPaidStoreError::PersistenceFailed)
        );
        let unchanged = store.get(&job.id).expect("confirmed job remains in memory");
        assert_eq!(unchanged.state, ProvisioningJobState::Planning);
        assert!(unchanged.paid_authorization.is_some());
        assert!(unchanged.paid_execution.is_none());
        let _ = std::fs::remove_file(obstruction);
    }

    fn setup_runtime_host(name: &str, backup_observations: Vec<BackupObservation>) -> Host {
        Host {
            name: name.to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1_700_000_020),
            heartbeat_log: vec![1_700_000_020],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness::default(),
            kernel: None,
            service_observations: vec![],
            backup_observations,
            preferences: Default::default(),
            requested_preferences: None,
        }
    }

    #[test]
    fn setup_jobs_reconcile_first_heartbeat_to_backup_pending_and_complete() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("reconcile-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::EnrollLater),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };
        let job = store
            .start(&request, 1_700_000_010, &ProviderRuntimeConfig::default())
            .expect("setup job starts");
        assert_eq!(job.state, ProvisioningJobState::WaitingForHeartbeat);

        reconcile_provisioning_jobs_with_runtime(
            &store,
            &[setup_runtime_host("reconcile-1", vec![])],
            1_700_000_020,
        );
        assert_eq!(
            store.get(&job.id).expect("job persisted").state,
            ProvisioningJobState::BackupPending
        );

        reconcile_provisioning_jobs_with_runtime(
            &store,
            &[setup_runtime_host(
                "reconcile-1",
                vec![backup_observation(BackupPostureState::Healthy)],
            )],
            1_700_000_030,
        );
        assert_eq!(
            store.get(&job.id).expect("job persisted").state,
            ProvisioningJobState::Complete
        );
    }

    #[test]
    fn setup_job_does_not_accept_a_heartbeat_older_than_the_wait_state() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("reconcile-stale".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::External),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };
        let job = store
            .start(&request, 1_700_000_100, &ProviderRuntimeConfig::default())
            .expect("setup job starts");
        let mut host = setup_runtime_host("reconcile-stale", vec![]);
        host.last_seen = Some(1_700_000_099);

        reconcile_provisioning_jobs_with_runtime(&store, &[host.clone()], 1_700_000_110);
        assert_eq!(
            store.get(&job.id).expect("job persisted").state,
            ProvisioningJobState::WaitingForHeartbeat
        );

        host.last_seen = Some(1_700_000_100);
        reconcile_provisioning_jobs_with_runtime(&store, &[host], 1_700_000_111);
        assert_eq!(
            store.get(&job.id).expect("job persisted").state,
            ProvisioningJobState::Complete
        );
    }

    #[test]
    fn authenticated_heartbeat_resolves_uncertain_native_install() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("reconcile-uncertain".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::External),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };
        let job = store
            .start(&request, 1_700_000_120, &ProviderRuntimeConfig::default())
            .expect("setup job starts");
        let uncertain = store
            .transition_existing_host(
                &job.id,
                ProvisioningJobState::CleanupNeeded,
                "Install result unknown; inspect the target before retrying.",
                "cleanup-needed",
                "Credential handoff may have completed; inspect the target.",
                1_700_000_125,
            )
            .expect("uncertain state persists");
        let mut host = setup_runtime_host("reconcile-uncertain", vec![]);
        host.last_seen = Some(1_700_000_126);

        reconcile_provisioning_jobs_with_runtime(&store, &[host], 1_700_000_127);

        let reconciled = store.get(&uncertain.id).expect("job persisted");
        assert_eq!(reconciled.state, ProvisioningJobState::Complete);
        assert!(reconciled
            .progress
            .last()
            .expect("progress")
            .message
            .contains("uncertain install result"));
    }

    #[test]
    fn setup_jobs_reconcile_external_backup_policy_to_complete() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("reconcile-2".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::External),
            location_intent: Some(LocationSetupIntent::SiteFallback),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };
        let job = store
            .start(&request, 1_700_000_011, &ProviderRuntimeConfig::default())
            .expect("setup job starts");

        reconcile_provisioning_jobs_with_runtime(
            &store,
            &[setup_runtime_host("reconcile-2", vec![])],
            1_700_000_021,
        );
        assert_eq!(
            store.get(&job.id).expect("job persisted").state,
            ProvisioningJobState::Complete
        );
    }

    #[test]
    fn provider_setup_job_persists_backup_intent_without_provider_apply() {
        let path = provisioning_store_test_path("provider-setup-intent");
        let store = ProvisioningJobStore::new(Some(path.clone()));
        let request = ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            apply: false,
            host_need_intent: None,
            host_name: Some("hcloud-lab-2".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Optional),
            location_intent: Some(LocationSetupIntent::Manual),
            access_intent: Some(AccessSetupIntent::AllOperators),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
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
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn existing_host_runtime_defaults_fail_closed() {
        let runtime = ExistingHostRuntimeConfig::default();

        assert!(!runtime.execute_enabled);
        assert_eq!(
            runtime.validate_native_systemd(),
            Err(ExistingHostExecutionError::RuntimeDisabled)
        );
    }

    #[cfg(unix)]
    #[test]
    fn existing_host_runtime_files_reject_symlinks_and_unsafe_modes() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let dir = std::env::temp_dir().join(format!(
            "pharos-existing-file-check-{}-{}",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("test directory");
        let trusted = dir.join("trusted");
        let linked = dir.join("linked");
        std::fs::write(&trusted, b"bounded-runtime-input").expect("trusted fixture");
        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o600))
            .expect("trusted permissions");
        symlink(&trusted, &linked).expect("symlink fixture");

        assert!(open_trusted_runtime_file(&trusted, 1024, 0o077, false).is_some());
        assert!(open_trusted_runtime_file(&linked, 1024, 0o077, false).is_none());

        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o620))
            .expect("broad permissions");
        assert!(open_trusted_runtime_file(&trusted, 1024, 0o077, false).is_none());

        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o600))
            .expect("non-executable permissions");
        assert!(open_trusted_runtime_file(&trusted, 1024, 0o022, true).is_none());
        std::fs::set_permissions(&trusted, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");
        assert!(open_trusted_runtime_file(&trusted, 1024, 0o022, true).is_some());

        std::fs::remove_file(linked).expect("remove symlink fixture");
        std::fs::remove_file(trusted).expect("remove file fixture");
        std::fs::remove_dir(dir).expect("remove test directory");
    }

    #[cfg(unix)]
    #[test]
    fn existing_host_runtime_files_reject_unexpected_owners_and_special_modes() {
        let effective_uid = unsafe { libc::geteuid() };
        let unexpected_uid = if effective_uid == 1000 { 1001 } else { 1000 };

        assert!(trusted_runtime_owner_and_mode(
            0,
            0o600,
            effective_uid,
            0o077,
            false
        ));
        assert!(trusted_runtime_owner_and_mode(
            effective_uid,
            0o700,
            effective_uid,
            0o022,
            true
        ));
        assert!(!trusted_runtime_owner_and_mode(
            unexpected_uid,
            0o600,
            effective_uid,
            0o077,
            false
        ));
        assert!(!trusted_runtime_owner_and_mode(
            effective_uid,
            0o4600,
            effective_uid,
            0o077,
            false
        ));
    }

    #[cfg(unix)]
    #[test]
    fn existing_host_child_runner_enforces_total_deadline() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 5"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let started = Instant::now();

        let error = run_child_with_deadline(&mut command, None, Duration::from_millis(100), 4096)
            .expect_err("the fixed deadline stops a hung child");

        assert_eq!(error, ExistingHostExecutionError::RemoteCommandTimedOut);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[cfg(unix)]
    #[test]
    fn existing_host_child_runner_deadline_covers_descendant_held_pipes() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "(sleep 5) & exit 0"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let error = run_child_with_deadline(&mut command, None, Duration::from_millis(100), 4096)
            .expect_err("a descendant cannot hold the output pipe past the deadline");

        assert_eq!(error, ExistingHostExecutionError::RemoteCommandTimedOut);
    }

    #[cfg(unix)]
    #[test]
    fn existing_host_child_runner_bounds_output_and_drains_stdin() {
        let mut echo_command = Command::new("/bin/sh");
        echo_command
            .args(["-c", "cat"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        let payload = b"bounded-input";
        assert_eq!(
            run_child_with_deadline(
                &mut echo_command,
                Some(payload),
                Duration::from_secs(1),
                4096
            )
            .expect("bounded input is drained concurrently"),
            payload
        );

        let mut noisy_command = Command::new("/bin/sh");
        noisy_command
            .args(["-c", "printf 123456789"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        assert_eq!(
            run_child_with_deadline(&mut noisy_command, None, Duration::from_secs(1), 4),
            Err(ExistingHostExecutionError::RemoteCommandFailed)
        );
    }

    #[test]
    fn native_systemd_target_fields_cannot_become_ssh_options() {
        assert!(!valid_ssh_endpoint("-oProxyCommand=unsafe"));
        assert!(!valid_ssh_user("-root"));
        assert!(!valid_bootstrap_name("-host"));
        assert!(valid_ssh_endpoint("host-01.example"));
        assert!(valid_ssh_user("bootstrap_user"));
        assert!(valid_bootstrap_name("host-01"));
    }

    #[test]
    fn native_systemd_bootstrap_keeps_raw_token_on_stdin_only() {
        let (runtime, dir) = test_existing_host_runtime();
        let spec = test_native_bootstrap_spec();
        let runner = FakeExistingHostSshRunner::new(test_ready_arch());
        let prepared = prepare_native_systemd_bootstrap(&runner, &runtime, &spec)
            .expect("target preparation succeeds");
        let token = "pharos_test_runtime_token";

        install_native_systemd_bootstrap(&runner, &runtime, &spec, &prepared, token)
            .expect("native install succeeds");

        let calls = runner.calls();
        assert!(calls.iter().all(|call| !call.command.contains(token)));
        let token_payload = format!("PHAROS_TOKEN={token}\n").into_bytes();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.stdin == token_payload)
                .count(),
            1
        );
        assert!(calls.iter().any(|call| {
            call.command == REMOTE_NATIVE_SYSTEMD_TOKEN_WRITE && call.stdin == token_payload
        }));
        assert!(calls.iter().any(|call| {
            call.command.contains("install-pharos-beacon-systemd.sh")
                && call
                    .command
                    .contains("--token-env /etc/pharos/pharos-beacon.env")
                && call.stdin.is_empty()
        }));
        cleanup_test_existing_host_runtime(&runtime, &dir);
    }

    #[test]
    fn native_systemd_bootstrap_refuses_implicit_token_rotation() {
        let (runtime, dir) = test_existing_host_runtime();
        let spec = test_native_bootstrap_spec();
        let runner = FakeExistingHostSshRunner::new("existing-token");

        let error = prepare_native_systemd_bootstrap(&runner, &runtime, &spec)
            .expect_err("existing token blocks preparation");

        assert_eq!(error, ExistingHostExecutionError::ExistingTokenFile);
        assert!(runner
            .calls()
            .iter()
            .all(|call| !String::from_utf8_lossy(&call.stdin).contains("PHAROS_TOKEN=")));
        cleanup_test_existing_host_runtime(&runtime, &dir);
    }

    #[test]
    fn native_systemd_bootstrap_refuses_mismatched_architecture() {
        let (runtime, dir) = test_existing_host_runtime();
        let spec = test_native_bootstrap_spec();
        let runner = FakeExistingHostSshRunner::new("ready:unsupported-arch");

        let error = prepare_native_systemd_bootstrap(&runner, &runtime, &spec)
            .expect_err("architecture mismatch blocks preparation");

        assert_eq!(error, ExistingHostExecutionError::ArchitectureMismatch);
        assert!(runner
            .calls()
            .iter()
            .all(|call| !String::from_utf8_lossy(&call.stdin).contains("PHAROS_TOKEN=")));
        cleanup_test_existing_host_runtime(&runtime, &dir);
    }

    #[test]
    fn existing_host_manual_path_waits_for_heartbeat_without_secrets() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "manual-deferred".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("legacy-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(120),
            backup_intent: Some(BackupSetupIntent::External),
            location_intent: Some(LocationSetupIntent::SiteFallback),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_005, &runtime)
            .expect("manual existing-host path records setup state");

        assert_eq!(job.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(job.host_name.as_deref(), Some("legacy-1"));
        assert_eq!(job.role.as_deref(), Some("server"));
        assert_eq!(job.is_nix, Some(false));
        assert_eq!(job.heartbeat_interval_secs, Some(120));
        let context = job.existing_host_context.as_ref().expect("manual context");
        assert_eq!(context.selected_bootstrap, BootstrapMethod::Manual);
        assert_eq!(context.ssh.route, SshRoute::None);
        assert!(context
            .verification_steps
            .iter()
            .any(|step| step.contains("legacy-1")));
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
        assert!(handoff
            .next_steps
            .iter()
            .any(|step| step.contains("120s heartbeat interval")));
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
    fn existing_host_automated_path_waits_for_runtime_credential_handoff() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "native-systemd".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("legacy-2".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::EnrollLater),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: Some(SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("root".to_string()),
                host: Some("legacy-2".to_string()),
                port: None,
            }),
            preflight_summary: Some(ExistingHostPreflightSummary {
                state: PreflightCheckState::Pass,
                label: "Ready for bootstrap".to_string(),
                message: "Existing host checks passed.".to_string(),
            }),
            preflight_checks: ready_existing_host_preflight_checks(),
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_006, &runtime)
            .expect("automated existing-host path records safe handoff");

        assert_eq!(job.state, ProvisioningJobState::WaitingForHeartbeat);
        assert_eq!(job.host_name.as_deref(), Some("legacy-2"));
        assert_eq!(job.role.as_deref(), Some("server"));
        assert_eq!(job.is_nix, Some(false));
        assert_eq!(job.heartbeat_interval_secs, Some(60));
        let context = job
            .existing_host_context
            .as_ref()
            .expect("existing-host context");
        assert_eq!(context.selected_bootstrap, BootstrapMethod::NativeSystemd);
        assert_eq!(context.ssh.route, SshRoute::Tailnet);
        assert_eq!(context.ssh.host.as_deref(), Some("legacy-2"));
        assert_eq!(
            context
                .preflight_summary
                .as_ref()
                .expect("preflight summary")
                .label,
            "Ready for bootstrap"
        );
        assert!(context
            .preflight_checks
            .iter()
            .any(|check| check.key == "ssh-reachability"));
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::EnrollLater);
        assert_eq!(setup_intent.location, LocationSetupIntent::Auto);
        let handoff = job.handoff.as_ref().expect("native handoff");
        assert_eq!(handoff.method, BootstrapMethod::NativeSystemd);
        assert_eq!(handoff.status, "runtime-credential-required");
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
            ProvisioningJobState::WaitingForHeartbeat
        );
        assert!(job
            .progress
            .last()
            .expect("progress entry")
            .message
            .contains("runtime credential handoff"));
        let json = serde_json::to_string(&job).expect("job serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn automated_existing_host_handoff_requires_ssh_target() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "native-systemd".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("missing-ssh".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Deferred),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: None,
            preflight_summary: None,
            preflight_checks: vec![],
        };

        let job = store
            .start(&request, 1_700_000_006, &ProviderRuntimeConfig::default())
            .expect("failed handoff is still tracked");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert!(job.handoff.is_none());
        assert!(job.existing_host_context.is_none());
        assert!(job
            .progress
            .last()
            .expect("progress")
            .message
            .contains("needs a non-secret SSH target"));
    }

    #[test]
    fn automated_existing_host_handoff_requires_completed_preflight() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "native-systemd".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("needs-preflight".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Deferred),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: Some(SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("root".to_string()),
                host: Some("needs-preflight".to_string()),
                port: None,
            }),
            preflight_summary: None,
            preflight_checks: vec![],
        };

        let job = store
            .start(&request, 1_700_000_006, &ProviderRuntimeConfig::default())
            .expect("failed handoff is still tracked");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert!(job.handoff.is_none());
        assert!(job.existing_host_context.is_some());
        assert!(job
            .progress
            .last()
            .expect("progress")
            .message
            .contains("needs a completed preflight"));
    }

    #[test]
    fn automated_existing_host_handoff_rejects_failed_preflight() {
        let store = ProvisioningJobStore::new(None);
        let mut checks = ready_existing_host_preflight_checks();
        let disk = checks
            .iter_mut()
            .find(|check| check.key == "disk-space")
            .expect("disk check");
        disk.state = PreflightCheckState::Fail;
        disk.message = "1 GiB free is too little for a safe bootstrap.".to_string();
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "native-systemd".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("failed-preflight".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(false),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Deferred),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: Some(SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("root".to_string()),
                host: Some("failed-preflight".to_string()),
                port: None,
            }),
            preflight_summary: Some(ExistingHostPreflightSummary {
                state: PreflightCheckState::Fail,
                label: "Needs attention".to_string(),
                message: "Fix failed checks before registering a beacon token.".to_string(),
            }),
            preflight_checks: checks,
        };

        let job = store
            .start(&request, 1_700_000_006, &ProviderRuntimeConfig::default())
            .expect("failed handoff is still tracked");

        assert_eq!(job.state, ProvisioningJobState::Failed);
        assert!(job.handoff.is_none());
        let context = job
            .existing_host_context
            .as_ref()
            .expect("failed preflight context");
        assert!(context
            .preflight_checks
            .iter()
            .any(|check| check.key == "disk-space" && check.state == PreflightCheckState::Fail));
        assert!(job
            .progress
            .last()
            .expect("progress")
            .message
            .contains("preflight has failed checks"));
    }

    #[test]
    fn nixos_existing_host_handoff_proposes_secret_safe_backup_config() {
        let store = ProvisioningJobStore::new(None);
        let request = ProvisioningJobStartRequest {
            provider: "existing-host".to_string(),
            template: "nixos-anywhere".to_string(),
            apply: true,
            host_need_intent: None,
            host_name: Some("nix-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            backup_intent: Some(BackupSetupIntent::Required),
            location_intent: Some(LocationSetupIntent::Auto),
            access_intent: Some(AccessSetupIntent::OperatorOnly),
            location: None,
            server_type: None,
            image: None,
            ssh_key_ref: None,
            ssh: Some(SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("root".to_string()),
                host: Some("nix-1".to_string()),
                port: None,
            }),
            preflight_summary: Some(ExistingHostPreflightSummary {
                state: PreflightCheckState::Pass,
                label: "Ready for bootstrap".to_string(),
                message: "Existing host checks passed.".to_string(),
            }),
            preflight_checks: ready_existing_host_preflight_checks(),
        };
        let runtime = ProviderRuntimeConfig::default();

        let job = store
            .start(&request, 1_700_000_007, &runtime)
            .expect("nixos existing-host handoff records setup state");

        assert_eq!(job.state, ProvisioningJobState::WaitingForHeartbeat);
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup, BackupSetupIntent::Required);
        let handoff = job.handoff.as_ref().expect("nixos handoff");
        assert_eq!(handoff.method, BootstrapMethod::NixosAnywhere);
        assert_eq!(handoff.status, "runtime-credential-required");
        assert_eq!(
            handoff.secret_target.as_deref(),
            Some("/etc/pharos/pharos-beacon.token")
        );
        assert_eq!(
            handoff.command_ref.as_deref(),
            Some("scripts/bootstrap-pharos-nixos-anywhere.sh")
        );
        assert!(handoff
            .token_policy
            .contains("never enter command arguments or the Nix store"));
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
            .any(|resource| resource.key == "firewall"
                && resource.required
                && resource.detail.contains("refuses to create")));
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
            .any(|handoff| handoff.key == "provider_executor"
                && handoff.target == "Hetzner Cloud executor"));
        let json = serde_json::to_string(&plan).expect("plan serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        assert_eq!(
            setup_provider_plan("hetzner-cloud", "manual-import").err(),
            Some(ProvisioningJobStartError::UnsupportedTemplate)
        );
    }

    fn ready_provider_connection_store(now: i64) -> ProviderConnectionStore {
        let store = ProviderConnectionStore::new(None).expect("in-memory provider store starts");
        let catalog = HetznerCatalog {
            refreshed_at: now,
            currency: "EUR".to_string(),
            locations: vec![HetznerLocation {
                name: "fsn1".to_string(),
                city: "Falkenstein".to_string(),
                country: "DE".to_string(),
                network_zone: "eu-central".to_string(),
            }],
            server_types: vec![HetznerServerType {
                name: "cx22".to_string(),
                description: "Shared vCPU".to_string(),
                category: "shared".to_string(),
                cores: 2,
                memory_gb: "4".to_string(),
                disk_gb: 40,
                architecture: "x86".to_string(),
                locations: vec![HetznerServerTypeLocation {
                    name: "fsn1".to_string(),
                    available: true,
                    recommended: true,
                    monthly_gross: Some("4.51".to_string()),
                    hourly_gross: Some("0.0071".to_string()),
                }],
            }],
            ssh_keys: vec!["pharos-bootstrap-key".to_string()],
            firewalls: vec!["pharos-bootstrap-firewall".to_string()],
        };
        store
            .record_test(HetznerConnectionTestResult {
                attempt: HetznerConnectionAttempt {
                    tested_at: now,
                    code: HetznerConnectionCode::Ready,
                    api_access: true,
                    credential_boundary_ready: true,
                    execution_enabled: true,
                    ssh_key_ready: true,
                    firewall_ready: true,
                    default_location_ready: true,
                    catalog_ready: true,
                },
                catalog: Some(catalog),
            })
            .expect("provider evidence persists");
        store
            .update_preferences(
                HetznerConnectionPreferences {
                    default_location: Some("fsn1".to_string()),
                    ssh_key_ref: Some("pharos-bootstrap-key".to_string()),
                    firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
                },
                now,
                60 * 60,
            )
            .expect("test provider preferences are valid");
        store
    }

    #[tokio::test]
    async fn provider_test_api_returns_unavailable_when_evidence_cannot_persist() {
        let path = std::env::temp_dir().join(format!(
            "pharos-provider-api-persistence-failure-{}-{}",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut state = report_test_state(true);
        state.provider_connections = Arc::new(
            ProviderConnectionStore::new(Some(path.clone()))
                .expect("durable provider store starts"),
        );
        std::fs::create_dir(&path).expect("rename-blocking destination created");

        let response = test_hetzner_provider_connection(State(state.clone()), action_headers())
            .await
            .into_response();

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(state.provider_connections.last_attempt().is_none());
        std::fs::remove_dir_all(path).expect("test destination removed");
    }

    #[test]
    fn human_provider_resource_names_remain_valid_through_paid_review() {
        assert!(valid_provider_resource_name("ops@workstation"));
        assert!(valid_provider_resource_name("Bootstrap firewall 2026"));
        assert!(!valid_provider_resource_name("line\nbreak"));

        let request = ProvisioningJobStartRequest {
            provider: "hetzner-cloud".to_string(),
            template: "nixos-pharos".to_string(),
            apply: false,
            host_need_intent: None,
            host_name: Some("lab-01".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: None,
            backup_intent: None,
            location_intent: None,
            access_intent: None,
            location: Some("fsn1".to_string()),
            server_type: Some("cx23".to_string()),
            image: Some("debian-12".to_string()),
            ssh_key_ref: Some("ops@workstation".to_string()),
            ssh: None,
            preflight_summary: None,
            preflight_checks: Vec::new(),
        };
        let runtime = HetznerCloudRuntimeConfig {
            firewall_ref: Some("Bootstrap firewall 2026".to_string()),
            ..HetznerCloudRuntimeConfig::default()
        };

        assert!(!invalid_hetzner_create_inputs(&request, &runtime));
    }

    #[test]
    fn hetzner_runtime_readiness_exposes_only_safe_capabilities() {
        let now = 1_700_000_000;
        let empty_store =
            ProviderConnectionStore::new(None).expect("in-memory provider store starts");
        let blocked =
            hetzner_runtime_readiness(&HetznerCloudRuntimeConfig::default(), &empty_store, now);
        assert!(!blocked.connection_ready);
        assert!(!blocked.provider_ready);
        assert!(!blocked.ready_with_defaults);
        assert!(blocked.message.contains("not connected"));

        let token_path = std::env::temp_dir().join(format!(
            "pharos-runtime-readiness-token-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::write(&token_path, "test-provider-token").expect("write provider token fixture");
        let runtime = HetznerCloudRuntimeConfig {
            credential_source: Some(ProviderCredentialSource::File(token_path.clone())),
            execute_enabled: true,
            project_label: Some("test-project".to_string()),
            default_ssh_key_ref: Some("pharos-bootstrap-key".to_string()),
            firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
            default_location: Some("fsn1".to_string()),
            ..HetznerCloudRuntimeConfig::default()
        };
        let untested = hetzner_runtime_readiness(&runtime, &empty_store, now);
        assert!(!untested.connection_ready);
        assert!(!untested.provider_ready);
        assert!(untested.message.contains("Test the connection"));

        let store = ready_provider_connection_store(now);
        let ready = hetzner_runtime_readiness(&runtime, &store, now);
        assert!(ready.connection_ready);
        assert!(ready.provider_ready);
        assert!(ready.ready_with_defaults);
        let json = serde_json::to_string(&ready).expect("runtime readiness serializes");
        assert!(!json.contains("pharos-bootstrap-key"));
        assert!(!json.contains("pharos-bootstrap-firewall"));
        assert!(!json.contains("test-provider-token"));
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn execution_disabled_provider_can_retest_without_unlocking_paid_work() {
        let now = now_unix();
        let token_path = std::env::temp_dir().join(format!(
            "pharos-disabled-provider-token-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::write(&token_path, "disabled-provider-token")
            .expect("write provider token fixture");
        let runtime = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File(token_path.clone())),
                execute_enabled: false,
                project_label: Some("test-project".to_string()),
                default_ssh_key_ref: Some("pharos-bootstrap-key".to_string()),
                firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
                default_location: Some("fsn1".to_string()),
                ..HetznerCloudRuntimeConfig::default()
            },
            ..ProviderRuntimeConfig::default()
        };
        let store = Arc::new(ready_provider_connection_store(now));

        let readiness = hetzner_runtime_readiness(&runtime.hetzner_cloud, &store, now);
        assert!(readiness.api_access);
        assert!(readiness.evidence_fresh);
        assert!(!readiness.execution_enabled);
        assert!(readiness.connection_ready);
        assert!(!readiness.provider_ready);
        assert!(!readiness.ready_with_defaults);
        assert_eq!(
            readiness.message,
            HetznerConnectionCode::ExecutionDisabled.safe_message()
        );
        let provider =
            provider_connection(&runtime, &store, "hetzner-cloud", now).expect("Hetzner provider");
        assert_eq!(provider.state, ProviderConnectionState::NeedsAttention);
        assert!(!provider.available_in_add_server);

        let mut state = report_test_state(false);
        state.provider_runtime = runtime.clone();
        state.provider_connections = store.clone();
        assert_eq!(
            guarded_hetzner_runtime(&state, &hcloud_review_request("disabled-review"), now)
                .expect_err("paid review stays disabled"),
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Managed Hetzner Cloud execution is disabled."
            )
        );

        let shell = ShellContext {
            user_label: "markus",
            logout_enabled: true,
        };
        let managed = render_hetzner_connection_page(&runtime, &store, shell, true, None);
        assert_eq!(managed.matches(r#" data-provider-test>"#).count(), 1);
        assert!(managed.contains("Test connection</button>"));
        assert!(managed.contains(r#"data-provider-ready="true""#));
        assert!(managed.contains("Provider setup complete"));
        assert!(managed.contains("installation-level activation step"));
        assert!(managed.contains(r#"class="provider-primary" href="/?setup=add-server"#));
        assert!(managed.contains("Continue to server assistant"));

        let viewer = render_hetzner_connection_page(&runtime, &store, shell, false, None);
        assert!(!viewer.contains(r#" data-provider-test>"#));
        assert!(!viewer.contains(r#"class="provider-primary" href="/?setup=add-server"#));
        assert!(viewer.contains("Ask a Pharos administrator"));
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn provider_setup_url_accepts_only_safe_public_bases() {
        let public = provider_setup_base_url("https://vault.barta.cm/")
            .expect("public HTTPS Janus URL is accepted");
        assert_eq!(public.host_str(), Some("vault.barta.cm"));
        assert!(provider_setup_base_url("http://127.0.0.1:8081").is_some());
        assert!(provider_setup_base_url("http://localhost:8081/").is_some());

        for unsafe_url in [
            "http://vault.barta.cm",
            "https://user@vault.barta.cm",
            "https://vault.barta.cm?token=value",
            "https://vault.barta.cm/#secret",
        ] {
            assert!(
                provider_setup_base_url(unsafe_url).is_none(),
                "unsafe Janus base URL must be rejected"
            );
        }
    }

    #[test]
    fn provider_catalog_is_small_honest_and_secret_free() {
        let store = ProviderConnectionStore::new(None).expect("in-memory provider store starts");
        let catalog =
            provider_connections(&ProviderRuntimeConfig::default(), &store, 1_700_000_000);
        assert_eq!(catalog.schema, PROVIDER_CONNECTIONS_SCHEMA);
        assert_eq!(catalog.providers.len(), 5);
        assert_eq!(
            catalog
                .providers
                .iter()
                .map(|provider| provider.key)
                .collect::<Vec<_>>(),
            vec![
                "hetzner-cloud",
                "netcup",
                "aws",
                "google-cloud",
                "oracle-cloud"
            ]
        );

        let hetzner = catalog
            .providers
            .iter()
            .find(|provider| provider.key == "hetzner-cloud")
            .expect("Hetzner connection");
        assert_eq!(hetzner.capability, ProviderConnectionCapability::Managed);
        assert_eq!(hetzner.state, ProviderConnectionState::NotConnected);
        assert!(!hetzner.available_in_add_server);
        assert!(catalog
            .providers
            .iter()
            .filter(|provider| provider.key != "hetzner-cloud")
            .all(
                |provider| provider.capability == ProviderConnectionCapability::Guided
                    && provider.state == ProviderConnectionState::Guided
                    && !provider.available_in_add_server
            ));

        let json = serde_json::to_string(&catalog).expect("catalog serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn provider_catalog_unlocks_hetzner_only_after_every_gate() {
        let token_path = std::env::temp_dir().join(format!(
            "pharos-provider-catalog-token-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::write(&token_path, "test-provider-token").expect("write provider token fixture");
        let runtime = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File(token_path.clone())),
                execute_enabled: true,
                project_label: Some("test-project".to_string()),
                default_ssh_key_ref: Some("pharos-bootstrap-key".to_string()),
                firewall_ref: Some("pharos-bootstrap-firewall".to_string()),
                default_location: Some("fsn1".to_string()),
                ..HetznerCloudRuntimeConfig::default()
            },
            ..ProviderRuntimeConfig::default()
        };
        let now = 1_700_000_000;
        let store = ready_provider_connection_store(now);
        let provider =
            provider_connection(&runtime, &store, "hetzner-cloud", now).expect("Hetzner provider");
        assert_eq!(provider.state, ProviderConnectionState::Ready);
        assert_eq!(provider.state_label, "Ready");
        assert!(provider.available_in_add_server);
        let _ = std::fs::remove_file(token_path);
    }

    #[test]
    fn provider_connections_page_keeps_the_first_screen_reduced() {
        let store = ProviderConnectionStore::new(None).expect("in-memory provider store starts");
        let catalog =
            provider_connections(&ProviderRuntimeConfig::default(), &store, 1_700_000_000);
        let managed = render_provider_connections_page(
            &catalog,
            ShellContext {
                user_label: "markus",
                logout_enabled: true,
            },
            true,
        );
        assert!(managed.contains("Settings"));
        assert!(managed.contains("Appearance and provider connections."));
        assert!(managed.contains("Still sidebar image"));
        assert!(managed.contains("Gentle motion is on."));
        assert!(managed.contains(r#"data-sidebar-still-toggle"#));
        assert!(managed.contains(r#"aria-describedby="sidebar-still-note""#));
        assert!(!managed.contains(r#"data-sidebar-still-toggle checked"#));
        assert_eq!(managed.matches(r#"data-provider=""#).count(), 5);
        assert!(managed.contains(r#"href="/settings/providers/hetzner-cloud""#));
        assert!(
            managed.contains("Managed creation unlocks only after every readiness check passes.")
        );
        assert!(!managed.contains("API token later"));
        assert!(!managed.contains("Credentials needed"));

        let read_only = render_provider_connections_page(
            &catalog,
            ShellContext {
                user_label: "viewer",
                logout_enabled: true,
            },
            false,
        );
        assert_eq!(read_only.matches("Ask an administrator").count(), 5);
        assert!(!read_only.contains(r#"class="provider-action""#));
    }

    #[test]
    fn hetzner_setup_help_is_generic_complete_and_secret_safe() {
        let managed = render_hetzner_setup_help(
            true,
            Some("https://secrets.example.test/provider-setup"),
            true,
            false,
            false,
            false,
            false,
        );
        let api = managed.find("API connection").expect("API help");
        let ssh = managed.find("SSH key").expect("SSH help");
        let firewall = managed.find("Firewall").expect("firewall help");

        assert!(api < ssh && ssh < firewall);
        assert!(managed.contains(r#"data-provider-setup-guide"#));
        assert!(managed.contains(r#"data-provider-setup-guide data-initial-step="ssh" open"#));
        assert!(managed.contains("expand or collapse this guide"));
        assert!(HEAD.contains(
            ".provider-guide-task{display:grid;grid-template-columns:28px minmax(0,1fr)"
        ));
        assert!(HEAD.contains(".provider-guide-task>*{grid-column:2}"));
        assert!(HEAD.contains(
            ".provider-step>span,.provider-help-number,.provider-guide-progress i,.provider-guide-task::before{font-family:-apple-system"
        ));
        assert!(HEAD.contains("font-variant-numeric:tabular-nums;line-height:1"));
        assert!(managed.contains(r#"data-initial-step="ssh""#));
        assert_eq!(managed.matches(r#"data-guide-panel="#).count(), 4);
        assert_eq!(managed.matches(r#"data-guide-copy-status"#).count(), 2);
        assert_eq!(
            managed.matches("<section").count(),
            managed.matches("</section>").count()
        );
        assert_eq!(
            managed.matches("<div").count(),
            managed.matches("</div>").count()
        );
        assert_eq!(
            managed.matches("<ol").count(),
            managed.matches("</ol>").count()
        );
        assert!(managed.contains("Read &amp; Write"));
        assert!(managed.contains(r#"data-guide-language="de""#));
        assert!(managed.contains("Sicherheit → API-Tokens"));
        assert!(managed.contains("Sicherheit → SSH-Keys → SSH-Key hinzufügen"));
        assert!(managed.contains("https://docs.hetzner.com/de/cloud/api/"));
        assert!(managed.contains("https://docs.hetzner.com/de/cloud/firewalls/"));
        assert!(managed.contains("https://console.hetzner.com/projects"));
        assert!(managed.contains("same Hetzner project"));
        assert!(managed.contains("My Mac"));
        assert!(managed.contains("Linux or automation executor"));
        assert!(managed.contains("PUBLIC KEY COPIED"));
        assert_eq!(managed.matches(">bash -c '").count(), 8);
        assert!(managed.contains("ssh-keygen -t ed25519 -a 100"));
        assert!(managed.contains("public key normally begins"));
        assert!(managed.contains("PUBLIC IPv4 RANGE COPIED"));
        assert_eq!(managed.matches(r#"data-guide-network=""#).count(), 3);
        assert_eq!(managed.matches(r#"data-guide-network-panel=""#).count(), 3);
        assert!(managed.contains(r#"data-guide-network-workflow hidden"#));
        assert!(managed.contains(r#"data-guide-firewall-finish data-guide-next="finish" disabled"#));
        assert!(managed.contains("Static IP / executor"));
        assert!(managed.contains("Dynamic IP"));
        assert!(managed.contains("Dynamische IP"));
        assert!(managed.contains("Temporary, attended bootstrap only"));
        assert!(managed.contains("Nur für temporäres, begleitetes Bootstrap"));
        assert!(managed.contains("even behind CGNAT"));
        assert!(managed.contains("Do not enter a Tailscale 100.x address"));
        assert!(managed.contains("Trage keine Tailscale-Adresse mit 100.x"));
        assert!(managed.contains("that path is not implemented yet"));
        assert!(managed.contains("dieser Weg ist noch nicht implementiert"));
        assert!(managed.contains("https://tailscale.com/docs/concepts/tailscale-ip-addresses"));
        assert!(managed.contains("https://tailscale.com/docs/reference/faq/firewall-ports"));
        assert!(managed.contains("Keep Protocol set to TCP and Port set to 22"));
        assert!(managed.contains("Lass Protokoll auf TCP und Port auf 22"));
        assert!(managed.contains("Press Backspace until both are gone"));
        assert!(managed.contains("Drücke die Rückschritttaste"));
        assert!(managed.contains("second ICMP rule"));
        assert!(managed.contains("zweite ICMP-Regel"));
        assert!(managed.contains("x.x.x.x/32"));
        assert!(managed.contains("Ready check: one source entry ending in /32"));
        assert!(managed.contains("Bereit-Check: ein Quell-Eintrag mit /32"));
        assert_eq!(
            managed
                .matches(r#"class="provider-guide-screen-help""#)
                .count(),
            1
        );
        assert!(managed.contains("Firewalls is a separate item in the left Cloud menu"));
        assert!(managed.contains("Cloud: Firewalls → Firewall erstellen"));
        assert!(!managed.contains("Security → Firewalls"));
        assert!(managed.contains("Any IPv4 or Any IPv6"));
        assert!(!managed.contains("Beliebige IPv4"));
        assert!(managed.contains("Open Connection details"));
        assert!(managed.contains("How the SSH-key dropdown works"));
        assert!(managed.contains("names of public SSH keys already stored in this project"));
        assert!(managed.contains("If a dropdown is empty"));
        assert!(managed.contains("https://docs.hetzner.com/cloud/api/"));
        assert!(managed.contains("https://docs.hetzner.com/cloud/servers/"));
        assert!(managed.contains("https://docs.hetzner.com/cloud/firewalls/"));
        assert!(!managed.contains("https://secrets.example.test/provider-setup"));
        assert!(!managed.contains(r#"name="token""#));
        assert!(!managed.contains(r#"type="password""#));
        for installation_specific in [
            "Janus",
            "agenix",
            "/run/",
            "pharos-bootstrap-key",
            "pharos-bootstrap-firewall",
        ] {
            assert!(!managed.contains(installation_specific));
        }

        let needs_api = render_hetzner_setup_help(
            true,
            Some("https://secrets.example.test/provider-setup"),
            false,
            false,
            false,
            false,
            false,
        );
        assert!(needs_api.contains(r#"data-initial-step="api""#));
        assert!(needs_api.contains("https://secrets.example.test/provider-setup"));

        let ready_locked = render_hetzner_setup_help(true, None, true, true, true, true, false);
        assert!(ready_locked.contains(r#"data-initial-step="finish""#));
        assert!(ready_locked.contains("selections have been verified"));
        assert!(ready_locked.contains("Provider setup complete"));
        assert!(ready_locked.contains("Next: installation activation"));
        assert!(ready_locked.contains("No more provider-portal work is needed"));
        assert!(ready_locked.contains("Continue to server assistant"));
        assert!(!ready_locked.contains(r#"data-initial-step="finish" open"#));
        assert!(ready_locked.contains("expand for details and next steps"));

        let ready_enabled = render_hetzner_setup_help(true, None, true, true, true, true, true);
        assert!(ready_enabled.contains("Next: prepare the first server"));
        assert!(ready_enabled.contains("Review, authorization, and creation remain separate"));

        let viewer = render_hetzner_setup_help(
            false,
            Some("https://secrets.example.test/provider-setup"),
            false,
            false,
            false,
            false,
            false,
        );
        assert!(viewer.contains("An administrator must complete"));
        assert!(!viewer.contains("https://secrets.example.test/provider-setup"));
    }

    #[test]
    fn hetzner_connection_page_has_three_plain_checks_and_hides_managed_names_from_viewers() {
        let now = now_unix();
        let store = ready_provider_connection_store(now);
        let token_path = std::env::temp_dir().join(format!(
            "pharos-provider-page-token-{}-{}",
            std::process::id(),
            now
        ));
        std::fs::write(&token_path, "provider-page-fixture").expect("write provider token fixture");
        let runtime = ProviderRuntimeConfig {
            hetzner_cloud: HetznerCloudRuntimeConfig {
                credential_source: Some(ProviderCredentialSource::File(token_path.clone())),
                execute_enabled: true,
                ..HetznerCloudRuntimeConfig::default()
            },
            ..ProviderRuntimeConfig::default()
        };
        let shell = ShellContext {
            user_label: "markus",
            logout_enabled: true,
        };
        let managed = render_hetzner_connection_page(&runtime, &store, shell, true, None);
        assert_eq!(managed.matches(r#"class="provider-check""#).count(), 3);
        assert!(managed.contains("API connection"));
        assert!(managed.contains("SSH key"));
        assert!(managed.contains("Firewall"));
        assert!(managed.contains("Add a server"));
        assert!(managed.contains(r#"class="provider-details""#));
        assert!(managed.contains(r#"class="provider-help""#));
        assert!(managed.contains("Prepare the Hetzner project"));
        let managed_page = managed
            .split_once("</aside>")
            .map(|(_, page)| page)
            .expect("provider page contains the application sidebar");
        assert!(!managed_page.contains(">Services<"));
        assert!(!managed_page.contains(">Access<"));
        assert!(!managed.contains("provider-page-fixture"));

        let viewer = render_hetzner_connection_page(&runtime, &store, shell, false, None);
        assert!(viewer.contains("Ask a Pharos administrator"));
        assert!(!viewer.contains("pharos-bootstrap-key"));
        assert!(!viewer.contains("pharos-bootstrap-firewall"));
        assert!(!viewer.contains(r#"class="provider-details""#));
        assert!(viewer.contains(r#"class="provider-help""#));
        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn provider_connection_test_requires_an_explicit_managed_action() {
        let state = report_test_state(false);
        let denied = test_hetzner_provider_connection(State(state.clone()), HeaderMap::new())
            .await
            .into_response();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(state.provider_connections.last_attempt().is_none());

        let allowed = test_hetzner_provider_connection(State(state.clone()), action_headers())
            .await
            .into_response();
        assert_eq!(allowed.status(), StatusCode::OK);
        assert_eq!(
            state
                .provider_connections
                .last_attempt()
                .map(|attempt| attempt.code),
            Some(HetznerConnectionCode::CredentialUnavailable)
        );
    }

    #[test]
    fn provider_env_file_reads_only_the_named_fixture_value() {
        let path = std::env::temp_dir().join(format!(
            "pharos-provider-env-fixture-{}-{}",
            std::process::id(),
            now_unix()
        ));
        std::fs::write(
            &path,
            "IGNORED_VALUE=not-used\nexport PHAROS_HCLOUD_API_TOKEN='provider-env-fixture'\n",
        )
        .expect("write provider env fixture");
        let runtime = HetznerCloudRuntimeConfig {
            credential_source: Some(ProviderCredentialSource::EnvFile(path.clone())),
            ..HetznerCloudRuntimeConfig::default()
        };
        assert!(runtime
            .api_token()
            .is_ok_and(|value| value == "provider-env-fixture"));
        assert!(read_provider_env_file(&path, "OTHER_VALUE").is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn hetzner_secure_setup_link_contains_names_not_secret_values() {
        let runtime = ProviderRuntimeConfig {
            janus_public_url: provider_setup_base_url("https://vault.barta.cm"),
            ..ProviderRuntimeConfig::default()
        };
        let setup = hetzner_janus_setup_url(&runtime, "csb1").expect("Janus setup link");
        let url = Url::parse(&setup).expect("setup link parses");
        let query = url.query_pairs().collect::<BTreeMap<_, _>>();
        assert_eq!(url.path(), "/vault/new");
        assert_eq!(query.get("host").map(|value| value.as_ref()), Some("csb1"));
        assert_eq!(
            query.get("env").map(|value| value.as_ref()),
            Some("PHAROS_HCLOUD_API_TOKEN")
        );
        assert!(!query.contains_key("value"));
        assert!(!setup.to_ascii_lowercase().contains("bearer "));
        assert!(hetzner_janus_setup_url(&runtime, "../../other-host").is_none());
    }

    #[test]
    fn provider_return_path_stays_on_the_current_origin() {
        assert_eq!(
            safe_provider_return_path(Some("/?setup=add-server&setup_path=new")),
            Some("/?setup=add-server&setup_path=new".to_string())
        );
        for unsafe_path in [
            "",
            "https://example.com",
            "//example.com",
            "/\\example.com",
            "/\nnext",
        ] {
            assert!(safe_provider_return_path(Some(unsafe_path)).is_none());
        }
    }

    #[test]
    fn netcup_manual_import_plan_stays_external_and_caveated() {
        let plan = setup_provider_plan("manual-import", "netcup-manual-import")
            .expect("netcup manual import has a plan");

        assert_eq!(plan.provider, "manual-import");
        assert_eq!(plan.template, "netcup-manual-import");
        assert_eq!(plan.strategy, "netcup-manual-import");
        assert!(plan.approach.contains("externally-created server"));
        assert!(plan.summary.contains("ordering"));
        assert!(plan.summary.contains("billing"));
        assert!(plan.summary.contains("rescue/ISO"));
        assert!(plan
            .docs
            .iter()
            .any(|doc| doc.url
                == "https://www.netcup.com/en/helpcenter/documentation/server/rest-api"));
        assert!(plan
            .resources
            .iter()
            .any(|resource| resource.key == "netcup_server"
                && resource.api.contains("Netcup SCP")
                && resource.detail.contains("does not order")));
        assert!(plan
            .resources
            .iter()
            .any(|resource| resource.key == "backup_snapshot_expectation"
                && resource.detail.contains("pricing")));
        assert!(plan
            .runtime_checks
            .contains(&"current Netcup product price and billing state"));
        assert!(plan
            .steps
            .iter()
            .any(|step| step.key == "bootstrap" && step.detail.contains("existing-host")));
        let json = serde_json::to_string(&plan).expect("plan serializes");
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
    }

    #[test]
    fn free_tier_lab_plans_are_import_only_and_runtime_verified() {
        for (template, strategy, doc_url, expected_check) in [
            (
                "oracle-always-free-lab",
                "oracle-always-free-lab-import",
                "https://docs.oracle.com/iaas/Content/FreeTier/freetier_topic-Always_Free_Resources.htm",
                "current Oracle Always Free eligibility",
            ),
            (
                "gcp-free-tier-lab",
                "gcp-free-tier-lab-import",
                "https://cloud.google.com/free/docs/free-cloud-features",
                "current Google Cloud free-tier limits",
            ),
        ] {
            let plan = setup_provider_plan("manual-import", template)
                .expect("free-tier lab template has a plan");

            assert_eq!(plan.provider, "manual-import");
            assert_eq!(plan.template, template);
            assert_eq!(plan.strategy, strategy);
            assert!(plan.approach.contains("externally-created lab VM"));
            assert!(plan.summary.contains("lab/demo"));
            assert!(plan.summary.contains("does not promise"));
            assert!(plan.summary.contains("does not store"));
            assert!(plan.docs.iter().any(|doc| doc.url == doc_url));
            assert!(plan
                .resources
                .iter()
                .any(|resource| resource.key.ends_with("_vm")
                    && resource.detail.contains("before import")));
            assert!(plan.runtime_checks.contains(&expected_check));
            assert!(plan
                .runtime_checks
                .iter()
                .any(|check| check.contains("billing")));
            assert!(plan
                .steps
                .iter()
                .any(|step| step.key == "bootstrap" && step.status == "handoff"));
            let json = serde_json::to_string(&plan).expect("plan serializes");
            assert!(!json.to_ascii_lowercase().contains("bearer "));
            assert!(!json.to_ascii_lowercase().contains("token="));
        }
    }

    fn report_test_state(require_report_token: bool) -> AppState {
        report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token,
            report_token_mode: BeaconTokenMode::Local,
            janus_tokens: None,
            local_register_enabled: true,
        })
    }

    fn report_test_state_with_auth(beacon_auth: BeaconAuth) -> AppState {
        AppState {
            store: Arc::new(Store::new(None).expect("in-memory host store starts")),
            provisioning_jobs: Arc::new(ProvisioningJobStore::new(None)),
            manifests: Arc::new(ManifestRegistry::default()),
            managed_setup_intents: None,
            managed_service_operations: Arc::new(
                ManagedServiceOperationStore::new(None)
                    .expect("in-memory managed operation store starts"),
            ),
            auth: AuthState::default(),
            beacon_auth,
            provider_runtime: ProviderRuntimeConfig::default(),
            provider_connections: Arc::new(
                ProviderConnectionStore::new(None).expect("in-memory provider store starts"),
            ),
            paid_create_lock: Arc::new(tokio::sync::Mutex::new(())),
            settings_change_lock: Arc::new(tokio::sync::Mutex::new(())),
            nixcfg_dispatch: NixcfgDispatch::disabled(),
            retirement_owner: RetirementOwnerAuth::default(),
            host_actions: Arc::new(HostActionStore::new(None)),
            retired_hosts: Arc::new(RetiredHostStore::new(None)),
            alert_health: AlertWorkerHealth::new(false, now_unix(), 60),
        }
    }

    static JANUS_HASH_FIXTURE_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn janus_generation_dir(entries: &[(&str, &str)]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let counter = JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "pharos-janus-token-generation-{}-{}-{}",
            std::process::id(),
            nanos,
            counter
        ));
        crate::janus_auth::write_test_generation(
            &dir,
            entries
                .iter()
                .map(|(host, token)| ((*host).to_string(), token_hash(token))),
        );
        dir
    }

    fn janus_test_store(entries: &[(&str, &str)]) -> (PathBuf, JanusTokenStore) {
        let root = janus_generation_dir(entries);
        let store = JanusTokenStore::load(root.clone()).expect("load Janus generation fixture");
        (root, store)
    }

    #[test]
    fn beacon_token_mode_rejects_unknown_values() {
        assert!(parse_beacon_token_mode("janus").is_ok());
        assert!(parse_beacon_token_mode("typo").is_err());
    }

    #[test]
    fn janus_mode_enforces_startup_invariants() {
        let (root, store) = janus_test_store(&[("ares", "test-token")]);

        assert!(BeaconAuth::validated(
            None,
            false,
            BeaconTokenMode::Janus,
            Some(store.clone()),
            false,
        )
        .is_err());
        assert!(BeaconAuth::validated(
            None,
            true,
            BeaconTokenMode::Janus,
            Some(store.clone()),
            true,
        )
        .is_err());
        assert!(BeaconAuth::validated(
            Some("unused-registration-value".to_string()),
            true,
            BeaconTokenMode::Janus,
            Some(store.clone()),
            false,
        )
        .is_err());
        assert!(BeaconAuth::validated(None, true, BeaconTokenMode::Janus, None, false,).is_err());
        assert!(
            BeaconAuth::validated(None, true, BeaconTokenMode::Janus, Some(store), false,).is_ok()
        );

        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn janus_mode_rejects_unavailable_or_empty_sources_at_startup() {
        let missing = std::env::temp_dir().join(format!(
            "pharos-missing-janus-source-{}-{}",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(JanusTokenStore::load(missing).is_err());

        let empty = janus_generation_dir(&[]);
        assert!(JanusTokenStore::load(empty.clone()).is_err());
        let _ = std::fs::remove_dir_all(empty);
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            inbound_rtt_ms: None,
            location: None,
            preferences: Default::default(),
        }
    }

    fn register_test_token(state: &AppState, host: &str, token: &str) {
        state
            .store
            .register(
                HostRegistration {
                    schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
                    version: pharos_core::HOST_REGISTRATION_VERSION,
                    name: host.to_string(),
                    role: "server".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 60,
                },
                token_hash(token),
            )
            .expect("test registration persists");
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

    fn action_headers() -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert("X-Pharos-Action", axum::http::HeaderValue::from_static("1"));
        headers
    }

    fn action_headers_with_ack(job_id: &str) -> HeaderMap {
        let mut headers = action_headers();
        headers.insert(
            "X-Pharos-Acknowledge-Uncertainty",
            axum::http::HeaderValue::from_str(job_id).expect("valid uncertainty acknowledgement"),
        );
        headers
    }

    #[tokio::test]
    async fn host_action_job_reads_require_agora_and_host_access() {
        let mut state = report_test_state(false);
        let job = state
            .host_actions
            .create_update_review("hsb8", "fixture-operator", now_unix())
            .expect("host-action fixture starts");

        let host_limited_human = AccessGrant::limited(["hsb8"], false);
        state.auth = AuthState::for_test_access(host_limited_human);
        let (status, _) = host_action_job_json(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(job.id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        let fleet_read_machine = AccessGrant::fleet_read();
        state.auth = AuthState::for_test_access(fleet_read_machine);
        let (status, _) =
            host_action_job_json(State(state), HeaderMap::new(), AxumPath(job.id)).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn settings_host_check_is_an_idempotent_read_of_the_same_durable_run() {
        let mut state = report_test_state(false);
        state.auth = AuthState::for_test_access(AccessGrant::full());
        let requested = HostPreferences {
            accent: Some("#98b8d8".to_string()),
            ..HostPreferences::default()
        };
        let preferences_path = std::env::temp_dir().join(format!(
            "pharos-settings-host-check-{}-{}.json",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &preferences_path,
            serde_json::to_vec(&json!({
                "schema": "inspr.pharos.host-preferences.v1",
                "version": 1,
                "hosts": { "csb0": requested.clone() }
            }))
            .expect("declared preferences serialize"),
        )
        .expect("declared preferences fixture writes");
        state.manifests = Arc::new(ManifestRegistry::from_sources(
            Vec::new(),
            Some(preferences_path.clone()),
        ));
        let job = state
            .host_actions
            .begin_settings_change("csb0", "fixture-operator", 1_700_000_200)
            .expect("settings workflow starts");
        state
            .host_actions
            .record_settings_request(&job.id, &requested, 1_700_000_201)
            .expect("requested settings recorded");
        state
            .host_actions
            .mark_dispatch_submitted(&job.id, 1_700_000_202)
            .expect("repository handoff recorded");
        state
            .host_actions
            .accept_settings_change(&job.id, 1_700_000_203)
            .expect("repository handoff accepted");

        let before = state.host_actions.get(&job.id).expect("saved run exists");
        let (first_status, Json(first)) = host_action_job_json(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(job.id.clone()),
        )
        .await;
        let (second_status, Json(second)) = host_action_job_json(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(job.id.clone()),
        )
        .await;
        let after = state.host_actions.get(&job.id).expect("saved run retained");

        assert_eq!(first_status, StatusCode::OK);
        assert_eq!(second_status, StatusCode::OK);
        assert_eq!(first, second);
        assert_eq!(first["job"]["id"], job.id);
        assert!(first["job"]["workflow"]["primary_action"].is_null());
        assert_eq!(first["job"]["workflow"]["ladder"][1]["key"], "declared");
        assert_eq!(first["job"]["workflow"]["ladder"][1]["state"], "complete");
        assert_eq!(
            first["job"]["workflow"]["status_label"],
            "guarded apply unavailable"
        );
        assert!(first["job"]["workflow"]["guidance"].as_str().is_some_and(
            |guidance| guidance.contains("target-local Janus actions are not enabled")
        ));
        assert_eq!(after.state, HostActionState::ProposalRequested);
        assert_eq!(after.updated_at, before.updated_at);
        assert_eq!(after.events, before.events);
        std::fs::remove_file(preferences_path).expect("remove declared preferences fixture");
    }

    struct JanusActionFixture {
        manifest_path: PathBuf,
        generation_root: PathBuf,
    }

    impl Drop for JanusActionFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.manifest_path);
            let _ = std::fs::remove_dir_all(&self.generation_root);
        }
    }

    fn state_with_janus_manifest(host: &str, token: &str) -> (AppState, JanusActionFixture) {
        let path = std::env::temp_dir().join(format!(
            "pharos-action-manifest-{}-{}-{}.json",
            std::process::id(),
            host,
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &path,
            serde_json::to_vec(&test_manifest(host, true)).expect("manifest serializes"),
        )
        .expect("write action manifest");
        let (generation_root, janus_tokens) = janus_test_store(&[(host, token)]);
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Dual,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: true,
        });
        state.manifests = Arc::new(ManifestRegistry::from_paths(vec![path.clone()]));
        register_test_token(&state, host, token);
        let mut report = test_report(host);
        report.kernel = Some(reboot_required_kernel(now_unix()));
        report.freshness.commits_behind = Some(1);
        state
            .store
            .record(report, now_unix())
            .expect("test report persists");
        (
            state,
            JanusActionFixture {
                manifest_path: path,
                generation_root,
            },
        )
    }

    #[tokio::test]
    async fn guarded_update_endpoint_requires_host_review_and_attended_confirmation() {
        let (state, _fixture) = state_with_janus_manifest("hsb8", "action-token");
        let (status, Json(payload)) = request_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest::default()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let id = payload["job"]["id"].as_str().expect("job id").to_string();

        let claim = claim_host_action(
            State(state.clone()),
            bearer_headers("action-token"),
            Json(AgentActionClaimRequest {
                host: "hsb8".to_string(),
            }),
        )
        .await;
        assert_eq!(claim.status(), StatusCode::OK);

        let result = record_host_action_result(
            State(state.clone()),
            bearer_headers("action-token"),
            AxumPath(id.clone()),
            Json(AgentActionResultRequest {
                host: "hsb8".to_string(),
                phase: host_actions::AgentActionPhase::Review,
                outcome: AgentActionOutcome::Succeeded,
                plan: Some(host_actions::HostActionPlan {
                    changed_file_count: 2,
                    changed_areas: vec!["flake.lock".to_string(), "hosts".to_string()],
                    all_host_eval_passed: true,
                    target_build_passed: true,
                    backup_ready: true,
                    running_kernel: Some("6.18.26".to_string()),
                    expected_kernel: Some("7.0.14".to_string()),
                    restart_required: true,
                }),
                result: None,
            }),
        )
        .await;
        assert_eq!(result.status(), StatusCode::OK);

        let (status, _) = confirm_update_restart(
            State(state.clone()),
            action_headers(),
            AxumPath(id.clone()),
            Json(ConfirmHostActionRequest {
                confirmation: "hsb8".to_string(),
                attended: false,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, Json(payload)) = confirm_update_restart(
            State(state.clone()),
            action_headers(),
            AxumPath(id),
            Json(ConfirmHostActionRequest {
                confirmation: "hsb8".to_string(),
                attended: true,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "queued_apply");
    }

    #[tokio::test]
    async fn declared_apply_endpoint_is_typed_gated_and_names_the_fleet_lock_holder() {
        let (state, _fixture) = state_with_janus_manifest("hsb8", "apply-token");
        let (status, Json(payload)) = request_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest {
                intent: UpdateRestartIntent::ApplyDeclared,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["intent"], "apply_declared");
        assert_eq!(payload["job"]["ticket"], "PHAROS-216");

        let (blocked_state, _blocked_fixture) =
            state_with_janus_manifest("hsb8", "blocked-apply-token");
        let mut current = test_report("hsb8");
        current.kernel = None;
        blocked_state
            .store
            .record(current, now_unix().saturating_add(1))
            .expect("current report replaces drift fixture");
        let (status, Json(payload)) = request_update_restart_review(
            State(blocked_state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest {
                intent: UpdateRestartIntent::ApplyDeclared,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(payload["error"]
            .as_str()
            .is_some_and(|message| message.contains("No declared preference or kernel drift")));

        let (status, _) = request_update_restart_review(
            State(blocked_state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest {
                intent: UpdateRestartIntent::RestartOnly,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);

        let mut drifted = test_report("hsb8");
        drifted.kernel = Some(reboot_required_kernel(now_unix()));
        blocked_state
            .store
            .record(drifted, now_unix().saturating_add(2))
            .expect("kernel drift restored");
        blocked_state
            .host_actions
            .create_update_review("csb0", "fixture-operator", now_unix())
            .expect("other host holds fleet gate");
        let (status, Json(payload)) = request_update_restart_review(
            State(blocked_state),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest {
                intent: UpdateRestartIntent::ApplyDeclared,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(payload["error"]
            .as_str()
            .is_some_and(|message| message.contains("csb0 holds the fleet update lock")));
    }

    #[tokio::test]
    async fn settings_apply_endpoint_links_once_and_keeps_parent_until_exact_beacon() {
        let (state, _fixture) = state_with_janus_manifest("hsb8", "settings-apply-token");
        let requested = state
            .manifests
            .declared_preferences_for("hsb8")
            .expect("declared preferences")
            .clone();
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "fixture-operator", now_unix())
            .expect("settings workflow starts");
        state
            .host_actions
            .record_settings_request(&settings.id, &requested, now_unix())
            .expect("request saved");
        state
            .host_actions
            .mark_dispatch_submitted(&settings.id, now_unix())
            .expect("handoff submitted");
        state
            .host_actions
            .accept_settings_change(&settings.id, now_unix())
            .expect("handoff accepted");

        let (denied, _) = apply_declared_settings_change(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(settings.id.clone()),
        )
        .await;
        assert_eq!(denied, StatusCode::FORBIDDEN);

        let (first_status, Json(first)) = apply_declared_settings_change(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;
        let (second_status, Json(second)) = apply_declared_settings_change(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;

        assert_eq!(first_status, StatusCode::ACCEPTED);
        assert_eq!(second_status, StatusCode::ACCEPTED);
        assert_eq!(first["job"]["id"], settings.id);
        assert_eq!(second["job"]["id"], settings.id);
        assert_eq!(
            first["job"]["workflow"]["linked_run_id"],
            second["job"]["workflow"]["linked_run_id"]
        );
        assert_eq!(
            first["job"]["workflow"]["linked_run_state"],
            "queued_review"
        );
        assert_eq!(first["job"]["workflow"]["can_withdraw"], false);
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| job.settings_change_id() == Some(settings.id.as_str()))
                .count(),
            1
        );
        assert_eq!(
            state
                .host_actions
                .get(&settings.id)
                .expect("parent remains open")
                .state,
            HostActionState::ProposalRequested
        );
    }

    #[test]
    fn accepted_declared_settings_name_missing_target_local_janus_in_fleet_payload() {
        let mut manifest = test_manifest("hsb0", true);
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..HostPreferences::default()
        };
        manifest.host.preferences = requested.clone();
        let mut host = host_with_backups("hsb0", 970, vec![]);
        host.requested_preferences = Some(requested.clone());
        let store = HostActionStore::new(None);
        let settings = store
            .begin_settings_change("hsb0", "markus", 950)
            .expect("settings workflow starts");
        store
            .record_settings_request(&settings.id, &requested, 951)
            .expect("settings request recorded");
        store
            .mark_dispatch_submitted(&settings.id, 952)
            .expect("repository handoff recorded");
        store
            .accept_settings_change(&settings.id, 953)
            .expect("repository handoff accepted");
        let declarations = BTreeMap::from([("hsb0".to_string(), requested)]);
        let no_janus_agents = BTreeSet::new();

        let payload = hosts_payload(
            vec![host],
            &[manifest],
            &declarations,
            &store.list(),
            Some(&no_janus_agents),
            1_000,
        );
        let workflow = &payload["hosts"][0]["host_action"]["workflow"];
        assert_eq!(workflow["status_label"], "guarded apply unavailable");
        assert!(workflow["guidance"].as_str().is_some_and(
            |guidance| guidance.contains("target-local Janus actions are not enabled")
        ));
        assert!(workflow["primary_action"].is_null());
    }

    #[tokio::test]
    async fn guarded_review_cancellation_is_persisted_and_releases_the_host() {
        let (state, _fixture) = state_with_janus_manifest("hsb8", "action-token");
        let (status, Json(payload)) = request_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest::default()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let id = payload["job"]["id"].as_str().expect("job id").to_string();
        assert_eq!(payload["job"]["workflow"]["can_cancel"], true);

        let (status, Json(cancelled)) = cancel_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath(id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(cancelled["job"]["state"], "cancelled");
        assert_eq!(
            cancelled["job"]["workflow"]["status_label"],
            "cancelled safely"
        );
        assert_eq!(cancelled["job"]["workflow"]["can_cancel"], false);
        assert!(cancelled["job"]["workflow"]["current_step"].is_null());

        let (status, _) =
            cancel_update_restart_review(State(state.clone()), action_headers(), AxumPath(id))
                .await;
        assert_eq!(status, StatusCode::CONFLICT);
        let (status, _) = request_update_restart_review(
            State(state),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest::default()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
    }

    #[tokio::test]
    async fn failed_guarded_review_requires_explicit_linked_retry() {
        let (state, _fixture) = state_with_janus_manifest("hsb8", "action-token");
        let (status, Json(payload)) = request_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest::default()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let failed_id = payload["job"]["id"].as_str().expect("job id").to_string();
        assert_eq!(
            claim_host_action(
                State(state.clone()),
                bearer_headers("action-token"),
                Json(AgentActionClaimRequest {
                    host: "hsb8".to_string(),
                }),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            record_host_action_result(
                State(state.clone()),
                bearer_headers("action-token"),
                AxumPath(failed_id.clone()),
                Json(AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: host_actions::AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                }),
            )
            .await
            .status(),
            StatusCode::OK
        );

        let (status, Json(payload)) = request_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(UpdateRestartActionRequest::default()),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(payload["error"]
            .as_str()
            .is_some_and(|message| message.contains("retry")));

        let (status, Json(payload)) = retry_update_restart_review(
            State(state.clone()),
            action_headers(),
            AxumPath(failed_id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "queued_review");
        assert_eq!(payload["job"]["retry_of"], failed_id);
        assert_eq!(payload["job"]["retryable"], false);
        assert_eq!(
            state
                .host_actions
                .get(&failed_id)
                .expect("failed attempt retained")
                .state,
            HostActionState::Failed
        );
        let latest = state
            .host_actions
            .latest_for_host("hsb8")
            .expect("retry is latest");
        assert_eq!(latest.id, payload["job"]["id"]);
        assert_eq!(
            claim_host_action(
                State(state.clone()),
                bearer_headers("action-token"),
                Json(AgentActionClaimRequest {
                    host: "hsb8".to_string(),
                }),
            )
            .await
            .status(),
            StatusCode::OK
        );
    }

    #[tokio::test]
    async fn runtime_host_removal_revokes_reports_and_reonboarding_is_explicit() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "remove-token");
        let mut runtime_report = test_report("ares");
        runtime_report.is_nix = false;
        runtime_report.freshness.applicable = false;
        state
            .store
            .record(runtime_report, now_unix())
            .expect("test report persists");

        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("ares".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "wrong".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!state.retired_hosts.is_retired("ares"));

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("ares".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "ares".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "succeeded");
        assert_eq!(payload["job"]["removal_plan"]["disposition"], "unmanaged");
        assert!(state.retired_hosts.is_retired("ares"));
        let retirement = state.retired_hosts.get("ares").expect("retirement stored");
        assert_eq!(retirement.disposition, HostRetirementDisposition::Unmanaged);
        assert!(retirement.successor.is_none());
        assert!(state.store.get("ares").is_none());

        let report_status = report(
            State(state.clone()),
            bearer_headers("remove-token"),
            Json(test_report("ares")),
        )
        .await;
        assert_eq!(report_status.status(), StatusCode::GONE);

        let (status, _) = allow_host_reonboarding(
            State(state.clone()),
            action_headers(),
            AxumPath("ares".to_string()),
            Json(ConfirmHostNameRequest {
                confirmation: "ares".to_string(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        register_test_token(&state, "ares", "new-token");
        let report_status = report(
            State(state.clone()),
            bearer_headers("new-token"),
            Json(test_report("ares")),
        )
        .await;
        assert_eq!(report_status.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn rebuilt_host_requires_an_active_distinct_successor() {
        let state = report_test_state(true);
        for (host, token) in [("gpc0", "old-token"), ("stm2607", "successor-token")] {
            register_test_token(&state, host, token);
            let mut runtime_report = test_report(host);
            runtime_report.is_nix = false;
            runtime_report.freshness.applicable = false;
            state
                .store
                .record(runtime_report, now_unix())
                .expect("test report persists");
        }

        for successor in [None, Some("gpc0"), Some("not-onboarded")] {
            let (status, _) = request_host_removal(
                State(state.clone()),
                action_headers(),
                AxumPath("gpc0".to_string()),
                Json(RemoveHostActionRequest {
                    confirmation: "gpc0".to_string(),
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: successor.map(str::to_string),
                }),
            )
            .await;
            assert!(matches!(
                status,
                StatusCode::BAD_REQUEST | StatusCode::CONFLICT
            ));
            assert!(!state.retired_hosts.is_retired("gpc0"));
        }

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("gpc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "gpc0".to_string(),
                disposition: HostRetirementDisposition::Rebuilt,
                successor: Some("stm2607".to_string()),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["removal_plan"]["disposition"], "rebuilt");
        assert_eq!(payload["job"]["removal_plan"]["successor"], "stm2607");
        let retirement = state.retired_hosts.get("gpc0").expect("retirement stored");
        assert_eq!(retirement.disposition, HostRetirementDisposition::Rebuilt);
        assert_eq!(retirement.successor.as_deref(), Some("stm2607"));
        assert!(state.store.get("gpc0").is_none());
        assert!(state.store.get("stm2607").is_some());
    }

    #[tokio::test]
    async fn runtime_only_nix_host_removal_does_not_assume_declarative_ownership() {
        let state = report_test_state(true);
        register_test_token(&state, "gpc0", "remove-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("gpc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "gpc0".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "succeeded");
        assert_eq!(payload["job"]["removal_plan"]["declaration_pending"], false);
        assert!(state.retired_hosts.is_retired("gpc0"));
        assert!(state.store.get("gpc0").is_none());
    }

    #[tokio::test]
    async fn declarative_host_removal_fails_closed_without_declarative_dispatch() {
        let manifest_path = std::env::temp_dir().join(format!(
            "pharos-removal-manifest-only-{}-{}.json",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&test_manifest("gpc0", true)).expect("manifest serializes"),
        )
        .expect("manifest written");
        let mut state = report_test_state(true);
        state.manifests = Arc::new(ManifestRegistry::from_paths(vec![manifest_path.clone()]));
        register_test_token(&state, "gpc0", "remove-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("gpc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "gpc0".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!state.retired_hosts.is_retired("gpc0"));
        assert!(state.store.get("gpc0").is_some());
        let failed = state
            .host_actions
            .latest_for_host("gpc0")
            .expect("failed removal checklist retained");
        assert_eq!(failed.state, HostActionState::Failed);
        assert_eq!(payload["job"]["workflow"]["kind"], "remove_host");
        assert_eq!(payload["job"]["workflow"]["current_step"], "revoke");
        let _ = std::fs::remove_file(manifest_path);
    }

    #[tokio::test]
    async fn janus_managed_removal_requires_a_distinct_configured_owner() {
        let (generation_root, janus_tokens) = janus_test_store(&[("hsb8", "retirement-token")]);
        let manifest_path = std::env::temp_dir().join(format!(
            "pharos-retirement-owner-manifest-{}-{}.json",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &manifest_path,
            serde_json::to_vec(&test_manifest("hsb8", true)).expect("manifest serializes"),
        )
        .expect("manifest written");
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });
        state.manifests = Arc::new(ManifestRegistry::from_paths(vec![manifest_path.clone()]));
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("test report persists");

        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "hsb8".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!state.retired_hosts.is_retired("hsb8"));

        state.retirement_owner = RetirementOwnerAuth {
            owner_host: Some("hsb8".to_string()),
        };
        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("hsb8".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "hsb8".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!state.retired_hosts.is_retired("hsb8"));

        let _ = std::fs::remove_dir_all(generation_root);
        let _ = std::fs::remove_file(manifest_path);
    }

    /// PHAROS-194: a Janus-issued credential and a declared manifest come from
    /// independent sources. An undeclared managed host must still be removable,
    /// and must stay durably visible until its credential is retired.
    /// PHAROS-197: a one-shot local endpoint standing in for the nixcfg
    /// workflow dispatch, returning the request body it received.
    fn mock_dispatch_endpoint() -> (String, std::sync::mpsc::Receiver<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock dispatch");
        let address = listener.local_addr().expect("mock address");
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    break;
                }
                raw.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&raw).to_string();
                if let Some((head, body)) = text.split_once("\r\n\r\n") {
                    let length = head
                        .lines()
                        .find_map(|line| {
                            line.strip_prefix("content-length: ")
                                .or_else(|| line.strip_prefix("Content-Length: "))
                        })
                        .and_then(|value| value.trim().parse::<usize>().ok())
                        .unwrap_or(0);
                    if body.len() >= length {
                        let _ = sender.send(body.to_string());
                        break;
                    }
                }
            }
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        (format!("http://{address}"), receiver)
    }

    fn mock_counting_dispatch_endpoint() -> (String, Arc<std::sync::atomic::AtomicUsize>) {
        use std::io::{Read, Write};
        use std::sync::atomic::AtomicUsize;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock dispatch");
        let address = listener.local_addr().expect("mock address");
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = Arc::clone(&count);
        std::thread::spawn(move || {
            for mut stream in listener.incoming().flatten() {
                let mut raw = Vec::new();
                let mut buffer = [0_u8; 4096];
                while let Ok(read) = stream.read(&mut buffer) {
                    if read == 0 {
                        break;
                    }
                    raw.extend_from_slice(&buffer[..read]);
                    let text = String::from_utf8_lossy(&raw).to_string();
                    if let Some((head, body)) = text.split_once("\r\n\r\n") {
                        let length = head
                            .lines()
                            .find_map(|line| {
                                line.strip_prefix("content-length: ")
                                    .or_else(|| line.strip_prefix("Content-Length: "))
                            })
                            .and_then(|value| value.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        if body.len() >= length {
                            count_clone.fetch_add(1, Ordering::SeqCst);
                            let _ = stream
                                .write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
                            let _ = stream.flush();
                            break;
                        }
                    }
                }
            }
        });
        (format!("http://{address}"), count)
    }

    fn mock_blocking_dispatch_endpoint() -> (
        String,
        std::sync::mpsc::Receiver<()>,
        std::sync::mpsc::Sender<()>,
    ) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock dispatch");
        let address = listener.local_addr().expect("mock address");
        let (arrived_tx, arrived_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            let mut raw = Vec::new();
            let mut buffer = [0_u8; 4096];
            while let Ok(read) = stream.read(&mut buffer) {
                if read == 0 {
                    return;
                }
                raw.extend_from_slice(&buffer[..read]);
                let text = String::from_utf8_lossy(&raw).to_string();
                let Some((head, body)) = text.split_once("\r\n\r\n") else {
                    continue;
                };
                let length = head
                    .lines()
                    .find_map(|line| {
                        line.strip_prefix("content-length: ")
                            .or_else(|| line.strip_prefix("Content-Length: "))
                    })
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if body.len() >= length {
                    break;
                }
            }
            let _ = arrived_tx.send(());
            let _ = release_rx.recv();
            let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\ncontent-length: 0\r\n\r\n");
            let _ = stream.flush();
        });
        (format!("http://{address}"), arrived_rx, release_tx)
    }

    struct DispatchTokenFixture {
        path: PathBuf,
    }

    impl Drop for DispatchTokenFixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.path);
        }
    }

    fn dispatch_token_file() -> DispatchTokenFixture {
        let path = std::env::temp_dir().join(format!(
            "pharos-197-dispatch-token-{}-{}",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        use std::io::Write as _;
        let mut file = options.open(&path).expect("create dispatch token fixture");
        file.write_all(b"test-dispatch-token\n")
            .expect("write dispatch token fixture");
        DispatchTokenFixture { path }
    }

    fn janus_managed_undeclared_state() -> (PathBuf, AppState) {
        let (generation_root, janus_tokens) =
            janus_test_store(&[("dsc0", "beacon-token"), ("own0", "owner-token")]);
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });
        state.retirement_owner = RetirementOwnerAuth {
            owner_host: Some("own0".to_string()),
        };
        for host in ["dsc0", "own0"] {
            state
                .store
                .record(test_report(host), now_unix())
                .expect("test report persists");
        }
        assert!(!host_is_declared(&state, "dsc0"));
        (generation_root, state)
    }

    /// PHAROS-197: the proposal records the retirement intent the retirement
    /// agent reads, so without a working dispatch this removal must fail closed
    /// rather than revoke reporting and strand the credential.
    #[tokio::test]
    async fn janus_managed_undeclared_removal_fails_closed_without_a_proposal() {
        let (generation_root, state) = janus_managed_undeclared_state();
        assert!(!state.nixcfg_dispatch.host_removal_available());

        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "dsc0".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert!(!state.retired_hosts.is_retired("dsc0"));
        assert!(state.store.get("dsc0").is_some());
        assert_eq!(
            state
                .host_actions
                .latest_for_host("dsc0")
                .expect("checklist retained")
                .state,
            HostActionState::Failed
        );

        let _ = std::fs::remove_dir_all(generation_root);
    }

    #[tokio::test]
    async fn janus_managed_host_without_a_declaration_can_be_removed_and_retired() {
        let (generation_root, mut state) = janus_managed_undeclared_state();
        // PHAROS-197: a reachable proposal endpoint, so the retirement intent
        // this removal depends on is actually requested.
        let (api_base, dispatched) = mock_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "dsc0".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        // The proposal that records the retirement intent was requested, and it
        // told nixcfg this is the undeclared credential-retirement case.
        let body = dispatched
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("removal proposal dispatched");
        assert!(body.contains("\"host\":\"dsc0\""), "{body}");
        assert!(
            body.contains("\"credential_retirement_required\":\"true\""),
            "{body}"
        );
        assert_eq!(payload["job"]["state"], "removal_pending");
        assert_eq!(payload["job"]["removal_plan"]["declaration_pending"], false);
        assert_eq!(
            payload["job"]["removal_plan"]["credential_retirement_required"],
            true
        );
        assert!(state.retired_hosts.is_retired("dsc0"));
        // Beacon access is revoked immediately, but the host stays durably
        // visible so the outstanding credential retirement cannot be mistaken
        // for a finished removal.
        assert!(state.store.get("dsc0").is_some());

        // Reconciliation must not shortcut the unfinished checklist either.
        assert_eq!(reconcile_completed_removals(&state, now_unix()), 0);
        assert!(state.store.get("dsc0").is_some());
        let job = state
            .host_actions
            .latest_for_host("dsc0")
            .expect("removal checklist retained");
        assert_eq!(job.state, HostActionState::RemovalPending);

        assert_eq!(
            claim_retirement_action(
                State(state.clone()),
                bearer_headers("owner-token"),
                Json(RetirementAgentClaimRequest {
                    owner: "own0".to_string(),
                }),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            record_retirement_action_result(
                State(state.clone()),
                bearer_headers("owner-token"),
                AxumPath(job.id.clone()),
                Json(RetirementAgentResultRequest {
                    owner: "own0".to_string(),
                    host: "dsc0".to_string(),
                    outcome: host_actions::RetirementAgentOutcome::Succeeded,
                    reason: None,
                }),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );

        assert_eq!(
            state
                .host_actions
                .get(&job.id)
                .expect("completed retirement")
                .state,
            HostActionState::Succeeded
        );
        assert!(state.store.get("dsc0").is_none());

        let _ = std::fs::remove_dir_all(generation_root);
    }

    #[tokio::test]
    async fn concurrent_removal_requests_send_exactly_one_dispatch() {
        let (generation_root, mut state) = janus_managed_undeclared_state();
        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);
        let request = RemoveHostActionRequest {
            confirmation: "dsc0".to_string(),
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
        };

        let (left, right) = tokio::join!(
            request_host_removal(
                State(state.clone()),
                action_headers(),
                AxumPath("dsc0".to_string()),
                Json(request.clone()),
            ),
            request_host_removal(
                State(state.clone()),
                action_headers(),
                AxumPath("dsc0".to_string()),
                Json(request),
            ),
        );
        let statuses = [left.0, right.0];
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::ACCEPTED)
                .count(),
            1
        );
        assert_eq!(
            statuses
                .iter()
                .filter(|status| **status == StatusCode::CONFLICT)
                .count(),
            1
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        let _ = std::fs::remove_dir_all(generation_root);
    }

    /// PHAROS-194: retirement records are durable, so reconciliation keeps
    /// revisiting terminal removals. Only the pass that actually completes one
    /// may announce it; later passes must stay silent and stable.
    #[tokio::test]
    async fn completed_removal_reconciliation_announces_each_removal_once() {
        let state = report_test_state(true);
        register_test_token(&state, "gpc0", "remove-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");
        let job = state
            .host_actions
            .begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Unmanaged,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                100,
            )
            .expect("removal recorded");
        state
            .retired_hosts
            .retire(RetiredHost {
                host: "gpc0".to_string(),
                requested_by: "markus".to_string(),
                removal_job_id: job.id.clone(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
                declaration_pending: true,
                retired_at: 100,
            })
            .expect("retirement recorded");

        // The declaration is gone, so this pass finishes the removal exactly once.
        assert_eq!(reconcile_completed_removals(&state, now_unix()), 1);
        assert!(state.store.get("gpc0").is_none());
        assert_eq!(
            state
                .host_actions
                .get(&job.id)
                .expect("completed removal")
                .state,
            HostActionState::Succeeded
        );

        // The durable retirement record survives, and further passes are quiet.
        assert!(state.retired_hosts.is_retired("gpc0"));
        for _ in 0..3 {
            assert_eq!(reconcile_completed_removals(&state, now_unix()), 0);
        }
        assert!(state.store.get("gpc0").is_none());
        assert_eq!(
            state
                .host_actions
                .get(&job.id)
                .expect("completed removal")
                .state,
            HostActionState::Succeeded
        );
    }

    #[tokio::test]
    async fn janus_managed_undeclared_removal_still_fails_closed_on_real_invariants() {
        let (generation_root, mut state) = janus_managed_undeclared_state();

        let unconfigured = std::mem::take(&mut state.retirement_owner);
        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "dsc0".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(!state.retired_hosts.is_retired("dsc0"));
        state.retirement_owner = unconfigured;

        // The retirement owner itself still cannot be removed.
        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("own0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "own0".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!state.retired_hosts.is_retired("own0"));

        // A mistyped confirmation is still refused.
        let (status, _) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(RemoveHostActionRequest {
                confirmation: "dsc".to_string(),
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
            }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(!state.retired_hosts.is_retired("dsc0"));

        let _ = std::fs::remove_dir_all(generation_root);
    }

    #[tokio::test]
    async fn configured_retirement_owner_is_the_only_identity_that_can_finish_janus_cleanup() {
        let mut state = report_test_state(true);
        state.retirement_owner = RetirementOwnerAuth {
            owner_host: Some("csb1".to_string()),
        };
        register_test_token(&state, "csb1", "owner-token");
        let job = state
            .host_actions
            .begin_removal(
                "hsb8",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Destroyed,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: true,
                },
                100,
            )
            .expect("retirement recorded");
        state
            .host_actions
            .mark_removal_access_revoked(&job.id, 101)
            .expect("access revoked");
        state
            .retired_hosts
            .retire(RetiredHost {
                host: "hsb8".to_string(),
                requested_by: "markus".to_string(),
                removal_job_id: job.id.clone(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
                declaration_pending: true,
                retired_at: 100,
            })
            .expect("retired host recorded");

        assert_eq!(
            claim_retirement_action(
                State(state.clone()),
                bearer_headers("wrong-token"),
                Json(RetirementAgentClaimRequest {
                    owner: "csb1".to_string(),
                }),
            )
            .await
            .status(),
            StatusCode::UNAUTHORIZED
        );
        assert_eq!(
            claim_retirement_action(
                State(state.clone()),
                bearer_headers("owner-token"),
                Json(RetirementAgentClaimRequest {
                    owner: "csb1".to_string(),
                }),
            )
            .await
            .status(),
            StatusCode::OK
        );
        assert_eq!(
            record_retirement_action_result(
                State(state.clone()),
                bearer_headers("owner-token"),
                AxumPath(job.id.clone()),
                Json(RetirementAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "hsb8".to_string(),
                    outcome: host_actions::RetirementAgentOutcome::Succeeded,
                    reason: None,
                }),
            )
            .await
            .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            state
                .host_actions
                .get(&job.id)
                .expect("completed retirement")
                .state,
            HostActionState::Succeeded
        );
    }

    #[tokio::test]
    async fn system_update_dispatch_failure_keeps_a_persisted_checklist() {
        let state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers(),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let failed = state
            .host_actions
            .latest_for_host("gpc0")
            .expect("failed update proposal checklist retained");
        assert_eq!(failed.state, HostActionState::Failed);
        assert_eq!(payload["job"]["workflow"]["kind"], "system_update_proposal");
        assert_eq!(payload["job"]["workflow"]["current_step"], "request");
    }

    #[tokio::test]
    async fn system_update_duplicate_invoke_returns_conflict_with_active_job() {
        let state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");
        state
            .host_actions
            .begin_system_update_proposal("gpc0", "markus", now_unix(), None)
            .expect("active system update proposal recorded");

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers(),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(payload["job"]["state"], "proposal_requested");
        assert!(payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("already open")));
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.workflow_kind() == host_actions::HostWorkflowKind::SystemUpdateProposal
                })
                .count(),
            1
        );
    }

    #[tokio::test]
    async fn concurrent_system_update_ack_sends_one_dispatch() {
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");

        let uncertain_id = "action-system-update-gpc0-concurrent-1".to_string();
        state
            .host_actions
            .create_system_update_proposal(uncertain_id.clone(), "gpc0", "markus", 820)
            .expect("uncertain job created");
        state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_id, 821)
            .expect("uncertain failure recorded");

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let headers = action_headers_with_ack(&uncertain_id);
        let (left, right) = tokio::join!(
            request_system_update(
                State(state.clone()),
                headers.clone(),
                Json(SystemUpdateActionRequest {
                    host: "gpc0".to_string(),
                }),
            ),
            request_system_update(
                State(state.clone()),
                headers,
                Json(SystemUpdateActionRequest {
                    host: "gpc0".to_string(),
                }),
            ),
        );
        assert_eq!(left.0, StatusCode::ACCEPTED);
        assert_eq!(right.0, StatusCode::ACCEPTED);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn system_update_cross_host_ack_forbidden_without_foreign_job_or_dispatch() {
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        register_test_token(&state, "hsb8", "update-token-hsb8");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("gpc0 report persists");
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("hsb8 report persists");

        let uncertain_gpc0 = "action-system-update-gpc0-cross-handler-1".to_string();
        state
            .host_actions
            .create_system_update_proposal(uncertain_gpc0.clone(), "gpc0", "markus", 830)
            .expect("gpc0 uncertain job created");
        state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_gpc0, 831)
            .expect("gpc0 uncertain failure recorded");
        let replacement = state
            .host_actions
            .begin_system_update_proposal("gpc0", "markus", 832, Some(&uncertain_gpc0))
            .expect("gpc0 replacement created")
            .into_job();
        state
            .host_actions
            .accept_system_update_proposal(&replacement.id, 833)
            .expect("gpc0 replacement accepted");

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers_with_ack(&uncertain_gpc0),
            Json(SystemUpdateActionRequest {
                host: "hsb8".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(payload.get("job").is_none());
        assert!(payload.get("workflow_html").is_none());
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        let gpc0_prior = state
            .host_actions
            .get(&uncertain_gpc0)
            .expect("gpc0 prior retained");
        assert!(gpc0_prior.events.iter().any(|event| {
            event.kind == host_actions::HostActionEventKind::DispatchUncertaintyAcknowledged
        }));
        let gpc0_replacement = state
            .host_actions
            .get(&replacement.id)
            .expect("gpc0 replacement retained");
        assert_eq!(gpc0_replacement.host, "gpc0");
        assert_eq!(gpc0_replacement.state, HostActionState::Succeeded);
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.host == "hsb8"
                        && job.kind == host_actions::HostActionKind::SystemUpdateProposal
                })
                .count(),
            0
        );
    }

    #[tokio::test]
    async fn partial_ack_replay_after_other_replacement_sends_no_dispatch() {
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token-gpc0");
        register_test_token(&state, "hsb8", "update-token-hsb8");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("gpc0 report persists");
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("hsb8 report persists");

        let uncertain_gpc0 = "action-system-update-gpc0-partial-handler-1".to_string();
        let uncertain_hsb8 = "action-system-update-hsb8-partial-handler-1".to_string();
        state
            .host_actions
            .create_system_update_proposal(uncertain_gpc0.clone(), "gpc0", "markus", 840)
            .expect("gpc0 uncertain job created");
        state
            .host_actions
            .create_system_update_proposal(uncertain_hsb8.clone(), "hsb8", "markus", 841)
            .expect("hsb8 uncertain job created");
        state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_gpc0, 842)
            .expect("gpc0 uncertain failure recorded");
        state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_hsb8, 843)
            .expect("hsb8 uncertain failure recorded");

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        assert!(matches!(
            state
                .host_actions
                .begin_system_update_proposal("gpc0", "markus", 844, Some(&uncertain_gpc0)),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                if job.id == uncertain_hsb8
        ));

        let (lost_response_replay_status, Json(lost_response_replay_payload)) =
            request_system_update(
                State(state.clone()),
                action_headers_with_ack(&uncertain_gpc0),
                Json(SystemUpdateActionRequest {
                    host: "gpc0".to_string(),
                }),
            )
            .await;
        assert_eq!(lost_response_replay_status, StatusCode::CONFLICT);
        assert_eq!(lost_response_replay_payload["job"]["id"], uncertain_hsb8);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);

        let replacement = state
            .host_actions
            .begin_system_update_proposal("hsb8", "markus", 845, Some(&uncertain_hsb8))
            .expect("hsb8 replacement created")
            .into_job();
        state
            .host_actions
            .accept_system_update_proposal(&replacement.id, 846)
            .expect("hsb8 replacement accepted");

        let headers = action_headers_with_ack(&uncertain_gpc0);
        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            headers,
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(payload["job"]["id"], uncertain_gpc0);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.kind == host_actions::HostActionKind::SystemUpdateProposal
                        && job.retry_of.as_deref() == Some(uncertain_gpc0.as_str())
                })
                .count(),
            0
        );
    }

    #[test]
    fn system_update_presentation_distinguishes_handoff_rejection_and_uncertainty() {
        let store = HostActionStore::new(None);
        let handoff = store
            .create_system_update_proposal(
                "action-system-update-hsb8-800-1".to_string(),
                "hsb8",
                "markus",
                800,
            )
            .expect("handoff proposal created");
        let completed = store
            .accept_system_update_proposal(&handoff.id, 801)
            .expect("handoff completed");
        let handoff_workflow = completed.summary().workflow;
        assert_eq!(handoff_workflow.status_label, "review handed to nixcfg");
        let handoff_html = host_workflow_markup(&handoff_workflow);
        assert!(handoff_html.contains("continues in nixcfg"));
        assert!(!handoff_html.contains("not attempted"));

        let rejected = store
            .create_system_update_proposal(
                "action-system-update-gpc0-802-1".to_string(),
                "gpc0",
                "markus",
                802,
            )
            .expect("rejected proposal created");
        let failed = store
            .fail_system_update_proposal(&rejected.id, 803)
            .expect("known rejection recorded");
        let rejected_workflow = failed.summary().workflow;
        assert_eq!(rejected_workflow.status_label, "update review stopped");
        let rejected_html = host_workflow_markup(&rejected_workflow);
        assert!(rejected_html.contains("not attempted"));
        assert!(!rejected_html.contains("continues in nixcfg"));

        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-athena-804-1".to_string(),
                "athena",
                "markus",
                804,
            )
            .expect("uncertain proposal created");
        let uncertain_failed = store
            .fail_system_update_proposal_uncertain(&uncertain.id, 805)
            .expect("uncertain failure recorded");
        let uncertain_workflow = uncertain_failed.summary().workflow;
        assert_eq!(
            uncertain_workflow.status_label,
            "dispatch outcome uncertain"
        );
        let uncertain_html = host_workflow_markup(&uncertain_workflow);
        assert!(uncertain_html.contains("not confirmed"));
        assert!(!uncertain_html.contains("did not accept"));
        assert!(!uncertain_html.contains("continues in nixcfg"));

        let handoff_dispatch = handoff_workflow
            .evidence
            .iter()
            .find(|item| item.label == "Repository dispatch")
            .expect("handoff dispatch evidence");
        assert_eq!(handoff_dispatch.value, "accepted");
        let rejected_dispatch = rejected_workflow
            .evidence
            .iter()
            .find(|item| item.label == "Repository dispatch")
            .expect("rejected dispatch evidence");
        assert_eq!(rejected_dispatch.value, "stopped");
        let uncertain_dispatch = uncertain_workflow
            .evidence
            .iter()
            .find(|item| item.label == "Repository dispatch")
            .expect("uncertain dispatch evidence");
        assert_eq!(uncertain_dispatch.value, "outcome uncertain");
        assert!(handoff_html.contains("Repository dispatch</dt><dd>accepted</dd>"));
        assert!(rejected_html.contains("Repository dispatch</dt><dd>stopped</dd>"));
        assert!(uncertain_html.contains("Repository dispatch</dt><dd>outcome uncertain</dd>"));
    }

    #[tokio::test]
    async fn settings_and_removal_uncertainty_ack_endpoint_reopens_each_workflow() {
        let state = report_test_state(true);
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 900)
            .expect("settings workflow created");
        state
            .host_actions
            .fail_settings_change_uncertain(&settings.id, 901)
            .expect("settings uncertainty recorded");
        let (status, Json(payload)) = acknowledge_dispatch_uncertainty(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            payload["job"]["workflow"]["status_label"],
            "uncertainty acknowledged"
        );
        state
            .host_actions
            .begin_settings_change("hsb8", "markus", 902)
            .expect("fresh settings request allowed");

        let plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let removal = state
            .host_actions
            .begin_removal("gpc0", "markus", plan.clone(), 903)
            .expect("removal workflow created");
        state
            .host_actions
            .fail_removal_uncertain(&removal.id, 904)
            .expect("removal uncertainty recorded");
        let (status, Json(payload)) = acknowledge_dispatch_uncertainty(
            State(state.clone()),
            action_headers(),
            AxumPath(removal.id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            payload["job"]["workflow"]["status_label"],
            "uncertainty acknowledged"
        );
        state
            .host_actions
            .begin_removal("gpc0", "markus", plan, 905)
            .expect("fresh removal request allowed");
    }

    #[tokio::test]
    async fn accepted_settings_and_removal_dispatches_reconcile_locally_without_redispatch() {
        let actions_path = std::env::temp_dir().join(format!(
            "pharos-next-action-restart-{}-{}.json",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let mut state = report_test_state(true);
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");

        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 910)
            .expect("settings workflow created");
        state
            .host_actions
            .record_settings_request(&settings.id, &requested, 911)
            .expect("settings recovery payload recorded");
        state
            .host_actions
            .prepare_repository_dispatch(&settings.id, &settings.id)
            .expect("settings dispatch coordinate saved");
        state
            .host_actions
            .mark_settings_dispatch_submitted(&settings.id, &settings.id, 912)
            .expect("settings dispatch accepted");

        let plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Destroyed,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: true,
        };
        let removal = state
            .host_actions
            .begin_removal("gpc0", "markus", plan, 913)
            .expect("removal workflow created");
        state
            .host_actions
            .prepare_repository_dispatch(&removal.id, &removal.id)
            .expect("removal dispatch coordinate saved");
        state
            .host_actions
            .mark_dispatch_submitted_with_request_id(&removal.id, &removal.id, 914)
            .expect("removal dispatch accepted");

        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        assert_eq!(
            state
                .host_actions
                .get(&settings.id)
                .expect("settings run reloaded")
                .repository_request_id(),
            Some(settings.id.as_str())
        );
        assert_eq!(
            state
                .host_actions
                .get(&removal.id)
                .expect("removal run reloaded")
                .repository_request_id(),
            Some(removal.id.as_str())
        );
        let (status, Json(payload)) = reconcile_accepted_dispatch(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["job"]["workflow"]["status_label"], "change waiting");
        assert!(payload["job"]["workflow"]["primary_action"].is_null());
        assert_eq!(
            payload["job"]["workflow"]["next_action"]["availability"]["operation"],
            "poll_host_evidence"
        );
        assert_eq!(
            payload["job"]["workflow"]["next_action"]["availability"]["execution"],
            "automatic"
        );
        assert_eq!(payload["job"]["workflow"]["next"]["location"], "hsb8");
        assert!(payload["job"]["workflow"]["next"]["consequence"]
            .as_str()
            .is_some_and(|consequence| consequence.contains("keeps this run saved")));
        assert_eq!(
            state
                .store
                .get("hsb8")
                .and_then(|host| host.requested_preferences),
            Some(requested)
        );
        let (second_status, _) = reconcile_accepted_dispatch(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id),
        )
        .await;
        assert_eq!(second_status, StatusCode::CONFLICT);

        let (status, Json(payload)) = reconcile_accepted_dispatch(
            State(state.clone()),
            action_headers(),
            AxumPath(removal.id.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "removal_pending");
        assert!(payload["job"]["workflow"]["primary_action"].is_null());
        assert!(state.retired_hosts.is_retired("gpc0"));
        assert!(state.store.get("gpc0").is_none());

        let (second_status, Json(second_payload)) =
            reconcile_accepted_dispatch(State(state), action_headers(), AxumPath(removal.id)).await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert!(second_payload["error"]
            .as_str()
            .expect("safe reconciliation error")
            .contains("Only a saved"));
        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn legacy_accepted_settings_continue_dispatches_once_and_saves_the_receipt() {
        let mut state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        state
            .store
            .request_preferences("hsb8", requested.clone())
            .expect("legacy pending preferences retained");
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 915)
            .expect("legacy settings workflow created");
        state
            .host_actions
            .accept_settings_change(&settings.id, 916)
            .expect("legacy request accepted without receipt");

        let (read_status, Json(read_payload)) = host_action_job_json(
            State(state.clone()),
            HeaderMap::new(),
            AxumPath(settings.id.clone()),
        )
        .await;
        assert_eq!(read_status, StatusCode::OK);
        assert!(read_payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("no durable repository receipt")));
        assert_eq!(
            read_payload["job"]["workflow"]["primary_action"]["label"],
            "Continue request"
        );
        let host = state.store.get("hsb8").expect("settings host retained");
        let fleet_payload = hosts_payload(
            vec![host],
            &[],
            &BTreeMap::new(),
            &state.host_actions.list(),
            None,
            916,
        );
        assert_eq!(
            fleet_payload["hosts"][0]["lifecycle"]["label"],
            "request needs continuation"
        );
        assert_eq!(
            fleet_payload["hosts"][0]["lifecycle"]["primary_action"]["label"],
            "Continue request"
        );
        assert_eq!(
            fleet_payload["hosts"][0]["host_action"]["workflow"]["status_label"],
            "request needs continuation"
        );

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = continue_legacy_settings_dispatch(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        assert!(payload["job"]["workflow"]["primary_action"].is_null());
        assert_eq!(
            payload["job"]["workflow"]["next_action"]["availability"]["operation"],
            "poll_host_evidence"
        );
        assert!(payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("reviewed nixcfg workflow")));
        let continued = state
            .host_actions
            .get(&settings.id)
            .expect("continued workflow retained");
        assert_eq!(continued.requested_preferences(), Some(&requested));
        assert!(continued.dispatch_submitted());
        assert!(continued
            .summary()
            .workflow
            .evidence
            .iter()
            .any(|item| item.label == "Repository request"));

        let (second_status, _) = continue_legacy_settings_dispatch(
            State(state),
            action_headers(),
            AxumPath(settings.id),
        )
        .await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn legacy_accepted_settings_continue_skips_dispatch_when_declaration_matches() {
        let mut state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        state
            .store
            .request_preferences("hsb8", requested.clone())
            .expect("legacy pending preferences retained");
        let preferences_path = std::env::temp_dir().join(format!(
            "pharos-legacy-settings-declared-{}-{}.json",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(
            &preferences_path,
            serde_json::to_vec(&json!({
                "schema": "inspr.pharos.host-preferences.v1",
                "version": 1,
                "hosts": { "hsb8": requested.clone() }
            }))
            .expect("declared preferences serialize"),
        )
        .expect("declared preferences fixture writes");
        state.manifests = Arc::new(ManifestRegistry::from_sources(
            Vec::new(),
            Some(preferences_path.clone()),
        ));
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 917)
            .expect("legacy settings workflow created");
        state
            .host_actions
            .accept_settings_change(&settings.id, 918)
            .expect("legacy request accepted without receipt");

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = continue_legacy_settings_dispatch(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        assert!(payload["job"]["workflow"]["primary_action"].is_null());
        assert_eq!(
            payload["job"]["workflow"]["next_action"]["availability"]["operation"],
            "poll_host_evidence"
        );
        assert!(payload["message"]
            .as_str()
            .is_some_and(|message| message.contains("already contains these settings")));
        let unchanged = state
            .host_actions
            .get(&settings.id)
            .expect("legacy workflow retained");
        assert!(!unchanged.dispatch_submitted());
        assert!(unchanged.requested_preferences().is_none());
        std::fs::remove_file(preferences_path).expect("remove declared preferences fixture");
    }

    #[tokio::test]
    async fn legacy_accepted_settings_continue_without_saved_values_never_dispatches() {
        let mut state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 919)
            .expect("legacy settings workflow created");
        state
            .host_actions
            .accept_settings_change(&settings.id, 920)
            .expect("legacy request accepted without receipt");

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = continue_legacy_settings_dispatch(
            State(state),
            action_headers(),
            AxumPath(settings.id),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        assert!(payload["error"]
            .as_str()
            .is_some_and(|message| message.contains("no longer recoverable")));
    }

    #[tokio::test]
    async fn withdrawn_settings_cannot_be_resurrected_by_queued_dispatch_reconciliation() {
        let state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 916)
            .expect("settings workflow created");
        state
            .host_actions
            .record_settings_request(&settings.id, &requested, 917)
            .expect("settings recovery payload recorded");
        state
            .host_actions
            .mark_dispatch_submitted(&settings.id, 918)
            .expect("settings dispatch accepted");

        let held = state.settings_change_lock.lock().await;
        let withdraw_state = state.clone();
        let withdraw_id = settings.id.clone();
        let withdrawal = tokio::spawn(async move {
            withdraw_settings_change(
                State(withdraw_state),
                action_headers(),
                AxumPath(withdraw_id),
            )
            .await
        });
        tokio::task::yield_now().await;
        let reconcile_state = state.clone();
        let reconcile_id = settings.id.clone();
        let reconciliation = tokio::spawn(async move {
            reconcile_accepted_dispatch(
                State(reconcile_state),
                action_headers(),
                AxumPath(reconcile_id),
            )
            .await
        });
        tokio::task::yield_now().await;
        drop(held);

        let (withdraw_status, Json(withdraw_payload)) = withdrawal.await.expect("withdrawal joins");
        assert_eq!(withdraw_status, StatusCode::OK);
        assert_eq!(withdraw_payload["job"]["state"], "cancelled");
        let (reconcile_status, _) = reconciliation.await.expect("reconciliation joins");
        assert_eq!(reconcile_status, StatusCode::CONFLICT);
        assert!(state
            .store
            .get("hsb8")
            .expect("host retained")
            .requested_preferences
            .is_none());
        assert_eq!(
            state
                .host_actions
                .get(&settings.id)
                .expect("workflow retained")
                .state,
            HostActionState::Cancelled
        );
    }

    #[tokio::test]
    async fn background_reconciliation_cannot_resurrect_withdrawn_or_complete_replacement_run() {
        let state = report_test_state(true);
        let old_preferences = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        let replacement_preferences = HostPreferences {
            accent: Some("#1f7fb5".to_string()),
            ..Default::default()
        };
        let mut report = test_report("hsb8");
        report.preferences = old_preferences.clone();
        state
            .store
            .record(report, now_unix())
            .expect("settings host recorded");
        let old = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 924)
            .expect("old settings workflow created");
        state
            .host_actions
            .record_settings_request(&old.id, &old_preferences, 925)
            .expect("old settings payload recorded");
        state
            .host_actions
            .mark_settings_dispatch_submitted(&old.id, &old.id, 926)
            .expect("old repository receipt recorded");

        let held = state.settings_change_lock.lock().await;
        let withdraw_state = state.clone();
        let old_id = old.id.clone();
        let withdrawal = tokio::spawn(async move {
            withdraw_settings_change(State(withdraw_state), action_headers(), AxumPath(old_id))
                .await
        });
        tokio::task::yield_now().await;

        let replacement_state = state.clone();
        let replacement = tokio::spawn(async move {
            let _guard = replacement_state.settings_change_lock.lock().await;
            let job = replacement_state
                .host_actions
                .begin_settings_change("hsb8", "markus", 927)
                .expect("replacement settings workflow created");
            replacement_state
                .host_actions
                .record_settings_request(&job.id, &replacement_preferences, 928)
                .expect("replacement settings payload recorded");
            job.id
        });
        tokio::task::yield_now().await;

        let reconcile_state = state.clone();
        let mut reconciliation =
            tokio::spawn(async move { reconcile_saved_next_actions(&reconcile_state, 929).await });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut reconciliation)
                .await
                .is_err(),
            "background reconciliation must wait for the settings transaction"
        );
        drop(held);

        let (withdraw_status, _) = withdrawal.await.expect("withdrawal joins");
        assert_eq!(withdraw_status, StatusCode::OK);
        let replacement_id = replacement.await.expect("replacement joins");
        assert_eq!(reconciliation.await.expect("reconciliation joins"), 0);
        assert_eq!(
            state
                .host_actions
                .get(&old.id)
                .expect("old run retained")
                .state,
            HostActionState::Cancelled
        );
        assert_eq!(
            state
                .host_actions
                .get(&replacement_id)
                .expect("replacement retained")
                .state,
            HostActionState::ProposalRequested
        );
        assert!(state
            .store
            .get("hsb8")
            .expect("host retained")
            .requested_preferences
            .is_none());
    }

    #[tokio::test]
    async fn settings_withdrawal_clears_pending_preferences_without_repository_dispatch() {
        let mut state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        state
            .store
            .request_preferences("hsb8", requested.clone())
            .expect("pending preferences recorded");
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 920)
            .expect("settings workflow created");
        state
            .host_actions
            .record_settings_request(&settings.id, &requested, 921)
            .expect("settings request audit recorded");
        state
            .host_actions
            .mark_dispatch_submitted(&settings.id, 922)
            .expect("repository handoff recorded");
        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = withdraw_settings_change(
            State(state.clone()),
            action_headers(),
            AxumPath(settings.id.clone()),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["job"]["state"], "cancelled");
        assert_eq!(
            payload["message"],
            "Clears the pending request. An open nixcfg proposal stays open there."
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        let host = state.store.get("hsb8").expect("host remains recorded");
        assert!(host.requested_preferences.is_none());
        let payload = hosts_payload(
            vec![host],
            &[],
            &BTreeMap::new(),
            &state.host_actions.list(),
            None,
            923,
        );
        assert_eq!(
            payload["hosts"][0]["lifecycle"]["label"],
            "settings change cancelled"
        );
        assert!(!payload.to_string().contains("Change requested"));

        let (second_status, _) =
            withdraw_settings_change(State(state), action_headers(), AxumPath(settings.id)).await;
        assert_eq!(second_status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn settings_withdrawal_waits_for_in_flight_submission_then_clears_it() {
        let mut state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let (api_base, dispatch_arrived, release_dispatch) = mock_blocking_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let submit_state = state.clone();
        let submission = tokio::spawn(async move {
            agora::request_host_preferences(
                State(submit_state),
                action_headers(),
                Json(
                    serde_json::from_value(serde_json::json!({
                        "host": "hsb8",
                        "preferences": { "accent": "#48b8a8" }
                    }))
                    .expect("settings request parses"),
                ),
            )
            .await
        });
        tokio::task::spawn_blocking(move || {
            dispatch_arrived
                .recv_timeout(std::time::Duration::from_secs(2))
                .expect("dispatch reached blocking endpoint")
        })
        .await
        .expect("dispatch waiter joins");

        let settings = state
            .host_actions
            .latest_settings_change_for_host("hsb8")
            .expect("in-flight settings workflow exists");
        let withdraw_state = state.clone();
        let settings_id = settings.id.clone();
        let mut withdrawal = tokio::spawn(async move {
            withdraw_settings_change(
                State(withdraw_state),
                action_headers(),
                AxumPath(settings_id),
            )
            .await
        });
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut withdrawal)
                .await
                .is_err(),
            "withdrawal must wait for the in-flight submission transaction"
        );

        release_dispatch.send(()).expect("dispatch released");
        let (submit_status, _) = submission.await.expect("submission joins");
        assert_eq!(submit_status, StatusCode::OK);
        let (withdraw_status, Json(withdraw_payload)) = withdrawal.await.expect("withdrawal joins");
        assert_eq!(withdraw_status, StatusCode::OK);
        assert_eq!(withdraw_payload["job"]["state"], "cancelled");
        assert!(state
            .store
            .get("hsb8")
            .expect("host retained")
            .requested_preferences
            .is_none());
        assert_eq!(
            state
                .host_actions
                .get(&settings.id)
                .expect("workflow retained")
                .state,
            HostActionState::Cancelled
        );
    }

    fn post_commit_host_actions_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-handler-{}-{}.json",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[tokio::test]
    async fn settings_begin_persistence_committed_continues_same_request_through_dispatch() {
        let actions_path = post_commit_host_actions_path();
        let mut state = report_test_state(true);
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        state
            .store
            .record(test_report("hsb8"), now_unix())
            .expect("settings host recorded");
        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);
        let settings_request = || {
            serde_json::from_value(serde_json::json!({
                "host": "hsb8",
                "preferences": {
                    "accent": "#48b8a8"
                }
            }))
            .expect("settings request parses")
        };
        let (status, Json(payload)) = agora::request_host_preferences(
            State(state.clone()),
            action_headers(),
            Json(settings_request()),
        )
        .await;

        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload["status"], "dispatch_accepted");
        assert_eq!(payload["job"]["workflow"]["status_label"], "change waiting");
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        let settings_id = payload["job"]["id"].as_str().expect("settings run id");
        assert_eq!(
            state
                .host_actions
                .get(settings_id)
                .expect("settings run persisted")
                .repository_request_id(),
            Some(settings_id)
        );
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.host == "hsb8"
                        && job.workflow_kind() == host_actions::HostWorkflowKind::SettingsChange
                })
                .count(),
            1
        );

        let (second_status, Json(second_payload)) = agora::request_host_preferences(
            State(state.clone()),
            action_headers(),
            Json(settings_request()),
        )
        .await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert_eq!(
            second_payload["error"],
            "A settings change is already waiting for this host"
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn removal_begin_persistence_committed_continues_same_request_through_dispatch() {
        let (generation_root, mut state) = janus_managed_undeclared_state();
        let actions_path = post_commit_host_actions_path();
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);
        let request = RemoveHostActionRequest {
            confirmation: "dsc0".to_string(),
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
        };

        let (status, Json(payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(request.clone()),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "removal_pending");
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        let removal_id = payload["job"]["id"].as_str().expect("removal run id");
        assert_eq!(
            state
                .host_actions
                .get(removal_id)
                .expect("removal run persisted")
                .repository_request_id(),
            Some(removal_id)
        );
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.host == "dsc0" && job.kind == host_actions::HostActionKind::RemoveHost
                })
                .count(),
            1
        );

        let (second_status, Json(second_payload)) = request_host_removal(
            State(state.clone()),
            action_headers(),
            AxumPath("dsc0".to_string()),
            Json(request),
        )
        .await;
        assert_eq!(second_status, StatusCode::CONFLICT);
        assert_eq!(
            second_payload["error"],
            "This host is already being removed"
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

        let _ = std::fs::remove_dir_all(generation_root);
        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn system_update_begin_persistence_committed_continues_same_request_through_dispatch() {
        let actions_path = post_commit_host_actions_path();
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("system update host recorded");
        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers(),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "succeeded");
        assert_eq!(
            payload["job"]["workflow"]["status_label"],
            "review handed to nixcfg"
        );
        assert!(host_actions::system_update_dispatch_handed_off(
            &state
                .host_actions
                .get(payload["job"]["id"].as_str().expect("job id"))
                .expect("handed-off workflow retained")
        ));
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            state
                .host_actions
                .list()
                .into_iter()
                .filter(|job| {
                    job.workflow_kind() == host_actions::HostWorkflowKind::SystemUpdateProposal
                })
                .count(),
            1
        );

        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn system_update_ack_replacement_begin_persistence_committed_continues_through_dispatch()
    {
        let actions_path = post_commit_host_actions_path();
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("system update host recorded");
        let uncertain_id = format!(
            "action-system-update-gpc0-post-commit-{}-{}",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        match state.host_actions.create_system_update_proposal(
            uncertain_id.clone(),
            "gpc0",
            "markus",
            850,
        ) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain system update created: {error:?}"),
        }
        match state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_id, 851)
        {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain system update recorded: {error:?}"),
        }
        assert!(state.host_actions.get(&uncertain_id).is_some());

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers_with_ack(&uncertain_id),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::ACCEPTED);
        assert_eq!(payload["job"]["state"], "succeeded");
        assert_eq!(
            payload["job"]["workflow"]["status_label"],
            "review handed to nixcfg"
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);
        let prior = state
            .host_actions
            .get(&uncertain_id)
            .expect("acknowledged prior retained");
        assert!(prior.events.iter().any(|event| {
            event.kind == host_actions::HostActionEventKind::DispatchUncertaintyAcknowledged
        }));
        let replacement = state
            .host_actions
            .get(payload["job"]["id"].as_str().expect("replacement id"))
            .expect("replacement workflow retained");
        assert_eq!(replacement.retry_of.as_deref(), Some(uncertain_id.as_str()));
        assert!(host_actions::system_update_dispatch_handed_off(
            &replacement
        ));

        let (second_status, _) = request_system_update(
            State(state.clone()),
            action_headers_with_ack(&uncertain_id),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;
        assert_eq!(second_status, StatusCode::ACCEPTED);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 1);

        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn system_update_migration_persistence_committed_blocks_dispatch_with_failed_ack_replacement(
    ) {
        let actions_path = post_commit_host_actions_path();
        let mut state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state.host_actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("system update host recorded");
        let stale_at = now_unix() - 150;
        let uncertain_id = format!(
            "action-system-update-gpc0-migrate-handler-{}-{}",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        match state.host_actions.create_system_update_proposal(
            uncertain_id.clone(),
            "gpc0",
            "markus",
            stale_at.saturating_sub(200),
        ) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain system update created: {error:?}"),
        }
        match state
            .host_actions
            .fail_system_update_proposal_uncertain(&uncertain_id, stale_at.saturating_sub(199))
        {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain system update recorded: {error:?}"),
        }
        let replacement_created_at = stale_at.saturating_sub(50);
        let replacement = match state.host_actions.begin_system_update_proposal(
            "gpc0",
            "markus",
            replacement_created_at,
            Some(&uncertain_id),
        ) {
            Ok(begin) => begin.into_job(),
            Err(error) => panic!("ack replacement seeded: {error:?}"),
        };
        match state
            .host_actions
            .fail_system_update_proposal(&replacement.id, replacement_created_at + 1)
        {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("failed replacement recorded: {error:?}"),
        }
        let stalled_id = format!(
            "action-system-update-gpc0-stalled-handler-{}-{}",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        match state.host_actions.create_system_update_proposal(
            stalled_id.clone(),
            "gpc0",
            "markus",
            stale_at,
        ) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("stalled proposal seeded: {error:?}"),
        }
        let stalled = state
            .host_actions
            .get(&stalled_id)
            .expect("stalled proposal retained in memory");
        assert_eq!(
            stalled.state,
            host_actions::HostActionState::ProposalRequested
        );

        let (api_base, dispatch_count) = mock_counting_dispatch_endpoint();
        let dispatch_token = dispatch_token_file();
        state.nixcfg_dispatch =
            NixcfgDispatch::for_test(Some(dispatch_token.path.clone()), api_base);

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers_with_ack(&uncertain_id),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            payload["error"],
            "The update review checklist could not be recorded"
        );
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);
        let retained = state
            .host_actions
            .get(&replacement.id)
            .expect("failed replacement retained");
        assert_eq!(retained.state, host_actions::HostActionState::Failed);
        assert!(!host_actions::system_update_dispatch_handed_off(&retained));

        let (second_status, _) = request_system_update(
            State(state.clone()),
            action_headers_with_ack(&uncertain_id),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;
        assert_ne!(second_status, StatusCode::ACCEPTED);
        assert_eq!(dispatch_count.load(Ordering::SeqCst), 0);

        let _ = std::fs::remove_file(actions_path);
    }

    #[tokio::test]
    async fn system_update_active_job_conflict_never_panics_without_a_lookup_job() {
        let state = report_test_state(true);
        register_test_token(&state, "gpc0", "update-token");
        state
            .store
            .record(test_report("gpc0"), now_unix())
            .expect("test report persists");
        state
            .host_actions
            .begin_system_update_proposal("gpc0", "markus", now_unix(), None)
            .expect("active system update proposal recorded");

        let (status, Json(payload)) = request_system_update(
            State(state.clone()),
            action_headers(),
            Json(SystemUpdateActionRequest {
                host: "gpc0".to_string(),
            }),
        )
        .await;

        assert_eq!(status, StatusCode::CONFLICT);
        assert_eq!(payload["job"]["state"], "proposal_requested");
    }

    #[test]
    fn system_update_success_copy_honestly_describes_nixcfg_handoff() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_system_update_proposal("hsb8", "markus", 700, None)
            .expect("proposal workflow created")
            .into_job();
        let completed = store
            .accept_system_update_proposal(&job.id, 701)
            .expect("proposal dispatch accepted");
        let message = action_message(&completed);
        assert!(message.contains("handed"));
        assert!(message.contains("nixcfg"));
        assert!(message.contains("No host was deployed or verified from Pharos."));
        assert!(!message.contains("guarded action completed"));

        let workflow = completed.summary().workflow;
        let html = host_workflow_markup(&workflow);
        assert!(html.contains("continues in nixcfg"));
        assert!(!html.contains("not required"));
        assert!(html.contains("not deployed"));
    }

    #[test]
    fn system_update_activity_title_describes_nixcfg_handoff() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_system_update_proposal("athena", "markus", 710, None)
            .expect("proposal workflow created")
            .into_job();
        let completed = store
            .accept_system_update_proposal(&job.id, 711)
            .expect("proposal dispatch accepted");
        let html = render_activity_with_actions(
            runtime(&[], &[]),
            "csb1",
            720,
            ActivitySources {
                manifests: &[],
                load_errors: &[],
                server_probes: &BTreeMap::new(),
                action_jobs: &[completed],
            },
            shell("markus", true),
        );
        assert!(html.contains("System update review handed to nixcfg"));
        assert!(!html.contains("System update review completed"));
        assert!(html.contains("handed the update review request to nixcfg"));
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

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(state
            .store
            .list()
            .into_iter()
            .find(|host| host.name == "ares")
            .and_then(|host| host.last_seen)
            .is_some());
    }

    #[tokio::test]
    async fn report_rejects_reserved_appliance_observation_without_mutating_host() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");
        let before = state.store.get("ares").expect("registered host exists");
        let mut spoofed = test_report("ares");
        spoofed.service_observations = vec![ServiceObservation {
            id: appliance_probes::APPLIANCE_OBSERVATION_ID.to_string(),
            label: "Appliance convergence".to_string(),
            state: pharos_core::ServiceObservationState::Healthy,
            summary: "powered off as expected".to_string(),
        }];

        let response = report(
            State(state.clone()),
            bearer_headers("valid-token"),
            Json(spoofed),
        )
        .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(state.store.get("ares"), Some(before));
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

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
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

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_rejects_missing_token_when_strict_enabled() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "valid-token");

        let status = report(State(state), HeaderMap::new(), Json(test_report("ares"))).await;

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_returns_unavailable_and_rolls_back_when_host_store_persistence_fails() {
        let path = std::env::temp_dir().join(format!(
            "pharos-report-persistence-failure-{}-{}",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut state = report_test_state(false);
        state.store = Arc::new(Store::new(Some(path.clone())).expect("durable store starts"));
        std::fs::create_dir(&path).expect("rename-blocking destination created");

        let response = report(
            State(state.clone()),
            HeaderMap::new(),
            Json(test_report("persistence-test")),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(state.store.get("persistence-test").is_none());
        std::fs::remove_dir_all(path).expect("test destination removed");
    }

    #[tokio::test]
    async fn registration_never_returns_a_credential_when_persistence_fails() {
        let path = std::env::temp_dir().join(format!(
            "pharos-registration-persistence-failure-{}-{}",
            std::process::id(),
            JANUS_HASH_FIXTURE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Local,
            janus_tokens: None,
            local_register_enabled: true,
        });
        state.store = Arc::new(Store::new(Some(path.clone())).expect("durable store starts"));
        std::fs::create_dir(&path).expect("rename-blocking destination created");

        let response = register(
            State(state.clone()),
            bearer_headers("bootstrap-fixture"),
            Json(HostRegistration {
                schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
                version: pharos_core::HOST_REGISTRATION_VERSION,
                name: "registration-test".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            }),
        )
        .await;
        let (status, _, payload) = json_response(response).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(payload.get("token").is_none());
        assert!(state.store.get("registration-test").is_none());
        std::fs::remove_dir_all(path).expect("test destination removed");
    }

    #[tokio::test]
    async fn credential_bearing_registration_response_is_never_cacheable() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Local,
            janus_tokens: None,
            local_register_enabled: true,
        });
        let response = register(
            State(state),
            bearer_headers("bootstrap-fixture"),
            Json(HostRegistration {
                schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
                version: pharos_core::HOST_REGISTRATION_VERSION,
                name: "registration-cache-test".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            }),
        )
        .await;
        let (status, headers, payload) = json_response(response).await;

        assert_eq!(status, StatusCode::CREATED);
        assert!(payload.get("token").is_some());
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, max-age=0, must-revalidate")
        );
        assert_eq!(
            headers.get(header::PRAGMA).and_then(|v| v.to_str().ok()),
            Some("no-cache")
        );
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

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_returns_pending_preferences_only_to_the_reporting_non_nix_host() {
        let state = report_test_state(false);
        let mut initial = test_report("gpc0");
        initial.is_nix = false;
        initial.freshness = NixFreshness::default();
        state
            .store
            .record(initial.clone(), now_unix())
            .expect("test report persists");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            kind: HostKind::Workstation,
            alerts: pharos_core::HostAlertPreferences {
                suppress_down: false,
                suppress_backup: true,
                suppress_nix_freshness: false,
            },
        };
        state
            .store
            .request_preferences("gpc0", requested.clone())
            .expect("preferences request queued");

        let response = report(State(state.clone()), HeaderMap::new(), Json(initial)).await;

        assert_eq!(response.status(), StatusCode::OK);
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body reads");
        let payload: HostReportResponse =
            serde_json::from_slice(&bytes).expect("response contract parses");
        assert_eq!(payload.preferences_for("gpc0"), Ok(Some(&requested)));
        assert_eq!(
            state
                .store
                .get("gpc0")
                .and_then(|host| host.requested_preferences),
            Some(requested),
            "delivery is not acknowledgement"
        );
    }

    #[tokio::test]
    async fn report_never_returns_local_write_preferences_to_nix_hosts() {
        let state = report_test_state(false);
        let initial = test_report("ares");
        state
            .store
            .record(initial.clone(), now_unix())
            .expect("test report persists");
        state
            .store
            .request_preferences(
                "ares",
                HostPreferences {
                    accent: Some("#48b8a8".to_string()),
                    ..Default::default()
                },
            )
            .expect("preferences request queued");

        let response = report(State(state.clone()), HeaderMap::new(), Json(initial)).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(state
            .store
            .get("ares")
            .and_then(|host| host.requested_preferences)
            .is_some());
    }

    #[tokio::test]
    async fn matching_non_nix_report_acknowledges_pending_preferences() {
        let state = report_test_state(false);
        let mut initial = test_report("gpc0");
        initial.is_nix = false;
        initial.freshness = NixFreshness::default();
        state
            .store
            .record(initial.clone(), now_unix())
            .expect("test report persists");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        state
            .store
            .request_preferences("gpc0", requested.clone())
            .expect("preferences request queued");
        initial.preferences = requested.clone();

        let response = report(State(state.clone()), HeaderMap::new(), Json(initial)).await;

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        let host = state.store.get("gpc0").expect("host remains");
        assert_eq!(host.preferences, requested);
        assert!(host.requested_preferences.is_none());
    }

    #[tokio::test]
    async fn report_accepts_janus_generation_token_without_local_registration() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "janus-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });

        let status = report(
            State(state.clone()),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(!state.store.has_token("ares"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_rejects_local_token_when_janus_mode_is_enabled() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "janus-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });
        register_test_token(&state, "ares", "local-token");

        let status = report(
            State(state),
            bearer_headers("local-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_accepts_local_or_janus_token_in_dual_mode() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "janus-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Dual,
            janus_tokens: Some(janus_tokens),
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

        assert_eq!(janus_status.status(), StatusCode::NO_CONTENT);
        assert_eq!(local_status.status(), StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_accepts_complete_janus_generation() {
        let (root, janus_tokens) =
            janus_test_store(&[("ares", "ares-token"), ("athena", "athena-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
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

        assert_eq!(ares_status.status(), StatusCode::NO_CONTENT);
        assert_eq!(athena_status.status(), StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_ignores_files_outside_the_active_janus_generation() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "ares-token")]);
        std::fs::write(root.join(".ares.json.123.tmp"), "not-json")
            .expect("write unrelated temporary file");
        std::fs::write(root.join("unrelated.json"), "not-json").expect("write unrelated JSON file");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("ares-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn report_fails_closed_when_janus_generation_becomes_unavailable() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "janus-token")]);
        std::fs::write(
            root.join(crate::janus_auth::JANUS_CURRENT_FILE),
            format!("{}\n", "f".repeat(64)),
        )
        .expect("point fixture at unavailable generation");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::SERVICE_UNAVAILABLE);
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn readiness_and_metrics_track_the_active_janus_generation() {
        let (root, janus_tokens) = janus_test_store(&[("ares", "janus-token")]);
        let generation = janus_tokens
            .readiness()
            .generation
            .expect("fixture generation id");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: Some(janus_tokens),
            local_register_enabled: false,
        });

        let response = readyz(State(state.clone())).await;
        assert_eq!(response.status(), StatusCode::OK);
        let metric_response = metrics(State(state.clone())).await.into_response();
        let body = axum::body::to_bytes(metric_response.into_body(), 64 * 1024)
            .await
            .expect("metrics body reads");
        let body = String::from_utf8(body.to_vec()).expect("metrics are utf8");
        assert!(body.contains("pharos_janus_sidecar_ready 1"));
        assert!(body.contains(&format!("generation=\"{generation}\"")));

        std::fs::write(
            root.join(crate::janus_auth::JANUS_CURRENT_FILE),
            format!("{}\n", "e".repeat(64)),
        )
        .expect("point fixture at unavailable generation");
        let response = readyz(State(state)).await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn dead_or_stale_alert_worker_fails_readiness_and_is_measurable() {
        let mut state = report_test_state(false);
        let health = AlertWorkerHealth::new(true, now_unix(), 5);
        state.alert_health = health.clone();
        assert_eq!(
            readyz(State(state.clone())).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );

        health.mark_running(true);
        health.record_cycle(now_unix(), true, 3);
        assert_eq!(readyz(State(state.clone())).await.status(), StatusCode::OK);
        let response = metrics(State(state)).await.into_response();
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let body = String::from_utf8(body.to_vec()).unwrap();
        assert!(body.contains("pharos_alert_worker_ready 1"));
        assert!(body.contains("pharos_alert_outbox_pending 3"));

        health.mark_running(false);
        let mut state = report_test_state(false);
        state.alert_health = health;
        assert_eq!(
            readyz(State(state)).await.status(),
            StatusCode::SERVICE_UNAVAILABLE
        );
    }

    #[tokio::test]
    async fn local_register_is_disabled_by_default_in_janus_mode() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap".to_string()),
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_tokens: None,
            local_register_enabled: false,
        });

        let response = register(
            State(state),
            bearer_headers("bootstrap"),
            Json(HostRegistration {
                schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
                version: pharos_core::HOST_REGISTRATION_VERSION,
                name: "ares".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            }),
        )
        .await;
        let (status, _, payload) = json_response(response).await;

        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            payload["error"],
            "local registration disabled; use Janus-managed beacon token issuance"
        );
    }

    #[test]
    fn janus_token_hash_contract_rejects_secret_shaped_or_invalid_hashes() {
        let root = janus_generation_dir(&[]);
        crate::janus_auth::write_test_generation(
            &root,
            [("ares".to_string(), "pharos_not_a_hash".to_string())],
        );
        let err = JanusTokenStore::load(root.clone()).expect_err("invalid hash is rejected");

        assert_eq!(err, JanusTokenHashError::InvalidHash);
        let _ = std::fs::remove_dir_all(root);
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

    #[tokio::test]
    async fn background_next_action_reconciles_saved_settings_receipt_once() {
        let state = report_test_state(true);
        state
            .store
            .record(test_report("hsb8"), 1_000)
            .expect("settings host recorded");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        let settings = state
            .host_actions
            .begin_settings_change("hsb8", "markus", 1_001)
            .expect("settings workflow created");
        state
            .host_actions
            .record_settings_request(&settings.id, &requested, 1_002)
            .expect("settings payload recorded");
        state
            .host_actions
            .mark_settings_dispatch_submitted(&settings.id, &settings.id, 1_003)
            .expect("repository receipt recorded");

        assert_eq!(reconcile_saved_next_actions(&state, 1_004).await, 1);
        assert_eq!(reconcile_saved_next_actions(&state, 1_005).await, 0);
        let reconciled = state
            .host_actions
            .get(&settings.id)
            .expect("saved run remains available");
        assert!(reconciled.accepted_dispatch_reconciled());
        assert_eq!(
            state
                .store
                .get("hsb8")
                .and_then(|host| host.requested_preferences),
            Some(requested)
        );
    }
}
