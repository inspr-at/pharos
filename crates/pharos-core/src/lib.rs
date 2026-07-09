//! Shared Pharos types: hosts, reports, nix-freshness, liveness.
//!
//! Used by both `pharosd` (server) and `pharos-beacon` (agent) so the report
//! schema cannot drift — the typed-integration win that drove the Rust stack
//! choice (PHAROS-2 / ADR-001). See PHAROS-3 (data model) and PHAROS-15
//! (nix freshness) for the tickets these types back.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

/// Unix epoch seconds (UTC). Kept as a plain `i64` so `pharos-core` stays
/// dependency-light; the server stamps these from its own clock — liveness is
/// always derived, never self-asserted by the agent (PHAROS-9).
pub type UnixSeconds = i64;

/// Upper bound for beacon-reported host-to-Pharos submit latency. This catches
/// malformed values while keeping unusually slow mobile or VPN paths valid.
pub const MAX_INBOUND_RTT_MS: u64 = 3_600_000;

/// Server-stamped observation of the host-to-Pharos report submission path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundRttObservation {
    pub millis: u64,
    pub observed_at: UnixSeconds,
}

/// A managed host as seen by the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Host {
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    /// Latest report contract version observed from the beacon.
    #[serde(default = "default_host_report_version")]
    pub report_version: u16,
    /// SHA-256 hash of the per-host beacon token. The raw token is returned
    /// only at registration time and never rendered by the dashboard API.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
    /// Server-received time of the last beacon report. `None` = never seen.
    pub last_seen: Option<UnixSeconds>,
    /// Recent server-received heartbeat times. These are real report events,
    /// retained only so the dashboard can draw an honest pulse history.
    #[serde(default)]
    pub heartbeat_log: Vec<UnixSeconds>,
    /// Beacon's reported heartbeat cadence — drives the "expected next" pulse.
    pub heartbeat_interval_secs: Option<u64>,
    /// Most recent measured host-to-Pharos report submission round trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_rtt: Option<InboundRttObservation>,
    /// Optional runtime-reported approximate host location. This is an
    /// observation overlay, not declared config intent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<HostLocation>,
    pub freshness: NixFreshness,
    /// Non-secret service facts from the latest beacon report. Runtime only;
    /// declared service intent stays in the manifest.
    #[serde(default)]
    pub service_observations: Vec<ServiceObservation>,
    /// Latest non-secret backup runtime observations from the beacon.
    /// Declared backup intent and enrollment policy are modeled elsewhere.
    #[serde(default)]
    pub backup_observations: Vec<BackupObservation>,
}

/// Nix freshness for a host (PHAROS-15): what it is "missing".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct NixFreshness {
    /// `false` for non-Nix hosts → renders `nix: n/a`.
    pub applicable: bool,
    /// Age of `flake.lock` in days (time since the last `nix flake update`).
    pub flake_lock_age_days: Option<u32>,
    /// How many commits the running config is behind the host's nixcfg.
    pub commits_behind: Option<u32>,
}

impl NixFreshness {
    /// Human one-liner TL;DR, e.g. `flake.lock 12d old · 3 commits behind nixcfg`,
    /// `up to date`, or `nix: n/a`.
    pub fn tldr(&self) -> String {
        if !self.applicable {
            return "nix: n/a".to_string();
        }
        let mut parts = Vec::new();
        if let Some(d) = self.flake_lock_age_days {
            if d > 0 {
                parts.push(format!("flake.lock {d}d old"));
            }
        }
        if let Some(c) = self.commits_behind {
            if c > 0 {
                parts.push(format!("{c} commits behind nixcfg"));
            }
        }
        if parts.is_empty() {
            "up to date".to_string()
        } else {
            parts.join(" · ")
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostLocationSource {
    Wifi,
    Ip,
    Provider,
    Declared,
    Fallback,
    Unknown,
}

/// Approximate host location. It deliberately carries source and quality, not
/// raw Wi-Fi scan data, provider payloads, or private address evidence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostLocation {
    pub latitude: f64,
    pub longitude: f64,
    pub source: HostLocationSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accuracy_meters: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub precision_meters: Option<f64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<UnixSeconds>,
    #[serde(default)]
    pub stale: bool,
    #[serde(default)]
    pub manual_override: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl HostLocation {
    pub fn validate_contract(&self) -> Result<(), String> {
        if !self.latitude.is_finite() || !(-90.0..=90.0).contains(&self.latitude) {
            return Err(format!("latitude {} is outside -90..90", self.latitude));
        }
        if !self.longitude.is_finite() || !(-180.0..=180.0).contains(&self.longitude) {
            return Err(format!("longitude {} is outside -180..180", self.longitude));
        }
        if let Some(accuracy) = self.accuracy_meters {
            if !accuracy.is_finite() || accuracy < 0.0 {
                return Err(format!("accuracy_meters {accuracy} must be non-negative"));
            }
        }
        if let Some(precision) = self.precision_meters {
            if !precision.is_finite() || precision < 0.0 {
                return Err(format!("precision_meters {precision} must be non-negative"));
            }
        }
        Ok(())
    }
}

pub const SERVER_LIFECYCLE_SCHEMA: &str = "inspr.pharos.server-lifecycle.v1";
pub const SERVER_LIFECYCLE_VERSION: u16 = 1;
pub const PROVISIONING_JOB_SCHEMA: &str = "inspr.pharos.provisioning-job.v1";
pub const PROVISIONING_JOB_VERSION: u16 = 1;
pub const EXISTING_HOST_PREFLIGHT_SCHEMA: &str = "inspr.pharos.existing-host-preflight.v1";
pub const EXISTING_HOST_PREFLIGHT_VERSION: u16 = 1;

fn default_server_lifecycle_schema() -> String {
    SERVER_LIFECYCLE_SCHEMA.to_string()
}

fn default_server_lifecycle_version() -> u16 {
    SERVER_LIFECYCLE_VERSION
}

fn default_provisioning_job_schema() -> String {
    PROVISIONING_JOB_SCHEMA.to_string()
}

fn default_provisioning_job_version() -> u16 {
    PROVISIONING_JOB_VERSION
}

fn default_existing_host_preflight_schema() -> String {
    EXISTING_HOST_PREFLIGHT_SCHEMA.to_string()
}

fn default_existing_host_preflight_version() -> u16 {
    EXISTING_HOST_PREFLIGHT_VERSION
}

/// Provider/server intent for onboarding jobs. It is not embedded in
/// `HostManifest`: manifests stay declared service/host intent, while this
/// model tracks provisioning/import intent and safe secret references.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerLifecycleIntent {
    #[serde(default = "default_server_lifecycle_schema")]
    pub schema: String,
    #[serde(default = "default_server_lifecycle_version")]
    pub version: u16,
    pub host_name: String,
    pub origin: ServerOrigin,
    pub owner: ServerLifecycleOwner,
    pub state: ServerLifecycleState,
    pub hostname: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<ServerProviderRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_type: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<ServerImageRef>,
    pub bootstrap: BootstrapSource,
    pub ssh: SshAccessIntent,
    #[serde(default)]
    pub secrets: ServerSecretBoundary,
}

impl ServerLifecycleIntent {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        if self.schema != SERVER_LIFECYCLE_SCHEMA {
            return Err(ServerLifecycleContractError::UnsupportedSchema {
                expected: SERVER_LIFECYCLE_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.version != SERVER_LIFECYCLE_VERSION {
            return Err(ServerLifecycleContractError::UnsupportedVersion {
                expected: SERVER_LIFECYCLE_VERSION,
                actual: self.version,
            });
        }
        if self.host_name.trim().is_empty() {
            return Err(ServerLifecycleContractError::EmptyHostName);
        }
        if self.hostname.trim().is_empty() {
            return Err(ServerLifecycleContractError::EmptyHostname);
        }
        match self.origin {
            ServerOrigin::ProviderCreated if self.provider.is_none() => {
                return Err(ServerLifecycleContractError::ProviderRequired);
            }
            ServerOrigin::ImportedExisting | ServerOrigin::ManualDeferred => {}
            ServerOrigin::ProviderCreated => {}
        }
        if matches!(self.owner, ServerLifecycleOwner::External)
            && !matches!(self.state, ServerLifecycleState::ExternallyManaged)
        {
            return Err(ServerLifecycleContractError::ExternalOwnerMustBeExternal);
        }
        self.ssh.validate_contract()?;
        self.secrets.validate_contract()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerOrigin {
    ProviderCreated,
    ImportedExisting,
    ManualDeferred,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerLifecycleOwner {
    Pharos,
    Nixcfg,
    Janus,
    Operator,
    External,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerLifecycleState {
    Pending,
    Planning,
    Provisioning,
    Bootstrapping,
    AwaitingFirstHeartbeat,
    Live,
    Failed,
    CleanupNeeded,
    Retired,
    ExternallyManaged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerProviderRef {
    pub kind: ServerProviderKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_id: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerProviderKind {
    HetznerCloud,
    NetcupManual,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerImageRef {
    pub source: ServerImageSource,
    pub name: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ServerImageSource {
    ProviderImage,
    NixosAnywhere,
    Snapshot,
    ImportedHost,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BootstrapSource {
    pub method: BootstrapMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flake_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BootstrapMethod {
    NixosAnywhere,
    NativeSystemd,
    Manual,
    Deferred,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SshAccessIntent {
    pub route: SshRoute,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl SshAccessIntent {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        if matches!(
            self.route,
            SshRoute::Direct | SshRoute::Tailnet | SshRoute::Bastion
        ) && self.host.as_ref().is_none_or(|host| host.trim().is_empty())
        {
            return Err(ServerLifecycleContractError::SshHostRequired);
        }
        Ok(())
    }
}

/// Read-only facts used to decide whether an existing host can be bootstrapped.
/// These are observations or operator-provided facts only; credentials and raw
/// token material must never be sent in this request.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostPreflightFacts {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_authenticated: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sudo: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os_family: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixos: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nix_available: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free_disk_gib: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pharos_reachable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostPreflightRequest {
    #[serde(default = "default_existing_host_preflight_schema")]
    pub schema: String,
    #[serde(default = "default_existing_host_preflight_version")]
    pub version: u16,
    pub host_name: String,
    pub ssh: SshAccessIntent,
    #[serde(default)]
    pub facts: ExistingHostPreflightFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pharos_url: Option<String>,
}

impl ExistingHostPreflightRequest {
    pub fn validate_contract(&self) -> Result<(), String> {
        validate_preflight_schema_version(&self.schema, self.version)?;
        if !safe_preflight_text(&self.host_name) {
            return Err("preflight host_name must be plain non-secret text".to_string());
        }
        self.ssh
            .validate_contract()
            .map_err(|error| error.to_string())?;
        for value in [
            self.ssh.user.as_deref(),
            self.ssh.host.as_deref(),
            self.facts.os_family.as_deref(),
            self.pharos_url.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if !safe_preflight_text(value) {
                return Err("preflight request contains unsafe text".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PreflightCheckState {
    Pass,
    Warn,
    Fail,
    Unknown,
}

impl PreflightCheckState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Pass => "pass",
            Self::Warn => "warn",
            Self::Fail => "fail",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostPreflightCheck {
    pub key: String,
    pub label: String,
    pub state: PreflightCheckState,
    pub message: String,
}

impl ExistingHostPreflightCheck {
    fn validate_contract(&self) -> Result<(), String> {
        for value in [&self.key, &self.label, self.state.label(), &self.message] {
            if !safe_preflight_text(value) {
                return Err("preflight check must be plain non-secret text".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostBootstrapOption {
    pub method: BootstrapMethod,
    pub label: String,
    pub available: bool,
    pub message: String,
    #[serde(default)]
    pub changes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_handoff: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_token_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_state: Option<String>,
}

impl ExistingHostBootstrapOption {
    fn validate_contract(&self) -> Result<(), String> {
        let mut values = vec![self.label.as_str(), self.message.as_str()];
        values.extend(self.changes.iter().map(String::as_str));
        values.extend(self.token_handoff.as_deref());
        values.extend(self.existing_token_policy.as_deref());
        values.extend(self.next_state.as_deref());
        for value in values {
            if !safe_preflight_text(value) {
                return Err("bootstrap option must be plain non-secret text".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostPreflightSummary {
    pub state: PreflightCheckState,
    pub label: String,
    pub message: String,
}

impl ExistingHostPreflightSummary {
    fn validate_contract(&self) -> Result<(), String> {
        for value in [&self.label, &self.message] {
            if !safe_preflight_text(value) {
                return Err("preflight summary must be plain non-secret text".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExistingHostPreflightReport {
    #[serde(default = "default_existing_host_preflight_schema")]
    pub schema: String,
    #[serde(default = "default_existing_host_preflight_version")]
    pub version: u16,
    pub host_name: String,
    pub checked_at: UnixSeconds,
    pub summary: ExistingHostPreflightSummary,
    #[serde(default)]
    pub checks: Vec<ExistingHostPreflightCheck>,
    #[serde(default)]
    pub bootstrap_options: Vec<ExistingHostBootstrapOption>,
    pub next_action: String,
}

impl ExistingHostPreflightReport {
    pub fn validate_contract(&self) -> Result<(), String> {
        validate_preflight_schema_version(&self.schema, self.version)?;
        if !safe_preflight_text(&self.host_name) {
            return Err("preflight report host_name must be plain non-secret text".to_string());
        }
        self.summary.validate_contract()?;
        for check in &self.checks {
            check.validate_contract()?;
        }
        for option in &self.bootstrap_options {
            option.validate_contract()?;
        }
        if !safe_preflight_text(&self.next_action) {
            return Err("preflight next_action must be plain non-secret text".to_string());
        }
        Ok(())
    }
}

fn validate_preflight_schema_version(schema: &str, version: u16) -> Result<(), String> {
    if schema != EXISTING_HOST_PREFLIGHT_SCHEMA {
        return Err(format!(
            "unsupported preflight schema {schema:?}; expected {EXISTING_HOST_PREFLIGHT_SCHEMA:?}"
        ));
    }
    if version != EXISTING_HOST_PREFLIGHT_VERSION {
        return Err(format!(
            "unsupported preflight version {version}; expected {EXISTING_HOST_PREFLIGHT_VERSION}"
        ));
    }
    Ok(())
}

fn safe_preflight_text(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.contains('\n')
        && !value.contains('\r')
        && !looks_like_secret_material(value)
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SshRoute {
    Direct,
    Tailnet,
    Bastion,
    None,
    Unknown,
}

/// Secret material is modeled only as references to the owner/location that
/// stores it. Provider API tokens, SSH private keys, registration tokens, and
/// raw beacon tokens must never live in this value.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerSecretBoundary {
    #[serde(default)]
    pub refs: Vec<SecretReference>,
}

impl ServerSecretBoundary {
    fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for reference in &self.refs {
            reference.validate_contract()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SecretReference {
    pub kind: SecretMaterialKind,
    pub owner: SecretOwner,
    pub location: SecretLocation,
    pub reference: String,
}

impl SecretReference {
    fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        let value = self.reference.trim();
        if value.is_empty() || value.contains('\n') || value.contains('\r') {
            return Err(ServerLifecycleContractError::InvalidSecretReference);
        }
        let lowered = value.to_ascii_lowercase();
        if lowered.contains("-----begin")
            || lowered.starts_with("bearer ")
            || lowered.starts_with("pat_")
        {
            return Err(ServerLifecycleContractError::InvalidSecretReference);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretMaterialKind {
    ProviderApiToken,
    SshPrivateKey,
    RegistrationToken,
    BeaconToken,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretOwner {
    Janus,
    Agenix,
    OperatorLocal,
    ExternalVault,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SecretLocation {
    Environment,
    File,
    JanusSecret,
    AgeRecipient,
    ExternalSecretRef,
}

/// Runtime-only overlay derived from `Host`/`HostReport`; this is what can back
/// `/hosts.json` or `/declared-hosts.json` without contaminating declaration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ServerObservedState {
    pub liveness: Liveness,
    pub last_seen: Option<UnixSeconds>,
    pub heartbeat_interval_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_rtt: Option<InboundRttObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<HostLocation>,
    pub freshness: NixFreshness,
    #[serde(default)]
    pub service_observations: Vec<ServiceObservation>,
    #[serde(default)]
    pub backup_observations: Vec<BackupObservation>,
}

impl ServerObservedState {
    pub fn from_host(host: &Host, now: UnixSeconds) -> Self {
        Self {
            liveness: liveness(host.last_seen, host.heartbeat_interval_secs, now),
            last_seen: host.last_seen,
            heartbeat_interval_secs: host.heartbeat_interval_secs,
            inbound_rtt: host.inbound_rtt,
            location: host.location.clone(),
            freshness: host.freshness.clone(),
            service_observations: host.service_observations.clone(),
            backup_observations: host.backup_observations.clone(),
        }
    }
}

/// Visible state machine for a provisioning/import job. These values are safe
/// for activity text and UI progress strips; provider credentials and raw
/// tokens are never represented here.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningJobState {
    Planning,
    Provisioning,
    Bootstrapping,
    WaitingForHeartbeat,
    BackupPending,
    Complete,
    Failed,
    CleanupNeeded,
}

impl ProvisioningJobState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Planning => "planning",
            Self::Provisioning => "provisioning",
            Self::Bootstrapping => "bootstrapping",
            Self::WaitingForHeartbeat => "waiting for heartbeat",
            Self::BackupPending => "backup pending",
            Self::Complete => "complete",
            Self::Failed => "failed",
            Self::CleanupNeeded => "cleanup needed",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupSetupIntent {
    Required,
    External,
    EnrollLater,
    Absent,
    Deferred,
}

impl BackupSetupIntent {
    pub fn label(self) -> &'static str {
        match self {
            Self::Required => "backup required",
            Self::External => "managed elsewhere",
            Self::EnrollLater => "enroll later",
            Self::Absent => "no backups",
            Self::Deferred => "backup decision pending",
        }
    }

    pub fn next_action(self) -> &'static str {
        match self {
            Self::Required => "observe existing jobs or queue Pharos enrollment",
            Self::External => "observe external backup evidence when available",
            Self::EnrollLater => "queue backup enrollment after first heartbeat",
            Self::Absent => "record that backups are intentionally absent",
            Self::Deferred => "ask again before marking onboarding complete",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum LocationSetupIntent {
    Auto,
    Manual,
    SiteFallback,
    Hidden,
}

impl LocationSetupIntent {
    pub fn label(self) -> &'static str {
        match self {
            Self::Auto => "auto location",
            Self::Manual => "manual location",
            Self::SiteFallback => "site fallback",
            Self::Hidden => "hidden location",
        }
    }

    pub fn next_action(self) -> &'static str {
        match self {
            Self::Auto => "use runtime auto-detection when the beacon reports",
            Self::Manual => "collect declared coordinates outside runtime facts",
            Self::SiteFallback => "use provider or site fallback when runtime is missing",
            Self::Hidden => "keep host coordinates hidden",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningSetupIntent {
    pub backup: BackupSetupIntent,
    pub location: LocationSetupIntent,
}

impl ProvisioningSetupIntent {
    pub fn backup_label(&self) -> &'static str {
        self.backup.label()
    }

    pub fn backup_next_action(&self) -> &'static str {
        self.backup.next_action()
    }

    pub fn location_label(&self) -> &'static str {
        self.location.label()
    }

    pub fn location_next_action(&self) -> &'static str {
        self.location.next_action()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningProgressEntry {
    pub state: ProvisioningJobState,
    pub message: String,
    pub observed_at: UnixSeconds,
}

impl ProvisioningProgressEntry {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        let message = self.message.trim();
        if message.is_empty()
            || message.contains('\n')
            || message.contains('\r')
            || looks_like_secret_material(message)
        {
            return Err(ServerLifecycleContractError::InvalidProgressMessage);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningHandoff {
    pub method: BootstrapMethod,
    pub status: String,
    pub title: String,
    pub summary: String,
    pub token_policy: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_target: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_ref: Option<String>,
    #[serde(default)]
    pub next_steps: Vec<String>,
}

impl ProvisioningHandoff {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for value in [
            self.status.as_str(),
            self.title.as_str(),
            self.summary.as_str(),
            self.token_policy.as_str(),
        ] {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidHandoff);
            }
        }
        for value in self
            .secret_target
            .as_deref()
            .into_iter()
            .chain(self.command_ref.as_deref())
            .chain(self.next_steps.iter().map(String::as_str))
        {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidHandoff);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningJob {
    #[serde(default = "default_provisioning_job_schema")]
    pub schema: String,
    #[serde(default = "default_provisioning_job_version")]
    pub version: u16,
    pub id: String,
    pub provider: String,
    pub template: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub is_nix: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval_secs: Option<u64>,
    pub state: ProvisioningJobState,
    pub created_at: UnixSeconds,
    pub updated_at: UnixSeconds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<ProvisioningHandoff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_intent: Option<ProvisioningSetupIntent>,
    #[serde(default)]
    pub progress: Vec<ProvisioningProgressEntry>,
}

impl ProvisioningJob {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        if self.schema != PROVISIONING_JOB_SCHEMA {
            return Err(ServerLifecycleContractError::UnsupportedSchema {
                expected: PROVISIONING_JOB_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.version != PROVISIONING_JOB_VERSION {
            return Err(ServerLifecycleContractError::UnsupportedVersion {
                expected: PROVISIONING_JOB_VERSION,
                actual: self.version,
            });
        }
        if self.id.trim().is_empty() {
            return Err(ServerLifecycleContractError::EmptyJobId);
        }
        if self.provider.trim().is_empty() {
            return Err(ServerLifecycleContractError::EmptyProvider);
        }
        if self.template.trim().is_empty() {
            return Err(ServerLifecycleContractError::EmptyTemplate);
        }
        if let Some(handoff) = &self.handoff {
            handoff.validate_contract()?;
        }
        for entry in &self.progress {
            entry.validate_contract()?;
        }
        Ok(())
    }
}

fn safe_provisioning_text(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && !value.contains('\n')
        && !value.contains('\r')
        && !looks_like_secret_material(value)
}

fn looks_like_secret_material(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("-----begin")
        || lowered.contains("bearer ")
        || lowered.contains(" api_key")
        || lowered.contains("api-key")
        || lowered.contains("token=")
        || lowered.starts_with("pat_")
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServerLifecycleContractError {
    UnsupportedSchema { expected: String, actual: String },
    UnsupportedVersion { expected: u16, actual: u16 },
    EmptyHostName,
    EmptyHostname,
    ProviderRequired,
    ExternalOwnerMustBeExternal,
    SshHostRequired,
    InvalidSecretReference,
    InvalidProgressMessage,
    InvalidHandoff,
    EmptyJobId,
    EmptyProvider,
    EmptyTemplate,
}

impl std::fmt::Display for ServerLifecycleContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => {
                write!(
                    f,
                    "unsupported server lifecycle schema {actual:?}; expected {expected:?}"
                )
            }
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported server lifecycle version {actual}; expected {expected}"
                )
            }
            Self::EmptyHostName => write!(f, "server lifecycle host_name is empty"),
            Self::EmptyHostname => write!(f, "server lifecycle hostname is empty"),
            Self::ProviderRequired => write!(f, "provider-created server requires provider"),
            Self::ExternalOwnerMustBeExternal => {
                write!(
                    f,
                    "external owner requires externally-managed lifecycle state"
                )
            }
            Self::SshHostRequired => write!(f, "ssh route requires host"),
            Self::InvalidSecretReference => write!(f, "secret reference must not be raw material"),
            Self::InvalidProgressMessage => {
                write!(f, "progress message must be plain non-secret text")
            }
            Self::InvalidHandoff => write!(f, "handoff must be plain non-secret text"),
            Self::EmptyJobId => write!(f, "provisioning job id is required"),
            Self::EmptyProvider => write!(f, "provisioning provider is required"),
            Self::EmptyTemplate => write!(f, "provisioning template is required"),
        }
    }
}

impl std::error::Error for ServerLifecycleContractError {}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestLocationMode {
    /// Use runtime observations when available, then declared/site fallback.
    #[default]
    Auto,
    /// Always use the declared coordinates for this host.
    DeclaredOverride,
    /// Use declared coordinates only when no runtime observation exists.
    DeclaredFallback,
    /// Do not expose host-level coordinates in Pharos.
    Hidden,
}

/// Derived liveness — never stored; computed from `now - last_seen` (PHAROS-9).
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Liveness {
    Live,
    Stale,
    Down,
    /// Onboarded but no heartbeat yet — the grey state (PHAROS-10).
    AwaitingFirstHeartbeat,
}

impl Liveness {
    /// Accessible status badge: `(css_color, word)`. In the UI this is paired
    /// with an SVG icon + the word (PHAROS-10, point 3) — colour is never the
    /// only cue. Amber is used for `Stale`, not yellow.
    pub fn badge(self) -> (&'static str, &'static str) {
        match self {
            Liveness::Live => ("#2e7d32", "live"),
            Liveness::Stale => ("#b26a00", "stale"),
            Liveness::Down => ("#c62828", "down"),
            Liveness::AwaitingFirstHeartbeat => ("#9e9e9e", "awaiting"),
        }
    }
}

/// Derive liveness from the heartbeat cadence: `Live` within 2× the interval,
/// `Stale` within 5×, `Down` beyond; `AwaitingFirstHeartbeat` if never seen.
/// `now` and `last_seen` are both server-stamped (PHAROS-9).
pub fn liveness(
    last_seen: Option<UnixSeconds>,
    interval_secs: Option<u64>,
    now: UnixSeconds,
) -> Liveness {
    let Some(last) = last_seen else {
        return Liveness::AwaitingFirstHeartbeat;
    };
    let interval = i64::try_from(interval_secs.unwrap_or(60)).unwrap_or(60);
    let age = (now - last).max(0);
    if age <= interval * 2 {
        Liveness::Live
    } else if age <= interval * 5 {
        Liveness::Stale
    } else {
        Liveness::Down
    }
}

pub const HOST_REPORT_SCHEMA: &str = "inspr.pharos.host-report.v1";
pub const HOST_REPORT_VERSION: u16 = 1;

fn default_host_report_schema() -> String {
    HOST_REPORT_SCHEMA.to_string()
}

fn default_host_report_version() -> u16 {
    HOST_REPORT_VERSION
}

/// What a `pharos-beacon` sends to `pharosd` (PHAROS-9 ingestion). The server
/// adds the receive timestamp; the agent never sends its own liveness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostReport {
    #[serde(default = "default_host_report_schema")]
    pub schema: String,
    #[serde(default = "default_host_report_version")]
    pub version: u16,
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    pub heartbeat_interval_secs: u64,
    pub freshness: NixFreshness,
    #[serde(default)]
    pub service_observations: Vec<ServiceObservation>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_observations: Vec<BackupObservation>,
    /// Previous successful host-to-Pharos report submission round trip, in
    /// milliseconds. First reports and old beacons omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound_rtt_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<HostLocation>,
}

impl HostReport {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != HOST_REPORT_SCHEMA {
            return Err(format!(
                "unsupported report schema {:?}; expected {:?}",
                self.schema, HOST_REPORT_SCHEMA
            ));
        }
        if self.version != HOST_REPORT_VERSION {
            return Err(format!(
                "unsupported report version {}; expected {}",
                self.version, HOST_REPORT_VERSION
            ));
        }
        if self
            .inbound_rtt_ms
            .is_some_and(|millis| millis > MAX_INBOUND_RTT_MS)
        {
            return Err(format!("inbound_rtt_ms must be <= {}", MAX_INBOUND_RTT_MS));
        }
        for observation in &self.backup_observations {
            observation.validate_contract()?;
        }
        if let Some(location) = &self.location {
            location.validate_contract()?;
            if location.manual_override {
                return Err("runtime report location cannot be a manual override".to_string());
            }
            if matches!(
                location.source,
                HostLocationSource::Declared | HostLocationSource::Fallback
            ) {
                return Err(
                    "runtime report location source must be wifi, ip, provider, or unknown"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServiceObservationState {
    Healthy,
    Warning,
    Stale,
    Unknown,
}

impl ServiceObservationState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Warning => "warning",
            Self::Stale => "stale",
            Self::Unknown => "unknown",
        }
    }
}

/// Non-secret runtime observation about a service or host subsystem.
/// Keep this intentionally coarse: stable id, human label, state, and summary.
/// Do not include process lists, env vars, URLs with credentials, or raw probe
/// payloads.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServiceObservation {
    pub id: String,
    pub label: String,
    pub state: ServiceObservationState,
    pub summary: String,
}

impl ServiceObservation {
    pub fn nix_freshness(freshness: &NixFreshness) -> Self {
        let (state, summary) = if !freshness.applicable {
            (ServiceObservationState::Unknown, "nix: n/a".to_string())
        } else if freshness.flake_lock_age_days.is_none() || freshness.commits_behind.is_none() {
            (
                ServiceObservationState::Unknown,
                "freshness partially observed".to_string(),
            )
        } else if freshness.flake_lock_age_days.unwrap_or(0) > 0
            || freshness.commits_behind.unwrap_or(0) > 0
        {
            (ServiceObservationState::Warning, freshness.tldr())
        } else {
            (ServiceObservationState::Healthy, "up to date".to_string())
        };
        Self {
            id: "nix-freshness".to_string(),
            label: "Nix freshness".to_string(),
            state,
            summary,
        }
    }
}

/// Typed backup posture observation carried by beacons once PHAROS-63 adds
/// collectors. PHAROS-62 deliberately keeps this separate from the generic
/// `ServiceObservation`: backup status needs attempt/success/check/restore
/// evidence, while `ServiceObservation` stays a compact scan signal.
///
/// Staged rollout relationship:
/// - `HostReport.backup_observations` can accept these additively now.
/// - `Host` JSON persistence and dashboard overlays stay unchanged until
///   PHAROS-64 wires storage/API surfaces.
/// - Values are sanitized metadata only: no repository passwords, env values,
///   credential-bearing URLs, raw logs, or secret paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupObservation {
    pub id: String,
    pub label: String,
    pub engine: BackupEngine,
    pub state: BackupPostureState,
    pub configured: BackupConfiguredState,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub schedule: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_attempt_state: Option<BackupRunState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snapshot_count: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latest_snapshot_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_check_state: Option<BackupValidationState>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restore_validation: Option<BackupValidationObservation>,
}

impl BackupObservation {
    pub fn validate_contract(&self) -> Result<(), String> {
        for value in [self.id.as_str(), self.label.as_str(), self.summary.as_str()] {
            if !safe_observation_text(value) {
                return Err("backup observation text must be sanitized".to_string());
            }
        }
        for value in self
            .target_label
            .as_deref()
            .into_iter()
            .chain(self.repository_id.as_deref())
            .chain(self.schedule.as_deref())
        {
            if !safe_observation_text(value) {
                return Err("backup observation metadata must be sanitized".to_string());
            }
        }
        if let Some(restore) = &self.restore_validation {
            restore.validate_contract()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupEngine {
    Restic,
    Borg,
    Kopia,
    ProviderSnapshot,
    Other,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupPostureState {
    Healthy,
    Warning,
    Stale,
    Failed,
    Unknown,
    Missing,
    NotConfigured,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupConfiguredState {
    Enabled,
    Disabled,
    External,
    Missing,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupRunState {
    Succeeded,
    Failed,
    Running,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BackupValidationObservation {
    pub level: BackupValidationLevel,
    pub state: BackupValidationState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checked_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
}

impl BackupValidationObservation {
    pub fn validate_contract(&self) -> Result<(), String> {
        for value in self
            .evidence_label
            .as_deref()
            .into_iter()
            .chain(self.summary.as_deref())
        {
            if !safe_observation_text(value) {
                return Err("backup validation evidence must be sanitized".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupValidationLevel {
    SnapshotExists,
    RepositoryCheck,
    MountList,
    RestoreSample,
    DiffHash,
    OperatorTest,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupValidationState {
    Passed,
    Failed,
    Stale,
    Unknown,
}

fn safe_observation_text(value: &str) -> bool {
    let value = value.trim();
    let lowered = value.to_ascii_lowercase();
    !value.is_empty()
        && !value.contains('\n')
        && !value.contains('\r')
        && !value.contains("://")
        && !value.contains('?')
        && !value.contains('#')
        && !lowered.contains("password")
        && !lowered.contains("secret=")
        && !lowered.contains("pass=")
        && !looks_like_secret_material(value)
}

/// What `inspr onboard` will send before installing `pharos-beacon` (PHAROS-7).
/// The server creates/rotates the per-host token and starts the host in the
/// grey "awaiting first heartbeat" state.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRegistration {
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    pub heartbeat_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostRegistrationResponse {
    pub name: String,
    pub token: String,
}

/// The declared host/service manifest shared with nixcfg and HostDash
/// (PHAROS-26). Version 1 is additive: consumers must ignore unknown fields,
/// producers must default newly-added optional fields, and incompatible changes
/// need a new schema/version pair rather than changing this contract in place.
pub const HOST_MANIFEST_SCHEMA: &str = "inspr.hostdash.config.v1";
pub const HOST_MANIFEST_VERSION: u16 = 1;

/// A declared host/service manifest generated by nixcfg. This is configuration
/// intent only; runtime observations belong to Pharos overlays, not this value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct HostManifest {
    pub schema: String,
    pub version: u16,
    #[serde(default, rename = "generatedBy")]
    pub generated_by: Option<String>,
    pub slug: String,
    #[serde(default, rename = "storageKey")]
    pub storage_key: Option<String>,
    pub host: ManifestHost,
    #[serde(default)]
    pub meta: Vec<ManifestMeta>,
    #[serde(default)]
    pub palette: Option<ManifestPalette>,
    #[serde(default)]
    pub wings: Vec<ManifestWing>,
    #[serde(default)]
    pub services: Vec<ManifestService>,
    #[serde(default)]
    pub policy: ManifestPolicy,
}

impl HostManifest {
    pub fn validate_contract(&self) -> Result<(), ManifestContractError> {
        if self.schema != HOST_MANIFEST_SCHEMA {
            return Err(ManifestContractError::UnsupportedSchema {
                expected: HOST_MANIFEST_SCHEMA.to_string(),
                actual: self.schema.clone(),
            });
        }
        if self.version != HOST_MANIFEST_VERSION {
            return Err(ManifestContractError::UnsupportedVersion {
                expected: HOST_MANIFEST_VERSION,
                actual: self.version,
            });
        }
        if self.slug.trim().is_empty() {
            return Err(ManifestContractError::EmptySlug);
        }
        if self.host.name.trim().is_empty() {
            return Err(ManifestContractError::EmptyHostName);
        }
        if let Some(location) = &self.host.location {
            location
                .validate_contract()
                .map_err(ManifestContractError::InvalidHostLocation)?;
            if location.source != HostLocationSource::Declared {
                return Err(ManifestContractError::InvalidHostLocation(
                    "declared host location source must be declared".to_string(),
                ));
            }
        }
        match self.host.location_mode {
            ManifestLocationMode::DeclaredOverride | ManifestLocationMode::DeclaredFallback
                if self.host.location.is_none() =>
            {
                return Err(ManifestContractError::InvalidHostLocation(format!(
                    "locationMode {:?} requires declared host.location",
                    self.host.location_mode
                )));
            }
            ManifestLocationMode::Hidden if self.host.location.is_some() => {
                return Err(ManifestContractError::InvalidHostLocation(
                    "locationMode hidden cannot also declare host.location".to_string(),
                ));
            }
            _ => {}
        }
        if !self.policy.declared_only {
            return Err(ManifestContractError::ManifestEmbedsRuntimeState);
        }
        if self.policy.privileged_actions.janus_required
            && self.policy.privileged_actions.mode != PrivilegedActionMode::Janus
        {
            return Err(ManifestContractError::JanusRequiredWithoutJanus);
        }

        let wing_ids: BTreeSet<&str> = self.wings.iter().map(|wing| wing.id.as_str()).collect();
        for service in &self.services {
            if !wing_ids.contains(service.wing.as_str()) {
                return Err(ManifestContractError::UndefinedWing {
                    service: service.name.clone(),
                    wing: service.wing.clone(),
                });
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestHost {
    pub name: String,
    #[serde(default)]
    pub role: Option<String>,
    #[serde(default)]
    pub os: Option<String>,
    #[serde(default)]
    pub fqdn: Option<String>,
    #[serde(default)]
    pub ip: Option<String>,
    #[serde(default)]
    pub site: Option<String>,
    #[serde(default, rename = "locationMode")]
    pub location_mode: ManifestLocationMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<HostLocation>,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub heading: Option<String>,
    #[serde(default)]
    pub eyebrow: Option<String>,
    #[serde(default)]
    pub subtitle: Option<String>,
    #[serde(default)]
    pub access: BTreeMap<String, String>,
}

impl ManifestHost {
    pub fn lan_hostname(&self) -> Option<&str> {
        self.access
            .get("lanHostname")
            .or(self.fqdn.as_ref())
            .map(String::as_str)
    }

    pub fn lan_ip(&self) -> Option<&str> {
        self.access
            .get("lanIp")
            .or(self.ip.as_ref())
            .map(String::as_str)
    }

    pub fn tailnet_hostname(&self) -> Option<&str> {
        self.access.get("tailnet").map(String::as_str)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ManifestMeta {
    Text(String),
    Item(ManifestMetaItem),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestMetaItem {
    pub text: String,
    #[serde(default)]
    pub code: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ManifestPalette {
    pub name: String,
    #[serde(default, rename = "displayName")]
    pub display_name: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub accent: Option<String>,
    #[serde(default)]
    pub gradient: BTreeMap<String, String>,
    #[serde(default)]
    pub text: serde_json::Value,
    #[serde(default)]
    pub zellij: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestWing {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub color: Option<String>,
    #[serde(default)]
    pub icon: Option<String>,
}

/// Declared service card. `passive` declares a non-clickable/passive service;
/// `status_policy.source` declares who may produce status:
/// HostDash client probes, static declaration, passive/no probe, or Pharos
/// server/runtime observations. The manifest never stores probe results.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestService {
    pub wing: String,
    pub name: String,
    #[serde(default)]
    pub purpose: String,
    #[serde(default)]
    pub icon: String,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub urls: BTreeMap<String, String>,
    #[serde(default, rename = "sameHost")]
    pub same_host: bool,
    #[serde(default)]
    pub scheme: Option<String>,
    #[serde(default)]
    pub port: Option<String>,
    #[serde(default, rename = "hostPort")]
    pub host_port: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub search: Option<String>,
    #[serde(default)]
    pub passive: bool,
    #[serde(default)]
    pub foot: Option<String>,
    #[serde(default)]
    pub status: Option<ManifestStaticStatus>,
    #[serde(default)]
    pub probe: Option<ManifestProbePolicy>,
    #[serde(default, rename = "certIssue")]
    pub cert_issue: bool,
    #[serde(default)]
    pub note: Option<String>,
    #[serde(default, rename = "statusPolicy")]
    pub status_policy: ManifestStatusPolicy,
    #[serde(default, rename = "privilegedAction")]
    pub privileged_action: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ManifestStaticStatus {
    Up,
    Down,
    Cert,
    External,
    Protected,
    Checking,
    Passive,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ManifestProbePolicy {
    Enabled(bool),
    Named(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestStatusPolicy {
    #[serde(default)]
    pub source: ManifestStatusSource,
    #[serde(default, rename = "staticState")]
    pub static_state: Option<ManifestStaticStatus>,
}

impl Default for ManifestStatusPolicy {
    fn default() -> Self {
        Self {
            source: ManifestStatusSource::HostDashProbe,
            static_state: None,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
pub enum ManifestStatusSource {
    /// Client/HostDash reachability probe. This answers "can this browser reach
    /// the declared URL variant?"
    #[serde(rename = "hostdash-probe", alias = "client-reachable")]
    #[default]
    HostDashProbe,
    /// Static declaration such as protected/external/cert without live probing.
    #[serde(rename = "hostdash-static", alias = "static")]
    HostDashStatic,
    /// Passive/informational service; no click target or active probe expected.
    #[serde(rename = "passive")]
    Passive,
    /// Pharos-owned server/runtime observation, including beacon- or
    /// server-probe-derived status overlays.
    #[serde(rename = "pharos-runtime", alias = "server-probed")]
    PharosRuntime,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestPolicy {
    #[serde(default = "default_true", rename = "declaredOnly")]
    pub declared_only: bool,
    #[serde(default, rename = "runtimeStateOwner")]
    pub runtime_state_owner: RuntimeStateOwner,
    #[serde(default, rename = "privilegedActions")]
    pub privileged_actions: PrivilegedActions,
}

impl Default for ManifestPolicy {
    fn default() -> Self {
        Self {
            declared_only: true,
            runtime_state_owner: RuntimeStateOwner::Pharos,
            privileged_actions: PrivilegedActions::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeStateOwner {
    #[default]
    Pharos,
    Hostdash,
    None,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PrivilegedActions {
    #[serde(default)]
    pub mode: PrivilegedActionMode,
    #[serde(default, rename = "janusRequired")]
    pub janus_required: bool,
}

impl Default for PrivilegedActions {
    fn default() -> Self {
        Self {
            mode: PrivilegedActionMode::None,
            janus_required: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PrivilegedActionMode {
    #[default]
    None,
    Janus,
    External,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ManifestContractError {
    UnsupportedSchema { expected: String, actual: String },
    UnsupportedVersion { expected: u16, actual: u16 },
    EmptySlug,
    EmptyHostName,
    InvalidHostLocation(String),
    ManifestEmbedsRuntimeState,
    UndefinedWing { service: String, wing: String },
    JanusRequiredWithoutJanus,
}

impl std::fmt::Display for ManifestContractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsupportedSchema { expected, actual } => {
                write!(
                    f,
                    "unsupported manifest schema {actual:?}; expected {expected:?}"
                )
            }
            Self::UnsupportedVersion { expected, actual } => {
                write!(
                    f,
                    "unsupported manifest version {actual}; expected {expected}"
                )
            }
            Self::EmptySlug => write!(f, "manifest slug is empty"),
            Self::EmptyHostName => write!(f, "manifest host.name is empty"),
            Self::InvalidHostLocation(error) => write!(f, "invalid host location: {error}"),
            Self::ManifestEmbedsRuntimeState => {
                write!(f, "manifest policy.declaredOnly must be true")
            }
            Self::UndefinedWing { service, wing } => {
                write!(f, "service {service:?} references undefined wing {wing:?}")
            }
            Self::JanusRequiredWithoutJanus => {
                write!(
                    f,
                    "manifest requires Janus but privilegedActions.mode is not janus"
                )
            }
        }
    }
}

impl std::error::Error for ManifestContractError {}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tldr_variants() {
        let na = NixFreshness {
            applicable: false,
            ..Default::default()
        };
        assert_eq!(na.tldr(), "nix: n/a");

        let fresh = NixFreshness {
            applicable: true,
            ..Default::default()
        };
        assert_eq!(fresh.tldr(), "up to date");

        let behind = NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(12),
            commits_behind: Some(3),
        };
        assert_eq!(
            behind.tldr(),
            "flake.lock 12d old · 3 commits behind nixcfg"
        );
    }

    #[test]
    fn liveness_thresholds() {
        assert_eq!(
            liveness(None, Some(60), 1000),
            Liveness::AwaitingFirstHeartbeat
        );
        assert_eq!(liveness(Some(1000), Some(60), 1000), Liveness::Live);
        assert_eq!(liveness(Some(1000), Some(60), 1000 + 121), Liveness::Stale);
        assert_eq!(liveness(Some(1000), Some(60), 1000 + 301), Liveness::Down);
    }

    #[test]
    fn host_heartbeat_log_defaults_for_existing_json() {
        let host: Host = serde_json::from_str(
            r#"{"name":"hades","role":"NixOS Host","is_nix":true,"last_seen":1000,"heartbeat_interval_secs":60,"freshness":{"applicable":true,"flake_lock_age_days":null,"commits_behind":null}}"#,
        )
        .expect("deserialize old host json");

        assert_eq!(host.token_hash, None);
        assert_eq!(host.report_version, HOST_REPORT_VERSION);
        assert!(host.heartbeat_log.is_empty());
        assert!(host.inbound_rtt.is_none());
        assert!(host.location.is_none());
        assert!(host.service_observations.is_empty());
        assert!(host.backup_observations.is_empty());
    }

    #[test]
    fn host_report_location_is_optional_and_runtime_only() {
        let legacy: HostReport = serde_json::from_str(
            r#"{"schema":"inspr.pharos.host-report.v1","version":1,"name":"hsb8","role":"server","is_nix":true,"heartbeat_interval_secs":60,"freshness":{"applicable":true}}"#,
        )
        .expect("deserialize legacy report");
        assert!(legacy.location.is_none());
        assert!(legacy.inbound_rtt_ms.is_none());
        assert!(legacy.backup_observations.is_empty());
        legacy.validate_contract().expect("legacy report valid");

        let runtime = HostReport {
            inbound_rtt_ms: Some(42),
            location: Some(HostLocation {
                latitude: 48.2082,
                longitude: 16.3738,
                source: HostLocationSource::Wifi,
                accuracy_meters: Some(1200.0),
                precision_meters: None,
                observed_at: Some(1_700_000_000),
                stale: false,
                manual_override: false,
                label: Some("Vienna area".to_string()),
            }),
            ..legacy.clone()
        };
        runtime
            .validate_contract()
            .expect("runtime location source is valid");
        assert_eq!(runtime.inbound_rtt_ms, Some(42));

        let too_slow = HostReport {
            inbound_rtt_ms: Some(MAX_INBOUND_RTT_MS + 1),
            ..legacy.clone()
        };
        assert!(too_slow.validate_contract().is_err());

        let declared_runtime = HostReport {
            location: Some(HostLocation {
                latitude: 48.2082,
                longitude: 16.3738,
                source: HostLocationSource::Declared,
                accuracy_meters: None,
                precision_meters: None,
                observed_at: None,
                stale: false,
                manual_override: true,
                label: None,
            }),
            ..legacy
        };
        assert!(declared_runtime.validate_contract().is_err());
    }

    #[test]
    fn backup_observation_contract_is_typed_and_sanitized() {
        let supported_states = serde_json::to_value([
            BackupPostureState::Healthy,
            BackupPostureState::Warning,
            BackupPostureState::Stale,
            BackupPostureState::Failed,
            BackupPostureState::Unknown,
            BackupPostureState::Missing,
            BackupPostureState::NotConfigured,
        ])
        .expect("states serialize");
        assert_eq!(
            supported_states,
            serde_json::json!([
                "healthy",
                "warning",
                "stale",
                "failed",
                "unknown",
                "missing",
                "not-configured"
            ])
        );

        let observation = BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: BackupEngine::Restic,
            state: BackupPostureState::Healthy,
            configured: BackupConfiguredState::Enabled,
            summary: "last backup succeeded".to_string(),
            target_label: Some("off-box repository".to_string()),
            repository_id: Some("restic-main-repository".to_string()),
            schedule: Some("hourly".to_string()),
            next_run_at: Some(1_700_003_600),
            last_attempt_at: Some(1_700_000_000),
            last_attempt_state: Some(BackupRunState::Succeeded),
            last_success_at: Some(1_700_000_000),
            snapshot_count: Some(42),
            total_bytes: Some(1_024 * 1_024),
            latest_snapshot_bytes: Some(12_345),
            last_check_at: Some(1_699_990_000),
            last_check_state: Some(BackupValidationState::Passed),
            restore_validation: Some(BackupValidationObservation {
                level: BackupValidationLevel::RestoreSample,
                state: BackupValidationState::Passed,
                checked_at: Some(1_699_980_000),
                evidence_label: Some("sample restore drill".to_string()),
                summary: Some("operator-validated sample restore".to_string()),
            }),
        };
        observation
            .validate_contract()
            .expect("sanitized observation validates");

        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: "hsb8".to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            backup_observations: vec![observation.clone()],
            inbound_rtt_ms: None,
            location: None,
        };
        report
            .validate_contract()
            .expect("backup observations are accepted additively");

        let credential_bearing = BackupObservation {
            repository_id: Some("s3://user:password@example.invalid/bucket".to_string()),
            ..observation
        };
        assert!(credential_bearing.validate_contract().is_err());
    }

    #[test]
    fn nix_freshness_observation_is_coarse_and_non_secret() {
        let warning = ServiceObservation::nix_freshness(&NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(2),
            commits_behind: Some(0),
        });
        assert_eq!(warning.id, "nix-freshness");
        assert_eq!(warning.state, ServiceObservationState::Warning);
        assert_eq!(warning.summary, "flake.lock 2d old");

        let healthy = ServiceObservation::nix_freshness(&NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind: Some(0),
        });
        assert_eq!(healthy.state, ServiceObservationState::Healthy);
    }

    #[test]
    fn server_lifecycle_accepts_provider_created_intent_without_secret_values() {
        let intent = ServerLifecycleIntent {
            schema: SERVER_LIFECYCLE_SCHEMA.to_string(),
            version: SERVER_LIFECYCLE_VERSION,
            host_name: "hcloud-lab-1".to_string(),
            origin: ServerOrigin::ProviderCreated,
            owner: ServerLifecycleOwner::Pharos,
            state: ServerLifecycleState::Planning,
            hostname: "hcloud-lab-1".to_string(),
            provider: Some(ServerProviderRef {
                kind: ServerProviderKind::HetznerCloud,
                account_ref: Some("janus:pharos/hcloud/main".to_string()),
                resource_id: None,
            }),
            region: Some("fsn1".to_string()),
            site: Some("cloud-de".to_string()),
            instance_type: Some("cx22".to_string()),
            image: Some(ServerImageRef {
                source: ServerImageSource::ProviderImage,
                name: "debian-12".to_string(),
            }),
            bootstrap: BootstrapSource {
                method: BootstrapMethod::NixosAnywhere,
                flake_ref: Some("nixcfg#hcloud-lab-1".to_string()),
                profile: Some("server".to_string()),
            },
            ssh: SshAccessIntent {
                route: SshRoute::Direct,
                user: Some("root".to_string()),
                host: Some("203.0.113.10".to_string()),
                port: Some(22),
            },
            secrets: ServerSecretBoundary {
                refs: vec![
                    SecretReference {
                        kind: SecretMaterialKind::ProviderApiToken,
                        owner: SecretOwner::Janus,
                        location: SecretLocation::JanusSecret,
                        reference: "pharos/hcloud/main".to_string(),
                    },
                    SecretReference {
                        kind: SecretMaterialKind::SshPrivateKey,
                        owner: SecretOwner::Agenix,
                        location: SecretLocation::AgeRecipient,
                        reference: "pharos-bootstrap-root".to_string(),
                    },
                ],
            },
        };

        intent.validate_contract().expect("provider intent valid");
        let serialized = serde_json::to_string(&intent).expect("intent serializes");
        assert!(serialized.contains("hetzner-cloud"));
        assert!(serialized.contains("fsn1"));
        assert!(!serialized.contains("BEGIN OPENSSH"));
        assert!(!serialized.contains("Bearer "));

        let mut missing_provider = intent.clone();
        missing_provider.provider = None;
        assert_eq!(
            missing_provider.validate_contract(),
            Err(ServerLifecycleContractError::ProviderRequired)
        );

        let mut raw_secret = intent;
        raw_secret.secrets.refs[0].reference = "Bearer raw-provider-token".to_string();
        assert_eq!(
            raw_secret.validate_contract(),
            Err(ServerLifecycleContractError::InvalidSecretReference)
        );
    }

    #[test]
    fn server_lifecycle_supports_imported_hosts_and_runtime_overlay() {
        let intent = ServerLifecycleIntent {
            schema: SERVER_LIFECYCLE_SCHEMA.to_string(),
            version: SERVER_LIFECYCLE_VERSION,
            host_name: "hsb8".to_string(),
            origin: ServerOrigin::ImportedExisting,
            owner: ServerLifecycleOwner::Nixcfg,
            state: ServerLifecycleState::AwaitingFirstHeartbeat,
            hostname: "hsb8.lan".to_string(),
            provider: None,
            region: None,
            site: Some("parents-home".to_string()),
            instance_type: None,
            image: Some(ServerImageRef {
                source: ServerImageSource::ImportedHost,
                name: "existing-nixos".to_string(),
            }),
            bootstrap: BootstrapSource {
                method: BootstrapMethod::NativeSystemd,
                flake_ref: Some("nixcfg#hsb8".to_string()),
                profile: None,
            },
            ssh: SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("mba".to_string()),
                host: Some("hsb8".to_string()),
                port: None,
            },
            secrets: ServerSecretBoundary {
                refs: vec![SecretReference {
                    kind: SecretMaterialKind::BeaconToken,
                    owner: SecretOwner::Janus,
                    location: SecretLocation::JanusSecret,
                    reference: "pharos/beacon/hsb8".to_string(),
                }],
            },
        };
        intent
            .validate_contract()
            .expect("imported host intent valid");

        let host = Host {
            name: "hsb8".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1_000),
            heartbeat_log: vec![940, 1_000],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: Some(InboundRttObservation {
                millis: 42,
                observed_at: 1_000,
            }),
            location: None,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            },
            service_observations: vec![ServiceObservation::nix_freshness(&NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            })],
            backup_observations: vec![],
        };

        let observed = ServerObservedState::from_host(&host, 1_020);
        assert_eq!(observed.liveness, Liveness::Live);
        assert_eq!(observed.last_seen, Some(1_000));
        assert_eq!(observed.inbound_rtt.map(|rtt| rtt.millis), Some(42));
        assert_eq!(observed.freshness.tldr(), "up to date");
        assert!(observed.backup_observations.is_empty());
    }

    #[test]
    fn provisioning_progress_states_are_plain_and_non_secret() {
        let states = [
            ProvisioningJobState::Planning,
            ProvisioningJobState::Provisioning,
            ProvisioningJobState::Bootstrapping,
            ProvisioningJobState::WaitingForHeartbeat,
            ProvisioningJobState::BackupPending,
            ProvisioningJobState::Complete,
            ProvisioningJobState::Failed,
            ProvisioningJobState::CleanupNeeded,
        ];
        let labels: Vec<&str> = states.iter().map(|state| state.label()).collect();
        assert_eq!(
            labels,
            vec![
                "planning",
                "provisioning",
                "bootstrapping",
                "waiting for heartbeat",
                "backup pending",
                "complete",
                "failed",
                "cleanup needed"
            ]
        );

        let entry = ProvisioningProgressEntry {
            state: ProvisioningJobState::Planning,
            message: "Plan prepared; waiting for operator confirmation.".to_string(),
            observed_at: 1_700_000_000,
        };
        entry.validate_contract().expect("plain progress is valid");

        let token_shaped = ProvisioningProgressEntry {
            message: "provider token=raw-value".to_string(),
            ..entry.clone()
        };
        assert_eq!(
            token_shaped.validate_contract(),
            Err(ServerLifecycleContractError::InvalidProgressMessage)
        );

        let job = ProvisioningJob {
            schema: PROVISIONING_JOB_SCHEMA.to_string(),
            version: PROVISIONING_JOB_VERSION,
            id: "setup-1700000000-1".to_string(),
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            host_name: Some("hcloud-lab-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            state: ProvisioningJobState::Planning,
            created_at: 1_700_000_000,
            updated_at: 1_700_000_000,
            handoff: Some(ProvisioningHandoff {
                method: BootstrapMethod::NativeSystemd,
                status: "manual-handoff".to_string(),
                title: "Native beacon handoff".to_string(),
                summary: "Install the beacon with a runtime credential file.".to_string(),
                token_policy: "Use a file handoff; do not put credentials in command arguments."
                    .to_string(),
                secret_target: Some("/etc/pharos/pharos-beacon.env".to_string()),
                command_ref: Some("scripts/install-pharos-beacon-systemd.sh".to_string()),
                next_steps: vec!["Wait for the first heartbeat.".to_string()],
            }),
            setup_intent: Some(ProvisioningSetupIntent {
                backup: BackupSetupIntent::External,
                location: LocationSetupIntent::SiteFallback,
            }),
            progress: vec![entry],
        };
        job.validate_contract().expect("job contract is valid");
        let setup_intent = job.setup_intent.as_ref().expect("setup intent");
        assert_eq!(setup_intent.backup_label(), "managed elsewhere");
        assert_eq!(
            setup_intent.backup_next_action(),
            "observe external backup evidence when available"
        );
        assert_eq!(setup_intent.location_label(), "site fallback");
        assert_eq!(
            setup_intent.location_next_action(),
            "use provider or site fallback when runtime is missing"
        );

        let secret_handoff = ProvisioningJob {
            handoff: Some(ProvisioningHandoff {
                token_policy: "set PHAROS_TOKEN=raw-value".to_string(),
                ..job.handoff.clone().expect("handoff")
            }),
            ..job.clone()
        };
        assert_eq!(
            secret_handoff.validate_contract(),
            Err(ServerLifecycleContractError::InvalidHandoff)
        );

        let empty_provider = ProvisioningJob {
            provider: " ".to_string(),
            ..job
        };
        assert_eq!(
            empty_provider.validate_contract(),
            Err(ServerLifecycleContractError::EmptyProvider)
        );
    }

    #[test]
    fn existing_host_preflight_contract_is_plain_and_actionable() {
        let request = ExistingHostPreflightRequest {
            schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
            version: EXISTING_HOST_PREFLIGHT_VERSION,
            host_name: "legacy-1".to_string(),
            ssh: SshAccessIntent {
                route: SshRoute::Tailnet,
                user: Some("mba".to_string()),
                host: Some("legacy-1.ts.barta.cm".to_string()),
                port: Some(22),
            },
            facts: ExistingHostPreflightFacts {
                ssh_authenticated: Some(true),
                root: Some(false),
                sudo: Some(true),
                os_family: Some("linux".to_string()),
                nixos: Some(false),
                nix_available: Some(true),
                free_disk_gib: Some(12),
                pharos_reachable: Some(true),
            },
            pharos_url: Some("https://pharos.barta.cm/report".to_string()),
        };
        request.validate_contract().expect("request is valid");

        let report = ExistingHostPreflightReport {
            schema: EXISTING_HOST_PREFLIGHT_SCHEMA.to_string(),
            version: EXISTING_HOST_PREFLIGHT_VERSION,
            host_name: "legacy-1".to_string(),
            checked_at: 1_700_000_000,
            summary: ExistingHostPreflightSummary {
                state: PreflightCheckState::Pass,
                label: "Ready".to_string(),
                message: "Choose a bootstrap method; no token has been registered yet.".to_string(),
            },
            checks: vec![ExistingHostPreflightCheck {
                key: "ssh-authentication".to_string(),
                label: "SSH authentication".to_string(),
                state: PreflightCheckState::Pass,
                message: "SSH authentication has been verified.".to_string(),
            }],
            bootstrap_options: vec![ExistingHostBootstrapOption {
                method: BootstrapMethod::NativeSystemd,
                label: "Native beacon".to_string(),
                available: true,
                message: "Use this when the host should keep its current OS.".to_string(),
                changes: vec!["Install the portable beacon service.".to_string()],
                token_handoff: Some("Use a file or env-file handoff.".to_string()),
                existing_token_policy: Some(
                    "Review existing token files before rotation.".to_string(),
                ),
                next_state: Some("awaiting-first-heartbeat".to_string()),
            }],
            next_action: "Choose NixOS/declarative or native beacon bootstrap.".to_string(),
        };
        report.validate_contract().expect("report is valid");

        let raw_secret = ExistingHostPreflightRequest {
            host_name: "legacy-1 token=raw".to_string(),
            ..request
        };
        assert!(raw_secret.validate_contract().is_err());
    }

    #[test]
    fn manifest_contract_accepts_nixcfg_v1_shape() {
        let manifest: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "generatedBy": "nixcfg",
            "slug": "hsb8",
            "storageKey": "hostdash.hsb8",
            "host": {
                "name": "hsb8",
                "role": "parents' home",
                "os": "NixOS",
                "fqdn": "hsb8.lan",
                "ip": "192.168.1.100",
                "location": {
                    "latitude": 48.32,
                    "longitude": 15.92,
                    "source": "declared",
                    "accuracy_meters": 5000,
                    "manual_override": true,
                    "label": "Parents' home"
                },
                "access": {
                    "lanHostname": "hsb8.lan",
                    "lanIp": "192.168.1.100",
                    "tailnet": "hsb8"
                }
            },
            "palette": {
                "name": "custom-hsb8",
                "accent": "#e09051",
                "gradient": { "primary": "#e09051" }
            },
            "wings": [
                { "id": "home", "name": "Home Automation", "color": "var(--home)", "icon": "house" },
                { "id": "ops", "name": "Fleet & Ops", "color": "var(--signals)", "icon": "radar" }
            ],
            "services": [
                {
                    "wing": "home",
                    "name": "Home Assistant",
                    "purpose": "Home automation hub",
                    "icon": "logo-ha",
                    "url": "http://hsb8.lan:8123/",
                    "urls": {
                        "lanHostname": "http://hsb8.lan:8123/",
                        "lanIp": "http://192.168.1.100:8123/",
                        "tailnet": "http://hsb8:8123/"
                    },
                    "sameHost": true,
                    "port": ":8123",
                    "statusPolicy": { "source": "hostdash-probe" }
                },
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
        .expect("manifest json parses");

        manifest.validate_contract().expect("manifest is valid");
        assert_eq!(
            manifest
                .host
                .location
                .as_ref()
                .map(|location| location.source),
            Some(HostLocationSource::Declared)
        );
        assert_eq!(manifest.host.location_mode, ManifestLocationMode::Auto);
        assert_eq!(
            manifest
                .host
                .location
                .as_ref()
                .and_then(|location| location.label.as_deref()),
            Some("Parents' home")
        );
        assert_eq!(manifest.host.lan_hostname(), Some("hsb8.lan"));
        assert_eq!(manifest.host.lan_ip(), Some("192.168.1.100"));
        assert_eq!(manifest.host.tailnet_hostname(), Some("hsb8"));
        assert_eq!(
            manifest.services[0].status_policy.source,
            ManifestStatusSource::HostDashProbe
        );
        assert_eq!(
            manifest.services[1].status_policy.source,
            ManifestStatusSource::PharosRuntime
        );
    }

    #[test]
    fn manifest_contract_rejects_runtime_embedded_or_unknown_wings() {
        let mut manifest: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8" },
            "wings": [{ "id": "home", "name": "Home" }],
            "services": [{ "wing": "missing", "name": "Unknown" }],
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest json parses");
        assert_eq!(
            manifest.validate_contract(),
            Err(ManifestContractError::UndefinedWing {
                service: "Unknown".to_string(),
                wing: "missing".to_string()
            })
        );

        manifest.services[0].wing = "home".to_string();
        manifest.policy.declared_only = false;
        assert_eq!(
            manifest.validate_contract(),
            Err(ManifestContractError::ManifestEmbedsRuntimeState)
        );

        let invalid_location: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "location": {
                    "latitude": 91.0,
                    "longitude": 15.92,
                    "source": "declared"
                }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest json parses");
        assert!(matches!(
            invalid_location.validate_contract(),
            Err(ManifestContractError::InvalidHostLocation(_))
        ));
    }

    #[test]
    fn manifest_location_mode_validation_is_explicit() {
        let hidden_with_location: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "locationMode": "hidden",
                "location": {
                    "latitude": 48.32,
                    "longitude": 15.92,
                    "source": "declared"
                }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest json parses");
        assert!(matches!(
            hidden_with_location.validate_contract(),
            Err(ManifestContractError::InvalidHostLocation(_))
        ));

        let fallback_without_location: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "locationMode": "declared-fallback"
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest json parses");
        assert!(matches!(
            fallback_without_location.validate_contract(),
            Err(ManifestContractError::InvalidHostLocation(_))
        ));

        let partial_location = serde_json::from_value::<HostManifest>(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "locationMode": "declared-override",
                "location": {
                    "latitude": 48.32,
                    "source": "declared"
                }
            },
            "policy": { "declaredOnly": true }
        }));
        assert!(partial_location.is_err());
    }
}
