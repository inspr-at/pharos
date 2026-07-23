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
pub const MIN_HEARTBEAT_INTERVAL_SECS: u64 = 10;
pub const MAX_HEARTBEAT_INTERVAL_SECS: u64 = 3_600;
pub const MAX_FLAKE_LOCK_AGE_DAYS: u32 = 36_500;
pub const MAX_COMMITS_BEHIND: u32 = 1_000_000;
pub const MAX_SERVICE_OBSERVATIONS: usize = 64;
pub const MAX_BACKUP_OBSERVATIONS: usize = 64;
pub const MAX_HOST_REPORT_BYTES: usize = 64 * 1024;
pub const MAX_HOST_REGISTRATION_BYTES: usize = 4 * 1024;

const MAX_ROLE_BYTES: usize = 96;
const MAX_OBSERVATION_ID_BYTES: usize = 64;
const MAX_OBSERVATION_LABEL_BYTES: usize = 96;
const MAX_OBSERVATION_SUMMARY_BYTES: usize = 512;

/// Server-stamped observation of the host-to-Pharos report submission path.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct InboundRttObservation {
    pub millis: u64,
    pub observed_at: UnixSeconds,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    #[default]
    Server,
    Workstation,
}

impl HostKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Server => "server",
            Self::Workstation => "workstation",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostAlertPreferences {
    #[serde(default)]
    pub suppress_down: bool,
    #[serde(default)]
    pub suppress_backup: bool,
    #[serde(default)]
    pub suppress_nix_freshness: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostPreferences {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub accent: Option<String>,
    #[serde(default)]
    pub kind: HostKind,
    #[serde(default)]
    pub alerts: HostAlertPreferences,
}

impl HostPreferences {
    pub fn suppresses_down_alerts(&self) -> bool {
        self.kind == HostKind::Workstation || self.alerts.suppress_down
    }

    pub fn validate_contract(&self) -> Result<(), String> {
        if let Some(accent) = self.accent.as_deref() {
            let bytes = accent.as_bytes();
            if bytes.len() != 7
                || bytes.first() != Some(&b'#')
                || !bytes[1..].iter().all(u8::is_ascii_hexdigit)
            {
                return Err("host preference accent must be a six-digit hex color".to_string());
            }
        }
        Ok(())
    }
}

pub const HOST_PREFERENCES_SCHEMA: &str = "inspr.pharos.host-preferences.v1";
pub const HOST_PREFERENCES_VERSION: u16 = 1;
pub const HOST_REPORT_RESPONSE_SCHEMA: &str = "inspr.pharos.report-response.v1";
pub const HOST_REPORT_RESPONSE_VERSION: u16 = 1;

/// Narrow declarative preference registry shared with nixcfg. It contains
/// display/alert metadata only and is not extensible to commands or paths.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostPreferencesRegistry {
    pub schema: String,
    pub version: u16,
    pub hosts: BTreeMap<String, HostPreferences>,
}

impl HostPreferencesRegistry {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != HOST_PREFERENCES_SCHEMA {
            return Err(format!(
                "unsupported host preferences schema {:?}",
                self.schema
            ));
        }
        if self.version != HOST_PREFERENCES_VERSION {
            return Err(format!(
                "unsupported host preferences version {}",
                self.version
            ));
        }
        if self.hosts.is_empty() {
            return Err("host preferences registry must contain at least one host".to_string());
        }
        for (host, preferences) in &self.hosts {
            if host.is_empty()
                || host.len() > 63
                || !host.bytes().enumerate().all(|(index, byte)| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || (byte == b'-' && index > 0)
                })
                || host.ends_with('-')
            {
                return Err("host preferences registry contains an invalid host name".to_string());
            }
            preferences.validate_contract()?;
            if preferences.accent.is_none() {
                return Err("declared host preferences require an accent".to_string());
            }
        }
        Ok(())
    }

    pub fn preferences_for(&self, host: &str) -> Option<&HostPreferences> {
        self.hosts.get(host)
    }
}

/// Optional server response to a successful beacon report. Pending settings
/// reuse the exact declarative registry accepted from nixcfg; this envelope
/// cannot carry commands, paths, or arbitrary extension fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostReportResponse {
    pub schema: String,
    pub version: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_preferences: Option<HostPreferencesRegistry>,
}

impl HostReportResponse {
    pub fn pending(host: &str, preferences: HostPreferences) -> Result<Self, String> {
        let mut hosts = BTreeMap::new();
        hosts.insert(host.to_string(), preferences);
        let response = Self {
            schema: HOST_REPORT_RESPONSE_SCHEMA.to_string(),
            version: HOST_REPORT_RESPONSE_VERSION,
            pending_preferences: Some(HostPreferencesRegistry {
                schema: HOST_PREFERENCES_SCHEMA.to_string(),
                version: HOST_PREFERENCES_VERSION,
                hosts,
            }),
        };
        response.validate_contract_for(host)?;
        Ok(response)
    }

    pub fn validate_contract_for(&self, host: &str) -> Result<(), String> {
        if self.schema != HOST_REPORT_RESPONSE_SCHEMA {
            return Err(format!(
                "unsupported report response schema {:?}",
                self.schema
            ));
        }
        if self.version != HOST_REPORT_RESPONSE_VERSION {
            return Err(format!(
                "unsupported report response version {}",
                self.version
            ));
        }
        let Some(registry) = &self.pending_preferences else {
            return Ok(());
        };
        registry.validate_contract()?;
        if registry.hosts.len() != 1 || !registry.hosts.contains_key(host) {
            return Err(
                "report response preferences must contain exactly the reporting host".to_string(),
            );
        }
        Ok(())
    }

    pub fn preferences_for(&self, host: &str) -> Result<Option<&HostPreferences>, String> {
        self.validate_contract_for(host)?;
        Ok(self
            .pending_preferences
            .as_ref()
            .and_then(|registry| registry.preferences_for(host)))
    }
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
    /// Latest sanitized kernel posture reported by the beacon. Older beacons
    /// and persisted host records omit this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<KernelPosture>,
    /// Non-secret service facts from the latest beacon report. Runtime only;
    /// declared service intent stays in the manifest.
    #[serde(default)]
    pub service_observations: Vec<ServiceObservation>,
    /// Latest non-secret backup runtime observations from the beacon.
    /// Declared backup intent and enrollment policy are modeled elsewhere.
    #[serde(default)]
    pub backup_observations: Vec<BackupObservation>,
    /// Last host-reported preferences. Alert behavior may use only this applied
    /// state, never an unacknowledged UI request.
    #[serde(default)]
    pub preferences: HostPreferences,
    /// Operator intent waiting for the host-owned declarative mechanism to
    /// apply and report it back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_preferences: Option<HostPreferences>,
}

/// Nix freshness for a host (PHAROS-15): what it is "missing".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixFreshness {
    /// `false` for non-Nix hosts → renders `nix: n/a`.
    pub applicable: bool,
    /// Age of `flake.lock` in days (time since the last `nix flake update`).
    pub flake_lock_age_days: Option<u32>,
    /// How many commits the running config is behind the host's nixcfg.
    pub commits_behind: Option<u32>,
}

impl NixFreshness {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self
            .flake_lock_age_days
            .is_some_and(|days| days > MAX_FLAKE_LOCK_AGE_DAYS)
        {
            return Err(format!(
                "flake_lock_age_days must be <= {MAX_FLAKE_LOCK_AGE_DAYS}"
            ));
        }
        if self
            .commits_behind
            .is_some_and(|commits| commits > MAX_COMMITS_BEHIND)
        {
            return Err(format!("commits_behind must be <= {MAX_COMMITS_BEHIND}"));
        }
        if !self.applicable && (self.flake_lock_age_days.is_some() || self.commits_behind.is_some())
        {
            return Err("non-Nix freshness must not carry Nix values".to_string());
        }
        Ok(())
    }

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

pub const KERNEL_POSTURE_SCHEMA: &str = "inspr.pharos.kernel-posture.v1";
pub const KERNEL_POSTURE_VERSION: u16 = 1;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KernelPostureState {
    Current,
    RebootRequired,
    Unknown,
    NotApplicable,
}

impl KernelPostureState {
    pub fn label(self) -> &'static str {
        match self {
            Self::Current => "current",
            Self::RebootRequired => "reboot required",
            Self::Unknown => "unknown",
            Self::NotApplicable => "not applicable",
        }
    }
}

/// Sanitized kernel posture from a beacon. Version strings are deliberately
/// narrow and may never carry paths, derivation identifiers, or free-form
/// command output.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct KernelPosture {
    pub schema: String,
    pub version: u16,
    pub state: KernelPostureState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub running_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_version: Option<String>,
    pub observed_at: UnixSeconds,
}

impl KernelPosture {
    /// Construct posture from raw observations without retaining malformed
    /// version strings. Nix hosts need two semantic versions for a decisive
    /// state; incomplete observations remain unknown.
    pub fn observed(
        is_nix: bool,
        running_version: Option<String>,
        expected_version: Option<String>,
        observed_at: UnixSeconds,
    ) -> Self {
        let running_version = running_version.filter(|value| safe_kernel_version(value));
        let expected_version = expected_version.filter(|value| safe_kernel_version(value));
        let state = if !is_nix {
            KernelPostureState::NotApplicable
        } else {
            match (
                running_version.as_deref().and_then(kernel_semantic_version),
                expected_version
                    .as_deref()
                    .and_then(kernel_semantic_version),
            ) {
                (Some(running), Some(expected)) if running == expected => {
                    KernelPostureState::Current
                }
                (Some(_), Some(_)) => KernelPostureState::RebootRequired,
                _ => KernelPostureState::Unknown,
            }
        };
        Self {
            schema: KERNEL_POSTURE_SCHEMA.to_string(),
            version: KERNEL_POSTURE_VERSION,
            state,
            running_version,
            expected_version: is_nix.then_some(expected_version).flatten(),
            observed_at,
        }
    }

    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != KERNEL_POSTURE_SCHEMA {
            return Err("unsupported kernel posture schema".to_string());
        }
        if self.version != KERNEL_POSTURE_VERSION {
            return Err("unsupported kernel posture version".to_string());
        }
        if self.observed_at < 0 {
            return Err("kernel posture observed_at must be non-negative".to_string());
        }
        for value in self
            .running_version
            .as_deref()
            .into_iter()
            .chain(self.expected_version.as_deref())
        {
            if !safe_kernel_version(value) {
                return Err("kernel version must be sanitized".to_string());
            }
        }

        let semantic = (
            self.running_version
                .as_deref()
                .and_then(kernel_semantic_version),
            self.expected_version
                .as_deref()
                .and_then(kernel_semantic_version),
        );
        match self.state {
            KernelPostureState::Current if semantic.0.is_some() && semantic.0 == semantic.1 => {}
            KernelPostureState::RebootRequired
                if semantic.0.is_some() && semantic.1.is_some() && semantic.0 != semantic.1 => {}
            KernelPostureState::Unknown if semantic.0.is_none() || semantic.1.is_none() => {}
            KernelPostureState::NotApplicable if self.expected_version.is_none() => {}
            _ => return Err("kernel posture state does not match its versions".to_string()),
        }
        Ok(())
    }
}

fn safe_kernel_version(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && value.trim() == value
        && bytes.first().is_some_and(u8::is_ascii_digit)
        && bytes.last().is_some_and(u8::is_ascii_alphanumeric)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'+'))
        && kernel_semantic_version(value).is_some()
}

fn kernel_semantic_version(value: &str) -> Option<(u64, u64, u64)> {
    let core = value.split(['-', '_', '+']).next()?;
    let mut parts = core.split('.');
    let major = parts.next()?.parse().ok()?;
    let minor = parts.next()?.parse().ok()?;
    let patch = parts.next().unwrap_or("0").parse().ok()?;
    if parts.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
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
#[serde(deny_unknown_fields)]
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
        if self
            .label
            .as_deref()
            .is_some_and(|label| label.len() > 128 || !safe_observation_text(label))
        {
            return Err("location label must be bounded sanitized text".to_string());
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
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub backup_tools: Vec<String>,
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
        for value in &self.facts.backup_tools {
            if !safe_preflight_text(value) {
                return Err("preflight request contains unsafe backup facts".to_string());
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

/// Why a provisioning job reached its terminal `Complete` state. This is an
/// additive field so older Pharos rollback images can still read newer job
/// stores and safely ignore the richer outcome.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningTerminalOutcome {
    Provisioned,
    RolledBack,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BackupSetupIntent {
    Required,
    Optional,
    External,
    EnrollLater,
    Absent,
    Deferred,
}

impl BackupSetupIntent {
    pub fn label(self) -> &'static str {
        match self {
            Self::Required => "backup required",
            Self::Optional => "backup optional",
            Self::External => "managed elsewhere",
            Self::EnrollLater => "enroll later",
            Self::Absent => "no backups",
            Self::Deferred => "backup decision pending",
        }
    }

    pub fn next_action(self) -> &'static str {
        match self {
            Self::Required => "observe existing jobs or queue Pharos enrollment",
            Self::Optional => "offer enrollment, but do not block onboarding",
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AccessSetupIntent {
    OperatorOnly,
    AllOperators,
    LimitedUsers,
    Deferred,
}

impl AccessSetupIntent {
    pub fn label(self) -> &'static str {
        match self {
            Self::OperatorOnly => "operator only",
            Self::AllOperators => "all operators",
            Self::LimitedUsers => "limited users",
            Self::Deferred => "access decision pending",
        }
    }

    pub fn next_action(self) -> &'static str {
        match self {
            Self::OperatorOnly => {
                "keep the new host visible only to the onboarding operator until review"
            }
            Self::AllOperators => "grant the normal operator group after the host reports",
            Self::LimitedUsers => {
                "create an explicit host access grant before broadening visibility"
            }
            Self::Deferred => "ask again before making the host broadly visible",
        }
    }
}

fn default_access_setup_intent() -> AccessSetupIntent {
    AccessSetupIntent::OperatorOnly
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningSetupIntent {
    pub backup: BackupSetupIntent,
    pub location: LocationSetupIntent,
    #[serde(default = "default_access_setup_intent")]
    pub access: AccessSetupIntent,
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

    pub fn access_label(&self) -> &'static str {
        self.access.label()
    }

    pub fn access_next_action(&self) -> &'static str {
        self.access.next_action()
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningBackupProposalKind {
    NixosResticBeaconObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningBackupSecretFile {
    pub key: String,
    pub owner: SecretOwner,
    pub path: String,
    pub purpose: String,
}

impl ProvisioningBackupSecretFile {
    fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for value in [&self.key, &self.path, &self.purpose] {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidBackupProposal);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningBackupProposal {
    pub kind: ProvisioningBackupProposalKind,
    pub title: String,
    pub summary: String,
    pub module_attribute: String,
    pub nix_module: String,
    #[serde(default)]
    pub secret_files: Vec<ProvisioningBackupSecretFile>,
    #[serde(default)]
    pub next_steps: Vec<String>,
}

impl ProvisioningBackupProposal {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for value in [&self.title, &self.summary, &self.module_attribute] {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidBackupProposal);
            }
        }
        if !safe_provisioning_artifact_text(&self.nix_module) {
            return Err(ServerLifecycleContractError::InvalidBackupProposal);
        }
        for secret_file in &self.secret_files {
            secret_file.validate_contract()?;
        }
        for value in self.next_steps.iter().map(String::as_str) {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidBackupProposal);
            }
        }
        Ok(())
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
pub struct ExistingHostSetupContext {
    pub ssh: SshAccessIntent,
    pub selected_bootstrap: BootstrapMethod,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preflight_summary: Option<ExistingHostPreflightSummary>,
    #[serde(default)]
    pub preflight_checks: Vec<ExistingHostPreflightCheck>,
    #[serde(default)]
    pub verification_steps: Vec<String>,
}

impl ExistingHostSetupContext {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        self.ssh.validate_contract()?;
        for value in [self.ssh.user.as_deref(), self.ssh.host.as_deref()]
            .into_iter()
            .flatten()
        {
            if !safe_preflight_text(value) {
                return Err(ServerLifecycleContractError::InvalidExistingHostContext);
            }
        }
        if let Some(summary) = &self.preflight_summary {
            summary
                .validate_contract()
                .map_err(|_| ServerLifecycleContractError::InvalidExistingHostContext)?;
        }
        for check in &self.preflight_checks {
            check
                .validate_contract()
                .map_err(|_| ServerLifecycleContractError::InvalidExistingHostContext)?;
        }
        for value in self.verification_steps.iter().map(String::as_str) {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidExistingHostContext);
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProvisioningProviderResource {
    pub provider: String,
    pub kind: String,
    pub provider_id: String,
    pub name: String,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub location: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh: Option<SshAccessIntent>,
}

impl ProvisioningProviderResource {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for value in [
            self.provider.as_str(),
            self.kind.as_str(),
            self.provider_id.as_str(),
            self.name.as_str(),
            self.state.as_str(),
        ] {
            if !safe_provisioning_text(value) {
                return Err(ServerLifecycleContractError::InvalidProviderResource);
            }
        }
        if self
            .location
            .as_deref()
            .is_some_and(|value| !safe_provisioning_text(value))
        {
            return Err(ServerLifecycleContractError::InvalidProviderResource);
        }
        if let Some(ssh) = &self.ssh {
            ssh.validate_contract()?;
            for value in [ssh.user.as_deref(), ssh.host.as_deref()]
                .into_iter()
                .flatten()
            {
                if !safe_preflight_text(value) {
                    return Err(ServerLifecycleContractError::InvalidProviderResource);
                }
            }
        }
        Ok(())
    }
}

/// Exact, secret-free provider plan shown to an operator before paid-service
/// authorization. It may contain a one-way credential binding, but provider
/// credentials and other secret values never belong in this record.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningReviewedPaidPlan {
    pub provider_project: String,
    pub credential_binding_sha256: String,
    pub server_name: String,
    pub location: String,
    pub location_label: String,
    pub server_type: String,
    pub server_type_label: String,
    pub image: String,
    pub price_currency: String,
    pub price_hourly_gross: String,
    pub price_monthly_gross: String,
    pub max_hourly_gross: String,
    pub max_monthly_gross: String,
    pub observed_active_servers: u16,
    pub max_active_servers: u16,
    pub catalog_refreshed_at: UnixSeconds,
    pub expires_at: UnixSeconds,
    pub ssh_key_ref: String,
    pub firewall_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_executor_owner: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_credential_ref: Option<String>,
    #[serde(default)]
    pub required_labels: BTreeMap<String, String>,
    #[serde(default)]
    pub allowed_operations: Vec<String>,
    pub cleanup_policy: String,
    pub plan_sha256: String,
}

impl ProvisioningReviewedPaidPlan {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        for value in [
            self.provider_project.as_str(),
            self.location_label.as_str(),
            self.server_type_label.as_str(),
        ] {
            if !safe_paid_text(value, 200) {
                return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
            }
        }
        if self.managed_executor_owner.as_deref().is_some_and(|owner| {
            let bytes = owner.as_bytes();
            !(1..=63).contains(&bytes.len())
                || !(bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
                || bytes.iter().any(|byte| {
                    !byte.is_ascii_lowercase() && !byte.is_ascii_digit() && *byte != b'-'
                })
        }) {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        let managed_ref_valid = self
            .managed_credential_ref
            .as_deref()
            .is_none_or(|reference| {
                reference.len() == 24
                    && reference.starts_with("sec_")
                    && reference[4..]
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            });
        if !managed_ref_valid
            || self.managed_executor_owner.is_some() != self.managed_credential_ref.is_some()
        {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if !safe_paid_text(&self.cleanup_policy, 600) {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        for value in [
            self.server_name.as_str(),
            self.location.as_str(),
            self.server_type.as_str(),
            self.image.as_str(),
            self.ssh_key_ref.as_str(),
            self.firewall_ref.as_str(),
        ] {
            if !safe_paid_identifier(value, 160) {
                return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
            }
        }
        if self.price_currency.len() != 3
            || !self
                .price_currency
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        let Some(hourly) = gross_price_units(&self.price_hourly_gross) else {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        };
        let Some(monthly) = gross_price_units(&self.price_monthly_gross) else {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        };
        let Some(max_hourly) = gross_price_units(&self.max_hourly_gross) else {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        };
        let Some(max_monthly) = gross_price_units(&self.max_monthly_gross) else {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        };
        if hourly > max_hourly || monthly > max_monthly {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if self.max_active_servers != 1 || self.observed_active_servers >= self.max_active_servers {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if self.catalog_refreshed_at <= 0 || self.expires_at <= self.catalog_refreshed_at {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if self.required_labels.len() < 2 || self.required_labels.len() > 16 {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        for (key, value) in &self.required_labels {
            if !safe_paid_identifier(key, 63) || !safe_paid_identifier(value, 63) {
                return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
            }
        }
        if self.required_labels.get("managed-by").map(String::as_str) != Some("pharos")
            || self.required_labels.get("pharos-setup").map(String::as_str) != Some("tracked-job")
        {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if self.allowed_operations.len() != 2
            || !self
                .allowed_operations
                .iter()
                .any(|operation| operation == "create-server")
            || !self
                .allowed_operations
                .iter()
                .any(|operation| operation == "delete-server")
            || self
                .allowed_operations
                .iter()
                .any(|operation| !safe_paid_identifier(operation, 64))
        {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        if !lower_hex_sha256(&self.credential_binding_sha256)
            || !lower_hex_sha256(&self.plan_sha256)
        {
            return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
        }
        Ok(())
    }
}

/// Attended operator authorization for one exact reviewed paid plan.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPaidAuthorization {
    pub plan_sha256: String,
    pub operator_ref: String,
    pub operator_label: String,
    pub confirmed_at: UnixSeconds,
    pub expires_at: UnixSeconds,
}

impl ProvisioningPaidAuthorization {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        if !lower_hex_sha256(&self.plan_sha256)
            || !lower_hex_sha256(&self.operator_ref)
            || !safe_paid_text(&self.operator_label, 200)
            || self.confirmed_at <= 0
            || self.expires_at <= self.confirmed_at
        {
            return Err(ServerLifecycleContractError::InvalidPaidAuthorization);
        }
        Ok(())
    }
}

/// Single-use paid execution claim bound to the authorized plan hash.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningPaidExecution {
    pub plan_sha256: String,
    pub attempt_id: String,
    pub state: String,
    pub claimed_at: UnixSeconds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request_started_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_id: Option<String>,
}

impl ProvisioningPaidExecution {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        if !lower_hex_sha256(&self.plan_sha256)
            || !safe_paid_identifier(&self.attempt_id, 128)
            || self.claimed_at <= 0
            || !matches!(
                self.state.as_str(),
                "claimed"
                    | "request-started"
                    | "created"
                    | "reconciled"
                    | "failed-closed"
                    | "uncertain"
            )
            || self
                .provider_request_started_at
                .is_some_and(|started_at| started_at < self.claimed_at)
            || self
                .provider_id
                .as_deref()
                .is_some_and(|provider_id| !safe_paid_identifier(provider_id, 160))
        {
            return Err(ServerLifecycleContractError::InvalidPaidExecution);
        }
        let timestamps_and_identity_match_state = match self.state.as_str() {
            "claimed" => self.provider_request_started_at.is_none() && self.provider_id.is_none(),
            "request-started" => {
                self.provider_request_started_at.is_some() && self.provider_id.is_none()
            }
            "created" | "reconciled" => {
                self.provider_request_started_at.is_some() && self.provider_id.is_some()
            }
            "failed-closed" => self.provider_id.is_none(),
            "uncertain" => self.provider_request_started_at.is_some(),
            _ => false,
        };
        if !timestamps_and_identity_match_state {
            return Err(ServerLifecycleContractError::InvalidPaidExecution);
        }
        Ok(())
    }
}

/// Value-free ownership and progress for the Janus-backed identity used by a
/// managed provider server. The raw credential and SSH key never belong in
/// this contract.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProvisioningManagedIdentityState {
    AwaitingHostKey,
    Ready,
    BootstrapClaimed,
    RetryRequired,
    Uncertain,
    ReconciliationPending,
    ReconciliationClaimed,
    AwaitingHeartbeat,
    HeartbeatObserved,
    RetirementPending,
    RetirementClaimed,
    CredentialRetired,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProvisioningManagedFailure {
    CheckoutNotReady,
    JanusUnavailable,
    JanusRejected,
    SshIdentityUnavailable,
    SshUnreachable,
    HostKeyMismatch,
    BootstrapFailed,
    ResultContractInvalid,
    UncertainExecution,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProvisioningManagedIdentity {
    pub credential_ref: String,
    pub executor_owner: String,
    pub state: ProvisioningManagedIdentityState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_operator_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_key_attested_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lease_until: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_ready_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bootstrap_completed_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_heartbeat_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_retired_at: Option<UnixSeconds>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<ProvisioningManagedFailure>,
}

impl ProvisioningManagedIdentity {
    pub fn validate_contract(&self) -> Result<(), ServerLifecycleContractError> {
        let credential_ref_valid = self.credential_ref.len() == 24
            && self.credential_ref.starts_with("sec_")
            && self.credential_ref[4..]
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        let executor_valid = self.executor_owner.len() <= 63
            && self.executor_owner.chars().next().is_some_and(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit()
            })
            && self.executor_owner.chars().all(|character| {
                character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
            });
        let fingerprint_valid = self
            .host_key_fingerprint
            .as_deref()
            .is_none_or(|fingerprint| {
                fingerprint.len() == 50
                    && fingerprint.starts_with("SHA256:")
                    && fingerprint[7..]
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
            });
        let attestation_complete = self.host_key_fingerprint.is_some()
            == self.host_key_operator_ref.is_some()
            && self.host_key_fingerprint.is_some() == self.host_key_attested_at.is_some();
        let timestamps_valid = [
            self.host_key_attested_at,
            self.lease_until,
            self.credential_ready_at,
            self.bootstrap_completed_at,
            self.first_heartbeat_at,
            self.credential_retired_at,
        ]
        .into_iter()
        .flatten()
        .all(|value| value > 0);
        let state_valid = match self.state {
            ProvisioningManagedIdentityState::AwaitingHostKey => {
                self.host_key_fingerprint.is_none() && self.lease_until.is_none()
            }
            ProvisioningManagedIdentityState::Ready
            | ProvisioningManagedIdentityState::RetryRequired
            | ProvisioningManagedIdentityState::Uncertain
            | ProvisioningManagedIdentityState::ReconciliationPending => {
                self.host_key_fingerprint.is_some() && self.lease_until.is_none()
            }
            ProvisioningManagedIdentityState::BootstrapClaimed
            | ProvisioningManagedIdentityState::ReconciliationClaimed
            | ProvisioningManagedIdentityState::RetirementClaimed => self.lease_until.is_some(),
            ProvisioningManagedIdentityState::AwaitingHeartbeat => {
                self.lease_until.is_none()
                    && self.credential_ready_at.is_some()
                    && self.bootstrap_completed_at.is_some()
            }
            ProvisioningManagedIdentityState::HeartbeatObserved => {
                self.lease_until.is_none() && self.first_heartbeat_at.is_some()
            }
            ProvisioningManagedIdentityState::RetirementPending => self.lease_until.is_none(),
            ProvisioningManagedIdentityState::CredentialRetired => {
                self.lease_until.is_none() && self.credential_retired_at.is_some()
            }
        };
        if !credential_ref_valid
            || !executor_valid
            || !fingerprint_valid
            || !attestation_complete
            || self
                .host_key_operator_ref
                .as_deref()
                .is_some_and(|value| !lower_hex_sha256(value))
            || !timestamps_valid
            || !state_valid
        {
            return Err(ServerLifecycleContractError::InvalidManagedIdentity);
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_host_context: Option<ExistingHostSetupContext>,
    pub state: ProvisioningJobState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terminal_outcome: Option<ProvisioningTerminalOutcome>,
    pub created_at: UnixSeconds,
    pub updated_at: UnixSeconds,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<ProvisioningHandoff>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub setup_intent: Option<ProvisioningSetupIntent>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup_proposal: Option<ProvisioningBackupProposal>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reviewed_plan: Option<ProvisioningReviewedPaidPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_authorization: Option<ProvisioningPaidAuthorization>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_execution: Option<ProvisioningPaidExecution>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed_identity: Option<ProvisioningManagedIdentity>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub provider_resources: Vec<ProvisioningProviderResource>,
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
        if let Some(context) = &self.existing_host_context {
            context.validate_contract()?;
        }
        if let Some(backup_proposal) = &self.backup_proposal {
            backup_proposal.validate_contract()?;
        }
        if let Some(reviewed_plan) = &self.reviewed_plan {
            reviewed_plan.validate_contract()?;
            if self.provider != "hetzner-cloud"
                || self.host_name.as_deref().is_none_or(|host| {
                    !safe_paid_identifier(host, 63) || host != reviewed_plan.server_name
                })
                || self.created_at <= 0
                || self.updated_at < self.created_at
                || reviewed_plan.catalog_refreshed_at > self.created_at
                || reviewed_plan.expires_at <= self.created_at
            {
                return Err(ServerLifecycleContractError::InvalidReviewedPaidPlan);
            }
        }
        if let Some(authorization) = &self.paid_authorization {
            authorization.validate_contract()?;
            let Some(reviewed_plan) = &self.reviewed_plan else {
                return Err(ServerLifecycleContractError::PaidAuthorizationWithoutReviewedPlan);
            };
            if authorization.plan_sha256 != reviewed_plan.plan_sha256 {
                return Err(ServerLifecycleContractError::PaidPlanHashMismatch);
            }
            if authorization.expires_at != reviewed_plan.expires_at {
                return Err(ServerLifecycleContractError::PaidAuthorizationExpiryMismatch);
            }
            if authorization.confirmed_at < self.created_at
                || authorization.confirmed_at >= authorization.expires_at
                || authorization.confirmed_at > self.updated_at
            {
                return Err(ServerLifecycleContractError::InvalidPaidAuthorization);
            }
        }
        if let Some(execution) = &self.paid_execution {
            execution.validate_contract()?;
            let Some(authorization) = &self.paid_authorization else {
                return Err(ServerLifecycleContractError::PaidExecutionWithoutAuthorization);
            };
            if execution.plan_sha256 != authorization.plan_sha256
                || self
                    .reviewed_plan
                    .as_ref()
                    .is_some_and(|reviewed_plan| execution.plan_sha256 != reviewed_plan.plan_sha256)
            {
                return Err(ServerLifecycleContractError::PaidPlanHashMismatch);
            }
            if execution.claimed_at < authorization.confirmed_at
                || execution.claimed_at >= authorization.expires_at
                || execution.claimed_at > self.updated_at
                || execution
                    .provider_request_started_at
                    .is_some_and(|started_at| started_at > self.updated_at)
            {
                return Err(ServerLifecycleContractError::InvalidPaidExecution);
            }
        }
        if let Some(identity) = &self.managed_identity {
            identity.validate_contract()?;
            if self.provider != "hetzner-cloud"
                || self.reviewed_plan.is_none()
                || self.paid_execution.as_ref().is_none_or(|execution| {
                    !matches!(execution.state.as_str(), "created" | "reconciled")
                })
            {
                return Err(ServerLifecycleContractError::InvalidManagedIdentity);
            }
            if identity
                .host_key_attested_at
                .is_some_and(|at| at < self.created_at || at > self.updated_at)
                || identity
                    .credential_ready_at
                    .is_some_and(|at| at < self.created_at || at > self.updated_at)
                || identity
                    .bootstrap_completed_at
                    .is_some_and(|at| at < self.created_at || at > self.updated_at)
                || identity
                    .first_heartbeat_at
                    .is_some_and(|at| at < self.created_at || at > self.updated_at)
                || identity
                    .credential_retired_at
                    .is_some_and(|at| at < self.created_at || at > self.updated_at)
            {
                return Err(ServerLifecycleContractError::InvalidManagedIdentity);
            }
        }
        for resource in &self.provider_resources {
            resource.validate_contract()?;
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

fn safe_provisioning_artifact_text(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty() && !value.contains('\r') && !looks_like_secret_material(value)
}

fn safe_paid_text(value: &str, max_chars: usize) -> bool {
    value == value.trim()
        && value.chars().count() <= max_chars
        && safe_provisioning_text(value)
        && !value.chars().any(char::is_control)
}

fn safe_paid_identifier(value: &str, max_len: usize) -> bool {
    value == value.trim()
        && !value.is_empty()
        && value.len() <= max_len
        && value
            .chars()
            .next()
            .is_some_and(|character| character.is_ascii_alphanumeric())
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-' | ':' | '/')
        })
        && !looks_like_secret_material(value)
}

fn lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn gross_price_units(value: &str) -> Option<u128> {
    if value != value.trim() || value.is_empty() || value.len() > 21 {
        return None;
    }
    let (whole, fraction) = match value.split_once('.') {
        Some((whole, fraction)) if !fraction.is_empty() => (whole, fraction),
        Some(_) => return None,
        None => (value, ""),
    };
    if whole.is_empty()
        || whole.len() > 12
        || !whole.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.len() > 8
        || !fraction.bytes().all(|byte| byte.is_ascii_digit())
        || value.matches('.').count() > 1
    {
        return None;
    }
    let whole = whole.parse::<u128>().ok()?;
    let fraction = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u128>().ok()? * 10_u128.pow((8 - fraction.len()) as u32)
    };
    whole.checked_mul(100_000_000)?.checked_add(fraction)
}

fn looks_like_secret_material(value: &str) -> bool {
    let lowered = value.to_ascii_lowercase();
    lowered.contains("-----begin")
        || lowered.contains("bearer ")
        || lowered.contains(" api_key")
        || lowered.contains("api_key=")
        || lowered.contains("api_key:")
        || lowered.contains("apikey=")
        || lowered.contains("api-key")
        || lowered.contains("authorization:")
        || lowered.contains("token=")
        || lowered.contains("token =")
        || lowered.contains("token:")
        || lowered.contains("password=")
        || lowered.contains("password =")
        || lowered.contains("password:")
        || lowered.contains("secret=")
        || lowered.contains("secret =")
        || lowered.contains("secret:")
        || lowered.starts_with("pat_")
        || lowered.starts_with("sk-")
        || lowered.starts_with("ghp_")
        || lowered.starts_with("github_pat_")
        || lowered.starts_with("xoxb-")
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
    InvalidExistingHostContext,
    InvalidBackupProposal,
    InvalidProviderResource,
    InvalidReviewedPaidPlan,
    InvalidPaidAuthorization,
    InvalidPaidExecution,
    InvalidManagedIdentity,
    PaidAuthorizationWithoutReviewedPlan,
    PaidExecutionWithoutAuthorization,
    PaidPlanHashMismatch,
    PaidAuthorizationExpiryMismatch,
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
            Self::InvalidExistingHostContext => {
                write!(f, "existing-host context must be plain non-secret text")
            }
            Self::InvalidBackupProposal => {
                write!(f, "backup proposal must be plain non-secret text")
            }
            Self::InvalidProviderResource => {
                write!(f, "provider resource must be plain non-secret text")
            }
            Self::InvalidReviewedPaidPlan => {
                write!(
                    f,
                    "reviewed paid plan is invalid or exceeds its bounded policy"
                )
            }
            Self::InvalidPaidAuthorization => {
                write!(
                    f,
                    "paid authorization is invalid or outside its review window"
                )
            }
            Self::InvalidPaidExecution => {
                write!(
                    f,
                    "paid execution is invalid or outside its authorization window"
                )
            }
            Self::InvalidManagedIdentity => {
                write!(f, "managed provisioning identity is invalid")
            }
            Self::PaidAuthorizationWithoutReviewedPlan => {
                write!(f, "paid authorization requires an exact reviewed plan")
            }
            Self::PaidExecutionWithoutAuthorization => {
                write!(f, "paid execution requires an attended authorization")
            }
            Self::PaidPlanHashMismatch => {
                write!(
                    f,
                    "paid review, authorization, and execution hashes must match"
                )
            }
            Self::PaidAuthorizationExpiryMismatch => {
                write!(
                    f,
                    "paid authorization expiry must exactly match the reviewed plan expiry"
                )
            }
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
    let interval = interval_secs.unwrap_or(60);
    let age = now.saturating_sub(last).max(0) as u64;
    if age <= interval.saturating_mul(2) {
        Liveness::Live
    } else if age <= interval.saturating_mul(5) {
        Liveness::Stale
    } else {
        Liveness::Down
    }
}

pub const HOST_REPORT_SCHEMA: &str = "inspr.pharos.host-report.v2";
pub const HOST_REPORT_VERSION: u16 = 2;
pub const PREVIOUS_HOST_REPORT_SCHEMA: &str = "inspr.pharos.host-report.v1";
pub const PREVIOUS_HOST_REPORT_VERSION: u16 = 1;
pub const SUPPORTED_HOST_REPORT_CONTRACTS: [(&str, u16); 2] = [
    (PREVIOUS_HOST_REPORT_SCHEMA, PREVIOUS_HOST_REPORT_VERSION),
    (HOST_REPORT_SCHEMA, HOST_REPORT_VERSION),
];

fn default_host_report_version() -> u16 {
    HOST_REPORT_VERSION
}

/// What a `pharos-beacon` sends to `pharosd` (PHAROS-9 ingestion). The server
/// adds the receive timestamp; the agent never sends its own liveness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HostReport {
    pub schema: String,
    pub version: u16,
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    pub heartbeat_interval_secs: u64,
    pub freshness: NixFreshness,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel: Option<KernelPosture>,
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
    /// Host-owned preferences loaded and applied by the beacon. Pending
    /// operator requests are delivered separately and do not appear here until
    /// the host accepts them.
    #[serde(default)]
    pub preferences: HostPreferences,
}

impl HostReport {
    pub fn validate_contract(&self) -> Result<(), String> {
        if !SUPPORTED_HOST_REPORT_CONTRACTS
            .iter()
            .any(|(schema, version)| self.schema == *schema && self.version == *version)
        {
            return Err("unsupported report schema/version pair".to_string());
        }
        validate_report_identity(&self.name, &self.role)?;
        validate_heartbeat_interval(self.heartbeat_interval_secs)?;
        self.freshness.validate_contract()?;
        if self.service_observations.len() > MAX_SERVICE_OBSERVATIONS {
            return Err(format!(
                "service_observations must contain <= {MAX_SERVICE_OBSERVATIONS} entries"
            ));
        }
        if self.backup_observations.len() > MAX_BACKUP_OBSERVATIONS {
            return Err(format!(
                "backup_observations must contain <= {MAX_BACKUP_OBSERVATIONS} entries"
            ));
        }
        for observation in &self.service_observations {
            observation.validate_contract()?;
        }
        if self
            .inbound_rtt_ms
            .is_some_and(|millis| millis > MAX_INBOUND_RTT_MS)
        {
            return Err(format!("inbound_rtt_ms must be <= {}", MAX_INBOUND_RTT_MS));
        }
        if let Some(kernel) = &self.kernel {
            kernel.validate_contract()?;
        }
        for observation in &self.backup_observations {
            observation.validate_contract()?;
        }
        self.preferences.validate_contract()?;
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
        let encoded = serde_json::to_vec(self)
            .map_err(|_| "report cannot be encoded as bounded JSON".to_string())?;
        if encoded.len() > MAX_HOST_REPORT_BYTES {
            return Err(format!(
                "report must be <= {MAX_HOST_REPORT_BYTES} encoded bytes"
            ));
        }
        Ok(())
    }
}

fn validate_report_identity(name: &str, role: &str) -> Result<(), String> {
    if !valid_canonical_hostname(name) {
        return Err("host name must be a canonical DNS-style name".to_string());
    }
    if role.is_empty()
        || role.len() > MAX_ROLE_BYTES
        || role.trim() != role
        || !role.is_ascii()
        || role.bytes().any(|byte| {
            !(byte.is_ascii_alphanumeric()
                || matches!(byte, b' ' | b'-' | b'_' | b'/' | b'.' | b'(' | b')'))
        })
        || looks_like_secret_material(role)
    {
        return Err("host role must be bounded plain text".to_string());
    }
    Ok(())
}

fn valid_canonical_hostname(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.bytes().any(|byte| byte.is_ascii_uppercase())
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

fn validate_heartbeat_interval(interval: u64) -> Result<(), String> {
    if !(MIN_HEARTBEAT_INTERVAL_SECS..=MAX_HEARTBEAT_INTERVAL_SECS).contains(&interval) {
        return Err(format!(
            "heartbeat_interval_secs must be between {MIN_HEARTBEAT_INTERVAL_SECS} and {MAX_HEARTBEAT_INTERVAL_SECS}"
        ));
    }
    Ok(())
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
#[serde(deny_unknown_fields)]
pub struct ServiceObservation {
    pub id: String,
    pub label: String,
    pub state: ServiceObservationState,
    pub summary: String,
}

impl ServiceObservation {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > MAX_OBSERVATION_ID_BYTES
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.id.starts_with('-')
            || self.id.ends_with('-')
        {
            return Err("service observation id must be a canonical identifier".to_string());
        }
        if self.label.len() > MAX_OBSERVATION_LABEL_BYTES || !safe_observation_text(&self.label) {
            return Err("service observation label must be bounded sanitized text".to_string());
        }
        if self.summary.len() > MAX_OBSERVATION_SUMMARY_BYTES
            || !safe_observation_text(&self.summary)
        {
            return Err("service observation summary must be bounded sanitized text".to_string());
        }
        Ok(())
    }

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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
    if value.trim() != value || value.len() > MAX_OBSERVATION_SUMMARY_BYTES {
        return false;
    }
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
#[serde(deny_unknown_fields)]
pub struct HostRegistration {
    pub schema: String,
    pub version: u16,
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    pub heartbeat_interval_secs: u64,
}

pub const HOST_REGISTRATION_SCHEMA: &str = "inspr.pharos.host-registration.v1";
pub const HOST_REGISTRATION_VERSION: u16 = 1;

impl HostRegistration {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != HOST_REGISTRATION_SCHEMA {
            return Err("unsupported registration schema".to_string());
        }
        if self.version != HOST_REGISTRATION_VERSION {
            return Err(format!(
                "unsupported registration version {}; expected {}",
                self.version, HOST_REGISTRATION_VERSION
            ));
        }
        validate_report_identity(&self.name, &self.role)?;
        validate_heartbeat_interval(self.heartbeat_interval_secs)
    }
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
        self.host
            .preferences
            .validate_contract()
            .map_err(ManifestContractError::InvalidHostPreferences)?;
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
    #[serde(default)]
    pub preferences: HostPreferences,
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
    InvalidHostPreferences(String),
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
            Self::InvalidHostPreferences(error) => {
                write!(f, "invalid host preferences: {error}")
            }
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
    fn managed_identity_states_serialize_as_the_ui_contract() {
        let cases = [
            (
                ProvisioningManagedIdentityState::AwaitingHostKey,
                "awaiting-host-key",
            ),
            (ProvisioningManagedIdentityState::Ready, "ready"),
            (
                ProvisioningManagedIdentityState::BootstrapClaimed,
                "bootstrap-claimed",
            ),
            (
                ProvisioningManagedIdentityState::RetryRequired,
                "retry-required",
            ),
            (ProvisioningManagedIdentityState::Uncertain, "uncertain"),
            (
                ProvisioningManagedIdentityState::ReconciliationPending,
                "reconciliation-pending",
            ),
            (
                ProvisioningManagedIdentityState::ReconciliationClaimed,
                "reconciliation-claimed",
            ),
            (
                ProvisioningManagedIdentityState::AwaitingHeartbeat,
                "awaiting-heartbeat",
            ),
            (
                ProvisioningManagedIdentityState::HeartbeatObserved,
                "heartbeat-observed",
            ),
            (
                ProvisioningManagedIdentityState::RetirementPending,
                "retirement-pending",
            ),
            (
                ProvisioningManagedIdentityState::RetirementClaimed,
                "retirement-claimed",
            ),
            (
                ProvisioningManagedIdentityState::CredentialRetired,
                "credential-retired",
            ),
        ];

        for (state, expected) in cases {
            assert_eq!(
                serde_json::to_value(state).expect("managed identity state serializes"),
                serde_json::Value::String(expected.to_string())
            );
        }
    }

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
    fn kernel_posture_derives_current_from_semantic_versions() {
        let posture = KernelPosture::observed(
            true,
            Some("7.0.14-nixos".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_000,
        );

        assert_eq!(posture.state, KernelPostureState::Current);
        posture.validate_contract().expect("current posture valid");
    }

    #[test]
    fn kernel_posture_derives_reboot_required_from_staged_kernel() {
        let posture = KernelPosture::observed(
            true,
            Some("6.18.26".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_000,
        );

        assert_eq!(posture.state, KernelPostureState::RebootRequired);
        posture
            .validate_contract()
            .expect("reboot-required posture valid");
    }

    #[test]
    fn kernel_posture_fails_incomplete_or_malformed_observations_safe() {
        let missing =
            KernelPosture::observed(true, Some("7.0.14".to_string()), None, 1_700_000_000);
        assert_eq!(missing.state, KernelPostureState::Unknown);
        missing.validate_contract().expect("unknown posture valid");

        let malformed = KernelPosture::observed(
            true,
            Some("/nix/store/opaque-kernel".to_string()),
            Some("also invalid".to_string()),
            1_700_000_000,
        );
        assert_eq!(malformed.state, KernelPostureState::Unknown);
        assert!(malformed.running_version.is_none());
        assert!(malformed.expected_version.is_none());
        malformed
            .validate_contract()
            .expect("sanitized unknown posture valid");

        let ambiguous = KernelPosture::observed(
            true,
            Some("7.0.14.1".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_000,
        );
        assert_eq!(ambiguous.state, KernelPostureState::Unknown);
        assert!(ambiguous.running_version.is_none());
    }

    #[test]
    fn kernel_posture_rejects_state_version_mismatch() {
        let mut posture = KernelPosture::observed(
            true,
            Some("6.18.26".to_string()),
            Some("7.0.14".to_string()),
            1_700_000_000,
        );
        posture.state = KernelPostureState::Current;

        assert_eq!(
            posture.validate_contract(),
            Err("kernel posture state does not match its versions".to_string())
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
    fn liveness_is_total_and_saturating_for_extreme_inputs() {
        for last_seen in [i64::MIN, -1, 0, i64::MAX] {
            for now in [i64::MIN, -1, 0, i64::MAX] {
                for interval in [0, 1, 60, u64::MAX / 2, u64::MAX] {
                    let result =
                        std::panic::catch_unwind(|| liveness(Some(last_seen), Some(interval), now));
                    assert!(result.is_ok(), "liveness must be total");
                }
            }
        }
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
        assert!(host.kernel.is_none());
        assert!(host.service_observations.is_empty());
        assert!(host.backup_observations.is_empty());
        assert_eq!(host.preferences, HostPreferences::default());
        assert!(host.requested_preferences.is_none());
    }

    #[test]
    fn host_report_location_is_optional_and_runtime_only() {
        let current: HostReport = serde_json::from_value(serde_json::json!({
            "schema": HOST_REPORT_SCHEMA,
            "version": HOST_REPORT_VERSION,
            "name": "hsb8",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {"applicable": true}
        }))
        .expect("deserialize current report");
        assert!(current.location.is_none());
        assert!(current.inbound_rtt_ms.is_none());
        assert!(current.kernel.is_none());
        assert!(current.backup_observations.is_empty());
        assert_eq!(current.preferences, HostPreferences::default());
        current.validate_contract().expect("current report valid");

        let legacy: HostReport = serde_json::from_value(serde_json::json!({
            "schema": PREVIOUS_HOST_REPORT_SCHEMA,
            "version": PREVIOUS_HOST_REPORT_VERSION,
            "name": "hsb8",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {"applicable": true}
        }))
        .expect("legacy report remains structurally parseable");
        legacy
            .validate_contract()
            .expect("the immediately preceding report remains valid during rollout");

        let mismatched = HostReport {
            version: HOST_REPORT_VERSION,
            ..legacy.clone()
        };
        assert!(mismatched.validate_contract().is_err());

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
            ..current.clone()
        };
        runtime
            .validate_contract()
            .expect("runtime location source is valid");
        assert_eq!(runtime.inbound_rtt_ms, Some(42));

        let too_slow = HostReport {
            inbound_rtt_ms: Some(MAX_INBOUND_RTT_MS + 1),
            ..current.clone()
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
            ..current
        };
        assert!(declared_runtime.validate_contract().is_err());
    }

    #[test]
    fn report_and_registration_envelopes_are_explicit_and_closed() {
        let report = serde_json::json!({
            "schema": HOST_REPORT_SCHEMA,
            "version": HOST_REPORT_VERSION,
            "name": "athena.example",
            "role": "Control Server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {"applicable": true}
        });
        let mut missing_schema = report.clone();
        missing_schema.as_object_mut().unwrap().remove("schema");
        assert!(serde_json::from_value::<HostReport>(missing_schema).is_err());
        let mut unknown = report.clone();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostReport>(unknown).is_err());

        let registration = serde_json::json!({
            "schema": HOST_REGISTRATION_SCHEMA,
            "version": HOST_REGISTRATION_VERSION,
            "name": "athena.example",
            "role": "Control Server",
            "is_nix": true,
            "heartbeat_interval_secs": 60
        });
        let parsed: HostRegistration = serde_json::from_value(registration.clone()).unwrap();
        parsed.validate_contract().unwrap();
        let mut missing_version = registration.clone();
        missing_version.as_object_mut().unwrap().remove("version");
        assert!(serde_json::from_value::<HostRegistration>(missing_version).is_err());
        let mut unknown = registration;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HostRegistration>(unknown).is_err());
    }

    #[test]
    fn report_contract_enforces_identity_bounds_and_sanitized_observations() {
        let valid = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: "athena.example".to_string(),
            role: "Control Server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(1),
                commits_behind: Some(0),
            },
            kernel: None,
            service_observations: vec![ServiceObservation {
                id: "nix-freshness".to_string(),
                label: "Nix freshness".to_string(),
                state: ServiceObservationState::Healthy,
                summary: "up to date".to_string(),
            }],
            backup_observations: vec![],
            inbound_rtt_ms: Some(5),
            location: None,
            preferences: Default::default(),
        };
        valid.validate_contract().unwrap();

        for name in ["Athena", "-athena", "athena-", "athena..example", ""] {
            assert!(HostReport {
                name: name.to_string(),
                ..valid.clone()
            }
            .validate_contract()
            .is_err());
        }
        for interval in [
            0,
            MIN_HEARTBEAT_INTERVAL_SECS - 1,
            MAX_HEARTBEAT_INTERVAL_SECS + 1,
            u64::MAX,
        ] {
            assert!(HostReport {
                heartbeat_interval_secs: interval,
                ..valid.clone()
            }
            .validate_contract()
            .is_err());
        }
        assert!(HostReport {
            freshness: NixFreshness {
                flake_lock_age_days: Some(MAX_FLAKE_LOCK_AGE_DAYS + 1),
                ..valid.freshness.clone()
            },
            ..valid.clone()
        }
        .validate_contract()
        .is_err());
        assert!(HostReport {
            service_observations: vec![ServiceObservation {
                summary: "token=must-not-be-forwarded".to_string(),
                ..valid.service_observations[0].clone()
            }],
            ..valid.clone()
        }
        .validate_contract()
        .is_err());
        let large_backup = BackupObservation {
            id: "backup".to_string(),
            label: "b".repeat(MAX_OBSERVATION_LABEL_BYTES),
            engine: BackupEngine::Restic,
            state: BackupPostureState::Healthy,
            configured: BackupConfiguredState::Enabled,
            summary: "s".repeat(MAX_OBSERVATION_SUMMARY_BYTES),
            target_label: Some("t".repeat(MAX_OBSERVATION_SUMMARY_BYTES)),
            repository_id: Some("r".repeat(MAX_OBSERVATION_SUMMARY_BYTES)),
            schedule: Some("c".repeat(MAX_OBSERVATION_SUMMARY_BYTES)),
            next_run_at: None,
            last_attempt_at: None,
            last_attempt_state: None,
            last_success_at: None,
            snapshot_count: None,
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: Some(BackupValidationObservation {
                level: BackupValidationLevel::RestoreSample,
                state: BackupValidationState::Passed,
                checked_at: None,
                evidence_label: Some("e".repeat(MAX_OBSERVATION_SUMMARY_BYTES)),
                summary: Some("v".repeat(MAX_OBSERVATION_SUMMARY_BYTES)),
            }),
        };
        let oversized = HostReport {
            backup_observations: vec![large_backup; MAX_BACKUP_OBSERVATIONS],
            ..valid.clone()
        };
        assert!(oversized
            .validate_contract()
            .is_err_and(|error| error.contains("encoded bytes")));
        assert!(HostReport {
            service_observations: vec![
                valid.service_observations[0].clone();
                MAX_SERVICE_OBSERVATIONS + 1
            ],
            ..valid
        }
        .validate_contract()
        .is_err());
    }

    #[test]
    fn heartbeat_contract_property_holds_for_generated_inputs() {
        let mut state = 0x4d595df4d0f33173_u64;
        for _ in 0..10_000 {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
            let interval = state;
            let registration = HostRegistration {
                schema: HOST_REGISTRATION_SCHEMA.to_string(),
                version: HOST_REGISTRATION_VERSION,
                name: "property-host.example".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: interval,
            };
            assert_eq!(
                registration.validate_contract().is_ok(),
                (MIN_HEARTBEAT_INTERVAL_SECS..=MAX_HEARTBEAT_INTERVAL_SECS).contains(&interval)
            );
        }
    }

    #[test]
    fn host_preferences_are_typed_validated_and_backward_compatible_with_old_reports() {
        let preferences: HostPreferences = serde_json::from_value(serde_json::json!({
            "accent": "#48b8a8",
            "kind": "workstation",
            "alerts": {
                "suppress_down": true,
                "suppress_backup": false,
                "suppress_nix_freshness": true
            }
        }))
        .expect("typed preferences parse");
        preferences.validate_contract().expect("valid preferences");
        assert_eq!(preferences.kind, HostKind::Workstation);
        assert!(preferences.alerts.suppress_down);
        assert!(preferences.alerts.suppress_nix_freshness);

        let malformed = HostPreferences {
            accent: Some("orange".to_string()),
            ..Default::default()
        };
        assert!(malformed.validate_contract().is_err());
        assert!(
            serde_json::from_value::<HostPreferences>(serde_json::json!({
                "unexpected": true
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<HostPreferences>(serde_json::json!({
                "alerts": { "unexpected": true }
            }))
            .is_err()
        );
    }

    #[test]
    fn workstation_kind_suppresses_down_alerts_without_changing_manual_preference() {
        let workstation = HostPreferences {
            kind: HostKind::Workstation,
            ..Default::default()
        };
        assert!(workstation.suppresses_down_alerts());
        assert!(!workstation.alerts.suppress_down);

        let server = HostPreferences::default();
        assert!(!server.suppresses_down_alerts());

        let muted_server = HostPreferences {
            alerts: HostAlertPreferences {
                suppress_down: true,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(muted_server.suppresses_down_alerts());
    }

    #[test]
    fn host_preferences_registry_matches_nixcfg_schema_and_rejects_extensions() {
        let registry: HostPreferencesRegistry = serde_json::from_value(serde_json::json!({
            "schema": "inspr.pharos.host-preferences.v1",
            "version": 1,
            "hosts": {
                "gpc0": {
                    "accent": "#9868d0",
                    "kind": "workstation",
                    "alerts": {
                        "suppress_down": true,
                        "suppress_backup": false,
                        "suppress_nix_freshness": true
                    }
                }
            }
        }))
        .expect("nixcfg registry parses");
        registry.validate_contract().expect("registry validates");
        assert_eq!(
            registry.preferences_for("gpc0").map(|value| value.kind),
            Some(HostKind::Workstation)
        );

        assert!(
            serde_json::from_value::<HostPreferencesRegistry>(serde_json::json!({
                "schema": "inspr.pharos.host-preferences.v1",
                "version": 1,
                "hosts": {},
                "commands": ["rebuild"]
            }))
            .is_err()
        );
    }

    #[test]
    fn report_response_reuses_one_strict_host_preferences_registry() {
        let preferences = HostPreferences {
            accent: Some("#9868d0".to_string()),
            kind: HostKind::Workstation,
            alerts: HostAlertPreferences {
                suppress_down: false,
                suppress_backup: true,
                suppress_nix_freshness: false,
            },
        };
        let response = HostReportResponse::pending("gpc0", preferences.clone())
            .expect("pending response validates");
        assert_eq!(response.preferences_for("gpc0"), Ok(Some(&preferences)));
        assert_eq!(
            response.pending_preferences.as_ref().map(|registry| {
                (
                    registry.schema.as_str(),
                    registry.version,
                    registry.hosts.len(),
                )
            }),
            Some((HOST_PREFERENCES_SCHEMA, HOST_PREFERENCES_VERSION, 1))
        );

        let mismatched: HostReportResponse = serde_json::from_value(serde_json::json!({
            "schema": "inspr.pharos.report-response.v1",
            "version": 1,
            "pending_preferences": {
                "schema": "inspr.pharos.host-preferences.v1",
                "version": 1,
                "hosts": {
                    "athena": {
                        "accent": "#9868d0",
                        "kind": "workstation",
                        "alerts": {}
                    }
                }
            }
        }))
        .expect("typed but mismatched response parses");
        assert!(mismatched.validate_contract_for("gpc0").is_err());

        assert!(
            serde_json::from_value::<HostReportResponse>(serde_json::json!({
                "schema": "inspr.pharos.report-response.v1",
                "version": 1,
                "pending_preferences": {
                    "schema": "inspr.pharos.host-preferences.v1",
                    "version": 1,
                    "hosts": {
                        "gpc0": {
                            "accent": "#9868d0",
                            "kind": "workstation",
                            "alerts": {},
                            "command": "rebuild"
                        }
                    }
                }
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<HostReportResponse>(serde_json::json!({
                "schema": "inspr.pharos.report-response.v1",
                "version": 1,
                "pending_preferences": null,
                "command": "rebuild"
            }))
            .is_err()
        );
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
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![observation.clone()],
            inbound_rtt_ms: None,
            location: None,
            preferences: Default::default(),
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
            kernel: None,
            service_observations: vec![ServiceObservation::nix_freshness(&NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            })],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
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
            existing_host_context: None,
            state: ProvisioningJobState::Planning,
            terminal_outcome: None,
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
                access: AccessSetupIntent::LimitedUsers,
            }),
            backup_proposal: None,
            reviewed_plan: None,
            paid_authorization: None,
            paid_execution: None,
            managed_identity: None,
            provider_resources: vec![ProvisioningProviderResource {
                provider: "hetzner-cloud".to_string(),
                kind: "server".to_string(),
                provider_id: "4242".to_string(),
                name: "hcloud-lab-1".to_string(),
                state: "created".to_string(),
                location: Some("fsn1".to_string()),
                ssh: Some(SshAccessIntent {
                    route: SshRoute::Direct,
                    user: Some("root".to_string()),
                    host: Some("192.0.2.10".to_string()),
                    port: Some(22),
                }),
            }],
            progress: vec![entry],
        };
        job.validate_contract().expect("job contract is valid");
        let active_json = serde_json::to_string(&job).expect("active job serializes");
        assert!(!active_json.contains("terminal_outcome"));

        let mut rolled_back = job.clone();
        rolled_back.state = ProvisioningJobState::Complete;
        rolled_back.terminal_outcome = Some(ProvisioningTerminalOutcome::RolledBack);
        let rolled_back_json =
            serde_json::to_string(&rolled_back).expect("rolled-back job serializes");
        assert!(rolled_back_json.contains(r#""terminal_outcome":"rolled-back""#));
        #[derive(Deserialize)]
        struct LegacyProvisioningJobView {
            state: ProvisioningJobState,
        }
        let legacy_view: LegacyProvisioningJobView =
            serde_json::from_str(&rolled_back_json).expect("legacy view ignores additive outcome");
        assert_eq!(legacy_view.state, ProvisioningJobState::Complete);

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
        assert_eq!(setup_intent.access_label(), "limited users");
        assert_eq!(
            setup_intent.access_next_action(),
            "create an explicit host access grant before broadening visibility"
        );

        let backup_proposal = ProvisioningBackupProposal {
            kind: ProvisioningBackupProposalKind::NixosResticBeaconObservation,
            title: "NixOS restic backup proposal".to_string(),
            summary: "Uses runtime files for restic configuration.".to_string(),
            module_attribute: "services.pharos-beacon.extraEnvironment".to_string(),
            nix_module: r#"{ config, ... }:
{
  services.pharos-beacon.extraEnvironment = {
    PHAROS_BACKUP_MODE = "restic";
    RESTIC_REPOSITORY_FILE = "/run/agenix/host-restic-repository";
    RESTIC_PASSWORD_FILE = "/run/agenix/host-restic-password";
  };
}
"#
            .to_string(),
            secret_files: vec![ProvisioningBackupSecretFile {
                key: "restic-repository-file".to_string(),
                owner: SecretOwner::Agenix,
                path: "/run/agenix/host-restic-repository".to_string(),
                purpose: "Repository file reference.".to_string(),
            }],
            next_steps: vec!["Create the runtime files before deployment.".to_string()],
        };
        backup_proposal
            .validate_contract()
            .expect("safe backup proposal is valid");

        let secret_proposal = ProvisioningBackupProposal {
            nix_module: r#"{ config, ... }: { services.pharos-beacon.extraEnvironment.PHAROS_TOKEN = "raw"; }"#.to_string(),
            ..backup_proposal
        };
        assert_eq!(
            secret_proposal.validate_contract(),
            Err(ServerLifecycleContractError::InvalidBackupProposal)
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

        let secret_resource = ProvisioningJob {
            provider_resources: vec![ProvisioningProviderResource {
                provider_id: "token=raw-value".to_string(),
                ..job.provider_resources[0].clone()
            }],
            ..job.clone()
        };
        assert_eq!(
            secret_resource.validate_contract(),
            Err(ServerLifecycleContractError::InvalidProviderResource)
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

    fn reviewed_paid_plan_fixture() -> ProvisioningReviewedPaidPlan {
        ProvisioningReviewedPaidPlan {
            provider_project: "Hetzner Cloud / Pharos production".to_string(),
            credential_binding_sha256: "b".repeat(64),
            server_name: "paid-lab-1".to_string(),
            location: "fsn1".to_string(),
            location_label: "Falkenstein (fsn1)".to_string(),
            server_type: "cx23".to_string(),
            server_type_label: "CX23 · 2 vCPU · 4 GB".to_string(),
            image: "debian-12".to_string(),
            price_currency: "EUR".to_string(),
            price_hourly_gross: "0.0060".to_string(),
            price_monthly_gross: "3.4900".to_string(),
            max_hourly_gross: "0.0060".to_string(),
            max_monthly_gross: "3.4900".to_string(),
            observed_active_servers: 0,
            max_active_servers: 1,
            catalog_refreshed_at: 1_700_000_000,
            expires_at: 1_700_000_900,
            ssh_key_ref: "pharos-bootstrap-key".to_string(),
            firewall_ref: "pharos-bootstrap-firewall".to_string(),
            managed_executor_owner: Some("csb1".to_string()),
            managed_credential_ref: Some(format!("sec_{}", "c".repeat(20))),
            required_labels: BTreeMap::from([
                ("managed-by".to_string(), "pharos".to_string()),
                ("pharos-setup".to_string(), "tracked-job".to_string()),
            ]),
            allowed_operations: vec!["create-server".to_string(), "delete-server".to_string()],
            cleanup_policy: "No silent retry or automatic deletion; separately confirm cleanup."
                .to_string(),
            plan_sha256: "a".repeat(64),
        }
    }

    fn paid_provisioning_job_fixture() -> ProvisioningJob {
        ProvisioningJob {
            schema: PROVISIONING_JOB_SCHEMA.to_string(),
            version: PROVISIONING_JOB_VERSION,
            id: "setup-paid-1700000100-1".to_string(),
            provider: "hetzner-cloud".to_string(),
            template: "hetzner-small-nixos".to_string(),
            host_name: Some("paid-lab-1".to_string()),
            role: Some("server".to_string()),
            is_nix: Some(true),
            heartbeat_interval_secs: Some(60),
            existing_host_context: None,
            state: ProvisioningJobState::Planning,
            terminal_outcome: None,
            created_at: 1_700_000_100,
            updated_at: 1_700_000_300,
            handoff: None,
            setup_intent: None,
            backup_proposal: None,
            reviewed_plan: Some(reviewed_paid_plan_fixture()),
            paid_authorization: Some(ProvisioningPaidAuthorization {
                plan_sha256: "a".repeat(64),
                operator_ref: "b".repeat(64),
                operator_label: "operator@example.test".to_string(),
                confirmed_at: 1_700_000_200,
                expires_at: 1_700_000_900,
            }),
            paid_execution: Some(ProvisioningPaidExecution {
                plan_sha256: "a".repeat(64),
                attempt_id: "paid-attempt-1".to_string(),
                state: "claimed".to_string(),
                claimed_at: 1_700_000_300,
                provider_request_started_at: None,
                provider_id: None,
            }),
            managed_identity: None,
            provider_resources: vec![],
            progress: vec![ProvisioningProgressEntry {
                state: ProvisioningJobState::Planning,
                message: "Paid plan reviewed, authorized, and claimed for one execution."
                    .to_string(),
                observed_at: 1_700_000_300,
            }],
        }
    }

    #[test]
    fn paid_provisioning_contract_is_additive_value_free_and_exactly_bound() {
        let job = paid_provisioning_job_fixture();
        job.validate_contract()
            .expect("exact paid review chain is valid");

        let json = serde_json::to_string(&job).expect("paid job serializes");
        assert!(json.contains(r#""reviewed_plan""#));
        assert!(json.contains(r#""paid_authorization""#));
        assert!(json.contains(r#""paid_execution""#));
        assert!(json.contains(r#""max_active_servers":1"#));
        assert!(json.contains(r#""state":"claimed""#));
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.to_ascii_lowercase().contains("token="));
        assert!(!json.to_ascii_lowercase().contains("password="));

        let round_trip: ProvisioningJob =
            serde_json::from_str(&json).expect("paid job round trips");
        assert_eq!(round_trip, job);

        let legacy: ProvisioningJob = serde_json::from_value(serde_json::json!({
            "id": "legacy-setup-1",
            "provider": "existing-host",
            "template": "manual-deferred",
            "state": "planning",
            "created_at": 1_700_000_000,
            "updated_at": 1_700_000_000
        }))
        .expect("legacy v1 job without paid fields remains readable");
        assert!(legacy.reviewed_plan.is_none());
        assert!(legacy.paid_authorization.is_none());
        assert!(legacy.paid_execution.is_none());
        legacy
            .validate_contract()
            .expect("legacy v1 job remains valid");
    }

    #[test]
    fn paid_review_rejects_unbounded_stale_secret_or_malformed_policy() {
        let valid = reviewed_paid_plan_fixture();
        valid.validate_contract().expect("fixture is valid");

        for invalid in [
            ProvisioningReviewedPaidPlan {
                max_active_servers: 2,
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                observed_active_servers: 1,
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                max_monthly_gross: "3.4800".to_string(),
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                price_hourly_gross: "6e-3".to_string(),
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                provider_project: "provider token=raw-value".to_string(),
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                expires_at: valid.catalog_refreshed_at,
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                required_labels: BTreeMap::from([("managed-by".to_string(), "pharos".to_string())]),
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                allowed_operations: vec!["create-server".to_string()],
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                plan_sha256: "A".repeat(64),
                ..valid.clone()
            },
            ProvisioningReviewedPaidPlan {
                credential_binding_sha256: "B".repeat(64),
                ..valid.clone()
            },
        ] {
            assert_eq!(
                invalid.validate_contract(),
                Err(ServerLifecycleContractError::InvalidReviewedPaidPlan)
            );
        }
    }

    #[test]
    fn paid_authorization_and_execution_fail_closed_on_missing_or_changed_review() {
        let valid = paid_provisioning_job_fixture();

        let authorization_without_review = ProvisioningJob {
            reviewed_plan: None,
            paid_execution: None,
            ..valid.clone()
        };
        assert_eq!(
            authorization_without_review.validate_contract(),
            Err(ServerLifecycleContractError::PaidAuthorizationWithoutReviewedPlan)
        );

        let authorization_hash_mismatch = ProvisioningJob {
            paid_authorization: Some(ProvisioningPaidAuthorization {
                plan_sha256: "c".repeat(64),
                ..valid.paid_authorization.clone().expect("authorization")
            }),
            paid_execution: None,
            ..valid.clone()
        };
        assert_eq!(
            authorization_hash_mismatch.validate_contract(),
            Err(ServerLifecycleContractError::PaidPlanHashMismatch)
        );

        let server_name_outside_review = ProvisioningJob {
            host_name: Some("different-paid-host".to_string()),
            ..valid.clone()
        };
        assert_eq!(
            server_name_outside_review.validate_contract(),
            Err(ServerLifecycleContractError::InvalidReviewedPaidPlan)
        );

        let extended_authorization = ProvisioningJob {
            paid_authorization: Some(ProvisioningPaidAuthorization {
                expires_at: 1_700_001_000,
                ..valid.paid_authorization.clone().expect("authorization")
            }),
            paid_execution: None,
            ..valid.clone()
        };
        assert_eq!(
            extended_authorization.validate_contract(),
            Err(ServerLifecycleContractError::PaidAuthorizationExpiryMismatch)
        );

        let execution_without_authorization = ProvisioningJob {
            paid_authorization: None,
            ..valid.clone()
        };
        assert_eq!(
            execution_without_authorization.validate_contract(),
            Err(ServerLifecycleContractError::PaidExecutionWithoutAuthorization)
        );

        let execution_at_expiry = ProvisioningJob {
            updated_at: 1_700_000_900,
            paid_execution: Some(ProvisioningPaidExecution {
                claimed_at: 1_700_000_900,
                ..valid.paid_execution.clone().expect("execution")
            }),
            ..valid.clone()
        };
        assert_eq!(
            execution_at_expiry.validate_contract(),
            Err(ServerLifecycleContractError::InvalidPaidExecution)
        );

        let unknown_execution_state = ProvisioningJob {
            paid_execution: Some(ProvisioningPaidExecution {
                state: "retry-anything".to_string(),
                ..valid.paid_execution.clone().expect("execution")
            }),
            ..valid.clone()
        };
        assert_eq!(
            unknown_execution_state.validate_contract(),
            Err(ServerLifecycleContractError::InvalidPaidExecution)
        );

        let created_without_provider_identity = ProvisioningJob {
            paid_execution: Some(ProvisioningPaidExecution {
                state: "created".to_string(),
                provider_request_started_at: Some(1_700_000_300),
                provider_id: None,
                ..valid.paid_execution.clone().expect("execution")
            }),
            ..valid
        };
        assert_eq!(
            created_without_provider_identity.validate_contract(),
            Err(ServerLifecycleContractError::InvalidPaidExecution)
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
                backup_tools: vec!["restic".to_string()],
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
