//! Shared Pharos types: hosts, reports, nix-freshness, liveness.
//!
//! Used by both `pharosd` (server) and `pharos-beacon` (agent) so the report
//! schema cannot drift — the typed-integration win that drove the Rust stack
//! choice (PHAROS-2 / ADR-001). See PHAROS-3 (data model) and PHAROS-15
//! (nix freshness) for the tickets these types back.

pub mod contact;
pub mod cve_status;
pub mod fleet_data;
pub mod image_identity;
pub mod public_path;
pub mod secret_input;
pub mod updates_due;

pub use image_identity::{
    classify_image_identity, classify_media_type, parse_image_descriptor_format,
    resolve_config_digest_from_image_archive, ImageConfigDigestCache, ImageDescriptorMeasurement,
    ImageIdentityClass, DOCKER_CONFIG_MEDIA_TYPE, DOCKER_INDEX_MEDIA_TYPE,
    DOCKER_MANIFEST_MEDIA_TYPE, IMAGE_DESCRIPTOR_DOCKER_FORMAT, OCI_CONFIG_MEDIA_TYPE,
    OCI_INDEX_MEDIA_TYPE, OCI_MANIFEST_MEDIA_TYPE,
};
pub use public_path::{PublicBasePath, PublicOrigin};

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
/// PHAROS-193: a release channel name such as `nixos-25.05`.
pub const MAX_NIX_CHANNEL_BYTES: usize = 64;
/// PHAROS-201: a root flake input name such as `nixpkgs-stable`.
pub const MAX_NIX_INPUT_NAME_BYTES: usize = 64;
/// Git object identifiers are SHA-1 today; accept SHA-256 repositories without
/// weakening the exact-identity check.
pub const MIN_GIT_REVISION_HEX_BYTES: usize = 40;
pub const MAX_GIT_REVISION_HEX_BYTES: usize = 64;
pub const SHA256_HEX_BYTES: usize = 64;
pub const NIX_DEPLOYMENT_EVIDENCE_SCHEMA: &str = "inspr.pharos.nix-deployment-evidence.v1";
pub const NIX_DEPLOYMENT_EVIDENCE_VERSION: u16 = 1;
pub const DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA: &str = "inspr.pharos.deployed-artifact.v1";
pub const DEPLOYED_ARTIFACT_EVIDENCE_VERSION: u16 = 1;
pub const MAX_DEPLOYED_ARTIFACT_EVIDENCE_BYTES: u64 = 4 * 1024;
pub const APPROVED_RELEASE_ENVELOPE_SCHEMA: &str = "inspr.pharos.approved-release-envelope.v1";
pub const APPROVED_RELEASE_ENVELOPE_VERSION: u16 = 1;
pub const RUNNING_CONTAINER_DOCKER_FORMAT: &str = "{{.State.Running}}\t{{.Id}}\t{{.Image}}\t{{index .Config.Labels \"org.inspr.release.environment\"}}\t{{index .Config.Labels \"org.inspr.release.version_scheme\"}}\t{{index .Config.Labels \"org.inspr.release.version\"}}\t{{index .Config.Labels \"org.inspr.release.channel\"}}\t{{index .Config.Labels \"org.inspr.release.sequence\"}}\t{{index .Config.Labels \"org.inspr.release.commit_digest\"}}\t{{index .Config.Labels \"org.inspr.release.manifest_coordinate\"}}\t{{index .Config.Labels \"org.inspr.release.manifest_digest\"}}";
const MAX_UNIX_TIMESTAMP: UnixSeconds = 253_402_300_799;
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
    /// Optional deployed-nixpkgs age limit. Omitted on the wire until configured,
    /// so unchanged preferences remain readable by older beacons and servers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixpkgs_warn_after_days: Option<u32>,
    /// Optional late-heartbeat grace, in seconds after the reported cadence.
    /// Omitted on the wire until a host override is configured, so older
    /// beacons and preference documents keep parsing. Null and absence both
    /// inherit the fleet default. Zero is a real override.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub heartbeat_grace_secs: Option<u64>,
}

pub const DEFAULT_NIXPKGS_WARN_AFTER_DAYS: u32 = 30;
pub const MAX_NIXPKGS_WARN_AFTER_DAYS: u32 = 3650;
/// Extra seconds after the reported heartbeat interval before a gap is late.
/// PHAROS-292. This does not move the 2× stale or 5× down liveness cuts.
pub const DEFAULT_HEARTBEAT_GRACE_SECS: u64 = 15;
pub const MAX_HEARTBEAT_GRACE_SECS: u64 = MAX_HEARTBEAT_INTERVAL_SECS;
pub const HEARTBEAT_GRACE_RANGE_ERROR: &str =
    "heartbeat grace must be a whole number of seconds from 0 through 3600";

pub fn valid_nixpkgs_warn_after_days(days: u32) -> bool {
    (1..=MAX_NIXPKGS_WARN_AFTER_DAYS).contains(&days)
}

pub fn valid_heartbeat_grace_secs(secs: u64) -> bool {
    secs <= MAX_HEARTBEAT_GRACE_SECS
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
    pub fn nixpkgs_warn_after_days(&self, fleet_default: Option<u32>) -> u32 {
        self.alerts
            .nixpkgs_warn_after_days
            .filter(|days| valid_nixpkgs_warn_after_days(*days))
            .or(fleet_default.filter(|days| valid_nixpkgs_warn_after_days(*days)))
            .unwrap_or(DEFAULT_NIXPKGS_WARN_AFTER_DAYS)
    }

    /// Effective late-heartbeat grace: a valid host override, else a valid
    /// fleet value, else [`DEFAULT_HEARTBEAT_GRACE_SECS`].
    pub fn heartbeat_grace_secs(&self, fleet_default: Option<u64>) -> u64 {
        self.heartbeat_grace_policy(fleet_default, None)
            .effective_secs
    }

    /// Applied grace plus the interval it was combined with. `interval_secs`
    /// `None` uses the dashboard's 60-second stand-in. The returned interval
    /// is at least 1, matching historical mark rendering. [`liveness`] does
    /// not use that floor and does not take grace.
    pub fn heartbeat_grace_policy(
        &self,
        fleet_default: Option<u64>,
        interval_secs: Option<u64>,
    ) -> HeartbeatGracePolicy {
        let override_secs = self
            .alerts
            .heartbeat_grace_secs
            .filter(|secs| valid_heartbeat_grace_secs(*secs));
        let fleet_secs = fleet_default
            .filter(|secs| valid_heartbeat_grace_secs(*secs))
            .unwrap_or(DEFAULT_HEARTBEAT_GRACE_SECS);
        let (effective_secs, source) = match override_secs {
            Some(secs) => (secs, HeartbeatGraceSource::Host),
            None => (fleet_secs, HeartbeatGraceSource::Fleet),
        };
        let interval_secs = interval_secs.unwrap_or(60).max(1);
        let late_after_secs = heartbeat_late_after_secs(interval_secs, effective_secs);
        let stale_after_secs = interval_secs.saturating_mul(2);
        let down_after_secs = interval_secs.saturating_mul(5);
        HeartbeatGracePolicy {
            effective_secs,
            source,
            override_secs,
            fleet_secs,
            interval_secs,
            late_after_secs,
            on_time_through_secs: late_after_secs.min(stale_after_secs),
            stale_after_secs,
            down_after_secs,
        }
    }

    pub fn suppresses_down_alerts(&self) -> bool {
        self.kind == HostKind::Workstation || self.alerts.suppress_down
    }

    pub fn validate_contract(&self) -> Result<(), String> {
        if self
            .alerts
            .nixpkgs_warn_after_days
            .is_some_and(|days| !valid_nixpkgs_warn_after_days(days))
        {
            return Err("nixpkgs warning threshold must be between 1 and 3650 days".to_string());
        }
        if self
            .alerts
            .heartbeat_grace_secs
            .is_some_and(|secs| !valid_heartbeat_grace_secs(secs))
        {
            return Err(HEARTBEAT_GRACE_RANGE_ERROR.to_string());
        }
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
    /// Latest measured deployed-release identity. Absence is unknown; Nix
    /// generation evidence never substitutes for this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployed_artifact: Option<DeployedArtifactEvidence>,
}

/// A non-system root nixpkgs input observed for lock-maintenance context.
///
/// This must never drive the host's patch posture: only `NixFreshness`'s
/// primary `nixpkgs_*` fields describe the nixpkgs the system is built from.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixpkgsInputFreshness {
    pub input: String,
    pub age_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel: Option<String>,
}

impl NixpkgsInputFreshness {
    pub fn validate_contract(&self) -> Result<(), String> {
        let family_name = self.input.to_ascii_lowercase();
        if !valid_nix_input_name(&self.input)
            || !family_name.contains("nixpkgs")
            || family_name == "nixpkgs"
        {
            return Err(
                "secondary nixpkgs input must be a bounded non-system nixpkgs-family name"
                    .to_string(),
            );
        }
        if self.age_days > MAX_FLAKE_LOCK_AGE_DAYS {
            return Err(format!(
                "secondary nixpkgs age_days must be <= {MAX_FLAKE_LOCK_AGE_DAYS}"
            ));
        }
        if self
            .channel
            .as_deref()
            .is_some_and(|channel| !valid_nix_channel(channel))
        {
            return Err("secondary nixpkgs channel must be a bounded channel name".to_string());
        }
        Ok(())
    }
}

fn valid_hex_identifier(value: &str, allowed_lengths: &[usize]) -> bool {
    allowed_lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Exact, generation-owned facts embedded by the NixOS evaluation that built
/// `/run/current-system`. Unlike a mutable checkout, these values move only
/// when the active system generation moves.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixDeploymentEvidence {
    pub schema: String,
    pub version: u16,
    pub source_revision: String,
    pub flake_lock_sha256: String,
    pub nixpkgs_revision: String,
    pub nixpkgs_last_modified: UnixSeconds,
    pub nixpkgs_channel: String,
}

impl NixDeploymentEvidence {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != NIX_DEPLOYMENT_EVIDENCE_SCHEMA
            || self.version != NIX_DEPLOYMENT_EVIDENCE_VERSION
        {
            return Err("unsupported Nix deployment evidence schema/version pair".to_string());
        }
        if !valid_hex_identifier(
            &self.source_revision,
            &[MIN_GIT_REVISION_HEX_BYTES, MAX_GIT_REVISION_HEX_BYTES],
        ) {
            return Err("deployment source_revision must be an exact Git object id".to_string());
        }
        if !valid_hex_identifier(&self.flake_lock_sha256, &[SHA256_HEX_BYTES]) {
            return Err("deployment flake_lock_sha256 must be a SHA-256 hex digest".to_string());
        }
        if !valid_hex_identifier(
            &self.nixpkgs_revision,
            &[MIN_GIT_REVISION_HEX_BYTES, MAX_GIT_REVISION_HEX_BYTES],
        ) {
            return Err("deployment nixpkgs_revision must be an exact Git object id".to_string());
        }
        if !(1..=MAX_UNIX_TIMESTAMP).contains(&self.nixpkgs_last_modified) {
            return Err("deployment nixpkgs_last_modified must be a bounded timestamp".to_string());
        }
        if !valid_nix_channel(&self.nixpkgs_channel) {
            return Err("deployment nixpkgs_channel must be a bounded channel name".to_string());
        }
        Ok(())
    }
}

/// Which digest a measured deployed artifact actually captured.
///
/// Container runtimes expose several unrelated OCI hashes. An index digest,
/// manifest digest, and config digest must never be compared as equal.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactDigestClass {
    GenericSha256,
    OciIndex,
    OciManifest,
    OciConfig,
}

impl ArtifactDigestClass {
    pub fn key(self) -> &'static str {
        match self {
            Self::GenericSha256 => "generic_sha256",
            Self::OciIndex => "oci_index",
            Self::OciManifest => "oci_manifest",
            Self::OciConfig => "oci_config",
        }
    }
}

/// Explicitly discriminated release identity. Calendar strings are validated
/// as calendar dates; they are never inferred from punctuation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ArtifactVersionScheme {
    #[serde(rename = "legacy")]
    Legacy,
    #[serde(rename = "inspr-calendar-v1")]
    InsprCalendarV1,
    /// INSPR calendar v2 (INSPR-395 / PHAROS-259): the UTC reservation second
    /// as a twelve-digit SemVer MAJOR with MINOR and PATCH fixed at 0.0.
    /// SemVer-shaped on purpose and still never inferred from punctuation.
    #[serde(rename = "inspr-calendar-v2")]
    InsprCalendarV2,
    /// INSPR-CalVer3: the same coordinate as v2 under the identifier new
    /// reservations declare. Beacons on either keep reporting during a rollout.
    #[serde(rename = "inspr-calver-3")]
    InsprCalver3,
}

impl ArtifactVersionScheme {
    pub fn key(self) -> &'static str {
        match self {
            Self::Legacy => "legacy",
            Self::InsprCalendarV1 => "inspr-calendar-v1",
            Self::InsprCalendarV2 => "inspr-calendar-v2",
            Self::InsprCalver3 => "inspr-calver-3",
        }
    }

    /// Validate a version spelling against the grammar of its declared scheme.
    /// Legacy spellings stay opaque (bounded elsewhere); calendar eras are exact.
    pub fn accepts_version(self, value: &str) -> bool {
        match self {
            Self::Legacy => true,
            Self::InsprCalendarV1 => valid_inspr_calendar_version(value),
            Self::InsprCalendarV2 | Self::InsprCalver3 => valid_inspr_calendar_v2_version(value),
        }
    }
}

/// Host-measured identity of a deployed release artifact. This is not Nix
/// generation evidence and must not be copied from a configured expectation.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeployedArtifactEvidence {
    pub schema: String,
    pub version: u16,
    pub environment: String,
    pub version_scheme: ArtifactVersionScheme,
    pub artifact_version: String,
    pub release_channel: String,
    pub release_sequence: i64,
    pub digest: String,
    pub digest_class: ArtifactDigestClass,
    pub commit_digest: String,
    pub release_manifest_coordinate: String,
    pub release_manifest_digest: String,
    /// Distinct OCI index digest when measured. Never equal to the manifest or
    /// config digest of the same image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_index_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_manifest_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub oci_config_digest: Option<String>,
    /// Clock time of the local measurement. Never copied from operator JSON.
    pub observed_at: UnixSeconds,
}

impl DeployedArtifactEvidence {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA
            || self.version != DEPLOYED_ARTIFACT_EVIDENCE_VERSION
        {
            return Err("unsupported deployed artifact evidence schema/version pair".to_string());
        }
        if !valid_symbol(&self.environment) {
            return Err("deployed artifact environment must be a bounded symbol".to_string());
        }
        if !valid_artifact_version(&self.artifact_version) {
            return Err("deployed artifact version is not a bounded version string".to_string());
        }
        match self.version_scheme {
            ArtifactVersionScheme::Legacy => {}
            ArtifactVersionScheme::InsprCalendarV1 => {
                if !valid_inspr_calendar_version(&self.artifact_version) {
                    return Err(
                        "inspr-calendar-v1 artifact version is not a valid calendar coordinate"
                            .to_string(),
                    );
                }
            }
            ArtifactVersionScheme::InsprCalendarV2 | ArtifactVersionScheme::InsprCalver3 => {
                if !valid_inspr_calendar_v2_version(&self.artifact_version) {
                    return Err(format!(
                        "{} artifact version is not a valid YYMMDDhhmmss.0.0 coordinate",
                        self.version_scheme.key()
                    ));
                }
            }
        }
        if !valid_symbol(&self.release_channel) {
            return Err("deployed artifact release_channel must be a bounded symbol".to_string());
        }
        if self.release_sequence < 0 {
            return Err("deployed artifact release_sequence must be >= 0".to_string());
        }
        if !valid_prefixed_sha256(&self.digest) {
            return Err("deployed artifact digest must be a sha256: hex digest".to_string());
        }
        if !valid_hex_identifier(
            &self.commit_digest,
            &[MIN_GIT_REVISION_HEX_BYTES, MAX_GIT_REVISION_HEX_BYTES],
        ) {
            return Err(
                "deployed artifact commit_digest must be an exact Git object id".to_string(),
            );
        }
        if !valid_release_manifest_coordinate(&self.release_manifest_coordinate) {
            return Err(
                "deployed artifact release_manifest_coordinate must be a bounded coordinate"
                    .to_string(),
            );
        }
        if !valid_prefixed_sha256(&self.release_manifest_digest) {
            return Err(
                "deployed artifact release_manifest_digest must be a sha256: hex digest"
                    .to_string(),
            );
        }
        validate_optional_prefixed_sha256(self.oci_index_digest.as_deref(), "oci_index_digest")?;
        validate_optional_prefixed_sha256(
            self.oci_manifest_digest.as_deref(),
            "oci_manifest_digest",
        )?;
        validate_optional_prefixed_sha256(self.oci_config_digest.as_deref(), "oci_config_digest")?;
        let class_digest = match self.digest_class {
            ArtifactDigestClass::GenericSha256 => None,
            ArtifactDigestClass::OciIndex => self.oci_index_digest.as_deref(),
            ArtifactDigestClass::OciManifest => self.oci_manifest_digest.as_deref(),
            ArtifactDigestClass::OciConfig => self.oci_config_digest.as_deref(),
        };
        if let Some(class_digest) = class_digest {
            if class_digest != self.digest {
                return Err(
                    "deployed artifact digest must equal the digest of its declared class"
                        .to_string(),
                );
            }
        }
        if oci_digests_overlap(
            self.oci_index_digest.as_deref(),
            self.oci_manifest_digest.as_deref(),
            self.oci_config_digest.as_deref(),
        ) {
            return Err(
                "OCI index, manifest, and config digests must remain distinct measurements"
                    .to_string(),
            );
        }
        if self.observed_at < 0 || self.observed_at > MAX_UNIX_TIMESTAMP {
            return Err("deployed artifact observed_at must be a valid Unix timestamp".to_string());
        }
        Ok(())
    }

    /// True only when the measured identity equals the expected tuple and the
    /// compared digest is the one named by `digest_class`.
    #[allow(clippy::too_many_arguments)]
    pub fn matches_expected(
        &self,
        environment: &str,
        version_scheme: ArtifactVersionScheme,
        version: &str,
        release_channel: &str,
        release_sequence: i64,
        digest: &str,
        commit_digest: &str,
        release_manifest_coordinate: &str,
        release_manifest_digest: &str,
    ) -> bool {
        self.validate_contract().is_ok()
            && self.environment == environment
            && self.version_scheme == version_scheme
            && self.artifact_version == version
            && self.release_channel == release_channel
            && self.release_sequence == release_sequence
            && self.digest == digest
            && self.commit_digest == commit_digest
            && self.release_manifest_coordinate == release_manifest_coordinate
            && self.release_manifest_digest == release_manifest_digest
            && match self.digest_class {
                ArtifactDigestClass::GenericSha256 => {
                    self.oci_index_digest.is_none()
                        && self.oci_manifest_digest.is_none()
                        && self.oci_config_digest.is_none()
                }
                ArtifactDigestClass::OciIndex => self.oci_index_digest.as_deref() == Some(digest),
                ArtifactDigestClass::OciManifest => {
                    self.oci_manifest_digest.as_deref() == Some(digest)
                }
                ArtifactDigestClass::OciConfig => self.oci_config_digest.as_deref() == Some(digest),
            }
    }

    pub fn is_config_class_measurement(&self) -> bool {
        self.digest_class == ArtifactDigestClass::OciConfig
            && self.oci_config_digest.as_deref() == Some(self.digest.as_str())
            && self.oci_index_digest.is_none()
            && self.oci_manifest_digest.is_none()
    }
}

/// Release tuple bound to an immutable image config digest. This is not an
/// observation and carries no timestamp.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ApprovedReleaseEnvelope {
    pub schema: String,
    pub version: u16,
    pub environment: String,
    pub version_scheme: ArtifactVersionScheme,
    pub artifact_version: String,
    pub release_channel: String,
    pub release_sequence: i64,
    pub commit_digest: String,
    pub release_manifest_coordinate: String,
    pub release_manifest_digest: String,
    pub oci_config_digest: String,
}

impl ApprovedReleaseEnvelope {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.schema != APPROVED_RELEASE_ENVELOPE_SCHEMA
            || self.version != APPROVED_RELEASE_ENVELOPE_VERSION
        {
            return Err("unsupported approved release envelope schema/version pair".to_string());
        }
        let probe = DeployedArtifactEvidence {
            schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
            version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
            environment: self.environment.clone(),
            version_scheme: self.version_scheme,
            artifact_version: self.artifact_version.clone(),
            release_channel: self.release_channel.clone(),
            release_sequence: self.release_sequence,
            digest: self.oci_config_digest.clone(),
            digest_class: ArtifactDigestClass::OciConfig,
            commit_digest: self.commit_digest.clone(),
            release_manifest_coordinate: self.release_manifest_coordinate.clone(),
            release_manifest_digest: self.release_manifest_digest.clone(),
            oci_index_digest: None,
            oci_manifest_digest: None,
            oci_config_digest: Some(self.oci_config_digest.clone()),
            observed_at: 0,
        };
        probe.validate_contract().map(|_| ())
    }
}

/// Filtered facts from a fixed `docker inspect --format` query.
///
/// `image_identity` is the engine-reported image id (Docker 29 may put a
/// *manifest* digest in `{{.Image}}`). It is not a digest class. Config-class
/// evidence requires a separately resolved config digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunningContainerObservation {
    pub running: bool,
    pub container_id: String,
    pub image_identity: String,
    pub environment: Option<String>,
    pub version_scheme: Option<String>,
    pub artifact_version: Option<String>,
    pub release_channel: Option<String>,
    pub release_sequence: Option<String>,
    pub commit_digest: Option<String>,
    pub release_manifest_coordinate: Option<String>,
    pub release_manifest_digest: Option<String>,
}

/// Parse a locally allowlisted evidence document. This is a type decoder, not a
/// measurement producer: it cannot invent a running artifact or a timestamp.
pub fn collect_deployed_artifact_from_metadata_file(
    raw: &[u8],
) -> Result<DeployedArtifactEvidence, String> {
    let evidence =
        decode_bounded_json::<DeployedArtifactEvidence>(raw, "deployed artifact metadata")?;
    evidence.validate_contract()?;
    Ok(evidence)
}

/// Parse a trusted release envelope. The envelope never becomes evidence by itself.
pub fn parse_approved_release_envelope(raw: &[u8]) -> Result<ApprovedReleaseEnvelope, String> {
    let envelope =
        decode_bounded_json::<ApprovedReleaseEnvelope>(raw, "approved release envelope")?;
    envelope.validate_contract()?;
    Ok(envelope)
}

pub fn parse_running_container_format(raw: &str) -> Result<RunningContainerObservation, String> {
    let line = raw.trim_end_matches(['\n', '\r']);
    if line.is_empty() || line.lines().count() != 1 {
        return Err("running container measurement must be exactly one filtered line".to_string());
    }
    let fields: Vec<&str> = line.split('\t').collect();
    if fields.len() != 11 {
        return Err(
            "running container measurement must contain exactly eleven filtered fields".to_string(),
        );
    }
    let running = match fields[0] {
        "true" => true,
        "false" => false,
        _ => return Err("running container measurement running flag is not boolean".to_string()),
    };
    let container_id = normalize_container_id(fields[1])
        .ok_or_else(|| "running container identity is not an exact container id".to_string())?;
    let image_identity = normalize_prefixed_sha256(fields[2])
        .ok_or_else(|| "running container image is not a sha256 image identity".to_string())?;
    Ok(RunningContainerObservation {
        running,
        container_id,
        image_identity,
        environment: optional_measured_field(fields[3]),
        version_scheme: optional_measured_field(fields[4]),
        artifact_version: optional_measured_field(fields[5]),
        release_channel: optional_measured_field(fields[6]),
        release_sequence: optional_measured_field(fields[7]),
        commit_digest: optional_measured_field(fields[8]),
        release_manifest_coordinate: optional_measured_field(fields[9]),
        release_manifest_digest: optional_measured_field(fields[10]),
    })
}

/// Bind a running-container measurement to an optional digest-locked envelope.
/// `image_config_digest` is the resolved OCI config digest, never an untyped
/// engine id. Observation time is supplied by the caller from the measurement
/// clock.
pub fn evidence_from_running_container(
    observation: &RunningContainerObservation,
    image_config_digest: &str,
    envelope: Option<&ApprovedReleaseEnvelope>,
    observed_at: UnixSeconds,
) -> Result<DeployedArtifactEvidence, String> {
    if !observation.running {
        return Err("allowlisted container is not running".to_string());
    }
    let image_config_digest = normalize_prefixed_sha256(image_config_digest)
        .ok_or_else(|| "measured image config is not an OCI config digest".to_string())?;
    if let Some(envelope) = envelope {
        envelope.validate_contract()?;
        if envelope.oci_config_digest != image_config_digest {
            return Err(
                "approved release envelope is not immutably bound to the measured config digest"
                    .to_string(),
            );
        }
    }
    let environment = merge_measured_field(
        observation.environment.as_deref(),
        envelope.map(|envelope| envelope.environment.as_str()),
        "environment",
    )?;
    let version_scheme = parse_measured_version_scheme(&merge_measured_field(
        observation.version_scheme.as_deref(),
        envelope.map(|envelope| envelope.version_scheme.key()),
        "version_scheme",
    )?)?;
    let artifact_version = merge_measured_field(
        observation.artifact_version.as_deref(),
        envelope.map(|envelope| envelope.artifact_version.as_str()),
        "version",
    )?;
    let release_channel = merge_measured_field(
        observation.release_channel.as_deref(),
        envelope.map(|envelope| envelope.release_channel.as_str()),
        "release_channel",
    )?;
    let release_sequence_text = envelope.map(|envelope| envelope.release_sequence.to_string());
    let release_sequence = merge_measured_field(
        observation.release_sequence.as_deref(),
        release_sequence_text.as_deref(),
        "release_sequence",
    )?
    .parse::<i64>()
    .map_err(|_| "release_sequence is not a non-negative integer".to_string())?;
    let commit_digest = merge_measured_field(
        observation.commit_digest.as_deref(),
        envelope.map(|envelope| envelope.commit_digest.as_str()),
        "commit_digest",
    )?;
    let release_manifest_coordinate = merge_measured_field(
        observation.release_manifest_coordinate.as_deref(),
        envelope.map(|envelope| envelope.release_manifest_coordinate.as_str()),
        "release_manifest_coordinate",
    )?;
    let release_manifest_digest = merge_measured_field(
        observation.release_manifest_digest.as_deref(),
        envelope.map(|envelope| envelope.release_manifest_digest.as_str()),
        "release_manifest_digest",
    )?;
    let evidence = DeployedArtifactEvidence {
        schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
        version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
        environment,
        version_scheme,
        artifact_version,
        release_channel,
        release_sequence,
        digest: image_config_digest.clone(),
        digest_class: ArtifactDigestClass::OciConfig,
        commit_digest,
        release_manifest_coordinate,
        release_manifest_digest,
        oci_index_digest: None,
        oci_manifest_digest: None,
        oci_config_digest: Some(image_config_digest),
        observed_at,
    };
    evidence.validate_contract()?;
    Ok(evidence)
}

pub fn valid_allowlisted_container_ref(value: &str) -> bool {
    if normalize_prefixed_sha256(value).is_some() || normalize_container_id(value).is_some() {
        return true;
    }
    (1..=128).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !value.starts_with('-')
        && !value.contains("--")
}

pub fn configured_container_matches_measurement(
    configured: &str,
    measured_container_id: &str,
) -> bool {
    match (
        normalize_container_id(configured),
        normalize_container_id(measured_container_id),
    ) {
        (Some(configured), Some(measured)) => configured == measured,
        (None, Some(_)) => valid_allowlisted_container_ref(configured),
        _ => false,
    }
}

fn decode_bounded_json<T: serde::de::DeserializeOwned>(
    raw: &[u8],
    name: &str,
) -> Result<T, String> {
    if raw.is_empty() || raw.len() as u64 > MAX_DEPLOYED_ARTIFACT_EVIDENCE_BYTES {
        return Err(format!("{name} exceeds the bounded collector size"));
    }
    let mut deserializer = serde_json::Deserializer::from_slice(raw);
    let value = T::deserialize(&mut deserializer)
        .map_err(|_| format!("{name} is not a typed measurement"))?;
    deserializer
        .end()
        .map_err(|_| format!("{name} has trailing data"))?;
    Ok(value)
}

fn optional_measured_field(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value == "<no value>" {
        None
    } else {
        Some(value.to_string())
    }
}

fn merge_measured_field(
    label: Option<&str>,
    envelope: Option<&str>,
    name: &str,
) -> Result<String, String> {
    match (
        label.filter(|value| !value.is_empty()),
        envelope.filter(|value| !value.is_empty()),
    ) {
        (Some(label), Some(envelope)) if label == envelope => Ok(label.to_string()),
        (Some(_), Some(_)) => Err(format!(
            "{name} label disagrees with the approved release envelope"
        )),
        (Some(label), None) => Ok(label.to_string()),
        (None, Some(envelope)) => Ok(envelope.to_string()),
        (None, None) => Err(format!("{name} was not measured")),
    }
}

fn parse_measured_version_scheme(value: &str) -> Result<ArtifactVersionScheme, String> {
    match value {
        "legacy" => Ok(ArtifactVersionScheme::Legacy),
        "inspr-calendar-v1" => Ok(ArtifactVersionScheme::InsprCalendarV1),
        "inspr-calendar-v2" => Ok(ArtifactVersionScheme::InsprCalendarV2),
        "inspr-calver-3" => Ok(ArtifactVersionScheme::InsprCalver3),
        _ => Err("version_scheme is not an explicit supported scheme".to_string()),
    }
}

pub(crate) fn normalize_prefixed_sha256(value: &str) -> Option<String> {
    let value = value.trim();
    if valid_prefixed_sha256(value) {
        Some(value.to_string())
    } else if valid_hex_identifier(value, &[SHA256_HEX_BYTES]) {
        Some(format!("sha256:{value}"))
    } else {
        None
    }
}

fn normalize_container_id(value: &str) -> Option<String> {
    normalize_prefixed_sha256(value)
}

fn oci_digests_overlap(index: Option<&str>, manifest: Option<&str>, config: Option<&str>) -> bool {
    let ids: Vec<&str> = [index, manifest, config].into_iter().flatten().collect();
    ids.iter()
        .any(|left| ids.iter().filter(|right| left == *right).count() > 1)
}

fn validate_optional_prefixed_sha256(value: Option<&str>, name: &str) -> Result<(), String> {
    match value {
        None => Ok(()),
        Some(value) if valid_prefixed_sha256(value) => Ok(()),
        Some(_) => Err(format!("{name} must be a sha256: hex digest")),
    }
}

fn valid_prefixed_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| valid_hex_identifier(digest, &[SHA256_HEX_BYTES]))
}

fn valid_symbol(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_artifact_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn valid_release_manifest_coordinate(value: &str) -> bool {
    let Some((kind, coordinate)) = value.split_once(':') else {
        return false;
    };
    valid_symbol(kind)
        && (1..=190).contains(&coordinate.len())
        && coordinate.as_bytes()[0].is_ascii_alphanumeric()
        && coordinate.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'/' | b'@' | b':' | b'+' | b'-')
        })
}

/// INSPR Calendar Version v1: `YY.MM.DD` or `YY.MM.DD.hh.mm.ss`, proleptic
/// Gregorian, UTC fields. Invalid dates such as `26.02.29` fail closed.
pub fn valid_inspr_calendar_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    if parts
        .iter()
        .any(|part| part.len() != 2 || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return false;
    }
    let numbers = match parts
        .iter()
        .map(|part| part.parse::<u32>())
        .collect::<Result<Vec<_>, _>>()
    {
        Ok(numbers) => numbers,
        Err(_) => return false,
    };
    let (year, month, day, hour, minute, second) = match numbers.as_slice() {
        [year, month, day] => (2000 + *year, *month, *day, 0, 0, 0),
        [year, month, day, hour, minute, second] => {
            (2000 + *year, *month, *day, *hour, *minute, *second)
        }
        _ => return false,
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// Exact INSPR calendar v2 coordinate: `YYMMDDhhmmss.0.0` with a real UTC date.
/// Twelve fixed-width digits that never start with zero, then the literal
/// constant `0.0`. Shorter or longer majors, prerelease or build suffixes and
/// any non-zero MINOR/PATCH are rejected.
pub fn valid_inspr_calendar_v2_version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    let [stamp, minor, patch] = parts.as_slice() else {
        return false;
    };
    if *minor != "0" || *patch != "0" {
        return false;
    }
    if stamp.len() != 12
        || !stamp.bytes().all(|byte| byte.is_ascii_digit())
        || stamp.starts_with('0')
    {
        return false;
    }
    let field = |start: usize| stamp[start..start + 2].parse::<u32>().unwrap_or(u32::MAX);
    let (year, month, day, hour, minute, second) = (
        2000 + field(0),
        field(2),
        field(4),
        field(6),
        field(8),
        field(10),
    );
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GitRevisionRelation {
    Current,
    Behind,
    Ahead,
    Diverged,
}

/// Fresh comparison of the deployed generation against one explicitly
/// configured authoritative Git branch.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixcfgGitComparison {
    pub upstream_revision: String,
    pub relation: GitRevisionRelation,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commits_behind: Option<u32>,
}

impl NixcfgGitComparison {
    pub fn validate_contract(&self, deployed_revision: &str) -> Result<(), String> {
        if !valid_hex_identifier(
            &self.upstream_revision,
            &[MIN_GIT_REVISION_HEX_BYTES, MAX_GIT_REVISION_HEX_BYTES],
        ) {
            return Err("upstream_revision must be an exact Git object id".to_string());
        }
        if self
            .commits_behind
            .is_some_and(|commits| commits > MAX_COMMITS_BEHIND)
        {
            return Err(format!("commits_behind must be <= {MAX_COMMITS_BEHIND}"));
        }
        match self.relation {
            GitRevisionRelation::Current
                if self.upstream_revision == deployed_revision
                    && self.commits_behind == Some(0) => {}
            GitRevisionRelation::Behind
                if self.upstream_revision != deployed_revision
                    && self.commits_behind.is_some_and(|commits| commits > 0) => {}
            GitRevisionRelation::Ahead | GitRevisionRelation::Diverged
                if self.upstream_revision != deployed_revision && self.commits_behind.is_none() => {
            }
            _ => {
                return Err(
                    "Git relation, exact revisions, and commits_behind are inconsistent"
                        .to_string(),
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NixpkgsRevisionRelation {
    Current,
    Different,
}

/// Exact comparison of the generation's locked nixpkgs revision with the
/// freshly observed tip of its declared channel. `Different` deliberately
/// does not claim ancestry that was not fetched and proven.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixpkgsGitComparison {
    pub upstream_revision: String,
    pub relation: NixpkgsRevisionRelation,
}

impl NixpkgsGitComparison {
    pub fn validate_contract(&self, deployed_revision: &str) -> Result<(), String> {
        if !valid_hex_identifier(
            &self.upstream_revision,
            &[MIN_GIT_REVISION_HEX_BYTES, MAX_GIT_REVISION_HEX_BYTES],
        ) {
            return Err("nixpkgs upstream_revision must be an exact Git object id".to_string());
        }
        let consistent = match self.relation {
            NixpkgsRevisionRelation::Current => self.upstream_revision == deployed_revision,
            NixpkgsRevisionRelation::Different => self.upstream_revision != deployed_revision,
        };
        consistent
            .then_some(())
            .ok_or_else(|| "nixpkgs relation and exact revisions are inconsistent".to_string())
    }
}

/// Nix freshness for a host (PHAROS-15): what it is "missing".
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NixFreshness {
    /// `false` for non-Nix hosts → renders `nix: n/a`.
    pub applicable: bool,
    /// Age of `flake.lock` in days (time since the last `nix flake update`).
    ///
    /// This is the age of the *newest* input, so it answers "when did someone
    /// last update this flake" and not "is anything here stale". PHAROS-193: a
    /// lock whose nixpkgs is frozen still reports `0d` here the moment any
    /// trivial input moves, so never read this alone as a security posture.
    pub flake_lock_age_days: Option<u32>,
    /// Compatibility mirror of the exact proven count in `nixcfg_comparison`.
    /// It is absent for unknown, ahead, or diverged state and must never be
    /// calculated from a stale local tracking ref.
    pub commits_behind: Option<u32>,
    /// Server-normalized age context for the exact generation-owned nixpkgs
    /// revision. Age alone never proves whether the lock matches its channel.
    ///
    /// PHAROS-196: specifically the flake's own `nixpkgs` input, not the oldest
    /// node whose name contains "nixpkgs". A lock also holds other root inputs
    /// that may be unreferenced and transitive inputs of unrelated flakes;
    /// reporting the worst of those describes the lock file, not the host, and
    /// reads as a patching gap that does not exist.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixpkgs_age_days: Option<u32>,
    /// PHAROS-193: the release channel that nixpkgs input tracks, such as
    /// `nixos-25.05`. The beacon reports the observed channel only; the control
    /// plane decides whether it is end-of-life, so a newly expired release
    /// needs no fleet-wide beacon roll.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixpkgs_channel: Option<String>,
    /// PHAROS-201: the stalest other root input whose declared name identifies
    /// it as nixpkgs-family. This is secondary lock-maintenance context only;
    /// it does not participate in attention or service-posture classification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secondary_nixpkgs: Option<NixpkgsInputFreshness>,
    /// PHAROS-202: facts tied to the active NixOS generation. Absence means
    /// freshness is unverified; callers must never fall back to claiming that
    /// the host is up to date.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployment_evidence: Option<NixDeploymentEvidence>,
    /// Fresh authoritative nixcfg comparison. Absence is explicitly unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixcfg_comparison: Option<NixcfgGitComparison>,
    /// Fresh exact comparison with the declared nixpkgs channel tip. Absence
    /// is explicitly unknown.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nixpkgs_comparison: Option<NixpkgsGitComparison>,
}

/// Support state of a NixOS release channel (PHAROS-193).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NixChannelState {
    /// A dated `nixos-YY.MM` release that is past end of life.
    EndOfLife,
    /// A dated release still inside its support window.
    Supported,
    /// A rolling channel such as `nixos-unstable`, or anything undated. Age is
    /// the only available signal for these.
    Rolling,
}

/// End of life for a dated NixOS release, as a `(year, month)` pair.
///
/// NixOS supports a release until roughly one month after its successor ships,
/// and releases ship in May and November. So `YY.05` ends shortly after
/// `YY.11` + one month, and `YY.11` ends shortly after `(YY+1).05` + one month.
/// Deliberately coarse: it resolves to the first day of the month after that
/// window, so a channel is only ever flagged once it is unambiguously expired.
fn nixos_release_end_of_life(year: u32, month: u32) -> Option<(u32, u32)> {
    match month {
        5 => Some((year + 1, 1)),
        11 => Some((year + 1, 7)),
        _ => None,
    }
}

/// Classify a reported channel against the release calendar.
///
/// `now_year`/`now_month` come from the caller so this stays a pure function
/// and tests do not depend on the wall clock.
pub fn nix_channel_state(channel: &str, now_year: u32, now_month: u32) -> NixChannelState {
    let Some(release) = channel.strip_prefix("nixos-") else {
        return NixChannelState::Rolling;
    };
    let Some((year, month)) = release.split_once('.') else {
        return NixChannelState::Rolling;
    };
    let (Ok(year), Ok(month)) = (year.parse::<u32>(), month.parse::<u32>()) else {
        return NixChannelState::Rolling;
    };
    // Two-digit release years are 20YY; anything else is not a dated release.
    if year > 99 || !(1..=12).contains(&month) {
        return NixChannelState::Rolling;
    }
    let Some((eol_year, eol_month)) = nixos_release_end_of_life(2000 + year, month) else {
        return NixChannelState::Rolling;
    };
    if (now_year, now_month) >= (eol_year, eol_month) {
        NixChannelState::EndOfLife
    } else {
        NixChannelState::Supported
    }
}

/// A channel name is a short, bounded, value-free identifier.
pub fn valid_nix_channel(channel: &str) -> bool {
    !channel.is_empty()
        && channel.len() <= MAX_NIX_CHANNEL_BYTES
        && channel
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '.' | '_'))
}

/// A root flake input name is a short value-free identifier.
pub fn valid_nix_input_name(input: &str) -> bool {
    !input.is_empty()
        && input.len() <= MAX_NIX_INPUT_NAME_BYTES
        && input
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
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
        if self
            .nixpkgs_age_days
            .is_some_and(|days| days > MAX_FLAKE_LOCK_AGE_DAYS)
        {
            return Err(format!(
                "nixpkgs_age_days must be <= {MAX_FLAKE_LOCK_AGE_DAYS}"
            ));
        }
        if self
            .nixpkgs_channel
            .as_deref()
            .is_some_and(|channel| !valid_nix_channel(channel))
        {
            return Err("nixpkgs_channel must be a bounded channel name".to_string());
        }
        if let Some(secondary) = &self.secondary_nixpkgs {
            secondary.validate_contract()?;
            if self.nixpkgs_age_days.is_none() {
                return Err(
                    "secondary nixpkgs context requires primary nixpkgs freshness".to_string(),
                );
            }
        }
        if let Some(evidence) = &self.deployment_evidence {
            evidence.validate_contract()?;
            if self.nixpkgs_channel.as_deref() != Some(evidence.nixpkgs_channel.as_str()) {
                return Err(
                    "reported nixpkgs_channel must match active-generation evidence".to_string(),
                );
            }
        }
        if let Some(comparison) = &self.nixcfg_comparison {
            let evidence = self.deployment_evidence.as_ref().ok_or_else(|| {
                "nixcfg comparison requires active-generation evidence".to_string()
            })?;
            comparison.validate_contract(&evidence.source_revision)?;
            if self.commits_behind != comparison.commits_behind {
                return Err(
                    "legacy commits_behind must exactly mirror the proven comparison".to_string(),
                );
            }
        } else if self.deployment_evidence.is_some() && self.commits_behind.is_some() {
            return Err(
                "commits_behind must be absent when the authoritative comparison is unknown"
                    .to_string(),
            );
        }
        if let Some(comparison) = &self.nixpkgs_comparison {
            let evidence = self.deployment_evidence.as_ref().ok_or_else(|| {
                "nixpkgs comparison requires active-generation evidence".to_string()
            })?;
            comparison.validate_contract(&evidence.nixpkgs_revision)?;
        }
        if !self.applicable
            && (self.flake_lock_age_days.is_some()
                || self.commits_behind.is_some()
                || self.nixpkgs_age_days.is_some()
                || self.nixpkgs_channel.is_some()
                || self.secondary_nixpkgs.is_some()
                || self.deployment_evidence.is_some()
                || self.nixcfg_comparison.is_some()
                || self.nixpkgs_comparison.is_some())
        {
            return Err("non-Nix freshness must not carry Nix values".to_string());
        }
        Ok(())
    }

    /// PHAROS-193: how the reported channel stands against the release calendar.
    pub fn channel_state(&self, now_year: u32, now_month: u32) -> Option<NixChannelState> {
        self.deployment_evidence
            .as_ref()
            .map(|evidence| evidence.nixpkgs_channel.as_str())
            .or(self.nixpkgs_channel.as_deref())
            .map(|channel| nix_channel_state(channel, now_year, now_month))
    }

    pub fn has_verified_current_state(&self) -> bool {
        self.deployment_evidence.is_some()
            && self
                .nixcfg_comparison
                .as_ref()
                .is_some_and(|comparison| comparison.relation == GitRevisionRelation::Current)
            && self
                .nixpkgs_comparison
                .as_ref()
                .is_some_and(|comparison| comparison.relation == NixpkgsRevisionRelation::Current)
    }

    pub fn has_proven_deployable_update(&self) -> bool {
        self.nixcfg_comparison.as_ref().is_some_and(|comparison| {
            comparison.relation == GitRevisionRelation::Behind
                && comparison.commits_behind.is_some_and(|commits| commits > 0)
        })
    }

    /// Attention policy only: a revision difference needs age-based attention
    /// once the deployed revision's server-clock age exceeds the configured limit.
    /// Missing generation evidence or unknown age never proves staleness.
    pub fn nixpkgs_age_warning_at(&self, now: UnixSeconds, threshold_days: u32) -> bool {
        self.applicable
            && self.deployment_evidence.is_some()
            && self
                .nixpkgs_comparison
                .as_ref()
                .is_some_and(|comparison| comparison.relation == NixpkgsRevisionRelation::Different)
            && self
                .nixpkgs_age_days_at(now)
                .is_some_and(|days| days > threshold_days)
    }

    /// Server-clock age of the generation's exact locked nixpkgs revision.
    /// Legacy reports have no generation timestamp and retain their explicitly
    /// unverified numeric context, but v5 proof never trusts the host clock.
    pub fn nixpkgs_age_days_at(&self, now: UnixSeconds) -> Option<u32> {
        match self.deployment_evidence.as_ref() {
            Some(evidence) => {
                u32::try_from(now.saturating_sub(evidence.nixpkgs_last_modified).max(0) / 86_400)
                    .ok()
                    .filter(|days| *days <= MAX_FLAKE_LOCK_AGE_DAYS)
            }
            None => self.nixpkgs_age_days,
        }
    }

    /// Human one-liner TL;DR, e.g. `flake.lock 12d old · 3 commits behind nixcfg`,
    /// `up to date`, or `nix: n/a`.
    pub fn tldr(&self) -> String {
        if !self.applicable {
            return "nix: n/a".to_string();
        }
        let Some(evidence) = &self.deployment_evidence else {
            return "freshness unverified".to_string();
        };
        let mut parts = Vec::new();
        match self.nixpkgs_comparison.as_ref().map(|value| value.relation) {
            Some(NixpkgsRevisionRelation::Current) => {}
            Some(NixpkgsRevisionRelation::Different) => {
                parts.push(format!("nixpkgs differs from {}", evidence.nixpkgs_channel))
            }
            None => parts.push("nixpkgs comparison unknown".to_string()),
        }
        match self.nixcfg_comparison.as_ref() {
            Some(comparison) if comparison.relation == GitRevisionRelation::Current => {}
            Some(comparison) if comparison.relation == GitRevisionRelation::Behind => {
                let commits = comparison.commits_behind.unwrap_or(0);
                parts.push(format!("{commits} commits behind nixcfg"));
            }
            Some(comparison) if comparison.relation == GitRevisionRelation::Ahead => {
                parts.push("deployed revision is ahead of nixcfg".to_string());
            }
            Some(comparison) if comparison.relation == GitRevisionRelation::Diverged => {
                parts.push("deployed revision diverges from nixcfg".to_string());
            }
            None => parts.push("nixcfg comparison unknown".to_string()),
            Some(_) => {}
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
    /// The kernel a reboot would run. Beacons that cannot see the system profile
    /// report the active system's kernel here instead, which misses a staged boot.
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
/// `now` and `last_seen` are both server-stamped (PHAROS-9). Late-heartbeat
/// grace does not change these cuts (PHAROS-292).
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

/// Where a host's effective late-heartbeat grace came from. Fleet includes the
/// built-in 15 seconds when no saved fleet value is available.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HeartbeatGraceSource {
    Host,
    Fleet,
}

impl HeartbeatGraceSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Host => "host",
            Self::Fleet => "fleet",
        }
    }
}

/// Applied grace and the thresholds it produces for one reported cadence.
/// `late_after_secs` is the policy cut (`interval + grace`). Stale and down
/// stay at 2× and 5×. `on_time_through_secs` is the last second that is still
/// on time after those older cuts outrank grace.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct HeartbeatGracePolicy {
    pub effective_secs: u64,
    pub source: HeartbeatGraceSource,
    pub override_secs: Option<u64>,
    pub fleet_secs: u64,
    pub interval_secs: u64,
    pub late_after_secs: u64,
    pub on_time_through_secs: u64,
    pub stale_after_secs: u64,
    pub down_after_secs: u64,
}

pub fn heartbeat_policy_interval(interval_secs: u64) -> u64 {
    interval_secs.max(1)
}

pub fn heartbeat_late_after_secs(interval_secs: u64, grace_secs: u64) -> u64 {
    heartbeat_policy_interval(interval_secs).saturating_add(grace_secs)
}

// PHAROS-206 moved the contract to v6 by adding optional measured deployed
// artifact identity, distinct from Nix generation / flake.lock evidence.
// PHAROS-304 moved it to v7 by adding optional selective-restore history on
// `BackupValidationObservation` (`last_success_at`, `restored_files`), so a
// later failed attempt no longer erases the last successful restore.
// `deny_unknown_fields` makes any addition breaking for an older consumer, so
// the version moves with it and the rollout order in README applies: control
// plane first, then beacons. Known browser clients still emit v4, so the
// control plane keeps accepting v4, v5 and v6 as supported predecessors.
pub const HOST_REPORT_SCHEMA: &str = "inspr.pharos.host-report.v7";
pub const HOST_REPORT_VERSION: u16 = 7;
pub const PREVIOUS_HOST_REPORT_SCHEMA: &str = HOST_REPORT_V6_SCHEMA;
pub const PREVIOUS_HOST_REPORT_VERSION: u16 = HOST_REPORT_V6_VERSION;
pub const HOST_REPORT_V4_SCHEMA: &str = "inspr.pharos.host-report.v4";
pub const HOST_REPORT_V4_VERSION: u16 = 4;
pub const HOST_REPORT_V5_SCHEMA: &str = "inspr.pharos.host-report.v5";
pub const HOST_REPORT_V5_VERSION: u16 = 5;
pub const HOST_REPORT_V6_SCHEMA: &str = "inspr.pharos.host-report.v6";
pub const HOST_REPORT_V6_VERSION: u16 = 6;
pub const SUPPORTED_HOST_REPORT_CONTRACTS: [(&str, u16); 4] = [
    (HOST_REPORT_V4_SCHEMA, HOST_REPORT_V4_VERSION),
    (HOST_REPORT_V5_SCHEMA, HOST_REPORT_V5_VERSION),
    (HOST_REPORT_V6_SCHEMA, HOST_REPORT_V6_VERSION),
    (HOST_REPORT_SCHEMA, HOST_REPORT_VERSION),
];

fn default_host_report_version() -> u16 {
    HOST_REPORT_VERSION
}

/// v7 evidence: a retained last successful selective restore or a restored
/// file count on the validation observation. Older report versions cannot
/// carry it, so the control plane refuses it there instead of guessing.
fn backup_observations_carry_restore_history(observations: &[BackupObservation]) -> bool {
    observations.iter().any(|observation| {
        observation
            .restore_validation
            .as_ref()
            .is_some_and(|validation| {
                validation.last_success_at.is_some() || validation.restored_files.is_some()
            })
    })
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
    /// Optional measured deployed-release identity. Missing means unknown, not
    /// that the configured artifact is running. v4 and v5 reports must omit this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deployed_artifact: Option<DeployedArtifactEvidence>,
}

impl HostReport {
    pub fn validate_contract(&self) -> Result<(), String> {
        if !SUPPORTED_HOST_REPORT_CONTRACTS
            .iter()
            .any(|(schema, version)| self.schema == *schema && self.version == *version)
        {
            return Err("unsupported report schema/version pair".to_string());
        }
        if self.version == HOST_REPORT_V4_VERSION {
            if freshness_carries_v5_proof(&self.freshness) {
                return Err("report v4 must not carry v5 freshness evidence".to_string());
            }
            if self.deployed_artifact.is_some() {
                return Err("report v4 must not carry v6 deployed artifact evidence".to_string());
            }
        }
        if self.version == HOST_REPORT_V5_VERSION && self.deployed_artifact.is_some() {
            return Err("report v5 must not carry v6 deployed artifact evidence".to_string());
        }
        if self.version < HOST_REPORT_VERSION
            && backup_observations_carry_restore_history(&self.backup_observations)
        {
            return Err(format!(
                "report v{} must not carry v7 selective restore history",
                self.version
            ));
        }
        validate_report_identity(&self.name, &self.role)?;
        validate_heartbeat_interval(self.heartbeat_interval_secs)?;
        if self.is_nix != self.freshness.applicable {
            return Err("is_nix and freshness applicability must match".to_string());
        }
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
        if let Some(evidence) = &self.deployed_artifact {
            evidence.validate_contract()?;
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

fn freshness_carries_v5_proof(freshness: &NixFreshness) -> bool {
    freshness.deployment_evidence.is_some()
        || freshness.nixcfg_comparison.is_some()
        || freshness.nixpkgs_comparison.is_some()
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
        Self::nix_freshness_at(freshness, None)
    }

    /// PHAROS-193: `now` is `(year, month)` for the release-calendar check, and
    /// is `None` where the caller has no calendar to apply (the beacon reports
    /// the observed channel; the control plane classifies it).
    pub fn nix_freshness_at(freshness: &NixFreshness, now: Option<(u32, u32)>) -> Self {
        let end_of_life = now.and_then(|(year, month)| freshness.channel_state(year, month))
            == Some(NixChannelState::EndOfLife);
        let (state, summary) = if !freshness.applicable {
            (ServiceObservationState::Unknown, "nix: n/a".to_string())
        } else if freshness.deployment_evidence.is_none() {
            (
                ServiceObservationState::Unknown,
                "active-generation freshness unverified".to_string(),
            )
        } else if end_of_life {
            // A stale channel outranks any age number: no age is small enough
            // to make an end-of-life release safe.
            (
                ServiceObservationState::Stale,
                match freshness
                    .deployment_evidence
                    .as_ref()
                    .map(|evidence| evidence.nixpkgs_channel.as_str())
                {
                    Some(channel) => format!("{channel} is end of life; no security fixes"),
                    None => "nixpkgs channel is end of life; no security fixes".to_string(),
                },
            )
        } else if freshness.nixcfg_comparison.is_none() || freshness.nixpkgs_comparison.is_none() {
            (
                ServiceObservationState::Unknown,
                "authoritative freshness comparison unavailable".to_string(),
            )
        } else if !freshness.has_verified_current_state() {
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

/// One validation record per backup observation. `level`, `state` and
/// `checked_at` describe the latest attempt. Since host-report v7 (PHAROS-304)
/// the record also retains the last successful selective restore on its own:
/// `last_success_at` survives a later failed or stale attempt, and
/// `restored_files` is the count of files that restore actually brought back.
/// A selective restore satisfies the monthly requirement only with at least
/// one restored file; a record without that evidence stays "not observed".
/// Legacy documents without the two fields still deserialize.
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
    /// Time of the last successful selective restore, independent of the
    /// latest attempt recorded in `state` / `checked_at`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_success_at: Option<UnixSeconds>,
    /// Files actually restored by that last success. Zero means the attempt
    /// restored nothing and is not evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub restored_files: Option<u32>,
}

impl BackupValidationObservation {
    pub fn validate_contract(&self) -> Result<(), String> {
        if self.last_success_at.is_some_and(|at| at <= 0) {
            return Err(
                "backup validation last_success_at must be a positive unix time".to_string(),
            );
        }
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

    fn test_deployment_evidence(channel: &str) -> NixDeploymentEvidence {
        NixDeploymentEvidence {
            schema: NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "1".repeat(40),
            flake_lock_sha256: "2".repeat(64),
            nixpkgs_revision: "3".repeat(40),
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: channel.to_string(),
        }
    }

    fn measured_artifact() -> DeployedArtifactEvidence {
        DeployedArtifactEvidence {
            schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
            version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
            environment: "production-eu1".to_string(),
            version_scheme: ArtifactVersionScheme::InsprCalendarV1,
            artifact_version: "26.09.05.09.00.00".to_string(),
            release_channel: "stable".to_string(),
            release_sequence: 260_905_090_000,
            digest: format!("sha256:{}", "3".repeat(64)),
            digest_class: ArtifactDigestClass::OciManifest,
            commit_digest: "b".repeat(40),
            release_manifest_coordinate: "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00"
                .to_string(),
            release_manifest_digest: format!("sha256:{}", "4".repeat(64)),
            oci_index_digest: Some(format!("sha256:{}", "5".repeat(64))),
            oci_manifest_digest: Some(format!("sha256:{}", "3".repeat(64))),
            oci_config_digest: Some(format!("sha256:{}", "6".repeat(64))),
            observed_at: 1_700_000_000,
        }
    }

    #[test]
    fn calendar_versions_reject_non_gregorian_and_ambiguous_strings() {
        for valid in [
            "26.09.05",
            "26.09.05.09.00.00",
            "24.02.29",
            "00.01.01.00.00.00",
        ] {
            assert!(
                valid_inspr_calendar_version(valid),
                "{valid} must be a valid calendar coordinate"
            );
        }
        for invalid in [
            "2026.08.31",
            "26.8.31",
            "26.02.29",
            "26.04.31",
            "26.08.31.24.00.00",
            "26.08.31.12.60.00",
            "26.08.31.12.00",
            "1.2.3",
        ] {
            assert!(
                !valid_inspr_calendar_version(invalid),
                "{invalid} must fail closed"
            );
        }
    }

    #[test]
    fn calendar_v2_versions_are_exact_and_scheme_discriminated() {
        for value in [
            "260909194540.0.0",
            "261231235959.0.0",
            "280229120000.0.0",
            "100101000000.0.0",
        ] {
            assert!(valid_inspr_calendar_v2_version(value), "{value}");
            assert!(
                !valid_inspr_calendar_version(value),
                "{value} must not pass v1"
            );
            assert!(ArtifactVersionScheme::InsprCalendarV2.accepts_version(value));
            assert!(!ArtifactVersionScheme::InsprCalendarV1.accepts_version(value));
        }
        for value in [
            "26.09.09",
            "26.09.09.19.45.40",
            "2609091945.0.0",
            "20260909194540.0.0",
            "260909194540",
            "260909194540.0",
            "260909194540.0.1",
            "260909194540.1.0",
            "260909194540.0.0-rc1",
            "260909194540.0.0+g1",
            "090909194540.0.0",
            "260230194540.0.0",
            "260431194540.0.0",
            "260909240000.0.0",
            "260909196000.0.0",
            "260909194560.0.0",
            "260909194540.00.0",
            " 260909194540.0.0",
            "v260909194540.0.0",
            "٢٦0909194540.0.0",
        ] {
            assert!(!valid_inspr_calendar_v2_version(value), "{value}");
        }
        assert!(ArtifactVersionScheme::InsprCalendarV1.accepts_version("26.09.09.19.45.40"));
        assert!(!ArtifactVersionScheme::InsprCalendarV2.accepts_version("26.09.09.19.45.40"));
        assert_eq!(
            parse_measured_version_scheme("inspr-calendar-v2").unwrap(),
            ArtifactVersionScheme::InsprCalendarV2
        );
        assert_eq!(
            parse_measured_version_scheme("inspr-calver-3").unwrap(),
            ArtifactVersionScheme::InsprCalver3
        );
        assert!(ArtifactVersionScheme::InsprCalver3.accepts_version("260909194540.0.0"));
        assert!(!ArtifactVersionScheme::InsprCalver3.accepts_version("26.09.09.19.45.40"));
        assert_eq!(
            serde_json::to_string(&ArtifactVersionScheme::InsprCalver3).unwrap(),
            "\"inspr-calver-3\""
        );
        assert!(parse_measured_version_scheme("inspr-calendar-v3").is_err());
        assert_eq!(
            serde_json::to_string(&ArtifactVersionScheme::InsprCalendarV2).unwrap(),
            "\"inspr-calendar-v2\""
        );
    }

    #[test]
    fn deployed_artifact_preserves_distinct_oci_digest_classes() {
        let evidence = measured_artifact();
        evidence.validate_contract().unwrap();
        assert!(evidence.matches_expected(
            "production-eu1",
            ArtifactVersionScheme::InsprCalendarV1,
            "26.09.05.09.00.00",
            "stable",
            260_905_090_000,
            &format!("sha256:{}", "3".repeat(64)),
            &"b".repeat(40),
            "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00",
            &format!("sha256:{}", "4".repeat(64)),
        ));
        assert!(!evidence.matches_expected(
            "production-eu1",
            ArtifactVersionScheme::InsprCalendarV1,
            "26.09.05.09.00.00",
            "stable",
            260_905_090_000,
            evidence.oci_index_digest.as_deref().unwrap(),
            &"b".repeat(40),
            "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00",
            &format!("sha256:{}", "4".repeat(64)),
        ));
        let mut overlapped = evidence.clone();
        overlapped.oci_config_digest = overlapped.oci_manifest_digest.clone();
        assert!(overlapped.validate_contract().is_err());

        let encoded = serde_json::to_vec(&evidence).unwrap();
        let parsed = collect_deployed_artifact_from_metadata_file(&encoded).unwrap();
        assert_eq!(parsed.digest_class, ArtifactDigestClass::OciManifest);
        assert_ne!(parsed.oci_index_digest, parsed.oci_manifest_digest);
        assert_ne!(parsed.oci_manifest_digest, parsed.oci_config_digest);
    }

    fn approved_envelope(config_digest: &str) -> ApprovedReleaseEnvelope {
        ApprovedReleaseEnvelope {
            schema: APPROVED_RELEASE_ENVELOPE_SCHEMA.to_string(),
            version: APPROVED_RELEASE_ENVELOPE_VERSION,
            environment: "production-eu1".to_string(),
            version_scheme: ArtifactVersionScheme::InsprCalendarV1,
            artifact_version: "26.09.05.09.00.00".to_string(),
            release_channel: "stable".to_string(),
            release_sequence: 260_905_090_000,
            commit_digest: "b".repeat(40),
            release_manifest_coordinate: "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00"
                .to_string(),
            release_manifest_digest: format!("sha256:{}", "4".repeat(64)),
            oci_config_digest: config_digest.to_string(),
        }
    }

    fn filtered_container_line(running: &str, image: &str) -> String {
        let mut fields = vec![
            running.to_string(),
            format!("sha256:{}", "a".repeat(64)),
            image.to_string(),
        ];
        fields.resize(11, String::new());
        fields.join("\t")
    }

    #[test]
    fn running_container_measurement_binds_digest_locked_envelope() {
        let config = format!("sha256:{}", "3".repeat(64));
        let envelope = approved_envelope(&config);
        let observation = parse_running_container_format(&filtered_container_line("true", &config))
            .expect("filtered docker format");
        let evidence =
            evidence_from_running_container(&observation, &config, Some(&envelope), 1_700_000_100)
                .unwrap();
        assert!(evidence.is_config_class_measurement());
        assert_eq!(evidence.observed_at, 1_700_000_100);
        assert!(evidence.oci_index_digest.is_none());
        assert!(evidence.oci_manifest_digest.is_none());
        assert!(evidence.matches_expected(
            "production-eu1",
            ArtifactVersionScheme::InsprCalendarV1,
            "26.09.05.09.00.00",
            "stable",
            260_905_090_000,
            &config,
            &"b".repeat(40),
            "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00",
            &format!("sha256:{}", "4".repeat(64)),
        ));
        assert!(!evidence.matches_expected(
            "production-eu1",
            ArtifactVersionScheme::InsprCalendarV1,
            "26.09.05.09.00.00",
            "stable",
            260_905_090_000,
            &format!("sha256:{}", "5".repeat(64)),
            &"b".repeat(40),
            "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00",
            &format!("sha256:{}", "4".repeat(64)),
        ));
    }

    #[test]
    fn docker29_manifest_identity_requires_resolved_config_digest() {
        let config = format!("sha256:{}", "1".repeat(64));
        let manifest = format!("sha256:{}", "b".repeat(64));
        let envelope = approved_envelope(&config);
        let observation =
            parse_running_container_format(&filtered_container_line("true", &manifest)).unwrap();
        assert_eq!(observation.image_identity, manifest);
        assert!(
            evidence_from_running_container(
                &observation,
                &manifest,
                Some(&envelope),
                1_700_000_100
            )
            .is_err(),
            "a manifest identity must not be compared as a config digest"
        );
        let evidence =
            evidence_from_running_container(&observation, &config, Some(&envelope), 1_700_000_100)
                .unwrap();
        assert!(evidence.is_config_class_measurement());
        assert_eq!(evidence.digest, config);
        assert!(evidence.oci_manifest_digest.is_none());
    }

    #[test]
    fn running_container_mismatch_keeps_expected_metadata_unchanged() {
        let expected = format!("sha256:{}", "3".repeat(64));
        let running = format!("sha256:{}", "9".repeat(64));
        let envelope = approved_envelope(&expected);
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let parsed = parse_approved_release_envelope(&encoded).unwrap();
        assert_eq!(parsed, envelope);
        let observation =
            parse_running_container_format(&filtered_container_line("true", &running)).unwrap();
        assert_eq!(observation.image_identity, running);
        assert!(evidence_from_running_container(
            &observation,
            &running,
            Some(&envelope),
            1_700_000_100
        )
        .is_err());
        assert_eq!(envelope.oci_config_digest, expected);
        assert_eq!(envelope.artifact_version, "26.09.05.09.00.00");
    }

    #[test]
    fn running_container_fail_closed_cases() {
        let config = format!("sha256:{}", "3".repeat(64));
        let envelope = approved_envelope(&config);
        let stopped =
            parse_running_container_format(&filtered_container_line("false", &config)).unwrap();
        assert!(evidence_from_running_container(&stopped, &config, Some(&envelope), 1).is_err());
        assert!(parse_running_container_format("true\tonly-two-fields\n").is_err());
        assert!(parse_running_container_format(&format!(
            "true\tsha256:{}\tsha256:{}\nextra\n",
            "a".repeat(64),
            "3".repeat(64)
        ))
        .is_err());
        let mut with_timestamp = serde_json::to_value(&envelope).unwrap();
        with_timestamp["observed_at"] = serde_json::json!(1_700_000_100);
        assert!(
            parse_approved_release_envelope(&serde_json::to_vec(&with_timestamp).unwrap()).is_err()
        );
        assert!(parse_approved_release_envelope(b"{}").is_err());
        assert!(evidence_from_running_container(
            &parse_running_container_format(&filtered_container_line("true", &config)).unwrap(),
            &config,
            None,
            1
        )
        .is_err());
        assert!(valid_allowlisted_container_ref("pharos-prod"));
        assert!(!valid_allowlisted_container_ref("../etc/passwd"));
        assert!(!valid_allowlisted_container_ref("--privileged"));
        assert!(configured_container_matches_measurement(
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "a".repeat(64))
        ));
        assert!(!configured_container_matches_measurement(
            &format!("sha256:{}", "a".repeat(64)),
            &format!("sha256:{}", "b".repeat(64))
        ));
    }

    #[test]
    fn previous_host_report_must_not_carry_deployed_artifact_evidence() {
        // v5 is the last contract without deployed-artifact evidence; v6 (the
        // current predecessor since PHAROS-304) carries it.
        let mut report = HostReport {
            schema: HOST_REPORT_V5_SCHEMA.to_string(),
            version: HOST_REPORT_V5_VERSION,
            name: "hermes".to_string(),
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
            deployed_artifact: Some(measured_artifact()),
        };
        assert!(report.validate_contract().is_err());
        report.schema = HOST_REPORT_SCHEMA.to_string();
        report.version = HOST_REPORT_VERSION;
        report.validate_contract().unwrap();

        let mut v4 = report.clone();
        v4.schema = HOST_REPORT_V4_SCHEMA.to_string();
        v4.version = HOST_REPORT_V4_VERSION;
        assert!(v4.validate_contract().is_err());
        v4.deployed_artifact = None;
        v4.validate_contract().unwrap();
    }

    fn proven_current_freshness(channel: &str) -> NixFreshness {
        let evidence = test_deployment_evidence(channel);
        NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind: Some(0),
            nixpkgs_age_days: Some(0),
            nixpkgs_channel: Some(channel.to_string()),
            secondary_nixpkgs: None,
            deployment_evidence: Some(evidence.clone()),
            nixcfg_comparison: Some(NixcfgGitComparison {
                upstream_revision: evidence.source_revision.clone(),
                relation: GitRevisionRelation::Current,
                commits_behind: Some(0),
            }),
            nixpkgs_comparison: Some(NixpkgsGitComparison {
                upstream_revision: evidence.nixpkgs_revision.clone(),
                relation: NixpkgsRevisionRelation::Current,
            }),
        }
    }

    #[test]
    fn nixpkgs_threshold_resolution_and_wire_compatibility() {
        let mut preferences: HostPreferences = serde_json::from_str(
            r#"{"kind":"server","alerts":{"suppress_down":false,"suppress_backup":false,"suppress_nix_freshness":false}}"#,
        ).unwrap();
        assert_eq!(preferences.nixpkgs_warn_after_days(None), 30);
        assert_eq!(preferences.nixpkgs_warn_after_days(Some(45)), 45);
        assert!(!serde_json::to_string(&preferences)
            .unwrap()
            .contains("nixpkgs_warn_after_days"));
        preferences.alerts.nixpkgs_warn_after_days = Some(7);
        assert_eq!(preferences.nixpkgs_warn_after_days(Some(45)), 7);
        assert_eq!(
            serde_json::from_str::<HostPreferences>(&serde_json::to_string(&preferences).unwrap())
                .unwrap(),
            preferences
        );
        for days in [1, 30, 3650] {
            preferences.alerts.nixpkgs_warn_after_days = Some(days);
            assert!(preferences.validate_contract().is_ok());
        }
        for days in [0, 3651, u32::MAX] {
            preferences.alerts.nixpkgs_warn_after_days = Some(days);
            assert!(preferences.validate_contract().is_err());
        }
        for invalid in ["-1", "1.5", "\"30\""] {
            let raw = format!(r#"{{"alerts":{{"nixpkgs_warn_after_days":{invalid}}}}}"#);
            assert!(serde_json::from_str::<HostPreferences>(&raw).is_err());
        }
    }

    #[test]
    fn heartbeat_grace_inherits_overrides_and_stays_off_old_wires() {
        let mut preferences: HostPreferences = serde_json::from_str(
            r#"{"kind":"server","alerts":{"suppress_down":false,"suppress_backup":false,"suppress_nix_freshness":false}}"#,
        )
        .unwrap();
        assert_eq!(preferences.alerts.heartbeat_grace_secs, None);
        assert_eq!(preferences.heartbeat_grace_secs(None), 15);
        assert_eq!(preferences.heartbeat_grace_secs(Some(40)), 40);
        let inherited = preferences.heartbeat_grace_policy(Some(40), Some(60));
        assert_eq!(inherited.source, HeartbeatGraceSource::Fleet);
        assert_eq!(inherited.override_secs, None);
        assert_eq!(inherited.fleet_secs, 40);
        assert_eq!(inherited.effective_secs, 40);
        assert_eq!(inherited.late_after_secs, 100);
        assert_eq!(inherited.on_time_through_secs, 100);
        assert!(!serde_json::to_string(&preferences)
            .unwrap()
            .contains("heartbeat_grace_secs"));

        preferences.alerts.heartbeat_grace_secs = Some(0);
        assert_eq!(preferences.heartbeat_grace_secs(Some(40)), 0);
        assert_eq!(
            preferences
                .heartbeat_grace_policy(Some(40), Some(60))
                .source,
            HeartbeatGraceSource::Host
        );
        let wire = serde_json::to_string(&preferences).unwrap();
        assert!(wire.contains("\"heartbeat_grace_secs\":0"));
        assert_eq!(
            serde_json::from_str::<HostPreferences>(&wire).unwrap(),
            preferences
        );

        let cleared: HostPreferences = serde_json::from_str(
            r#"{"alerts":{"heartbeat_grace_secs":null,"suppress_down":false}}"#,
        )
        .unwrap();
        assert_eq!(cleared.alerts.heartbeat_grace_secs, None);
        assert_eq!(
            cleared.heartbeat_grace_policy(Some(40), None).source,
            HeartbeatGraceSource::Fleet
        );

        for secs in [0, 15, 3600] {
            preferences.alerts.heartbeat_grace_secs = Some(secs);
            assert!(preferences.validate_contract().is_ok(), "{secs}");
        }
        preferences.alerts.heartbeat_grace_secs = Some(3601);
        assert_eq!(
            preferences.validate_contract(),
            Err(HEARTBEAT_GRACE_RANGE_ERROR.to_string())
        );
        assert!(HEARTBEAT_GRACE_RANGE_ERROR.contains(&MAX_HEARTBEAT_GRACE_SECS.to_string()));
        preferences.alerts.heartbeat_grace_secs = Some(u64::MAX);
        assert!(preferences.validate_contract().is_err());
        // A corrupt override does not become the effective policy.
        assert_eq!(preferences.heartbeat_grace_secs(Some(40)), 40);

        for invalid in ["-1", "1.5", "\"15\""] {
            let raw = format!(r#"{{"alerts":{{"heartbeat_grace_secs":{invalid}}}}}"#);
            assert!(serde_json::from_str::<HostPreferences>(&raw).is_err());
        }
    }

    #[test]
    fn nixpkgs_age_warning_uses_strict_server_clock_boundary_and_requires_proof() {
        let mut freshness = proven_current_freshness("nixos-unstable");
        let modified = freshness
            .deployment_evidence
            .as_ref()
            .unwrap()
            .nixpkgs_last_modified;
        freshness.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "4".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        // A fresh host-clock mirror must not hide the actual deployed age.
        freshness.nixpkgs_age_days = Some(0);
        for age in [0, 29, 30] {
            assert!(!freshness.nixpkgs_age_warning_at(modified + age * 86_400, 30));
        }
        assert!(!freshness.nixpkgs_age_warning_at(modified + 31 * 86_400 - 1, 30));
        assert!(freshness.nixpkgs_age_warning_at(modified + 31 * 86_400, 30));
        assert!(freshness.nixpkgs_age_warning_at(modified + 8 * 86_400, 7));
        assert!(!freshness.nixpkgs_age_warning_at(modified - 1, 30));
        assert!(!freshness.nixpkgs_age_warning_at(i64::MAX, 30));
        // A channel tip is an age-warning input, not a locked deployable update.
        assert!(!freshness.has_proven_deployable_update());
        assert!(freshness.tldr().contains("nixpkgs differs"));
        let now = modified + 31 * 86_400;
        freshness.nixpkgs_comparison.as_mut().unwrap().relation = NixpkgsRevisionRelation::Current;
        assert!(!freshness.nixpkgs_age_warning_at(now, 30));
        freshness.nixpkgs_comparison = None;
        assert!(!freshness.nixpkgs_age_warning_at(now, 30));
        freshness.deployment_evidence = None;
        freshness.nixpkgs_age_days = Some(100);
        assert!(!freshness.nixpkgs_age_warning_at(now, 30));
        freshness.nixpkgs_age_days = None;
        assert!(!freshness.nixpkgs_age_warning_at(now, 30));
    }

    #[test]
    fn proven_deployable_update_requires_nixcfg_commits_not_a_channel_tip() {
        let mut channel_only = proven_current_freshness("nixos-unstable");
        channel_only.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "4".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        assert!(!channel_only.has_proven_deployable_update());

        let mut behind = proven_current_freshness("nixos-unstable");
        behind.nixcfg_comparison = Some(NixcfgGitComparison {
            upstream_revision: "5".repeat(40),
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(3),
        });
        behind.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "4".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        assert!(behind.has_proven_deployable_update());

        behind.nixcfg_comparison.as_mut().unwrap().commits_behind = Some(0);
        assert!(!behind.has_proven_deployable_update());
        behind.nixcfg_comparison.as_mut().unwrap().commits_behind = None;
        assert!(!behind.has_proven_deployable_update());
        assert!(!NixFreshness::default().has_proven_deployable_update());
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
        assert_eq!(fresh.tldr(), "freshness unverified");

        let mut behind = proven_current_freshness("nixos-unstable");
        behind.commits_behind = Some(3);
        behind.nixcfg_comparison = Some(NixcfgGitComparison {
            upstream_revision: "4".repeat(40),
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(3),
        });
        assert_eq!(behind.tldr(), "3 commits behind nixcfg");
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
            "name": "hermes",
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
            "name": "hermes",
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
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
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
            deployed_artifact: None,
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
                last_success_at: None,
                restored_files: Some(1),
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
                "demeter": {
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
            registry.preferences_for("demeter").map(|value| value.kind),
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
    fn selective_restore_history_is_v7_only_and_legacy_records_still_load() {
        let legacy: BackupValidationObservation = serde_json::from_value(serde_json::json!({
            "level": "restore-sample",
            "state": "passed",
            "checked_at": 1_699_980_000
        }))
        .expect("legacy validation record deserializes");
        assert_eq!(legacy.last_success_at, None);
        assert_eq!(legacy.restored_files, None);
        legacy.validate_contract().expect("legacy record validates");

        let retained = BackupValidationObservation {
            level: BackupValidationLevel::RestoreSample,
            state: BackupValidationState::Failed,
            checked_at: Some(1_700_000_000),
            evidence_label: None,
            summary: None,
            last_success_at: Some(1_699_000_000),
            restored_files: Some(3),
        };
        retained
            .validate_contract()
            .expect("retained history validates");
        let encoded = serde_json::to_value(&retained).expect("serializes");
        assert_eq!(encoded["last_success_at"], 1_699_000_000);
        assert_eq!(encoded["restored_files"], 3);
        assert!(BackupValidationObservation {
            last_success_at: Some(0),
            ..retained.clone()
        }
        .validate_contract()
        .is_err());

        let mut observation = BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: BackupEngine::Restic,
            state: BackupPostureState::Healthy,
            configured: BackupConfiguredState::Enabled,
            summary: "last backup succeeded".to_string(),
            target_label: None,
            repository_id: None,
            schedule: Some("daily".to_string()),
            next_run_at: None,
            last_attempt_at: Some(1_700_000_000),
            last_attempt_state: Some(BackupRunState::Succeeded),
            last_success_at: Some(1_700_000_000),
            snapshot_count: None,
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: Some(retained.clone()),
        };
        let mut report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: "hermes".to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            kernel: None,
            service_observations: Vec::new(),
            backup_observations: vec![observation.clone()],
            inbound_rtt_ms: None,
            location: None,
            preferences: HostPreferences::default(),
            deployed_artifact: None,
        };
        report
            .validate_contract()
            .expect("v7 carries restore history");
        for (schema, version) in [
            (HOST_REPORT_V4_SCHEMA, HOST_REPORT_V4_VERSION),
            (HOST_REPORT_V5_SCHEMA, HOST_REPORT_V5_VERSION),
            (HOST_REPORT_V6_SCHEMA, HOST_REPORT_V6_VERSION),
        ] {
            report.schema = schema.to_string();
            report.version = version;
            assert!(
                report.validate_contract().is_err(),
                "{schema} must refuse v7 restore history"
            );
        }
        observation.restore_validation = Some(legacy);
        report.backup_observations = vec![observation];
        report
            .validate_contract()
            .expect("v6 without restore history stays valid");
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
                last_success_at: Some(1_699_980_000),
                restored_files: Some(1),
            }),
        };
        observation
            .validate_contract()
            .expect("sanitized observation validates");

        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: "hermes".to_string(),
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
            deployed_artifact: None,
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
        let unverified = ServiceObservation::nix_freshness(&NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(2),
            commits_behind: Some(0),
            nixpkgs_age_days: None,
            nixpkgs_channel: None,
            secondary_nixpkgs: None,
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
        });
        assert_eq!(unverified.id, "nix-freshness");
        assert_eq!(unverified.state, ServiceObservationState::Unknown);
        assert_eq!(unverified.summary, "active-generation freshness unverified");

        let healthy =
            ServiceObservation::nix_freshness(&proven_current_freshness("nixos-unstable"));
        assert_eq!(healthy.state, ServiceObservationState::Healthy);
    }

    #[test]
    fn manifest_contract_accepts_nixcfg_v1_shape() {
        let manifest: HostManifest = serde_json::from_value(serde_json::json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "generatedBy": "nixcfg",
            "slug": "hermes",
            "storageKey": "hostdash.hermes",
            "host": {
                "name": "hermes",
                "role": "parents' home",
                "os": "NixOS",
                "fqdn": "hermes.lan",
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
                    "lanHostname": "hermes.lan",
                    "lanIp": "192.168.1.100",
                    "tailnet": "hermes"
                }
            },
            "palette": {
                "name": "custom-hermes",
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
                    "url": "http://hermes.lan:8123/",
                    "urls": {
                        "lanHostname": "http://hermes.lan:8123/",
                        "lanIp": "http://192.168.1.100:8123/",
                        "tailnet": "http://hermes:8123/"
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
        assert_eq!(manifest.host.lan_hostname(), Some("hermes.lan"));
        assert_eq!(manifest.host.lan_ip(), Some("192.168.1.100"));
        assert_eq!(manifest.host.tailnet_hostname(), Some("hermes"));
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
            "slug": "hermes",
            "host": { "name": "hermes" },
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
            "slug": "hermes",
            "host": {
                "name": "hermes",
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
            "slug": "hermes",
            "host": {
                "name": "hermes",
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
            "slug": "hermes",
            "host": {
                "name": "hermes",
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
            "slug": "hermes",
            "host": {
                "name": "hermes",
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

    #[test]
    fn nix_channel_state_follows_the_release_support_window() {
        // nixos-25.05 went end of life at the start of 2026, which is the case
        // that produced this ticket.
        assert_eq!(
            nix_channel_state("nixos-25.05", 2025, 12),
            NixChannelState::Supported
        );
        assert_eq!(
            nix_channel_state("nixos-25.05", 2026, 1),
            NixChannelState::EndOfLife
        );
        // A November release is supported roughly a month past the next May.
        assert_eq!(
            nix_channel_state("nixos-25.11", 2026, 6),
            NixChannelState::Supported
        );
        assert_eq!(
            nix_channel_state("nixos-25.11", 2026, 7),
            NixChannelState::EndOfLife
        );
        // The current release is not flagged.
        assert_eq!(
            nix_channel_state("nixos-26.05", 2026, 8),
            NixChannelState::Supported
        );
        // Rolling and unparseable channels are never flagged as expired.
        for rolling in [
            "nixos-unstable",
            "nixpkgs-unstable",
            "master",
            "nixos-",
            "nixos-25",
            "nixos-25.13",
            "nixos-2025.05",
            "",
        ] {
            assert_eq!(
                nix_channel_state(rolling, 2026, 8),
                NixChannelState::Rolling,
                "{rolling} should not be classified as a dated release"
            );
        }
    }

    #[test]
    fn valid_nix_channel_rejects_unbounded_or_unsafe_names() {
        assert!(valid_nix_channel("nixos-25.05"));
        assert!(valid_nix_channel("nixos-unstable"));
        assert!(!valid_nix_channel(""));
        assert!(!valid_nix_channel(&"n".repeat(MAX_NIX_CHANNEL_BYTES + 1)));
        for bad in [
            "nixos 25.05",
            "nixos-25.05/../etc",
            "a?b",
            "https://x",
            "a\nb",
        ] {
            assert!(!valid_nix_channel(bad), "{bad} must be rejected");
        }
    }

    #[test]
    fn deployment_evidence_requires_canonical_lowercase_digests() {
        let mut evidence = test_deployment_evidence("nixos-unstable");
        evidence.source_revision = "A".repeat(40);
        assert!(evidence.validate_contract().is_err());

        let mut evidence = test_deployment_evidence("nixos-unstable");
        evidence.flake_lock_sha256 = "B".repeat(64);
        assert!(evidence.validate_contract().is_err());

        let mut evidence = test_deployment_evidence("nixos-unstable");
        evidence.nixpkgs_revision = "C".repeat(40);
        assert!(evidence.validate_contract().is_err());
    }

    #[test]
    fn freshness_reports_nixpkgs_rather_than_the_newest_input() {
        // A host whose *system* nixpkgs is frozen on an expired release while a
        // trivial input moved today, so the lock age alone reads as fresh.
        // PHAROS-196: which input produces these numbers is the beacon's job;
        // here the contract only has to escalate correctly once they arrive.
        let mut freshness = proven_current_freshness("nixos-25.05");
        freshness.nixpkgs_age_days = Some(218);
        freshness.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "4".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        freshness.validate_contract().expect("valid freshness");
        assert!(
            freshness
                .tldr()
                .contains("nixpkgs differs from nixos-25.05"),
            "tldr was {}",
            freshness.tldr()
        );
        assert_eq!(
            freshness.channel_state(2026, 8),
            Some(NixChannelState::EndOfLife)
        );

        // Without a calendar the observation still warns rather than claiming health.
        let unclassified = ServiceObservation::nix_freshness(&freshness);
        assert_eq!(unclassified.state, ServiceObservationState::Warning);

        // With one, an expired channel outranks the reassuring 0d lock age.
        let classified = ServiceObservation::nix_freshness_at(&freshness, Some((2026, 8)));
        assert_eq!(classified.state, ServiceObservationState::Stale);
        assert!(classified.summary.contains("end of life"));
    }

    #[test]
    fn freshness_stays_healthy_when_nixpkgs_is_current() {
        let freshness = proven_current_freshness("nixos-26.05");
        freshness.validate_contract().expect("valid freshness");
        assert_eq!(freshness.tldr(), "up to date");
        assert_eq!(
            ServiceObservation::nix_freshness_at(&freshness, Some((2026, 8))).state,
            ServiceObservationState::Healthy
        );
    }

    #[test]
    fn freshness_rejects_unbounded_or_non_nix_nixpkgs_values() {
        let over_bound = NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind: Some(0),
            nixpkgs_age_days: Some(MAX_FLAKE_LOCK_AGE_DAYS + 1),
            nixpkgs_channel: None,
            secondary_nixpkgs: None,
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
        };
        assert!(over_bound.validate_contract().is_err());

        let bad_channel = NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind: Some(0),
            nixpkgs_age_days: Some(1),
            nixpkgs_channel: Some("nixos 25.05".to_string()),
            secondary_nixpkgs: None,
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
        };
        assert!(bad_channel.validate_contract().is_err());

        let non_nix = NixFreshness {
            applicable: false,
            flake_lock_age_days: None,
            commits_behind: None,
            nixpkgs_age_days: Some(1),
            nixpkgs_channel: None,
            secondary_nixpkgs: None,
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
        };
        assert!(non_nix.validate_contract().is_err());
    }

    #[test]
    fn previous_contract_reports_without_secondary_nixpkgs_are_still_accepted() {
        // A v4 beacon that has not rolled yet must keep reporting. PHAROS-202
        // added exact evidence, and the rollout order is control plane first.
        let report: HostReport = serde_json::from_value(serde_json::json!({
            "schema": HOST_REPORT_V4_SCHEMA,
            "version": HOST_REPORT_V4_VERSION,
            "name": "hermes",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {"applicable": true, "flake_lock_age_days": 3, "commits_behind": 0}
        }))
        .expect("a v4 report still deserializes");
        report.validate_contract().expect("v4 remains valid");
        assert_eq!(report.freshness.nixpkgs_age_days, None);
        assert_eq!(report.freshness.nixpkgs_channel, None);
        assert_eq!(report.freshness.secondary_nixpkgs, None);
        // It degrades honestly rather than claiming nixpkgs is fresh.
        assert_eq!(report.freshness.channel_state(2026, 8), None);
        assert_eq!(report.freshness.tldr(), "freshness unverified");
    }

    #[test]
    fn secondary_nixpkgs_is_bounded_and_v4_cannot_forge_v5_evidence() {
        let secondary = NixpkgsInputFreshness {
            input: "nixpkgs-stable".to_string(),
            age_days: 218,
            channel: Some("nixos-25.05".to_string()),
        };
        secondary.validate_contract().expect("bounded context");

        let invalid_name = NixpkgsInputFreshness {
            input: "../nixpkgs?token=value".to_string(),
            ..secondary.clone()
        };
        assert!(invalid_name.validate_contract().is_err());
        let unrelated_name = NixpkgsInputFreshness {
            input: "disko".to_string(),
            ..secondary.clone()
        };
        assert!(unrelated_name.validate_contract().is_err());
        let primary_name = NixpkgsInputFreshness {
            input: "nixpkgs".to_string(),
            ..secondary.clone()
        };
        assert!(primary_name.validate_contract().is_err());
        let invalid_age = NixpkgsInputFreshness {
            age_days: MAX_FLAKE_LOCK_AGE_DAYS + 1,
            ..secondary.clone()
        };
        assert!(invalid_age.validate_contract().is_err());

        let secondary_without_primary = NixFreshness {
            applicable: true,
            secondary_nixpkgs: Some(secondary.clone()),
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
            ..Default::default()
        };
        assert!(secondary_without_primary.validate_contract().is_err());

        let previous: HostReport = serde_json::from_value(serde_json::json!({
            "schema": HOST_REPORT_V4_SCHEMA,
            "version": HOST_REPORT_V4_VERSION,
            "name": "hermes",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {
                "applicable": true,
                "flake_lock_age_days": 0,
                "commits_behind": 0,
                "nixpkgs_age_days": 0,
                "nixpkgs_channel": "nixos-unstable",
                "secondary_nixpkgs": secondary
            }
        }))
        .expect("shared type can decode for version-aware validation");
        previous
            .validate_contract()
            .expect("secondary nixpkgs is valid in predecessor v4");

        let mut forged = previous;
        forged.freshness = proven_current_freshness("nixos-unstable");
        assert!(forged.validate_contract().is_err());

        let mut v5 = forged.clone();
        v5.schema = HOST_REPORT_V5_SCHEMA.to_string();
        v5.version = HOST_REPORT_V5_VERSION;
        v5.validate_contract()
            .expect("v5 may carry current generation freshness");
        v5.deployed_artifact = Some(measured_artifact());
        assert!(v5.validate_contract().is_err());

        let mut v6 = v5.clone();
        v6.schema = HOST_REPORT_SCHEMA.to_string();
        v6.version = HOST_REPORT_VERSION;
        v6.validate_contract()
            .expect("v6 accepts valid current freshness and deployed-artifact evidence");

        let v2: HostReport = serde_json::from_value(serde_json::json!({
            "schema": "inspr.pharos.host-report.v2",
            "version": 2,
            "name": "hermes",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
            "freshness": {"applicable": true, "flake_lock_age_days": 0, "commits_behind": 0}
        }))
        .expect("old shape still decodes before contract validation");
        assert!(v2.validate_contract().is_err());
    }
}
