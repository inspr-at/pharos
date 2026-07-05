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

/// A managed host as seen by the dashboard.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Host {
    pub name: String,
    pub role: String,
    pub is_nix: bool,
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
    pub freshness: NixFreshness,
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

/// What a `pharos-beacon` sends to `pharosd` (PHAROS-9 ingestion). The server
/// adds the receive timestamp; the agent never sends its own liveness.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct HostReport {
    pub name: String,
    pub role: String,
    pub is_nix: bool,
    pub heartbeat_interval_secs: u64,
    pub freshness: NixFreshness,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
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
        assert!(host.heartbeat_log.is_empty());
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
    }
}
