use std::cmp::Ordering;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering as AtomicOrdering};
use std::sync::RwLock;
use std::time::Duration;

use reqwest::StatusCode;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use url::Url;

const STORE_SCHEMA: &str = "inspr.pharos.provider-connection-state.v1";
const STORE_VERSION: u16 = 1;
const MAX_RESPONSE_BYTES: usize = 2 * 1024 * 1024;
const MAX_PAGES: u32 = 10;
const PAGE_SIZE: u32 = 50;
static PERSIST_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub(crate) struct HetznerConnectionPreferences {
    pub(crate) default_location: Option<String>,
    pub(crate) ssh_key_ref: Option<String>,
    pub(crate) firewall_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum HetznerConnectionCode {
    Ready,
    CredentialUnavailable,
    CredentialBoundaryRequired,
    ExecutionDisabled,
    Unauthorized,
    Forbidden,
    RateLimited,
    ProviderUnavailable,
    RequestFailed,
    InvalidResponse,
    SshKeyRequired,
    SshKeyMissing,
    FirewallRequired,
    FirewallMissing,
    DefaultLocationRequired,
    DefaultLocationUnavailable,
    CatalogUnavailable,
    Disconnected,
}

impl HetznerConnectionCode {
    pub(crate) fn safe_message(self) -> &'static str {
        match self {
            Self::Ready => "Provider connection, SSH key, firewall, region, and prices are ready.",
            Self::CredentialUnavailable => {
                "The secure Hetzner Cloud credential is not available to Pharos."
            }
            Self::CredentialBoundaryRequired => {
                "The connection works, but the credential must be mounted through Janus and agenix."
            }
            Self::ExecutionDisabled => {
                "The connection works, but managed server creation is disabled on this Pharos installation."
            }
            Self::Unauthorized => {
                "Hetzner Cloud did not accept the configured credential. No resources were changed."
            }
            Self::Forbidden => {
                "Hetzner Cloud denied a required read-only check. No resources were changed."
            }
            Self::RateLimited => {
                "Hetzner Cloud temporarily limited the connection test. Try again later."
            }
            Self::ProviderUnavailable => {
                "Hetzner Cloud is temporarily unavailable. No resources were changed."
            }
            Self::RequestFailed => {
                "The Hetzner Cloud connection test did not complete. No resources were changed."
            }
            Self::InvalidResponse => {
                "Hetzner Cloud returned an unexpected response. No resources were changed."
            }
            Self::SshKeyRequired => "Choose the SSH public key Pharos should use.",
            Self::SshKeyMissing => {
                "The selected SSH public key is no longer available in Hetzner Cloud."
            }
            Self::FirewallRequired => "Choose the reviewed firewall Pharos should use.",
            Self::FirewallMissing => {
                "The selected firewall is no longer available in Hetzner Cloud."
            }
            Self::DefaultLocationRequired => "Choose the default server location.",
            Self::DefaultLocationUnavailable => {
                "The selected location has no currently available, priced server plan."
            }
            Self::CatalogUnavailable => {
                "Current Hetzner Cloud locations, server plans, or prices could not be verified."
            }
            Self::Disconnected => {
                "Hetzner Cloud is disconnected in Pharos. The encrypted credential remains in Janus."
            }
        }
    }

    fn from_status(status: StatusCode) -> Self {
        match status {
            StatusCode::UNAUTHORIZED => Self::Unauthorized,
            StatusCode::FORBIDDEN => Self::Forbidden,
            StatusCode::TOO_MANY_REQUESTS => Self::RateLimited,
            status if status.is_server_error() => Self::ProviderUnavailable,
            _ => Self::RequestFailed,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HetznerConnectionAttempt {
    pub(crate) tested_at: i64,
    pub(crate) code: HetznerConnectionCode,
    pub(crate) api_access: bool,
    pub(crate) credential_boundary_ready: bool,
    pub(crate) execution_enabled: bool,
    pub(crate) ssh_key_ready: bool,
    pub(crate) firewall_ready: bool,
    pub(crate) default_location_ready: bool,
    pub(crate) catalog_ready: bool,
}

impl HetznerConnectionAttempt {
    pub(crate) fn ready(&self) -> bool {
        self.code == HetznerConnectionCode::Ready
            && self.api_access
            && self.credential_boundary_ready
            && self.execution_enabled
            && self.ssh_key_ready
            && self.firewall_ready
            && self.default_location_ready
            && self.catalog_ready
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HetznerLocation {
    pub(crate) name: String,
    pub(crate) city: String,
    pub(crate) country: String,
    pub(crate) network_zone: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HetznerServerTypeLocation {
    pub(crate) name: String,
    pub(crate) available: bool,
    pub(crate) recommended: bool,
    pub(crate) monthly_gross: Option<String>,
    pub(crate) hourly_gross: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HetznerServerType {
    pub(crate) name: String,
    pub(crate) description: String,
    pub(crate) category: String,
    pub(crate) cores: u32,
    pub(crate) memory_gb: String,
    pub(crate) disk_gb: u32,
    pub(crate) architecture: String,
    pub(crate) locations: Vec<HetznerServerTypeLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HetznerCatalog {
    pub(crate) refreshed_at: i64,
    pub(crate) currency: String,
    pub(crate) locations: Vec<HetznerLocation>,
    pub(crate) server_types: Vec<HetznerServerType>,
    pub(crate) ssh_keys: Vec<String>,
    pub(crate) firewalls: Vec<String>,
}

/// Safe, immutable catalog facts for one exact location/server-type choice.
/// Prices are canonical fixed-point decimal strings so callers can persist and
/// hash them without depending on floating-point formatting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HetznerCatalogSelection {
    pub(crate) catalog_refreshed_at: i64,
    pub(crate) location: String,
    pub(crate) location_label: String,
    pub(crate) server_type: String,
    pub(crate) server_type_label: String,
    pub(crate) hardware_summary: String,
    pub(crate) currency: String,
    pub(crate) hourly_gross: String,
    pub(crate) monthly_gross: String,
}

impl HetznerCatalog {
    pub(crate) fn supports_location(&self, location: &str) -> bool {
        self.locations.iter().any(|item| item.name == location)
            && self.server_types.iter().any(|server_type| {
                server_type.locations.iter().any(|item| {
                    item.name == location && item.available && item.monthly_gross.is_some()
                })
            })
    }

    pub(crate) fn supports_plan(&self, location: &str, server_type: &str) -> bool {
        self.server_types.iter().any(|item| {
            item.name == server_type
                && item.locations.iter().any(|availability| {
                    availability.name == location
                        && availability.available
                        && availability.monthly_gross.is_some()
                })
        })
    }

    pub(crate) fn recommended_plan(&self, location: &str) -> Option<&HetznerServerType> {
        let mut candidates = self
            .server_types
            .iter()
            .filter(|server_type| server_type.architecture == "x86")
            .filter(|server_type| server_type.cores >= 2 && memory_gb(server_type) >= 4.0)
            .filter(|server_type| self.supports_plan(location, &server_type.name))
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            let price_order = match (
                monthly_price(left, location),
                monthly_price(right, location),
            ) {
                (Some(left), Some(right)) => {
                    compare_gross_prices(left, right).unwrap_or(Ordering::Equal)
                }
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (None, None) => Ordering::Equal,
            };
            price_order.then_with(|| left.name.cmp(&right.name))
        });
        candidates.into_iter().next()
    }

    pub(crate) fn exact_selection(
        &self,
        location: &str,
        server_type: &str,
    ) -> Option<HetznerCatalogSelection> {
        let location_record = self.locations.iter().find(|item| item.name == location)?;
        let server_type_record = self
            .server_types
            .iter()
            .find(|item| item.name == server_type)?;
        let availability = server_type_record
            .locations
            .iter()
            .find(|item| item.name == location && item.available)?;
        let hourly_gross = normalize_gross_price(availability.hourly_gross.as_deref()?)?;
        let monthly_gross = normalize_gross_price(availability.monthly_gross.as_deref()?)?;

        Some(HetznerCatalogSelection {
            catalog_refreshed_at: self.refreshed_at,
            location: location_record.name.clone(),
            location_label: format!(
                "{}, {} ({})",
                location_record.city, location_record.country, location_record.name
            ),
            server_type: server_type_record.name.clone(),
            server_type_label: format!(
                "{} ({})",
                server_type_record.description, server_type_record.name
            ),
            hardware_summary: format!(
                "{} vCPU · {} GB RAM · {} GB disk · {}",
                server_type_record.cores,
                server_type_record.memory_gb,
                server_type_record.disk_gb,
                server_type_record.architecture
            ),
            currency: self.currency.clone(),
            hourly_gross,
            monthly_gross,
        })
    }
}

fn memory_gb(server_type: &HetznerServerType) -> f64 {
    server_type.memory_gb.parse::<f64>().unwrap_or(0.0)
}

fn monthly_price<'a>(server_type: &'a HetznerServerType, location: &str) -> Option<&'a str> {
    server_type
        .locations
        .iter()
        .find(|item| item.name == location && item.available)
        .and_then(|item| item.monthly_gross.as_deref())
}

/// Canonicalize a non-negative fixed-point gross price without floating-point
/// parsing. The accepted grammar is `DIGITS` or `DIGITS.DIGITS`; signs,
/// exponents, whitespace, separators, and empty integer/fraction parts fail
/// closed. Leading integer zeroes and trailing fractional zeroes are removed.
pub(crate) fn normalize_gross_price(value: &str) -> Option<String> {
    if value.is_empty()
        || value.len() > 32
        || value.trim() != value
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }

    let mut parts = value.split('.');
    let integer = parts.next()?;
    let fraction = parts.next();
    if integer.is_empty()
        || parts.next().is_some()
        || fraction.is_some_and(str::is_empty)
        || !integer.bytes().all(|byte| byte.is_ascii_digit())
        || fraction.is_some_and(|part| !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return None;
    }

    let integer = integer.trim_start_matches('0');
    let integer = if integer.is_empty() { "0" } else { integer };
    let fraction = fraction.unwrap_or_default().trim_end_matches('0');
    if fraction.is_empty() {
        Some(integer.to_string())
    } else {
        Some(format!("{integer}.{fraction}"))
    }
}

/// Compare two strict fixed-point gross prices exactly. Invalid inputs return
/// `None`; valid values are compared without a bounded integer conversion.
pub(crate) fn compare_gross_prices(left: &str, right: &str) -> Option<Ordering> {
    let left = normalize_gross_price(left)?;
    let right = normalize_gross_price(right)?;
    let (left_integer, left_fraction) = left.split_once('.').unwrap_or((&left, ""));
    let (right_integer, right_fraction) = right.split_once('.').unwrap_or((&right, ""));

    let integer_order = left_integer
        .len()
        .cmp(&right_integer.len())
        .then_with(|| left_integer.cmp(right_integer));
    if integer_order != Ordering::Equal {
        return Some(integer_order);
    }

    let width = left_fraction.len().max(right_fraction.len());
    for index in 0..width {
        let left_digit = left_fraction.as_bytes().get(index).copied().unwrap_or(b'0');
        let right_digit = right_fraction
            .as_bytes()
            .get(index)
            .copied()
            .unwrap_or(b'0');
        match left_digit.cmp(&right_digit) {
            Ordering::Equal => {}
            ordering => return Some(ordering),
        }
    }
    Some(Ordering::Equal)
}

#[derive(Debug, Clone)]
pub(crate) struct HetznerConnectionTestResult {
    pub(crate) attempt: HetznerConnectionAttempt,
    pub(crate) catalog: Option<HetznerCatalog>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
struct HetznerConnectionRecord {
    preferences: HetznerConnectionPreferences,
    last_attempt: Option<HetznerConnectionAttempt>,
    catalog: Option<HetznerCatalog>,
    disconnected_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ProviderConnectionStateFile {
    schema: String,
    version: u16,
    hetzner_cloud: HetznerConnectionRecord,
}

impl Default for ProviderConnectionStateFile {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            version: STORE_VERSION,
            hetzner_cloud: HetznerConnectionRecord::default(),
        }
    }
}

pub(crate) struct ProviderConnectionStore {
    path: Option<PathBuf>,
    state: RwLock<ProviderConnectionStateFile>,
}

impl ProviderConnectionStore {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        let state = path
            .as_ref()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice::<ProviderConnectionStateFile>(&bytes).ok())
            .filter(|state| state.schema == STORE_SCHEMA && state.version == STORE_VERSION)
            .unwrap_or_default();
        Self {
            path,
            state: RwLock::new(state),
        }
    }

    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        if let Ok(path) = std::env::var("PHAROS_PROVIDER_CONNECTIONS_DB") {
            let path = path.trim();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
        let host_store_path = host_store_path?;
        let file_name = host_store_path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.trim().is_empty())
            .unwrap_or("pharos.json");
        Some(host_store_path.with_file_name(format!("{file_name}.provider-connections.json")))
    }

    pub(crate) fn preferences(&self) -> HetznerConnectionPreferences {
        self.state
            .read()
            .expect("provider connection store lock")
            .hetzner_cloud
            .preferences
            .clone()
    }

    pub(crate) fn last_attempt(&self) -> Option<HetznerConnectionAttempt> {
        self.state
            .read()
            .expect("provider connection store lock")
            .hetzner_cloud
            .last_attempt
            .clone()
    }

    pub(crate) fn catalog(&self) -> Option<HetznerCatalog> {
        self.state
            .read()
            .expect("provider connection store lock")
            .hetzner_cloud
            .catalog
            .clone()
    }

    pub(crate) fn disconnected_at(&self) -> Option<i64> {
        self.state
            .read()
            .expect("provider connection store lock")
            .hetzner_cloud
            .disconnected_at
    }

    pub(crate) fn record_test(&self, result: HetznerConnectionTestResult) {
        {
            let mut state = self.state.write().expect("provider connection store lock");
            if result.attempt.api_access {
                state.hetzner_cloud.disconnected_at = None;
            }
            if let Some(catalog) = result.catalog {
                state.hetzner_cloud.catalog = Some(catalog);
            }
            state.hetzner_cloud.last_attempt = Some(result.attempt);
        }
        self.persist();
    }

    pub(crate) fn update_preferences(
        &self,
        preferences: HetznerConnectionPreferences,
        now: i64,
        ttl_secs: i64,
    ) -> Result<(), HetznerPreferenceError> {
        let mut state = self.state.write().expect("provider connection store lock");
        let catalog = state
            .hetzner_cloud
            .catalog
            .as_ref()
            .filter(|catalog| evidence_is_fresh(catalog.refreshed_at, now, ttl_secs))
            .ok_or(HetznerPreferenceError::CatalogStale)?;
        let location = preferences
            .default_location
            .as_deref()
            .ok_or(HetznerPreferenceError::InvalidLocation)?;
        let ssh_key = preferences
            .ssh_key_ref
            .as_deref()
            .ok_or(HetznerPreferenceError::InvalidSshKey)?;
        let firewall = preferences
            .firewall_ref
            .as_deref()
            .ok_or(HetznerPreferenceError::InvalidFirewall)?;
        if !catalog.supports_location(location) {
            return Err(HetznerPreferenceError::InvalidLocation);
        }
        if !catalog.ssh_keys.iter().any(|value| value == ssh_key) {
            return Err(HetznerPreferenceError::InvalidSshKey);
        }
        if !catalog.firewalls.iter().any(|value| value == firewall) {
            return Err(HetznerPreferenceError::InvalidFirewall);
        }
        state.hetzner_cloud.preferences = preferences;
        drop(state);
        self.persist();
        Ok(())
    }

    pub(crate) fn disconnect(&self, now: i64) {
        {
            let mut state = self.state.write().expect("provider connection store lock");
            state.hetzner_cloud.disconnected_at = Some(now);
            state.hetzner_cloud.last_attempt = Some(HetznerConnectionAttempt {
                tested_at: now,
                code: HetznerConnectionCode::Disconnected,
                api_access: false,
                credential_boundary_ready: false,
                execution_enabled: false,
                ssh_key_ready: false,
                firewall_ready: false,
                default_location_ready: false,
                catalog_ready: false,
            });
        }
        self.persist();
    }

    pub(crate) fn ready(&self, now: i64, ttl_secs: i64) -> bool {
        let state = self.state.read().expect("provider connection store lock");
        state.hetzner_cloud.disconnected_at.is_none()
            && state
                .hetzner_cloud
                .last_attempt
                .as_ref()
                .is_some_and(|attempt| {
                    attempt.ready() && evidence_is_fresh(attempt.tested_at, now, ttl_secs)
                })
            && state
                .hetzner_cloud
                .catalog
                .as_ref()
                .is_some_and(|catalog| evidence_is_fresh(catalog.refreshed_at, now, ttl_secs))
    }

    pub(crate) fn catalog_if_fresh(&self, now: i64, ttl_secs: i64) -> Option<HetznerCatalog> {
        if self.disconnected_at().is_some() {
            return None;
        }
        self.catalog()
            .filter(|catalog| evidence_is_fresh(catalog.refreshed_at, now, ttl_secs))
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let state = self
            .state
            .read()
            .expect("provider connection store lock")
            .clone();
        let Ok(json) = serde_json::to_vec_pretty(&state) else {
            return;
        };
        let result = (|| -> std::io::Result<()> {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let counter = PERSIST_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
            let temporary = path.with_extension(format!(
                "provider-connection-tmp-{}-{counter}",
                std::process::id()
            ));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let write_result = (|| -> std::io::Result<()> {
                let mut file = options.open(&temporary)?;
                file.write_all(&json)?;
                file.sync_all()?;
                std::fs::rename(&temporary, path)?;
                Ok(())
            })();
            if write_result.is_err() {
                let _ = std::fs::remove_file(temporary);
            }
            write_result
        })();
        if result.is_err() {
            tracing::warn!("failed to durably persist provider connection state");
        }
    }
}

pub(crate) fn evidence_is_fresh(observed_at: i64, now: i64, ttl_secs: i64) -> bool {
    ttl_secs > 0 && observed_at > 0 && observed_at <= now && now - observed_at <= ttl_secs
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HetznerPreferenceError {
    CatalogStale,
    InvalidLocation,
    InvalidSshKey,
    InvalidFirewall,
}

impl HetznerPreferenceError {
    pub(crate) fn safe_message(self) -> &'static str {
        match self {
            Self::CatalogStale => "Test the provider connection before saving these choices.",
            Self::InvalidLocation => "Choose a currently available Hetzner Cloud location.",
            Self::InvalidSshKey => "Choose an SSH public key returned by Hetzner Cloud.",
            Self::InvalidFirewall => "Choose a firewall returned by Hetzner Cloud.",
        }
    }
}

pub(crate) struct HetznerTestConfig<'a> {
    pub(crate) api_base_url: &'a str,
    pub(crate) request_timeout: Duration,
    pub(crate) token: &'a str,
    pub(crate) credential_boundary_ready: bool,
    pub(crate) execution_enabled: bool,
    pub(crate) ssh_key_ref: Option<&'a str>,
    pub(crate) firewall_ref: Option<&'a str>,
    pub(crate) default_location: Option<&'a str>,
}

pub(crate) async fn test_hetzner_connection(
    config: HetznerTestConfig<'_>,
    now: i64,
) -> HetznerConnectionTestResult {
    let failed = |code| HetznerConnectionTestResult {
        attempt: HetznerConnectionAttempt {
            tested_at: now,
            code,
            api_access: false,
            credential_boundary_ready: config.credential_boundary_ready,
            execution_enabled: config.execution_enabled,
            ssh_key_ready: false,
            firewall_ready: false,
            default_location_ready: false,
            catalog_ready: false,
        },
        catalog: None,
    };
    if config.token.trim().is_empty() {
        return failed(HetznerConnectionCode::CredentialUnavailable);
    }
    let Some(api_base) = safe_hcloud_api_base(config.api_base_url) else {
        return failed(HetznerConnectionCode::RequestFailed);
    };
    let Ok(client) = reqwest::Client::builder()
        .timeout(config.request_timeout)
        .user_agent("Pharos provider connection test")
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .build()
    else {
        return failed(HetznerConnectionCode::RequestFailed);
    };

    let fetched = fetch_hetzner_catalog(&client, &api_base, config.token, now).await;
    let catalog = match fetched {
        Ok(catalog) => catalog,
        Err(code) => return failed(code),
    };
    let ssh_key_ready = config
        .ssh_key_ref
        .is_some_and(|reference| catalog.ssh_keys.iter().any(|item| item == reference));
    let firewall_ready = config
        .firewall_ref
        .is_some_and(|reference| catalog.firewalls.iter().any(|item| item == reference));
    let default_location_ready = config
        .default_location
        .is_some_and(|location| catalog.supports_location(location));
    let catalog_ready = !catalog.locations.is_empty()
        && !catalog.server_types.is_empty()
        && catalog.server_types.iter().any(|server_type| {
            server_type
                .locations
                .iter()
                .any(|location| location.available && location.monthly_gross.is_some())
        });
    let code = if !config.credential_boundary_ready {
        HetznerConnectionCode::CredentialBoundaryRequired
    } else if !config.execution_enabled {
        HetznerConnectionCode::ExecutionDisabled
    } else if config.ssh_key_ref.is_none() {
        HetznerConnectionCode::SshKeyRequired
    } else if !ssh_key_ready {
        HetznerConnectionCode::SshKeyMissing
    } else if config.firewall_ref.is_none() {
        HetznerConnectionCode::FirewallRequired
    } else if !firewall_ready {
        HetznerConnectionCode::FirewallMissing
    } else if config.default_location.is_none() {
        HetznerConnectionCode::DefaultLocationRequired
    } else if !default_location_ready {
        HetznerConnectionCode::DefaultLocationUnavailable
    } else if !catalog_ready {
        HetznerConnectionCode::CatalogUnavailable
    } else {
        HetznerConnectionCode::Ready
    };
    HetznerConnectionTestResult {
        attempt: HetznerConnectionAttempt {
            tested_at: now,
            code,
            api_access: true,
            credential_boundary_ready: config.credential_boundary_ready,
            execution_enabled: config.execution_enabled,
            ssh_key_ready,
            firewall_ready,
            default_location_ready,
            catalog_ready,
        },
        catalog: Some(catalog),
    }
}

pub(crate) fn safe_hcloud_api_base(value: &str) -> Option<Url> {
    let mut url = Url::parse(value.trim()).ok()?;
    let host = url.host_str()?;
    let production = url.scheme() == "https" && host.eq_ignore_ascii_case("api.hetzner.cloud");
    let local_test = url.scheme() == "http"
        && host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback());
    if !(production || local_test)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let path = url.path().trim_end_matches('/').to_string();
    if production && path != "/v1" {
        return None;
    }
    url.set_path(&path);
    Some(url)
}

async fn fetch_hetzner_catalog(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
    now: i64,
) -> Result<HetznerCatalog, HetznerConnectionCode> {
    let locations = fetch_locations(client, api_base, token).await?;
    let raw_server_types = fetch_server_types(client, api_base, token).await?;
    let pricing = fetch_pricing(client, api_base, token).await?;
    let ssh_keys = fetch_named_resources::<SshKeyListResponse>(
        client,
        api_base,
        token,
        "ssh_keys",
        |response| response.ssh_keys,
    )
    .await?;
    let firewalls = fetch_named_resources::<FirewallListResponse>(
        client,
        api_base,
        token,
        "firewalls",
        |response| response.firewalls,
    )
    .await?;
    let currency = safe_short_text(&pricing.pricing.currency, 8)
        .filter(|value| {
            value
                .chars()
                .all(|character| character.is_ascii_uppercase())
        })
        .ok_or(HetznerConnectionCode::InvalidResponse)?;
    let mut server_types = Vec::new();
    for raw in raw_server_types {
        let Some(name) = safe_selector(&raw.name) else {
            continue;
        };
        let description = safe_short_text(&raw.description, 160).unwrap_or_else(|| name.clone());
        let category = safe_short_text(&raw.category, 80).unwrap_or_else(|| "server".to_string());
        let architecture =
            safe_selector(&raw.architecture).unwrap_or_else(|| "unknown".to_string());
        let memory_gb = if raw.memory.is_finite() && raw.memory >= 0.0 && raw.memory <= 4096.0 {
            format_memory(raw.memory)
        } else {
            continue;
        };
        let prices = pricing
            .pricing
            .server_types
            .iter()
            .find(|item| item.name == raw.name)
            .map(|item| item.prices.as_slice())
            .unwrap_or(&[]);
        let mut type_locations = Vec::new();
        for raw_location in raw.locations {
            let Some(location_name) = safe_selector(&raw_location.name) else {
                continue;
            };
            let price = prices.iter().find(|item| item.location == location_name);
            type_locations.push(HetznerServerTypeLocation {
                name: location_name,
                available: raw_location.available,
                recommended: raw_location.recommended,
                monthly_gross: price.and_then(|item| safe_price(&item.price_monthly.gross)),
                hourly_gross: price.and_then(|item| safe_price(&item.price_hourly.gross)),
            });
        }
        type_locations.sort_by(|left, right| left.name.cmp(&right.name));
        if type_locations.is_empty() {
            continue;
        }
        server_types.push(HetznerServerType {
            name,
            description,
            category,
            cores: raw.cores,
            memory_gb,
            disk_gb: raw.disk,
            architecture,
            locations: type_locations,
        });
    }
    server_types.sort_by(|left, right| left.name.cmp(&right.name));
    let mut safe_locations = locations
        .into_iter()
        .filter_map(|location| {
            Some(HetznerLocation {
                name: safe_selector(&location.name)?,
                city: safe_short_text(&location.city, 120)?,
                country: safe_short_text(&location.country, 8)?,
                network_zone: safe_selector(&location.network_zone)?,
            })
        })
        .collect::<Vec<_>>();
    safe_locations.sort_by(|left, right| left.name.cmp(&right.name));
    if safe_locations.is_empty() || server_types.is_empty() {
        return Err(HetznerConnectionCode::CatalogUnavailable);
    }
    Ok(HetznerCatalog {
        refreshed_at: now,
        currency,
        locations: safe_locations,
        server_types,
        ssh_keys,
        firewalls,
    })
}

fn format_memory(value: f64) -> String {
    let rounded = (value * 10.0).round() / 10.0;
    if rounded.fract() == 0.0 {
        format!("{rounded:.0}")
    } else {
        format!("{rounded:.1}")
    }
}

fn safe_short_text(value: &str, max: usize) -> Option<String> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > max || value.chars().any(char::is_control) {
        return None;
    }
    Some(value.to_string())
}

fn safe_selector(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty()
        || value.len() > 160
        || !value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
        })
    {
        return None;
    }
    Some(value.to_string())
}

fn safe_price(value: &str) -> Option<String> {
    let value = value.trim();
    normalize_gross_price(value).map(|_| value.to_string())
}

async fn fetch_locations(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
) -> Result<Vec<ApiLocation>, HetznerConnectionCode> {
    let mut output = Vec::new();
    for page in 1..=MAX_PAGES {
        let response: LocationListResponse =
            get_page(client, api_base, token, "locations", page).await?;
        output.extend(response.locations);
        if response.meta.pagination.next_page.is_none() {
            return Ok(output);
        }
    }
    Err(HetznerConnectionCode::InvalidResponse)
}

async fn fetch_server_types(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
) -> Result<Vec<ApiServerType>, HetznerConnectionCode> {
    let mut output = Vec::new();
    for page in 1..=MAX_PAGES {
        let response: ServerTypeListResponse =
            get_page(client, api_base, token, "server_types", page).await?;
        output.extend(response.server_types);
        if response.meta.pagination.next_page.is_none() {
            return Ok(output);
        }
    }
    Err(HetznerConnectionCode::InvalidResponse)
}

async fn fetch_named_resources<T>(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
    path: &str,
    select: impl Fn(T) -> Vec<ApiNamedResource>,
) -> Result<Vec<String>, HetznerConnectionCode>
where
    T: DeserializeOwned + Paginated,
{
    let mut output = Vec::new();
    for page in 1..=MAX_PAGES {
        let response: T = get_page(client, api_base, token, path, page).await?;
        let next_page = response.next_page();
        output.extend(
            select(response)
                .into_iter()
                .filter_map(|item| safe_selector(&item.name)),
        );
        if next_page.is_none() {
            output.sort();
            output.dedup();
            return Ok(output);
        }
    }
    Err(HetznerConnectionCode::InvalidResponse)
}

async fn fetch_pricing(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
) -> Result<PricingResponse, HetznerConnectionCode> {
    let endpoint = endpoint_url(api_base, "pricing")?;
    get_json(client, endpoint, token).await
}

async fn get_page<T: DeserializeOwned>(
    client: &reqwest::Client,
    api_base: &Url,
    token: &str,
    path: &str,
    page: u32,
) -> Result<T, HetznerConnectionCode> {
    let mut endpoint = endpoint_url(api_base, path)?;
    endpoint
        .query_pairs_mut()
        .append_pair("page", &page.to_string())
        .append_pair("per_page", &PAGE_SIZE.to_string());
    get_json(client, endpoint, token).await
}

fn endpoint_url(api_base: &Url, path: &str) -> Result<Url, HetznerConnectionCode> {
    let mut endpoint = api_base.clone();
    let base_path = api_base.path().trim_end_matches('/');
    endpoint.set_path(&format!("{base_path}/{}", path.trim_start_matches('/')));
    Ok(endpoint)
}

async fn get_json<T: DeserializeOwned>(
    client: &reqwest::Client,
    endpoint: Url,
    token: &str,
) -> Result<T, HetznerConnectionCode> {
    let response = client
        .get(endpoint)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| HetznerConnectionCode::RequestFailed)?;
    if !response.status().is_success() {
        return Err(HetznerConnectionCode::from_status(response.status()));
    }
    let bytes = response
        .bytes()
        .await
        .map_err(|_| HetznerConnectionCode::InvalidResponse)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(HetznerConnectionCode::InvalidResponse);
    }
    serde_json::from_slice(&bytes).map_err(|_| HetznerConnectionCode::InvalidResponse)
}

trait Paginated {
    fn next_page(&self) -> Option<u32>;
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ApiMeta {
    pagination: ApiPagination,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ApiPagination {
    next_page: Option<u32>,
}

#[derive(Debug, Deserialize)]
struct LocationListResponse {
    #[serde(default)]
    locations: Vec<ApiLocation>,
    #[serde(default)]
    meta: ApiMeta,
}

#[derive(Debug, Deserialize)]
struct ApiLocation {
    name: String,
    city: String,
    country: String,
    network_zone: String,
}

#[derive(Debug, Deserialize)]
struct ServerTypeListResponse {
    #[serde(default)]
    server_types: Vec<ApiServerType>,
    #[serde(default)]
    meta: ApiMeta,
}

#[derive(Debug, Deserialize)]
struct ApiServerType {
    name: String,
    description: String,
    #[serde(default)]
    category: String,
    cores: u32,
    memory: f64,
    disk: u32,
    architecture: String,
    #[serde(default)]
    locations: Vec<ApiServerTypeLocation>,
}

#[derive(Debug, Deserialize)]
struct ApiServerTypeLocation {
    name: String,
    #[serde(default)]
    recommended: bool,
    #[serde(default)]
    available: bool,
}

#[derive(Debug, Deserialize)]
struct PricingResponse {
    pricing: ApiPricing,
}

#[derive(Debug, Deserialize)]
struct ApiPricing {
    currency: String,
    #[serde(default)]
    server_types: Vec<ApiPricingServerType>,
}

#[derive(Debug, Deserialize)]
struct ApiPricingServerType {
    name: String,
    #[serde(default)]
    prices: Vec<ApiServerTypePrice>,
}

#[derive(Debug, Deserialize)]
struct ApiServerTypePrice {
    location: String,
    price_hourly: ApiPrice,
    price_monthly: ApiPrice,
}

#[derive(Debug, Deserialize)]
struct ApiPrice {
    gross: String,
}

#[derive(Debug, Deserialize)]
struct ApiNamedResource {
    name: String,
}

#[derive(Debug, Deserialize)]
struct SshKeyListResponse {
    #[serde(default)]
    ssh_keys: Vec<ApiNamedResource>,
    #[serde(default)]
    meta: ApiMeta,
}

impl Paginated for SshKeyListResponse {
    fn next_page(&self) -> Option<u32> {
        self.meta.pagination.next_page
    }
}

#[derive(Debug, Deserialize)]
struct FirewallListResponse {
    #[serde(default)]
    firewalls: Vec<ApiNamedResource>,
    #[serde(default)]
    meta: ApiMeta,
}

impl Paginated for FirewallListResponse {
    fn next_page(&self) -> Option<u32> {
        self.meta.pagination.next_page
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{SystemTime, UNIX_EPOCH};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    const TOKEN: &str = "provider-test-token";

    async fn mock_api(status: &'static str) -> (String, Arc<Mutex<Vec<String>>>) {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind provider mock");
        let address = listener.local_addr().expect("provider mock address");
        let requests = Arc::new(Mutex::new(Vec::new()));
        let recorded = requests.clone();
        tokio::spawn(async move {
            for _ in 0..5 {
                let Ok(Ok((mut stream, _))) =
                    timeout(Duration::from_secs(2), listener.accept()).await
                else {
                    break;
                };
                let mut buffer = vec![0; 16 * 1024];
                let size = stream
                    .read(&mut buffer)
                    .await
                    .expect("read provider request");
                let request = String::from_utf8_lossy(&buffer[..size]);
                let path = request
                    .lines()
                    .next()
                    .and_then(|line| line.split_whitespace().nth(1))
                    .unwrap_or_default()
                    .to_string();
                assert!(
                    request.contains("authorization: Bearer provider-test-token")
                        || request.contains("Authorization: Bearer provider-test-token")
                );
                recorded
                    .lock()
                    .expect("provider request lock")
                    .push(path.clone());
                let body = if !status.starts_with("200") {
                    r#"{"error":{"code":"denied","message":"must stay redacted"}}"#
                } else if path.starts_with("/locations?") {
                    r#"{"locations":[{"name":"fsn1","city":"Falkenstein","country":"DE","network_zone":"eu-central"}]}"#
                } else if path.starts_with("/server_types?") {
                    r#"{"server_types":[{"name":"cx23","description":"CX23","category":"cost_optimized","cores":2,"memory":4.0,"disk":40,"architecture":"x86","locations":[{"name":"fsn1","recommended":true,"available":true}]}]}"#
                } else if path == "/pricing" {
                    r#"{"pricing":{"currency":"EUR","server_types":[{"name":"cx23","prices":[{"location":"fsn1","price_hourly":{"gross":"0.0060"},"price_monthly":{"gross":"3.4900"}}]}]}}"#
                } else if path.starts_with("/ssh_keys?") {
                    r#"{"ssh_keys":[{"name":"pharos-bootstrap-key"}]}"#
                } else {
                    r#"{"firewalls":[{"name":"pharos-bootstrap-firewall"}]}"#
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: application/json\r\nconnection: close\r\ncontent-length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("write provider response");
            }
        });
        (format!("http://{address}"), requests)
    }

    fn test_config(api_base_url: &str) -> HetznerTestConfig<'_> {
        HetznerTestConfig {
            api_base_url,
            request_timeout: Duration::from_secs(2),
            token: TOKEN,
            credential_boundary_ready: true,
            execution_enabled: true,
            ssh_key_ref: Some("pharos-bootstrap-key"),
            firewall_ref: Some("pharos-bootstrap-firewall"),
            default_location: Some("fsn1"),
        }
    }

    fn catalog_fixture() -> HetznerCatalog {
        HetznerCatalog {
            refreshed_at: 1_700_000_000,
            currency: "EUR".to_string(),
            locations: vec![HetznerLocation {
                name: "fsn1".to_string(),
                city: "Falkenstein".to_string(),
                country: "DE".to_string(),
                network_zone: "eu-central".to_string(),
            }],
            server_types: vec![HetznerServerType {
                name: "cx23".to_string(),
                description: "CX23".to_string(),
                category: "cost_optimized".to_string(),
                cores: 2,
                memory_gb: "4".to_string(),
                disk_gb: 40,
                architecture: "x86".to_string(),
                locations: vec![HetznerServerTypeLocation {
                    name: "fsn1".to_string(),
                    available: true,
                    recommended: true,
                    monthly_gross: Some("3.4900".to_string()),
                    hourly_gross: Some("0.0060".to_string()),
                }],
            }],
            ssh_keys: vec!["pharos-bootstrap-key".to_string()],
            firewalls: vec!["pharos-bootstrap-firewall".to_string()],
        }
    }

    #[test]
    fn gross_prices_are_normalized_strictly_without_floating_point() {
        for (input, expected) in [
            ("0", "0"),
            ("000", "0"),
            ("0003.4900", "3.49"),
            ("0.0060", "0.006"),
            ("3.0000", "3"),
            (
                "99999999999999999999999999999999",
                "99999999999999999999999999999999",
            ),
        ] {
            assert_eq!(normalize_gross_price(input).as_deref(), Some(expected));
        }

        for invalid in [
            "",
            " 1",
            "1 ",
            "+1",
            "-1",
            ".1",
            "1.",
            "1..0",
            "1e2",
            "1,00",
            "NaN",
            "١.0",
            "999999999999999999999999999999999",
        ] {
            assert_eq!(normalize_gross_price(invalid), None, "accepted {invalid:?}");
        }
    }

    #[test]
    fn gross_price_comparison_is_exact_and_rejects_invalid_values() {
        assert_eq!(
            compare_gross_prices("3.4900", "3.49"),
            Some(Ordering::Equal)
        );
        assert_eq!(compare_gross_prices("0.006", "0.01"), Some(Ordering::Less));
        assert_eq!(
            compare_gross_prices("100000000000000000000", "99999999999999999999.99"),
            Some(Ordering::Greater)
        );
        assert_eq!(
            compare_gross_prices("1.0001", "1.00001"),
            Some(Ordering::Greater)
        );
        assert_eq!(compare_gross_prices("1e2", "100"), None);
    }

    #[test]
    fn exact_catalog_selection_returns_canonical_safe_review_facts() {
        let catalog = catalog_fixture();
        let selection = catalog
            .exact_selection("fsn1", "cx23")
            .expect("exact available selection");

        assert_eq!(selection.catalog_refreshed_at, 1_700_000_000);
        assert_eq!(selection.location, "fsn1");
        assert_eq!(selection.location_label, "Falkenstein, DE (fsn1)");
        assert_eq!(selection.server_type, "cx23");
        assert_eq!(selection.server_type_label, "CX23 (cx23)");
        assert_eq!(
            selection.hardware_summary,
            "2 vCPU · 4 GB RAM · 40 GB disk · x86"
        );
        assert_eq!(selection.currency, "EUR");
        assert_eq!(selection.hourly_gross, "0.006");
        assert_eq!(selection.monthly_gross, "3.49");

        assert!(catalog.exact_selection("hel1", "cx23").is_none());
        assert!(catalog.exact_selection("fsn1", "cpx21").is_none());

        let mut unavailable = catalog.clone();
        unavailable.server_types[0].locations[0].available = false;
        assert!(unavailable.exact_selection("fsn1", "cx23").is_none());

        let mut unpriced = catalog;
        unpriced.server_types[0].locations[0].hourly_gross = None;
        assert!(unpriced.exact_selection("fsn1", "cx23").is_none());
    }

    #[tokio::test]
    async fn read_only_test_builds_a_current_safe_catalog() {
        let (api, requests) = mock_api("200 OK").await;
        let result = test_hetzner_connection(test_config(&api), 1_700_000_000).await;

        assert!(result.attempt.ready());
        let catalog = result.catalog.expect("safe catalog");
        assert_eq!(catalog.currency, "EUR");
        assert_eq!(catalog.locations[0].name, "fsn1");
        assert_eq!(catalog.server_types[0].name, "cx23");
        assert_eq!(
            catalog
                .recommended_plan("fsn1")
                .map(|server_type| server_type.name.as_str()),
            Some("cx23")
        );
        assert_eq!(requests.lock().expect("provider requests").len(), 5);
        let json = serde_json::to_string(&catalog).expect("catalog serializes");
        assert!(!json.contains(TOKEN));
        assert!(!json.to_ascii_lowercase().contains("bearer "));
        assert!(!json.contains("must stay redacted"));
    }

    #[tokio::test]
    async fn provider_errors_are_redacted_and_fail_closed() {
        let (api, _) = mock_api("401 Unauthorized").await;
        let result = test_hetzner_connection(test_config(&api), 1_700_000_000).await;

        assert_eq!(result.attempt.code, HetznerConnectionCode::Unauthorized);
        assert!(!result.attempt.api_access);
        assert!(result.catalog.is_none());
        let json = serde_json::to_string(&result.attempt).expect("attempt serializes");
        assert!(!json.contains(TOKEN));
        assert!(!json.contains("must stay redacted"));
    }

    #[tokio::test]
    async fn missing_choices_preserve_catalog_but_do_not_unlock_creation() {
        let (api, _) = mock_api("200 OK").await;
        let mut config = test_config(&api);
        config.ssh_key_ref = None;
        let result = test_hetzner_connection(config, 1_700_000_000).await;

        assert_eq!(result.attempt.code, HetznerConnectionCode::SshKeyRequired);
        assert!(result.attempt.api_access);
        assert!(!result.attempt.ready());
        assert!(result.catalog.is_some());
    }

    #[test]
    fn persisted_evidence_expires_and_disconnects_closed() {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pharos-provider-connections-{}-{nanos}.json",
            std::process::id()
        ));
        let store = ProviderConnectionStore::new(Some(path.clone()));
        let catalog = HetznerCatalog {
            refreshed_at: 100,
            currency: "EUR".to_string(),
            locations: vec![HetznerLocation {
                name: "fsn1".to_string(),
                city: "Falkenstein".to_string(),
                country: "DE".to_string(),
                network_zone: "eu-central".to_string(),
            }],
            server_types: vec![HetznerServerType {
                name: "cx23".to_string(),
                description: "CX23".to_string(),
                category: "cost_optimized".to_string(),
                cores: 2,
                memory_gb: "4".to_string(),
                disk_gb: 40,
                architecture: "x86".to_string(),
                locations: vec![HetznerServerTypeLocation {
                    name: "fsn1".to_string(),
                    available: true,
                    recommended: true,
                    monthly_gross: Some("3.4900".to_string()),
                    hourly_gross: Some("0.0060".to_string()),
                }],
            }],
            ssh_keys: vec!["pharos-bootstrap-key".to_string()],
            firewalls: vec!["pharos-bootstrap-firewall".to_string()],
        };
        store.record_test(HetznerConnectionTestResult {
            attempt: HetznerConnectionAttempt {
                tested_at: 100,
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
        });
        assert!(store.ready(150, 60));
        assert!(!store.ready(161, 60));

        store.disconnect(170);
        assert!(!store.ready(170, 60));
        assert!(store.catalog_if_fresh(170, 60).is_none());
        let reloaded = ProviderConnectionStore::new(Some(path.clone()));
        assert_eq!(reloaded.disconnected_at(), Some(170));
        let contents = std::fs::read_to_string(&path).expect("state is persisted");
        assert!(!contents.contains(TOKEN));
        assert!(!contents.to_ascii_lowercase().contains("bearer "));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn api_base_cannot_send_credentials_to_an_unreviewed_host() {
        assert!(safe_hcloud_api_base("https://api.hetzner.cloud/v1").is_some());
        assert!(safe_hcloud_api_base("http://127.0.0.1:1234").is_some());
        assert!(safe_hcloud_api_base("https://example.com/v1").is_none());
        assert!(safe_hcloud_api_base("https://user@api.hetzner.cloud/v1").is_none());
        assert!(safe_hcloud_api_base("https://api.hetzner.cloud/v2").is_none());
    }
}
