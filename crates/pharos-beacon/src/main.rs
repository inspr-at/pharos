//! pharos-beacon — per-host agent (PHAROS-6 / PHAROS-15).
//!
//! Computes this host's Nix freshness (flake.lock age + commits behind nixcfg)
//! and reports it to pharosd. With PHAROS_INTERVAL set it loops as a recurring
//! service; otherwise it reports once and exits. Token auth via Janus is
//! PHAROS-8; the native (musl) Nix-module deployment is PHAROS-6/7.
//!
//! Env: PHAROS_URL (required pharosd base),
//!      PHAROS_INTERVAL (secs; loop if set), NIXCFG_DIR (flake checkout;
//!      auto-detected otherwise), PHAROS_HOSTNAME / PHAROS_ROLE (overrides),
//!      PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE (active-generation evidence),
//!      PHAROS_NIXCFG_REMOTE_URL / PHAROS_NIXCFG_REMOTE_REF (authoritative Git),
//!      PHAROS_NIXPKGS_CHANNEL_BASE_URL (authoritative channel publication),
//!      PHAROS_NIXPKGS_REMOTE_URL (legacy/custom authoritative Git fallback),
//!      PHAROS_TOKEN / PHAROS_TOKEN_FILE (per-host bearer token from /register),
//!      PHAROS_BACKUP_MODE (auto/off/restic/status-file/command).

use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pharos_core::{
    BackupConfiguredState, BackupEngine, BackupObservation, BackupPostureState, BackupRunState,
    GitRevisionRelation, HostLocation, HostLocationSource, HostPreferences,
    HostPreferencesRegistry, HostReport, HostReportResponse, KernelPosture, NixDeploymentEvidence,
    NixFreshness, NixcfgGitComparison, NixpkgsGitComparison, NixpkgsInputFreshness,
    NixpkgsRevisionRelation, ServiceObservation, ServiceObservationState, HOST_REPORT_SCHEMA,
    HOST_REPORT_VERSION, MAX_HEARTBEAT_INTERVAL_SECS, MAX_INBOUND_RTT_MS,
    MIN_HEARTBEAT_INTERVAL_SECS,
};
use sha2::{Digest, Sha256};
use url::Url;

const MAX_REPORT_RESPONSE_BYTES: u64 = 64 * 1024;
const LOCATION_COMMAND_OUTPUT_LIMIT_BYTES: usize = 64 * 1024;
const GIT_COMPARISON_TIMEOUT: Duration = Duration::from_secs(12);
const NIXPKGS_CHANNEL_TIMEOUT: Duration = Duration::from_secs(12);
const MAX_NIXPKGS_REVISION_BYTES: u64 = 128;
const DEFAULT_NIXPKGS_CHANNEL_BASE_URL: &str = "https://channels.nixos.org/";
const OFFICIAL_NIXPKGS_GIT_REMOTE: &str = "https://github.com/NixOS/nixpkgs.git";
const MAX_DEPLOYMENT_EVIDENCE_BYTES: u64 = 4 * 1024;
const MAX_FLAKE_LOCK_BYTES: u64 = 8 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReportEndpoint {
    request_url: String,
    safe_origin: String,
}

fn report_endpoint(raw: &str) -> Result<ReportEndpoint, &'static str> {
    let mut base = Url::parse(raw.trim()).map_err(|_| "invalid_url")?;
    if !matches!(base.scheme(), "http" | "https")
        || base.host_str().is_none()
        || !base.username().is_empty()
        || base.password().is_some()
        || base.query().is_some()
        || base.fragment().is_some()
    {
        return Err("unsafe_url");
    }
    if !base.path().ends_with('/') {
        let mut path = base.path().to_string();
        path.push('/');
        base.set_path(&path);
    }
    let endpoint = base.join("report").map_err(|_| "invalid_url")?;
    Ok(ReportEndpoint {
        request_url: endpoint.as_str().to_string(),
        safe_origin: endpoint.origin().ascii_serialization(),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestDeadlines {
    connect: Duration,
    read: Duration,
    write: Duration,
    overall: Duration,
}

impl RequestDeadlines {
    fn for_cadence(cadence_secs: u64) -> Result<Self, &'static str> {
        if !(MIN_HEARTBEAT_INTERVAL_SECS..=MAX_HEARTBEAT_INTERVAL_SECS).contains(&cadence_secs) {
            return Err("invalid_cadence");
        }
        let overall_secs = cadence_secs.saturating_sub(1).min(15);
        Ok(Self {
            connect: Duration::from_secs(overall_secs.min(5)),
            read: Duration::from_secs(overall_secs.min(10)),
            write: Duration::from_secs(overall_secs.min(10)),
            overall: Duration::from_secs(overall_secs),
        })
    }

    fn agent(self) -> ureq::Agent {
        ureq::Agent::config_builder()
            .timeout_connect(Some(self.connect))
            .timeout_send_request(Some(self.write))
            .timeout_send_body(Some(self.write))
            .timeout_recv_response(Some(self.read))
            .timeout_recv_body(Some(self.read))
            .timeout_global(Some(self.overall))
            .max_redirects(0)
            .build()
            .into()
    }
}

fn retry_delay(cadence_secs: u64, consecutive_failures: u32, jitter_seed: u64) -> Duration {
    let exponent = consecutive_failures.saturating_sub(1).min(6);
    let base_millis = 1_000_u64
        .saturating_mul(1_u64 << exponent)
        .min(cadence_secs.saturating_mul(500).max(1_000));
    let jitter_window = (base_millis / 2).max(1);
    let cap_millis = cadence_secs.saturating_mul(1_000).saturating_sub(1);
    Duration::from_millis(
        base_millis
            .saturating_add(jitter_seed % jitter_window)
            .min(cap_millis),
    )
}

fn jitter_seed() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
        ^ u64::from(std::process::id())
}

#[cfg(target_os = "linux")]
fn systemd_notify(message: &str) {
    use std::os::linux::net::SocketAddrExt;
    use std::os::unix::net::{SocketAddr, UnixDatagram};

    let Some(socket_name) = std::env::var_os("NOTIFY_SOCKET") else {
        return;
    };
    let socket_name = socket_name.as_encoded_bytes();
    let Ok(socket) = UnixDatagram::unbound() else {
        return;
    };
    if let Some(abstract_name) = socket_name.strip_prefix(b"@") {
        if let Ok(address) = SocketAddr::from_abstract_name(abstract_name) {
            let _ = socket.send_to_addr(message.as_bytes(), &address);
        }
    } else if let Ok(path) = std::str::from_utf8(socket_name) {
        let _ = socket.send_to(message.as_bytes(), path);
    }
}

#[cfg(not(target_os = "linux"))]
fn systemd_notify(_message: &str) {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PreferencesApplyError {
    InvalidResponse,
    HostMismatch,
    NotConfigured,
    UnsupportedOnNix,
    WriteFailed,
}

impl PreferencesApplyError {
    fn code(self) -> &'static str {
        match self {
            Self::InvalidResponse => "invalid_response",
            Self::HostMismatch => "host_mismatch",
            Self::NotConfigured => "preferences_file_not_configured",
            Self::UnsupportedOnNix => "nix_host_uses_declarative_delivery",
            Self::WriteFailed => "atomic_write_failed",
        }
    }

    fn observation(self) -> ServiceObservation {
        ServiceObservation {
            id: "host-preferences".to_string(),
            label: "Host settings".to_string(),
            state: ServiceObservationState::Warning,
            summary: format!("settings apply failed: {}", self.code()),
        }
    }
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn report_rtt_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(MAX_INBOUND_RTT_MS)
        .clamp(1, MAX_INBOUND_RTT_MS)
}

fn hostname() -> String {
    std::env::var("PHAROS_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn bearer_token() -> Result<Option<String>, pharos_core::secret_input::SecretInputError> {
    pharos_core::secret_input::optional_secret("PHAROS_TOKEN")
}

fn parse_host_preferences(raw: &str, host: &str) -> Result<HostPreferences, &'static str> {
    let registry = serde_json::from_str::<HostPreferencesRegistry>(raw)
        .map_err(|_| "host preference registry is invalid")?;
    registry
        .validate_contract()
        .map_err(|_| "host preference registry is invalid")?;
    registry
        .preferences_for(host)
        .cloned()
        .ok_or("host preference registry does not contain this host")
}

fn read_host_preferences(path: &Path, host: &str) -> Result<HostPreferences, &'static str> {
    let raw =
        std::fs::read_to_string(path).map_err(|_| "host preference registry is unavailable")?;
    parse_host_preferences(&raw, host)
}

fn atomic_write_host_preferences(
    path: &Path,
    registry: &HostPreferencesRegistry,
) -> Result<(), PreferencesApplyError> {
    registry
        .validate_contract()
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    let parent = path.parent().ok_or(PreferencesApplyError::WriteFailed)?;
    if !parent.is_dir() {
        return Err(PreferencesApplyError::WriteFailed);
    }
    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or(PreferencesApplyError::WriteFailed)?;
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| PreferencesApplyError::WriteFailed)?
        .as_nanos();
    let temporary = parent.join(format!(".{file_name}.{}.{}.tmp", std::process::id(), nonce));
    let mut bytes =
        serde_json::to_vec_pretty(registry).map_err(|_| PreferencesApplyError::InvalidResponse)?;
    bytes.push(b'\n');

    let write_result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        let _ = File::open(parent).and_then(|directory| directory.sync_all());
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&temporary);
        return Err(PreferencesApplyError::WriteFailed);
    }
    Ok(())
}

fn apply_report_response(
    body: &str,
    host: &str,
    is_nix: bool,
    preferences_path: Option<&Path>,
) -> Result<Option<HostPreferences>, PreferencesApplyError> {
    let response = serde_json::from_str::<HostReportResponse>(body)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    if response
        .pending_preferences
        .as_ref()
        .is_some_and(|registry| registry.hosts.len() != 1 || !registry.hosts.contains_key(host))
    {
        return Err(PreferencesApplyError::HostMismatch);
    }
    response
        .validate_contract_for(host)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    let Some(registry) = response.pending_preferences.as_ref() else {
        return Ok(None);
    };
    if is_nix {
        return Err(PreferencesApplyError::UnsupportedOnNix);
    }
    let path = preferences_path.ok_or(PreferencesApplyError::NotConfigured)?;
    atomic_write_host_preferences(path, registry)?;
    Ok(registry.preferences_for(host).cloned())
}

fn apply_report_http_response(
    response: ureq::http::Response<ureq::Body>,
    host: &str,
    is_nix: bool,
    preferences_path: Option<&Path>,
) -> Result<Option<HostPreferences>, PreferencesApplyError> {
    if response.status() == 204 {
        return Ok(None);
    }
    if response.status() != 200 {
        return Err(PreferencesApplyError::InvalidResponse);
    }
    let body = read_bounded_report_response(response.into_body().into_reader())?;
    apply_report_response(&body, host, is_nix, preferences_path)
}

fn read_bounded_report_response(reader: impl Read) -> Result<String, PreferencesApplyError> {
    let mut body = String::new();
    reader
        .take(MAX_REPORT_RESPONSE_BYTES + 1)
        .read_to_string(&mut body)
        .map_err(|_| PreferencesApplyError::InvalidResponse)?;
    if body.len() as u64 > MAX_REPORT_RESPONSE_BYTES {
        return Err(PreferencesApplyError::InvalidResponse);
    }
    Ok(body)
}

/// Locate a flake checkout (one containing flake.lock).
fn nixcfg_dir() -> Option<String> {
    if let Ok(d) = std::env::var("NIXCFG_DIR") {
        return Some(d);
    }
    ["/etc/nixos"]
        .into_iter()
        .find(|d| Path::new(&format!("{d}/flake.lock")).exists())
        .map(String::from)
}

fn kernel_running_path() -> PathBuf {
    env_value("PHAROS_RUNNING_KERNEL_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/proc/sys/kernel/osrelease"))
}

fn kernel_expected_modules_dir() -> PathBuf {
    if let Some(path) = env_value("PHAROS_CURRENT_KERNEL_MODULES_DIR") {
        return PathBuf::from(path);
    }
    [
        "/host/run/current-system/kernel-modules/lib/modules",
        "/run/current-system/kernel-modules/lib/modules",
    ]
    .into_iter()
    .map(PathBuf::from)
    .find(|path| path.is_dir())
    .unwrap_or_else(|| PathBuf::from("/run/current-system/kernel-modules/lib/modules"))
}

fn read_running_kernel(path: &Path) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn read_single_kernel_module_version(path: &Path) -> Option<String> {
    let mut entries = std::fs::read_dir(path)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned());
    let version = entries.next()?;
    entries.next().is_none().then_some(version)
}

fn collect_kernel_posture_at(
    is_nix: bool,
    observed_at: i64,
    running_path: &Path,
    expected_modules_dir: &Path,
) -> KernelPosture {
    KernelPosture::observed(
        is_nix,
        read_running_kernel(running_path),
        is_nix
            .then(|| read_single_kernel_module_version(expected_modules_dir))
            .flatten(),
        observed_at,
    )
}

fn collect_kernel_posture(is_nix: bool, observed_at: i64) -> KernelPosture {
    collect_kernel_posture_at(
        is_nix,
        observed_at,
        &kernel_running_path(),
        &kernel_expected_modules_dir(),
    )
}

fn deployment_evidence_path() -> PathBuf {
    env_value("PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/host/pharos-deployment/evidence.json"))
}

fn read_deployment_evidence(path: &Path) -> Option<NixDeploymentEvidence> {
    let mut raw = String::new();
    File::open(path)
        .ok()?
        .take(MAX_DEPLOYMENT_EVIDENCE_BYTES + 1)
        .read_to_string(&mut raw)
        .ok()?;
    if raw.len() as u64 > MAX_DEPLOYMENT_EVIDENCE_BYTES {
        return None;
    }
    let evidence: NixDeploymentEvidence = serde_json::from_str(&raw).ok()?;
    evidence.validate_contract().ok()?;
    Some(evidence)
}

fn sha256_hex(raw: &[u8]) -> String {
    format!("{:x}", Sha256::digest(raw))
}

/// Read the checkout lock only when its digest and primary node exactly match
/// the active generation. A checkout may move independently after activation;
/// treating that newer mutable file as deployed state would be false evidence.
fn matching_flake_lock(dir: &str, evidence: &NixDeploymentEvidence) -> Option<serde_json::Value> {
    let path = format!("{dir}/flake.lock");
    if std::fs::metadata(&path).ok()?.len() > MAX_FLAKE_LOCK_BYTES {
        return None;
    }
    let raw = std::fs::read(path).ok()?;
    if sha256_hex(&raw) != evidence.flake_lock_sha256 {
        return None;
    }
    let value: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    let nodes = value.get("nodes")?.as_object()?;
    let root_name = value
        .get("root")
        .and_then(|root| root.as_str())
        .unwrap_or("root");
    let target = nodes.get(root_name)?.get("inputs")?.get("nixpkgs")?;
    let node = nodes.get(input_target_name(target)?)?;
    if node.get("locked")?.get("rev")?.as_str()? != evidence.nixpkgs_revision
        || node.get("locked")?.get("lastModified")?.as_i64()? != evidence.nixpkgs_last_modified
        || nixpkgs_channel(node).as_deref() != Some(evidence.nixpkgs_channel.as_str())
    {
        return None;
    }
    Some(value)
}

/// Days since the newest input in the generation-matched flake.lock.
fn flake_lock_age_days(lock: &serde_json::Value) -> Option<u32> {
    let v = lock;
    let newest = v
        .get("nodes")?
        .as_object()?
        .values()
        .filter_map(|n| n.get("locked")?.get("lastModified")?.as_i64())
        .max()?;
    days_since(newest)
}

fn days_since(unix_seconds: i64) -> Option<u32> {
    u32::try_from((now_unix() - unix_seconds).max(0) / 86_400).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CollectedNixpkgsFreshness {
    age_days: u32,
    channel: Option<String>,
    secondary: Option<NixpkgsInputFreshness>,
}

/// PHAROS-193/196/201: the system nixpkgs plus secondary root-input context.
///
/// `flake_lock_age_days` reports the newest input, so one freshly bumped helper
/// hides a frozen nixpkgs behind a reassuring `0d`. Security fixes arrive
/// through the system nixpkgs, so report that as primary posture and preserve
/// the stalest other root nixpkgs input as explicitly secondary context.
fn nixpkgs_freshness(
    v: &serde_json::Value,
    evidence: &NixDeploymentEvidence,
) -> Option<CollectedNixpkgsFreshness> {
    let nodes = v.get("nodes")?.as_object()?;
    // PHAROS-196: resolve the flake's own `nixpkgs` input rather than scanning
    // for the oldest node whose name happens to contain "nixpkgs". A lock mixes
    // the input the system is built from, other root inputs that may be
    // unreferenced, and transitive inputs of unrelated flakes. Reporting the
    // worst of all three describes the lock file, not the host.
    let root_name = v
        .get("root")
        .and_then(|root| root.as_str())
        .unwrap_or("root");
    let root_inputs = nodes.get(root_name)?.get("inputs")?.as_object()?;
    let target = root_inputs.get("nixpkgs")?;
    let node_name = input_target_name(target)?;
    let node = nodes.get(node_name)?;
    let modified = node.get("locked")?.get("lastModified")?.as_i64()?;
    let channel = nixpkgs_channel(node);
    if modified != evidence.nixpkgs_last_modified
        || channel.as_deref() != Some(evidence.nixpkgs_channel.as_str())
        || node.get("locked")?.get("rev")?.as_str()? != evidence.nixpkgs_revision
    {
        return None;
    }

    // Only other root inputs are secondary context. Transitive nixpkgs nodes
    // belong to unrelated flakes and must not be presented as this host's lock
    // maintenance. Aliases that resolve to the system node are excluded too.
    let secondary = root_inputs
        .iter()
        .filter(|(input, _)| {
            input.as_str() != "nixpkgs"
                && input.to_ascii_lowercase().contains("nixpkgs")
                && pharos_core::valid_nix_input_name(input)
        })
        .filter_map(|(input, target)| {
            let secondary_node_name = input_target_name(target)?;
            if secondary_node_name == node_name {
                return None;
            }
            let secondary_node = nodes.get(secondary_node_name)?;
            let modified = secondary_node
                .get("locked")?
                .get("lastModified")?
                .as_i64()?;
            Some(NixpkgsInputFreshness {
                input: input.clone(),
                age_days: days_since(modified)?,
                channel: nixpkgs_channel(secondary_node),
            })
        })
        .max_by(|left, right| {
            left.age_days
                .cmp(&right.age_days)
                .then_with(|| right.input.cmp(&left.input))
        });

    Some(CollectedNixpkgsFreshness {
        age_days: days_since(evidence.nixpkgs_last_modified)?,
        channel: Some(evidence.nixpkgs_channel.clone()),
        secondary,
    })
}

fn nixpkgs_channel(node: &serde_json::Value) -> Option<String> {
    node.get("original")
        .and_then(|original| original.get("ref"))
        .and_then(|reference| reference.as_str())
        .filter(|reference| pharos_core::valid_nix_channel(reference))
        .map(str::to_string)
}

/// An `inputs` entry is either a node name or, for a `follows`, the path to the
/// node being followed. Only the first element names a node.
fn input_target_name(target: &serde_json::Value) -> Option<&str> {
    match target {
        serde_json::Value::String(name) => Some(name.as_str()),
        serde_json::Value::Array(path) => path.first()?.as_str(),
        _ => None,
    }
}

fn safe_git_remote(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.len() > 2_048 {
        return None;
    }
    let url = Url::parse(raw).ok()?;
    (url.scheme() == "https"
        && url.host_str().is_some()
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none())
    .then(|| url.to_string())
}

fn safe_git_branch_ref(raw: &str) -> Option<String> {
    let reference = raw.trim();
    let branch = reference.strip_prefix("refs/heads/")?;
    (!branch.is_empty()
        && reference.len() <= 256
        && !reference.contains("..")
        && !reference.contains("@{")
        && !reference.ends_with('/')
        && !reference.ends_with('.')
        && reference
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-._/".contains(&byte)))
    .then(|| reference.to_string())
}

fn git_output(args: &[String]) -> Option<String> {
    run_location_command("git", args, GIT_COMPARISON_TIMEOUT).ok()
}

fn exact_revision(raw: &str) -> Option<String> {
    let revision = raw.trim();
    ((revision.len() == 40 || revision.len() == 64)
        && revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| revision.to_string())
}

fn git_success(args: &[String]) -> bool {
    run_location_command("git", args, GIT_COMPARISON_TIMEOUT).is_ok()
}

fn nixcfg_reference_dir() -> PathBuf {
    PathBuf::from("/tmp/pharos-nixcfg-reference.git")
}

fn prepare_reference_repo(reference_dir: &Path, checkout: &str) -> Option<()> {
    if !reference_dir.is_absolute() || !reference_dir.starts_with(std::env::temp_dir()) {
        return None;
    }
    if std::fs::symlink_metadata(reference_dir)
        .ok()
        .is_some_and(|metadata| metadata.file_type().is_symlink())
    {
        return None;
    }
    if !reference_dir.join("HEAD").is_file() {
        let path = reference_dir.to_str()?.to_string();
        git_success(&["init".into(), "--bare".into(), "--quiet".into(), path]).then_some(())?;
    }
    let git_dir = git_output(&[
        "-C".into(),
        checkout.into(),
        "rev-parse".into(),
        "--absolute-git-dir".into(),
    ])?;
    let objects = PathBuf::from(git_dir.trim()).join("objects");
    if !objects.is_dir() {
        return None;
    }
    let info = reference_dir.join("objects/info");
    std::fs::create_dir_all(&info).ok()?;
    std::fs::write(info.join("alternates"), format!("{}\n", objects.display())).ok()?;
    Some(())
}

fn nixcfg_git_comparison(checkout: &str, deployed_revision: &str) -> Option<NixcfgGitComparison> {
    let remote = safe_git_remote(&env_value("PHAROS_NIXCFG_REMOTE_URL")?)?;
    let remote_ref = safe_git_branch_ref(&env_value("PHAROS_NIXCFG_REMOTE_REF")?)?;
    let reference_dir = nixcfg_reference_dir();
    nixcfg_git_comparison_from_remote(
        checkout,
        deployed_revision,
        &remote,
        &remote_ref,
        &reference_dir,
    )
}

fn nixcfg_git_comparison_from_remote(
    checkout: &str,
    deployed_revision: &str,
    remote: &str,
    remote_ref: &str,
    reference_dir: &Path,
) -> Option<NixcfgGitComparison> {
    prepare_reference_repo(reference_dir, checkout)?;
    let reference_dir = reference_dir.to_str()?.to_string();
    let local_ref = "refs/remotes/pharos/authoritative";
    let refspec = format!("+{remote_ref}:{local_ref}");
    git_success(&[
        "-C".into(),
        reference_dir.clone(),
        "fetch".into(),
        "--quiet".into(),
        "--force".into(),
        "--no-tags".into(),
        "--filter=blob:none".into(),
        remote.to_string(),
        refspec,
    ])
    .then_some(())?;
    let upstream_revision = exact_revision(&git_output(&[
        "-C".into(),
        reference_dir.clone(),
        "rev-parse".into(),
        format!("{local_ref}^{{commit}}"),
    ])?)?;
    let deployed_revision = exact_revision(deployed_revision)?;
    if upstream_revision == deployed_revision {
        return Some(NixcfgGitComparison {
            upstream_revision,
            relation: GitRevisionRelation::Current,
            commits_behind: Some(0),
        });
    }
    let merge_base = exact_revision(&git_output(&[
        "-C".into(),
        reference_dir.clone(),
        "merge-base".into(),
        deployed_revision.clone(),
        upstream_revision.clone(),
    ])?)?;
    if merge_base == deployed_revision {
        let count = git_output(&[
            "-C".into(),
            reference_dir.clone(),
            "rev-list".into(),
            "--count".into(),
            format!("{deployed_revision}..{upstream_revision}"),
        ])?
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|count| *count > 0)?;
        return Some(NixcfgGitComparison {
            upstream_revision,
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(count),
        });
    }
    let relation = if merge_base == upstream_revision {
        GitRevisionRelation::Ahead
    } else {
        GitRevisionRelation::Diverged
    };
    Some(NixcfgGitComparison {
        upstream_revision,
        relation,
        commits_behind: None,
    })
}

fn safe_nixpkgs_channel_base_url(raw: &str) -> Option<Url> {
    let mut url = Url::parse(raw.trim()).ok()?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    if !url.path().ends_with('/') {
        let mut path = url.path().to_string();
        path.push('/');
        url.set_path(&path);
    }
    Some(url)
}

fn nixpkgs_channel_revision_url(channel: &str, base_url: &str) -> Option<Url> {
    if !pharos_core::valid_nix_channel(channel) {
        return None;
    }
    let base = safe_nixpkgs_channel_base_url(base_url)?;
    base.join(&format!("{channel}/git-revision")).ok()
}

fn safe_nixpkgs_channel_redirect(source: &Url, location: &str) -> Option<Url> {
    let target = source.join(location).ok()?;
    if target.scheme() != "https"
        || target.host_str().is_none()
        || !target.username().is_empty()
        || target.password().is_some()
        || target.query().is_some()
        || target.fragment().is_some()
        || !target.path().ends_with("/git-revision")
    {
        return None;
    }
    let same_host = target.host_str() == source.host_str()
        && target.port_or_known_default() == source.port_or_known_default();
    let official_release_redirect = source.host_str() == Some("channels.nixos.org")
        && target.host_str() == Some("releases.nixos.org")
        && target.path().starts_with("/nixos/");
    (same_host || official_release_redirect).then_some(target)
}

fn read_bounded_nixpkgs_revision(reader: impl Read) -> Option<String> {
    let mut body = String::new();
    reader
        .take(MAX_NIXPKGS_REVISION_BYTES + 1)
        .read_to_string(&mut body)
        .ok()?;
    ((body.len() as u64) <= MAX_NIXPKGS_REVISION_BYTES)
        .then_some(())
        .and_then(|()| exact_revision(&body))
}

fn fetch_nixpkgs_channel_revision(url: &Url) -> Option<String> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_connect(Some(Duration::from_secs(5)))
        .timeout_send_request(Some(Duration::from_secs(5)))
        .timeout_recv_response(Some(Duration::from_secs(10)))
        .timeout_recv_body(Some(Duration::from_secs(10)))
        .timeout_global(Some(NIXPKGS_CHANNEL_TIMEOUT))
        .max_redirects(0)
        .build()
        .into();
    let response = agent.get(url.as_str()).call().ok()?;
    if response.status().is_success() {
        return read_bounded_nixpkgs_revision(response.into_body().into_reader());
    }
    if !matches!(response.status().as_u16(), 301 | 302 | 307 | 308) {
        return None;
    }
    let location = response.headers().get("location")?.to_str().ok()?;
    let target = safe_nixpkgs_channel_redirect(url, location)?;
    let response = agent.get(target.as_str()).call().ok()?;
    response
        .status()
        .is_success()
        .then(|| read_bounded_nixpkgs_revision(response.into_body().into_reader()))?
}

fn nixpkgs_comparison_from_revision(
    evidence: &NixDeploymentEvidence,
    upstream_revision: &str,
) -> Option<NixpkgsGitComparison> {
    let upstream_revision = exact_revision(upstream_revision)?;
    Some(NixpkgsGitComparison {
        relation: if upstream_revision == evidence.nixpkgs_revision {
            NixpkgsRevisionRelation::Current
        } else {
            NixpkgsRevisionRelation::Different
        },
        upstream_revision,
    })
}

fn is_official_nixpkgs_git_remote(remote: &str) -> bool {
    safe_git_remote(remote).as_deref() == safe_git_remote(OFFICIAL_NIXPKGS_GIT_REMOTE).as_deref()
}

fn nixpkgs_comparison(evidence: &NixDeploymentEvidence) -> Option<NixpkgsGitComparison> {
    if let Some(base_url) = env_value("PHAROS_NIXPKGS_CHANNEL_BASE_URL") {
        let url = nixpkgs_channel_revision_url(&evidence.nixpkgs_channel, &base_url)?;
        let revision = fetch_nixpkgs_channel_revision(&url)?;
        return nixpkgs_comparison_from_revision(evidence, &revision);
    }

    let remote = safe_git_remote(&env_value("PHAROS_NIXPKGS_REMOTE_URL")?)?;
    if is_official_nixpkgs_git_remote(&remote) {
        let url = nixpkgs_channel_revision_url(
            &evidence.nixpkgs_channel,
            DEFAULT_NIXPKGS_CHANNEL_BASE_URL,
        )?;
        let revision = fetch_nixpkgs_channel_revision(&url)?;
        nixpkgs_comparison_from_revision(evidence, &revision)
    } else {
        nixpkgs_git_comparison_from_remote(evidence, &remote)
    }
}

fn nixpkgs_git_comparison_from_remote(
    evidence: &NixDeploymentEvidence,
    remote: &str,
) -> Option<NixpkgsGitComparison> {
    let remote_ref = safe_git_branch_ref(&format!("refs/heads/{}", evidence.nixpkgs_channel))?;
    let output = git_output(&[
        "ls-remote".into(),
        "--exit-code".into(),
        "--refs".into(),
        remote.to_string(),
        remote_ref.clone(),
    ])?;
    let mut fields = output.split_whitespace();
    let upstream_revision = exact_revision(fields.next()?)?;
    (fields.next()? == remote_ref && fields.next().is_none()).then_some(())?;
    Some(NixpkgsGitComparison {
        relation: if upstream_revision == evidence.nixpkgs_revision {
            NixpkgsRevisionRelation::Current
        } else {
            NixpkgsRevisionRelation::Different
        },
        upstream_revision,
    })
}

fn freshness_log_summary(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return "nix=n/a".to_string();
    }

    let generation = if freshness.deployment_evidence.is_some() {
        "verified"
    } else {
        "unverified"
    };
    let nixcfg = match freshness
        .nixcfg_comparison
        .as_ref()
        .map(|comparison| comparison.relation)
    {
        Some(GitRevisionRelation::Current) => "current",
        Some(GitRevisionRelation::Behind) => "behind",
        Some(GitRevisionRelation::Ahead) => "ahead",
        Some(GitRevisionRelation::Diverged) => "diverged",
        None => "unknown",
    };
    let nixpkgs = match freshness
        .nixpkgs_comparison
        .as_ref()
        .map(|comparison| comparison.relation)
    {
        Some(NixpkgsRevisionRelation::Current) => "current",
        Some(NixpkgsRevisionRelation::Different) => "different",
        None => "unknown",
    };
    format!("generation={generation}; nixcfg={nixcfg}; nixpkgs={nixpkgs}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationMode {
    Off,
    Env,
    IpApi,
    Command,
}

impl LocationMode {
    fn from_env_value(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("env") => Self::Env,
            Some("ip") | Some("ip-api") | Some("ipapi") | Some("geoip") => Self::IpApi,
            Some("command") | Some("cmd") | Some("provider-command") => Self::Command,
            _ => Self::Off,
        }
    }
}

const LOCATION_COMMAND_TIMEOUT_MS: u64 = 2_000;

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_f64(value: Option<String>) -> Option<f64> {
    value
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

fn parse_location_source(value: Option<String>, default: HostLocationSource) -> HostLocationSource {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("wifi") => HostLocationSource::Wifi,
        Some("ip") => HostLocationSource::Ip,
        Some("provider") => HostLocationSource::Provider,
        Some("unknown") => HostLocationSource::Unknown,
        _ => default,
    }
}

fn parse_u64(value: Option<String>) -> Option<u64> {
    value.and_then(|value| value.parse::<u64>().ok())
}

fn location_command_args_from_raw(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Vec<String>>(raw).ok()
}

fn location_command_args() -> Vec<String> {
    let Some(raw) = env_value("PHAROS_LOCATION_COMMAND_ARGS") else {
        return Vec::new();
    };
    match location_command_args_from_raw(&raw) {
        Some(args) => args,
        None => {
            eprintln!("pharos-beacon: location command args invalid");
            Vec::new()
        }
    }
}

fn location_command_timeout() -> Duration {
    let millis = parse_u64(env_value("PHAROS_LOCATION_COMMAND_TIMEOUT_MS"))
        .filter(|millis| (100..=30_000).contains(millis))
        .unwrap_or(LOCATION_COMMAND_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn location_from_env(now: i64) -> Option<HostLocation> {
    let location = HostLocation {
        latitude: parse_f64(env_value("PHAROS_LOCATION_LATITUDE"))?,
        longitude: parse_f64(env_value("PHAROS_LOCATION_LONGITUDE"))?,
        source: parse_location_source(
            env_value("PHAROS_LOCATION_SOURCE"),
            HostLocationSource::Unknown,
        ),
        accuracy_meters: parse_f64(env_value("PHAROS_LOCATION_ACCURACY_METERS")),
        precision_meters: parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS"))
            .or(Some(25_000.0)),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: env_value("PHAROS_LOCATION_LABEL"),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn json_f64(value: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_f64())
        .filter(|value| value.is_finite())
}

fn json_optional_f64(value: &serde_json::Value, key: &str) -> Option<f64> {
    value
        .get(key)
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite())
}

fn location_from_command_json(raw: &str, now: i64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let source = parse_location_source(
        value
            .get("source")
            .and_then(|source| source.as_str())
            .map(str::to_string),
        HostLocationSource::Provider,
    );
    let location = HostLocation {
        latitude: json_f64(&value, &["latitude", "lat"])?,
        longitude: json_f64(&value, &["longitude", "lon"])?,
        source,
        accuracy_meters: json_optional_f64(&value, "accuracy_meters"),
        precision_meters: json_optional_f64(&value, "precision_meters").or(Some(25_000.0)),
        observed_at: value
            .get("observed_at")
            .and_then(|observed_at| observed_at.as_i64())
            .or(Some(now)),
        stale: false,
        manual_override: false,
        label: value
            .get("label")
            .and_then(|label| label.as_str())
            .map(str::to_string),
    };
    location.validate_contract().ok()?;
    Some(location)
}

#[derive(Debug)]
struct BoundedOutput {
    bytes: Vec<u8>,
    truncated: bool,
}

fn drain_bounded(
    mut pipe: impl Read + Send + 'static,
    limit: usize,
) -> mpsc::Receiver<Result<BoundedOutput, &'static str>> {
    let (sender, receiver) = mpsc::sync_channel(1);
    thread::spawn(move || {
        let mut retained = Vec::with_capacity(limit.min(8 * 1024));
        let mut truncated = false;
        let mut chunk = [0_u8; 8 * 1024];
        let result = loop {
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    break Ok(BoundedOutput {
                        bytes: retained,
                        truncated,
                    });
                }
                Ok(read) => {
                    let remaining = limit.saturating_sub(retained.len());
                    let keep = remaining.min(read);
                    retained.extend_from_slice(&chunk[..keep]);
                    truncated |= keep < read;
                }
                Err(_) => break Err("output_read"),
            }
        };
        let _ = sender.send(result);
    });
    receiver
}

fn collect_bounded(
    receiver: &mpsc::Receiver<Result<BoundedOutput, &'static str>>,
    deadline: Instant,
) -> Result<BoundedOutput, &'static str> {
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "output_timeout")?
}

#[cfg(unix)]
fn isolate_process_group(command: &mut Command) {
    use std::os::unix::process::CommandExt;
    command.process_group(0);
}

#[cfg(not(unix))]
fn isolate_process_group(_command: &mut Command) {}

fn terminate_process_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    if let Ok(group) = i32::try_from(child.id()) {
        // The child is started as its own process group so inherited collector
        // pipes cannot survive in a background descendant past the deadline.
        unsafe {
            libc::kill(-group, libc::SIGKILL);
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn wait_for_child(
    child: &mut std::process::Child,
    deadline: Instant,
) -> Result<ExitStatus, &'static str> {
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) if Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20));
            }
            Ok(None) => {
                terminate_process_tree(child);
                return Err("timeout");
            }
            Err(_) => {
                terminate_process_tree(child);
                return Err("wait");
            }
        }
    }
}

fn output_string(output: BoundedOutput) -> Result<String, &'static str> {
    if output.truncated {
        return Err("output_limit");
    }
    String::from_utf8(output.bytes).map_err(|_| "output_encoding")
}

fn run_location_command(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<String, &'static str> {
    let mut command = Command::new(command);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    isolate_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| "spawn")?;
    let output = child
        .stdout
        .take()
        .map(|pipe| drain_bounded(pipe, LOCATION_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stdout")?;
    let deadline = Instant::now() + timeout;
    let status = wait_for_child(&mut child, deadline)?;
    let stdout = match collect_bounded(&output, deadline).and_then(output_string) {
        Ok(stdout) => stdout,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    if status.success() {
        Ok(stdout)
    } else {
        Err("exit")
    }
}

fn location_from_command(now: i64) -> Option<HostLocation> {
    let Some(command) = env_value("PHAROS_LOCATION_COMMAND") else {
        eprintln!("pharos-beacon: location command not configured");
        return None;
    };
    let raw = match run_location_command(
        &command,
        &location_command_args(),
        location_command_timeout(),
    ) {
        Ok(raw) => raw,
        Err(reason) => {
            eprintln!("pharos-beacon: location command failed: {reason}");
            return None;
        }
    };
    match location_from_command_json(&raw, now) {
        Some(location) => Some(location),
        None => {
            eprintln!("pharos-beacon: location command returned invalid location");
            None
        }
    }
}

fn location_label_from_parts(
    city: Option<&str>,
    region: Option<&str>,
    country: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    for part in [city, region, country].into_iter().flatten() {
        let part = part.trim();
        if !part.is_empty()
            && !parts
                .iter()
                .any(|existing: &&str| existing.eq_ignore_ascii_case(part))
        {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn location_from_ip_api_json(raw: &str, now: i64, precision_meters: f64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    if value
        .get("status")
        .and_then(|status| status.as_str())
        .is_some_and(|status| status != "success")
    {
        return None;
    }
    let location = HostLocation {
        latitude: value.get("lat")?.as_f64()?,
        longitude: value.get("lon")?.as_f64()?,
        source: HostLocationSource::Ip,
        accuracy_meters: None,
        precision_meters: Some(precision_meters),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: location_label_from_parts(
            value.get("city").and_then(|v| v.as_str()),
            value.get("regionName").and_then(|v| v.as_str()),
            value.get("countryCode").and_then(|v| v.as_str()),
        ),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn location_from_ip_api(now: i64) -> Option<HostLocation> {
    let url = env_value("PHAROS_LOCATION_IP_API_URL").unwrap_or_else(|| {
        "http://ip-api.com/json/?fields=status,lat,lon,city,regionName,countryCode".to_string()
    });
    let precision = parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS")).unwrap_or(50_000.0);
    let mut response = ureq::get(&url)
        .config()
        .timeout_global(Some(std::time::Duration::from_secs(3)))
        .max_redirects(0)
        .build()
        .call()
        .ok()?;
    let raw = response.body_mut().read_to_string().ok()?;
    location_from_ip_api_json(&raw, now, precision)
}

fn collect_location(now: i64) -> Option<HostLocation> {
    match LocationMode::from_env_value(env_value("PHAROS_LOCATION_MODE")) {
        LocationMode::Off => None,
        LocationMode::Env => location_from_env(now),
        LocationMode::IpApi => location_from_ip_api(now),
        LocationMode::Command => location_from_command(now),
    }
}

fn location_log_summary(location: Option<&HostLocation>) -> String {
    let Some(location) = location else {
        return "location=off".to_string();
    };
    let source = match location.source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared
        | HostLocationSource::Fallback
        | HostLocationSource::Unknown => "unknown",
    };
    let accuracy = location
        .accuracy_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    let precision = location
        .precision_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    format!("location={source}; accuracy={accuracy}; precision={precision}")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackupMode {
    Off,
    Auto,
    Restic,
    StatusFile,
    Command,
}

impl BackupMode {
    fn from_env_value(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("off") | Some("none") | Some("disabled") => Self::Off,
            Some("restic") => Self::Restic,
            Some("status-file") | Some("file") => Self::StatusFile,
            Some("command") | Some("cmd") => Self::Command,
            _ => Self::Auto,
        }
    }
}

const BACKUP_COMMAND_TIMEOUT_MS: u64 = 5_000;
const BACKUP_COMMAND_OUTPUT_LIMIT_BYTES: usize = 128 * 1024;
const DEFAULT_BACKUP_STALE_AFTER_SECS: i64 = 36 * 60 * 60;

#[derive(Debug)]
struct CommandCapture {
    success: bool,
    stdout: String,
    stderr: String,
}

fn backup_stale_after_secs() -> i64 {
    parse_u64(env_value("PHAROS_BACKUP_STALE_AFTER_SECS"))
        .and_then(|seconds| i64::try_from(seconds).ok())
        .filter(|seconds| (60..=31_536_000).contains(seconds))
        .unwrap_or(DEFAULT_BACKUP_STALE_AFTER_SECS)
}

fn backup_command_timeout() -> Duration {
    let millis = parse_u64(env_value("PHAROS_BACKUP_COMMAND_TIMEOUT_MS"))
        .filter(|millis| (100..=120_000).contains(millis))
        .unwrap_or(BACKUP_COMMAND_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn backup_command_args() -> Vec<String> {
    let Some(raw) = env_value("PHAROS_BACKUP_COMMAND_ARGS") else {
        return Vec::new();
    };
    match location_command_args_from_raw(&raw) {
        Some(args) => args,
        None => {
            eprintln!("pharos-beacon: backup command args invalid");
            Vec::new()
        }
    }
}

fn safe_backup_text(value: &str) -> bool {
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
}

fn safe_backup_env(key: &str) -> Option<String> {
    env_value(key).filter(|value| safe_backup_text(value))
}

fn validated_backup_observation(observation: BackupObservation) -> Option<BackupObservation> {
    observation.validate_contract().ok()?;
    Some(observation)
}

fn restic_observation_base(state: BackupPostureState, summary: &str) -> BackupObservation {
    BackupObservation {
        id: safe_backup_env("PHAROS_BACKUP_ID").unwrap_or_else(|| "restic-main".to_string()),
        label: safe_backup_env("PHAROS_BACKUP_LABEL")
            .unwrap_or_else(|| "Restic backup".to_string()),
        engine: BackupEngine::Restic,
        state,
        configured: BackupConfiguredState::Enabled,
        summary: summary.to_string(),
        target_label: safe_backup_env("PHAROS_BACKUP_TARGET_LABEL")
            .or_else(|| Some("off-box repository".to_string())),
        repository_id: safe_backup_env("PHAROS_BACKUP_REPOSITORY_ID"),
        schedule: safe_backup_env("PHAROS_BACKUP_SCHEDULE"),
        next_run_at: None,
        last_attempt_at: None,
        last_attempt_state: None,
        last_success_at: None,
        snapshot_count: None,
        total_bytes: None,
        latest_snapshot_bytes: None,
        last_check_at: None,
        last_check_state: None,
        restore_validation: None,
    }
}

fn backup_observations_from_json(raw: &str) -> Result<Vec<BackupObservation>, &'static str> {
    let parsed = serde_json::from_str::<Vec<BackupObservation>>(raw)
        .or_else(|_| serde_json::from_str::<BackupObservation>(raw).map(|one| vec![one]))
        .map_err(|_| "json")?;
    let mut observations = Vec::new();
    for observation in parsed {
        observation.validate_contract().map_err(|_| "contract")?;
        observations.push(observation);
    }
    Ok(observations)
}

fn collect_backup_status_file() -> Vec<BackupObservation> {
    let Some(path) = env_value("PHAROS_BACKUP_STATUS_FILE") else {
        return Vec::new();
    };
    let Ok(raw) = std::fs::read_to_string(&path) else {
        eprintln!("pharos-beacon: backup status file unavailable");
        return vec![restic_observation_base(
            BackupPostureState::Unknown,
            "backup status file unavailable",
        )]
        .into_iter()
        .filter_map(validated_backup_observation)
        .collect();
    };
    match backup_observations_from_json(&raw) {
        Ok(observations) => observations,
        Err(reason) => {
            eprintln!("pharos-beacon: backup status file invalid: {reason}");
            vec![restic_observation_base(
                BackupPostureState::Unknown,
                "backup status file invalid",
            )]
            .into_iter()
            .filter_map(validated_backup_observation)
            .collect()
        }
    }
}

fn run_capture_command(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<CommandCapture, &'static str> {
    let mut command = Command::new(command);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    isolate_process_group(&mut command);
    let mut child = command.spawn().map_err(|_| "spawn")?;
    let stdout = child
        .stdout
        .take()
        .map(|pipe| drain_bounded(pipe, BACKUP_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stdout")?;
    let stderr = child
        .stderr
        .take()
        .map(|pipe| drain_bounded(pipe, BACKUP_COMMAND_OUTPUT_LIMIT_BYTES))
        .ok_or("stderr")?;
    let deadline = Instant::now() + timeout;
    let status = wait_for_child(&mut child, deadline)?;
    let stdout = match collect_bounded(&stdout, deadline).and_then(output_string) {
        Ok(stdout) => stdout,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    let stderr = match collect_bounded(&stderr, deadline).and_then(output_string) {
        Ok(stderr) => stderr,
        Err(error) => {
            terminate_process_tree(&mut child);
            return Err(error);
        }
    };
    Ok(CommandCapture {
        success: status.success(),
        stdout,
        stderr,
    })
}

fn collect_backup_command(now: i64) -> Vec<BackupObservation> {
    let Some(command) = env_value("PHAROS_BACKUP_COMMAND") else {
        return Vec::new();
    };
    let result = run_capture_command(&command, &backup_command_args(), backup_command_timeout());
    match result {
        Ok(output) if output.success => match backup_observations_from_json(&output.stdout) {
            Ok(observations) => observations,
            Err(reason) => {
                eprintln!("pharos-beacon: backup command returned invalid JSON: {reason}");
                vec![command_backup_observation(
                    BackupPostureState::Unknown,
                    "backup command returned invalid status",
                    now,
                )]
            }
        },
        Ok(_) => vec![command_backup_observation(
            BackupPostureState::Failed,
            "backup command failed",
            now,
        )],
        Err(reason) => {
            eprintln!("pharos-beacon: backup command failed: {reason}");
            vec![command_backup_observation(
                BackupPostureState::Unknown,
                "backup command unavailable",
                now,
            )]
        }
    }
}

fn command_backup_observation(
    state: BackupPostureState,
    summary: &str,
    now: i64,
) -> BackupObservation {
    BackupObservation {
        id: safe_backup_env("PHAROS_BACKUP_ID").unwrap_or_else(|| "backup-command".to_string()),
        label: safe_backup_env("PHAROS_BACKUP_LABEL")
            .unwrap_or_else(|| "Backup collector".to_string()),
        engine: BackupEngine::Unknown,
        state,
        configured: BackupConfiguredState::Unknown,
        summary: summary.to_string(),
        target_label: safe_backup_env("PHAROS_BACKUP_TARGET_LABEL"),
        repository_id: safe_backup_env("PHAROS_BACKUP_REPOSITORY_ID"),
        schedule: safe_backup_env("PHAROS_BACKUP_SCHEDULE"),
        next_run_at: None,
        last_attempt_at: Some(now),
        last_attempt_state: if state == BackupPostureState::Failed {
            Some(BackupRunState::Failed)
        } else {
            Some(BackupRunState::Unknown)
        },
        last_success_at: None,
        snapshot_count: None,
        total_bytes: None,
        latest_snapshot_bytes: None,
        last_check_at: None,
        last_check_state: None,
        restore_validation: None,
    }
}

fn restic_repository_args_from_backup_options(raw: &str) -> Vec<String> {
    let parts: Vec<&str> = raw.split_whitespace().collect();
    let mut args = Vec::new();
    let mut idx = 0;
    while idx < parts.len() {
        match parts[idx] {
            "-r" | "--repo" | "--repository" => {
                if let Some(repo) = parts.get(idx + 1) {
                    args.push("-r".to_string());
                    args.push((*repo).to_string());
                    idx += 2;
                    continue;
                }
            }
            "--repository-file" => {
                if let Some(repo) = parts.get(idx + 1) {
                    args.push("--repository-file".to_string());
                    args.push((*repo).to_string());
                    idx += 2;
                    continue;
                }
            }
            value if value.starts_with("-r=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("-r=").to_string());
            }
            value if value.starts_with("--repo=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("--repo=").to_string());
            }
            value if value.starts_with("--repository=") => {
                args.push("-r".to_string());
                args.push(value.trim_start_matches("--repository=").to_string());
            }
            value if value.starts_with("--repository-file=") => {
                args.push("--repository-file".to_string());
                args.push(value.trim_start_matches("--repository-file=").to_string());
            }
            _ => {}
        }
        idx += 1;
    }
    args
}

fn restic_repository_args() -> Vec<String> {
    if let Some(repo) = env_value("RESTIC_REPOSITORY") {
        return vec!["-r".to_string(), repo];
    }
    if let Some(repo_file) = env_value("RESTIC_REPOSITORY_FILE") {
        return vec!["--repository-file".to_string(), repo_file];
    }
    env_value("RESTIC_BACKUP_OPTIONS")
        .map(|raw| restic_repository_args_from_backup_options(&raw))
        .unwrap_or_default()
}

fn collect_restic_repository(now: i64, explicit: bool) -> Vec<BackupObservation> {
    let repository_args = restic_repository_args();
    if repository_args.is_empty() {
        if explicit {
            return vec![BackupObservation {
                configured: BackupConfiguredState::Missing,
                ..restic_observation_base(
                    BackupPostureState::NotConfigured,
                    "restic repository not configured",
                )
            }]
            .into_iter()
            .filter_map(validated_backup_observation)
            .collect();
        }
        return Vec::new();
    }

    let restic = env_value("PHAROS_RESTIC_COMMAND").unwrap_or_else(|| "restic".to_string());
    let mut args = repository_args;
    args.extend([
        "snapshots".to_string(),
        "--json".to_string(),
        "--latest".to_string(),
        "1".to_string(),
    ]);
    match run_capture_command(&restic, &args, backup_command_timeout()) {
        Ok(output) if output.success => {
            vec![restic_snapshot_observation(
                &output.stdout,
                now,
                backup_stale_after_secs(),
            )]
        }
        Ok(output) => vec![restic_error_observation(&output.stderr, now)],
        Err("spawn") if explicit => vec![BackupObservation {
            configured: BackupConfiguredState::Unknown,
            ..restic_observation_base(BackupPostureState::Unknown, "restic command unavailable")
        }]
        .into_iter()
        .filter_map(validated_backup_observation)
        .collect(),
        Err("spawn") => Vec::new(),
        Err(_) => vec![restic_error_observation("timeout", now)],
    }
}

fn restic_error_observation(stderr: &str, now: i64) -> BackupObservation {
    let lower = stderr.to_ascii_lowercase();
    let (state, summary) = if lower.contains("lock") {
        (BackupPostureState::Warning, "restic repository locked")
    } else if lower.contains("no repository")
        || lower.contains("repository does not exist")
        || lower.contains("unable to open config file")
    {
        (BackupPostureState::Missing, "restic repository missing")
    } else if lower.contains("password")
        || lower.contains("authentication")
        || lower.contains("permission denied")
        || lower.contains("wrong password")
    {
        (BackupPostureState::Failed, "restic authentication failed")
    } else {
        (BackupPostureState::Failed, "restic snapshot probe failed")
    };
    BackupObservation {
        last_attempt_at: Some(now),
        last_attempt_state: Some(BackupRunState::Failed),
        ..restic_observation_base(state, summary)
    }
}

fn parse_restic_latest_snapshot(raw: &str) -> Result<(i64, u64), &'static str> {
    let value: serde_json::Value = serde_json::from_str(raw).map_err(|_| "json")?;
    let snapshots = value.as_array().ok_or("array")?;
    let mut latest = None;
    for snapshot in snapshots {
        let Some(time) = snapshot.get("time").and_then(|time| time.as_str()) else {
            continue;
        };
        let parsed = parse_rfc3339_unix(time).ok_or("time")?;
        latest = Some(latest.map_or(parsed, |existing: i64| existing.max(parsed)));
    }
    let count = u64::try_from(snapshots.len()).unwrap_or(u64::MAX);
    latest.map(|time| (time, count)).ok_or("empty")
}

fn restic_snapshot_observation(raw: &str, now: i64, stale_after_secs: i64) -> BackupObservation {
    match parse_restic_latest_snapshot(raw) {
        Ok((last_success_at, snapshot_count)) => {
            let age = now.saturating_sub(last_success_at);
            let state = if age > stale_after_secs {
                BackupPostureState::Stale
            } else {
                BackupPostureState::Healthy
            };
            let summary = if state == BackupPostureState::Stale {
                "last restic snapshot is stale"
            } else {
                "last restic snapshot is fresh"
            };
            BackupObservation {
                state,
                summary: summary.to_string(),
                last_attempt_at: Some(last_success_at),
                last_attempt_state: Some(BackupRunState::Succeeded),
                last_success_at: Some(last_success_at),
                snapshot_count: Some(snapshot_count),
                ..restic_observation_base(state, summary)
            }
        }
        Err("empty") => BackupObservation {
            configured: BackupConfiguredState::Enabled,
            last_attempt_at: Some(now),
            last_attempt_state: Some(BackupRunState::Unknown),
            snapshot_count: Some(0),
            ..restic_observation_base(BackupPostureState::Missing, "no restic snapshots observed")
        },
        Err(_) => BackupObservation {
            configured: BackupConfiguredState::Unknown,
            last_attempt_at: Some(now),
            last_attempt_state: Some(BackupRunState::Unknown),
            ..restic_observation_base(
                BackupPostureState::Unknown,
                "restic snapshot metadata invalid",
            )
        },
    }
}

fn parse_rfc3339_unix(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if raw.len() < 20 {
        return None;
    }
    let year = raw.get(0..4)?.parse::<i64>().ok()?;
    let month = raw.get(5..7)?.parse::<i64>().ok()?;
    let day = raw.get(8..10)?.parse::<i64>().ok()?;
    let hour = raw.get(11..13)?.parse::<i64>().ok()?;
    let minute = raw.get(14..16)?.parse::<i64>().ok()?;
    let second = raw.get(17..19)?.parse::<i64>().ok()?;
    let after_time = raw.get(19..)?;
    let tz_start = after_time.find(['Z', '+', '-']).map(|index| 19 + index)?;
    let tz = raw.get(tz_start..)?;
    let offset_seconds = if tz == "Z" {
        0
    } else {
        let sign = match tz.as_bytes().first().copied()? {
            b'+' => 1,
            b'-' => -1,
            _ => return None,
        };
        let hours = tz.get(1..3)?.parse::<i64>().ok()?;
        let minutes = tz.get(4..6)?.parse::<i64>().ok()?;
        sign * ((hours * 60 + minutes) * 60)
    };
    if !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
        || !(0..=23).contains(&hour)
        || !(0..=59).contains(&minute)
        || !(0..=60).contains(&second)
    {
        return None;
    }
    Some(
        days_from_civil(year, month, day) * 86_400 + hour * 3600 + minute * 60 + second
            - offset_seconds,
    )
}

fn days_from_civil(mut year: i64, month: i64, day: i64) -> i64 {
    year -= if month <= 2 { 1 } else { 0 };
    let era = if year >= 0 { year } else { year - 399 } / 400;
    let year_of_era = year - era * 400;
    let month_prime = month + if month > 2 { -3 } else { 9 };
    let day_of_year = (153 * month_prime + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

fn collect_backup_observations(now: i64) -> Vec<BackupObservation> {
    match BackupMode::from_env_value(env_value("PHAROS_BACKUP_MODE")) {
        BackupMode::Off => Vec::new(),
        BackupMode::StatusFile => collect_backup_status_file(),
        BackupMode::Command => collect_backup_command(now),
        BackupMode::Restic => collect_restic_repository(now, true),
        BackupMode::Auto => {
            let mut observations = collect_backup_status_file();
            if observations.is_empty() {
                observations = collect_backup_command(now);
            }
            if observations.is_empty() {
                observations = collect_restic_repository(now, false);
            }
            observations
        }
    }
}

fn backup_log_summary(observations: &[BackupObservation]) -> String {
    if observations.is_empty() {
        return "backup=not-observed".to_string();
    }
    let state = if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Failed)
    {
        "failed"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Missing)
    {
        "missing"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Stale)
    {
        "stale"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Warning)
    {
        "warning"
    } else if observations
        .iter()
        .any(|observation| observation.state == BackupPostureState::Healthy)
    {
        "healthy"
    } else {
        "unknown"
    };
    format!("backup={state}; backup_observations={}", observations.len())
}

fn success_log_line(
    host: &str,
    endpoint: &str,
    status: u16,
    freshness: &NixFreshness,
    location: Option<&HostLocation>,
    backup_observations: &[BackupObservation],
) -> String {
    format!(
        "pharos-beacon: reported {host} -> {endpoint} (HTTP {status}; {}; {}; {})",
        freshness_log_summary(freshness),
        location_log_summary(location),
        backup_log_summary(backup_observations)
    )
}

fn reporting_interval() -> Result<Option<u64>, &'static str> {
    match std::env::var("PHAROS_INTERVAL") {
        Ok(raw) => {
            let seconds = raw.parse::<u64>().map_err(|_| "invalid_interval")?;
            RequestDeadlines::for_cadence(seconds)?;
            Ok(Some(seconds))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(std::env::VarError::NotUnicode(_)) => Err("invalid_interval"),
    }
}

fn main() {
    let base = env_value("PHAROS_URL").unwrap_or_else(|| {
        eprintln!("pharos-beacon: PHAROS_URL is required");
        std::process::exit(2);
    });
    let endpoint = report_endpoint(&base).unwrap_or_else(|_| {
        eprintln!("pharos-beacon: PHAROS_URL is invalid or unsafe");
        std::process::exit(2);
    });
    let host = hostname();
    let is_nix = Path::new("/etc/NIXOS").exists();
    let dir = nixcfg_dir();
    let role = std::env::var("PHAROS_ROLE").unwrap_or_else(|_| "server".into());
    let token = bearer_token().unwrap_or_else(|error| {
        eprintln!("pharos-beacon: {error}");
        std::process::exit(2);
    });
    let preferences_path = env_value("PHAROS_PREFERENCES_FILE").map(std::path::PathBuf::from);
    let mut preferences = HostPreferences::default();
    let mut preferences_error_reported = false;
    let mut preferences_apply_error: Option<PreferencesApplyError> = None;

    // PHAROS_INTERVAL (secs) set => loop forever (recurring service);
    // unset => report once and exit (one-shot / timer-driven).
    let interval = reporting_interval().unwrap_or_else(|_| {
        eprintln!(
            "pharos-beacon: PHAROS_INTERVAL must be between {MIN_HEARTBEAT_INTERVAL_SECS} and {MAX_HEARTBEAT_INTERVAL_SECS} seconds"
        );
        std::process::exit(2);
    });
    let beat = interval.unwrap_or(60);
    let deadlines = RequestDeadlines::for_cadence(beat).expect("default cadence is valid");
    let agent = deadlines.agent();
    let mut last_report_rtt_ms: Option<u64> = None;
    let mut consecutive_failures = 0_u32;
    systemd_notify("READY=1\nSTATUS=Waiting for first successful report");

    loop {
        if let Some(path) = preferences_path.as_deref() {
            match read_host_preferences(path, &host) {
                Ok(next) => {
                    preferences = next;
                    preferences_error_reported = false;
                }
                Err(error) if !preferences_error_reported => {
                    eprintln!("pharos-beacon: {error}; keeping last valid host preferences");
                    preferences_error_reported = true;
                }
                Err(_) => {}
            }
        }
        let freshness = if is_nix {
            let evidence = read_deployment_evidence(&deployment_evidence_path());
            let matching_lock = match (dir.as_deref(), evidence.as_ref()) {
                (Some(dir), Some(evidence)) => matching_flake_lock(dir, evidence),
                _ => None,
            };
            let nixpkgs = match (matching_lock.as_ref(), evidence.as_ref()) {
                (Some(lock), Some(evidence)) => nixpkgs_freshness(lock, evidence),
                _ => None,
            };
            let nixcfg_comparison = match (dir.as_deref(), evidence.as_ref()) {
                (Some(dir), Some(evidence)) => {
                    nixcfg_git_comparison(dir, &evidence.source_revision)
                }
                _ => None,
            };
            let channel_comparison = evidence.as_ref().and_then(nixpkgs_comparison);
            NixFreshness {
                applicable: true,
                flake_lock_age_days: matching_lock.as_ref().and_then(flake_lock_age_days),
                commits_behind: nixcfg_comparison
                    .as_ref()
                    .and_then(|comparison| comparison.commits_behind),
                nixpkgs_age_days: evidence
                    .as_ref()
                    .and_then(|evidence| days_since(evidence.nixpkgs_last_modified)),
                nixpkgs_channel: evidence
                    .as_ref()
                    .map(|evidence| evidence.nixpkgs_channel.clone()),
                secondary_nixpkgs: nixpkgs.and_then(|freshness| freshness.secondary),
                deployment_evidence: evidence,
                nixcfg_comparison,
                nixpkgs_comparison: channel_comparison,
            }
        } else {
            NixFreshness::default()
        };
        let mut service_observations = vec![ServiceObservation::nix_freshness(&freshness)];
        if let Some(error) = preferences_apply_error {
            service_observations.push(error.observation());
        }
        let observed_at = now_unix();
        let kernel = collect_kernel_posture(is_nix, observed_at);
        let location = collect_location(observed_at);
        let backup_observations = collect_backup_observations(observed_at);
        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: host.clone(),
            role: role.clone(),
            is_nix,
            heartbeat_interval_secs: beat,
            freshness,
            kernel: Some(kernel),
            service_observations,
            backup_observations,
            inbound_rtt_ms: last_report_rtt_ms,
            location,
            preferences: preferences.clone(),
        };
        if report.validate_contract().is_err() {
            eprintln!("pharos-beacon: locally collected report violates the report contract");
            std::process::exit(2);
        }
        let body = serde_json::to_string(&report).expect("serialize report");
        let mut request = agent
            .post(&endpoint.request_url)
            .header("Content-Type", "application/json");
        if let Some(token) = &token {
            request = request.header("Authorization", &format!("Bearer {token}"));
        }
        let started = Instant::now();
        let report_succeeded = match request.send(body.as_str()) {
            Ok(resp) if resp.status().is_success() => {
                let status = resp.status().as_u16();
                last_report_rtt_ms = Some(report_rtt_millis(started.elapsed()));
                consecutive_failures = 0;
                systemd_notify("WATCHDOG=1\nSTATUS=Last report succeeded");
                println!(
                    "{}",
                    success_log_line(
                        &host,
                        &endpoint.safe_origin,
                        status,
                        &report.freshness,
                        report.location.as_ref(),
                        &report.backup_observations
                    )
                );
                match apply_report_http_response(resp, &host, is_nix, preferences_path.as_deref()) {
                    Ok(Some(applied)) => {
                        preferences = applied;
                        preferences_apply_error = None;
                        println!("pharos-beacon: applied pending host settings");
                    }
                    Ok(None) => {
                        preferences_apply_error = None;
                    }
                    Err(error) => {
                        preferences_apply_error = Some(error);
                        eprintln!(
                            "pharos-beacon: pending host settings were not applied ({})",
                            error.code()
                        );
                    }
                }
                true
            }
            Ok(_) => {
                last_report_rtt_ms = None;
                consecutive_failures = consecutive_failures.saturating_add(1);
                systemd_notify("STATUS=Report failed; retrying");
                eprintln!("pharos-beacon: report failed (unexpected HTTP status)");
                false
            }
            Err(_) => {
                last_report_rtt_ms = None;
                consecutive_failures = consecutive_failures.saturating_add(1);
                systemd_notify("STATUS=Report failed; retrying");
                eprintln!("pharos-beacon: report failed (transport or HTTP error)");
                false
            }
        };
        let Some(cadence) = interval else {
            if !report_succeeded {
                std::process::exit(1);
            }
            break;
        };
        if report_succeeded {
            thread::sleep(Duration::from_secs(cadence));
        } else {
            thread::sleep(retry_delay(cadence, consecutive_failures, jitter_seed()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kernel_fixture(label: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "pharos-kernel-{}-{nonce}-{label}",
            std::process::id()
        ))
    }

    fn write_kernel_fixture(root: &Path, running: &str, expected: &[&str]) -> (PathBuf, PathBuf) {
        let running_path = root.join("osrelease");
        let expected_path = root.join("modules");
        std::fs::create_dir_all(&expected_path).expect("create module fixture");
        std::fs::write(&running_path, running).expect("write running version");
        for version in expected {
            std::fs::create_dir(expected_path.join(version)).expect("create version fixture");
        }
        (running_path, expected_path)
    }

    #[test]
    fn beacon_reads_exact_nixcfg_host_preferences_schema() {
        let raw = r##"{
          "schema": "inspr.pharos.host-preferences.v1",
          "version": 1,
          "hosts": {
            "gpc0": {
              "accent": "#9868d0",
              "kind": "workstation",
              "alerts": {
                "suppress_backup": false,
                "suppress_down": true,
                "suppress_nix_freshness": true
              }
            }
          }
        }"##;

        let preferences = parse_host_preferences(raw, "gpc0").expect("preferences parse");
        assert_eq!(preferences.accent.as_deref(), Some("#9868d0"));
        assert_eq!(preferences.kind, pharos_core::HostKind::Workstation);
        assert!(preferences.alerts.suppress_down);
        assert!(preferences.alerts.suppress_nix_freshness);
    }

    #[test]
    fn beacon_rejects_unknown_preferences_and_keeps_previous_state_available() {
        let extended = r##"{
          "schema": "inspr.pharos.host-preferences.v1",
          "version": 1,
          "hosts": {
            "gpc0": {
              "accent": "#9868d0",
              "kind": "workstation",
              "alerts": {
                "suppress_backup": false,
                "suppress_down": false,
                "suppress_nix_freshness": false
              },
              "command": "rebuild"
            }
          }
        }"##;
        let previous = HostPreferences::default();

        assert!(parse_host_preferences(extended, "gpc0").is_err());
        assert!(parse_host_preferences(
            r#"{"schema":"inspr.pharos.host-preferences.v1","version":1,"hosts":{}}"#,
            "gpc0"
        )
        .is_err());
        assert_eq!(previous, HostPreferences::default());
    }

    #[test]
    fn pending_preferences_are_atomically_written_as_the_shared_registry() {
        let root = kernel_fixture("pending-preferences");
        std::fs::create_dir(&root).expect("create preferences fixture");
        let path = root.join("host-preferences.json");
        let preferences = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            kind: pharos_core::HostKind::Workstation,
            alerts: pharos_core::HostAlertPreferences {
                suppress_down: false,
                suppress_backup: true,
                suppress_nix_freshness: false,
            },
        };
        let response = HostReportResponse::pending("gpc0", preferences.clone())
            .expect("pending response validates");
        let body = serde_json::to_string(&response).expect("response serializes");

        let applied = apply_report_response(&body, "gpc0", false, Some(&path))
            .expect("pending preferences apply");
        assert_eq!(applied, Some(preferences.clone()));
        assert_eq!(
            read_host_preferences(&path, "gpc0").expect("written registry parses"),
            preferences
        );
        #[cfg(unix)]
        assert_eq!(
            std::fs::metadata(&path)
                .expect("preferences metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_dir(&root)
                .expect("fixture directory readable")
                .count(),
            1,
            "atomic apply must not leave temporary files behind"
        );
        std::fs::remove_dir_all(root).expect("remove preferences fixture");
    }

    #[test]
    fn invalid_or_misdirected_pending_preferences_keep_the_previous_file() {
        let root = kernel_fixture("invalid-pending-preferences");
        std::fs::create_dir(&root).expect("create preferences fixture");
        let path = root.join("host-preferences.json");
        let previous = HostPreferences {
            accent: Some("#1f7fb5".to_string()),
            ..Default::default()
        };
        let initial = HostReportResponse::pending("gpc0", previous.clone())
            .expect("initial response validates");
        apply_report_response(
            &serde_json::to_string(&initial).expect("initial response serializes"),
            "gpc0",
            false,
            Some(&path),
        )
        .expect("initial preferences apply");
        let previous_bytes = std::fs::read(&path).expect("read previous registry");

        let invalid = r##"{
          "schema":"inspr.pharos.report-response.v1",
          "version":1,
          "pending_preferences":{
            "schema":"inspr.pharos.host-preferences.v1",
            "version":1,
            "hosts":{
              "gpc0":{
                "accent":"#48b8a8",
                "kind":"workstation",
                "alerts":{},
                "command":"rebuild"
              }
            }
          }
        }"##;
        assert_eq!(
            apply_report_response(invalid, "gpc0", false, Some(&path)),
            Err(PreferencesApplyError::InvalidResponse)
        );

        let wrong_host = HostReportResponse::pending(
            "athena",
            HostPreferences {
                accent: Some("#48b8a8".to_string()),
                ..Default::default()
            },
        )
        .expect("other host response validates for its host");
        assert_eq!(
            apply_report_response(
                &serde_json::to_string(&wrong_host).expect("response serializes"),
                "gpc0",
                false,
                Some(&path),
            ),
            Err(PreferencesApplyError::HostMismatch)
        );
        assert_eq!(
            std::fs::read(&path).expect("previous registry remains"),
            previous_bytes
        );
        std::fs::remove_dir_all(root).expect("remove preferences fixture");
    }

    #[test]
    fn pending_preferences_require_a_non_nix_host_and_configured_file() {
        let response = HostReportResponse::pending(
            "gpc0",
            HostPreferences {
                accent: Some("#48b8a8".to_string()),
                ..Default::default()
            },
        )
        .expect("pending response validates");
        let body = serde_json::to_string(&response).expect("response serializes");

        assert_eq!(
            apply_report_response(&body, "gpc0", false, None),
            Err(PreferencesApplyError::NotConfigured)
        );
        assert_eq!(
            apply_report_response(
                &body,
                "gpc0",
                true,
                Some(Path::new("/unused/preferences.json")),
            ),
            Err(PreferencesApplyError::UnsupportedOnNix)
        );
        let observation = PreferencesApplyError::WriteFailed.observation();
        assert_eq!(observation.id, "host-preferences");
        assert_eq!(observation.state, ServiceObservationState::Warning);
        assert_eq!(
            observation.summary,
            "settings apply failed: atomic_write_failed"
        );
    }

    #[test]
    fn pending_preferences_response_body_is_bounded() {
        let at_limit = vec![b' '; MAX_REPORT_RESPONSE_BYTES as usize];
        assert_eq!(
            read_bounded_report_response(std::io::Cursor::new(at_limit))
                .expect("body at limit is accepted")
                .len(),
            MAX_REPORT_RESPONSE_BYTES as usize
        );
        let oversized = vec![b' '; MAX_REPORT_RESPONSE_BYTES as usize + 1];
        assert_eq!(
            read_bounded_report_response(std::io::Cursor::new(oversized)),
            Err(PreferencesApplyError::InvalidResponse)
        );
    }

    #[test]
    fn report_rtt_millis_is_protocol_bounded() {
        assert_eq!(report_rtt_millis(Duration::from_nanos(1)), 1);
        assert_eq!(report_rtt_millis(Duration::from_millis(42)), 42);
        assert_eq!(
            report_rtt_millis(Duration::from_millis(MAX_INBOUND_RTT_MS + 1)),
            MAX_INBOUND_RTT_MS
        );
    }

    #[test]
    fn kernel_collector_reports_current_and_staged_versions() {
        let current_root = kernel_fixture("current");
        let (running, expected) =
            write_kernel_fixture(&current_root, "7.0.14-nixos\n", &["7.0.14"]);
        let current = collect_kernel_posture_at(true, 100, &running, &expected);
        assert_eq!(current.state, pharos_core::KernelPostureState::Current);
        assert_eq!(current.running_version.as_deref(), Some("7.0.14-nixos"));
        assert_eq!(current.expected_version.as_deref(), Some("7.0.14"));
        current.validate_contract().expect("current posture valid");
        std::fs::remove_dir_all(current_root).expect("remove current fixture");

        let staged_root = kernel_fixture("staged");
        let (running, expected) = write_kernel_fixture(&staged_root, "6.18.26\n", &["7.0.14"]);
        let staged = collect_kernel_posture_at(true, 200, &running, &expected);
        assert_eq!(
            staged.state,
            pharos_core::KernelPostureState::RebootRequired
        );
        staged.validate_contract().expect("staged posture valid");
        std::fs::remove_dir_all(staged_root).expect("remove staged fixture");
    }

    #[test]
    fn kernel_collector_fails_multiple_missing_and_malformed_versions_safe() {
        let root = kernel_fixture("unknown");
        let (running, expected) = write_kernel_fixture(&root, "7.0.14\n", &["7.0.14", "7.1.0"]);
        let multiple = collect_kernel_posture_at(true, 300, &running, &expected);
        assert_eq!(multiple.state, pharos_core::KernelPostureState::Unknown);
        assert!(multiple.expected_version.is_none());

        let missing = collect_kernel_posture_at(true, 301, &running, &root.join("missing"));
        assert_eq!(missing.state, pharos_core::KernelPostureState::Unknown);

        std::fs::write(&running, "/nix/store/not-a-version\n").expect("write malformed version");
        let malformed = collect_kernel_posture_at(true, 302, &running, &expected);
        assert_eq!(malformed.state, pharos_core::KernelPostureState::Unknown);
        assert!(malformed.running_version.is_none());
        std::fs::remove_dir_all(root).expect("remove unknown fixture");
    }

    #[test]
    fn kernel_collector_marks_non_nix_hosts_not_applicable() {
        let posture = collect_kernel_posture_at(
            false,
            400,
            Path::new("/path/that/does/not/exist"),
            Path::new("/another/missing/path"),
        );

        assert_eq!(
            posture.state,
            pharos_core::KernelPostureState::NotApplicable
        );
        assert!(posture.expected_version.is_none());
        posture.validate_contract().expect("non-Nix posture valid");
    }

    #[test]
    fn success_log_line_keeps_operational_context_without_report_body() {
        let line = success_log_line(
            "hsb8",
            "http://pharos.example/report",
            204,
            &NixFreshness {
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
            None,
            &[],
        );

        assert!(line.contains("hsb8"));
        assert!(line.contains("http://pharos.example/report"));
        assert!(line.contains("HTTP 204"));
        assert!(line.contains("generation=unverified"));
        assert!(line.contains("nixcfg=unknown"));
        assert!(line.contains("nixpkgs=unknown"));
        assert!(line.contains("location=off"));
        assert!(!line.contains("\"name\""));
        assert!(!line.contains("heartbeat_interval_secs"));
        assert!(!line.contains("freshness"));
    }

    #[test]
    fn success_log_line_handles_non_nix_hosts() {
        let line = success_log_line(
            "hermes",
            "http://pharos.example/report",
            204,
            &NixFreshness::default(),
            None,
            &[],
        );

        assert!(line.contains("nix=n/a"));
        assert!(!line.contains("\"applicable\""));
    }

    #[test]
    fn backup_mode_defaults_to_auto_and_supports_explicit_collectors() {
        assert_eq!(BackupMode::from_env_value(None), BackupMode::Auto);
        assert_eq!(
            BackupMode::from_env_value(Some(" off ".to_string())),
            BackupMode::Off
        );
        assert_eq!(
            BackupMode::from_env_value(Some("restic".to_string())),
            BackupMode::Restic
        );
        assert_eq!(
            BackupMode::from_env_value(Some("status-file".to_string())),
            BackupMode::StatusFile
        );
        assert_eq!(
            BackupMode::from_env_value(Some("command".to_string())),
            BackupMode::Command
        );
    }

    #[test]
    fn restic_backup_options_extract_repository_only() {
        assert_eq!(
            restic_repository_args_from_backup_options(
                "-r sftp:backup.example.invalid:/ --host csb1 --verbose"
            ),
            vec![
                "-r".to_string(),
                "sftp:backup.example.invalid:/".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository=sftp:backup.example.invalid:/ --password-file /run/secret"
            ),
            vec![
                "-r".to_string(),
                "sftp:backup.example.invalid:/".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository-file /run/agenix/restic-repository --password-file /run/agenix/restic-password"
            ),
            vec![
                "--repository-file".to_string(),
                "/run/agenix/restic-repository".to_string()
            ]
        );
        assert_eq!(
            restic_repository_args_from_backup_options(
                "--repository-file=/run/agenix/restic-repository --password-file /run/agenix/restic-password"
            ),
            vec![
                "--repository-file".to_string(),
                "/run/agenix/restic-repository".to_string()
            ]
        );
        assert!(restic_repository_args_from_backup_options("--host csb1").is_empty());
    }

    #[test]
    fn rfc3339_parser_handles_utc_and_offsets() {
        assert_eq!(parse_rfc3339_unix("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339_unix("1970-01-01T01:00:00+01:00"), Some(0));
        assert_eq!(parse_rfc3339_unix("1969-12-31T23:00:00-01:00"), Some(0));
        assert!(parse_rfc3339_unix("not a timestamp").is_none());
    }

    #[test]
    fn restic_snapshot_metadata_classifies_healthy_stale_and_missing() {
        let raw = r#"[{
            "time": "2023-11-14T21:13:20Z",
            "hostname": "csb1",
            "paths": ["/backup/home"],
            "id": "abcdef"
        }]"#;

        let healthy = restic_snapshot_observation(raw, 1_700_000_000, 7_200);
        assert_eq!(healthy.state, BackupPostureState::Healthy);
        assert_eq!(healthy.last_success_at, Some(1_699_996_400));
        assert_eq!(healthy.last_attempt_state, Some(BackupRunState::Succeeded));
        assert_eq!(healthy.snapshot_count, Some(1));
        assert!(!serde_json::to_string(&healthy)
            .unwrap()
            .contains("/backup/home"));

        let stale = restic_snapshot_observation(raw, 1_700_000_000, 60);
        assert_eq!(stale.state, BackupPostureState::Stale);

        let missing = restic_snapshot_observation("[]", 1_700_000_000, 7_200);
        assert_eq!(missing.state, BackupPostureState::Missing);
        assert_eq!(missing.snapshot_count, Some(0));
    }

    #[test]
    fn restic_errors_are_coarse_and_do_not_leak_raw_output() {
        let locked = restic_error_observation(
            "repository is already locked by /tmp/restic-lock",
            1_700_000_000,
        );
        assert_eq!(locked.state, BackupPostureState::Warning);
        assert_eq!(locked.summary, "restic repository locked");
        assert!(!serde_json::to_string(&locked)
            .unwrap()
            .contains("/tmp/restic-lock"));

        let missing = restic_error_observation("Fatal: unable to open config file", 1_700_000_000);
        assert_eq!(missing.state, BackupPostureState::Missing);

        let failed = restic_error_observation("wrong password or no key found", 1_700_000_000);
        assert_eq!(failed.state, BackupPostureState::Failed);
        assert_eq!(failed.last_attempt_state, Some(BackupRunState::Failed));
    }

    #[test]
    fn backup_status_json_accepts_sanitized_observations_only() {
        let clean = r#"{
            "id":"restic-main",
            "label":"Restic main",
            "engine":"restic",
            "state":"healthy",
            "configured":"enabled",
            "summary":"last backup succeeded"
        }"#;
        let observations = backup_observations_from_json(clean).expect("clean observation");
        assert_eq!(observations.len(), 1);
        assert_eq!(observations[0].state, BackupPostureState::Healthy);

        let secret_shaped = r#"{
            "id":"restic-main",
            "label":"Restic main",
            "engine":"restic",
            "state":"healthy",
            "configured":"enabled",
            "summary":"last backup succeeded",
            "repository_id":"s3://user:password@example.invalid/bucket"
        }"#;
        assert_eq!(
            backup_observations_from_json(secret_shaped).expect_err("secret-shaped metadata"),
            "contract"
        );
    }

    #[test]
    fn location_mode_is_disabled_by_default_and_explicitly_selected() {
        assert_eq!(LocationMode::from_env_value(None), LocationMode::Off);
        assert_eq!(
            LocationMode::from_env_value(Some(" env ".to_string())),
            LocationMode::Env
        );
        assert_eq!(
            LocationMode::from_env_value(Some("ip-api".to_string())),
            LocationMode::IpApi
        );
        assert_eq!(
            LocationMode::from_env_value(Some("command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("provider-command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("wifi".to_string())),
            LocationMode::Off
        );
    }

    #[test]
    fn env_location_reports_quality_without_sensitive_log_details() {
        std::env::set_var("PHAROS_LOCATION_LATITUDE", "48.2082");
        std::env::set_var("PHAROS_LOCATION_LONGITUDE", "16.3738");
        std::env::set_var("PHAROS_LOCATION_SOURCE", "wifi");
        std::env::set_var("PHAROS_LOCATION_ACCURACY_METERS", "1200");
        std::env::set_var("PHAROS_LOCATION_PRECISION_METERS", "2500");
        std::env::set_var("PHAROS_LOCATION_LABEL", "Vienna area");

        let location = location_from_env(1_700_000_000).expect("env location");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(1200.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(summary.contains("location=wifi"));
        assert!(summary.contains("accuracy=1200m"));
        assert!(summary.contains("precision=2500m"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));

        for key in [
            "PHAROS_LOCATION_LATITUDE",
            "PHAROS_LOCATION_LONGITUDE",
            "PHAROS_LOCATION_SOURCE",
            "PHAROS_LOCATION_ACCURACY_METERS",
            "PHAROS_LOCATION_PRECISION_METERS",
            "PHAROS_LOCATION_LABEL",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn ip_api_location_uses_coarse_precision_and_not_raw_ip() {
        let raw = r#"{
            "status":"success",
            "lat":52.52,
            "lon":13.405,
            "city":"Berlin",
            "regionName":"Berlin",
            "countryCode":"DE",
            "query":"203.0.113.10"
        }"#;

        let location =
            location_from_ip_api_json(raw, 1_700_000_000, 50_000.0).expect("ip api location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Ip);
        assert_eq!(location.accuracy_meters, None);
        assert_eq!(location.precision_meters, Some(50_000.0));
        assert_eq!(location.label.as_deref(), Some("Berlin, DE"));
        assert!(!body.contains("203.0.113.10"));
        assert!(summary.contains("location=ip"));
        assert!(summary.contains("precision=50000m"));
        assert!(!summary.contains("52.52"));
        assert!(!summary.contains("13.405"));
    }

    #[test]
    fn command_location_parses_sanitized_payload_only() {
        let raw = r#"{
            "latitude": 48.2082,
            "longitude": 16.3738,
            "source": "wifi",
            "accuracy_meters": 900,
            "precision_meters": 2500,
            "observed_at": 1700000000,
            "label": "Vienna area",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "private-network"
        }"#;

        let location = location_from_command_json(raw, 1_700_000_100).expect("command location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(900.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(!body.contains("aa:bb"));
        assert!(!body.contains("private-network"));
        assert!(summary.contains("location=wifi"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));
    }

    #[test]
    fn command_location_rejects_malformed_or_invalid_payload() {
        assert!(location_from_command_json("not json", 1_700_000_000).is_none());
        assert!(
            location_from_command_json(r#"{"latitude":99,"longitude":16}"#, 1_700_000_000)
                .is_none()
        );
        assert!(location_from_command_json(
            r#"{"latitude":48.2,"longitude":"bad"}"#,
            1_700_000_000
        )
        .is_none());
    }

    #[test]
    fn command_location_args_are_json_array_only() {
        assert_eq!(
            location_command_args_from_raw(r#"["--format","json"]"#),
            Some(vec!["--format".to_string(), "json".to_string()])
        );
        assert!(location_command_args_from_raw("--format json").is_none());
    }

    #[test]
    fn command_runner_reports_failure_without_leaking_output() {
        let args = vec![
            "-c".to_string(),
            "printf 'BSSID=aa:bb:cc:dd:ee:ff'; exit 7".to_string(),
        ];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_secs(1)).expect_err("fails");
        assert_eq!(error, "exit");
        assert!(!error.contains("aa:bb"));
        assert!(!error.contains("BSSID"));
    }

    #[test]
    fn command_runner_times_out() {
        let args = vec!["-c".to_string(), "sleep 1".to_string()];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_millis(10)).expect_err("timeout");
        assert_eq!(error, "timeout");
    }

    #[test]
    fn command_collectors_drain_large_stdout_and_stderr_concurrently() {
        let block = "x".repeat(60);
        let location_script =
            format!("i=0; while [ \"$i\" -lt 1000 ]; do printf '%s' '{block}'; i=$((i+1)); done");
        let output = run_location_command(
            "/bin/sh",
            &["-c".to_string(), location_script],
            Duration::from_secs(3),
        )
        .expect("large output below the limit drains without pipe deadlock");
        assert_eq!(output.len(), 60_000);

        let capture_script = format!(
            "i=0; while [ \"$i\" -lt 1500 ]; do printf '%s' '{block}'; i=$((i+1)); done; i=0; while [ \"$i\" -lt 1500 ]; do printf '%s' '{block}' >&2; i=$((i+1)); done"
        );
        let capture = run_capture_command(
            "/bin/sh",
            &["-c".to_string(), capture_script],
            Duration::from_secs(3),
        )
        .expect("both pipes drain concurrently");
        assert!(capture.success);
        assert_eq!(capture.stdout.len(), 90_000);
        assert_eq!(capture.stderr.len(), 90_000);
    }

    #[test]
    fn command_collectors_enforce_output_and_descendant_deadlines() {
        let block = "x".repeat(60);
        let oversized =
            format!("i=0; while [ \"$i\" -lt 1200 ]; do printf '%s' '{block}'; i=$((i+1)); done");
        assert_eq!(
            run_location_command(
                "/bin/sh",
                &["-c".to_string(), oversized],
                Duration::from_secs(3)
            )
            .expect_err("oversized output is rejected"),
            "output_limit"
        );

        let started = Instant::now();
        let inherited_pipe = vec!["-c".to_string(), "(sleep 2) & printf '{}'".to_string()];
        assert_eq!(
            run_location_command("/bin/sh", &inherited_pipe, Duration::from_millis(100))
                .expect_err("background descendants cannot hold the pipe forever"),
            "output_timeout"
        );
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn report_endpoint_is_https_capable_and_never_exposes_unsafe_components() {
        let endpoint = report_endpoint("https://pharos.example/base").expect("https endpoint");
        assert_eq!(endpoint.request_url, "https://pharos.example/base/report");
        assert_eq!(endpoint.safe_origin, "https://pharos.example");
        assert!(!endpoint.safe_origin.contains("base"));

        for unsafe_url in [
            "ftp://pharos.example",
            "https://user@pharos.example",
            "https://pharos.example?token=hidden",
            "https://pharos.example/#fragment",
            "not a url",
        ] {
            assert!(report_endpoint(unsafe_url).is_err());
        }
    }

    #[test]
    fn request_deadlines_and_retry_delays_are_bounded_by_cadence() {
        for cadence in [MIN_HEARTBEAT_INTERVAL_SECS, 60, MAX_HEARTBEAT_INTERVAL_SECS] {
            let deadlines = RequestDeadlines::for_cadence(cadence).unwrap();
            for deadline in [
                deadlines.connect,
                deadlines.read,
                deadlines.write,
                deadlines.overall,
            ] {
                assert!(deadline < Duration::from_secs(cadence));
                assert!(!deadline.is_zero());
            }
            for failure in 1..=100 {
                assert!(retry_delay(cadence, failure, u64::MAX) < Duration::from_secs(cadence));
            }
        }
        assert!(RequestDeadlines::for_cadence(MIN_HEARTBEAT_INTERVAL_SECS - 1).is_err());
        assert!(RequestDeadlines::for_cadence(MAX_HEARTBEAT_INTERVAL_SECS + 1).is_err());
        assert!(retry_delay(60, 2, 0) > retry_delay(60, 1, 0));
        assert_ne!(retry_delay(60, 1, 0), retry_delay(60, 1, 499));
    }

    #[test]
    fn stalled_report_connection_obeys_the_overall_deadline() {
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fixture listener");
        let address = listener.local_addr().unwrap();
        let server = thread::spawn(move || {
            let (_stream, _) = listener.accept().expect("accept fixture request");
            thread::sleep(Duration::from_millis(250));
        });
        let deadline = Duration::from_millis(50);
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_connect(Some(deadline))
            .timeout_send_request(Some(deadline))
            .timeout_send_body(Some(deadline))
            .timeout_recv_response(Some(deadline))
            .timeout_recv_body(Some(deadline))
            .timeout_global(Some(deadline))
            .max_redirects(0)
            .build()
            .into();
        let started = Instant::now();
        assert!(agent
            .post(&format!("http://{address}/report"))
            .send("{}")
            .is_err());
        assert!(started.elapsed() < Duration::from_millis(500));
        server.join().unwrap();
    }

    #[test]
    fn bearer_token_prefers_file_and_fails_closed() {
        let temp = std::env::temp_dir().join(format!("pharos-token-test-{}", std::process::id()));
        std::fs::write(&temp, "file-token\n").expect("write token fixture");
        std::env::set_var("PHAROS_TOKEN", " env-token ");
        std::env::set_var("PHAROS_TOKEN_FILE", &temp);

        assert_eq!(bearer_token().unwrap(), Some("file-token".to_string()));

        std::fs::remove_file(&temp).expect("remove token fixture");
        let error = bearer_token().expect_err("missing configured file must fail closed");
        assert!(error.to_string().contains("PHAROS_TOKEN_FILE"));
        assert!(!error.to_string().contains("env-token"));

        std::env::remove_var("PHAROS_TOKEN");
        std::env::remove_var("PHAROS_TOKEN_FILE");
    }

    // PHAROS-193 --------------------------------------------------------------

    /// Tests run in parallel and each removes its own directory, so the name
    /// needs a counter: a timestamp alone can collide and one test then deletes
    /// another's lock mid-run.
    static LOCK_FIXTURE_COUNTER: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    fn write_lock_document(document: serde_json::Value) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "pharos-beacon-lock-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("temp flake dir");
        std::fs::write(
            dir.join("flake.lock"),
            serde_json::to_vec(&document).expect("lock serializes"),
        )
        .expect("write lock");
        dir
    }

    fn write_lock_with_root(
        root_inputs: serde_json::Value,
        nodes: serde_json::Value,
    ) -> std::path::PathBuf {
        let mut all = nodes.as_object().expect("nodes object").clone();
        all.insert(
            "root".to_string(),
            serde_json::json!({ "inputs": root_inputs }),
        );
        write_lock_document(serde_json::json!({
            "root": "root",
            "nodes": serde_json::Value::Object(all)
        }))
    }

    fn days_ago(days: i64) -> i64 {
        now_unix() - days * 86_400
    }

    fn fixture_lock_and_evidence(dir: &Path) -> Option<(serde_json::Value, NixDeploymentEvidence)> {
        let raw = std::fs::read(dir.join("flake.lock")).ok()?;
        let lock: serde_json::Value = serde_json::from_slice(&raw).ok()?;
        let nodes = lock.get("nodes")?.as_object()?;
        let root = lock.get("root")?.as_str()?;
        let target = nodes.get(root)?.get("inputs")?.get("nixpkgs")?;
        let node = nodes.get(input_target_name(target)?)?;
        let evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "a".repeat(40),
            flake_lock_sha256: sha256_hex(&raw),
            nixpkgs_revision: node.get("locked")?.get("rev")?.as_str()?.to_string(),
            nixpkgs_last_modified: node.get("locked")?.get("lastModified")?.as_i64()?,
            nixpkgs_channel: nixpkgs_channel(node)?,
        };
        Some((matching_flake_lock(dir.to_str()?, &evidence)?, evidence))
    }

    /// The real csb1 lock shape. The system tracks nixos-unstable and is 21
    /// days old, while a separate root input sits 218 days stale on an expired
    /// channel and transitive inputs of nixos-hardware are older still.
    /// PHAROS-196: only the system input may drive the reported number.
    fn fleet_shaped_lock() -> std::path::PathBuf {
        write_lock_with_root(
            serde_json::json!({
                "nixpkgs": "nixpkgs_6",
                "nixpkgs-stable": "nixpkgs-stable_2",
                "nixos-hardware": "nixos-hardware"
            }),
            serde_json::json!({
                "nixpkgs_6": {
                    "locked":   { "lastModified": days_ago(21), "rev": "1111111111111111111111111111111111111111" },
                    "original": { "ref": "nixos-unstable" }
                },
                "nixpkgs-stable_2": {
                    "locked":   { "lastModified": days_ago(218) },
                    "original": { "ref": "nixos-25.05" }
                },
                "nixos-hardware": {
                    "inputs": { "nixpkgs": "nixpkgs_3" },
                    "locked": { "lastModified": days_ago(30) }
                },
                "nixpkgs_3": { "locked": { "lastModified": days_ago(211) } },
                "disko":   { "locked": { "lastModified": days_ago(0) } },
                "systems": { "locked": { "lastModified": days_ago(1217) } }
            }),
        )
    }

    #[test]
    fn nixpkgs_freshness_reports_the_system_input_not_the_oldest_lookalike() {
        let dir = fleet_shaped_lock();

        // The original signal reads as completely fresh because disko moved today.
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        assert_eq!(flake_lock_age_days(&lock), Some(0));

        // PHAROS-193 replaced that with the oldest nixpkgs-family node, which
        // reported 218d on an expired channel and reads as a patching gap the
        // host does not have. The system input is what decides its posture.
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("nixpkgs observed");
        assert_eq!(
            freshness.age_days, 21,
            "must report the flake's own nixpkgs input"
        );
        assert_eq!(freshness.channel.as_deref(), Some("nixos-unstable"));
        assert_eq!(
            freshness.secondary,
            Some(NixpkgsInputFreshness {
                input: "nixpkgs-stable".to_string(),
                age_days: 218,
                channel: Some("nixos-25.05".to_string()),
            }),
            "the stale root side input remains visible as secondary context"
        );

        // An unstable channel is rolling, so it is never flagged end of life.
        assert_eq!(
            pharos_core::nix_channel_state("nixos-unstable", 2026, 8),
            pharos_core::NixChannelState::Rolling
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_still_flags_a_system_input_on_an_expired_channel() {
        // The case that must keep working: the system itself is on a dead release.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": "nixpkgs" }),
            serde_json::json!({
                "nixpkgs": {
                    "locked":   { "lastModified": days_ago(218), "rev": "2222222222222222222222222222222222222222" },
                    "original": { "ref": "nixos-25.05" }
                },
                "disko": { "locked": { "lastModified": days_ago(0) } }
            }),
        );
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("observed");
        assert_eq!(freshness.age_days, 218);
        assert_eq!(freshness.channel.as_deref(), Some("nixos-25.05"));
        assert_eq!(freshness.secondary, None);
        assert_eq!(
            pharos_core::nix_channel_state("nixos-25.05", 2026, 8),
            pharos_core::NixChannelState::EndOfLife
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_resolves_a_follows_target_and_tolerates_odd_locks() {
        // A `follows` entry is a path; only its first element names a node.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": ["nixpkgs_2"] }),
            serde_json::json!({
                "nixpkgs_2": {
                    "locked":   { "lastModified": days_ago(9), "rev": "3333333333333333333333333333333333333333" },
                    "original": { "ref": "nixos-26.05" }
                }
            }),
        );
        let (lock, evidence) = fixture_lock_and_evidence(&dir).expect("generation evidence");
        let freshness = nixpkgs_freshness(&lock, &evidence).expect("observed");
        assert_eq!(freshness.age_days, 9);
        assert_eq!(freshness.channel.as_deref(), Some("nixos-26.05"));
        let _ = std::fs::remove_dir_all(dir);

        // No nixpkgs input at all: report nothing rather than guess.
        let dir = write_lock_with_root(
            serde_json::json!({ "disko": "disko" }),
            serde_json::json!({ "disko": { "locked": { "lastModified": days_ago(3) } } }),
        );
        assert_eq!(fixture_lock_and_evidence(&dir), None);
        let _ = std::fs::remove_dir_all(dir);

        // An unsafe ref is dropped rather than propagated into the report.
        let dir = write_lock_with_root(
            serde_json::json!({ "nixpkgs": "nixpkgs" }),
            serde_json::json!({
                "nixpkgs": {
                    "locked":   { "lastModified": days_ago(4), "rev": "4444444444444444444444444444444444444444" },
                    "original": { "ref": "https://example.invalid/x?token=abc" }
                }
            }),
        );
        assert_eq!(fixture_lock_and_evidence(&dir), None);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn nixpkgs_freshness_is_absent_without_a_readable_lock() {
        assert_eq!(
            fixture_lock_and_evidence(Path::new("/nonexistent/pharos-193")),
            None
        );
    }

    fn test_git(dir: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(args)
            .output()
            .expect("run fixture git");
        assert!(
            output.status.success(),
            "git {:?} failed: {}",
            args,
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout)
            .expect("git output utf-8")
            .trim()
            .to_string()
    }

    fn commit_fixture(checkout: &Path, name: &str, body: &str) -> String {
        std::fs::write(checkout.join(name), body).expect("write fixture file");
        test_git(checkout, &["add", name]);
        test_git(
            checkout,
            &[
                "-c",
                "user.name=Pharos Test",
                "-c",
                "user.email=pharos@example.invalid",
                "commit",
                "-m",
                name,
            ],
        );
        test_git(checkout, &["rev-parse", "HEAD"])
    }

    #[test]
    fn exact_git_comparison_proves_current_behind_ahead_and_diverged() {
        let root = std::env::temp_dir().join(format!(
            "pharos-git-proof-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let checkout = root.join("checkout");
        let remote = root.join("remote.git");
        let reference = root.join("reference.git");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        test_git(&checkout, &["init", "--initial-branch=main"]);
        let first = commit_fixture(&checkout, "first", "one");
        std::fs::create_dir_all(&remote).expect("create remote");
        test_git(&remote, &["init", "--bare"]);
        test_git(
            &checkout,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("remote path"),
            ],
        );
        test_git(&checkout, &["push", "-u", "origin", "main"]);

        let current = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &first,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("current comparison");
        assert_eq!(current.relation, GitRevisionRelation::Current);
        assert_eq!(current.commits_behind, Some(0));

        let second = commit_fixture(&checkout, "second", "two");
        test_git(&checkout, &["push", "origin", "main"]);
        let behind = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &first,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("behind comparison");
        assert_eq!(behind.upstream_revision, second);
        assert_eq!(behind.relation, GitRevisionRelation::Behind);
        assert_eq!(behind.commits_behind, Some(1));

        let ahead_revision = commit_fixture(&checkout, "ahead", "three");
        let ahead = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &ahead_revision,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("ahead comparison");
        assert_eq!(ahead.relation, GitRevisionRelation::Ahead);
        assert_eq!(ahead.commits_behind, None);

        test_git(&checkout, &["checkout", "-b", "divergent", &first]);
        let divergent_revision = commit_fixture(&checkout, "divergent", "other");
        let diverged = nixcfg_git_comparison_from_remote(
            checkout.to_str().expect("checkout path"),
            &divergent_revision,
            remote.to_str().expect("remote path"),
            "refs/heads/main",
            &reference,
        )
        .expect("diverged comparison");
        assert_eq!(diverged.relation, GitRevisionRelation::Diverged);
        assert_eq!(diverged.commits_behind, None);

        assert_eq!(
            nixcfg_git_comparison_from_remote(
                checkout.to_str().expect("checkout path"),
                &first,
                root.join("missing.git").to_str().expect("missing path"),
                "refs/heads/main",
                &reference,
            ),
            None,
            "a failed authoritative fetch must never reuse the previous success"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nixpkgs_comparison_is_exact_or_unknown_never_inferred() {
        let root = std::env::temp_dir().join(format!(
            "pharos-nixpkgs-proof-{}-{}",
            std::process::id(),
            LOCK_FIXTURE_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let checkout = root.join("checkout");
        let remote = root.join("remote.git");
        std::fs::create_dir_all(&checkout).expect("create checkout");
        test_git(&checkout, &["init", "--initial-branch=main"]);
        let revision = commit_fixture(&checkout, "nixpkgs", "locked");
        std::fs::create_dir_all(&remote).expect("create remote");
        test_git(&remote, &["init", "--bare"]);
        test_git(
            &checkout,
            &[
                "remote",
                "add",
                "origin",
                remote.to_str().expect("remote path"),
            ],
        );
        test_git(&checkout, &["push", "origin", "main"]);

        let mut evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "1".repeat(40),
            flake_lock_sha256: "2".repeat(64),
            nixpkgs_revision: revision,
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "main".to_string(),
        };
        let current =
            nixpkgs_git_comparison_from_remote(&evidence, remote.to_str().expect("remote path"))
                .expect("exact comparison");
        assert_eq!(current.relation, NixpkgsRevisionRelation::Current);

        evidence.nixpkgs_revision = "9".repeat(40);
        let different =
            nixpkgs_git_comparison_from_remote(&evidence, remote.to_str().expect("remote path"))
                .expect("different comparison");
        assert_eq!(different.relation, NixpkgsRevisionRelation::Different);
        assert_eq!(
            nixpkgs_git_comparison_from_remote(
                &evidence,
                root.join("missing.git").to_str().expect("missing path")
            ),
            None
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn official_nixpkgs_channel_revision_is_bounded_exact_and_fail_closed() {
        let evidence = NixDeploymentEvidence {
            schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
            version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
            source_revision: "1".repeat(40),
            flake_lock_sha256: "2".repeat(64),
            nixpkgs_revision: "3".repeat(40),
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "nixos-unstable".to_string(),
        };
        let current = nixpkgs_comparison_from_revision(&evidence, &format!("{}\n", "3".repeat(40)))
            .expect("exact channel revision");
        assert_eq!(current.relation, NixpkgsRevisionRelation::Current);
        let different = nixpkgs_comparison_from_revision(&evidence, &"4".repeat(40))
            .expect("different channel revision");
        assert_eq!(different.relation, NixpkgsRevisionRelation::Different);
        for malformed in ["", "3", &"G".repeat(40), &"3".repeat(129)] {
            assert_eq!(nixpkgs_comparison_from_revision(&evidence, malformed), None);
        }
        assert_eq!(
            read_bounded_nixpkgs_revision(format!("{}\n", "3".repeat(40)).as_bytes()),
            Some("3".repeat(40))
        );
        assert_eq!(
            read_bounded_nixpkgs_revision("3".repeat(129).as_bytes()),
            None
        );
    }

    #[test]
    fn official_nixpkgs_channel_urls_reject_unsafe_authorities_and_redirects() {
        let source =
            nixpkgs_channel_revision_url("nixos-unstable", DEFAULT_NIXPKGS_CHANNEL_BASE_URL)
                .expect("official channel URL");
        assert_eq!(
            source.as_str(),
            "https://channels.nixos.org/nixos-unstable/git-revision"
        );
        for base in [
            "http://channels.nixos.org/",
            "https://user:secret@channels.nixos.org/",
            "https://channels.nixos.org/?token=value",
            "file:///tmp/channels/",
        ] {
            assert!(nixpkgs_channel_revision_url("nixos-unstable", base).is_none());
        }
        for channel in ["", "../unstable", "nixos unstable", "nixos/unstable"] {
            assert!(
                nixpkgs_channel_revision_url(channel, DEFAULT_NIXPKGS_CHANNEL_BASE_URL).is_none()
            );
        }

        let release = safe_nixpkgs_channel_redirect(
            &source,
            "https://releases.nixos.org/nixos/unstable/nixos-test/git-revision",
        )
        .expect("official release redirect");
        assert_eq!(release.host_str(), Some("releases.nixos.org"));
        for location in [
            "http://releases.nixos.org/nixos/unstable/nixos-test/git-revision",
            "https://example.com/nixos/unstable/nixos-test/git-revision",
            "https://releases.nixos.org/other/git-revision",
            "https://releases.nixos.org/nixos/unstable/nixos-test/archive.tar.xz",
            "https://user:secret@releases.nixos.org/nixos/unstable/nixos-test/git-revision",
        ] {
            assert!(safe_nixpkgs_channel_redirect(&source, location).is_none());
        }
        assert!(is_official_nixpkgs_git_remote(OFFICIAL_NIXPKGS_GIT_REMOTE));
        assert!(!is_official_nixpkgs_git_remote(
            "https://github.com/example/nixpkgs.git"
        ));
    }

    #[test]
    fn generation_lock_and_remote_configuration_fail_closed() {
        assert!(safe_git_remote("https://github.com/markus-barta/nixcfg.git").is_some());
        for unsafe_remote in [
            "http://github.com/markus-barta/nixcfg.git",
            "https://user:secret@github.com/repo.git",
            "https://github.com/repo.git?token=value",
            "file:///tmp/repo.git",
        ] {
            assert!(safe_git_remote(unsafe_remote).is_none(), "{unsafe_remote}");
        }
        assert!(safe_git_branch_ref("refs/heads/main").is_some());
        for unsafe_ref in [
            "main",
            "refs/tags/main",
            "refs/heads/../main",
            "refs/heads/x@{1}",
        ] {
            assert!(safe_git_branch_ref(unsafe_ref).is_none(), "{unsafe_ref}");
        }

        let dir = fleet_shaped_lock();
        let (_, evidence) = fixture_lock_and_evidence(&dir).expect("fixture evidence");
        std::fs::write(dir.join("flake.lock"), b"{}").expect("replace mutable checkout lock");
        assert_eq!(
            matching_flake_lock(dir.to_str().expect("path"), &evidence),
            None,
            "a checkout lock that differs from the generation digest is not evidence"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
