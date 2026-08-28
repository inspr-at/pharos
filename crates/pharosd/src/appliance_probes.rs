//! Server-side appliance convergence observations (PHAROS-180).
//!
//! Appliance hosts deliberately have no beacon or credential. Pharos therefore
//! uses one fixed ICMP-presence check, one fixed SSH-port check, and an optional
//! bounded read of a convergence marker through the existing strict SSH trust
//! boundary. No probe target or raw command output reaches an observation.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use pharos_core::{ServiceObservation, ServiceObservationState};
use serde::{Deserialize, Serialize};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::durable_file::{atomic_write_json, load_optional_json};
use crate::provisioning::{
    open_trusted_runtime_file, read_trusted_runtime_file, run_child_with_deadline,
    valid_bootstrap_name, valid_ssh_endpoint, valid_ssh_user, ExistingHostRuntimeConfig,
};
use crate::store::Store;

pub(crate) const APPLIANCE_OBSERVATION_ID: &str = "appliance-convergence";
const APPLIANCE_REGISTRY_SCHEMA: &str = "inspr.pharos.appliance-probes.v1";
const APPLIANCE_REGISTRY_VERSION: u16 = 1;
const APPLIANCE_STATE_SCHEMA: &str = "inspr.pharos.appliance-probe-state.v1";
const APPLIANCE_STATE_VERSION: u16 = 1;
const MAX_REGISTRY_BYTES: u64 = 64 * 1024;
const MAX_APPLIANCES: usize = 64;
const DEFAULT_DEBOUNCE_SAMPLES: u8 = 3;
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
const MIN_PROBE_INTERVAL_SECS: u64 = 10;
const MAX_PROBE_INTERVAL_SECS: u64 = 3600;
const MAX_MARKER_BYTES: usize = 256;
const PRESENCE_TIMEOUT: Duration = Duration::from_secs(2);
const SSH_PORT_TIMEOUT: Duration = Duration::from_secs(2);
const MARKER_SSH_TIMEOUT: Duration = Duration::from_secs(12);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplianceProbeRegistry {
    schema: String,
    version: u16,
    #[serde(default = "default_probe_interval_secs")]
    probe_interval_secs: u64,
    appliances: Vec<ApplianceProbeDeclaration>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplianceProbeDeclaration {
    host: String,
    target: String,
    ssh_user: String,
    #[serde(default = "default_ssh_port")]
    ssh_port: u16,
    marker_path: String,
    #[serde(default = "default_debounce_samples")]
    debounce_samples: u8,
}

fn default_ssh_port() -> u16 {
    22
}

fn default_debounce_samples() -> u8 {
    DEFAULT_DEBOUNCE_SAMPLES
}

fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}

impl ApplianceProbeRegistry {
    fn validate(&self) -> Result<(), String> {
        if self.schema != APPLIANCE_REGISTRY_SCHEMA || self.version != APPLIANCE_REGISTRY_VERSION {
            return Err("unsupported appliance probe registry schema/version".to_string());
        }
        if self.appliances.is_empty() || self.appliances.len() > MAX_APPLIANCES {
            return Err("appliance probe registry must contain 1..=64 hosts".to_string());
        }
        if !(MIN_PROBE_INTERVAL_SECS..=MAX_PROBE_INTERVAL_SECS).contains(&self.probe_interval_secs)
        {
            return Err("appliance probe interval must be between 10 and 3600 seconds".to_string());
        }
        let mut hosts = BTreeSet::new();
        for declaration in &self.appliances {
            declaration.validate()?;
            if !hosts.insert(declaration.host.as_str()) {
                return Err("appliance probe registry contains a duplicate host".to_string());
            }
        }
        Ok(())
    }
}

impl ApplianceProbeDeclaration {
    fn validate(&self) -> Result<(), String> {
        if !valid_bootstrap_name(&self.host)
            || !valid_ssh_endpoint(&self.target)
            || !valid_ssh_user(&self.ssh_user)
            || self.ssh_port == 0
            || !(2..=10).contains(&self.debounce_samples)
            || !valid_marker_path(&self.marker_path)
        {
            return Err("appliance probe declaration is invalid".to_string());
        }
        Ok(())
    }

    fn ssh_target(&self) -> String {
        format!("{}@{}", self.ssh_user, self.target)
    }
}

fn valid_marker_path(value: &str) -> bool {
    if value.is_empty()
        || value.len() > 256
        || !value.is_ascii()
        || !value.starts_with('/')
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'.' | b'_' | b'-'))
    {
        return false;
    }
    Path::new(value)
        .components()
        .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplianceHostProbeState {
    consecutive_online_without_ssh: u8,
    checked_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ApplianceProbeStateDocument {
    schema: String,
    version: u16,
    hosts: BTreeMap<String, ApplianceHostProbeState>,
}

impl Default for ApplianceProbeStateDocument {
    fn default() -> Self {
        Self {
            schema: APPLIANCE_STATE_SCHEMA.to_string(),
            version: APPLIANCE_STATE_VERSION,
            hosts: BTreeMap::new(),
        }
    }
}

impl ApplianceProbeStateDocument {
    fn validate(&self, registry: &ApplianceProbeRegistry) -> Result<(), String> {
        if self.schema != APPLIANCE_STATE_SCHEMA || self.version != APPLIANCE_STATE_VERSION {
            return Err("unsupported appliance probe state schema/version".to_string());
        }
        let declarations: BTreeMap<&str, &ApplianceProbeDeclaration> = registry
            .appliances
            .iter()
            .map(|declaration| (declaration.host.as_str(), declaration))
            .collect();
        for (host, state) in &self.hosts {
            let Some(declaration) = declarations.get(host.as_str()) else {
                return Err("appliance probe state names an undeclared host".to_string());
            };
            if state.checked_at < 0
                || state.consecutive_online_without_ssh > declaration.debounce_samples
            {
                return Err("appliance probe state is invalid".to_string());
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum MarkerResult {
    Valid {
        build_id: String,
        converged_at: String,
    },
    Missing,
    Invalid,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ApplianceProbeSample {
    Offline,
    OnlineWithoutSsh,
    Converged(MarkerResult),
    Unavailable,
}

pub(crate) struct ApplianceProbeRuntime {
    registry: ApplianceProbeRegistry,
    state_path: PathBuf,
    state: Mutex<ApplianceProbeStateDocument>,
    ssh: ExistingHostRuntimeConfig,
}

impl ApplianceProbeRuntime {
    pub(crate) fn from_env(
        host_store_path: Option<&Path>,
        ssh: ExistingHostRuntimeConfig,
    ) -> Result<Option<Self>, String> {
        let Some(registry_path) = std::env::var("PHAROS_APPLIANCE_PROBES_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
        else {
            return Ok(None);
        };
        let bytes = read_trusted_runtime_file(&registry_path, MAX_REGISTRY_BYTES, 0o022, false)
            .ok_or_else(|| "appliance probe registry is unavailable".to_string())?;
        let registry = serde_json::from_slice::<ApplianceProbeRegistry>(&bytes)
            .map_err(|_| "appliance probe registry JSON is invalid".to_string())?;
        registry.validate()?;
        let state_path = Self::path_for(host_store_path).ok_or_else(|| {
            "appliance probes require PHAROS_DB for durable debounce state".to_string()
        })?;
        Self::new(registry, state_path, ssh).map(Some)
    }

    fn new(
        registry: ApplianceProbeRegistry,
        state_path: PathBuf,
        ssh: ExistingHostRuntimeConfig,
    ) -> Result<Self, String> {
        registry.validate()?;
        let mut state = load_optional_json::<ApplianceProbeStateDocument>(&state_path)
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        state.hosts.retain(|host, _| {
            registry
                .appliances
                .iter()
                .any(|declaration| declaration.host == *host)
        });
        state.validate(&registry)?;
        Ok(Self {
            registry,
            state_path,
            state: Mutex::new(state),
            ssh,
        })
    }

    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        host_store_path.map(|path| {
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("pharos.json");
            path.with_file_name(format!("{name}.appliance-probes.json"))
        })
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(self.registry.probe_interval_secs)
    }

    async fn collect_samples(&self) -> Vec<(ApplianceProbeDeclaration, ApplianceProbeSample)> {
        let mut tasks = JoinSet::new();
        for declaration in self.registry.appliances.clone() {
            let ssh = self.ssh.clone();
            tasks.spawn(async move {
                let sample = probe_appliance(&declaration, ssh).await;
                (declaration, sample)
            });
        }
        let mut samples = Vec::with_capacity(self.registry.appliances.len());
        while let Some(result) = tasks.join_next().await {
            if let Ok(sample) = result {
                samples.push(sample);
            }
        }
        samples.sort_by(|left, right| left.0.host.cmp(&right.0.host));
        samples
    }

    fn apply_samples(
        &self,
        samples: Vec<(ApplianceProbeDeclaration, ApplianceProbeSample)>,
        now: i64,
    ) -> Result<BTreeMap<String, ServiceObservation>, String> {
        let mut state = self.state.lock().expect("appliance probe state lock");
        let previous = state.clone();
        let mut observations = BTreeMap::new();
        for (declaration, sample) in samples {
            let host_state = state.hosts.entry(declaration.host.clone()).or_default();
            let maximum_consecutive_gap =
                i64::try_from(self.registry.probe_interval_secs.saturating_mul(3))
                    .unwrap_or(i64::MAX);
            if host_state.checked_at > 0
                && (now <= host_state.checked_at
                    || now.saturating_sub(host_state.checked_at) > maximum_consecutive_gap)
            {
                host_state.consecutive_online_without_ssh = 0;
            }
            let observation = observation_for_sample(&declaration, host_state, sample, now);
            observation.validate_contract()?;
            observations.insert(declaration.host, observation);
        }
        state.validate(&self.registry)?;
        if let Err(error) = atomic_write_json(&self.state_path, &*state) {
            if !error.final_file_replaced() {
                *state = previous;
            }
            return Err("appliance debounce state could not be persisted".to_string());
        }
        Ok(observations)
    }

    async fn probe_and_publish(&self, store: &Store, now: i64) {
        let samples = self.collect_samples().await;
        if samples.len() != self.registry.appliances.len() {
            tracing::warn!("appliance probe task did not return every declared host");
            return;
        }
        let observations = match self.apply_samples(samples, now) {
            Ok(observations) => observations,
            Err(error) => {
                tracing::warn!(error = %error, "appliance observations were not published");
                return;
            }
        };
        match store.replace_server_observations(APPLIANCE_OBSERVATION_ID, &observations) {
            Ok(missing) => {
                for host in missing {
                    tracing::warn!(host = %host, "appliance probe declaration has no Pharos host record");
                }
            }
            Err(error) => {
                tracing::warn!(error = %error, "appliance observations could not be recorded");
            }
        }
    }
}

pub(crate) fn spawn_appliance_probe_loop(runtime: Arc<ApplianceProbeRuntime>, store: Arc<Store>) {
    tokio::spawn(async move {
        loop {
            runtime.probe_and_publish(&store, crate::now_unix()).await;
            sleep(runtime.interval()).await;
        }
    });
}

pub(crate) fn is_appliance_observation(observation: &ServiceObservation) -> bool {
    observation.id == APPLIANCE_OBSERVATION_ID
}

fn observation_for_sample(
    declaration: &ApplianceProbeDeclaration,
    state: &mut ApplianceHostProbeState,
    sample: ApplianceProbeSample,
    now: i64,
) -> ServiceObservation {
    state.checked_at = now.max(0);
    let (observation_state, summary) = match sample {
        ApplianceProbeSample::Offline => {
            state.consecutive_online_without_ssh = 0;
            (
                ServiceObservationState::Healthy,
                "powered off as expected".to_string(),
            )
        }
        ApplianceProbeSample::OnlineWithoutSsh => {
            state.consecutive_online_without_ssh = state
                .consecutive_online_without_ssh
                .saturating_add(1)
                .min(declaration.debounce_samples);
            if state.consecutive_online_without_ssh < declaration.debounce_samples {
                (
                    ServiceObservationState::Unknown,
                    format!(
                        "online; allowing SSH startup ({} of {})",
                        state.consecutive_online_without_ssh, declaration.debounce_samples
                    ),
                )
            } else {
                (
                    ServiceObservationState::Warning,
                    "un-converged: online but SSH is unavailable".to_string(),
                )
            }
        }
        ApplianceProbeSample::Converged(marker) => {
            state.consecutive_online_without_ssh = 0;
            let summary = match marker {
                MarkerResult::Valid {
                    build_id,
                    converged_at,
                } => format!("converged; build {build_id} at {converged_at}"),
                MarkerResult::Missing => "converged; marker missing".to_string(),
                MarkerResult::Invalid => "converged; marker invalid".to_string(),
                MarkerResult::Unavailable => "converged; marker unavailable".to_string(),
            };
            (ServiceObservationState::Healthy, summary)
        }
        ApplianceProbeSample::Unavailable => {
            state.consecutive_online_without_ssh = 0;
            (
                ServiceObservationState::Unknown,
                "appliance presence probe unavailable".to_string(),
            )
        }
    };
    ServiceObservation {
        id: APPLIANCE_OBSERVATION_ID.to_string(),
        label: "Appliance convergence".to_string(),
        state: observation_state,
        summary,
    }
}

async fn probe_appliance(
    declaration: &ApplianceProbeDeclaration,
    ssh: ExistingHostRuntimeConfig,
) -> ApplianceProbeSample {
    let target = declaration.target.clone();
    let presence = tokio::task::spawn_blocking(move || ping_present(&target)).await;
    match presence {
        Ok(Ok(false)) => return ApplianceProbeSample::Offline,
        Ok(Ok(true)) => {}
        Ok(Err(())) | Err(_) => return ApplianceProbeSample::Unavailable,
    }

    let ssh_open = timeout(
        SSH_PORT_TIMEOUT,
        TcpStream::connect((declaration.target.as_str(), declaration.ssh_port)),
    )
    .await;
    if !matches!(ssh_open, Ok(Ok(_))) {
        return ApplianceProbeSample::OnlineWithoutSsh;
    }

    let declaration = declaration.clone();
    let marker = tokio::task::spawn_blocking(move || read_marker(&declaration, &ssh))
        .await
        .unwrap_or(MarkerResult::Unavailable);
    ApplianceProbeSample::Converged(marker)
}

fn ping_present(target: &str) -> Result<bool, ()> {
    let mut command = Command::new(ping_binary());
    command
        .args(ping_arguments(target))
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    let mut child = command.spawn().map_err(|_| ())?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return classify_ping_exit(status.code()),
            Ok(None) if started.elapsed() < PRESENCE_TIMEOUT => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Ok(None) | Err(_) => {
                #[cfg(unix)]
                if let Ok(pid) = i32::try_from(child.id()) {
                    unsafe {
                        libc::kill(-pid, libc::SIGKILL);
                    }
                }
                let _ = child.kill();
                let _ = child.wait();
                return Err(());
            }
        }
    }
}

fn classify_ping_exit(code: Option<i32>) -> Result<bool, ()> {
    match code {
        Some(0) => Ok(true),
        // iputils and macOS ping reserve exit 1 for a completed probe that
        // received no reply. Invocation, permission, and network errors use a
        // different status and must not be misreported as a safely powered-off
        // appliance.
        Some(1) => Ok(false),
        Some(_) | None => Err(()),
    }
}

#[cfg(target_os = "macos")]
fn ping_binary() -> &'static str {
    "/sbin/ping"
}

#[cfg(not(target_os = "macos"))]
fn ping_binary() -> &'static str {
    "/bin/ping"
}

fn ping_arguments(target: &str) -> Vec<String> {
    #[cfg(target_os = "macos")]
    let wait = "1000";
    #[cfg(not(target_os = "macos"))]
    let wait = "1";
    vec![
        "-n".to_string(),
        "-c".to_string(),
        "1".to_string(),
        "-W".to_string(),
        wait.to_string(),
        target.to_string(),
    ]
}

fn read_marker(
    declaration: &ApplianceProbeDeclaration,
    ssh: &ExistingHostRuntimeConfig,
) -> MarkerResult {
    let (Some(known_hosts), Some(identity)) = (
        ssh.known_hosts_file.as_deref(),
        ssh.identity_file.as_deref(),
    ) else {
        return MarkerResult::Unavailable;
    };
    if open_trusted_runtime_file(known_hosts, 1024 * 1024, 0o022, false).is_none()
        || open_trusted_runtime_file(identity, 64 * 1024, 0o077, false).is_none()
    {
        return MarkerResult::Unavailable;
    }
    let mut child = marker_ssh_command(declaration, known_hosts, identity);
    let output = match run_child_with_deadline(&mut child, None, MARKER_SSH_TIMEOUT, 512) {
        Ok(output) => output,
        Err(_) => return MarkerResult::Unavailable,
    };
    parse_marker_response(&output)
}

fn marker_ssh_command(
    declaration: &ApplianceProbeDeclaration,
    known_hosts: &Path,
    identity: &Path,
) -> Command {
    let remote_command = marker_remote_command(&declaration.marker_path);
    let mut child = Command::new("/usr/bin/ssh");
    child
        .arg("-F")
        .arg("/dev/null")
        .arg("-o")
        .arg("BatchMode=yes")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg(format!("UserKnownHostsFile={}", known_hosts.display()))
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-o")
        .arg("ClearAllForwardings=yes")
        .arg("-o")
        .arg("PermitLocalCommand=no")
        .arg("-o")
        .arg("ConnectTimeout=8")
        .arg("-o")
        .arg("ServerAliveInterval=5")
        .arg("-o")
        .arg("ServerAliveCountMax=1")
        .arg("-o")
        .arg("LogLevel=ERROR")
        .arg("-i")
        .arg(identity)
        .arg("-p")
        .arg(declaration.ssh_port.to_string())
        .arg(declaration.ssh_target())
        .arg(remote_command)
        .env_clear()
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    child
}

fn marker_remote_command(path: &str) -> String {
    debug_assert!(valid_marker_path(path));
    format!(
        "if test -r {path}; then printf 'present\\n'; head -c {} -- {path}; else printf 'missing\\n'; fi",
        MAX_MARKER_BYTES + 1
    )
}

fn parse_marker_response(output: &[u8]) -> MarkerResult {
    if output == b"missing\n" {
        return MarkerResult::Missing;
    }
    let Some(marker) = output.strip_prefix(b"present\n") else {
        return MarkerResult::Invalid;
    };
    if marker.len() > MAX_MARKER_BYTES || !marker.is_ascii() {
        return MarkerResult::Invalid;
    }
    let Ok(marker) = std::str::from_utf8(marker) else {
        return MarkerResult::Invalid;
    };
    let marker = marker
        .strip_suffix("\r\n")
        .or_else(|| marker.strip_suffix('\n'))
        .unwrap_or(marker);
    let Some((build_id, converged_at)) = marker.split_once(' ') else {
        return MarkerResult::Invalid;
    };
    if build_id.is_empty()
        || build_id.len() > 64
        || !build_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        || converged_at.len() > 40
        || converged_at.contains(char::is_whitespace)
        || OffsetDateTime::parse(converged_at, &Rfc3339).is_err()
    {
        return MarkerResult::Invalid;
    }
    let candidate = ServiceObservation {
        id: APPLIANCE_OBSERVATION_ID.to_string(),
        label: "Appliance convergence".to_string(),
        state: ServiceObservationState::Healthy,
        summary: format!("converged; build {build_id} at {converged_at}"),
    };
    if candidate.validate_contract().is_err() {
        return MarkerResult::Invalid;
    }
    MarkerResult::Valid {
        build_id: build_id.to_string(),
        converged_at: converged_at.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> ApplianceProbeRegistry {
        serde_json::from_str(include_str!("../../../contracts/appliance-probes-v1.json")).unwrap()
    }

    fn temporary_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-appliance-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ))
    }

    fn declaration() -> ApplianceProbeDeclaration {
        ApplianceProbeDeclaration {
            host: "appliance-test".to_string(),
            target: "appliance.example.test".to_string(),
            ssh_user: "operator".to_string(),
            ssh_port: 22,
            marker_path: "/home/operator/.appliance-converged".to_string(),
            debounce_samples: 3,
        }
    }

    #[test]
    fn registry_is_strict_bounded_and_command_free() {
        let registry = registry();
        registry.validate().unwrap();

        let mut unknown_field = serde_json::to_value(&registry).unwrap();
        unknown_field
            .as_object_mut()
            .unwrap()
            .insert("command".to_string(), serde_json::json!("arbitrary"));
        assert!(serde_json::from_value::<ApplianceProbeRegistry>(unknown_field).is_err());

        let mut duplicate = registry.clone();
        duplicate.appliances.push(duplicate.appliances[0].clone());
        assert!(duplicate.validate().is_err());

        let mut unsafe_path = registry.clone();
        unsafe_path.appliances[0].marker_path = "/home/operator/../secret".to_string();
        assert!(unsafe_path.validate().is_err());

        let mut unsafe_target = registry;
        unsafe_target.appliances[0].target = "host; cat /etc/passwd".to_string();
        assert!(unsafe_target.validate().is_err());
    }

    #[test]
    fn debounce_distinguishes_offline_grace_unconverged_and_converged() {
        let declaration = declaration();
        let mut state = ApplianceHostProbeState::default();

        let offline =
            observation_for_sample(&declaration, &mut state, ApplianceProbeSample::Offline, 100);
        assert_eq!(offline.state, ServiceObservationState::Healthy);
        assert_eq!(offline.summary, "powered off as expected");

        for expected in 1..3 {
            let grace = observation_for_sample(
                &declaration,
                &mut state,
                ApplianceProbeSample::OnlineWithoutSsh,
                100 + i64::from(expected),
            );
            assert_eq!(grace.state, ServiceObservationState::Unknown);
            assert!(grace.summary.contains(&format!("{expected} of 3")));
        }
        let unconverged = observation_for_sample(
            &declaration,
            &mut state,
            ApplianceProbeSample::OnlineWithoutSsh,
            103,
        );
        assert_eq!(unconverged.state, ServiceObservationState::Warning);
        assert!(unconverged.summary.starts_with("un-converged:"));

        let converged = observation_for_sample(
            &declaration,
            &mut state,
            ApplianceProbeSample::Converged(MarkerResult::Valid {
                build_id: "20260827.1".to_string(),
                converged_at: "2026-08-27T20:15:00Z".to_string(),
            }),
            104,
        );
        assert_eq!(converged.state, ServiceObservationState::Healthy);
        assert_eq!(state.consecutive_online_without_ssh, 0);
        assert_eq!(
            converged.summary,
            "converged; build 20260827.1 at 2026-08-27T20:15:00Z"
        );

        let unknown = observation_for_sample(
            &declaration,
            &mut state,
            ApplianceProbeSample::Unavailable,
            105,
        );
        assert_eq!(unknown.state, ServiceObservationState::Unknown);
        assert_eq!(state.consecutive_online_without_ssh, 0);
        for observation in [offline, unconverged, converged, unknown] {
            observation.validate_contract().unwrap();
        }
    }

    #[test]
    fn debounce_survives_restart_without_persisting_probe_targets() {
        let state_path = temporary_path("debounce");
        let runtime = ApplianceProbeRuntime::new(
            registry(),
            state_path.clone(),
            ExistingHostRuntimeConfig::default(),
        )
        .unwrap();
        let declaration = declaration();
        for now in [100, 101] {
            let observations = runtime
                .apply_samples(
                    vec![(declaration.clone(), ApplianceProbeSample::OnlineWithoutSsh)],
                    now,
                )
                .unwrap();
            assert_eq!(
                observations["appliance-test"].state,
                ServiceObservationState::Unknown
            );
        }
        drop(runtime);

        let persisted = std::fs::read_to_string(&state_path).unwrap();
        assert!(!persisted.contains("appliance.example.test"));
        assert!(!persisted.contains(".appliance-converged"));
        let reloaded = ApplianceProbeRuntime::new(
            registry(),
            state_path.clone(),
            ExistingHostRuntimeConfig::default(),
        )
        .unwrap();
        let observations = reloaded
            .apply_samples(
                vec![(declaration.clone(), ApplianceProbeSample::OnlineWithoutSsh)],
                102,
            )
            .unwrap();
        assert_eq!(
            observations["appliance-test"].state,
            ServiceObservationState::Warning
        );
        assert!(observations["appliance-test"]
            .summary
            .starts_with("un-converged:"));
        drop(reloaded);

        let after_long_gap = ApplianceProbeRuntime::new(
            registry(),
            state_path.clone(),
            ExistingHostRuntimeConfig::default(),
        )
        .unwrap()
        .apply_samples(
            vec![(declaration, ApplianceProbeSample::OnlineWithoutSsh)],
            1_000,
        )
        .unwrap();
        assert_eq!(
            after_long_gap["appliance-test"].state,
            ServiceObservationState::Unknown
        );
        assert!(after_long_gap["appliance-test"].summary.contains("1 of 3"));

        let _ = std::fs::remove_file(state_path);
    }

    #[test]
    fn marker_parser_accepts_only_two_sanitized_bounded_facts() {
        assert_eq!(
            parse_marker_response(b"present\n20260827.1 2026-08-27T20:15:00Z\n"),
            MarkerResult::Valid {
                build_id: "20260827.1".to_string(),
                converged_at: "2026-08-27T20:15:00Z".to_string(),
            }
        );
        assert_eq!(parse_marker_response(b"missing\n"), MarkerResult::Missing);
        for invalid in [
            b"present\n".as_slice(),
            b"present\nbuild-only".as_slice(),
            b"present\npassword=secret 2026-08-27T20:15:00Z".as_slice(),
            b"present\npassword 2026-08-27T20:15:00Z".as_slice(),
            b"present\nbuild 27 August 2026".as_slice(),
            b"present\n build 2026-08-27T20:15:00Z".as_slice(),
            b"present\nbuild  2026-08-27T20:15:00Z".as_slice(),
            b"credential-bearing-output".as_slice(),
        ] {
            assert_eq!(parse_marker_response(invalid), MarkerResult::Invalid);
        }
        let oversized = [b"present\n".as_slice(), &vec![b'a'; MAX_MARKER_BYTES + 1]].concat();
        assert_eq!(parse_marker_response(&oversized), MarkerResult::Invalid);
    }

    #[test]
    fn ping_and_marker_commands_are_fixed_and_argument_safe() {
        let declaration = declaration();
        assert_eq!(
            ping_arguments(&declaration.target),
            vec![
                "-n",
                "-c",
                "1",
                "-W",
                if cfg!(target_os = "macos") {
                    "1000"
                } else {
                    "1"
                },
                "appliance.example.test"
            ]
        );
        assert_eq!(
            marker_remote_command(&declaration.marker_path),
            "if test -r /home/operator/.appliance-converged; then printf 'present\\n'; head -c 257 -- /home/operator/.appliance-converged; else printf 'missing\\n'; fi"
        );
        let command = marker_ssh_command(
            &declaration,
            Path::new("/run/pharos/known-hosts"),
            Path::new("/run/pharos/appliance-key"),
        );
        let arguments: Vec<_> = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect();
        assert_eq!(arguments[0..2], ["-F", "/dev/null"]);
        for fixed in [
            "BatchMode=yes",
            "PasswordAuthentication=no",
            "KbdInteractiveAuthentication=no",
            "StrictHostKeyChecking=yes",
            "IdentitiesOnly=yes",
            "IdentityAgent=none",
            "ClearAllForwardings=yes",
            "PermitLocalCommand=no",
        ] {
            assert!(arguments.iter().any(|argument| argument == fixed));
        }
        assert_eq!(
            arguments[arguments.len() - 2],
            "operator@appliance.example.test"
        );
        assert_eq!(
            arguments.last().unwrap(),
            "if test -r /home/operator/.appliance-converged; then printf 'present\\n'; head -c 257 -- /home/operator/.appliance-converged; else printf 'missing\\n'; fi"
        );
        assert_eq!(classify_ping_exit(Some(0)), Ok(true));
        assert_eq!(classify_ping_exit(Some(1)), Ok(false));
        assert_eq!(classify_ping_exit(Some(2)), Err(()));
        assert_eq!(classify_ping_exit(None), Err(()));
    }
}
