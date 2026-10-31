//! Reachability of hosts that cannot report for themselves.
//!
//! One ICMP check and one TCP connection per host, with no credential and nothing
//! run on the far side, so a probe can only say whether a host answered. Its
//! versions stay hand-declared. No probe target reaches an observation. The last
//! time a host answered survives a restart, because a client's offline thresholds
//! count from it.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{sleep, timeout};

use crate::durable_file::{atomic_write_json, load_optional_json, DurableFileError};
use crate::probe_support::{read_trusted_runtime_file, valid_bootstrap_name, valid_ssh_endpoint};

const HOST_PROBE_REGISTRY_ENV: &str = "PHAROS_HOST_PROBES_PATH";
const HOST_PROBE_REGISTRY_SCHEMA: &str = "inspr.pharos.host-probes.v1";
const HOST_PROBE_REGISTRY_VERSION: u16 = 1;
const HOST_PROBE_STATE_SCHEMA: &str = "inspr.pharos.host-probe-state.v1";
const HOST_PROBE_STATE_VERSION: u16 = 1;
const MAX_REGISTRY_BYTES: u64 = 64 * 1024;
const MAX_HOSTS: usize = 64;
const DEFAULT_PROBE_INTERVAL_SECS: u64 = 30;
const MIN_PROBE_INTERVAL_SECS: u64 = 10;
const MAX_PROBE_INTERVAL_SECS: u64 = 3600;
const STALE_AFTER_INTERVALS: u64 = 3;
// Past ping's own wait, which takes about two seconds on macOS for a one-second -W.
const PRESENCE_TIMEOUT: Duration = Duration::from_secs(3);
const TCP_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostProbeRegistry {
    schema: String,
    version: u16,
    #[serde(default = "default_probe_interval_secs")]
    probe_interval_secs: u64,
    hosts: Vec<HostProbeDeclaration>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostProbeDeclaration {
    host: String,
    target: String,
    #[serde(default = "default_tcp_port")]
    tcp_port: u16,
}

fn default_tcp_port() -> u16 {
    22
}

fn default_probe_interval_secs() -> u64 {
    DEFAULT_PROBE_INTERVAL_SECS
}

impl HostProbeRegistry {
    fn validate(&self) -> Result<(), String> {
        if self.schema != HOST_PROBE_REGISTRY_SCHEMA || self.version != HOST_PROBE_REGISTRY_VERSION
        {
            return Err("unsupported host probe registry schema/version".to_string());
        }
        if self.hosts.is_empty() || self.hosts.len() > MAX_HOSTS {
            return Err("host probe registry must contain 1..=64 hosts".to_string());
        }
        if !(MIN_PROBE_INTERVAL_SECS..=MAX_PROBE_INTERVAL_SECS).contains(&self.probe_interval_secs)
        {
            return Err("host probe interval must be between 10 and 3600 seconds".to_string());
        }
        let mut hosts = BTreeSet::new();
        for declaration in &self.hosts {
            if !valid_bootstrap_name(&declaration.host)
                || !valid_ssh_endpoint(&declaration.target)
                || declaration.tcp_port == 0
            {
                return Err("host probe declaration is invalid".to_string());
            }
            if !hosts.insert(declaration.host.as_str()) {
                return Err("host probe registry contains a duplicate host".to_string());
            }
        }
        Ok(())
    }
}

/// What is kept across a restart. It names hosts and times, never a target.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HostProbeStateDocument {
    schema: String,
    version: u16,
    last_reachable_at: BTreeMap<String, i64>,
}

/// One host as the API and the page see it.
#[derive(Clone, Debug, Default, Serialize, PartialEq, Eq)]
pub(crate) struct HostProbeObservation {
    /// `None` until a check finishes, when the check itself could not run, or when
    /// the checks have stopped.
    pub(crate) reachable: Option<bool>,
    pub(crate) checked_at: Option<i64>,
    pub(crate) last_reachable_at: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProbeResult {
    Reachable,
    NoReply,
    /// The check could not run, which says nothing about the host.
    Unavailable,
}

pub(crate) struct HostProbeRuntime {
    registry: HostProbeRegistry,
    state_path: PathBuf,
    observations: RwLock<BTreeMap<String, HostProbeObservation>>,
}

impl HostProbeRuntime {
    pub(crate) fn from_env(host_store_path: Option<&Path>) -> Result<Option<Self>, String> {
        let Some(registry_path) =
            configured_registry_path(std::env::var(HOST_PROBE_REGISTRY_ENV).ok())
        else {
            return Ok(None);
        };
        Self::load(&registry_path, host_store_path).map(Some)
    }

    /// A registry that is configured but missing or invalid refuses startup: the
    /// operator asked for probes, and silently running without them would show
    /// hosts as out of contact.
    fn load(registry_path: &Path, host_store_path: Option<&Path>) -> Result<Self, String> {
        let bytes = read_trusted_runtime_file(registry_path, MAX_REGISTRY_BYTES, 0o022, false)
            .ok_or_else(|| "host probe registry is unavailable".to_string())?;
        let registry = serde_json::from_slice::<HostProbeRegistry>(&bytes)
            .map_err(|_| "host probe registry JSON is invalid".to_string())?;
        registry.validate()?;
        let store_path = host_store_path
            .ok_or_else(|| "host probes require PHAROS_DB for durable state".to_string())?;
        Self::new(registry, state_path_for(store_path))
    }

    fn new(registry: HostProbeRegistry, state_path: PathBuf) -> Result<Self, String> {
        let state = match load_optional_json::<HostProbeStateDocument>(&state_path) {
            Ok(Some(state))
                if state.schema == HOST_PROBE_STATE_SCHEMA
                    && state.version == HOST_PROBE_STATE_VERSION =>
            {
                state.last_reachable_at
            }
            Ok(Some(_)) | Ok(None) | Err(DurableFileError::Decode(_)) => BTreeMap::new(),
            Err(error) => return Err(error.to_string()),
        };
        let observations = registry
            .hosts
            .iter()
            .map(|declaration| {
                let observation = HostProbeObservation {
                    last_reachable_at: state
                        .get(&declaration.host)
                        .copied()
                        .filter(|time| *time >= 0),
                    ..HostProbeObservation::default()
                };
                (declaration.host.clone(), observation)
            })
            .collect();
        Ok(Self {
            registry,
            state_path,
            observations: RwLock::new(observations),
        })
    }

    fn interval(&self) -> Duration {
        Duration::from_secs(self.registry.probe_interval_secs)
    }

    pub(crate) fn snapshot(&self, now: i64) -> BTreeMap<String, HostProbeObservation> {
        let stale_after = i64::try_from(
            self.registry
                .probe_interval_secs
                .saturating_mul(STALE_AFTER_INTERVALS),
        )
        .unwrap_or(i64::MAX);
        let mut observations = self.observations.read().expect("host probe lock").clone();
        for observation in observations.values_mut() {
            let current = observation
                .checked_at
                .is_some_and(|at| at <= now && now.saturating_sub(at) <= stale_after);
            if !current {
                observation.reachable = None;
            }
        }
        observations
    }

    fn record(&self, results: Vec<(String, ProbeResult)>, now: i64) {
        let mut observations = self.observations.write().expect("host probe lock");
        let mut answered = false;
        for (host, result) in results {
            let Some(observation) = observations.get_mut(&host) else {
                continue;
            };
            observation.checked_at = Some(now);
            observation.reachable = match result {
                ProbeResult::Reachable => {
                    observation.last_reachable_at = Some(now);
                    answered = true;
                    Some(true)
                }
                ProbeResult::NoReply => Some(false),
                ProbeResult::Unavailable => None,
            };
        }
        if !answered {
            return;
        }
        let document = HostProbeStateDocument {
            schema: HOST_PROBE_STATE_SCHEMA.to_string(),
            version: HOST_PROBE_STATE_VERSION,
            last_reachable_at: observations
                .iter()
                .filter_map(|(host, observation)| {
                    observation
                        .last_reachable_at
                        .map(|time| (host.clone(), time))
                })
                .collect(),
        };
        drop(observations);
        if let Err(error) = atomic_write_json(&self.state_path, &document) {
            tracing::warn!(error = %error, "host probe state could not be saved");
        }
    }

    async fn probe_all(&self, now: i64) {
        let mut tasks = JoinSet::new();
        for declaration in self.registry.hosts.clone() {
            tasks.spawn(async move {
                let result = probe_host(&declaration).await;
                (declaration.host, result)
            });
        }
        let mut results = Vec::with_capacity(self.registry.hosts.len());
        while let Some(result) = tasks.join_next().await {
            if let Ok(result) = result {
                results.push(result);
            }
        }
        self.record(results, now);
    }
}

fn configured_registry_path(value: Option<String>) -> Option<PathBuf> {
    value
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn state_path_for(store_path: &Path) -> PathBuf {
    let name = store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("pharos.json");
    store_path.with_file_name(format!("{name}.host-probes.json"))
}

pub(crate) fn spawn_host_probe_loop(runtime: Arc<HostProbeRuntime>) {
    tokio::spawn(async move {
        loop {
            runtime.probe_all(crate::now_unix()).await;
            sleep(runtime.interval()).await;
        }
    });
}

/// Either signal counts, because a host can drop one and answer the other: a Mac in
/// stealth mode ignores ICMP, and a Pi may run no SSH.
async fn probe_host(declaration: &HostProbeDeclaration) -> ProbeResult {
    let target = declaration.target.clone();
    let presence = tokio::task::spawn_blocking(move || ping_present(&target))
        .await
        .unwrap_or(Err(()));
    answer_after_ping(presence, declaration).await
}

async fn answer_after_ping(
    presence: Result<bool, ()>,
    declaration: &HostProbeDeclaration,
) -> ProbeResult {
    if presence == Ok(true) {
        return ProbeResult::Reachable;
    }
    let connected = timeout(
        TCP_TIMEOUT,
        TcpStream::connect((declaration.target.as_str(), declaration.tcp_port)),
    )
    .await;
    if matches!(connected, Ok(Ok(_))) {
        return ProbeResult::Reachable;
    }
    match presence {
        Ok(false) => ProbeResult::NoReply,
        Ok(true) | Err(()) => ProbeResult::Unavailable,
    }
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
    #[cfg(target_os = "macos")]
    const NO_REPLY: i32 = 2;
    #[cfg(not(target_os = "macos"))]
    const NO_REPLY: i32 = 1;
    match code {
        Some(0) => Ok(true),
        // iputils reserves exit 1 and macOS ping reserves exit 2 for a completed
        // probe that received no reply. Other statuses are errors and must not be
        // misreported as a host that did not answer.
        Some(code) if code == NO_REPLY => Ok(false),
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

#[cfg(test)]
pub(crate) fn runtime_for_test(hosts: &[&str]) -> (Arc<HostProbeRuntime>, TestDirectory) {
    let directory = TestDirectory::new("api");
    let registry = HostProbeRegistry {
        schema: HOST_PROBE_REGISTRY_SCHEMA.to_string(),
        version: HOST_PROBE_REGISTRY_VERSION,
        probe_interval_secs: 60,
        hosts: hosts
            .iter()
            .map(|host| HostProbeDeclaration {
                host: host.to_string(),
                target: format!("{host}.example.test"),
                tcp_port: 22,
            })
            .collect(),
    };
    let runtime = HostProbeRuntime::new(registry, directory.0.join("state.json")).expect("runtime");
    (Arc::new(runtime), directory)
}

#[cfg(test)]
pub(crate) struct TestDirectory(PathBuf);

#[cfg(test)]
impl TestDirectory {
    fn new(label: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "pharos-host-probes-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("directory created");
        Self(path)
    }
}

#[cfg(test)]
impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
impl HostProbeRuntime {
    pub(crate) fn record_reachable_for_test(&self, host: &str, now: i64) {
        self.record(vec![(host.to_string(), ProbeResult::Reachable)], now);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    const CONTRACT: &str = include_str!("../../../contracts/host-probes-v1.json");
    const NOW: i64 = 951_868_800;

    fn registry() -> HostProbeRegistry {
        serde_json::from_str(CONTRACT).expect("contract parses")
    }

    fn write_registry(directory: &TestDirectory, content: &str) -> PathBuf {
        let path = directory.0.join("registry.json");
        std::fs::write(&path, content).expect("registry written");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("mode");
        path
    }

    fn store_path(directory: &TestDirectory) -> PathBuf {
        directory.0.join("pharos.json")
    }

    fn runtime_in(directory: &TestDirectory) -> HostProbeRuntime {
        HostProbeRuntime::new(registry(), state_path_for(&store_path(directory))).expect("runtime")
    }

    #[test]
    fn registry_is_strict_bounded_and_command_free() {
        let good = registry();
        good.validate().expect("the contract is valid");
        assert_eq!(good.hosts[0].tcp_port, 22, "the port defaults to SSH");

        let mut unknown_field = serde_json::to_value(&good).expect("value");
        unknown_field["command"] = serde_json::json!("arbitrary");
        assert!(serde_json::from_value::<HostProbeRegistry>(unknown_field).is_err());

        type Change = (&'static str, fn(&mut HostProbeRegistry));
        let changes: [Change; 7] = [
            ("wrong schema", |r| r.schema = "other".to_string()),
            ("wrong version", |r| r.version = 2),
            ("no hosts", |r| r.hosts.clear()),
            ("a duplicate host", |r| {
                let first = r.hosts[0].clone();
                r.hosts.push(first);
            }),
            ("too frequent", |r| r.probe_interval_secs = 9),
            ("too rare", |r| r.probe_interval_secs = 3601),
            ("port zero", |r| r.hosts[0].tcp_port = 0),
        ];
        for (name, change) in changes {
            let mut changed = good.clone();
            change(&mut changed);
            assert!(changed.validate().is_err(), "{name}");
        }

        let mut unsafe_target = good.clone();
        for target in ["host; cat /etc/passwd", "-oProxyCommand=x", ""] {
            unsafe_target.hosts[0].target = target.to_string();
            assert!(unsafe_target.validate().is_err(), "{target}");
        }

        let mut too_many = good.clone();
        too_many.hosts = (0..=MAX_HOSTS)
            .map(|index| HostProbeDeclaration {
                host: format!("host-{index}"),
                target: "192.0.2.1".to_string(),
                tcp_port: 22,
            })
            .collect();
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn probes_are_off_unless_a_path_is_configured() {
        assert_eq!(configured_registry_path(None), None);
        assert_eq!(configured_registry_path(Some(String::new())), None);
        assert_eq!(configured_registry_path(Some("  ".to_string())), None);
        assert_eq!(
            configured_registry_path(Some(" /etc/probes.json ".to_string())),
            Some(PathBuf::from("/etc/probes.json"))
        );
    }

    #[test]
    fn a_configured_registry_that_is_missing_or_invalid_refuses_startup() {
        let directory = TestDirectory::new("refuse");
        let store = store_path(&directory);
        let error = |path: &Path| {
            HostProbeRuntime::load(path, Some(&store))
                .err()
                .expect("startup is refused")
        };

        assert_eq!(
            error(&directory.0.join("missing.json")),
            "host probe registry is unavailable"
        );

        let path = write_registry(&directory, "not json");
        assert_eq!(error(&path), "host probe registry JSON is invalid");

        let path = write_registry(&directory, r#"{"schema":"x","version":1,"hosts":[]}"#);
        assert_eq!(
            error(&path),
            "unsupported host probe registry schema/version"
        );

        // The file shape this replaces asks for fields that no longer exist.
        let path = write_registry(
            &directory,
            r#"{"schema":"inspr.pharos.host-probes.v1","version":1,"hosts":[{"host":"a","target":"b","marker_path":"/x"}]}"#,
        );
        assert_eq!(error(&path), "host probe registry JSON is invalid");

        // Anyone who can write it could aim the probes.
        let path = write_registry(&directory, CONTRACT);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).expect("mode");
        assert_eq!(error(&path), "host probe registry is unavailable");

        let link = directory.0.join("link.json");
        let path = write_registry(&directory, CONTRACT);
        std::os::unix::fs::symlink(&path, &link).expect("link");
        assert_eq!(error(&link), "host probe registry is unavailable");

        let path = write_registry(&directory, CONTRACT);
        assert_eq!(
            HostProbeRuntime::load(&path, None).err().expect("refused"),
            "host probes require PHAROS_DB for durable state"
        );
        assert!(HostProbeRuntime::load(&path, Some(&store)).is_ok());
    }

    #[test]
    fn the_last_reachable_time_survives_a_restart() {
        let directory = TestDirectory::new("restart");
        let first = runtime_in(&directory);
        first.record(vec![("hermes".to_string(), ProbeResult::Reachable)], NOW);

        let restarted = runtime_in(&directory);
        let observation = restarted.snapshot(NOW + 5)["hermes"].clone();
        assert_eq!(observation.last_reachable_at, Some(NOW));
        // Nothing is known about right now until the first check after the restart.
        assert_eq!(observation.reachable, None);
        assert_eq!(observation.checked_at, None);
        assert_eq!(
            restarted.snapshot(NOW + 5)["artemis"],
            HostProbeObservation::default()
        );
    }

    #[test]
    fn only_an_answer_moves_the_last_reachable_time() {
        let directory = TestDirectory::new("answers");
        let runtime = runtime_in(&directory);
        let host = "hermes".to_string();

        runtime.record(vec![(host.clone(), ProbeResult::NoReply)], NOW);
        assert_eq!(
            runtime.snapshot(NOW)["hermes"],
            HostProbeObservation {
                reachable: Some(false),
                checked_at: Some(NOW),
                last_reachable_at: None,
            }
        );
        assert!(
            !state_path_for(&store_path(&directory)).exists(),
            "nothing to save yet"
        );

        runtime.record(vec![(host.clone(), ProbeResult::Reachable)], NOW + 60);
        assert_eq!(
            runtime.snapshot(NOW + 60)["hermes"],
            HostProbeObservation {
                reachable: Some(true),
                checked_at: Some(NOW + 60),
                last_reachable_at: Some(NOW + 60),
            }
        );

        runtime.record(vec![(host.clone(), ProbeResult::NoReply)], NOW + 120);
        let observation = runtime.snapshot(NOW + 120)["hermes"].clone();
        assert_eq!(observation.reachable, Some(false));
        assert_eq!(observation.last_reachable_at, Some(NOW + 60));

        // A check that could not run says nothing about the host.
        runtime.record(vec![(host, ProbeResult::Unavailable)], NOW + 180);
        assert_eq!(
            runtime.snapshot(NOW + 180)["hermes"],
            HostProbeObservation {
                reachable: None,
                checked_at: Some(NOW + 180),
                last_reachable_at: Some(NOW + 60),
            }
        );
        assert_eq!(
            runtime_in(&directory).snapshot(NOW)["hermes"].last_reachable_at,
            Some(NOW + 60)
        );
    }

    #[test]
    fn a_result_stops_counting_when_the_checks_stop() {
        let directory = TestDirectory::new("stale");
        let runtime = runtime_in(&directory);
        runtime.record(vec![("hermes".to_string(), ProbeResult::Reachable)], NOW);
        let limit = runtime.registry.probe_interval_secs as i64 * STALE_AFTER_INTERVALS as i64;

        assert_eq!(
            runtime.snapshot(NOW + limit)["hermes"].reachable,
            Some(true)
        );
        let late = runtime.snapshot(NOW + limit + 1)["hermes"].clone();
        assert_eq!(late.reachable, None);
        assert_eq!(late.last_reachable_at, Some(NOW));

        // A check from the future is not a current one either.
        assert_eq!(runtime.snapshot(NOW - 1)["hermes"].reachable, None);
    }

    #[test]
    fn bad_saved_state_starts_empty_and_does_not_block_startup() {
        for (label, content) in [
            ("corrupt", "not json"),
            (
                "other-schema",
                r#"{"schema":"other","version":1,"last_reachable_at":{"hermes":5}}"#,
            ),
            (
                "unknown-field",
                r#"{"schema":"inspr.pharos.host-probe-state.v1","version":1,"last_reachable_at":{},"x":1}"#,
            ),
        ] {
            let directory = TestDirectory::new(label);
            std::fs::write(state_path_for(&store_path(&directory)), content).expect("state");
            let runtime = runtime_in(&directory);
            assert_eq!(
                runtime.snapshot(NOW)["hermes"].last_reachable_at,
                None,
                "{label}"
            );
        }

        let directory = TestDirectory::new("partly-bad");
        std::fs::write(
            state_path_for(&store_path(&directory)),
            r#"{"schema":"inspr.pharos.host-probe-state.v1","version":1,"last_reachable_at":{"hermes":-1,"artemis":5,"gone":6}}"#,
        )
        .expect("state");
        let snapshot = runtime_in(&directory).snapshot(NOW);
        assert_eq!(snapshot["hermes"].last_reachable_at, None);
        assert_eq!(snapshot["artemis"].last_reachable_at, Some(5));
        assert!(!snapshot.contains_key("gone"));
    }

    #[test]
    fn saved_state_and_observations_never_carry_a_target() {
        let directory = TestDirectory::new("targets");
        let runtime = runtime_in(&directory);
        runtime.record(vec![("hermes".to_string(), ProbeResult::Reachable)], NOW);
        let saved =
            std::fs::read_to_string(state_path_for(&store_path(&directory))).expect("saved");
        let shown = serde_json::to_string(&runtime.snapshot(NOW)).expect("serializes");
        for target in registry().hosts.iter().map(|host| host.target.clone()) {
            assert!(!saved.contains(&target), "{saved}");
            assert!(!shown.contains(&target), "{shown}");
        }
    }

    #[test]
    fn the_state_file_sits_beside_the_store_and_is_not_pharos_ones() {
        assert_eq!(
            state_path_for(Path::new("/data/pharos.json")),
            PathBuf::from("/data/pharos.json.host-probes.json")
        );
    }

    #[tokio::test]
    async fn an_open_port_is_an_answer_even_with_no_icmp() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let declaration = HostProbeDeclaration {
            host: "hermes".to_string(),
            target: "127.0.0.1".to_string(),
            tcp_port: listener.local_addr().expect("address").port(),
        };
        for presence in [Ok(false), Err(())] {
            assert_eq!(
                answer_after_ping(presence, &declaration).await,
                ProbeResult::Reachable
            );
            timeout(Duration::from_secs(2), listener.accept())
                .await
                .expect("the probe connected")
                .expect("accept");
        }

        // With the port closed the ping's own answer stands. Bound and never
        // listening, so no parallel test can pick this port up meanwhile.
        let closed = tokio::net::TcpSocket::new_v4().expect("socket");
        closed
            .bind("127.0.0.1:0".parse().expect("address"))
            .expect("bind");
        let declaration = HostProbeDeclaration {
            tcp_port: closed.local_addr().expect("address").port(),
            ..declaration
        };
        assert_eq!(
            answer_after_ping(Ok(false), &declaration).await,
            ProbeResult::NoReply
        );
        assert_eq!(
            answer_after_ping(Err(()), &declaration).await,
            ProbeResult::Unavailable
        );
        assert_eq!(
            answer_after_ping(Ok(true), &declaration).await,
            ProbeResult::Reachable
        );
    }

    #[test]
    fn the_ping_command_is_fixed_and_argument_safe() {
        assert_eq!(
            ping_arguments("hermes.example.test"),
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
                "hermes.example.test"
            ]
        );
        assert_eq!(classify_ping_exit(Some(0)), Ok(true));
        if cfg!(target_os = "macos") {
            assert_eq!(classify_ping_exit(Some(1)), Err(()));
            assert_eq!(classify_ping_exit(Some(2)), Ok(false));
        } else {
            assert_eq!(classify_ping_exit(Some(1)), Ok(false));
            assert_eq!(classify_ping_exit(Some(2)), Err(()));
        }
        assert_eq!(classify_ping_exit(None), Err(()));
    }
}
