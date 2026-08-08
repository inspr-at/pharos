//! Host store: a serialized in-memory map with transactional durable snapshots.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pharos_core::{
    Host, HostPreferences, HostRegistration, HostReport, InboundRttObservation, NixFreshness,
    UnixSeconds,
};

use crate::durable_file::{atomic_write_json, load_optional_json, DurableFileError};

const HEARTBEAT_RETENTION_SECS: UnixSeconds = 24 * 3600;
const MAX_HEARTBEAT_LOG: usize = 3_000;

#[derive(Debug)]
pub(crate) enum StoreError {
    Persistence(DurableFileError),
    InvalidState(&'static str),
    InvalidContract,
    HostNotFound,
    InvalidPreferences,
}

impl StoreError {
    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::HostNotFound => "host not found",
            Self::InvalidContract => "invalid host contract",
            Self::InvalidPreferences => "invalid host preferences",
            Self::Persistence(_) | Self::InvalidState(_) => {
                "fleet state could not be durably recorded"
            }
        }
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistence(error) => write!(formatter, "{error}"),
            Self::InvalidState(reason) => write!(formatter, "invalid host store: {reason}"),
            Self::InvalidContract => formatter.write_str("invalid host contract"),
            Self::HostNotFound => formatter.write_str("host not found"),
            Self::InvalidPreferences => formatter.write_str("invalid host preferences"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<DurableFileError> for StoreError {
    fn from(error: DurableFileError) -> Self {
        Self::Persistence(error)
    }
}

pub(crate) struct Store {
    /// `None` = in-memory only (ephemeral). `Some(path)` = persist to JSON.
    path: Option<PathBuf>,
    hosts: RwLock<BTreeMap<String, Host>>,
}

impl Store {
    /// Load from the JSON file at `path` (if set and present), else start empty.
    /// Corrupt, unreadable, or internally inconsistent state rejects startup.
    pub(crate) fn new(path: Option<PathBuf>) -> Result<Self, StoreError> {
        let loaded = match path.as_deref() {
            Some(path) => load_optional_json::<Vec<Host>>(path)?.unwrap_or_default(),
            None => Vec::new(),
        };
        let mut hosts = BTreeMap::new();
        for mut host in loaded {
            if host.name.trim().is_empty() {
                return Err(StoreError::InvalidState("host name is empty"));
            }
            if host.heartbeat_log.is_empty() {
                if let Some(last_seen) = host.last_seen {
                    host.heartbeat_log.push(last_seen);
                }
            }
            trim_heartbeat_log(&mut host.heartbeat_log, current_unix());
            if hosts.insert(host.name.clone(), host).is_some() {
                return Err(StoreError::InvalidState("duplicate host name"));
            }
        }
        Ok(Self {
            path,
            hosts: RwLock::new(hosts),
        })
    }

    pub(crate) fn list(&self) -> Vec<Host> {
        self.hosts
            .read()
            .expect("store lock")
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn get(&self, host: &str) -> Option<Host> {
        self.hosts.read().expect("store lock").get(host).cloned()
    }

    pub(crate) fn remove(&self, host: &str) -> Result<Option<Host>, StoreError> {
        let mut hosts = self.hosts.write().expect("store lock");
        let removed = hosts.remove(host);
        if let Some(previous) = removed.as_ref() {
            if let Err(error) = self.persist(&hosts) {
                if !store_error_replaced_final_file(&error) {
                    hosts.insert(host.to_string(), previous.clone());
                }
                return Err(error);
            }
        }
        Ok(removed)
    }

    /// Register or rotate a host token. Existing heartbeat/report data is kept
    /// so manual rotation does not make a live host look new again.
    pub(crate) fn register(
        &self,
        registration: HostRegistration,
        token_hash: String,
    ) -> Result<Host, StoreError> {
        registration
            .validate_contract()
            .map_err(|_| StoreError::InvalidContract)?;
        let mut map = self.hosts.write().expect("store lock");
        let existing = map.get(&registration.name);
        let host = Host {
            name: registration.name.clone(),
            role: registration.role,
            is_nix: registration.is_nix,
            report_version: existing
                .map(|h| h.report_version)
                .unwrap_or(pharos_core::HOST_REPORT_VERSION),
            token_hash: Some(token_hash),
            last_seen: existing.and_then(|h| h.last_seen),
            heartbeat_log: existing
                .map(|h| h.heartbeat_log.clone())
                .unwrap_or_default(),
            heartbeat_interval_secs: Some(registration.heartbeat_interval_secs),
            inbound_rtt: existing.and_then(|h| h.inbound_rtt),
            location: existing.and_then(|h| h.location.clone()),
            freshness: existing
                .map(|h| h.freshness.clone())
                .unwrap_or_else(|| NixFreshness {
                    applicable: registration.is_nix,
                    ..Default::default()
                }),
            kernel: existing.and_then(|h| h.kernel.clone()),
            service_observations: existing
                .map(|h| h.service_observations.clone())
                .unwrap_or_default(),
            backup_observations: existing
                .map(|h| h.backup_observations.clone())
                .unwrap_or_default(),
            preferences: existing.map(|h| h.preferences.clone()).unwrap_or_default(),
            requested_preferences: existing.and_then(|h| h.requested_preferences.clone()),
        };
        let previous = map.insert(registration.name.clone(), host.clone());
        if let Err(error) = self.persist(&map) {
            if !store_error_replaced_final_file(&error) {
                match previous {
                    Some(previous) => {
                        map.insert(registration.name, previous);
                    }
                    None => {
                        map.remove(&registration.name);
                    }
                }
            }
            return Err(error);
        }
        Ok(host)
    }

    #[cfg(test)]
    pub(crate) fn has_token(&self, host: &str) -> bool {
        self.hosts
            .read()
            .expect("store lock")
            .get(host)
            .and_then(|h| h.token_hash.as_deref())
            .is_some()
    }

    pub(crate) fn token_hash_for(&self, host: &str) -> Option<String> {
        self.hosts
            .read()
            .expect("store lock")
            .get(host)
            .and_then(|h| h.token_hash.clone())
    }

    pub(crate) fn request_preferences(
        &self,
        host_name: &str,
        requested: HostPreferences,
    ) -> Result<Host, StoreError> {
        requested
            .validate_contract()
            .map_err(|_| StoreError::InvalidPreferences)?;
        let mut map = self.hosts.write().expect("store lock");
        let host = map.get_mut(host_name).ok_or(StoreError::HostNotFound)?;
        let previous = host.requested_preferences.clone();
        host.requested_preferences = if host.preferences == requested {
            None
        } else {
            Some(requested)
        };
        let host = host.clone();
        if let Err(error) = self.persist(&map) {
            if !store_error_replaced_final_file(&error) {
                map.get_mut(host_name)
                    .expect("mutated host remains present")
                    .requested_preferences = previous;
            }
            return Err(error);
        }
        Ok(host)
    }

    /// Upsert from a beacon report. `now` is the **server** receive time — the
    /// agent never asserts its own liveness (PHAROS-9).
    pub(crate) fn record(&self, report: HostReport, now: UnixSeconds) -> Result<(), StoreError> {
        report
            .validate_contract()
            .map_err(|_| StoreError::InvalidContract)?;
        let mut map = self.hosts.write().expect("store lock");
        let existing = map.get(&report.name);
        let token_hash = existing.and_then(|h| h.token_hash.clone());
        let mut heartbeat_log = existing
            .map(|h| h.heartbeat_log.clone())
            .unwrap_or_default();
        if heartbeat_log.last().copied() != Some(now) {
            heartbeat_log.push(now);
        }
        trim_heartbeat_log(&mut heartbeat_log, now);
        let inbound_rtt = report.inbound_rtt_ms.map(|millis| InboundRttObservation {
            millis,
            observed_at: now,
        });
        let requested_preferences = existing
            .and_then(|host| host.requested_preferences.clone())
            .filter(|requested| requested != &report.preferences);
        let host_name = report.name.clone();
        let previous = map.insert(
            host_name.clone(),
            Host {
                name: report.name,
                role: report.role,
                is_nix: report.is_nix,
                report_version: report.version,
                token_hash,
                last_seen: Some(now),
                heartbeat_log,
                heartbeat_interval_secs: Some(report.heartbeat_interval_secs),
                inbound_rtt,
                location: report.location,
                freshness: report.freshness,
                kernel: report.kernel,
                service_observations: report.service_observations,
                backup_observations: report.backup_observations,
                preferences: report.preferences,
                requested_preferences,
            },
        );
        if let Err(error) = self.persist(&map) {
            if !store_error_replaced_final_file(&error) {
                match previous {
                    Some(previous) => {
                        map.insert(host_name, previous);
                    }
                    None => {
                        map.remove(&host_name);
                    }
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn persist(&self, hosts: &BTreeMap<String, Host>) -> Result<(), StoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let snapshot: Vec<_> = hosts.values().cloned().collect();
        atomic_write_json(path, &snapshot).map_err(StoreError::from)
    }
}

fn store_error_replaced_final_file(error: &StoreError) -> bool {
    matches!(error, StoreError::Persistence(error) if error.final_file_replaced())
}

fn current_unix() -> UnixSeconds {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn trim_heartbeat_log(log: &mut Vec<UnixSeconds>, now: UnixSeconds) {
    log.sort_unstable();
    log.dedup();
    let cutoff = now.saturating_sub(HEARTBEAT_RETENTION_SECS);
    log.retain(|stamp| *stamp >= cutoff);
    if log.len() > MAX_HEARTBEAT_LOG {
        log.drain(0..log.len() - MAX_HEARTBEAT_LOG);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::{
        BackupConfiguredState, BackupEngine, BackupObservation, BackupPostureState, BackupRunState,
        KernelPosture, KernelPostureState, NixFreshness, HOST_REGISTRATION_SCHEMA,
        HOST_REGISTRATION_VERSION, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION,
    };
    use std::sync::Arc;

    fn backup_observation(state: BackupPostureState) -> BackupObservation {
        BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: BackupEngine::Restic,
            state,
            configured: BackupConfiguredState::Enabled,
            summary: "last backup succeeded".to_string(),
            target_label: Some("off-box repository".to_string()),
            repository_id: Some("restic-main-repository".to_string()),
            schedule: Some("hourly".to_string()),
            next_run_at: None,
            last_attempt_at: Some(1_700_000_000),
            last_attempt_state: Some(BackupRunState::Succeeded),
            last_success_at: Some(1_700_000_000),
            snapshot_count: Some(3),
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: None,
        }
    }

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pharos-store-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        std::fs::create_dir(&path).expect("temporary directory created");
        path
    }

    fn registration(name: &str) -> HostRegistration {
        HostRegistration {
            schema: HOST_REGISTRATION_SCHEMA.to_string(),
            version: HOST_REGISTRATION_VERSION,
            name: name.to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
        }
    }

    fn basic_report(name: &str) -> HostReport {
        HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: name.to_string(),
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

    #[test]
    fn store_revalidates_registration_and_report_before_mutation() {
        let store = Store::new(None).expect("in-memory store starts");
        let invalid_registration = HostRegistration {
            heartbeat_interval_secs: 0,
            ..registration("athena")
        };
        assert!(matches!(
            store.register(invalid_registration, "hash".to_string()),
            Err(StoreError::InvalidContract)
        ));
        assert!(store.list().is_empty());

        let invalid_report = HostReport {
            name: "Athena".to_string(),
            ..basic_report("athena")
        };
        assert!(matches!(
            store.record(invalid_report, 120),
            Err(StoreError::InvalidContract)
        ));
        assert!(store.list().is_empty());
    }

    #[test]
    fn corrupt_or_unreadable_startup_state_is_rejected() {
        let directory = temporary_directory("corrupt-startup");
        let path = directory.join("hosts.json");
        std::fs::write(&path, b"{not-json").expect("corrupt fixture written");
        assert!(matches!(
            Store::new(Some(path)),
            Err(StoreError::Persistence(DurableFileError::Decode(_)))
        ));
        assert!(matches!(
            Store::new(Some(directory.clone())),
            Err(StoreError::Persistence(DurableFileError::Read(_)))
        ));
        std::fs::remove_dir_all(directory).expect("temporary directory removed");
    }

    #[test]
    fn every_mutation_rolls_back_when_atomic_rename_fails() {
        let directory = temporary_directory("rollback");
        let failing_path = directory.join("destination-is-a-directory");
        std::fs::create_dir(&failing_path).expect("failing destination created");

        let store = Store {
            path: Some(failing_path.clone()),
            hosts: RwLock::new(BTreeMap::new()),
        };
        assert!(store
            .register(registration("new-host"), "hash".into())
            .is_err());
        assert!(store.get("new-host").is_none());
        assert!(store.record(basic_report("reported-host"), 100).is_err());
        assert!(store.get("reported-host").is_none());

        let seed = Store::new(None).expect("in-memory store starts");
        let host = seed
            .register(registration("existing-host"), "hash".into())
            .expect("seed host registers");
        let mut hosts = BTreeMap::new();
        hosts.insert(host.name.clone(), host);
        let store = Store {
            path: Some(failing_path),
            hosts: RwLock::new(hosts),
        };
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        assert!(store
            .request_preferences("existing-host", requested)
            .is_err());
        assert!(store
            .get("existing-host")
            .expect("host rolled back")
            .requested_preferences
            .is_none());
        assert!(store.remove("existing-host").is_err());
        assert!(store.get("existing-host").is_some());

        std::fs::remove_dir_all(directory).expect("temporary directory removed");
    }

    #[test]
    fn concurrent_mutations_persist_in_lock_order_without_lost_hosts() {
        let directory = temporary_directory("concurrency");
        let path = directory.join("hosts.json");
        let store = Arc::new(Store::new(Some(path.clone())).expect("durable store starts"));
        let workers: Vec<_> = (0..24)
            .map(|index| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    let name = format!("host-{index:02}");
                    store
                        .register(registration(&name), format!("hash-{index}"))
                        .expect("concurrent registration persists");
                })
            })
            .collect();
        for worker in workers {
            worker.join().expect("registration worker completes");
        }
        assert_eq!(store.list().len(), 24);
        drop(store);

        let reloaded = Store::new(Some(path.clone())).expect("concurrent snapshot reloads");
        assert_eq!(reloaded.list().len(), 24);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(path)
                    .expect("snapshot metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        std::fs::remove_dir_all(directory).expect("temporary directory removed");
    }

    #[test]
    fn incomplete_temporary_file_does_not_replace_committed_snapshot() {
        let directory = temporary_directory("crash");
        let path = directory.join("hosts.json");
        let store = Store::new(Some(path.clone())).expect("durable store starts");
        store
            .register(registration("committed-host"), "hash".into())
            .expect("committed snapshot written");
        std::fs::write(directory.join(".hosts.json.tmp-crash"), b"[")
            .expect("incomplete temporary fixture written");
        drop(store);

        let reloaded = Store::new(Some(path)).expect("committed snapshot survives");
        assert!(reloaded.get("committed-host").is_some());
        std::fs::remove_dir_all(directory).expect("temporary directory removed");
    }

    #[test]
    fn record_retains_recent_real_heartbeat_events() {
        let store = Store::new(None).expect("in-memory store starts");

        for now in 1..=(MAX_HEARTBEAT_LOG + 6) as UnixSeconds {
            store
                .record(
                    HostReport {
                        schema: HOST_REPORT_SCHEMA.to_string(),
                        version: HOST_REPORT_VERSION,
                        name: "poseidon".to_string(),
                        role: "NixOS Host".to_string(),
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
                    },
                    now,
                )
                .expect("heartbeat persists");
        }

        let host = store.list().pop().expect("host recorded");
        assert_eq!(host.last_seen, Some((MAX_HEARTBEAT_LOG + 6) as UnixSeconds));
        assert_eq!(host.heartbeat_log.len(), MAX_HEARTBEAT_LOG);
        assert_eq!(host.heartbeat_log.first(), Some(&7));
        assert_eq!(
            host.heartbeat_log.last(),
            Some(&((MAX_HEARTBEAT_LOG + 6) as UnixSeconds))
        );
    }

    #[test]
    fn heartbeat_log_retains_roughly_twenty_four_hours() {
        let mut log = vec![1, 3600, 86_399, 86_400, 86_401];

        trim_heartbeat_log(&mut log, 86_401);

        assert_eq!(log, vec![1, 3600, 86_399, 86_400, 86_401]);

        trim_heartbeat_log(&mut log, 172_801);

        assert_eq!(log, vec![86_401]);
    }

    #[test]
    fn register_preserves_report_history_and_sets_token_hash() {
        let store = Store::new(None).expect("in-memory store starts");
        let backup = backup_observation(BackupPostureState::Healthy);
        store
            .record(
                HostReport {
                    schema: HOST_REPORT_SCHEMA.to_string(),
                    version: HOST_REPORT_VERSION,
                    name: "athena".to_string(),
                    role: "NixOS Host".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 60,
                    freshness: NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(1),
                        commits_behind: Some(0),
                        nixpkgs_age_days: None,
                        nixpkgs_channel: None,
                    },
                    kernel: Some(KernelPosture::observed(
                        true,
                        Some("6.18.26".to_string()),
                        Some("7.0.14".to_string()),
                        120,
                    )),
                    service_observations: vec![pharos_core::ServiceObservation::nix_freshness(
                        &NixFreshness {
                            applicable: true,
                            flake_lock_age_days: Some(1),
                            commits_behind: Some(0),
                            nixpkgs_age_days: None,
                            nixpkgs_channel: None,
                        },
                    )],
                    backup_observations: vec![backup.clone()],
                    inbound_rtt_ms: Some(37),
                    location: None,
                    preferences: Default::default(),
                },
                120,
            )
            .expect("report persists");

        let host = store
            .register(
                HostRegistration {
                    schema: HOST_REGISTRATION_SCHEMA.to_string(),
                    version: HOST_REGISTRATION_VERSION,
                    name: "athena".to_string(),
                    role: "Control Server".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 30,
                },
                "hash".to_string(),
            )
            .expect("registration persists");

        assert_eq!(host.token_hash.as_deref(), Some("hash"));
        assert_eq!(host.last_seen, Some(120));
        assert_eq!(host.heartbeat_log, vec![120]);
        assert_eq!(host.heartbeat_interval_secs, Some(30));
        assert_eq!(host.inbound_rtt.expect("rtt kept").millis, 37);
        assert_eq!(host.freshness.flake_lock_age_days, Some(1));
        assert_eq!(
            host.kernel.as_ref().map(|kernel| kernel.state),
            Some(KernelPostureState::RebootRequired)
        );
        assert_eq!(host.backup_observations, vec![backup]);
        assert!(store.has_token("athena"));
        assert_eq!(store.token_hash_for("athena").as_deref(), Some("hash"));

        store
            .record(
                HostReport {
                    schema: HOST_REPORT_SCHEMA.to_string(),
                    version: HOST_REPORT_VERSION,
                    name: "athena".to_string(),
                    role: "Control Server".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 30,
                    freshness: NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(0),
                        commits_behind: Some(0),
                        nixpkgs_age_days: None,
                        nixpkgs_channel: None,
                    },
                    kernel: None,
                    service_observations: vec![],
                    backup_observations: vec![],
                    inbound_rtt_ms: None,
                    location: None,
                    preferences: Default::default(),
                },
                150,
            )
            .expect("updated report persists");

        let updated = store.list().pop().expect("host remains recorded");
        assert_eq!(updated.token_hash.as_deref(), Some("hash"));
        assert_eq!(updated.last_seen, Some(150));
        assert!(updated.inbound_rtt.is_none());
        assert!(updated.backup_observations.is_empty());
    }

    #[test]
    fn preference_request_persists_until_matching_host_report_applies_it() {
        let path = std::env::temp_dir().join(format!(
            "pharos-host-preferences-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        let report = |preferences: HostPreferences| HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: "athena".to_string(),
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
            preferences,
        };
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            alerts: pharos_core::HostAlertPreferences {
                suppress_down: true,
                suppress_backup: false,
                suppress_nix_freshness: true,
            },
            ..Default::default()
        };

        let store = Store::new(Some(path.clone())).expect("durable store starts");
        store
            .record(report(HostPreferences::default()), 100)
            .expect("initial report persists");
        let queued = store
            .request_preferences("athena", requested.clone())
            .expect("request queued");
        assert_eq!(queued.preferences, HostPreferences::default());
        assert_eq!(queued.requested_preferences.as_ref(), Some(&requested));
        drop(store);

        let reloaded = Store::new(Some(path.clone())).expect("durable store reloads");
        assert_eq!(
            reloaded.list()[0].requested_preferences.as_ref(),
            Some(&requested)
        );

        reloaded
            .record(report(HostPreferences::default()), 160)
            .expect("old report persists");
        assert_eq!(
            reloaded.list()[0].requested_preferences.as_ref(),
            Some(&requested),
            "an old host report must not acknowledge a pending request"
        );

        reloaded
            .record(report(requested.clone()), 220)
            .expect("matching report persists");
        let applied = reloaded.list().pop().expect("host remains");
        assert_eq!(applied.preferences, requested);
        assert!(applied.requested_preferences.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn preference_request_rejects_invalid_or_unknown_host_state() {
        let store = Store::new(None).expect("in-memory store starts");
        let malformed = HostPreferences {
            accent: Some("orange".to_string()),
            ..Default::default()
        };

        assert!(matches!(
            store.request_preferences("missing", HostPreferences::default()),
            Err(StoreError::HostNotFound)
        ));
        assert!(matches!(
            store.request_preferences("missing", malformed),
            Err(StoreError::InvalidPreferences)
        ));
    }
}
