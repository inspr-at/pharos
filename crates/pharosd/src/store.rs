//! Host store: in-memory map, optionally persisted to a JSON file. Adequate for
//! the MVP fleet (~handful of hosts). The sqlx+SQLite store (ADR-001) is
//! PHAROS-3 — swappable behind this small API without touching the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pharos_core::{
    Host, HostPreferences, HostRegistration, HostReport, InboundRttObservation, NixFreshness,
    UnixSeconds,
};

const HEARTBEAT_RETENTION_SECS: UnixSeconds = 24 * 3600;
const MAX_HEARTBEAT_LOG: usize = 3_000;

pub struct Store {
    /// `None` = in-memory only (ephemeral). `Some(path)` = persist to JSON.
    path: Option<PathBuf>,
    hosts: RwLock<BTreeMap<String, Host>>,
}

impl Store {
    /// Load from the JSON file at `path` (if set and present), else start empty.
    pub fn new(path: Option<PathBuf>) -> Self {
        let hosts = path
            .as_ref()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|bytes| serde_json::from_slice::<Vec<Host>>(&bytes).ok())
            .map(|v| {
                v.into_iter()
                    .map(|mut h| {
                        if h.heartbeat_log.is_empty() {
                            if let Some(last_seen) = h.last_seen {
                                h.heartbeat_log.push(last_seen);
                            }
                        }
                        trim_heartbeat_log(&mut h.heartbeat_log, current_unix());
                        (h.name.clone(), h)
                    })
                    .collect()
            })
            .unwrap_or_default();
        Self {
            path,
            hosts: RwLock::new(hosts),
        }
    }

    pub fn list(&self) -> Vec<Host> {
        self.hosts
            .read()
            .expect("store lock")
            .values()
            .cloned()
            .collect()
    }

    /// Register or rotate a host token. Existing heartbeat/report data is kept
    /// so manual rotation does not make a live host look new again.
    pub fn register(&self, registration: HostRegistration, token_hash: String) -> Host {
        let host = {
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
            map.insert(registration.name, host.clone());
            host
        };
        self.persist();
        host
    }

    pub fn has_token(&self, host: &str) -> bool {
        self.hosts
            .read()
            .expect("store lock")
            .get(host)
            .and_then(|h| h.token_hash.as_deref())
            .is_some()
    }

    pub fn token_hash_for(&self, host: &str) -> Option<String> {
        self.hosts
            .read()
            .expect("store lock")
            .get(host)
            .and_then(|h| h.token_hash.clone())
    }

    pub fn request_preferences(
        &self,
        host_name: &str,
        requested: HostPreferences,
    ) -> Result<Host, &'static str> {
        requested
            .validate_contract()
            .map_err(|_| "invalid host preferences")?;
        let host = {
            let mut map = self.hosts.write().expect("store lock");
            let host = map.get_mut(host_name).ok_or("host not found")?;
            host.requested_preferences = if host.preferences == requested {
                None
            } else {
                Some(requested)
            };
            host.clone()
        };
        self.persist();
        Ok(host)
    }

    /// Upsert from a beacon report. `now` is the **server** receive time — the
    /// agent never asserts its own liveness (PHAROS-9).
    pub fn record(&self, report: HostReport, now: UnixSeconds) {
        {
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
            map.insert(
                report.name.clone(),
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
        }
        self.persist();
    }

    fn persist(&self) {
        let Some(path) = &self.path else { return };
        let snapshot: Vec<Host> = self
            .hosts
            .read()
            .expect("store lock")
            .values()
            .cloned()
            .collect();
        let Ok(json) = serde_json::to_vec_pretty(&snapshot) else {
            return;
        };
        if let Some(dir) = path.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        if let Err(e) = std::fs::write(path, json) {
            tracing::warn!("failed to persist store to {}: {e}", path.display());
        }
    }
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
        KernelPosture, KernelPostureState, NixFreshness, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION,
    };

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

    #[test]
    fn record_retains_recent_real_heartbeat_events() {
        let store = Store::new(None);

        for now in 1..=(MAX_HEARTBEAT_LOG + 6) as UnixSeconds {
            store.record(
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
            );
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
        let store = Store::new(None);
        let backup = backup_observation(BackupPostureState::Healthy);
        store.record(
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
                    },
                )],
                backup_observations: vec![backup.clone()],
                inbound_rtt_ms: Some(37),
                location: None,
                preferences: Default::default(),
            },
            120,
        );

        let host = store.register(
            HostRegistration {
                name: "athena".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 30,
            },
            "hash".to_string(),
        );

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

        store.record(
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
                },
                kernel: None,
                service_observations: vec![],
                backup_observations: vec![],
                inbound_rtt_ms: None,
                location: None,
                preferences: Default::default(),
            },
            150,
        );

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

        let store = Store::new(Some(path.clone()));
        store.record(report(HostPreferences::default()), 100);
        let queued = store
            .request_preferences("athena", requested.clone())
            .expect("request queued");
        assert_eq!(queued.preferences, HostPreferences::default());
        assert_eq!(queued.requested_preferences.as_ref(), Some(&requested));
        drop(store);

        let reloaded = Store::new(Some(path.clone()));
        assert_eq!(
            reloaded.list()[0].requested_preferences.as_ref(),
            Some(&requested)
        );

        reloaded.record(report(HostPreferences::default()), 160);
        assert_eq!(
            reloaded.list()[0].requested_preferences.as_ref(),
            Some(&requested),
            "an old host report must not acknowledge a pending request"
        );

        reloaded.record(report(requested.clone()), 220);
        let applied = reloaded.list().pop().expect("host remains");
        assert_eq!(applied.preferences, requested);
        assert!(applied.requested_preferences.is_none());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn preference_request_rejects_invalid_or_unknown_host_state() {
        let store = Store::new(None);
        let malformed = HostPreferences {
            accent: Some("orange".to_string()),
            ..Default::default()
        };

        assert_eq!(
            store.request_preferences("missing", HostPreferences::default()),
            Err("host not found")
        );
        assert_eq!(
            store.request_preferences("missing", malformed),
            Err("invalid host preferences")
        );
    }
}
