//! Host store: in-memory map, optionally persisted to a JSON file. Adequate for
//! the MVP fleet (~handful of hosts). The sqlx+SQLite store (ADR-001) is
//! PHAROS-3 — swappable behind this small API without touching the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pharos_core::{Host, HostRegistration, HostReport, NixFreshness, UnixSeconds};

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
                token_hash: Some(token_hash),
                last_seen: existing.and_then(|h| h.last_seen),
                heartbeat_log: existing
                    .map(|h| h.heartbeat_log.clone())
                    .unwrap_or_default(),
                heartbeat_interval_secs: Some(registration.heartbeat_interval_secs),
                freshness: existing
                    .map(|h| h.freshness.clone())
                    .unwrap_or_else(|| NixFreshness {
                        applicable: registration.is_nix,
                        ..Default::default()
                    }),
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
            map.insert(
                report.name.clone(),
                Host {
                    name: report.name,
                    role: report.role,
                    is_nix: report.is_nix,
                    token_hash,
                    last_seen: Some(now),
                    heartbeat_log,
                    heartbeat_interval_secs: Some(report.heartbeat_interval_secs),
                    freshness: report.freshness,
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
    use pharos_core::NixFreshness;

    #[test]
    fn record_retains_recent_real_heartbeat_events() {
        let store = Store::new(None);

        for now in 1..=(MAX_HEARTBEAT_LOG + 6) as UnixSeconds {
            store.record(
                HostReport {
                    name: "poseidon".to_string(),
                    role: "NixOS Host".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 60,
                    freshness: NixFreshness {
                        applicable: true,
                        ..Default::default()
                    },
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
        store.record(
            HostReport {
                name: "athena".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(0),
                },
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
        assert_eq!(host.freshness.flake_lock_age_days, Some(1));
        assert!(store.has_token("athena"));
        assert_eq!(store.token_hash_for("athena").as_deref(), Some("hash"));

        store.record(
            HostReport {
                name: "athena".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 30,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(0),
                    commits_behind: Some(0),
                },
            },
            150,
        );

        let updated = store.list().pop().expect("host remains recorded");
        assert_eq!(updated.token_hash.as_deref(), Some("hash"));
        assert_eq!(updated.last_seen, Some(150));
    }
}
