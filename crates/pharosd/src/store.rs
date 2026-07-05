//! Host store: in-memory map, optionally persisted to a JSON file. Adequate for
//! the MVP fleet (~handful of hosts). The sqlx+SQLite store (ADR-001) is
//! PHAROS-3 — swappable behind this small API without touching the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pharos_core::{Host, HostReport, UnixSeconds};

const MAX_HEARTBEAT_LOG: usize = 24;

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
                        trim_heartbeat_log(&mut h.heartbeat_log);
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

    /// Upsert from a beacon report. `now` is the **server** receive time — the
    /// agent never asserts its own liveness (PHAROS-9).
    pub fn record(&self, report: HostReport, now: UnixSeconds) {
        {
            let mut map = self.hosts.write().expect("store lock");
            let mut heartbeat_log = map
                .get(&report.name)
                .map(|h| h.heartbeat_log.clone())
                .unwrap_or_default();
            if heartbeat_log.last().copied() != Some(now) {
                heartbeat_log.push(now);
            }
            trim_heartbeat_log(&mut heartbeat_log);
            map.insert(
                report.name.clone(),
                Host {
                    name: report.name,
                    role: report.role,
                    is_nix: report.is_nix,
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

fn trim_heartbeat_log(log: &mut Vec<UnixSeconds>) {
    log.sort_unstable();
    log.dedup();
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

        for now in 1..=30 {
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
        assert_eq!(host.last_seen, Some(30));
        assert_eq!(host.heartbeat_log.len(), MAX_HEARTBEAT_LOG);
        assert_eq!(host.heartbeat_log.first(), Some(&7));
        assert_eq!(host.heartbeat_log.last(), Some(&30));
    }
}
