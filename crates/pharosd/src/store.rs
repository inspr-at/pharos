//! Host store: in-memory map, optionally persisted to a JSON file. Adequate for
//! the MVP fleet (~handful of hosts). The sqlx+SQLite store (ADR-001) is
//! PHAROS-3 — swappable behind this small API without touching the rest.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::RwLock;

use pharos_core::{Host, HostReport, UnixSeconds};

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
            .map(|v| v.into_iter().map(|h| (h.name.clone(), h)).collect())
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
            map.insert(
                report.name.clone(),
                Host {
                    name: report.name,
                    role: report.role,
                    is_nix: report.is_nix,
                    last_seen: Some(now),
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
