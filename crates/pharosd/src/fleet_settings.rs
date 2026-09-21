//! Fleet-wide attention policy, using the same durable JSON transaction as other stores.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use pharos_core::{
    DEFAULT_HEARTBEAT_GRACE_SECS, DEFAULT_NIXPKGS_WARN_AFTER_DAYS, HEARTBEAT_GRACE_RANGE_ERROR,
    valid_heartbeat_grace_secs, valid_nixpkgs_warn_after_days,
};
use serde::{Deserialize, Serialize};

use crate::durable_file::{atomic_write_json, load_optional_json};

fn default_heartbeat_grace_secs() -> u64 {
    DEFAULT_HEARTBEAT_GRACE_SECS
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetSettings {
    pub(crate) nixpkgs_warn_after_days: u32,
    /// Late-heartbeat grace for hosts that do not set their own override.
    /// Missing on older sidecar files, which keep the 15-second default.
    #[serde(default = "default_heartbeat_grace_secs")]
    pub(crate) heartbeat_grace_secs: u64,
}

/// `POST /settings/fleet.json` body. Omitting `heartbeat_grace_secs` keeps the
/// saved grace so the existing freshness form does not reset it.
#[derive(Debug, Clone, Copy, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetSettingsUpdate {
    pub(crate) nixpkgs_warn_after_days: u32,
    #[serde(default)]
    pub(crate) heartbeat_grace_secs: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FleetSettingsWriteError {
    Invalid(&'static str),
    Unavailable(&'static str),
}

impl FleetSettingsWriteError {
    pub(crate) fn message(self) -> &'static str {
        match self {
            Self::Invalid(message) | Self::Unavailable(message) => message,
        }
    }
}

impl Default for FleetSettings {
    fn default() -> Self {
        Self {
            nixpkgs_warn_after_days: DEFAULT_NIXPKGS_WARN_AFTER_DAYS,
            heartbeat_grace_secs: DEFAULT_HEARTBEAT_GRACE_SECS,
        }
    }
}

impl FleetSettings {
    pub(crate) fn validation_error(self) -> Option<&'static str> {
        if !valid_nixpkgs_warn_after_days(self.nixpkgs_warn_after_days) {
            return Some("nixpkgs warning threshold must be between 1 and 3650 days");
        }
        if !valid_heartbeat_grace_secs(self.heartbeat_grace_secs) {
            return Some(HEARTBEAT_GRACE_RANGE_ERROR);
        }
        None
    }

    pub(crate) fn valid(self) -> bool {
        self.validation_error().is_none()
    }
}

pub(crate) struct FleetSettingsStore {
    path: Option<PathBuf>,
    settings: RwLock<FleetSettings>,
}

impl FleetSettingsStore {
    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        host_store_path.map(|path| {
            let name = path.file_name().unwrap_or_default().to_string_lossy();
            path.with_file_name(format!("{name}.fleet-settings.json"))
        })
    }

    pub(crate) fn new(path: Option<PathBuf>) -> Result<Self, &'static str> {
        let settings = match path.as_deref() {
            Some(path) => load_optional_json::<FleetSettings>(path)
                .map_err(|_| "fleet settings could not be loaded")?
                .unwrap_or_default(),
            None => FleetSettings::default(),
        };
        if !settings.valid() {
            return Err("fleet settings contain an invalid attention policy");
        }
        Ok(Self {
            path,
            settings: RwLock::new(settings),
        })
    }

    pub(crate) fn get(&self) -> FleetSettings {
        *self.settings.read().expect("fleet settings lock")
    }

    pub(crate) fn apply(&self, update: FleetSettingsUpdate) -> Result<(), FleetSettingsWriteError> {
        let current = self.get();
        let next = FleetSettings {
            nixpkgs_warn_after_days: update.nixpkgs_warn_after_days,
            heartbeat_grace_secs: update
                .heartbeat_grace_secs
                .unwrap_or(current.heartbeat_grace_secs),
        };
        if let Some(error) = next.validation_error() {
            return Err(FleetSettingsWriteError::Invalid(error));
        }
        self.update(next)
            .map_err(FleetSettingsWriteError::Unavailable)
    }

    pub(crate) fn update(&self, next: FleetSettings) -> Result<(), &'static str> {
        if let Some(error) = next.validation_error() {
            return Err(error);
        }
        let mut settings = self.settings.write().expect("fleet settings lock");
        let Some(path) = self.path.as_deref() else {
            return Err("fleet settings require PHAROS_DB for durable storage");
        };
        if let Err(error) = atomic_write_json(path, &next) {
            if error.final_file_replaced() {
                *settings = next;
            }
            return Err("fleet settings could not be durably recorded");
        }
        *settings = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_persist_and_invalid_updates_preserve_the_saved_value() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-fleet-settings-{}-{}",
            std::process::id(),
            crate::now_unix()
        ));
        let path = dir.join("settings.json");
        let store = FleetSettingsStore::new(Some(path.clone())).unwrap();
        assert_eq!(store.get().nixpkgs_warn_after_days, 30);
        assert_eq!(store.get().heartbeat_grace_secs, 15);
        store
            .update(FleetSettings {
                nixpkgs_warn_after_days: 45,
                ..FleetSettings::default()
            })
            .unwrap();
        for invalid in [0, 3651, u32::MAX] {
            assert!(store
                .update(FleetSettings {
                    nixpkgs_warn_after_days: invalid,
                    ..FleetSettings::default()
                })
                .is_err());
        }
        assert_eq!(store.get().nixpkgs_warn_after_days, 45);
        assert_eq!(store.get().heartbeat_grace_secs, 15);
        assert_eq!(
            FleetSettingsStore::new(Some(path.clone())).unwrap().get(),
            store.get()
        );
        std::fs::write(&path, br#"{"nixpkgs_warn_after_days":0}"#).unwrap();
        assert!(FleetSettingsStore::new(Some(path.clone())).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn heartbeat_grace_loads_from_older_files_and_partial_writes_keep_it() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-fleet-grace-{}-{}",
            std::process::id(),
            crate::now_unix()
        ));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("settings.json");
        std::fs::write(&path, br#"{"nixpkgs_warn_after_days":45}"#).unwrap();
        let store = FleetSettingsStore::new(Some(path.clone())).unwrap();
        assert_eq!(
            store.get(),
            FleetSettings {
                nixpkgs_warn_after_days: 45,
                heartbeat_grace_secs: 15,
            }
        );
        store
            .apply(FleetSettingsUpdate {
                nixpkgs_warn_after_days: 45,
                heartbeat_grace_secs: Some(0),
            })
            .unwrap();
        let omitted: FleetSettingsUpdate =
            serde_json::from_str(r#"{"nixpkgs_warn_after_days":12}"#).unwrap();
        assert_eq!(omitted.heartbeat_grace_secs, None);
        store.apply(omitted).unwrap();
        assert_eq!(store.get().nixpkgs_warn_after_days, 12);
        assert_eq!(store.get().heartbeat_grace_secs, 0);
        let explicit_null: FleetSettingsUpdate =
            serde_json::from_str(r#"{"nixpkgs_warn_after_days":12,"heartbeat_grace_secs":null}"#)
                .unwrap();
        store.apply(explicit_null).unwrap();
        assert_eq!(store.get().heartbeat_grace_secs, 0);
        for invalid in [3601, u64::MAX] {
            assert_eq!(
                store.apply(FleetSettingsUpdate {
                    nixpkgs_warn_after_days: 12,
                    heartbeat_grace_secs: Some(invalid),
                }),
                Err(FleetSettingsWriteError::Invalid(
                    pharos_core::HEARTBEAT_GRACE_RANGE_ERROR
                ))
            );
        }
        assert_eq!(store.get().heartbeat_grace_secs, 0);
        store
            .apply(FleetSettingsUpdate {
                nixpkgs_warn_after_days: 12,
                heartbeat_grace_secs: Some(3600),
            })
            .unwrap();
        assert_eq!(
            FleetSettingsStore::new(Some(path.clone())).unwrap().get(),
            store.get()
        );
        std::fs::write(&path, br#"{"nixpkgs_warn_after_days":30,"heartbeat_grace_secs":3601}"#)
            .unwrap();
        assert!(FleetSettingsStore::new(Some(path.clone())).is_err());
        std::fs::remove_file(path).unwrap();
        std::fs::remove_dir(dir).unwrap();
    }

    #[test]
    fn failed_write_and_ephemeral_mode_never_claim_saved_settings() {
        let store = FleetSettingsStore::new(None).unwrap();
        assert!(store
            .update(FleetSettings {
                nixpkgs_warn_after_days: 45,
                ..FleetSettings::default()
            })
            .is_err());
        assert_eq!(store.get(), FleetSettings::default());
        let path = std::env::temp_dir().join(format!(
            "pharos-fleet-settings-blocked-{}",
            std::process::id()
        ));
        std::fs::create_dir(&path).unwrap();
        let store = FleetSettingsStore {
            path: Some(path.clone()),
            settings: RwLock::new(FleetSettings::default()),
        };
        assert!(store
            .update(FleetSettings {
                nixpkgs_warn_after_days: 45,
                ..FleetSettings::default()
            })
            .is_err());
        assert_eq!(store.get(), FleetSettings::default());
        std::fs::remove_dir(path).unwrap();
    }
}
