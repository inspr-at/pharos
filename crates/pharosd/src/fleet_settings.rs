//! Fleet-wide attention policy, using the same durable JSON transaction as other stores.

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use pharos_core::{valid_nixpkgs_warn_after_days, DEFAULT_NIXPKGS_WARN_AFTER_DAYS};
use serde::{Deserialize, Serialize};

use crate::durable_file::{atomic_write_json, load_optional_json};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct FleetSettings {
    pub(crate) nixpkgs_warn_after_days: u32,
}

impl Default for FleetSettings {
    fn default() -> Self {
        Self {
            nixpkgs_warn_after_days: DEFAULT_NIXPKGS_WARN_AFTER_DAYS,
        }
    }
}

impl FleetSettings {
    pub(crate) fn valid(self) -> bool {
        valid_nixpkgs_warn_after_days(self.nixpkgs_warn_after_days)
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
            return Err("fleet settings contain an invalid nixpkgs age threshold");
        }
        Ok(Self {
            path,
            settings: RwLock::new(settings),
        })
    }

    pub(crate) fn get(&self) -> FleetSettings {
        *self.settings.read().expect("fleet settings lock")
    }

    pub(crate) fn update(&self, next: FleetSettings) -> Result<(), &'static str> {
        if !next.valid() {
            return Err("nixpkgs warning threshold must be between 1 and 3650 days");
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
        store
            .update(FleetSettings {
                nixpkgs_warn_after_days: 45,
            })
            .unwrap();
        for invalid in [0, 3651, u32::MAX] {
            assert!(store
                .update(FleetSettings {
                    nixpkgs_warn_after_days: invalid
                })
                .is_err());
        }
        assert_eq!(store.get().nixpkgs_warn_after_days, 45);
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
    fn failed_write_and_ephemeral_mode_never_claim_saved_settings() {
        let store = FleetSettingsStore::new(None).unwrap();
        assert!(store
            .update(FleetSettings {
                nixpkgs_warn_after_days: 45
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
                nixpkgs_warn_after_days: 45
            })
            .is_err());
        assert_eq!(store.get(), FleetSettings::default());
        std::fs::remove_dir(path).unwrap();
    }
}
