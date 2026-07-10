//! Declared host manifest loading for PHAROS-26/29.
//!
//! These files are nixcfg-generated configuration intent. Loading them here
//! must not mutate runtime host state; pharosd overlays beacon/probe state in
//! API responses instead.

use std::{collections::BTreeMap, path::PathBuf};

use pharos_core::{HostManifest, HostPreferences, HostPreferencesRegistry};
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct ManifestRegistry {
    manifests: Vec<HostManifest>,
    declared_preferences: BTreeMap<String, HostPreferences>,
    load_errors: Vec<ManifestLoadIssue>,
}

impl ManifestRegistry {
    pub fn from_env() -> Self {
        let paths = std::env::var("PHAROS_MANIFEST_PATHS")
            .ok()
            .map(|value| parse_manifest_paths(&value))
            .unwrap_or_default();
        let preferences_path = std::env::var("PHAROS_HOST_PREFERENCES_PATH")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        Self::from_sources(paths, preferences_path)
    }

    pub fn from_paths(paths: Vec<PathBuf>) -> Self {
        Self::from_sources(paths, None)
    }

    pub fn from_sources(paths: Vec<PathBuf>, preferences_path: Option<PathBuf>) -> Self {
        let mut manifests = Vec::new();
        let mut load_errors = Vec::new();

        for path in paths {
            match load_manifest(&path) {
                Ok(manifest) => manifests.push(manifest),
                Err(error) => load_errors.push(ManifestLoadIssue {
                    path: path.display().to_string(),
                    error,
                }),
            }
        }

        let declared_preferences = preferences_path
            .map(|path| match load_host_preferences(&path) {
                Ok(registry) => registry.hosts,
                Err(error) => {
                    load_errors.push(ManifestLoadIssue {
                        path: path.display().to_string(),
                        error,
                    });
                    BTreeMap::new()
                }
            })
            .unwrap_or_default();

        manifests.sort_by(|left, right| left.host.name.cmp(&right.host.name));
        Self {
            manifests,
            declared_preferences,
            load_errors,
        }
    }

    pub fn manifests(&self) -> &[HostManifest] {
        &self.manifests
    }

    pub fn load_errors(&self) -> &[ManifestLoadIssue] {
        &self.load_errors
    }

    pub fn declared_preferences(&self) -> &BTreeMap<String, HostPreferences> {
        &self.declared_preferences
    }

    pub fn declared_preferences_for(&self, host: &str) -> Option<&HostPreferences> {
        self.declared_preferences.get(host).or_else(|| {
            self.manifests
                .iter()
                .find(|manifest| manifest.host.name == host || manifest.slug == host)
                .map(|manifest| &manifest.host.preferences)
        })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManifestLoadIssue {
    pub path: String,
    pub error: String,
}

fn parse_manifest_paths(value: &str) -> Vec<PathBuf> {
    value
        .split([':', ','])
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(PathBuf::from)
        .collect()
}

fn load_manifest(path: &PathBuf) -> Result<HostManifest, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("failed to read manifest: {error}"))?;
    let manifest = serde_json::from_slice::<HostManifest>(&bytes)
        .map_err(|error| format!("failed to parse manifest JSON: {error}"))?;
    manifest
        .validate_contract()
        .map_err(|error| format!("manifest contract invalid: {error}"))?;
    Ok(manifest)
}

fn load_host_preferences(path: &PathBuf) -> Result<HostPreferencesRegistry, String> {
    let bytes =
        std::fs::read(path).map_err(|error| format!("failed to read host preferences: {error}"))?;
    let registry = serde_json::from_slice::<HostPreferencesRegistry>(&bytes)
        .map_err(|error| format!("failed to parse host preferences JSON: {error}"))?;
    registry
        .validate_contract()
        .map_err(|error| format!("host preferences contract invalid: {error}"))?;
    Ok(registry)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-manifests-{label}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ))
    }

    #[test]
    fn parses_colon_or_comma_separated_manifest_paths() {
        assert_eq!(
            parse_manifest_paths("/etc/a.json:/etc/b.json, /etc/c.json"),
            vec![
                PathBuf::from("/etc/a.json"),
                PathBuf::from("/etc/b.json"),
                PathBuf::from("/etc/c.json"),
            ]
        );
    }

    #[test]
    fn loads_exact_host_preferences_registry_as_declared_state() {
        let path = temp_path("preferences");
        std::fs::write(
            &path,
            r##"{
              "schema":"inspr.pharos.host-preferences.v1",
              "version":1,
              "hosts":{
                "gpc0":{
                  "accent":"#9868d0",
                  "kind":"workstation",
                  "alerts":{
                    "suppress_down":false,
                    "suppress_backup":false,
                    "suppress_nix_freshness":false
                  }
                }
              }
            }"##,
        )
        .expect("write registry fixture");

        let registry = ManifestRegistry::from_sources(Vec::new(), Some(path.clone()));
        let declared = registry
            .declared_preferences_for("gpc0")
            .expect("gpc0 declaration");
        assert_eq!(declared.accent.as_deref(), Some("#9868d0"));
        assert_eq!(declared.kind.label(), "workstation");
        assert!(registry.load_errors().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn rejects_divergent_host_preferences_schema() {
        let path = temp_path("bad-preferences");
        std::fs::write(
            &path,
            r##"{
              "schema":"inspr.pharos.host-preferences.v2",
              "version":1,
              "hosts":{"gpc0":{"accent":"#9868d0"}}
            }"##,
        )
        .expect("write registry fixture");

        let registry = ManifestRegistry::from_sources(Vec::new(), Some(path.clone()));
        assert!(registry.declared_preferences().is_empty());
        assert_eq!(registry.load_errors().len(), 1);

        let _ = std::fs::remove_file(path);
    }
}
