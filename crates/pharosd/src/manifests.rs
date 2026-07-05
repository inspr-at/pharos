//! Declared host manifest loading for PHAROS-26/29.
//!
//! These files are nixcfg-generated configuration intent. Loading them here
//! must not mutate runtime host state; pharosd overlays beacon/probe state in
//! API responses instead.

use std::path::PathBuf;

use pharos_core::HostManifest;
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct ManifestRegistry {
    manifests: Vec<HostManifest>,
    load_errors: Vec<ManifestLoadIssue>,
}

impl ManifestRegistry {
    pub fn from_env() -> Self {
        let paths = std::env::var("PHAROS_MANIFEST_PATHS")
            .ok()
            .map(|value| parse_manifest_paths(&value))
            .unwrap_or_default();
        Self::from_paths(paths)
    }

    pub fn from_paths(paths: Vec<PathBuf>) -> Self {
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

        manifests.sort_by(|left, right| left.host.name.cmp(&right.host.name));
        Self {
            manifests,
            load_errors,
        }
    }

    pub fn manifests(&self) -> &[HostManifest] {
        &self.manifests
    }

    pub fn load_errors(&self) -> &[ManifestLoadIssue] {
        &self.load_errors
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
