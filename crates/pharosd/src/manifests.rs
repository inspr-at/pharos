//! Declared host manifest loading for PHAROS-26/29.
//!
//! These files are nixcfg-generated configuration intent. Loading them here
//! must not mutate runtime host state; pharosd overlays beacon/probe state in
//! API responses instead.

use std::{
    collections::{BTreeMap, BTreeSet},
    io::Read,
    path::PathBuf,
};

use pharos_core::{
    managed_services::{
        ManagedSecretSlotDeclarationV1, ManagedServiceManifestV1,
        MAX_MANAGED_SERVICE_MANIFEST_BYTES,
    },
    HostManifest, HostPreferences, HostPreferencesRegistry,
};
use serde::Serialize;

#[derive(Debug, Clone, Default)]
pub struct ManifestRegistry {
    manifests: Vec<HostManifest>,
    declared_preferences: BTreeMap<String, HostPreferences>,
    load_errors: Vec<ManifestLoadIssue>,
    managed_service_manifests: Vec<ManagedServiceManifestV1>,
    managed_service_load_errors: Vec<ManifestLoadIssue>,
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
        let managed_service_paths = std::env::var("PHAROS_MANAGED_SERVICE_MANIFEST_PATHS")
            .ok()
            .map(|value| parse_manifest_paths(&value))
            .unwrap_or_default();
        Self::from_all_sources(paths, preferences_path, managed_service_paths)
    }

    pub fn from_paths(paths: Vec<PathBuf>) -> Self {
        Self::from_sources(paths, None)
    }

    pub fn from_sources(paths: Vec<PathBuf>, preferences_path: Option<PathBuf>) -> Self {
        Self::from_all_sources(paths, preferences_path, Vec::new())
    }

    pub fn from_all_sources(
        paths: Vec<PathBuf>,
        preferences_path: Option<PathBuf>,
        managed_service_paths: Vec<PathBuf>,
    ) -> Self {
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

        let (managed_service_manifests, managed_service_load_errors) =
            load_managed_service_manifests(managed_service_paths);
        manifests.sort_by(|left, right| left.host.name.cmp(&right.host.name));
        Self {
            manifests,
            declared_preferences,
            load_errors,
            managed_service_manifests,
            managed_service_load_errors,
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

    pub fn managed_service_manifests(&self) -> &[ManagedServiceManifestV1] {
        &self.managed_service_manifests
    }

    pub fn managed_service_load_errors(&self) -> &[ManifestLoadIssue] {
        &self.managed_service_load_errors
    }

    /// Resolve one exact declared slot for a mutation. Any manifest load
    /// ambiguity blocks all mutation, while still leaving valid declarations
    /// and load issues available to read-only status surfaces.
    pub fn managed_secret_slot_for_mutation(
        &self,
        host_ref: &str,
        service_ref: &str,
        slot_ref: &str,
        expected_declaration_fingerprint: &str,
    ) -> Result<&ManagedSecretSlotDeclarationV1, ManagedServiceMutationBlock> {
        if !self.managed_service_load_errors.is_empty() {
            return Err(ManagedServiceMutationBlock::RegistryInvalid);
        }
        let manifest = self
            .managed_service_manifests
            .iter()
            .find(|manifest| manifest.host_ref == host_ref)
            .ok_or(ManagedServiceMutationBlock::MissingDeclaration)?;
        if manifest.declaration_fingerprint != expected_declaration_fingerprint {
            return Err(ManagedServiceMutationBlock::StaleDeclaration);
        }
        manifest
            .services
            .iter()
            .find(|service| service.service_ref == service_ref)
            .and_then(|service| service.slots.iter().find(|slot| slot.slot_ref == slot_ref))
            .ok_or(ManagedServiceMutationBlock::MissingDeclaration)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ManifestLoadIssue {
    pub path: String,
    pub error: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManagedServiceMutationBlock {
    RegistryInvalid,
    MissingDeclaration,
    StaleDeclaration,
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

fn load_managed_service_manifests(
    paths: Vec<PathBuf>,
) -> (Vec<ManagedServiceManifestV1>, Vec<ManifestLoadIssue>) {
    let mut manifests = Vec::new();
    let mut issues = Vec::new();
    let mut host_refs = BTreeSet::new();
    let mut service_refs: BTreeMap<String, String> = BTreeMap::new();
    let mut slot_refs: BTreeMap<String, String> = BTreeMap::new();

    for path in paths {
        let manifest = match load_managed_service_manifest(&path) {
            Ok(manifest) => manifest,
            Err(error) => {
                issues.push(ManifestLoadIssue {
                    path: path.display().to_string(),
                    error,
                });
                continue;
            }
        };
        let mut conflict = host_refs
            .contains(&manifest.host_ref)
            .then_some("duplicate managed-service host declaration");
        for service in &manifest.services {
            if let Some(previous_host) = service_refs.get(&service.service_ref) {
                conflict = Some(if previous_host == &manifest.host_ref {
                    "duplicate managed-service declaration"
                } else {
                    "cross-host managed-service declaration"
                });
            }
            for slot in &service.slots {
                if let Some(previous_host) = slot_refs.get(&slot.slot_ref) {
                    conflict = Some(if previous_host == &manifest.host_ref {
                        "duplicate managed-service slot declaration"
                    } else {
                        "cross-host managed-service slot declaration"
                    });
                }
            }
        }
        if let Some(error) = conflict {
            issues.push(ManifestLoadIssue {
                path: path.display().to_string(),
                error: error.to_string(),
            });
        } else {
            host_refs.insert(manifest.host_ref.clone());
            for service in &manifest.services {
                service_refs.insert(service.service_ref.clone(), manifest.host_ref.clone());
                for slot in &service.slots {
                    slot_refs.insert(slot.slot_ref.clone(), manifest.host_ref.clone());
                }
            }
            manifests.push(manifest);
        }
    }
    manifests.sort_by(|left, right| left.host_ref.cmp(&right.host_ref));
    (manifests, issues)
}

fn load_managed_service_manifest(path: &PathBuf) -> Result<ManagedServiceManifestV1, String> {
    let file = std::fs::File::open(path)
        .map_err(|_| "managed-service manifest unavailable".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "managed-service manifest unavailable".to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_MANAGED_SERVICE_MANIFEST_BYTES as u64 {
        return Err("managed-service manifest is not a bounded regular file".to_string());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_MANAGED_SERVICE_MANIFEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "managed-service manifest unavailable".to_string())?;
    if bytes.len() > MAX_MANAGED_SERVICE_MANIFEST_BYTES {
        return Err("managed-service manifest is not a bounded regular file".to_string());
    }
    let manifest = serde_json::from_slice::<ManagedServiceManifestV1>(&bytes)
        .map_err(|_| "managed-service manifest JSON is invalid".to_string())?;
    manifest
        .validate_contract()
        .map_err(|error| format!("managed-service manifest contract invalid: {error}"))?;
    Ok(manifest)
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

    fn managed_fixture() -> &'static str {
        include_str!("../../../contracts/managed-service-declarations-v1.json")
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

    #[test]
    fn loads_managed_service_declarations_without_runtime_state() {
        let path = temp_path("managed");
        std::fs::write(&path, managed_fixture()).expect("write managed fixture");
        let registry = ManifestRegistry::from_all_sources(Vec::new(), None, vec![path.clone()]);

        assert!(registry.managed_service_load_errors().is_empty());
        assert_eq!(registry.managed_service_manifests().len(), 1);
        let manifest = &registry.managed_service_manifests()[0];
        let slot = registry
            .managed_secret_slot_for_mutation(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &manifest.services[0].slots[0].slot_ref,
                &manifest.declaration_fingerprint,
            )
            .expect("exact current slot");
        assert_eq!(slot.safe_label, "Canary API token");
        assert_eq!(
            registry.managed_secret_slot_for_mutation(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &manifest.services[0].slots[0].slot_ref,
                "decl_aaaaaaaaaaaa",
            ),
            Err(ManagedServiceMutationBlock::StaleDeclaration)
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn managed_service_registry_keeps_issues_legible_and_mutation_closed() {
        let first = temp_path("managed-first");
        let duplicate = temp_path("managed-duplicate");
        std::fs::write(&first, managed_fixture()).expect("write managed fixture");
        std::fs::write(&duplicate, managed_fixture()).expect("write duplicate fixture");
        let registry = ManifestRegistry::from_all_sources(
            Vec::new(),
            None,
            vec![first.clone(), duplicate.clone()],
        );

        assert_eq!(registry.managed_service_manifests().len(), 1);
        assert_eq!(registry.managed_service_load_errors().len(), 1);
        assert_eq!(
            registry.managed_secret_slot_for_mutation(
                "host_58f36c72a91e",
                "svc_0bca8d31f7e2",
                "slot_49c0e8a17d63",
                "decl_1e0775870c7d987ec744b94ec096d7f8985aae059248856ebcf1d9a52bacbc2e",
            ),
            Err(ManagedServiceMutationBlock::RegistryInvalid)
        );

        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(duplicate);
    }

    #[test]
    fn managed_service_loader_rejects_oversized_and_cross_host_declarations() {
        let oversized = temp_path("managed-oversized");
        std::fs::write(
            &oversized,
            vec![b' '; MAX_MANAGED_SERVICE_MANIFEST_BYTES + 1],
        )
        .expect("write oversized fixture");
        let registry =
            ManifestRegistry::from_all_sources(Vec::new(), None, vec![oversized.clone()]);
        assert!(registry.managed_service_manifests().is_empty());
        assert_eq!(registry.managed_service_load_errors().len(), 1);

        let first = temp_path("managed-cross-first");
        let second = temp_path("managed-cross-second");
        std::fs::write(&first, managed_fixture()).expect("write first fixture");
        let mut other: ManagedServiceManifestV1 = serde_json::from_str(managed_fixture()).unwrap();
        other.host_ref = "host_aaaaaaaaaaaa".to_string();
        other.declaration_fingerprint = other.computed_declaration_fingerprint().unwrap();
        std::fs::write(&second, serde_json::to_vec_pretty(&other).unwrap())
            .expect("write cross-host fixture");
        let registry = ManifestRegistry::from_all_sources(
            Vec::new(),
            None,
            vec![first.clone(), second.clone()],
        );
        assert_eq!(registry.managed_service_manifests().len(), 1);
        assert!(registry.managed_service_load_errors()[0]
            .error
            .contains("cross-host"));

        let _ = std::fs::remove_file(oversized);
        let _ = std::fs::remove_file(first);
        let _ = std::fs::remove_file(second);
    }
}
