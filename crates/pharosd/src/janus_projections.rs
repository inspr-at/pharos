//! Capability-named, value-free Janus projection consumers.
//!
//! Janus owns credential values. Pharos names a closed capability and consumes
//! only its reviewed projection: the beacon verifier hash-dir v2 or a scoped
//! machine-operator verifier generation. No API in this module reveals a
//! credential value.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::janus_auth::{read_hash_dir_file, validate_hash_dir_root, JanusTokenHashError};

pub(crate) const JANUS_PROJECTION_ROOT_ENV: &str = "PHAROS_JANUS_PROJECTION_ROOT";
pub(crate) const MACHINE_OPERATOR_HASH_DIR_ENV: &str = "PHAROS_MACHINE_OPERATOR_TOKEN_HASH_DIR";
pub(crate) const MACHINE_OPERATOR_SCHEMA: &str =
    "inspr.pharos.machine-operator-token-generation.v2";
const MAX_CURRENT_BYTES: u64 = 65;
const MAX_GENERATION_BYTES: u64 = 1024 * 1024;
const MAX_OPERATORS: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum JanusCapability {
    PharosBeaconToken,
    PharosMachineOperator,
    // Delivered through the separate signed setup-intent consumer rather than
    // the hash-directory resolver in production.
    #[allow(dead_code)]
    ManagedServiceEnvironment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProjectionDelivery {
    VerifierGeneration,
    SignedSetupIntent,
}

impl JanusCapability {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::PharosBeaconToken => "pharos-beacon-token",
            Self::PharosMachineOperator => "pharos-machine-operator",
            Self::ManagedServiceEnvironment => "managed-service-environment",
        }
    }

    pub(crate) const fn delivery(self) -> ProjectionDelivery {
        match self {
            Self::PharosBeaconToken | Self::PharosMachineOperator => {
                ProjectionDelivery::VerifierGeneration
            }
            Self::ManagedServiceEnvironment => ProjectionDelivery::SignedSetupIntent,
        }
    }
}

/// Resolve one closed capability to a projection root. The legacy beacon
/// variable remains accepted during migration, but ambiguous configuration is
/// rejected instead of picking one source.
pub(crate) fn capability_root_from_env(
    capability: JanusCapability,
    legacy_env: Option<&str>,
) -> Result<Option<PathBuf>, String> {
    if capability.delivery() != ProjectionDelivery::VerifierGeneration {
        return Err(format!(
            "capability {} is delivered through the managed setup-intent contract, not a hash directory",
            capability.as_str()
        ));
    }
    let named = env_nonempty(JANUS_PROJECTION_ROOT_ENV)
        .map(PathBuf::from)
        .map(|root| root.join(capability.as_str()));
    let legacy = legacy_env.and_then(env_nonempty).map(PathBuf::from);
    if named.is_some() && legacy.is_some() {
        return Err(format!(
            "{JANUS_PROJECTION_ROOT_ENV} and {} cannot both configure capability {}",
            legacy_env.unwrap_or("a legacy projection variable"),
            capability.as_str()
        ));
    }
    Ok(named.or(legacy))
}

/// Resolve an optional capability. A configured direct root is always
/// authoritative (and later validation will fail closed). Under the shared
/// named root, an absent capability directory means that capability has not
/// been projected yet; malformed or unsafe existing paths still reach strict
/// validation.
pub(crate) fn optional_capability_root_from_env(
    capability: JanusCapability,
    legacy_env: &str,
) -> Result<Option<PathBuf>, String> {
    if env_nonempty(legacy_env).is_some() {
        return capability_root_from_env(capability, Some(legacy_env));
    }
    let Some(root) = env_nonempty(JANUS_PROJECTION_ROOT_ENV).map(PathBuf::from) else {
        return Ok(None);
    };
    let candidate = root.join(capability.as_str());
    match fs::symlink_metadata(&candidate) {
        Ok(_) => Ok(Some(candidate)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(format!(
            "capability {} could not be resolved beneath {JANUS_PROJECTION_ROOT_ENV}",
            capability.as_str()
        )),
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MachineOperatorScope {
    FleetRead,
    FleetWrite,
}

impl MachineOperatorScope {
    fn parse(value: &str) -> Option<Self> {
        match value {
            "fleet:read" => Some(Self::FleetRead),
            "fleet:write" => Some(Self::FleetWrite),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MachineOperatorPrincipal {
    pub(crate) operator_ref: String,
    pub(crate) label: String,
    pub(crate) can_write: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct MachineOperatorTokenStore {
    root: Arc<PathBuf>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorGeneration {
    schema: String,
    generation: String,
    operators: Vec<OperatorVerifier>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OperatorVerifier {
    operator_ref: String,
    label: String,
    token_sha256: String,
    scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MachineOperatorError {
    InvalidRoot,
    MissingCurrent,
    UnsafeMetadata,
    InputTooLarge,
    Read,
    Parse,
    UnsupportedSchema,
    InvalidGeneration,
    InvalidOperator,
    InvalidHash,
    InvalidScope,
    DuplicateOperator,
    EmptyGeneration,
    ChangedDuringLoad,
}

impl std::fmt::Display for MachineOperatorError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::InvalidRoot => "machine-operator projection root is invalid",
            Self::MissingCurrent => "machine-operator projection pointer is unavailable",
            Self::UnsafeMetadata => "machine-operator projection metadata is unsafe",
            Self::InputTooLarge => "machine-operator projection exceeds its input bound",
            Self::Read => "machine-operator projection could not be read",
            Self::Parse => "machine-operator projection could not be parsed",
            Self::UnsupportedSchema => "machine-operator projection schema is unsupported",
            Self::InvalidGeneration => "machine-operator generation identifier is invalid",
            Self::InvalidOperator => "machine-operator projection contains an invalid operator",
            Self::InvalidHash => "machine-operator projection contains an invalid verifier",
            Self::InvalidScope => "machine-operator projection contains an invalid scope",
            Self::DuplicateOperator => "machine-operator projection contains a duplicate operator",
            Self::EmptyGeneration => "machine-operator projection contains no operators",
            Self::ChangedDuringLoad => "machine-operator projection changed while loading",
        };
        formatter.write_str(message)
    }
}

impl MachineOperatorTokenStore {
    pub(crate) fn load(root: PathBuf) -> Result<Self, MachineOperatorError> {
        validate_hash_dir_root(&root).map_err(map_hash_dir_error)?;
        let store = Self {
            root: Arc::new(root),
        };
        store.read_generation()?;
        Ok(store)
    }

    pub(crate) fn authenticate(
        &self,
        token: &str,
    ) -> Result<Option<MachineOperatorPrincipal>, MachineOperatorError> {
        if token.is_empty() || token.len() > 4096 {
            return Ok(None);
        }
        let generation = self.read_generation()?;
        let actual_hash = sha256_hex(token.as_bytes());
        let mut matched = None;
        for operator in generation.operators {
            if constant_time_eq(&actual_hash, &operator.token_sha256) {
                let can_write = operator.scopes.iter().any(|scope| scope == "fleet:write");
                matched = Some(MachineOperatorPrincipal {
                    operator_ref: operator.operator_ref,
                    label: operator.label,
                    can_write,
                });
            }
        }
        Ok(matched)
    }

    pub(crate) fn ready(&self) -> bool {
        self.read_generation().is_ok()
    }

    fn read_generation(&self) -> Result<OperatorGeneration, MachineOperatorError> {
        let generation_id = read_current(&self.root)?;
        let generation_file = format!("generation-{generation_id}.json");
        let bytes = read_hash_dir_file(&self.root, &generation_file, MAX_GENERATION_BYTES)
            .map_err(map_hash_dir_error)?;
        let generation: OperatorGeneration =
            serde_json::from_slice(&bytes).map_err(|_| MachineOperatorError::Parse)?;
        validate_generation(&generation, &generation_id)?;
        if read_current(&self.root)? != generation_id {
            return Err(MachineOperatorError::ChangedDuringLoad);
        }
        Ok(generation)
    }
}

fn validate_generation(
    generation: &OperatorGeneration,
    expected_id: &str,
) -> Result<(), MachineOperatorError> {
    if generation.schema != MACHINE_OPERATOR_SCHEMA {
        return Err(MachineOperatorError::UnsupportedSchema);
    }
    if generation.generation != expected_id || !valid_generation_id(&generation.generation) {
        return Err(MachineOperatorError::InvalidGeneration);
    }
    if generation.operators.is_empty() || generation.operators.len() > MAX_OPERATORS {
        return Err(MachineOperatorError::EmptyGeneration);
    }
    let mut seen = BTreeSet::new();
    let mut verifier_hashes = BTreeSet::new();
    for operator in &generation.operators {
        if !valid_operator_ref(&operator.operator_ref) || !valid_label(&operator.label) {
            return Err(MachineOperatorError::InvalidOperator);
        }
        if !valid_lower_hex_sha256(&operator.token_sha256) {
            return Err(MachineOperatorError::InvalidHash);
        }
        if operator.scopes.is_empty()
            || operator
                .scopes
                .iter()
                .any(|scope| MachineOperatorScope::parse(scope).is_none())
            || !operator.scopes.iter().any(|scope| scope == "fleet:read")
            || operator.scopes.iter().collect::<BTreeSet<_>>().len() != operator.scopes.len()
        {
            return Err(MachineOperatorError::InvalidScope);
        }
        if !seen.insert(operator.operator_ref.as_str())
            || !verifier_hashes.insert(operator.token_sha256.as_str())
        {
            return Err(MachineOperatorError::DuplicateOperator);
        }
    }
    if machine_operator_generation_id(&generation.operators) != expected_id {
        return Err(MachineOperatorError::InvalidGeneration);
    }
    Ok(())
}

fn read_current(root: &Path) -> Result<String, MachineOperatorError> {
    let bytes = read_hash_dir_file(root, "current", MAX_CURRENT_BYTES)
        .map_err(map_hash_dir_error)
        .map_err(|error| {
            if matches!(error, MachineOperatorError::Read) {
                MachineOperatorError::MissingCurrent
            } else {
                error
            }
        })?;
    let current =
        std::str::from_utf8(&bytes).map_err(|_| MachineOperatorError::InvalidGeneration)?;
    let value = current.strip_suffix('\n').unwrap_or(current);
    if !valid_generation_id(value) {
        return Err(MachineOperatorError::InvalidGeneration);
    }
    Ok(value.to_string())
}

fn map_hash_dir_error(error: JanusTokenHashError) -> MachineOperatorError {
    match error {
        JanusTokenHashError::InvalidRoot => MachineOperatorError::InvalidRoot,
        JanusTokenHashError::UnsafeMetadata => MachineOperatorError::UnsafeMetadata,
        JanusTokenHashError::InputTooLarge => MachineOperatorError::InputTooLarge,
        JanusTokenHashError::ChangedDuringLoad => MachineOperatorError::ChangedDuringLoad,
        JanusTokenHashError::Read | JanusTokenHashError::MissingCurrent => {
            MachineOperatorError::Read
        }
        JanusTokenHashError::NotConfigured
        | JanusTokenHashError::Parse
        | JanusTokenHashError::UnsupportedSchema
        | JanusTokenHashError::InvalidGeneration
        | JanusTokenHashError::InvalidHost
        | JanusTokenHashError::InvalidHash
        | JanusTokenHashError::DuplicateHost
        | JanusTokenHashError::EmptyGeneration
        | JanusTokenHashError::StateUnavailable => MachineOperatorError::Read,
    }
}

fn machine_operator_generation_id(operators: &[OperatorVerifier]) -> String {
    let mut sorted = operators.iter().collect::<Vec<_>>();
    sorted.sort_by(|left, right| left.operator_ref.cmp(&right.operator_ref));

    let mut digest = Sha256::new();
    digest.update(MACHINE_OPERATOR_SCHEMA.as_bytes());
    digest.update([0]);
    for operator in sorted {
        hash_generation_field(&mut digest, &operator.operator_ref);
        hash_generation_field(&mut digest, &operator.label);
        hash_generation_field(&mut digest, &operator.token_sha256);
        let mut scopes = operator.scopes.iter().collect::<Vec<_>>();
        scopes.sort();
        digest.update((scopes.len() as u64).to_be_bytes());
        for scope in scopes {
            hash_generation_field(&mut digest, scope);
        }
    }
    hex_digest(&digest.finalize())
}

fn hash_generation_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn valid_generation_id(value: &str) -> bool {
    valid_lower_hex_sha256(value)
}

fn valid_lower_hex_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_operator_ref(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':' | b'.'))
}

fn valid_label(value: &str) -> bool {
    !value.trim().is_empty()
        && value.len() <= 160
        && !value.chars().any(char::is_control)
        && !value.to_ascii_lowercase().contains("bearer ")
        && !value.to_ascii_lowercase().contains("token=")
}

fn sha256_hex(value: &[u8]) -> String {
    let digest = Sha256::digest(value);
    let mut output = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let length = left.len().max(right.len());
    let mut difference = left.len() ^ right.len();
    for index in 0..length {
        difference |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    difference == 0
}

#[cfg(test)]
pub(crate) fn write_test_generation(
    root: &Path,
    operator_ref: &str,
    label: &str,
    token_sha256: &str,
    scopes: &[&str],
) -> String {
    let operators = vec![OperatorVerifier {
        operator_ref: operator_ref.to_string(),
        label: label.to_string(),
        token_sha256: token_sha256.to_string(),
        scopes: scopes.iter().map(|scope| (*scope).to_string()).collect(),
    }];
    let generation = machine_operator_generation_id(&operators);
    let document = OperatorGeneration {
        schema: MACHINE_OPERATOR_SCHEMA.to_string(),
        generation: generation.clone(),
        operators,
    };
    fs::create_dir_all(root).expect("create machine-operator fixture root");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
            .expect("secure machine-operator fixture root");
    }
    let generation_path = root.join(format!("generation-{generation}.json"));
    fs::write(
        &generation_path,
        serde_json::to_vec(&document).expect("encode machine-operator fixture"),
    )
    .expect("write machine-operator fixture");
    let current_path = root.join("current");
    fs::write(&current_path, format!("{generation}\n"))
        .expect("write machine-operator fixture pointer");
    #[cfg(unix)]
    for path in [generation_path, current_path] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure machine-operator fixture file");
    }
    generation
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn fixture_root() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pharos-machine-operator-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        path
    }

    fn write_generation(root: &Path, token: &str, scopes: &[&str]) -> String {
        let token_hash = sha256_hex(token.as_bytes());
        write_test_generation(
            root,
            "operator:automation",
            "automation operator",
            &token_hash,
            scopes,
        )
    }

    #[test]
    fn scoped_generation_authenticates_without_returning_a_value() {
        let root = fixture_root();
        let credential = format!(
            "fixture-credential-{}",
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        write_generation(&root, &credential, &["fleet:read"]);
        let store = MachineOperatorTokenStore::load(root.clone()).unwrap();

        let principal = store.authenticate(&credential).unwrap().unwrap();
        assert_eq!(principal.operator_ref, "operator:automation");
        assert!(!principal.can_write);
        assert!(store.authenticate("unrelated").unwrap().is_none());

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn legacy_layout_and_tampered_v2_content_fail_closed() {
        let legacy_root = fixture_root();
        let legacy_generation = write_generation(&legacy_root, "unused", &["fleet:read"]);
        fs::rename(
            legacy_root.join(format!("generation-{legacy_generation}.json")),
            legacy_root.join(format!("{legacy_generation}.json")),
        )
        .unwrap();
        assert_eq!(
            MachineOperatorTokenStore::load(legacy_root.clone()).unwrap_err(),
            MachineOperatorError::Read
        );

        let legacy_schema_root = fixture_root();
        let legacy_schema_generation =
            write_generation(&legacy_schema_root, "unused", &["fleet:read"]);
        let legacy_schema_path =
            legacy_schema_root.join(format!("generation-{legacy_schema_generation}.json"));
        let mut legacy_document: serde_json::Value =
            serde_json::from_slice(&fs::read(&legacy_schema_path).unwrap()).unwrap();
        legacy_document["schema"] =
            serde_json::json!("inspr.pharos.machine-operator-token-generation.v1");
        fs::write(
            &legacy_schema_path,
            serde_json::to_vec(&legacy_document).unwrap(),
        )
        .unwrap();
        assert_eq!(
            MachineOperatorTokenStore::load(legacy_schema_root.clone()).unwrap_err(),
            MachineOperatorError::UnsupportedSchema
        );

        let tampered_root = fixture_root();
        let tampered_generation = write_generation(&tampered_root, "unused", &["fleet:read"]);
        let tampered_path = tampered_root.join(format!("generation-{tampered_generation}.json"));
        let mut document: serde_json::Value =
            serde_json::from_slice(&fs::read(&tampered_path).unwrap()).unwrap();
        document["operators"][0]["label"] = serde_json::json!("changed operator");
        fs::write(&tampered_path, serde_json::to_vec(&document).unwrap()).unwrap();
        assert_eq!(
            MachineOperatorTokenStore::load(tampered_root.clone()).unwrap_err(),
            MachineOperatorError::InvalidGeneration
        );

        fs::remove_dir_all(legacy_root).unwrap();
        fs::remove_dir_all(legacy_schema_root).unwrap();
        fs::remove_dir_all(tampered_root).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn generation_symlinks_fail_closed() {
        use std::os::unix::fs::symlink;

        let root = fixture_root();
        let generation = write_generation(&root, "unused", &["fleet:read"]);
        let generation_path = root.join(format!("generation-{generation}.json"));
        let target_path = root.join("generation-target.json");
        fs::rename(&generation_path, &target_path).unwrap();
        symlink(&target_path, &generation_path).unwrap();

        assert_eq!(
            MachineOperatorTokenStore::load(root.clone()).unwrap_err(),
            MachineOperatorError::UnsafeMetadata
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unknown_scope_and_world_writable_generation_fail_closed() {
        let root = fixture_root();
        let generation = write_generation(&root, "unused", &["fleet:admin"]);
        assert_eq!(
            MachineOperatorTokenStore::load(root.clone()).unwrap_err(),
            MachineOperatorError::InvalidScope
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                root.join(format!("generation-{generation}.json")),
                fs::Permissions::from_mode(0o666),
            )
            .unwrap();
            assert_eq!(
                MachineOperatorTokenStore::load(root.clone()).unwrap_err(),
                MachineOperatorError::UnsafeMetadata
            );
        }

        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn capability_names_are_closed_and_stable() {
        assert_eq!(
            JanusCapability::PharosBeaconToken.as_str(),
            "pharos-beacon-token"
        );
        assert_eq!(
            JanusCapability::PharosMachineOperator.as_str(),
            "pharos-machine-operator"
        );
        assert_eq!(
            JanusCapability::ManagedServiceEnvironment.delivery(),
            ProjectionDelivery::SignedSetupIntent
        );
        assert!(
            capability_root_from_env(JanusCapability::ManagedServiceEnvironment, None).is_err()
        );
    }
}
