use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(all(unix, test))]
use std::os::unix::fs::PermissionsExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub(crate) const JANUS_GENERATION_SCHEMA: &str = "inspr.pharos.beacon-token-generation.v2";
pub(crate) const JANUS_CURRENT_FILE: &str = "current";
const MAX_CURRENT_BYTES: u64 = 65;
const MAX_GENERATION_BYTES: u64 = 1024 * 1024;
const MAX_GENERATION_HOSTS: usize = 1024;

#[derive(Clone, Debug)]
pub(crate) struct JanusTokenStore {
    root: Arc<PathBuf>,
    state: Arc<RwLock<JanusTokenState>>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct JanusTokenReadiness {
    pub(crate) ready: bool,
    pub(crate) status: &'static str,
    pub(crate) generation: Option<String>,
    pub(crate) last_success_unix: Option<u64>,
    pub(crate) host_count: usize,
}

#[derive(Debug, Default)]
struct JanusTokenState {
    active: Option<Arc<ValidatedGeneration>>,
    last_success_unix: Option<u64>,
    last_error: Option<JanusTokenHashError>,
}

#[derive(Debug)]
struct ValidatedGeneration {
    id: String,
    hosts: BTreeMap<String, String>,
    file_identity: FileIdentity,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct FileIdentity {
    len: u64,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    uid: u32,
    #[cfg(unix)]
    mode: u32,
    #[cfg(unix)]
    modified_seconds: i64,
    #[cfg(unix)]
    modified_nanoseconds: i64,
    #[cfg(not(unix))]
    modified: Option<SystemTime>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenGeneration {
    schema: String,
    generation: String,
    hosts: Vec<TokenGenerationHost>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TokenGenerationHost {
    name: String,
    token_sha256: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum JanusTokenHashError {
    NotConfigured,
    InvalidRoot,
    MissingCurrent,
    UnsafeMetadata,
    InputTooLarge,
    Read,
    Parse,
    UnsupportedSchema,
    InvalidGeneration,
    InvalidHost,
    InvalidHash,
    DuplicateHost,
    EmptyGeneration,
    ChangedDuringLoad,
    StateUnavailable,
}

impl std::fmt::Display for JanusTokenHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::NotConfigured => "janus token generation is not configured",
            Self::InvalidRoot => "janus token generation root is invalid",
            Self::MissingCurrent => "janus token generation pointer is unavailable",
            Self::UnsafeMetadata => "janus token generation metadata is unsafe",
            Self::InputTooLarge => "janus token generation exceeds its input bound",
            Self::Read => "janus token generation could not be read",
            Self::Parse => "janus token generation could not be parsed",
            Self::UnsupportedSchema => "janus token generation schema is unsupported",
            Self::InvalidGeneration => "janus token generation identifier is invalid",
            Self::InvalidHost => "janus token generation contains an invalid host",
            Self::InvalidHash => "janus token generation contains an invalid hash",
            Self::DuplicateHost => "janus token generation contains a duplicate host",
            Self::EmptyGeneration => "janus token generation contains no hosts",
            Self::ChangedDuringLoad => "janus token generation changed while loading",
            Self::StateUnavailable => "janus token generation state is unavailable",
        };
        f.write_str(message)
    }
}

impl JanusTokenStore {
    pub(crate) fn load(root: PathBuf) -> Result<Self, JanusTokenHashError> {
        validate_root(&root)?;
        let store = Self {
            root: Arc::new(root),
            state: Arc::new(RwLock::new(JanusTokenState::default())),
        };
        store.refresh()?;
        Ok(store)
    }

    pub(crate) fn token_matches(
        &self,
        host: &str,
        expected_hash: &str,
    ) -> Result<bool, JanusTokenHashError> {
        let generation = self.refresh()?;
        Ok(generation
            .hosts
            .get(host)
            .is_some_and(|stored| constant_time_eq(stored, expected_hash)))
    }

    pub(crate) fn manages_host(&self, host: &str) -> Result<bool, JanusTokenHashError> {
        Ok(self.refresh()?.hosts.contains_key(host))
    }

    pub(crate) fn readiness(&self) -> JanusTokenReadiness {
        let Ok(state) = self.state.read() else {
            return JanusTokenReadiness {
                ready: false,
                status: "state-unavailable",
                generation: None,
                last_success_unix: None,
                host_count: 0,
            };
        };
        let active = state.active.as_deref();
        JanusTokenReadiness {
            ready: active.is_some() && state.last_error.is_none(),
            status: if state.last_error.is_none() {
                "ready"
            } else {
                "unavailable"
            },
            generation: active.map(|generation| generation.id.clone()),
            last_success_unix: state.last_success_unix,
            host_count: active.map_or(0, |generation| generation.hosts.len()),
        }
    }

    pub(crate) fn refresh_readiness(&self) -> JanusTokenReadiness {
        let _ = self.refresh();
        self.readiness()
    }

    fn refresh(&self) -> Result<Arc<ValidatedGeneration>, JanusTokenHashError> {
        for _ in 0..3 {
            let generation_id = match read_current_id(&self.root) {
                Ok(id) => id,
                Err(error) => return self.fail(error),
            };
            let cached = {
                let state = self
                    .state
                    .read()
                    .map_err(|_| JanusTokenHashError::StateUnavailable)?;
                state
                    .active
                    .as_ref()
                    .filter(|active| active.id == generation_id && state.last_error.is_none())
                    .cloned()
            };
            if let Some(active) = cached {
                let identity = match generation_file_identity(&self.root, &generation_id) {
                    Ok(identity) => identity,
                    Err(error) => return self.fail(error),
                };
                if identity != active.file_identity {
                    return self.fail(JanusTokenHashError::UnsafeMetadata);
                }
                return Ok(active);
            }

            let generation = match load_generation(&self.root, &generation_id) {
                Ok(generation) => Arc::new(generation),
                Err(error) => return self.fail(error),
            };
            let stable_id = match read_current_id(&self.root) {
                Ok(id) => id,
                Err(error) => return self.fail(error),
            };
            if stable_id != generation_id {
                continue;
            }

            let mut state = self
                .state
                .write()
                .map_err(|_| JanusTokenHashError::StateUnavailable)?;
            state.active = Some(generation.clone());
            state.last_success_unix = Some(unix_now());
            state.last_error = None;
            return Ok(generation);
        }
        self.fail(JanusTokenHashError::ChangedDuringLoad)
    }

    fn fail<T>(&self, error: JanusTokenHashError) -> Result<T, JanusTokenHashError> {
        if let Ok(mut state) = self.state.write() {
            // Never retain a stale verifier after a changed or unavailable
            // current pointer: delayed revocation is less safe than outage.
            state.active = None;
            state.last_error = Some(error.clone());
        }
        Err(error)
    }
}

fn validate_root(root: &Path) -> Result<(), JanusTokenHashError> {
    if !root.is_absolute() {
        return Err(JanusTokenHashError::InvalidRoot);
    }
    let metadata = fs::symlink_metadata(root).map_err(|_| JanusTokenHashError::InvalidRoot)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(JanusTokenHashError::InvalidRoot);
    }
    #[cfg(unix)]
    if metadata.mode() & 0o027 != 0 {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }
    Ok(())
}

fn read_current_id(root: &Path) -> Result<String, JanusTokenHashError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| JanusTokenHashError::InvalidRoot)?;
    let path = root.join(JANUS_CURRENT_FILE);
    let (bytes, _) = read_bounded_regular_file(
        &path,
        MAX_CURRENT_BYTES,
        #[cfg(unix)]
        root_metadata.uid(),
    )
    .map_err(|error| {
        if matches!(error, JanusTokenHashError::Read) {
            JanusTokenHashError::MissingCurrent
        } else {
            error
        }
    })?;
    let value = std::str::from_utf8(&bytes)
        .map_err(|_| JanusTokenHashError::InvalidGeneration)?
        .strip_suffix('\n')
        .unwrap_or_else(|| std::str::from_utf8(&bytes).unwrap_or_default());
    if !is_generation_id(value) {
        return Err(JanusTokenHashError::InvalidGeneration);
    }
    Ok(value.to_string())
}

fn load_generation(
    root: &Path,
    expected_id: &str,
) -> Result<ValidatedGeneration, JanusTokenHashError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| JanusTokenHashError::InvalidRoot)?;
    let path = root.join(format!("generation-{expected_id}.json"));
    let (contents, file_identity) = read_bounded_regular_file(
        &path,
        MAX_GENERATION_BYTES,
        #[cfg(unix)]
        root_metadata.uid(),
    )?;
    let payload: TokenGeneration =
        serde_json::from_slice(&contents).map_err(|_| JanusTokenHashError::Parse)?;
    if payload.schema != JANUS_GENERATION_SCHEMA {
        return Err(JanusTokenHashError::UnsupportedSchema);
    }
    if payload.generation != expected_id || !is_generation_id(&payload.generation) {
        return Err(JanusTokenHashError::InvalidGeneration);
    }
    if payload.hosts.is_empty() {
        return Err(JanusTokenHashError::EmptyGeneration);
    }
    if payload.hosts.len() > MAX_GENERATION_HOSTS {
        return Err(JanusTokenHashError::InputTooLarge);
    }

    let mut hosts = BTreeMap::new();
    for entry in payload.hosts {
        if !valid_token_subject(&entry.name) {
            return Err(JanusTokenHashError::InvalidHost);
        }
        if !is_sha256_hex(&entry.token_sha256) {
            return Err(JanusTokenHashError::InvalidHash);
        }
        if hosts
            .insert(entry.name.clone(), entry.token_sha256)
            .is_some()
        {
            return Err(JanusTokenHashError::DuplicateHost);
        }
    }
    if generation_id(&hosts) != expected_id {
        return Err(JanusTokenHashError::InvalidGeneration);
    }
    Ok(ValidatedGeneration {
        id: expected_id.to_string(),
        hosts,
        file_identity,
    })
}

fn generation_file_identity(
    root: &Path,
    generation_id: &str,
) -> Result<FileIdentity, JanusTokenHashError> {
    let root_metadata = fs::symlink_metadata(root).map_err(|_| JanusTokenHashError::InvalidRoot)?;
    let path = root.join(format!("generation-{generation_id}.json"));
    let metadata = fs::symlink_metadata(path).map_err(|_| JanusTokenHashError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }
    validate_file_metadata(
        &metadata,
        MAX_GENERATION_BYTES,
        #[cfg(unix)]
        root_metadata.uid(),
    )?;
    Ok(FileIdentity::from_metadata(&metadata))
}

fn read_bounded_regular_file(
    path: &Path,
    max_bytes: u64,
    #[cfg(unix)] expected_uid: u32,
) -> Result<(Vec<u8>, FileIdentity), JanusTokenHashError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| JanusTokenHashError::Read)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }
    validate_file_metadata(
        &metadata,
        max_bytes,
        #[cfg(unix)]
        expected_uid,
    )?;

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|_| JanusTokenHashError::Read)?;
    let opened_metadata = file.metadata().map_err(|_| JanusTokenHashError::Read)?;
    validate_file_metadata(
        &opened_metadata,
        max_bytes,
        #[cfg(unix)]
        expected_uid,
    )?;
    #[cfg(unix)]
    if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }

    let mut bytes = Vec::with_capacity(opened_metadata.len() as usize);
    file.by_ref()
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| JanusTokenHashError::Read)?;
    if bytes.len() as u64 > max_bytes {
        return Err(JanusTokenHashError::InputTooLarge);
    }
    Ok((bytes, FileIdentity::from_metadata(&opened_metadata)))
}

impl FileIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            #[cfg(unix)]
            device: metadata.dev(),
            #[cfg(unix)]
            inode: metadata.ino(),
            #[cfg(unix)]
            uid: metadata.uid(),
            #[cfg(unix)]
            mode: metadata.mode(),
            #[cfg(unix)]
            modified_seconds: metadata.mtime(),
            #[cfg(unix)]
            modified_nanoseconds: metadata.mtime_nsec(),
            #[cfg(not(unix))]
            modified: metadata.modified().ok(),
        }
    }
}

fn validate_file_metadata(
    metadata: &fs::Metadata,
    max_bytes: u64,
    #[cfg(unix)] expected_uid: u32,
) -> Result<(), JanusTokenHashError> {
    if !metadata.is_file() {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }
    if metadata.len() > max_bytes {
        return Err(JanusTokenHashError::InputTooLarge);
    }
    #[cfg(unix)]
    if metadata.uid() != expected_uid || metadata.mode() & 0o027 != 0 {
        return Err(JanusTokenHashError::UnsafeMetadata);
    }
    Ok(())
}

pub(crate) fn valid_host_name(value: &str) -> bool {
    if value.is_empty() || value.len() > 253 || value.bytes().any(|byte| byte.is_ascii_uppercase())
    {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            && label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            && label
                .as_bytes()
                .last()
                .is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn valid_token_subject(value: &str) -> bool {
    valid_host_name(value)
        || (value.len() >= "host_".len() + 8
            && value.len() <= 96
            && value.starts_with("host_")
            && value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_'))
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_generation_id(value: &str) -> bool {
    is_sha256_hex(value)
}

pub(crate) fn generation_id(hosts: &BTreeMap<String, String>) -> String {
    let mut digest = Sha256::new();
    digest.update(b"inspr.pharos.beacon-token-generation.v2\0");
    for (host, hash) in hosts {
        digest.update((host.len() as u64).to_be_bytes());
        digest.update(host.as_bytes());
        digest.update(hash.as_bytes());
    }
    hex(&digest.finalize())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for index in 0..len {
        diff |= usize::from(
            left.get(index).copied().unwrap_or(0) ^ right.get(index).copied().unwrap_or(0),
        );
    }
    diff == 0
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(CHARS[(byte >> 4) as usize] as char);
        output.push(CHARS[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
pub(crate) fn write_test_generation(
    root: &Path,
    hosts: impl IntoIterator<Item = (String, String)>,
) -> String {
    let hosts = hosts.into_iter().collect::<BTreeMap<_, _>>();
    let id = generation_id(&hosts);
    let payload = TokenGeneration {
        schema: JANUS_GENERATION_SCHEMA.to_string(),
        generation: id.clone(),
        hosts: hosts
            .into_iter()
            .map(|(name, token_sha256)| TokenGenerationHost { name, token_sha256 })
            .collect(),
    };
    fs::create_dir_all(root).expect("create generation fixture root");
    #[cfg(unix)]
    fs::set_permissions(root, fs::Permissions::from_mode(0o700)).expect("secure fixture root");
    let generation_path = root.join(format!("generation-{id}.json"));
    fs::write(
        &generation_path,
        serde_json::to_vec(&payload).expect("encode generation fixture"),
    )
    .expect("write generation fixture");
    fs::write(root.join(JANUS_CURRENT_FILE), format!("{id}\n"))
        .expect("write generation pointer fixture");
    #[cfg(unix)]
    for path in [generation_path, root.join(JANUS_CURRENT_FILE)] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("secure generation fixture");
    }
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-janus-generation-{label}-{}-{}",
            std::process::id(),
            unix_now()
        ))
    }

    #[test]
    fn generation_round_trip_caches_until_the_atomic_pointer_changes() {
        let root = fixture_root("round-trip");
        let first_hash = "1".repeat(64);
        let first_id = write_test_generation(&root, [("csb0".to_string(), first_hash.clone())]);
        let store = JanusTokenStore::load(root.clone()).expect("load first generation");
        assert!(store
            .token_matches("csb0", &first_hash)
            .expect("first token lookup"));
        assert_eq!(
            store.readiness().generation.as_deref(),
            Some(first_id.as_str())
        );

        let second_hash = "2".repeat(64);
        let second_id = write_test_generation(&root, [("csb0".to_string(), second_hash.clone())]);
        assert!(!store
            .token_matches("csb0", &first_hash)
            .expect("revoked token lookup"));
        assert!(store
            .token_matches("csb0", &second_hash)
            .expect("replacement token lookup"));
        assert_eq!(
            store.readiness().generation.as_deref(),
            Some(second_id.as_str())
        );
    }

    #[test]
    fn unrelated_files_do_not_participate_in_the_generation() {
        let root = fixture_root("unrelated");
        let hash = "3".repeat(64);
        write_test_generation(&root, [("hsb0".to_string(), hash.clone())]);
        fs::write(root.join("unrelated.json"), b"not json").expect("write unrelated file");

        let store = JanusTokenStore::load(root).expect("ignore unrelated file");
        assert!(store
            .token_matches("hsb0", &hash)
            .expect("valid generation remains available"));
    }

    #[test]
    fn invalid_new_pointer_clears_the_old_verifier_and_readiness() {
        let root = fixture_root("fail-closed");
        let hash = "4".repeat(64);
        write_test_generation(&root, [("dsc0".to_string(), hash.clone())]);
        let store = JanusTokenStore::load(root.clone()).expect("load generation");
        fs::write(
            root.join(JANUS_CURRENT_FILE),
            format!("{}\n", "5".repeat(64)),
        )
        .expect("replace pointer");

        assert!(store.token_matches("dsc0", &hash).is_err());
        let readiness = store.readiness();
        assert!(!readiness.ready);
        assert_eq!(readiness.status, "unavailable");
        assert!(readiness.generation.is_none());
    }

    #[test]
    fn missing_active_generation_is_not_hidden_by_the_cache() {
        let root = fixture_root("missing-active");
        let hash = "7".repeat(64);
        let generation = write_test_generation(&root, [("gpc0".to_string(), hash.clone())]);
        let store = JanusTokenStore::load(root.clone()).expect("load generation");
        fs::remove_file(root.join(format!("generation-{generation}.json")))
            .expect("remove active generation fixture");

        assert!(store.token_matches("gpc0", &hash).is_err());
        assert!(!store.readiness().ready);
        assert!(store.readiness().generation.is_none());
    }

    #[test]
    fn contract_rejects_unknown_fields_noncanonical_hosts_and_bad_generation_ids() {
        let root = fixture_root("strict");
        let hash = "6".repeat(64);
        let id = write_test_generation(&root, [("csb0".to_string(), hash)]);
        let path = root.join(format!("generation-{id}.json"));
        let mut payload: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("read fixture")).expect("parse fixture");
        payload["extra"] = serde_json::Value::Bool(true);
        fs::write(
            &path,
            serde_json::to_vec(&payload).expect("encode malformed fixture"),
        )
        .expect("write malformed fixture");
        assert_eq!(
            JanusTokenStore::load(root).err(),
            Some(JanusTokenHashError::Parse)
        );

        assert!(!valid_host_name("UPPER"));
        assert!(!valid_host_name("bad_host"));
        assert!(!valid_host_name("-bad"));
        assert!(!valid_host_name("bad-"));
        assert!(valid_host_name("host-1.example"));
    }

    #[test]
    fn host_ref_is_a_valid_agent_token_subject_but_not_a_hostname() {
        let root = fixture_root("host-ref-subject");
        let host_ref = "host_58f36c72a91e";
        let hash = "8".repeat(64);
        write_test_generation(&root, [(host_ref.to_string(), hash.clone())]);
        let store = JanusTokenStore::load(root).expect("load host-ref generation");

        assert!(store.token_matches(host_ref, &hash).unwrap());
        assert!(!valid_host_name(host_ref));
        assert!(valid_token_subject(host_ref));
        assert!(!valid_token_subject("host_short"));
    }

    #[test]
    fn shared_janus_producer_fixture_is_consumer_compatible() {
        let root = fixture_root("shared-contract");
        fs::create_dir_all(&root).expect("create shared contract fixture root");
        #[cfg(unix)]
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
            .expect("secure shared contract fixture root");
        let generation = "17fa715d01efa6a7a08c8ebccbe93d1e0239b5601ee455ff1f22675dff3233f4";
        let generation_path = root.join(format!("generation-{generation}.json"));
        fs::write(
            &generation_path,
            include_bytes!("../../../contracts/pharos-beacon-token-generation-v2.json"),
        )
        .expect("write shared producer fixture");
        fs::write(root.join(JANUS_CURRENT_FILE), format!("{generation}\n"))
            .expect("write shared fixture pointer");
        #[cfg(unix)]
        for path in [generation_path, root.join(JANUS_CURRENT_FILE)] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("secure shared fixture file");
        }

        let store = JanusTokenStore::load(root).expect("Pharos accepts the Janus fixture");
        assert_eq!(store.readiness().generation.as_deref(), Some(generation));
        assert_eq!(store.readiness().host_count, 2);
    }
}
