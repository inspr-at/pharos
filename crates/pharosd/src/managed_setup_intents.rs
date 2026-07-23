//! Signed, short-lived, value-free handoffs from Pharos to Janus.
//!
//! The browser receives only an opaque `intent_…` reference. Janus retrieves
//! the signed payload over an authenticated server-to-server route, verifies
//! the signature and current declaration, and is the sole replay authority.

use std::collections::BTreeMap;
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

use crate::durable_file::{atomic_write_json, load_optional_json};

pub(crate) const SIGNED_INTENT_SCHEMA: &str = "inspr.janus.signed-managed-service-setup-intent.v1";
pub(crate) const SETUP_INTENT_SCHEMA: &str = "inspr.janus.managed-service-setup-intent.v1";
pub(crate) const DELIVERY_SCHEMA: &str = "inspr.pharos.managed-service-setup-intent-delivery.v1";
pub(crate) const CONTRACT_VERSION: u16 = 1;
pub(crate) const INTENT_TTL_SECS: i64 = 300;
const STORE_SCHEMA: &str = "inspr.pharos.managed-service-setup-intent-store.v1";
const SIGNING_KEY_SCHEMA: &str = "inspr.pharos.managed-service-setup-signing-key.v1";
const SIGNATURE_DOMAIN: &[u8] = b"inspr.janus.signed-managed-service-setup-intent.v1";
const MAX_INTENTS: usize = 4_096;
const MAX_KEY_FILE_BYTES: u64 = 8 * 1024;
const MAX_TOKEN_FILE_BYTES: u64 = 8 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedOperationKind {
    Create,
    Replace,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedSecretSource {
    Generated,
    Import,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct ManagedSetupIntentV1 {
    pub schema: String,
    pub schema_version: u16,
    pub intent_ref: String,
    pub operation_kind: ManagedOperationKind,
    pub source: ManagedSecretSource,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub human_session_ref: String,
    pub issuer_ref: String,
    pub audience_ref: String,
    pub nonce_ref: String,
    pub declaration_fingerprint: String,
    pub issued_at_unix_secs: i64,
    pub expires_at_unix_secs: i64,
    pub return_target: ManagedReturnTarget,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedReturnTarget {
    PharosService,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct SignedManagedSetupIntentV1 {
    pub schema: String,
    pub schema_version: u16,
    pub key_id: String,
    pub payload_base64url: String,
    pub signature_base64url: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct SigningKeyDocument {
    schema: String,
    schema_version: u16,
    key_id: String,
    private_key_base64url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum StoredIntentState {
    Pending,
    Delivered,
    Cancelled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct StoredIntent {
    envelope: SignedManagedSetupIntentV1,
    human_session_ref: String,
    expires_at_unix_secs: i64,
    state: StoredIntentState,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IntentStoreDocument {
    schema: String,
    schema_version: u16,
    intents: BTreeMap<String, StoredIntent>,
}

impl Default for IntentStoreDocument {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            schema_version: CONTRACT_VERSION,
            intents: BTreeMap::new(),
        }
    }
}

pub(crate) struct ManagedSetupIntentConfig {
    signer: SigningKey,
    key_id: String,
    janus_origin: Url,
    internal_token_hash: [u8; 32],
    issuer_ref: String,
    audience_ref: String,
}

impl fmt::Debug for ManagedSetupIntentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ManagedSetupIntentConfig")
            .field("key_id", &self.key_id)
            .field("janus_origin", &self.janus_origin)
            .field("issuer_ref", &self.issuer_ref)
            .field("audience_ref", &self.audience_ref)
            .finish_non_exhaustive()
    }
}

impl ManagedSetupIntentConfig {
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let key_path = env_nonempty("PHAROS_MANAGED_SETUP_SIGNING_KEY_FILE");
        let janus_origin = env_nonempty("PHAROS_MANAGED_SETUP_JANUS_ORIGIN");
        let token_path = env_nonempty("PHAROS_MANAGED_SETUP_INTERNAL_TOKEN_FILE");
        if key_path.is_none() && janus_origin.is_none() && token_path.is_none() {
            return Ok(None);
        }
        let key_path = key_path.ok_or_else(|| {
            "PHAROS_MANAGED_SETUP_SIGNING_KEY_FILE is required when managed setup is enabled"
                .to_string()
        })?;
        let janus_origin = janus_origin.ok_or_else(|| {
            "PHAROS_MANAGED_SETUP_JANUS_ORIGIN is required when managed setup is enabled"
                .to_string()
        })?;
        let token_path = token_path.ok_or_else(|| {
            "PHAROS_MANAGED_SETUP_INTERNAL_TOKEN_FILE is required when managed setup is enabled"
                .to_string()
        })?;
        let key_document: SigningKeyDocument =
            read_bounded_private_json(Path::new(&key_path), MAX_KEY_FILE_BYTES)
                .map_err(|error| format!("managed setup signing key: {error}"))?;
        if key_document.schema != SIGNING_KEY_SCHEMA
            || key_document.schema_version != CONTRACT_VERSION
            || !valid_ref("key_", &key_document.key_id)
        {
            return Err("managed setup signing key contract is invalid".to_string());
        }
        let key_bytes = URL_SAFE_NO_PAD
            .decode(&key_document.private_key_base64url)
            .map_err(|_| "managed setup signing key encoding is invalid".to_string())?;
        let key_bytes: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| "managed setup signing key must contain 32 bytes".to_string())?;
        let janus_origin = parse_origin(&janus_origin, "Janus")?;
        let token = read_bounded_private_secret(Path::new(&token_path), MAX_TOKEN_FILE_BYTES)
            .map_err(|error| format!("managed setup internal token: {error}"))?;
        Ok(Some(Self {
            signer: SigningKey::from_bytes(&key_bytes),
            key_id: key_document.key_id,
            janus_origin,
            internal_token_hash: Sha256::digest(token.as_bytes()).into(),
            issuer_ref: env_ref(
                "PHAROS_MANAGED_SETUP_ISSUER_REF",
                "sys_pharos_control_plane_v1",
                "sys_",
            )?,
            audience_ref: env_ref(
                "PHAROS_MANAGED_SETUP_AUDIENCE_REF",
                "sys_janus_secret_custody_v1",
                "sys_",
            )?,
        }))
    }

    #[cfg(test)]
    pub(crate) fn for_test(seed: [u8; 32], key_id: &str, token: &str) -> Self {
        Self {
            signer: SigningKey::from_bytes(&seed),
            key_id: key_id.to_string(),
            janus_origin: Url::parse("https://vault.example.test").unwrap(),
            internal_token_hash: Sha256::digest(token.as_bytes()).into(),
            issuer_ref: "sys_pharos_control_plane_v1".to_string(),
            audience_ref: "sys_janus_secret_custody_v1".to_string(),
        }
    }

    pub(crate) fn continue_url(&self, intent_ref: &str) -> String {
        let mut target = self.janus_origin.clone();
        target.set_path("/managed-service/setup");
        target
            .query_pairs_mut()
            .clear()
            .append_pair("intent", intent_ref);
        target.to_string()
    }

    pub(crate) fn token_matches(&self, actual: &str) -> bool {
        let actual_hash: [u8; 32] = Sha256::digest(actual.as_bytes()).into();
        constant_time_equal(&self.internal_token_hash, &actual_hash)
    }
}

pub(crate) struct ManagedSetupIntentStore {
    path: PathBuf,
    config: ManagedSetupIntentConfig,
    document: Mutex<IntentStoreDocument>,
}

#[derive(Clone, Debug)]
pub(crate) struct IssueIntent {
    pub operation_kind: ManagedOperationKind,
    pub source: ManagedSecretSource,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub human_session_ref: String,
    pub declaration_fingerprint: String,
    pub now_unix_secs: i64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IssuedIntent {
    pub intent_ref: String,
    pub continue_url: String,
    pub expires_at_unix_secs: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum IntentReason {
    Disabled,
    AuthenticationRequired,
    Forbidden,
    InvalidRequest,
    DeclarationUnavailable,
    DeclarationDrift,
    AlreadyDelivered,
    Unknown,
    Expired,
    Cancelled,
    WrongUser,
    UnauthorizedSystem,
    Capacity,
    PersistenceUnavailable,
}

impl IntentReason {
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Disabled => "managed_intent_disabled",
            Self::AuthenticationRequired => "managed_intent_authentication_required",
            Self::Forbidden => "managed_intent_forbidden",
            Self::InvalidRequest => "managed_intent_invalid_request",
            Self::DeclarationUnavailable => "managed_intent_declaration_unavailable",
            Self::DeclarationDrift => "managed_intent_declaration_drift",
            Self::AlreadyDelivered => "managed_intent_already_delivered",
            Self::Unknown => "managed_intent_unknown",
            Self::Expired => "managed_intent_expired",
            Self::Cancelled => "managed_intent_cancelled",
            Self::WrongUser => "managed_intent_wrong_user",
            Self::UnauthorizedSystem => "managed_intent_unauthorized_system",
            Self::Capacity => "managed_intent_capacity",
            Self::PersistenceUnavailable => "managed_intent_persistence_unavailable",
        }
    }
}

impl ManagedSetupIntentStore {
    pub(crate) fn new(path: PathBuf, config: ManagedSetupIntentConfig) -> Result<Self, String> {
        let document = load_optional_json::<IntentStoreDocument>(&path)
            .map_err(|error| error.to_string())?
            .unwrap_or_default();
        validate_store_document(&document)?;
        Ok(Self {
            path,
            config,
            document: Mutex::new(document),
        })
    }

    pub(crate) fn path_for(database_path: Option<&Path>) -> Option<PathBuf> {
        database_path.map(|path| path.with_file_name("managed-setup-intents.json"))
    }

    pub(crate) fn issue(&self, request: IssueIntent) -> Result<IssuedIntent, IntentReason> {
        if request.now_unix_secs <= 0
            || !valid_ref("host_", &request.host_ref)
            || !valid_ref("svc_", &request.service_ref)
            || !valid_ref("slot_", &request.slot_ref)
            || !valid_ref("hsn_", &request.human_session_ref)
            || !valid_ref("decl_", &request.declaration_fingerprint)
        {
            return Err(IntentReason::InvalidRequest);
        }
        let intent_ref = random_ref("intent_").map_err(|_| IntentReason::PersistenceUnavailable)?;
        let nonce_ref = random_ref("nonce_").map_err(|_| IntentReason::PersistenceUnavailable)?;
        let expires_at = request.now_unix_secs.saturating_add(INTENT_TTL_SECS);
        let intent = ManagedSetupIntentV1 {
            schema: SETUP_INTENT_SCHEMA.to_string(),
            schema_version: CONTRACT_VERSION,
            intent_ref: intent_ref.clone(),
            operation_kind: request.operation_kind,
            source: request.source,
            host_ref: request.host_ref,
            service_ref: request.service_ref,
            slot_ref: request.slot_ref,
            human_session_ref: request.human_session_ref.clone(),
            issuer_ref: self.config.issuer_ref.clone(),
            audience_ref: self.config.audience_ref.clone(),
            nonce_ref,
            declaration_fingerprint: request.declaration_fingerprint,
            issued_at_unix_secs: request.now_unix_secs,
            expires_at_unix_secs: expires_at,
            return_target: ManagedReturnTarget::PharosService,
        };
        let envelope =
            sign_intent(&self.config, &intent).map_err(|_| IntentReason::PersistenceUnavailable)?;
        let stored = StoredIntent {
            envelope,
            human_session_ref: request.human_session_ref,
            expires_at_unix_secs: expires_at,
            state: StoredIntentState::Pending,
        };
        let mut document = self.document.lock().expect("managed intent lock");
        sweep_expired(&mut document, request.now_unix_secs);
        if document.intents.len() >= MAX_INTENTS || document.intents.contains_key(&intent_ref) {
            return Err(IntentReason::Capacity);
        }
        document.intents.insert(intent_ref.clone(), stored);
        if let Err(error) = atomic_write_json(&self.path, &*document) {
            if !error.final_file_replaced() {
                document.intents.remove(&intent_ref);
            }
            return Err(IntentReason::PersistenceUnavailable);
        }
        Ok(IssuedIntent {
            continue_url: self.config.continue_url(&intent_ref),
            intent_ref,
            expires_at_unix_secs: expires_at,
        })
    }

    pub(crate) fn retrieve(
        &self,
        intent_ref: &str,
        bearer_token: &str,
        now_unix_secs: i64,
    ) -> Result<SignedManagedSetupIntentV1, IntentReason> {
        if !self.config.token_matches(bearer_token) {
            return Err(IntentReason::UnauthorizedSystem);
        }
        if !valid_ref("intent_", intent_ref) {
            return Err(IntentReason::Unknown);
        }
        let mut document = self.document.lock().expect("managed intent lock");
        let stored = document
            .intents
            .get_mut(intent_ref)
            .ok_or(IntentReason::Unknown)?;
        if now_unix_secs < 0 || now_unix_secs >= stored.expires_at_unix_secs {
            return Err(IntentReason::Expired);
        }
        match stored.state {
            StoredIntentState::Cancelled => return Err(IntentReason::Cancelled),
            StoredIntentState::Delivered => return Ok(stored.envelope.clone()),
            StoredIntentState::Pending => {
                stored.state = StoredIntentState::Delivered;
            }
        }
        let envelope = document
            .intents
            .get(intent_ref)
            .expect("intent remains present")
            .envelope
            .clone();
        if let Err(error) = atomic_write_json(&self.path, &*document) {
            if !error.final_file_replaced() {
                if let Some(stored) = document.intents.get_mut(intent_ref) {
                    stored.state = StoredIntentState::Pending;
                }
            }
            return Err(IntentReason::PersistenceUnavailable);
        }
        Ok(envelope)
    }

    pub(crate) fn cancel(
        &self,
        intent_ref: &str,
        human_session_ref: &str,
        now_unix_secs: i64,
    ) -> Result<(), IntentReason> {
        if !valid_ref("intent_", intent_ref) || !valid_ref("hsn_", human_session_ref) {
            return Err(IntentReason::Unknown);
        }
        let mut document = self.document.lock().expect("managed intent lock");
        let stored = document
            .intents
            .get_mut(intent_ref)
            .ok_or(IntentReason::Unknown)?;
        if now_unix_secs < 0 || now_unix_secs >= stored.expires_at_unix_secs {
            return Err(IntentReason::Expired);
        }
        if stored.human_session_ref != human_session_ref {
            return Err(IntentReason::WrongUser);
        }
        if stored.state == StoredIntentState::Cancelled {
            return Ok(());
        }
        if stored.state == StoredIntentState::Delivered {
            return Err(IntentReason::AlreadyDelivered);
        }
        stored.state = StoredIntentState::Cancelled;
        if let Err(error) = atomic_write_json(&self.path, &*document) {
            if !error.final_file_replaced() {
                if let Some(stored) = document.intents.get_mut(intent_ref) {
                    stored.state = StoredIntentState::Pending;
                }
            }
            return Err(IntentReason::PersistenceUnavailable);
        }
        Ok(())
    }
}

fn sign_intent(
    config: &ManagedSetupIntentConfig,
    intent: &ManagedSetupIntentV1,
) -> Result<SignedManagedSetupIntentV1, serde_json::Error> {
    let payload = serde_json::to_vec(intent)?;
    let signature = config
        .signer
        .sign(&signature_message(&config.key_id, &payload));
    Ok(SignedManagedSetupIntentV1 {
        schema: SIGNED_INTENT_SCHEMA.to_string(),
        schema_version: CONTRACT_VERSION,
        key_id: config.key_id.clone(),
        payload_base64url: URL_SAFE_NO_PAD.encode(payload),
        signature_base64url: URL_SAFE_NO_PAD.encode(signature.to_bytes()),
    })
}

pub(crate) fn signature_message(key_id: &str, payload: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(SIGNATURE_DOMAIN.len() + key_id.len() + payload.len() + 2);
    message.extend_from_slice(SIGNATURE_DOMAIN);
    message.push(0);
    message.extend_from_slice(key_id.as_bytes());
    message.push(0);
    message.extend_from_slice(payload);
    message
}

fn sweep_expired(document: &mut IntentStoreDocument, now_unix_secs: i64) {
    document
        .intents
        .retain(|_, intent| intent.expires_at_unix_secs > now_unix_secs);
}

fn validate_store_document(document: &IntentStoreDocument) -> Result<(), String> {
    if document.schema != STORE_SCHEMA
        || document.schema_version != CONTRACT_VERSION
        || document.intents.len() > MAX_INTENTS
        || document.intents.iter().any(|(intent_ref, intent)| {
            !valid_ref("intent_", intent_ref)
                || intent_ref != &intent_payload_ref(&intent.envelope).unwrap_or_default()
                || !valid_ref("hsn_", &intent.human_session_ref)
                || intent.expires_at_unix_secs <= 0
        })
    {
        return Err("managed setup intent store contract is invalid".to_string());
    }
    Ok(())
}

fn intent_payload_ref(envelope: &SignedManagedSetupIntentV1) -> Option<String> {
    if envelope.schema != SIGNED_INTENT_SCHEMA
        || envelope.schema_version != CONTRACT_VERSION
        || !valid_ref("key_", &envelope.key_id)
    {
        return None;
    }
    let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_base64url).ok()?;
    let intent: ManagedSetupIntentV1 = serde_json::from_slice(&payload).ok()?;
    Some(intent.intent_ref)
}

fn random_ref(prefix: &str) -> Result<String, getrandom::Error> {
    let mut bytes = [0_u8; 16];
    getrandom::getrandom(&mut bytes)?;
    Ok(format!("{prefix}{}", hex(&bytes)))
}

fn hex(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(ALPHABET[usize::from(byte >> 4)] as char);
        encoded.push(ALPHABET[usize::from(byte & 0x0f)] as char);
    }
    encoded
}

pub(crate) fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn parse_origin(value: &str, label: &str) -> Result<Url, String> {
    let url = Url::parse(value).map_err(|_| format!("{label} origin is invalid"))?;
    let loopback_http =
        url.scheme() == "http" && matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !loopback_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err(format!(
            "{label} origin must be an HTTPS origin without path, credentials, query, or fragment"
        ));
    }
    Ok(url)
}

fn read_bounded_private_json<T: for<'de> Deserialize<'de>>(
    path: &Path,
    max_bytes: u64,
) -> Result<T, String> {
    ensure_private_regular_file(path, max_bytes)?;
    let bytes = fs::read(path).map_err(|error| error.to_string())?;
    serde_json::from_slice(&bytes).map_err(|_| "JSON contract is invalid".to_string())
}

fn read_bounded_private_secret(path: &Path, max_bytes: u64) -> Result<String, String> {
    ensure_private_regular_file(path, max_bytes)?;
    let value = fs::read_to_string(path).map_err(|error| error.to_string())?;
    let value = value.trim();
    if value.len() < 32 || value.chars().any(char::is_whitespace) {
        return Err("token contract is invalid".to_string());
    }
    Ok(value.to_string())
}

fn ensure_private_regular_file(path: &Path, max_bytes: u64) -> Result<(), String> {
    let metadata = fs::metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err("file size is invalid".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("file permissions must deny group and other access".to_string());
        }
    }
    Ok(())
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_ref(name: &str, default: &str, prefix: &str) -> Result<String, String> {
    let value = env_nonempty(name).unwrap_or_else(|| default.to_string());
    if !valid_ref(prefix, &value) {
        return Err(format!("{name} is not a valid opaque reference"));
    }
    Ok(value)
}

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in left.iter().zip(right) {
        difference |= left ^ right;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, Verifier};
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn test_path() -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-managed-intents-{}-{}.json",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn request(now: i64) -> IssueIntent {
        IssueIntent {
            operation_kind: ManagedOperationKind::Create,
            source: ManagedSecretSource::Generated,
            host_ref: "host_7f94a1c8e912".to_string(),
            service_ref: "svc_24b7c8f0aa19".to_string(),
            slot_ref: "slot_d5019e2a7b11".to_string(),
            human_session_ref: "hsn_489e126a70bf".to_string(),
            declaration_fingerprint: "decl_41268e2b772a".to_string(),
            now_unix_secs: now,
        }
    }

    #[test]
    fn issues_signed_value_free_intent_and_browser_gets_only_opaque_ref() {
        let path = test_path();
        let token = "t".repeat(32);
        let config = ManagedSetupIntentConfig::for_test([7; 32], "key_primary0001", &token);
        let public_key = config.signer.verifying_key();
        let store = ManagedSetupIntentStore::new(path.clone(), config).unwrap();
        let issued = store.issue(request(1_784_833_200)).unwrap();
        assert_eq!(
            issued.continue_url,
            format!(
                "https://vault.example.test/managed-service/setup?intent={}",
                issued.intent_ref
            )
        );
        assert!(!issued.continue_url.contains("host_"));
        assert!(!issued.continue_url.contains("slot_"));
        assert!(!issued.continue_url.contains("callback"));

        let envelope = store
            .retrieve(&issued.intent_ref, &token, 1_784_833_201)
            .unwrap();
        let payload = URL_SAFE_NO_PAD.decode(&envelope.payload_base64url).unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(&envelope.signature_base64url)
                .unwrap(),
        )
        .unwrap();
        public_key
            .verify(&signature_message(&envelope.key_id, &payload), &signature)
            .unwrap();
        let intent: ManagedSetupIntentV1 = serde_json::from_slice(&payload).unwrap();
        assert_eq!(intent.intent_ref, issued.intent_ref);
        assert_eq!(
            intent.expires_at_unix_secs - intent.issued_at_unix_secs,
            300
        );
        let encoded = serde_json::to_string(&envelope).unwrap();
        for forbidden in ["password", "ciphertext", "callback", "/run/", "permit"] {
            assert!(!encoded.contains(forbidden));
        }
        let _ = fs::remove_file(path);
    }

    #[test]
    fn retrieval_is_machine_authenticated_and_cancellation_is_user_bound() {
        let path = test_path();
        let token = "u".repeat(32);
        let config = ManagedSetupIntentConfig::for_test([8; 32], "key_primary0002", &token);
        let store = ManagedSetupIntentStore::new(path.clone(), config).unwrap();
        let issued = store.issue(request(100)).unwrap();
        assert_eq!(
            store.retrieve(&issued.intent_ref, &"x".repeat(32), 101),
            Err(IntentReason::UnauthorizedSystem)
        );
        assert_eq!(
            store.cancel(&issued.intent_ref, "hsn_someone_else0", 101),
            Err(IntentReason::WrongUser)
        );
        store
            .cancel(&issued.intent_ref, "hsn_489e126a70bf", 101)
            .unwrap();
        assert_eq!(
            store.retrieve(&issued.intent_ref, &token, 101),
            Err(IntentReason::Cancelled)
        );
        assert_eq!(
            store.retrieve(&issued.intent_ref, &token, 400),
            Err(IntentReason::Expired)
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn delivery_is_idempotent_and_closes_the_pharos_cancellation_race() {
        let path = test_path();
        let token = "d".repeat(32);
        let config = ManagedSetupIntentConfig::for_test([12; 32], "key_delivery0001", &token);
        let store = ManagedSetupIntentStore::new(path.clone(), config).unwrap();
        let issued = store.issue(request(500)).unwrap();
        let first = store.retrieve(&issued.intent_ref, &token, 501).unwrap();
        let duplicate = store.retrieve(&issued.intent_ref, &token, 502).unwrap();
        assert_eq!(first, duplicate);
        assert_eq!(
            store.cancel(&issued.intent_ref, "hsn_489e126a70bf", 503),
            Err(IntentReason::AlreadyDelivered)
        );
        let restarted = ManagedSetupIntentStore::new(
            path.clone(),
            ManagedSetupIntentConfig::for_test([12; 32], "key_delivery0001", &token),
        )
        .unwrap();
        assert_eq!(
            restarted.retrieve(&issued.intent_ref, &token, 504).unwrap(),
            first
        );
        let _ = fs::remove_file(path);
    }

    #[test]
    fn key_identity_is_covered_by_signature_for_safe_rotation() {
        let config =
            ManagedSetupIntentConfig::for_test([9; 32], "key_rotating0001", &"v".repeat(32));
        let envelope = sign_intent(
            &config,
            &ManagedSetupIntentV1 {
                schema: SETUP_INTENT_SCHEMA.to_string(),
                schema_version: 1,
                intent_ref: "intent_0f92b78c3d16".to_string(),
                operation_kind: ManagedOperationKind::Create,
                source: ManagedSecretSource::Generated,
                host_ref: "host_7f94a1c8e912".to_string(),
                service_ref: "svc_24b7c8f0aa19".to_string(),
                slot_ref: "slot_d5019e2a7b11".to_string(),
                human_session_ref: "hsn_489e126a70bf".to_string(),
                issuer_ref: "sys_pharos_control_plane_v1".to_string(),
                audience_ref: "sys_janus_secret_custody_v1".to_string(),
                nonce_ref: "nonce_a280fd61b9ce".to_string(),
                declaration_fingerprint: "decl_41268e2b772a".to_string(),
                issued_at_unix_secs: 1_784_833_200,
                expires_at_unix_secs: 1_784_833_500,
                return_target: ManagedReturnTarget::PharosService,
            },
        )
        .unwrap();
        let payload = URL_SAFE_NO_PAD.decode(envelope.payload_base64url).unwrap();
        let signature = Signature::from_slice(
            &URL_SAFE_NO_PAD
                .decode(envelope.signature_base64url)
                .unwrap(),
        )
        .unwrap();
        assert!(config
            .signer
            .verifying_key()
            .verify(
                &signature_message("key_different0001", &payload),
                &signature
            )
            .is_err());
        assert_eq!(
            URL_SAFE_NO_PAD.encode(config.signer.verifying_key().to_bytes()),
            "_RckOFqgx1tk-3jNYC-h2ZH96_drE8WO1wLqyDXp9hg"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(&payload),
            "eyJzY2hlbWEiOiJpbnNwci5qYW51cy5tYW5hZ2VkLXNlcnZpY2Utc2V0dXAtaW50ZW50LnYxIiwic2NoZW1hX3ZlcnNpb24iOjEsImludGVudF9yZWYiOiJpbnRlbnRfMGY5MmI3OGMzZDE2Iiwib3BlcmF0aW9uX2tpbmQiOiJjcmVhdGUiLCJzb3VyY2UiOiJnZW5lcmF0ZWQiLCJob3N0X3JlZiI6Imhvc3RfN2Y5NGExYzhlOTEyIiwic2VydmljZV9yZWYiOiJzdmNfMjRiN2M4ZjBhYTE5Iiwic2xvdF9yZWYiOiJzbG90X2Q1MDE5ZTJhN2IxMSIsImh1bWFuX3Nlc3Npb25fcmVmIjoiaHNuXzQ4OWUxMjZhNzBiZiIsImlzc3Vlcl9yZWYiOiJzeXNfcGhhcm9zX2NvbnRyb2xfcGxhbmVfdjEiLCJhdWRpZW5jZV9yZWYiOiJzeXNfamFudXNfc2VjcmV0X2N1c3RvZHlfdjEiLCJub25jZV9yZWYiOiJub25jZV9hMjgwZmQ2MWI5Y2UiLCJkZWNsYXJhdGlvbl9maW5nZXJwcmludCI6ImRlY2xfNDEyNjhlMmI3NzJhIiwiaXNzdWVkX2F0X3VuaXhfc2VjcyI6MTc4NDgzMzIwMCwiZXhwaXJlc19hdF91bml4X3NlY3MiOjE3ODQ4MzM1MDAsInJldHVybl90YXJnZXQiOiJwaGFyb3Nfc2VydmljZSJ9"
        );
        assert_eq!(
            URL_SAFE_NO_PAD.encode(signature.to_bytes()),
            "HzAdIgR9Tu2uRIjXeSXVuUKI2Qz_iRaNc8jLspprckTvx-XGRFFwaYT8D1ntisizZ1dIIDBsXQ5XD0-s3GBkAg"
        );
    }

    #[test]
    fn rejects_open_redirect_shaped_origins() {
        for value in [
            "https://vault.example.test/path",
            "https://user@vault.example.test",
            "https://vault.example.test?next=https://evil.test",
            "http://vault.example.test",
        ] {
            assert!(parse_origin(value, "Janus").is_err(), "{value}");
        }
        assert!(parse_origin("http://127.0.0.1:8080", "Janus").is_ok());
    }

    #[test]
    fn signing_material_and_internal_tokens_require_private_files() {
        let path = test_path();
        fs::write(&path, "x".repeat(32)).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
            assert!(ensure_private_regular_file(&path, 1024).is_err());
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        ensure_private_regular_file(&path, 1024).unwrap();
        let _ = fs::remove_file(path);
    }
}
