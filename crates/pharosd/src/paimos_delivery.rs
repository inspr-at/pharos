//! Reporter-only Paimos external-stage adapter (PHAROS-206).
//!
//! Paimos supplies an opaque handoff and a value-free stage projection. Every
//! authority-bearing choice remains in this service's owner-only local intent
//! file: host, guarded workflow, environment, artifact, and existing Pharos
//! workflow binding. This module can report observations; it cannot create,
//! confirm, claim, or execute a host action.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use reqwest::header::{
    HeaderMap, HeaderValue, ACCEPT, ACCEPT_ENCODING, AUTHORIZATION, CONTENT_ENCODING, CONTENT_TYPE,
    USER_AGENT,
};
use reqwest::{Method, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

use crate::durable_file::atomic_write_json;
use crate::host_actions::{HostActionState, HostActionStore, HostWorkflowKind};
use crate::store::Store;

pub(crate) const PAIMOS_SCHEMA_MAJOR: u16 = 1;
pub(crate) const PAIMOS_RELEASE: &str = "v5.11.0";
pub(crate) const PAIMOS_CERTIFIED_COMMIT: &str = "e5f4c86bc061775c853d5847e8fb8bb7e3a31c34";
pub(crate) const PAIMOS_FIXTURE_DIGEST: &str =
    "sha256:0318f4025902c9d5dd790384950cc9daebb16e02e79a4a90ce7dddc673e68bed";

const CONFIG_SCHEMA: &str = "inspr.pharos.paimos-delivery-adapter.v1";
const JOURNAL_SCHEMA: &str = "inspr.pharos.paimos-delivery-journal.v1";
const INTENT_BINDING_DOMAIN: &str = "inspr.pharos.paimos-delivery-intent.v1";
const CONTRACT_MEDIA_TYPE: &str = "application/vnd.paimos.external-stage.v1+json";
const HANDOFF_SECRET_HEADER: &str = "X-PAIMOS-Handoff-Secret";
const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
const USER_AGENT_VALUE: &str = "pharosd-paimos-delivery/1";
const IDENTITY_ENCODING: &str = "identity";
const HANDOFF_SECRET_BYTES: usize = 32;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_API_KEY_BYTES: u64 = 512;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_INTENTS: usize = 128;
const MAX_JOURNAL_RECORDS: usize = MAX_INTENTS * 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const IDEMPOTENCY_DOMAIN: &[u8] = b"inspr.pharos.paimos-delivery-idempotency.v1\0";

#[derive(Debug)]
enum AdapterError {
    Configuration,
    Credential,
    Contract,
    Journal,
    LocalBinding,
    Transport,
    Refused(StatusCode),
}

impl AdapterError {
    fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "configuration_invalid",
            Self::Credential => "credential_unavailable",
            Self::Contract => "contract_refused",
            Self::Journal => "journal_unavailable",
            Self::LocalBinding => "local_binding_refused",
            Self::Transport => "transport_unavailable",
            Self::Refused(_) => "paimos_refused",
        }
    }
}

impl fmt::Display for AdapterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Refused(status) => write!(formatter, "{} ({})", self.code(), status.as_u16()),
            _ => formatter.write_str(self.code()),
        }
    }
}

impl std::error::Error for AdapterError {}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum IntentStage {
    Deployment,
    Verification,
}

impl IntentStage {
    fn key(self) -> &'static str {
        match self {
            Self::Deployment => "deployment",
            Self::Verification => "verification",
        }
    }

    fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Deployment => EvidenceKind::Deployment,
            Self::Verification => EvidenceKind::Verification,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum GuardedWorkflow {
    DeployProduction,
    VerifyProduction,
}

impl GuardedWorkflow {
    fn key(self) -> &'static str {
        match self {
            Self::DeployProduction => "deploy-production",
            Self::VerifyProduction => "verify-production",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ArtifactEvidence {
    version: String,
    digest: String,
    commit_digest: String,
}

impl ArtifactEvidence {
    fn valid(&self) -> bool {
        valid_version(&self.version)
            && valid_sha256_digest(&self.digest)
            && valid_lower_hex(&self.commit_digest, &[40, 64])
    }
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryIntent {
    handoff_id: String,
    handoff_secret_file: PathBuf,
    stage: IntentStage,
    workflow: GuardedWorkflow,
    environment: String,
    host: String,
    artifact: ArtifactEvidence,
    #[serde(default)]
    update_restart_job_id: Option<String>,
    #[serde(default)]
    deployment_handoff_id: Option<String>,
}

impl DeliveryIntent {
    fn valid_shape(&self) -> bool {
        valid_handoff_id(&self.handoff_id)
            && valid_symbol(&self.environment)
            && valid_host(&self.host)
            && self.artifact.valid()
            && match self.stage {
                IntentStage::Deployment => {
                    self.workflow == GuardedWorkflow::DeployProduction
                        && self
                            .update_restart_job_id
                            .as_deref()
                            .is_some_and(valid_action_id)
                        && self.deployment_handoff_id.is_none()
                }
                IntentStage::Verification => {
                    self.workflow == GuardedWorkflow::VerifyProduction
                        && self.update_restart_job_id.is_none()
                        && self
                            .deployment_handoff_id
                            .as_deref()
                            .is_some_and(valid_handoff_id)
                }
            }
    }

    fn binding_digest(&self, paimos_origin: &Url) -> Result<String, AdapterError> {
        #[derive(Serialize)]
        struct IntentBinding<'a> {
            domain: &'static str,
            paimos_origin: &'a str,
            handoff_id: &'a str,
            stage: &'static str,
            workflow: &'static str,
            environment: &'a str,
            host: &'a str,
            artifact: &'a ArtifactEvidence,
            update_restart_job_id: Option<&'a str>,
            deployment_handoff_id: Option<&'a str>,
        }

        let binding = IntentBinding {
            domain: INTENT_BINDING_DOMAIN,
            paimos_origin: paimos_origin.as_str(),
            handoff_id: &self.handoff_id,
            stage: self.stage.key(),
            workflow: self.workflow.key(),
            environment: &self.environment,
            host: &self.host,
            artifact: &self.artifact,
            update_restart_job_id: self.update_restart_job_id.as_deref(),
            deployment_handoff_id: self.deployment_handoff_id.as_deref(),
        };
        let bytes = serde_json::to_vec(&binding).map_err(|_| AdapterError::Contract)?;
        Ok(hex_digest(&bytes))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema: String,
    schema_version: u16,
    paimos_origin: String,
    api_key_file: PathBuf,
    poll_interval_secs: u64,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntent>,
}

struct AdapterConfig {
    paimos_origin: Url,
    api_key_file: PathBuf,
    poll_interval: Duration,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntent>,
}

impl AdapterConfig {
    fn load(path: &Path) -> Result<Self, AdapterError> {
        let (bytes, _) = read_private_file(path, MAX_CONFIG_BYTES, None)?;
        let document: ConfigDocument =
            serde_json::from_slice(&bytes).map_err(|_| AdapterError::Configuration)?;
        if document.schema != CONFIG_SCHEMA
            || document.schema_version != PAIMOS_SCHEMA_MAJOR
            || !(5..=3600).contains(&document.poll_interval_secs)
            || !(30..=900).contains(&document.verification_freshness_secs)
            || document.intents.is_empty()
            || document.intents.len() > MAX_INTENTS
            || document.intents.iter().any(|intent| !intent.valid_shape())
        {
            return Err(AdapterError::Configuration);
        }
        let paimos_origin = parse_origin(&document.paimos_origin)?;
        let (mut api_key, api_identity) =
            read_private_file(&document.api_key_file, MAX_API_KEY_BYTES, None)?;
        let api_key_valid =
            api_key.len() >= 32 && api_key.iter().all(|byte| (0x21..=0x7e).contains(byte));
        api_key.fill(0);
        if !api_key_valid {
            return Err(AdapterError::Credential);
        }
        let mut handoff_ids = BTreeSet::new();
        let mut credential_files = BTreeSet::new();
        credential_files.insert(api_identity);
        for intent in &document.intents {
            if !handoff_ids.insert(intent.handoff_id.clone()) {
                return Err(AdapterError::Configuration);
            }
            let (mut secret, identity) = read_private_file(
                &intent.handoff_secret_file,
                HANDOFF_SECRET_BYTES as u64,
                Some(HANDOFF_SECRET_BYTES),
            )?;
            secret.fill(0);
            if !credential_files.insert(identity) {
                return Err(AdapterError::Credential);
            }
        }
        for intent in document
            .intents
            .iter()
            .filter(|intent| intent.stage == IntentStage::Verification)
        {
            let deployment = document.intents.iter().find(|candidate| {
                Some(candidate.handoff_id.as_str()) == intent.deployment_handoff_id.as_deref()
                    && candidate.stage == IntentStage::Deployment
            });
            if deployment.is_none_or(|deployment| {
                deployment.handoff_id == intent.handoff_id
                    || deployment.host != intent.host
                    || deployment.environment != intent.environment
                    || deployment.artifact != intent.artifact
            }) {
                return Err(AdapterError::Configuration);
            }
        }
        Ok(Self {
            paimos_origin,
            api_key_file: document.api_key_file,
            poll_interval: Duration::from_secs(document.poll_interval_secs),
            verification_freshness_secs: document.verification_freshness_secs,
            intents: document.intents,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HandoffState {
    Issued,
    Accepted,
    Active,
    Waiting,
    Blocked,
    Succeeded,
    Failed,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum EvidenceKind {
    Deployment,
    Verification,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PullResponse {
    handoff_id: String,
    contract_major: u16,
    fixture_digest: String,
    credential_epoch: i64,
    expires_at: String,
    state: HandoffState,
    reporter_class: String,
    reporter_role: String,
    #[serde(default)]
    dependency_key: Option<String>,
    evidence_ceiling: Vec<EvidenceKind>,
    stage_key: String,
    execution_number: i64,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    context_digest: String,
}

impl PullResponse {
    fn validate(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let unique_ceiling: BTreeSet<_> = self
            .evidence_ceiling
            .iter()
            .map(|kind| match kind {
                EvidenceKind::Deployment => "deployment",
                EvidenceKind::Verification => "verification",
            })
            .collect();
        if self.handoff_id != intent.handoff_id
            || self.contract_major != PAIMOS_SCHEMA_MAJOR
            || self.fixture_digest != PAIMOS_FIXTURE_DIGEST
            || self.credential_epoch < 1
            || parse_timestamp(&self.expires_at).is_err()
            || self.reporter_class != "pharos"
            || self.reporter_role != "owner"
            || self.dependency_key.is_some()
            || unique_ceiling.len() != self.evidence_ceiling.len()
            || self.evidence_ceiling.is_empty()
            || self.evidence_ceiling.len() > 2
            || !self
                .evidence_ceiling
                .contains(&intent.stage.evidence_kind())
            || self.stage_key != intent.stage.key()
            || self.execution_number < 1
            || self.authority_epoch < 1
            || !valid_sha256_digest(&self.plan_digest)
            || !valid_sha256_digest(&self.predecessor_digest)
            || !valid_sha256_digest(&self.context_digest)
        {
            return Err(AdapterError::Contract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AcceptRequest {
    sequence: i64,
    observed_at: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceResult {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct PharosEvidence {
    kind: EvidenceKind,
    workflow: String,
    environment: String,
    artifact: ArtifactEvidence,
    result: EvidenceResult,
    observed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReportRequest {
    sequence: i64,
    state: HandoffState,
    observed_at: String,
    heartbeat: bool,
    pharos_evidence: PharosEvidence,
}

impl ReportRequest {
    fn validate(&self) -> bool {
        self.sequence == 2
            && !self.heartbeat
            && parse_timestamp(&self.observed_at).is_ok()
            && self.pharos_evidence.observed_at == self.observed_at
            && self.pharos_evidence.artifact.valid()
            && valid_symbol(&self.pharos_evidence.workflow)
            && valid_symbol(&self.pharos_evidence.environment)
            && matches!(
                (self.state, self.pharos_evidence.result),
                (HandoffState::Succeeded, EvidenceResult::Succeeded)
                    | (HandoffState::Failed, EvidenceResult::Failed)
            )
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ReportReceipt {
    handoff_id: String,
    sequence: i64,
    state: HandoffState,
    credential_epoch: i64,
    duplicate: bool,
    server_received_at: String,
}

impl ReportReceipt {
    fn validate(
        &self,
        handoff_id: &str,
        sequence: i64,
        expected_state: HandoffState,
    ) -> Result<(), AdapterError> {
        if self.handoff_id != handoff_id
            || self.sequence != sequence
            || self.state != expected_state
            || self.credential_epoch < 1
            || parse_timestamp(&self.server_received_at).is_err()
        {
            return Err(AdapterError::Contract);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum JournalRequestKind {
    Accept,
    Report,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct JournalRecord {
    handoff_id: String,
    intent_digest: String,
    sequence: i64,
    request_kind: JournalRequestKind,
    request_digest: String,
    idempotency_key: String,
    body_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<ReportReceipt>,
}

impl JournalRecord {
    fn new(
        intent: &DeliveryIntent,
        paimos_origin: &Url,
        sequence: i64,
        request_kind: JournalRequestKind,
        body: &[u8],
    ) -> Result<Self, AdapterError> {
        let request_digest = hex_digest(body);
        Ok(Self {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(paimos_origin)?,
            sequence,
            request_kind,
            idempotency_key: idempotency_key(&intent.handoff_id, sequence, &request_digest),
            request_digest,
            body_json: String::from_utf8(body.to_vec()).map_err(|_| AdapterError::Contract)?,
            receipt: None,
        })
    }

    fn key(&self) -> String {
        format!("{}:{}", self.handoff_id, self.sequence)
    }

    fn expected_state(&self) -> Result<HandoffState, AdapterError> {
        match self.request_kind {
            JournalRequestKind::Accept => {
                let body: AcceptRequest = decode_strict(self.body_json.as_bytes())?;
                if body.sequence != 1 || parse_timestamp(&body.observed_at).is_err() {
                    return Err(AdapterError::Journal);
                }
                Ok(HandoffState::Accepted)
            }
            JournalRequestKind::Report => {
                let body: ReportRequest = decode_strict(self.body_json.as_bytes())?;
                if !body.validate() {
                    return Err(AdapterError::Journal);
                }
                Ok(body.state)
            }
        }
    }

    fn valid(&self) -> bool {
        self.sequence
            == match self.request_kind {
                JournalRequestKind::Accept => 1,
                JournalRequestKind::Report => 2,
            }
            && valid_handoff_id(&self.handoff_id)
            && valid_lower_hex(&self.intent_digest, &[64])
            && self.request_digest == hex_digest(self.body_json.as_bytes())
            && self.idempotency_key
                == idempotency_key(&self.handoff_id, self.sequence, &self.request_digest)
            && self.expected_state().is_ok()
            && self.receipt.as_ref().is_none_or(|receipt| {
                self.expected_state().is_ok_and(|state| {
                    receipt
                        .validate(&self.handoff_id, self.sequence, state)
                        .is_ok()
                })
            })
    }

    fn bound_to(&self, intent: &DeliveryIntent, paimos_origin: &Url) -> bool {
        self.handoff_id == intent.handoff_id
            && intent
                .binding_digest(paimos_origin)
                .is_ok_and(|digest| digest == self.intent_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDocument {
    schema: String,
    schema_version: u16,
    records: BTreeMap<String, JournalRecord>,
}

impl Default for JournalDocument {
    fn default() -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            schema_version: 1,
            records: BTreeMap::new(),
        }
    }
}

struct JournalStore {
    path: PathBuf,
    document: Mutex<JournalDocument>,
}

impl JournalStore {
    fn new(path: PathBuf) -> Result<Self, AdapterError> {
        let document = if path.exists() {
            let (bytes, _) = read_private_file(&path, MAX_CONFIG_BYTES, None)?;
            decode_strict::<JournalDocument>(&bytes).map_err(|_| AdapterError::Journal)?
        } else {
            JournalDocument::default()
        };
        if document.schema != JOURNAL_SCHEMA
            || document.schema_version != 1
            || document.records.len() > MAX_JOURNAL_RECORDS
            || document
                .records
                .iter()
                .any(|(key, record)| key != &record.key() || !record.valid())
        {
            return Err(AdapterError::Journal);
        }
        Ok(Self {
            path,
            document: Mutex::new(document),
        })
    }

    fn pending_for(&self, handoff_id: &str) -> Option<JournalRecord> {
        self.document
            .lock()
            .expect("Paimos delivery journal lock")
            .records
            .values()
            .find(|record| record.handoff_id == handoff_id && record.receipt.is_none())
            .cloned()
    }

    fn assert_bound(
        &self,
        intent: &DeliveryIntent,
        paimos_origin: &Url,
    ) -> Result<(), AdapterError> {
        let document = self.document.lock().expect("Paimos delivery journal lock");
        if document
            .records
            .values()
            .filter(|record| record.handoff_id == intent.handoff_id)
            .any(|record| !record.bound_to(intent, paimos_origin))
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    fn ensure(&self, record: JournalRecord) -> Result<JournalRecord, AdapterError> {
        if !record.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        if let Some(existing) = document.records.get(&record.key()) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(AdapterError::Journal)
            };
        }
        if document.records.len() >= MAX_JOURNAL_RECORDS {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated.records.insert(record.key(), record.clone());
        match atomic_write_json(&self.path, &updated) {
            Ok(()) => {
                *document = updated;
                Ok(record)
            }
            Err(error) if error.final_file_replaced() => {
                *document = updated;
                Err(AdapterError::Journal)
            }
            Err(_) => Err(AdapterError::Journal),
        }
    }

    fn acknowledge(
        &self,
        record: &JournalRecord,
        receipt: ReportReceipt,
    ) -> Result<(), AdapterError> {
        let expected_state = record.expected_state()?;
        receipt.validate(&record.handoff_id, record.sequence, expected_state)?;
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        let existing = document
            .records
            .get(&record.key())
            .ok_or(AdapterError::Journal)?;
        if existing.receipt.as_ref() == Some(&receipt) {
            return Ok(());
        }
        if existing.receipt.is_some() || existing.body_json != record.body_json {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated
            .records
            .get_mut(&record.key())
            .expect("journal record remains present")
            .receipt = Some(receipt);
        match atomic_write_json(&self.path, &updated) {
            Ok(()) => {
                *document = updated;
                Ok(())
            }
            Err(error) if error.final_file_replaced() => {
                *document = updated;
                Err(AdapterError::Journal)
            }
            Err(_) => Err(AdapterError::Journal),
        }
    }

    fn receipt(&self, handoff_id: &str, sequence: i64) -> Option<ReportReceipt> {
        self.document
            .lock()
            .expect("Paimos delivery journal lock")
            .records
            .get(&format!("{handoff_id}:{sequence}"))
            .and_then(|record| record.receipt.clone())
    }

    fn report(&self, handoff_id: &str) -> Option<ReportRequest> {
        let document = self.document.lock().expect("Paimos delivery journal lock");
        let record = document.records.get(&format!("{handoff_id}:2"))?;
        decode_strict(record.body_json.as_bytes()).ok()
    }
}

struct Credentials {
    api_key: Vec<u8>,
    handoff_secret: Vec<u8>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.api_key.fill(0);
        self.handoff_secret.fill(0);
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

struct PaimosClient {
    origin: Url,
    api_key_file: PathBuf,
    client: reqwest::Client,
}

impl PaimosClient {
    fn new(origin: Url, api_key_file: PathBuf) -> Result<Self, AdapterError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|_| AdapterError::Configuration)?;
        Ok(Self {
            origin,
            api_key_file,
            client,
        })
    }

    async fn pull(&self, intent: &DeliveryIntent) -> Result<PullResponse, AdapterError> {
        let credentials = self.credentials(intent)?;
        let response = self
            .request(
                Method::GET,
                &format!("/api/external-stage/handoffs/{}", intent.handoff_id),
                None,
                None,
                &credentials,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(AdapterError::Refused(response.status()));
        }
        self.decode_response(response, &credentials, None).await
    }

    async fn mutate(
        &self,
        intent: &DeliveryIntent,
        record: &JournalRecord,
    ) -> Result<ReportReceipt, AdapterError> {
        let credentials = self.credentials(intent)?;
        let suffix = match record.request_kind {
            JournalRequestKind::Accept => "accept",
            JournalRequestKind::Report => "reports",
        };
        let response = self
            .request(
                Method::POST,
                &format!(
                    "/api/external-stage/handoffs/{}/{suffix}",
                    intent.handoff_id
                ),
                Some(record.body_json.as_bytes()),
                Some(&record.idempotency_key),
                &credentials,
            )
            .await?;
        let status = response.status();
        if status != StatusCode::CREATED && status != StatusCode::OK {
            return Err(AdapterError::Refused(status));
        }
        let receipt: ReportReceipt = self
            .decode_response(response, &credentials, Some(&record.idempotency_key))
            .await?;
        receipt.validate(
            &record.handoff_id,
            record.sequence,
            record.expected_state()?,
        )?;
        if !receipt_status_valid(status, receipt.duplicate) {
            return Err(AdapterError::Contract);
        }
        Ok(receipt)
    }

    async fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        idempotency_key: Option<&str>,
        credentials: &Credentials,
    ) -> Result<reqwest::Response, AdapterError> {
        let url = self.origin.join(path).map_err(|_| AdapterError::Contract)?;
        let mut authorization = Vec::with_capacity(7 + credentials.api_key.len());
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(&credentials.api_key);
        let mut authorization_value =
            HeaderValue::from_bytes(&authorization).map_err(|_| AdapterError::Credential)?;
        authorization_value.set_sensitive(true);
        authorization.fill(0);
        let mut encoded_secret = URL_SAFE_NO_PAD
            .encode(&credentials.handoff_secret)
            .into_bytes();
        let mut secret_value = match HeaderValue::from_bytes(&encoded_secret) {
            Ok(value) => value,
            Err(_) => {
                encoded_secret.fill(0);
                return Err(AdapterError::Credential);
            }
        };
        encoded_secret.fill(0);
        secret_value.set_sensitive(true);
        let mut builder = self
            .client
            .request(method, url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ACCEPT, CONTRACT_MEDIA_TYPE)
            .header(ACCEPT_ENCODING, IDENTITY_ENCODING)
            .header(AUTHORIZATION, authorization_value)
            .header(HANDOFF_SECRET_HEADER, secret_value);
        if let Some(idempotency_key) = idempotency_key {
            builder = builder.header(IDEMPOTENCY_HEADER, idempotency_key);
        }
        if let Some(body) = body {
            builder = builder
                .header(CONTENT_TYPE, CONTRACT_MEDIA_TYPE)
                .body(body.to_vec());
        }
        builder.send().await.map_err(|_| AdapterError::Transport)
    }

    async fn decode_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
        credentials: &Credentials,
        idempotency_key: Option<&str>,
    ) -> Result<T, AdapterError> {
        if !response_media_valid(response.headers()) {
            return Err(AdapterError::Contract);
        }
        reject_reflected_headers(
            response.headers(),
            credentials,
            idempotency_key.unwrap_or_default(),
        )?;
        let bytes = bounded_body(response).await?;
        reject_reflected_bytes(&bytes, credentials, idempotency_key.unwrap_or_default())?;
        decode_strict(&bytes)
    }

    fn credentials(&self, intent: &DeliveryIntent) -> Result<Credentials, AdapterError> {
        let (mut api_key, api_identity) =
            read_private_file(&self.api_key_file, MAX_API_KEY_BYTES, None)?;
        if api_key.len() < 32 || !api_key.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
            api_key.fill(0);
            return Err(AdapterError::Credential);
        }
        let (mut handoff_secret, handoff_identity) = match read_private_file(
            &intent.handoff_secret_file,
            HANDOFF_SECRET_BYTES as u64,
            Some(HANDOFF_SECRET_BYTES),
        ) {
            Ok(value) => value,
            Err(error) => {
                api_key.fill(0);
                return Err(error);
            }
        };
        if api_identity == handoff_identity {
            api_key.fill(0);
            handoff_secret.fill(0);
            return Err(AdapterError::Credential);
        }
        Ok(Credentials {
            api_key,
            handoff_secret,
        })
    }
}

pub(crate) struct PaimosDeliveryAdapter {
    config: AdapterConfig,
    journal: JournalStore,
    paimos: PaimosClient,
    hosts: Arc<Store>,
    host_actions: Arc<HostActionStore>,
}

impl PaimosDeliveryAdapter {
    pub(crate) fn from_env(
        host_store_path: Option<&Path>,
        hosts: Arc<Store>,
        host_actions: Arc<HostActionStore>,
    ) -> Result<Option<Self>, String> {
        let Some(config_path) = std::env::var("PHAROS_PAIMOS_DELIVERY_CONFIG_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let host_store_path = host_store_path.ok_or_else(|| {
            "PHAROS_PAIMOS_DELIVERY_CONFIG_FILE requires PHAROS_DB for its durable journal"
                .to_string()
        })?;
        let config = AdapterConfig::load(Path::new(&config_path))
            .map_err(|error| format!("Paimos delivery adapter startup failed: {error}"))?;
        let journal_path = derived_journal_path(host_store_path);
        let journal = JournalStore::new(journal_path)
            .map_err(|error| format!("Paimos delivery adapter startup failed: {error}"))?;
        let paimos = PaimosClient::new(config.paimos_origin.clone(), config.api_key_file.clone())
            .map_err(|error| format!("Paimos delivery adapter startup failed: {error}"))?;
        tracing::info!(
            paimos_release = PAIMOS_RELEASE,
            paimos_commit = PAIMOS_CERTIFIED_COMMIT,
            schema_major = PAIMOS_SCHEMA_MAJOR,
            fixture_digest = PAIMOS_FIXTURE_DIGEST,
            "Paimos reporter-only delivery adapter enabled"
        );
        Ok(Some(Self {
            config,
            journal,
            paimos,
            hosts,
            host_actions,
        }))
    }

    pub(crate) fn spawn(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(self) {
        let mut interval = tokio::time::interval(self.config.poll_interval);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            for intent in &self.config.intents {
                if let Err(error) = self.process_intent(intent).await {
                    tracing::warn!(
                        handoff_id = %intent.handoff_id,
                        reason = error.code(),
                        "Paimos delivery observation was not reported"
                    );
                }
            }
        }
    }

    async fn process_intent(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        self.journal
            .assert_bound(intent, &self.config.paimos_origin)?;
        if let Some(pending) = self.journal.pending_for(&intent.handoff_id) {
            return self.replay(intent, pending).await;
        }
        let pull = self.paimos.pull(intent).await?;
        pull.validate(intent)?;
        match pull.state {
            HandoffState::Issued => {
                if self.journal.receipt(&intent.handoff_id, 1).is_some() {
                    return Err(AdapterError::Contract);
                }
                let request = AcceptRequest {
                    sequence: 1,
                    observed_at: format_timestamp(now_unix())?,
                };
                self.send_new(intent, JournalRequestKind::Accept, &request)
                    .await
            }
            HandoffState::Accepted => {
                if self.journal.receipt(&intent.handoff_id, 1).is_none() {
                    return Err(AdapterError::LocalBinding);
                }
                let Some(request) = self.local_terminal_report(intent, now_unix())? else {
                    return Ok(());
                };
                self.send_new(intent, JournalRequestKind::Report, &request)
                    .await
            }
            HandoffState::Succeeded | HandoffState::Failed => {
                let receipt = self
                    .journal
                    .receipt(&intent.handoff_id, 2)
                    .ok_or(AdapterError::LocalBinding)?;
                let report = self
                    .journal
                    .report(&intent.handoff_id)
                    .ok_or(AdapterError::Journal)?;
                if receipt.state != pull.state || report.state != pull.state {
                    return Err(AdapterError::Contract);
                }
                Ok(())
            }
            HandoffState::Active | HandoffState::Waiting | HandoffState::Blocked => {
                Err(AdapterError::Contract)
            }
        }
    }

    async fn send_new<T: Serialize>(
        &self,
        intent: &DeliveryIntent,
        kind: JournalRequestKind,
        request: &T,
    ) -> Result<(), AdapterError> {
        let body = serde_json::to_vec(request).map_err(|_| AdapterError::Contract)?;
        let sequence = match kind {
            JournalRequestKind::Accept => 1,
            JournalRequestKind::Report => 2,
        };
        let record = self.journal.ensure(JournalRecord::new(
            intent,
            &self.config.paimos_origin,
            sequence,
            kind,
            &body,
        )?)?;
        self.replay(intent, record).await
    }

    async fn replay(
        &self,
        intent: &DeliveryIntent,
        record: JournalRecord,
    ) -> Result<(), AdapterError> {
        if !record.bound_to(intent, &self.config.paimos_origin) || !record.valid() {
            return Err(AdapterError::Journal);
        }
        let receipt = self.paimos.mutate(intent, &record).await?;
        self.journal.acknowledge(&record, receipt)
    }

    fn local_terminal_report(
        &self,
        intent: &DeliveryIntent,
        now: i64,
    ) -> Result<Option<ReportRequest>, AdapterError> {
        match intent.stage {
            IntentStage::Deployment => self.deployment_report(intent, now),
            IntentStage::Verification => self.verification_report(intent, now),
        }
    }

    fn deployment_report(
        &self,
        intent: &DeliveryIntent,
        now: i64,
    ) -> Result<Option<ReportRequest>, AdapterError> {
        let job_id = intent
            .update_restart_job_id
            .as_deref()
            .ok_or(AdapterError::LocalBinding)?;
        let Some(job) = self.host_actions.get(job_id) else {
            return Ok(None);
        };
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        match job.state {
            HostActionState::Failed | HostActionState::Cancelled => {
                Ok(Some(terminal_report(intent, job.updated_at, false)?))
            }
            HostActionState::Succeeded => {
                if job.confirmed_at.is_none() || job.result.is_none() {
                    return Err(AdapterError::LocalBinding);
                }
                let Some(observed_at) = self.matching_fresh_beacon(intent, job.updated_at, now)?
                else {
                    return Ok(None);
                };
                Ok(Some(terminal_report(intent, observed_at, true)?))
            }
            _ => Ok(None),
        }
    }

    fn verification_report(
        &self,
        intent: &DeliveryIntent,
        now: i64,
    ) -> Result<Option<ReportRequest>, AdapterError> {
        let deployment_handoff = intent
            .deployment_handoff_id
            .as_deref()
            .ok_or(AdapterError::LocalBinding)?;
        let deployment_intent = self
            .config
            .intents
            .iter()
            .find(|candidate| {
                candidate.handoff_id == deployment_handoff
                    && candidate.stage == IntentStage::Deployment
            })
            .ok_or(AdapterError::LocalBinding)?;
        self.journal
            .assert_bound(deployment_intent, &self.config.paimos_origin)?;
        let Some(receipt) = self.journal.receipt(deployment_handoff, 2) else {
            return Ok(None);
        };
        let Some(report) = self.journal.report(deployment_handoff) else {
            return Err(AdapterError::Journal);
        };
        if receipt.state != HandoffState::Succeeded
            || report.state != HandoffState::Succeeded
            || report.pharos_evidence.kind != EvidenceKind::Deployment
            || report.pharos_evidence.environment != intent.environment
            || report.pharos_evidence.artifact != intent.artifact
        {
            return Err(AdapterError::LocalBinding);
        }
        let deployment_received_at = parse_timestamp(&receipt.server_received_at)?;
        let Some(observed_at) =
            self.matching_fresh_beacon(intent, deployment_received_at.unix_timestamp(), now)?
        else {
            return Ok(None);
        };
        Ok(Some(terminal_report(intent, observed_at, true)?))
    }

    fn matching_fresh_beacon(
        &self,
        intent: &DeliveryIntent,
        strictly_after: i64,
        now: i64,
    ) -> Result<Option<i64>, AdapterError> {
        let Some(host) = self.hosts.get(&intent.host) else {
            return Ok(None);
        };
        let Some(observed_at) = host.last_seen else {
            return Ok(None);
        };
        let Some(evidence) = host.freshness.deployment_evidence else {
            return Ok(None);
        };
        if evidence.source_revision != intent.artifact.commit_digest
            || format!("sha256:{}", evidence.flake_lock_sha256) != intent.artifact.digest
        {
            return Err(AdapterError::LocalBinding);
        }
        if observed_at <= strictly_after
            || observed_at > now.saturating_add(120)
            || now.saturating_sub(observed_at) > self.config.verification_freshness_secs
        {
            return Ok(None);
        }
        Ok(Some(observed_at))
    }
}

fn terminal_report(
    intent: &DeliveryIntent,
    observed_at: i64,
    succeeded: bool,
) -> Result<ReportRequest, AdapterError> {
    let observed_at = format_timestamp(observed_at)?;
    let (state, result) = if succeeded {
        (HandoffState::Succeeded, EvidenceResult::Succeeded)
    } else {
        (HandoffState::Failed, EvidenceResult::Failed)
    };
    let report = ReportRequest {
        sequence: 2,
        state,
        observed_at: observed_at.clone(),
        heartbeat: false,
        pharos_evidence: PharosEvidence {
            kind: intent.stage.evidence_kind(),
            workflow: intent.workflow.key().to_string(),
            environment: intent.environment.clone(),
            artifact: intent.artifact.clone(),
            result,
            observed_at,
        },
    };
    if !report.validate() {
        return Err(AdapterError::Contract);
    }
    Ok(report)
}

async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, AdapterError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(AdapterError::Contract);
    }
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| AdapterError::Transport)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(AdapterError::Contract);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn reject_reflected_headers(
    headers: &HeaderMap,
    credentials: &Credentials,
    idempotency_key: &str,
) -> Result<(), AdapterError> {
    for value in headers.values() {
        let bytes = value.as_bytes();
        if contains_credentials(bytes, credentials, idempotency_key) {
            return Err(AdapterError::Contract);
        }
    }
    Ok(())
}

fn reject_reflected_bytes(
    bytes: &[u8],
    credentials: &Credentials,
    idempotency_key: &str,
) -> Result<(), AdapterError> {
    if contains_credentials(bytes, credentials, idempotency_key) {
        return Err(AdapterError::Contract);
    }
    Ok(())
}

fn contains_credentials(bytes: &[u8], credentials: &Credentials, idempotency_key: &str) -> bool {
    let mut encoded_secret = URL_SAFE_NO_PAD
        .encode(&credentials.handoff_secret)
        .into_bytes();
    let contains = contains_slice(bytes, &credentials.api_key)
        || contains_slice(bytes, &credentials.handoff_secret)
        || contains_slice(bytes, &encoded_secret)
        || (!idempotency_key.is_empty() && contains_slice(bytes, idempotency_key.as_bytes()));
    encoded_secret.fill(0);
    contains
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn read_private_file(
    path: &Path,
    max_bytes: u64,
    exact_bytes: Option<usize>,
) -> Result<(Vec<u8>, FileIdentity), AdapterError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| AdapterError::Credential)?;
    let before = private_file_metadata(&file, max_bytes, exact_bytes)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| AdapterError::Credential)?;
    let after = private_file_metadata(&file, max_bytes, exact_bytes)?;
    if before != after || bytes.len() as u64 > max_bytes {
        bytes.fill(0);
        return Err(AdapterError::Credential);
    }
    if exact_bytes.is_some_and(|expected| bytes.len() != expected) {
        bytes.fill(0);
        return Err(AdapterError::Credential);
    }
    Ok((bytes, before))
}

fn private_file_metadata(
    file: &File,
    max_bytes: u64,
    exact_bytes: Option<usize>,
) -> Result<FileIdentity, AdapterError> {
    let metadata = file.metadata().map_err(|_| AdapterError::Credential)?;
    if !metadata.is_file()
        || metadata.len() == 0
        || metadata.len() > max_bytes
        || exact_bytes.is_some_and(|expected| metadata.len() != expected as u64)
    {
        return Err(AdapterError::Credential);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.permissions().mode() & 0o077 != 0
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.nlink() != 1
        {
            return Err(AdapterError::Credential);
        }
        Ok(FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity {
            device: 0,
            inode: metadata.len(),
        })
    }
}

fn parse_origin(value: &str) -> Result<Url, AdapterError> {
    let url = Url::parse(value).map_err(|_| AdapterError::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err(AdapterError::Configuration);
    }
    Ok(url)
}

/// The only place cleartext loopback HTTP is reachable. It is `#[cfg(test)]`,
/// so it is compiled out of every shipped binary: the production entry points
/// (`from_env` -> `AdapterConfig::load`) can reach only `parse_origin`, which
/// requires HTTPS.
#[cfg(test)]
fn loopback_origin_for_tests(value: &str) -> Url {
    let url = Url::parse(value).expect("test loopback origin parses");
    assert_eq!(url.scheme(), "http", "test origin is cleartext loopback");
    match url.host() {
        Some(url::Host::Ipv4(address)) => assert!(address.is_loopback()),
        Some(url::Host::Ipv6(address)) => assert!(address.is_loopback()),
        Some(url::Host::Domain("localhost")) => {}
        _ => panic!("test origin must be a loopback host"),
    }
    assert!(
        matches!(parse_origin(value), Err(AdapterError::Configuration)),
        "production parsing must still refuse this origin"
    );
    url
}

/// Exactly one canonical `Content-Type` and no `Content-Encoding` at all. The
/// request side pins `Accept-Encoding: identity`, and the HTTP client is built
/// without any decompression feature, so an encoded body reaches this check
/// with its header intact instead of being transparently decoded away.
fn response_media_valid(headers: &HeaderMap) -> bool {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    content_types.next().and_then(|value| value.to_str().ok()) == Some(CONTRACT_MEDIA_TYPE)
        && content_types.next().is_none()
        && !headers.contains_key(CONTENT_ENCODING)
}

fn receipt_status_valid(status: StatusCode, duplicate: bool) -> bool {
    matches!(
        (status, duplicate),
        (StatusCode::CREATED, false) | (StatusCode::OK, true)
    )
}

fn derived_journal_path(host_store_path: &Path) -> PathBuf {
    let file_name = host_store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("pharos.json");
    host_store_path.with_file_name(format!("{file_name}.paimos-delivery-journal.json"))
}

fn decode_strict<T: for<'de> Deserialize<'de>>(bytes: &[u8]) -> Result<T, AdapterError> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let value = T::deserialize(&mut deserializer).map_err(|_| AdapterError::Contract)?;
    deserializer.end().map_err(|_| AdapterError::Contract)?;
    Ok(value)
}

fn idempotency_key(handoff_id: &str, sequence: i64, request_digest: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(IDEMPOTENCY_DOMAIN);
    digest.update(handoff_id.as_bytes());
    digest.update([0]);
    digest.update(sequence.to_string().as_bytes());
    digest.update([0]);
    digest.update(request_digest.as_bytes());
    let mut bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .expect("SHA-256 prefix has fixed width");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{}-{}-{}-{}-{}",
        hex_bytes(&bytes[0..4]),
        hex_bytes(&bytes[4..6]),
        hex_bytes(&bytes[6..8]),
        hex_bytes(&bytes[8..10]),
        hex_bytes(&bytes[10..16])
    )
}

fn hex_digest(bytes: &[u8]) -> String {
    hex_bytes(&Sha256::digest(bytes))
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

fn parse_timestamp(value: &str) -> Result<OffsetDateTime, AdapterError> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|_| AdapterError::Contract)
}

fn format_timestamp(unix_seconds: i64) -> Result<String, AdapterError> {
    OffsetDateTime::from_unix_timestamp(unix_seconds)
        .map_err(|_| AdapterError::Contract)?
        .format(&Rfc3339)
        .map_err(|_| AdapterError::Contract)
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn valid_handoff_id(value: &str) -> bool {
    value.len() == 26
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'A'..=b'H' | b'J'..=b'N' | b'P'..=b'T' | b'V'..=b'Z'))
}

fn valid_symbol(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
}

fn valid_version(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphanumeric()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'+' | b'-'))
}

fn valid_sha256_digest(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|digest| valid_lower_hex(digest, &[64]))
}

fn valid_lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_host(value: &str) -> bool {
    (1..=63).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

fn valid_action_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

    use axum::body::{to_bytes, Body};
    use axum::extract::State;
    use axum::http::{Request, Response};
    use axum::Router;
    use pharos_core::{
        HostReport, NixDeploymentEvidence, NixFreshness, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION,
        NIX_DEPLOYMENT_EVIDENCE_SCHEMA, NIX_DEPLOYMENT_EVIDENCE_VERSION,
    };
    use serde_json::{json, Value};

    use crate::host_actions::{
        AgentActionOutcome, AgentActionPhase, AgentActionResultRequest, HostActionPlan,
        HostActionResult,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const DEPLOYMENT_HANDOFF: &str = "01K3A000000000000000000001";
    const VERIFICATION_HANDOFF: &str = "01K3A000000000000000000002";
    const API_KEY_SENTINEL: &[u8] = b"PAIMOS_API_KEY_SENTINEL_1234567890";
    const HANDOFF_SENTINEL: &[u8; 32] = b"HANDOFF_SECRET_SENTINEL_12345678";

    fn temporary_directory(label: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pharos-paimos-delivery-{label}-{}-{}",
            std::process::id(),
            TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&path).expect("temporary test directory");
        path
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).expect("write private test file");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .expect("secure private test file");
        }
    }

    fn artifact() -> ArtifactEvidence {
        ArtifactEvidence {
            version: "1.2.3".to_string(),
            digest: format!("sha256:{}", "1".repeat(64)),
            commit_digest: "a".repeat(40),
        }
    }

    fn intent(handoff_id: &str, secret_path: PathBuf, stage: IntentStage) -> DeliveryIntent {
        DeliveryIntent {
            handoff_id: handoff_id.to_string(),
            handoff_secret_file: secret_path,
            stage,
            workflow: match stage {
                IntentStage::Deployment => GuardedWorkflow::DeployProduction,
                IntentStage::Verification => GuardedWorkflow::VerifyProduction,
            },
            environment: "production-eu1".to_string(),
            host: "hsb8".to_string(),
            artifact: artifact(),
            update_restart_job_id: (stage == IntentStage::Deployment)
                .then(|| "action-update-restart-hsb8-placeholder".to_string()),
            deployment_handoff_id: (stage == IntentStage::Verification)
                .then(|| DEPLOYMENT_HANDOFF.to_string()),
        }
    }

    fn config(origin: Url, api_key_file: PathBuf, intents: Vec<DeliveryIntent>) -> AdapterConfig {
        AdapterConfig {
            paimos_origin: origin,
            api_key_file,
            poll_interval: Duration::from_secs(5),
            verification_freshness_secs: 300,
            intents,
        }
    }

    fn completed_update(store: &HostActionStore, now: i64) -> String {
        let job = store
            .create_update_review("hsb8", "operator", now - 40)
            .expect("create guarded update");
        let review = store
            .claim("hsb8", now - 39)
            .expect("claim review")
            .expect("review lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: review.phase,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(HostActionPlan {
                        changed_file_count: 2,
                        changed_areas: vec!["flake.lock".to_string()],
                        all_host_eval_passed: true,
                        target_build_passed: true,
                        backup_ready: true,
                        running_kernel: Some("6.18.1".to_string()),
                        expected_kernel: Some("6.18.2".to_string()),
                        restart_required: true,
                    }),
                    result: None,
                },
                now - 38,
            )
            .expect("record review");
        store
            .confirm_update(&job.id, "hsb8", "operator", now - 37)
            .expect("confirm guarded update");
        let apply = store
            .claim("hsb8", now - 36)
            .expect("claim apply")
            .expect("apply lease");
        assert_eq!(apply.phase, AgentActionPhase::Apply);
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: apply.phase,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: None,
                    result: Some(HostActionResult {
                        backup_validated: true,
                        switch_passed: true,
                        reboot_observed: true,
                        kernel_verified: true,
                        rollback_available: true,
                        failure_gate: None,
                        recovery_mode: None,
                    }),
                },
                now - 30,
            )
            .expect("record guarded update result");
        job.id
    }

    fn record_beacon(store: &Store, observed_at: i64, artifact: &ArtifactEvidence) {
        let source_revision = artifact.commit_digest.clone();
        let flake_lock_sha256 = artifact
            .digest
            .strip_prefix("sha256:")
            .expect("test digest prefix")
            .to_string();
        store
            .record(
                HostReport {
                    schema: HOST_REPORT_SCHEMA.to_string(),
                    version: HOST_REPORT_VERSION,
                    name: "hsb8".to_string(),
                    role: "server".to_string(),
                    is_nix: true,
                    heartbeat_interval_secs: 60,
                    freshness: NixFreshness {
                        applicable: true,
                        nixpkgs_channel: Some("nixos-unstable".to_string()),
                        deployment_evidence: Some(NixDeploymentEvidence {
                            schema: NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
                            version: NIX_DEPLOYMENT_EVIDENCE_VERSION,
                            source_revision,
                            flake_lock_sha256,
                            nixpkgs_revision: "b".repeat(40),
                            nixpkgs_last_modified: observed_at - 100,
                            nixpkgs_channel: "nixos-unstable".to_string(),
                        }),
                        ..Default::default()
                    },
                    kernel: None,
                    service_observations: vec![],
                    backup_observations: vec![],
                    inbound_rtt_ms: None,
                    location: None,
                    preferences: Default::default(),
                },
                observed_at,
            )
            .expect("record test beacon");
    }

    #[derive(Clone, Debug)]
    struct CapturedRequest {
        method: String,
        path: String,
        authorization: String,
        handoff_secret: String,
        idempotency_key: String,
        content_type: String,
        accept: String,
        body: Vec<u8>,
    }

    #[derive(Clone)]
    struct FakePaimos {
        states: Arc<Mutex<BTreeMap<String, HandoffState>>>,
        captures: Arc<Mutex<Vec<CapturedRequest>>>,
        refuse_next_mutation: Arc<AtomicBool>,
        deployment_received_at: String,
    }

    impl FakePaimos {
        fn new(now: i64) -> Self {
            Self {
                states: Arc::new(Mutex::new(BTreeMap::from([
                    (DEPLOYMENT_HANDOFF.to_string(), HandoffState::Issued),
                    (VERIFICATION_HANDOFF.to_string(), HandoffState::Issued),
                ]))),
                captures: Arc::new(Mutex::new(Vec::new())),
                refuse_next_mutation: Arc::new(AtomicBool::new(false)),
                deployment_received_at: format_timestamp(now - 15).unwrap(),
            }
        }
    }

    async fn fake_paimos_handler(
        State(fake): State<FakePaimos>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), MAX_RESPONSE_BYTES)
            .await
            .expect("capture fake request")
            .to_vec();
        fake.captures
            .lock()
            .expect("capture lock")
            .push(CapturedRequest {
                method: method.clone(),
                path: path.clone(),
                authorization: header_text(&headers, AUTHORIZATION.as_str()),
                handoff_secret: header_text(&headers, HANDOFF_SECRET_HEADER),
                idempotency_key: header_text(&headers, IDEMPOTENCY_HEADER),
                content_type: header_text(&headers, CONTENT_TYPE.as_str()),
                accept: header_text(&headers, ACCEPT.as_str()),
                body: body.clone(),
            });
        let handoff_id = path
            .split('/')
            .nth(4)
            .expect("fake handoff id in fixed route")
            .to_string();
        if method == "GET" {
            let state = fake
                .states
                .lock()
                .expect("fake states")
                .get(&handoff_id)
                .copied()
                .unwrap_or(HandoffState::Issued);
            let stage = if handoff_id == VERIFICATION_HANDOFF {
                "verification"
            } else {
                "deployment"
            };
            return fake_json_response(
                StatusCode::OK,
                json!({
                    "handoff_id": handoff_id,
                    "contract_major": 1,
                    "fixture_digest": PAIMOS_FIXTURE_DIGEST,
                    "credential_epoch": 9,
                    "expires_at": "2030-01-01T00:00:00Z",
                    "state": state,
                    "reporter_class": "pharos",
                    "reporter_role": "owner",
                    "evidence_ceiling": ["deployment", "verification"],
                    "stage_key": stage,
                    "execution_number": 1,
                    "plan_digest": format!("sha256:{}", "2".repeat(64)),
                    "predecessor_digest": format!("sha256:{}", "3".repeat(64)),
                    "authority_epoch": 4,
                    "context_digest": format!("sha256:{}", "4".repeat(64))
                }),
            );
        }
        if fake.refuse_next_mutation.swap(false, Ordering::SeqCst) {
            return fake_json_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({"error":"reporter unavailable"}),
            );
        }
        let value: Value = serde_json::from_slice(&body).expect("strict adapter JSON");
        let sequence = value["sequence"].as_i64().expect("request sequence");
        let state = if sequence == 1 {
            HandoffState::Accepted
        } else if value["state"] == "failed" {
            HandoffState::Failed
        } else {
            HandoffState::Succeeded
        };
        fake.states
            .lock()
            .expect("fake states")
            .insert(handoff_id.clone(), state);
        fake_json_response(
            StatusCode::CREATED,
            json!({
                "handoff_id": handoff_id,
                "sequence": sequence,
                "state": state,
                "credential_epoch": 9,
                "duplicate": false,
                "server_received_at": fake.deployment_received_at
            }),
        )
    }

    fn header_text(headers: &HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    fn fake_json_response(status: StatusCode, value: Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, CONTRACT_MEDIA_TYPE)
            .body(Body::from(serde_json::to_vec(&value).unwrap()))
            .unwrap()
    }

    async fn serve_fake(fake: FakePaimos) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Paimos");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(fake_paimos_handler).with_state(fake),
            )
            .await
            .unwrap();
        });
        (
            loopback_origin_for_tests(&format!("http://127.0.0.1:{}", address.port())),
            task,
        )
    }

    fn test_adapter(
        config: AdapterConfig,
        journal_path: PathBuf,
        hosts: Arc<Store>,
        actions: Arc<HostActionStore>,
    ) -> PaimosDeliveryAdapter {
        let journal = JournalStore::new(journal_path).expect("test journal");
        let paimos = PaimosClient::new(config.paimos_origin.clone(), config.api_key_file.clone())
            .expect("test Paimos client");
        PaimosDeliveryAdapter {
            config,
            journal,
            paimos,
            hosts,
            host_actions: actions,
        }
    }

    #[test]
    fn released_contract_pins_and_fixture_bytes_are_exact() {
        let dependency =
            include_bytes!("../../../contracts/paimos-external-stage-v1/dependency-janus-v1.json");
        let owner =
            include_bytes!("../../../contracts/paimos-external-stage-v1/owner-pharos-v1.json");
        let manifest =
            include_bytes!("../../../contracts/paimos-external-stage-v1/manifest-v1.json");
        assert_eq!(dependency.len(), 1115);
        assert_eq!(owner.len(), 1504);
        assert_eq!(
            hex_digest(dependency),
            "52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b"
        );
        assert_eq!(
            hex_digest(owner),
            "8ab2ab9df3f5e12cf225a83d77129bdcab14241bc2a5ab03505811a556e016fc"
        );
        assert_eq!(
            hex_digest(manifest),
            "6aaad204b9e086e49eb0c7c10681ae334819c8d06faf621c68df16bde9ecef87"
        );
        let mut set = Sha256::new();
        set.update(b"paimos.external-stage.fixtures.v1\0");
        for (name, bytes) in [
            ("dependency-janus-v1.json", dependency.as_slice()),
            ("owner-pharos-v1.json", owner.as_slice()),
        ] {
            set.update(name.as_bytes());
            set.update([0]);
            set.update(bytes);
            set.update([0]);
        }
        assert_eq!(
            format!("sha256:{}", hex_bytes(&set.finalize())),
            PAIMOS_FIXTURE_DIGEST
        );
        let manifest: Value = decode_strict(manifest).unwrap();
        assert_eq!(manifest["schema_major"], PAIMOS_SCHEMA_MAJOR);
        assert_eq!(manifest["paimos_release"], PAIMOS_RELEASE);
        assert_eq!(manifest["paimos_commit"], PAIMOS_CERTIFIED_COMMIT);
        assert_eq!(manifest["fixture_digest"], PAIMOS_FIXTURE_DIGEST);
    }

    #[test]
    fn idempotency_uses_handoff_sequence_and_request_digest_not_epoch() {
        let digest = hex_digest(br#"{"sequence":1,"observed_at":"2026-08-20T10:00:00Z"}"#);
        let first = idempotency_key(DEPLOYMENT_HANDOFF, 1, &digest);
        let after_credential_rotation = idempotency_key(DEPLOYMENT_HANDOFF, 1, &digest);
        assert_eq!(first, after_credential_rotation);
        assert_ne!(first, idempotency_key(DEPLOYMENT_HANDOFF, 2, &digest));
        assert_ne!(
            first,
            idempotency_key(DEPLOYMENT_HANDOFF, 1, &hex_digest(b"different"))
        );
        assert_eq!(first.len(), 36);
        assert_eq!(&first[14..15], "5");
    }

    #[test]
    fn production_origin_and_response_semantics_fail_closed() {
        assert!(parse_origin("https://paimos.example.test").is_ok());
        for origin in [
            "http://localhost",
            "http://127.0.0.1",
            "http://[::1]",
            "http://paimos.example.test",
        ] {
            assert!(matches!(
                parse_origin(origin),
                Err(AdapterError::Configuration)
            ));
        }

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CONTRACT_MEDIA_TYPE));
        assert!(response_media_valid(&headers));

        headers.append(CONTENT_TYPE, HeaderValue::from_static(CONTRACT_MEDIA_TYPE));
        assert!(!response_media_valid(&headers));
        headers.remove(CONTENT_TYPE);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CONTRACT_MEDIA_TYPE));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!response_media_valid(&headers));

        assert!(receipt_status_valid(StatusCode::CREATED, false));
        assert!(receipt_status_valid(StatusCode::OK, true));
        assert!(!receipt_status_valid(StatusCode::CREATED, true));
        assert!(!receipt_status_valid(StatusCode::OK, false));
    }

    #[test]
    fn journal_binding_covers_every_non_secret_authority_selector() {
        let origin = Url::parse("https://paimos.example.test").unwrap();
        let base = intent(
            DEPLOYMENT_HANDOFF,
            PathBuf::from("/run/credentials/handoff-secret"),
            IntentStage::Deployment,
        );
        let base_digest = base.binding_digest(&origin).unwrap();

        let mut variants = Vec::new();
        let mut changed = base.clone();
        changed.handoff_id = VERIFICATION_HANDOFF.to_string();
        variants.push(changed);
        let mut changed = base.clone();
        changed.stage = IntentStage::Verification;
        variants.push(changed);
        let mut changed = base.clone();
        changed.workflow = GuardedWorkflow::VerifyProduction;
        variants.push(changed);
        let mut changed = base.clone();
        changed.environment = "production-eu2".to_string();
        variants.push(changed);
        let mut changed = base.clone();
        changed.host = "hsb9".to_string();
        variants.push(changed);
        let mut changed = base.clone();
        changed.artifact.version = "1.2.4".to_string();
        variants.push(changed);
        let mut changed = base.clone();
        changed.artifact.digest = format!("sha256:{}", "2".repeat(64));
        variants.push(changed);
        let mut changed = base.clone();
        changed.artifact.commit_digest = "b".repeat(40);
        variants.push(changed);
        let mut changed = base.clone();
        changed.update_restart_job_id = Some("action-update-restart-hsb9".to_string());
        variants.push(changed);
        let mut changed = base.clone();
        changed.deployment_handoff_id = Some(VERIFICATION_HANDOFF.to_string());
        variants.push(changed);

        for changed in variants {
            assert_ne!(changed.binding_digest(&origin).unwrap(), base_digest);
        }
        assert_ne!(
            base.binding_digest(&Url::parse("https://replacement.example.test").unwrap())
                .unwrap(),
            base_digest
        );

        let mut credential_rotation = base.clone();
        credential_rotation.handoff_secret_file =
            PathBuf::from("/run/credentials/rotated-handoff-secret");
        assert_eq!(
            credential_rotation.binding_digest(&origin).unwrap(),
            base_digest
        );
    }

    #[test]
    fn private_separate_credentials_and_config_fail_closed() {
        let directory = temporary_directory("credentials");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        let config_path = directory.join("adapter.json");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        write_private(
            &config_path,
            &serde_json::to_vec(&json!({
                "schema": CONFIG_SCHEMA,
                "schema_version": 1,
                "paimos_origin": "https://paimos.example.test",
                "api_key_file": api_path,
                "poll_interval_secs": 5,
                "verification_freshness_secs": 300,
                "intents": [{
                    "handoff_id": DEPLOYMENT_HANDOFF,
                    "handoff_secret_file": secret_path,
                    "stage": "deployment",
                    "workflow": "deploy-production",
                    "environment": "production-eu1",
                    "host": "hsb8",
                    "artifact": artifact(),
                    "update_restart_job_id": "action-update-restart-hsb8-placeholder"
                }]
            }))
            .unwrap(),
        );
        assert!(AdapterConfig::load(&config_path).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(matches!(
                AdapterConfig::load(&config_path),
                Err(AdapterError::Credential)
            ));
        }
    }

    #[test]
    fn journal_contains_exact_safe_request_but_no_credentials() {
        let directory = temporary_directory("sentinel-journal");
        let journal_path = directory.join("journal.json");
        let secret_path = directory.join("handoff-secret");
        let journal = JournalStore::new(journal_path.clone()).unwrap();
        let body = serde_json::to_vec(&AcceptRequest {
            sequence: 1,
            observed_at: "2026-08-20T10:00:00Z".to_string(),
        })
        .unwrap();
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        journal
            .ensure(
                JournalRecord::new(
                    &deployment,
                    &Url::parse("https://paimos.example.test").unwrap(),
                    1,
                    JournalRequestKind::Accept,
                    &body,
                )
                .unwrap(),
            )
            .unwrap();
        let durable = std::fs::read(&journal_path).unwrap();
        assert!(!contains_slice(&durable, API_KEY_SENTINEL));
        assert!(!contains_slice(&durable, HANDOFF_SENTINEL));
        assert!(!contains_slice(
            &durable,
            URL_SAFE_NO_PAD.encode(HANDOFF_SENTINEL).as_bytes()
        ));
        let reloaded = JournalStore::new(journal_path).unwrap();
        assert_eq!(
            reloaded
                .pending_for(DEPLOYMENT_HANDOFF)
                .unwrap()
                .body_json
                .as_bytes(),
            body
        );
    }

    #[tokio::test]
    async fn fake_paimos_conformance_reports_accept_then_terminal_without_heartbeat() {
        let now = now_unix();
        let directory = temporary_directory("conformance");
        let api_path = directory.join("api-key");
        let deployment_secret = directory.join("deployment-secret");
        let verification_secret = directory.join("verification-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&deployment_secret, HANDOFF_SENTINEL);
        write_private(&verification_secret, &[8; HANDOFF_SECRET_BYTES]);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 20, &artifact());
        let mut deployment = intent(
            DEPLOYMENT_HANDOFF,
            deployment_secret,
            IntentStage::Deployment,
        );
        deployment.update_restart_job_id = Some(job_id);
        let verification = intent(
            VERIFICATION_HANDOFF,
            verification_secret,
            IntentStage::Verification,
        );
        let intents = vec![deployment, verification];
        let adapter = test_adapter(
            config(origin, api_path, intents.clone()),
            directory.join("journal.json"),
            hosts.clone(),
            actions,
        );

        adapter.process_intent(&intents[0]).await.unwrap();
        adapter.process_intent(&intents[0]).await.unwrap();
        adapter.process_intent(&intents[1]).await.unwrap();
        // The deployment receipt is newer than the only beacon, so verification
        // remains accepted and unreported until a later beacon arrives.
        adapter.process_intent(&intents[1]).await.unwrap();
        let before_fresh_beacon = fake
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.method == "POST")
            .count();
        assert_eq!(before_fresh_beacon, 3);
        record_beacon(&hosts, now - 5, &artifact());
        adapter.process_intent(&intents[1]).await.unwrap();

        let captures = fake.captures.lock().unwrap().clone();
        let posts: Vec<_> = captures
            .iter()
            .filter(|capture| capture.method == "POST")
            .collect();
        assert_eq!(posts.len(), 4);
        for capture in &captures {
            assert_eq!(capture.accept, CONTRACT_MEDIA_TYPE);
            assert_eq!(
                capture.authorization,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY_SENTINEL))
            );
            assert!(!capture
                .path
                .contains(&String::from_utf8_lossy(API_KEY_SENTINEL).to_string()));
            assert!(!contains_slice(&capture.body, API_KEY_SENTINEL));
            assert!(!contains_slice(&capture.body, HANDOFF_SENTINEL));
        }
        for capture in &posts {
            assert_eq!(capture.content_type, CONTRACT_MEDIA_TYPE);
            assert_eq!(capture.idempotency_key.len(), 36);
        }
        let bodies: Vec<Value> = posts
            .iter()
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .collect();
        assert_eq!(bodies[0]["sequence"], 1);
        assert_eq!(bodies[1]["sequence"], 2);
        assert_eq!(bodies[1]["state"], "succeeded");
        assert_eq!(bodies[1]["heartbeat"], false);
        assert_eq!(bodies[1]["pharos_evidence"]["kind"], "deployment");
        assert_eq!(bodies[2]["sequence"], 1);
        assert_eq!(bodies[3]["sequence"], 2);
        assert_eq!(bodies[3]["heartbeat"], false);
        assert_eq!(bodies[3]["pharos_evidence"]["kind"], "verification");
        assert_eq!(
            bodies[1]["pharos_evidence"]["artifact"],
            bodies[3]["pharos_evidence"]["artifact"]
        );
        assert_eq!(
            bodies[1]["pharos_evidence"]["environment"],
            bodies[3]["pharos_evidence"]["environment"]
        );
        assert!(bodies.iter().all(|body| body["state"] != "active"));
        assert!(posts[0].handoff_secret != posts[2].handoff_secret);
        server.abort();
    }

    #[tokio::test]
    async fn crash_before_receipt_replays_exact_journaled_request() {
        let now = now_unix();
        let directory = temporary_directory("crash-replay");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        let journal_path = directory.join("journal.json");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        fake.refuse_next_mutation.store(true, Ordering::SeqCst);
        let (origin, server) = serve_fake(fake.clone()).await;
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let make_adapter = || {
            test_adapter(
                config(origin.clone(), api_path.clone(), vec![deployment.clone()]),
                journal_path.clone(),
                Arc::new(Store::new(None).unwrap()),
                Arc::new(HostActionStore::new(None)),
            )
        };
        assert!(matches!(
            make_adapter().process_intent(&deployment).await,
            Err(AdapterError::Refused(StatusCode::SERVICE_UNAVAILABLE))
        ));
        let captures_before_drift = fake.captures.lock().unwrap().len();

        let replacement_fake = FakePaimos::new(now);
        let (replacement_origin, replacement_server) = serve_fake(replacement_fake.clone()).await;
        let replacement_adapter = test_adapter(
            config(
                replacement_origin,
                api_path.clone(),
                vec![deployment.clone()],
            ),
            journal_path.clone(),
            Arc::new(Store::new(None).unwrap()),
            Arc::new(HostActionStore::new(None)),
        );
        assert!(matches!(
            replacement_adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert!(replacement_fake.captures.lock().unwrap().is_empty());

        let mut changed_intent = deployment.clone();
        changed_intent.environment = "production-eu2".to_string();
        let changed_adapter = test_adapter(
            config(
                origin.clone(),
                api_path.clone(),
                vec![changed_intent.clone()],
            ),
            journal_path.clone(),
            Arc::new(Store::new(None).unwrap()),
            Arc::new(HostActionStore::new(None)),
        );
        assert!(matches!(
            changed_adapter.process_intent(&changed_intent).await,
            Err(AdapterError::LocalBinding)
        ));
        assert_eq!(fake.captures.lock().unwrap().len(), captures_before_drift);

        let rotated_api_key = [b'K'; 40];
        let rotated_handoff_secret = [b'S'; HANDOFF_SECRET_BYTES];
        write_private(&api_path, &rotated_api_key);
        write_private(&deployment.handoff_secret_file, &rotated_handoff_secret);
        // A fresh adapter instance models a process restart. It sends the
        // journaled request before another pull, preserves exact bytes/key,
        // and deliberately uses the newly rotated credentials.
        make_adapter().process_intent(&deployment).await.unwrap();
        let captures = fake.captures.lock().unwrap().clone();
        let posts: Vec<_> = captures
            .iter()
            .filter(|capture| capture.method == "POST")
            .collect();
        assert_eq!(posts.len(), 2);
        assert_eq!(posts[0].path, posts[1].path);
        assert_eq!(posts[0].body, posts[1].body);
        assert_eq!(posts[0].idempotency_key, posts[1].idempotency_key);
        assert_ne!(posts[0].authorization, posts[1].authorization);
        assert_ne!(posts[0].handoff_secret, posts[1].handoff_secret);
        assert_eq!(
            posts[1].authorization,
            format!("Bearer {}", String::from_utf8_lossy(&rotated_api_key))
        );
        assert_eq!(
            posts[1].handoff_secret,
            URL_SAFE_NO_PAD.encode(rotated_handoff_secret)
        );
        assert_eq!(
            captures
                .iter()
                .filter(|capture| capture.method == "GET")
                .count(),
            1
        );
        replacement_server.abort();
        server.abort();
    }

    /// A Paimos impersonator that answers the accept mutation with a response
    /// shape the contract forbids. Every field here is something a compromised
    /// or buggy peer controls.
    #[derive(Clone)]
    struct WireAbuse {
        status: StatusCode,
        content_types: Vec<String>,
        content_encoding: Option<String>,
        duplicate: bool,
    }

    impl WireAbuse {
        fn canonical() -> Self {
            Self {
                status: StatusCode::CREATED,
                content_types: vec![CONTRACT_MEDIA_TYPE.to_string()],
                content_encoding: None,
                duplicate: false,
            }
        }

        fn media(content_types: &[&str]) -> Self {
            Self {
                content_types: content_types
                    .iter()
                    .map(|value| value.to_string())
                    .collect(),
                ..Self::canonical()
            }
        }

        fn encoding(value: &str) -> Self {
            Self {
                content_encoding: Some(value.to_string()),
                ..Self::canonical()
            }
        }

        fn receipt(status: StatusCode, duplicate: bool) -> Self {
            Self {
                status,
                duplicate,
                ..Self::canonical()
            }
        }
    }

    async fn wire_abuse_handler(
        State(abuse): State<WireAbuse>,
        request: Request<Body>,
    ) -> Response<Body> {
        let method = request.method().to_string();
        let handoff_id = request
            .uri()
            .path()
            .split('/')
            .nth(4)
            .expect("abusive handoff id in fixed route")
            .to_string();
        if method == "GET" {
            return fake_json_response(
                StatusCode::OK,
                json!({
                    "handoff_id": handoff_id,
                    "contract_major": 1,
                    "fixture_digest": PAIMOS_FIXTURE_DIGEST,
                    "credential_epoch": 9,
                    "expires_at": "2030-01-01T00:00:00Z",
                    "state": HandoffState::Issued,
                    "reporter_class": "pharos",
                    "reporter_role": "owner",
                    "evidence_ceiling": ["deployment"],
                    "stage_key": "deployment",
                    "execution_number": 1,
                    "plan_digest": format!("sha256:{}", "2".repeat(64)),
                    "predecessor_digest": format!("sha256:{}", "3".repeat(64)),
                    "authority_epoch": 4,
                    "context_digest": format!("sha256:{}", "4".repeat(64))
                }),
            );
        }
        let body = serde_json::to_vec(&json!({
            "handoff_id": handoff_id,
            "sequence": 1,
            "state": HandoffState::Accepted,
            "credential_epoch": 9,
            "duplicate": abuse.duplicate,
            "server_received_at": "2026-08-20T10:00:01Z"
        }))
        .expect("abusive receipt body");
        let mut builder = Response::builder().status(abuse.status);
        for content_type in &abuse.content_types {
            builder = builder.header(CONTENT_TYPE, content_type);
        }
        if let Some(encoding) = &abuse.content_encoding {
            builder = builder.header(CONTENT_ENCODING, encoding);
        }
        builder.body(Body::from(body)).expect("abusive response")
    }

    async fn serve_wire_abuse(abuse: WireAbuse) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind abusive Paimos");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(wire_abuse_handler).with_state(abuse),
            )
            .await
            .unwrap();
        });
        (
            loopback_origin_for_tests(&format!("http://127.0.0.1:{}", address.port())),
            task,
        )
    }

    /// Drives one accept mutation against an abusive peer and reports whether
    /// the adapter refused and whether anything reached the durable journal.
    async fn wire_abuse_outcome(abuse: WireAbuse) -> (Result<(), AdapterError>, bool) {
        let directory = temporary_directory("wire-abuse");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let (origin, server) = serve_wire_abuse(abuse).await;
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            directory.join("journal.json"),
            Arc::new(Store::new(None).unwrap()),
            Arc::new(HostActionStore::new(None)),
        );
        let outcome = adapter.process_intent(&deployment).await;
        let journaled = adapter.journal.receipt(DEPLOYMENT_HANDOFF, 1).is_some();
        server.abort();
        (outcome, journaled)
    }

    /// Exercises the real reqwest/hyper path, not just the header predicate, so
    /// a client rebuilt with transparent decompression or a relaxed media check
    /// fails here instead of shipping.
    #[tokio::test]
    async fn wire_level_media_and_receipt_abuse_fails_closed() {
        let charset = format!("{CONTRACT_MEDIA_TYPE}; charset=utf-8");
        let list = format!("{CONTRACT_MEDIA_TYPE}, application/json");
        let refused = vec![
            (
                "duplicate content-type",
                WireAbuse::media(&[CONTRACT_MEDIA_TYPE, CONTRACT_MEDIA_TYPE]),
            ),
            ("parameterised content-type", WireAbuse::media(&[&charset])),
            ("ambiguous content-type list", WireAbuse::media(&[&list])),
            (
                "foreign content-type",
                WireAbuse::media(&["application/json"]),
            ),
            ("absent content-type", WireAbuse::media(&[])),
            ("compressed body", WireAbuse::encoding("gzip")),
            ("identity content-encoding", WireAbuse::encoding("identity")),
            (
                "created claims duplicate",
                WireAbuse::receipt(StatusCode::CREATED, true),
            ),
            (
                "ok denies duplicate",
                WireAbuse::receipt(StatusCode::OK, false),
            ),
        ];
        for (label, abuse) in refused {
            let (outcome, journaled) = wire_abuse_outcome(abuse).await;
            assert!(
                matches!(outcome, Err(AdapterError::Contract)),
                "{label} must fail closed, got {outcome:?}"
            );
            assert!(!journaled, "{label} must not journal a receipt");
        }

        for (label, abuse) in [
            (
                "created for a new receipt",
                WireAbuse::receipt(StatusCode::CREATED, false),
            ),
            (
                "ok for a replayed receipt",
                WireAbuse::receipt(StatusCode::OK, true),
            ),
        ] {
            let (outcome, journaled) = wire_abuse_outcome(abuse).await;
            assert!(outcome.is_ok(), "{label} must be accepted, got {outcome:?}");
            assert!(journaled, "{label} must journal its receipt");
        }
    }

    #[test]
    fn wrong_artifact_and_predeploy_verification_fail_closed() {
        let now = now_unix();
        let directory = temporary_directory("evidence-refusal");
        let api_path = directory.join("api-key");
        let deployment_secret = directory.join("deployment-secret");
        let verification_secret = directory.join("verification-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&deployment_secret, HANDOFF_SENTINEL);
        write_private(&verification_secret, &[8; HANDOFF_SECRET_BYTES]);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        let mut wrong = artifact();
        wrong.commit_digest = "c".repeat(40);
        record_beacon(&hosts, now - 20, &wrong);
        let mut deployment = intent(
            DEPLOYMENT_HANDOFF,
            deployment_secret,
            IntentStage::Deployment,
        );
        deployment.update_restart_job_id = Some(job_id);
        let verification = intent(
            VERIFICATION_HANDOFF,
            verification_secret,
            IntentStage::Verification,
        );
        let adapter = test_adapter(
            config(
                Url::parse("https://paimos.example.test").unwrap(),
                api_path,
                vec![deployment.clone(), verification.clone()],
            ),
            directory.join("journal.json"),
            hosts,
            actions,
        );
        assert!(matches!(
            adapter.deployment_report(&deployment, now),
            Err(AdapterError::LocalBinding)
        ));
        assert!(adapter
            .verification_report(&verification, now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn configuration_rejects_wrong_environment_pairing_and_unknown_fields() {
        let directory = temporary_directory("config-pairing");
        let api_path = directory.join("api-key");
        let deployment_secret = directory.join("deployment-secret");
        let verification_secret = directory.join("verification-secret");
        let config_path = directory.join("adapter.json");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&deployment_secret, HANDOFF_SENTINEL);
        write_private(&verification_secret, &[8; HANDOFF_SECRET_BYTES]);
        let mut document = json!({
            "schema": CONFIG_SCHEMA,
            "schema_version": 1,
            "paimos_origin": "https://paimos.example.test",
            "api_key_file": api_path.clone(),
            "poll_interval_secs": 5,
            "verification_freshness_secs": 300,
            "intents": [
                {
                    "handoff_id": DEPLOYMENT_HANDOFF,
                    "handoff_secret_file": deployment_secret.clone(),
                    "stage": "deployment",
                    "workflow": "deploy-production",
                    "environment": "production-eu1",
                    "host": "hsb8",
                    "artifact": artifact(),
                    "update_restart_job_id": "action-update-restart-hsb8-placeholder"
                },
                {
                    "handoff_id": VERIFICATION_HANDOFF,
                    "handoff_secret_file": verification_secret.clone(),
                    "stage": "verification",
                    "workflow": "verify-production",
                    "environment": "production-us1",
                    "host": "hsb8",
                    "artifact": artifact(),
                    "deployment_handoff_id": DEPLOYMENT_HANDOFF
                }
            ]
        });
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));
        document["intents"][1]["environment"] = json!("production-eu1");
        document["intents"][1]["callback"] = json!("https://attacker.invalid");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document["intents"][1]
            .as_object_mut()
            .expect("intent object")
            .remove("callback");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        AdapterConfig::load(&config_path).expect("repaired document loads");

        // Defect class: cleartext delivery of the handoff secret. The loopback
        // forms the conformance harness uses must stay unreachable from the
        // production document, not merely discouraged.
        for origin in [
            "http://localhost",
            "http://localhost:8080",
            "http://127.0.0.1",
            "http://127.0.0.1:8080",
            "http://[::1]",
            "http://paimos.example.test",
        ] {
            document["paimos_origin"] = json!(origin);
            write_private(&config_path, &serde_json::to_vec(&document).unwrap());
            let loaded = AdapterConfig::load(&config_path);
            assert!(
                matches!(loaded, Err(AdapterError::Configuration)),
                "{origin} must not configure a production reporter"
            );
        }
    }
}
