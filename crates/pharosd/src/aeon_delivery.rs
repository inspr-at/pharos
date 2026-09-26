//! Aeon stage-handoff delivery adapter (PHAROS-313).
//!
//! Selected only by `PHAROS_AEON_DELIVERY_CONFIG_FILE`. Classic Paimos delivery
//! stays on its own config and journal. This adapter reads an Aeon handoff,
//! binds one guarded `UpdateRestart` for a deploy intent, and — when the
//! intent opts into `delegated_launch` — posts launch readiness, checks a
//! one-use admission, consumes it, and only then confirms that same job.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
use crate::host_actions::{
    HostActionJob, HostActionPlan, HostActionState, HostActionStore, HostActionStoreError,
    HostWorkflowKind, UpdateRestartIntent,
};
use crate::paimos_delivery::{
    load_ca_certificates, observed_fresh_config_beacon, read_private_file, reviewed_plan_digest,
    AdapterError as SharedError, ArtifactEvidence,
};
use crate::store::Store;

const CONFIG_SCHEMA: &str = "inspr.pharos.aeon-delivery-adapter.v1";
const CONFIG_SCHEMA_VERSION: u16 = 1;
const JOURNAL_SCHEMA: &str = "inspr.pharos.aeon-delivery-journal.v1";
const JOURNAL_SCHEMA_VERSION: u16 = 1;
const OPERATION_DOMAIN: &str = "inspr.pharos.aeon-delivery-operation.v1";
const INTENT_DOMAIN: &str = "inspr.pharos.aeon-delivery-intent.v1";
const LAUNCH_BINDING_DOMAIN: &[u8] = b"inspr.aeon.launch-binding.v1\0";
const IDEMPOTENCY_DOMAIN: &[u8] = b"inspr.pharos.aeon-delivery-idempotency.v1\0";
const USER_AGENT_VALUE: &str = "pharosd-aeon-delivery/1";
const JSON_MEDIA: &str = "application/json";
const IDENTITY_ENCODING: &str = "identity";
const PLUGIN_ID: &str = "pharos";
const STAGE_DEPLOY: &str = "deploy";
const ACTOR: &str = "aeon-delivery";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_API_KEY_BYTES: u64 = 512;
const MIN_API_KEY_BYTES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_INTENTS: usize = 128;
const MAX_JOURNAL_RECORDS: usize = MAX_INTENTS * 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OBSERVED_AT_SKEW_SECS: i64 = 5 * 60;

#[derive(Debug)]
enum AdapterError {
    Configuration,
    Credential,
    Trust,
    Contract,
    Journal,
    LocalBinding,
    Transport,
    Refused(StatusCode),
    LaunchUnresolved,
}

impl AdapterError {
    fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "configuration_invalid",
            Self::Credential => "credential_unavailable",
            Self::Trust => "trust_configuration_invalid",
            Self::Contract => "contract_refused",
            Self::Journal => "journal_unavailable",
            Self::LocalBinding => "local_binding_refused",
            Self::Transport => "transport_unavailable",
            Self::Refused(_) => "aeon_refused",
            Self::LaunchUnresolved => "launch_consume_unresolved",
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

fn map_shared(error: SharedError) -> AdapterError {
    match error {
        SharedError::Configuration => AdapterError::Configuration,
        SharedError::Credential => AdapterError::Credential,
        SharedError::Trust => AdapterError::Trust,
        SharedError::Contract => AdapterError::Contract,
        SharedError::Journal => AdapterError::Journal,
        SharedError::LocalBinding => AdapterError::LocalBinding,
        SharedError::Transport => AdapterError::Transport,
        SharedError::Refused(status) => AdapterError::Refused(status),
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Operation {
    Deploy,
    Verify,
}

impl Operation {
    fn key(self) -> &'static str {
        match self {
            Self::Deploy => "deploy",
            Self::Verify => "verify",
        }
    }

    fn evidence_kind(self) -> EvidenceKind {
        match self {
            Self::Deploy => EvidenceKind::Deployment,
            Self::Verify => EvidenceKind::Verification,
        }
    }

    fn ceilings_allow(self, delegated_launch: bool, ceiling: &[EvidenceCeiling]) -> bool {
        match self {
            Self::Deploy => {
                ceiling.contains(&EvidenceCeiling::Deployment)
                    && (!delegated_launch || ceiling.contains(&EvidenceCeiling::LaunchReadiness))
            }
            Self::Verify => ceiling.contains(&EvidenceCeiling::Verification),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DelegatedLaunchSelection {
    target_ref: String,
}

impl DelegatedLaunchSelection {
    fn valid(&self) -> bool {
        valid_prefixed_sha256(&self.target_ref)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryIntent {
    handoff_id: String,
    project_node_id: String,
    release_node_id: String,
    operation: Operation,
    workflow: GuardedWorkflow,
    environment: String,
    host: String,
    artifact: ArtifactEvidence,
    #[serde(default)]
    update_restart_job_id: Option<String>,
    #[serde(default)]
    deployment_handoff_id: Option<String>,
    #[serde(default)]
    delegated_launch: Option<DelegatedLaunchSelection>,
}

impl DeliveryIntent {
    fn valid_shape(&self) -> bool {
        valid_uuid(&self.handoff_id)
            && valid_uuid(&self.project_node_id)
            && valid_uuid(&self.release_node_id)
            && valid_symbol(&self.environment)
            && valid_host(&self.host)
            && self.artifact.valid()
            && self.artifact.release_sequence >= 1
            && match self.operation {
                Operation::Deploy => {
                    self.workflow == GuardedWorkflow::DeployProduction
                        && self
                            .update_restart_job_id
                            .as_deref()
                            .is_none_or(valid_action_id)
                        && self.deployment_handoff_id.is_none()
                        && self
                            .delegated_launch
                            .as_ref()
                            .is_none_or(DelegatedLaunchSelection::valid)
                }
                Operation::Verify => {
                    self.workflow == GuardedWorkflow::VerifyProduction
                        && self.update_restart_job_id.is_none()
                        && self.delegated_launch.is_none()
                        && self
                            .deployment_handoff_id
                            .as_deref()
                            .is_some_and(valid_uuid)
                }
            }
    }

    fn binding_digest(&self, origin: &Url) -> Result<String, AdapterError> {
        #[derive(Serialize)]
        struct IntentBinding<'a> {
            domain: &'static str,
            aeon_origin: &'a str,
            handoff_id: &'a str,
            project_node_id: &'a str,
            release_node_id: &'a str,
            operation: &'static str,
            workflow: &'static str,
            environment: &'a str,
            host: &'a str,
            artifact: &'a ArtifactEvidence,
            update_restart_job_id: Option<&'a str>,
            deployment_handoff_id: Option<&'a str>,
            delegated_launch_target_ref: Option<&'a str>,
        }

        let bytes = serde_json::to_vec(&IntentBinding {
            domain: INTENT_DOMAIN,
            aeon_origin: origin.as_str(),
            handoff_id: &self.handoff_id,
            project_node_id: &self.project_node_id,
            release_node_id: &self.release_node_id,
            operation: self.operation.key(),
            workflow: self.workflow.key(),
            environment: &self.environment,
            host: &self.host,
            artifact: &self.artifact,
            update_restart_job_id: self.update_restart_job_id.as_deref(),
            deployment_handoff_id: self.deployment_handoff_id.as_deref(),
            delegated_launch_target_ref: self
                .delegated_launch
                .as_ref()
                .map(|selection| selection.target_ref.as_str()),
        })
        .map_err(|_| AdapterError::Contract)?;
        Ok(hex_digest(&bytes))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocument {
    schema: String,
    schema_version: u16,
    aeon_origin: String,
    api_key_file: PathBuf,
    #[serde(default)]
    aeon_ca_file: Option<PathBuf>,
    poll_interval_secs: u64,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntent>,
}

struct AdapterConfig {
    aeon_origin: Url,
    api_key_file: PathBuf,
    aeon_ca_certificates: Vec<reqwest::Certificate>,
    poll_interval: Duration,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntent>,
}

impl AdapterConfig {
    fn load(path: &Path) -> Result<Self, AdapterError> {
        owner_parent(path, false)?;
        let (bytes, config_identity) =
            read_private_file(path, MAX_CONFIG_BYTES, None).map_err(map_shared)?;
        let document: ConfigDocument =
            decode_strict(&bytes).map_err(|_| AdapterError::Configuration)?;
        if document.schema != CONFIG_SCHEMA || document.schema_version != CONFIG_SCHEMA_VERSION {
            return Err(AdapterError::Configuration);
        }
        if !(5..=3600).contains(&document.poll_interval_secs)
            || !(30..=900).contains(&document.verification_freshness_secs)
            || document.intents.is_empty()
            || document.intents.len() > MAX_INTENTS
            || document.intents.iter().any(|intent| !intent.valid_shape())
        {
            return Err(AdapterError::Configuration);
        }
        let aeon_origin = parse_origin(&document.aeon_origin)?;
        owner_parent(&document.api_key_file, false)?;
        let (mut api_key, api_identity) =
            read_private_file(&document.api_key_file, MAX_API_KEY_BYTES, None)
                .map_err(map_shared)?;
        let api_key_valid = valid_api_key(&api_key);
        api_key.fill(0);
        if !api_key_valid {
            return Err(AdapterError::Credential);
        }
        if config_identity == api_identity {
            return Err(AdapterError::Credential);
        }
        let (aeon_ca_certificates, ca_identity) = match &document.aeon_ca_file {
            Some(ca_path) => {
                owner_parent(ca_path, true)?;
                let (certificates, identity) = load_ca_certificates(ca_path).map_err(map_shared)?;
                if identity == config_identity || identity == api_identity {
                    return Err(AdapterError::Trust);
                }
                (certificates, Some(identity))
            }
            None => (Vec::new(), None),
        };
        let _ = ca_identity;
        let mut handoff_ids = BTreeSet::new();
        for intent in &document.intents {
            if !handoff_ids.insert(intent.handoff_id.clone()) {
                return Err(AdapterError::Configuration);
            }
        }
        for intent in document
            .intents
            .iter()
            .filter(|intent| intent.operation == Operation::Verify)
        {
            let deployment = document.intents.iter().find(|candidate| {
                Some(candidate.handoff_id.as_str()) == intent.deployment_handoff_id.as_deref()
                    && candidate.operation == Operation::Deploy
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
            aeon_origin,
            api_key_file: document.api_key_file,
            aeon_ca_certificates,
            poll_interval: Duration::from_secs(document.poll_interval_secs),
            verification_freshness_secs: document.verification_freshness_secs,
            intents: document.intents,
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HandoffState {
    Requested,
    Active,
    Blocked,
    Succeeded,
    Failed,
    Revoked,
}

impl HandoffState {
    fn key(self) -> &'static str {
        match self {
            Self::Requested => "requested",
            Self::Active => "active",
            Self::Blocked => "blocked",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Revoked => "revoked",
        }
    }

    fn is_open(self) -> bool {
        matches!(self, Self::Requested | Self::Active)
    }

    fn is_closed(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Revoked | Self::Blocked
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceCeiling {
    Deployment,
    Verification,
    Authorization,
    CredentialHandoff,
    LaunchReadiness,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceKind {
    LaunchReadiness,
    Deployment,
    Verification,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum EvidenceOutcome {
    Succeeded,
    Failed,
    Satisfied,
    Blocked,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ResultOutcome {
    Succeeded,
    Failed,
}

impl ResultOutcome {
    fn from_evidence(outcome: EvidenceOutcome) -> Result<Self, AdapterError> {
        match outcome {
            EvidenceOutcome::Succeeded => Ok(Self::Succeeded),
            EvidenceOutcome::Failed => Ok(Self::Failed),
            EvidenceOutcome::Satisfied | EvidenceOutcome::Blocked => Err(AdapterError::Contract),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum BlockerCode {
    DependencyPending,
    DependencyFailed,
    ReporterStale,
    ExternalWaiting,
    PolicyRefused,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct WireArtifact {
    version_scheme: pharos_core::ArtifactVersionScheme,
    version: String,
    release_channel: String,
    release_sequence: i64,
    digest_sha256: String,
    commit_digest: String,
    manifest_coordinate: String,
    manifest_digest_sha256: String,
}

impl WireArtifact {
    fn from_evidence(artifact: &ArtifactEvidence) -> Result<Self, AdapterError> {
        if !artifact.valid() || artifact.release_sequence < 1 {
            return Err(AdapterError::Contract);
        }
        Ok(Self {
            version_scheme: artifact.version_scheme,
            version: artifact.version.clone(),
            release_channel: artifact.release_channel.clone(),
            release_sequence: artifact.release_sequence,
            digest_sha256: strip_sha256(&artifact.digest)?,
            commit_digest: artifact.commit_digest.clone(),
            manifest_coordinate: artifact.release_manifest_coordinate.clone(),
            manifest_digest_sha256: strip_sha256(&artifact.release_manifest_digest)?,
        })
    }

    fn valid(&self) -> bool {
        valid_hex64(&self.digest_sha256)
            && valid_hex64(&self.manifest_digest_sha256)
            && self.release_sequence >= 1
            && valid_lower_hex(&self.commit_digest, &[40, 64])
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HandoffResult {
    outcome: ResultOutcome,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
    #[serde(default)]
    blocker_code: Option<BlockerCode>,
    handoff_id: String,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HandoffDocument {
    id: String,
    project_node_id: String,
    release_node_id: String,
    stage: String,
    operation: Operation,
    plugin_id: String,
    attempt: i64,
    authority_epoch: i64,
    journey_revision: i64,
    state: HandoffState,
    expires_at: String,
    evidence_ceiling: Vec<EvidenceCeiling>,
    plan_digest: String,
    predecessor_digest: String,
    context_digest: String,
    prerequisite_seal_sha256: String,
    #[serde(default)]
    result: Option<HandoffResult>,
}

impl HandoffDocument {
    fn validate(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let unique: BTreeSet<_> = self
            .evidence_ceiling
            .iter()
            .map(|kind| *kind as u8)
            .collect();
        if self.id != intent.handoff_id
            || self.project_node_id != intent.project_node_id
            || self.release_node_id != intent.release_node_id
            || self.stage != STAGE_DEPLOY
            || self.operation != intent.operation
            || self.plugin_id != PLUGIN_ID
            || self.attempt < 1
            || self.authority_epoch < 1
            || self.journey_revision < 0
            || parse_timestamp(&self.expires_at).is_err()
            || unique.len() != self.evidence_ceiling.len()
            || self.evidence_ceiling.is_empty()
            || self.evidence_ceiling.len() > 4
            || !intent
                .operation
                .ceilings_allow(intent.delegated_launch.is_some(), &self.evidence_ceiling)
            || !valid_hex64(&self.plan_digest)
            || !valid_hex64(&self.predecessor_digest)
            || !valid_hex64(&self.context_digest)
            || !valid_hex64(&self.prerequisite_seal_sha256)
        {
            return Err(AdapterError::Contract);
        }
        if let Some(result) = &self.result {
            if result.handoff_id != self.id
                || result.authority_epoch < 1
                || result.terminal_sequence < 1
                || !valid_hex64(&result.prerequisite_seal_sha256)
                || parse_timestamp(&result.completed_at).is_err()
                || (result.outcome == ResultOutcome::Succeeded && result.blocker_code.is_some())
            {
                return Err(AdapterError::Contract);
            }
        }
        Ok(())
    }

    fn open_for_write(&self, now: i64) -> Result<(), AdapterError> {
        if !self.state.is_open() || unix_of(&self.expires_at)? <= now {
            return Err(AdapterError::Contract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
struct EvidenceWrite<'a> {
    sequence: i64,
    kind: EvidenceKind,
    outcome: EvidenceOutcome,
    observed_at: &'a str,
    authority_epoch: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    workflow: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    environment: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    artifact: Option<&'a WireArtifact>,
    #[serde(skip_serializing_if = "Option::is_none")]
    reviewed_plan_digest: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    host: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    all_host_eval_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    target_build_passed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_ready: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    backup_observed_at: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    restart_required: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    running_kernel: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_kernel: Option<&'a str>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceResponse {
    handoff_id: String,
    sequence: i64,
    kind: EvidenceKind,
    outcome: EvidenceOutcome,
    observed_at: String,
    authority_epoch: i64,
    received_at: String,
    #[serde(default)]
    workflow: Option<String>,
    #[serde(default)]
    environment: Option<String>,
    #[serde(default)]
    artifact: Option<WireArtifact>,
    #[serde(default)]
    reviewed_plan_digest: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    all_host_eval_passed: Option<bool>,
    #[serde(default)]
    target_build_passed: Option<bool>,
    #[serde(default)]
    backup_ready: Option<bool>,
    #[serde(default)]
    backup_observed_at: Option<String>,
    #[serde(default)]
    restart_required: Option<bool>,
    #[serde(default)]
    running_kernel: Option<String>,
    #[serde(default)]
    expected_kernel: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceReceipt {
    handoff_id: String,
    sequence: i64,
    kind: EvidenceKind,
    outcome: EvidenceOutcome,
    authority_epoch: i64,
    received_at: String,
}

impl EvidenceReceipt {
    fn from_response(response: &EvidenceResponse) -> Result<Self, AdapterError> {
        parse_timestamp(&response.received_at)?;
        parse_timestamp(&response.observed_at)?;
        Ok(Self {
            handoff_id: response.handoff_id.clone(),
            sequence: response.sequence,
            kind: response.kind,
            outcome: response.outcome,
            authority_epoch: response.authority_epoch,
            received_at: response.received_at.clone(),
        })
    }

    fn matches_request(&self, body: &str, handoff_id: &str) -> bool {
        let Ok(request) = decode_strict::<serde_json::Value>(body.as_bytes()) else {
            return false;
        };
        self.handoff_id == handoff_id
            && request.get("sequence").and_then(serde_json::Value::as_i64) == Some(self.sequence)
            && request.get("kind").and_then(serde_json::Value::as_str) == Some(self.kind_key())
            && request.get("outcome").and_then(serde_json::Value::as_str)
                == Some(self.outcome_key())
            && request
                .get("authority_epoch")
                .and_then(serde_json::Value::as_i64)
                == Some(self.authority_epoch)
            && self.authority_epoch >= 1
            && self.sequence >= 1
    }

    fn kind_key(&self) -> &'static str {
        match self.kind {
            EvidenceKind::LaunchReadiness => "launch_readiness",
            EvidenceKind::Deployment => "deployment",
            EvidenceKind::Verification => "verification",
        }
    }

    fn outcome_key(&self) -> &'static str {
        match self.outcome {
            EvidenceOutcome::Succeeded => "succeeded",
            EvidenceOutcome::Failed => "failed",
            EvidenceOutcome::Satisfied => "satisfied",
            EvidenceOutcome::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchAdmission {
    id: String,
    handoff_id: String,
    binding_digest_sha256: String,
    artifact_digest_sha256: String,
    authority_epoch: i64,
    expires_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consumed_at: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
struct ConsumeRequest<'a> {
    admission_id: &'a str,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsumeResponse {
    handoff_id: String,
    admission_id: String,
    consumed: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsumeReceipt {
    handoff_id: String,
    admission_id: String,
    consumed: bool,
    consumed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultRequest {
    outcome: ResultOutcome,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultResponse {
    outcome: ResultOutcome,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
    #[serde(default)]
    blocker_code: Option<BlockerCode>,
    handoff_id: String,
    completed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultReceipt {
    handoff_id: String,
    outcome: ResultOutcome,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
    completed_at: String,
}

impl ResultReceipt {
    fn from_response(response: &ResultResponse) -> Result<Self, AdapterError> {
        parse_timestamp(&response.completed_at)?;
        if response.terminal_sequence < 1
            || response.authority_epoch < 1
            || !valid_hex64(&response.prerequisite_seal_sha256)
            || (response.outcome == ResultOutcome::Succeeded && response.blocker_code.is_some())
        {
            return Err(AdapterError::Contract);
        }
        Ok(Self {
            handoff_id: response.handoff_id.clone(),
            outcome: response.outcome,
            terminal_sequence: response.terminal_sequence,
            authority_epoch: response.authority_epoch,
            prerequisite_seal_sha256: response.prerequisite_seal_sha256.clone(),
            completed_at: response.completed_at.clone(),
        })
    }

    fn matches_request(&self, body: &str, handoff_id: &str) -> bool {
        let Ok(request) = decode_strict::<ResultRequest>(body.as_bytes()) else {
            return false;
        };
        self.handoff_id == handoff_id
            && request.outcome == self.outcome
            && request.terminal_sequence == self.terminal_sequence
            && request.authority_epoch == self.authority_epoch
            && request.prerequisite_seal_sha256 == self.prerequisite_seal_sha256
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct EvidenceJournalRecord {
    handoff_id: String,
    intent_digest: String,
    sequence: i64,
    kind: EvidenceKind,
    request_digest: String,
    idempotency_key: String,
    body_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<EvidenceReceipt>,
}

impl EvidenceJournalRecord {
    fn new(
        intent: &DeliveryIntent,
        origin: &Url,
        sequence: i64,
        kind: EvidenceKind,
        body: &[u8],
    ) -> Result<Self, AdapterError> {
        if sequence < 1 || body.len() > MAX_RESPONSE_BYTES {
            return Err(AdapterError::Contract);
        }
        let request_digest = hex_digest(body);
        Ok(Self {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(origin)?,
            sequence,
            kind,
            idempotency_key: idempotency_key(&intent.handoff_id, sequence, &request_digest),
            request_digest,
            body_json: String::from_utf8(body.to_vec()).map_err(|_| AdapterError::Contract)?,
            receipt: None,
        })
    }

    fn key(&self) -> String {
        format!("{}:{}", self.handoff_id, self.sequence)
    }

    fn valid(&self) -> bool {
        self.sequence >= 1
            && valid_uuid(&self.handoff_id)
            && valid_hex64(&self.intent_digest)
            && self.request_digest == hex_digest(self.body_json.as_bytes())
            && self.idempotency_key
                == idempotency_key(&self.handoff_id, self.sequence, &self.request_digest)
            && self.body_json.len() <= MAX_RESPONSE_BYTES
            && json_kind_matches(&self.body_json, self.kind, self.sequence)
            && self
                .receipt
                .as_ref()
                .is_none_or(|receipt| receipt.matches_request(&self.body_json, &self.handoff_id))
    }

    fn bound_to(&self, intent: &DeliveryIntent, origin: &Url) -> bool {
        self.handoff_id == intent.handoff_id
            && intent
                .binding_digest(origin)
                .is_ok_and(|digest| digest == self.intent_digest)
    }
}

fn json_kind_matches(body: &str, kind: EvidenceKind, sequence: i64) -> bool {
    let Ok(value) = decode_strict::<serde_json::Value>(body.as_bytes()) else {
        return false;
    };
    let kind_key = match kind {
        EvidenceKind::LaunchReadiness => "launch_readiness",
        EvidenceKind::Deployment => "deployment",
        EvidenceKind::Verification => "verification",
    };
    value.get("sequence").and_then(serde_json::Value::as_i64) == Some(sequence)
        && value.get("kind").and_then(serde_json::Value::as_str) == Some(kind_key)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OperationBinding {
    handoff_id: String,
    job_id: String,
    host: String,
    workflow: String,
    environment: String,
    release_node_id: String,
    artifact: ArtifactEvidence,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    context_digest: String,
    attempt: i64,
    operation_id: String,
}

impl OperationBinding {
    fn valid(&self) -> bool {
        valid_uuid(&self.handoff_id)
            && valid_action_id(&self.job_id)
            && valid_host(&self.host)
            && valid_symbol(&self.workflow)
            && valid_symbol(&self.environment)
            && valid_uuid(&self.release_node_id)
            && self.artifact.valid()
            && valid_hex64(&self.plan_digest)
            && valid_hex64(&self.predecessor_digest)
            && valid_hex64(&self.context_digest)
            && self.authority_epoch >= 1
            && self.attempt >= 1
            && valid_hex64(&self.operation_id)
    }

    fn matches_handoff(&self, handoff: &HandoffDocument) -> bool {
        self.plan_digest == handoff.plan_digest
            && self.predecessor_digest == handoff.predecessor_digest
            && self.authority_epoch == handoff.authority_epoch
            && self.context_digest == handoff.context_digest
            && self.attempt == handoff.attempt
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchJournalRecord {
    handoff_id: String,
    intent_digest: String,
    job_id: String,
    readiness_sequence: i64,
    reviewed_plan_digest: String,
    admit_digest: String,
    admit_idempotency_key: String,
    admit_body_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admission: Option<LaunchAdmission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consume_digest: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consume_idempotency_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consume_body_json: Option<String>,
    #[serde(default)]
    consume_started: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consume_unresolved: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    admit_unresolved: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<ConsumeReceipt>,
}

impl LaunchJournalRecord {
    fn valid(&self) -> bool {
        if !valid_uuid(&self.handoff_id)
            || !valid_action_id(&self.job_id)
            || !valid_hex64(&self.intent_digest)
            || self.readiness_sequence < 1
            || self.reviewed_plan_digest.is_empty()
            || self.admit_digest != hex_digest(self.admit_body_json.as_bytes())
            || self.admit_idempotency_key
                != idempotency_key(
                    &self.handoff_id,
                    self.readiness_sequence,
                    &self.admit_digest,
                )
        {
            return false;
        }
        let Ok(artifact) = decode_strict::<WireArtifact>(self.admit_body_json.as_bytes()) else {
            return false;
        };
        if !artifact.valid() {
            return false;
        }
        let Some(admission) = &self.admission else {
            let admit_marker_ok = match self.admit_unresolved {
                None => true,
                Some(status) => status == StatusCode::CONFLICT.as_u16(),
            };
            return self.consume_digest.is_none()
                && self.consume_idempotency_key.is_none()
                && self.consume_body_json.is_none()
                && !self.consume_started
                && self.consume_unresolved.is_none()
                && self.receipt.is_none()
                && admit_marker_ok;
        };
        if self.admit_unresolved.is_some() {
            return false;
        }
        if !valid_uuid(&admission.id)
            || admission.handoff_id != self.handoff_id
            || !valid_hex64(&admission.binding_digest_sha256)
            || admission.artifact_digest_sha256 != artifact.digest_sha256
            || admission.consumed_at.is_some()
        {
            return false;
        }
        let Some(consume_body) = self.consume_body_json.as_deref() else {
            return false;
        };
        let Some(consume_digest) = self.consume_digest.as_deref() else {
            return false;
        };
        if consume_digest != hex_digest(consume_body.as_bytes())
            || self.consume_idempotency_key.as_deref()
                != Some(
                    idempotency_key(&self.handoff_id, self.readiness_sequence, consume_digest)
                        .as_str(),
                )
        {
            return false;
        }
        if let Some(status) = self.consume_unresolved {
            if status != StatusCode::CONFLICT.as_u16()
                || !self.consume_started
                || self.receipt.is_some()
            {
                return false;
            }
        }
        self.receipt.as_ref().is_none_or(|receipt| {
            self.consume_started
                && self.consume_unresolved.is_none()
                && receipt.consumed
                && receipt.handoff_id == self.handoff_id
                && receipt.admission_id == admission.id
                && parse_timestamp(&receipt.consumed_at).is_ok()
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultJournalRecord {
    handoff_id: String,
    intent_digest: String,
    terminal_sequence: i64,
    request_digest: String,
    idempotency_key: String,
    body_json: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<ResultReceipt>,
}

impl ResultJournalRecord {
    fn new(
        intent: &DeliveryIntent,
        origin: &Url,
        terminal_sequence: i64,
        body: &[u8],
    ) -> Result<Self, AdapterError> {
        let request_digest = hex_digest(body);
        Ok(Self {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(origin)?,
            terminal_sequence,
            idempotency_key: idempotency_key(
                &intent.handoff_id,
                terminal_sequence.saturating_add(1),
                &request_digest,
            ),
            request_digest,
            body_json: String::from_utf8(body.to_vec()).map_err(|_| AdapterError::Contract)?,
            receipt: None,
        })
    }

    fn valid(&self) -> bool {
        self.terminal_sequence >= 1
            && valid_uuid(&self.handoff_id)
            && valid_hex64(&self.intent_digest)
            && self.request_digest == hex_digest(self.body_json.as_bytes())
            && self.idempotency_key
                == idempotency_key(
                    &self.handoff_id,
                    self.terminal_sequence.saturating_add(1),
                    &self.request_digest,
                )
            && decode_strict::<ResultRequest>(self.body_json.as_bytes())
                .is_ok_and(|request| request.terminal_sequence == self.terminal_sequence)
            && self
                .receipt
                .as_ref()
                .is_none_or(|receipt| receipt.matches_request(&self.body_json, &self.handoff_id))
    }

    fn bound_to(&self, intent: &DeliveryIntent, origin: &Url) -> bool {
        self.handoff_id == intent.handoff_id
            && intent
                .binding_digest(origin)
                .is_ok_and(|digest| digest == self.intent_digest)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDocument {
    schema: String,
    schema_version: u16,
    records: BTreeMap<String, EvidenceJournalRecord>,
    #[serde(default)]
    operations: BTreeMap<String, OperationBinding>,
    #[serde(default)]
    launches: BTreeMap<String, LaunchJournalRecord>,
    #[serde(default)]
    results: BTreeMap<String, ResultJournalRecord>,
}

impl Default for JournalDocument {
    fn default() -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            schema_version: JOURNAL_SCHEMA_VERSION,
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
            launches: BTreeMap::new(),
            results: BTreeMap::new(),
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
            let (bytes, _) = read_private_file(&path, MAX_JOURNAL_BYTES, None)
                .map_err(|_| AdapterError::Journal)?;
            decode_strict::<JournalDocument>(&bytes).map_err(|_| AdapterError::Journal)?
        } else {
            JournalDocument::default()
        };
        if !journal_document_valid(&document) {
            return Err(AdapterError::Journal);
        }
        Ok(Self {
            path,
            document: Mutex::new(document),
        })
    }

    fn assert_bound(&self, intent: &DeliveryIntent, origin: &Url) -> Result<(), AdapterError> {
        let document = self.document.lock().expect("Aeon delivery journal lock");
        let records_diverge = document
            .records
            .values()
            .filter(|record| record.handoff_id == intent.handoff_id)
            .any(|record| !record.bound_to(intent, origin));
        let result_diverges = document
            .results
            .get(&intent.handoff_id)
            .is_some_and(|record| !record.bound_to(intent, origin));
        let launch_diverges = document
            .launches
            .get(&intent.handoff_id)
            .is_some_and(|record| {
                record.intent_digest != intent.binding_digest(origin).unwrap_or_default()
            });
        if records_diverge || result_diverges || launch_diverges {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    fn pending_evidence(&self, handoff_id: &str) -> Option<EvidenceJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .records
            .values()
            .filter(|record| record.handoff_id == handoff_id && record.receipt.is_none())
            .min_by_key(|record| record.sequence)
            .cloned()
    }

    fn evidence_with_kind(
        &self,
        handoff_id: &str,
        kind: EvidenceKind,
    ) -> Option<EvidenceJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .records
            .values()
            .find(|record| record.handoff_id == handoff_id && record.kind == kind)
            .cloned()
    }

    fn next_sequence(&self, handoff_id: &str) -> Result<i64, AdapterError> {
        let document = self.document.lock().expect("Aeon delivery journal lock");
        let max = document
            .records
            .values()
            .filter(|record| record.handoff_id == handoff_id)
            .map(|record| record.sequence)
            .max()
            .unwrap_or(0);
        max.checked_add(1)
            .filter(|sequence| *sequence >= 1)
            .ok_or(AdapterError::Journal)
    }

    fn ensure_evidence(
        &self,
        record: EvidenceJournalRecord,
    ) -> Result<EvidenceJournalRecord, AdapterError> {
        if !record.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
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
        persist_journal(&self.path, &mut document, updated)?;
        Ok(record)
    }

    fn acknowledge_evidence(
        &self,
        record: &EvidenceJournalRecord,
        receipt: EvidenceReceipt,
    ) -> Result<(), AdapterError> {
        if !receipt.matches_request(&record.body_json, &record.handoff_id) {
            return Err(AdapterError::Contract);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .records
            .get(&record.key())
            .ok_or(AdapterError::Journal)?;
        if existing.body_json != record.body_json {
            return Err(AdapterError::Journal);
        }
        if existing.receipt.as_ref() == Some(&receipt) {
            return Ok(());
        }
        if existing.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated
            .records
            .get_mut(&record.key())
            .expect("evidence record remains present")
            .receipt = Some(receipt);
        let saved = updated.records.get(&record.key()).expect("saved").clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)
    }

    fn operation(&self, handoff_id: &str) -> Option<OperationBinding> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .operations
            .get(handoff_id)
            .cloned()
    }

    fn retry_predecessor(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<Option<OperationBinding>, AdapterError> {
        if handoff.attempt < 2 {
            return Ok(None);
        }
        let document = self.document.lock().expect("Aeon delivery journal lock");
        let mut matches = document.operations.values().filter(|binding| {
            binding.handoff_id != intent.handoff_id
                && binding.host == intent.host
                && binding.workflow == intent.workflow.key()
                && binding.environment == intent.environment
                && binding.artifact == intent.artifact
                && binding.release_node_id == intent.release_node_id
                && binding.plan_digest == handoff.predecessor_digest
        });
        let predecessor = matches.next().cloned();
        if predecessor.is_some() && matches.next().is_some() {
            return Err(AdapterError::LocalBinding);
        }
        Ok(predecessor)
    }

    fn persist_operation(
        &self,
        binding: OperationBinding,
    ) -> Result<OperationBinding, AdapterError> {
        if !binding.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        if let Some(existing) = document.operations.get(&binding.handoff_id) {
            return if existing == &binding {
                Ok(existing.clone())
            } else {
                Err(AdapterError::LocalBinding)
            };
        }
        if document.operations.len() >= MAX_JOURNAL_RECORDS {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated
            .operations
            .insert(binding.handoff_id.clone(), binding.clone());
        persist_journal(&self.path, &mut document, updated)?;
        Ok(binding)
    }

    fn launch(&self, handoff_id: &str) -> Option<LaunchJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .launches
            .get(handoff_id)
            .cloned()
    }

    fn ensure_launch(
        &self,
        record: LaunchJournalRecord,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if !record.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        if let Some(existing) = document.launches.get(&record.handoff_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(AdapterError::LocalBinding)
            };
        }
        let mut updated = document.clone();
        updated
            .launches
            .insert(record.handoff_id.clone(), record.clone());
        persist_journal(&self.path, &mut document, updated)?;
        Ok(record)
    }

    fn store_admission(
        &self,
        handoff_id: &str,
        admission: LaunchAdmission,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .launches
            .get(handoff_id)
            .ok_or(AdapterError::Journal)?
            .clone();
        if let Some(saved) = &existing.admission {
            return if saved == &admission {
                Ok(existing)
            } else {
                Err(AdapterError::Contract)
            };
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(handoff_id)
            .expect("launch record remains present");
        launch.admission = Some(admission);
        let consume = ConsumeRequest {
            admission_id: launch
                .admission
                .as_ref()
                .expect("admission was stored")
                .id
                .as_str(),
        };
        let consume_body = serde_json::to_vec(&consume).map_err(|_| AdapterError::Contract)?;
        let consume_digest = hex_digest(&consume_body);
        launch.consume_idempotency_key = Some(idempotency_key(
            handoff_id,
            launch.readiness_sequence,
            &consume_digest,
        ));
        launch.consume_digest = Some(consume_digest);
        launch.consume_body_json =
            Some(String::from_utf8(consume_body).map_err(|_| AdapterError::Contract)?);
        let saved = launch.clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn mark_consume_started(&self, handoff_id: &str) -> Result<LaunchJournalRecord, AdapterError> {
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .launches
            .get(handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing.admission.is_none() || existing.consume_body_json.is_none() {
            return Err(AdapterError::Journal);
        }
        if existing.consume_started {
            return Ok(existing.clone());
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(handoff_id)
            .expect("launch record remains present");
        launch.consume_started = true;
        launch.consume_unresolved = None;
        let saved = launch.clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn mark_consume_unresolved(
        &self,
        handoff_id: &str,
        status: StatusCode,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if status != StatusCode::CONFLICT {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .launches
            .get(handoff_id)
            .ok_or(AdapterError::Journal)?
            .clone();
        if !existing.consume_started || existing.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        if existing.consume_unresolved == Some(status.as_u16()) {
            return Ok(existing);
        }
        if existing.consume_unresolved.is_some() {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(handoff_id)
            .expect("launch record remains present");
        launch.consume_unresolved = Some(status.as_u16());
        let saved = launch.clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn mark_admit_unresolved(
        &self,
        handoff_id: &str,
        status: StatusCode,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if status != StatusCode::CONFLICT {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .launches
            .get(handoff_id)
            .ok_or(AdapterError::Journal)?
            .clone();
        if existing.admission.is_some() || existing.consume_started || existing.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        if existing.admit_unresolved == Some(status.as_u16()) {
            return Ok(existing);
        }
        if existing.admit_unresolved.is_some() {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(handoff_id)
            .expect("launch record remains present");
        launch.admit_unresolved = Some(status.as_u16());
        let saved = launch.clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn acknowledge_consume(
        &self,
        handoff_id: &str,
        receipt: ConsumeReceipt,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if !receipt.consumed || parse_timestamp(&receipt.consumed_at).is_err() {
            return Err(AdapterError::Contract);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .launches
            .get(handoff_id)
            .ok_or(AdapterError::Journal)?
            .clone();
        if !existing.consume_started {
            return Err(AdapterError::Journal);
        }
        if let Some(saved) = &existing.receipt {
            return if saved == &receipt {
                Ok(existing)
            } else {
                Err(AdapterError::Contract)
            };
        }
        let admission = existing.admission.as_ref().ok_or(AdapterError::Journal)?;
        if receipt.handoff_id != handoff_id || receipt.admission_id != admission.id {
            return Err(AdapterError::Contract);
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(handoff_id)
            .expect("launch record remains present");
        launch.receipt = Some(receipt);
        let saved = launch.clone();
        if !saved.valid() {
            return Err(AdapterError::Journal);
        }
        persist_journal(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn result(&self, handoff_id: &str) -> Option<ResultJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .results
            .get(handoff_id)
            .cloned()
    }

    fn ensure_result(
        &self,
        record: ResultJournalRecord,
    ) -> Result<ResultJournalRecord, AdapterError> {
        if !record.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        if let Some(existing) = document.results.get(&record.handoff_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(AdapterError::Journal)
            };
        }
        let mut updated = document.clone();
        updated
            .results
            .insert(record.handoff_id.clone(), record.clone());
        persist_journal(&self.path, &mut document, updated)?;
        Ok(record)
    }

    fn replace_unacked_result(
        &self,
        record: ResultJournalRecord,
    ) -> Result<ResultJournalRecord, AdapterError> {
        if !record.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .results
            .get(&record.handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        if existing == &record {
            return Ok(existing.clone());
        }
        let mut updated = document.clone();
        updated
            .results
            .insert(record.handoff_id.clone(), record.clone());
        persist_journal(&self.path, &mut document, updated)?;
        Ok(record)
    }

    fn acknowledge_result(
        &self,
        record: &ResultJournalRecord,
        receipt: ResultReceipt,
    ) -> Result<(), AdapterError> {
        if !receipt.matches_request(&record.body_json, &record.handoff_id) {
            return Err(AdapterError::Contract);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        let existing = document
            .results
            .get(&record.handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing.body_json != record.body_json {
            return Err(AdapterError::Journal);
        }
        if existing.receipt.as_ref() == Some(&receipt) {
            return Ok(());
        }
        if existing.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated
            .results
            .get_mut(&record.handoff_id)
            .expect("result record remains present")
            .receipt = Some(receipt);
        persist_journal(&self.path, &mut document, updated)
    }
}

fn journal_document_valid(document: &JournalDocument) -> bool {
    document.schema == JOURNAL_SCHEMA
        && document.schema_version == JOURNAL_SCHEMA_VERSION
        && document.schema != "inspr.pharos.paimos-delivery-journal.v1"
        && document.records.len() <= MAX_JOURNAL_RECORDS
        && document.operations.len() <= MAX_JOURNAL_RECORDS
        && document.launches.len() <= MAX_INTENTS
        && document.results.len() <= MAX_INTENTS
        && document
            .records
            .iter()
            .all(|(key, record)| key == &record.key() && record.valid())
        && document
            .operations
            .iter()
            .all(|(key, binding)| key == &binding.handoff_id && binding.valid())
        && document
            .launches
            .iter()
            .all(|(key, launch)| key == &launch.handoff_id && launch.valid())
        && document
            .results
            .iter()
            .all(|(key, result)| key == &result.handoff_id && result.valid())
}

fn persist_journal(
    path: &Path,
    document: &mut JournalDocument,
    updated: JournalDocument,
) -> Result<(), AdapterError> {
    if !journal_document_valid(&updated) {
        return Err(AdapterError::Journal);
    }
    match atomic_write_json(path, &updated) {
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

struct Credentials {
    api_key: Vec<u8>,
}

impl Drop for Credentials {
    fn drop(&mut self) {
        self.api_key.fill(0);
    }
}

struct AeonClient {
    origin: Url,
    api_key_file: PathBuf,
    client: reqwest::Client,
}

impl AeonClient {
    fn new(
        origin: Url,
        api_key_file: PathBuf,
        root_certificates: &[reqwest::Certificate],
    ) -> Result<Self, AdapterError> {
        let has_custom_roots = !root_certificates.is_empty();
        let mut builder = reqwest::Client::builder()
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(REQUEST_TIMEOUT);
        for certificate in root_certificates {
            builder = builder.add_root_certificate(certificate.clone());
        }
        let client = builder.build().map_err(|_| {
            if has_custom_roots {
                AdapterError::Trust
            } else {
                AdapterError::Configuration
            }
        })?;
        Ok(Self {
            origin,
            api_key_file,
            client,
        })
    }

    fn credentials(&self) -> Result<Credentials, AdapterError> {
        let (mut api_key, _) =
            read_private_file(&self.api_key_file, MAX_API_KEY_BYTES, None).map_err(map_shared)?;
        if !valid_api_key(&api_key) {
            api_key.fill(0);
            return Err(AdapterError::Credential);
        }
        Ok(Credentials { api_key })
    }

    async fn get_handoff(&self, handoff_id: &str) -> Result<HandoffDocument, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(
                Method::GET,
                &format!("/api/stage-handoffs/{handoff_id}"),
                None,
                None,
                &credentials,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        decode_strict(&bytes)
    }

    async fn post_evidence(
        &self,
        record: &EvidenceJournalRecord,
    ) -> Result<EvidenceReceipt, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(
                Method::POST,
                &format!("/api/stage-handoffs/{}/evidence", record.handoff_id),
                Some(record.body_json.as_bytes()),
                Some(&record.idempotency_key),
                &credentials,
            )
            .await?;
        if status != StatusCode::CREATED {
            return Err(status_error(status));
        }
        let response: EvidenceResponse = decode_strict(&bytes)?;
        let receipt = EvidenceReceipt::from_response(&response)?;
        if !receipt.matches_request(&record.body_json, &record.handoff_id)
            || !evidence_echo_matches(&response, &record.body_json)
        {
            return Err(AdapterError::Contract);
        }
        Ok(receipt)
    }

    async fn post_admit(
        &self,
        record: &LaunchJournalRecord,
    ) -> Result<LaunchAdmission, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(
                Method::POST,
                &format!("/api/stage-handoffs/{}/launch/admit", record.handoff_id),
                Some(record.admit_body_json.as_bytes()),
                Some(&record.admit_idempotency_key),
                &credentials,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        decode_strict(&bytes)
    }

    async fn post_consume(
        &self,
        record: &LaunchJournalRecord,
    ) -> Result<ConsumeResponse, AdapterError> {
        let body = record
            .consume_body_json
            .as_deref()
            .ok_or(AdapterError::Journal)?;
        let idempotency = record
            .consume_idempotency_key
            .as_deref()
            .ok_or(AdapterError::Journal)?;
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(
                Method::POST,
                &format!("/api/stage-handoffs/{}/launch/consume", record.handoff_id),
                Some(body.as_bytes()),
                Some(idempotency),
                &credentials,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        let response: ConsumeResponse = decode_strict(&bytes)?;
        if !response.consumed
            || response.handoff_id != record.handoff_id
            || response.admission_id != record.admission.as_ref().ok_or(AdapterError::Journal)?.id
        {
            return Err(AdapterError::Contract);
        }
        Ok(response)
    }

    async fn post_result(
        &self,
        record: &ResultJournalRecord,
    ) -> Result<ResultReceipt, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(
                Method::POST,
                &format!("/api/stage-handoffs/{}/result", record.handoff_id),
                Some(record.body_json.as_bytes()),
                Some(&record.idempotency_key),
                &credentials,
            )
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        let response: ResultResponse = decode_strict(&bytes)?;
        let receipt = ResultReceipt::from_response(&response)?;
        if !receipt.matches_request(&record.body_json, &record.handoff_id) {
            return Err(AdapterError::Contract);
        }
        Ok(receipt)
    }

    async fn exchange(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
        idempotency_key: Option<&str>,
        credentials: &Credentials,
    ) -> Result<(StatusCode, Vec<u8>), AdapterError> {
        let url = self.origin.join(path).map_err(|_| AdapterError::Contract)?;
        let mut authorization = Vec::with_capacity(7 + credentials.api_key.len());
        authorization.extend_from_slice(b"Bearer ");
        authorization.extend_from_slice(&credentials.api_key);
        let mut authorization_value =
            HeaderValue::from_bytes(&authorization).map_err(|_| AdapterError::Credential)?;
        authorization_value.set_sensitive(true);
        authorization.fill(0);
        let mut builder = self
            .client
            .request(method, url)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(ACCEPT, JSON_MEDIA)
            .header(ACCEPT_ENCODING, IDENTITY_ENCODING)
            .header(AUTHORIZATION, authorization_value);
        if let Some(idempotency_key) = idempotency_key {
            builder = builder.header("idempotency-key", idempotency_key);
        }
        if let Some(body) = body {
            builder = builder.header(CONTENT_TYPE, JSON_MEDIA).body(body.to_vec());
        }
        let response = builder.send().await.map_err(|_| AdapterError::Transport)?;
        if response.headers().contains_key(CONTENT_ENCODING) {
            return Err(AdapterError::Contract);
        }
        reject_reflected_headers(response.headers(), credentials)?;
        let media_ok = response_media_json(response.headers());
        let status = response.status();
        let bytes = bounded_body(response).await?;
        reject_reflected_bytes(&bytes, credentials)?;
        if status.is_success() && !media_ok {
            return Err(AdapterError::Contract);
        }
        Ok((status, bytes))
    }
}

pub(crate) struct AeonDeliveryAdapter {
    config: AdapterConfig,
    journal: JournalStore,
    aeon: AeonClient,
    hosts: Arc<Store>,
    host_actions: Arc<HostActionStore>,
}

impl AeonDeliveryAdapter {
    pub(crate) fn from_env(
        host_store_path: Option<&Path>,
        hosts: Arc<Store>,
        host_actions: Arc<HostActionStore>,
    ) -> Result<Option<Self>, String> {
        let Some(config_path) = std::env::var("PHAROS_AEON_DELIVERY_CONFIG_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
        else {
            return Ok(None);
        };
        let host_store_path = host_store_path.ok_or_else(|| {
            "PHAROS_AEON_DELIVERY_CONFIG_FILE requires PHAROS_DB for its durable journal"
                .to_string()
        })?;
        let config = AdapterConfig::load(Path::new(&config_path))
            .map_err(|error| format!("Aeon delivery adapter startup failed: {error}"))?;
        let journal = JournalStore::new(derived_journal_path(host_store_path))
            .map_err(|error| format!("Aeon delivery adapter startup failed: {error}"))?;
        let aeon = AeonClient::new(
            config.aeon_origin.clone(),
            config.api_key_file.clone(),
            &config.aeon_ca_certificates,
        )
        .map_err(|error| format!("Aeon delivery adapter startup failed: {error}"))?;
        tracing::info!("Aeon delivery adapter enabled");
        Ok(Some(Self {
            config,
            journal,
            aeon,
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
                        "Aeon delivery observation was not reported"
                    );
                }
            }
        }
    }

    async fn process_intent(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        self.journal
            .assert_bound(intent, &self.config.aeon_origin)?;
        if self.replay_started_consume(intent).await? {
            return Ok(());
        }
        self.confirm_if_consumed(intent)?;
        if let Some(pending) = self.journal.pending_evidence(&intent.handoff_id) {
            return self.replay_evidence(intent, &pending).await;
        }
        if self
            .journal
            .result(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_none())
        {
            let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
            handoff.validate(intent)?;
            if handoff.state.is_closed() {
                self.log_closed(&handoff);
                return Ok(());
            }
            handoff.open_for_write(now_unix())?;
            let pending = self
                .journal
                .result(&intent.handoff_id)
                .ok_or(AdapterError::Journal)?;
            let request: ResultRequest = decode_strict(pending.body_json.as_bytes())?;
            return self
                .finish_result(intent, &handoff, request.terminal_sequence, request.outcome)
                .await;
        }
        let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
        handoff.validate(intent)?;
        if handoff.state.is_closed() {
            self.log_closed(&handoff);
            return Ok(());
        }
        handoff.open_for_write(now_unix())?;
        if intent.operation == Operation::Deploy {
            self.bind_deployment(intent, &handoff)?;
        }
        self.maybe_launch(intent, &handoff).await?;
        self.maybe_report(intent, &handoff).await
    }

    fn log_closed(&self, handoff: &HandoffDocument) {
        tracing::debug!(
            handoff_id = %handoff.id,
            state = handoff.state.key(),
            "Aeon delivery handoff is closed"
        );
    }

    async fn replay_started_consume(&self, intent: &DeliveryIntent) -> Result<bool, AdapterError> {
        let Some(launch) = self.journal.launch(&intent.handoff_id) else {
            return Ok(false);
        };
        if launch.consume_unresolved.is_some() {
            return Err(AdapterError::LaunchUnresolved);
        }
        if !launch.consume_started || launch.receipt.is_some() {
            return Ok(false);
        }
        if intent.delegated_launch.is_none() || !launch.valid() {
            return Err(AdapterError::LocalBinding);
        }
        match self.aeon.post_consume(&launch).await {
            Ok(response) => {
                let receipt = consume_receipt(&response, now_unix())?;
                let launch = self
                    .journal
                    .acknowledge_consume(&intent.handoff_id, receipt)?;
                self.finish_confirmation(intent, &launch)?;
                Ok(true)
            }
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT => {
                self.journal
                    .mark_consume_unresolved(&intent.handoff_id, status)?;
                Err(AdapterError::LaunchUnresolved)
            }
            Err(error) => Err(error),
        }
    }

    fn confirm_if_consumed(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let Some(launch) = self.journal.launch(&intent.handoff_id) else {
            return Ok(());
        };
        if launch.receipt.is_none() {
            return Ok(());
        }
        self.finish_confirmation(intent, &launch)
    }

    async fn replay_evidence(
        &self,
        intent: &DeliveryIntent,
        record: &EvidenceJournalRecord,
    ) -> Result<(), AdapterError> {
        if !record.bound_to(intent, &self.config.aeon_origin) || !record.valid() {
            return Err(AdapterError::Journal);
        }
        let receipt = self.aeon.post_evidence(record).await?;
        self.journal.acknowledge_evidence(record, receipt)
    }

    fn bind_deployment(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        if let Some(existing) = self.journal.operation(&intent.handoff_id) {
            return self.adopt_operation(intent, handoff, &existing);
        }
        let operation_id = operation_identity(intent, &self.config.aeon_origin, handoff)?;
        let job_id = if let Some(configured) = intent.update_restart_job_id.as_deref() {
            let job = self
                .host_actions
                .get(configured)
                .ok_or(AdapterError::LocalBinding)?;
            if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
                return Err(AdapterError::LocalBinding);
            }
            configured.to_string()
        } else {
            let job_id = deterministic_job_id(&intent.host, &operation_id)?;
            let predecessor = self.journal.retry_predecessor(intent, handoff)?;
            let job = match predecessor.as_ref() {
                Some(predecessor) => self.host_actions.retry_update_review_with_id(
                    &predecessor.job_id,
                    &job_id,
                    &intent.host,
                    ACTOR,
                    now_unix(),
                ),
                None => self.host_actions.ensure_update_review_with_id(
                    &job_id,
                    &intent.host,
                    ACTOR,
                    UpdateRestartIntent::Update,
                    now_unix(),
                ),
            }
            .map_err(map_host_action_error)?;
            self.validate_new_owned_job(intent, handoff, &job)?;
            job.id
        };
        self.journal.persist_operation(OperationBinding {
            handoff_id: intent.handoff_id.clone(),
            job_id,
            host: intent.host.clone(),
            workflow: intent.workflow.key().to_string(),
            environment: intent.environment.clone(),
            release_node_id: intent.release_node_id.clone(),
            artifact: intent.artifact.clone(),
            plan_digest: handoff.plan_digest.clone(),
            predecessor_digest: handoff.predecessor_digest.clone(),
            authority_epoch: handoff.authority_epoch,
            context_digest: handoff.context_digest.clone(),
            attempt: handoff.attempt,
            operation_id,
        })?;
        Ok(())
    }

    fn adopt_operation(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        existing: &OperationBinding,
    ) -> Result<(), AdapterError> {
        if existing.host != intent.host
            || existing.workflow != intent.workflow.key()
            || existing.environment != intent.environment
            || existing.release_node_id != intent.release_node_id
            || existing.artifact != intent.artifact
            || !existing.matches_handoff(handoff)
        {
            return Err(AdapterError::LocalBinding);
        }
        if intent
            .update_restart_job_id
            .as_deref()
            .is_some_and(|job_id| job_id != existing.job_id)
        {
            return Err(AdapterError::LocalBinding);
        }
        let job = self
            .host_actions
            .get(&existing.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        if intent.update_restart_job_id.is_none() {
            self.validate_bound_owned_job(intent, existing, &job)?;
        }
        Ok(())
    }

    fn validate_bound_owned_job(
        &self,
        intent: &DeliveryIntent,
        binding: &OperationBinding,
        job: &HostActionJob,
    ) -> Result<(), AdapterError> {
        let expected = deterministic_job_id(&intent.host, &binding.operation_id)?;
        if job.id != binding.job_id
            || job.id != expected
            || job.host != intent.host
            || job.workflow_kind() != HostWorkflowKind::UpdateRestart
            || job.update_restart_intent() != UpdateRestartIntent::Update
            || job.requested_by != ACTOR
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    fn validate_new_owned_job(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        job: &HostActionJob,
    ) -> Result<(), AdapterError> {
        let predecessor = self.journal.retry_predecessor(intent, handoff)?;
        if job.host != intent.host
            || job.workflow_kind() != HostWorkflowKind::UpdateRestart
            || job.update_restart_intent() != UpdateRestartIntent::Update
            || job.requested_by != ACTOR
            || job.retry_of.as_deref()
                != predecessor.as_ref().map(|binding| binding.job_id.as_str())
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    async fn maybe_launch(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        if intent.operation != Operation::Deploy || intent.delegated_launch.is_none() {
            return Ok(());
        }
        if let Some(launch) = self.journal.launch(&intent.handoff_id) {
            if launch.receipt.is_some() {
                return Ok(());
            }
            // Consume was journaled. Admit must not run again, even when the
            // one-use consume came back unresolved.
            if launch.consume_started
                || launch.consume_unresolved.is_some()
                || launch.admit_unresolved.is_some()
            {
                return Err(AdapterError::LaunchUnresolved);
            }
        }
        let Some(operation) = self.journal.operation(&intent.handoff_id) else {
            return Ok(());
        };
        if !operation.matches_handoff(handoff) {
            return Err(AdapterError::LocalBinding);
        }
        let Some(job) = self.host_actions.get(&operation.job_id) else {
            return Err(AdapterError::LocalBinding);
        };
        if !awaiting_ready_review(&job, &intent.host) {
            return Ok(());
        }
        let reviewed = reviewed_plan_digest(&job).map_err(map_shared)?;
        self.send_readiness(intent, handoff, &operation.job_id, &reviewed)
            .await?;
        let launch = self
            .ensure_admission(intent, &operation.job_id, &reviewed)
            .await?;
        let admission = launch.admission.clone().ok_or(AdapterError::Journal)?;
        self.validate_admission(&admission, intent, handoff, &reviewed, now_unix())?;
        let fresh = self.aeon.get_handoff(&intent.handoff_id).await?;
        fresh.validate(intent)?;
        fresh.open_for_write(now_unix())?;
        if fresh.plan_digest != handoff.plan_digest
            || fresh.predecessor_digest != handoff.predecessor_digest
            || fresh.context_digest != handoff.context_digest
            || fresh.authority_epoch != handoff.authority_epoch
        {
            return Err(AdapterError::LocalBinding);
        }
        let fresh_job = self
            .host_actions
            .get(&operation.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if !consumable_for_launch(&fresh_job, &intent.host)
            || reviewed_plan_digest(&fresh_job).map_err(map_shared)? != reviewed
        {
            return Err(AdapterError::LocalBinding);
        }
        self.validate_admission(&admission, intent, &fresh, &reviewed, now_unix())?;
        self.consume_and_confirm(intent).await
    }

    async fn send_readiness(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        job_id: &str,
        reviewed: &str,
    ) -> Result<(), AdapterError> {
        if let Some(existing) = self
            .journal
            .evidence_with_kind(&intent.handoff_id, EvidenceKind::LaunchReadiness)
        {
            if existing.receipt.is_none() {
                self.replay_evidence(intent, &existing).await?;
            }
            let current = self
                .journal
                .evidence_with_kind(&intent.handoff_id, EvidenceKind::LaunchReadiness)
                .ok_or(AdapterError::Journal)?;
            let posted = evidence_string_field(&current.body_json, "reviewed_plan_digest")?;
            if posted != bare_plan_digest(reviewed)? {
                return Err(AdapterError::LocalBinding);
            }
            return Ok(());
        }
        let job = self
            .host_actions
            .get(job_id)
            .ok_or(AdapterError::LocalBinding)?;
        let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
        let observed_at = format_timestamp(now_unix())?;
        let bare_reviewed = bare_plan_digest(reviewed)?;
        // The plan has backup_ready and no clock. Aeon's backup time is
        // optional, so omit it unless the host store has a success.
        let backup_at = backup_observed_at(&self.hosts, &intent.host);
        let running_kernel = kernel_token(plan.running_kernel.as_deref());
        let expected_kernel = kernel_token(plan.expected_kernel.as_deref());
        let sequence = self.journal.next_sequence(&intent.handoff_id)?;
        let write = EvidenceWrite {
            sequence,
            kind: EvidenceKind::LaunchReadiness,
            outcome: EvidenceOutcome::Satisfied,
            observed_at: &observed_at,
            authority_epoch: handoff.authority_epoch,
            workflow: None,
            environment: None,
            artifact: None,
            reviewed_plan_digest: Some(&bare_reviewed),
            host: Some(&intent.host),
            all_host_eval_passed: Some(plan.all_host_eval_passed),
            target_build_passed: Some(plan.target_build_passed),
            backup_ready: Some(plan.backup_ready),
            backup_observed_at: backup_at.as_deref(),
            restart_required: Some(plan.restart_required),
            running_kernel: Some(running_kernel),
            expected_kernel: Some(expected_kernel),
        };
        self.send_new_evidence(intent, EvidenceKind::LaunchReadiness, &write)
            .await?;
        Ok(())
    }

    async fn ensure_admission(
        &self,
        intent: &DeliveryIntent,
        job_id: &str,
        reviewed: &str,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if let Some(existing) = self.journal.launch(&intent.handoff_id) {
            if existing.reviewed_plan_digest != reviewed || existing.job_id != job_id {
                return Err(AdapterError::LocalBinding);
            }
            if existing.admit_unresolved.is_some() {
                return Err(AdapterError::LaunchUnresolved);
            }
            if existing.admission.is_some() {
                return Ok(existing);
            }
            return self.replay_admit(intent, &existing).await;
        }
        let readiness = self
            .journal
            .evidence_with_kind(&intent.handoff_id, EvidenceKind::LaunchReadiness)
            .ok_or(AdapterError::Journal)?;
        let artifact = WireArtifact::from_evidence(&intent.artifact)?;
        let body = serde_json::to_vec(&artifact).map_err(|_| AdapterError::Contract)?;
        let admit_digest = hex_digest(&body);
        let record = LaunchJournalRecord {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(&self.config.aeon_origin)?,
            job_id: job_id.to_string(),
            readiness_sequence: readiness.sequence,
            reviewed_plan_digest: reviewed.to_string(),
            admit_idempotency_key: idempotency_key(
                &intent.handoff_id,
                readiness.sequence,
                &admit_digest,
            ),
            admit_digest,
            admit_body_json: String::from_utf8(body).map_err(|_| AdapterError::Contract)?,
            admission: None,
            consume_digest: None,
            consume_idempotency_key: None,
            consume_body_json: None,
            consume_started: false,
            consume_unresolved: None,
            admit_unresolved: None,
            receipt: None,
        };
        let record = self.journal.ensure_launch(record)?;
        self.replay_admit(intent, &record).await
    }

    async fn replay_admit(
        &self,
        intent: &DeliveryIntent,
        record: &LaunchJournalRecord,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if record.consume_started {
            return Err(AdapterError::LaunchUnresolved);
        }
        match self.aeon.post_admit(record).await {
            Ok(admission) => self.journal.store_admission(&intent.handoff_id, admission),
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT => {
                self.journal
                    .mark_admit_unresolved(&intent.handoff_id, status)?;
                Err(AdapterError::LaunchUnresolved)
            }
            Err(error) => Err(error),
        }
    }

    fn validate_admission(
        &self,
        admission: &LaunchAdmission,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        reviewed: &str,
        now: i64,
    ) -> Result<(), AdapterError> {
        let artifact_digest = strip_sha256(&intent.artifact.digest)?;
        let expected = launch_binding_digest(
            &artifact_digest,
            handoff.authority_epoch,
            &intent.handoff_id,
            &intent.release_node_id,
            reviewed,
        )?;
        let expires_at = unix_of(&admission.expires_at)?;
        let handoff_expires = unix_of(&handoff.expires_at)?;
        if !valid_uuid(&admission.id)
            || admission.handoff_id != intent.handoff_id
            || admission.artifact_digest_sha256 != artifact_digest
            || admission.authority_epoch != handoff.authority_epoch
            || admission.binding_digest_sha256 != expected
            || admission.consumed_at.is_some()
            || expires_at <= now
            || expires_at > handoff_expires
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    async fn consume_and_confirm(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let launch = self.journal.mark_consume_started(&intent.handoff_id)?;
        let response = self.aeon.post_consume(&launch).await?;
        let receipt = consume_receipt(&response, now_unix())?;
        let launch = self
            .journal
            .acknowledge_consume(&intent.handoff_id, receipt)?;
        self.finish_confirmation(intent, &launch)
    }

    fn finish_confirmation(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
    ) -> Result<(), AdapterError> {
        let receipt = launch.receipt.as_ref().ok_or(AdapterError::Journal)?;
        let admission = launch.admission.as_ref().ok_or(AdapterError::Journal)?;
        let job = self
            .host_actions
            .get(&launch.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        if reviewed_plan_digest(&job).map_err(map_shared)? != launch.reviewed_plan_digest {
            return Err(AdapterError::LocalBinding);
        }
        if job.state == HostActionState::AwaitingConfirmation {
            self.host_actions
                .confirm_update_delegated(
                    &launch.job_id,
                    &intent.host,
                    &admission.id,
                    unix_of(&receipt.consumed_at)?,
                )
                .map_err(map_host_action_error)?;
            return Ok(());
        }
        if matches!(
            job.state,
            HostActionState::QueuedApply
                | HostActionState::Applying
                | HostActionState::Rebooting
                | HostActionState::Succeeded
                | HostActionState::Failed
                | HostActionState::Cancelled
        ) {
            return Ok(());
        }
        Err(AdapterError::LocalBinding)
    }

    async fn maybe_report(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        match intent.operation {
            Operation::Deploy => self.report_deployment(intent, handoff).await,
            Operation::Verify => self.report_verification(intent, handoff).await,
        }
    }

    async fn report_deployment(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        let Some(operation) = self.journal.operation(&intent.handoff_id) else {
            return Err(AdapterError::LocalBinding);
        };
        if !operation.matches_handoff(handoff) {
            return Err(AdapterError::LocalBinding);
        }
        let Some(job) = self.host_actions.get(&operation.job_id) else {
            return Ok(());
        };
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        match job.state {
            HostActionState::Failed | HostActionState::Cancelled => {
                self.write_observation(intent, handoff, EvidenceOutcome::Failed, job.updated_at)
                    .await
            }
            HostActionState::Succeeded => {
                if job.confirmed_at.is_none() || job.result.is_none() {
                    return Err(AdapterError::LocalBinding);
                }
                if intent.delegated_launch.is_some()
                    && self
                        .journal
                        .launch(&intent.handoff_id)
                        .is_none_or(|launch| launch.receipt.is_none())
                {
                    return Err(AdapterError::LocalBinding);
                }
                let host = self.hosts.get(&intent.host);
                let observed = observed_fresh_config_beacon(
                    host.as_ref(),
                    &intent.environment,
                    &intent.artifact,
                    job.updated_at,
                    now_unix(),
                    self.config.verification_freshness_secs,
                )
                .map_err(map_shared)?;
                let Some(observed_at) = observed else {
                    return Ok(());
                };
                self.write_observation(intent, handoff, EvidenceOutcome::Succeeded, observed_at)
                    .await
            }
            _ => Ok(()),
        }
    }

    async fn report_verification(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        let deploy_id = intent
            .deployment_handoff_id
            .as_deref()
            .ok_or(AdapterError::LocalBinding)?;
        let Some(binding) = self.journal.operation(deploy_id) else {
            return Ok(());
        };
        if handoff.predecessor_digest != binding.plan_digest
            || handoff.authority_epoch != binding.authority_epoch
            || binding.host != intent.host
            || binding.environment != intent.environment
            || binding.artifact != intent.artifact
        {
            return Err(AdapterError::LocalBinding);
        }
        let Some(deploy_result) = self.journal.result(deploy_id) else {
            return Ok(());
        };
        let Some(receipt) = deploy_result.receipt else {
            return Ok(());
        };
        if receipt.outcome != ResultOutcome::Succeeded {
            return Err(AdapterError::LocalBinding);
        }
        let host = self.hosts.get(&intent.host);
        match observed_fresh_config_beacon(
            host.as_ref(),
            &intent.environment,
            &intent.artifact,
            unix_of(&receipt.completed_at)?,
            now_unix(),
            self.config.verification_freshness_secs,
        ) {
            Ok(Some(observed_at)) => {
                self.write_observation(intent, handoff, EvidenceOutcome::Succeeded, observed_at)
                    .await
            }
            Ok(None) => Ok(()),
            Err(_) => {
                self.write_observation(intent, handoff, EvidenceOutcome::Failed, now_unix())
                    .await
            }
        }
    }

    async fn write_observation(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        outcome: EvidenceOutcome,
        observed_at: i64,
    ) -> Result<(), AdapterError> {
        let kind = intent.operation.evidence_kind();
        let record =
            if let Some(existing) = self.journal.evidence_with_kind(&intent.handoff_id, kind) {
                if existing.receipt.is_none() {
                    self.replay_evidence(intent, &existing).await?;
                }
                self.journal
                    .evidence_with_kind(&intent.handoff_id, kind)
                    .ok_or(AdapterError::Journal)?
            } else {
                let observed_at = format_timestamp(observed_at)?;
                if unix_of(&observed_at)? > now_unix().saturating_add(OBSERVED_AT_SKEW_SECS) {
                    return Err(AdapterError::Contract);
                }
                let artifact = WireArtifact::from_evidence(&intent.artifact)?;
                let sequence = self.journal.next_sequence(&intent.handoff_id)?;
                let write = EvidenceWrite {
                    sequence,
                    kind,
                    outcome,
                    observed_at: &observed_at,
                    authority_epoch: handoff.authority_epoch,
                    workflow: Some(intent.workflow.key()),
                    environment: Some(&intent.environment),
                    artifact: Some(&artifact),
                    reviewed_plan_digest: None,
                    host: None,
                    all_host_eval_passed: None,
                    target_build_passed: None,
                    backup_ready: None,
                    backup_observed_at: None,
                    restart_required: None,
                    running_kernel: None,
                    expected_kernel: None,
                };
                self.send_new_evidence(intent, kind, &write).await?
            };
        let receipt = record.receipt.as_ref().ok_or(AdapterError::Journal)?;
        if receipt.outcome != outcome {
            return Err(AdapterError::LocalBinding);
        }
        let result_outcome = ResultOutcome::from_evidence(outcome)?;
        self.finish_result(intent, handoff, record.sequence, result_outcome)
            .await
    }

    async fn send_new_evidence(
        &self,
        intent: &DeliveryIntent,
        kind: EvidenceKind,
        write: &EvidenceWrite<'_>,
    ) -> Result<EvidenceJournalRecord, AdapterError> {
        let body = serde_json::to_vec(write).map_err(|_| AdapterError::Contract)?;
        let record = self.journal.ensure_evidence(EvidenceJournalRecord::new(
            intent,
            &self.config.aeon_origin,
            write.sequence,
            kind,
            &body,
        )?)?;
        let receipt = self.aeon.post_evidence(&record).await?;
        self.journal.acknowledge_evidence(&record, receipt)?;
        self.journal
            .evidence_with_kind(&intent.handoff_id, kind)
            .ok_or(AdapterError::Journal)
    }

    async fn finish_result(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        terminal_sequence: i64,
        outcome: ResultOutcome,
    ) -> Result<(), AdapterError> {
        if self
            .journal
            .result(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_some())
        {
            return Ok(());
        }
        let record = self.stage_result(intent, handoff, terminal_sequence, outcome)?;
        match self.aeon.post_result(&record).await {
            Ok(receipt) => self.journal.acknowledge_result(&record, receipt),
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT => {
                self.retry_result_seal(intent, &record).await
            }
            Err(error) => Err(error),
        }
    }

    fn stage_result(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        terminal_sequence: i64,
        outcome: ResultOutcome,
    ) -> Result<ResultJournalRecord, AdapterError> {
        if let Some(existing) = self.journal.result(&intent.handoff_id) {
            // Replay the journaled bytes. A different seal replaces this record
            // only after Aeon rejects those exact bytes.
            return Ok(existing);
        }
        let request = ResultRequest {
            outcome,
            terminal_sequence,
            authority_epoch: handoff.authority_epoch,
            prerequisite_seal_sha256: handoff.prerequisite_seal_sha256.clone(),
        };
        let body = serde_json::to_vec(&request).map_err(|_| AdapterError::Contract)?;
        let record =
            ResultJournalRecord::new(intent, &self.config.aeon_origin, terminal_sequence, &body)?;
        self.journal.ensure_result(record)
    }

    async fn retry_result_seal(
        &self,
        intent: &DeliveryIntent,
        failed: &ResultJournalRecord,
    ) -> Result<(), AdapterError> {
        let fresh = self.aeon.get_handoff(&intent.handoff_id).await?;
        fresh.validate(intent)?;
        fresh.open_for_write(now_unix())?;
        let operation = self
            .journal
            .operation(&intent.handoff_id)
            .ok_or(AdapterError::LocalBinding)?;
        if !operation.matches_handoff(&fresh) {
            return Err(AdapterError::LocalBinding);
        }
        let failed_request: ResultRequest = decode_strict(failed.body_json.as_bytes())?;
        if fresh.authority_epoch != failed_request.authority_epoch
            || fresh.prerequisite_seal_sha256 == failed_request.prerequisite_seal_sha256
        {
            return Err(AdapterError::Refused(StatusCode::CONFLICT));
        }
        let request = ResultRequest {
            outcome: failed_request.outcome,
            terminal_sequence: failed_request.terminal_sequence,
            authority_epoch: fresh.authority_epoch,
            prerequisite_seal_sha256: fresh.prerequisite_seal_sha256,
        };
        let body = serde_json::to_vec(&request).map_err(|_| AdapterError::Contract)?;
        let record = ResultJournalRecord::new(
            intent,
            &self.config.aeon_origin,
            request.terminal_sequence,
            &body,
        )?;
        let record = self.journal.replace_unacked_result(record)?;
        let receipt = self.aeon.post_result(&record).await?;
        self.journal.acknowledge_result(&record, receipt)
    }
}

fn awaiting_ready_review(job: &HostActionJob, host: &str) -> bool {
    job.host == host
        && job.workflow_kind() == HostWorkflowKind::UpdateRestart
        && job.state == HostActionState::AwaitingConfirmation
        && job.plan.as_ref().is_some_and(HostActionPlan::ready)
}

fn consumable_for_launch(job: &HostActionJob, host: &str) -> bool {
    awaiting_ready_review(job, host) && job.requested_by == ACTOR && job.confirmed_at.is_none()
}

fn consume_receipt(response: &ConsumeResponse, now: i64) -> Result<ConsumeReceipt, AdapterError> {
    if !response.consumed {
        return Err(AdapterError::Contract);
    }
    Ok(ConsumeReceipt {
        handoff_id: response.handoff_id.clone(),
        admission_id: response.admission_id.clone(),
        consumed: true,
        consumed_at: format_timestamp(now)?,
    })
}

fn backup_observed_at(hosts: &Store, host_name: &str) -> Option<String> {
    let host = hosts.get(host_name)?;
    let at = host
        .backup_observations
        .iter()
        .filter_map(|observation| observation.last_success_at)
        .filter(|at| *at > 0)
        .max()?;
    format_timestamp(at).ok()
}

fn evidence_string_field(body: &str, key: &str) -> Result<String, AdapterError> {
    let value: serde_json::Value = decode_strict(body.as_bytes())?;
    value
        .get(key)
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .ok_or(AdapterError::Contract)
}

fn evidence_echo_matches(response: &EvidenceResponse, body: &str) -> bool {
    let Ok(request) = decode_strict::<serde_json::Value>(body.as_bytes()) else {
        return false;
    };
    opt_str_matches(&request, "workflow", response.workflow.as_deref())
        && opt_str_matches(&request, "environment", response.environment.as_deref())
        && opt_str_matches(
            &request,
            "reviewed_plan_digest",
            response.reviewed_plan_digest.as_deref(),
        )
        && opt_str_matches(&request, "host", response.host.as_deref())
        && opt_str_matches(
            &request,
            "backup_observed_at",
            response.backup_observed_at.as_deref(),
        )
        && opt_str_matches(
            &request,
            "running_kernel",
            response.running_kernel.as_deref(),
        )
        && opt_str_matches(
            &request,
            "expected_kernel",
            response.expected_kernel.as_deref(),
        )
        && opt_bool_matches(
            &request,
            "all_host_eval_passed",
            response.all_host_eval_passed,
        )
        && opt_bool_matches(
            &request,
            "target_build_passed",
            response.target_build_passed,
        )
        && opt_bool_matches(&request, "backup_ready", response.backup_ready)
        && opt_bool_matches(&request, "restart_required", response.restart_required)
        && artifact_echo_matches(&request, response.artifact.as_ref())
}

fn opt_str_matches(request: &serde_json::Value, key: &str, actual: Option<&str>) -> bool {
    match (request.get(key).and_then(serde_json::Value::as_str), actual) {
        (None, None) => true,
        (Some(expected), Some(actual)) => expected == actual,
        _ => false,
    }
}

fn opt_bool_matches(request: &serde_json::Value, key: &str, actual: Option<bool>) -> bool {
    match (
        request.get(key).and_then(serde_json::Value::as_bool),
        actual,
    ) {
        (None, None) => true,
        (Some(expected), Some(actual)) => expected == actual,
        _ => false,
    }
}

fn artifact_echo_matches(request: &serde_json::Value, artifact: Option<&WireArtifact>) -> bool {
    match (request.get("artifact"), artifact) {
        (None, None) => true,
        (Some(value), Some(artifact)) => {
            value
                .get("digest_sha256")
                .and_then(serde_json::Value::as_str)
                == Some(artifact.digest_sha256.as_str())
                && value
                    .get("manifest_digest_sha256")
                    .and_then(serde_json::Value::as_str)
                    == Some(artifact.manifest_digest_sha256.as_str())
                && value.get("version").and_then(serde_json::Value::as_str)
                    == Some(artifact.version.as_str())
                && value
                    .get("commit_digest")
                    .and_then(serde_json::Value::as_str)
                    == Some(artifact.commit_digest.as_str())
        }
        _ => false,
    }
}

fn bare_plan_digest(value: &str) -> Result<String, AdapterError> {
    let bare = value.strip_prefix("sha256:").unwrap_or(value);
    if !valid_hex64(bare) {
        return Err(AdapterError::Contract);
    }
    Ok(bare.to_string())
}

fn kernel_token(value: Option<&str>) -> &str {
    value
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .unwrap_or("unknown")
}

fn launch_binding_digest(
    artifact_digest_sha256: &str,
    authority_epoch: i64,
    handoff_id: &str,
    release_node_id: &str,
    reviewed_plan_digest: &str,
) -> Result<String, AdapterError> {
    let reviewed_plan_digest = bare_plan_digest(reviewed_plan_digest)?;
    if !valid_hex64(artifact_digest_sha256)
        || authority_epoch < 1
        || !valid_uuid(handoff_id)
        || !valid_uuid(release_node_id)
    {
        return Err(AdapterError::Contract);
    }
    let canonical = format!(
        "{{\"artifact_digest_sha256\":\"{artifact_digest_sha256}\",\"authority_epoch\":{authority_epoch},\"handoff_id\":\"{handoff_id}\",\"release_node_id\":\"{release_node_id}\",\"reviewed_plan_digest\":\"{reviewed_plan_digest}\"}}"
    );
    let mut hasher = Sha256::new();
    hasher.update(LAUNCH_BINDING_DOMAIN);
    hasher.update(canonical.as_bytes());
    Ok(hex_bytes(&hasher.finalize()))
}

fn operation_identity(
    intent: &DeliveryIntent,
    origin: &Url,
    handoff: &HandoffDocument,
) -> Result<String, AdapterError> {
    #[derive(Serialize)]
    struct Identity<'a> {
        domain: &'static str,
        aeon_origin: &'a str,
        handoff_id: &'a str,
        host: &'a str,
        workflow: &'static str,
        environment: &'a str,
        artifact: &'a ArtifactEvidence,
        plan_digest: &'a str,
        predecessor_digest: &'a str,
        context_digest: &'a str,
        authority_epoch: i64,
        attempt: i64,
    }

    let bytes = serde_json::to_vec(&Identity {
        domain: OPERATION_DOMAIN,
        aeon_origin: origin.as_str(),
        handoff_id: &intent.handoff_id,
        host: &intent.host,
        workflow: intent.workflow.key(),
        environment: &intent.environment,
        artifact: &intent.artifact,
        plan_digest: &handoff.plan_digest,
        predecessor_digest: &handoff.predecessor_digest,
        context_digest: &handoff.context_digest,
        authority_epoch: handoff.authority_epoch,
        attempt: handoff.attempt,
    })
    .map_err(|_| AdapterError::Contract)?;
    Ok(hex_digest(&bytes))
}

fn deterministic_job_id(host: &str, operation_id: &str) -> Result<String, AdapterError> {
    if operation_id.len() < 16 {
        return Err(AdapterError::Contract);
    }
    Ok(format!(
        "action-update-restart-{host}-{}",
        &operation_id[..16]
    ))
}

fn map_host_action_error(error: HostActionStoreError) -> AdapterError {
    match error {
        HostActionStoreError::Persistence | HostActionStoreError::PersistenceCommitted => {
            AdapterError::Journal
        }
        _ => AdapterError::LocalBinding,
    }
}

fn owner_parent(path: &Path, trust: bool) -> Result<(), AdapterError> {
    let error = || {
        if trust {
            AdapterError::Trust
        } else {
            AdapterError::Credential
        }
    };
    let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    else {
        return Err(error());
    };
    let metadata = std::fs::metadata(parent).map_err(|_| error())?;
    if !metadata.is_dir() {
        return Err(error());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err(error());
        }
    }
    Ok(())
}

fn valid_api_key(bytes: &[u8]) -> bool {
    (MIN_API_KEY_BYTES..=MAX_API_KEY_BYTES as usize).contains(&bytes.len())
        && bytes.iter().all(|byte| (0x21..=0x7e).contains(byte))
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

fn derived_journal_path(host_store_path: &Path) -> PathBuf {
    let file_name = host_store_path
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("pharos.json");
    host_store_path.with_file_name(format!("{file_name}.aeon-delivery-journal.json"))
}

fn response_media_json(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Ok(text) = value.to_str() else {
        return false;
    };
    let media = text.split(';').next().unwrap_or(text).trim();
    media.eq_ignore_ascii_case(JSON_MEDIA)
}

fn status_error(status: StatusCode) -> AdapterError {
    match status.as_u16() {
        401 | 403 => AdapterError::Credential,
        _ => AdapterError::Refused(status),
    }
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
) -> Result<(), AdapterError> {
    for value in headers.values() {
        if contains_slice(value.as_bytes(), &credentials.api_key) {
            return Err(AdapterError::Contract);
        }
    }
    Ok(())
}

fn reject_reflected_bytes(bytes: &[u8], credentials: &Credentials) -> Result<(), AdapterError> {
    if contains_slice(bytes, &credentials.api_key) {
        return Err(AdapterError::Contract);
    }
    Ok(())
}

fn contains_slice(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
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

fn unix_of(value: &str) -> Result<i64, AdapterError> {
    Ok(parse_timestamp(value)?.unix_timestamp())
}

fn now_unix() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

fn strip_sha256(value: &str) -> Result<String, AdapterError> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| valid_hex64(digest))
        .map(str::to_string)
        .ok_or(AdapterError::Contract)
}

fn valid_symbol(value: &str) -> bool {
    (1..=64).contains(&value.len())
        && value.as_bytes()[0].is_ascii_lowercase()
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'_' | b'-')
        })
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

fn valid_prefixed_sha256(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(valid_hex64)
}

fn valid_hex64(value: &str) -> bool {
    valid_lower_hex(value, &[64])
}

fn valid_lower_hex(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && [8, 13, 18, 23]
            .into_iter()
            .all(|index| bytes[index] == b'-')
        && bytes.iter().enumerate().all(|(index, byte)| {
            matches!(index, 8 | 13 | 18 | 23)
                || byte.is_ascii_digit()
                || matches!(byte, b'a'..=b'f')
        })
        && matches!(bytes[14], b'1'..=b'8')
        && matches!(bytes[19], b'8' | b'9' | b'a' | b'b')
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    use axum::body::{to_bytes, Body};
    use axum::extract::State;
    use axum::http::{Request, Response};
    use axum::Router;
    use pharos_core::{
        ArtifactDigestClass, BackupConfiguredState, BackupEngine, BackupObservation,
        BackupPostureState, BackupRunState, DeployedArtifactEvidence, HostReport,
        NixDeploymentEvidence, NixFreshness, DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA,
        DEPLOYED_ARTIFACT_EVIDENCE_VERSION, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION,
        NIX_DEPLOYMENT_EVIDENCE_SCHEMA, NIX_DEPLOYMENT_EVIDENCE_VERSION,
    };
    use serde_json::{json, Value};

    use crate::host_actions::{
        AgentActionOutcome, AgentActionPhase, AgentActionResultRequest, HostActionEventKind,
        HostActionEventSource, HostActionKind, HostActionPlan, HostActionResult,
    };

    static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(1);
    const DEPLOY_HANDOFF: &str = "11111111-1111-4111-8111-111111111111";
    const VERIFY_HANDOFF: &str = "22222222-2222-4222-8222-222222222222";
    const PROJECT_NODE: &str = "33333333-3333-4333-8333-333333333333";
    const RELEASE_NODE: &str = "44444444-4444-4444-8444-444444444444";
    const ADMISSION_ID: &str = "55555555-5555-4555-8555-555555555555";
    const OTHER_RELEASE: &str = "66666666-6666-4666-8666-666666666666";
    const OTHER_HANDOFF: &str = "88888888-8888-4888-8888-888888888888";
    const NEW_HANDOFF: &str = "77777777-7777-4777-8777-777777777777";
    const API_KEY: &[u8] = b"AEON_API_KEY_SENTINEL_0123456789ABCD";

    struct TestDir {
        path: PathBuf,
    }

    impl TestDir {
        fn new(label: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "pharos-aeon-delivery-{label}-{}-{}",
                std::process::id(),
                TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ));
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&path)
                    .expect("private test directory");
            }
            #[cfg(not(unix))]
            std::fs::create_dir(&path).expect("test directory");
            Self { path }
        }

        fn path(&self) -> &Path {
            &self.path
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            if self.path.starts_with(std::env::temp_dir())
                && self
                    .path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("pharos-aeon-delivery-"))
            {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
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
            version_scheme: pharos_core::ArtifactVersionScheme::Legacy,
            version: "1.2.3".to_string(),
            release_channel: "stable".to_string(),
            release_sequence: 123,
            digest: format!("sha256:{}", "1".repeat(64)),
            commit_digest: "a".repeat(40),
            release_manifest_coordinate: "ghcr:inspr-at/pharos/releases/1.2.3".to_string(),
            release_manifest_digest: format!("sha256:{}", "9".repeat(64)),
        }
    }

    fn deploy_intent(delegated: bool) -> DeliveryIntent {
        DeliveryIntent {
            handoff_id: DEPLOY_HANDOFF.to_string(),
            project_node_id: PROJECT_NODE.to_string(),
            release_node_id: RELEASE_NODE.to_string(),
            operation: Operation::Deploy,
            workflow: GuardedWorkflow::DeployProduction,
            environment: "production-eu1".to_string(),
            host: "hsb8".to_string(),
            artifact: artifact(),
            update_restart_job_id: None,
            deployment_handoff_id: None,
            delegated_launch: delegated.then(|| DelegatedLaunchSelection {
                target_ref: format!("sha256:{}", "a".repeat(64)),
            }),
        }
    }

    fn verify_intent() -> DeliveryIntent {
        DeliveryIntent {
            handoff_id: VERIFY_HANDOFF.to_string(),
            project_node_id: PROJECT_NODE.to_string(),
            release_node_id: RELEASE_NODE.to_string(),
            operation: Operation::Verify,
            workflow: GuardedWorkflow::VerifyProduction,
            environment: "production-eu1".to_string(),
            host: "hsb8".to_string(),
            artifact: artifact(),
            update_restart_job_id: None,
            deployment_handoff_id: Some(DEPLOY_HANDOFF.to_string()),
            delegated_launch: None,
        }
    }

    fn loopback_origin_for_tests(value: &str) -> Url {
        let url = Url::parse(value).expect("test loopback origin parses");
        assert_eq!(url.scheme(), "http");
        match url.host() {
            Some(url::Host::Ipv4(address)) => assert!(address.is_loopback()),
            Some(url::Host::Ipv6(address)) => assert!(address.is_loopback()),
            Some(url::Host::Domain("localhost")) => {}
            _ => panic!("test origin must be loopback"),
        }
        assert!(matches!(
            parse_origin(value),
            Err(AdapterError::Configuration)
        ));
        url
    }

    fn config_document(api: &Path, origin: &str, intents: Value) -> Value {
        json!({
            "schema": CONFIG_SCHEMA,
            "schema_version": CONFIG_SCHEMA_VERSION,
            "aeon_origin": origin,
            "api_key_file": api,
            "poll_interval_secs": 5,
            "verification_freshness_secs": 300,
            "intents": intents,
        })
    }

    fn deploy_intent_json() -> Value {
        json!({
            "handoff_id": DEPLOY_HANDOFF,
            "project_node_id": PROJECT_NODE,
            "release_node_id": RELEASE_NODE,
            "operation": "deploy",
            "workflow": "deploy-production",
            "environment": "production-eu1",
            "host": "hsb8",
            "artifact": artifact(),
        })
    }

    fn verify_intent_json() -> Value {
        json!({
            "handoff_id": VERIFY_HANDOFF,
            "project_node_id": PROJECT_NODE,
            "release_node_id": RELEASE_NODE,
            "operation": "verify",
            "workflow": "verify-production",
            "environment": "production-eu1",
            "host": "hsb8",
            "artifact": artifact(),
            "deployment_handoff_id": DEPLOY_HANDOFF,
        })
    }

    #[test]
    fn config_validation_rejects_bad_shape_and_cleartext_origin() {
        let directory = TestDir::new("config");
        let api = directory.path().join("api-key");
        let config_path = directory.path().join("adapter.json");
        write_private(&api, API_KEY);
        let mut document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json(), verify_intent_json()]),
        );
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(AdapterConfig::load(&config_path).is_ok());

        document["schema"] = json!("inspr.pharos.aeon-delivery-adapter.v2");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json()]),
        );
        document["unexpected"] = json!(true);
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json()]),
        );
        document["intents"][0]["handoff_id"] = json!("not-a-uuid");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([verify_intent_json()]),
        );
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json(), verify_intent_json()]),
        );
        document["intents"][1]["host"] = json!("other-host");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document = config_document(&api, "http://127.0.0.1:9", json!([deploy_intent_json()]));
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));
        let _ = loopback_origin_for_tests("http://127.0.0.1:9/");

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json()]),
        );
        document["intents"][0]["artifact"]["release_sequence"] = json!(0);
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        write_private(&api, b"too-short-key");
        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json()]),
        );
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Credential)
        ));
        write_private(&api, API_KEY);

        let ca = directory.path().join("ca.pem");
        write_private(&ca, b"not a certificate\n");
        document["aeon_ca_file"] = json!(ca);
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Trust)
        ));
        document.as_object_mut().unwrap().remove("aeon_ca_file");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(AdapterConfig::load(&config_path).is_ok());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o640)).unwrap();
            assert!(matches!(
                AdapterConfig::load(&config_path),
                Err(AdapterError::Credential)
            ));
            std::fs::set_permissions(&api, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755))
                .unwrap();
            assert!(matches!(
                AdapterConfig::load(&config_path),
                Err(AdapterError::Credential)
            ));
        }
    }

    #[test]
    fn launch_binding_digest_uses_sorted_canonical_json() {
        let digest = "1".repeat(64);
        let reviewed = format!("sha256:{}", "ab".repeat(32));
        let bare = "ab".repeat(32);
        let canonical = format!(
            "{{\"artifact_digest_sha256\":\"{digest}\",\"authority_epoch\":3,\"handoff_id\":\"{DEPLOY_HANDOFF}\",\"release_node_id\":\"{RELEASE_NODE}\",\"reviewed_plan_digest\":\"{bare}\"}}"
        );
        assert!(!canonical.contains(' '));
        let mut hasher = Sha256::new();
        hasher.update(b"inspr.aeon.launch-binding.v1\0");
        hasher.update(canonical.as_bytes());
        assert_eq!(
            launch_binding_digest(&digest, 3, DEPLOY_HANDOFF, RELEASE_NODE, &reviewed).unwrap(),
            hex_bytes(&hasher.finalize())
        );
    }

    #[test]
    fn classic_journal_is_not_resumed() {
        let directory = TestDir::new("classic-journal");
        let path = directory
            .path()
            .join("hosts.json.aeon-delivery-journal.json");
        write_private(
            &path,
            br#"{"schema":"inspr.pharos.paimos-delivery-journal.v1","schema_version":1,"records":{}}"#,
        );
        assert!(matches!(
            JournalStore::new(path),
            Err(AdapterError::Journal)
        ));
    }

    fn hex_chars(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    struct StoredEvidence {
        body: Vec<u8>,
        received_at: String,
    }

    struct FakeHandoff {
        id: String,
        project_node_id: String,
        release_node_id: String,
        operation: String,
        plugin_id: String,
        stage: String,
        attempt: i64,
        authority_epoch: i64,
        journey_revision: i64,
        state: String,
        expires_at: String,
        evidence_ceiling: Vec<String>,
        plan_digest: String,
        predecessor_digest: String,
        context_digest: String,
        prerequisite_seal_sha256: String,
        evidence: BTreeMap<i64, StoredEvidence>,
        admission: Option<Value>,
        admit_idempotency_key: Option<String>,
        consumed: bool,
        result_body: Option<Vec<u8>>,
        result: Option<Value>,
    }

    impl FakeHandoff {
        fn deploy(now: i64) -> Self {
            let mut handoff = Self::open(DEPLOY_HANDOFF, "deploy", "deployment", now);
            handoff.evidence_ceiling =
                vec!["deployment".to_string(), "launch_readiness".to_string()];
            handoff
        }

        fn verify(now: i64) -> Self {
            let mut handoff = Self::open(VERIFY_HANDOFF, "verify", "verification", now);
            handoff.evidence_ceiling = vec!["verification".to_string()];
            handoff.predecessor_digest = hex_chars('b');
            handoff
        }

        fn open(id: &str, operation: &str, ceiling: &str, now: i64) -> Self {
            Self {
                id: id.to_string(),
                project_node_id: PROJECT_NODE.to_string(),
                release_node_id: RELEASE_NODE.to_string(),
                operation: operation.to_string(),
                plugin_id: PLUGIN_ID.to_string(),
                stage: STAGE_DEPLOY.to_string(),
                attempt: 1,
                authority_epoch: 3,
                journey_revision: 4,
                state: "requested".to_string(),
                expires_at: format_timestamp(now + 3600).unwrap(),
                evidence_ceiling: vec![ceiling.to_string()],
                plan_digest: hex_chars('a'),
                predecessor_digest: hex_chars('b'),
                context_digest: hex_chars('c'),
                prerequisite_seal_sha256: hex_chars('d'),
                evidence: BTreeMap::new(),
                admission: None,
                admit_idempotency_key: None,
                consumed: false,
                result_body: None,
                result: None,
            }
        }

        fn json(&self) -> Value {
            let mut value = json!({
                "id": self.id,
                "project_node_id": self.project_node_id,
                "release_node_id": self.release_node_id,
                "stage": self.stage,
                "operation": self.operation,
                "plugin_id": self.plugin_id,
                "attempt": self.attempt,
                "authority_epoch": self.authority_epoch,
                "journey_revision": self.journey_revision,
                "state": self.state,
                "expires_at": self.expires_at,
                "evidence_ceiling": self.evidence_ceiling,
                "plan_digest": self.plan_digest,
                "predecessor_digest": self.predecessor_digest,
                "context_digest": self.context_digest,
                "prerequisite_seal_sha256": self.prerequisite_seal_sha256,
            });
            if let Some(result) = &self.result {
                value["result"] = result.clone();
            }
            value
        }
    }

    struct FakeInner {
        api_key: Vec<u8>,
        now: i64,
        handoffs: BTreeMap<String, FakeHandoff>,
        fail_next_post: bool,
        bump_seal_on_result: bool,
        corrupt_binding: bool,
        expire_admission: bool,
        get_status: Option<StatusCode>,
        approved_digest: String,
        drop_accepted_consume: bool,
        drop_accepted_admit: bool,
        drop_accepted_result: bool,
        drift_plan_on_next_get: bool,
        arm_lineage_drift: bool,
    }

    #[derive(Clone)]
    struct Captured {
        method: String,
        path: String,
        authorization: String,
        idempotency: String,
        body: Vec<u8>,
    }

    type RereadHook = Arc<Mutex<Option<Box<dyn Fn() + Send>>>>;

    #[derive(Clone)]
    struct FakeAeon {
        inner: Arc<Mutex<FakeInner>>,
        captures: Arc<Mutex<Vec<Captured>>>,
        reread_hook: RereadHook,
    }

    impl FakeAeon {
        fn new(now: i64) -> Self {
            Self {
                inner: Arc::new(Mutex::new(FakeInner {
                    api_key: API_KEY.to_vec(),
                    now,
                    handoffs: BTreeMap::from([
                        (DEPLOY_HANDOFF.to_string(), FakeHandoff::deploy(now)),
                        (VERIFY_HANDOFF.to_string(), FakeHandoff::verify(now)),
                    ]),
                    fail_next_post: false,
                    bump_seal_on_result: false,
                    corrupt_binding: false,
                    expire_admission: false,
                    get_status: None,
                    approved_digest: "1".repeat(64),
                    drop_accepted_consume: false,
                    drop_accepted_admit: false,
                    drop_accepted_result: false,
                    drift_plan_on_next_get: false,
                    arm_lineage_drift: false,
                })),
                captures: Arc::new(Mutex::new(Vec::new())),
                reread_hook: Arc::new(Mutex::new(None)),
            }
        }

        fn update<T>(&self, update: impl FnOnce(&mut FakeInner) -> T) -> T {
            let mut inner = self.inner.lock().expect("fake lock");
            update(&mut inner)
        }
    }

    fn json_response(status: StatusCode, value: &Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE.as_str(), JSON_MEDIA)
            .body(Body::from(serde_json::to_vec(value).unwrap()))
            .unwrap()
    }

    fn header_text(headers: &HeaderMap, name: &str) -> String {
        headers
            .get(name)
            .and_then(|value| value.to_str().ok())
            .unwrap_or("")
            .to_string()
    }

    fn authorized(inner: &FakeInner, header: &str) -> bool {
        header == format!("Bearer {}", String::from_utf8_lossy(&inner.api_key))
    }

    fn evidence_echo(body: &[u8], handoff_id: &str, received_at: &str) -> Value {
        let mut value: Value = serde_json::from_slice(body).unwrap_or(json!({}));
        if let Some(object) = value.as_object_mut() {
            object.insert("handoff_id".to_string(), json!(handoff_id));
            object.insert("received_at".to_string(), json!(received_at));
        }
        value
    }

    fn plain_token(value: &str, max: usize) -> bool {
        !value.is_empty()
            && value.len() <= max
            && value.trim() == value
            && value.chars().all(|ch| !ch.is_control())
    }

    fn launch_readiness_tokens(value: &Value) -> bool {
        value["reviewed_plan_digest"]
            .as_str()
            .is_some_and(valid_hex64)
            && plain_token(value["host"].as_str().unwrap_or(""), 256)
            && plain_token(value["running_kernel"].as_str().unwrap_or(""), 128)
            && plain_token(value["expected_kernel"].as_str().unwrap_or(""), 128)
    }

    fn observation_fresh(stamp: &str, now: i64) -> bool {
        let Ok(parsed) = parse_timestamp(stamp) else {
            return false;
        };
        let unix = parsed.unix_timestamp();
        now.saturating_sub(unix) <= 900 && unix <= now + 300
    }

    fn satisfying_readiness(body: &[u8], now: i64) -> Option<String> {
        let value: Value = serde_json::from_slice(body).ok()?;
        if value["kind"] != "launch_readiness" || value["outcome"] != "satisfied" {
            return None;
        }
        if value["all_host_eval_passed"] != true
            || value["target_build_passed"] != true
            || value["backup_ready"] != true
        {
            return None;
        }
        if !observation_fresh(value["observed_at"].as_str()?, now) {
            return None;
        }
        // A ready backup needs its own fresh success. A missing or stale
        // backup_observed_at does not satisfy the provider.
        if !value["backup_observed_at"]
            .as_str()
            .is_some_and(|stamp| observation_fresh(stamp, now))
        {
            return None;
        }
        value["reviewed_plan_digest"].as_str().map(str::to_string)
    }

    fn handle_evidence(handoff: &mut FakeHandoff, body: &[u8], now: i64) -> Response<Body> {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        };
        let Some(sequence) = value["sequence"].as_i64().filter(|sequence| *sequence >= 1) else {
            return json_response(StatusCode::CONFLICT, &json!({}));
        };
        if let Some(stored) = handoff.evidence.get(&sequence) {
            return if stored.body == body {
                json_response(
                    StatusCode::CREATED,
                    &evidence_echo(body, &handoff.id, &stored.received_at),
                )
            } else {
                json_response(StatusCode::CONFLICT, &json!({}))
            };
        }
        if value["authority_epoch"].as_i64() != Some(handoff.authority_epoch) {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        if value["kind"] == "launch_readiness" && !launch_readiness_tokens(&value) {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        }
        let received_at = format_timestamp(now).unwrap();
        let response = evidence_echo(body, &handoff.id, &received_at);
        handoff.evidence.insert(
            sequence,
            StoredEvidence {
                body: body.to_vec(),
                received_at,
            },
        );
        json_response(StatusCode::CREATED, &response)
    }

    fn handle_admit(flags: &AdmitFlags, handoff: &mut FakeHandoff, body: &[u8]) -> Response<Body> {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        };
        let Some(digest) = value["digest_sha256"].as_str() else {
            return json_response(StatusCode::CONFLICT, &json!({}));
        };
        if digest != flags.approved {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        let mut reviewed = None;
        let mut best_sequence = 0;
        for (sequence, evidence) in &handoff.evidence {
            if let Some(plan) = satisfying_readiness(&evidence.body, flags.now) {
                if *sequence >= best_sequence {
                    best_sequence = *sequence;
                    reviewed = Some(plan);
                }
            }
        }
        let Some(reviewed) = reviewed else {
            return json_response(StatusCode::CONFLICT, &json!({}));
        };
        let contradicted = handoff.evidence.iter().any(|(sequence, evidence)| {
            *sequence > best_sequence
                && serde_json::from_slice::<Value>(&evidence.body)
                    .ok()
                    .is_some_and(|value| value["kind"] == "launch_readiness")
                && satisfying_readiness(&evidence.body, flags.now).is_none()
        });
        if contradicted {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        if let Some(existing) = &handoff.admission {
            let expires_at = existing["expires_at"]
                .as_str()
                .and_then(|value| parse_timestamp(value).ok())
                .map(|time| time.unix_timestamp())
                .unwrap_or(0);
            let open = !handoff.consumed && expires_at > flags.now;
            if open && handoff.admit_idempotency_key.as_deref() == Some(flags.idempotency) {
                return json_response(StatusCode::OK, existing);
            }
            if open {
                return json_response(StatusCode::CONFLICT, &json!({}));
            }
        }
        let binding = if flags.corrupt {
            "0".repeat(64)
        } else {
            launch_binding_digest(
                digest,
                handoff.authority_epoch,
                &handoff.id,
                &handoff.release_node_id,
                &reviewed,
            )
            .unwrap_or_else(|_| "0".repeat(64))
        };
        let expires_at = if flags.expire {
            format_timestamp(flags.now - 120).unwrap()
        } else {
            handoff.expires_at.clone()
        };
        let admission = json!({
            "id": ADMISSION_ID,
            "handoff_id": handoff.id,
            "binding_digest_sha256": binding,
            "artifact_digest_sha256": digest,
            "authority_epoch": handoff.authority_epoch,
            "expires_at": expires_at,
        });
        handoff.admission = Some(admission.clone());
        handoff.admit_idempotency_key = Some(flags.idempotency.to_string());
        if flags.drop_response {
            return json_response(StatusCode::OK, &json!({}));
        }
        json_response(StatusCode::OK, &admission)
    }

    fn handle_consume(
        handoff: &mut FakeHandoff,
        body: &[u8],
        drop_response: bool,
    ) -> Response<Body> {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        };
        let Some(admission_id) = value["admission_id"].as_str() else {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        };
        let Some(admission) = &handoff.admission else {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        };
        if admission["id"] != admission_id {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        }
        if handoff.consumed {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        handoff.consumed = true;
        if drop_response {
            return json_response(StatusCode::OK, &json!({}));
        }
        json_response(
            StatusCode::OK,
            &json!({
                "handoff_id": handoff.id,
                "admission_id": admission_id,
                "consumed": true,
            }),
        )
    }

    fn handle_result(inner: &mut FakeInner, id: &str, body: &[u8]) -> Response<Body> {
        if inner.bump_seal_on_result {
            inner.bump_seal_on_result = false;
            if inner.arm_lineage_drift {
                inner.arm_lineage_drift = false;
                inner.drift_plan_on_next_get = true;
            }
            let Some(handoff) = inner.handoffs.get_mut(id) else {
                return json_response(StatusCode::NOT_FOUND, &json!({}));
            };
            handoff.prerequisite_seal_sha256 = hex_chars('f');
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        let now = inner.now;
        let drop_result = inner.drop_accepted_result;
        inner.drop_accepted_result = false;
        let Some(handoff) = inner.handoffs.get_mut(id) else {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        };
        if let Some(stored) = &handoff.result_body {
            return if stored == body {
                json_response(StatusCode::OK, handoff.result.as_ref().unwrap())
            } else {
                json_response(StatusCode::CONFLICT, &json!({}))
            };
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        };
        let last = handoff.evidence.keys().max().copied();
        if value["prerequisite_seal_sha256"].as_str()
            != Some(handoff.prerequisite_seal_sha256.as_str())
            || value["authority_epoch"].as_i64() != Some(handoff.authority_epoch)
            || value["terminal_sequence"].as_i64() != last
        {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        let response = json!({
            "outcome": value["outcome"],
            "terminal_sequence": value["terminal_sequence"],
            "authority_epoch": value["authority_epoch"],
            "prerequisite_seal_sha256": value["prerequisite_seal_sha256"],
            "handoff_id": handoff.id,
            "completed_at": format_timestamp(now).unwrap(),
        });
        handoff.result_body = Some(body.to_vec());
        handoff.result = Some(response.clone());
        if drop_result {
            return json_response(StatusCode::OK, &json!({}));
        }
        json_response(StatusCode::OK, &response)
    }

    fn dispatch(
        inner: &mut FakeInner,
        method: &str,
        path: &str,
        body: &[u8],
        idempotency: &str,
    ) -> Response<Body> {
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        if parts.len() < 3 || parts[0] != "api" || parts[1] != "stage-handoffs" {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        }
        let id = parts[2].to_string();
        if method == "GET" {
            if inner.drift_plan_on_next_get {
                inner.drift_plan_on_next_get = false;
                if let Some(handoff) = inner.handoffs.get_mut(&id) {
                    handoff.plan_digest = hex_chars('e');
                }
            }
            if let Some(status) = inner.get_status {
                return json_response(status, &json!({}));
            }
        }
        let route = (method, parts.get(3).copied(), parts.get(4).copied());
        if matches!(route, ("POST", Some("result"), None)) {
            return handle_result(inner, &id, body);
        }
        let now = inner.now;
        let corrupt = inner.corrupt_binding;
        let expire = inner.expire_admission;
        let approved = inner.approved_digest.clone();
        let drop_admit =
            matches!(route, ("POST", Some("launch"), Some("admit"))) && inner.drop_accepted_admit;
        let drop_consume = matches!(route, ("POST", Some("launch"), Some("consume")))
            && inner.drop_accepted_consume;
        if drop_admit {
            inner.drop_accepted_admit = false;
        }
        if drop_consume {
            inner.drop_accepted_consume = false;
        }
        let Some(handoff) = inner.handoffs.get_mut(&id) else {
            return json_response(StatusCode::NOT_FOUND, &json!({}));
        };
        match route {
            ("GET", None, None) => json_response(StatusCode::OK, &handoff.json()),
            ("POST", Some("evidence"), None) => handle_evidence(handoff, body, now),
            ("POST", Some("launch"), Some("admit")) => {
                let flags = AdmitFlags {
                    now,
                    corrupt,
                    expire,
                    approved,
                    idempotency,
                    drop_response: drop_admit,
                };
                handle_admit(&flags, handoff, body)
            }
            ("POST", Some("launch"), Some("consume")) => {
                handle_consume(handoff, body, drop_consume)
            }
            _ => json_response(StatusCode::NOT_FOUND, &json!({})),
        }
    }

    struct AdmitFlags<'a> {
        now: i64,
        corrupt: bool,
        expire: bool,
        approved: String,
        idempotency: &'a str,
        drop_response: bool,
    }

    async fn handler(State(fake): State<FakeAeon>, request: Request<Body>) -> Response<Body> {
        let method = request.method().as_str().to_string();
        let path = request.uri().path().to_string();
        let headers = request.headers().clone();
        let body = to_bytes(request.into_body(), MAX_RESPONSE_BYTES)
            .await
            .unwrap_or_default()
            .to_vec();
        let authorization = header_text(&headers, "authorization");
        fake.captures.lock().expect("captures").push(Captured {
            method: method.clone(),
            path: path.clone(),
            authorization: authorization.clone(),
            idempotency: header_text(&headers, "idempotency-key"),
            body: body.clone(),
        });
        let mut inner = fake.inner.lock().expect("fake lock");
        if !authorized(&inner, &authorization) {
            return json_response(StatusCode::UNAUTHORIZED, &json!({}));
        }
        if method == "POST" && inner.fail_next_post {
            inner.fail_next_post = false;
            return json_response(StatusCode::SERVICE_UNAVAILABLE, &json!({}));
        }
        let fire_reread = method == "GET"
            && inner
                .handoffs
                .values()
                .any(|handoff| path.contains(&handoff.id) && handoff.admission.is_some());
        drop(inner);
        if fire_reread {
            if let Some(hook) = fake.reread_hook.lock().expect("reread hook").take() {
                hook();
            }
        }
        let mut inner = fake.inner.lock().expect("fake lock");
        let idempotency = header_text(&headers, "idempotency-key");
        dispatch(&mut inner, &method, &path, &body, &idempotency)
    }

    async fn serve(fake: FakeAeon) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake Aeon");
        let port = listener.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            axum::serve(listener, Router::new().fallback(handler).with_state(fake))
                .await
                .unwrap();
        });
        (
            loopback_origin_for_tests(&format!("http://127.0.0.1:{port}/")),
            task,
        )
    }

    fn runtime_config(
        origin: Url,
        api_key_file: PathBuf,
        intents: Vec<DeliveryIntent>,
    ) -> AdapterConfig {
        AdapterConfig {
            aeon_origin: origin,
            api_key_file,
            aeon_ca_certificates: Vec::new(),
            poll_interval: Duration::from_secs(5),
            verification_freshness_secs: 900,
            intents,
        }
    }

    fn test_adapter(
        config: AdapterConfig,
        journal_path: PathBuf,
        hosts: Arc<Store>,
        actions: Arc<HostActionStore>,
    ) -> AeonDeliveryAdapter {
        let journal = JournalStore::new(journal_path).expect("test journal");
        let aeon = AeonClient::new(
            config.aeon_origin.clone(),
            config.api_key_file.clone(),
            &config.aeon_ca_certificates,
        )
        .expect("test Aeon client");
        AeonDeliveryAdapter {
            config,
            journal,
            aeon,
            hosts,
            host_actions: actions,
        }
    }

    fn ready_plan() -> HostActionPlan {
        HostActionPlan {
            changed_file_count: 2,
            changed_areas: vec!["flake.lock".to_string()],
            all_host_eval_passed: true,
            target_build_passed: true,
            backup_ready: true,
            running_kernel: Some("6.18.1".to_string()),
            expected_kernel: Some("6.18.2".to_string()),
            restart_required: true,
        }
    }

    fn review_job(store: &HostActionStore, job_id: &str, at: i64) {
        let review = store
            .claim("hsb8", at)
            .expect("claim review")
            .expect("review lease");
        store
            .record_agent_result(
                job_id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: review.phase,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                at,
            )
            .expect("record review");
    }

    fn fail_review(store: &HostActionStore, job_id: &str, at: i64) {
        let review = store
            .claim("hsb8", at)
            .expect("claim review")
            .expect("review lease");
        assert_eq!(review.id, job_id);
        store
            .record_agent_result(
                job_id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: review.phase,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                },
                at,
            )
            .expect("fail review");
    }

    fn finish_apply(store: &HostActionStore, job_id: &str, at: i64) {
        let apply = store
            .claim("hsb8", at)
            .expect("claim apply")
            .expect("apply lease");
        assert_eq!(apply.phase, AgentActionPhase::Apply);
        store
            .record_agent_result(
                job_id,
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
                at,
            )
            .expect("record apply");
    }

    fn measured(artifact: &ArtifactEvidence, observed_at: i64) -> DeployedArtifactEvidence {
        DeployedArtifactEvidence {
            schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
            version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
            environment: "production-eu1".to_string(),
            version_scheme: artifact.version_scheme,
            artifact_version: artifact.version.clone(),
            release_channel: artifact.release_channel.clone(),
            release_sequence: artifact.release_sequence,
            digest: artifact.digest.clone(),
            digest_class: ArtifactDigestClass::OciConfig,
            commit_digest: artifact.commit_digest.clone(),
            release_manifest_coordinate: artifact.release_manifest_coordinate.clone(),
            release_manifest_digest: artifact.release_manifest_digest.clone(),
            oci_index_digest: None,
            oci_manifest_digest: None,
            oci_config_digest: Some(artifact.digest.clone()),
            observed_at,
        }
    }

    fn record_beacon(store: &Store, observed_at: i64, artifact: &ArtifactEvidence) {
        record_host(store, observed_at, artifact, None);
    }

    fn record_backup(store: &Store, success_at: i64) {
        record_host(store, success_at, &artifact(), Some(success_at));
    }

    fn backup_success(success_at: i64) -> BackupObservation {
        BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: BackupEngine::Restic,
            state: BackupPostureState::Healthy,
            configured: BackupConfiguredState::Enabled,
            summary: "last backup succeeded".to_string(),
            target_label: None,
            repository_id: None,
            schedule: None,
            next_run_at: None,
            last_attempt_at: Some(success_at),
            last_attempt_state: Some(BackupRunState::Succeeded),
            last_success_at: Some(success_at),
            snapshot_count: Some(1),
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: None,
        }
    }

    fn record_host(
        store: &Store,
        observed_at: i64,
        artifact: &ArtifactEvidence,
        backup_success_at: Option<i64>,
    ) {
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
                            source_revision: artifact.commit_digest.clone(),
                            flake_lock_sha256: "1".repeat(64),
                            nixpkgs_revision: "b".repeat(40),
                            nixpkgs_last_modified: observed_at - 100,
                            nixpkgs_channel: "nixos-unstable".to_string(),
                        }),
                        ..Default::default()
                    },
                    kernel: None,
                    service_observations: vec![],
                    backup_observations: backup_success_at
                        .map(|at| vec![backup_success(at)])
                        .unwrap_or_default(),
                    inbound_rtt_ms: None,
                    location: None,
                    preferences: Default::default(),
                    deployed_artifact: Some(measured(artifact, observed_at)),
                },
                observed_at,
            )
            .expect("record host");
    }

    fn fake_now(fake: &FakeAeon) -> i64 {
        fake.update(|inner| inner.now)
    }

    fn completed_update(store: &HostActionStore, now: i64) -> String {
        let job = store
            .create_update_review("hsb8", "operator", now - 40)
            .expect("create update");
        review_job(store, &job.id, now - 39);
        store
            .confirm_update(&job.id, "hsb8", "operator", now - 38)
            .expect("confirm");
        finish_apply(store, &job.id, now - 30);
        job.id
    }

    struct Harness {
        fake: FakeAeon,
        server: tokio::task::JoinHandle<()>,
        adapter: AeonDeliveryAdapter,
        actions: Arc<HostActionStore>,
        hosts: Arc<Store>,
        journal: PathBuf,
        intent: DeliveryIntent,
        _directory: TestDir,
    }

    async fn harness(delegated: bool) -> Harness {
        let now = now_unix();
        let directory = TestDir::new("runtime");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let journal = directory
            .path()
            .join("hosts.json.aeon-delivery-journal.json");
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(delegated);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone(), verify_intent()]),
            journal.clone(),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        Harness {
            fake,
            server,
            adapter,
            actions,
            hosts,
            journal,
            intent,
            _directory: directory,
        }
    }

    fn posts(fake: &FakeAeon) -> Vec<Captured> {
        fake.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.method == "POST")
            .cloned()
            .collect()
    }

    fn assert_no_key(bytes: &[u8]) {
        assert!(!contains_slice(bytes, API_KEY));
    }

    #[tokio::test]
    async fn delegated_deploy_requires_launch_readiness_on_the_ceiling() {
        let fixture = harness(true).await;
        fixture.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .evidence_ceiling = vec!["deployment".to_string()];
        });
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Contract));
        assert!(fixture.actions.list().is_empty());
        fixture.server.abort();
    }

    #[tokio::test]
    async fn launch_readiness_posts_bare_digest_and_kernel_tokens() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake).await;
        let client = reqwest::Client::new();
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
            .unwrap();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let send = |body: Value| {
            let client = client.clone();
            let url = url.clone();
            let bearer = bearer.clone();
            async move {
                client
                    .post(url)
                    .header(AUTHORIZATION, bearer)
                    .header(CONTENT_TYPE, JSON_MEDIA)
                    .body(serde_json::to_vec(&body).unwrap())
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        let mut readiness = json!({
            "sequence": 1,
            "kind": "launch_readiness",
            "outcome": "satisfied",
            "observed_at": format_timestamp(now).unwrap(),
            "authority_epoch": 3,
            "reviewed_plan_digest": "ab".repeat(32),
            "host": "hsb8",
            "all_host_eval_passed": true,
            "target_build_passed": true,
            "backup_ready": true,
            "backup_observed_at": format_timestamp(now).unwrap(),
            "restart_required": true,
            "running_kernel": "6.18.1",
            "expected_kernel": "6.18.2"
        });
        readiness["reviewed_plan_digest"] = json!(format!("sha256:{}", "ab".repeat(32)));
        assert_eq!(send(readiness.clone()).await, StatusCode::BAD_REQUEST);
        readiness["reviewed_plan_digest"] = json!("ab".repeat(32));
        readiness["running_kernel"] = json!("");
        assert_eq!(send(readiness).await, StatusCode::BAD_REQUEST);
        server.abort();

        let fixture = harness(true).await;
        prepare_ready_launch(&fixture).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let posted: Value = posts(&fixture.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        let digest = posted["reviewed_plan_digest"].as_str().unwrap();
        assert!(valid_hex64(digest));
        assert_eq!(posted["running_kernel"], "6.18.1");
        assert_eq!(posted["expected_kernel"], "6.18.2");
        fixture.server.abort();

        let missing = harness(true).await;
        missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap();
        let job_id = missing.actions.list()[0].id.clone();
        let at = missing.actions.get(&job_id).unwrap().created_at;
        let review = missing
            .actions
            .claim("hsb8", at)
            .expect("claim")
            .expect("lease");
        let mut plan = ready_plan();
        plan.running_kernel = None;
        plan.expected_kernel = None;
        missing
            .actions
            .record_agent_result(
                &job_id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: review.phase,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(plan),
                    result: None,
                },
                at,
            )
            .expect("review without kernels");
        let error = missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LaunchUnresolved));
        let omitted: Value = posts(&missing.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(omitted["running_kernel"], "unknown");
        assert_eq!(omitted["expected_kernel"], "unknown");
        assert!(valid_hex64(
            omitted["reviewed_plan_digest"].as_str().unwrap()
        ));
        missing.server.abort();
    }

    #[tokio::test]
    async fn handoff_validation_refusals_do_not_bind() {
        for label in [
            "project",
            "release",
            "plugin",
            "operation",
            "ceiling",
            "expired",
        ] {
            let fixture = harness(false).await;
            let expired_at = format_timestamp(now_unix() - 60).unwrap();
            fixture.fake.update(|inner| {
                let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
                match label {
                    "project" => handoff.project_node_id = VERIFY_HANDOFF.to_string(),
                    "release" => handoff.release_node_id = PROJECT_NODE.to_string(),
                    "plugin" => handoff.plugin_id = "other".to_string(),
                    "operation" => handoff.operation = "verify".to_string(),
                    "ceiling" => handoff.evidence_ceiling = vec!["authorization".to_string()],
                    "expired" => handoff.expires_at = expired_at.clone(),
                    _ => unreachable!(),
                }
            });
            let error = fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .expect_err(label);
            assert!(
                matches!(error, AdapterError::Contract),
                "{label} yielded {error}"
            );
            assert!(fixture.actions.list().is_empty(), "{label} bound a job");
            fixture.server.abort();
        }

        let fixture = harness(false).await;
        fixture
            .fake
            .update(|inner| inner.get_status = Some(StatusCode::CONFLICT));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Refused(status) if status == StatusCode::CONFLICT));
        assert!(fixture.actions.list().is_empty());
        fixture
            .fake
            .update(|inner| inner.get_status = Some(StatusCode::UNAUTHORIZED));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Credential));
        fixture
            .fake
            .update(|inner| inner.get_status = Some(StatusCode::NOT_FOUND));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Refused(status) if status == StatusCode::NOT_FOUND));
        assert!(fixture.actions.list().is_empty());
        fixture.server.abort();
    }

    #[tokio::test]
    async fn requested_handoff_binds_one_job_and_replay_adopts_it() {
        let fixture = harness(false).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let jobs: Vec<_> = fixture
            .actions
            .list()
            .into_iter()
            .filter(|job| job.kind == HostActionKind::UpdateRestart)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].requested_by, ACTOR);
        assert_eq!(jobs[0].state, HostActionState::QueuedReview);
        assert_eq!(jobs[0].host, "hsb8");
        let job_id = jobs[0].id.clone();
        let again = test_adapter(
            runtime_config(
                fixture.adapter.config.aeon_origin.clone(),
                fixture.adapter.config.api_key_file.clone(),
                vec![fixture.intent.clone()],
            ),
            fixture.journal.clone(),
            Arc::clone(&fixture.hosts),
            Arc::clone(&fixture.actions),
        );
        again.process_intent(&fixture.intent).await.unwrap();
        assert_eq!(fixture.actions.list().len(), 1);
        assert_eq!(fixture.actions.list()[0].id, job_id);
        assert!(posts(&fixture.fake).is_empty());
        fixture.server.abort();
    }

    #[tokio::test]
    async fn delegated_launch_replays_exact_bytes_then_confirms_and_seals() {
        let fixture = harness(true).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let job_id = fixture.actions.list()[0].id.clone();
        let created = fixture.actions.get(&job_id).unwrap().created_at;
        review_job(&fixture.actions, &job_id, created);
        record_backup(&fixture.hosts, fake_now(&fixture.fake));
        fixture.fake.update(|inner| inner.fail_next_post = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let failed = posts(&fixture.fake);
        assert_eq!(failed.len(), 1);
        let journaled = fixture
            .adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::LaunchReadiness)
            .unwrap();
        assert_eq!(failed[0].body, journaled.body_json.as_bytes());

        for _ in 0..6 {
            fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap();
            if fixture.actions.get(&job_id).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::QueuedApply);
        let confirmation = job.events.last().unwrap();
        assert_eq!(confirmation.kind, HostActionEventKind::Confirmed);
        assert_eq!(confirmation.source, HostActionEventSource::Pharos);
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert_eq!(
            confirmation.actor.as_deref(),
            Some(launch.admission.as_ref().unwrap().id.as_str())
        );
        let readiness: Vec<_> = posts(&fixture.fake)
            .into_iter()
            .filter(|capture| {
                capture.path.ends_with("/evidence")
                    && serde_json::from_slice::<Value>(&capture.body).unwrap()["kind"]
                        == "launch_readiness"
            })
            .collect();
        assert!(readiness.len() >= 2);
        assert_eq!(readiness[0].body, readiness[1].body);
        assert_eq!(readiness[0].body, journaled.body_json.as_bytes());
        let admit = posts(&fixture.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/launch/admit"))
            .unwrap();
        assert_eq!(admit.body, launch.admit_body_json.as_bytes());
        let consumes: Vec<_> = posts(&fixture.fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/launch/consume"))
            .collect();
        assert_eq!(consumes.len(), 1);
        assert_eq!(
            consumes[0].body,
            launch.consume_body_json.as_deref().unwrap().as_bytes()
        );

        let confirmed_at = fixture.actions.get(&job_id).unwrap().updated_at;
        finish_apply(&fixture.actions, &job_id, confirmed_at + 1);
        record_beacon(&fixture.hosts, confirmed_at + 2, &artifact());
        for _ in 0..4 {
            fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap();
            if fixture
                .adapter
                .journal
                .result(DEPLOY_HANDOFF)
                .is_some_and(|record| record.receipt.is_some())
            {
                break;
            }
        }
        let result = fixture.adapter.journal.result(DEPLOY_HANDOFF).unwrap();
        assert_eq!(
            result.receipt.as_ref().unwrap().outcome,
            ResultOutcome::Succeeded
        );
        let deployment = fixture
            .adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::Deployment)
            .unwrap();
        assert_eq!(
            deployment.receipt.unwrap().outcome,
            EvidenceOutcome::Succeeded
        );
        assert_eq!(result.terminal_sequence, deployment.sequence);
        for capture in fixture.fake.captures.lock().unwrap().iter() {
            assert_no_key(&capture.body);
            assert!(!capture.path.contains("AEON_API_KEY_SENTINEL"));
            assert!(capture.authorization.starts_with("Bearer "));
            if capture.method == "POST" {
                assert_eq!(capture.idempotency.len(), 36);
            }
        }
        assert_no_key(&std::fs::read(&fixture.journal).unwrap());

        let client = reqwest::Client::new();
        let consume_url = fixture
            .adapter
            .config
            .aeon_origin
            .join(&format!(
                "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/consume"
            ))
            .unwrap();
        let second = client
            .post(consume_url)
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(launch.consume_body_json.clone().unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let saved = JournalStore::new(fixture.journal.clone()).unwrap();
        let saved_launch = saved.launch(DEPLOY_HANDOFF).unwrap();
        assert!(saved_launch.receipt.is_some());
        assert_eq!(saved_launch.consume_body_json, launch.consume_body_json);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn binding_digest_mismatch_and_expired_admission_do_not_consume() {
        for corrupt in [true, false] {
            let fixture = harness(true).await;
            fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap();
            let job_id = fixture.actions.list()[0].id.clone();
            review_job(
                &fixture.actions,
                &job_id,
                fixture.actions.get(&job_id).unwrap().created_at,
            );
            record_backup(&fixture.hosts, fake_now(&fixture.fake));
            fixture.fake.update(|inner| {
                inner.corrupt_binding = corrupt;
                inner.expire_admission = !corrupt;
            });
            let error = fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap_err();
            assert!(matches!(error, AdapterError::LocalBinding));
            assert_eq!(
                fixture.actions.get(&job_id).unwrap().state,
                HostActionState::AwaitingConfirmation
            );
            assert!(posts(&fixture.fake)
                .iter()
                .all(|capture| !capture.path.ends_with("/launch/consume")));
            fixture.server.abort();
        }
    }

    #[tokio::test]
    async fn stale_authority_conflict_leaves_the_job_untouched() {
        let fixture = harness(true).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let job_id = fixture.actions.list()[0].id.clone();
        review_job(
            &fixture.actions,
            &job_id,
            fixture.actions.get(&job_id).unwrap().created_at,
        );
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        fixture
            .fake
            .update(|inner| inner.get_status = Some(StatusCode::CONFLICT));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Refused(status) if status == StatusCode::CONFLICT));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert!(posts(&fixture.fake)
            .iter()
            .all(|capture| !capture.path.contains("/launch/")));
        fixture.server.abort();
    }

    #[tokio::test]
    async fn wrong_result_seal_is_retried_with_the_current_seal() {
        let now = now_unix();
        let directory = TestDir::new("seal");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| inner.bump_seal_on_result = true);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 10, &artifact());
        let mut intent = deploy_intent(false);
        intent.update_restart_job_id = Some(job_id.clone());
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            Arc::clone(&actions),
        );
        adapter.process_intent(&intent).await.unwrap();
        let results: Vec<_> = posts(&fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/result"))
            .collect();
        assert_eq!(results.len(), 2);
        let first: Value = serde_json::from_slice(&results[0].body).unwrap();
        let second: Value = serde_json::from_slice(&results[1].body).unwrap();
        assert_eq!(first["prerequisite_seal_sha256"], hex_chars('d'));
        assert_eq!(second["prerequisite_seal_sha256"], hex_chars('f'));
        assert_eq!(
            adapter
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .receipt
                .unwrap()
                .prerequisite_seal_sha256,
            hex_chars('f')
        );
        assert_eq!(
            actions.get(&job_id).unwrap().state,
            HostActionState::Succeeded
        );
        server.abort();
    }

    #[tokio::test]
    async fn result_seal_retry_refuses_lineage_drift() {
        let now = now_unix();
        let directory = TestDir::new("seal-drift");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| {
            inner.bump_seal_on_result = true;
            inner.arm_lineage_drift = true;
        });
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 10, &artifact());
        let mut intent = deploy_intent(false);
        intent.update_restart_job_id = Some(job_id);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            actions,
        );
        let error = adapter.process_intent(&intent).await.unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert_eq!(
            posts(&fake)
                .iter()
                .filter(|capture| capture.path.ends_with("/result"))
                .count(),
            1
        );
        assert!(adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_none());
        server.abort();
    }

    #[tokio::test]
    async fn verify_lineage_mismatch_is_refused() {
        let fixture = harness(false).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        fixture.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(VERIFY_HANDOFF)
                .unwrap()
                .predecessor_digest = hex_chars('e');
        });
        let error = fixture
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert!(posts(&fixture.fake)
            .iter()
            .all(|capture| !capture.path.contains(VERIFY_HANDOFF)));
        fixture.server.abort();
    }

    #[tokio::test]
    async fn retry_predecessor_follows_the_release_lineage() {
        let now = now_unix();
        let directory = TestDir::new("retry-lineage");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| {
            let mut other = FakeHandoff::deploy(now);
            other.id = OTHER_HANDOFF.to_string();
            other.release_node_id = OTHER_RELEASE.to_string();
            inner.handoffs.insert(OTHER_HANDOFF.to_string(), other);
            let mut next = FakeHandoff::deploy(now);
            next.id = NEW_HANDOFF.to_string();
            next.attempt = 2;
            next.plan_digest = hex_chars('e');
            next.predecessor_digest = hex_chars('a');
            inner.handoffs.insert(NEW_HANDOFF.to_string(), next);
        });
        let (origin, server) = serve(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let mut other_intent = deploy_intent(false);
        other_intent.handoff_id = OTHER_HANDOFF.to_string();
        other_intent.release_node_id = OTHER_RELEASE.to_string();
        let lineage_intent = deploy_intent(false);
        let mut next_intent = deploy_intent(false);
        next_intent.handoff_id = NEW_HANDOFF.to_string();
        next_intent.release_node_id = RELEASE_NODE.to_string();
        let adapter = test_adapter(
            runtime_config(
                origin,
                api,
                vec![
                    other_intent.clone(),
                    lineage_intent.clone(),
                    next_intent.clone(),
                ],
            ),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            Arc::clone(&actions),
        );

        adapter.process_intent(&other_intent).await.unwrap();
        let other_job = adapter.journal.operation(OTHER_HANDOFF).unwrap().job_id;
        actions
            .cancel_update_review(&other_job, "hsb8", "operator", now_unix())
            .expect("cancel the other release");
        let other_created = actions.get(&other_job).unwrap().created_at;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        while now_unix() <= other_created && std::time::Instant::now() < deadline {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(now_unix() > other_created);

        adapter.process_intent(&lineage_intent).await.unwrap();
        let lineage_job = adapter.journal.operation(DEPLOY_HANDOFF).unwrap().job_id;
        fail_review(&actions, &lineage_job, now_unix());
        adapter.process_intent(&next_intent).await.unwrap();
        let retried = adapter.journal.operation(NEW_HANDOFF).unwrap().job_id;
        assert_eq!(
            actions.get(&retried).unwrap().retry_of.as_deref(),
            Some(lineage_job.as_str())
        );
        assert_eq!(
            adapter
                .journal
                .operation(OTHER_HANDOFF)
                .unwrap()
                .release_node_id,
            OTHER_RELEASE
        );
        assert_ne!(other_job, lineage_job);
        server.abort();
    }

    #[tokio::test]
    async fn evidence_replay_is_idempotent_and_divergent_replay_conflicts() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let client = reqwest::Client::new();
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
            .unwrap();
        let body = serde_json::to_vec(&json!({
            "sequence": 1,
            "kind": "deployment",
            "outcome": "succeeded",
            "observed_at": format_timestamp(now).unwrap(),
            "authority_epoch": 3
        }))
        .unwrap();
        let send = |body: Vec<u8>| {
            let client = client.clone();
            let url = url.clone();
            async move {
                client
                    .post(url)
                    .header(
                        AUTHORIZATION,
                        format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
                    )
                    .header(CONTENT_TYPE, JSON_MEDIA)
                    .body(body)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(send(body.clone()).await, StatusCode::CREATED);
        assert_eq!(send(body.clone()).await, StatusCode::CREATED);
        let mut divergent: Value = serde_json::from_slice(&body).unwrap();
        divergent["outcome"] = json!("failed");
        assert_eq!(
            send(serde_json::to_vec(&divergent).unwrap()).await,
            StatusCode::CONFLICT
        );
        server.abort();
    }

    #[tokio::test]
    async fn concurrent_consume_lets_exactly_one_win() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let client = reqwest::Client::new();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let evidence = serde_json::to_vec(&json!({
            "sequence": 1,
            "kind": "launch_readiness",
            "outcome": "satisfied",
            "observed_at": format_timestamp(now).unwrap(),
            "authority_epoch": 3,
            "reviewed_plan_digest": "ab".repeat(32),
            "host": "hsb8",
            "all_host_eval_passed": true,
            "target_build_passed": true,
            "backup_ready": true,
            "backup_observed_at": format_timestamp(now).unwrap(),
            "restart_required": true,
            "running_kernel": "unknown",
            "expected_kernel": "unknown"
        }))
        .unwrap();
        let evidence_status = client
            .post(
                origin
                    .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
                    .unwrap(),
            )
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(evidence)
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(evidence_status, StatusCode::CREATED);
        let admit = serde_json::to_vec(&json!({
            "version_scheme": "legacy",
            "version": "1.2.3",
            "release_channel": "stable",
            "release_sequence": 123,
            "digest_sha256": "1".repeat(64),
            "commit_digest": "a".repeat(40),
            "manifest_coordinate": "ghcr:inspr-at/pharos/releases/1.2.3",
            "manifest_digest_sha256": "9".repeat(64)
        }))
        .unwrap();
        let admitted = client
            .post(
                origin
                    .join(&format!(
                        "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"
                    ))
                    .unwrap(),
            )
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(admit)
            .send()
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
        let consume_url = origin
            .join(&format!(
                "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/consume"
            ))
            .unwrap();
        let consume_body = serde_json::to_vec(&json!({"admission_id": ADMISSION_ID})).unwrap();
        let first = client
            .post(consume_url.clone())
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(consume_body.clone())
            .send();
        let second = client
            .post(consume_url)
            .header(AUTHORIZATION, bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(consume_body)
            .send();
        let (left, right) = tokio::join!(first, second);
        let mut statuses = [left.unwrap().status(), right.unwrap().status()];
        statuses.sort_by_key(|status| status.as_u16());
        assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
        server.abort();
    }

    fn post_count(fake: &FakeAeon, suffix: &str) -> usize {
        fake.captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.method == "POST" && capture.path.ends_with(suffix))
            .count()
    }

    #[tokio::test]
    async fn consume_crash_before_ack_marks_unresolved_and_leaves_the_job() {
        let fixture = harness(true).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let job_id = fixture.actions.list()[0].id.clone();
        review_job(
            &fixture.actions,
            &job_id,
            fixture.actions.get(&job_id).unwrap().created_at,
        );
        record_backup(&fixture.hosts, fake_now(&fixture.fake));
        fixture
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .consume_unresolved
            .is_none());
        let consumes_after_crash = post_count(&fixture.fake, "/launch/consume");
        let admits_after_crash = post_count(&fixture.fake, "/launch/admit");
        assert_eq!(consumes_after_crash, 1);

        let replay = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(replay, Err(AdapterError::LaunchUnresolved)));
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert_eq!(
            launch.consume_unresolved,
            Some(StatusCode::CONFLICT.as_u16())
        );
        assert!(launch.receipt.is_none());
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert!(fixture.actions.get(&job_id).unwrap().confirmed_at.is_none());
        assert_eq!(
            post_count(&fixture.fake, "/launch/consume"),
            consumes_after_crash + 1
        );
        assert_eq!(
            post_count(&fixture.fake, "/launch/admit"),
            admits_after_crash
        );

        let later = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(later, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(
            post_count(&fixture.fake, "/launch/consume"),
            consumes_after_crash + 1
        );
        assert_eq!(
            post_count(&fixture.fake, "/launch/admit"),
            admits_after_crash
        );
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        fixture.server.abort();
    }

    async fn prepare_ready_launch(fixture: &Harness) -> String {
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let job_id = fixture.actions.list()[0].id.clone();
        review_job(
            &fixture.actions,
            &job_id,
            fixture.actions.get(&job_id).unwrap().created_at,
        );
        record_backup(&fixture.hosts, fake_now(&fixture.fake));
        job_id
    }

    #[tokio::test]
    async fn admit_replay_same_key_recovers_and_different_key_is_unresolved() {
        let same = harness(true).await;
        let same_job = prepare_ready_launch(&same).await;
        same.fake.update(|inner| inner.drop_accepted_admit = true);
        assert!(same.adapter.process_intent(&same.intent).await.is_err());
        assert_eq!(post_count(&same.fake, "/launch/consume"), 0);
        assert_eq!(
            same.actions.get(&same_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        for _ in 0..4 {
            same.adapter.process_intent(&same.intent).await.unwrap();
            if same.actions.get(&same_job).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            same.actions.get(&same_job).unwrap().state,
            HostActionState::QueuedApply
        );
        assert_eq!(post_count(&same.fake, "/launch/consume"), 1);
        assert_eq!(post_count(&same.fake, "/launch/admit"), 2);
        let admit_keys: Vec<_> = same
            .fake
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.path.ends_with("/launch/admit"))
            .map(|capture| capture.idempotency.clone())
            .collect();
        assert_eq!(admit_keys.len(), 2);
        assert_eq!(admit_keys[0], admit_keys[1]);
        same.server.abort();

        let other = harness(true).await;
        let other_job = prepare_ready_launch(&other).await;
        other.fake.update(|inner| inner.drop_accepted_admit = true);
        assert!(other.adapter.process_intent(&other.intent).await.is_err());
        let admits_before = post_count(&other.fake, "/launch/admit");
        other.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .admit_idempotency_key = Some("different-admit-key".to_string());
        });
        let replay = other.adapter.process_intent(&other.intent).await;
        assert!(matches!(replay, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(post_count(&other.fake, "/launch/consume"), 0);
        assert_eq!(
            other.actions.get(&other_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert_eq!(
            other
                .adapter
                .journal
                .launch(DEPLOY_HANDOFF)
                .unwrap()
                .admit_unresolved,
            Some(StatusCode::CONFLICT.as_u16())
        );
        let later = other.adapter.process_intent(&other.intent).await;
        assert!(matches!(later, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(post_count(&other.fake, "/launch/admit"), admits_before + 1);
        assert_eq!(post_count(&other.fake, "/launch/consume"), 0);
        other.server.abort();
    }

    #[tokio::test]
    async fn cancelled_job_between_admit_and_consume_sends_no_consume() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let actions = Arc::clone(&fixture.actions);
        let cancel_id = job_id.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            actions
                .cancel_update_review(&cancel_id, "hsb8", "operator", now_unix())
                .expect("cancel between admit and consume");
        }));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), 0);
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::Cancelled
        );
        assert!(fixture.actions.get(&job_id).unwrap().confirmed_at.is_none());
        fixture.server.abort();
    }

    #[tokio::test]
    async fn missing_backup_observation_omits_the_clock_and_refuses_admit() {
        let missing = harness(true).await;
        missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap();
        let missing_job = missing.actions.list()[0].id.clone();
        review_job(
            &missing.actions,
            &missing_job,
            missing.actions.get(&missing_job).unwrap().created_at,
        );
        let error = missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LaunchUnresolved));
        let readiness: Value = posts(&missing.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(readiness["kind"], "launch_readiness");
        assert_eq!(readiness["backup_ready"], true);
        assert!(readiness.get("backup_observed_at").is_none());
        assert_eq!(post_count(&missing.fake, "/launch/admit"), 1);
        assert_eq!(post_count(&missing.fake, "/launch/consume"), 0);
        assert_eq!(
            missing
                .adapter
                .journal
                .launch(DEPLOY_HANDOFF)
                .unwrap()
                .admit_unresolved,
            Some(StatusCode::CONFLICT.as_u16())
        );
        assert_eq!(
            missing.actions.get(&missing_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        let later = missing.adapter.process_intent(&missing.intent).await;
        assert!(matches!(later, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(post_count(&missing.fake, "/launch/admit"), 1);
        missing.server.abort();

        let stale = harness(true).await;
        let stale_at = fake_now(&stale.fake) - 901;
        record_backup(&stale.hosts, stale_at);
        stale.adapter.process_intent(&stale.intent).await.unwrap();
        let stale_job = stale.actions.list()[0].id.clone();
        review_job(
            &stale.actions,
            &stale_job,
            stale.actions.get(&stale_job).unwrap().created_at,
        );
        let stale_error = stale
            .adapter
            .process_intent(&stale.intent)
            .await
            .unwrap_err();
        assert!(matches!(stale_error, AdapterError::LaunchUnresolved));
        let stale_body: Value = posts(&stale.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(
            stale_body["backup_observed_at"],
            format_timestamp(stale_at).unwrap()
        );
        assert_eq!(post_count(&stale.fake, "/launch/consume"), 0);
        assert_eq!(
            stale
                .adapter
                .journal
                .launch(DEPLOY_HANDOFF)
                .unwrap()
                .admit_unresolved,
            Some(StatusCode::CONFLICT.as_u16())
        );
        stale.server.abort();

        let present = harness(true).await;
        let present_job = prepare_ready_launch(&present).await;
        for _ in 0..4 {
            present
                .adapter
                .process_intent(&present.intent)
                .await
                .unwrap();
            if present.actions.get(&present_job).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            present.actions.get(&present_job).unwrap().state,
            HostActionState::QueuedApply
        );
        let admitted: Value = posts(&present.fake)
            .into_iter()
            .find(|capture| {
                capture.path.ends_with("/evidence")
                    && serde_json::from_slice::<Value>(&capture.body).unwrap()["kind"]
                        == "launch_readiness"
            })
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(
            admitted["backup_observed_at"],
            format_timestamp(fake_now(&present.fake)).unwrap()
        );
        assert_eq!(post_count(&present.fake, "/launch/consume"), 1);
        present.server.abort();
    }

    #[tokio::test]
    async fn result_replay_after_accepted_send_does_not_replace_the_journal() {
        let now = now_unix();
        let directory = TestDir::new("result-replay");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| inner.drop_accepted_result = true);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 10, &artifact());
        let mut intent = deploy_intent(false);
        intent.update_restart_job_id = Some(job_id);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            actions,
        );
        assert!(adapter.process_intent(&intent).await.is_err());
        let first = posts(&fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/result"))
            .unwrap();
        let journaled = adapter.journal.result(DEPLOY_HANDOFF).unwrap().body_json;
        assert_eq!(first.body, journaled.as_bytes());
        fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .prerequisite_seal_sha256 = hex_chars('f');
        });
        adapter.process_intent(&intent).await.unwrap();
        let result_posts: Vec<_> = posts(&fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/result"))
            .collect();
        assert_eq!(result_posts.len(), 2);
        assert_eq!(result_posts[0].body, result_posts[1].body);
        let saved = adapter.journal.result(DEPLOY_HANDOFF).unwrap();
        assert_eq!(saved.body_json, journaled);
        assert_eq!(
            saved.receipt.unwrap().prerequisite_seal_sha256,
            hex_chars('d')
        );
        server.abort();
    }
}
