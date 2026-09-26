//! Aeon stage-handoff delivery adapter (PHAROS-313).
//!
//! Selected only by `PHAROS_AEON_DELIVERY_CONFIG_FILE`. Classic Paimos delivery
//! stays on its own config and journal. This adapter reads an Aeon handoff,
//! binds one guarded `UpdateRestart` for a deploy intent. Every deploy intent
//! carries `delegated_launch`: readiness is posted, a one-use admission is
//! checked and consumed, and only then is that same job confirmed.

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
    HostActionEventKind, HostActionEventSource, HostActionJob, HostActionKind, HostActionPlan,
    HostActionState, HostActionStore, HostActionStoreError, HostWorkflowKind, UpdateRestartIntent,
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
pub(crate) const ACTOR: &str = "aeon-delivery";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_API_KEY_BYTES: u64 = 512;
const MIN_API_KEY_BYTES: usize = 32;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_INTENTS: usize = 128;
const MAX_JOURNAL_RECORDS: usize = MAX_INTENTS * 8;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const OBSERVED_AT_SKEW_SECS: i64 = 5 * 60;
const READINESS_REFRESH_SECS: i64 = 600;
#[cfg(test)]
const TRACE_EXCERPT_MAX_BYTES: usize = 300;
#[cfg(test)]
const REFLECTED_CREDENTIAL_MARKER: &str = "<body withheld: reflected credential>";
const BACKUP_FUTURE_SKEW_SECS: i64 = 5 * 60;
const LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING: &str = "backup_success_missing";
const LAUNCH_BLOCK_BACKUP_NOT_READY: &str = "backup_not_ready";
const LAUNCH_BLOCK_READINESS_PLAN_CHANGED: &str = "readiness_plan_changed";
const LAUNCH_BLOCK_READINESS_FLAG_FALSE: &str = "readiness_flag_false";
const LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED: &str = "delegated_launch_required";
const LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB: &str = "consumed_without_confirmable_job";
const LAUNCH_BLOCK_CONSUME_ABANDONED: &str = "consume_abandoned";
const LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED: &str = "confirmation_not_delegated";
const LAUNCH_BLOCK_ADMISSION_EXPIRED: &str = "admission_expired";
const LAUNCH_BLOCK_AUTHORITY_CLOSED: &str = "handoff_authority_closed";
const LAUNCH_BLOCK_LAUNCH_NOT_OWNED: &str = "launch_not_owned";
const LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED: &str = "configured_job_not_owned";

const LAUNCH_BLOCK_REASONS: &[&str] = &[
    LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING,
    LAUNCH_BLOCK_BACKUP_NOT_READY,
    LAUNCH_BLOCK_READINESS_PLAN_CHANGED,
    LAUNCH_BLOCK_READINESS_FLAG_FALSE,
    LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED,
    LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB,
    LAUNCH_BLOCK_CONSUME_ABANDONED,
    LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED,
    LAUNCH_BLOCK_ADMISSION_EXPIRED,
    LAUNCH_BLOCK_AUTHORITY_CLOSED,
    LAUNCH_BLOCK_LAUNCH_NOT_OWNED,
    LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED,
];

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
    LaunchBlocked(&'static str),
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
            Self::LaunchBlocked(reason) => reason,
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

    fn ceilings_allow(self, ceiling: &[EvidenceCeiling]) -> bool {
        match self {
            // Aeon accepts launch_readiness on a pharos deploy even when the
            // stored ceiling was written before that kind existed.
            Self::Deploy => ceiling.contains(&EvidenceCeiling::Deployment),
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
                        && self.delegated_launch.as_ref().is_some_and(|selection| {
                            selection.valid() && selection.target_ref == self.artifact.digest
                        })
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

/// Codes Aeon accepts on a stage result. Anything else is HTTP 400, and a
/// journaled body with that code would replay forever.
const AEON_BLOCKER_CODES: &[&str] = &[
    "dependency_pending",
    "dependency_failed",
    "reporter_stale",
    "external_waiting",
    "policy_refused",
];

fn blocker_code_wire(code: BlockerCode) -> &'static str {
    match code {
        BlockerCode::DependencyPending => "dependency_pending",
        BlockerCode::DependencyFailed => "dependency_failed",
        BlockerCode::ReporterStale => "reporter_stale",
        BlockerCode::ExternalWaiting => "external_waiting",
        BlockerCode::PolicyRefused => "policy_refused",
    }
}

fn require_accepted_blocker(code: BlockerCode) -> Result<(), AdapterError> {
    if AEON_BLOCKER_CODES.contains(&blocker_code_wire(code)) {
        Ok(())
    } else {
        Err(AdapterError::Contract)
    }
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
    #[serde(default)]
    admission: Option<HandoffAdmission>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HandoffAdmission {
    admission_id: String,
    epoch: i64,
    expires_at: String,
    #[serde(default)]
    consumed_at: Option<String>,
    #[serde(default)]
    consumed_by_principal_id: Option<String>,
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
            || !intent.operation.ceilings_allow(&self.evidence_ceiling)
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

    fn open_for_write(&self) -> Result<(), AdapterError> {
        if !self.state.is_open() || stamp_passed(&self.expires_at)? {
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
    consumed_at: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ConsumeReceipt {
    handoff_id: String,
    admission_id: String,
    consumed: bool,
    consumed_at: String,
    /// Set when the receipt was synthesised from GET because the consume replay
    /// was refused. The API key and principal id are not stored.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    reconciled_from_get: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ResultRequest {
    outcome: ResultOutcome,
    terminal_sequence: i64,
    authority_epoch: i64,
    prerequisite_seal_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    blocker_code: Option<BlockerCode>,
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

    fn from_handoff(result: &HandoffResult) -> Result<Self, AdapterError> {
        Self::from_response(&ResultResponse {
            outcome: result.outcome,
            terminal_sequence: result.terminal_sequence,
            authority_epoch: result.authority_epoch,
            prerequisite_seal_sha256: result.prerequisite_seal_sha256.clone(),
            blocker_code: result.blocker_code,
            handoff_id: result.handoff_id.clone(),
            completed_at: result.completed_at.clone(),
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
    /// Pharos reason token. Aeon rejects unknown result fields, so this stays
    /// off the posted bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
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
            detail: None,
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
                .detail
                .as_deref()
                .is_none_or(|detail| launch_block_reason(detail).is_some())
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchBlock {
    handoff_id: String,
    intent_digest: String,
    reason: String,
    #[serde(default)]
    terminal: bool,
}

impl LaunchBlock {
    fn valid(&self) -> bool {
        valid_uuid(&self.handoff_id)
            && valid_hex64(&self.intent_digest)
            && launch_block_reason(&self.reason).is_some()
    }
}

/// Same predicate as `HostActionJob::review_retryable`, which is private to
/// the host-action store. Failed, unconfirmed, and still without a plan or result.
fn review_retryable_job(job: &HostActionJob) -> bool {
    job.kind == HostActionKind::UpdateRestart
        && job.state == HostActionState::Failed
        && job.confirmed_at.is_none()
        && job.plan.is_none()
        && job.result.is_none()
}

/// `latest_update_for` is private. Rank updates the same way: created_at, then
/// updated_at, then id. `except_job_id` drops a job inserted before this check.
fn latest_update_id(
    actions: &HostActionStore,
    host: &str,
    except_job_id: Option<&str>,
) -> Option<String> {
    actions
        .list()
        .into_iter()
        .filter(|job| {
            job.kind == HostActionKind::UpdateRestart
                && job.host == host
                && except_job_id != Some(job.id.as_str())
        })
        .max_by(|left, right| {
            left.created_at
                .cmp(&right.created_at)
                .then_with(|| left.updated_at.cmp(&right.updated_at))
                .then_with(|| left.id.cmp(&right.id))
        })
        .map(|job| job.id)
}

/// A configured `update_restart_job_id` must already belong to this adapter.
/// Checked at startup, before the first poll, and again when the intent binds.
fn refuse_unowned_configured_jobs(
    config: &AdapterConfig,
    actions: &HostActionStore,
) -> Result<(), String> {
    for intent in &config.intents {
        let Some(job_id) = intent.update_restart_job_id.as_deref() else {
            continue;
        };
        let Some(job) = actions.get(job_id) else {
            return Err(format!(
                "Aeon delivery intent {} names update_restart_job_id {job_id}, which is not in the host action store",
                intent.handoff_id
            ));
        };
        if job.requested_by != ACTOR {
            return Err(format!(
                "Aeon delivery intent {} names update_restart_job_id {job_id} requested by {}, not {ACTOR}",
                intent.handoff_id, job.requested_by
            ));
        }
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(format!(
                "Aeon delivery intent {} names update_restart_job_id {job_id} for a different host or workflow",
                intent.handoff_id
            ));
        }
    }
    Ok(())
}

fn job_links_as_review_retry(
    actions: &HostActionStore,
    predecessor: &HostActionJob,
    except_job_id: Option<&str>,
) -> bool {
    review_retryable_job(predecessor)
        && latest_update_id(actions, &predecessor.host, except_job_id)
            .is_some_and(|id| id == predecessor.id)
}

fn launch_block_reason(token: &str) -> Option<&'static str> {
    LAUNCH_BLOCK_REASONS
        .iter()
        .copied()
        .find(|reason| *reason == token)
}

fn aeon_blocker_for_reason(reason: &str) -> Option<BlockerCode> {
    Some(match reason {
        LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING | LAUNCH_BLOCK_BACKUP_NOT_READY => {
            BlockerCode::ExternalWaiting
        }
        // A false flag after a posted readiness row is a local precondition,
        // not a refused plan. The same wait applies before the first row.
        LAUNCH_BLOCK_READINESS_FLAG_FALSE => BlockerCode::ExternalWaiting,
        LAUNCH_BLOCK_READINESS_PLAN_CHANGED
        | LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED
        | LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED
        | LAUNCH_BLOCK_LAUNCH_NOT_OWNED
        | LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED
        | LAUNCH_BLOCK_ADMISSION_EXPIRED => BlockerCode::PolicyRefused,
        LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB
        | LAUNCH_BLOCK_CONSUME_ABANDONED
        | LAUNCH_BLOCK_AUTHORITY_CLOSED => BlockerCode::DependencyFailed,
        _ => return None,
    })
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
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    launch_blocks: BTreeMap<String, LaunchBlock>,
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
            launch_blocks: BTreeMap::new(),
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
        let block_diverges = document
            .launch_blocks
            .get(&intent.handoff_id)
            .is_some_and(|block| {
                block.intent_digest != intent.binding_digest(origin).unwrap_or_default()
            });
        if records_diverge || result_diverges || launch_diverges || block_diverges {
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
        self.newest_evidence(handoff_id, kind)
    }

    fn newest_evidence(
        &self,
        handoff_id: &str,
        kind: EvidenceKind,
    ) -> Option<EvidenceJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .records
            .values()
            .filter(|record| record.handoff_id == handoff_id && record.kind == kind)
            .max_by_key(|record| record.sequence)
            .cloned()
    }

    fn oldest_evidence(
        &self,
        handoff_id: &str,
        kind: EvidenceKind,
    ) -> Option<EvidenceJournalRecord> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .records
            .values()
            .filter(|record| record.handoff_id == handoff_id && record.kind == kind)
            .min_by_key(|record| record.sequence)
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
        let candidates: Vec<_> = document
            .operations
            .values()
            .filter(|binding| {
                binding.handoff_id != intent.handoff_id
                    && binding.release_node_id == intent.release_node_id
                    && binding.workflow == intent.workflow.key()
                    && binding.host == intent.host
                    && binding.attempt < handoff.attempt
            })
            .cloned()
            .collect();
        let Some(best_attempt) = candidates.iter().map(|binding| binding.attempt).max() else {
            return Ok(None);
        };
        let mut chosen = candidates
            .into_iter()
            .filter(|binding| binding.attempt == best_attempt);
        let predecessor = chosen.next();
        if predecessor.is_some() && chosen.next().is_some() {
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

    fn launch_block(&self, handoff_id: &str) -> Option<LaunchBlock> {
        self.document
            .lock()
            .expect("Aeon delivery journal lock")
            .launch_blocks
            .get(handoff_id)
            .cloned()
    }

    fn record_launch_block(&self, block: LaunchBlock) -> Result<(), AdapterError> {
        if !block.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        if let Some(existing) = document.launch_blocks.get(&block.handoff_id) {
            if existing.terminal || existing == &block {
                return Ok(());
            }
        }
        if document.launch_blocks.len() >= MAX_INTENTS
            && !document.launch_blocks.contains_key(&block.handoff_id)
        {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated
            .launch_blocks
            .insert(block.handoff_id.clone(), block);
        persist_journal(&self.path, &mut document, updated)
    }

    fn clear_launch_block(&self, handoff_id: &str) -> Result<(), AdapterError> {
        let mut document = self.document.lock().expect("Aeon delivery journal lock");
        if document
            .launch_blocks
            .get(handoff_id)
            .is_none_or(|block| block.terminal)
        {
            return Ok(());
        }
        let mut updated = document.clone();
        updated.launch_blocks.remove(handoff_id);
        persist_journal(&self.path, &mut document, updated)
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
        && document.launch_blocks.len() <= MAX_INTENTS
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
        && document
            .launch_blocks
            .iter()
            .all(|(key, block)| key == &block.handoff_id && block.valid())
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

#[cfg(test)]
#[derive(Clone, Debug)]
struct RequestTrace {
    method: String,
    path: String,
    status: u16,
    request_id: Option<String>,
    error_excerpt: Option<String>,
}

struct AeonClient {
    origin: Url,
    api_key_file: PathBuf,
    client: reqwest::Client,
    #[cfg(test)]
    traces: Option<Arc<Mutex<Vec<RequestTrace>>>>,
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
            #[cfg(test)]
            traces: None,
        })
    }

    #[cfg(test)]
    fn enable_trace(&mut self, traces: Arc<Mutex<Vec<RequestTrace>>>) {
        self.traces = Some(traces);
    }

    #[cfg(test)]
    fn note_exchange(
        &self,
        method: &Method,
        path: &str,
        status: StatusCode,
        request_id: Option<String>,
        body: &[u8],
        credentials: &Credentials,
    ) {
        let Some(traces) = &self.traces else {
            return;
        };
        let path = path.split('?').next().unwrap_or(path);
        let error_excerpt = if status.is_success() {
            None
        } else {
            Some(trace_body_excerpt(body, credentials))
        };
        traces
            .lock()
            .expect("Aeon request trace lock")
            .push(RequestTrace {
                method: method.as_str().to_string(),
                path: path.to_string(),
                status: status.as_u16(),
                request_id,
                error_excerpt,
            });
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

    #[cfg(test)]
    async fn get_json(&self, path: &str) -> Result<serde_json::Value, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(Method::GET, path, None, None, &credentials)
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        serde_json::from_slice(&bytes).map_err(|_| AdapterError::Contract)
    }

    async fn get_principal(&self) -> Result<String, AdapterError> {
        let credentials = self.credentials()?;
        let (status, bytes) = self
            .exchange(Method::GET, "/api/me", None, None, &credentials)
            .await?;
        if status != StatusCode::OK {
            return Err(status_error(status));
        }
        let document: serde_json::Value =
            serde_json::from_slice(&bytes).map_err(|_| AdapterError::Contract)?;
        let id = document
            .get("principal")
            .and_then(|principal| principal.get("id"))
            .and_then(serde_json::Value::as_str)
            .ok_or(AdapterError::Contract)?;
        if !valid_uuid(id) {
            return Err(AdapterError::Contract);
        }
        Ok(id.to_string())
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
            || parse_timestamp(&response.consumed_at).is_err()
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
        #[cfg(test)]
        let method_name = method.clone();
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
        let status = response.status();
        // Every header is checked before any header value is copied. A reflected
        // key in x-request-id must not reach a trace, a panic, or the report.
        reject_reflected_headers(response.headers(), credentials)?;
        #[cfg(test)]
        let request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(str::to_string);
        if response.headers().contains_key(CONTENT_ENCODING) {
            #[cfg(test)]
            self.note_exchange(&method_name, path, status, request_id, &[], credentials);
            return Err(AdapterError::Contract);
        }
        let media_ok = response_media_json(response.headers());
        let bytes = match bounded_body(response).await {
            Ok(bytes) => bytes,
            Err(error) => {
                #[cfg(test)]
                self.note_exchange(&method_name, path, status, request_id, &[], credentials);
                return Err(error);
            }
        };
        #[cfg(test)]
        self.note_exchange(&method_name, path, status, request_id, &bytes, credentials);
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
    /// Principal id from GET /api/me. Memory only; the API key is never stored.
    principal_id: Mutex<Option<String>>,
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
        refuse_unowned_configured_jobs(&config, &host_actions)
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
            principal_id: Mutex::new(None),
        }))
    }

    pub(crate) fn spawn(self) {
        tokio::spawn(async move { self.run().await });
    }

    async fn run(self) {
        if let Err(error) = self.remember_principal().await {
            tracing::warn!(
                reason = error.code(),
                "Aeon principal was not loaded; consume reconciliation will retry"
            );
        }
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
        match self.replay_started_consume(intent).await {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(error) => return self.finish_blocked_confirmation(intent, error).await,
        }
        if let Err(error) = self.confirm_if_consumed(intent).await {
            return self.finish_blocked_confirmation(intent, error).await;
        }
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
            let pending = self
                .journal
                .result(&intent.handoff_id)
                .ok_or(AdapterError::Journal)?;
            if let Some(result) = handoff.result.as_ref() {
                if !handoff_result_matches(result, &pending.body_json, &intent.handoff_id) {
                    return Err(AdapterError::LocalBinding);
                }
                let receipt = ResultReceipt::from_handoff(result)?;
                self.journal.acknowledge_result(&pending, receipt)?;
                return Ok(());
            }
            if handoff.state.is_closed() {
                self.log_closed(&handoff);
            } else {
                handoff.open_for_write()?;
            }
            let request: ResultRequest = decode_strict(pending.body_json.as_bytes())?;
            return self
                .finish_result(
                    intent,
                    &handoff,
                    request.terminal_sequence,
                    request.outcome,
                    request.blocker_code,
                    pending.detail.as_deref(),
                )
                .await;
        }
        let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
        handoff.validate(intent)?;
        if handoff.state.is_closed() {
            self.log_closed(&handoff);
            return Ok(());
        }
        handoff.open_for_write()?;
        if intent.operation == Operation::Deploy {
            self.bind_deployment(intent, &handoff)?;
        }
        if let Err(error) = self.maybe_launch(intent, &handoff).await {
            if self
                .journal
                .launch_block(&intent.handoff_id)
                .is_some_and(|block| block.terminal)
            {
                self.maybe_report(intent, &handoff).await?;
            }
            return self.finish_blocked_confirmation(intent, error).await;
        }
        self.maybe_report(intent, &handoff).await
    }

    async fn finish_blocked_confirmation(
        &self,
        intent: &DeliveryIntent,
        error: AdapterError,
    ) -> Result<(), AdapterError> {
        // Crash recovery returns here before maybe_report. A later poll stops
        // at reject_terminal_block and lands here again, so this is the post.
        if let AdapterError::LaunchBlocked(reason) = error {
            if self
                .journal
                .launch_block(&intent.handoff_id)
                .is_some_and(|block| block.terminal && block.reason == reason)
            {
                self.report_terminal_launch_block(intent, reason).await?;
            }
            return Err(AdapterError::LaunchBlocked(reason));
        }
        Err(error)
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
        self.reject_terminal_block(&intent.handoff_id)?;
        let observed = self.aeon.get_handoff(&intent.handoff_id).await?;
        observed.validate(intent)?;
        let server_consumed_ours = observed.admission.as_ref().is_some_and(|admission| {
            admission.consumed_at.is_some()
                && launch
                    .admission
                    .as_ref()
                    .is_some_and(|stored| stored.id == admission.admission_id)
        });
        let job = self
            .host_actions
            .get(&launch.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        let confirmable = consume_job_confirmable(intent, &job, &launch.reviewed_plan_digest)?;
        if server_consumed_ours {
            tracing::debug!(
                handoff_id = %intent.handoff_id,
                "Aeon shows the journaled admission consumed; replaying that consume"
            );
            if !confirmable {
                return self
                    .replay_consume_without_confirming(
                        intent,
                        &launch,
                        LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB,
                    )
                    .await;
            }
        } else {
            // The consume has not committed. Re-check the handoff, the journaled
            // admission, and the job before sending it again.
            observed.open_for_write()?;
            let admission = launch.admission.as_ref().ok_or(AdapterError::Journal)?;
            // Consume accepts the admission only while expires_at is strictly
            // after now (launch.go). Truncating to the second closes a fraction
            // that is still valid.
            if stamp_reached(&admission.expires_at)? {
                return self
                    .block_launch(intent, LAUNCH_BLOCK_ADMISSION_EXPIRED, true)
                    .map(|_| true);
            }
            self.validate_admission(admission, intent, &observed, &launch.reviewed_plan_digest)?;
            if !confirmable {
                return self
                    .block_launch(intent, LAUNCH_BLOCK_CONSUME_ABANDONED, true)
                    .map(|_| true);
            }
            // A same-plan refresh is not a contradiction. An exact replay of a
            // consume that did commit still returns the stored receipt.
            self.refresh_readiness_for_consume(intent).await?;
        }
        let launch = self
            .journal
            .launch(&intent.handoff_id)
            .ok_or(AdapterError::Journal)?;
        match self.aeon.post_consume(&launch).await {
            Ok(response) => {
                let receipt = consume_receipt(&response)?;
                let launch = self
                    .journal
                    .acknowledge_consume(&intent.handoff_id, receipt)?;
                self.confirm_consumed(intent, &launch).await?;
                Ok(true)
            }
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT => {
                self.finish_consume_conflict(intent, &launch, true).await
            }
            Err(error) => Err(error),
        }
    }

    async fn confirm_if_consumed(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let Some(launch) = self.journal.launch(&intent.handoff_id) else {
            return Ok(());
        };
        if launch.receipt.is_none() {
            return Ok(());
        }
        self.reject_terminal_block(&intent.handoff_id)?;
        let job = self
            .host_actions
            .get(&launch.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.state == HostActionState::AwaitingConfirmation {
            return self.confirm_consumed(intent, &launch).await;
        }
        self.finish_confirmation(intent, &launch, "")
    }

    async fn report_terminal_launch_block(
        &self,
        intent: &DeliveryIntent,
        reason: &'static str,
    ) -> Result<(), AdapterError> {
        if self
            .journal
            .result(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_some())
        {
            return Ok(());
        }
        let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
        handoff.validate(intent)?;
        if stamp_passed(&handoff.expires_at)? || handoff.result.is_some() {
            return Ok(());
        }
        if reason == LAUNCH_BLOCK_ADMISSION_EXPIRED {
            return self.report_admission_expired(intent).await;
        }
        let blocker = aeon_blocker_for_reason(reason).ok_or(AdapterError::Journal)?;
        self.write_observation(
            intent,
            &handoff,
            EvidenceOutcome::Failed,
            now_unix(),
            Some(blocker),
            Some(reason),
        )
        .await
    }

    async fn report_admission_expired(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        if self
            .journal
            .result(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_some())
        {
            return Ok(());
        }
        let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
        handoff.validate(intent)?;
        // Aeon current() is false only once now is strictly after expires_at
        // (store.go). A later result is 409 and must not be journaled. The
        // admission expiry equals the handoff and a second admit is refused
        // (launch.go), so the code is always policy_refused.
        if !handoff.state.is_open() || stamp_passed(&handoff.expires_at)? {
            return Ok(());
        }
        self.write_observation(
            intent,
            &handoff,
            EvidenceOutcome::Failed,
            now_unix(),
            Some(BlockerCode::PolicyRefused),
            Some(LAUNCH_BLOCK_ADMISSION_EXPIRED),
        )
        .await
    }

    async fn confirm_consumed(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
    ) -> Result<(), AdapterError> {
        let handoff = self.aeon.get_handoff(&intent.handoff_id).await?;
        handoff.validate(intent)?;
        self.require_open_authority(intent, launch, &handoff)?;
        self.finish_confirmation(intent, launch, &handoff.expires_at)
    }

    fn require_open_authority(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
        handoff: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        let operation = self
            .journal
            .operation(&intent.handoff_id)
            .ok_or(AdapterError::LocalBinding)?;
        let admission = launch.admission.as_ref().ok_or(AdapterError::Journal)?;
        let current = handoff.state.is_open()
            && handoff.authority_epoch == admission.authority_epoch
            && handoff.release_node_id == operation.release_node_id
            && handoff.operation == intent.operation
            && handoff.attempt == operation.attempt;
        if current {
            return Ok(());
        }
        self.block_launch(intent, LAUNCH_BLOCK_AUTHORITY_CLOSED, true)
    }

    fn reject_terminal_block(&self, handoff_id: &str) -> Result<(), AdapterError> {
        let Some(block) = self.journal.launch_block(handoff_id) else {
            return Ok(());
        };
        if !block.terminal {
            return Ok(());
        }
        let reason = launch_block_reason(&block.reason).ok_or(AdapterError::Journal)?;
        Err(AdapterError::LaunchBlocked(reason))
    }

    async fn replay_consume_without_confirming(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
        reason: &'static str,
    ) -> Result<bool, AdapterError> {
        match self.aeon.post_consume(launch).await {
            Ok(response) => {
                let receipt = consume_receipt(&response)?;
                self.journal
                    .acknowledge_consume(&intent.handoff_id, receipt)?;
                self.block_launch(intent, reason, true).map(|_| true)
            }
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT => {
                self.finish_consume_conflict(intent, launch, false).await
            }
            Err(error) => Err(error),
        }
    }

    async fn remember_principal(&self) -> Result<(), AdapterError> {
        if self.principal_id.lock().expect("aeon principal").is_some() {
            return Ok(());
        }
        let id = self.aeon.get_principal().await?;
        *self.principal_id.lock().expect("aeon principal") = Some(id);
        Ok(())
    }

    async fn finish_consume_conflict(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
        confirm: bool,
    ) -> Result<bool, AdapterError> {
        let Some(receipt) = self.receipt_reconciled_from_handoff(intent, launch).await? else {
            self.journal
                .mark_consume_unresolved(&intent.handoff_id, StatusCode::CONFLICT)?;
            return Err(AdapterError::LaunchUnresolved);
        };
        self.journal
            .acknowledge_consume(&intent.handoff_id, receipt)?;
        if !confirm {
            return self
                .block_launch(intent, LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB, true)
                .map(|_| true);
        }
        let launch = self
            .journal
            .launch(&intent.handoff_id)
            .ok_or(AdapterError::Journal)?;
        self.confirm_consumed(intent, &launch).await?;
        Ok(true)
    }

    async fn receipt_reconciled_from_handoff(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
    ) -> Result<Option<ConsumeReceipt>, AdapterError> {
        let observed = self.aeon.get_handoff(&intent.handoff_id).await?;
        let Some(admission) = observed.admission.as_ref() else {
            return Ok(None);
        };
        let Some(stored) = launch.admission.as_ref() else {
            return Ok(None);
        };
        let Some(consumed_at) = admission.consumed_at.as_deref() else {
            return Ok(None);
        };
        if admission.admission_id != stored.id || parse_timestamp(consumed_at).is_err() {
            return Ok(None);
        }
        self.remember_principal().await?;
        let principal = self
            .principal_id
            .lock()
            .expect("aeon principal")
            .clone()
            .ok_or(AdapterError::Contract)?;
        if admission.consumed_by_principal_id.as_deref() != Some(principal.as_str()) {
            return Ok(None);
        }
        Ok(Some(ConsumeReceipt {
            handoff_id: intent.handoff_id.clone(),
            admission_id: stored.id.clone(),
            consumed: true,
            consumed_at: consumed_at.to_string(),
            reconciled_from_get: true,
        }))
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
            // An operator-owned job can be confirmed through the operator route.
            // Binding it here would let that confirmation apply before any admission.
            if job.requested_by != ACTOR {
                return self.block_launch(intent, LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED, true);
            }
            configured.to_string()
        } else {
            let job_id = deterministic_job_id(&intent.host, &operation_id)?;
            let predecessor = self.journal.retry_predecessor(intent, handoff)?;
            // retry_update_review only accepts a review-retryable predecessor
            // that is still this host's latest update. A cancelled or succeeded
            // predecessor, or one an operator already retried, takes a fresh review.
            let job = if let Some(binding) = predecessor.as_ref().filter(|binding| {
                self.host_actions
                    .get(&binding.job_id)
                    .is_some_and(|job| job_links_as_review_retry(&self.host_actions, &job, None))
            }) {
                self.host_actions.retry_update_review_with_id(
                    &binding.job_id,
                    &job_id,
                    &intent.host,
                    ACTOR,
                    now_unix(),
                )
            } else {
                self.host_actions.ensure_update_review_with_id(
                    &job_id,
                    &intent.host,
                    ACTOR,
                    UpdateRestartIntent::Update,
                    now_unix(),
                )
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
        if intent.update_restart_job_id.is_some() && job.requested_by != ACTOR {
            return self.block_launch(intent, LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED, true);
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
        // The new job is already inserted, so it is the latest update. Compare
        // the predecessor with every other update on the host.
        let linked_to = predecessor.as_ref().and_then(|binding| {
            let previous = self.host_actions.get(&binding.job_id)?;
            job_links_as_review_retry(&self.host_actions, &previous, Some(job.id.as_str()))
                .then(|| binding.job_id.clone())
        });
        if job.host != intent.host
            || job.workflow_kind() != HostWorkflowKind::UpdateRestart
            || job.update_restart_intent() != UpdateRestartIntent::Update
            || job.requested_by != ACTOR
            || job.retry_of != linked_to
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
        if intent.operation != Operation::Deploy {
            return Ok(());
        }
        if intent.delegated_launch.is_none() {
            return self.refuse_undelegated_launch(intent);
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
        if let Some(block) = self.journal.launch_block(&intent.handoff_id) {
            if block.terminal {
                let reason = launch_block_reason(&block.reason).ok_or(AdapterError::Journal)?;
                return Err(AdapterError::LaunchBlocked(reason));
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
        if let Some(reason) = self.readiness_contradiction(intent, &job)? {
            return self.block_launch(intent, reason, true);
        }
        if job.host == intent.host
            && job.workflow_kind() == HostWorkflowKind::UpdateRestart
            && job.state == HostActionState::AwaitingConfirmation
            && job.plan.as_ref().is_some_and(|plan| !plan.backup_ready)
        {
            return self.block_launch(intent, LAUNCH_BLOCK_BACKUP_NOT_READY, false);
        }
        if !awaiting_ready_review(&job, &intent.host) {
            return Ok(());
        }
        let reviewed = reviewed_plan_digest(&job).map_err(map_shared)?;
        self.send_readiness(intent, handoff, &operation.job_id, &reviewed)
            .await?;
        let launch = self
            .ensure_admission(intent, handoff, &operation.job_id, &reviewed)
            .await?;
        let admission = launch.admission.clone().ok_or(AdapterError::Journal)?;
        if stamp_reached(&admission.expires_at)? {
            return self.block_launch(intent, LAUNCH_BLOCK_ADMISSION_EXPIRED, true);
        }
        self.validate_admission(&admission, intent, handoff, &reviewed)?;
        let fresh = self.aeon.get_handoff(&intent.handoff_id).await?;
        fresh.validate(intent)?;
        fresh.open_for_write()?;
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
        self.validate_admission(&admission, intent, &fresh, &reviewed)?;
        self.consume_and_confirm(intent).await
    }

    fn refuse_undelegated_launch(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let Some(operation) = self.journal.operation(&intent.handoff_id) else {
            return Ok(());
        };
        let Some(job) = self.host_actions.get(&operation.job_id) else {
            return Ok(());
        };
        if job.host != intent.host
            || job.workflow_kind() != HostWorkflowKind::UpdateRestart
            || job.state != HostActionState::AwaitingConfirmation
        {
            return Ok(());
        }
        self.block_launch(intent, LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED, true)
    }

    fn block_launch(
        &self,
        intent: &DeliveryIntent,
        reason: &'static str,
        terminal: bool,
    ) -> Result<(), AdapterError> {
        self.journal.record_launch_block(LaunchBlock {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(&self.config.aeon_origin)?,
            reason: reason.to_string(),
            terminal,
        })?;
        Err(AdapterError::LaunchBlocked(reason))
    }

    fn readiness_contradiction(
        &self,
        intent: &DeliveryIntent,
        job: &HostActionJob,
    ) -> Result<Option<&'static str>, AdapterError> {
        let Some(anchor) = self
            .journal
            .oldest_evidence(&intent.handoff_id, EvidenceKind::LaunchReadiness)
        else {
            return Ok(None);
        };
        if anchor.receipt.is_none() {
            return Ok(None);
        }
        let body: serde_json::Value = decode_strict(anchor.body_json.as_bytes())?;
        let anchor_digest = body
            .get("reviewed_plan_digest")
            .and_then(serde_json::Value::as_str)
            .ok_or(AdapterError::Contract)?;
        let flags_true = job.plan.as_ref().is_some_and(|plan| {
            plan.all_host_eval_passed && plan.target_build_passed && plan.backup_ready
        }) && evidence_flag_true(&body, "all_host_eval_passed")
            && evidence_flag_true(&body, "target_build_passed")
            && evidence_flag_true(&body, "backup_ready");
        if !flags_true {
            return Ok(Some(LAUNCH_BLOCK_READINESS_FLAG_FALSE));
        }
        let current = bare_plan_digest(&reviewed_plan_digest(job).map_err(map_shared)?)?;
        if current != anchor_digest {
            return Ok(Some(LAUNCH_BLOCK_READINESS_PLAN_CHANGED));
        }
        Ok(None)
    }

    fn withhold_unusable_readiness(
        &self,
        intent: &DeliveryIntent,
        job_id: &str,
    ) -> Result<(), AdapterError> {
        let job = self
            .host_actions
            .get(job_id)
            .ok_or(AdapterError::LocalBinding)?;
        let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
        let backup_at = backup_observed_at(&self.hosts, &intent.host);
        if let Some(reason) = readiness_wait_reason(plan, backup_at.as_deref(), now_unix()) {
            return self.block_launch(intent, reason, false);
        }
        self.journal.clear_launch_block(&intent.handoff_id)
    }

    async fn refresh_readiness_for_consume(
        &self,
        intent: &DeliveryIntent,
    ) -> Result<(), AdapterError> {
        let Some(existing) = self
            .journal
            .evidence_with_kind(&intent.handoff_id, EvidenceKind::LaunchReadiness)
        else {
            return Err(AdapterError::Journal);
        };
        if existing.receipt.is_none() {
            self.replay_evidence(intent, &existing).await?;
        }
        let current = self
            .journal
            .evidence_with_kind(&intent.handoff_id, EvidenceKind::LaunchReadiness)
            .ok_or(AdapterError::Journal)?;
        let observed = evidence_string_field(&current.body_json, "observed_at")?;
        if now_unix().saturating_sub(unix_of(&observed)?) <= READINESS_REFRESH_SECS {
            return Ok(());
        }
        let now = now_unix();
        let observed_at = format_timestamp(now)?;
        let sequence = self.journal.next_sequence(&intent.handoff_id)?;
        let launch = self
            .journal
            .launch(&intent.handoff_id)
            .ok_or(AdapterError::Journal)?;
        let job = self
            .host_actions
            .get(&launch.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
        let host = self.hosts.get(&intent.host);
        let backup_at = backup_stamp(host.as_ref());
        let posted_backup = match validated_readiness_backup(plan, backup_at.as_deref(), now) {
            Ok(stamp) => stamp.to_string(),
            Err(reason) => return self.block_launch(intent, reason, false),
        };
        let reviewed = bare_plan_digest(&reviewed_plan_digest(&job).map_err(map_shared)?)?;
        let mut value: serde_json::Value = decode_strict(&readiness_refresh_candidate(
            &current.body_json,
            sequence,
            &observed_at,
            &reviewed,
            plan,
        )?)?;
        value.as_object_mut().ok_or(AdapterError::Contract)?.insert(
            "backup_observed_at".to_string(),
            serde_json::Value::String(posted_backup),
        );
        let body = serde_json::to_vec(&value).map_err(|_| AdapterError::Contract)?;
        self.journal.clear_launch_block(&intent.handoff_id)?;
        if let Some(reason) = refresh_refusal(&current.body_json, &body)? {
            return self.block_launch(intent, reason, true);
        }
        let record = self.journal.ensure_evidence(EvidenceJournalRecord::new(
            intent,
            &self.config.aeon_origin,
            sequence,
            EvidenceKind::LaunchReadiness,
            &body,
        )?)?;
        let receipt = self.aeon.post_evidence(&record).await?;
        self.journal.acknowledge_evidence(&record, receipt)
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
                return self.block_launch(intent, LAUNCH_BLOCK_READINESS_PLAN_CHANGED, true);
            }
            let observed = evidence_string_field(&current.body_json, "observed_at")?;
            self.withhold_unusable_readiness(intent, job_id)?;
            if now_unix().saturating_sub(unix_of(&observed)?) <= READINESS_REFRESH_SECS {
                return Ok(());
            }
            let observed_at = format_timestamp(now_unix())?;
            let sequence = self.journal.next_sequence(&intent.handoff_id)?;
            let job = self
                .host_actions
                .get(job_id)
                .ok_or(AdapterError::LocalBinding)?;
            let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
            let body = readiness_refresh_candidate(
                &current.body_json,
                sequence,
                &observed_at,
                &bare_plan_digest(reviewed)?,
                plan,
            )?;
            if let Some(reason) = refresh_refusal(&current.body_json, &body)? {
                return self.block_launch(intent, reason, true);
            }
            let record = self.journal.ensure_evidence(EvidenceJournalRecord::new(
                intent,
                &self.config.aeon_origin,
                sequence,
                EvidenceKind::LaunchReadiness,
                &body,
            )?)?;
            let receipt = self.aeon.post_evidence(&record).await?;
            self.journal.acknowledge_evidence(&record, receipt)?;
            return Ok(());
        }
        let job = self
            .host_actions
            .get(job_id)
            .ok_or(AdapterError::LocalBinding)?;
        let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
        let now = now_unix();
        let observed_at = format_timestamp(now)?;
        let bare_reviewed = bare_plan_digest(reviewed)?;
        // One host snapshot feeds both the gate and the posted stamp. A second
        // read could omit backup_observed_at after the gate had passed.
        let host = self.hosts.get(&intent.host);
        let backup_at = backup_stamp(host.as_ref());
        let posted_backup = match validated_readiness_backup(plan, backup_at.as_deref(), now) {
            Ok(stamp) => stamp.to_string(),
            Err(reason) => return self.block_launch(intent, reason, false),
        };
        self.journal.clear_launch_block(&intent.handoff_id)?;
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
            backup_observed_at: Some(posted_backup.as_str()),
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
        handoff: &HandoffDocument,
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
            return self
                .replay_admit(intent, handoff, &existing, reviewed)
                .await;
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
        self.replay_admit(intent, handoff, &record, reviewed).await
    }

    async fn replay_admit(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        record: &LaunchJournalRecord,
        reviewed: &str,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        if record.consume_started {
            return Err(AdapterError::LaunchUnresolved);
        }
        match self.aeon.post_admit(record).await {
            Ok(admission) => {
                self.validate_admission(&admission, intent, handoff, reviewed)?;
                self.journal.store_admission(&intent.handoff_id, admission)
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
    ) -> Result<(), AdapterError> {
        let artifact_digest = strip_sha256(&intent.artifact.digest)?;
        let expected = launch_binding_digest(
            &artifact_digest,
            handoff.authority_epoch,
            &intent.handoff_id,
            &intent.release_node_id,
            reviewed,
        )?;
        let expires_at = timestamp_nanos(&admission.expires_at)?;
        let handoff_expires = timestamp_nanos(&handoff.expires_at)?;
        if !valid_uuid(&admission.id)
            || admission.handoff_id != intent.handoff_id
            || admission.artifact_digest_sha256 != artifact_digest
            || admission.authority_epoch != handoff.authority_epoch
            || admission.binding_digest_sha256 != expected
            || admission.consumed_at.is_some()
            || now_nanos() >= expires_at
            || expires_at > handoff_expires
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
    }

    async fn consume_and_confirm(&self, intent: &DeliveryIntent) -> Result<(), AdapterError> {
        let launch = self.journal.mark_consume_started(&intent.handoff_id)?;
        let response = self.aeon.post_consume(&launch).await?;
        let receipt = consume_receipt(&response)?;
        let launch = self
            .journal
            .acknowledge_consume(&intent.handoff_id, receipt)?;
        self.confirm_consumed(intent, &launch).await
    }

    fn finish_confirmation(
        &self,
        intent: &DeliveryIntent,
        launch: &LaunchJournalRecord,
        handoff_expires_at: &str,
    ) -> Result<(), AdapterError> {
        if launch.receipt.is_none() {
            return Err(AdapterError::Journal);
        }
        let admission = launch.admission.as_ref().ok_or(AdapterError::Journal)?;
        let job = self
            .host_actions
            .get(&launch.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        if job.requested_by != ACTOR {
            return self.block_launch(intent, LAUNCH_BLOCK_LAUNCH_NOT_OWNED, true);
        }
        if reviewed_plan_digest(&job).map_err(map_shared)? != launch.reviewed_plan_digest {
            return Err(AdapterError::LocalBinding);
        }
        if job.state == HostActionState::AwaitingConfirmation {
            if stamp_reached(&admission.expires_at)? || stamp_reached(handoff_expires_at)? {
                return self.block_launch(intent, LAUNCH_BLOCK_ADMISSION_EXPIRED, true);
            }
            let now = now_unix();
            // Aeon's consumed_at stays in the journal. The host job clock is
            // local, and never earlier than the review that produced this job.
            let confirmed_at = now.max(job.updated_at);
            self.host_actions
                .confirm_update_delegated(&launch.job_id, &intent.host, &admission.id, confirmed_at)
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
            if confirmation_is_delegated(&job, &admission.id) {
                return Ok(());
            }
            return self.block_launch(intent, LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED, true);
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
        if let Some(block) = self.journal.launch_block(&intent.handoff_id) {
            if block.terminal {
                let reason = launch_block_reason(&block.reason).ok_or(AdapterError::Journal)?;
                return self.report_terminal_launch_block(intent, reason).await;
            }
        }
        match job.state {
            HostActionState::Failed | HostActionState::Cancelled => {
                let detail = self
                    .journal
                    .launch_block(&intent.handoff_id)
                    .map(|block| block.reason);
                let blocker = detail
                    .as_deref()
                    .and_then(aeon_blocker_for_reason)
                    .unwrap_or(BlockerCode::DependencyFailed);
                // Aeon rejects evidence observed more than a minute before the
                // handoff was created (report.go). The job clock can be older
                // than that, and a 409 on those bytes would replay forever.
                self.write_observation(
                    intent,
                    handoff,
                    EvidenceOutcome::Failed,
                    now_unix(),
                    Some(blocker),
                    detail.as_deref(),
                )
                .await
            }
            HostActionState::Succeeded => {
                if job.confirmed_at.is_none() || job.result.is_none() {
                    return Err(AdapterError::LocalBinding);
                }
                let host = self.hosts.get(&intent.host);
                let now = now_unix();
                let observed = observed_fresh_config_beacon(
                    host.as_ref(),
                    &intent.environment,
                    &intent.artifact,
                    job.updated_at,
                    now,
                    self.config.verification_freshness_secs,
                )
                .map_err(map_shared)?;
                let Some(observed_at) = observed else {
                    if beacon_window_closed(
                        job.updated_at,
                        now,
                        self.config.verification_freshness_secs,
                    ) {
                        return self
                            .write_observation(
                                intent,
                                handoff,
                                EvidenceOutcome::Failed,
                                now,
                                Some(BlockerCode::ReporterStale),
                                None,
                            )
                            .await;
                    }
                    return Ok(());
                };
                if self
                    .journal
                    .launch(&intent.handoff_id)
                    .is_none_or(|launch| launch.receipt.is_none())
                {
                    return Err(AdapterError::LocalBinding);
                }
                self.write_observation(
                    intent,
                    handoff,
                    EvidenceOutcome::Succeeded,
                    observed_at,
                    None,
                    None,
                )
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
        if handoff.plan_digest != binding.plan_digest
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
        if receipt.outcome != ResultOutcome::Succeeded
            || handoff.predecessor_digest
                != dependency_digest(&binding.handoff_id, "deployment", receipt.terminal_sequence)
        {
            return Err(AdapterError::LocalBinding);
        }
        let host = self.hosts.get(&intent.host);
        let anchor = unix_of(&receipt.completed_at)?;
        let now = now_unix();
        match observed_fresh_config_beacon(
            host.as_ref(),
            &intent.environment,
            &intent.artifact,
            anchor,
            now,
            self.config.verification_freshness_secs,
        ) {
            Ok(Some(observed_at)) => {
                self.write_observation(
                    intent,
                    handoff,
                    EvidenceOutcome::Succeeded,
                    observed_at,
                    None,
                    None,
                )
                .await
            }
            Ok(None)
                if beacon_window_closed(anchor, now, self.config.verification_freshness_secs) =>
            {
                self.write_observation(
                    intent,
                    handoff,
                    EvidenceOutcome::Failed,
                    now,
                    Some(BlockerCode::ReporterStale),
                    None,
                )
                .await
            }
            Ok(None) => Ok(()),
            Err(_) if config_measurement_mismatches(host.as_ref(), intent) => {
                self.write_observation(
                    intent,
                    handoff,
                    EvidenceOutcome::Failed,
                    now,
                    Some(BlockerCode::DependencyFailed),
                    None,
                )
                .await
            }
            Err(error) => Err(map_shared(error)),
        }
    }

    async fn write_observation(
        &self,
        intent: &DeliveryIntent,
        handoff: &HandoffDocument,
        outcome: EvidenceOutcome,
        observed_at: i64,
        blocker: Option<BlockerCode>,
        detail: Option<&str>,
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
        self.finish_result(
            intent,
            handoff,
            record.sequence,
            result_outcome,
            blocker,
            detail,
        )
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
        blocker: Option<BlockerCode>,
        detail: Option<&str>,
    ) -> Result<(), AdapterError> {
        if self
            .journal
            .result(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_some())
        {
            return Ok(());
        }
        let record =
            self.stage_result(intent, handoff, terminal_sequence, outcome, blocker, detail)?;
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
        blocker: Option<BlockerCode>,
        detail: Option<&str>,
    ) -> Result<ResultJournalRecord, AdapterError> {
        if let Some(existing) = self.journal.result(&intent.handoff_id) {
            // Replay the journaled bytes. A different seal replaces this record
            // only after Aeon rejects those exact bytes.
            return Ok(existing);
        }
        if (outcome == ResultOutcome::Succeeded) != blocker.is_none() {
            return Err(AdapterError::Contract);
        }
        if detail.is_some_and(|token| launch_block_reason(token).is_none()) {
            return Err(AdapterError::Journal);
        }
        if let Some(code) = blocker {
            require_accepted_blocker(code)?;
        }
        let request = ResultRequest {
            outcome,
            terminal_sequence,
            authority_epoch: handoff.authority_epoch,
            prerequisite_seal_sha256: handoff.prerequisite_seal_sha256.clone(),
            blocker_code: blocker,
        };
        let body = serde_json::to_vec(&request).map_err(|_| AdapterError::Contract)?;
        let mut record =
            ResultJournalRecord::new(intent, &self.config.aeon_origin, terminal_sequence, &body)?;
        record.detail = detail.map(str::to_string);
        self.journal.ensure_result(record)
    }

    async fn retry_result_seal(
        &self,
        intent: &DeliveryIntent,
        failed: &ResultJournalRecord,
    ) -> Result<(), AdapterError> {
        let fresh = self.aeon.get_handoff(&intent.handoff_id).await?;
        fresh.validate(intent)?;
        fresh.open_for_write()?;
        self.result_retry_binding(intent, &fresh)?;
        let failed_request: ResultRequest = decode_strict(failed.body_json.as_bytes())?;
        // Real Aeon writes the seal once and never updates it. This replacement
        // runs only when GET returns a different seal. FakeAeon simulates that
        // with bump_seal_on_result; a live handoff does not.
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
            blocker_code: failed_request.blocker_code,
        };
        let body = serde_json::to_vec(&request).map_err(|_| AdapterError::Contract)?;
        let mut record = ResultJournalRecord::new(
            intent,
            &self.config.aeon_origin,
            request.terminal_sequence,
            &body,
        )?;
        record.detail = failed.detail.clone();
        let record = self.journal.replace_unacked_result(record)?;
        let receipt = self.aeon.post_result(&record).await?;
        self.journal.acknowledge_result(&record, receipt)
    }

    fn result_retry_binding(
        &self,
        intent: &DeliveryIntent,
        fresh: &HandoffDocument,
    ) -> Result<(), AdapterError> {
        if intent.operation == Operation::Verify {
            let deploy_id = intent
                .deployment_handoff_id
                .as_deref()
                .ok_or(AdapterError::LocalBinding)?;
            let operation = self
                .journal
                .operation(deploy_id)
                .ok_or(AdapterError::LocalBinding)?;
            if operation.host != intent.host
                || operation.environment != intent.environment
                || operation.artifact != intent.artifact
            {
                return Err(AdapterError::LocalBinding);
            }
            return Ok(());
        }
        let operation = self
            .journal
            .operation(&intent.handoff_id)
            .ok_or(AdapterError::LocalBinding)?;
        if !operation.matches_handoff(fresh) {
            return Err(AdapterError::LocalBinding);
        }
        Ok(())
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

fn confirmation_is_delegated(job: &HostActionJob, admission_id: &str) -> bool {
    job.events.iter().any(|event| {
        event.kind == HostActionEventKind::Confirmed
            && event.source == HostActionEventSource::Pharos
            && event.actor.as_deref() == Some(admission_id)
    })
}

fn consume_job_confirmable(
    intent: &DeliveryIntent,
    job: &HostActionJob,
    reviewed: &str,
) -> Result<bool, AdapterError> {
    if job.host != intent.host
        || job.workflow_kind() != HostWorkflowKind::UpdateRestart
        || job.requested_by != ACTOR
        || job.state != HostActionState::AwaitingConfirmation
    {
        return Ok(false);
    }
    match reviewed_plan_digest(job) {
        Ok(digest) => Ok(digest == reviewed),
        Err(SharedError::LocalBinding) => Ok(false),
        Err(error) => Err(map_shared(error)),
    }
}

fn consume_receipt(response: &ConsumeResponse) -> Result<ConsumeReceipt, AdapterError> {
    if !response.consumed || parse_timestamp(&response.consumed_at).is_err() {
        return Err(AdapterError::Contract);
    }
    Ok(ConsumeReceipt {
        handoff_id: response.handoff_id.clone(),
        admission_id: response.admission_id.clone(),
        consumed: true,
        consumed_at: response.consumed_at.clone(),
        reconciled_from_get: false,
    })
}

fn readiness_refresh_candidate(
    previous: &str,
    sequence: i64,
    observed_at: &str,
    reviewed_plan_digest: &str,
    plan: &HostActionPlan,
) -> Result<Vec<u8>, AdapterError> {
    let mut value: serde_json::Value =
        decode_strict(&refreshed_readiness_body(previous, sequence, observed_at)?)?;
    let object = value.as_object_mut().ok_or(AdapterError::Contract)?;
    object.insert(
        "reviewed_plan_digest".to_string(),
        serde_json::Value::String(reviewed_plan_digest.to_string()),
    );
    object.insert(
        "all_host_eval_passed".to_string(),
        serde_json::Value::Bool(plan.all_host_eval_passed),
    );
    object.insert(
        "target_build_passed".to_string(),
        serde_json::Value::Bool(plan.target_build_passed),
    );
    object.insert(
        "backup_ready".to_string(),
        serde_json::Value::Bool(plan.backup_ready),
    );
    serde_json::to_vec(&value).map_err(|_| AdapterError::Contract)
}

fn refreshed_readiness_body(
    body: &str,
    sequence: i64,
    observed_at: &str,
) -> Result<Vec<u8>, AdapterError> {
    let mut value: serde_json::Value = decode_strict(body.as_bytes())?;
    let object = value.as_object_mut().ok_or(AdapterError::Contract)?;
    object.insert("sequence".to_string(), serde_json::Value::from(sequence));
    object.insert(
        "observed_at".to_string(),
        serde_json::Value::String(observed_at.to_string()),
    );
    serde_json::to_vec(&value).map_err(|_| AdapterError::Contract)
}

fn config_measurement_mismatches(
    host: Option<&pharos_core::Host>,
    intent: &DeliveryIntent,
) -> bool {
    let Some(evidence) = host.and_then(|host| host.deployed_artifact.as_ref()) else {
        return false;
    };
    let artifact = &intent.artifact;
    evidence.is_config_class_measurement()
        && !evidence.matches_expected(
            &intent.environment,
            artifact.version_scheme,
            &artifact.version,
            &artifact.release_channel,
            artifact.release_sequence,
            &artifact.digest,
            &artifact.commit_digest,
            &artifact.release_manifest_coordinate,
            &artifact.release_manifest_digest,
        )
}

fn handoff_result_matches(result: &HandoffResult, body: &str, handoff_id: &str) -> bool {
    let Ok(request) = decode_strict::<ResultRequest>(body.as_bytes()) else {
        return false;
    };
    result.handoff_id == handoff_id
        && result.outcome == request.outcome
        && result.terminal_sequence == request.terminal_sequence
        && result.authority_epoch == request.authority_epoch
        && result.prerequisite_seal_sha256 == request.prerequisite_seal_sha256
        && result.blocker_code == request.blocker_code
}

fn beacon_window_closed(anchor: i64, now: i64, freshness_secs: i64) -> bool {
    now.saturating_sub(anchor) > freshness_secs
}

fn evidence_flag_true(body: &serde_json::Value, key: &str) -> bool {
    body.get(key).and_then(serde_json::Value::as_bool) == Some(true)
}

fn refresh_refusal(previous: &str, refreshed: &[u8]) -> Result<Option<&'static str>, AdapterError> {
    let previous: serde_json::Value = decode_strict(previous.as_bytes())?;
    let refreshed: serde_json::Value = decode_strict(refreshed)?;
    if refreshed.get("reviewed_plan_digest") != previous.get("reviewed_plan_digest") {
        return Ok(Some(LAUNCH_BLOCK_READINESS_PLAN_CHANGED));
    }
    for flag in [
        "all_host_eval_passed",
        "target_build_passed",
        "backup_ready",
    ] {
        if !evidence_flag_true(&refreshed, flag) || refreshed.get(flag) != previous.get(flag) {
            return Ok(Some(LAUNCH_BLOCK_READINESS_FLAG_FALSE));
        }
    }
    Ok(None)
}

fn validated_readiness_backup<'a>(
    plan: &HostActionPlan,
    backup_at: Option<&'a str>,
    now: i64,
) -> Result<&'a str, &'static str> {
    if let Some(reason) = readiness_wait_reason(plan, backup_at, now) {
        return Err(reason);
    }
    backup_at.ok_or(LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING)
}

fn readiness_wait_reason(
    plan: &HostActionPlan,
    backup_at: Option<&str>,
    now: i64,
) -> Option<&'static str> {
    if !plan.backup_ready {
        return Some(LAUNCH_BLOCK_BACKUP_NOT_READY);
    }
    if !acceptable_backup_stamp(backup_at, now) {
        return Some(LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING);
    }
    None
}

fn acceptable_backup_stamp(stamp: Option<&str>, now: i64) -> bool {
    let Some(stamp) = stamp else {
        return false;
    };
    let Ok(parsed) = parse_timestamp(stamp) else {
        return false;
    };
    if parsed.year() <= 1 {
        return false;
    }
    let unix = parsed.unix_timestamp();
    unix > 0 && unix <= now.saturating_add(BACKUP_FUTURE_SKEW_SECS)
}

fn backup_observed_at(hosts: &Store, host_name: &str) -> Option<String> {
    backup_stamp(hosts.get(host_name).as_ref())
}

fn backup_stamp(host: Option<&pharos_core::Host>) -> Option<String> {
    let host = host?;
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
        && backup_clocks_match(&request, response.backup_observed_at.as_deref())
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

fn backup_clocks_match(request: &serde_json::Value, echoed: Option<&str>) -> bool {
    let sent = request
        .get("backup_observed_at")
        .and_then(serde_json::Value::as_str);
    match (present_instant(sent), present_instant(echoed)) {
        (None, None) => true,
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

fn present_instant(stamp: Option<&str>) -> Option<i128> {
    let parsed = parse_timestamp(stamp?).ok()?;
    if parsed.year() <= 1 {
        return None;
    }
    Some(parsed.unix_timestamp_nanos() / 1_000)
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

#[cfg(test)]
fn trace_body_excerpt(body: &[u8], credentials: &Credentials) -> String {
    if contains_slice(body, &credentials.api_key) {
        return REFLECTED_CREDENTIAL_MARKER.to_string();
    }
    let end = body.len().min(TRACE_EXCERPT_MAX_BYTES);
    truncate_to_bytes(
        &String::from_utf8_lossy(&body[..end]),
        TRACE_EXCERPT_MAX_BYTES,
    )
}

#[cfg(test)]
fn truncate_to_bytes(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
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

fn dependency_digest(handoff_id: &str, kind: &str, sequence: i64) -> String {
    hex_digest(format!("{handoff_id}\0{kind}\0{sequence}").as_bytes())
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

fn timestamp_nanos(value: &str) -> Result<i128, AdapterError> {
    Ok(parse_timestamp(value)?.unix_timestamp_nanos())
}

/// Aeon consume accepts an expiry only while it is strictly after now.
fn stamp_reached(stamp: &str) -> Result<bool, AdapterError> {
    Ok(now_nanos() >= timestamp_nanos(stamp)?)
}

/// Aeon `current()` is false only once now is strictly after `expires_at`.
fn stamp_passed(stamp: &str) -> Result<bool, AdapterError> {
    Ok(now_nanos() > timestamp_nanos(stamp)?)
}

#[cfg(test)]
thread_local! {
    static TEST_NOW: std::cell::Cell<Option<i64>> = const { std::cell::Cell::new(None) };
    static TEST_NOW_EXTRA_NANOS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

fn now_unix() -> i64 {
    #[cfg(test)]
    if let Some(now) = TEST_NOW.with(std::cell::Cell::get) {
        return now;
    }
    OffsetDateTime::now_utc().unix_timestamp()
}

fn now_nanos() -> i128 {
    #[cfg(test)]
    if let Some(seconds) = TEST_NOW.with(std::cell::Cell::get) {
        let extra = TEST_NOW_EXTRA_NANOS.with(std::cell::Cell::get) as i128;
        return (seconds as i128)
            .saturating_mul(1_000_000_000)
            .saturating_add(extra);
    }
    OffsetDateTime::now_utc().unix_timestamp_nanos()
}

fn strip_sha256(value: &str) -> Result<String, AdapterError> {
    value
        .strip_prefix("sha256:")
        .filter(|digest| valid_hex64(digest))
        .map(str::to_string)
        .ok_or(AdapterError::Contract)
}

fn valid_symbol(value: &str) -> bool {
    // Aeon symbolicRE: ^[a-z][a-z0-9_-]{0,127}$
    let bytes = value.as_bytes();
    (1..=128).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
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
    const LAUNCH_PRINCIPAL: &str = "99999999-9999-4999-8999-999999999999";

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

    fn held_launch_artifact() -> Value {
        serde_json::to_value(WireArtifact::from_evidence(&artifact()).expect("held artifact"))
            .expect("held artifact json")
    }

    fn full_deployment(sequence: i64, outcome: &str, now: i64) -> Value {
        json!({
            "sequence": sequence,
            "kind": "deployment",
            "outcome": outcome,
            "observed_at": format_timestamp(now).unwrap(),
            "authority_epoch": 3,
            "workflow": "deploy-production",
            "environment": "production-eu1",
            "artifact": held_launch_artifact(),
        })
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
                target_ref: artifact().digest,
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
            "delegated_launch": {
                "target_ref": artifact().digest,
            },
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

        document["intents"][0]
            .as_object_mut()
            .unwrap()
            .remove("delegated_launch");
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
            json!([deploy_intent_json()]),
        );
        document["intents"][0]["environment"] = json!("production.eu1");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));
        assert!(valid_symbol("production-eu1"));
        assert!(!valid_symbol("1production"));
        assert!(!valid_symbol(&"a".repeat(129)));

        document = config_document(
            &api,
            "https://aeon.example.test",
            json!([deploy_intent_json()]),
        );
        document["intents"][0]["delegated_launch"]["target_ref"] =
            json!(format!("sha256:{}", "b".repeat(64)));
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

    /// Known answer, computed outside this function:
    /// ```text
    /// DIGEST=$(python3 -c 'print("1"*64)')
    /// REVIEWED=$(python3 -c 'print("ab"*32)')
    /// CANON=$(printf '{"artifact_digest_sha256":"%s","authority_epoch":3,"handoff_id":"11111111-1111-4111-8111-111111111111","release_node_id":"44444444-4444-4444-8444-444444444444","reviewed_plan_digest":"%s"}' "$DIGEST" "$REVIEWED")
    /// { printf 'inspr.aeon.launch-binding.v1'; printf '\0'; printf '%s' "$CANON"; } | shasum -a 256
    /// 6ce52bc92820607606e43a5dc3edc86ac6220d3aeed5d6e6c5f1df593f5148fd
    /// ```
    #[test]
    fn launch_binding_digest_matches_an_independent_vector() {
        let reviewed = format!("sha256:{}", "ab".repeat(32));
        assert_eq!(
            launch_binding_digest(&"1".repeat(64), 3, DEPLOY_HANDOFF, RELEASE_NODE, &reviewed)
                .unwrap(),
            "6ce52bc92820607606e43a5dc3edc86ac6220d3aeed5d6e6c5f1df593f5148fd"
        );
    }

    #[test]
    fn readiness_row_posts_the_backup_stamp_it_validated() {
        let plan = ready_plan();
        let now = 1_700_000_100;
        let stamp = format_timestamp(now - 30).unwrap();
        assert_eq!(
            validated_readiness_backup(&plan, Some(&stamp), now).unwrap(),
            stamp
        );
        assert_eq!(
            validated_readiness_backup(&plan, None, now).unwrap_err(),
            LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING
        );
        let mut unready = plan;
        unready.backup_ready = false;
        assert_eq!(
            validated_readiness_backup(&unready, Some(&stamp), now).unwrap_err(),
            LAUNCH_BLOCK_BACKUP_NOT_READY
        );
    }

    #[test]
    fn refresh_refusal_compares_the_current_plan_with_the_journaled_row() {
        let previous = r#"{"sequence":1,"reviewed_plan_digest":"aa","all_host_eval_passed":true,"target_build_passed":true,"backup_ready":true,"observed_at":"2026-01-01T00:00:00Z"}"#;
        let plan = ready_plan();
        let same =
            readiness_refresh_candidate(previous, 2, "2026-01-01T00:10:00Z", "aa", &plan).unwrap();
        assert!(refresh_refusal(previous, &same).unwrap().is_none());
        let mut changed = plan.clone();
        changed.backup_ready = false;
        let flagged =
            readiness_refresh_candidate(previous, 2, "2026-01-01T00:10:00Z", "aa", &changed)
                .unwrap();
        assert_eq!(
            refresh_refusal(previous, &flagged).unwrap(),
            Some(LAUNCH_BLOCK_READINESS_FLAG_FALSE)
        );
        let drifted =
            readiness_refresh_candidate(previous, 2, "2026-01-01T00:10:00Z", "bb", &plan).unwrap();
        assert_eq!(
            refresh_refusal(previous, &drifted).unwrap(),
            Some(LAUNCH_BLOCK_READINESS_PLAN_CHANGED)
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
        /// When the handoff was opened. Not part of the GET document. Aeon
        /// stores this as `created_at` and rejects evidence observed more than
        /// a minute earlier.
        created_at: i64,
        evidence: BTreeMap<i64, StoredEvidence>,
        admission: Option<Value>,
        admit_idempotency_key: Option<String>,
        launch_calls: BTreeMap<String, StoredLaunchCall>,
        consumed: bool,
        consumed_at: Option<String>,
        consumed_by_principal_id: Option<String>,
        held_artifact: Value,
        result_body: Option<Vec<u8>>,
        result: Option<Value>,
    }

    impl FakeHandoff {
        fn deploy(now: i64) -> Self {
            let mut handoff = Self::open(DEPLOY_HANDOFF, "deploy", "deployment", now);
            handoff.evidence_ceiling =
                vec!["deployment".to_string(), "launch_readiness".to_string()];
            handoff.held_artifact = held_launch_artifact();
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
                created_at: now,
                evidence: BTreeMap::new(),
                admission: None,
                admit_idempotency_key: None,
                launch_calls: BTreeMap::new(),
                consumed: false,
                consumed_at: None,
                consumed_by_principal_id: None,
                held_artifact: Value::Null,
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
            if let Some(admission) = &self.admission {
                let mut view = json!({
                    "admission_id": admission["id"],
                    "epoch": admission["authority_epoch"],
                    "expires_at": admission["expires_at"],
                });
                if let Some(consumed_at) = &self.consumed_at {
                    view["consumed_at"] = json!(consumed_at);
                }
                if let Some(principal) = &self.consumed_by_principal_id {
                    view["consumed_by_principal_id"] = json!(principal);
                }
                value["admission"] = view;
            }
            value
        }
    }

    struct FakeInner {
        api_key: Vec<u8>,
        now: i64,
        handoffs: BTreeMap<String, FakeHandoff>,
        fail_next_post: bool,
        /// FakeAeon only. Real Aeon writes `prerequisite_seal_sha256` once and
        /// `current()` only compares it. Set to make the next result 409 and
        /// replace the seal, which is the only way `retry_result_seal` replaces
        /// a journaled body.
        bump_seal_on_result: bool,
        reject_result: bool,
        corrupt_binding: bool,
        expire_admission: bool,
        /// FakeAeon only. Real Aeon sets admission `expires_at` equal to the
        /// handoff and refuses a second admit. A shorter lifetime is how a test
        /// expires the admission while the handoff is still current.
        admission_lifetime_secs: Option<i64>,
        get_status: Option<StatusCode>,
        drop_accepted_consume: bool,
        drop_accepted_admit: bool,
        drop_accepted_result: bool,
        drift_plan_on_next_get: bool,
        arm_lineage_drift: bool,
        journey_project_key: String,
        journey_node_key: String,
        journey_tenant_slug: String,
        /// When true, the journey fixture reports one live gate.
        journey_gate_live: bool,
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
        consume_hook: RereadHook,
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
                    reject_result: false,
                    corrupt_binding: false,
                    expire_admission: false,
                    admission_lifetime_secs: None,
                    get_status: None,
                    drop_accepted_consume: false,
                    drop_accepted_admit: false,
                    drop_accepted_result: false,
                    drift_plan_on_next_get: false,
                    arm_lineage_drift: false,
                    journey_project_key: "lab".to_string(),
                    journey_node_key: "PRJ-17".to_string(),
                    journey_tenant_slug: "inspr".to_string(),
                    journey_gate_live: false,
                })),
                captures: Arc::new(Mutex::new(Vec::new())),
                reread_hook: Arc::new(Mutex::new(None)),
                consume_hook: Arc::new(Mutex::new(None)),
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
            .header("x-request-id", "fake-aeon-request")
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
            let echoed = object
                .get("backup_observed_at")
                .and_then(Value::as_str)
                .and_then(go_backup_time)
                .unwrap_or_else(|| "0001-01-01T00:00:00Z".to_string());
            object.insert("backup_observed_at".to_string(), json!(echoed));
        }
        value
    }

    fn go_backup_time(stamp: &str) -> Option<String> {
        let parsed = parse_timestamp(stamp).ok()?;
        if parsed.year() <= 1 {
            return None;
        }
        let micros = parsed.unix_timestamp_nanos() / 1_000;
        let truncated = time::OffsetDateTime::from_unix_timestamp_nanos(micros * 1_000).ok()?;
        if truncated.nanosecond() == 0 {
            return format_timestamp(truncated.unix_timestamp()).ok();
        }
        let whole = format_timestamp(truncated.unix_timestamp()).ok()?;
        let fraction = format!("{:06}", truncated.nanosecond() / 1_000);
        let fraction = fraction.trim_end_matches('0');
        Some(format!("{}.{}Z", whole.trim_end_matches('Z'), fraction))
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
        // Aeon checks the 900s window on observed_at only. backup_observed_at
        // has to be present, non-zero, and no more than five minutes ahead.
        if !acceptable_backup_stamp(value["backup_observed_at"].as_str(), now) {
            return None;
        }
        value["reviewed_plan_digest"].as_str().map(str::to_string)
    }

    fn readiness_observed_at_is_stale(body: &[u8], now: i64) -> bool {
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return false;
        };
        if value["kind"] != "launch_readiness" || value["outcome"] != "satisfied" {
            return false;
        }
        if value["all_host_eval_passed"] != true
            || value["target_build_passed"] != true
            || value["backup_ready"] != true
        {
            return false;
        }
        let Some(stamp) = value["observed_at"].as_str() else {
            return false;
        };
        let Ok(parsed) = parse_timestamp(stamp) else {
            return false;
        };
        now.saturating_sub(parsed.unix_timestamp()) > 900
    }

    fn same_held_artifact(body: &Value, held: &Value) -> bool {
        [
            "version_scheme",
            "version",
            "release_channel",
            "release_sequence",
            "digest_sha256",
            "commit_digest",
            "manifest_coordinate",
            "manifest_digest_sha256",
        ]
        .iter()
        .all(|key| body.get(*key).is_some() && body.get(*key) == held.get(*key))
    }

    fn pharos_evidence_complete(value: &Value) -> bool {
        value["workflow"].as_str().is_some_and(valid_symbol)
            && value["environment"].as_str().is_some_and(valid_symbol)
            && value.get("artifact").is_some_and(|artifact| {
                artifact["version"]
                    .as_str()
                    .is_some_and(|item| !item.is_empty())
                    && artifact["release_channel"]
                        .as_str()
                        .is_some_and(|item| !item.is_empty())
                    && artifact["release_sequence"]
                        .as_i64()
                        .is_some_and(|item| item >= 1)
                    && artifact["digest_sha256"].as_str().is_some_and(valid_hex64)
                    && artifact["commit_digest"]
                        .as_str()
                        .is_some_and(|item| !item.is_empty())
                    && artifact["manifest_coordinate"]
                        .as_str()
                        .is_some_and(|item| !item.is_empty())
                    && artifact["manifest_digest_sha256"]
                        .as_str()
                        .is_some_and(valid_hex64)
                    && artifact["version_scheme"]
                        .as_str()
                        .is_some_and(|item| !item.is_empty())
            })
    }

    fn readiness_contradicts(handoff: &FakeHandoff, value: &Value) -> bool {
        let Some((_, first)) = handoff.evidence.iter().find(|(_, evidence)| {
            serde_json::from_slice::<Value>(&evidence.body)
                .ok()
                .is_some_and(|stored| stored["kind"] == "launch_readiness")
        }) else {
            return false;
        };
        let Ok(first) = serde_json::from_slice::<Value>(&first.body) else {
            return false;
        };
        first["reviewed_plan_digest"] != value["reviewed_plan_digest"]
            || value["all_host_eval_passed"] != true
            || value["target_build_passed"] != true
            || value["backup_ready"] != true
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
        let max_sequence = handoff.evidence.keys().max().copied().unwrap_or(0);
        if sequence != max_sequence + 1 {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        if value["authority_epoch"].as_i64() != Some(handoff.authority_epoch) {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        // report.go: observed_at before created_at minus one minute is 409.
        // Before is strict, so the exact one-minute boundary is still accepted.
        if value["observed_at"].as_str().is_some_and(|stamp| {
            parse_timestamp(stamp)
                .map(|time| time.unix_timestamp().saturating_add(60) < handoff.created_at)
                .unwrap_or(false)
        }) {
            return json_response(
                StatusCode::CONFLICT,
                &json!({"error": "evidence predates handoff"}),
            );
        }
        if value["kind"] == "launch_readiness"
            && (!launch_readiness_tokens(&value)
                || !acceptable_backup_stamp(value["backup_observed_at"].as_str(), now))
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "invalid launch readiness"}),
            );
        }
        if value["kind"] == "launch_readiness" && readiness_contradicts(handoff, &value) {
            return json_response(
                StatusCode::CONFLICT,
                &json!({"error": "launch readiness was contradicted"}),
            );
        }
        if matches!(value["kind"].as_str(), Some("deployment" | "verification"))
            && !pharos_evidence_complete(&value)
        {
            return json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "invalid Pharos evidence"}),
            );
        }
        if value["kind"] == "deployment"
            && matches!(value["outcome"].as_str(), Some("succeeded" | "satisfied"))
            && !handoff.consumed
        {
            return json_response(
                StatusCode::CONFLICT,
                &json!({"error": "deployment lacks consumed launch admission"}),
            );
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

    fn rejected_launch_key(key: &str) -> Option<Response<Body>> {
        if valid_uuid(key) {
            None
        } else {
            Some(json_response(
                StatusCode::BAD_REQUEST,
                &json!({"error": "Idempotency-Key must be a UUID"}),
            ))
        }
    }

    fn handle_admit(flags: &AdmitFlags, handoff: &mut FakeHandoff, body: &[u8]) -> Response<Body> {
        if let Some(response) = rejected_launch_key(flags.idempotency) {
            return response;
        }
        let Ok(value) = serde_json::from_slice::<Value>(body) else {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        };
        let Some(digest) = value["digest_sha256"].as_str() else {
            return json_response(StatusCode::CONFLICT, &json!({}));
        };
        if !same_held_artifact(&value, &handoff.held_artifact) {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        if let Some(response) = replay_response(launch_replay(
            handoff,
            "admit",
            flags.principal,
            flags.idempotency,
            body,
            flags.now,
        )) {
            return response;
        }
        let mut reviewed = None;
        let mut best_sequence = 0;
        let mut saw_stale = false;
        for (sequence, evidence) in &handoff.evidence {
            if let Some(plan) = satisfying_readiness(&evidence.body, flags.now) {
                if *sequence >= best_sequence {
                    best_sequence = *sequence;
                    reviewed = Some(plan);
                }
            } else if readiness_observed_at_is_stale(&evidence.body, flags.now) {
                saw_stale = true;
            }
        }
        let Some(reviewed) = reviewed else {
            if saw_stale {
                return json_response(
                    StatusCode::CONFLICT,
                    &json!({"error": "launch readiness is stale"}),
                );
            }
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
        if handoff.admission.is_some() {
            return json_response(StatusCode::CONFLICT, &json!({}));
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
        // `expire` and `admission_lifetime_secs` are FakeAeon-only. Real Aeon
        // copies the handoff expiry and does not issue a shorter admission.
        let expires_at = if flags.expire {
            format_timestamp(flags.now - 120).unwrap()
        } else if let Some(lifetime) = flags.admission_lifetime_secs {
            let handoff_expires = parse_timestamp(&handoff.expires_at)
                .map(|time| time.unix_timestamp())
                .unwrap_or(flags.now);
            format_timestamp(flags.now.saturating_add(lifetime).min(handoff_expires)).unwrap()
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
        remember_launch(
            handoff,
            "admit",
            flags.principal,
            flags.idempotency,
            body,
            &admission,
        );
        if flags.drop_response {
            return json_response(StatusCode::OK, &json!({}));
        }
        json_response(StatusCode::OK, &admission)
    }

    fn handle_consume(
        handoff: &mut FakeHandoff,
        body: &[u8],
        principal: &str,
        idempotency: &str,
        now: i64,
        drop_response: bool,
    ) -> Response<Body> {
        if let Some(response) = rejected_launch_key(idempotency) {
            return response;
        }
        if let Some(response) = replay_response(launch_replay(
            handoff,
            "consume",
            principal,
            idempotency,
            body,
            now,
        )) {
            return response;
        }
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
        // Whole seconds. Real Aeon compares `expires_at > now()` at full
        // time.Time precision. A fraction inside this second can still be valid.
        let admission_expires = admission["expires_at"]
            .as_str()
            .and_then(|stamp| parse_timestamp(stamp).ok())
            .map(|time| time.unix_timestamp())
            .unwrap_or(0);
        let handoff_expires = parse_timestamp(&handoff.expires_at)
            .map(|time| time.unix_timestamp())
            .unwrap_or(0);
        let fresh = handoff
            .evidence
            .values()
            .any(|evidence| satisfying_readiness(&evidence.body, now).is_some());
        if admission_expires <= now
            || handoff_expires <= now
            || !matches!(handoff.state.as_str(), "requested" | "active")
            || !fresh
        {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        let consumed_at = format_timestamp(now).unwrap();
        let response = json!({
            "handoff_id": handoff.id,
            "admission_id": admission_id,
            "consumed": true,
            "consumed_at": consumed_at,
        });
        handoff.consumed = true;
        handoff.consumed_at = Some(consumed_at);
        handoff.consumed_by_principal_id = Some(LAUNCH_PRINCIPAL.to_string());
        remember_launch(handoff, "consume", principal, idempotency, body, &response);
        if drop_response {
            return json_response(StatusCode::OK, &json!({}));
        }
        json_response(StatusCode::OK, &response)
    }

    fn handle_result(inner: &mut FakeInner, id: &str, body: &[u8]) -> Response<Body> {
        if inner.reject_result {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        // FakeAeon only. Real Aeon does not change the stored seal on 409.
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
        let blocker = value["blocker_code"].as_str();
        let failed_blocker = blocker.is_some_and(|code| AEON_BLOCKER_CODES.contains(&code));
        if (value["outcome"] == "failed" && !failed_blocker)
            || (value["outcome"] == "succeeded" && blocker.is_some())
        {
            return json_response(StatusCode::BAD_REQUEST, &json!({}));
        }
        // Whole seconds. Real Aeon uses time.Now().After(expires_at), so a
        // fraction inside this second is already stale.
        let expires_at = parse_timestamp(&handoff.expires_at)
            .map(|time| time.unix_timestamp())
            .unwrap_or(0);
        if expires_at < now {
            return json_response(StatusCode::CONFLICT, &json!({"error": "handoff is stale"}));
        }
        let last = handoff.evidence.keys().max().copied();
        if value["prerequisite_seal_sha256"].as_str()
            != Some(handoff.prerequisite_seal_sha256.as_str())
            || value["authority_epoch"].as_i64() != Some(handoff.authority_epoch)
            || value["terminal_sequence"].as_i64() != last
        {
            return json_response(StatusCode::CONFLICT, &json!({}));
        }
        let mut response = json!({
            "outcome": value["outcome"],
            "terminal_sequence": value["terminal_sequence"],
            "authority_epoch": value["authority_epoch"],
            "prerequisite_seal_sha256": value["prerequisite_seal_sha256"],
            "handoff_id": handoff.id,
            "completed_at": format_timestamp(now).unwrap(),
        });
        if let Some(blocker) = value["blocker_code"].as_str() {
            response["blocker_code"] = json!(blocker);
        }
        handoff.state = if value["outcome"] == "succeeded" {
            "succeeded".to_string()
        } else {
            "failed".to_string()
        };
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
        principal: &str,
        idempotency: &str,
    ) -> Response<Body> {
        if method == "GET" && path == "/api/me" {
            return json_response(
                StatusCode::OK,
                &json!({
                    "principal": {
                        "id": LAUNCH_PRINCIPAL,
                        "tenant_id": "55555555-5555-4555-8555-555555555555",
                        "kind": "agent",
                        "name": "pharos-delivery",
                        "roles": []
                    },
                    "tenant": {
                        "id": "55555555-5555-4555-8555-555555555555",
                        "slug": "lab",
                        "name": "lab"
                    },
                    "identity": null
                }),
            );
        }
        let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
        if method == "GET"
            && parts.len() == 4
            && parts[0] == "api"
            && parts[1] == "projects"
            && parts[3] == "journey"
        {
            return json_response(
                StatusCode::OK,
                &json!({
                    "project_node_id": parts[2],
                    "project_key": inner.journey_project_key,
                    "node_key": inner.journey_node_key,
                    "tenant_slug": inner.journey_tenant_slug,
                    "stages": [{
                        "key": "deploy",
                        "state": "current",
                        "gate_live": inner.journey_gate_live,
                    }],
                }),
            );
        }
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
        let admission_lifetime_secs = inner.admission_lifetime_secs;
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
                    admission_lifetime_secs,
                    principal,
                    idempotency,
                    drop_response: drop_admit,
                };
                handle_admit(&flags, handoff, body)
            }
            ("POST", Some("launch"), Some("consume")) => {
                handle_consume(handoff, body, principal, idempotency, now, drop_consume)
            }
            _ => json_response(StatusCode::NOT_FOUND, &json!({})),
        }
    }

    struct StoredLaunchCall {
        action: String,
        principal: String,
        body_digest: String,
        response: Value,
    }

    struct AdmitFlags<'a> {
        now: i64,
        corrupt: bool,
        expire: bool,
        admission_lifetime_secs: Option<i64>,
        principal: &'a str,
        idempotency: &'a str,
        drop_response: bool,
    }

    fn canonical_body_digest(body: &[u8]) -> Result<String, ()> {
        let value: Value = serde_json::from_slice(body).map_err(|_| ())?;
        let canonical = canonical_json(&value).ok_or(())?;
        Ok(hex_digest(canonical.as_bytes()))
    }

    fn canonical_json(value: &Value) -> Option<String> {
        match value {
            Value::Null => Some("null".to_string()),
            Value::Bool(bit) => Some(if *bit { "true" } else { "false" }.to_string()),
            Value::Number(number) => Some(number.to_string()),
            Value::String(text) => serde_json::to_string(text).ok(),
            Value::Array(items) => {
                let mut rendered = String::from("[");
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        rendered.push(',');
                    }
                    rendered.push_str(&canonical_json(item)?);
                }
                rendered.push(']');
                Some(rendered)
            }
            Value::Object(entries) => {
                let mut keys: Vec<_> = entries.keys().collect();
                keys.sort();
                let mut rendered = String::from("{");
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        rendered.push(',');
                    }
                    rendered.push_str(&serde_json::to_string(key).ok()?);
                    rendered.push(':');
                    rendered.push_str(&canonical_json(&entries[*key])?);
                }
                rendered.push('}');
                Some(rendered)
            }
        }
    }

    fn launch_replay_expired(handoff: &FakeHandoff, now: i64) -> bool {
        let Some(result) = &handoff.result else {
            return false;
        };
        let Some(completed_at) = result.get("completed_at").and_then(Value::as_str) else {
            return false;
        };
        let Ok(completed) = parse_timestamp(completed_at) else {
            return false;
        };
        matches!(handoff.state.as_str(), "succeeded" | "failed")
            && now >= completed.unix_timestamp().saturating_add(24 * 60 * 60)
    }

    enum LaunchReplay {
        Miss,
        Hit(Value),
        Conflict,
        BadRequest,
    }

    fn launch_replay(
        handoff: &FakeHandoff,
        action: &str,
        principal: &str,
        key: &str,
        body: &[u8],
        now: i64,
    ) -> LaunchReplay {
        let Some(stored) = handoff.launch_calls.get(key) else {
            return LaunchReplay::Miss;
        };
        let Ok(digest) = canonical_body_digest(body) else {
            return LaunchReplay::BadRequest;
        };
        if stored.action != action
            || stored.principal != principal
            || stored.body_digest != digest
            || launch_replay_expired(handoff, now)
        {
            return LaunchReplay::Conflict;
        }
        LaunchReplay::Hit(stored.response.clone())
    }

    fn replay_response(replay: LaunchReplay) -> Option<Response<Body>> {
        match replay {
            LaunchReplay::Miss => None,
            LaunchReplay::Hit(response) => Some(json_response(StatusCode::OK, &response)),
            LaunchReplay::Conflict => Some(json_response(
                StatusCode::CONFLICT,
                &json!({"error": "idempotency_conflict"}),
            )),
            LaunchReplay::BadRequest => Some(json_response(StatusCode::BAD_REQUEST, &json!({}))),
        }
    }

    fn remember_launch(
        handoff: &mut FakeHandoff,
        action: &str,
        principal: &str,
        key: &str,
        body: &[u8],
        response: &Value,
    ) {
        let Ok(digest) = canonical_body_digest(body) else {
            return;
        };
        handoff.launch_calls.insert(
            key.to_string(),
            StoredLaunchCall {
                action: action.to_string(),
                principal: principal.to_string(),
                body_digest: digest,
                response: response.clone(),
            },
        );
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
        if method == "POST" && path.ends_with("/launch/consume") {
            if let Some(hook) = fake.consume_hook.lock().expect("consume hook").take() {
                hook();
            }
        }
        let mut inner = fake.inner.lock().expect("fake lock");
        let idempotency = header_text(&headers, "idempotency-key");
        dispatch(
            &mut inner,
            &method,
            &path,
            &body,
            &authorization,
            &idempotency,
        )
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
            principal_id: Mutex::new(None),
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
        review_job_for(store, "hsb8", job_id, at);
    }

    fn review_job_for(store: &HostActionStore, host: &str, job_id: &str, at: i64) {
        let review = store
            .claim(host, at)
            .expect("claim review")
            .expect("review lease");
        store
            .record_agent_result(
                job_id,
                host,
                AgentActionResultRequest {
                    host: host.to_string(),
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
        finish_apply_for(store, "hsb8", job_id, at);
    }

    fn finish_apply_for(store: &HostActionStore, host: &str, job_id: &str, at: i64) {
        let apply = store
            .claim(host, at)
            .expect("claim apply")
            .expect("apply lease");
        assert_eq!(apply.phase, AgentActionPhase::Apply);
        store
            .record_agent_result(
                job_id,
                host,
                AgentActionResultRequest {
                    host: host.to_string(),
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
        measured_for("production-eu1", artifact, observed_at)
    }

    fn measured_for(
        environment: &str,
        artifact: &ArtifactEvidence,
        observed_at: i64,
    ) -> DeployedArtifactEvidence {
        DeployedArtifactEvidence {
            schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
            version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
            environment: environment.to_string(),
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

    fn record_beacon_for(
        store: &Store,
        host: &str,
        environment: &str,
        observed_at: i64,
        artifact: &ArtifactEvidence,
        backup_success_at: Option<i64>,
    ) {
        record_named_host(
            store,
            host,
            environment,
            observed_at,
            artifact,
            backup_success_at,
        );
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
        record_named_host(
            store,
            "hsb8",
            "production-eu1",
            observed_at,
            artifact,
            backup_success_at,
        );
    }

    fn record_named_host(
        store: &Store,
        host: &str,
        environment: &str,
        observed_at: i64,
        artifact: &ArtifactEvidence,
        backup_success_at: Option<i64>,
    ) {
        store
            .record(
                HostReport {
                    schema: HOST_REPORT_SCHEMA.to_string(),
                    version: HOST_REPORT_VERSION,
                    name: host.to_string(),
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
                    deployed_artifact: Some(measured_for(environment, artifact, observed_at)),
                },
                observed_at,
            )
            .expect("record host");
    }

    fn record_deployed(store: &Store, observed_at: i64, evidence: DeployedArtifactEvidence) {
        let artifact = artifact();
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
                    backup_observations: vec![],
                    inbound_rtt_ms: None,
                    location: None,
                    preferences: Default::default(),
                    deployed_artifact: Some(evidence),
                },
                observed_at,
            )
            .expect("record deployed artifact");
    }

    fn fake_now(fake: &FakeAeon) -> i64 {
        fake.update(|inner| inner.now)
    }

    async fn advance_delegated_job_to_succeeded(
        adapter: &AeonDeliveryAdapter,
        actions: &HostActionStore,
        hosts: &Store,
        intent: &DeliveryIntent,
    ) -> String {
        adapter.process_intent(intent).await.unwrap();
        let job_id = actions.list()[0].id.clone();
        review_job(actions, &job_id, actions.get(&job_id).unwrap().created_at);
        record_backup(hosts, now_unix());
        for _ in 0..8 {
            adapter.process_intent(intent).await.unwrap();
            if actions.get(&job_id).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        let at = now_unix().max(actions.get(&job_id).unwrap().updated_at);
        finish_apply(actions, &job_id, at);
        record_beacon(hosts, at + 1, &intent.artifact);
        job_id
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
    async fn delegated_deploy_allows_launch_readiness_without_that_ceiling() {
        let allowed = harness(true).await;
        allowed.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .evidence_ceiling = vec!["deployment".to_string()];
        });
        allowed
            .adapter
            .process_intent(&allowed.intent)
            .await
            .unwrap();
        assert_eq!(allowed.actions.list().len(), 1);
        allowed.server.abort();

        let refused = harness(true).await;
        refused.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .evidence_ceiling = vec!["launch_readiness".to_string()];
        });
        let error = refused
            .adapter
            .process_intent(&refused.intent)
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::Contract));
        assert!(refused.actions.list().is_empty());
        refused.server.abort();
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
        record_backup(&missing.hosts, fake_now(&missing.fake));
        missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap();
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
            .header("idempotency-key", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
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

    struct FrozenNow;

    impl FrozenNow {
        fn at(now: i64) -> Self {
            TEST_NOW.with(|cell| cell.set(Some(now)));
            TEST_NOW_EXTRA_NANOS.with(|cell| cell.set(0));
            Self
        }

        fn set(now: i64) {
            TEST_NOW.with(|cell| cell.set(Some(now)));
            TEST_NOW_EXTRA_NANOS.with(|cell| cell.set(0));
        }

        fn set_extra_nanos(extra: u32) {
            TEST_NOW_EXTRA_NANOS.with(|cell| cell.set(extra));
        }
    }

    impl Drop for FrozenNow {
        fn drop(&mut self) {
            TEST_NOW.with(|cell| cell.set(None));
            TEST_NOW_EXTRA_NANOS.with(|cell| cell.set(0));
        }
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_readiness_is_reposted_and_a_bad_admission_is_not_journaled() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        fixture
            .fake
            .update(|inner| inner.drop_accepted_admit = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .admission
            .is_none());
        FrozenNow::set(now + 700);
        fixture.fake.update(|inner| inner.now = now + 700);
        for _ in 0..4 {
            fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap();
            if fixture.actions.get(&job_id).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        let readiness: Vec<Value> = posts(&fixture.fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .filter(|body: &Value| body["kind"] == "launch_readiness")
            .collect();
        assert_eq!(readiness.len(), 2);
        assert_eq!(readiness[0]["sequence"], 1);
        assert_eq!(readiness[1]["sequence"], 2);
        assert_ne!(readiness[0]["observed_at"], readiness[1]["observed_at"]);
        assert_eq!(
            readiness[0]["reviewed_plan_digest"],
            readiness[1]["reviewed_plan_digest"]
        );
        assert_eq!(
            readiness[0]["backup_observed_at"],
            readiness[1]["backup_observed_at"]
        );
        fixture.server.abort();

        let stale_now = now + 700;
        let stale = FakeAeon::new(stale_now);
        // 1000s is past the 900s freshness window. The handoff has to exist
        // by the observation, or Aeon rejects it as predating the handoff.
        stale.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .expect("deploy handoff")
                .created_at = stale_now - 1000;
        });
        let (origin, server) = serve(stale).await;
        let client = reqwest::Client::new();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let evidence_status = client
            .post(
                origin
                    .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
                    .unwrap(),
            )
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(
                serde_json::to_vec(&json!({
                    "sequence": 1,
                    "kind": "launch_readiness",
                    "outcome": "satisfied",
                    "observed_at": format_timestamp(stale_now - 1000).unwrap(),
                    "authority_epoch": 3,
                    "reviewed_plan_digest": "ab".repeat(32),
                    "host": "hsb8",
                    "all_host_eval_passed": true,
                    "target_build_passed": true,
                    "backup_ready": true,
                    "backup_observed_at": format_timestamp(stale_now).unwrap(),
                    "restart_required": true,
                    "running_kernel": "unknown",
                    "expected_kernel": "unknown"
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(evidence_status, StatusCode::CREATED);
        let refused = client
            .post(
                origin
                    .join(&format!(
                        "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"
                    ))
                    .unwrap(),
            )
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .header("idempotency-key", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .body(
                serde_json::to_vec(&json!({
                    "version_scheme": "legacy",
                    "version": "1.2.3",
                    "release_channel": "stable",
                    "release_sequence": 123,
                    "digest_sha256": "1".repeat(64),
                    "commit_digest": "a".repeat(40),
                    "manifest_coordinate": "ghcr:inspr-at/pharos/releases/1.2.3",
                    "manifest_digest_sha256": "9".repeat(64)
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), StatusCode::CONFLICT);
        let refused: Value = refused.json().await.unwrap();
        assert_eq!(refused["error"], "launch readiness is stale");
        server.abort();

        let bad = harness(true).await;
        prepare_ready_launch(&bad).await;
        bad.fake.update(|inner| inner.corrupt_binding = true);
        let error = bad.adapter.process_intent(&bad.intent).await.unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert!(bad
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .admission
            .is_none());
        assert_eq!(post_count(&bad.fake, "/launch/consume"), 0);
        bad.server.abort();
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
    async fn failed_result_names_a_blocker_and_a_closed_window_is_reporter_stale() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake).await;
        let status = reqwest::Client::new()
            .post(
                origin
                    .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/result"))
                    .unwrap(),
            )
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(
                serde_json::to_vec(&json!({
                    "outcome": "failed",
                    "terminal_sequence": 1,
                    "authority_epoch": 3,
                    "prerequisite_seal_sha256": hex_chars('d')
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::BAD_REQUEST);
        server.abort();

        let failed = harness(false).await;
        failed.adapter.process_intent(&failed.intent).await.unwrap();
        let job_id = failed.actions.list()[0].id.clone();
        fail_review(&failed.actions, &job_id, now_unix());
        failed.adapter.process_intent(&failed.intent).await.unwrap();
        let blocked: Value = posts(&failed.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(blocked["outcome"], "failed");
        assert_eq!(blocked["blocker_code"], "dependency_failed");
        failed.server.abort();

        let now = now_unix();
        let directory = TestDir::new("stale-beacon");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        let mut intent = deploy_intent(false);
        intent.update_restart_job_id = Some(job_id);
        let mut config = runtime_config(origin, api, vec![intent.clone()]);
        config.verification_freshness_secs = 10;
        let adapter = test_adapter(
            config,
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            actions,
        );
        adapter.process_intent(&intent).await.unwrap();
        let stale: Value = posts(&fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(stale["blocker_code"], "reporter_stale");
        server.abort();
    }

    #[tokio::test]
    async fn evidence_predating_the_handoff_is_refused() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake).await;
        let early =
            post_deployment_evidence(&origin, &full_deployment(1, "failed", now - 61)).await;
        assert_eq!(early.0, StatusCode::CONFLICT);
        assert_eq!(early.1["error"], "evidence predates handoff");
        let boundary =
            post_deployment_evidence(&origin, &full_deployment(1, "failed", now - 60)).await;
        assert_eq!(boundary.0, StatusCode::CREATED);
        server.abort();
    }

    async fn post_deployment_evidence(origin: &Url, body: &Value) -> (StatusCode, Value) {
        let response = reqwest::Client::new()
            .post(
                origin
                    .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
                    .unwrap(),
            )
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(serde_json::to_vec(body).unwrap())
            .send()
            .await
            .unwrap();
        let status = response.status();
        let payload = response.json::<Value>().await.unwrap_or(Value::Null);
        (status, payload)
    }

    fn test_adapter_config(intents: Vec<DeliveryIntent>) -> AdapterConfig {
        AdapterConfig {
            aeon_origin: Url::parse("https://aeon.example.test").unwrap(),
            api_key_file: PathBuf::from("api-key"),
            aeon_ca_certificates: Vec::new(),
            poll_interval: Duration::from_secs(5),
            verification_freshness_secs: 300,
            intents,
        }
    }

    #[test]
    fn startup_refuses_a_configured_job_the_adapter_does_not_own() {
        let actions = HostActionStore::new(None);
        let operator = actions
            .create_update_review("hsb8", "operator", 1_700_000_000)
            .unwrap();
        let mut intent = deploy_intent(true);
        intent.update_restart_job_id = Some(operator.id.clone());
        let error = refuse_unowned_configured_jobs(&test_adapter_config(vec![intent]), &actions)
            .unwrap_err();
        assert!(error.contains(operator.id.as_str()));
        assert!(error.contains("not aeon-delivery"));
        assert!(error.contains("operator"));

        let mut missing = deploy_intent(true);
        missing.update_restart_job_id = Some("missingjob".to_string());
        let error = refuse_unowned_configured_jobs(&test_adapter_config(vec![missing]), &actions)
            .unwrap_err();
        assert!(error.contains("not in the host action store"));

        let owned_store = HostActionStore::new(None);
        let owned = owned_store
            .create_update_review("hsb8", ACTOR, 1_700_000_000)
            .unwrap();
        let mut owned_intent = deploy_intent(true);
        owned_intent.update_restart_job_id = Some(owned.id);
        assert!(refuse_unowned_configured_jobs(
            &test_adapter_config(vec![owned_intent]),
            &owned_store
        )
        .is_ok());
    }

    #[tokio::test]
    async fn operator_owned_configured_job_never_binds() {
        let fixture = harness(true).await;
        let job = fixture
            .actions
            .create_update_review("hsb8", "operator", now_unix())
            .unwrap();
        let mut intent = fixture.intent.clone();
        intent.update_restart_job_id = Some(job.id.clone());
        let blocked = fixture.adapter.process_intent(&intent).await.unwrap_err();
        assert!(matches!(
            blocked,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED)
        ));
        assert!(fixture.adapter.journal.operation(DEPLOY_HANDOFF).is_none());
        assert_eq!(readiness_post_count(&fixture.fake), 0);
        assert_eq!(post_count(&fixture.fake, "/launch/admit"), 0);
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), 0);
        let block = fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .unwrap();
        assert_eq!(block.reason, LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED);
        assert!(block.terminal);
        let stored = fixture.actions.get(&job.id).unwrap();
        assert_eq!(stored.requested_by, "operator");
        assert!(stored.confirmed_at.is_none());
        assert_eq!(stored.state, HostActionState::QueuedReview);
        let again = fixture.adapter.process_intent(&intent).await.unwrap_err();
        assert!(matches!(
            again,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED)
        ));
        assert!(fixture.adapter.journal.operation(DEPLOY_HANDOFF).is_none());
        assert_eq!(readiness_post_count(&fixture.fake), 0);
        fixture.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn failed_job_that_predates_the_handoff_posts_evidence_at_now() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let directory = TestDir::new("predate-evidence");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let job = actions
            .create_update_review("hsb8", "operator", now - 10_000)
            .expect("old review");
        fail_review(&actions, &job.id, now - 9_999);
        let failed = actions.get(&job.id).unwrap();
        assert_eq!(failed.state, HostActionState::Failed);
        assert!(failed.updated_at + 60 < now);
        let hosts = Arc::new(Store::new(None).unwrap());
        let mut intent = deploy_intent(false);
        intent.update_restart_job_id = Some(job.id);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            actions,
        );
        adapter.process_intent(&intent).await.unwrap();
        let evidence: Value = posts(&fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(evidence["kind"], "deployment");
        assert_eq!(evidence["outcome"], "failed");
        assert_eq!(evidence["observed_at"], format_timestamp(now).unwrap());
        let recorded = adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::Deployment)
            .unwrap();
        let journaled: Value = serde_json::from_str(&recorded.body_json).unwrap();
        assert_eq!(journaled["observed_at"], evidence["observed_at"]);
        assert!(recorded.receipt.is_some());
        let result: Value = posts(&fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(result["outcome"], "failed");
        assert_eq!(result["blocker_code"], "dependency_failed");
        assert!(adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_some());
        server.abort();
    }

    #[tokio::test]
    async fn wrong_result_seal_is_refused() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let status = reqwest::Client::new()
            .post(
                origin
                    .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/result"))
                    .unwrap(),
            )
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(
                serde_json::to_vec(&json!({
                    "outcome": "succeeded",
                    "terminal_sequence": 1,
                    "authority_epoch": 3,
                    "prerequisite_seal_sha256": hex_chars('e')
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(status, StatusCode::CONFLICT);
        server.abort();

        let directory = TestDir::new("seal");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        let job_id = advance_delegated_job_to_succeeded(&adapter, &actions, &hosts, &intent).await;
        fake.update(|inner| inner.reject_result = true);
        let error = adapter.process_intent(&intent).await.unwrap_err();
        assert!(matches!(error, AdapterError::Refused(status) if status == StatusCode::CONFLICT));
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
        assert_ne!(actions.get(&job_id).unwrap().state, HostActionState::Failed);
        server.abort();
    }

    #[tokio::test]
    async fn result_seal_retry_refuses_lineage_drift() {
        let now = now_unix();
        let directory = TestDir::new("seal-drift");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        advance_delegated_job_to_succeeded(&adapter, &actions, &hosts, &intent).await;
        fake.update(|inner| {
            inner.bump_seal_on_result = true;
            inner.arm_lineage_drift = true;
        });
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

    struct SealedDeploy {
        fake: FakeAeon,
        server: tokio::task::JoinHandle<()>,
        adapter: AeonDeliveryAdapter,
        hosts: Arc<Store>,
        _directory: TestDir,
    }

    async fn sealed_deploy() -> SealedDeploy {
        let now = now_unix();
        let directory = TestDir::new("verify-lineage");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone(), verify_intent()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        advance_delegated_job_to_succeeded(&adapter, &actions, &hosts, &intent).await;
        adapter.process_intent(&intent).await.unwrap();
        SealedDeploy {
            fake,
            server,
            adapter,
            hosts,
            _directory: directory,
        }
    }

    fn arm_verify_seal(fake: &FakeAeon, predecessor: &str, epoch: i64) {
        fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(VERIFY_HANDOFF).unwrap();
            handoff.authority_epoch = epoch;
            handoff.predecessor_digest = predecessor.to_string();
            handoff.prerequisite_seal_sha256 = predecessor.to_string();
        });
    }

    #[tokio::test]
    async fn verify_lineage_matches_the_deployment_dependency_digest() {
        let sealed = sealed_deploy().await;
        let receipt = sealed
            .adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .unwrap();
        let seal = dependency_digest(DEPLOY_HANDOFF, "deployment", receipt.terminal_sequence);
        assert_ne!(
            sealed
                .fake
                .update(|inner| inner.handoffs[DEPLOY_HANDOFF].authority_epoch),
            11
        );
        arm_verify_seal(&sealed.fake, &seal, 11);
        record_beacon(&sealed.hosts, now_unix() + 1, &artifact());
        sealed
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap();
        let verification: Value = posts(&sealed.fake)
            .into_iter()
            .find(|capture| {
                capture.path.contains(VERIFY_HANDOFF) && capture.path.ends_with("/evidence")
            })
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(verification["kind"], "verification");
        assert_eq!(verification["outcome"], "succeeded");
        assert_eq!(
            sealed
                .adapter
                .journal
                .result(VERIFY_HANDOFF)
                .unwrap()
                .receipt
                .unwrap()
                .outcome,
            ResultOutcome::Succeeded
        );
        assert_eq!(
            sealed
                .fake
                .update(|inner| inner.handoffs[VERIFY_HANDOFF].predecessor_digest.clone()),
            dependency_digest(DEPLOY_HANDOFF, "deployment", receipt.terminal_sequence)
        );
        sealed.server.abort();
    }

    #[tokio::test]
    async fn verify_result_rotated_seal_retry_succeeds() {
        let sealed = sealed_deploy().await;
        let receipt = sealed
            .adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .unwrap();
        let seal = dependency_digest(DEPLOY_HANDOFF, "deployment", receipt.terminal_sequence);
        arm_verify_seal(&sealed.fake, &seal, 11);
        record_beacon(&sealed.hosts, now_unix() + 1, &artifact());
        sealed.fake.update(|inner| inner.bump_seal_on_result = true);
        sealed
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap();
        let results: Vec<Value> = posts(&sealed.fake)
            .into_iter()
            .filter(|capture| {
                capture.path.contains(VERIFY_HANDOFF) && capture.path.ends_with("/result")
            })
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .collect();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0]["prerequisite_seal_sha256"], seal);
        assert_eq!(results[1]["prerequisite_seal_sha256"], hex_chars('f'));
        assert_eq!(
            sealed
                .adapter
                .journal
                .result(VERIFY_HANDOFF)
                .unwrap()
                .receipt
                .unwrap()
                .outcome,
            ResultOutcome::Succeeded
        );
        sealed.server.abort();
    }

    #[tokio::test]
    async fn verify_lineage_mismatch_is_refused() {
        let sealed = sealed_deploy().await;
        arm_verify_seal(&sealed.fake, &hex_chars('e'), 11);
        let error = sealed
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert!(posts(&sealed.fake)
            .iter()
            .all(|capture| !capture.path.contains(VERIFY_HANDOFF)));
        sealed.server.abort();
    }

    fn arm_recorded_deploy(sealed: &SealedDeploy) {
        let receipt = sealed
            .adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .unwrap();
        let seal = dependency_digest(DEPLOY_HANDOFF, "deployment", receipt.terminal_sequence);
        arm_verify_seal(&sealed.fake, &seal, 11);
    }

    #[tokio::test]
    async fn verify_mismatch_fails_and_an_unreadable_beacon_is_not_terminal() {
        let mismatched = sealed_deploy().await;
        arm_recorded_deploy(&mismatched);
        let mut evidence = measured(&artifact(), now_unix() + 1);
        evidence.artifact_version = "9.9.9".to_string();
        record_deployed(&mismatched.hosts, now_unix() + 1, evidence);
        mismatched
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap();
        let failed: Value = posts(&mismatched.fake)
            .into_iter()
            .find(|capture| {
                capture.path.contains(VERIFY_HANDOFF) && capture.path.ends_with("/evidence")
            })
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(failed["outcome"], "failed");
        let result: Value = posts(&mismatched.fake)
            .into_iter()
            .find(|capture| {
                capture.path.contains(VERIFY_HANDOFF) && capture.path.ends_with("/result")
            })
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(result["blocker_code"], "dependency_failed");
        mismatched
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap();
        assert_eq!(
            posts(&mismatched.fake)
                .iter()
                .filter(|capture| {
                    capture.path.contains(VERIFY_HANDOFF) && capture.path.ends_with("/evidence")
                })
                .count(),
            1
        );
        mismatched.server.abort();

        let unreadable = sealed_deploy().await;
        arm_recorded_deploy(&unreadable);
        let mut evidence = measured(&artifact(), now_unix() + 1);
        evidence.digest_class = ArtifactDigestClass::OciManifest;
        evidence.oci_config_digest = None;
        evidence.oci_manifest_digest = Some(evidence.digest.clone());
        record_deployed(&unreadable.hosts, now_unix() + 1, evidence);
        let error = unreadable
            .adapter
            .process_intent(&verify_intent())
            .await
            .unwrap_err();
        assert!(matches!(error, AdapterError::LocalBinding));
        assert!(unreadable
            .adapter
            .journal
            .evidence_with_kind(VERIFY_HANDOFF, EvidenceKind::Verification)
            .is_none());
        let again = unreadable.adapter.process_intent(&verify_intent()).await;
        assert!(matches!(again, Err(AdapterError::LocalBinding)));
        assert!(posts(&unreadable.fake)
            .iter()
            .all(|capture| !capture.path.contains(VERIFY_HANDOFF)));
        unreadable.server.abort();
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
            // Aeon sets predecessor_digest to the dependency seal, not the
            // previous attempt's plan digest.
            next.predecessor_digest = hex_chars('f');
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
        assert_ne!(
            adapter
                .journal
                .operation(DEPLOY_HANDOFF)
                .unwrap()
                .plan_digest,
            adapter
                .journal
                .operation(NEW_HANDOFF)
                .unwrap()
                .predecessor_digest
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

    async fn attempt_two_after(
        label: &str,
        settle: impl FnOnce(&HostActionStore, &str),
    ) -> (Arc<HostActionStore>, String, String) {
        let now = now_unix();
        let directory = TestDir::new(label);
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| {
            let mut next = FakeHandoff::deploy(now);
            next.id = NEW_HANDOFF.to_string();
            next.attempt = 2;
            next.plan_digest = hex_chars('e');
            next.predecessor_digest = hex_chars('f');
            inner.handoffs.insert(NEW_HANDOFF.to_string(), next);
        });
        let (origin, server) = serve(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let first = deploy_intent(false);
        let mut next = deploy_intent(false);
        next.handoff_id = NEW_HANDOFF.to_string();
        let adapter = test_adapter(
            runtime_config(origin, api, vec![first.clone(), next.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            Arc::clone(&actions),
        );
        adapter.process_intent(&first).await.unwrap();
        let predecessor = adapter.journal.operation(DEPLOY_HANDOFF).unwrap().job_id;
        settle(&actions, &predecessor);
        adapter.process_intent(&next).await.unwrap();
        let retried = adapter.journal.operation(NEW_HANDOFF).unwrap().job_id;
        adapter.process_intent(&next).await.unwrap();
        server.abort();
        (actions, predecessor, retried)
    }

    #[tokio::test]
    async fn cancelled_predecessor_starts_a_fresh_review() {
        let (actions, predecessor, retried) =
            attempt_two_after("retry-cancelled", |actions, id| {
                let at = now_unix().max(actions.get(id).unwrap().updated_at);
                actions
                    .cancel_update_review(id, "hsb8", "operator", at)
                    .expect("cancel predecessor");
            })
            .await;
        assert_eq!(
            actions.get(&predecessor).unwrap().state,
            HostActionState::Cancelled
        );
        let job = actions.get(&retried).unwrap();
        assert_eq!(job.state, HostActionState::QueuedReview);
        assert!(job.retry_of.is_none());
        assert_ne!(retried, predecessor);
        assert_eq!(job.requested_by, ACTOR);
    }

    #[tokio::test]
    async fn succeeded_predecessor_starts_a_fresh_review() {
        let (actions, predecessor, retried) =
            attempt_two_after("retry-succeeded", |actions, id| {
                let created = actions.get(id).unwrap().created_at;
                review_job(actions, id, created);
                let reviewed = actions.get(id).unwrap().updated_at;
                actions
                    .confirm_update(id, "hsb8", "operator", reviewed)
                    .expect("confirm predecessor");
                let confirmed = actions.get(id).unwrap().updated_at;
                finish_apply(actions, id, confirmed);
            })
            .await;
        assert_eq!(
            actions.get(&predecessor).unwrap().state,
            HostActionState::Succeeded
        );
        let job = actions.get(&retried).unwrap();
        assert_eq!(job.state, HostActionState::QueuedReview);
        assert!(job.retry_of.is_none());
        assert_ne!(retried, predecessor);
        assert_eq!(job.requested_by, ACTOR);
    }

    #[tokio::test]
    async fn launch_readiness_backup_time_is_present_and_not_ahead() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake).await;
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
            .unwrap();
        let client = reqwest::Client::new();
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
            "restart_required": true,
            "running_kernel": "unknown",
            "expected_kernel": "unknown"
        });
        let missing = send(readiness.clone()).await;
        assert_eq!(missing.status(), StatusCode::BAD_REQUEST);
        let missing: Value = missing.json().await.unwrap();
        assert_eq!(missing["error"], "invalid launch readiness");
        readiness["backup_observed_at"] = json!("0001-01-01T00:00:00Z");
        let zero = send(readiness.clone()).await;
        assert_eq!(zero.status(), StatusCode::BAD_REQUEST);
        readiness["backup_observed_at"] = json!("yesterday");
        let unparsed = send(readiness.clone()).await;
        assert_eq!(unparsed.status(), StatusCode::BAD_REQUEST);
        readiness["backup_observed_at"] = json!(format_timestamp(now + 301).unwrap());
        let ahead = send(readiness.clone()).await;
        assert_eq!(ahead.status(), StatusCode::BAD_REQUEST);
        readiness["backup_observed_at"] = json!(format_timestamp(now - 901).unwrap());
        let aged = send(readiness).await;
        assert_eq!(aged.status(), StatusCode::CREATED);
        let admitted = client
            .post(
                origin
                    .join(&format!(
                        "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"
                    ))
                    .unwrap(),
            )
            .header(AUTHORIZATION, bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .header("idempotency-key", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            .body(
                serde_json::to_vec(&json!({
                    "version_scheme": "legacy",
                    "version": "1.2.3",
                    "release_channel": "stable",
                    "release_sequence": 123,
                    "digest_sha256": "1".repeat(64),
                    "commit_digest": "a".repeat(40),
                    "manifest_coordinate": "ghcr:inspr-at/pharos/releases/1.2.3",
                    "manifest_digest_sha256": "9".repeat(64)
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(admitted.status(), StatusCode::OK);
        server.abort();
    }

    #[tokio::test]
    async fn backup_clock_echo_uses_go_zero_time_when_omitted() {
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
            }
        };
        let omitted = send(json!({
            "sequence": 1,
            "kind": "deployment",
            "outcome": "succeeded",
            "observed_at": format_timestamp(now).unwrap(),
            "authority_epoch": 3
        }))
        .await;
        assert_eq!(omitted.status(), StatusCode::BAD_REQUEST);
        let unconsumed = send(full_deployment(1, "succeeded", now)).await;
        assert_eq!(unconsumed.status(), StatusCode::CONFLICT);
        server.abort();

        let now = now_unix();
        let fake = FakeAeon::new(now);
        let (origin, server) = serve(fake.clone()).await;
        let client = reqwest::Client::new();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let readiness = json!({
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
            "running_kernel": "6.18.1",
            "expected_kernel": "6.18.2"
        });
        let post = |path: String, body: Value, key: Option<&str>| {
            let client = client.clone();
            let origin = origin.clone();
            let bearer = bearer.clone();
            let key = key.map(str::to_string);
            async move {
                let mut request = client
                    .post(origin.join(&path).unwrap())
                    .header(AUTHORIZATION, bearer)
                    .header(CONTENT_TYPE, JSON_MEDIA);
                if let Some(key) = key {
                    request = request.header("idempotency-key", key);
                }
                request
                    .body(serde_json::to_vec(&body).unwrap())
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(
            post(
                format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"),
                readiness.clone(),
                None
            )
            .await,
            StatusCode::CREATED
        );
        let mut changed = readiness.clone();
        changed["sequence"] = json!(2);
        changed["reviewed_plan_digest"] = json!("cd".repeat(32));
        assert_eq!(
            post(
                format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"),
                changed,
                None
            )
            .await,
            StatusCode::CONFLICT
        );
        let mut wrong = held_launch_artifact();
        wrong["digest_sha256"] = json!("2".repeat(64));
        assert_eq!(
            post(
                format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"),
                wrong,
                Some("aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
            )
            .await,
            StatusCode::CONFLICT
        );
        assert_eq!(
            post(
                format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"),
                held_launch_artifact(),
                Some("bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            )
            .await,
            StatusCode::OK
        );
        fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            handoff.consumed = true;
            handoff.consumed_at = Some(format_timestamp(now).unwrap());
        });
        assert_eq!(
            post(
                format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"),
                held_launch_artifact(),
                Some("cccccccc-cccc-4ccc-8ccc-cccccccccccc")
            )
            .await,
            StatusCode::CONFLICT
        );
        server.abort();
    }

    #[tokio::test]
    async fn evidence_replay_is_idempotent_and_divergent_replay_conflicts() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        fake.update(|inner| {
            inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap().consumed = true;
        });
        let (origin, server) = serve(fake.clone()).await;
        let client = reqwest::Client::new();
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
            .unwrap();
        let body = serde_json::to_vec(&full_deployment(1, "succeeded", now)).unwrap();
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

        let replayed = harness(false).await;
        replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .unwrap();
        let job_id = replayed.actions.list()[0].id.clone();
        fail_review(&replayed.actions, &job_id, now_unix());
        replayed.fake.update(|inner| inner.fail_next_post = true);
        assert!(replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .is_err());
        let journaled = replayed
            .adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::Deployment)
            .unwrap();
        assert!(journaled.receipt.is_none());
        replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .unwrap();
        let saved = replayed
            .adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::Deployment)
            .unwrap();
        assert!(saved.receipt.is_some());
        let bodies: Vec<_> = posts(&replayed.fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| capture.body)
            .collect();
        assert_eq!(bodies.len(), 2);
        assert_eq!(bodies[0], bodies[1]);
        assert_eq!(bodies[0], journaled.body_json.as_bytes());
        replayed.server.abort();
    }

    #[tokio::test]
    async fn evidence_sequence_must_be_contiguous_and_replay_reuses_it() {
        let now = now_unix();
        let fake = FakeAeon::new(now);
        fake.update(|inner| {
            inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap().consumed = true;
        });
        let (origin, server) = serve(fake).await;
        let client = reqwest::Client::new();
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/evidence"))
            .unwrap();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let send = |sequence: i64| {
            let client = client.clone();
            let url = url.clone();
            let bearer = bearer.clone();
            async move {
                client
                    .post(url)
                    .header(AUTHORIZATION, bearer)
                    .header(CONTENT_TYPE, JSON_MEDIA)
                    .body(serde_json::to_vec(&full_deployment(sequence, "succeeded", now)).unwrap())
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(send(2).await, StatusCode::CONFLICT);
        assert_eq!(send(1).await, StatusCode::CREATED);
        assert_eq!(send(1).await, StatusCode::CREATED);
        assert_eq!(send(3).await, StatusCode::CONFLICT);
        server.abort();

        let replayed = harness(false).await;
        replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .unwrap();
        let job_id = replayed.actions.list()[0].id.clone();
        fail_review(&replayed.actions, &job_id, now_unix());
        replayed.fake.update(|inner| inner.fail_next_post = true);
        assert!(replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .is_err());
        replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .unwrap();
        let sequences: Vec<i64> = posts(&replayed.fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| {
                serde_json::from_slice::<Value>(&capture.body).unwrap()["sequence"]
                    .as_i64()
                    .unwrap()
            })
            .collect();
        assert_eq!(sequences, vec![1, 1]);
        assert!(replayed
            .adapter
            .journal
            .evidence_with_kind(DEPLOY_HANDOFF, EvidenceKind::Deployment)
            .unwrap()
            .receipt
            .is_some());
        replayed.server.abort();
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
        let admit_url = origin
            .join(&format!(
                "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/admit"
            ))
            .unwrap();
        let missing_key = client
            .post(admit_url.clone())
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(admit.clone())
            .send()
            .await
            .unwrap();
        assert_eq!(missing_key.status(), StatusCode::BAD_REQUEST);
        let missing_key: Value = missing_key.json().await.unwrap();
        assert_eq!(missing_key["error"], "Idempotency-Key must be a UUID");
        let admitted = client
            .post(admit_url)
            .header(AUTHORIZATION, &bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .header("idempotency-key", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
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
            .header("idempotency-key", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            .body(consume_body.clone())
            .send();
        let second = client
            .post(consume_url)
            .header(AUTHORIZATION, bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .header("idempotency-key", "cccccccc-cccc-4ccc-8ccc-cccccccccccc")
            .body(consume_body)
            .send();
        let (left, right) = tokio::join!(first, second);
        let mut statuses = [left.unwrap().status(), right.unwrap().status()];
        statuses.sort_by_key(|status| status.as_u16());
        assert_eq!(statuses, [StatusCode::OK, StatusCode::CONFLICT]);
        server.abort();

        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        for _ in 0..4 {
            fixture
                .adapter
                .process_intent(&fixture.intent)
                .await
                .unwrap();
            if fixture.actions.get(&job_id).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), 1);
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        let again = reqwest::Client::new()
            .post(
                fixture
                    .adapter
                    .config
                    .aeon_origin
                    .join(&format!(
                        "/api/stage-handoffs/{DEPLOY_HANDOFF}/launch/consume"
                    ))
                    .unwrap(),
            )
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .header(CONTENT_TYPE, JSON_MEDIA)
            .header("idempotency-key", "dddddddd-dddd-4ddd-8ddd-dddddddddddd")
            .body(launch.consume_body_json.unwrap())
            .send()
            .await
            .unwrap();
        assert_eq!(again.status(), StatusCode::CONFLICT);
        fixture.server.abort();
    }

    fn readiness_bodies(fake: &FakeAeon) -> Vec<Value> {
        posts(fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/evidence"))
            .filter_map(|capture| serde_json::from_slice::<Value>(&capture.body).ok())
            .filter(|body| body["kind"] == "launch_readiness")
            .collect()
    }

    fn readiness_post_count(fake: &FakeAeon) -> usize {
        readiness_bodies(fake).len()
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
    async fn consume_crash_before_ack_recovers_on_replay_and_confirms_once() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
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
        let crashed = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(crashed.consume_started);
        assert!(crashed.receipt.is_none());
        assert!(crashed.consume_unresolved.is_none());
        let consumes_after_crash = post_count(&fixture.fake, "/launch/consume");
        let admits_after_crash = post_count(&fixture.fake, "/launch/admit");
        assert_eq!(consumes_after_crash, 1);

        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        let receipt = launch.receipt.unwrap();
        assert!(receipt.consumed);
        assert_eq!(receipt.admission_id, ADMISSION_ID);
        assert!(parse_timestamp(&receipt.consumed_at).is_ok());
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::QueuedApply);
        assert_eq!(
            job.events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        assert_eq!(
            post_count(&fixture.fake, "/launch/consume"),
            consumes_after_crash + 1
        );
        assert_eq!(
            post_count(&fixture.fake, "/launch/admit"),
            admits_after_crash
        );

        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        assert_eq!(
            fixture
                .actions
                .get(&job_id)
                .unwrap()
                .events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        assert_eq!(
            post_count(&fixture.fake, "/launch/consume"),
            consumes_after_crash + 1
        );
        fixture.server.abort();
    }

    #[tokio::test]
    async fn divergent_consume_replay_is_unresolved_without_a_host_change() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        fixture
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        fixture.fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            handoff.consumed_by_principal_id =
                Some("88888888-8888-4888-8888-888888888888".to_string());
            for call in handoff.launch_calls.values_mut() {
                if call.action == "consume" {
                    call.body_digest = "0".repeat(64);
                }
            }
        });
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
        let consumes = post_count(&fixture.fake, "/launch/consume");
        let later = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(later, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        fixture.server.abort();
    }

    #[tokio::test]
    async fn get_admission_does_not_stand_in_for_the_consume_receipt() {
        let admitted = harness(true).await;
        let _job = prepare_ready_launch(&admitted).await;
        admitted
            .fake
            .update(|inner| inner.drop_accepted_admit = true);
        assert!(admitted
            .adapter
            .process_intent(&admitted.intent)
            .await
            .is_err());
        let document = fetch_handoff(&admitted.adapter.config.aeon_origin, DEPLOY_HANDOFF).await;
        assert_eq!(
            admission_keys(&document),
            vec!["admission_id", "epoch", "expires_at"]
        );
        assert_eq!(document["admission"]["admission_id"], ADMISSION_ID);
        assert_eq!(document["admission"]["epoch"], 3);
        assert!(document["admission"]["expires_at"].is_string());
        admitted.server.abort();

        let recovered = harness(true).await;
        let job_id = prepare_ready_launch(&recovered).await;
        recovered
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(recovered
            .adapter
            .process_intent(&recovered.intent)
            .await
            .is_err());
        let before = recovered.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(before.consume_started);
        assert!(before.receipt.is_none());
        let document = fetch_handoff(&recovered.adapter.config.aeon_origin, DEPLOY_HANDOFF).await;
        assert_eq!(
            admission_keys(&document),
            vec![
                "admission_id",
                "consumed_at",
                "consumed_by_principal_id",
                "epoch",
                "expires_at",
            ]
        );
        assert_eq!(document["admission"]["admission_id"], ADMISSION_ID);
        assert!(document["admission"]["consumed_at"].is_string());
        assert_eq!(
            document["admission"]["consumed_by_principal_id"],
            LAUNCH_PRINCIPAL
        );
        assert!(recovered
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_none());
        let consumes = post_count(&recovered.fake, "/launch/consume");
        recovered
            .adapter
            .process_intent(&recovered.intent)
            .await
            .unwrap();
        assert_eq!(post_count(&recovered.fake, "/launch/consume"), consumes + 1);
        let launch = recovered.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        let receipt = launch.receipt.unwrap();
        assert!(receipt.consumed);
        assert_eq!(receipt.admission_id, ADMISSION_ID);
        assert!(parse_timestamp(&receipt.consumed_at).is_ok());
        assert_eq!(
            recovered.actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        assert_eq!(
            recovered
                .actions
                .get(&job_id)
                .unwrap()
                .events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        recovered
            .adapter
            .process_intent(&recovered.intent)
            .await
            .unwrap();
        assert_eq!(post_count(&recovered.fake, "/launch/consume"), consumes + 1);
        assert_eq!(
            recovered
                .actions
                .get(&job_id)
                .unwrap()
                .events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        recovered.server.abort();

        let unresolved = harness(true).await;
        let unresolved_job = prepare_ready_launch(&unresolved).await;
        unresolved
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(unresolved
            .adapter
            .process_intent(&unresolved.intent)
            .await
            .is_err());
        unresolved.fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            handoff.consumed_by_principal_id =
                Some("88888888-8888-4888-8888-888888888888".to_string());
            for call in handoff.launch_calls.values_mut() {
                if call.action == "consume" {
                    call.body_digest = "0".repeat(64);
                }
            }
        });
        let document = fetch_handoff(&unresolved.adapter.config.aeon_origin, DEPLOY_HANDOFF).await;
        assert!(document["admission"]["consumed_at"].is_string());
        assert_eq!(document["admission"]["admission_id"], ADMISSION_ID);
        assert_ne!(
            document["admission"]["consumed_by_principal_id"],
            LAUNCH_PRINCIPAL
        );
        let replay = unresolved.adapter.process_intent(&unresolved.intent).await;
        assert!(matches!(replay, Err(AdapterError::LaunchUnresolved)));
        let launch = unresolved.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert_eq!(
            launch.consume_unresolved,
            Some(StatusCode::CONFLICT.as_u16())
        );
        assert!(launch.receipt.is_none());
        assert_eq!(
            unresolved.actions.get(&unresolved_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert!(unresolved
            .actions
            .get(&unresolved_job)
            .unwrap()
            .confirmed_at
            .is_none());
        let consumes = post_count(&unresolved.fake, "/launch/consume");
        let later = unresolved.adapter.process_intent(&unresolved.intent).await;
        assert!(matches!(later, Err(AdapterError::LaunchUnresolved)));
        assert_eq!(post_count(&unresolved.fake, "/launch/consume"), consumes);
        unresolved.server.abort();
    }

    async fn fetch_handoff(origin: &Url, id: &str) -> Value {
        let response = reqwest::Client::new()
            .get(origin.join(&format!("/api/stage-handoffs/{id}")).unwrap())
            .header(
                AUTHORIZATION,
                format!("Bearer {}", String::from_utf8_lossy(API_KEY)),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        response.json().await.unwrap()
    }

    fn admission_keys(document: &Value) -> Vec<String> {
        let mut keys: Vec<_> = document["admission"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        keys.sort();
        keys
    }

    #[tokio::test]
    async fn exact_consume_replay_expires_a_day_after_the_handoff_is_terminal() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        fixture
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        fixture.fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            let completed_at = format_timestamp(inner.now - 24 * 60 * 60 - 5).unwrap();
            handoff.state = "succeeded".to_string();
            handoff.result = Some(json!({
                "outcome": "succeeded",
                "terminal_sequence": 1,
                "authority_epoch": 3,
                "prerequisite_seal_sha256": hex_chars('d'),
                "handoff_id": DEPLOY_HANDOFF,
                "completed_at": completed_at,
            }));
        });
        let replay = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            replay,
            Err(AdapterError::LaunchBlocked(LAUNCH_BLOCK_AUTHORITY_CLOSED))
        ));
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(launch.consume_unresolved.is_none());
        let receipt = launch.receipt.as_ref().unwrap();
        assert!(receipt.reconciled_from_get);
        assert!(receipt.consumed);
        assert_eq!(receipt.admission_id, ADMISSION_ID);
        let rendered = serde_json::to_string(&launch).unwrap();
        assert!(!rendered.contains(LAUNCH_PRINCIPAL));
        assert!(!rendered.contains("AEON_API_KEY_SENTINEL"));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert!(result_posts(&fixture.fake).is_empty());
        fixture.server.abort();
    }

    async fn closed_authority_is_not_confirmed(edit: impl FnOnce(&mut FakeHandoff)) {
        let fixture = harness(true).await;
        let job_id = dropped_consume(&fixture).await;
        fixture.fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            edit(handoff);
        });
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_AUTHORITY_CLOSED)
        ));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        let results = result_posts(&fixture.fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "dependency_failed");
        assert!(results[0].get("detail").is_none());
        assert_eq!(
            fixture
                .adapter
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some(LAUNCH_BLOCK_AUTHORITY_CLOSED)
        );
        let later = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            later,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_AUTHORITY_CLOSED)
        ));
        assert_eq!(result_posts(&fixture.fake).len(), 1);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn failed_handoff_does_not_queue_a_recovered_job() {
        closed_authority_is_not_confirmed(|handoff| {
            handoff.state = "failed".to_string();
        })
        .await;
    }

    #[tokio::test]
    async fn moved_authority_epoch_does_not_queue_a_recovered_job() {
        closed_authority_is_not_confirmed(|handoff| {
            handoff.authority_epoch = 4;
        })
        .await;
    }

    fn expected_blocker_for_reason(reason: &str) -> &'static str {
        match reason {
            LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING
            | LAUNCH_BLOCK_BACKUP_NOT_READY
            | LAUNCH_BLOCK_READINESS_FLAG_FALSE => "external_waiting",
            LAUNCH_BLOCK_READINESS_PLAN_CHANGED
            | LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED
            | LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED
            | LAUNCH_BLOCK_LAUNCH_NOT_OWNED
            | LAUNCH_BLOCK_CONFIGURED_JOB_NOT_OWNED
            | LAUNCH_BLOCK_ADMISSION_EXPIRED => "policy_refused",
            LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB
            | LAUNCH_BLOCK_CONSUME_ABANDONED
            | LAUNCH_BLOCK_AUTHORITY_CLOSED => "dependency_failed",
            _ => panic!("reason {reason} has no Aeon blocker code"),
        }
    }

    #[test]
    fn every_launch_block_reason_maps_to_an_accepted_blocker_code() {
        assert_eq!(
            AEON_BLOCKER_CODES,
            [
                "dependency_pending",
                "dependency_failed",
                "reporter_stale",
                "external_waiting",
                "policy_refused",
            ]
        );
        assert!(!LAUNCH_BLOCK_REASONS.is_empty());
        let mut seen = BTreeSet::new();
        for reason in LAUNCH_BLOCK_REASONS {
            assert_eq!(launch_block_reason(reason), Some(*reason));
            let code = aeon_blocker_for_reason(reason)
                .unwrap_or_else(|| panic!("unmapped reason {reason}"));
            let wire = blocker_code_wire(code);
            assert_eq!(serde_json::to_value(code).unwrap(), json!(wire));
            assert!(
                AEON_BLOCKER_CODES.contains(&wire),
                "{reason} maps to {wire}"
            );
            assert_eq!(wire, expected_blocker_for_reason(reason), "{reason}");
            let posted = serde_json::to_value(ResultRequest {
                outcome: ResultOutcome::Failed,
                terminal_sequence: 1,
                authority_epoch: 1,
                prerequisite_seal_sha256: "ab".repeat(32),
                blocker_code: Some(code),
            })
            .unwrap();
            assert_eq!(posted["blocker_code"], wire);
            assert!(posted.get("detail").is_none());
            assert!(seen.insert(*reason));
        }
        assert_eq!(seen.len(), LAUNCH_BLOCK_REASONS.len());
        assert!(aeon_blocker_for_reason("not_a_pharos_reason").is_none());
        for code in [
            BlockerCode::DependencyPending,
            BlockerCode::DependencyFailed,
            BlockerCode::ReporterStale,
            BlockerCode::ExternalWaiting,
            BlockerCode::PolicyRefused,
        ] {
            let wire = blocker_code_wire(code);
            assert!(AEON_BLOCKER_CODES.contains(&wire));
            assert_eq!(serde_json::to_value(code).unwrap(), json!(wire));
        }
    }

    #[tokio::test]
    async fn fake_aeon_rejects_a_blocker_code_aeon_would_not_accept() {
        let fake = FakeAeon::new(now_unix());
        let (origin, server) = serve(fake).await;
        let client = reqwest::Client::new();
        let url = origin
            .join(&format!("/api/stage-handoffs/{DEPLOY_HANDOFF}/result"))
            .unwrap();
        let bearer = format!("Bearer {}", String::from_utf8_lossy(API_KEY));
        let send = |blocker: Value| {
            let client = client.clone();
            let url = url.clone();
            let bearer = bearer.clone();
            async move {
                client
                    .post(url)
                    .header(AUTHORIZATION, bearer)
                    .header(CONTENT_TYPE, JSON_MEDIA)
                    .body(
                        serde_json::to_vec(&json!({
                            "outcome": "failed",
                            "terminal_sequence": 1,
                            "authority_epoch": 3,
                            "prerequisite_seal_sha256": hex_chars('d'),
                            "blocker_code": blocker,
                        }))
                        .unwrap(),
                    )
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        for reason in LAUNCH_BLOCK_REASONS {
            assert_eq!(
                send(json!(reason)).await,
                StatusCode::BAD_REQUEST,
                "{reason}"
            );
        }
        assert_eq!(send(json!("not_a_blocker")).await, StatusCode::BAD_REQUEST);
        for code in AEON_BLOCKER_CODES {
            assert_eq!(send(json!(code)).await, StatusCode::CONFLICT, "{code}");
        }
        let succeeded_with_blocker = client
            .post(url)
            .header(AUTHORIZATION, bearer)
            .header(CONTENT_TYPE, JSON_MEDIA)
            .body(
                serde_json::to_vec(&json!({
                    "outcome": "succeeded",
                    "terminal_sequence": 1,
                    "authority_epoch": 3,
                    "prerequisite_seal_sha256": hex_chars('d'),
                    "blocker_code": "policy_refused",
                }))
                .unwrap(),
            )
            .send()
            .await
            .unwrap()
            .status();
        assert_eq!(succeeded_with_blocker, StatusCode::BAD_REQUEST);
        server.abort();
    }

    fn result_posts(fake: &FakeAeon) -> Vec<Value> {
        posts(fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .collect()
    }

    async fn dropped_consume(fixture: &Harness) -> String {
        let job_id = prepare_ready_launch(fixture).await;
        fixture
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_none());
        job_id
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_admission_closes_the_handoff_without_confirming() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = dropped_consume(&fixture).await;
        FrozenNow::set(now + 3600);
        fixture.fake.update(|inner| inner.now = now + 3600);
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_some());
        let results = result_posts(&fixture.fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "policy_refused");
        assert!(results[0].get("detail").is_none());
        let recorded = fixture.adapter.journal.result(DEPLOY_HANDOFF).unwrap();
        assert_eq!(
            recorded.detail.as_deref(),
            Some(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        );
        assert!(recorded.receipt.is_some());
        let document = fetch_handoff(&fixture.adapter.config.aeon_origin, DEPLOY_HANDOFF).await;
        assert_eq!(document["state"], "failed");
        assert_eq!(document["result"]["blocker_code"], "policy_refused");
        let later = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            later,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        assert_eq!(result_posts(&fixture.fake).len(), 1);
        fixture.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn expired_admission_is_not_confirmed_after_the_handoff_is_stale() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = dropped_consume(&fixture).await;
        FrozenNow::set(now + 4000);
        fixture.fake.update(|inner| inner.now = now + 4000);
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_some());
        assert_eq!(
            fixture
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_ADMISSION_EXPIRED
        );
        assert!(fixture.adapter.journal.result(DEPLOY_HANDOFF).is_none());
        assert!(result_posts(&fixture.fake).is_empty());
        let later = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            later,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        assert!(fixture.adapter.journal.result(DEPLOY_HANDOFF).is_none());
        assert!(result_posts(&fixture.fake).is_empty());
        fixture.server.abort();
    }

    fn stamp_with_millis(unix_seconds: i64, millis: u32) -> String {
        assert!(millis < 1000);
        let whole = format_timestamp(unix_seconds).unwrap();
        let split = whole.rfind(['Z', '+']).expect("rfc3339 offset");
        let (bare, suffix) = whole.split_at(split);
        format!("{bare}.{millis:03}{suffix}")
    }

    #[test]
    fn timestamp_nanos_keeps_a_fractional_second() {
        let whole = format_timestamp(1_800_000_000).unwrap();
        let fractional = stamp_with_millis(1_800_000_000, 800);
        assert_eq!(
            timestamp_nanos(&fractional).unwrap() - timestamp_nanos(&whole).unwrap(),
            800_000_000
        );
    }

    fn set_deploy_expiry(fake: &FakeAeon, expires_at: String) {
        fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .expect("deploy handoff")
                .expires_at = expires_at;
        });
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fractional_expiry_still_confirms_inside_the_same_second() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        set_deploy_expiry(&fixture.fake, stamp_with_millis(now + 3600, 800));
        let job_id = dropped_consume(&fixture).await;
        let admission = fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .admission
            .unwrap();
        assert!(
            admission.expires_at.contains(".800"),
            "{}",
            admission.expires_at
        );
        FrozenNow::set(now + 3600);
        FrozenNow::set_extra_nanos(100_000_000);
        fixture.fake.update(|inner| inner.now = now + 3600);
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        assert!(fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .is_none());
        assert!(result_posts(&fixture.fake).is_empty());
        fixture.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn fractional_expiry_after_the_instant_posts_nothing() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        set_deploy_expiry(&fixture.fake, stamp_with_millis(now + 3600, 200));
        let job_id = dropped_consume(&fixture).await;
        FrozenNow::set(now + 3600);
        FrozenNow::set_extra_nanos(500_000_000);
        fixture.fake.update(|inner| inner.now = now + 3600);
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert_eq!(
            fixture
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_ADMISSION_EXPIRED
        );
        assert!(fixture.adapter.journal.result(DEPLOY_HANDOFF).is_none());
        assert!(result_posts(&fixture.fake).is_empty());
        fixture.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unconsumed_expired_admission_reports_policy_refused() {
        // admission_lifetime_secs is FakeAeon-only. Real Aeon copies the handoff
        // expiry, so this shorter admission cannot be issued there.
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        fixture
            .fake
            .update(|inner| inner.admission_lifetime_secs = Some(30));
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(launch.admission.is_some());
        assert!(launch.consume_started);
        assert!(launch.receipt.is_none());
        let consumes = post_count(&fixture.fake, "/launch/consume");
        FrozenNow::set(now + 60);
        fixture.fake.update(|inner| inner.now = now + 60);
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        let results = result_posts(&fixture.fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "policy_refused");
        assert!(results[0].get("detail").is_none());
        assert_eq!(
            fixture
                .adapter
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        );
        let document = fetch_handoff(&fixture.adapter.config.aeon_origin, DEPLOY_HANDOFF).await;
        assert_eq!(document["state"], "failed");
        let later = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            later,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_ADMISSION_EXPIRED)
        ));
        assert_eq!(result_posts(&fixture.fake).len(), 1);
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
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            let stored: Vec<_> = std::mem::take(&mut handoff.launch_calls)
                .into_values()
                .collect();
            for call in stored {
                handoff
                    .launch_calls
                    .insert("66666666-6666-4666-8666-666666666666".to_string(), call);
            }
            handoff.admit_idempotency_key =
                Some("66666666-6666-4666-8666-666666666666".to_string());
        });
        let replay = other.adapter.process_intent(&other.intent).await;
        assert!(matches!(
            replay,
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT
        ));
        assert_eq!(post_count(&other.fake, "/launch/consume"), 0);
        assert_eq!(
            other.actions.get(&other_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert!(other
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .admit_unresolved
            .is_none());
        let later = other.adapter.process_intent(&other.intent).await;
        assert!(matches!(
            later,
            Err(AdapterError::Refused(status)) if status == StatusCode::CONFLICT
        ));
        assert_eq!(post_count(&other.fake, "/launch/admit"), admits_before + 2);
        assert_eq!(post_count(&other.fake, "/launch/consume"), 0);
        other.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn stale_consume_replay_refreshes_readiness_then_confirms() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let crashed = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(crashed.consume_started);
        assert!(crashed.receipt.is_none());
        FrozenNow::set(now + 1000);
        fixture.fake.update(|inner| inner.now = now + 1000);
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::QueuedApply
        );
        let readiness = readiness_bodies(&fixture.fake);
        assert!(readiness.len() >= 2);
        assert_eq!(
            readiness[0]["reviewed_plan_digest"],
            readiness.last().unwrap()["reviewed_plan_digest"]
        );
        assert_ne!(
            readiness[0]["observed_at"],
            readiness.last().unwrap()["observed_at"]
        );
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_some());
        fixture.server.abort();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn consume_replay_does_not_refresh_after_the_backup_success_disappears() {
        let now = now_unix();
        let _clock = FrozenNow::at(now);
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let consumes = post_count(&fixture.fake, "/launch/consume");
        let readiness = readiness_post_count(&fixture.fake);
        FrozenNow::set(now + 1000);
        fixture.fake.update(|inner| inner.now = now + 1000);
        record_host(&fixture.hosts, now + 1000, &fixture.intent.artifact, None);
        let replay = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING)
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        assert_eq!(readiness_post_count(&fixture.fake), readiness);
        let block = fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .unwrap();
        assert_eq!(block.reason, LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING);
        assert!(!block.terminal);
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_none());
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        fixture.server.abort();
    }

    #[tokio::test]
    async fn unconsumed_replay_abandons_a_job_that_is_no_longer_confirmable() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let consumes = post_count(&fixture.fake, "/launch/consume");
        assert_eq!(consumes, 1);
        let job = fixture.actions.get(&job_id).unwrap();
        fixture
            .actions
            .cancel_update_review(&job_id, "hsb8", "operator", now_unix().max(job.updated_at))
            .unwrap();
        let replay = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            replay,
            Err(AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONSUME_ABANDONED))
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::Cancelled);
        assert!(job.confirmed_at.is_none());
        assert_eq!(
            fixture
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_CONSUME_ABANDONED
        );
        let later = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            later,
            Err(AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONSUME_ABANDONED))
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn restart_after_cancelled_consume_posts_dependency_failed() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let launch = fixture.adapter.journal.launch(DEPLOY_HANDOFF).unwrap();
        assert!(launch.consume_started);
        assert!(launch.receipt.is_none());
        let job = fixture.actions.get(&job_id).unwrap();
        fixture
            .actions
            .cancel_update_review(&job_id, "hsb8", "operator", now_unix().max(job.updated_at))
            .unwrap();
        let restarted = test_adapter(
            runtime_config(
                fixture.adapter.config.aeon_origin.clone(),
                fixture.adapter.config.api_key_file.clone(),
                vec![fixture.intent.clone()],
            ),
            fixture.journal.clone(),
            Arc::clone(&fixture.hosts),
            Arc::clone(&fixture.actions),
        );
        let replay = restarted.process_intent(&fixture.intent).await.unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONSUME_ABANDONED)
        ));
        let results = result_posts(&fixture.fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "dependency_failed");
        assert!(results[0].get("detail").is_none());
        assert_eq!(
            restarted
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some("consume_abandoned")
        );
        let again = restarted.process_intent(&fixture.intent).await.unwrap_err();
        assert!(matches!(
            again,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONSUME_ABANDONED)
        ));
        assert_eq!(result_posts(&fixture.fake).len(), 1);
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::Cancelled
        );
        fixture.server.abort();
    }

    #[tokio::test]
    async fn consumed_replay_does_not_confirm_an_unconfirmable_job() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        fixture
            .fake
            .update(|inner| inner.drop_accepted_consume = true);
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        let consumes = post_count(&fixture.fake, "/launch/consume");
        let job = fixture.actions.get(&job_id).unwrap();
        fixture
            .actions
            .cancel_update_review(&job_id, "hsb8", "operator", now_unix().max(job.updated_at))
            .unwrap();
        let replay = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            replay,
            Err(AdapterError::LaunchBlocked(
                LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB
            ))
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes + 1);
        assert!(fixture
            .adapter
            .journal
            .launch(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_some());
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::Cancelled);
        assert!(job.confirmed_at.is_none());
        assert_eq!(
            job.events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            0
        );
        let later = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            later,
            Err(AdapterError::LaunchBlocked(
                LAUNCH_BLOCK_CONSUMED_WITHOUT_CONFIRMABLE_JOB
            ))
        ));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes + 1);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn unconsumed_replay_does_not_send_when_the_handoff_cannot_be_written() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let fake = fixture.fake.clone();
        *fixture.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .is_err());
        fixture.fake.update(|inner| {
            let handoff = inner.handoffs.get_mut(DEPLOY_HANDOFF).unwrap();
            handoff.expires_at = format_timestamp(inner.now - 5).unwrap();
        });
        let consumes = post_count(&fixture.fake, "/launch/consume");
        let replay = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(replay, Err(AdapterError::Contract)));
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), consumes);
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        assert!(fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .is_none());
        fixture.server.abort();
    }

    #[tokio::test]
    async fn changed_requester_is_not_confirmed() {
        let owned = harness(true).await;
        let job_id = prepare_ready_launch(&owned).await;
        let actions = Arc::clone(&owned.actions);
        let confirm_id = job_id.clone();
        *owned.fake.consume_hook.lock().expect("consume hook") = Some(Box::new(move || {
            actions.set_requested_by_for_test(&confirm_id, "operator");
        }));
        let error = owned
            .adapter
            .process_intent(&owned.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_LAUNCH_NOT_OWNED)
        ));
        let job = owned.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        assert_eq!(
            owned
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_LAUNCH_NOT_OWNED
        );
        owned.server.abort();

        let replayed = harness(true).await;
        let replay_job = prepare_ready_launch(&replayed).await;
        let fake = replayed.fake.clone();
        *replayed.fake.reread_hook.lock().expect("reread hook") = Some(Box::new(move || {
            fake.update(|inner| inner.fail_next_post = true);
        }));
        assert!(replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .is_err());
        replayed
            .actions
            .set_requested_by_for_test(&replay_job, "operator");
        let replay = replayed
            .adapter
            .process_intent(&replayed.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            replay,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONSUME_ABANDONED)
        ));
        let job = replayed.actions.get(&replay_job).unwrap();
        assert_eq!(job.state, HostActionState::AwaitingConfirmation);
        assert!(job.confirmed_at.is_none());
        replayed.server.abort();
    }

    #[tokio::test]
    async fn foreign_confirmation_does_not_claim_the_launch() {
        let fixture = harness(true).await;
        let job_id = prepare_ready_launch(&fixture).await;
        let actions = Arc::clone(&fixture.actions);
        let confirm_id = job_id.clone();
        *fixture.fake.consume_hook.lock().expect("consume hook") = Some(Box::new(move || {
            let job = actions.get(&confirm_id).expect("job");
            actions
                .confirm_update(
                    &confirm_id,
                    "hsb8",
                    "operator",
                    now_unix().max(job.updated_at),
                )
                .expect("operator confirms ahead of the admission");
        }));
        let error = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            AdapterError::LaunchBlocked(LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED)
        ));
        let job = fixture.actions.get(&job_id).unwrap();
        assert_eq!(job.state, HostActionState::QueuedApply);
        assert!(job.events.iter().any(|event| {
            event.kind == HostActionEventKind::Confirmed
                && event.source == HostActionEventSource::Operator
        }));
        assert!(!confirmation_is_delegated(
            &job,
            &fixture
                .adapter
                .journal
                .launch(DEPLOY_HANDOFF)
                .unwrap()
                .admission
                .unwrap()
                .id
        ));
        assert_eq!(
            fixture
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED
        );
        let results: Vec<Value> = posts(&fixture.fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "policy_refused");
        assert!(results[0].get("detail").is_none());
        assert_eq!(
            fixture
                .adapter
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some(LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED)
        );
        let later = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(matches!(
            later,
            Err(AdapterError::LaunchBlocked(
                LAUNCH_BLOCK_CONFIRMATION_NOT_DELEGATED
            ))
        ));
        assert_eq!(
            posts(&fixture.fake)
                .iter()
                .filter(|capture| capture.path.ends_with("/result"))
                .count(),
            1
        );
        fixture.server.abort();
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
    async fn readiness_waits_for_a_backup_success_before_posting() {
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
        let waiting = missing
            .adapter
            .process_intent(&missing.intent)
            .await
            .unwrap_err();
        assert_eq!(waiting.code(), LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING);
        assert_eq!(readiness_post_count(&missing.fake), 0);
        assert_eq!(post_count(&missing.fake, "/launch/admit"), 0);
        assert_eq!(post_count(&missing.fake, "/launch/consume"), 0);
        assert_eq!(
            missing
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING
        );
        assert!(missing.adapter.journal.launch(DEPLOY_HANDOFF).is_none());
        assert_eq!(
            missing.actions.get(&missing_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        let still_waiting = missing.adapter.process_intent(&missing.intent).await;
        assert!(matches!(
            still_waiting,
            Err(AdapterError::LaunchBlocked(
                LAUNCH_BLOCK_BACKUP_SUCCESS_MISSING
            ))
        ));
        assert_eq!(readiness_post_count(&missing.fake), 0);

        record_backup(&missing.hosts, fake_now(&missing.fake));
        for _ in 0..4 {
            missing
                .adapter
                .process_intent(&missing.intent)
                .await
                .unwrap();
            if missing.actions.get(&missing_job).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            missing.actions.get(&missing_job).unwrap().state,
            HostActionState::QueuedApply
        );
        assert!(missing
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .is_none());
        let readiness = readiness_bodies(&missing.fake);
        assert_eq!(readiness.len(), 1);
        assert_eq!(readiness[0]["backup_ready"], true);
        assert_eq!(
            readiness[0]["backup_observed_at"],
            format_timestamp(fake_now(&missing.fake)).unwrap()
        );
        assert_eq!(post_count(&missing.fake, "/launch/consume"), 1);
        let saved = JournalStore::new(missing.journal.clone()).unwrap();
        assert!(saved.launch_block(DEPLOY_HANDOFF).is_none());
        assert!(saved.launch(DEPLOY_HANDOFF).unwrap().receipt.is_some());
        missing.server.abort();

        let unready = harness(true).await;
        unready
            .adapter
            .process_intent(&unready.intent)
            .await
            .unwrap();
        let unready_job = unready.actions.list()[0].id.clone();
        let at = unready.actions.get(&unready_job).unwrap().created_at;
        let review = unready
            .actions
            .claim("hsb8", at)
            .expect("claim")
            .expect("lease");
        let mut plan = ready_plan();
        plan.backup_ready = false;
        unready
            .actions
            .record_agent_result(
                &unready_job,
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
            .expect("review without a ready backup");
        record_backup(&unready.hosts, fake_now(&unready.fake));
        let blocked = unready
            .adapter
            .process_intent(&unready.intent)
            .await
            .unwrap_err();
        assert_eq!(blocked.code(), LAUNCH_BLOCK_BACKUP_NOT_READY);
        assert_eq!(readiness_post_count(&unready.fake), 0);
        assert_eq!(post_count(&unready.fake, "/launch/admit"), 0);
        assert_eq!(
            unready
                .adapter
                .journal
                .launch_block(DEPLOY_HANDOFF)
                .unwrap()
                .reason,
            LAUNCH_BLOCK_BACKUP_NOT_READY
        );
        let later = unready.adapter.process_intent(&unready.intent).await;
        assert!(matches!(
            later,
            Err(AdapterError::LaunchBlocked(LAUNCH_BLOCK_BACKUP_NOT_READY))
        ));
        assert_eq!(readiness_post_count(&unready.fake), 0);
        assert_eq!(
            unready.actions.get(&unready_job).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        unready.server.abort();

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
        for _ in 0..4 {
            stale.adapter.process_intent(&stale.intent).await.unwrap();
            if stale.actions.get(&stale_job).unwrap().state == HostActionState::QueuedApply {
                break;
            }
        }
        assert_eq!(
            stale.actions.get(&stale_job).unwrap().state,
            HostActionState::QueuedApply
        );
        let stale_body: Value = posts(&stale.fake)
            .into_iter()
            .find(|capture| capture.path.ends_with("/evidence"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .unwrap();
        assert_eq!(
            stale_body["backup_observed_at"],
            format_timestamp(stale_at).unwrap()
        );
        assert_eq!(post_count(&stale.fake, "/launch/consume"), 1);
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
    async fn in_memory_deploy_without_delegated_launch_does_not_start() {
        let fixture = harness(false).await;
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        assert!(fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .is_none());
        let job_id = fixture.actions.list()[0].id.clone();
        review_job(
            &fixture.actions,
            &job_id,
            fixture.actions.get(&job_id).unwrap().created_at,
        );
        record_backup(&fixture.hosts, fake_now(&fixture.fake));
        let blocked = fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap_err();
        assert_eq!(blocked.code(), LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED);
        assert_eq!(readiness_post_count(&fixture.fake), 0);
        assert_eq!(post_count(&fixture.fake, "/launch/admit"), 0);
        assert_eq!(post_count(&fixture.fake, "/launch/consume"), 0);
        let block = fixture
            .adapter
            .journal
            .launch_block(DEPLOY_HANDOFF)
            .unwrap();
        assert_eq!(block.reason, LAUNCH_BLOCK_DELEGATED_LAUNCH_REQUIRED);
        assert!(block.terminal);
        assert!(fixture.adapter.journal.launch(DEPLOY_HANDOFF).is_none());
        let again = fixture.adapter.process_intent(&fixture.intent).await;
        assert!(again.is_ok());
        let results = result_posts(&fixture.fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["blocker_code"], "policy_refused");
        assert_eq!(readiness_post_count(&fixture.fake), 0);
        assert_eq!(
            fixture.actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        fixture.server.abort();
    }

    #[tokio::test]
    async fn cancelled_job_reports_a_failed_result_after_a_terminal_launch_block() {
        let directory = TestDir::new("blocked-cancel");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let actions_path = directory.path().join("host-actions.json");
        let journal = directory
            .path()
            .join("hosts.json.aeon-delivery-journal.json");
        let fake = FakeAeon::new(now_unix());
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            journal.clone(),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        adapter.process_intent(&intent).await.unwrap();
        let job_id = actions.list()[0].id.clone();
        review_job(&actions, &job_id, actions.get(&job_id).unwrap().created_at);
        record_backup(&hosts, fake_now(&fake));
        fake.update(|inner| inner.drop_accepted_admit = true);
        assert!(adapter.process_intent(&intent).await.is_err());
        let mut saved: Value =
            serde_json::from_slice(&std::fs::read(&actions_path).expect("saved actions")).unwrap();
        let plan = saved
            .as_array_mut()
            .expect("action list")
            .iter_mut()
            .find(|job| job["kind"] == "update_restart")
            .expect("update job")
            .get_mut("plan")
            .expect("reviewed plan")
            .as_object_mut()
            .expect("plan object");
        plan["changed_file_count"] = json!(9);
        std::fs::write(&actions_path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let reloaded_actions = Arc::new(HostActionStore::new(Some(actions_path)));
        let reloaded = test_adapter(
            runtime_config(
                adapter.config.aeon_origin.clone(),
                adapter.config.api_key_file.clone(),
                vec![intent.clone()],
            ),
            journal,
            hosts,
            Arc::clone(&reloaded_actions),
        );
        let blocked = reloaded.process_intent(&intent).await.unwrap_err();
        assert_eq!(blocked.code(), LAUNCH_BLOCK_READINESS_PLAN_CHANGED);
        let job = reloaded_actions.get(&job_id).unwrap();
        reloaded_actions
            .cancel_update_review(&job_id, "hsb8", "operator", now_unix().max(job.updated_at))
            .unwrap();
        let reported = reloaded.process_intent(&intent).await;
        assert!(reported.is_ok());
        let results: Vec<Value> = posts(&fake)
            .into_iter()
            .filter(|capture| capture.path.ends_with("/result"))
            .map(|capture| serde_json::from_slice(&capture.body).unwrap())
            .collect();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert_eq!(results[0]["blocker_code"], "policy_refused");
        assert!(results[0].get("detail").is_none());
        assert_eq!(
            reloaded
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some(LAUNCH_BLOCK_READINESS_PLAN_CHANGED)
        );
        assert_eq!(
            reloaded_actions.get(&job_id).unwrap().state,
            HostActionState::Cancelled
        );
        server.abort();
    }

    #[tokio::test]
    async fn readiness_refresh_refuses_a_changed_plan_and_a_false_flag() {
        contradict_settled_readiness(
            "readiness-plan",
            LAUNCH_BLOCK_READINESS_PLAN_CHANGED,
            |plan| {
                plan["changed_file_count"] = json!(3);
            },
        )
        .await;
        contradict_settled_readiness(
            "readiness-flag",
            LAUNCH_BLOCK_READINESS_FLAG_FALSE,
            |plan| {
                plan["backup_ready"] = json!(false);
            },
        )
        .await;
    }

    async fn contradict_settled_readiness(
        label: &str,
        reason: &str,
        edit: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) {
        let directory = TestDir::new(label);
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let actions_path = directory.path().join("host-actions.json");
        let journal = directory
            .path()
            .join("hosts.json.aeon-delivery-journal.json");
        let fake = FakeAeon::new(now_unix());
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            journal.clone(),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        adapter.process_intent(&intent).await.unwrap();
        let job_id = actions.list()[0].id.clone();
        review_job(&actions, &job_id, actions.get(&job_id).unwrap().created_at);
        record_backup(&hosts, fake_now(&fake));
        fake.update(|inner| inner.drop_accepted_admit = true);
        assert!(adapter.process_intent(&intent).await.is_err());
        assert_eq!(readiness_post_count(&fake), 1);
        assert_eq!(post_count(&fake, "/launch/admit"), 1);
        assert_eq!(post_count(&fake, "/launch/consume"), 0);
        let mut saved: Value =
            serde_json::from_slice(&std::fs::read(&actions_path).expect("saved actions")).unwrap();
        let plan = saved
            .as_array_mut()
            .expect("action list")
            .iter_mut()
            .find(|job| job["kind"] == "update_restart")
            .expect("update job")
            .get_mut("plan")
            .expect("reviewed plan")
            .as_object_mut()
            .expect("plan object");
        edit(plan);
        std::fs::write(&actions_path, serde_json::to_vec(&saved).unwrap()).unwrap();
        let reloaded_actions = Arc::new(HostActionStore::new(Some(actions_path)));
        let reloaded = test_adapter(
            runtime_config(
                adapter.config.aeon_origin.clone(),
                adapter.config.api_key_file.clone(),
                vec![intent.clone()],
            ),
            journal,
            hosts,
            Arc::clone(&reloaded_actions),
        );
        let readiness = readiness_post_count(&fake);
        let admits = post_count(&fake, "/launch/admit");
        let blocked = reloaded.process_intent(&intent).await.unwrap_err();
        assert_eq!(blocked.code(), reason);
        let block = reloaded.journal.launch_block(DEPLOY_HANDOFF).unwrap();
        assert_eq!(block.reason, reason);
        assert!(block.terminal);
        assert_eq!(readiness_post_count(&fake), readiness);
        assert_eq!(post_count(&fake, "/launch/admit"), admits);
        assert_eq!(post_count(&fake, "/launch/consume"), 0);
        assert_eq!(
            reloaded_actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        let results = result_posts(&fake);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0]["outcome"], "failed");
        assert!(results[0].get("detail").is_none());
        // Literals, so a mapper that returns the wrong variant fails this test.
        assert_eq!(
            results[0]["blocker_code"],
            match reason {
                LAUNCH_BLOCK_READINESS_PLAN_CHANGED => "policy_refused",
                LAUNCH_BLOCK_READINESS_FLAG_FALSE => "external_waiting",
                other => panic!("settled readiness reason {other} has no literal code"),
            }
        );
        assert_eq!(
            reloaded
                .journal
                .result(DEPLOY_HANDOFF)
                .unwrap()
                .detail
                .as_deref(),
            Some(reason)
        );
        let again = reloaded.process_intent(&intent).await;
        assert!(again.is_ok());
        assert_eq!(result_posts(&fake).len(), 1);
        assert_eq!(readiness_post_count(&fake), readiness);
        assert_eq!(post_count(&fake, "/launch/admit"), admits);
        assert_eq!(
            reloaded_actions.get(&job_id).unwrap().state,
            HostActionState::AwaitingConfirmation
        );
        server.abort();
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
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        advance_delegated_job_to_succeeded(&adapter, &actions, &hosts, &intent).await;
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
        assert_eq!(result_posts.len(), 1);
        let saved = adapter.journal.result(DEPLOY_HANDOFF).unwrap();
        assert_eq!(saved.body_json, journaled);
        assert_eq!(
            saved.receipt.unwrap().prerequisite_seal_sha256,
            hex_chars('d')
        );
        server.abort();
    }

    #[tokio::test]
    async fn closed_handoff_replays_a_lost_result_and_verification_continues() {
        let now = now_unix();
        let directory = TestDir::new("closed-result");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let fake = FakeAeon::new(now);
        fake.update(|inner| inner.drop_accepted_result = true);
        let (origin, server) = serve(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let intent = deploy_intent(true);
        let adapter = test_adapter(
            runtime_config(origin, api, vec![intent.clone(), verify_intent()]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        advance_delegated_job_to_succeeded(&adapter, &actions, &hosts, &intent).await;
        assert!(adapter.process_intent(&intent).await.is_err());
        assert!(adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .is_none());
        adapter.process_intent(&intent).await.unwrap();
        let receipt = adapter
            .journal
            .result(DEPLOY_HANDOFF)
            .unwrap()
            .receipt
            .unwrap();
        assert_eq!(receipt.outcome, ResultOutcome::Succeeded);
        let seal = dependency_digest(DEPLOY_HANDOFF, "deployment", receipt.terminal_sequence);
        arm_verify_seal(&fake, &seal, 11);
        record_beacon(&hosts, now_unix() + 1, &artifact());
        adapter.process_intent(&verify_intent()).await.unwrap();
        assert_eq!(
            adapter
                .journal
                .result(VERIFY_HANDOFF)
                .unwrap()
                .receipt
                .unwrap()
                .outcome,
            ResultOutcome::Succeeded
        );
        server.abort();
    }

    #[tokio::test]
    async fn skewed_aeon_clock_does_not_break_the_confirmed_job() {
        for skew in [-30_i64, 30] {
            let fixture = harness(true).await;
            let job_id = prepare_ready_launch(&fixture).await;
            let local = now_unix();
            fixture.fake.update(|inner| inner.now = local + skew);
            for _ in 0..4 {
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
            assert!(job.updated_at >= job.created_at);
            assert!(job.confirmed_at.unwrap() >= job.created_at);
            assert!(job
                .events
                .windows(2)
                .all(|events| events[0].at <= events[1].at));
            assert!(job
                .events
                .iter()
                .all(|event| { event.at >= job.created_at && event.at <= job.updated_at }));
            let consumed_at = unix_of(
                &fixture
                    .adapter
                    .journal
                    .launch(DEPLOY_HANDOFF)
                    .unwrap()
                    .receipt
                    .unwrap()
                    .consumed_at,
            )
            .unwrap();
            assert_eq!(consumed_at, local + skew);
            assert_ne!(job.confirmed_at.unwrap(), consumed_at);
            finish_apply(&fixture.actions, &job_id, now_unix().max(job.updated_at));
            assert_eq!(
                fixture.actions.get(&job_id).unwrap().state,
                HostActionState::Succeeded
            );
            fixture.server.abort();
        }
    }

    #[tokio::test]
    async fn request_trace_records_status_and_request_id_only() {
        let mut fixture = harness(false).await;
        let traces = Arc::new(Mutex::new(Vec::new()));
        fixture.adapter.aeon.enable_trace(Arc::clone(&traces));
        fixture
            .adapter
            .process_intent(&fixture.intent)
            .await
            .unwrap();
        let recorded = traces.lock().expect("traces").clone();
        assert!(recorded.iter().any(|trace| {
            trace.method == "GET"
                && trace.path.starts_with("/api/stage-handoffs/")
                && !trace.path.contains('?')
                && trace.status == 200
                && trace.request_id.as_deref() == Some("fake-aeon-request")
                && trace.error_excerpt.is_none()
        }));
        let rendered = format!("{recorded:?}");
        assert_no_key(rendered.as_bytes());
        assert!(!rendered.contains("authorization"));
        assert_trace_excerpts(&traces);
        fixture.server.abort();
    }

    #[tokio::test]
    async fn reflected_api_key_is_withheld_from_the_trace_and_the_report() {
        let directory = TestDir::new("reflect-key");
        let api = directory.path().join("api-key");
        write_private(&api, API_KEY);
        let report = directory.path().join("report.json");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind reflecting origin");
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                Router::new().fallback(|request: Request<Body>| async move {
                    let path = request.uri().path().to_string();
                    let authorization = request
                        .headers()
                        .get(AUTHORIZATION)
                        .and_then(|value| value.to_str().ok())
                        .unwrap_or("")
                        .to_string();
                    let header_key = path.ends_with("/header-key");
                    let body = if header_key {
                        "{}".to_string()
                    } else if path.ends_with("/long-error") {
                        "n".repeat(500)
                    } else {
                        format!("{{\"error\":\"reflected {authorization}\"}}")
                    };
                    let mut response = Response::builder()
                        .status(if header_key {
                            StatusCode::OK
                        } else {
                            StatusCode::BAD_REQUEST
                        })
                        .header(CONTENT_TYPE.as_str(), JSON_MEDIA);
                    if header_key {
                        response = response
                            .header(CONTENT_ENCODING.as_str(), "gzip")
                            .header("x-request-id", authorization.clone())
                            .header("x-echo", authorization);
                    }
                    response.body(Body::from(body)).unwrap()
                }),
            )
            .await
            .unwrap();
        });
        let origin = loopback_origin_for_tests(&format!("http://127.0.0.1:{port}/"));
        let hosts = Arc::new(Store::new(None).unwrap());
        let actions = Arc::new(HostActionStore::new(None));
        let mut adapter = test_adapter(
            runtime_config(origin, api.clone(), vec![deploy_intent(true)]),
            directory
                .path()
                .join("hosts.json.aeon-delivery-journal.json"),
            hosts,
            actions,
        );
        let traces = Arc::new(Mutex::new(Vec::new()));
        adapter.aeon.enable_trace(Arc::clone(&traces));
        let credentials = adapter.aeon.credentials().expect("test key");
        let long = adapter
            .aeon
            .exchange(Method::GET, "/long-error", None, None, &credentials)
            .await
            .expect("long error body is not a reflected key");
        drop(credentials);
        assert_eq!(long.0, StatusCode::BAD_REQUEST);
        let reflected = adapter.aeon.get_handoff(DEPLOY_HANDOFF).await;
        assert!(matches!(reflected, Err(AdapterError::Contract)));
        assert_trace_excerpts(&traces);
        let recorded = traces.lock().expect("traces").clone();
        assert!(recorded.iter().any(|trace| {
            trace.status == 400
                && trace.error_excerpt.as_deref() == Some(REFLECTED_CREDENTIAL_MARKER)
        }));
        assert!(recorded.iter().any(|trace| {
            trace.path == "/long-error"
                && trace
                    .error_excerpt
                    .as_ref()
                    .is_some_and(|excerpt| excerpt.len() == TRACE_EXCERPT_MAX_BYTES)
        }));
        for trace in &recorded {
            assert_no_key(format!("{trace:?}").as_bytes());
        }
        let message = live_failure(&traces);
        assert_no_key(message.as_bytes());
        assert!(message.contains(REFLECTED_CREDENTIAL_MARKER));
        save_live_failure(&report, &traces, &api, &message);
        let report_bytes = std::fs::read(&report).unwrap();
        assert_no_key(&report_bytes);
        assert_live_bytes_exclude_key(&report_bytes, &api);
        let credentials = adapter.aeon.credentials().expect("test key");
        let header_key = adapter
            .aeon
            .exchange(Method::GET, "/header-key", None, None, &credentials)
            .await;
        drop(credentials);
        assert!(matches!(header_key, Err(AdapterError::Contract)));
        let recorded = traces.lock().expect("traces").clone();
        assert!(recorded.iter().all(|trace| trace.path != "/header-key"));
        for trace in &recorded {
            assert_no_key(format!("{trace:?}").as_bytes());
        }
        let message = live_failure(&traces);
        assert_no_key(message.as_bytes());
        save_live_failure(&report, &traces, &api, &message);
        let report_bytes = std::fs::read(&report).unwrap();
        assert_no_key(&report_bytes);
        server.abort();
    }

    #[tokio::test]
    async fn live_guard_identifies_the_disposable_target_before_any_write() {
        let allowed = harness(true).await;
        let identity = confirm_live_target(
            &allowed.adapter,
            "lab",
            "PRJ-17",
            &allowed.intent.project_node_id,
            RELEASE_NODE,
            allowed.intent.artifact.release_sequence,
            &[allowed.intent.handoff_id.as_str()],
        )
        .await
        .expect("disposable lab target");
        assert_eq!(identity.project_key, "lab");
        assert_eq!(identity.node_key, "PRJ-17");
        assert_eq!(identity.release_number, 123);
        assert!(posts(&allowed.fake).is_empty());
        allowed.server.abort();

        let production = harness(true).await;
        production
            .fake
            .update(|inner| inner.journey_project_key = "PHAROS".to_string());
        let refused = confirm_live_target(
            &production.adapter,
            "PHAROS",
            "PRJ-17",
            &production.intent.project_node_id,
            RELEASE_NODE,
            production.intent.artifact.release_sequence,
            &[production.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused.unwrap_err().contains("project_key is PHAROS"));
        assert!(posts(&production.fake).is_empty());
        production.server.abort();

        let other_tenant = harness(true).await;
        other_tenant
            .fake
            .update(|inner| inner.journey_tenant_slug = "other".to_string());
        let refused = confirm_live_target(
            &other_tenant.adapter,
            "lab",
            "PRJ-17",
            &other_tenant.intent.project_node_id,
            RELEASE_NODE,
            other_tenant.intent.artifact.release_sequence,
            &[other_tenant.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused.unwrap_err().contains("tenant is not inspr"));
        assert!(posts(&other_tenant.fake).is_empty());
        other_tenant.server.abort();

        let mismatch = harness(true).await;
        let refused = confirm_live_target(
            &mismatch.adapter,
            "lumen",
            "PRJ-17",
            &mismatch.intent.project_node_id,
            RELEASE_NODE,
            mismatch.intent.artifact.release_sequence,
            &[mismatch.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused
            .unwrap_err()
            .contains("PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY"));
        assert!(posts(&mismatch.fake).is_empty());
        mismatch.server.abort();

        let other_release = harness(true).await;
        other_release.fake.update(|inner| {
            inner
                .handoffs
                .get_mut(DEPLOY_HANDOFF)
                .unwrap()
                .release_node_id = OTHER_RELEASE.to_string();
        });
        let refused = confirm_live_target(
            &other_release.adapter,
            "lab",
            "PRJ-17",
            &other_release.intent.project_node_id,
            RELEASE_NODE,
            other_release.intent.artifact.release_sequence,
            &[other_release.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused
            .unwrap_err()
            .contains("PHAROS_AEON_LIVE_RELEASE_NODE_ID"));
        assert!(posts(&other_release.fake).is_empty());
        other_release.server.abort();

        let live_gate = harness(true).await;
        live_gate
            .fake
            .update(|inner| inner.journey_gate_live = true);
        let refused = confirm_live_target(
            &live_gate.adapter,
            "lab",
            "PRJ-17",
            &live_gate.intent.project_node_id,
            RELEASE_NODE,
            live_gate.intent.artifact.release_sequence,
            &[live_gate.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused.unwrap_err().contains("gate_live is true"));
        assert!(posts(&live_gate.fake).is_empty());
        live_gate.server.abort();

        let other_node = harness(true).await;
        let refused = confirm_live_target(
            &other_node.adapter,
            "lab",
            "LAB-1",
            &other_node.intent.project_node_id,
            RELEASE_NODE,
            other_node.intent.artifact.release_sequence,
            &[other_node.intent.handoff_id.as_str()],
        )
        .await;
        assert!(refused
            .unwrap_err()
            .contains("PHAROS_AEON_LIVE_EXPECT_NODE_KEY"));
        assert!(posts(&other_node.fake).is_empty());
        other_node.server.abort();
    }

    #[tokio::test]
    #[ignore = "live Aeon roundtrip; set PHAROS_AEON_LIVE_ACK=disposable"]
    async fn live_roundtrip_against_aeon() {
        let Some(live) = live_roundtrip_env() else {
            eprintln!("live Aeon roundtrip skipped: PHAROS_AEON_LIVE_ORIGIN is unset");
            return;
        };
        let directory = TestDir::new("live-roundtrip");
        let journal = directory
            .path()
            .join("hosts.json.aeon-delivery-journal.json");
        let traces = Arc::new(Mutex::new(Vec::new()));
        let hosts = Arc::new(Store::new(None).unwrap());
        let actions = Arc::new(HostActionStore::new(None));
        let mut intents = vec![live.deploy.clone()];
        if let Some(verify) = &live.verify {
            intents.push(verify.clone());
        }
        let mut adapter = test_adapter(
            runtime_config(live.origin.clone(), live.key_file.clone(), intents),
            journal.clone(),
            Arc::clone(&hosts),
            Arc::clone(&actions),
        );
        adapter.aeon.enable_trace(Arc::clone(&traces));
        let mut handoff_ids = vec![live.deploy.handoff_id.as_str()];
        if let Some(verify) = &live.verify {
            handoff_ids.push(verify.handoff_id.as_str());
        }
        if let Err(reason) = confirm_live_target(
            &adapter,
            &live.expect_project_key,
            &live.expect_node_key,
            &live.deploy.project_node_id,
            &live.deploy.release_node_id,
            live.artifact.release_sequence,
            &handoff_ids,
        )
        .await
        {
            panic!("live Aeon roundtrip refused: {reason}");
        }
        let started = std::time::Instant::now();
        let deadline = started + std::time::Duration::from_secs(90);
        let now = now_unix();
        record_beacon_for(
            &hosts,
            &live.host,
            &live.environment,
            now,
            &live.artifact,
            Some(now),
        );
        live_step(
            &adapter,
            &live.deploy,
            &traces,
            &live.report,
            &live.key_file,
        )
        .await;
        let job_id = actions
            .list()
            .into_iter()
            .find(|job| job.kind == HostActionKind::UpdateRestart)
            .expect("adapter created the update review")
            .id;
        assert_eq!(
            actions.get(&job_id).unwrap().requested_by,
            ACTOR,
            "the adapter must create the job through ensure_update_review_with_id"
        );
        review_job_for(&actions, &live.host, &job_id, now_unix());
        live_until(
            &adapter,
            &live.deploy,
            &traces,
            &live.report,
            &live.key_file,
            deadline,
            || {
                let launch = adapter.journal.launch(&live.deploy.handoff_id);
                let readiness = adapter
                    .journal
                    .evidence_with_kind(&live.deploy.handoff_id, EvidenceKind::LaunchReadiness);
                launch.is_some_and(|launch| launch.admission.is_some() && launch.receipt.is_some())
                    && readiness.is_some_and(|row| row.receipt.is_some())
                    && actions.get(&job_id).unwrap().confirmed_at.is_some()
            },
        )
        .await;
        let confirmed = actions.get(&job_id).unwrap();
        assert_eq!(confirmed.state, HostActionState::QueuedApply);
        finish_apply_for(
            &actions,
            &live.host,
            &job_id,
            now_unix().max(confirmed.updated_at),
        );
        live_until(
            &adapter,
            &live.deploy,
            &traces,
            &live.report,
            &live.key_file,
            deadline,
            || {
                let applied = actions.get(&job_id).unwrap();
                let stamp = now_unix().max(applied.updated_at.saturating_add(1));
                record_beacon_for(
                    &hosts,
                    &live.host,
                    &live.environment,
                    stamp,
                    &live.artifact,
                    None,
                );
                let deployment = adapter
                    .journal
                    .evidence_with_kind(&live.deploy.handoff_id, EvidenceKind::Deployment);
                let result = adapter.journal.result(&live.deploy.handoff_id);
                deployment.is_some_and(|row| row.receipt.is_some())
                    && result.is_some_and(|row| {
                        row.receipt
                            .is_some_and(|receipt| receipt.outcome == ResultOutcome::Succeeded)
                    })
            },
        )
        .await;
        if let Some(verify) = &live.verify {
            let result = adapter.journal.result(&live.deploy.handoff_id).unwrap();
            let anchor = unix_of(&result.receipt.unwrap().completed_at).unwrap();
            record_beacon_for(
                &hosts,
                &live.host,
                &live.environment,
                now_unix().max(anchor.saturating_add(1)),
                &live.artifact,
                None,
            );
            live_until(
                &adapter,
                verify,
                &traces,
                &live.report,
                &live.key_file,
                deadline,
                || {
                    let evidence = adapter
                        .journal
                        .evidence_with_kind(&verify.handoff_id, EvidenceKind::Verification);
                    let result = adapter.journal.result(&verify.handoff_id);
                    evidence.is_some_and(|row| row.receipt.is_some())
                        && result.is_some_and(|row| {
                            row.receipt
                                .is_some_and(|receipt| receipt.outcome == ResultOutcome::Succeeded)
                        })
                },
            )
            .await;
        }
        let mut handoffs = vec![live_handoff_state(&adapter, &live.deploy.handoff_id).await];
        if let Some(verify) = &live.verify {
            handoffs.push(live_handoff_state(&adapter, &verify.handoff_id).await);
        }
        let report = live_report(&live, &adapter, &journal, &traces, &handoffs, started);
        std::fs::write(&live.report, serde_json::to_vec_pretty(&report).unwrap())
            .expect("write live report");
        let report_bytes = std::fs::read(&live.report).unwrap();
        let journal_bytes = std::fs::read(&journal).unwrap();
        assert_trace_excerpts(&traces);
        assert_no_key(&report_bytes);
        assert_live_bytes_exclude_key(&report_bytes, &live.key_file);
        assert_live_bytes_exclude_key(&journal_bytes, &live.key_file);
        println!("live Aeon roundtrip report: {}", live.report.display());
    }

    struct LiveRoundtrip {
        origin: Url,
        key_file: PathBuf,
        expect_project_key: String,
        expect_node_key: String,
        host: String,
        environment: String,
        artifact: ArtifactEvidence,
        deploy: DeliveryIntent,
        verify: Option<DeliveryIntent>,
        report: PathBuf,
    }

    fn live_roundtrip_env() -> Option<LiveRoundtrip> {
        let Ok(origin_text) = std::env::var("PHAROS_AEON_LIVE_ORIGIN") else {
            return None;
        };
        if origin_text.trim().is_empty() {
            return None;
        }
        let ack = std::env::var("PHAROS_AEON_LIVE_ACK").unwrap_or_default();
        if ack != "disposable" {
            panic!("live Aeon roundtrip refused: set PHAROS_AEON_LIVE_ACK=disposable");
        }
        let origin =
            parse_origin(origin_text.trim()).expect("PHAROS_AEON_LIVE_ORIGIN https origin");
        let expect_project_key = std::env::var("PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY")
            .unwrap_or_default()
            .trim()
            .to_string();
        assert!(
            !expect_project_key.is_empty(),
            "live Aeon roundtrip missing PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY"
        );
        assert!(
            expect_project_key != "PHAROS",
            "live Aeon roundtrip refused: PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY is PHAROS"
        );
        let expect_node_key = std::env::var("PHAROS_AEON_LIVE_EXPECT_NODE_KEY")
            .unwrap_or_default()
            .trim()
            .to_string();
        assert!(
            !expect_node_key.is_empty(),
            "live Aeon roundtrip missing PHAROS_AEON_LIVE_EXPECT_NODE_KEY"
        );
        let key_file = required_live_path("PHAROS_AEON_LIVE_KEY_FILE");
        let project = required_live_uuid("PHAROS_AEON_LIVE_PROJECT_NODE_ID");
        let release = required_live_uuid("PHAROS_AEON_LIVE_RELEASE_NODE_ID");
        let deploy_handoff = required_live_uuid("PHAROS_AEON_LIVE_DEPLOY_HANDOFF");
        let verify_handoff = std::env::var("PHAROS_AEON_LIVE_VERIFY_HANDOFF")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let host =
            std::env::var("PHAROS_AEON_LIVE_HOST").unwrap_or_else(|_| "lab-roundtrip".to_string());
        let environment =
            std::env::var("PHAROS_AEON_LIVE_ENVIRONMENT").unwrap_or_else(|_| "lab".to_string());
        assert!(
            valid_host(&host),
            "PHAROS_AEON_LIVE_HOST is not a host name"
        );
        assert!(
            valid_symbol(&environment),
            "PHAROS_AEON_LIVE_ENVIRONMENT is not a symbol"
        );
        let artifact_json = std::env::var("PHAROS_AEON_LIVE_ARTIFACT_JSON").unwrap_or_default();
        assert!(
            !artifact_json.trim().is_empty(),
            "live Aeon roundtrip missing PHAROS_AEON_LIVE_ARTIFACT_JSON"
        );
        let artifact: ArtifactEvidence = serde_json::from_str(&artifact_json)
            .unwrap_or_else(|_| panic!("PHAROS_AEON_LIVE_ARTIFACT_JSON is not ArtifactEvidence"));
        assert!(artifact.valid(), "live artifact is not valid evidence");
        assert!(
            valid_prefixed_sha256(&artifact.digest),
            "live artifact digest must be sha256-prefixed"
        );
        let report = required_live_path("PHAROS_AEON_LIVE_REPORT");
        let shared = LiveShared {
            project: &project,
            release: &release,
            host: &host,
            environment: &environment,
            artifact: &artifact,
        };
        let deploy = live_intent(
            &deploy_handoff,
            &shared,
            Operation::Deploy,
            GuardedWorkflow::DeployProduction,
            None,
        );
        let verify = verify_handoff.map(|handoff| {
            assert!(
                valid_uuid(handoff.trim()),
                "PHAROS_AEON_LIVE_VERIFY_HANDOFF is not a uuid"
            );
            assert_ne!(handoff.trim(), deploy_handoff);
            live_intent(
                handoff.trim(),
                &shared,
                Operation::Verify,
                GuardedWorkflow::VerifyProduction,
                Some(deploy_handoff.clone()),
            )
        });
        Some(LiveRoundtrip {
            origin,
            key_file,
            expect_project_key,
            expect_node_key,
            host,
            environment,
            artifact,
            deploy,
            verify,
            report,
        })
    }

    fn required_live_path(name: &str) -> PathBuf {
        let value = std::env::var(name).unwrap_or_default();
        assert!(
            !value.trim().is_empty(),
            "live Aeon roundtrip missing {name}"
        );
        PathBuf::from(value.trim())
    }

    fn required_live_uuid(name: &str) -> String {
        let value = std::env::var(name).unwrap_or_default();
        let value = value.trim().to_string();
        assert!(
            valid_uuid(&value),
            "live Aeon roundtrip missing or invalid {name}"
        );
        value
    }

    struct LiveShared<'a> {
        project: &'a str,
        release: &'a str,
        host: &'a str,
        environment: &'a str,
        artifact: &'a ArtifactEvidence,
    }

    fn live_intent(
        handoff_id: &str,
        shared: &LiveShared<'_>,
        operation: Operation,
        workflow: GuardedWorkflow,
        deployment_handoff_id: Option<String>,
    ) -> DeliveryIntent {
        DeliveryIntent {
            handoff_id: handoff_id.to_string(),
            project_node_id: shared.project.to_string(),
            release_node_id: shared.release.to_string(),
            operation,
            workflow,
            environment: shared.environment.to_string(),
            host: shared.host.to_string(),
            artifact: shared.artifact.clone(),
            update_restart_job_id: None,
            deployment_handoff_id,
            delegated_launch: matches!(operation, Operation::Deploy).then(|| {
                DelegatedLaunchSelection {
                    target_ref: shared.artifact.digest.clone(),
                }
            }),
        }
    }

    #[derive(Debug)]
    struct LiveIdentity {
        project_key: String,
        node_key: String,
        release_number: i64,
    }

    async fn confirm_live_target(
        adapter: &AeonDeliveryAdapter,
        expected_project_key: &str,
        expected_node_key: &str,
        project_node_id: &str,
        expected_release_node: &str,
        release_number: i64,
        handoff_ids: &[&str],
    ) -> Result<LiveIdentity, String> {
        if expected_project_key.is_empty() {
            return Err(
                "live Aeon roundtrip missing PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY".to_string(),
            );
        }
        if release_number < 1 {
            return Err("live Aeon roundtrip release number is missing".to_string());
        }
        let journey = adapter
            .aeon
            .get_json(&format!("/api/projects/{project_node_id}/journey"))
            .await
            .map_err(|error| format!("live Aeon journey read failed ({})", error.code()))?;
        let project_key = journey
            .get("project_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let node_key = journey
            .get("node_key")
            .and_then(Value::as_str)
            .unwrap_or("");
        let tenant = journey
            .get("tenant_slug")
            .and_then(Value::as_str)
            .unwrap_or("");
        let project_node = journey
            .get("project_node_id")
            .and_then(Value::as_str)
            .unwrap_or("");
        if project_node != project_node_id {
            return Err(
                "journey project_node_id differs from PHAROS_AEON_LIVE_PROJECT_NODE_ID".to_string(),
            );
        }
        if project_key != expected_project_key {
            return Err(
                "journey project_key differs from PHAROS_AEON_LIVE_EXPECT_PROJECT_KEY".to_string(),
            );
        }
        if project_key == "PHAROS" {
            return Err("live Aeon roundtrip refused: project_key is PHAROS".to_string());
        }
        if tenant != "inspr" {
            return Err("live Aeon roundtrip refused: tenant is not inspr".to_string());
        }
        if expected_node_key.is_empty() {
            return Err("live Aeon roundtrip missing PHAROS_AEON_LIVE_EXPECT_NODE_KEY".to_string());
        }
        if node_key != expected_node_key {
            return Err(
                "journey node_key differs from PHAROS_AEON_LIVE_EXPECT_NODE_KEY".to_string(),
            );
        }
        // Aeon has no disposable-project field. gate_live is the current
        // approval/grant check on each stage (journey doc.go). Every stage
        // must be dark before this harness writes.
        let stages = journey
            .get("stages")
            .and_then(Value::as_array)
            .ok_or_else(|| "journey stages are missing".to_string())?;
        if stages.is_empty() {
            return Err("journey has no stages".to_string());
        }
        for stage in stages {
            match stage.get("gate_live").and_then(Value::as_bool) {
                Some(false) => {}
                Some(true) => {
                    let key = stage
                        .get("key")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown");
                    return Err(format!(
                        "live Aeon roundtrip refused: journey stage {key} gate_live is true"
                    ));
                }
                None => return Err("journey stage is missing gate_live".to_string()),
            }
        }
        if handoff_ids.is_empty() {
            return Err("live Aeon roundtrip has no handoff".to_string());
        }
        for handoff_id in handoff_ids {
            let handoff = adapter
                .aeon
                .get_handoff(handoff_id)
                .await
                .map_err(|error| format!("live Aeon handoff read failed ({})", error.code()))?;
            if handoff.release_node_id != expected_release_node {
                return Err(
                    "handoff release_node_id differs from PHAROS_AEON_LIVE_RELEASE_NODE_ID"
                        .to_string(),
                );
            }
            if handoff.project_node_id != project_node_id {
                return Err(
                    "handoff project_node_id differs from PHAROS_AEON_LIVE_PROJECT_NODE_ID"
                        .to_string(),
                );
            }
        }
        println!(
            "live Aeon roundtrip target: project_key={project_key} node_key={node_key} release_number={release_number} gate_live=false"
        );
        Ok(LiveIdentity {
            project_key: project_key.to_string(),
            node_key: node_key.to_string(),
            release_number,
        })
    }

    async fn live_step(
        adapter: &AeonDeliveryAdapter,
        intent: &DeliveryIntent,
        traces: &Arc<Mutex<Vec<RequestTrace>>>,
        report: &Path,
        key_file: &Path,
    ) {
        if let Err(error) = adapter.process_intent(intent).await {
            let message = format!("{} ({})", live_failure(traces), error.code());
            save_live_failure(report, traces, key_file, &message);
            panic!("{message}");
        }
    }

    async fn live_until(
        adapter: &AeonDeliveryAdapter,
        intent: &DeliveryIntent,
        traces: &Arc<Mutex<Vec<RequestTrace>>>,
        report: &Path,
        key_file: &Path,
        deadline: std::time::Instant,
        mut ready: impl FnMut() -> bool,
    ) {
        loop {
            if std::time::Instant::now() >= deadline {
                let message = format!("live Aeon roundtrip exceeded 90s: {}", live_failure(traces));
                save_live_failure(report, traces, key_file, &message);
                panic!("{message}");
            }
            live_step(adapter, intent, traces, report, key_file).await;
            if ready() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    fn save_live_failure(
        report: &Path,
        traces: &Arc<Mutex<Vec<RequestTrace>>>,
        key_file: &Path,
        message: &str,
    ) {
        assert_trace_excerpts(traces);
        let reason = withheld_live_text(message, key_file);
        let body = json!({
            "failed": true,
            "reason": reason,
            "requests": live_trace_rows(traces),
        });
        let bytes = serde_json::to_vec_pretty(&body).unwrap_or_default();
        let bytes = if live_bytes_contain_key(&bytes, key_file) {
            serde_json::to_vec_pretty(&json!({
                "failed": true,
                "reason": REFLECTED_CREDENTIAL_MARKER,
                "requests": [],
            }))
            .unwrap_or_default()
        } else {
            bytes
        };
        if std::fs::write(report, &bytes).is_ok() {
            eprintln!("live Aeon roundtrip report: {}", report.display());
        }
    }

    fn withheld_live_text(text: &str, key_file: &Path) -> String {
        if live_bytes_contain_key(text.as_bytes(), key_file) {
            REFLECTED_CREDENTIAL_MARKER.to_string()
        } else {
            text.to_string()
        }
    }

    fn live_bytes_contain_key(bytes: &[u8], key_file: &Path) -> bool {
        let Ok((mut key, _)) = read_private_file(key_file, MAX_API_KEY_BYTES, None) else {
            return false;
        };
        let leaked = contains_slice(bytes, &key);
        key.fill(0);
        leaked
    }

    fn assert_trace_excerpts(traces: &Arc<Mutex<Vec<RequestTrace>>>) {
        for trace in traces.lock().expect("traces").iter() {
            if let Some(excerpt) = &trace.error_excerpt {
                assert!(
                    excerpt.len() <= TRACE_EXCERPT_MAX_BYTES,
                    "trace excerpt exceeds {TRACE_EXCERPT_MAX_BYTES} bytes"
                );
            }
        }
    }

    fn live_trace_rows(traces: &Arc<Mutex<Vec<RequestTrace>>>) -> Vec<Value> {
        traces
            .lock()
            .expect("traces")
            .iter()
            .map(|trace| {
                json!({
                    "method": trace.method,
                    "path": trace.path,
                    "status": trace.status,
                    "request_id": trace.request_id,
                })
            })
            .collect()
    }

    fn live_failure(traces: &Arc<Mutex<Vec<RequestTrace>>>) -> String {
        let recorded = traces.lock().expect("traces");
        let Some(trace) = recorded.iter().rev().find(|trace| trace.status >= 400) else {
            return "no Aeon error status recorded".to_string();
        };
        let excerpt = trace.error_excerpt.as_deref().unwrap_or("");
        if excerpt == REFLECTED_CREDENTIAL_MARKER {
            return format!(
                "Aeon {} {} status {} request_id {} {}",
                trace.method,
                trace.path,
                trace.status,
                trace.request_id.as_deref().unwrap_or(""),
                REFLECTED_CREDENTIAL_MARKER
            );
        }
        let (code, reason) = live_error_parts(excerpt);
        format!(
            "Aeon {} {} status {} request_id {} code {} reason {}",
            trace.method,
            trace.path,
            trace.status,
            trace.request_id.as_deref().unwrap_or(""),
            code,
            reason
        )
    }

    fn live_error_parts(excerpt: &str) -> (String, String) {
        let Ok(value) = serde_json::from_str::<Value>(excerpt) else {
            return (
                String::new(),
                truncate_to_bytes(excerpt, TRACE_EXCERPT_MAX_BYTES),
            );
        };
        let code = value
            .get("code")
            .map(|item| match item {
                Value::String(text) => text.clone(),
                Value::Number(number) => number.to_string(),
                _ => String::new(),
            })
            .unwrap_or_default();
        let reason = value
            .get("reason")
            .and_then(Value::as_str)
            .or_else(|| value.get("error").and_then(Value::as_str))
            .unwrap_or("");
        (
            truncate_to_bytes(&code, TRACE_EXCERPT_MAX_BYTES),
            truncate_to_bytes(reason, TRACE_EXCERPT_MAX_BYTES),
        )
    }

    async fn live_handoff_state(adapter: &AeonDeliveryAdapter, handoff_id: &str) -> Value {
        let handoff = match adapter.aeon.get_handoff(handoff_id).await {
            Ok(handoff) => handoff,
            Err(error) => panic!(
                "{} ({})",
                live_failure(&adapter.aeon.traces.clone().expect("request trace")),
                error.code()
            ),
        };
        json!({
            "id": handoff.id,
            "state": handoff.state.key(),
        })
    }

    fn live_report(
        live: &LiveRoundtrip,
        adapter: &AeonDeliveryAdapter,
        journal: &Path,
        traces: &Arc<Mutex<Vec<RequestTrace>>>,
        handoffs: &[Value],
        started: std::time::Instant,
    ) -> Value {
        let launch = adapter.journal.launch(&live.deploy.handoff_id).unwrap();
        let admission = launch.admission.unwrap();
        let receipt = launch.receipt.unwrap();
        let saved: Value = serde_json::from_slice(&std::fs::read(journal).unwrap()).unwrap();
        let mut evidence: Vec<Value> = saved["records"]
            .as_object()
            .unwrap()
            .values()
            .cloned()
            .collect();
        evidence.sort_by_key(|row| row["sequence"].as_i64().unwrap_or(0));
        let mut evidence_cursor = 0usize;
        let mut results: Vec<Value> = saved["results"]
            .as_object()
            .map(|rows| rows.values().cloned().collect())
            .unwrap_or_default();
        results.sort_by_key(|row| row["terminal_sequence"].as_i64().unwrap_or(0));
        let mut result_cursor = 0usize;
        let requests: Vec<Value> = traces
            .lock()
            .expect("traces")
            .iter()
            .map(|trace| {
                let mut item = json!({
                    "method": trace.method,
                    "path": trace.path,
                    "status": trace.status,
                    "request_id": trace.request_id,
                });
                if trace.path.ends_with("/evidence") {
                    if let Some(row) = evidence.get(evidence_cursor) {
                        item["sequence"] = row["sequence"].clone();
                        item["receipt_id"] = json!(format!(
                            "{}:{}",
                            row["handoff_id"].as_str().unwrap_or(""),
                            row["sequence"].as_i64().unwrap_or(0)
                        ));
                        evidence_cursor += 1;
                    }
                } else if trace.path.ends_with("/launch/admit")
                    || trace.path.ends_with("/launch/consume")
                {
                    item["receipt_id"] = json!(admission.id);
                } else if trace.path.ends_with("/result") {
                    if let Some(row) = results.get(result_cursor) {
                        item["sequence"] = row["terminal_sequence"].clone();
                        item["receipt_id"] = json!(format!(
                            "{}:{}",
                            row["handoff_id"].as_str().unwrap_or(""),
                            row["terminal_sequence"].as_i64().unwrap_or(0)
                        ));
                        result_cursor += 1;
                    }
                }
                item
            })
            .collect();
        json!({
            "origin": live.origin.as_str(),
            "host": live.host,
            "environment": live.environment,
            "deploy_handoff": live.deploy.handoff_id,
            "verify_handoff": live.verify.as_ref().map(|intent| intent.handoff_id.clone()),
            "requests": requests,
            "handoffs": handoffs,
            "admission_id": admission.id,
            "binding_digest": admission.binding_digest_sha256,
            "consume_receipt": {
                "handoff_id": receipt.handoff_id,
                "admission_id": receipt.admission_id,
                "consumed": receipt.consumed,
                "consumed_at": receipt.consumed_at,
            },
            "timestamps": {
                "started_at": format_timestamp(now_unix().saturating_sub(started.elapsed().as_secs() as i64)).unwrap(),
                "finished_at": format_timestamp(now_unix()).unwrap(),
            },
        })
    }

    fn assert_live_bytes_exclude_key(bytes: &[u8], key_file: &Path) {
        let (mut key, _) = read_private_file(key_file, MAX_API_KEY_BYTES, None).expect("live key");
        let leaked = !key.is_empty() && contains_slice(bytes, &key);
        key.fill(0);
        assert!(!leaked, "live output contains the api key");
    }
}
