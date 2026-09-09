//! Guarded Paimos external-stage adapter (PHAROS-206).
//!
//! Paimos supplies an opaque handoff and a value-free stage projection. Every
//! authority-bearing choice remains in this service's owner-only local intent
//! file: host, guarded workflow, environment, and exact artifact identity.
//! After a durable deployment accept this adapter creates or attaches exactly
//! one locally configured `UpdateRestart` review. The default attended path
//! never confirms it; a v3 intent can opt into one Paimos-rooted, consumed
//! launch admission after the complete host-agent review. Neither path claims,
//! dispatches, or executes host commands. Sequence-2 reports require a later
//! measured deployed-artifact observation; Nix generation / `flake.lock`
//! evidence is not that proof.

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
use crate::host_actions::{
    HostActionJob, HostActionPlan, HostActionState, HostActionStore, HostActionStoreError,
    HostWorkflowKind, UpdateRestartIntent,
};
use crate::store::Store;
use pharos_core::{valid_inspr_calendar_version, ArtifactVersionScheme};

pub(crate) const PAIMOS_SCHEMA_MAJOR: u16 = 2;
pub(crate) const PAIMOS_RELEASE: &str = "v26.09.05";
pub(crate) const PAIMOS_CERTIFIED_COMMIT: &str = "bb3b874f22a14fbe3879b1b575f33d55a001312d";
pub(crate) const PAIMOS_FIXTURE_DIGEST: &str =
    "sha256:6bba9613230c6ea728db58ffea5533399caed19e6d56a8d78ef19d0fde20be8a";
#[cfg(test)]
pub(crate) const PAIMOS_JANUS_DEPENDENCY_SHA256: &str =
    "52a647abd52e229fcdef8461eeb9f7d31f07632501ad33f594cdfbc155c23d4b";

const CONFIG_SCHEMA_V2: &str = "inspr.pharos.paimos-delivery-adapter.v2";
const CONFIG_SCHEMA_V3: &str = "inspr.pharos.paimos-delivery-adapter.v3";
const CONFIG_SCHEMA_VERSION_V2: u16 = 2;
const CONFIG_SCHEMA_VERSION_V3: u16 = 3;
const JOURNAL_SCHEMA: &str = "inspr.pharos.paimos-delivery-journal.v1";
const INTENT_BINDING_DOMAIN: &str = "inspr.pharos.paimos-delivery-intent.v2";
const DELEGATED_INTENT_BINDING_DOMAIN: &str = "inspr.pharos.paimos-delivery-intent.v3";
const OPERATION_BINDING_DOMAIN: &str = "inspr.pharos.paimos-delivery-operation.v1";
const CONTRACT_MEDIA_TYPE: &str = "application/vnd.paimos.external-stage.v2+json";
const LAUNCH_MEDIA_TYPE: &str = "application/vnd.paimos.external-stage-launch-admission.v1+json";
const LAUNCH_SCHEMA: &str = "paimos.external-stage-launch-admission";
const LAUNCH_VERSION: u16 = 1;
const LAUNCH_WORKFLOW: &str = "deploy-production";
const LAUNCH_STAGE: &str = "deployment";
const REVIEWED_PLAN_DOMAIN: &[u8] = b"inspr.pharos.paimos-launch-reviewed-plan.v1\0";
const LAUNCH_OPERATION_DOMAIN: &[u8] = b"inspr.pharos.paimos-launch-operation.v1\0";
const LAUNCH_CANDIDATE_IDEMPOTENCY_DOMAIN: &[u8] =
    b"inspr.pharos.paimos-launch-candidate-idempotency.v1\0";
const LAUNCH_CONSUME_IDEMPOTENCY_DOMAIN: &[u8] =
    b"inspr.pharos.paimos-launch-consume-idempotency.v1\0";
const HANDOFF_SECRET_HEADER: &str = "X-PAIMOS-Handoff-Secret";
const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";
const USER_AGENT_VALUE: &str = "pharosd-paimos-delivery/1";
const IDENTITY_ENCODING: &str = "identity";
const HANDOFF_SECRET_BYTES: usize = 32;
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;
const MAX_API_KEY_BYTES: u64 = 512;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MAX_INTENTS: usize = 128;
const MAX_JOURNAL_RECORDS: usize = MAX_INTENTS * 2;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const IDEMPOTENCY_DOMAIN: &[u8] = b"inspr.pharos.paimos-delivery-idempotency.v1\0";
const GUARDED_ACTOR: &str = "paimos-delivery";

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
    version_scheme: ArtifactVersionScheme,
    version: String,
    release_channel: String,
    release_sequence: i64,
    digest: String,
    commit_digest: String,
    release_manifest_coordinate: String,
    release_manifest_digest: String,
}

impl ArtifactEvidence {
    fn valid(&self) -> bool {
        let scheme_ok = match self.version_scheme {
            ArtifactVersionScheme::Legacy => valid_version(&self.version),
            ArtifactVersionScheme::InsprCalendarV1 => valid_inspr_calendar_version(&self.version),
        };
        scheme_ok
            && valid_symbol(&self.release_channel)
            && self.release_sequence >= 0
            && valid_sha256_digest(&self.digest)
            && valid_lower_hex(&self.commit_digest, &[40, 64])
            && valid_release_manifest_coordinate(&self.release_manifest_coordinate)
            && valid_sha256_digest(&self.release_manifest_digest)
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
    #[serde(default)]
    delegated_launch: Option<DelegatedLaunchSelection>,
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
                            .is_none_or(valid_action_id)
                        && self.deployment_handoff_id.is_none()
                        && self
                            .delegated_launch
                            .as_ref()
                            .is_none_or(DelegatedLaunchSelection::valid)
                }
                IntentStage::Verification => {
                    self.workflow == GuardedWorkflow::VerifyProduction
                        && self.update_restart_job_id.is_none()
                        && self.delegated_launch.is_none()
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

        let bytes = if let Some(selection) = &self.delegated_launch {
            #[derive(Serialize)]
            struct DelegatedIntentBinding<'a> {
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
                delegated_launch_target_ref: &'a str,
            }
            serde_json::to_vec(&DelegatedIntentBinding {
                domain: DELEGATED_INTENT_BINDING_DOMAIN,
                paimos_origin: paimos_origin.as_str(),
                handoff_id: &self.handoff_id,
                stage: self.stage.key(),
                workflow: self.workflow.key(),
                environment: &self.environment,
                host: &self.host,
                artifact: &self.artifact,
                update_restart_job_id: self.update_restart_job_id.as_deref(),
                deployment_handoff_id: self.deployment_handoff_id.as_deref(),
                delegated_launch_target_ref: &selection.target_ref,
            })
        } else {
            serde_json::to_vec(&IntentBinding {
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
            })
        }
        .map_err(|_| AdapterError::Contract)?;
        Ok(hex_digest(&bytes))
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct DelegatedLaunchSelection {
    target_ref: String,
}

impl DelegatedLaunchSelection {
    fn valid(&self) -> bool {
        valid_sha256_digest(&self.target_ref)
    }
}

#[derive(Deserialize)]
struct ConfigVersionProbe {
    schema: String,
    schema_version: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocumentV2 {
    #[serde(rename = "schema")]
    _schema: String,
    #[serde(rename = "schema_version")]
    _schema_version: u16,
    paimos_origin: String,
    api_key_file: PathBuf,
    poll_interval_secs: u64,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntentV2>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConfigDocumentV3 {
    #[serde(rename = "schema")]
    _schema: String,
    #[serde(rename = "schema_version")]
    _schema_version: u16,
    paimos_origin: String,
    api_key_file: PathBuf,
    poll_interval_secs: u64,
    verification_freshness_secs: i64,
    intents: Vec<DeliveryIntent>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeliveryIntentV2 {
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

impl From<DeliveryIntentV2> for DeliveryIntent {
    fn from(intent: DeliveryIntentV2) -> Self {
        Self {
            handoff_id: intent.handoff_id,
            handoff_secret_file: intent.handoff_secret_file,
            stage: intent.stage,
            workflow: intent.workflow,
            environment: intent.environment,
            host: intent.host,
            artifact: intent.artifact,
            update_restart_job_id: intent.update_restart_job_id,
            deployment_handoff_id: intent.deployment_handoff_id,
            delegated_launch: None,
        }
    }
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
        let probe: ConfigVersionProbe =
            decode_strict(&bytes).map_err(|_| AdapterError::Configuration)?;
        let (paimos_origin, api_key_file, poll_interval_secs, verification_freshness_secs, intents) =
            match (probe.schema.as_str(), probe.schema_version) {
                (CONFIG_SCHEMA_V2, CONFIG_SCHEMA_VERSION_V2) => {
                    let document: ConfigDocumentV2 =
                        decode_strict(&bytes).map_err(|_| AdapterError::Configuration)?;
                    (
                        document.paimos_origin,
                        document.api_key_file,
                        document.poll_interval_secs,
                        document.verification_freshness_secs,
                        document.intents.into_iter().map(Into::into).collect(),
                    )
                }
                (CONFIG_SCHEMA_V3, CONFIG_SCHEMA_VERSION_V3) => {
                    let document: ConfigDocumentV3 =
                        decode_strict(&bytes).map_err(|_| AdapterError::Configuration)?;
                    (
                        document.paimos_origin,
                        document.api_key_file,
                        document.poll_interval_secs,
                        document.verification_freshness_secs,
                        document.intents,
                    )
                }
                _ => return Err(AdapterError::Configuration),
            };
        if !(5..=3600).contains(&poll_interval_secs)
            || !(30..=900).contains(&verification_freshness_secs)
            || intents.is_empty()
            || intents.len() > MAX_INTENTS
            || intents.iter().any(|intent| !intent.valid_shape())
        {
            return Err(AdapterError::Configuration);
        }
        let paimos_origin = parse_origin(&paimos_origin)?;
        let (mut api_key, api_identity) =
            read_private_file(&api_key_file, MAX_API_KEY_BYTES, None)?;
        let api_key_valid =
            api_key.len() >= 32 && api_key.iter().all(|byte| (0x21..=0x7e).contains(byte));
        api_key.fill(0);
        if !api_key_valid {
            return Err(AdapterError::Credential);
        }
        let mut handoff_ids = BTreeSet::new();
        let mut credential_files = BTreeSet::new();
        credential_files.insert(api_identity);
        for intent in &intents {
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
        for intent in intents
            .iter()
            .filter(|intent| intent.stage == IntentStage::Verification)
        {
            let deployment = intents.iter().find(|candidate| {
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
            api_key_file,
            poll_interval: Duration::from_secs(poll_interval_secs),
            verification_freshness_secs,
            intents,
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

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchCandidate {
    schema: String,
    version: u16,
    target_ref: String,
    workflow: String,
    environment: String,
    artifact: ArtifactEvidence,
    reviewed_plan_digest: String,
    operation_binding_digest: String,
    observed_at: String,
}

impl LaunchCandidate {
    fn valid(&self) -> bool {
        self.schema == LAUNCH_SCHEMA
            && self.version == LAUNCH_VERSION
            && valid_sha256_digest(&self.target_ref)
            && self.workflow == LAUNCH_WORKFLOW
            && valid_symbol(&self.environment)
            && self.artifact.valid()
            && valid_sha256_digest(&self.reviewed_plan_digest)
            && valid_sha256_digest(&self.operation_binding_digest)
            && self.reviewed_plan_digest != self.operation_binding_digest
            && parse_timestamp(&self.observed_at).is_ok()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchAdmission {
    schema: String,
    version: u16,
    grant_id: String,
    grant_revision: i64,
    grant_digest: String,
    admission_id: String,
    admission_digest: String,
    handoff_id: String,
    credential_epoch: i64,
    target_ref: String,
    workflow: String,
    environment: String,
    artifact: ArtifactEvidence,
    stage: String,
    attempt: i64,
    plan: i64,
    execution: i64,
    authority: i64,
    plan_digest: String,
    predecessor_digest: String,
    context_digest: String,
    reviewed_plan_digest: String,
    operation_binding_digest: String,
    max_launches: i64,
    used_launches: i64,
    issued_at: String,
    expires_at: String,
    state: String,
}

impl LaunchAdmission {
    fn valid_journaled(&self, handoff_id: &str, candidate: &LaunchCandidate) -> bool {
        let times_valid = parse_timestamp(&self.issued_at)
            .and_then(|issued| {
                parse_timestamp(&self.expires_at).map(|expires| {
                    expires > issued && expires <= issued + time::Duration::minutes(15)
                })
            })
            .unwrap_or(false);
        self.schema == LAUNCH_SCHEMA
            && self.version == LAUNCH_VERSION
            && valid_uuid(&self.grant_id)
            && self.grant_revision == 1
            && valid_sha256_digest(&self.grant_digest)
            && valid_uuid(&self.admission_id)
            && self.admission_id != self.grant_id
            && valid_sha256_digest(&self.admission_digest)
            && self.handoff_id == handoff_id
            && self.credential_epoch >= 1
            && self.target_ref == candidate.target_ref
            && self.workflow == candidate.workflow
            && self.environment == candidate.environment
            && self.artifact == candidate.artifact
            && self.stage == LAUNCH_STAGE
            && self.attempt >= 1
            && self.plan >= 1
            && self.execution >= 1
            && self.authority >= 1
            && valid_sha256_digest(&self.plan_digest)
            && valid_sha256_digest(&self.predecessor_digest)
            && valid_sha256_digest(&self.context_digest)
            && self.reviewed_plan_digest == candidate.reviewed_plan_digest
            && self.operation_binding_digest == candidate.operation_binding_digest
            && self.max_launches == 1
            && self.used_launches == 0
            && self.state == "issued"
            && times_valid
    }

    fn validate(
        &self,
        handoff_id: &str,
        candidate: &LaunchCandidate,
        pull: &PullResponse,
        now: i64,
    ) -> Result<(), AdapterError> {
        let issued_at = parse_timestamp(&self.issued_at)?;
        let expires_at = parse_timestamp(&self.expires_at)?;
        let pull_expires_at = parse_timestamp(&pull.expires_at)?;
        if self.schema != LAUNCH_SCHEMA
            || self.version != LAUNCH_VERSION
            || !valid_uuid(&self.grant_id)
            || self.grant_revision != 1
            || !valid_sha256_digest(&self.grant_digest)
            || !valid_uuid(&self.admission_id)
            || self.admission_id == self.grant_id
            || !valid_sha256_digest(&self.admission_digest)
            || self.handoff_id != handoff_id
            || self.credential_epoch != pull.credential_epoch
            || self.target_ref != candidate.target_ref
            || self.workflow != candidate.workflow
            || self.environment != candidate.environment
            || self.artifact != candidate.artifact
            || self.stage != LAUNCH_STAGE
            || self.attempt < 1
            || self.plan < 1
            || self.execution != pull.execution_number
            || self.authority != pull.authority_epoch
            || self.plan_digest != pull.plan_digest
            || self.predecessor_digest != pull.predecessor_digest
            || self.context_digest != pull.context_digest
            || self.reviewed_plan_digest != candidate.reviewed_plan_digest
            || self.operation_binding_digest != candidate.operation_binding_digest
            || self.max_launches != 1
            || self.used_launches != 0
            || self.state != "issued"
            || issued_at.unix_timestamp() > now.saturating_add(120)
            || expires_at <= issued_at
            || expires_at.unix_timestamp() <= now
            || expires_at > pull_expires_at
            || expires_at > issued_at + time::Duration::minutes(15)
        {
            return Err(AdapterError::Contract);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchConsumeRequest {
    schema: String,
    version: u16,
    admission_digest: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchReceipt {
    schema: String,
    version: u16,
    admission_id: String,
    admission_digest: String,
    handoff_id: String,
    credential_epoch: i64,
    launch_number: i64,
    state: String,
    consumed_at: String,
}

impl LaunchReceipt {
    fn validate(&self, admission: &LaunchAdmission) -> Result<(), AdapterError> {
        let consumed_at = parse_timestamp(&self.consumed_at)?;
        let issued_at = parse_timestamp(&admission.issued_at)?;
        let expires_at = parse_timestamp(&admission.expires_at)?;
        if self.schema != LAUNCH_SCHEMA
            || self.version != LAUNCH_VERSION
            || self.admission_id != admission.admission_id
            || self.admission_digest != admission.admission_digest
            || self.handoff_id != admission.handoff_id
            || self.credential_epoch != admission.credential_epoch
            || self.launch_number != 1
            || self.state != "consumed"
            || consumed_at < issued_at
            || consumed_at >= expires_at
        {
            return Err(AdapterError::Contract);
        }
        Ok(())
    }
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

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OperationBinding {
    handoff_id: String,
    job_id: String,
    host: String,
    workflow: String,
    environment: String,
    artifact: ArtifactEvidence,
    plan_digest: String,
    predecessor_digest: String,
    authority_epoch: i64,
    execution_number: i64,
    context_digest: String,
    operation_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct LaunchJournalRecord {
    handoff_id: String,
    intent_digest: String,
    job_id: String,
    candidate_digest: String,
    candidate_idempotency_key: String,
    candidate_body_json: String,
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
    receipt: Option<LaunchReceipt>,
}

impl LaunchJournalRecord {
    fn new(
        intent: &DeliveryIntent,
        paimos_origin: &Url,
        job_id: &str,
        candidate: &LaunchCandidate,
    ) -> Result<Self, AdapterError> {
        let selection = intent
            .delegated_launch
            .as_ref()
            .ok_or(AdapterError::LocalBinding)?;
        if !candidate.valid()
            || !valid_action_id(job_id)
            || intent.stage != IntentStage::Deployment
            || candidate.target_ref != selection.target_ref
            || candidate.workflow != intent.workflow.key()
            || candidate.environment != intent.environment
            || candidate.artifact != intent.artifact
        {
            return Err(AdapterError::Contract);
        }
        let body = serde_json::to_vec(candidate).map_err(|_| AdapterError::Contract)?;
        let candidate_digest = sha256_digest(&body);
        Ok(Self {
            handoff_id: intent.handoff_id.clone(),
            intent_digest: intent.binding_digest(paimos_origin)?,
            job_id: job_id.to_string(),
            candidate_idempotency_key: launch_idempotency_key(
                LAUNCH_CANDIDATE_IDEMPOTENCY_DOMAIN,
                &intent.handoff_id,
                &candidate_digest,
            ),
            candidate_digest,
            candidate_body_json: String::from_utf8(body).map_err(|_| AdapterError::Contract)?,
            admission: None,
            consume_digest: None,
            consume_idempotency_key: None,
            consume_body_json: None,
            consume_started: false,
            receipt: None,
        })
    }

    fn candidate(&self) -> Result<LaunchCandidate, AdapterError> {
        decode_strict(self.candidate_body_json.as_bytes())
    }

    fn consume(&self) -> Result<LaunchConsumeRequest, AdapterError> {
        let body = self
            .consume_body_json
            .as_deref()
            .ok_or(AdapterError::Journal)?;
        decode_strict(body.as_bytes())
    }

    fn bound_to(&self, intent: &DeliveryIntent, paimos_origin: &Url, job_id: &str) -> bool {
        self.handoff_id == intent.handoff_id
            && self.job_id == job_id
            && intent
                .binding_digest(paimos_origin)
                .is_ok_and(|digest| digest == self.intent_digest)
    }

    fn valid(&self) -> bool {
        let Ok(candidate) = self.candidate() else {
            return false;
        };
        if !candidate.valid()
            || !valid_handoff_id(&self.handoff_id)
            || !valid_action_id(&self.job_id)
            || !valid_lower_hex(&self.intent_digest, &[64])
            || self.candidate_digest != sha256_digest(self.candidate_body_json.as_bytes())
            || self.candidate_idempotency_key
                != launch_idempotency_key(
                    LAUNCH_CANDIDATE_IDEMPOTENCY_DOMAIN,
                    &self.handoff_id,
                    &self.candidate_digest,
                )
        {
            return false;
        }
        let Some(admission) = &self.admission else {
            return self.consume_digest.is_none()
                && self.consume_idempotency_key.is_none()
                && self.consume_body_json.is_none()
                && !self.consume_started
                && self.receipt.is_none();
        };
        if !admission.valid_journaled(&self.handoff_id, &candidate) {
            return false;
        }
        let Ok(consume) = self.consume() else {
            return false;
        };
        let Some(consume_digest) = &self.consume_digest else {
            return false;
        };
        let Some(consume_idempotency_key) = &self.consume_idempotency_key else {
            return false;
        };
        consume.schema == LAUNCH_SCHEMA
            && consume.version == LAUNCH_VERSION
            && consume.admission_digest == admission.admission_digest
            && consume_digest
                == &sha256_digest(
                    self.consume_body_json
                        .as_deref()
                        .expect("decoded consume body exists")
                        .as_bytes(),
                )
            && consume_idempotency_key
                == &launch_idempotency_key(
                    LAUNCH_CONSUME_IDEMPOTENCY_DOMAIN,
                    &self.handoff_id,
                    consume_digest,
                )
            && self
                .receipt
                .as_ref()
                .is_none_or(|receipt| self.consume_started && receipt.validate(admission).is_ok())
    }
}

impl OperationBinding {
    fn valid(&self) -> bool {
        valid_handoff_id(&self.handoff_id)
            && valid_action_id(&self.job_id)
            && valid_host(&self.host)
            && valid_symbol(&self.workflow)
            && valid_symbol(&self.environment)
            && self.artifact.valid()
            && valid_sha256_digest(&self.plan_digest)
            && valid_sha256_digest(&self.predecessor_digest)
            && self.authority_epoch >= 1
            && self.execution_number >= 1
            && valid_sha256_digest(&self.context_digest)
            && valid_lower_hex(&self.operation_id, &[64])
    }

    fn matches_pull(&self, pull: &PullResponse) -> bool {
        self.plan_digest == pull.plan_digest
            && self.predecessor_digest == pull.predecessor_digest
            && self.authority_epoch == pull.authority_epoch
            && self.execution_number == pull.execution_number
            && self.context_digest == pull.context_digest
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalDocument {
    schema: String,
    schema_version: u16,
    records: BTreeMap<String, JournalRecord>,
    #[serde(default)]
    operations: BTreeMap<String, OperationBinding>,
    #[serde(default)]
    launches: BTreeMap<String, LaunchJournalRecord>,
}

impl Default for JournalDocument {
    fn default() -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_string(),
            schema_version: 1,
            records: BTreeMap::new(),
            operations: BTreeMap::new(),
            launches: BTreeMap::new(),
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
            let (bytes, _) = read_private_file(&path, MAX_JOURNAL_BYTES, None)?;
            decode_strict::<JournalDocument>(&bytes).map_err(|_| AdapterError::Journal)?
        } else {
            JournalDocument::default()
        };
        if document.schema != JOURNAL_SCHEMA
            || !matches!(document.schema_version, 1 | 2)
            || (document.schema_version == 1 && !document.launches.is_empty())
            || document.records.len() > MAX_JOURNAL_RECORDS
            || document.operations.len() > MAX_JOURNAL_RECORDS
            || document.launches.len() > MAX_INTENTS
            || document
                .records
                .iter()
                .any(|(key, record)| key != &record.key() || !record.valid())
            || document
                .operations
                .iter()
                .any(|(key, binding)| key != &binding.handoff_id || !binding.valid())
            || document
                .launches
                .iter()
                .any(|(key, launch)| key != &launch.handoff_id || !launch.valid())
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

    fn operation(&self, handoff_id: &str) -> Option<OperationBinding> {
        self.document
            .lock()
            .expect("Paimos delivery journal lock")
            .operations
            .get(handoff_id)
            .cloned()
    }

    fn persist_operation(
        &self,
        binding: OperationBinding,
    ) -> Result<OperationBinding, AdapterError> {
        if !binding.valid() {
            return Err(AdapterError::Journal);
        }
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
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
        match atomic_write_json(&self.path, &updated) {
            Ok(()) => {
                *document = updated;
                Ok(binding)
            }
            Err(error) if error.final_file_replaced() => {
                *document = updated;
                Err(AdapterError::Journal)
            }
            Err(_) => Err(AdapterError::Journal),
        }
    }

    fn launch(&self, handoff_id: &str) -> Option<LaunchJournalRecord> {
        self.document
            .lock()
            .expect("Paimos delivery journal lock")
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
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        if let Some(existing) = document.launches.get(&record.handoff_id) {
            return if existing == &record {
                Ok(existing.clone())
            } else {
                Err(AdapterError::LocalBinding)
            };
        }
        if document.launches.len() >= MAX_INTENTS {
            return Err(AdapterError::Journal);
        }
        let mut updated = document.clone();
        updated.schema_version = 2;
        updated
            .launches
            .insert(record.handoff_id.clone(), record.clone());
        persist_journal_update(&self.path, &mut document, updated)?;
        Ok(record)
    }

    fn acknowledge_launch_admission(
        &self,
        record: &LaunchJournalRecord,
        admission: LaunchAdmission,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        let existing = document
            .launches
            .get(&record.handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing != record {
            return Err(AdapterError::Journal);
        }
        if let Some(saved) = &existing.admission {
            return if saved == &admission {
                Ok(existing.clone())
            } else {
                Err(AdapterError::Contract)
            };
        }
        let candidate = existing.candidate()?;
        if !admission.valid_journaled(&record.handoff_id, &candidate) {
            return Err(AdapterError::Contract);
        }
        let consume = LaunchConsumeRequest {
            schema: LAUNCH_SCHEMA.to_string(),
            version: LAUNCH_VERSION,
            admission_digest: admission.admission_digest.clone(),
        };
        let consume_body = serde_json::to_vec(&consume).map_err(|_| AdapterError::Contract)?;
        let consume_digest = sha256_digest(&consume_body);
        let mut updated = document.clone();
        updated.schema_version = 2;
        let launch = updated
            .launches
            .get_mut(&record.handoff_id)
            .expect("launch record remains present");
        launch.admission = Some(admission);
        launch.consume_idempotency_key = Some(launch_idempotency_key(
            LAUNCH_CONSUME_IDEMPOTENCY_DOMAIN,
            &record.handoff_id,
            &consume_digest,
        ));
        launch.consume_digest = Some(consume_digest);
        launch.consume_body_json =
            Some(String::from_utf8(consume_body).map_err(|_| AdapterError::Contract)?);
        if !launch.valid() {
            return Err(AdapterError::Journal);
        }
        let saved = launch.clone();
        persist_journal_update(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn mark_launch_consume_started(
        &self,
        record: &LaunchJournalRecord,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        let existing = document
            .launches
            .get(&record.handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing != record || existing.admission.is_none() {
            return Err(AdapterError::Journal);
        }
        if existing.consume_started {
            return Ok(existing.clone());
        }
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(&record.handoff_id)
            .expect("launch record remains present");
        launch.consume_started = true;
        if !launch.valid() {
            return Err(AdapterError::Journal);
        }
        let saved = launch.clone();
        persist_journal_update(&self.path, &mut document, updated)?;
        Ok(saved)
    }

    fn acknowledge_launch_receipt(
        &self,
        record: &LaunchJournalRecord,
        receipt: LaunchReceipt,
    ) -> Result<LaunchJournalRecord, AdapterError> {
        let mut document = self.document.lock().expect("Paimos delivery journal lock");
        let existing = document
            .launches
            .get(&record.handoff_id)
            .ok_or(AdapterError::Journal)?;
        if existing != record || !existing.consume_started {
            return Err(AdapterError::Journal);
        }
        if let Some(saved) = &existing.receipt {
            return if saved == &receipt {
                Ok(existing.clone())
            } else {
                Err(AdapterError::Contract)
            };
        }
        let admission = existing.admission.as_ref().ok_or(AdapterError::Journal)?;
        receipt.validate(admission)?;
        let mut updated = document.clone();
        let launch = updated
            .launches
            .get_mut(&record.handoff_id)
            .expect("launch record remains present");
        launch.receipt = Some(receipt);
        if !launch.valid() {
            return Err(AdapterError::Journal);
        }
        let saved = launch.clone();
        persist_journal_update(&self.path, &mut document, updated)?;
        Ok(saved)
    }
}

fn persist_journal_update(
    path: &Path,
    document: &mut JournalDocument,
    updated: JournalDocument,
) -> Result<(), AdapterError> {
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
            .no_gzip()
            .no_brotli()
            .no_zstd()
            .no_deflate()
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
                CONTRACT_MEDIA_TYPE,
                None,
                None,
                &credentials,
            )
            .await?;
        if response.status() != StatusCode::OK {
            return Err(AdapterError::Refused(response.status()));
        }
        self.decode_response(response, CONTRACT_MEDIA_TYPE, &credentials, None)
            .await
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
                CONTRACT_MEDIA_TYPE,
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
            .decode_response(
                response,
                CONTRACT_MEDIA_TYPE,
                &credentials,
                Some(&record.idempotency_key),
            )
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
        media_type: &'static str,
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
            .header(ACCEPT, media_type)
            .header(ACCEPT_ENCODING, IDENTITY_ENCODING)
            .header(AUTHORIZATION, authorization_value)
            .header(HANDOFF_SECRET_HEADER, secret_value);
        if let Some(idempotency_key) = idempotency_key {
            builder = builder.header(IDEMPOTENCY_HEADER, idempotency_key);
        }
        if let Some(body) = body {
            builder = builder.header(CONTENT_TYPE, media_type).body(body.to_vec());
        }
        builder.send().await.map_err(|_| AdapterError::Transport)
    }

    async fn decode_response<T: for<'de> Deserialize<'de>>(
        &self,
        response: reqwest::Response,
        media_type: &'static str,
        credentials: &Credentials,
        idempotency_key: Option<&str>,
    ) -> Result<T, AdapterError> {
        if !response_media_valid(response.headers(), media_type) {
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

    async fn request_launch_candidate(
        &self,
        intent: &DeliveryIntent,
        record: &LaunchJournalRecord,
    ) -> Result<LaunchAdmission, AdapterError> {
        if !record.valid() || record.admission.is_some() || record.consume_started {
            return Err(AdapterError::Journal);
        }
        let credentials = self.credentials(intent)?;
        let response = self
            .request(
                Method::POST,
                &format!(
                    "/api/external-stage/handoffs/{}/launch-candidates",
                    intent.handoff_id
                ),
                LAUNCH_MEDIA_TYPE,
                Some(record.candidate_body_json.as_bytes()),
                Some(&record.candidate_idempotency_key),
                &credentials,
            )
            .await?;
        if response.status() != StatusCode::OK || !response_no_store(response.headers()) {
            return if response.status() == StatusCode::OK {
                Err(AdapterError::Contract)
            } else {
                Err(AdapterError::Refused(response.status()))
            };
        }
        self.decode_response(
            response,
            LAUNCH_MEDIA_TYPE,
            &credentials,
            Some(&record.candidate_idempotency_key),
        )
        .await
    }

    async fn consume_launch(
        &self,
        intent: &DeliveryIntent,
        record: &LaunchJournalRecord,
    ) -> Result<LaunchReceipt, AdapterError> {
        if !record.valid() || !record.consume_started || record.receipt.is_some() {
            return Err(AdapterError::Journal);
        }
        let admission = record.admission.as_ref().ok_or(AdapterError::Journal)?;
        let idempotency_key = record
            .consume_idempotency_key
            .as_deref()
            .ok_or(AdapterError::Journal)?;
        let body = record
            .consume_body_json
            .as_deref()
            .ok_or(AdapterError::Journal)?;
        let credentials = self.credentials(intent)?;
        let response = self
            .request(
                Method::POST,
                &format!(
                    "/api/external-stage/handoffs/{}/launch-admissions/{}/consume",
                    intent.handoff_id, admission.admission_id
                ),
                LAUNCH_MEDIA_TYPE,
                Some(body.as_bytes()),
                Some(idempotency_key),
                &credentials,
            )
            .await?;
        if response.status() != StatusCode::OK || !response_no_store(response.headers()) {
            return if response.status() == StatusCode::OK {
                Err(AdapterError::Contract)
            } else {
                Err(AdapterError::Refused(response.status()))
            };
        }
        self.decode_response(
            response,
            LAUNCH_MEDIA_TYPE,
            &credentials,
            Some(idempotency_key),
        )
        .await
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
            "Paimos guarded delivery adapter enabled"
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
        if self.replay_started_launch(intent).await? {
            return Ok(());
        }
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
                    .await?;
                self.bind_after_accept(intent, &pull, now_unix())
            }
            HandoffState::Accepted => {
                if self.journal.receipt(&intent.handoff_id, 1).is_none() {
                    return Err(AdapterError::LocalBinding);
                }
                self.bind_after_accept(intent, &pull, now_unix())?;
                if intent.delegated_launch.is_some() {
                    self.process_delegated_launch(intent, &pull, now_unix())
                        .await?;
                }
                let Some(request) = self.local_terminal_report(intent, &pull, now_unix())? else {
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

    /// Complete only an already-started consume replay before consulting the
    /// current handoff state. Paimos may return the immutable historical
    /// receipt after expiry; a never-consumed, revoked admission still refuses.
    async fn replay_started_launch(&self, intent: &DeliveryIntent) -> Result<bool, AdapterError> {
        let Some(record) = self.journal.launch(&intent.handoff_id) else {
            return Ok(false);
        };
        if intent.delegated_launch.is_none() || !record.valid() {
            return Err(AdapterError::LocalBinding);
        }
        let operation = self
            .journal
            .operation(&intent.handoff_id)
            .ok_or(AdapterError::LocalBinding)?;
        if !record.bound_to(intent, &self.config.paimos_origin, &operation.job_id) {
            return Err(AdapterError::LocalBinding);
        }
        if record.receipt.is_some() {
            self.finish_delegated_confirmation(intent, &record)?;
            return Ok(false);
        }
        if !record.consume_started {
            return Ok(false);
        }
        let receipt = self.paimos.consume_launch(intent, &record).await?;
        let admission = record.admission.as_ref().ok_or(AdapterError::Journal)?;
        receipt.validate(admission)?;
        let record = self.journal.acknowledge_launch_receipt(&record, receipt)?;
        self.finish_delegated_confirmation(intent, &record)?;
        Ok(true)
    }

    async fn process_delegated_launch(
        &self,
        intent: &DeliveryIntent,
        pull: &PullResponse,
        now: i64,
    ) -> Result<(), AdapterError> {
        let selection = intent
            .delegated_launch
            .as_ref()
            .ok_or(AdapterError::LocalBinding)?;
        if intent.stage != IntentStage::Deployment
            || intent.workflow != GuardedWorkflow::DeployProduction
            || pull.state != HandoffState::Accepted
            || parse_timestamp(&pull.expires_at)?.unix_timestamp() <= now
        {
            return Err(AdapterError::LocalBinding);
        }
        let operation = self
            .journal
            .operation(&intent.handoff_id)
            .ok_or(AdapterError::LocalBinding)?;
        if !operation.matches_pull(pull) {
            return Err(AdapterError::LocalBinding);
        }
        if self
            .journal
            .launch(&intent.handoff_id)
            .is_some_and(|record| record.receipt.is_some())
        {
            return Ok(());
        }
        let job = self.launch_ready_job(intent, &operation.job_id)?;
        let reviewed_digest = reviewed_plan_digest(&job)?;
        let expected_candidate = launch_candidate(intent, selection, pull, &reviewed_digest, now)?;
        let mut record = if let Some(existing) = self.journal.launch(&intent.handoff_id) {
            if !existing.bound_to(intent, &self.config.paimos_origin, &operation.job_id) {
                return Err(AdapterError::LocalBinding);
            }
            let saved = existing.candidate()?;
            if saved.target_ref != expected_candidate.target_ref
                || saved.workflow != expected_candidate.workflow
                || saved.environment != expected_candidate.environment
                || saved.artifact != expected_candidate.artifact
                || saved.reviewed_plan_digest != expected_candidate.reviewed_plan_digest
                || saved.operation_binding_digest != expected_candidate.operation_binding_digest
            {
                return Err(AdapterError::LocalBinding);
            }
            existing
        } else {
            self.journal.ensure_launch(LaunchJournalRecord::new(
                intent,
                &self.config.paimos_origin,
                &operation.job_id,
                &expected_candidate,
            )?)?
        };
        let candidate = record.candidate()?;
        if record.admission.is_none() {
            let admission = self
                .paimos
                .request_launch_candidate(intent, &record)
                .await?;
            admission.validate(&intent.handoff_id, &candidate, pull, now_unix())?;
            record = self
                .journal
                .acknowledge_launch_admission(&record, admission)?;
        }
        let fresh_pull = self.paimos.pull(intent).await?;
        fresh_pull.validate(intent)?;
        if fresh_pull.state != HandoffState::Accepted
            || fresh_pull != *pull
            || parse_timestamp(&fresh_pull.expires_at)?.unix_timestamp() <= now_unix()
        {
            return Err(AdapterError::LocalBinding);
        }
        let admission = record.admission.clone().ok_or(AdapterError::Journal)?;
        admission.validate(&intent.handoff_id, &candidate, &fresh_pull, now_unix())?;
        let fresh_job = self.launch_ready_job(intent, &operation.job_id)?;
        if reviewed_plan_digest(&fresh_job)? != candidate.reviewed_plan_digest {
            return Err(AdapterError::LocalBinding);
        }
        record = self.journal.mark_launch_consume_started(&record)?;
        let receipt = self.paimos.consume_launch(intent, &record).await?;
        receipt.validate(&admission)?;
        record = self.journal.acknowledge_launch_receipt(&record, receipt)?;
        self.finish_delegated_confirmation(intent, &record)
    }

    fn launch_ready_job(
        &self,
        intent: &DeliveryIntent,
        job_id: &str,
    ) -> Result<HostActionJob, AdapterError> {
        let job = self
            .host_actions
            .get(job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.host != intent.host
            || job.workflow_kind() != HostWorkflowKind::UpdateRestart
            || job.state != HostActionState::AwaitingConfirmation
            || !job.plan.as_ref().is_some_and(HostActionPlan::ready)
        {
            return Err(AdapterError::LocalBinding);
        }
        Ok(job)
    }

    fn finish_delegated_confirmation(
        &self,
        intent: &DeliveryIntent,
        record: &LaunchJournalRecord,
    ) -> Result<(), AdapterError> {
        let receipt = record.receipt.as_ref().ok_or(AdapterError::Journal)?;
        let admission = record.admission.as_ref().ok_or(AdapterError::Journal)?;
        receipt.validate(admission)?;
        let job = self
            .host_actions
            .get(&record.job_id)
            .ok_or(AdapterError::LocalBinding)?;
        if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
            return Err(AdapterError::LocalBinding);
        }
        let candidate = record.candidate()?;
        if reviewed_plan_digest(&job)? != candidate.reviewed_plan_digest {
            return Err(AdapterError::LocalBinding);
        }
        if job.state == HostActionState::AwaitingConfirmation {
            self.host_actions
                .confirm_update_delegated(
                    &record.job_id,
                    &intent.host,
                    &admission.admission_id,
                    parse_timestamp(&receipt.consumed_at)?.unix_timestamp(),
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
            // A prior exact delegated transition or a racing human transition
            // already moved this job. Historical receipt replay never invokes
            // confirmation again and never claims, dispatches, or executes it.
            return Ok(());
        }
        Err(AdapterError::LocalBinding)
    }

    fn local_terminal_report(
        &self,
        intent: &DeliveryIntent,
        pull: &PullResponse,
        now: i64,
    ) -> Result<Option<ReportRequest>, AdapterError> {
        match intent.stage {
            IntentStage::Deployment => self.deployment_report(intent, now),
            IntentStage::Verification => self.verification_report(intent, pull, now),
        }
    }

    fn bind_after_accept(
        &self,
        intent: &DeliveryIntent,
        pull: &PullResponse,
        now: i64,
    ) -> Result<(), AdapterError> {
        if intent.stage != IntentStage::Deployment {
            return Ok(());
        }
        if let Some(existing) = self.journal.operation(&intent.handoff_id) {
            if existing.host != intent.host
                || existing.workflow != intent.workflow.key()
                || existing.environment != intent.environment
                || existing.artifact != intent.artifact
                || !existing.matches_pull(pull)
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
            let Some(job) = self.host_actions.get(&existing.job_id) else {
                return Err(AdapterError::LocalBinding);
            };
            if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
                return Err(AdapterError::LocalBinding);
            }
            return Ok(());
        }
        let operation_id = operation_identity(intent, &self.config.paimos_origin, pull)?;
        let job_id = if let Some(configured) = intent.update_restart_job_id.as_deref() {
            let Some(job) = self.host_actions.get(configured) else {
                return Err(AdapterError::LocalBinding);
            };
            if job.host != intent.host || job.workflow_kind() != HostWorkflowKind::UpdateRestart {
                return Err(AdapterError::LocalBinding);
            }
            configured.to_string()
        } else {
            let job_id = deterministic_job_id(&intent.host, &operation_id);
            match self.host_actions.ensure_update_review_with_id(
                &job_id,
                &intent.host,
                GUARDED_ACTOR,
                UpdateRestartIntent::Update,
                now,
            ) {
                Ok(job) => {
                    if job.host != intent.host
                        || job.workflow_kind() != HostWorkflowKind::UpdateRestart
                    {
                        return Err(AdapterError::LocalBinding);
                    }
                    // Exact owned job may already be confirmed if the operator
                    // acted after insert and before journal persist. Bind that
                    // job only; never confirm, claim, dispatch, or adopt another.
                    job.id
                }
                Err(
                    HostActionStoreError::ActiveJob
                    | HostActionStoreError::FailedJobRequiresRetry
                    | HostActionStoreError::BlockedByFleetGate
                    | HostActionStoreError::WrongHost
                    | HostActionStoreError::InvalidJob,
                ) => return Err(AdapterError::LocalBinding),
                Err(_) => return Err(AdapterError::Journal),
            }
        };
        let binding = OperationBinding {
            handoff_id: intent.handoff_id.clone(),
            job_id,
            host: intent.host.clone(),
            workflow: intent.workflow.key().to_string(),
            environment: intent.environment.clone(),
            artifact: intent.artifact.clone(),
            plan_digest: pull.plan_digest.clone(),
            predecessor_digest: pull.predecessor_digest.clone(),
            authority_epoch: pull.authority_epoch,
            execution_number: pull.execution_number,
            context_digest: pull.context_digest.clone(),
            operation_id,
        };
        self.journal.persist_operation(binding)?;
        Ok(())
    }

    fn deployment_report(
        &self,
        intent: &DeliveryIntent,
        now: i64,
    ) -> Result<Option<ReportRequest>, AdapterError> {
        let job_id = self
            .journal
            .operation(&intent.handoff_id)
            .map(|binding| binding.job_id)
            .or_else(|| intent.update_restart_job_id.clone())
            .ok_or(AdapterError::LocalBinding)?;
        let Some(job) = self.host_actions.get(&job_id) else {
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
        pull: &PullResponse,
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
        let Some(deployment_op) = self.journal.operation(deployment_handoff) else {
            return Err(AdapterError::LocalBinding);
        };
        if deployment_op.artifact != intent.artifact
            || deployment_op.host != intent.host
            || deployment_op.environment != intent.environment
            || pull.predecessor_digest != deployment_op.plan_digest
            || pull.authority_epoch != deployment_op.authority_epoch
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
        let Some(evidence) = host.deployed_artifact.as_ref() else {
            return Ok(None);
        };
        if !evidence.is_config_class_measurement() {
            return Err(AdapterError::LocalBinding);
        }
        if !evidence.matches_expected(
            &intent.environment,
            intent.artifact.version_scheme,
            &intent.artifact.version,
            &intent.artifact.release_channel,
            intent.artifact.release_sequence,
            &intent.artifact.digest,
            &intent.artifact.commit_digest,
            &intent.artifact.release_manifest_coordinate,
            &intent.artifact.release_manifest_digest,
        ) {
            return Err(AdapterError::LocalBinding);
        }
        let observed_at = evidence.observed_at;
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
/// request side pins `Accept-Encoding: identity`, and the HTTP client disables
/// every reqwest response decompressor, so an encoded body reaches this check
/// with its header intact instead of being transparently decoded away.
fn response_media_valid(headers: &HeaderMap, expected: &str) -> bool {
    let mut content_types = headers.get_all(CONTENT_TYPE).iter();
    content_types.next().and_then(|value| value.to_str().ok()) == Some(expected)
        && content_types.next().is_none()
        && !headers.contains_key(CONTENT_ENCODING)
}

fn response_no_store(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(reqwest::header::CACHE_CONTROL).iter();
    values.next().and_then(|value| value.to_str().ok()) == Some("private, no-store")
        && values.next().is_none()
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

fn launch_idempotency_key(domain: &[u8], handoff_id: &str, request_digest: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(handoff_id.as_bytes());
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

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_digest(bytes))
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

fn valid_release_manifest_coordinate(value: &str) -> bool {
    let Some((kind, coordinate)) = value.split_once(':') else {
        return false;
    };
    valid_symbol(kind)
        && (1..=190).contains(&coordinate.len())
        && coordinate.as_bytes()[0].is_ascii_alphanumeric()
        && coordinate.bytes().all(|byte| {
            byte.is_ascii_alphanumeric()
                || matches!(byte, b'.' | b'_' | b'/' | b'@' | b':' | b'+' | b'-')
        })
}

fn operation_identity(
    intent: &DeliveryIntent,
    paimos_origin: &Url,
    pull: &PullResponse,
) -> Result<String, AdapterError> {
    #[derive(Serialize)]
    struct OperationIdentity<'a> {
        domain: &'static str,
        paimos_origin: &'a str,
        handoff_id: &'a str,
        host: &'a str,
        workflow: &'static str,
        environment: &'a str,
        artifact: &'a ArtifactEvidence,
        plan_digest: &'a str,
        predecessor_digest: &'a str,
        authority_epoch: i64,
        execution_number: i64,
        context_digest: &'a str,
    }

    let bytes = serde_json::to_vec(&OperationIdentity {
        domain: OPERATION_BINDING_DOMAIN,
        paimos_origin: paimos_origin.as_str(),
        handoff_id: &intent.handoff_id,
        host: &intent.host,
        workflow: intent.workflow.key(),
        environment: &intent.environment,
        artifact: &intent.artifact,
        plan_digest: &pull.plan_digest,
        predecessor_digest: &pull.predecessor_digest,
        authority_epoch: pull.authority_epoch,
        execution_number: pull.execution_number,
        context_digest: &pull.context_digest,
    })
    .map_err(|_| AdapterError::Contract)?;
    Ok(hex_digest(&bytes))
}

fn reviewed_plan_digest(job: &HostActionJob) -> Result<String, AdapterError> {
    #[derive(Serialize)]
    struct ReviewedPlanBinding<'a> {
        job_id: &'a str,
        host: &'a str,
        update_intent: &'static str,
        plan: &'a HostActionPlan,
    }

    let plan = job.plan.as_ref().ok_or(AdapterError::LocalBinding)?;
    if job.kind != crate::host_actions::HostActionKind::UpdateRestart || !plan.ready() {
        return Err(AdapterError::LocalBinding);
    }
    let canonical = serde_json::to_vec(&ReviewedPlanBinding {
        job_id: &job.id,
        host: &job.host,
        update_intent: job.update_restart_intent().key(),
        plan,
    })
    .map_err(|_| AdapterError::Contract)?;
    let mut bytes = Vec::with_capacity(REVIEWED_PLAN_DOMAIN.len() + canonical.len());
    bytes.extend_from_slice(REVIEWED_PLAN_DOMAIN);
    bytes.extend_from_slice(&canonical);
    Ok(sha256_digest(&bytes))
}

fn launch_candidate(
    intent: &DeliveryIntent,
    selection: &DelegatedLaunchSelection,
    pull: &PullResponse,
    reviewed_plan_digest: &str,
    observed_at: i64,
) -> Result<LaunchCandidate, AdapterError> {
    #[derive(Serialize)]
    struct LaunchOperationBinding<'a> {
        handoff_id: &'a str,
        credential_epoch: i64,
        target_ref: &'a str,
        workflow: &'static str,
        environment: &'a str,
        artifact: &'a ArtifactEvidence,
        stage: &'static str,
        execution: i64,
        authority: i64,
        plan_digest: &'a str,
        predecessor_digest: &'a str,
        context_digest: &'a str,
        reviewed_plan_digest: &'a str,
    }

    if !selection.valid()
        || intent.stage != IntentStage::Deployment
        || intent.workflow != GuardedWorkflow::DeployProduction
        || !valid_sha256_digest(reviewed_plan_digest)
    {
        return Err(AdapterError::LocalBinding);
    }
    let canonical = serde_json::to_vec(&LaunchOperationBinding {
        handoff_id: &intent.handoff_id,
        credential_epoch: pull.credential_epoch,
        target_ref: &selection.target_ref,
        workflow: LAUNCH_WORKFLOW,
        environment: &intent.environment,
        artifact: &intent.artifact,
        stage: LAUNCH_STAGE,
        execution: pull.execution_number,
        authority: pull.authority_epoch,
        plan_digest: &pull.plan_digest,
        predecessor_digest: &pull.predecessor_digest,
        context_digest: &pull.context_digest,
        reviewed_plan_digest,
    })
    .map_err(|_| AdapterError::Contract)?;
    let mut binding = Vec::with_capacity(LAUNCH_OPERATION_DOMAIN.len() + canonical.len());
    binding.extend_from_slice(LAUNCH_OPERATION_DOMAIN);
    binding.extend_from_slice(&canonical);
    let candidate = LaunchCandidate {
        schema: LAUNCH_SCHEMA.to_string(),
        version: LAUNCH_VERSION,
        target_ref: selection.target_ref.clone(),
        workflow: LAUNCH_WORKFLOW.to_string(),
        environment: intent.environment.clone(),
        artifact: intent.artifact.clone(),
        reviewed_plan_digest: reviewed_plan_digest.to_string(),
        operation_binding_digest: sha256_digest(&binding),
        observed_at: format_timestamp(observed_at)?,
    };
    if !candidate.valid() {
        return Err(AdapterError::Contract);
    }
    Ok(candidate)
}

fn map_host_action_error(error: HostActionStoreError) -> AdapterError {
    match error {
        HostActionStoreError::Persistence | HostActionStoreError::PersistenceCommitted => {
            AdapterError::Journal
        }
        _ => AdapterError::LocalBinding,
    }
}

fn deterministic_job_id(host: &str, operation_id: &str) -> String {
    format!("action-update-restart-{host}-{}", &operation_id[..16])
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

    use async_compression::tokio::write::{
        BrotliEncoder, DeflateEncoder, GzipEncoder, ZstdEncoder,
    };
    use axum::body::{to_bytes, Body};
    use axum::extract::State;
    use axum::http::{Request, Response};
    use axum::Router;
    use pharos_core::{
        evidence_from_running_container, parse_approved_release_envelope,
        parse_running_container_format, ArtifactDigestClass, ArtifactVersionScheme,
        DeployedArtifactEvidence, HostReport, NixDeploymentEvidence, NixFreshness,
        APPROVED_RELEASE_ENVELOPE_SCHEMA, APPROVED_RELEASE_ENVELOPE_VERSION,
        DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA, DEPLOYED_ARTIFACT_EVIDENCE_VERSION, HOST_REPORT_SCHEMA,
        HOST_REPORT_VERSION, NIX_DEPLOYMENT_EVIDENCE_SCHEMA, NIX_DEPLOYMENT_EVIDENCE_VERSION,
    };
    use serde_json::{json, Value};
    use tokio::io::AsyncWriteExt;

    use crate::host_actions::{
        AgentActionOutcome, AgentActionPhase, AgentActionResultRequest, HostActionEventKind,
        HostActionEventSource, HostActionKind, HostActionPlan, HostActionResult, HostActionState,
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
            version_scheme: ArtifactVersionScheme::Legacy,
            version: "1.2.3".to_string(),
            release_channel: "stable".to_string(),
            release_sequence: 123,
            digest: format!("sha256:{}", "1".repeat(64)),
            commit_digest: "a".repeat(40),
            release_manifest_coordinate: "ghcr:inspr-at/pharos/releases/1.2.3".to_string(),
            release_manifest_digest: format!("sha256:{}", "9".repeat(64)),
        }
    }

    fn calendar_artifact() -> ArtifactEvidence {
        ArtifactEvidence {
            version_scheme: ArtifactVersionScheme::InsprCalendarV1,
            version: "26.09.05.09.00.00".to_string(),
            release_channel: "stable".to_string(),
            release_sequence: 260_905_090_000,
            digest: format!("sha256:{}", "3".repeat(64)),
            commit_digest: "b".repeat(40),
            release_manifest_coordinate: "ghcr:inspr-at/pharos/releases/26.09.05.09.00.00"
                .to_string(),
            release_manifest_digest: format!("sha256:{}", "4".repeat(64)),
        }
    }

    fn measured_from(artifact: &ArtifactEvidence, observed_at: i64) -> DeployedArtifactEvidence {
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

    fn manifest_class_evidence(
        artifact: &ArtifactEvidence,
        observed_at: i64,
    ) -> DeployedArtifactEvidence {
        DeployedArtifactEvidence {
            schema: DEPLOYED_ARTIFACT_EVIDENCE_SCHEMA.to_string(),
            version: DEPLOYED_ARTIFACT_EVIDENCE_VERSION,
            environment: "production-eu1".to_string(),
            version_scheme: artifact.version_scheme,
            artifact_version: artifact.version.clone(),
            release_channel: artifact.release_channel.clone(),
            release_sequence: artifact.release_sequence,
            digest: artifact.digest.clone(),
            digest_class: ArtifactDigestClass::OciManifest,
            commit_digest: artifact.commit_digest.clone(),
            release_manifest_coordinate: artifact.release_manifest_coordinate.clone(),
            release_manifest_digest: artifact.release_manifest_digest.clone(),
            oci_index_digest: Some(format!("sha256:{}", "5".repeat(64))),
            oci_manifest_digest: Some(artifact.digest.clone()),
            oci_config_digest: Some(format!("sha256:{}", "6".repeat(64))),
            observed_at,
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
            update_restart_job_id: None,
            deployment_handoff_id: (stage == IntentStage::Verification)
                .then(|| DEPLOYMENT_HANDOFF.to_string()),
            delegated_launch: None,
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

    fn operator_confirm_existing_update(store: &HostActionStore, job_id: &str, now: i64) {
        review_existing_update(store, job_id, now);
        store
            .confirm_update(job_id, "hsb8", "operator", now + 2)
            .expect("operator confirm");
    }

    fn review_existing_update(store: &HostActionStore, job_id: &str, now: i64) {
        let review = store
            .claim("hsb8", now)
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
                now + 1,
            )
            .expect("record review");
    }

    fn record_nix_only_beacon(store: &Store, observed_at: i64, artifact: &ArtifactEvidence) {
        record_beacon_with(store, observed_at, artifact, false);
    }

    fn record_beacon(store: &Store, observed_at: i64, artifact: &ArtifactEvidence) {
        record_beacon_with(store, observed_at, artifact, true);
    }

    fn record_beacon_with(
        store: &Store,
        observed_at: i64,
        artifact: &ArtifactEvidence,
        include_measured: bool,
    ) {
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
                    deployed_artifact: include_measured
                        .then(|| measured_from(artifact, observed_at)),
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
        launch_issued_at: String,
        launch_expires_at: String,
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
                launch_issued_at: format_timestamp(now + 10).unwrap(),
                launch_expires_at: format_timestamp(now + 610).unwrap(),
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
            let (plan_digest, predecessor_digest) = if handoff_id == VERIFICATION_HANDOFF {
                (
                    format!("sha256:{}", "7".repeat(64)),
                    format!("sha256:{}", "2".repeat(64)),
                )
            } else {
                (
                    format!("sha256:{}", "2".repeat(64)),
                    format!("sha256:{}", "3".repeat(64)),
                )
            };
            return fake_json_response(
                StatusCode::OK,
                json!({
                    "handoff_id": handoff_id,
                    "contract_major": 2,
                    "fixture_digest": PAIMOS_FIXTURE_DIGEST,
                    "credential_epoch": 9,
                    "expires_at": "2030-01-01T00:00:00Z",
                    "state": state,
                    "reporter_class": "pharos",
                    "reporter_role": "owner",
                    "evidence_ceiling": ["deployment", "verification"],
                    "stage_key": stage,
                    "execution_number": 1,
                    "plan_digest": plan_digest,
                    "predecessor_digest": predecessor_digest,
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
        if path.ends_with("/launch-candidates") {
            let candidate: LaunchCandidate =
                decode_strict(&body).expect("strict launch candidate request");
            return fake_launch_json_response(
                StatusCode::OK,
                json!({
                    "schema": LAUNCH_SCHEMA,
                    "version": LAUNCH_VERSION,
                    "grant_id": "20600000-0000-4000-8000-000000000001",
                    "grant_revision": 1,
                    "grant_digest": format!("sha256:{}", "7".repeat(64)),
                    "admission_id": "20600000-0000-4000-8000-000000000002",
                    "admission_digest": format!("sha256:{}", "8".repeat(64)),
                    "handoff_id": handoff_id,
                    "credential_epoch": 9,
                    "target_ref": candidate.target_ref,
                    "workflow": candidate.workflow,
                    "environment": candidate.environment,
                    "artifact": candidate.artifact,
                    "stage": LAUNCH_STAGE,
                    "attempt": 1,
                    "plan": 1,
                    "execution": 1,
                    "authority": 4,
                    "plan_digest": format!("sha256:{}", "2".repeat(64)),
                    "predecessor_digest": format!("sha256:{}", "3".repeat(64)),
                    "context_digest": format!("sha256:{}", "4".repeat(64)),
                    "reviewed_plan_digest": candidate.reviewed_plan_digest,
                    "operation_binding_digest": candidate.operation_binding_digest,
                    "max_launches": 1,
                    "used_launches": 0,
                    "issued_at": fake.launch_issued_at,
                    "expires_at": fake.launch_expires_at,
                    "state": "issued"
                }),
            );
        }
        if path.ends_with("/consume") {
            let request: LaunchConsumeRequest =
                decode_strict(&body).expect("strict launch consume request");
            let admission_id = path
                .split('/')
                .nth(6)
                .expect("admission ID in fixed consume route");
            return fake_launch_json_response(
                StatusCode::OK,
                json!({
                    "schema": LAUNCH_SCHEMA,
                    "version": LAUNCH_VERSION,
                    "admission_id": admission_id,
                    "admission_digest": request.admission_digest,
                    "handoff_id": handoff_id,
                    "credential_epoch": 9,
                    "launch_number": 1,
                    "state": "consumed",
                    "consumed_at": fake.launch_issued_at
                }),
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

    fn fake_launch_json_response(status: StatusCode, value: Value) -> Response<Body> {
        Response::builder()
            .status(status)
            .header(CONTENT_TYPE, LAUNCH_MEDIA_TYPE)
            .header(reqwest::header::CACHE_CONTROL, "private, no-store")
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
            include_bytes!("../../../contracts/paimos-external-stage-v2/owner-pharos-v2.json");
        let manifest =
            include_bytes!("../../../contracts/paimos-external-stage-v2/manifest-v2.json");
        let schema = include_bytes!(
            "../../../contracts/paimos-external-stage-v2/external-stage-v2.schema.json"
        );
        let launch_schema = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/external-stage-launch-admission-v1.schema.json"
        );
        let launch_candidate = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/candidate.json"
        );
        let launch_admission = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/admission.json"
        );
        let launch_consume = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/consume.json"
        );
        let launch_receipt = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/receipt.json"
        );
        let launch_manifest = include_bytes!(
            "../../../contracts/paimos-external-stage-launch-admission-v1/manifest-v1.json"
        );
        assert_eq!(dependency.len(), 1115);
        assert_eq!(owner.len(), 3868);
        assert_eq!(schema.len(), 10292);
        assert_eq!(launch_schema.len(), 6738);
        assert_eq!(launch_candidate.len(), 909);
        assert_eq!(launch_admission.len(), 1707);
        assert_eq!(launch_consume.len(), 157);
        assert_eq!(launch_receipt.len(), 348);
        assert_eq!(hex_digest(dependency), PAIMOS_JANUS_DEPENDENCY_SHA256);
        assert_eq!(
            hex_digest(owner),
            "99abbf90592ff319b4e00319bc8bb5141572e6dc66cfcf074d781358c36954a9"
        );
        assert_eq!(
            hex_digest(schema),
            "57b2ceaebc2991f89b9adb4de713c2c760c40f521ee8bde8cd67dfb5559ae33a"
        );
        for (bytes, expected) in [
            (
                launch_schema.as_slice(),
                "6c7ac4984affdd0ead93091cf02b9c522b83ca5fdc56ab81c80507e547f7a066",
            ),
            (
                launch_candidate.as_slice(),
                "4eed040a5bef85899994c30751bb37ec135f81d42e5ff58a764cf51a87f0775b",
            ),
            (
                launch_admission.as_slice(),
                "00a564686330328c119f645f5ea9e16e1fab1569b76092b0822b773c8e84b248",
            ),
            (
                launch_consume.as_slice(),
                "014ced0d247386e30267b0c129c4c7d8abcc3e3987841c966a05ed0cc336159c",
            ),
            (
                launch_receipt.as_slice(),
                "bd57a2ae684af37a6d43f1888a402189aa48089f733ffb7ef73b40c2a9f3da01",
            ),
        ] {
            assert_eq!(hex_digest(bytes), expected);
        }
        let mut set = Sha256::new();
        set.update(b"paimos.external-stage.fixtures.v2\0");
        set.update(b"owner-pharos-v2.json");
        set.update([0]);
        set.update(owner);
        set.update([0]);
        assert_eq!(
            format!("sha256:{}", hex_bytes(&set.finalize())),
            PAIMOS_FIXTURE_DIGEST
        );
        assert_ne!(hex_digest(dependency), &PAIMOS_FIXTURE_DIGEST[7..]);
        let manifest: Value = decode_strict(manifest).unwrap();
        assert_eq!(manifest["schema_major"], PAIMOS_SCHEMA_MAJOR);
        assert_eq!(manifest["paimos_release"], PAIMOS_RELEASE);
        assert_eq!(manifest["paimos_commit"], PAIMOS_CERTIFIED_COMMIT);
        assert_eq!(manifest["fixture_digest"], PAIMOS_FIXTURE_DIGEST);
        assert_eq!(
            manifest["media_type"],
            "application/vnd.paimos.external-stage.v2+json"
        );
        assert!(owner
            .windows(b"janus_evidence".len())
            .all(|window| window != b"janus_evidence"));
        let launch_manifest: Value = decode_strict(launch_manifest).unwrap();
        assert_eq!(launch_manifest["source_status"], "source-candidate");
        assert_eq!(launch_manifest["paimos_release"], Value::Null);
        assert_eq!(
            launch_manifest["paimos_source_commit"],
            "90e34fa0d5dc9b6e59b62a9021138706cd73af84"
        );
        let fixture_candidate: LaunchCandidate = decode_strict(launch_candidate).unwrap();
        let fixture_admission: LaunchAdmission = decode_strict(launch_admission).unwrap();
        let fixture_consume: LaunchConsumeRequest = decode_strict(launch_consume).unwrap();
        let fixture_receipt: LaunchReceipt = decode_strict(launch_receipt).unwrap();
        assert!(fixture_candidate.valid());
        assert!(fixture_admission.valid_journaled("01K35P6YRG00000000000000AB", &fixture_candidate));
        assert_eq!(
            fixture_consume.admission_digest,
            fixture_admission.admission_digest
        );
        fixture_receipt.validate(&fixture_admission).unwrap();
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
        assert!(response_media_valid(&headers, CONTRACT_MEDIA_TYPE));

        headers.append(CONTENT_TYPE, HeaderValue::from_static(CONTRACT_MEDIA_TYPE));
        assert!(!response_media_valid(&headers, CONTRACT_MEDIA_TYPE));
        headers.remove(CONTENT_TYPE);
        headers.insert(CONTENT_TYPE, HeaderValue::from_static(CONTRACT_MEDIA_TYPE));
        headers.insert(CONTENT_ENCODING, HeaderValue::from_static("gzip"));
        assert!(!response_media_valid(&headers, CONTRACT_MEDIA_TYPE));

        let mut launch_headers = HeaderMap::new();
        launch_headers.insert(CONTENT_TYPE, HeaderValue::from_static(LAUNCH_MEDIA_TYPE));
        launch_headers.insert(
            reqwest::header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
        assert!(response_media_valid(&launch_headers, LAUNCH_MEDIA_TYPE));
        assert!(response_no_store(&launch_headers));
        assert!(!response_media_valid(&launch_headers, CONTRACT_MEDIA_TYPE));
        launch_headers.insert(
            reqwest::header::CACHE_CONTROL,
            HeaderValue::from_static("no-cache"),
        );
        assert!(!response_no_store(&launch_headers));

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
        changed.artifact.release_channel = "rollback".to_string();
        variants.push(changed);
        let mut changed = base.clone();
        changed.artifact.release_sequence = 124;
        variants.push(changed);
        let mut changed = base.clone();
        changed.artifact.version_scheme = ArtifactVersionScheme::InsprCalendarV1;
        changed.artifact.version = "26.09.05.09.00.00".to_string();
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

        let mut delegated = base.clone();
        delegated.delegated_launch = Some(DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "a".repeat(64)),
        });
        let delegated_digest = delegated.binding_digest(&origin).unwrap();
        assert_ne!(delegated_digest, base_digest);
        delegated
            .delegated_launch
            .as_mut()
            .expect("delegated selection")
            .target_ref = format!("sha256:{}", "b".repeat(64));
        assert_ne!(delegated.binding_digest(&origin).unwrap(), delegated_digest);
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
                "schema": CONFIG_SCHEMA_V2,
                "schema_version": CONFIG_SCHEMA_VERSION_V2,
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
    fn config_v2_stays_closed_and_v3_delegated_launch_is_presence_only() {
        let directory = temporary_directory("delegated-config");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        let config_path = directory.join("adapter.json");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let mut document = json!({
            "schema": CONFIG_SCHEMA_V2,
            "schema_version": CONFIG_SCHEMA_VERSION_V2,
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
        });
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        let v2 = AdapterConfig::load(&config_path).expect("unchanged v2 loads");
        assert!(v2.intents[0].delegated_launch.is_none());

        document["intents"][0]["delegated_launch"] = json!({
            "target_ref": format!("sha256:{}", "a".repeat(64))
        });
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));

        document["schema"] = json!(CONFIG_SCHEMA_V3);
        document["schema_version"] = json!(CONFIG_SCHEMA_VERSION_V3);
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        let v3 = AdapterConfig::load(&config_path).expect("closed v3 opt-in loads");
        assert_eq!(
            v3.intents[0]
                .delegated_launch
                .as_ref()
                .expect("delegated launch selection")
                .target_ref,
            format!("sha256:{}", "a".repeat(64))
        );

        document["intents"][0]["delegated_launch"]["workflow"] = json!("attacker-controlled");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));
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
        for body in [&bodies[1], &bodies[3]] {
            let artifact = body["pharos_evidence"]["artifact"]
                .as_object()
                .expect("v2 artifact object");
            assert_eq!(artifact.len(), 8);
            assert_eq!(artifact["version_scheme"], "legacy");
            assert!(artifact.contains_key("release_channel"));
            assert!(artifact.contains_key("release_sequence"));
            assert!(artifact.contains_key("release_manifest_coordinate"));
            assert!(artifact.contains_key("release_manifest_digest"));
            assert!(body
                .get("janus_evidence")
                .is_none_or(|value| value.is_null()));
        }
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

    #[derive(Clone, Copy)]
    enum WireEncoding {
        Brotli,
        Deflate,
        Gzip,
        Identity,
        Zstd,
    }

    impl WireEncoding {
        fn header(self) -> &'static str {
            match self {
                Self::Brotli => "br",
                Self::Deflate => "deflate",
                Self::Gzip => "gzip",
                Self::Identity => IDENTITY_ENCODING,
                Self::Zstd => "zstd",
            }
        }

        async fn encode(self, body: &[u8]) -> Vec<u8> {
            macro_rules! encode {
                ($encoder:ty) => {{
                    let mut encoder = <$encoder>::new(Vec::new());
                    encoder.write_all(body).await.expect("encode abusive body");
                    encoder.shutdown().await.expect("finish abusive body");
                    encoder.into_inner()
                }};
            }

            match self {
                Self::Brotli => encode!(BrotliEncoder<Vec<u8>>),
                Self::Deflate => encode!(DeflateEncoder<Vec<u8>>),
                Self::Gzip => encode!(GzipEncoder<Vec<u8>>),
                Self::Identity => body.to_vec(),
                Self::Zstd => encode!(ZstdEncoder<Vec<u8>>),
            }
        }
    }

    /// A Paimos impersonator that answers the accept mutation with a response
    /// shape the contract forbids. Every field here is something a compromised
    /// or buggy peer controls.
    #[derive(Clone)]
    struct WireAbuse {
        status: StatusCode,
        content_types: Vec<String>,
        content_encoding: Option<WireEncoding>,
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

        fn encoding(value: WireEncoding) -> Self {
            Self {
                content_encoding: Some(value),
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
        let mut accept_encodings = request.headers().get_all(ACCEPT_ENCODING).iter();
        assert_eq!(
            accept_encodings
                .next()
                .and_then(|value| value.to_str().ok()),
            Some(IDENTITY_ENCODING),
            "reporter must request only identity encoding"
        );
        assert!(
            accept_encodings.next().is_none(),
            "reporter must send exactly one Accept-Encoding header"
        );
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
                    "contract_major": 2,
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
        let mut body = serde_json::to_vec(&json!({
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
        if let Some(encoding) = abuse.content_encoding {
            body = encoding.encode(&body).await;
            builder = builder.header(CONTENT_ENCODING, encoding.header());
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

    /// Exercises the real reqwest/hyper path. The CI feature gate compiles in
    /// every transparent decoder, so removing decoder shutdown or relaxing the
    /// media check fails here instead of shipping.
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
            ("gzip-encoded body", WireAbuse::encoding(WireEncoding::Gzip)),
            (
                "Brotli-encoded body",
                WireAbuse::encoding(WireEncoding::Brotli),
            ),
            ("zstd-encoded body", WireAbuse::encoding(WireEncoding::Zstd)),
            (
                "deflate-encoded body",
                WireAbuse::encoding(WireEncoding::Deflate),
            ),
            (
                "identity content-encoding",
                WireAbuse::encoding(WireEncoding::Identity),
            ),
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
            .verification_report(
                &verification,
                &PullResponse {
                    handoff_id: VERIFICATION_HANDOFF.to_string(),
                    contract_major: PAIMOS_SCHEMA_MAJOR,
                    fixture_digest: PAIMOS_FIXTURE_DIGEST.to_string(),
                    credential_epoch: 9,
                    expires_at: "2030-01-01T00:00:00Z".to_string(),
                    state: HandoffState::Accepted,
                    reporter_class: "pharos".to_string(),
                    reporter_role: "owner".to_string(),
                    dependency_key: None,
                    evidence_ceiling: vec![EvidenceKind::Deployment, EvidenceKind::Verification],
                    stage_key: "verification".to_string(),
                    execution_number: 1,
                    plan_digest: format!("sha256:{}", "7".repeat(64)),
                    predecessor_digest: format!("sha256:{}", "2".repeat(64)),
                    authority_epoch: 4,
                    context_digest: format!("sha256:{}", "4".repeat(64)),
                },
                now
            )
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
            "schema": CONFIG_SCHEMA_V2,
            "schema_version": CONFIG_SCHEMA_VERSION_V2,
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

        document["intents"][0]["artifact"]["version_scheme"] = json!("inspr-calendar-v1");
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        assert!(matches!(
            AdapterConfig::load(&config_path),
            Err(AdapterError::Configuration)
        ));
        document["intents"][0]["artifact"]["version_scheme"] = json!("legacy");

        document["intents"][0]["artifact"] = serde_json::to_value(calendar_artifact()).unwrap();
        document["intents"][1]["artifact"] = serde_json::to_value(calendar_artifact()).unwrap();
        write_private(&config_path, &serde_json::to_vec(&document).unwrap());
        AdapterConfig::load(&config_path).expect("calendar v2 artifact loads");

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

    fn test_pull(handoff_id: &str, stage: &str, predecessor: &str) -> PullResponse {
        PullResponse {
            handoff_id: handoff_id.to_string(),
            contract_major: PAIMOS_SCHEMA_MAJOR,
            fixture_digest: PAIMOS_FIXTURE_DIGEST.to_string(),
            credential_epoch: 9,
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            state: HandoffState::Accepted,
            reporter_class: "pharos".to_string(),
            reporter_role: "owner".to_string(),
            dependency_key: None,
            evidence_ceiling: vec![EvidenceKind::Deployment, EvidenceKind::Verification],
            stage_key: stage.to_string(),
            execution_number: 1,
            plan_digest: format!("sha256:{}", "2".repeat(64)),
            predecessor_digest: predecessor.to_string(),
            authority_epoch: 4,
            context_digest: format!("sha256:{}", "4".repeat(64)),
        }
    }

    fn ready_update_with_id(store: &HostActionStore, job_id: &str, now: i64) -> HostActionJob {
        store
            .ensure_update_review_with_id(
                job_id,
                "hsb8",
                GUARDED_ACTOR,
                UpdateRestartIntent::Update,
                now,
            )
            .expect("create exact guarded update");
        review_existing_update(store, job_id, now + 1);
        store.get(job_id).expect("reviewed update")
    }

    fn test_launch_admission(
        candidate: &LaunchCandidate,
        pull: &PullResponse,
        now: i64,
    ) -> LaunchAdmission {
        LaunchAdmission {
            schema: LAUNCH_SCHEMA.to_string(),
            version: LAUNCH_VERSION,
            grant_id: "20600000-0000-4000-8000-000000000001".to_string(),
            grant_revision: 1,
            grant_digest: format!("sha256:{}", "7".repeat(64)),
            admission_id: "20600000-0000-4000-8000-000000000002".to_string(),
            admission_digest: format!("sha256:{}", "8".repeat(64)),
            handoff_id: pull.handoff_id.clone(),
            credential_epoch: pull.credential_epoch,
            target_ref: candidate.target_ref.clone(),
            workflow: candidate.workflow.clone(),
            environment: candidate.environment.clone(),
            artifact: candidate.artifact.clone(),
            stage: LAUNCH_STAGE.to_string(),
            attempt: 1,
            plan: 1,
            execution: pull.execution_number,
            authority: pull.authority_epoch,
            plan_digest: pull.plan_digest.clone(),
            predecessor_digest: pull.predecessor_digest.clone(),
            context_digest: pull.context_digest.clone(),
            reviewed_plan_digest: candidate.reviewed_plan_digest.clone(),
            operation_binding_digest: candidate.operation_binding_digest.clone(),
            max_launches: 1,
            used_launches: 0,
            issued_at: format_timestamp(now).unwrap(),
            expires_at: format_timestamp(now + 600).unwrap(),
            state: "issued".to_string(),
        }
    }

    #[test]
    fn launch_digests_bind_complete_review_and_every_public_pull_commitment() {
        let now = now_unix();
        let actions = HostActionStore::new(None);
        let job = ready_update_with_id(&actions, "action-update-restart-hsb8-launch-digest", now);
        let reviewed = reviewed_plan_digest(&job).unwrap();
        let expected_plan = format!(
            "{{\"job_id\":\"{}\",\"host\":\"hsb8\",\"update_intent\":\"update\",\"plan\":{{\"changed_file_count\":2,\"changed_areas\":[\"flake.lock\"],\"all_host_eval_passed\":true,\"target_build_passed\":true,\"backup_ready\":true,\"running_kernel\":\"6.18.1\",\"expected_kernel\":\"6.18.2\",\"restart_required\":true}}}}",
            job.id
        );
        let mut reviewed_bytes = REVIEWED_PLAN_DOMAIN.to_vec();
        reviewed_bytes.extend_from_slice(expected_plan.as_bytes());
        assert_eq!(reviewed, sha256_digest(&reviewed_bytes));

        let mut changed_job = job.clone();
        changed_job
            .plan
            .as_mut()
            .expect("reviewed plan")
            .changed_file_count += 1;
        assert_ne!(reviewed_plan_digest(&changed_job).unwrap(), reviewed);

        let mut deployment = intent(
            DEPLOYMENT_HANDOFF,
            PathBuf::from("/private/delegated-secret"),
            IntentStage::Deployment,
        );
        let selection = DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "a".repeat(64)),
        };
        deployment.delegated_launch = Some(selection.clone());
        let pull = test_pull(
            DEPLOYMENT_HANDOFF,
            "deployment",
            &format!("sha256:{}", "3".repeat(64)),
        );
        let baseline = launch_candidate(&deployment, &selection, &pull, &reviewed, now).unwrap();
        assert_ne!(
            baseline.reviewed_plan_digest,
            baseline.operation_binding_digest
        );

        let mut digests = BTreeSet::new();
        digests.insert(baseline.operation_binding_digest.clone());
        for changed_pull in [
            {
                let mut value = pull.clone();
                value.credential_epoch += 1;
                value
            },
            {
                let mut value = pull.clone();
                value.execution_number += 1;
                value
            },
            {
                let mut value = pull.clone();
                value.authority_epoch += 1;
                value
            },
            {
                let mut value = pull.clone();
                value.plan_digest = format!("sha256:{}", "5".repeat(64));
                value
            },
            {
                let mut value = pull.clone();
                value.predecessor_digest = format!("sha256:{}", "6".repeat(64));
                value
            },
            {
                let mut value = pull.clone();
                value.context_digest = format!("sha256:{}", "7".repeat(64));
                value
            },
        ] {
            digests.insert(
                launch_candidate(&deployment, &selection, &changed_pull, &reviewed, now)
                    .unwrap()
                    .operation_binding_digest,
            );
        }
        let mut changed_intent = deployment.clone();
        changed_intent.environment = "production-eu2".to_string();
        digests.insert(
            launch_candidate(&changed_intent, &selection, &pull, &reviewed, now)
                .unwrap()
                .operation_binding_digest,
        );
        changed_intent = deployment.clone();
        changed_intent.artifact.release_sequence += 1;
        digests.insert(
            launch_candidate(&changed_intent, &selection, &pull, &reviewed, now)
                .unwrap()
                .operation_binding_digest,
        );
        let changed_selection = DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "b".repeat(64)),
        };
        digests.insert(
            launch_candidate(&deployment, &changed_selection, &pull, &reviewed, now)
                .unwrap()
                .operation_binding_digest,
        );
        digests.insert(
            launch_candidate(
                &deployment,
                &selection,
                &pull,
                &format!("sha256:{}", "c".repeat(64)),
                now,
            )
            .unwrap()
            .operation_binding_digest,
        );
        assert_eq!(digests.len(), 11);
    }

    #[test]
    fn admission_validation_rejects_echo_pull_and_expiry_drift() {
        let now = now_unix();
        let actions = HostActionStore::new(None);
        let job = ready_update_with_id(&actions, "action-update-restart-hsb8-admission", now - 10);
        let mut deployment = intent(
            DEPLOYMENT_HANDOFF,
            PathBuf::from("/private/delegated-secret"),
            IntentStage::Deployment,
        );
        let selection = DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "a".repeat(64)),
        };
        deployment.delegated_launch = Some(selection.clone());
        let mut pull = test_pull(
            DEPLOYMENT_HANDOFF,
            "deployment",
            &format!("sha256:{}", "3".repeat(64)),
        );
        pull.expires_at = format_timestamp(now + 1_000).unwrap();
        let candidate = launch_candidate(
            &deployment,
            &selection,
            &pull,
            &reviewed_plan_digest(&job).unwrap(),
            now,
        )
        .unwrap();
        let admission = test_launch_admission(&candidate, &pull, now);
        admission
            .validate(DEPLOYMENT_HANDOFF, &candidate, &pull, now)
            .unwrap();

        let mut variants = Vec::new();
        let mut changed = admission.clone();
        changed.target_ref = format!("sha256:{}", "b".repeat(64));
        variants.push(changed);
        let mut changed = admission.clone();
        changed.environment = "production-eu2".to_string();
        variants.push(changed);
        let mut changed = admission.clone();
        changed.artifact.release_sequence += 1;
        variants.push(changed);
        let mut changed = admission.clone();
        changed.credential_epoch += 1;
        variants.push(changed);
        let mut changed = admission.clone();
        changed.execution += 1;
        variants.push(changed);
        let mut changed = admission.clone();
        changed.authority += 1;
        variants.push(changed);
        let mut changed = admission.clone();
        changed.plan_digest = format!("sha256:{}", "5".repeat(64));
        variants.push(changed);
        let mut changed = admission.clone();
        changed.reviewed_plan_digest = format!("sha256:{}", "6".repeat(64));
        variants.push(changed);
        let mut changed = admission.clone();
        changed.expires_at = format_timestamp(now).unwrap();
        variants.push(changed);
        let mut changed = admission.clone();
        changed.max_launches = 2;
        variants.push(changed);
        let mut changed = admission.clone();
        changed.state = "consumed".to_string();
        variants.push(changed);
        assert!(variants.iter().all(|changed| changed
            .validate(DEPLOYMENT_HANDOFF, &candidate, &pull, now)
            .is_err()));

        let bytes = serde_json::to_vec(&admission).unwrap();
        let mut unknown = bytes[..bytes.len() - 1].to_vec();
        unknown.extend_from_slice(b",\"callback\":\"https://invalid.example\"}");
        assert!(decode_strict::<LaunchAdmission>(&unknown).is_err());
        let mut trailing = bytes.clone();
        trailing.extend_from_slice(b" {}");
        assert!(decode_strict::<LaunchAdmission>(&trailing).is_err());
        let mut duplicate = br#"{"schema":"paimos.external-stage-launch-admission","#.to_vec();
        duplicate.extend_from_slice(&bytes[1..]);
        assert!(decode_strict::<LaunchAdmission>(&duplicate).is_err());
        let receipt_bytes = serde_json::to_vec(&LaunchReceipt {
            schema: LAUNCH_SCHEMA.to_string(),
            version: LAUNCH_VERSION,
            admission_id: admission.admission_id.clone(),
            admission_digest: admission.admission_digest.clone(),
            handoff_id: admission.handoff_id.clone(),
            credential_epoch: admission.credential_epoch,
            launch_number: 1,
            state: "consumed".to_string(),
            consumed_at: admission.issued_at.clone(),
        })
        .unwrap();
        assert!(decode_strict::<LaunchAdmission>(&receipt_bytes).is_err());
        assert!(decode_strict::<LaunchReceipt>(&bytes).is_err());

        let credentials = Credentials {
            api_key: API_KEY_SENTINEL.to_vec(),
            handoff_secret: HANDOFF_SENTINEL.to_vec(),
        };
        assert!(reject_reflected_bytes(API_KEY_SENTINEL, &credentials, "").is_err());
        assert!(reject_reflected_bytes(HANDOFF_SENTINEL, &credentials, "").is_err());
        assert!(reject_reflected_bytes(b"candidate-idem", &credentials, "candidate-idem").is_err());
    }

    #[test]
    fn durable_consumed_receipt_finishes_only_the_same_pending_transition_once() {
        let now = now_unix();
        let directory = temporary_directory("launch-receipt-restart");
        let actions_path = directory.join("host-actions.json");
        let journal_path = directory.join("journal.json");
        let api_path = directory.join("api-key");
        write_private(&api_path, API_KEY_SENTINEL);
        let actions = Arc::new(HostActionStore::new(Some(actions_path.clone())));
        let job_id = "action-update-restart-hsb8-receipt";
        let job = ready_update_with_id(&actions, job_id, now);
        let origin = Url::parse("https://paimos.example.test").unwrap();
        let mut deployment = intent(
            DEPLOYMENT_HANDOFF,
            PathBuf::from("/private/delegated-secret"),
            IntentStage::Deployment,
        );
        let selection = DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "a".repeat(64)),
        };
        deployment.delegated_launch = Some(selection.clone());
        let mut pull = test_pull(
            DEPLOYMENT_HANDOFF,
            "deployment",
            &format!("sha256:{}", "3".repeat(64)),
        );
        pull.expires_at = format_timestamp(now + 1_000).unwrap();
        let operation = OperationBinding {
            handoff_id: DEPLOYMENT_HANDOFF.to_string(),
            job_id: job_id.to_string(),
            host: "hsb8".to_string(),
            workflow: LAUNCH_WORKFLOW.to_string(),
            environment: deployment.environment.clone(),
            artifact: deployment.artifact.clone(),
            plan_digest: pull.plan_digest.clone(),
            predecessor_digest: pull.predecessor_digest.clone(),
            authority_epoch: pull.authority_epoch,
            execution_number: pull.execution_number,
            context_digest: pull.context_digest.clone(),
            operation_id: operation_identity(&deployment, &origin, &pull).unwrap(),
        };
        let journal = JournalStore::new(journal_path.clone()).unwrap();
        journal.persist_operation(operation).unwrap();
        let candidate = launch_candidate(
            &deployment,
            &selection,
            &pull,
            &reviewed_plan_digest(&job).unwrap(),
            now + 3,
        )
        .unwrap();
        let record = journal
            .ensure_launch(
                LaunchJournalRecord::new(&deployment, &origin, job_id, &candidate).unwrap(),
            )
            .unwrap();
        let candidate_bytes = record.candidate_body_json.clone();
        let candidate_key = record.candidate_idempotency_key.clone();
        drop(journal);
        let journal = JournalStore::new(journal_path.clone()).unwrap();
        let record = journal.launch(DEPLOYMENT_HANDOFF).unwrap();
        assert_eq!(record.candidate_body_json, candidate_bytes);
        assert_eq!(record.candidate_idempotency_key, candidate_key);
        let mut different_candidate = candidate.clone();
        different_candidate.observed_at = format_timestamp(now + 4).unwrap();
        let different_record =
            LaunchJournalRecord::new(&deployment, &origin, job_id, &different_candidate).unwrap();
        assert!(matches!(
            journal.ensure_launch(different_record),
            Err(AdapterError::LocalBinding)
        ));
        let admission = test_launch_admission(&candidate, &pull, now + 3);
        let record = journal
            .acknowledge_launch_admission(&record, admission.clone())
            .unwrap();
        let consume_bytes = record.consume_body_json.clone().unwrap();
        let consume_key = record.consume_idempotency_key.clone().unwrap();
        drop(journal);
        let journal = JournalStore::new(journal_path.clone()).unwrap();
        let record = journal.launch(DEPLOYMENT_HANDOFF).unwrap();
        assert_eq!(
            record.consume_body_json.as_deref(),
            Some(consume_bytes.as_str())
        );
        assert_eq!(
            record.consume_idempotency_key.as_deref(),
            Some(consume_key.as_str())
        );
        let record = journal.mark_launch_consume_started(&record).unwrap();
        let receipt = LaunchReceipt {
            schema: LAUNCH_SCHEMA.to_string(),
            version: LAUNCH_VERSION,
            admission_id: admission.admission_id.clone(),
            admission_digest: admission.admission_digest.clone(),
            handoff_id: DEPLOYMENT_HANDOFF.to_string(),
            credential_epoch: pull.credential_epoch,
            launch_number: 1,
            state: "consumed".to_string(),
            consumed_at: format_timestamp(now + 4).unwrap(),
        };
        journal
            .acknowledge_launch_receipt(&record, receipt)
            .unwrap();
        drop(journal);
        drop(actions);

        let restarted_actions = Arc::new(HostActionStore::new(Some(actions_path)));
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            journal_path,
            Arc::new(Store::new(None).unwrap()),
            restarted_actions.clone(),
        );
        let durable = adapter.journal.launch(DEPLOYMENT_HANDOFF).unwrap();
        adapter
            .finish_delegated_confirmation(&deployment, &durable)
            .unwrap();
        adapter
            .finish_delegated_confirmation(&deployment, &durable)
            .unwrap();
        let queued = restarted_actions.get(job_id).unwrap();
        assert_eq!(queued.state, HostActionState::QueuedApply);
        assert_eq!(
            queued
                .events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        assert_eq!(
            queued.events.last().unwrap().source,
            HostActionEventSource::Pharos
        );
        assert_eq!(restarted_actions.list().len(), 1);
    }

    #[tokio::test]
    async fn accept_creates_one_guarded_update_and_replays_the_same_job() {
        let now = now_unix();
        let directory = temporary_directory("accept-create");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            directory.join("journal.json"),
            hosts,
            actions.clone(),
        );

        adapter.process_intent(&deployment).await.unwrap();
        adapter.process_intent(&deployment).await.unwrap();
        let jobs: Vec<_> = actions
            .list()
            .into_iter()
            .filter(|job| job.kind == HostActionKind::UpdateRestart)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].host, "hsb8");
        assert_eq!(jobs[0].requested_by, GUARDED_ACTOR);
        assert_eq!(jobs[0].state, HostActionState::QueuedReview);
        assert!(jobs[0].confirmed_at.is_none());
        assert_eq!(jobs[0].events.len(), 1);
        assert_eq!(jobs[0].events[0].kind, HostActionEventKind::Requested);
        assert_eq!(
            adapter
                .journal
                .operation(DEPLOYMENT_HANDOFF)
                .expect("bound job")
                .job_id,
            jobs[0].id
        );
        let posts = fake
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.method == "POST")
            .count();
        assert_eq!(posts, 1);
        server.abort();
    }

    #[tokio::test]
    async fn delegated_launch_is_default_off_then_consumes_once_and_only_queues_existing_job() {
        let now = now_unix();
        let directory = temporary_directory("delegated-launch");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        let journal_path = directory.join("journal.json");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());

        let attended = intent(
            VERIFICATION_HANDOFF,
            directory.join("unused-secret"),
            IntentStage::Verification,
        );
        assert!(attended.delegated_launch.is_none());

        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.delegated_launch = Some(DelegatedLaunchSelection {
            target_ref: format!("sha256:{}", "a".repeat(64)),
        });
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            journal_path.clone(),
            hosts,
            actions.clone(),
        );

        adapter.process_intent(&deployment).await.unwrap();
        let operation = adapter
            .journal
            .operation(DEPLOYMENT_HANDOFF)
            .expect("accepted handoff binds one exact job");
        assert_eq!(actions.list().len(), 1);
        assert_eq!(
            actions.get(&operation.job_id).unwrap().state,
            HostActionState::QueuedReview
        );
        assert!(adapter.journal.launch(DEPLOYMENT_HANDOFF).is_none());

        review_existing_update(&actions, &operation.job_id, now + 1);
        adapter.process_intent(&deployment).await.unwrap();

        let queued = actions.get(&operation.job_id).unwrap();
        assert_eq!(queued.state, HostActionState::QueuedApply);
        assert_eq!(actions.list().len(), 1);
        let confirmation = queued.events.last().expect("delegated confirmation event");
        assert_eq!(confirmation.kind, HostActionEventKind::Confirmed);
        assert_eq!(confirmation.source, HostActionEventSource::Pharos);
        assert_eq!(
            confirmation.actor.as_deref(),
            Some("20600000-0000-4000-8000-000000000002")
        );

        let launch = adapter
            .journal
            .launch(DEPLOYMENT_HANDOFF)
            .expect("durable launch journal");
        assert!(launch.valid());
        assert!(launch.consume_started);
        assert!(launch.receipt.is_some());
        let durable = std::fs::read(&journal_path).unwrap();
        assert!(!contains_slice(&durable, API_KEY_SENTINEL));
        assert!(!contains_slice(&durable, HANDOFF_SENTINEL));

        let captures = fake.captures.lock().unwrap();
        let candidates: Vec<_> = captures
            .iter()
            .filter(|capture| capture.path.ends_with("/launch-candidates"))
            .collect();
        let consumes: Vec<_> = captures
            .iter()
            .filter(|capture| capture.path.ends_with("/consume"))
            .collect();
        assert_eq!(candidates.len(), 1);
        assert_eq!(consumes.len(), 1);
        assert_eq!(candidates[0].content_type, LAUNCH_MEDIA_TYPE);
        assert_eq!(candidates[0].accept, LAUNCH_MEDIA_TYPE);
        assert_eq!(candidates[0].body, launch.candidate_body_json.as_bytes());
        assert_eq!(
            candidates[0].idempotency_key,
            launch.candidate_idempotency_key
        );
        assert_eq!(consumes[0].content_type, LAUNCH_MEDIA_TYPE);
        assert_eq!(consumes[0].accept, LAUNCH_MEDIA_TYPE);
        assert_eq!(
            consumes[0].body,
            launch.consume_body_json.as_deref().unwrap().as_bytes()
        );

        drop(captures);
        adapter.process_intent(&deployment).await.unwrap();
        assert_eq!(actions.list().len(), 1);
        assert_eq!(
            actions
                .get(&operation.job_id)
                .unwrap()
                .events
                .iter()
                .filter(|event| event.kind == HostActionEventKind::Confirmed)
                .count(),
            1
        );
        server.abort();
    }

    #[tokio::test]
    async fn crash_after_create_before_operation_journal_binds_the_same_job() {
        let now = now_unix();
        let directory = temporary_directory("crash-after-create");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let adapter = test_adapter(
            config(origin.clone(), api_path.clone(), vec![deployment.clone()]),
            directory.join("journal.json"),
            hosts.clone(),
            actions.clone(),
        );
        let journal_path = directory.join("journal.json");
        adapter.process_intent(&deployment).await.unwrap();
        let job_id = adapter
            .journal
            .operation(DEPLOYMENT_HANDOFF)
            .expect("created job")
            .job_id;
        {
            let mut document = adapter.journal.document.lock().expect("journal");
            document.operations.clear();
            crate::durable_file::atomic_write_json(&journal_path, &*document)
                .expect("drop operation binding from durable journal");
        }

        let restarted = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            journal_path,
            hosts,
            actions.clone(),
        );
        restarted.process_intent(&deployment).await.unwrap();
        let jobs: Vec<_> = actions
            .list()
            .into_iter()
            .filter(|job| job.kind == HostActionKind::UpdateRestart)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job_id);
        assert_eq!(
            restarted
                .journal
                .operation(DEPLOYMENT_HANDOFF)
                .unwrap()
                .job_id,
            job_id
        );
        server.abort();
    }

    #[tokio::test]
    async fn crash_after_create_then_operator_confirm_still_binds_the_same_job() {
        let now = now_unix();
        let directory = temporary_directory("crash-after-confirm");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        let hosts = Arc::new(Store::new(None).unwrap());
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let adapter = test_adapter(
            config(origin.clone(), api_path.clone(), vec![deployment.clone()]),
            directory.join("journal.json"),
            hosts.clone(),
            actions.clone(),
        );
        let journal_path = directory.join("journal.json");
        adapter.process_intent(&deployment).await.unwrap();
        let job_id = adapter
            .journal
            .operation(DEPLOYMENT_HANDOFF)
            .expect("created job")
            .job_id;
        operator_confirm_existing_update(&actions, &job_id, now_unix());
        let confirmed = actions.get(&job_id).expect("confirmed owned job");
        assert_eq!(confirmed.state, HostActionState::QueuedApply);
        assert!(confirmed.confirmed_at.is_some());
        let confirmed_at = confirmed.confirmed_at;
        let event_count = confirmed.events.len();
        assert!(confirmed
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::Confirmed));
        {
            let mut document = adapter.journal.document.lock().expect("journal");
            document.operations.clear();
            crate::durable_file::atomic_write_json(&journal_path, &*document)
                .expect("drop operation binding from durable journal");
        }

        let restarted = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            journal_path,
            hosts,
            actions.clone(),
        );
        restarted.process_intent(&deployment).await.unwrap();
        let jobs: Vec<_> = actions
            .list()
            .into_iter()
            .filter(|job| job.kind == HostActionKind::UpdateRestart)
            .collect();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, job_id);
        assert_eq!(jobs[0].state, HostActionState::QueuedApply);
        assert_eq!(jobs[0].confirmed_at, confirmed_at);
        assert_eq!(jobs[0].events.len(), event_count);
        assert_eq!(jobs[0].requested_by, GUARDED_ACTOR);
        assert_eq!(
            restarted
                .journal
                .operation(DEPLOYMENT_HANDOFF)
                .unwrap()
                .job_id,
            job_id
        );
        server.abort();
    }

    #[tokio::test]
    async fn explicit_job_wrong_host_or_kind_fails_closed() {
        let now = now_unix();
        let directory = temporary_directory("wrong-bind");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        let other = actions
            .create_update_review("csb0", "operator", now)
            .expect("other host job");
        let proposal = actions
            .create_system_update_proposal(
                "action-system-update-hsb8-kind".to_string(),
                "hsb8",
                "operator",
                now + 1,
            )
            .expect("wrong kind");
        let hosts = Arc::new(Store::new(None).unwrap());
        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.update_restart_job_id = Some(other.id.clone());
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            directory.join("journal.json"),
            hosts,
            actions.clone(),
        );
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        deployment.update_restart_job_id = Some(proposal.id);
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert!(adapter.journal.operation(DEPLOYMENT_HANDOFF).is_none());
        server.abort();
    }

    #[tokio::test]
    async fn unrelated_active_job_and_fleetlock_are_not_adopted() {
        let now = now_unix();
        let directory = temporary_directory("unrelated-active");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake.clone()).await;
        let actions = Arc::new(HostActionStore::new(None));
        actions
            .create_update_review("hsb8", "operator", now)
            .expect("unrelated active job");
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            directory.join("journal.json"),
            Arc::new(Store::new(None).unwrap()),
            actions.clone(),
        );
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert_eq!(
            actions
                .list()
                .iter()
                .filter(|job| job.kind == HostActionKind::UpdateRestart)
                .count(),
            1
        );
        assert!(adapter.journal.operation(DEPLOYMENT_HANDOFF).is_none());
        let seq2 = fake
            .captures
            .lock()
            .unwrap()
            .iter()
            .filter(|capture| capture.method == "POST")
            .filter(|capture| {
                serde_json::from_slice::<Value>(&capture.body)
                    .ok()
                    .and_then(|body| body["sequence"].as_i64())
                    == Some(2)
            })
            .count();
        assert_eq!(seq2, 0);
        server.abort();
    }

    #[tokio::test]
    async fn fleetlock_on_another_host_blocks_create() {
        let now = now_unix();
        let directory = temporary_directory("fleetlock");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let fake = FakePaimos::new(now);
        let (origin, server) = serve_fake(fake).await;
        let actions = Arc::new(HostActionStore::new(None));
        actions
            .create_update_review("csb0", "operator", now)
            .expect("blocking fleet job");
        let deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        let adapter = test_adapter(
            config(origin, api_path, vec![deployment.clone()]),
            directory.join("journal.json"),
            Arc::new(Store::new(None).unwrap()),
            actions.clone(),
        );
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert!(matches!(
            adapter.process_intent(&deployment).await,
            Err(AdapterError::LocalBinding)
        ));
        assert!(actions
            .list()
            .iter()
            .all(|job| job.host != "hsb8" || job.kind != HostActionKind::UpdateRestart));
        server.abort();
    }

    #[test]
    fn nix_only_generation_evidence_is_not_release_artifact_proof() {
        let now = now_unix();
        let directory = temporary_directory("nix-only");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_nix_only_beacon(&hosts, now - 20, &artifact());
        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.update_restart_job_id = Some(job_id);
        let adapter = test_adapter(
            config(
                Url::parse("https://paimos.example.test").unwrap(),
                api_path,
                vec![deployment.clone()],
            ),
            directory.join("journal.json"),
            hosts,
            actions,
        );
        assert!(adapter
            .deployment_report(&deployment, now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn stale_mismatched_predated_and_wrong_environment_observations_fail_closed() {
        let now = now_unix();
        let directory = temporary_directory("observation-gates");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.update_restart_job_id = Some(job_id);
        let hosts = Arc::new(Store::new(None).unwrap());
        let adapter = test_adapter(
            config(
                Url::parse("https://paimos.example.test").unwrap(),
                api_path,
                vec![deployment.clone()],
            ),
            directory.join("journal.json"),
            hosts.clone(),
            actions,
        );

        record_beacon(&hosts, now - 400, &artifact());
        assert!(adapter
            .deployment_report(&deployment, now)
            .unwrap()
            .is_none());

        let mut mismatched = artifact();
        mismatched.digest = format!("sha256:{}", "c".repeat(64));
        record_beacon(&hosts, now - 20, &mismatched);
        assert!(matches!(
            adapter.deployment_report(&deployment, now),
            Err(AdapterError::LocalBinding)
        ));

        record_beacon(&hosts, now - 80, &artifact());
        assert!(adapter
            .deployment_report(&deployment, now)
            .unwrap()
            .is_none());

        record_beacon(&hosts, now + 200, &artifact());
        assert!(adapter
            .deployment_report(&deployment, now)
            .unwrap()
            .is_none());

        let mut wrong_env = measured_from(&artifact(), now - 5);
        wrong_env.environment = "production-us1".to_string();
        record_beacon(&hosts, now - 10, &artifact());
        let report = {
            let host = hosts.get("hsb8").unwrap();
            HostReport {
                schema: HOST_REPORT_SCHEMA.to_string(),
                version: HOST_REPORT_VERSION,
                name: host.name.clone(),
                role: host.role.clone(),
                is_nix: host.is_nix,
                heartbeat_interval_secs: host.heartbeat_interval_secs.unwrap_or(60),
                freshness: host.freshness.clone(),
                kernel: host.kernel.clone(),
                service_observations: host.service_observations.clone(),
                backup_observations: host.backup_observations.clone(),
                inbound_rtt_ms: None,
                location: None,
                preferences: host.preferences.clone(),
                deployed_artifact: Some(wrong_env),
            }
        };
        report.validate_contract().unwrap();
        hosts.record(report, now - 5).unwrap();
        assert!(matches!(
            adapter.deployment_report(&deployment, now),
            Err(AdapterError::LocalBinding)
        ));
    }

    #[test]
    fn real_producer_measurement_fixture_preserves_oci_classes() {
        let artifact = calendar_artifact();
        let envelope = pharos_core::ApprovedReleaseEnvelope {
            schema: APPROVED_RELEASE_ENVELOPE_SCHEMA.to_string(),
            version: APPROVED_RELEASE_ENVELOPE_VERSION,
            environment: "production-eu1".to_string(),
            version_scheme: artifact.version_scheme,
            artifact_version: artifact.version.clone(),
            release_channel: artifact.release_channel.clone(),
            release_sequence: artifact.release_sequence,
            commit_digest: artifact.commit_digest.clone(),
            release_manifest_coordinate: artifact.release_manifest_coordinate.clone(),
            release_manifest_digest: artifact.release_manifest_digest.clone(),
            oci_config_digest: artifact.digest.clone(),
        };
        parse_approved_release_envelope(&serde_json::to_vec(&envelope).unwrap()).unwrap();
        let mut fields = vec![
            "true".to_string(),
            format!("sha256:{}", "a".repeat(64)),
            artifact.digest.clone(),
        ];
        fields.resize(11, String::new());
        let line = fields.join("\t");
        let observation = parse_running_container_format(&line).unwrap();
        let parsed =
            evidence_from_running_container(&observation, Some(&envelope), 1_700_000_100).unwrap();
        assert_eq!(parsed.digest_class, ArtifactDigestClass::OciConfig);
        assert!(parsed.oci_index_digest.is_none());
        assert!(parsed.oci_manifest_digest.is_none());
        assert_eq!(parsed.observed_at, 1_700_000_100);
        assert!(parsed.matches_expected(
            "production-eu1",
            artifact.version_scheme,
            &artifact.version,
            &artifact.release_channel,
            artifact.release_sequence,
            &artifact.digest,
            &artifact.commit_digest,
            &artifact.release_manifest_coordinate,
            &artifact.release_manifest_digest,
        ));
        let index_digest = format!("sha256:{}", "5".repeat(64));
        assert!(!parsed.matches_expected(
            "production-eu1",
            artifact.version_scheme,
            &artifact.version,
            &artifact.release_channel,
            artifact.release_sequence,
            &index_digest,
            &artifact.commit_digest,
            &artifact.release_manifest_coordinate,
            &artifact.release_manifest_digest,
        ));
        let mut replaced_fields = vec![
            "true".to_string(),
            format!("sha256:{}", "a".repeat(64)),
            format!("sha256:{}", "9".repeat(64)),
        ];
        replaced_fields.resize(11, String::new());
        let replaced = replaced_fields.join("\t");
        assert!(evidence_from_running_container(
            &parse_running_container_format(&replaced).unwrap(),
            Some(&envelope),
            1_700_000_100
        )
        .is_err());
        assert_eq!(envelope.oci_config_digest, artifact.digest);
    }

    #[test]
    fn manifest_or_index_class_evidence_is_not_config_proof() {
        let now = now_unix();
        let directory = temporary_directory("manifest-class");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 20, &artifact());
        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.update_restart_job_id = Some(job_id);
        let adapter = test_adapter(
            config(
                Url::parse("https://paimos.example.test").unwrap(),
                api_path,
                vec![deployment.clone()],
            ),
            directory.join("journal.json"),
            hosts.clone(),
            actions,
        );
        let host = hosts.get("hsb8").unwrap();
        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: host.name.clone(),
            role: host.role.clone(),
            is_nix: host.is_nix,
            heartbeat_interval_secs: host.heartbeat_interval_secs.unwrap_or(60),
            freshness: host.freshness.clone(),
            kernel: host.kernel.clone(),
            service_observations: host.service_observations.clone(),
            backup_observations: host.backup_observations.clone(),
            inbound_rtt_ms: None,
            location: None,
            preferences: host.preferences.clone(),
            deployed_artifact: Some(manifest_class_evidence(&artifact(), now - 20)),
        };
        hosts.record(report, now - 5).unwrap();
        assert!(matches!(
            adapter.deployment_report(&deployment, now),
            Err(AdapterError::LocalBinding)
        ));
    }

    #[test]
    fn measurement_time_not_report_receive_time_gates_freshness() {
        let now = now_unix();
        let directory = temporary_directory("measurement-clock");
        let api_path = directory.join("api-key");
        let secret_path = directory.join("handoff-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&secret_path, HANDOFF_SENTINEL);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 5, &artifact());
        let mut deployment = intent(DEPLOYMENT_HANDOFF, secret_path, IntentStage::Deployment);
        deployment.update_restart_job_id = Some(job_id);
        let adapter = test_adapter(
            config(
                Url::parse("https://paimos.example.test").unwrap(),
                api_path,
                vec![deployment.clone()],
            ),
            directory.join("journal.json"),
            hosts.clone(),
            actions,
        );
        let host = hosts.get("hsb8").unwrap();
        let mut evidence = measured_from(&artifact(), now - 400);
        evidence.observed_at = now - 400;
        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: host.name.clone(),
            role: host.role.clone(),
            is_nix: host.is_nix,
            heartbeat_interval_secs: host.heartbeat_interval_secs.unwrap_or(60),
            freshness: host.freshness.clone(),
            kernel: host.kernel.clone(),
            service_observations: host.service_observations.clone(),
            backup_observations: host.backup_observations.clone(),
            inbound_rtt_ms: None,
            location: None,
            preferences: host.preferences.clone(),
            deployed_artifact: Some(evidence),
        };
        hosts.record(report, now - 5).unwrap();
        assert!(adapter
            .deployment_report(&deployment, now)
            .unwrap()
            .is_none());
    }

    #[test]
    fn verification_mismatched_lineage_fails_closed() {
        let now = now_unix();
        let directory = temporary_directory("lineage");
        let api_path = directory.join("api-key");
        let deployment_secret = directory.join("deployment-secret");
        let verification_secret = directory.join("verification-secret");
        write_private(&api_path, API_KEY_SENTINEL);
        write_private(&deployment_secret, HANDOFF_SENTINEL);
        write_private(&verification_secret, &[8; HANDOFF_SECRET_BYTES]);
        let actions = Arc::new(HostActionStore::new(None));
        let job_id = completed_update(&actions, now);
        let hosts = Arc::new(Store::new(None).unwrap());
        record_beacon(&hosts, now - 5, &artifact());
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
        let pull = test_pull(
            DEPLOYMENT_HANDOFF,
            "deployment",
            &format!("sha256:{}", "3".repeat(64)),
        );
        adapter.bind_after_accept(&deployment, &pull, now).unwrap();
        let record = adapter
            .journal
            .ensure(
                JournalRecord::new(
                    &deployment,
                    &Url::parse("https://paimos.example.test").unwrap(),
                    2,
                    JournalRequestKind::Report,
                    &serde_json::to_vec(&terminal_report(&deployment, now - 10, true).unwrap())
                        .unwrap(),
                )
                .unwrap(),
            )
            .unwrap();
        adapter
            .journal
            .acknowledge(
                &record,
                ReportReceipt {
                    handoff_id: DEPLOYMENT_HANDOFF.to_string(),
                    sequence: 2,
                    state: HandoffState::Succeeded,
                    credential_epoch: 9,
                    duplicate: false,
                    server_received_at: format_timestamp(now - 8).unwrap(),
                },
            )
            .unwrap();
        let mut bad = test_pull(
            VERIFICATION_HANDOFF,
            "verification",
            &format!("sha256:{}", "8".repeat(64)),
        );
        bad.authority_epoch = 9;
        assert!(matches!(
            adapter.verification_report(&verification, &bad, now),
            Err(AdapterError::LocalBinding)
        ));
    }
}
