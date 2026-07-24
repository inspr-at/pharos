//! Durable, value-free orchestration for declared managed-service secrets.
//!
//! Janus announces only an opaque ready operation. A host-ref-bound target
//! agent leases one fixed declared phase at a time. Pharos never handles the
//! envelope, secret, permit, host key, runtime path, command, or command output.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use pharos_core::managed_operations::{
    valid_ref, ManagedHealthEvidenceV1, ManagedOperationAgentOutcome, ManagedOperationAgentPhase,
    ManagedOperationKind, ManagedOperationLeaseV1, ManagedOperationReadyV1, ManagedOperationReason,
    ManagedOperationResultV1, MANAGED_OPERATION_CONTRACT_VERSION, MANAGED_OPERATION_LEASE_SCHEMA,
};
use pharos_core::managed_services::ManagedSecretSlotDeclarationV1;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::durable_file::{atomic_write_json, load_optional_json};

const STORE_SCHEMA: &str = "inspr.pharos.managed-service-operation-store.v1";
const RECORD_SCHEMA: &str = "inspr.pharos.managed-service-operation.v1";
const MAX_OPERATIONS: usize = 4_096;
const LEASE_SECONDS: i64 = 60;
const OPERATION_TIMEOUT_SECONDS: i64 = 30 * 60;
const MAX_UNCERTAIN_ATTEMPTS: u8 = 3;
const HEALTH_EVIDENCE_MAX_AGE_SECONDS: i64 = 120;
const CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedOperationPhase {
    InstallPending,
    Installing,
    ReloadPending,
    Reloading,
    VerifyPending,
    Verifying,
    Active,
    Failed,
    Superseded,
}

impl ManagedOperationPhase {
    pub(crate) fn name(self) -> &'static str {
        match self {
            Self::InstallPending => "install_pending",
            Self::Installing => "installing",
            Self::ReloadPending => "reload_pending",
            Self::Reloading => "reloading",
            Self::VerifyPending => "verify_pending",
            Self::Verifying => "verifying",
            Self::Active => "active",
            Self::Failed => "failed",
            Self::Superseded => "superseded",
        }
    }

    fn pending_agent_phase(self) -> Option<ManagedOperationAgentPhase> {
        match self {
            Self::InstallPending => Some(ManagedOperationAgentPhase::Install),
            Self::ReloadPending => Some(ManagedOperationAgentPhase::Reload),
            Self::VerifyPending => Some(ManagedOperationAgentPhase::Verify),
            _ => None,
        }
    }

    fn leased_agent_phase(self) -> Option<ManagedOperationAgentPhase> {
        match self {
            Self::Installing => Some(ManagedOperationAgentPhase::Install),
            Self::Reloading => Some(ManagedOperationAgentPhase::Reload),
            Self::Verifying => Some(ManagedOperationAgentPhase::Verify),
            _ => None,
        }
    }

    fn leased(phase: ManagedOperationAgentPhase) -> Self {
        match phase {
            ManagedOperationAgentPhase::Install => Self::Installing,
            ManagedOperationAgentPhase::Reload => Self::Reloading,
            ManagedOperationAgentPhase::Verify => Self::Verifying,
        }
    }

    fn pending(phase: ManagedOperationAgentPhase) -> Self {
        match phase {
            ManagedOperationAgentPhase::Install => Self::InstallPending,
            ManagedOperationAgentPhase::Reload => Self::ReloadPending,
            ManagedOperationAgentPhase::Verify => Self::VerifyPending,
        }
    }

    fn terminal(self) -> bool {
        matches!(self, Self::Active | Self::Failed | Self::Superseded)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ManagedHealthOutcome {
    Healthy,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AcceptedHealthEvidence {
    generation: u64,
    outcome: ManagedHealthOutcome,
    heartbeat_observed_at_unix_secs: i64,
    process_observed_at_unix_secs: i64,
    probe_observed_at_unix_secs: i64,
    accepted_at_unix_secs: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ActiveLease {
    lease_ref: String,
    phase: ManagedOperationAgentPhase,
    leased_at_unix_secs: i64,
    expires_at_unix_secs: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedOperationRecord {
    schema: String,
    schema_version: u16,
    operation_ref: String,
    operation_kind: ManagedOperationKind,
    host_ref: String,
    service_ref: String,
    slot_ref: String,
    declaration_fingerprint: String,
    generation: u64,
    delivery_profile_ref: String,
    reload_profile_ref: String,
    health_profile_ref: String,
    phase: ManagedOperationPhase,
    reason_code: Option<ManagedOperationReason>,
    created_at_unix_secs: i64,
    updated_at_unix_secs: i64,
    deadline_unix_secs: i64,
    delivery_completed_at_unix_secs: Option<i64>,
    reload_completed_at_unix_secs: Option<i64>,
    health: Option<AcceptedHealthEvidence>,
    active_lease: Option<ActiveLease>,
    uncertain_attempts: u8,
    last_result_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct ManagedOperationDocument {
    schema: String,
    schema_version: u16,
    operations: BTreeMap<String, ManagedOperationRecord>,
}

impl Default for ManagedOperationDocument {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            operations: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ManagedOperationSummary {
    pub operation_ref: String,
    pub operation_kind: ManagedOperationKind,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
    pub phase: ManagedOperationPhase,
    pub reason_code: Option<ManagedOperationReason>,
    pub created_at_unix_secs: i64,
    pub updated_at_unix_secs: i64,
    pub health: Option<ManagedHealthSummary>,
    pub value_returned: bool,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct ManagedHealthSummary {
    pub generation: u64,
    pub outcome: ManagedHealthOutcome,
    pub heartbeat_observed_at_unix_secs: i64,
    pub process_observed_at_unix_secs: i64,
    pub probe_observed_at_unix_secs: i64,
    pub accepted_at_unix_secs: i64,
}

impl From<&ManagedOperationRecord> for ManagedOperationSummary {
    fn from(record: &ManagedOperationRecord) -> Self {
        Self {
            operation_ref: record.operation_ref.clone(),
            operation_kind: record.operation_kind,
            host_ref: record.host_ref.clone(),
            service_ref: record.service_ref.clone(),
            slot_ref: record.slot_ref.clone(),
            declaration_fingerprint: record.declaration_fingerprint.clone(),
            generation: record.generation,
            phase: record.phase,
            reason_code: record.reason_code,
            created_at_unix_secs: record.created_at_unix_secs,
            updated_at_unix_secs: record.updated_at_unix_secs,
            health: record.health.as_ref().map(|health| ManagedHealthSummary {
                generation: health.generation,
                outcome: health.outcome,
                heartbeat_observed_at_unix_secs: health.heartbeat_observed_at_unix_secs,
                process_observed_at_unix_secs: health.process_observed_at_unix_secs,
                probe_observed_at_unix_secs: health.probe_observed_at_unix_secs,
                accepted_at_unix_secs: health.accepted_at_unix_secs,
            }),
            value_returned: false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedOperationStoreError {
    InvalidRequest,
    DeclarationDrift,
    GenerationDowngrade,
    Conflict,
    NotFound,
    WrongHost,
    LeaseExpired,
    InvalidEvidence,
    PersistenceUnavailable,
    Capacity,
}

pub(crate) struct ManagedServiceOperationStore {
    path: Option<PathBuf>,
    document: Mutex<ManagedOperationDocument>,
}

impl ManagedServiceOperationStore {
    pub(crate) fn new(path: Option<PathBuf>) -> Result<Self, String> {
        let document = match path.as_deref() {
            Some(path) => load_optional_json::<ManagedOperationDocument>(path)
                .map_err(|error| error.to_string())?
                .unwrap_or_default(),
            None => ManagedOperationDocument::default(),
        };
        validate_document(&document)?;
        Ok(Self {
            path,
            document: Mutex::new(document),
        })
    }

    pub(crate) fn path_for(database_path: Option<&Path>) -> Option<PathBuf> {
        database_path.map(|path| path.with_file_name("managed-service-operations.json"))
    }

    pub(crate) fn register(
        &self,
        request: &ManagedOperationReadyV1,
        slot: &ManagedSecretSlotDeclarationV1,
        now: i64,
    ) -> Result<ManagedOperationSummary, ManagedOperationStoreError> {
        request
            .validate_contract()
            .map_err(|_| ManagedOperationStoreError::InvalidRequest)?;
        if now <= 0 {
            return Err(ManagedOperationStoreError::InvalidRequest);
        }
        let mut document = self.document.lock().expect("managed operation lock");
        if let Some(existing) = document.operations.get(&request.operation_ref) {
            if record_matches_ready(existing, request, slot) {
                return Ok(ManagedOperationSummary::from(existing));
            }
            return Err(ManagedOperationStoreError::Conflict);
        }
        let max_generation = document
            .operations
            .values()
            .filter(|operation| same_slot(operation, request))
            .map(|operation| operation.generation)
            .max()
            .unwrap_or(0);
        if request.generation <= max_generation {
            return Err(ManagedOperationStoreError::GenerationDowngrade);
        }

        let previous = document.clone();
        prune_terminal_history(&mut document);
        if document.operations.len() >= MAX_OPERATIONS {
            *document = previous;
            return Err(ManagedOperationStoreError::Capacity);
        }
        for operation in document
            .operations
            .values_mut()
            .filter(|operation| same_slot(operation, request) && !operation.phase.terminal())
        {
            operation.phase = ManagedOperationPhase::Superseded;
            operation.reason_code = Some(ManagedOperationReason::OperationSuperseded);
            operation.active_lease = None;
            operation.updated_at_unix_secs = now;
        }
        let record = ManagedOperationRecord {
            schema: RECORD_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            operation_ref: request.operation_ref.clone(),
            operation_kind: request.operation_kind,
            host_ref: request.host_ref.clone(),
            service_ref: request.service_ref.clone(),
            slot_ref: request.slot_ref.clone(),
            declaration_fingerprint: request.declaration_fingerprint.clone(),
            generation: request.generation,
            delivery_profile_ref: slot.delivery.profile_ref.clone(),
            reload_profile_ref: slot.reload.profile_ref.clone(),
            health_profile_ref: slot.health.profile_ref.clone(),
            phase: ManagedOperationPhase::InstallPending,
            reason_code: None,
            created_at_unix_secs: now,
            updated_at_unix_secs: now,
            deadline_unix_secs: now.saturating_add(OPERATION_TIMEOUT_SECONDS),
            delivery_completed_at_unix_secs: None,
            reload_completed_at_unix_secs: None,
            health: None,
            active_lease: None,
            uncertain_attempts: 0,
            last_result_sha256: None,
        };
        document
            .operations
            .insert(request.operation_ref.clone(), record);
        self.persist_or_restore(&mut document, previous)?;
        Ok(ManagedOperationSummary::from(
            document
                .operations
                .get(&request.operation_ref)
                .expect("registered operation"),
        ))
    }

    pub(crate) fn get(
        &self,
        operation_ref: &str,
        now: i64,
    ) -> Result<ManagedOperationSummary, ManagedOperationStoreError> {
        if !valid_ref("op_", operation_ref) || now <= 0 {
            return Err(ManagedOperationStoreError::InvalidRequest);
        }
        let mut document = self.document.lock().expect("managed operation lock");
        let previous = document.clone();
        reconcile(&mut document, now);
        let summary = document
            .operations
            .get(operation_ref)
            .map(ManagedOperationSummary::from);
        if *document != previous {
            self.persist_or_restore(&mut document, previous)?;
        }
        summary.ok_or(ManagedOperationStoreError::NotFound)
    }

    pub(crate) fn claim(
        &self,
        host_ref: &str,
        now: i64,
    ) -> Result<Option<ManagedOperationLeaseV1>, ManagedOperationStoreError> {
        if !valid_ref("host_", host_ref) || now <= 0 {
            return Err(ManagedOperationStoreError::InvalidRequest);
        }
        let mut document = self.document.lock().expect("managed operation lock");
        let previous = document.clone();
        reconcile(&mut document, now);
        let candidate = document
            .operations
            .values_mut()
            .filter(|operation| operation.host_ref == host_ref)
            .filter_map(|operation| {
                operation
                    .phase
                    .pending_agent_phase()
                    .map(|phase| (operation.created_at_unix_secs, operation, phase))
            })
            .min_by_key(|(created_at, _, _)| *created_at);
        let Some((_, operation, phase)) = candidate else {
            if *document != previous {
                self.persist_or_restore(&mut document, previous)?;
            }
            return Ok(None);
        };
        let lease_ref =
            random_ref("lease_").map_err(|_| ManagedOperationStoreError::PersistenceUnavailable)?;
        let lease = ActiveLease {
            lease_ref: lease_ref.clone(),
            phase,
            leased_at_unix_secs: now,
            expires_at_unix_secs: now.saturating_add(LEASE_SECONDS),
        };
        operation.phase = ManagedOperationPhase::leased(phase);
        operation.active_lease = Some(lease.clone());
        operation.updated_at_unix_secs = now;
        let response = ManagedOperationLeaseV1 {
            schema: MANAGED_OPERATION_LEASE_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref,
            operation_ref: operation.operation_ref.clone(),
            host_ref: operation.host_ref.clone(),
            service_ref: operation.service_ref.clone(),
            slot_ref: operation.slot_ref.clone(),
            declaration_fingerprint: operation.declaration_fingerprint.clone(),
            generation: operation.generation,
            phase,
            profile_ref: match phase {
                ManagedOperationAgentPhase::Install => operation.delivery_profile_ref.clone(),
                ManagedOperationAgentPhase::Reload => operation.reload_profile_ref.clone(),
                ManagedOperationAgentPhase::Verify => operation.health_profile_ref.clone(),
            },
            leased_at_unix_secs: lease.leased_at_unix_secs,
            expires_at_unix_secs: lease.expires_at_unix_secs,
            value_returned: false,
        };
        response
            .validate_contract()
            .map_err(|_| ManagedOperationStoreError::InvalidRequest)?;
        self.persist_or_restore(&mut document, previous)?;
        Ok(Some(response))
    }

    pub(crate) fn record_result(
        &self,
        request: &ManagedOperationResultV1,
        now: i64,
    ) -> Result<ManagedOperationSummary, ManagedOperationStoreError> {
        request
            .validate_contract()
            .map_err(|_| ManagedOperationStoreError::InvalidRequest)?;
        if now <= 0 {
            return Err(ManagedOperationStoreError::InvalidRequest);
        }
        let result_hash = result_hash(request)?;
        let mut document = self.document.lock().expect("managed operation lock");
        let previous = document.clone();
        let operation = document
            .operations
            .get_mut(&request.operation_ref)
            .ok_or(ManagedOperationStoreError::NotFound)?;
        if operation.host_ref != request.host_ref {
            return Err(ManagedOperationStoreError::WrongHost);
        }
        if operation.generation != request.generation {
            return Err(ManagedOperationStoreError::Conflict);
        }
        if operation.last_result_sha256.as_deref() == Some(&result_hash) {
            return Ok(ManagedOperationSummary::from(&*operation));
        }
        let lease = operation
            .active_lease
            .as_ref()
            .ok_or(ManagedOperationStoreError::Conflict)?;
        if lease.lease_ref != request.lease_ref
            || lease.phase != request.phase
            || operation.phase.leased_agent_phase() != Some(request.phase)
        {
            return Err(ManagedOperationStoreError::Conflict);
        }
        if lease.expires_at_unix_secs <= now {
            operation.phase = ManagedOperationPhase::pending(request.phase);
            operation.active_lease = None;
            operation.reason_code = Some(ManagedOperationReason::LeaseExpired);
            operation.updated_at_unix_secs = now;
            self.persist_or_restore(&mut document, previous)?;
            return Err(ManagedOperationStoreError::LeaseExpired);
        }

        match request.outcome {
            ManagedOperationAgentOutcome::Succeeded => {
                apply_success(operation, request, now)?;
            }
            ManagedOperationAgentOutcome::Uncertain => {
                operation.uncertain_attempts = operation.uncertain_attempts.saturating_add(1);
                if operation.uncertain_attempts < MAX_UNCERTAIN_ATTEMPTS {
                    operation.phase = ManagedOperationPhase::pending(request.phase);
                    operation.reason_code = Some(request.reason_code);
                } else {
                    operation.phase = ManagedOperationPhase::Failed;
                    operation.reason_code = Some(request.reason_code);
                }
            }
            ManagedOperationAgentOutcome::Failed => {
                operation.phase = ManagedOperationPhase::Failed;
                operation.reason_code = Some(request.reason_code);
            }
        }
        operation.active_lease = None;
        operation.updated_at_unix_secs = now;
        operation.last_result_sha256 = Some(result_hash);
        self.persist_or_restore(&mut document, previous)?;
        Ok(ManagedOperationSummary::from(
            document
                .operations
                .get(&request.operation_ref)
                .expect("result operation"),
        ))
    }

    pub(crate) fn latest_for_slot(
        &self,
        host_ref: &str,
        service_ref: &str,
        slot_ref: &str,
        now: i64,
    ) -> Option<ManagedOperationSummary> {
        let mut document = self.document.lock().expect("managed operation lock");
        let previous = document.clone();
        reconcile(&mut document, now);
        let visible = document.clone();
        if *document != previous {
            // Status remains conservative even if this reconciliation cannot
            // be persisted: report the reconciled snapshot, never "missing"
            // or a stale success. Mutations and leases still fail closed.
            let _ = self.persist_or_restore(&mut document, previous);
        }
        visible
            .operations
            .values()
            .filter(|operation| {
                operation.host_ref == host_ref
                    && operation.service_ref == service_ref
                    && operation.slot_ref == slot_ref
            })
            .max_by_key(|operation| (operation.generation, operation.created_at_unix_secs))
            .map(ManagedOperationSummary::from)
    }

    pub(crate) fn for_host(&self, host_ref: &str, now: i64) -> Vec<ManagedOperationSummary> {
        let mut document = self.document.lock().expect("managed operation lock");
        let previous = document.clone();
        reconcile(&mut document, now);
        let visible = document.clone();
        if *document != previous {
            let _ = self.persist_or_restore(&mut document, previous);
        }
        visible
            .operations
            .values()
            .filter(|operation| operation.host_ref == host_ref)
            .map(ManagedOperationSummary::from)
            .collect()
    }

    fn persist_or_restore(
        &self,
        document: &mut ManagedOperationDocument,
        previous: ManagedOperationDocument,
    ) -> Result<(), ManagedOperationStoreError> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        if let Err(error) = atomic_write_json(path, &*document) {
            if !error.final_file_replaced() {
                *document = previous;
            }
            return Err(ManagedOperationStoreError::PersistenceUnavailable);
        }
        Ok(())
    }
}

fn apply_success(
    operation: &mut ManagedOperationRecord,
    request: &ManagedOperationResultV1,
    now: i64,
) -> Result<(), ManagedOperationStoreError> {
    match request.phase {
        ManagedOperationAgentPhase::Install => {
            operation.delivery_completed_at_unix_secs = Some(now);
            operation.phase = ManagedOperationPhase::ReloadPending;
        }
        ManagedOperationAgentPhase::Reload => {
            if operation.delivery_completed_at_unix_secs.is_none() {
                return Err(ManagedOperationStoreError::Conflict);
            }
            operation.reload_completed_at_unix_secs = Some(now);
            operation.phase = ManagedOperationPhase::VerifyPending;
        }
        ManagedOperationAgentPhase::Verify => {
            let evidence = request
                .health_evidence
                .as_ref()
                .ok_or(ManagedOperationStoreError::InvalidEvidence)?;
            validate_health_evidence(operation, evidence, now)?;
            operation.health = Some(AcceptedHealthEvidence {
                generation: evidence.generation,
                outcome: ManagedHealthOutcome::Healthy,
                heartbeat_observed_at_unix_secs: evidence.heartbeat_observed_at_unix_secs,
                process_observed_at_unix_secs: evidence.process_observed_at_unix_secs,
                probe_observed_at_unix_secs: evidence.probe_observed_at_unix_secs,
                accepted_at_unix_secs: now,
            });
            operation.phase = ManagedOperationPhase::Active;
        }
    }
    operation.uncertain_attempts = 0;
    operation.reason_code = Some(ManagedOperationReason::PhaseSucceeded);
    Ok(())
}

fn validate_health_evidence(
    operation: &ManagedOperationRecord,
    evidence: &ManagedHealthEvidenceV1,
    now: i64,
) -> Result<(), ManagedOperationStoreError> {
    let delivery_at = operation
        .delivery_completed_at_unix_secs
        .ok_or(ManagedOperationStoreError::InvalidEvidence)?;
    let reload_at = operation
        .reload_completed_at_unix_secs
        .ok_or(ManagedOperationStoreError::InvalidEvidence)?;
    let timestamps = [
        evidence.heartbeat_observed_at_unix_secs,
        evidence.process_observed_at_unix_secs,
        evidence.probe_observed_at_unix_secs,
    ];
    if evidence.generation != operation.generation
        || !evidence.materialized
        || timestamps.iter().any(|observed| {
            *observed < delivery_at
                || *observed < reload_at
                || *observed > now.saturating_add(CLOCK_SKEW_SECONDS)
                || now.saturating_sub(*observed) > HEALTH_EVIDENCE_MAX_AGE_SECONDS
        })
    {
        return Err(ManagedOperationStoreError::InvalidEvidence);
    }
    Ok(())
}

fn reconcile(document: &mut ManagedOperationDocument, now: i64) {
    for operation in document.operations.values_mut() {
        if operation.phase == ManagedOperationPhase::Active {
            let health_is_stale = operation.health.as_ref().is_none_or(|health| {
                [
                    health.heartbeat_observed_at_unix_secs,
                    health.process_observed_at_unix_secs,
                    health.probe_observed_at_unix_secs,
                ]
                .iter()
                .any(|observed| now.saturating_sub(*observed) > HEALTH_EVIDENCE_MAX_AGE_SECONDS)
            });
            if health_is_stale {
                operation.phase = ManagedOperationPhase::VerifyPending;
                operation.reason_code = Some(ManagedOperationReason::EvidenceStale);
                operation.health = None;
                operation.updated_at_unix_secs = now;
                operation.deadline_unix_secs = now.saturating_add(OPERATION_TIMEOUT_SECONDS);
            }
            continue;
        }
        if operation.phase.terminal() {
            continue;
        }
        if now >= operation.deadline_unix_secs {
            operation.phase = ManagedOperationPhase::Failed;
            operation.reason_code = Some(ManagedOperationReason::OperationTimeout);
            operation.active_lease = None;
            operation.updated_at_unix_secs = now;
            continue;
        }
        if let Some(lease) = operation
            .active_lease
            .as_ref()
            .filter(|lease| lease.expires_at_unix_secs <= now)
        {
            operation.phase = ManagedOperationPhase::pending(lease.phase);
            operation.reason_code = Some(ManagedOperationReason::LeaseExpired);
            operation.active_lease = None;
            operation.updated_at_unix_secs = now;
        }
    }
}

fn same_slot(operation: &ManagedOperationRecord, request: &ManagedOperationReadyV1) -> bool {
    operation.host_ref == request.host_ref
        && operation.service_ref == request.service_ref
        && operation.slot_ref == request.slot_ref
}

fn prune_terminal_history(document: &mut ManagedOperationDocument) {
    let mut latest_by_slot: BTreeMap<(&str, &str, &str), (u64, i64, &str)> = BTreeMap::new();
    for operation in document.operations.values() {
        let slot = (
            operation.host_ref.as_str(),
            operation.service_ref.as_str(),
            operation.slot_ref.as_str(),
        );
        let candidate = (
            operation.generation,
            operation.created_at_unix_secs,
            operation.operation_ref.as_str(),
        );
        if latest_by_slot
            .get(&slot)
            .is_none_or(|current| candidate > *current)
        {
            latest_by_slot.insert(slot, candidate);
        }
    }
    let retained: BTreeSet<String> = latest_by_slot
        .values()
        .map(|(_, _, operation_ref)| (*operation_ref).to_string())
        .collect();
    document.operations.retain(|operation_ref, operation| {
        !operation.phase.terminal() || retained.contains(operation_ref)
    });
}

fn record_matches_ready(
    operation: &ManagedOperationRecord,
    request: &ManagedOperationReadyV1,
    slot: &ManagedSecretSlotDeclarationV1,
) -> bool {
    operation.operation_kind == request.operation_kind
        && operation.host_ref == request.host_ref
        && operation.service_ref == request.service_ref
        && operation.slot_ref == request.slot_ref
        && operation.declaration_fingerprint == request.declaration_fingerprint
        && operation.generation == request.generation
        && operation.delivery_profile_ref == slot.delivery.profile_ref
        && operation.reload_profile_ref == slot.reload.profile_ref
        && operation.health_profile_ref == slot.health.profile_ref
}

fn result_hash(request: &ManagedOperationResultV1) -> Result<String, ManagedOperationStoreError> {
    let raw =
        serde_json::to_vec(request).map_err(|_| ManagedOperationStoreError::InvalidRequest)?;
    Ok(format!("{:x}", Sha256::digest(raw)))
}

fn random_ref(prefix: &str) -> Result<String, getrandom::Error> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random)?;
    let mut output = String::with_capacity(prefix.len() + random.len() * 2);
    output.push_str(prefix);
    for byte in random {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    Ok(output)
}

fn validate_document(document: &ManagedOperationDocument) -> Result<(), String> {
    if document.schema != STORE_SCHEMA
        || document.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
        || document.operations.len() > MAX_OPERATIONS
    {
        return Err("managed operation store contract is invalid".to_string());
    }
    for (reference, operation) in &document.operations {
        if reference != &operation.operation_ref
            || operation.schema != RECORD_SCHEMA
            || operation.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
            || !valid_ref("op_", &operation.operation_ref)
            || !valid_ref("host_", &operation.host_ref)
            || !valid_ref("svc_", &operation.service_ref)
            || !valid_ref("slot_", &operation.slot_ref)
            || !valid_ref("decl_", &operation.declaration_fingerprint)
            || !valid_ref("delivery_", &operation.delivery_profile_ref)
            || !valid_ref("reload_", &operation.reload_profile_ref)
            || !valid_ref("health_", &operation.health_profile_ref)
            || operation.generation == 0
            || operation.created_at_unix_secs <= 0
            || operation.updated_at_unix_secs < operation.created_at_unix_secs
            || operation.deadline_unix_secs <= operation.created_at_unix_secs
            || operation.uncertain_attempts > MAX_UNCERTAIN_ATTEMPTS
            || operation.phase.leased_agent_phase().is_some() != operation.active_lease.is_some()
            || operation.phase == ManagedOperationPhase::Active && operation.health.is_none()
            || operation.phase != ManagedOperationPhase::Active && operation.health.is_some()
            || !persisted_health_is_consistent(operation)
            || operation
                .last_result_sha256
                .as_ref()
                .is_some_and(|hash| !valid_sha256(hash))
        {
            return Err("managed operation store record is invalid".to_string());
        }
        if let Some(lease) = &operation.active_lease {
            if !valid_ref("lease_", &lease.lease_ref)
                || operation.phase.leased_agent_phase() != Some(lease.phase)
                || lease.leased_at_unix_secs <= 0
                || lease.expires_at_unix_secs <= lease.leased_at_unix_secs
            {
                return Err("managed operation store lease is invalid".to_string());
            }
        }
    }
    Ok(())
}

fn persisted_health_is_consistent(operation: &ManagedOperationRecord) -> bool {
    let Some(health) = operation.health.as_ref() else {
        return operation.phase != ManagedOperationPhase::Active;
    };
    let (Some(delivered_at), Some(reloaded_at)) = (
        operation.delivery_completed_at_unix_secs,
        operation.reload_completed_at_unix_secs,
    ) else {
        return false;
    };
    operation.phase == ManagedOperationPhase::Active
        && operation.reason_code == Some(ManagedOperationReason::PhaseSucceeded)
        && health.generation == operation.generation
        && health.accepted_at_unix_secs >= operation.created_at_unix_secs
        && [
            health.heartbeat_observed_at_unix_secs,
            health.process_observed_at_unix_secs,
            health.probe_observed_at_unix_secs,
        ]
        .iter()
        .all(|observed| *observed >= delivered_at && *observed >= reloaded_at)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use pharos_core::managed_operations::{
        ManagedOperationAgentOutcome, ManagedOperationClaimV1, ManagedOperationResultV1,
        ManagedProbeState, ManagedProcessState, MANAGED_OPERATION_CLAIM_SCHEMA,
        MANAGED_OPERATION_READY_SCHEMA, MANAGED_OPERATION_RESULT_SCHEMA,
    };
    use pharos_core::managed_services::ManagedServiceManifestV1;

    const NOW: i64 = 1_800_000_000;
    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn test_store_path(label: &str) -> PathBuf {
        let sequence = TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "pharos-managed-operation-{label}-{}-{sequence}.json",
            std::process::id()
        ))
    }

    fn fixture() -> ManagedServiceManifestV1 {
        serde_json::from_str(include_str!(
            "../../../contracts/managed-service-declarations-v1.json"
        ))
        .unwrap()
    }

    fn ready(operation_ref: &str, generation: u64) -> ManagedOperationReadyV1 {
        ManagedOperationReadyV1 {
            schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            operation_ref: operation_ref.to_string(),
            operation_kind: ManagedOperationKind::Create,
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint:
                "decl_1e0775870c7d987ec744b94ec096d7f8985aae059248856ebcf1d9a52bacbc2e".to_string(),
            generation,
            value_returned: false,
        }
    }

    fn result(
        lease: &ManagedOperationLeaseV1,
        outcome: ManagedOperationAgentOutcome,
        reason: ManagedOperationReason,
    ) -> ManagedOperationResultV1 {
        ManagedOperationResultV1 {
            schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: lease.lease_ref.clone(),
            operation_ref: lease.operation_ref.clone(),
            host_ref: lease.host_ref.clone(),
            phase: lease.phase,
            outcome,
            reason_code: reason,
            generation: lease.generation,
            health_evidence: None,
            value_returned: false,
        }
    }

    #[test]
    fn exact_fixed_phases_require_fresh_composite_generation_evidence() {
        let store = ManagedServiceOperationStore::new(None).unwrap();
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        store.register(&ready("op_00000001", 1), slot, NOW).unwrap();

        let install = store.claim(&manifest.host_ref, NOW + 1).unwrap().unwrap();
        assert_eq!(install.phase, ManagedOperationAgentPhase::Install);
        assert_eq!(install.profile_ref, slot.delivery.profile_ref);
        store
            .record_result(
                &result(
                    &install,
                    ManagedOperationAgentOutcome::Succeeded,
                    ManagedOperationReason::PhaseSucceeded,
                ),
                NOW + 2,
            )
            .unwrap();

        let reload = store.claim(&manifest.host_ref, NOW + 3).unwrap().unwrap();
        assert_eq!(reload.phase, ManagedOperationAgentPhase::Reload);
        assert_eq!(reload.profile_ref, slot.reload.profile_ref);
        store
            .record_result(
                &result(
                    &reload,
                    ManagedOperationAgentOutcome::Succeeded,
                    ManagedOperationReason::PhaseSucceeded,
                ),
                NOW + 4,
            )
            .unwrap();

        let first_verify = store.claim(&manifest.host_ref, NOW + 5).unwrap().unwrap();
        assert_eq!(first_verify.phase, ManagedOperationAgentPhase::Verify);
        let retryable = store
            .record_result(
                &result(
                    &first_verify,
                    ManagedOperationAgentOutcome::Uncertain,
                    ManagedOperationReason::ExecutorFailed,
                ),
                NOW + 6,
            )
            .unwrap();
        assert_eq!(retryable.phase, ManagedOperationPhase::VerifyPending);

        let verify = store.claim(&manifest.host_ref, NOW + 7).unwrap().unwrap();
        let mut verified = result(
            &verify,
            ManagedOperationAgentOutcome::Succeeded,
            ManagedOperationReason::PhaseSucceeded,
        );
        verified.health_evidence = Some(ManagedHealthEvidenceV1 {
            generation: 1,
            materialized: true,
            process_state: ManagedProcessState::Running,
            probe_state: ManagedProbeState::Healthy,
            heartbeat_observed_at_unix_secs: NOW + 7,
            process_observed_at_unix_secs: NOW + 7,
            probe_observed_at_unix_secs: NOW + 7,
        });
        let active = store.record_result(&verified, NOW + 8).unwrap();
        assert_eq!(active.phase, ManagedOperationPhase::Active);
        assert_eq!(active.health.unwrap().generation, 1);
        assert!(!active.value_returned);

        let stale = store
            .latest_for_slot(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &slot.slot_ref,
                NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 8,
            )
            .unwrap();
        assert_eq!(stale.phase, ManagedOperationPhase::VerifyPending);
        assert_eq!(
            stale.reason_code,
            Some(ManagedOperationReason::EvidenceStale)
        );
        assert!(stale.health.is_none());

        let refresh = store
            .claim(
                &manifest.host_ref,
                NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 9,
            )
            .unwrap()
            .unwrap();
        assert_eq!(refresh.phase, ManagedOperationAgentPhase::Verify);
        let mut refreshed = result(
            &refresh,
            ManagedOperationAgentOutcome::Succeeded,
            ManagedOperationReason::PhaseSucceeded,
        );
        refreshed.health_evidence = Some(ManagedHealthEvidenceV1 {
            generation: 1,
            materialized: true,
            process_state: ManagedProcessState::Running,
            probe_state: ManagedProbeState::Healthy,
            heartbeat_observed_at_unix_secs: NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 9,
            process_observed_at_unix_secs: NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 9,
            probe_observed_at_unix_secs: NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 9,
        });
        assert_eq!(
            store
                .record_result(&refreshed, NOW + HEALTH_EVIDENCE_MAX_AGE_SECONDS + 10)
                .unwrap()
                .phase,
            ManagedOperationPhase::Active
        );
    }

    #[test]
    fn stale_heartbeat_http_only_and_old_generation_cannot_fabricate_active() {
        let store = ManagedServiceOperationStore::new(None).unwrap();
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        store.register(&ready("op_00000002", 1), slot, NOW).unwrap();
        for expected in [
            ManagedOperationAgentPhase::Install,
            ManagedOperationAgentPhase::Reload,
        ] {
            let lease = store.claim(&manifest.host_ref, NOW + 1).unwrap().unwrap();
            assert_eq!(lease.phase, expected);
            store
                .record_result(
                    &result(
                        &lease,
                        ManagedOperationAgentOutcome::Succeeded,
                        ManagedOperationReason::PhaseSucceeded,
                    ),
                    NOW + 2,
                )
                .unwrap();
        }
        let verify = store.claim(&manifest.host_ref, NOW + 3).unwrap().unwrap();
        let mut stale = result(
            &verify,
            ManagedOperationAgentOutcome::Succeeded,
            ManagedOperationReason::PhaseSucceeded,
        );
        stale.health_evidence = Some(ManagedHealthEvidenceV1 {
            generation: 1,
            materialized: true,
            process_state: ManagedProcessState::Running,
            probe_state: ManagedProbeState::Healthy,
            heartbeat_observed_at_unix_secs: NOW - 500,
            process_observed_at_unix_secs: NOW + 3,
            probe_observed_at_unix_secs: NOW + 3,
        });
        assert_eq!(
            store.record_result(&stale, NOW + 4),
            Err(ManagedOperationStoreError::InvalidEvidence)
        );

        let mut old_generation = stale;
        old_generation.health_evidence.as_mut().unwrap().generation = 9;
        old_generation
            .health_evidence
            .as_mut()
            .unwrap()
            .heartbeat_observed_at_unix_secs = NOW + 3;
        assert_eq!(
            store.record_result(&old_generation, NOW + 4),
            Err(ManagedOperationStoreError::InvalidEvidence)
        );
    }

    #[test]
    fn lease_expiry_uncertain_retry_duplicate_and_supersede_are_recoverable() {
        let store = ManagedServiceOperationStore::new(None).unwrap();
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        store.register(&ready("op_00000003", 1), slot, NOW).unwrap();
        let expired = store.claim(&manifest.host_ref, NOW + 1).unwrap().unwrap();
        assert_eq!(
            store.record_result(
                &result(
                    &expired,
                    ManagedOperationAgentOutcome::Succeeded,
                    ManagedOperationReason::PhaseSucceeded,
                ),
                expired.expires_at_unix_secs
            ),
            Err(ManagedOperationStoreError::LeaseExpired)
        );
        let retried = store
            .claim(&manifest.host_ref, expired.expires_at_unix_secs + 1)
            .unwrap()
            .unwrap();
        let uncertain = result(
            &retried,
            ManagedOperationAgentOutcome::Uncertain,
            ManagedOperationReason::ExecutorFailed,
        );
        let pending = store
            .record_result(&uncertain, retried.leased_at_unix_secs + 1)
            .unwrap();
        assert_eq!(pending.phase, ManagedOperationPhase::InstallPending);

        let final_lease = store
            .claim(&manifest.host_ref, retried.leased_at_unix_secs + 2)
            .unwrap()
            .unwrap();
        let success = result(
            &final_lease,
            ManagedOperationAgentOutcome::Succeeded,
            ManagedOperationReason::PhaseSucceeded,
        );
        let first = store
            .record_result(&success, final_lease.leased_at_unix_secs + 1)
            .unwrap();
        let duplicate = store
            .record_result(&success, final_lease.leased_at_unix_secs + 2)
            .unwrap();
        assert_eq!(first, duplicate);

        store
            .register(
                &ready("op_00000004", 2),
                slot,
                final_lease.leased_at_unix_secs + 3,
            )
            .unwrap();
        let old = store
            .latest_for_slot(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &slot.slot_ref,
                final_lease.leased_at_unix_secs + 4,
            )
            .unwrap();
        assert_eq!(old.operation_ref, "op_00000004");
        assert_eq!(old.generation, 2);
    }

    #[test]
    fn claim_contract_is_closed_and_value_free() {
        let claim = ManagedOperationClaimV1 {
            schema: MANAGED_OPERATION_CLAIM_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            host_ref: "host_58f36c72a91e".to_string(),
        };
        claim.validate_contract().unwrap();
        let mut raw = serde_json::to_value(claim).unwrap();
        raw["command"] = serde_json::json!("forbidden");
        assert!(serde_json::from_value::<ManagedOperationClaimV1>(raw).is_err());
    }

    #[test]
    fn explicit_reload_failure_and_bounded_uncertainty_stop_safely() {
        let store = ManagedServiceOperationStore::new(None).unwrap();
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        store.register(&ready("op_00000007", 1), slot, NOW).unwrap();
        let install = store.claim(&manifest.host_ref, NOW + 1).unwrap().unwrap();
        store
            .record_result(
                &result(
                    &install,
                    ManagedOperationAgentOutcome::Succeeded,
                    ManagedOperationReason::PhaseSucceeded,
                ),
                NOW + 2,
            )
            .unwrap();
        let reload = store.claim(&manifest.host_ref, NOW + 3).unwrap().unwrap();
        let failed = store
            .record_result(
                &result(
                    &reload,
                    ManagedOperationAgentOutcome::Failed,
                    ManagedOperationReason::ReloadFailed,
                ),
                NOW + 4,
            )
            .unwrap();
        assert_eq!(failed.phase, ManagedOperationPhase::Failed);
        assert_eq!(
            failed.reason_code,
            Some(ManagedOperationReason::ReloadFailed)
        );

        store
            .register(&ready("op_00000008", 2), slot, NOW + 5)
            .unwrap();
        for attempt in 1..=MAX_UNCERTAIN_ATTEMPTS {
            let lease = store
                .claim(&manifest.host_ref, NOW + 5 + i64::from(attempt) * 2)
                .unwrap()
                .unwrap();
            let summary = store
                .record_result(
                    &result(
                        &lease,
                        ManagedOperationAgentOutcome::Uncertain,
                        ManagedOperationReason::ExecutorFailed,
                    ),
                    NOW + 6 + i64::from(attempt) * 2,
                )
                .unwrap();
            assert_eq!(
                summary.phase,
                if attempt < MAX_UNCERTAIN_ATTEMPTS {
                    ManagedOperationPhase::InstallPending
                } else {
                    ManagedOperationPhase::Failed
                }
            );
        }
        assert!(store.claim(&manifest.host_ref, NOW + 20).unwrap().is_none());

        store
            .register(&ready("op_00000009", 3), slot, NOW + 21)
            .unwrap();
        let document = store.document.lock().unwrap();
        assert_eq!(document.operations.len(), 2);
        assert!(!document.operations.contains_key("op_00000007"));
        assert!(document.operations.contains_key("op_00000008"));
        assert!(document.operations.contains_key("op_00000009"));
    }

    #[test]
    fn durable_state_survives_restart_and_contains_only_safe_metadata() {
        let path = test_store_path("restart");
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        {
            let store = ManagedServiceOperationStore::new(Some(path.clone())).unwrap();
            store.register(&ready("op_00000005", 1), slot, NOW).unwrap();
            let lease = store.claim(&manifest.host_ref, NOW + 1).unwrap().unwrap();
            store
                .record_result(
                    &result(
                        &lease,
                        ManagedOperationAgentOutcome::Succeeded,
                        ManagedOperationReason::PhaseSucceeded,
                    ),
                    NOW + 2,
                )
                .unwrap();
        }

        let raw = fs::read_to_string(&path).unwrap();
        for forbidden in [
            "secret_value",
            "ciphertext",
            "private_key",
            "permit",
            "runtime_path",
            "command",
            "stdout",
            "stderr",
        ] {
            assert!(
                !raw.contains(forbidden),
                "persisted forbidden field {forbidden}"
            );
        }
        let restarted = ManagedServiceOperationStore::new(Some(path.clone())).unwrap();
        let operation = restarted
            .latest_for_slot(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &slot.slot_ref,
                NOW + 3,
            )
            .unwrap();
        assert_eq!(operation.phase, ManagedOperationPhase::ReloadPending);
        assert_eq!(operation.operation_ref, "op_00000005");

        fs::remove_file(path).unwrap();
    }

    #[test]
    fn startup_rejects_unknown_persisted_fields_and_timeout_never_claims_work() {
        let corrupt = test_store_path("corrupt");
        fs::write(
            &corrupt,
            r#"{"schema":"inspr.pharos.managed-service-operation-store.v1","schema_version":1,"operations":{},"secret":"forbidden"}"#,
        )
        .unwrap();
        assert!(ManagedServiceOperationStore::new(Some(corrupt.clone())).is_err());
        fs::remove_file(corrupt).unwrap();

        let store = ManagedServiceOperationStore::new(None).unwrap();
        let manifest = fixture();
        let slot = &manifest.services[0].slots[0];
        store.register(&ready("op_00000006", 1), slot, NOW).unwrap();
        assert!(store
            .claim(&manifest.host_ref, NOW + OPERATION_TIMEOUT_SECONDS)
            .unwrap()
            .is_none());
        let timed_out = store
            .latest_for_slot(
                &manifest.host_ref,
                &manifest.services[0].service_ref,
                &slot.slot_ref,
                NOW + OPERATION_TIMEOUT_SECONDS,
            )
            .unwrap();
        assert_eq!(timed_out.phase, ManagedOperationPhase::Failed);
        assert_eq!(
            timed_out.reason_code,
            Some(ManagedOperationReason::OperationTimeout)
        );
        assert!(timed_out.health.is_none());
    }
}
