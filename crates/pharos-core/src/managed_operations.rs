//! Value-free contracts for fixed managed-service secret orchestration.
//!
//! Pharos coordinates declared work without carrying secret values, encrypted
//! envelopes, host keys, permits, private paths, commands, or command output.

use serde::{Deserialize, Serialize};

pub const MANAGED_OPERATION_READY_SCHEMA: &str = "inspr.janus.managed-service-operation-ready.v1";
pub const MANAGED_OPERATION_CLAIM_SCHEMA: &str = "inspr.pharos.managed-service-operation-claim.v1";
pub const MANAGED_OPERATION_LEASE_SCHEMA: &str = "inspr.pharos.managed-service-operation-lease.v1";
pub const MANAGED_OPERATION_RESULT_SCHEMA: &str =
    "inspr.pharos.managed-service-operation-result.v1";
pub const MANAGED_OPERATION_CONTRACT_VERSION: u16 = 1;
pub const MAX_MANAGED_OPERATION_REQUEST_BYTES: usize = 8 * 1024;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationKind {
    Create,
    Replace,
    Remove,
}

fn default_managed_operation_kind() -> ManagedOperationKind {
    ManagedOperationKind::Create
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationAgentPhase {
    Install,
    Reload,
    Verify,
    Remove,
}

impl ManagedOperationAgentPhase {
    pub fn profile_prefix(self) -> &'static str {
        match self {
            Self::Install => "delivery_",
            Self::Reload => "reload_",
            Self::Verify => "health_",
            Self::Remove => "detach_",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationAgentOutcome {
    Succeeded,
    Failed,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationReason {
    PhaseSucceeded,
    DeliveryFailed,
    ReloadFailed,
    ReloadUncertain,
    VerificationFailed,
    ExecutorFailed,
    EvidenceStale,
    HeartbeatStale,
    GenerationMismatch,
    LeaseExpired,
    OperationTimeout,
    OperationSuperseded,
    RemovalFailed,
    RemovalUncertain,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProcessState {
    Running,
    Stopped,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProbeState {
    Healthy,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedCacheState {
    Quarantined,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedOperationReadyV1 {
    pub schema: String,
    pub schema_version: u16,
    pub operation_ref: String,
    pub operation_kind: ManagedOperationKind,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_not_before_unix_secs: Option<i64>,
    pub value_returned: bool,
}

impl ManagedOperationReadyV1 {
    pub fn validate_contract(&self) -> Result<(), &'static str> {
        if self.schema != MANAGED_OPERATION_READY_SCHEMA
            || self.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
            || !valid_ref("op_", &self.operation_ref)
            || !valid_ref("host_", &self.host_ref)
            || !valid_ref("svc_", &self.service_ref)
            || !valid_ref("slot_", &self.slot_ref)
            || !valid_ref("decl_", &self.declaration_fingerprint)
            || self.generation == 0
            || match self.operation_kind {
                ManagedOperationKind::Remove => self
                    .purge_not_before_unix_secs
                    .is_none_or(|deadline| deadline <= 0),
                ManagedOperationKind::Create | ManagedOperationKind::Replace => {
                    self.purge_not_before_unix_secs.is_some()
                }
            }
            || self.value_returned
        {
            return Err("managed_operation_ready_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedOperationClaimV1 {
    pub schema: String,
    pub schema_version: u16,
    pub host_ref: String,
}

impl ManagedOperationClaimV1 {
    pub fn validate_contract(&self) -> Result<(), &'static str> {
        if self.schema != MANAGED_OPERATION_CLAIM_SCHEMA
            || self.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
            || !valid_ref("host_", &self.host_ref)
        {
            return Err("managed_operation_claim_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedOperationLeaseV1 {
    pub schema: String,
    pub schema_version: u16,
    pub lease_ref: String,
    pub operation_ref: String,
    #[serde(default = "default_managed_operation_kind")]
    pub operation_kind: ManagedOperationKind,
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purge_not_before_unix_secs: Option<i64>,
    pub phase: ManagedOperationAgentPhase,
    pub profile_ref: String,
    pub leased_at_unix_secs: i64,
    pub expires_at_unix_secs: i64,
    pub value_returned: bool,
}

impl ManagedOperationLeaseV1 {
    pub fn validate_contract(&self) -> Result<(), &'static str> {
        if self.schema != MANAGED_OPERATION_LEASE_SCHEMA
            || self.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
            || !valid_ref("lease_", &self.lease_ref)
            || !valid_ref("op_", &self.operation_ref)
            || !valid_ref("host_", &self.host_ref)
            || !valid_ref("svc_", &self.service_ref)
            || !valid_ref("slot_", &self.slot_ref)
            || !valid_ref("decl_", &self.declaration_fingerprint)
            || !valid_ref(self.phase.profile_prefix(), &self.profile_ref)
            || self.generation == 0
            || match self.operation_kind {
                ManagedOperationKind::Remove => self
                    .purge_not_before_unix_secs
                    .is_none_or(|deadline| deadline <= self.expires_at_unix_secs),
                ManagedOperationKind::Create | ManagedOperationKind::Replace => {
                    self.purge_not_before_unix_secs.is_some()
                }
            }
            || self.leased_at_unix_secs <= 0
            || self.expires_at_unix_secs <= self.leased_at_unix_secs
            || self.value_returned
        {
            return Err("managed_operation_lease_invalid");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedHealthEvidenceV1 {
    pub generation: u64,
    pub materialized: bool,
    pub process_state: ManagedProcessState,
    pub probe_state: ManagedProbeState,
    pub heartbeat_observed_at_unix_secs: i64,
    pub process_observed_at_unix_secs: i64,
    pub probe_observed_at_unix_secs: i64,
}

/// Fresh proof that a failed replacement restored the prior generation.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRollbackEvidenceV1 {
    pub restored_generation: u64,
    pub materialized: bool,
    pub process_state: ManagedProcessState,
    pub probe_state: ManagedProbeState,
    pub heartbeat_observed_at_unix_secs: i64,
    pub process_observed_at_unix_secs: i64,
    pub probe_observed_at_unix_secs: i64,
}

/// Fresh proof that the detached service stopped and its private material is
/// absent from the active host paths while ciphertext remains recoverable.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedRemovalEvidenceV1 {
    pub generation: u64,
    pub runtime_absent: bool,
    pub process_state: ManagedProcessState,
    pub cache_state: ManagedCacheState,
    pub heartbeat_observed_at_unix_secs: i64,
    pub process_observed_at_unix_secs: i64,
    pub cache_observed_at_unix_secs: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ManagedOperationResultV1 {
    pub schema: String,
    pub schema_version: u16,
    pub lease_ref: String,
    pub operation_ref: String,
    pub host_ref: String,
    pub phase: ManagedOperationAgentPhase,
    pub outcome: ManagedOperationAgentOutcome,
    pub reason_code: ManagedOperationReason,
    pub generation: u64,
    pub health_evidence: Option<ManagedHealthEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_evidence: Option<ManagedRollbackEvidenceV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removal_evidence: Option<ManagedRemovalEvidenceV1>,
    pub value_returned: bool,
}

impl ManagedOperationResultV1 {
    pub fn validate_contract(&self) -> Result<(), &'static str> {
        if self.schema != MANAGED_OPERATION_RESULT_SCHEMA
            || self.schema_version != MANAGED_OPERATION_CONTRACT_VERSION
            || !valid_ref("lease_", &self.lease_ref)
            || !valid_ref("op_", &self.operation_ref)
            || !valid_ref("host_", &self.host_ref)
            || self.generation == 0
            || self.value_returned
            || (self.outcome == ManagedOperationAgentOutcome::Succeeded
                && self.reason_code != ManagedOperationReason::PhaseSucceeded)
            || (self.outcome != ManagedOperationAgentOutcome::Succeeded
                && self.reason_code == ManagedOperationReason::PhaseSucceeded)
            || (self.outcome != ManagedOperationAgentOutcome::Succeeded
                && !agent_reason_matches_phase(self.phase, self.reason_code))
            || (self.phase != ManagedOperationAgentPhase::Verify && self.health_evidence.is_some())
            || (self.outcome != ManagedOperationAgentOutcome::Succeeded
                && self.health_evidence.is_some())
            || self.rollback_evidence.as_ref().is_some_and(|evidence| {
                self.outcome != ManagedOperationAgentOutcome::Failed
                    || evidence.restored_generation == 0
                    || evidence.restored_generation >= self.generation
                    || !evidence.materialized
                    || evidence.heartbeat_observed_at_unix_secs <= 0
                    || evidence.process_observed_at_unix_secs <= 0
                    || evidence.probe_observed_at_unix_secs <= 0
            })
            || self.outcome != ManagedOperationAgentOutcome::Failed
                && self.rollback_evidence.is_some()
            || self.removal_evidence.as_ref().is_some_and(|evidence| {
                self.phase != ManagedOperationAgentPhase::Remove
                    || self.outcome != ManagedOperationAgentOutcome::Succeeded
                    || evidence.generation != self.generation
                    || !evidence.runtime_absent
                    || evidence.process_state != ManagedProcessState::Stopped
                    || evidence.cache_state != ManagedCacheState::Quarantined
                    || evidence.heartbeat_observed_at_unix_secs <= 0
                    || evidence.process_observed_at_unix_secs <= 0
                    || evidence.cache_observed_at_unix_secs <= 0
            })
            || self.phase == ManagedOperationAgentPhase::Remove
                && self.outcome == ManagedOperationAgentOutcome::Succeeded
                && self.removal_evidence.is_none()
            || self.phase != ManagedOperationAgentPhase::Remove && self.removal_evidence.is_some()
        {
            return Err("managed_operation_result_invalid");
        }
        Ok(())
    }
}

fn agent_reason_matches_phase(
    phase: ManagedOperationAgentPhase,
    reason: ManagedOperationReason,
) -> bool {
    match phase {
        ManagedOperationAgentPhase::Install => matches!(
            reason,
            ManagedOperationReason::DeliveryFailed | ManagedOperationReason::ExecutorFailed
        ),
        ManagedOperationAgentPhase::Reload => matches!(
            reason,
            ManagedOperationReason::ReloadFailed
                | ManagedOperationReason::ReloadUncertain
                | ManagedOperationReason::ExecutorFailed
        ),
        ManagedOperationAgentPhase::Verify => matches!(
            reason,
            ManagedOperationReason::VerificationFailed
                | ManagedOperationReason::EvidenceStale
                | ManagedOperationReason::HeartbeatStale
                | ManagedOperationReason::GenerationMismatch
                | ManagedOperationReason::ExecutorFailed
        ),
        ManagedOperationAgentPhase::Remove => matches!(
            reason,
            ManagedOperationReason::RemovalFailed
                | ManagedOperationReason::RemovalUncertain
                | ManagedOperationReason::ExecutorFailed
        ),
    }
}

pub fn valid_ref(prefix: &str, value: &str) -> bool {
    value.len() >= prefix.len() + 8
        && value.len() <= 96
        && value.starts_with(prefix)
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result() -> ManagedOperationResultV1 {
        ManagedOperationResultV1 {
            schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: "lease_49c0e8a17d63".to_string(),
            operation_ref: "op_58f36c72a91e".to_string(),
            host_ref: "host_58f36c72a91e".to_string(),
            phase: ManagedOperationAgentPhase::Install,
            outcome: ManagedOperationAgentOutcome::Succeeded,
            reason_code: ManagedOperationReason::PhaseSucceeded,
            generation: 1,
            health_evidence: None,
            rollback_evidence: None,
            removal_evidence: None,
            value_returned: false,
        }
    }

    #[test]
    fn fixed_contracts_are_value_free_and_phase_profile_bound() {
        let lease = ManagedOperationLeaseV1 {
            schema: MANAGED_OPERATION_LEASE_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: "lease_49c0e8a17d63".to_string(),
            operation_ref: "op_58f36c72a91e".to_string(),
            operation_kind: ManagedOperationKind::Create,
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint: "decl_a84f209c4b32".to_string(),
            generation: 1,
            purge_not_before_unix_secs: None,
            phase: ManagedOperationAgentPhase::Install,
            profile_ref: "delivery_2d7a0f63c951".to_string(),
            leased_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_000_060,
            value_returned: false,
        };
        lease.validate_contract().unwrap();
        let serialized = serde_json::to_string(&lease).unwrap();
        for forbidden in [
            "secret",
            "ciphertext",
            "permit",
            "private_key",
            "command",
            "path",
            "stdout",
            "stderr",
        ] {
            assert!(!serialized.contains(forbidden), "found {forbidden}");
        }

        let mut previous_lease = serde_json::to_value(&lease).unwrap();
        previous_lease
            .as_object_mut()
            .unwrap()
            .remove("operation_kind");
        assert_eq!(
            serde_json::from_value::<ManagedOperationLeaseV1>(previous_lease)
                .unwrap()
                .operation_kind,
            ManagedOperationKind::Create
        );
    }

    #[test]
    fn result_rejects_output_shapes_and_health_on_non_verify_phases() {
        result().validate_contract().unwrap();
        let previous_result = serde_json::to_value(result()).unwrap();
        assert!(
            previous_result
                .as_object()
                .unwrap()
                .get("rollback_evidence")
                .is_none(),
            "empty replacement-only evidence must not break an older create peer"
        );
        serde_json::from_value::<ManagedOperationResultV1>(previous_result)
            .unwrap()
            .validate_contract()
            .unwrap();
        let mut with_health = result();
        with_health.health_evidence = Some(ManagedHealthEvidenceV1 {
            generation: 1,
            materialized: true,
            process_state: ManagedProcessState::Running,
            probe_state: ManagedProbeState::Healthy,
            heartbeat_observed_at_unix_secs: 1,
            process_observed_at_unix_secs: 1,
            probe_observed_at_unix_secs: 1,
        });
        assert!(with_health.validate_contract().is_err());

        let raw = serde_json::to_value(result()).unwrap();
        let mut object = raw.as_object().unwrap().clone();
        object.insert("stdout".to_string(), serde_json::json!("canary"));
        assert!(
            serde_json::from_value::<ManagedOperationResultV1>(serde_json::Value::Object(object))
                .is_err()
        );

        let mut wrong_phase_reason = result();
        wrong_phase_reason.outcome = ManagedOperationAgentOutcome::Failed;
        wrong_phase_reason.reason_code = ManagedOperationReason::ReloadFailed;
        assert!(wrong_phase_reason.validate_contract().is_err());

        wrong_phase_reason.reason_code = ManagedOperationReason::DeliveryFailed;
        wrong_phase_reason.validate_contract().unwrap();
    }

    #[test]
    fn removal_requires_a_recovery_deadline_and_exact_absence_evidence() {
        let lease = ManagedOperationLeaseV1 {
            schema: MANAGED_OPERATION_LEASE_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: "lease_49c0e8a17d63".to_string(),
            operation_ref: "op_58f36c72a91e".to_string(),
            operation_kind: ManagedOperationKind::Remove,
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint: "decl_a84f209c4b32".to_string(),
            generation: 3,
            purge_not_before_unix_secs: Some(1_800_086_400),
            phase: ManagedOperationAgentPhase::Remove,
            profile_ref: "detach_2d7a0f63c951".to_string(),
            leased_at_unix_secs: 1_800_000_000,
            expires_at_unix_secs: 1_800_000_060,
            value_returned: false,
        };
        lease.validate_contract().unwrap();

        let mut removal = ManagedOperationResultV1 {
            schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: lease.lease_ref.clone(),
            operation_ref: lease.operation_ref.clone(),
            host_ref: lease.host_ref.clone(),
            phase: ManagedOperationAgentPhase::Remove,
            outcome: ManagedOperationAgentOutcome::Succeeded,
            reason_code: ManagedOperationReason::PhaseSucceeded,
            generation: lease.generation,
            health_evidence: None,
            rollback_evidence: None,
            removal_evidence: Some(ManagedRemovalEvidenceV1 {
                generation: lease.generation,
                runtime_absent: true,
                process_state: ManagedProcessState::Stopped,
                cache_state: ManagedCacheState::Quarantined,
                heartbeat_observed_at_unix_secs: 1_800_000_010,
                process_observed_at_unix_secs: 1_800_000_010,
                cache_observed_at_unix_secs: 1_800_000_010,
            }),
            value_returned: false,
        };
        removal.validate_contract().unwrap();
        removal.removal_evidence.as_mut().unwrap().runtime_absent = false;
        assert_eq!(
            removal.validate_contract(),
            Err("managed_operation_result_invalid")
        );
    }
}
