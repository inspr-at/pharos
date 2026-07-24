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
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedOperationAgentPhase {
    Install,
    Reload,
    Verify,
}

impl ManagedOperationAgentPhase {
    pub fn profile_prefix(self) -> &'static str {
        match self {
            Self::Install => "delivery_",
            Self::Reload => "reload_",
            Self::Verify => "health_",
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
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProcessState {
    Running,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ManagedProbeState {
    Healthy,
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
    pub host_ref: String,
    pub service_ref: String,
    pub slot_ref: String,
    pub declaration_fingerprint: String,
    pub generation: u64,
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
            host_ref: "host_58f36c72a91e".to_string(),
            service_ref: "svc_0bca8d31f7e2".to_string(),
            slot_ref: "slot_49c0e8a17d63".to_string(),
            declaration_fingerprint: "decl_a84f209c4b32".to_string(),
            generation: 1,
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
    }

    #[test]
    fn result_rejects_output_shapes_and_health_on_non_verify_phases() {
        result().validate_contract().unwrap();
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
}
