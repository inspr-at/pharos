//! Value-free contract for one durable, executable next safe action.
//!
//! The contract deliberately carries only stable identifiers and typed facts.
//! Credentials, command text/output, provider URLs, and transient handles do
//! not have representable fields here.

use serde::{Deserialize, Serialize};

pub(crate) const NEXT_ACTION_SCHEMA: &str = "inspr.pharos.next-action.v1";
pub(crate) const NEXT_ACTION_VERSION: u16 = 1;
pub(crate) const TERMINAL_RECEIPT_SCHEMA: &str = "inspr.pharos.terminal-receipt.v1";
pub(crate) const TERMINAL_RECEIPT_VERSION: u16 = 1;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionOwnerKind {
    Operator,
    Pharos,
    PharosDaemon,
    Nixcfg,
    HostAgent,
    Janus,
    Provider,
    RetirementOwner,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionOwner {
    pub(crate) kind: NextActionOwnerKind,
    /// Stable value-free owner coordinate, such as `host-agent:hsb8`.
    pub(crate) key: String,
    pub(crate) label: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionEffect {
    RecordRequest,
    RepositoryHandoff,
    ReconcileHandoff,
    GuardedReview,
    GuardedConfirmation,
    GuardedApply,
    RuntimeVerification,
    Retirement,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionOperation {
    DispatchSettingsRequest,
    DispatchSystemUpdateProposal,
    DispatchHostRemoval,
    ContinueSettingsRequest,
    RestartSettingsRequest,
    ReconcileRepositoryReceipt,
    AdvanceRepositoryWorkflow,
    ClaimHostReview,
    ConfirmHostChange,
    ClaimHostApply,
    PollHostEvidence,
    RetryHostReview,
    ReconcileHostEvidence,
    ReconcileRetirement,
    RetryCredentialRetirement,
}

impl NextActionOperation {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::DispatchSettingsRequest => "dispatch-settings-request",
            Self::DispatchSystemUpdateProposal => "dispatch-system-update-proposal",
            Self::DispatchHostRemoval => "dispatch-host-removal",
            Self::ContinueSettingsRequest => "continue-settings-request",
            Self::RestartSettingsRequest => "restart-settings-request",
            Self::ReconcileRepositoryReceipt => "reconcile-repository-receipt",
            Self::AdvanceRepositoryWorkflow => "advance-repository-workflow",
            Self::ClaimHostReview => "claim-host-review",
            Self::ConfirmHostChange => "confirm-host-change",
            Self::ClaimHostApply => "claim-host-apply",
            Self::PollHostEvidence => "poll-host-evidence",
            Self::RetryHostReview => "retry-host-review",
            Self::ReconcileHostEvidence => "reconcile-host-evidence",
            Self::ReconcileRetirement => "reconcile-retirement",
            Self::RetryCredentialRetirement => "retry-credential-retirement",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionExecution {
    Automatic,
    OperatorConfirmation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionAvailabilityState {
    Ready,
    Running,
    Scheduled,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionAvailability {
    pub(crate) executable: bool,
    pub(crate) execution: NextActionExecution,
    pub(crate) state: NextActionAvailabilityState,
    pub(crate) operation: NextActionOperation,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum DuplicateActionBehavior {
    ReturnSameRun,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UncertainResponseBehavior {
    ReconcileBeforeRetry,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionIdempotency {
    pub(crate) key: String,
    pub(crate) duplicate: DuplicateActionBehavior,
    pub(crate) uncertain_response: UncertainResponseBehavior,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionTiming {
    pub(crate) since: i64,
    pub(crate) as_of: i64,
    pub(crate) age_secs: i64,
    pub(crate) expected_min_secs: u32,
    pub(crate) expected_max_secs: u32,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum NextActionRecoveryStrategy {
    AutomaticRetry,
    ReconcileBeforeRetry,
    RetrySameRun,
    EscalateToOwner,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionRecovery {
    pub(crate) strategy: NextActionRecoveryStrategy,
    pub(crate) escalation_after_secs: u32,
    pub(crate) escalation_owner: NextActionOwnerKind,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct NextActionDescriptor {
    pub(crate) schema: String,
    pub(crate) version: u16,
    pub(crate) owner: NextActionOwner,
    pub(crate) effect: NextActionEffect,
    pub(crate) availability: NextActionAvailability,
    pub(crate) idempotency: NextActionIdempotency,
    pub(crate) timing: NextActionTiming,
    pub(crate) recovery: NextActionRecovery,
}

pub(crate) struct NextActionDefinition {
    pub(crate) owner: NextActionOwner,
    pub(crate) effect: NextActionEffect,
    pub(crate) operation: NextActionOperation,
    pub(crate) execution: NextActionExecution,
    pub(crate) state: NextActionAvailabilityState,
    pub(crate) expected: (u32, u32),
    pub(crate) recovery: NextActionRecovery,
}

impl NextActionDescriptor {
    pub(crate) fn new(
        run_id: &str,
        since: i64,
        as_of: i64,
        definition: NextActionDefinition,
    ) -> Self {
        Self {
            schema: NEXT_ACTION_SCHEMA.to_string(),
            version: NEXT_ACTION_VERSION,
            owner: definition.owner,
            effect: definition.effect,
            availability: NextActionAvailability {
                executable: true,
                execution: definition.execution,
                state: definition.state,
                operation: definition.operation,
            },
            idempotency: NextActionIdempotency {
                key: format!("{run_id}:{}", definition.operation.key()),
                duplicate: DuplicateActionBehavior::ReturnSameRun,
                uncertain_response: UncertainResponseBehavior::ReconcileBeforeRetry,
            },
            timing: NextActionTiming {
                since,
                as_of: as_of.max(since),
                age_secs: as_of.saturating_sub(since).max(0),
                expected_min_secs: definition.expected.0,
                expected_max_secs: definition.expected.1.max(definition.expected.0),
            },
            recovery: definition.recovery,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalOutcome {
    Succeeded,
    Failed,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum TerminalEvidenceKind {
    RequestRecorded,
    RepositoryAccepted,
    ReviewPassed,
    ConfirmationRecorded,
    HostStateVerified,
    ReportingAccessRevoked,
    DeclarationRemoved,
    CredentialRetired,
    FailureRecorded,
    CancellationRecorded,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalEvidence {
    pub(crate) kind: TerminalEvidenceKind,
    pub(crate) recorded_at: i64,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct TerminalReceipt {
    pub(crate) schema: String,
    pub(crate) version: u16,
    pub(crate) run_id: String,
    pub(crate) outcome: TerminalOutcome,
    pub(crate) completed_at: i64,
    pub(crate) evidence: Vec<TerminalEvidence>,
}

impl TerminalReceipt {
    pub(crate) fn new(
        run_id: &str,
        outcome: TerminalOutcome,
        completed_at: i64,
        evidence: Vec<TerminalEvidence>,
    ) -> Self {
        Self {
            schema: TERMINAL_RECEIPT_SCHEMA.to_string(),
            version: TERMINAL_RECEIPT_VERSION,
            run_id: run_id.to_string(),
            outcome,
            completed_at,
            evidence,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_has_stable_idempotency_and_bounded_age() {
        let descriptor = NextActionDescriptor::new(
            "action-settings-hsb8-100-1",
            100,
            145,
            NextActionDefinition {
                owner: NextActionOwner {
                    kind: NextActionOwnerKind::PharosDaemon,
                    key: "pharos-daemon:evidence".to_string(),
                    label: "Pharos evidence poller".to_string(),
                },
                effect: NextActionEffect::RuntimeVerification,
                operation: NextActionOperation::PollHostEvidence,
                execution: NextActionExecution::Automatic,
                state: NextActionAvailabilityState::Scheduled,
                expected: (10, 30),
                recovery: NextActionRecovery {
                    strategy: NextActionRecoveryStrategy::AutomaticRetry,
                    escalation_after_secs: 60,
                    escalation_owner: NextActionOwnerKind::Pharos,
                },
            },
        );

        assert_eq!(descriptor.timing.age_secs, 45);
        assert_eq!(descriptor.timing.expected_min_secs, 10);
        assert_eq!(descriptor.timing.expected_max_secs, 30);
        assert_eq!(
            descriptor.idempotency.key,
            "action-settings-hsb8-100-1:poll-host-evidence"
        );
        assert!(descriptor.availability.executable);
        assert_eq!(
            descriptor.idempotency.uncertain_response,
            UncertainResponseBehavior::ReconcileBeforeRetry
        );
    }
}
