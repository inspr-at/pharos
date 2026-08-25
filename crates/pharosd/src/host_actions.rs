//! Persistent, value-free state for guarded per-host workflows.
//!
//! Browser requests create review jobs. A host-authenticated, target-local
//! agent may claim only the fixed review/apply phases represented here. This
//! store never carries credentials, permits, commands, Nix paths, or command
//! output.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::RwLock;

use pharos_core::HostPreferences;
use serde::{Deserialize, Serialize};

const ACTION_SCHEMA: &str = "inspr.pharos.host-action.v1";
const ACTION_VERSION: u16 = 1;
const HOST_LIFECYCLE_SCHEMA: &str = "inspr.pharos.host-lifecycle.v1";
const HOST_LIFECYCLE_VERSION: u16 = 1;
const RETIRED_SCHEMA: &str = "inspr.pharos.retired-hosts.v1";
const RETIRED_VERSION: u16 = 2;
const LEASE_SECS: i64 = 180;
const RETIREMENT_LEASE_SECS: i64 = 1800;
const WORKFLOW_SCHEMA: &str = "inspr.pharos.host-workflow.v1";
const WORKFLOW_VERSION: u16 = 2;
static ACTION_COUNTER: AtomicU64 = AtomicU64::new(1);
static PERSIST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionKind {
    SystemUpdateProposal,
    UpdateRestart,
    RemoveHost,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostWorkflowKind {
    SettingsChange,
    SystemUpdateProposal,
    UpdateRestart,
    RemoveHost,
}

impl HostWorkflowKind {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::SettingsChange => "settings_change",
            Self::SystemUpdateProposal => "system_update_proposal",
            Self::UpdateRestart => "update_restart",
            Self::RemoveHost => "remove_host",
        }
    }
}

impl From<HostActionKind> for HostWorkflowKind {
    fn from(kind: HostActionKind) -> Self {
        match kind {
            HostActionKind::SystemUpdateProposal => Self::SystemUpdateProposal,
            HostActionKind::UpdateRestart => Self::UpdateRestart,
            HostActionKind::RemoveHost => Self::RemoveHost,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostRetirementDisposition {
    Destroyed,
    #[default]
    Unmanaged,
    Rebuilt,
}

impl HostRetirementDisposition {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Destroyed => "destroyed",
            Self::Unmanaged => "unmanaged",
            Self::Rebuilt => "rebuilt",
        }
    }

    fn validates_successor(self, host: &str, successor: Option<&str>) -> bool {
        match self {
            Self::Rebuilt => {
                successor.is_some_and(|successor| valid_host_name(successor) && successor != host)
            }
            Self::Destroyed | Self::Unmanaged => successor.is_none(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionState {
    ProposalRequested,
    QueuedReview,
    Reviewing,
    AwaitingConfirmation,
    QueuedApply,
    Applying,
    Rebooting,
    RemovalPending,
    Succeeded,
    Failed,
    Cancelled,
}

impl HostActionState {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::ProposalRequested => "proposal_requested",
            Self::QueuedReview => "queued_review",
            Self::Reviewing => "reviewing",
            Self::AwaitingConfirmation => "awaiting_confirmation",
            Self::QueuedApply => "queued_apply",
            Self::Applying => "applying",
            Self::Rebooting => "rebooting",
            Self::RemovalPending => "removal_pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HostPreferencesState {
    Applied,
    RequestPending,
    DeclaredNotApplied,
}

impl HostPreferencesState {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Applied => "applied",
            Self::RequestPending => "request_pending",
            Self::DeclaredNotApplied => "declared_not_applied",
        }
    }
}

pub(crate) fn host_preferences_state(
    observed: &HostPreferences,
    declared: Option<&HostPreferences>,
    requested: Option<&HostPreferences>,
) -> HostPreferencesState {
    if let Some(requested) = requested {
        if declared.is_some_and(|declared| declared == requested && declared != observed) {
            return HostPreferencesState::DeclaredNotApplied;
        }
        if requested != observed {
            return HostPreferencesState::RequestPending;
        }
    }
    if declared.is_some_and(|declared| declared != observed) {
        HostPreferencesState::DeclaredNotApplied
    } else {
        HostPreferencesState::Applied
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostLifecycleSlot {
    RemoveHost,
    UpdateRestart,
    SettingsChange,
    PrefsDrift,
    KernelDrift,
    SystemUpdateProposal,
    Quiet,
}

impl HostLifecycleSlot {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::RemoveHost => "remove_host",
            Self::UpdateRestart => "update_restart",
            Self::SettingsChange => "settings_change",
            Self::PrefsDrift => "prefs_drift",
            Self::KernelDrift => "kernel_drift",
            Self::SystemUpdateProposal => "system_update_proposal",
            Self::Quiet => "quiet",
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostLifecycleInvoke {
    HostSettings,
    Workflow,
    UpdateRestart,
    KernelDetails,
}

impl HostLifecycleInvoke {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::HostSettings => "host_settings",
            Self::Workflow => "workflow",
            Self::UpdateRestart => "update_restart",
            Self::KernelDetails => "kernel_details",
        }
    }
}

/// One server-selected lifecycle signal for a host.
///
/// `blocked_by` contains stable workflow or observation step keys that must
/// complete before this lifecycle can become verified and quiet.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostLifecycle {
    pub(crate) schema: &'static str,
    pub(crate) version: u16,
    pub(crate) slot: HostLifecycleSlot,
    pub(crate) label: String,
    pub(crate) level: &'static str,
    pub(crate) invoke: HostLifecycleInvoke,
    pub(crate) run_id: Option<String>,
    pub(crate) detail: String,
    pub(crate) blocked_by: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionEventSource {
    Operator,
    HostAgent,
    RetirementAgent,
    Beacon,
    Pharos,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionEventKind {
    Requested,
    StateRecovered,
    DispatchAccepted,
    DispatchFailed,
    ReviewClaimed,
    ReviewPassed,
    ReviewFailed,
    Confirmed,
    ApplyClaimed,
    ApplyRebooting,
    ApplyPassed,
    ApplyFailed,
    RecoveryQueued,
    RecoveryClaimed,
    RecoveryRebooting,
    RecoveryPassed,
    RecoveryFailed,
    SettingsRequestAccepted,
    SettingsApplied,
    SettingsFailed,
    RemovalAccessRevoked,
    RemovalDeclarationCompleted,
    RemovalCredentialClaimed,
    RemovalCredentialRetired,
    RemovalCredentialFailed,
    RemovalCredentialRetryQueued,
    RemovalFailed,
    RemovalCompleted,
    Cancelled,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetirementFailureReason {
    CheckoutNotReady,
    RetirementContractInvalid,
    JanusUnavailable,
    JanusRejected,
    ResultContractInvalid,
}

impl RetirementFailureReason {
    fn label(self) -> &'static str {
        match self {
            Self::CheckoutNotReady => "reviewed checkout not ready",
            // PHAROS-197: the agent reports this when it finds no declared
            // retirement intent for the host, which retrying cannot change.
            // Name the missing artefact rather than the contract check.
            Self::RetirementContractInvalid => "no declared retirement intent for this host",
            Self::JanusUnavailable => "Janus unavailable",
            Self::JanusRejected => "Janus rejected retirement",
            Self::ResultContractInvalid => "retirement result invalid",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionFailureGate {
    Input,
    Preflight,
    Approval,
    Permit,
    ManagedRun,
    ManagedRunContract,
    ReviewBinding,
    AllHostEvaluation,
    TargetBuild,
    BackupReadiness,
    FreshBackup,
    Switch,
    RebootSchedule,
    BootChange,
    SystemIdentity,
    RevisionIdentity,
    Kernel,
    Rollback,
    Storage,
    FailedUnits,
    RequiredServices,
    Heartbeat,
}

impl HostActionFailureGate {
    fn label(self) -> &'static str {
        match self {
            Self::Input => "request validation",
            Self::Preflight => "target preflight",
            Self::Approval => "guarded approval",
            Self::Permit => "one-time permit",
            Self::ManagedRun => "target-local execution",
            Self::ManagedRunContract => "target result contract",
            Self::ReviewBinding => "review binding",
            Self::AllHostEvaluation => "all-host validation",
            Self::TargetBuild => "target build",
            Self::BackupReadiness => "backup readiness",
            Self::FreshBackup => "fresh backup",
            Self::Switch => "reviewed system switch",
            Self::RebootSchedule => "restart scheduling",
            Self::BootChange => "host restart evidence",
            Self::SystemIdentity => "running system verification",
            Self::RevisionIdentity => "deployed revision verification",
            Self::Kernel => "kernel verification",
            Self::Rollback => "rollback posture",
            Self::Storage => "storage health",
            Self::FailedUnits => "system service health",
            Self::RequiredServices => "required services",
            Self::Heartbeat => "fresh heartbeat",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionRecoveryMode {
    ExactReviewedSystem,
    TrustedDescendant,
}

impl HostActionRecoveryMode {
    fn label(self) -> &'static str {
        match self {
            Self::ExactReviewedSystem => "exact reviewed system verified",
            Self::TrustedDescendant => "newer trusted deployment verified",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostActionEvent {
    pub(crate) at: i64,
    pub(crate) state: HostActionState,
    pub(crate) source: HostActionEventSource,
    pub(crate) kind: HostActionEventKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) actor: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failure_gate: Option<HostActionFailureGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_mode: Option<HostActionRecoveryMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retirement_failure: Option<RetirementFailureReason>,
}

impl HostActionEvent {
    fn validate(&self, job: &HostActionJob) -> bool {
        self.at >= job.created_at
            && self.at <= job.updated_at
            && self.actor.as_deref().is_none_or(safe_actor)
            && self.failure_gate.is_none_or(|_| {
                matches!(
                    self.kind,
                    HostActionEventKind::ReviewFailed
                        | HostActionEventKind::ApplyFailed
                        | HostActionEventKind::RecoveryFailed
                )
            })
            && self
                .recovery_mode
                .is_none_or(|_| self.kind == HostActionEventKind::RecoveryPassed)
            && self
                .retirement_failure
                .is_none_or(|_| self.kind == HostActionEventKind::RemovalCredentialFailed)
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WorkflowStepState {
    Queued,
    Running,
    Waiting,
    ConfirmationRequired,
    ActionRequired,
    Passed,
    Failed,
    Skipped,
    Recovered,
    Cancelled,
}

impl WorkflowStepState {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Running => "running",
            Self::Waiting => "waiting",
            Self::ConfirmationRequired => "confirmation_required",
            Self::ActionRequired => "action_required",
            Self::Passed => "passed",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
            Self::Recovered => "recovered",
            Self::Cancelled => "cancelled",
        }
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowStep {
    pub(crate) key: String,
    pub(crate) group: String,
    pub(crate) label: String,
    pub(crate) state: WorkflowStepState,
    pub(crate) detail: String,
    pub(crate) location: HostWorkflowExecutionLocation,
}

impl HostWorkflowStep {
    fn at(mut self, location: HostWorkflowExecutionLocation) -> Self {
        self.location = location;
        self
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostWorkflowExecutionLocation {
    Pharos,
    Github,
    TargetHost,
    RetirementOwner,
}

impl HostWorkflowExecutionLocation {
    pub(crate) fn label(self, host: &str) -> String {
        match self {
            Self::Pharos => "Pharos".to_string(),
            Self::Github => "GitHub".to_string(),
            Self::TargetHost => host.to_string(),
            Self::RetirementOwner => "retirement owner".to_string(),
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostWorkflowActionKind {
    Confirm,
    Retry,
    Recover,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowAction {
    pub(crate) kind: HostWorkflowActionKind,
    pub(crate) label: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowEvent {
    pub(crate) at: i64,
    pub(crate) state: HostActionState,
    pub(crate) source: HostActionEventSource,
    pub(crate) label: String,
    pub(crate) actor: Option<String>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowEvidence {
    pub(crate) label: String,
    pub(crate) value: String,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowSummary {
    pub(crate) schema: &'static str,
    pub(crate) version: u16,
    pub(crate) kind: HostWorkflowKind,
    pub(crate) run_id: String,
    pub(crate) host: String,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) recorded_duration_secs: i64,
    pub(crate) title: String,
    pub(crate) guidance: String,
    pub(crate) status_label: String,
    pub(crate) status_level: &'static str,
    pub(crate) current_step: Option<String>,
    pub(crate) current_location: Option<HostWorkflowExecutionLocation>,
    pub(crate) can_cancel: bool,
    pub(crate) persisted: bool,
    pub(crate) primary_action: Option<HostWorkflowAction>,
    pub(crate) steps: Vec<HostWorkflowStep>,
    pub(crate) evidence: Vec<HostWorkflowEvidence>,
    pub(crate) events: Vec<HostWorkflowEvent>,
}

impl HostActionState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed | Self::Cancelled)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostActionPlan {
    pub(crate) changed_file_count: u32,
    pub(crate) changed_areas: Vec<String>,
    pub(crate) all_host_eval_passed: bool,
    pub(crate) target_build_passed: bool,
    pub(crate) backup_ready: bool,
    pub(crate) running_kernel: Option<String>,
    pub(crate) expected_kernel: Option<String>,
    pub(crate) restart_required: bool,
}

impl HostActionPlan {
    fn validate(&self) -> bool {
        self.changed_file_count <= 10_000
            && self.changed_areas.len() <= 24
            && self.changed_areas.iter().all(|value| safe_area(value))
            && self.running_kernel.as_deref().is_none_or(safe_version_fact)
            && self
                .expected_kernel
                .as_deref()
                .is_none_or(safe_version_fact)
    }

    pub(crate) fn ready(&self) -> bool {
        self.validate()
            && self.all_host_eval_passed
            && self.target_build_passed
            && self.backup_ready
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostRemovalPlan {
    pub(crate) disposition: HostRetirementDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) successor: Option<String>,
    pub(crate) declaration_pending: bool,
    #[serde(default)]
    pub(crate) credential_retirement_required: bool,
}

impl HostRemovalPlan {
    pub(crate) fn validate(&self, host: &str) -> bool {
        self.disposition
            .validates_successor(host, self.successor.as_deref())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostActionResult {
    pub(crate) backup_validated: bool,
    pub(crate) switch_passed: bool,
    pub(crate) reboot_observed: bool,
    pub(crate) kernel_verified: bool,
    pub(crate) rollback_available: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) failure_gate: Option<HostActionFailureGate>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_mode: Option<HostActionRecoveryMode>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct HostActionJob {
    schema: String,
    version: u16,
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) kind: HostActionKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    workflow_kind: Option<HostWorkflowKind>,
    pub(crate) state: HostActionState,
    pub(crate) requested_by: String,
    pub(crate) ticket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) retry_of: Option<String>,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) confirmed_at: Option<i64>,
    pub(crate) plan: Option<HostActionPlan>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) removal_plan: Option<HostRemovalPlan>,
    pub(crate) result: Option<HostActionResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) recovery_started_at: Option<i64>,
    #[serde(default)]
    pub(crate) events: Vec<HostActionEvent>,
    #[serde(default)]
    lease_phase: Option<AgentActionPhase>,
    lease_until: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retirement_lease_until: Option<i64>,
}

impl HostActionJob {
    pub(crate) fn workflow_kind(&self) -> HostWorkflowKind {
        self.workflow_kind.unwrap_or_else(|| self.kind.into())
    }

    fn validate(&self) -> bool {
        self.schema == ACTION_SCHEMA
            && self.version == ACTION_VERSION
            && safe_action_id(&self.id)
            && valid_host_name(&self.host)
            && safe_actor(&self.requested_by)
            && valid_ticket(&self.ticket)
            && self.retry_of.as_deref().is_none_or(safe_action_id)
            && self.retry_of.as_ref().is_none_or(|id| id != &self.id)
            && self.created_at > 0
            && self.updated_at >= self.created_at
            && self
                .recovery_started_at
                .is_none_or(|at| at >= self.created_at && at <= self.updated_at)
            && self.events.iter().all(|event| event.validate(self))
            && self
                .events
                .windows(2)
                .all(|events| events[0].at <= events[1].at)
            && self.plan.as_ref().is_none_or(HostActionPlan::validate)
            && self.workflow_kind.is_none_or(|kind| {
                kind == HostWorkflowKind::SettingsChange
                    && self.kind == HostActionKind::SystemUpdateProposal
                    && self.removal_plan.is_none()
            })
            && self.recovery_started_at.is_none_or(|_| {
                self.kind == HostActionKind::UpdateRestart && self.confirmed_at.is_some()
            })
            && (self.state != HostActionState::Cancelled
                || (self.kind == HostActionKind::UpdateRestart
                    && self.confirmed_at.is_none()
                    && self.recovery_started_at.is_none()
                    && self.result.is_none()))
            && self.lease_state_valid()
            && self.retirement_lease_state_valid()
            && match self.kind {
                HostActionKind::RemoveHost => self
                    .removal_plan
                    .as_ref()
                    .is_some_and(|plan| plan.validate(&self.host)),
                HostActionKind::SystemUpdateProposal | HostActionKind::UpdateRestart => {
                    self.removal_plan.is_none()
                }
            }
    }

    fn lease_state_valid(&self) -> bool {
        let active_deadline = self
            .lease_until
            .is_some_and(|until| until > self.updated_at);
        match self.state {
            HostActionState::Reviewing => {
                self.lease_phase == Some(AgentActionPhase::Review) && active_deadline
            }
            HostActionState::Applying => {
                matches!(
                    self.lease_phase,
                    Some(AgentActionPhase::Apply | AgentActionPhase::Resume)
                ) && active_deadline
            }
            _ => self.lease_phase.is_none() && self.lease_until.is_none(),
        }
    }

    fn retirement_lease_state_valid(&self) -> bool {
        self.retirement_lease_until.is_none_or(|until| {
            self.kind == HostActionKind::RemoveHost
                && self.state == HostActionState::RemovalPending
                && until > self.updated_at
                && self.removal_access_revoked()
                && self.declaration_removed()
                && self.credential_retirement_required()
                && !self.credentials_retired()
                && !self.credential_retry_required()
        })
    }

    fn has_event(&self, kind: HostActionEventKind) -> bool {
        self.events.iter().any(|event| event.kind == kind)
    }

    fn removal_access_revoked(&self) -> bool {
        self.has_event(HostActionEventKind::RemovalAccessRevoked)
    }

    fn declaration_removed(&self) -> bool {
        self.removal_plan
            .as_ref()
            .is_some_and(|plan| !plan.declaration_pending)
            || self.has_event(HostActionEventKind::RemovalDeclarationCompleted)
    }

    fn credential_retirement_required(&self) -> bool {
        self.removal_plan
            .as_ref()
            .is_some_and(|plan| plan.credential_retirement_required)
    }

    fn credentials_retired(&self) -> bool {
        !self.credential_retirement_required()
            || self.has_event(HostActionEventKind::RemovalCredentialRetired)
    }

    fn credential_retry_required(&self) -> bool {
        self.events
            .iter()
            .rev()
            .find_map(|event| match event.kind {
                HostActionEventKind::RemovalCredentialFailed => Some(true),
                HostActionEventKind::RemovalCredentialRetryQueued
                | HostActionEventKind::RemovalCredentialClaimed
                | HostActionEventKind::RemovalCredentialRetired => Some(false),
                _ => None,
            })
            .unwrap_or(false)
    }

    fn latest_retirement_failure(&self) -> Option<RetirementFailureReason> {
        self.events.iter().rev().find_map(|event| {
            (event.kind == HostActionEventKind::RemovalCredentialFailed)
                .then_some(event.retirement_failure)
                .flatten()
        })
    }

    fn removal_gates_ready(&self) -> bool {
        self.removal_access_revoked() && self.declaration_removed() && self.credentials_retired()
    }

    pub(crate) fn summary(&self) -> HostActionSummary {
        HostActionSummary {
            id: self.id.clone(),
            host: self.host.clone(),
            kind: self.kind,
            state: self.state,
            ticket: self.ticket.clone(),
            retry_of: self.retry_of.clone(),
            retryable: self.review_retryable(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            plan: self.plan.clone(),
            removal_plan: self.removal_plan.clone(),
            result: self.result.clone(),
            workflow: self.workflow(),
        }
    }

    fn record_event(
        &mut self,
        now: i64,
        source: HostActionEventSource,
        kind: HostActionEventKind,
        actor: Option<&str>,
    ) {
        self.record_event_with_evidence(now, source, kind, actor, None, None);
    }

    fn record_event_with_evidence(
        &mut self,
        now: i64,
        source: HostActionEventSource,
        kind: HostActionEventKind,
        actor: Option<&str>,
        failure_gate: Option<HostActionFailureGate>,
        recovery_mode: Option<HostActionRecoveryMode>,
    ) {
        self.events.push(HostActionEvent {
            at: now,
            state: self.state,
            source,
            kind,
            actor: actor.map(str::to_string),
            failure_gate,
            recovery_mode,
            retirement_failure: None,
        });
    }

    fn latest_failure_gate(&self) -> Option<HostActionFailureGate> {
        self.events
            .iter()
            .rev()
            .find(|event| {
                matches!(
                    event.kind,
                    HostActionEventKind::ReviewFailed
                        | HostActionEventKind::ApplyFailed
                        | HostActionEventKind::RecoveryFailed
                )
            })
            .and_then(|event| event.failure_gate)
    }

    fn recovery_mode(&self) -> Option<HostActionRecoveryMode> {
        self.events
            .iter()
            .rev()
            .find_map(|event| event.recovery_mode)
    }

    pub(crate) fn recoverable(&self) -> bool {
        self.kind == HostActionKind::UpdateRestart
            && self.state == HostActionState::Failed
            && self.confirmed_at.is_some()
            && self.plan.as_ref().is_some_and(HostActionPlan::ready)
            && self.result.is_none()
    }

    fn review_retryable(&self) -> bool {
        self.kind == HostActionKind::UpdateRestart
            && self.state == HostActionState::Failed
            && self.confirmed_at.is_none()
            && self.plan.is_none()
            && self.result.is_none()
    }

    fn can_cancel(&self) -> bool {
        self.kind == HostActionKind::UpdateRestart
            && self.confirmed_at.is_none()
            && self.recovery_started_at.is_none()
            && matches!(
                self.state,
                HostActionState::QueuedReview
                    | HostActionState::Reviewing
                    | HostActionState::AwaitingConfirmation
            )
    }

    fn workflow(&self) -> HostWorkflowSummary {
        let kind = self.workflow_kind();
        let (title, guidance, status_label, status_level, primary_action, steps) = match kind {
            HostWorkflowKind::SettingsChange => self.settings_workflow(),
            HostWorkflowKind::SystemUpdateProposal => self.system_update_workflow(),
            HostWorkflowKind::UpdateRestart => self.update_restart_workflow(),
            HostWorkflowKind::RemoveHost => self.removal_workflow(),
        };
        let current_step = workflow_current_step(&steps);
        let current_location = current_step.as_deref().and_then(|key| {
            steps
                .iter()
                .find(|step| step.key == key)
                .map(|step| step.location)
        });
        let evidence = self.workflow_evidence();
        let events = self
            .events
            .iter()
            .map(|event| HostWorkflowEvent {
                at: event.at,
                state: event.state,
                source: event.source,
                label: event_label(event),
                actor: event.actor.clone(),
            })
            .collect();
        HostWorkflowSummary {
            schema: WORKFLOW_SCHEMA,
            version: WORKFLOW_VERSION,
            kind,
            run_id: self.id.clone(),
            host: self.host.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            recorded_duration_secs: self.updated_at.saturating_sub(self.created_at),
            title,
            guidance,
            status_label,
            status_level,
            current_step,
            current_location,
            can_cancel: self.can_cancel(),
            persisted: true,
            primary_action,
            steps,
            evidence,
            events,
        }
    }

    fn workflow_evidence(&self) -> Vec<HostWorkflowEvidence> {
        let mut evidence = vec![workflow_evidence("Tracking", self.ticket.clone())];
        match self.workflow_kind() {
            HostWorkflowKind::SettingsChange => {
                let accepted = self
                    .events
                    .iter()
                    .any(|event| event.kind == HostActionEventKind::SettingsRequestAccepted);
                evidence.push(workflow_evidence(
                    "Delivery",
                    if self.state == HostActionState::Failed {
                        "stopped"
                    } else if accepted || self.state == HostActionState::Succeeded {
                        "accepted"
                    } else {
                        "recording"
                    },
                ));
                evidence.push(workflow_evidence(
                    "Host report",
                    if self.state == HostActionState::Succeeded {
                        "requested settings observed"
                    } else {
                        "not observed yet"
                    },
                ));
            }
            HostWorkflowKind::SystemUpdateProposal => {
                let accepted = self
                    .events
                    .iter()
                    .any(|event| event.kind == HostActionEventKind::DispatchAccepted);
                evidence.push(workflow_evidence(
                    "Repository dispatch",
                    if self.state == HostActionState::Failed {
                        "stopped"
                    } else if accepted {
                        "accepted"
                    } else {
                        "recording"
                    },
                ));
                evidence.push(workflow_evidence("Live host change", "not authorized"));
            }
            HostWorkflowKind::UpdateRestart => {
                if let Some(plan) = &self.plan {
                    evidence.extend([
                        workflow_evidence("Changed files", plan.changed_file_count.to_string()),
                        workflow_evidence(
                            "Changed areas",
                            if plan.changed_areas.is_empty() {
                                "none".to_string()
                            } else {
                                plan.changed_areas.join(", ")
                            },
                        ),
                        workflow_evidence(
                            "All-host validation",
                            evidence_result(plan.all_host_eval_passed),
                        ),
                        workflow_evidence(
                            "Target build",
                            evidence_result(plan.target_build_passed),
                        ),
                        workflow_evidence("Backup gate", evidence_ready(plan.backup_ready)),
                        workflow_evidence(
                            "Restart",
                            if plan.restart_required {
                                "required"
                            } else {
                                "not required"
                            },
                        ),
                    ]);
                    if let Some(version) = &plan.running_kernel {
                        evidence.push(workflow_evidence("Running kernel", version.clone()));
                    }
                    if let Some(version) = &plan.expected_kernel {
                        evidence.push(workflow_evidence("Expected kernel", version.clone()));
                    }
                }
                if let Some(result) = &self.result {
                    evidence.extend([
                        workflow_evidence(
                            "Backup validation",
                            evidence_result(result.backup_validated),
                        ),
                        workflow_evidence("Reviewed switch", evidence_result(result.switch_passed)),
                        workflow_evidence(
                            "Restart observed",
                            evidence_result(result.reboot_observed),
                        ),
                        workflow_evidence(
                            "Kernel verification",
                            evidence_result(result.kernel_verified),
                        ),
                        workflow_evidence(
                            "Rollback posture",
                            if result.rollback_available {
                                "available"
                            } else {
                                "not available"
                            },
                        ),
                    ]);
                }
                if self.recovery_started_at.is_some() {
                    evidence.push(workflow_evidence(
                        "Recovery mode",
                        self.recovery_mode().map_or(
                            "verify existing result; no second switch or restart",
                            HostActionRecoveryMode::label,
                        ),
                    ));
                }
                if let Some(gate) = self.latest_failure_gate() {
                    evidence.push(workflow_evidence("Stopped at", gate.label()));
                }
            }
            HostWorkflowKind::RemoveHost => {
                if let Some(plan) = &self.removal_plan {
                    evidence.push(workflow_evidence(
                        "Host disposition",
                        plan.disposition.key(),
                    ));
                    if let Some(successor) = &plan.successor {
                        evidence.push(workflow_evidence("Successor", successor.clone()));
                    }
                    evidence.push(workflow_evidence(
                        "Declarative cleanup",
                        if self.declaration_removed() {
                            "complete"
                        } else if plan.declaration_pending {
                            "pending"
                        } else {
                            "not required"
                        },
                    ));
                    evidence.push(workflow_evidence(
                        "Credential retirement",
                        if self.credentials_retired() {
                            if plan.credential_retirement_required {
                                "complete"
                            } else {
                                "not required"
                            }
                        } else if self.credential_retry_required() {
                            "action required"
                        } else if self.retirement_lease_until.is_some() {
                            "running"
                        } else {
                            "pending"
                        },
                    ));
                    if let Some(reason) = self.latest_retirement_failure() {
                        evidence.push(workflow_evidence(
                            "Credential retirement stopped at",
                            reason.label(),
                        ));
                    }
                }
            }
        }
        evidence
    }

    fn settings_workflow(
        &self,
    ) -> (
        String,
        String,
        String,
        &'static str,
        Option<HostWorkflowAction>,
        Vec<HostWorkflowStep>,
    ) {
        let accepted = self
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::SettingsRequestAccepted);
        let (guidance, status_label, status_level) = match self.state {
            HostActionState::Succeeded => (
                "The host reported the requested settings. The saved workflow is complete.",
                "settings applied",
                "clear",
            ),
            HostActionState::Failed => (
                "The request stopped safely. Review the recorded event before trying again.",
                "settings request stopped",
                "warning",
            ),
            _ if accepted => (
                "The request is saved. Pharos is waiting for the host to report the new settings.",
                "change waiting",
                "warning",
            ),
            _ => (
                "Pharos is recording and sending the requested settings.",
                "saving settings",
                "warning",
            ),
        };
        let request_state = match self.state {
            HostActionState::Succeeded => WorkflowStepState::Passed,
            HostActionState::Failed => WorkflowStepState::Failed,
            _ if accepted => WorkflowStepState::Passed,
            _ => WorkflowStepState::Running,
        };
        let wait_state = match self.state {
            HostActionState::Succeeded => WorkflowStepState::Passed,
            HostActionState::Failed => WorkflowStepState::Skipped,
            _ if accepted => WorkflowStepState::Waiting,
            _ => WorkflowStepState::Queued,
        };
        let record_state = match self.state {
            HostActionState::Succeeded | HostActionState::Failed => WorkflowStepState::Passed,
            _ => WorkflowStepState::Queued,
        };
        (
            format!("Change {} settings", self.host),
            guidance.to_string(),
            status_label.to_string(),
            status_level,
            None,
            vec![
                workflow_step(
                    "validate",
                    "PREPARE",
                    "Validate the selected settings",
                    WorkflowStepState::Passed,
                    "The values and host access passed validation.",
                ),
                workflow_step(
                    "request",
                    "SEND",
                    "Send the change request",
                    request_state,
                    if self.state == HostActionState::Failed {
                        "The delivery workflow did not accept the request."
                    } else if accepted {
                        "The durable delivery workflow accepted the request."
                    } else {
                        "Pharos is recording the delivery request."
                    },
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "host",
                    "APPLY",
                    "Wait for the host",
                    wait_state,
                    "Applied state changes only after the host reports the requested values.",
                )
                .at(HostWorkflowExecutionLocation::TargetHost),
                workflow_step(
                    "record",
                    "RECORD",
                    "Save the result",
                    record_state,
                    "The run remains available after refresh or restart.",
                ),
            ],
        )
    }

    fn system_update_workflow(
        &self,
    ) -> (
        String,
        String,
        String,
        &'static str,
        Option<HostWorkflowAction>,
        Vec<HostWorkflowStep>,
    ) {
        let failed = self.state == HostActionState::Failed;
        let accepted = self
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::DispatchAccepted);
        (
            "Review system updates".to_string(),
            if failed {
                "The repository review request stopped. No host change was authorized."
            } else {
                "The proposal is saved outside the live-change path. Repository checks and review must finish before any host action."
            }
            .to_string(),
            if failed {
                "update review stopped"
            } else {
                "review requested"
            }
            .to_string(),
            "warning",
            None,
            vec![
                workflow_step(
                    "request",
                    "PREPARE",
                    "Create an isolated update proposal",
                    if failed {
                        WorkflowStepState::Failed
                    } else if accepted {
                        WorkflowStepState::Passed
                    } else {
                        WorkflowStepState::Running
                    },
                    "This step cannot merge or deploy a host.",
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "validate",
                    "VALIDATE",
                    "Run repository and all-host checks",
                    if failed {
                        WorkflowStepState::Skipped
                    } else if accepted {
                        WorkflowStepState::Waiting
                    } else {
                        WorkflowStepState::Queued
                    },
                    "Completion is reported by the repository workflow.",
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "review",
                    "APPROVE",
                    "Review the proposal",
                    if failed {
                        WorkflowStepState::Skipped
                    } else {
                        WorkflowStepState::Queued
                    },
                    "A separate reviewed workflow is required before deployment.",
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "deploy",
                    "APPLY",
                    "Deploy hosts",
                    WorkflowStepState::Skipped,
                    "This proposal workflow never deploys hosts.",
                )
                .at(HostWorkflowExecutionLocation::TargetHost),
                workflow_step(
                    "record",
                    "RECORD",
                    "Save the request",
                    WorkflowStepState::Passed,
                    "The request remains available after refresh or restart.",
                ),
            ],
        )
    }

    fn update_restart_workflow(
        &self,
    ) -> (
        String,
        String,
        String,
        &'static str,
        Option<HostWorkflowAction>,
        Vec<HostWorkflowStep>,
    ) {
        let plan = self.plan.as_ref();
        let confirmed = self.confirmed_at.is_some();
        let recovery = self.recovery_started_at.is_some();
        let recovered = recovery && self.state == HostActionState::Succeeded;
        let cancelled = self.state == HostActionState::Cancelled;
        let preconfirm_failed = self.state == HostActionState::Failed && !confirmed;
        let recovery_failed = recovery && self.state == HostActionState::Failed;
        let failure_gate = self.latest_failure_gate();
        let primary_action = match self.state {
            HostActionState::AwaitingConfirmation => Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Confirm,
                label: "Confirm update".to_string(),
            }),
            HostActionState::Failed if self.review_retryable() => Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Retry,
                label: "Retry guarded review".to_string(),
            }),
            HostActionState::Failed if self.recoverable() => Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Recover,
                label: if recovery {
                    "Run recovery checks again"
                } else {
                    "Run recovery checks"
                }
                .to_string(),
            }),
            _ => None,
        };
        let (guidance, status_label, status_level) = match self.state {
            HostActionState::QueuedReview => (
                "The request is saved. No live change has started.",
                "review queued",
                "warning",
            ),
            HostActionState::Reviewing => (
                "The target-local agent is preparing a read-only plan and safety evidence.",
                "preparing safe plan",
                "warning",
            ),
            HostActionState::AwaitingConfirmation => (
                "The review passed. Confirm only while the host or recovery console is attended.",
                "ready for confirmation",
                "warning",
            ),
            HostActionState::QueuedApply => (
                "Confirmation is recorded. The target-local agent will continue one guarded step at a time.",
                "waiting for host",
                "warning",
            ),
            HostActionState::Applying if recovery => (
                "The host agent is reconciling the recorded failure with current machine evidence.",
                "recovery checks running",
                "warning",
            ),
            HostActionState::Applying => (
                "The guarded live workflow is running on the target host.",
                "applying update",
                "warning",
            ),
            HostActionState::Rebooting if recovery => (
                "Recovery is queued for the target-local agent. No second switch or reboot was requested.",
                "recovery queued",
                "warning",
            ),
            HostActionState::Rebooting => (
                "The host is restarting. Pharos is waiting for fresh runtime verification.",
                "waiting for restart",
                "warning",
            ),
            HostActionState::Succeeded if recovered => (
                "Current host evidence passed and the original failure remains in the audit history.",
                "recovered and verified",
                "clear",
            ),
            HostActionState::Succeeded => (
                "The guarded update completed and all required evidence was recorded.",
                "update completed",
                "clear",
            ),
            HostActionState::Failed if preconfirm_failed => (
                "The read-only review stopped before any live change. Correct the cause, then retry this recorded run.",
                "review stopped safely",
                "warning",
            ),
            HostActionState::Failed if recovery_failed => (
                "Recovery verification did not complete. Inspect the host evidence before trying the same recovery branch again.",
                "recovery needs attention",
                "warning",
            ),
            HostActionState::Failed => (
                "The live run stopped, but this does not by itself mean the host is unhealthy. Reconcile it with current host evidence.",
                "verification needed",
                "warning",
            ),
            HostActionState::Cancelled => (
                "The review was cancelled before any live change. No switch or restart was authorized.",
                "cancelled safely",
                "clear",
            ),
            _ => (
                "The guarded workflow is recorded.",
                "workflow recorded",
                "warning",
            ),
        };
        let guidance = if recovery_failed {
            failure_gate.map_or_else(
                || guidance.to_string(),
                |gate| {
                    format!(
                        "Recovery stopped at {}. The recorded failure remains available for another guarded check.",
                        gate.label()
                    )
                },
            )
        } else {
            guidance.to_string()
        };

        let review_state = match self.state {
            HostActionState::QueuedReview => WorkflowStepState::Waiting,
            HostActionState::Reviewing => WorkflowStepState::Running,
            HostActionState::Failed if !confirmed => WorkflowStepState::Failed,
            HostActionState::Cancelled if plan.is_some() => WorkflowStepState::Passed,
            HostActionState::Cancelled => WorkflowStepState::Cancelled,
            _ if plan.is_some() => WorkflowStepState::Passed,
            _ => WorkflowStepState::Queued,
        };
        let plan_step = |passed: Option<bool>| match passed {
            Some(true) => WorkflowStepState::Passed,
            Some(false) => WorkflowStepState::Failed,
            None if preconfirm_failed => WorkflowStepState::Skipped,
            None if cancelled => WorkflowStepState::Skipped,
            None if self.state == HostActionState::Reviewing => WorkflowStepState::Waiting,
            None => WorkflowStepState::Queued,
        };
        let confirmation_state = if confirmed {
            WorkflowStepState::Passed
        } else if self.state == HostActionState::AwaitingConfirmation {
            WorkflowStepState::ConfirmationRequired
        } else if preconfirm_failed {
            WorkflowStepState::Skipped
        } else if cancelled && plan.is_some() {
            WorkflowStepState::Cancelled
        } else if cancelled {
            WorkflowStepState::Skipped
        } else {
            WorkflowStepState::Queued
        };
        let apply_state = if recovered {
            WorkflowStepState::Recovered
        } else {
            match self.state {
                HostActionState::Applying if !recovery => WorkflowStepState::Running,
                HostActionState::Rebooting if !recovery => WorkflowStepState::Passed,
                HostActionState::Succeeded => WorkflowStepState::Passed,
                HostActionState::Failed if confirmed => WorkflowStepState::Failed,
                HostActionState::QueuedApply => WorkflowStepState::Waiting,
                HostActionState::Failed => WorkflowStepState::Skipped,
                HostActionState::Cancelled => WorkflowStepState::Skipped,
                _ => WorkflowStepState::Queued,
            }
        };
        let restart_state = if plan.is_some_and(|plan| !plan.restart_required) {
            WorkflowStepState::Skipped
        } else if recovered {
            WorkflowStepState::Recovered
        } else {
            match self.state {
                HostActionState::Rebooting if !recovery => WorkflowStepState::Running,
                HostActionState::Succeeded => WorkflowStepState::Passed,
                HostActionState::Applying if !recovery => WorkflowStepState::Waiting,
                HostActionState::Failed if confirmed => WorkflowStepState::Failed,
                HostActionState::Failed => WorkflowStepState::Skipped,
                HostActionState::Cancelled => WorkflowStepState::Skipped,
                _ => WorkflowStepState::Queued,
            }
        };
        let (host_return_state, runtime_state, heartbeat_state) = if recovered {
            (
                WorkflowStepState::Recovered,
                WorkflowStepState::Recovered,
                WorkflowStepState::Recovered,
            )
        } else if recovery_failed {
            recovery_failure_states(failure_gate)
        } else {
            let state = match self.state {
                HostActionState::Succeeded => WorkflowStepState::Passed,
                HostActionState::Rebooting if !recovery => WorkflowStepState::Waiting,
                HostActionState::Failed if confirmed => WorkflowStepState::ActionRequired,
                HostActionState::Failed => WorkflowStepState::Skipped,
                HostActionState::Cancelled => WorkflowStepState::Skipped,
                _ => WorkflowStepState::Queued,
            };
            (state, state, state)
        };
        let recovery_state = if !recovery {
            None
        } else {
            Some(match self.state {
                HostActionState::Applying => WorkflowStepState::Running,
                HostActionState::Rebooting => WorkflowStepState::Waiting,
                HostActionState::Succeeded => WorkflowStepState::Recovered,
                HostActionState::Failed => WorkflowStepState::Failed,
                _ => WorkflowStepState::Queued,
            })
        };
        let mut steps = vec![
            workflow_step(
                "review",
                "PREPARE",
                "Review the requested change",
                review_state,
                "The target-local agent reports only sanitized plan facts.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "validate",
                "PREPARE",
                "Validate all configured hosts",
                plan_step(plan.map(|plan| plan.all_host_eval_passed)),
                "Shared configuration must evaluate before this host can continue.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "build",
                "PREPARE",
                format!("Build {}", self.host),
                plan_step(plan.map(|plan| plan.target_build_passed)),
                "The target build must finish without changing the running host.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "backup",
                "PROTECT",
                "Create and validate a fresh backup",
                plan_step(plan.map(|plan| plan.backup_ready)),
                "The live gate remains blocked until backup evidence is ready.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "confirm",
                "APPROVE",
                "Confirm the live change",
                confirmation_state,
                "An attended operator must explicitly approve the switch.",
            ),
            workflow_step(
                "apply",
                "APPLY",
                "Switch the reviewed configuration",
                apply_state,
                "Only the reviewed target-local workflow may perform this step.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "restart",
                "APPLY",
                "Restart if required",
                restart_state,
                "Pharos waits for the original host to return before verification.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "host-return",
                "VERIFY",
                "Wait for the host",
                host_return_state,
                verification_step_detail(
                    host_return_state,
                    failure_gate,
                    "A fresh report must arrive after the live gate.",
                ),
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "runtime",
                "VERIFY",
                "Check kernel, services, and rollback posture",
                runtime_state,
                verification_step_detail(
                    runtime_state,
                    failure_gate,
                    "Verification uses current target-local and heartbeat evidence.",
                ),
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
            workflow_step(
                "heartbeat",
                "VERIFY",
                "Receive a fresh heartbeat",
                heartbeat_state,
                verification_step_detail(
                    heartbeat_state,
                    failure_gate,
                    "The reported runtime must match the expected system state.",
                ),
            )
            .at(HostWorkflowExecutionLocation::TargetHost),
        ];
        if let Some(state) = recovery_state {
            steps.push(workflow_step(
                "recovery",
                "RECOVER",
                "Reconcile the failed run with current host evidence",
                state,
                "This branch verifies the existing result; it does not request a second switch or reboot.",
            )
            .at(HostWorkflowExecutionLocation::TargetHost));
        }
        steps.push(workflow_step(
            "record",
            "RECORD",
            "Save the result",
            if self.state.is_terminal() {
                WorkflowStepState::Passed
            } else {
                WorkflowStepState::Queued
            },
            if self.state == HostActionState::Failed {
                "The failure is retained and can be resolved by the same workflow."
            } else if self.state == HostActionState::Cancelled {
                "The safe cancellation and completed review evidence remain recorded."
            } else {
                "The run remains available after refresh or restart."
            },
        ));
        (
            format!("Update {}", self.host),
            guidance,
            status_label.to_string(),
            status_level,
            primary_action,
            steps,
        )
    }

    fn removal_workflow(
        &self,
    ) -> (
        String,
        String,
        String,
        &'static str,
        Option<HostWorkflowAction>,
        Vec<HostWorkflowStep>,
    ) {
        let preparing = self.state == HostActionState::ProposalRequested;
        let pending = self.state == HostActionState::RemovalPending;
        let failed = self.state == HostActionState::Failed;
        let declaration_pending = self
            .removal_plan
            .as_ref()
            .is_some_and(|plan| plan.declaration_pending);
        let declaration_removed = self.declaration_removed();
        let credentials_required = self.credential_retirement_required();
        let credentials_retired = self.credentials_retired();
        let credential_running = self.retirement_lease_until.is_some();
        let credential_retry_required = self.credential_retry_required();
        let primary_action = credential_retry_required.then(|| HostWorkflowAction {
            kind: HostWorkflowActionKind::Retry,
            label: "Retry credential retirement".to_string(),
        });
        (
            format!("Remove {} from Pharos", self.host),
            if failed {
                "The removal request stopped before Pharos could finish revoking this host. Review the saved failure before trying again."
            } else if preparing {
                "The retirement intent is saved. Pharos is finishing the guarded handoff before changing host visibility."
            } else if credential_retry_required {
                "The reviewed declaration is gone, but owner-side credential retirement stopped. Review the recorded reason, then retry the same bounded workflow."
            } else if credential_running {
                "The reviewed declaration is gone. The retirement owner is removing the host credential through Janus."
            } else if pending && declaration_removed && credentials_required {
                "The reviewed declaration is gone. Pharos is waiting for the retirement owner to claim credential cleanup."
            } else if pending {
                "Reporting access is revoked. Pharos is waiting for the declared host entry to be reviewed and removed."
            } else {
                "The host retirement is complete. No server, disk, service, or application data was deleted."
            }
            .to_string(),
            if failed {
                "removal stopped"
            } else if preparing {
                "preparing removal"
            } else if credential_retry_required {
                "credential retirement needs attention"
            } else if credential_running {
                "retiring credentials"
            } else if pending {
                "removal pending"
            } else {
                "host retired"
            }
            .to_string(),
            if preparing || pending || failed {
                "warning"
            } else {
                "clear"
            },
            primary_action,
            vec![
                workflow_step(
                    "confirm",
                    "APPROVE",
                    "Confirm the retirement intent",
                    WorkflowStepState::Passed,
                    "The operator recorded what happened to the host.",
                ),
                workflow_step(
                    "revoke",
                    "PROTECT",
                    "Revoke reporting access",
                    if failed {
                        WorkflowStepState::Failed
                    } else if preparing {
                        WorkflowStepState::Running
                    } else {
                        WorkflowStepState::Passed
                    },
                    "New heartbeats from the retired identity are rejected.",
                ),
                workflow_step(
                    "declaration",
                    "APPLY",
                    "Remove the declarative host entry",
                    if failed {
                        WorkflowStepState::Skipped
                    } else if preparing {
                        WorkflowStepState::Queued
                    } else if declaration_removed {
                        WorkflowStepState::Passed
                    } else if declaration_pending {
                        WorkflowStepState::Waiting
                    } else {
                        WorkflowStepState::Skipped
                    },
                    if declaration_pending {
                        "The repository workflow must finish before Pharos hides the host."
                    } else {
                        "This host had no declaration to remove."
                    },
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "credentials",
                    "PROTECT",
                    "Retire the host credential",
                    if !credentials_required {
                        WorkflowStepState::Skipped
                    } else if credentials_retired {
                        WorkflowStepState::Passed
                    } else if credential_retry_required {
                        WorkflowStepState::ActionRequired
                    } else if credential_running {
                        WorkflowStepState::Running
                    } else if declaration_removed {
                        WorkflowStepState::Waiting
                    } else {
                        WorkflowStepState::Queued
                    },
                    if !credentials_required {
                        "No Janus-owned credential was registered for this host."
                    } else if credential_retry_required {
                        "The bounded owner-side run stopped without returning credential material."
                    } else {
                        "The configured owner runs only the reviewed Janus retirement intent."
                    },
                )
                .at(HostWorkflowExecutionLocation::RetirementOwner),
                workflow_step(
                    "record",
                    "RECORD",
                    "Save the retirement record",
                    if self.state == HostActionState::Succeeded {
                        WorkflowStepState::Passed
                    } else {
                        WorkflowStepState::Queued
                    },
                    "The retirement remains auditable after the runtime record is removed.",
                ),
            ],
        )
    }
}

fn workflow_step(
    key: impl Into<String>,
    group: impl Into<String>,
    label: impl Into<String>,
    state: WorkflowStepState,
    detail: impl Into<String>,
) -> HostWorkflowStep {
    HostWorkflowStep {
        key: key.into(),
        group: group.into(),
        label: label.into(),
        state,
        detail: detail.into(),
        location: HostWorkflowExecutionLocation::Pharos,
    }
}

fn recovery_failure_states(
    gate: Option<HostActionFailureGate>,
) -> (WorkflowStepState, WorkflowStepState, WorkflowStepState) {
    match gate {
        Some(HostActionFailureGate::BootChange) => (
            WorkflowStepState::Failed,
            WorkflowStepState::ActionRequired,
            WorkflowStepState::ActionRequired,
        ),
        Some(
            HostActionFailureGate::SystemIdentity
            | HostActionFailureGate::RevisionIdentity
            | HostActionFailureGate::Kernel
            | HostActionFailureGate::Rollback
            | HostActionFailureGate::Storage
            | HostActionFailureGate::FailedUnits
            | HostActionFailureGate::RequiredServices,
        ) => (
            WorkflowStepState::Passed,
            WorkflowStepState::Failed,
            WorkflowStepState::ActionRequired,
        ),
        Some(HostActionFailureGate::Heartbeat) => (
            WorkflowStepState::Passed,
            WorkflowStepState::Passed,
            WorkflowStepState::Failed,
        ),
        _ => (
            WorkflowStepState::ActionRequired,
            WorkflowStepState::ActionRequired,
            WorkflowStepState::ActionRequired,
        ),
    }
}

fn verification_step_detail(
    state: WorkflowStepState,
    gate: Option<HostActionFailureGate>,
    default: &'static str,
) -> String {
    match (state, gate) {
        (WorkflowStepState::Failed, Some(gate)) => {
            format!("Recovery stopped at {}.", gate.label())
        }
        (WorkflowStepState::ActionRequired, Some(gate)) => {
            format!("Not completed after {} stopped.", gate.label())
        }
        _ => default.to_string(),
    }
}

fn workflow_evidence(label: impl Into<String>, value: impl Into<String>) -> HostWorkflowEvidence {
    HostWorkflowEvidence {
        label: label.into(),
        value: value.into(),
    }
}

fn evidence_result(passed: bool) -> &'static str {
    if passed {
        "passed"
    } else {
        "not passed"
    }
}

fn evidence_ready(ready: bool) -> &'static str {
    if ready {
        "ready"
    } else {
        "not ready"
    }
}

fn workflow_current_step(steps: &[HostWorkflowStep]) -> Option<String> {
    const PRIORITY: [WorkflowStepState; 6] = [
        WorkflowStepState::Running,
        WorkflowStepState::ConfirmationRequired,
        WorkflowStepState::ActionRequired,
        WorkflowStepState::Waiting,
        WorkflowStepState::Failed,
        WorkflowStepState::Queued,
    ];
    PRIORITY.iter().find_map(|state| {
        steps
            .iter()
            .find(|step| step.state == *state)
            .map(|step| step.key.clone())
    })
}

fn event_label(event: &HostActionEvent) -> String {
    let mut label = match event.kind {
        HostActionEventKind::Requested => "Workflow requested",
        HostActionEventKind::StateRecovered => "Existing workflow state loaded",
        HostActionEventKind::DispatchAccepted => "Guarded dispatch accepted",
        HostActionEventKind::DispatchFailed => "Guarded dispatch stopped",
        HostActionEventKind::ReviewClaimed => "Host started the safe review",
        HostActionEventKind::ReviewPassed => "Safe review passed",
        HostActionEventKind::ReviewFailed => "Safe review stopped",
        HostActionEventKind::Confirmed => "Live change confirmed",
        HostActionEventKind::ApplyClaimed => "Host started the live workflow",
        HostActionEventKind::ApplyRebooting => "Host restart reported",
        HostActionEventKind::ApplyPassed => "Live workflow passed",
        HostActionEventKind::ApplyFailed => "Live workflow stopped",
        HostActionEventKind::RecoveryQueued => "Recovery verification queued",
        HostActionEventKind::RecoveryClaimed => "Host started recovery verification",
        HostActionEventKind::RecoveryRebooting => "Recovery is waiting for the host",
        HostActionEventKind::RecoveryPassed => "Recovery verification passed",
        HostActionEventKind::RecoveryFailed => "Recovery verification stopped",
        HostActionEventKind::SettingsRequestAccepted => "Settings request accepted",
        HostActionEventKind::SettingsApplied => "Host reported the requested settings",
        HostActionEventKind::SettingsFailed => "Settings request stopped",
        HostActionEventKind::RemovalAccessRevoked => "Host reporting access revoked",
        HostActionEventKind::RemovalDeclarationCompleted => "Declarative host entry removed",
        HostActionEventKind::RemovalCredentialClaimed => {
            "Retirement owner started credential retirement"
        }
        HostActionEventKind::RemovalCredentialRetired => "Host credential retired",
        HostActionEventKind::RemovalCredentialFailed => "Host credential retirement stopped",
        HostActionEventKind::RemovalCredentialRetryQueued => {
            "Host credential retirement retry queued"
        }
        HostActionEventKind::RemovalFailed => "Host removal stopped",
        HostActionEventKind::RemovalCompleted => "Host retirement completed",
        HostActionEventKind::Cancelled => "Workflow cancelled before live change",
    }
    .to_string();
    if let Some(gate) = event.failure_gate {
        label.push_str(" at ");
        label.push_str(gate.label());
    }
    if let Some(mode) = event.recovery_mode {
        label.push_str(": ");
        label.push_str(mode.label());
    }
    if let Some(reason) = event.retirement_failure {
        label.push_str(" at ");
        label.push_str(reason.label());
    }
    label
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostActionSummary {
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) kind: HostActionKind,
    pub(crate) state: HostActionState,
    pub(crate) ticket: String,
    pub(crate) retry_of: Option<String>,
    pub(crate) retryable: bool,
    pub(crate) created_at: i64,
    pub(crate) updated_at: i64,
    pub(crate) plan: Option<HostActionPlan>,
    pub(crate) removal_plan: Option<HostRemovalPlan>,
    pub(crate) result: Option<HostActionResult>,
    pub(crate) workflow: HostWorkflowSummary,
}

fn host_action_priority(job: &HostActionJob) -> u8 {
    match (job.workflow_kind(), job.state) {
        (HostWorkflowKind::RemoveHost, HostActionState::Succeeded | HostActionState::Cancelled) => {
            0
        }
        (HostWorkflowKind::RemoveHost, _) => 4,
        (
            HostWorkflowKind::UpdateRestart,
            HostActionState::Succeeded | HostActionState::Cancelled,
        ) => 0,
        (HostWorkflowKind::UpdateRestart, _) => 3,
        (HostWorkflowKind::SettingsChange, HostActionState::Succeeded) => 0,
        (HostWorkflowKind::SettingsChange, HostActionState::Cancelled) => 0,
        (HostWorkflowKind::SettingsChange, _) => 2,
        (
            HostWorkflowKind::SystemUpdateProposal,
            HostActionState::Succeeded | HostActionState::Cancelled,
        ) => 0,
        (HostWorkflowKind::SystemUpdateProposal, _) => 1,
    }
}

fn lifecycle_run_slot(job: &HostActionJob) -> Option<HostLifecycleSlot> {
    match (job.workflow_kind(), job.state) {
        (HostWorkflowKind::RemoveHost, HostActionState::Succeeded | HostActionState::Cancelled) => {
            None
        }
        (HostWorkflowKind::RemoveHost, _) => Some(HostLifecycleSlot::RemoveHost),
        (
            HostWorkflowKind::UpdateRestart,
            HostActionState::Succeeded | HostActionState::Cancelled,
        ) => None,
        (HostWorkflowKind::UpdateRestart, _) => Some(HostLifecycleSlot::UpdateRestart),
        (HostWorkflowKind::SettingsChange, HostActionState::Succeeded) => None,
        (HostWorkflowKind::SettingsChange, _) => Some(HostLifecycleSlot::SettingsChange),
        (
            HostWorkflowKind::SystemUpdateProposal,
            HostActionState::Succeeded | HostActionState::Cancelled,
        ) => None,
        (HostWorkflowKind::SystemUpdateProposal, _) => {
            Some(HostLifecycleSlot::SystemUpdateProposal)
        }
    }
}

fn lifecycle_run_priority(job: &HostActionJob) -> u8 {
    match lifecycle_run_slot(job) {
        Some(HostLifecycleSlot::RemoveHost) => 4,
        Some(HostLifecycleSlot::UpdateRestart) => 3,
        Some(HostLifecycleSlot::SettingsChange) => 2,
        Some(HostLifecycleSlot::SystemUpdateProposal) => 1,
        Some(
            HostLifecycleSlot::PrefsDrift
            | HostLifecycleSlot::KernelDrift
            | HostLifecycleSlot::Quiet,
        )
        | None => 0,
    }
}

fn dedupe_latest_workflow_jobs<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Vec<&'a HostActionJob> {
    jobs.iter()
        .filter(|job| {
            job.host == host
                && !jobs.iter().any(|other| {
                    other.host == host
                        && other.workflow_kind() == job.workflow_kind()
                        && (other.created_at, other.updated_at, &other.id)
                            > (job.created_at, job.updated_at, &job.id)
                })
        })
        .collect()
}

fn most_relevant_action_with_priority<'a, F>(
    jobs: &'a [HostActionJob],
    host: &str,
    priority: F,
) -> Option<&'a HostActionJob>
where
    F: Fn(&HostActionJob) -> u8,
{
    dedupe_latest_workflow_jobs(jobs, host)
        .into_iter()
        .max_by_key(|job| (priority(job), job.updated_at, job.created_at))
}

fn most_relevant_action<'a>(jobs: &'a [HostActionJob], host: &str) -> Option<&'a HostActionJob> {
    most_relevant_action_with_priority(jobs, host, host_action_priority)
}

pub(crate) fn most_relevant_host_action<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Option<&'a HostActionJob> {
    most_relevant_action(jobs, host)
}

fn most_relevant_lifecycle_run<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Option<&'a HostActionJob> {
    dedupe_latest_workflow_jobs(jobs, host)
        .into_iter()
        .filter(|job| lifecycle_run_slot(job).is_some())
        .max_by_key(|job| (lifecycle_run_priority(job), job.updated_at, job.created_at))
}

fn most_relevant_host_action_refs<'a>(
    jobs: &'a BTreeMap<String, HostActionJob>,
    host: &str,
) -> Option<&'a HostActionJob> {
    jobs.values()
        .filter(|job| job.host == host)
        .filter(|job| {
            !jobs.values().any(|other| {
                other.host == host
                    && other.workflow_kind() == job.workflow_kind()
                    && (other.created_at, other.updated_at, &other.id)
                        > (job.created_at, job.updated_at, &job.id)
            })
        })
        .max_by_key(|job| (host_action_priority(job), job.updated_at, job.created_at))
}

fn run_lifecycle(job: &HostActionJob, slot: HostLifecycleSlot) -> HostLifecycle {
    let workflow = job.workflow();
    let (label, level, detail, blocked_by) = if job.workflow_kind()
        == HostWorkflowKind::SettingsChange
        && job.state == HostActionState::Cancelled
    {
        (
            "settings change cancelled".to_string(),
            "clear",
            "The settings request was cancelled before the host reported the requested values."
                .to_string(),
            Vec::new(),
        )
    } else {
        (
            workflow.status_label,
            workflow.status_level,
            workflow.guidance,
            workflow.current_step.into_iter().collect(),
        )
    };
    HostLifecycle {
        schema: HOST_LIFECYCLE_SCHEMA,
        version: HOST_LIFECYCLE_VERSION,
        slot,
        label,
        level,
        invoke: if slot == HostLifecycleSlot::UpdateRestart {
            HostLifecycleInvoke::UpdateRestart
        } else {
            HostLifecycleInvoke::Workflow
        },
        run_id: Some(job.id.clone()),
        detail,
        blocked_by,
    }
}

pub(crate) fn host_lifecycle(
    jobs: &[HostActionJob],
    host: &str,
    preferences: HostPreferencesState,
    kernel_drift: bool,
) -> HostLifecycle {
    let action = most_relevant_lifecycle_run(jobs, host);
    if let Some((job, slot)) = action
        .and_then(|job| lifecycle_run_slot(job).map(|slot| (job, slot)))
        .filter(|(_, slot)| *slot != HostLifecycleSlot::SystemUpdateProposal)
    {
        return run_lifecycle(job, slot);
    }

    match preferences {
        HostPreferencesState::RequestPending => {
            return HostLifecycle {
                schema: HOST_LIFECYCLE_SCHEMA,
                version: HOST_LIFECYCLE_VERSION,
                slot: HostLifecycleSlot::PrefsDrift,
                label: "Change requested".to_string(),
                level: "warning",
                invoke: HostLifecycleInvoke::HostSettings,
                run_id: None,
                detail: "Requested preferences have not yet been observed by the host.".to_string(),
                blocked_by: vec!["host_report".to_string()],
            };
        }
        HostPreferencesState::DeclaredNotApplied => {
            return HostLifecycle {
                schema: HOST_LIFECYCLE_SCHEMA,
                version: HOST_LIFECYCLE_VERSION,
                slot: HostLifecycleSlot::PrefsDrift,
                label: "Ready to apply".to_string(),
                level: "info",
                invoke: HostLifecycleInvoke::HostSettings,
                run_id: None,
                detail: "Declared preferences differ from the host's observed preferences."
                    .to_string(),
                blocked_by: Vec::new(),
            };
        }
        HostPreferencesState::Applied => {}
    }

    if kernel_drift {
        return HostLifecycle {
            schema: HOST_LIFECYCLE_SCHEMA,
            version: HOST_LIFECYCLE_VERSION,
            slot: HostLifecycleSlot::KernelDrift,
            label: "Restart required".to_string(),
            level: "warning",
            invoke: HostLifecycleInvoke::KernelDetails,
            run_id: None,
            detail: "The running kernel differs from the kernel ready after restart.".to_string(),
            blocked_by: vec!["planned_restart".to_string()],
        };
    }

    if let Some((job, HostLifecycleSlot::SystemUpdateProposal)) =
        action.and_then(|job| lifecycle_run_slot(job).map(|slot| (job, slot)))
    {
        return run_lifecycle(job, HostLifecycleSlot::SystemUpdateProposal);
    }

    HostLifecycle {
        schema: HOST_LIFECYCLE_SCHEMA,
        version: HOST_LIFECYCLE_VERSION,
        slot: HostLifecycleSlot::Quiet,
        label: "Up to date".to_string(),
        level: "clear",
        invoke: HostLifecycleInvoke::HostSettings,
        run_id: None,
        detail: "No host lifecycle work is waiting.".to_string(),
        blocked_by: Vec::new(),
    }
}

fn valid_action_jobs(jobs: &BTreeMap<String, HostActionJob>) -> bool {
    jobs.values().all(|job| {
        job.validate()
            && job.retry_of.as_ref().is_none_or(|retry_of| {
                jobs.get(retry_of).is_some_and(|failed| {
                    failed.host == job.host
                        && failed.kind == HostActionKind::UpdateRestart
                        && failed.state == HostActionState::Failed
                        && job.kind == HostActionKind::UpdateRestart
                        && failed.created_at <= job.created_at
                })
            })
    })
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentActionPhase {
    Review,
    Apply,
    Resume,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct AgentActionLease {
    pub(crate) schema: &'static str,
    pub(crate) version: u16,
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) ticket: String,
    pub(crate) phase: AgentActionPhase,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum AgentActionOutcome {
    Succeeded,
    Rebooting,
    Failed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AgentActionResultRequest {
    pub(crate) host: String,
    pub(crate) phase: AgentActionPhase,
    pub(crate) outcome: AgentActionOutcome,
    pub(crate) plan: Option<HostActionPlan>,
    pub(crate) result: Option<HostActionResult>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct RetirementAgentLease {
    pub(crate) schema: &'static str,
    pub(crate) version: u16,
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) ticket: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetirementAgentOutcome {
    Succeeded,
    Failed,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RetirementAgentResultRequest {
    pub(crate) owner: String,
    pub(crate) host: String,
    pub(crate) outcome: RetirementAgentOutcome,
    #[serde(default)]
    pub(crate) reason: Option<RetirementFailureReason>,
}

impl RetirementAgentResultRequest {
    fn valid(&self) -> bool {
        valid_host_name(&self.owner)
            && valid_host_name(&self.host)
            && match self.outcome {
                RetirementAgentOutcome::Succeeded => self.reason.is_none(),
                RetirementAgentOutcome::Failed => self.reason.is_some(),
            }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostActionStoreError {
    ActiveJob,
    FailedJobRequiresRetry,
    InvalidJob,
    NotFound,
    WrongHost,
    InvalidTransition,
    ReviewFailed,
    BlockedByFleetGate,
    Persistence,
}

pub(crate) struct HostActionStore {
    path: Option<PathBuf>,
    jobs: RwLock<BTreeMap<String, HostActionJob>>,
}

struct NewHostAction<'a> {
    id: String,
    host: &'a str,
    kind: HostActionKind,
    actor: &'a str,
    ticket: &'a str,
    state: HostActionState,
    removal_plan: Option<HostRemovalPlan>,
    now: i64,
}

impl HostActionStore {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        let jobs = path
            .as_ref()
            .and_then(|path| read_persisted_state(path, "guarded host action"))
            .map(|jobs| {
                let mut jobs: Vec<HostActionJob> = serde_json::from_slice(&jobs)
                    .unwrap_or_else(|_| panic!("guarded host action state is malformed"));
                for job in &mut jobs {
                    if job.kind == HostActionKind::RemoveHost && job.removal_plan.is_none() {
                        job.removal_plan = Some(HostRemovalPlan {
                            disposition: HostRetirementDisposition::Unmanaged,
                            successor: None,
                            declaration_pending: job.state == HostActionState::RemovalPending,
                            credential_retirement_required: false,
                        });
                    }
                    if job.events.is_empty() {
                        let kind = legacy_state_event_kind(job);
                        job.events.push(HostActionEvent {
                            at: job.updated_at,
                            state: job.state,
                            source: HostActionEventSource::Pharos,
                            kind,
                            actor: None,
                            failure_gate: None,
                            recovery_mode: None,
                            retirement_failure: None,
                        });
                    }
                }
                let jobs: BTreeMap<_, _> =
                    jobs.into_iter().map(|job| (job.id.clone(), job)).collect();
                assert!(
                    valid_action_jobs(&jobs),
                    "guarded host action state failed validation"
                );
                jobs
            })
            .unwrap_or_default();
        Self {
            path,
            jobs: RwLock::new(jobs),
        }
    }

    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        derived_path(host_store_path, "host-actions")
    }

    pub(crate) fn list(&self) -> Vec<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn get(&self, id: &str) -> Option<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .get(id)
            .cloned()
    }

    #[cfg(test)]
    pub(crate) fn latest_for_host(&self, host: &str) -> Option<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .values()
            .filter(|job| job.host == host)
            .max_by_key(|job| job.updated_at)
            .cloned()
    }

    pub(crate) fn most_relevant_for_host(&self, host: &str) -> Option<HostActionJob> {
        let jobs = self.jobs.read().expect("host action store lock");
        most_relevant_host_action_refs(&jobs, host).cloned()
    }

    fn record_proposal(
        &self,
        proposal: NewHostAction<'_>,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: proposal.id,
            host: proposal.host.to_string(),
            kind: proposal.kind,
            workflow_kind: None,
            state: proposal.state,
            requested_by: proposal.actor.to_string(),
            ticket: proposal.ticket.to_string(),
            retry_of: None,
            created_at: proposal.now,
            updated_at: proposal.now,
            confirmed_at: None,
            plan: None,
            removal_plan: proposal.removal_plan,
            result: None,
            recovery_started_at: None,
            events: Vec::new(),
            lease_phase: None,
            lease_until: None,
            retirement_lease_until: None,
        };
        job.record_event(
            proposal.now,
            HostActionEventSource::Operator,
            HostActionEventKind::Requested,
            Some(proposal.actor),
        );
        self.insert(job)
    }

    pub(crate) fn create_system_update_proposal(
        &self,
        id: String,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.record_proposal(NewHostAction {
            id,
            host,
            kind: HostActionKind::SystemUpdateProposal,
            actor,
            ticket: "PHAROS-125",
            state: HostActionState::ProposalRequested,
            removal_plan: None,
            now,
        })
    }

    pub(crate) fn begin_system_update_proposal(
        &self,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.create_system_update_proposal(action_id("system-update", host, now), host, actor, now)
    }

    pub(crate) fn accept_system_update_proposal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_system_update_proposal(id, now, false)
    }

    pub(crate) fn fail_system_update_proposal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_system_update_proposal(id, now, true)
    }

    fn update_system_update_proposal(
        &self,
        id: &str,
        now: i64,
        failed: bool,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.workflow_kind() != HostWorkflowKind::SystemUpdateProposal
                || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            if failed {
                job.state = HostActionState::Failed;
            }
            job.updated_at = now;
            job.record_event(
                now,
                HostActionEventSource::Pharos,
                if failed {
                    HostActionEventKind::DispatchFailed
                } else {
                    HostActionEventKind::DispatchAccepted
                },
                None,
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn create_update_review(
        &self,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        if Self::has_active(&jobs, host, HostActionKind::UpdateRestart) {
            return Err(HostActionStoreError::ActiveJob);
        }
        if Self::latest_update_for(&jobs, host)
            .is_some_and(|job| job.state == HostActionState::Failed)
        {
            return Err(HostActionStoreError::FailedJobRequiresRetry);
        }
        if Self::blocked_by_other_update(&jobs, host) {
            return Err(HostActionStoreError::BlockedByFleetGate);
        }
        let job = Self::new_update_review(host, actor, now, None);
        self.insert_locked(&mut jobs, job)
    }

    pub(crate) fn retry_update_review(
        &self,
        id: &str,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let existing = jobs.get(id).ok_or(HostActionStoreError::NotFound)?;
        if existing.host != host {
            return Err(HostActionStoreError::WrongHost);
        }
        if !existing.review_retryable()
            || Self::latest_update_for(&jobs, host).is_none_or(|job| job.id != id)
        {
            return Err(HostActionStoreError::InvalidTransition);
        }
        if Self::has_active(&jobs, host, HostActionKind::UpdateRestart) {
            return Err(HostActionStoreError::ActiveJob);
        }
        if Self::blocked_by_other_update(&jobs, host) {
            return Err(HostActionStoreError::BlockedByFleetGate);
        }
        let job = Self::new_update_review(host, actor, now, Some(id.to_string()));
        self.insert_locked(&mut jobs, job)
    }

    pub(crate) fn cancel_update_review(
        &self,
        id: &str,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        if Self::latest_update_for(&jobs, host).is_none_or(|job| job.id != id) {
            return Err(HostActionStoreError::InvalidTransition);
        }
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.host != host {
                return Err(HostActionStoreError::WrongHost);
            }
            if !job.can_cancel() {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.state = HostActionState::Cancelled;
            job.updated_at = now;
            job.lease_phase = None;
            job.lease_until = None;
            job.record_event(
                now,
                HostActionEventSource::Operator,
                HostActionEventKind::Cancelled,
                Some(actor),
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    #[cfg(test)]
    pub(crate) fn create_removal(
        &self,
        host: &str,
        actor: &str,
        dispatch_id: Option<String>,
        removal_plan: HostRemovalPlan,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        if Self::has_active(
            &self.jobs.read().expect("host action store lock"),
            host,
            HostActionKind::RemoveHost,
        ) {
            return Err(HostActionStoreError::ActiveJob);
        }
        self.record_proposal(NewHostAction {
            id: dispatch_id.unwrap_or_else(|| action_id("remove-host", host, now)),
            host,
            kind: HostActionKind::RemoveHost,
            actor,
            ticket: "PHAROS-127",
            state: if removal_plan.declaration_pending
                || removal_plan.credential_retirement_required
            {
                HostActionState::RemovalPending
            } else {
                HostActionState::Succeeded
            },
            removal_plan: Some(removal_plan),
            now,
        })
    }

    pub(crate) fn begin_removal(
        &self,
        host: &str,
        actor: &str,
        removal_plan: HostRemovalPlan,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        if Self::has_active(
            &self.jobs.read().expect("host action store lock"),
            host,
            HostActionKind::RemoveHost,
        ) {
            return Err(HostActionStoreError::ActiveJob);
        }
        self.record_proposal(NewHostAction {
            id: action_id("remove-host", host, now),
            host,
            kind: HostActionKind::RemoveHost,
            actor,
            ticket: "PHAROS-127",
            state: HostActionState::ProposalRequested,
            removal_plan: Some(removal_plan),
            now,
        })
    }

    pub(crate) fn mark_removal_access_revoked(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.kind != HostActionKind::RemoveHost {
                return Err(HostActionStoreError::InvalidTransition);
            }
            if matches!(
                job.state,
                HostActionState::RemovalPending | HostActionState::Succeeded
            ) {
                return Ok(job.clone());
            }
            if job.state != HostActionState::ProposalRequested {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let declaration_pending = job
                .removal_plan
                .as_ref()
                .is_some_and(|plan| plan.declaration_pending);
            let credential_retirement_required = job.credential_retirement_required();
            job.state = if declaration_pending || credential_retirement_required {
                HostActionState::RemovalPending
            } else {
                HostActionState::Succeeded
            };
            job.updated_at = now;
            job.record_event(
                now,
                HostActionEventSource::Pharos,
                HostActionEventKind::RemovalAccessRevoked,
                None,
            );
            if !declaration_pending && !credential_retirement_required {
                job.record_event(
                    now,
                    HostActionEventSource::Pharos,
                    HostActionEventKind::RemovalCompleted,
                    None,
                );
            }
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn fail_removal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.kind != HostActionKind::RemoveHost
                || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.state = HostActionState::Failed;
            job.updated_at = now;
            job.record_event(
                now,
                HostActionEventSource::Pharos,
                HostActionEventKind::RemovalFailed,
                None,
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn begin_settings_change(
        &self,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        if jobs.values().any(|job| {
            job.host == host
                && job.workflow_kind() == HostWorkflowKind::SettingsChange
                && !job.state.is_terminal()
        }) {
            return Err(HostActionStoreError::ActiveJob);
        }
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("settings-change", host, now),
            host: host.to_string(),
            // Keep the persisted v1 action enum backward-readable. New clients
            // use workflow_kind for the precise user-facing workflow.
            kind: HostActionKind::SystemUpdateProposal,
            workflow_kind: Some(HostWorkflowKind::SettingsChange),
            state: HostActionState::ProposalRequested,
            requested_by: actor.to_string(),
            ticket: "PHAROS-129".to_string(),
            retry_of: None,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            plan: None,
            removal_plan: None,
            result: None,
            recovery_started_at: None,
            events: Vec::new(),
            lease_phase: None,
            lease_until: None,
            retirement_lease_until: None,
        };
        job.record_event(
            now,
            HostActionEventSource::Operator,
            HostActionEventKind::Requested,
            Some(actor),
        );
        self.insert_locked(&mut jobs, job)
    }

    pub(crate) fn accept_settings_change(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_settings_change(id, now, |job| {
            job.record_event(
                now,
                HostActionEventSource::Pharos,
                HostActionEventKind::SettingsRequestAccepted,
                None,
            );
        })
    }

    pub(crate) fn fail_settings_change(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_settings_change(id, now, |job| {
            job.state = HostActionState::Failed;
            job.record_event(
                now,
                HostActionEventSource::Pharos,
                HostActionEventKind::SettingsFailed,
                None,
            );
        })
    }

    pub(crate) fn complete_settings_change(
        &self,
        host: &str,
        now: i64,
    ) -> Result<Option<HostActionJob>, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let Some(id) = jobs
            .values()
            .filter(|job| {
                job.host == host
                    && job.workflow_kind() == HostWorkflowKind::SettingsChange
                    && job.state == HostActionState::ProposalRequested
            })
            .max_by_key(|job| (job.created_at, job.updated_at))
            .map(|job| job.id.clone())
        else {
            return Ok(None);
        };
        let (previous, updated) = {
            let job = jobs.get_mut(&id).expect("selected settings workflow");
            let previous = job.clone();
            job.state = HostActionState::Succeeded;
            job.updated_at = now;
            job.record_event(
                now,
                HostActionEventSource::Beacon,
                HostActionEventKind::SettingsApplied,
                None,
            );
            (previous, job.clone())
        };
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id, previous);
            return Err(error);
        }
        Ok(Some(updated))
    }

    fn update_settings_change(
        &self,
        id: &str,
        now: i64,
        update: impl FnOnce(&mut HostActionJob),
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.workflow_kind() != HostWorkflowKind::SettingsChange
                || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.updated_at = now;
            update(job);
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn queue_recovery(
        &self,
        id: &str,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        if Self::blocked_by_other_update(&jobs, host) {
            return Err(HostActionStoreError::BlockedByFleetGate);
        }
        if Self::latest_update_for(&jobs, host).is_none_or(|job| job.id != id) {
            return Err(HostActionStoreError::InvalidTransition);
        }
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.host != host {
                return Err(HostActionStoreError::WrongHost);
            }
            if !job.recoverable() {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.state = HostActionState::Rebooting;
            job.recovery_started_at.get_or_insert(now);
            job.updated_at = now;
            job.lease_phase = None;
            job.lease_until = None;
            job.record_event(
                now,
                HostActionEventSource::Operator,
                HostActionEventKind::RecoveryQueued,
                Some(actor),
            );
            (previous, job.clone())
        };
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn confirm_update(
        &self,
        id: &str,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.host != host {
                return Err(HostActionStoreError::WrongHost);
            }
            if job.kind != HostActionKind::UpdateRestart
                || job.state != HostActionState::AwaitingConfirmation
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            if !job.plan.as_ref().is_some_and(HostActionPlan::ready) {
                return Err(HostActionStoreError::ReviewFailed);
            }
            let previous = job.clone();
            job.state = HostActionState::QueuedApply;
            job.confirmed_at = Some(now);
            job.updated_at = now;
            job.lease_phase = None;
            job.lease_until = None;
            job.record_event(
                now,
                HostActionEventSource::Operator,
                HostActionEventKind::Confirmed,
                Some(actor),
            );
            (previous, job.clone())
        };
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn claim(
        &self,
        host: &str,
        now: i64,
    ) -> Result<Option<AgentActionLease>, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        if Self::blocked_by_other_update(&jobs, host) {
            return Err(HostActionStoreError::BlockedByFleetGate);
        }
        let candidate = jobs
            .values_mut()
            .filter(|job| job.host == host && job.kind == HostActionKind::UpdateRestart)
            .filter_map(|job| {
                let phase = match job.state {
                    HostActionState::QueuedReview => Some(AgentActionPhase::Review),
                    HostActionState::Reviewing
                        if job.lease_until.is_some_and(|until| until <= now) =>
                    {
                        job.lease_phase
                    }
                    HostActionState::QueuedApply => Some(AgentActionPhase::Apply),
                    HostActionState::Applying
                        if job.lease_until.is_some_and(|until| until <= now) =>
                    {
                        job.lease_phase
                    }
                    HostActionState::Rebooting => Some(AgentActionPhase::Resume),
                    _ => None,
                }?;
                Some((job.created_at, job, phase))
            })
            .min_by_key(|(created_at, _, _)| *created_at);
        let Some((_, job, phase)) = candidate else {
            return Ok(None);
        };
        let previous = job.clone();
        let recovery = job.recovery_started_at.is_some() && phase == AgentActionPhase::Resume;
        job.state = match phase {
            AgentActionPhase::Review => HostActionState::Reviewing,
            AgentActionPhase::Apply | AgentActionPhase::Resume => HostActionState::Applying,
        };
        job.updated_at = now;
        job.lease_phase = Some(phase);
        job.lease_until = Some(now.saturating_add(LEASE_SECS));
        job.record_event(
            now,
            HostActionEventSource::HostAgent,
            match (phase, recovery) {
                (AgentActionPhase::Review, _) => HostActionEventKind::ReviewClaimed,
                (AgentActionPhase::Resume, true) => HostActionEventKind::RecoveryClaimed,
                (AgentActionPhase::Apply, _) | (AgentActionPhase::Resume, false) => {
                    HostActionEventKind::ApplyClaimed
                }
            },
            None,
        );
        let lease = AgentActionLease {
            schema: "inspr.pharos.host-action-lease.v1",
            version: 1,
            id: job.id.clone(),
            host: job.host.clone(),
            ticket: job.ticket.clone(),
            phase,
        };
        let id = job.id.clone();
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id, previous);
            return Err(error);
        }
        Ok(Some(lease))
    }

    pub(crate) fn record_agent_result(
        &self,
        id: &str,
        host: &str,
        request: AgentActionResultRequest,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.host != host {
                return Err(HostActionStoreError::WrongHost);
            }
            let state_accepts_phase = matches!(
                (job.state, request.phase),
                (HostActionState::Reviewing, AgentActionPhase::Review)
                    | (HostActionState::Applying, AgentActionPhase::Apply)
                    | (HostActionState::Applying, AgentActionPhase::Resume)
            );
            if !state_accepts_phase || job.lease_phase != Some(request.phase) {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let recovery =
                job.recovery_started_at.is_some() && request.phase == AgentActionPhase::Resume;
            let failure_gate = request
                .result
                .as_ref()
                .and_then(|result| result.failure_gate);
            let recovery_mode = request
                .result
                .as_ref()
                .and_then(|result| result.recovery_mode);
            let event_kind;
            match (request.phase, request.outcome) {
                (AgentActionPhase::Review, AgentActionOutcome::Succeeded) => {
                    if request.result.is_some() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    let plan = request.plan.ok_or(HostActionStoreError::InvalidJob)?;
                    if !plan.validate() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.plan = Some(plan);
                    job.state = HostActionState::AwaitingConfirmation;
                    event_kind = HostActionEventKind::ReviewPassed;
                }
                (AgentActionPhase::Review, AgentActionOutcome::Failed) => {
                    if recovery_mode.is_some() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.state = HostActionState::Failed;
                    event_kind = HostActionEventKind::ReviewFailed;
                }
                (
                    AgentActionPhase::Apply | AgentActionPhase::Resume,
                    AgentActionOutcome::Rebooting,
                ) => {
                    if request.result.is_some() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.state = HostActionState::Rebooting;
                    event_kind = if recovery {
                        HostActionEventKind::RecoveryRebooting
                    } else {
                        HostActionEventKind::ApplyRebooting
                    };
                }
                (
                    AgentActionPhase::Apply | AgentActionPhase::Resume,
                    AgentActionOutcome::Succeeded,
                ) => {
                    let result = request.result.ok_or(HostActionStoreError::InvalidJob)?;
                    if !(result.backup_validated
                        && result.switch_passed
                        && result.reboot_observed
                        && result.kernel_verified
                        && result.rollback_available)
                        || result.failure_gate.is_some()
                        || (!recovery && result.recovery_mode.is_some())
                    {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.result = Some(result);
                    job.state = HostActionState::Succeeded;
                    event_kind = if recovery {
                        HostActionEventKind::RecoveryPassed
                    } else {
                        HostActionEventKind::ApplyPassed
                    };
                }
                (_, AgentActionOutcome::Failed) => {
                    if recovery_mode.is_some() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.state = HostActionState::Failed;
                    event_kind = if recovery {
                        HostActionEventKind::RecoveryFailed
                    } else if request.phase == AgentActionPhase::Review {
                        HostActionEventKind::ReviewFailed
                    } else {
                        HostActionEventKind::ApplyFailed
                    };
                }
                _ => return Err(HostActionStoreError::InvalidTransition),
            }
            job.updated_at = now;
            job.lease_phase = None;
            job.lease_until = None;
            let event_failed = matches!(
                event_kind,
                HostActionEventKind::ReviewFailed
                    | HostActionEventKind::ApplyFailed
                    | HostActionEventKind::RecoveryFailed
            );
            job.record_event_with_evidence(
                now,
                HostActionEventSource::HostAgent,
                event_kind,
                None,
                event_failed.then_some(failure_gate).flatten(),
                (event_kind == HostActionEventKind::RecoveryPassed)
                    .then_some(recovery_mode)
                    .flatten(),
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn complete_removal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<Option<HostActionJob>, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let Some(job) = jobs.get_mut(id) else {
            return Ok(None);
        };
        if job.kind != HostActionKind::RemoveHost || job.state != HostActionState::RemovalPending {
            return Ok(None);
        }
        if !job.removal_gates_ready() || job.retirement_lease_until.is_some() {
            return Ok(None);
        }
        let previous = job.clone();
        job.state = HostActionState::Succeeded;
        job.updated_at = now;
        job.record_event(
            now,
            HostActionEventSource::Pharos,
            HostActionEventKind::RemovalCompleted,
            None,
        );
        let updated = job.clone();
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(Some(updated))
    }

    pub(crate) fn mark_removal_declaration_completed(
        &self,
        id: &str,
        now: i64,
    ) -> Result<Option<HostActionJob>, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let Some(job) = jobs.get_mut(id) else {
            return Ok(None);
        };
        if job.kind != HostActionKind::RemoveHost || job.state != HostActionState::RemovalPending {
            return Ok(None);
        }
        if job.declaration_removed() {
            return Ok(Some(job.clone()));
        }
        let previous = job.clone();
        job.updated_at = now;
        job.record_event(
            now,
            HostActionEventSource::Pharos,
            HostActionEventKind::RemovalDeclarationCompleted,
            None,
        );
        let updated = job.clone();
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(Some(updated))
    }

    pub(crate) fn claim_retirement(
        &self,
        owner: &str,
        now: i64,
    ) -> Result<Option<RetirementAgentLease>, HostActionStoreError> {
        if !valid_host_name(owner) {
            return Err(HostActionStoreError::InvalidJob);
        }
        let mut jobs = self.jobs.write().expect("host action store lock");
        let candidate = jobs
            .values()
            .filter(|job| {
                job.kind == HostActionKind::RemoveHost
                    && job.state == HostActionState::RemovalPending
                    && job.removal_access_revoked()
                    && job.declaration_removed()
                    && job.credential_retirement_required()
                    && !job.credentials_retired()
                    && !job.credential_retry_required()
                    && job.retirement_lease_until.is_none_or(|until| until <= now)
            })
            .min_by_key(|job| (job.created_at, &job.id))
            .map(|job| job.id.clone());
        let Some(id) = candidate else {
            return Ok(None);
        };
        let (previous, updated, lease) = {
            let job = jobs.get_mut(&id).expect("retirement candidate exists");
            let previous = job.clone();
            job.updated_at = now;
            job.retirement_lease_until = Some(now + RETIREMENT_LEASE_SECS);
            job.record_event(
                now,
                HostActionEventSource::RetirementAgent,
                HostActionEventKind::RemovalCredentialClaimed,
                Some(owner),
            );
            let lease = RetirementAgentLease {
                schema: "inspr.pharos.retirement-agent-lease.v1",
                version: 1,
                id: job.id.clone(),
                host: job.host.clone(),
                ticket: job.ticket.clone(),
            };
            (previous, job.clone(), lease)
        };
        if !updated.validate() {
            jobs.insert(id, previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id, previous);
            return Err(error);
        }
        Ok(Some(lease))
    }

    pub(crate) fn record_retirement_result(
        &self,
        id: &str,
        request: &RetirementAgentResultRequest,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        if !request.valid() {
            return Err(HostActionStoreError::InvalidJob);
        }
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.host != request.host {
                return Err(HostActionStoreError::WrongHost);
            }
            if job.kind != HostActionKind::RemoveHost
                || job.state != HostActionState::RemovalPending
                || job.retirement_lease_until.is_none()
                || !job.declaration_removed()
                || !job.credential_retirement_required()
                || job.credentials_retired()
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.updated_at = now;
            job.retirement_lease_until = None;
            let event_kind = match request.outcome {
                RetirementAgentOutcome::Succeeded => HostActionEventKind::RemovalCredentialRetired,
                RetirementAgentOutcome::Failed => HostActionEventKind::RemovalCredentialFailed,
            };
            job.events.push(HostActionEvent {
                at: now,
                state: job.state,
                source: HostActionEventSource::RetirementAgent,
                kind: event_kind,
                actor: Some(request.owner.clone()),
                failure_gate: None,
                recovery_mode: None,
                retirement_failure: request.reason,
            });
            if request.outcome == RetirementAgentOutcome::Succeeded && job.removal_gates_ready() {
                job.state = HostActionState::Succeeded;
                job.record_event(
                    now,
                    HostActionEventSource::Pharos,
                    HostActionEventKind::RemovalCompleted,
                    None,
                );
            }
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn retry_retirement(
        &self,
        id: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.kind != HostActionKind::RemoveHost
                || job.state != HostActionState::RemovalPending
                || !job.credential_retry_required()
                || job.retirement_lease_until.is_some()
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.updated_at = now;
            job.record_event(
                now,
                HostActionEventSource::Operator,
                HostActionEventKind::RemovalCredentialRetryQueued,
                Some(actor),
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(updated)
    }

    fn new_update_review(
        host: &str,
        actor: &str,
        now: i64,
        retry_of: Option<String>,
    ) -> HostActionJob {
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("update-restart", host, now),
            host: host.to_string(),
            kind: HostActionKind::UpdateRestart,
            workflow_kind: None,
            state: HostActionState::QueuedReview,
            requested_by: actor.to_string(),
            ticket: "PHAROS-126".to_string(),
            retry_of,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            plan: None,
            removal_plan: None,
            result: None,
            recovery_started_at: None,
            events: Vec::new(),
            lease_phase: None,
            lease_until: None,
            retirement_lease_until: None,
        };
        job.record_event(
            now,
            HostActionEventSource::Operator,
            HostActionEventKind::Requested,
            Some(actor),
        );
        job
    }

    fn has_active(
        jobs: &BTreeMap<String, HostActionJob>,
        host: &str,
        kind: HostActionKind,
    ) -> bool {
        jobs.values()
            .any(|job| job.host == host && job.kind == kind && !job.state.is_terminal())
    }

    fn latest_update_for<'a>(
        jobs: &'a BTreeMap<String, HostActionJob>,
        host: &str,
    ) -> Option<&'a HostActionJob> {
        jobs.values()
            .filter(|job| job.kind == HostActionKind::UpdateRestart && job.host == host)
            .max_by(|left, right| {
                left.created_at
                    .cmp(&right.created_at)
                    .then_with(|| left.updated_at.cmp(&right.updated_at))
                    .then_with(|| left.id.cmp(&right.id))
            })
    }

    fn blocked_by_other_update(jobs: &BTreeMap<String, HostActionJob>, host: &str) -> bool {
        let mut latest_by_host: BTreeMap<&str, &HostActionJob> = BTreeMap::new();
        for job in jobs
            .values()
            .filter(|job| job.kind == HostActionKind::UpdateRestart)
        {
            let replace = latest_by_host.get(job.host.as_str()).is_none_or(|current| {
                (job.created_at, job.updated_at, &job.id)
                    > (current.created_at, current.updated_at, &current.id)
            });
            if replace {
                latest_by_host.insert(job.host.as_str(), job);
            }
        }
        latest_by_host.values().any(|job| {
            job.host != host
                && !matches!(
                    job.state,
                    HostActionState::Succeeded | HostActionState::Cancelled
                )
        })
    }

    fn insert(&self, job: HostActionJob) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        self.insert_locked(&mut jobs, job)
    }

    fn insert_locked(
        &self,
        jobs: &mut BTreeMap<String, HostActionJob>,
        job: HostActionJob,
    ) -> Result<HostActionJob, HostActionStoreError> {
        if !job.validate() {
            return Err(HostActionStoreError::InvalidJob);
        }
        if jobs.contains_key(&job.id) {
            return Err(HostActionStoreError::ActiveJob);
        }
        jobs.insert(job.id.clone(), job.clone());
        if !valid_action_jobs(jobs) {
            jobs.remove(&job.id);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(jobs) {
            jobs.remove(&job.id);
            return Err(error);
        }
        Ok(job)
    }

    fn persist_jobs(
        &self,
        jobs: &BTreeMap<String, HostActionJob>,
    ) -> Result<(), HostActionStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let snapshot: Vec<_> = jobs.values().cloned().collect();
        persist_json(path, &snapshot)
    }
}

fn legacy_state_event_kind(job: &HostActionJob) -> HostActionEventKind {
    match (job.workflow_kind(), job.state) {
        (_, HostActionState::Cancelled) => HostActionEventKind::Cancelled,
        (HostWorkflowKind::SettingsChange, HostActionState::Succeeded) => {
            HostActionEventKind::SettingsApplied
        }
        (HostWorkflowKind::SettingsChange, HostActionState::Failed) => {
            HostActionEventKind::SettingsFailed
        }
        (HostWorkflowKind::SystemUpdateProposal, HostActionState::ProposalRequested) => {
            HostActionEventKind::DispatchAccepted
        }
        (HostWorkflowKind::SystemUpdateProposal, HostActionState::Failed) => {
            HostActionEventKind::DispatchFailed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::AwaitingConfirmation) => {
            HostActionEventKind::ReviewPassed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::QueuedApply) => {
            HostActionEventKind::Confirmed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::Applying) => {
            HostActionEventKind::ApplyClaimed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::Rebooting) => {
            HostActionEventKind::ApplyRebooting
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::Succeeded) => {
            HostActionEventKind::ApplyPassed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::Failed)
            if job.confirmed_at.is_some() =>
        {
            HostActionEventKind::ApplyFailed
        }
        (HostWorkflowKind::UpdateRestart, HostActionState::Failed) => {
            HostActionEventKind::ReviewFailed
        }
        (HostWorkflowKind::RemoveHost, HostActionState::RemovalPending) => {
            HostActionEventKind::RemovalAccessRevoked
        }
        (HostWorkflowKind::RemoveHost, HostActionState::Succeeded) => {
            HostActionEventKind::RemovalCompleted
        }
        (HostWorkflowKind::RemoveHost, HostActionState::Failed) => {
            HostActionEventKind::RemovalFailed
        }
        _ => HostActionEventKind::StateRecovered,
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct RetiredHost {
    pub(crate) host: String,
    pub(crate) requested_by: String,
    pub(crate) removal_job_id: String,
    #[serde(default)]
    pub(crate) disposition: HostRetirementDisposition,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) successor: Option<String>,
    pub(crate) declaration_pending: bool,
    pub(crate) retired_at: i64,
}

impl RetiredHost {
    fn validate(&self) -> bool {
        valid_host_name(&self.host)
            && safe_actor(&self.requested_by)
            && safe_action_id(&self.removal_job_id)
            && self
                .disposition
                .validates_successor(&self.host, self.successor.as_deref())
            && self.retired_at > 0
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct RetiredHostDocument {
    schema: String,
    version: u16,
    hosts: Vec<RetiredHost>,
}

pub(crate) struct RetiredHostStore {
    path: Option<PathBuf>,
    hosts: RwLock<BTreeMap<String, RetiredHost>>,
}

impl RetiredHostStore {
    pub(crate) fn new(path: Option<PathBuf>) -> Self {
        let hosts = path
            .as_ref()
            .and_then(|path| read_persisted_state(path, "retired host"))
            .map(|bytes| {
                let document: RetiredHostDocument = serde_json::from_slice(&bytes)
                    .unwrap_or_else(|_| panic!("retired host state is malformed"));
                assert!(
                    document.schema == RETIRED_SCHEMA && matches!(document.version, 1 | 2),
                    "retired host state has an unsupported schema"
                );
                assert!(
                    document.hosts.iter().all(RetiredHost::validate),
                    "retired host state failed validation"
                );
                document
                    .hosts
                    .into_iter()
                    .map(|host| (host.host.clone(), host))
                    .collect()
            })
            .unwrap_or_default();
        Self {
            path,
            hosts: RwLock::new(hosts),
        }
    }

    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        derived_path(host_store_path, "retired-hosts")
    }

    pub(crate) fn is_retired(&self, host: &str) -> bool {
        self.hosts
            .read()
            .expect("retired host store lock")
            .contains_key(host)
    }

    pub(crate) fn list(&self) -> Vec<RetiredHost> {
        self.hosts
            .read()
            .expect("retired host store lock")
            .values()
            .cloned()
            .collect()
    }

    pub(crate) fn get(&self, host: &str) -> Option<RetiredHost> {
        self.hosts
            .read()
            .expect("retired host store lock")
            .get(host)
            .cloned()
    }

    pub(crate) fn retire(&self, retired: RetiredHost) -> Result<(), HostActionStoreError> {
        if !retired.validate() {
            return Err(HostActionStoreError::InvalidJob);
        }
        let mut hosts = self.hosts.write().expect("retired host store lock");
        let host = retired.host.clone();
        let previous = hosts.insert(host.clone(), retired);
        if let Err(error) = self.persist_hosts(&hosts) {
            match previous {
                Some(previous) => {
                    hosts.insert(host, previous);
                }
                None => {
                    hosts.remove(&host);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    pub(crate) fn clear(&self, host: &str) -> Result<bool, HostActionStoreError> {
        let mut hosts = self.hosts.write().expect("retired host store lock");
        let Some(removed) = hosts.remove(host) else {
            return Ok(false);
        };
        if let Err(error) = self.persist_hosts(&hosts) {
            hosts.insert(host.to_string(), removed);
            return Err(error);
        }
        Ok(true)
    }

    fn persist_hosts(
        &self,
        hosts: &BTreeMap<String, RetiredHost>,
    ) -> Result<(), HostActionStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let document = RetiredHostDocument {
            schema: RETIRED_SCHEMA.to_string(),
            version: RETIRED_VERSION,
            hosts: hosts.values().cloned().collect(),
        };
        persist_json(path, &document)
    }
}

fn action_id(action: &str, host: &str, now: i64) -> String {
    let counter = ACTION_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("action-{action}-{host}-{now}-{counter}")
}

fn derived_path(host_store_path: Option<&Path>, suffix: &str) -> Option<PathBuf> {
    host_store_path.map(|path| {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| !name.is_empty())
            .unwrap_or("pharos.json");
        path.with_file_name(format!("{file_name}.{suffix}.json"))
    })
}

fn read_persisted_state(path: &Path, label: &str) -> Option<Vec<u8>> {
    match std::fs::read(path) {
        Ok(bytes) => Some(bytes),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(_) => panic!("{label} state is unreadable"),
    }
}

fn persist_json<T: Serialize>(path: &Path, value: &T) -> Result<(), HostActionStoreError> {
    let json = serde_json::to_vec_pretty(value).map_err(|_| HostActionStoreError::Persistence)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|_| HostActionStoreError::Persistence)?;
    }
    let counter = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp-{}-{counter}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!("failed to durably persist guarded host action state");
        return Err(HostActionStoreError::Persistence);
    }
    Ok(())
}

fn valid_host_name(value: &str) -> bool {
    let bytes = value.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_ticket(value: &str) -> bool {
    let Some((project, number)) = value.split_once('-') else {
        return false;
    };
    (2..=16).contains(&project.len())
        && project.bytes().all(|byte| byte.is_ascii_uppercase())
        && !number.is_empty()
        && number.bytes().all(|byte| byte.is_ascii_digit())
}

fn safe_action_id(value: &str) -> bool {
    (8..=128).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase()
                || byte.is_ascii_uppercase()
                || byte.is_ascii_digit()
                || matches!(byte, b'-' | b'_')
        })
}

fn safe_actor(value: &str) -> bool {
    let value = value.trim();
    !value.is_empty()
        && value.len() <= 160
        && value.chars().all(|character| !character.is_control())
}

fn safe_area(value: &str) -> bool {
    (1..=48).contains(&value.len())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
        && !has_long_hex(value)
}

fn safe_version_fact(value: &str) -> bool {
    (1..=80).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'_' | b'-'))
        && !has_long_hex(value)
}

fn has_long_hex(value: &str) -> bool {
    value
        .split(|character: char| !character.is_ascii_hexdigit())
        .any(|part| part.len() >= 12)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ready_plan() -> HostActionPlan {
        HostActionPlan {
            changed_file_count: 3,
            changed_areas: vec!["flake.lock".to_string(), "hosts".to_string()],
            all_host_eval_passed: true,
            target_build_passed: true,
            backup_ready: true,
            running_kernel: Some("6.18.26".to_string()),
            expected_kernel: Some("7.0.14".to_string()),
            restart_required: true,
        }
    }

    fn lifecycle_job(
        kind: HostWorkflowKind,
        state: HostActionState,
        created_at: i64,
    ) -> HostActionJob {
        let action_kind = match kind {
            HostWorkflowKind::SettingsChange | HostWorkflowKind::SystemUpdateProposal => {
                HostActionKind::SystemUpdateProposal
            }
            HostWorkflowKind::UpdateRestart => HostActionKind::UpdateRestart,
            HostWorkflowKind::RemoveHost => HostActionKind::RemoveHost,
        };
        HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: format!("action-lifecycle-{}-{created_at}", kind.key()),
            host: "hsb8".to_string(),
            kind: action_kind,
            workflow_kind: (kind == HostWorkflowKind::SettingsChange).then_some(kind),
            state,
            requested_by: "markus".to_string(),
            ticket: "PHAROS-214".to_string(),
            retry_of: None,
            created_at,
            updated_at: created_at,
            confirmed_at: None,
            plan: None,
            removal_plan: (kind == HostWorkflowKind::RemoveHost).then_some(HostRemovalPlan {
                disposition: HostRetirementDisposition::Unmanaged,
                successor: None,
                declaration_pending: true,
                credential_retirement_required: false,
            }),
            result: None,
            recovery_started_at: None,
            events: Vec::new(),
            lease_phase: None,
            lease_until: None,
            retirement_lease_until: None,
        }
    }

    fn rebooting_update(store: &HostActionStore, started_at: i64) -> HostActionJob {
        let job = store
            .create_update_review("hsb8", "markus", started_at)
            .expect("job created");
        let review = store
            .claim("hsb8", started_at + 1)
            .expect("review claim")
            .expect("review lease");
        assert_eq!(review.phase, AgentActionPhase::Review);
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                started_at + 2,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", started_at + 3)
            .expect("update confirmed");
        let apply = store
            .claim("hsb8", started_at + 4)
            .expect("apply claim")
            .expect("apply lease");
        assert_eq!(apply.phase, AgentActionPhase::Apply);
        let rebooting = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Rebooting,
                    plan: None,
                    result: None,
                },
                started_at + 5,
            )
            .expect("rebooting state stored");
        assert_eq!(rebooting.state, HostActionState::Rebooting);
        rebooting
    }

    #[test]
    fn duplicate_resume_polls_receive_one_lease() {
        let store = std::sync::Arc::new(HostActionStore::new(None));
        let job = rebooting_update(&store, 100);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut workers = Vec::new();

        for _ in 0..2 {
            let store = std::sync::Arc::clone(&store);
            let barrier = std::sync::Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                store.claim("hsb8", 106).expect("resume poll")
            }));
        }
        barrier.wait();

        let leases: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("poll joined"))
            .collect();
        assert_eq!(leases.len(), 1);
        assert_eq!(leases[0].id, job.id);
        assert_eq!(leases[0].phase, AgentActionPhase::Resume);
        assert!(store.claim("hsb8", 107).expect("duplicate poll").is_none());
    }

    #[test]
    fn expired_resume_lease_remains_resume_instead_of_replaying_apply() {
        let store = HostActionStore::new(None);
        let job = rebooting_update(&store, 200);
        let first = store
            .claim("hsb8", 206)
            .expect("resume claim")
            .expect("resume lease");
        assert_eq!(first.id, job.id);
        assert_eq!(first.phase, AgentActionPhase::Resume);
        assert!(store.claim("hsb8", 207).expect("active lease").is_none());

        let reclaimed = store
            .claim("hsb8", 206 + LEASE_SECS)
            .expect("expired lease reclaimed")
            .expect("replacement lease");
        assert_eq!(reclaimed.id, job.id);
        assert_eq!(reclaimed.phase, AgentActionPhase::Resume);
    }

    #[test]
    fn resume_timeout_and_lease_phase_survive_store_reload() {
        let path = std::env::temp_dir().join(format!(
            "pharos-resume-lease-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let job = {
            let store = HostActionStore::new(Some(path.clone()));
            let job = rebooting_update(&store, 300);
            let lease = store
                .claim("hsb8", 306)
                .expect("resume claim")
                .expect("resume lease");
            assert_eq!(lease.phase, AgentActionPhase::Resume);
            job
        };

        let reloaded = HostActionStore::new(Some(path.clone()));
        assert!(reloaded
            .claim("hsb8", 307)
            .expect("pre-expiry poll")
            .is_none());
        let reclaimed = reloaded
            .claim("hsb8", 306 + LEASE_SECS)
            .expect("post-reload claim")
            .expect("expired resume lease");
        assert_eq!(reclaimed.id, job.id);
        assert_eq!(reclaimed.phase, AgentActionPhase::Resume);

        let failed = reloaded
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Resume,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: Some(HostActionResult {
                        backup_validated: true,
                        switch_passed: true,
                        reboot_observed: false,
                        kernel_verified: false,
                        rollback_available: false,
                        failure_gate: Some(HostActionFailureGate::BootChange),
                        recovery_mode: None,
                    }),
                },
                306 + LEASE_SECS + 1,
            )
            .expect("timeout persisted");
        assert_eq!(failed.state, HostActionState::Failed);
        assert_eq!(
            failed.latest_failure_gate(),
            Some(HostActionFailureGate::BootChange)
        );
        assert!(failed.recoverable());
        assert_eq!(
            failed
                .summary()
                .workflow
                .steps
                .iter()
                .find(|step| step.key == "host-return")
                .expect("host-return step")
                .state,
            WorkflowStepState::ActionRequired
        );

        let terminal = HostActionStore::new(Some(path.clone()));
        let persisted = terminal.get(&job.id).expect("failed action reloaded");
        assert_eq!(persisted.state, HostActionState::Failed);
        assert!(persisted
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::ApplyRebooting));
        assert!(persisted.events.iter().any(|event| {
            event.kind == HostActionEventKind::ApplyFailed
                && event.failure_gate == Some(HostActionFailureGate::BootChange)
        }));
        assert!(terminal
            .claim("hsb8", 306 + LEASE_SECS + 2)
            .expect("terminal poll")
            .is_none());
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn persisted_active_states_require_a_matching_lease_phase_and_deadline() {
        let store = HostActionStore::new(None);
        let mut job = rebooting_update(&store, 400);
        job.state = HostActionState::Applying;
        job.lease_phase = Some(AgentActionPhase::Resume);
        job.lease_until = None;
        assert!(!job.validate());

        job.state = HostActionState::Rebooting;
        job.lease_until = Some(job.updated_at + LEASE_SECS);
        assert!(!job.validate());
    }

    #[test]
    fn update_job_requires_review_then_explicit_confirmation() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 100)
            .expect("job created");
        let lease = store.claim("hsb8", 101).expect("claim").expect("lease");
        assert_eq!(lease.phase, AgentActionPhase::Review);
        let reviewed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                102,
            )
            .expect("review stored");
        assert_eq!(reviewed.state, HostActionState::AwaitingConfirmation);
        let confirmed = store
            .confirm_update(&job.id, "hsb8", "markus", 103)
            .expect("confirmed");
        assert_eq!(confirmed.state, HostActionState::QueuedApply);
        assert_eq!(
            store.claim("hsb8", 104).expect("claim").unwrap().phase,
            AgentActionPhase::Apply
        );
    }

    #[test]
    fn reviewed_update_can_be_cancelled_before_the_live_gate() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 200)
            .expect("job created");
        store.claim("hsb8", 201).expect("claim").expect("lease");
        let reviewed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                202,
            )
            .expect("review stored");
        let review_workflow = reviewed.summary().workflow;
        assert!(review_workflow.can_cancel);
        assert_eq!(review_workflow.run_id, job.id);
        assert_eq!(review_workflow.host, "hsb8");
        assert_eq!(review_workflow.created_at, 200);
        assert_eq!(review_workflow.updated_at, 202);
        assert_eq!(review_workflow.recorded_duration_secs, 2);
        assert_eq!(
            review_workflow.current_location,
            Some(HostWorkflowExecutionLocation::Pharos)
        );

        let cancelled = store
            .cancel_update_review(&job.id, "hsb8", "markus", 203)
            .expect("safe cancellation stored");
        assert_eq!(cancelled.state, HostActionState::Cancelled);
        assert!(cancelled.confirmed_at.is_none());
        let workflow = cancelled.summary().workflow;
        assert_eq!(workflow.status_label, "cancelled safely");
        assert_eq!(workflow.status_level, "clear");
        assert!(!workflow.can_cancel);
        assert!(workflow.current_step.is_none());
        assert!(workflow
            .events
            .iter()
            .any(|event| { event.label == "Workflow cancelled before live change" }));
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "confirm")
                .expect("confirmation step")
                .state,
            WorkflowStepState::Cancelled
        );
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "apply")
                .expect("apply step")
                .state,
            WorkflowStepState::Skipped
        );
        assert!(store.create_update_review("csb0", "markus", 204).is_ok());
    }

    #[test]
    fn cancellation_persists_and_rejects_a_late_agent_result() {
        let path = std::env::temp_dir().join(format!(
            "pharos-cancelled-review-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let job = {
            let store = HostActionStore::new(Some(path.clone()));
            let job = store
                .create_update_review("hsb8", "markus", 300)
                .expect("job created");
            store.claim("hsb8", 301).expect("claim").expect("lease");
            store
                .cancel_update_review(&job.id, "hsb8", "markus", 302)
                .expect("running review cancelled");
            job
        };

        let reloaded = HostActionStore::new(Some(path.clone()));
        let cancelled = reloaded.get(&job.id).expect("cancelled run reloaded");
        assert_eq!(cancelled.state, HostActionState::Cancelled);
        assert!(cancelled.lease_phase.is_none());
        assert!(cancelled.lease_until.is_none());
        assert!(reloaded.claim("hsb8", 303).expect("poll").is_none());
        assert_eq!(
            reloaded.record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                304,
            ),
            Err(HostActionStoreError::InvalidTransition)
        );
        assert_eq!(
            reloaded.get(&job.id).expect("run retained").state,
            HostActionState::Cancelled
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cancellation_is_rejected_after_attended_confirmation() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 400)
            .expect("job created");
        store.claim("hsb8", 401).expect("claim").expect("lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                402,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", 403)
            .expect("confirmed");

        assert_eq!(
            store.cancel_update_review(&job.id, "hsb8", "markus", 404),
            Err(HostActionStoreError::InvalidTransition)
        );
        assert_eq!(
            store.get(&job.id).expect("confirmed run retained").state,
            HostActionState::QueuedApply
        );
    }

    #[test]
    fn failed_review_requires_linked_retry_and_latest_attempt_controls_fleet_gate() {
        let store = HostActionStore::new(None);
        let failed = store
            .create_update_review("hsb8", "markus", 100)
            .expect("job created");
        store.claim("hsb8", 101).expect("claim").expect("lease");
        let failed_result = store
            .record_agent_result(
                &failed.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                },
                102,
            )
            .expect("failure stored");
        assert_eq!(failed_result.state, HostActionState::Failed);
        assert!(failed_result.summary().retryable);
        assert_eq!(
            store.create_update_review("hsb8", "markus", 103),
            Err(HostActionStoreError::FailedJobRequiresRetry)
        );
        assert_eq!(
            store.create_update_review("csb0", "markus", 103),
            Err(HostActionStoreError::BlockedByFleetGate)
        );

        let retry = store
            .retry_update_review(&failed.id, "hsb8", "markus", 104)
            .expect("retry created");
        assert_ne!(retry.id, failed.id);
        assert_eq!(retry.retry_of.as_deref(), Some(failed.id.as_str()));
        assert_eq!(store.latest_for_host("hsb8").expect("latest").id, retry.id);
        assert_eq!(
            store.create_update_review("csb0", "markus", 104),
            Err(HostActionStoreError::BlockedByFleetGate)
        );

        let lease = store.claim("hsb8", 105).expect("claim").expect("lease");
        assert_eq!(lease.id, retry.id);
        store
            .record_agent_result(
                &retry.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                106,
            )
            .expect("review stored");
        store
            .confirm_update(&retry.id, "hsb8", "markus", 107)
            .expect("confirmed");
        store.claim("hsb8", 108).expect("claim").expect("lease");
        store
            .record_agent_result(
                &retry.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
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
                109,
            )
            .expect("success stored");
        assert!(store.create_update_review("csb0", "markus", 110).is_ok());
        assert_eq!(
            store
                .get(&failed.id)
                .expect("failed attempt retained")
                .state,
            HostActionState::Failed
        );
    }

    #[test]
    fn post_confirmation_failure_is_not_automatically_retryable() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 200)
            .expect("job created");
        store.claim("hsb8", 201).expect("claim").expect("lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                202,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", 203)
            .expect("confirmed");
        store.claim("hsb8", 204).expect("claim").expect("lease");
        let failed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                },
                205,
            )
            .expect("failure stored");
        assert!(!failed.summary().retryable);
        assert_eq!(
            store.retry_update_review(&job.id, "hsb8", "markus", 206),
            Err(HostActionStoreError::InvalidTransition)
        );
    }

    #[test]
    fn failed_live_run_recovers_in_place_and_preserves_failure_history() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 300)
            .expect("job created");
        store.claim("hsb8", 301).expect("claim").expect("lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                302,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", 303)
            .expect("confirmed");
        store.claim("hsb8", 304).expect("claim").expect("lease");
        let failed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                },
                305,
            )
            .expect("failure stored");
        assert!(failed.recoverable());
        assert_eq!(
            failed.summary().workflow.status_label,
            "verification needed"
        );

        let queued = store
            .queue_recovery(&job.id, "hsb8", "markus", 306)
            .expect("recovery queued");
        assert_eq!(queued.state, HostActionState::Rebooting);
        assert_eq!(
            store.claim("hsb8", 307).expect("claim").unwrap().phase,
            AgentActionPhase::Resume
        );
        let recovered = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Resume,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: None,
                    result: Some(HostActionResult {
                        backup_validated: true,
                        switch_passed: true,
                        reboot_observed: true,
                        kernel_verified: true,
                        rollback_available: true,
                        failure_gate: None,
                        recovery_mode: Some(HostActionRecoveryMode::TrustedDescendant),
                    }),
                },
                308,
            )
            .expect("recovery stored");
        let workflow = recovered.summary().workflow;
        assert_eq!(recovered.state, HostActionState::Succeeded);
        assert_eq!(workflow.status_label, "recovered and verified");
        assert!(workflow
            .events
            .iter()
            .any(|event| event.label == "Live workflow stopped"));
        assert!(workflow.events.iter().any(|event| event.label
            == "Recovery verification passed: newer trusted deployment verified"));
        assert!(workflow.evidence.iter().any(|fact| {
            fact.label == "Recovery mode" && fact.value == "newer trusted deployment verified"
        }));
        assert!(workflow
            .steps
            .iter()
            .any(|step| { step.key == "recovery" && step.state == WorkflowStepState::Recovered }));
        assert!(store.create_update_review("csb0", "markus", 309).is_ok());
    }

    #[test]
    fn failed_recovery_persists_the_exact_safe_gate() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 320)
            .expect("job created");
        store.claim("hsb8", 321).expect("claim").expect("lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(ready_plan()),
                    result: None,
                },
                322,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", 323)
            .expect("confirmed");
        store.claim("hsb8", 324).expect("claim").expect("lease");
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: None,
                },
                325,
            )
            .expect("live failure stored");
        store
            .queue_recovery(&job.id, "hsb8", "markus", 326)
            .expect("recovery queued");
        store.claim("hsb8", 327).expect("claim").expect("lease");

        let failed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Resume,
                    outcome: AgentActionOutcome::Failed,
                    plan: None,
                    result: Some(HostActionResult {
                        backup_validated: true,
                        switch_passed: true,
                        reboot_observed: true,
                        kernel_verified: false,
                        rollback_available: true,
                        failure_gate: Some(HostActionFailureGate::RevisionIdentity),
                        recovery_mode: None,
                    }),
                },
                328,
            )
            .expect("recovery failure stored");

        assert!(failed.recoverable());
        let workflow = failed.summary().workflow;
        assert!(workflow.guidance.contains("deployed revision verification"));
        assert!(workflow.events.iter().any(|event| {
            event.label == "Recovery verification stopped at deployed revision verification"
        }));
        assert!(workflow.evidence.iter().any(|fact| {
            fact.label == "Stopped at" && fact.value == "deployed revision verification"
        }));
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "host-return")
                .expect("host return step")
                .state,
            WorkflowStepState::Passed
        );
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "runtime")
                .expect("runtime step")
                .state,
            WorkflowStepState::Failed
        );
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "heartbeat")
                .expect("heartbeat step")
                .state,
            WorkflowStepState::ActionRequired
        );
    }

    #[test]
    fn untyped_recovery_failure_does_not_inherit_an_older_apply_gate() {
        let store = HostActionStore::new(None);
        let mut job = store
            .create_update_review("hsb8", "markus", 340)
            .expect("job created");
        job.events.push(HostActionEvent {
            at: 341,
            state: HostActionState::Failed,
            source: HostActionEventSource::HostAgent,
            kind: HostActionEventKind::ApplyFailed,
            actor: None,
            failure_gate: Some(HostActionFailureGate::Switch),
            recovery_mode: None,
            retirement_failure: None,
        });
        job.events.push(HostActionEvent {
            at: 342,
            state: HostActionState::Failed,
            source: HostActionEventSource::HostAgent,
            kind: HostActionEventKind::RecoveryFailed,
            actor: None,
            failure_gate: None,
            recovery_mode: None,
            retirement_failure: None,
        });

        assert_eq!(job.latest_failure_gate(), None);
    }

    #[test]
    fn settings_change_uses_the_shared_persisted_workflow() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_settings_change("hsb8", "markus", 400)
            .expect("settings workflow created");
        assert_eq!(job.workflow_kind(), HostWorkflowKind::SettingsChange);
        assert_eq!(job.kind, HostActionKind::SystemUpdateProposal);
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 401),
            Err(HostActionStoreError::ActiveJob)
        );

        let accepted = store
            .accept_settings_change(&job.id, 402)
            .expect("request accepted");
        let wait = accepted
            .summary()
            .workflow
            .steps
            .into_iter()
            .find(|step| step.key == "host")
            .expect("host wait step");
        assert_eq!(wait.state, WorkflowStepState::Waiting);

        let completed = store
            .complete_settings_change("hsb8", 403)
            .expect("completion persisted")
            .expect("workflow completed");
        assert_eq!(completed.state, HostActionState::Succeeded);
        assert_eq!(
            completed.summary().workflow.status_label,
            "settings applied"
        );
        assert_eq!(WorkflowStepState::Cancelled.key(), "cancelled");
    }

    #[test]
    fn most_relevant_workflow_ignores_a_failure_superseded_by_success() {
        let store = HostActionStore::new(None);
        let failed = store
            .begin_settings_change("hsb8", "markus", 410)
            .expect("first settings workflow created");
        store
            .fail_settings_change(&failed.id, 411)
            .expect("first settings workflow failed");

        let retry = store
            .begin_settings_change("hsb8", "markus", 412)
            .expect("replacement settings workflow created");
        store
            .accept_settings_change(&retry.id, 413)
            .expect("replacement settings workflow accepted");
        store
            .complete_settings_change("hsb8", 414)
            .expect("replacement settings workflow persisted")
            .expect("replacement settings workflow completed");

        let relevant = store
            .most_relevant_for_host("hsb8")
            .expect("relevant settings workflow");
        assert_eq!(relevant.id, retry.id);
        assert_eq!(relevant.state, HostActionState::Succeeded);
    }

    /// PHAROS-214: exhaust every set of simultaneously true lifecycle facts.
    /// Reversing each job set also proves insertion order cannot alter the winner.
    #[test]
    fn lifecycle_precedence_property_holds_for_every_candidate_set() {
        const REMOVE: u8 = 1 << 0;
        const UPDATE: u8 = 1 << 1;
        const SETTINGS: u8 = 1 << 2;
        const PREFS: u8 = 1 << 3;
        const KERNEL: u8 = 1 << 4;
        const PROPOSAL: u8 = 1 << 5;

        for facts in 0..=(REMOVE | UPDATE | SETTINGS | PREFS | KERNEL | PROPOSAL) {
            let mut jobs = Vec::new();
            if facts & REMOVE != 0 {
                jobs.push(lifecycle_job(
                    HostWorkflowKind::RemoveHost,
                    HostActionState::RemovalPending,
                    100,
                ));
            }
            if facts & UPDATE != 0 {
                jobs.push(lifecycle_job(
                    HostWorkflowKind::UpdateRestart,
                    HostActionState::QueuedReview,
                    101,
                ));
            }
            if facts & SETTINGS != 0 {
                jobs.push(lifecycle_job(
                    HostWorkflowKind::SettingsChange,
                    HostActionState::ProposalRequested,
                    102,
                ));
            }
            if facts & PROPOSAL != 0 {
                jobs.push(lifecycle_job(
                    HostWorkflowKind::SystemUpdateProposal,
                    HostActionState::ProposalRequested,
                    103,
                ));
            }
            let preferences = if facts & PREFS != 0 {
                HostPreferencesState::DeclaredNotApplied
            } else {
                HostPreferencesState::Applied
            };
            let expected = if facts & REMOVE != 0 {
                HostLifecycleSlot::RemoveHost
            } else if facts & UPDATE != 0 {
                HostLifecycleSlot::UpdateRestart
            } else if facts & SETTINGS != 0 {
                HostLifecycleSlot::SettingsChange
            } else if facts & PREFS != 0 {
                HostLifecycleSlot::PrefsDrift
            } else if facts & KERNEL != 0 {
                HostLifecycleSlot::KernelDrift
            } else if facts & PROPOSAL != 0 {
                HostLifecycleSlot::SystemUpdateProposal
            } else {
                HostLifecycleSlot::Quiet
            };

            for reverse in [false, true] {
                if reverse {
                    jobs.reverse();
                }
                let lifecycle = host_lifecycle(&jobs, "hsb8", preferences, facts & KERNEL != 0);
                assert_eq!(
                    lifecycle.slot, expected,
                    "candidate facts {facts:06b}, reverse={reverse}"
                );
            }
        }
    }

    #[test]
    fn terminal_removal_does_not_mask_live_update_restart_in_host_action_selector() {
        let jobs = vec![
            lifecycle_job(
                HostWorkflowKind::RemoveHost,
                HostActionState::Succeeded,
                100,
            ),
            lifecycle_job(
                HostWorkflowKind::UpdateRestart,
                HostActionState::QueuedReview,
                200,
            ),
        ];
        let legacy = most_relevant_host_action(&jobs, "hsb8").expect("live update restart");
        assert_eq!(legacy.workflow_kind(), HostWorkflowKind::UpdateRestart);
        assert_eq!(legacy.state, HostActionState::QueuedReview);

        let lifecycle = host_lifecycle(&jobs, "hsb8", HostPreferencesState::Applied, false);
        assert_eq!(lifecycle.slot, HostLifecycleSlot::UpdateRestart);
        assert_eq!(lifecycle.run_id.as_deref(), Some(jobs[1].id.as_str()));
    }

    #[test]
    fn cancelled_settings_wins_lifecycle_but_live_proposal_wins_host_action_selector() {
        let jobs = vec![
            lifecycle_job(
                HostWorkflowKind::SettingsChange,
                HostActionState::Cancelled,
                100,
            ),
            lifecycle_job(
                HostWorkflowKind::SystemUpdateProposal,
                HostActionState::ProposalRequested,
                200,
            ),
        ];
        let legacy = most_relevant_host_action(&jobs, "hsb8").expect("live proposal");
        assert_eq!(
            legacy.workflow_kind(),
            HostWorkflowKind::SystemUpdateProposal
        );
        assert_eq!(legacy.id, jobs[1].id);

        let lifecycle = host_lifecycle(&jobs, "hsb8", HostPreferencesState::RequestPending, false);
        assert_eq!(lifecycle.slot, HostLifecycleSlot::SettingsChange);
        assert_eq!(lifecycle.run_id.as_deref(), Some(jobs[0].id.as_str()));
        assert_ne!(lifecycle.label, "Change requested");
    }

    #[test]
    fn completed_removal_does_not_hold_lifecycle_forever() {
        let jobs = vec![lifecycle_job(
            HostWorkflowKind::RemoveHost,
            HostActionState::Succeeded,
            100,
        )];
        let lifecycle = host_lifecycle(&jobs, "hsb8", HostPreferencesState::Applied, false);
        assert_eq!(lifecycle.slot, HostLifecycleSlot::Quiet);
        assert_eq!(lifecycle.run_id, None);
    }

    #[test]
    fn failed_and_cancelled_settings_runs_outrank_requested_preferences() {
        for state in [HostActionState::Failed, HostActionState::Cancelled] {
            let jobs = vec![lifecycle_job(HostWorkflowKind::SettingsChange, state, 200)];
            let lifecycle =
                host_lifecycle(&jobs, "hsb8", HostPreferencesState::RequestPending, true);

            assert_eq!(lifecycle.slot, HostLifecycleSlot::SettingsChange);
            assert_eq!(lifecycle.run_id.as_deref(), Some(jobs[0].id.as_str()));
            assert_ne!(lifecycle.label, "Change requested");
            assert_ne!(lifecycle.label, "Ready to apply");
        }
    }

    #[test]
    fn ready_to_apply_requires_declared_observed_drift_and_no_higher_run() {
        let observed = HostPreferences::default();
        let declared = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..Default::default()
        };
        let requested = HostPreferences {
            accent: Some("#9868d0".to_string()),
            ..Default::default()
        };

        let declared_state = host_preferences_state(&observed, Some(&declared), None);
        let ready = host_lifecycle(&[], "hsb8", declared_state, true);
        assert_eq!(ready.slot, HostLifecycleSlot::PrefsDrift);
        assert_eq!(ready.label, "Ready to apply");

        let requested_state = host_preferences_state(&observed, None, Some(&requested));
        let requested_lifecycle = host_lifecycle(&[], "hsb8", requested_state, false);
        assert_eq!(requested_lifecycle.label, "Change requested");

        let applied_state = host_preferences_state(&observed, Some(&observed), None);
        let quiet = host_lifecycle(&[], "hsb8", applied_state, false);
        assert_eq!(quiet.slot, HostLifecycleSlot::Quiet);
        assert_ne!(quiet.label, "Ready to apply");

        for kind in [
            HostWorkflowKind::RemoveHost,
            HostWorkflowKind::UpdateRestart,
            HostWorkflowKind::SettingsChange,
        ] {
            let state = match kind {
                HostWorkflowKind::RemoveHost => HostActionState::RemovalPending,
                HostWorkflowKind::UpdateRestart => HostActionState::QueuedReview,
                HostWorkflowKind::SettingsChange => HostActionState::ProposalRequested,
                HostWorkflowKind::SystemUpdateProposal => unreachable!(),
            };
            let lifecycle = host_lifecycle(
                &[lifecycle_job(kind, state, 300)],
                "hsb8",
                declared_state,
                true,
            );
            assert_ne!(lifecycle.label, "Ready to apply", "{kind:?} must win");
        }
    }

    #[test]
    fn lifecycle_contract_serializes_all_projection_fields() {
        let lifecycle = host_lifecycle(&[], "hsb8", HostPreferencesState::Applied, false);
        let value = serde_json::to_value(lifecycle).expect("lifecycle serializes");

        for field in [
            "schema",
            "version",
            "slot",
            "label",
            "level",
            "invoke",
            "run_id",
            "detail",
            "blocked_by",
        ] {
            assert!(
                value.get(field).is_some(),
                "missing lifecycle field {field}"
            );
        }
        assert_eq!(value["slot"], "quiet");
        assert_eq!(value["invoke"], "host_settings");
        assert!(value["run_id"].is_null());
    }

    #[test]
    fn system_update_proposal_uses_the_shared_read_only_workflow() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_system_update_proposal("hsb8", "markus", 450)
            .expect("proposal workflow created");
        let preparing = job.summary().workflow;

        assert_eq!(preparing.kind, HostWorkflowKind::SystemUpdateProposal);
        assert_eq!(preparing.current_step.as_deref(), Some("request"));
        assert_eq!(
            preparing
                .steps
                .iter()
                .find(|step| step.key == "request")
                .expect("dispatch step")
                .state,
            WorkflowStepState::Running
        );

        let accepted = store
            .accept_system_update_proposal(&job.id, 451)
            .expect("proposal dispatch accepted");
        let workflow = accepted.summary().workflow;

        assert_eq!(workflow.kind, HostWorkflowKind::SystemUpdateProposal);
        assert_eq!(workflow.status_label, "review requested");
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "validate")
                .expect("validation step")
                .state,
            WorkflowStepState::Waiting
        );
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "deploy")
                .expect("deployment boundary")
                .state,
            WorkflowStepState::Skipped
        );
    }

    #[test]
    fn removal_plan_records_lifecycle_and_rejects_invalid_lineage() {
        let store = HostActionStore::new(None);
        let started = store
            .begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: Some("stm2607".to_string()),
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                100,
            )
            .expect("removal recorded");
        assert_eq!(started.state, HostActionState::ProposalRequested);
        assert_eq!(
            started.summary().workflow.current_step.as_deref(),
            Some("revoke")
        );
        let removal = store
            .mark_removal_access_revoked(&started.id, 101)
            .expect("reporting access revoked");
        assert_eq!(removal.state, HostActionState::RemovalPending);
        let plan = removal
            .summary()
            .removal_plan
            .expect("removal plan exposed");
        assert_eq!(plan.disposition, HostRetirementDisposition::Rebuilt);
        assert_eq!(plan.successor.as_deref(), Some("stm2607"));
        assert!(plan.declaration_pending);
        let workflow = removal.summary().workflow;
        assert_eq!(workflow.kind, HostWorkflowKind::RemoveHost);
        assert_eq!(workflow.status_label, "removal pending");
        assert_eq!(workflow.current_step.as_deref(), Some("declaration"));
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "declaration")
                .expect("declaration cleanup step")
                .state,
            WorkflowStepState::Waiting
        );

        assert_eq!(
            store.create_removal(
                "hsb8",
                "markus",
                None,
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                102,
            ),
            Err(HostActionStoreError::InvalidJob)
        );
    }

    #[test]
    fn janus_retirement_requires_both_gates_and_supports_bounded_retry() {
        let store = HostActionStore::new(None);
        let started = store
            .begin_removal(
                "hsb8",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Destroyed,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: true,
                },
                200,
            )
            .expect("removal recorded");
        let pending = store
            .mark_removal_access_revoked(&started.id, 201)
            .expect("reporting revoked");
        assert_eq!(pending.state, HostActionState::RemovalPending);
        assert!(store
            .claim_retirement("csb1", 202)
            .expect("owner poll")
            .is_none());
        assert!(store
            .complete_removal(&started.id, 202)
            .expect("completion gate")
            .is_none());

        store
            .mark_removal_declaration_completed(&started.id, 203)
            .expect("declaration recorded");
        let lease = store
            .claim_retirement("csb1", 204)
            .expect("owner claim")
            .expect("retirement lease");
        assert_eq!(lease.host, "hsb8");
        let running = store.get(&started.id).expect("running retirement");
        assert_eq!(
            running.summary().workflow.current_step.as_deref(),
            Some("credentials")
        );
        assert_eq!(
            running
                .summary()
                .workflow
                .steps
                .iter()
                .find(|step| step.key == "credentials")
                .expect("credential step")
                .state,
            WorkflowStepState::Running
        );

        let stopped = store
            .record_retirement_result(
                &started.id,
                &RetirementAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "hsb8".to_string(),
                    outcome: RetirementAgentOutcome::Failed,
                    reason: Some(RetirementFailureReason::JanusUnavailable),
                },
                205,
            )
            .expect("typed failure recorded");
        assert_eq!(stopped.state, HostActionState::RemovalPending);
        assert_eq!(
            stopped
                .summary()
                .workflow
                .primary_action
                .expect("retry action")
                .label,
            "Retry credential retirement"
        );
        assert!(store
            .claim_retirement("csb1", 206)
            .expect("blocked poll")
            .is_none());

        store
            .retry_retirement(&started.id, "markus", 207)
            .expect("retry queued");
        store
            .claim_retirement("csb1", 208)
            .expect("retry claim")
            .expect("retry lease");
        let completed = store
            .record_retirement_result(
                &started.id,
                &RetirementAgentResultRequest {
                    owner: "csb1".to_string(),
                    host: "hsb8".to_string(),
                    outcome: RetirementAgentOutcome::Succeeded,
                    reason: None,
                },
                209,
            )
            .expect("retirement completed");
        assert_eq!(completed.state, HostActionState::Succeeded);
        assert_eq!(
            completed.summary().workflow.current_step,
            None,
            "all removal gates are complete"
        );
    }

    #[test]
    fn legacy_removal_jobs_migrate_to_conservative_lifecycle_intent() {
        let path = std::env::temp_dir().join(format!(
            "pharos-legacy-removal-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-remove-host-hsb8-100-1",
            "host": "hsb8",
            "kind": "remove_host",
            "state": "removal_pending",
            "requested_by": "markus",
            "ticket": "PHAROS-127",
            "created_at": 100,
            "updated_at": 100,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("legacy removal JSON"),
        )
        .expect("legacy removal state written");

        let store = HostActionStore::new(Some(path.clone()));
        let plan = store
            .latest_for_host("hsb8")
            .and_then(|job| job.removal_plan)
            .expect("legacy removal plan migrated");
        assert_eq!(plan.disposition, HostRetirementDisposition::Unmanaged);
        assert!(plan.successor.is_none());
        assert!(plan.declaration_pending);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_post_confirmation_failure_keeps_its_failure_audit_event() {
        let path = std::env::temp_dir().join(format!(
            "pharos-legacy-update-failure-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-update-restart-hsb8-100-1",
            "host": "hsb8",
            "kind": "update_restart",
            "state": "failed",
            "requested_by": "markus",
            "ticket": "PHAROS-126",
            "created_at": 100,
            "updated_at": 110,
            "confirmed_at": 105,
            "plan": {
                "changed_file_count": 3,
                "changed_areas": ["flake.lock", "hosts"],
                "all_host_eval_passed": true,
                "target_build_passed": true,
                "backup_ready": true,
                "running_kernel": "6.18.26",
                "expected_kernel": "7.0.14",
                "restart_required": true
            },
            "result": null,
            "lease_phase": null,
            "lease_until": null
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("legacy update JSON"),
        )
        .expect("legacy update state written");

        let store = HostActionStore::new(Some(path.clone()));
        let job = store.latest_for_host("hsb8").expect("legacy update loaded");
        assert_eq!(job.events[0].kind, HostActionEventKind::ApplyFailed);
        assert!(job
            .summary()
            .workflow
            .events
            .iter()
            .any(|event| event.label == "Live workflow stopped"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn retry_link_must_reference_failed_same_host_attempt() {
        let retry = HostActionStore::new_update_review(
            "hsb8",
            "markus",
            300,
            Some("action-update-restart-csb0-200-1".to_string()),
        );
        let mut jobs = BTreeMap::new();
        jobs.insert(retry.id.clone(), retry);
        assert!(!valid_action_jobs(&jobs));
    }

    #[test]
    fn unsafe_review_facts_and_incomplete_success_fail_closed() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 100)
            .expect("job created");
        store.claim("hsb8", 101).expect("claim").expect("lease");
        assert_eq!(
            store.record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Resume,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: None,
                    result: None,
                },
                102,
            ),
            Err(HostActionStoreError::InvalidTransition)
        );
        let mut unsafe_plan = ready_plan();
        unsafe_plan.changed_areas = vec!["0123456789abcdef".to_string()];
        assert_eq!(
            store.record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(unsafe_plan),
                    result: None,
                },
                102,
            ),
            Err(HostActionStoreError::InvalidJob)
        );
    }

    #[test]
    fn retired_host_state_persists_without_token_material() {
        let path = std::env::temp_dir().join(format!(
            "pharos-retired-hosts-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = RetiredHostStore::new(Some(path.clone()));
        store
            .retire(RetiredHost {
                host: "hsb8".to_string(),
                requested_by: "markus".to_string(),
                removal_job_id: "action-remove-host-hsb8-100-1".to_string(),
                disposition: HostRetirementDisposition::Rebuilt,
                successor: Some("stm2607".to_string()),
                declaration_pending: true,
                retired_at: 100,
            })
            .expect("retired");
        let reloaded = RetiredHostStore::new(Some(path.clone()));
        assert!(reloaded.is_retired("hsb8"));
        let retirement = reloaded.get("hsb8").expect("retirement reloaded");
        assert_eq!(retirement.disposition, HostRetirementDisposition::Rebuilt);
        assert_eq!(retirement.successor.as_deref(), Some("stm2607"));
        let raw = std::fs::read_to_string(&path).expect("retired state readable");
        let document: serde_json::Value =
            serde_json::from_str(&raw).expect("retired state is valid JSON");
        assert_eq!(document["version"], RETIRED_VERSION);
        assert!(!raw.to_ascii_lowercase().contains("token"));
        assert!(!raw.to_ascii_lowercase().contains("secret"));
        assert!(reloaded.clear("hsb8").expect("retirement cleared"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_retirement_state_migrates_to_unmanaged() {
        let path = std::env::temp_dir().join(format!(
            "pharos-legacy-retired-hosts-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!({
            "schema": RETIRED_SCHEMA,
            "version": 1,
            "hosts": [{
                "host": "hsb8",
                "requested_by": "markus",
                "removal_job_id": "action-remove-host-hsb8-100-1",
                "declaration_pending": true,
                "retired_at": 100
            }]
        });
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("legacy retirement JSON"),
        )
        .expect("legacy retirement state written");

        let store = RetiredHostStore::new(Some(path.clone()));
        let retirement = store.get("hsb8").expect("legacy retirement migrated");
        assert_eq!(retirement.disposition, HostRetirementDisposition::Unmanaged);
        assert!(retirement.successor.is_none());
        assert!(retirement.declaration_pending);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn retirement_rejects_successor_for_non_rebuilt_hosts() {
        let store = RetiredHostStore::new(None);
        assert_eq!(
            store.retire(RetiredHost {
                host: "hsb8".to_string(),
                requested_by: "markus".to_string(),
                removal_job_id: "action-remove-host-hsb8-100-1".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: Some("stm2607".to_string()),
                declaration_pending: true,
                retired_at: 100,
            }),
            Err(HostActionStoreError::InvalidJob)
        );
        assert!(!store.is_retired("hsb8"));
    }

    #[test]
    fn persistence_failure_rolls_back_guarded_state() {
        let blocker = std::env::temp_dir().join(format!(
            "pharos-action-persistence-blocker-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let actions = HostActionStore::new(Some(blocker.join("actions.json")));
        let retired = RetiredHostStore::new(Some(blocker.join("retired.json")));
        std::fs::write(&blocker, b"not a directory").expect("write blocker");

        assert_eq!(
            actions.create_update_review("hsb8", "markus", 100),
            Err(HostActionStoreError::Persistence)
        );
        assert!(actions.list().is_empty());

        assert_eq!(
            retired.retire(RetiredHost {
                host: "hsb8".to_string(),
                requested_by: "markus".to_string(),
                removal_job_id: "action-remove-host-hsb8-100-1".to_string(),
                disposition: HostRetirementDisposition::Destroyed,
                successor: None,
                declaration_pending: true,
                retired_at: 100,
            }),
            Err(HostActionStoreError::Persistence)
        );
        assert!(!retired.is_retired("hsb8"));
        let _ = std::fs::remove_file(blocker);
    }

    #[test]
    fn malformed_guard_state_stops_startup() {
        let path = std::env::temp_dir().join(format!(
            "pharos-malformed-action-state-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, b"not valid state").expect("write malformed state");

        assert!(std::panic::catch_unwind(|| HostActionStore::new(Some(path.clone()))).is_err());
        assert!(std::panic::catch_unwind(|| RetiredHostStore::new(Some(path.clone()))).is_err());

        let _ = std::fs::remove_file(path);
    }
}
