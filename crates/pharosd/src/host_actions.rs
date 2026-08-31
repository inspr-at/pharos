//! Persistent, value-free state for guarded per-host workflows.
//!
//! Browser requests create review jobs. A host-authenticated, target-local
//! agent may claim only the fixed review/apply phases represented here. This
//! store never carries credentials, permits, commands, Nix paths, or command
//! output.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

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
const SYSTEM_UPDATE_DISPATCH_STALL_SECS: i64 = 120;
static ACTION_COUNTER: AtomicU64 = AtomicU64::new(1);
static PERSIST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionKind {
    SystemUpdateProposal,
    UpdateRestart,
    RemoveHost,
}

/// The operator-selected purpose of an update/restart workflow.
///
/// Missing values on persisted v1 jobs deliberately mean `update`, preserving
/// the contract of jobs written before PHAROS-216.
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum UpdateRestartIntent {
    #[default]
    Update,
    ApplyDeclared,
    RestartOnly,
}

impl UpdateRestartIntent {
    pub(crate) fn key(self) -> &'static str {
        match self {
            Self::Update => "update",
            Self::ApplyDeclared => "apply_declared",
            Self::RestartOnly => "restart_only",
        }
    }
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
    Blocked,
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
            Self::Blocked => "blocked",
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) update_restart_intent: Option<UpdateRestartIntent>,
    pub(crate) detail: String,
    pub(crate) blocked_by: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) primary_action: Option<HostWorkflowAction>,
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
    DispatchSubmitted,
    DispatchOutcomeUncertain,
    DispatchUncertaintyAcknowledged,
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
    Acknowledge,
    Refresh,
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
pub(crate) struct HostWorkflowLadderFact {
    pub(crate) key: &'static str,
    pub(crate) label: &'static str,
    pub(crate) state: &'static str,
    pub(crate) fact: String,
    pub(crate) at: Option<i64>,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostWorkflowNext {
    pub(crate) title: String,
    pub(crate) consequence: String,
    pub(crate) location: String,
    pub(crate) boundary: String,
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
    pub(crate) can_withdraw: bool,
    pub(crate) persisted: bool,
    pub(crate) primary_action: Option<HostWorkflowAction>,
    pub(crate) ladder: Vec<HostWorkflowLadderFact>,
    pub(crate) next: HostWorkflowNext,
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
    intent: Option<UpdateRestartIntent>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    requested_preferences: Option<HostPreferences>,
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

    pub(crate) fn update_restart_intent(&self) -> UpdateRestartIntent {
        if self.kind == HostActionKind::UpdateRestart {
            self.intent.unwrap_or_default()
        } else {
            UpdateRestartIntent::Update
        }
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
            && self
                .requested_preferences
                .as_ref()
                .is_none_or(|preferences| {
                    self.workflow_kind() == HostWorkflowKind::SettingsChange
                        && preferences.validate_contract().is_ok()
                })
            && self.workflow_kind.is_none_or(|kind| {
                kind == HostWorkflowKind::SettingsChange
                    && self.kind == HostActionKind::SystemUpdateProposal
                    && self.removal_plan.is_none()
            })
            && (self.kind == HostActionKind::UpdateRestart || self.intent.is_none())
            && self.recovery_started_at.is_none_or(|_| {
                self.kind == HostActionKind::UpdateRestart && self.confirmed_at.is_some()
            })
            && (self.state != HostActionState::Cancelled
                || (self.workflow_kind() == HostWorkflowKind::SettingsChange
                    || (self.kind == HostActionKind::UpdateRestart
                        && self.confirmed_at.is_none()
                        && self.recovery_started_at.is_none()
                        && self.result.is_none())))
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

    pub(crate) fn dispatch_submitted(&self) -> bool {
        self.has_event(HostActionEventKind::DispatchSubmitted)
    }

    pub(crate) fn requested_preferences(&self) -> Option<&HostPreferences> {
        self.requested_preferences.as_ref()
    }

    pub(crate) fn accepted_dispatch_reconciled(&self) -> bool {
        match self.workflow_kind() {
            HostWorkflowKind::SettingsChange => {
                self.has_event(HostActionEventKind::SettingsRequestAccepted)
            }
            HostWorkflowKind::RemoveHost => self.removal_access_revoked(),
            _ => false,
        }
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
            intent: (self.kind == HostActionKind::UpdateRestart)
                .then_some(self.update_restart_intent()),
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

    pub(crate) fn can_withdraw(&self) -> bool {
        self.workflow_kind() == HostWorkflowKind::SettingsChange && !self.state.is_terminal()
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
        let ladder = self.workflow_ladder();
        let next = self.workflow_next(primary_action.as_ref(), current_location);
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
            can_withdraw: self.can_withdraw(),
            persisted: true,
            primary_action,
            ladder,
            next,
            steps,
            evidence,
            events,
        }
    }

    fn latest_event(&self, kinds: &[HostActionEventKind]) -> Option<&HostActionEvent> {
        self.events
            .iter()
            .rev()
            .find(|event| kinds.contains(&event.kind))
    }

    fn ladder_fact(
        key: &'static str,
        label: &'static str,
        state: &'static str,
        fact: impl Into<String>,
        event: Option<&HostActionEvent>,
    ) -> HostWorkflowLadderFact {
        HostWorkflowLadderFact {
            key,
            label,
            state,
            fact: fact.into(),
            at: event.map(|event| event.at),
        }
    }

    fn workflow_ladder(&self) -> Vec<HostWorkflowLadderFact> {
        let requested = self.latest_event(&[HostActionEventKind::Requested]);
        let cancelled = self.state == HostActionState::Cancelled;
        let stopped_state = if cancelled || self.state == HostActionState::Failed {
            "stopped"
        } else {
            "pending"
        };
        match self.workflow_kind() {
            HostWorkflowKind::SettingsChange => {
                let accepted = self.latest_event(&[HostActionEventKind::SettingsRequestAccepted]);
                let submitted = self.latest_event(&[HostActionEventKind::DispatchSubmitted]);
                let uncertain = self.latest_event(&[HostActionEventKind::DispatchOutcomeUncertain]);
                let rejected = self.latest_event(&[
                    HostActionEventKind::DispatchFailed,
                    HostActionEventKind::SettingsFailed,
                ]);
                let applied = self.latest_event(&[HostActionEventKind::SettingsApplied]);
                vec![
                    Self::ladder_fact(
                        "observed",
                        "Observed",
                        if applied.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if applied.is_some() {
                            "Host reported the requested values"
                        } else {
                            "No matching host report recorded"
                        },
                        applied,
                    ),
                    Self::ladder_fact(
                        "declared",
                        "Declared",
                        "not_observed",
                        "No declaration merge is observed by this run",
                        None,
                    ),
                    Self::ladder_fact(
                        "requested",
                        "Requested",
                        if submitted.is_some() || accepted.is_some() {
                            "complete"
                        } else if cancelled || self.state == HostActionState::Failed {
                            "stopped"
                        } else {
                            "current"
                        },
                        if submitted.is_some() {
                            "Repository handoff accepted"
                        } else if accepted.is_some() {
                            "Pending request saved for host delivery"
                        } else if uncertain.is_some() {
                            "Repository receipt is unconfirmed"
                        } else if rejected.is_some() || self.state == HostActionState::Failed {
                            "Request delivery stopped"
                        } else if cancelled {
                            "Pending request withdrawn"
                        } else {
                            "Operator request recorded"
                        },
                        submitted
                            .or(accepted)
                            .or(uncertain)
                            .or(rejected)
                            .or(requested),
                    ),
                    Self::ladder_fact(
                        "executed",
                        "Executed",
                        if applied.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if applied.is_some() {
                            "Requested values reported by the host"
                        } else {
                            "No host execution reported"
                        },
                        applied,
                    ),
                    Self::ladder_fact(
                        "verified",
                        "Verified",
                        if applied.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if applied.is_some() {
                            "Matching host report completed the run"
                        } else {
                            "No matching host report recorded"
                        },
                        applied,
                    ),
                ]
            }
            HostWorkflowKind::SystemUpdateProposal => {
                let accepted = self.latest_event(&[
                    HostActionEventKind::DispatchAccepted,
                    HostActionEventKind::DispatchSubmitted,
                ]);
                let uncertain = self.latest_event(&[HostActionEventKind::DispatchOutcomeUncertain]);
                let rejected = self.latest_event(&[HostActionEventKind::DispatchFailed]);
                let handoff_event = accepted.or(uncertain).or(rejected);
                vec![
                    Self::ladder_fact(
                        "observed",
                        "Observed",
                        "not_applicable",
                        "No host observation is part of this proposal",
                        None,
                    ),
                    Self::ladder_fact(
                        "declared",
                        "Declared",
                        "not_observed",
                        if accepted.is_some() {
                            "Repository review continues outside Pharos"
                        } else if uncertain.is_some() {
                            "Repository receipt is unconfirmed"
                        } else if rejected.is_some() {
                            "Repository handoff was rejected"
                        } else {
                            "No repository handoff was accepted"
                        },
                        handoff_event,
                    ),
                    Self::ladder_fact(
                        "requested",
                        "Requested",
                        if accepted.is_some() {
                            "complete"
                        } else if uncertain.is_some()
                            || rejected.is_some()
                            || cancelled
                            || self.state == HostActionState::Failed
                        {
                            "stopped"
                        } else {
                            "current"
                        },
                        if accepted.is_some() {
                            "nixcfg accepted the review handoff"
                        } else if uncertain.is_some() {
                            "nixcfg receipt could not be confirmed"
                        } else if rejected.is_some() {
                            "nixcfg rejected the review handoff"
                        } else if cancelled {
                            "Operator request was cancelled"
                        } else {
                            "Operator request recorded"
                        },
                        handoff_event.or(requested),
                    ),
                    Self::ladder_fact(
                        "executed",
                        "Executed",
                        "not_applicable",
                        "No host execution was authorized",
                        None,
                    ),
                    Self::ladder_fact(
                        "verified",
                        "Verified",
                        "not_applicable",
                        "No host verification is claimed",
                        None,
                    ),
                ]
            }
            HostWorkflowKind::UpdateRestart => {
                let observed = self.latest_event(&[
                    HostActionEventKind::ReviewPassed,
                    HostActionEventKind::RecoveryPassed,
                ]);
                let execution_completed = self.latest_event(&[
                    HostActionEventKind::ApplyPassed,
                    HostActionEventKind::RecoveryPassed,
                ]);
                let execution_started = self.latest_event(&[
                    HostActionEventKind::ApplyRebooting,
                    HostActionEventKind::ApplyClaimed,
                    HostActionEventKind::RecoveryRebooting,
                    HostActionEventKind::RecoveryClaimed,
                ]);
                let verified = self.latest_event(&[
                    HostActionEventKind::ApplyPassed,
                    HostActionEventKind::RecoveryPassed,
                ]);
                vec![
                    Self::ladder_fact(
                        "observed",
                        "Observed",
                        if observed.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if observed.is_some() {
                            "Target-local review evidence recorded"
                        } else {
                            "No completed host review recorded"
                        },
                        observed,
                    ),
                    Self::ladder_fact(
                        "declared",
                        "Declared",
                        "not_observed",
                        "No declaration merge is claimed by this run",
                        None,
                    ),
                    Self::ladder_fact(
                        "requested",
                        "Requested",
                        "complete",
                        "Operator request recorded",
                        requested,
                    ),
                    Self::ladder_fact(
                        "executed",
                        "Executed",
                        if execution_completed.is_some() {
                            "complete"
                        } else if execution_started.is_some() {
                            "current"
                        } else {
                            stopped_state
                        },
                        if execution_completed.is_some() {
                            "Target-local execution completed"
                        } else if execution_started.is_some() {
                            "Target-local execution started; completion is not recorded"
                        } else {
                            "No live execution recorded"
                        },
                        execution_completed.or(execution_started),
                    ),
                    Self::ladder_fact(
                        "verified",
                        "Verified",
                        if verified.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if verified.is_some() {
                            "Host verification evidence completed the run"
                        } else {
                            "No completed host verification recorded"
                        },
                        verified,
                    ),
                ]
            }
            HostWorkflowKind::RemoveHost => {
                let declaration =
                    self.latest_event(&[HostActionEventKind::RemovalDeclarationCompleted]);
                let executed = self.latest_event(&[
                    HostActionEventKind::RemovalAccessRevoked,
                    HostActionEventKind::RemovalCredentialRetired,
                ]);
                let verified = self.latest_event(&[HostActionEventKind::RemovalCompleted]);
                vec![
                    Self::ladder_fact(
                        "observed",
                        "Observed",
                        "not_applicable",
                        "Retirement does not claim a new host observation",
                        None,
                    ),
                    Self::ladder_fact(
                        "declared",
                        "Declared",
                        if declaration.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if declaration.is_some() {
                            "Host declaration removal recorded"
                        } else {
                            "No declaration removal recorded"
                        },
                        declaration,
                    ),
                    Self::ladder_fact(
                        "requested",
                        "Requested",
                        "complete",
                        "Operator retirement intent recorded",
                        requested,
                    ),
                    Self::ladder_fact(
                        "executed",
                        "Executed",
                        if executed.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if executed.is_some() {
                            "Retirement gate execution recorded"
                        } else {
                            "No completed retirement gate recorded"
                        },
                        executed,
                    ),
                    Self::ladder_fact(
                        "verified",
                        "Verified",
                        if verified.is_some() {
                            "complete"
                        } else {
                            stopped_state
                        },
                        if verified.is_some() {
                            "All retirement gates completed"
                        } else {
                            "Retirement is not complete"
                        },
                        verified,
                    ),
                ]
            }
        }
    }

    fn workflow_next(
        &self,
        primary: Option<&HostWorkflowAction>,
        current_location: Option<HostWorkflowExecutionLocation>,
    ) -> HostWorkflowNext {
        let location = match primary.map(|action| action.kind) {
            Some(HostWorkflowActionKind::Confirm) => HostWorkflowExecutionLocation::TargetHost,
            Some(HostWorkflowActionKind::Retry)
                if self.workflow_kind() == HostWorkflowKind::RemoveHost =>
            {
                HostWorkflowExecutionLocation::RetirementOwner
            }
            Some(HostWorkflowActionKind::Retry) => HostWorkflowExecutionLocation::TargetHost,
            Some(HostWorkflowActionKind::Recover)
                if self.workflow_kind() == HostWorkflowKind::UpdateRestart =>
            {
                HostWorkflowExecutionLocation::TargetHost
            }
            Some(HostWorkflowActionKind::Recover | HostWorkflowActionKind::Acknowledge) => {
                HostWorkflowExecutionLocation::Pharos
            }
            Some(HostWorkflowActionKind::Refresh) => HostWorkflowExecutionLocation::Pharos,
            None => current_location.unwrap_or(HostWorkflowExecutionLocation::Pharos),
        }
        .label(&self.host);
        let (title, consequence) = match primary.map(|action| action.kind) {
            Some(HostWorkflowActionKind::Confirm) => (
                primary.expect("matched primary action").label.clone(),
                "Queues the reviewed change for target-local execution, then waits for fresh host verification.".to_string(),
            ),
            Some(HostWorkflowActionKind::Retry) => (
                primary.expect("matched primary action").label.clone(),
                "Retries only the recorded failed step in this saved run.".to_string(),
            ),
            Some(HostWorkflowActionKind::Recover) => (
                primary.expect("matched primary action").label.clone(),
                if self.workflow_kind() == HostWorkflowKind::SettingsChange {
                    "Saves the already accepted request locally without another repository dispatch."
                } else {
                    "Queues verification of the current host state without replaying the live change."
                }
                .to_string(),
            ),
            Some(HostWorkflowActionKind::Acknowledge) => (
                primary.expect("matched primary action").label.clone(),
                "Records that the repository outcome was checked and permits a deliberate new request."
                    .to_string(),
            ),
            Some(HostWorkflowActionKind::Refresh) => (
                primary.expect("matched primary action").label.clone(),
                format!(
                    "Reads this saved run again. It does not resend the request; completion still requires {} to report the requested values.",
                    self.host
                ),
            ),
            None if self.state == HostActionState::Cancelled => (
                "No next action".to_string(),
                if self.workflow_kind() == HostWorkflowKind::SettingsChange {
                    "Clears the pending request. An open nixcfg proposal stays open there."
                        .to_string()
                } else {
                    "The run remains recorded as cancelled.".to_string()
                },
            ),
            None if self.state.is_terminal() => (
                "No next action".to_string(),
                "This run is terminal and remains available for review.".to_string(),
            ),
            None => (
                "Wait for the current step".to_string(),
                "Pharos keeps this run saved and updates it only from the recorded owner or host evidence."
                    .to_string(),
            ),
        };
        let boundary = match self.workflow_kind() {
            HostWorkflowKind::SettingsChange => {
                "Pharos will not close or merge a nixcfg proposal."
            }
            HostWorkflowKind::SystemUpdateProposal => {
                "Pharos will not merge, deploy, or verify a host change."
            }
            HostWorkflowKind::UpdateRestart => {
                "This step will not bypass backup, Janus, attended confirmation, or host verification."
            }
            HostWorkflowKind::RemoveHost => {
                "Pharos will not delete the server, disks, services, or application data."
            }
        };
        HostWorkflowNext {
            title,
            consequence,
            location,
            boundary: boundary.to_string(),
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
                let outcome_uncertain =
                    self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
                let submitted = self.has_event(HostActionEventKind::DispatchSubmitted);
                evidence.push(workflow_evidence(
                    "Delivery",
                    if self.state == HostActionState::Cancelled {
                        "withdrawn"
                    } else if outcome_uncertain {
                        "outcome uncertain"
                    } else if self.state == HostActionState::Failed {
                        "stopped"
                    } else if accepted || submitted || self.state == HostActionState::Succeeded {
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
                let outcome_uncertain =
                    self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
                evidence.push(workflow_evidence(
                    "Repository dispatch",
                    if self.state == HostActionState::Failed {
                        if outcome_uncertain {
                            "outcome uncertain"
                        } else {
                            "stopped"
                        }
                    } else if accepted || self.state == HostActionState::Succeeded {
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
                            if !result.reboot_observed
                                && self.plan.as_ref().is_some_and(|plan| {
                                    !plan.restart_required
                                        && self.update_restart_intent()
                                            != UpdateRestartIntent::RestartOnly
                                })
                            {
                                "not required"
                            } else {
                                evidence_result(result.reboot_observed)
                            },
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
                let outcome_uncertain =
                    self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
                let submitted = self.has_event(HostActionEventKind::DispatchSubmitted);
                evidence.push(workflow_evidence(
                    "Repository dispatch",
                    if outcome_uncertain {
                        "outcome uncertain"
                    } else if submitted {
                        "accepted"
                    } else if self.state == HostActionState::Failed {
                        "stopped"
                    } else {
                        "not required"
                    },
                ));
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
                        if outcome_uncertain {
                            "outcome uncertain"
                        } else if self.declaration_removed() {
                            "complete"
                        } else if plan.declaration_pending {
                            "pending"
                        } else {
                            "not required"
                        },
                    ));
                    evidence.push(workflow_evidence(
                        "Credential retirement",
                        if outcome_uncertain {
                            "not started; repository outcome uncertain"
                        } else if self.credentials_retired() {
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
        let submitted = self.has_event(HostActionEventKind::DispatchSubmitted);
        let repository_delivery = submitted
            || self.has_event(HostActionEventKind::DispatchOutcomeUncertain)
            || self.has_event(HostActionEventKind::DispatchFailed);
        let handoff_needs_reconciliation = submitted && !accepted;
        let outcome_uncertain = self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
        let uncertainty_acknowledged =
            self.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged);
        let uncertainty_needs_ack = outcome_uncertain && !uncertainty_acknowledged;
        let repository_wait_guidance = format!(
            "The repository handoff is accepted, but no matching host report is recorded. Finish the nixcfg review, merge, and deployment first. Then {} must report the requested values; Pharos will not mark this run complete without that matching host evidence.",
            self.host
        );
        let (guidance, status_label, status_level) = match self.state {
            HostActionState::Succeeded => (
                "The host reported the requested settings. The saved workflow is complete.",
                "settings applied",
                "clear",
            ),
            HostActionState::Cancelled => (
                "The pending request was cleared. An open nixcfg proposal stays open there.",
                "settings change withdrawn",
                "clear",
            ),
            HostActionState::Failed if uncertainty_needs_ack => (
                "Pharos could not confirm whether nixcfg received this settings request. Verify nixcfg before allowing another request.",
                "dispatch outcome uncertain",
                "warning",
            ),
            HostActionState::Failed if outcome_uncertain => (
                "The operator recorded that nixcfg was checked. A fresh settings request can now be submitted deliberately.",
                "uncertainty acknowledged",
                "warning",
            ),
            HostActionState::Failed => (
                "The request stopped safely. Review the recorded event before trying again.",
                "settings request stopped",
                "warning",
            ),
            _ if handoff_needs_reconciliation => (
                "The repository accepted this settings request. Pharos is preserving the handoff while its local pending record is reconciled; do not resend it.",
                "dispatch accepted",
                "warning",
            ),
            _ if accepted && submitted => (
                repository_wait_guidance.as_str(),
                "change waiting",
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
            HostActionState::Cancelled => WorkflowStepState::Cancelled,
            HostActionState::Failed if outcome_uncertain => WorkflowStepState::ActionRequired,
            HostActionState::Failed => WorkflowStepState::Failed,
            _ if accepted || submitted => WorkflowStepState::Passed,
            _ => WorkflowStepState::Running,
        };
        let wait_state = match self.state {
            HostActionState::Succeeded => WorkflowStepState::Passed,
            HostActionState::Cancelled => WorkflowStepState::Skipped,
            HostActionState::Failed if outcome_uncertain => WorkflowStepState::Queued,
            HostActionState::Failed => WorkflowStepState::Skipped,
            _ if accepted => WorkflowStepState::Waiting,
            _ => WorkflowStepState::Queued,
        };
        let record_state = match self.state {
            HostActionState::Succeeded | HostActionState::Failed | HostActionState::Cancelled => {
                WorkflowStepState::Passed
            }
            _ => WorkflowStepState::Queued,
        };
        (
            format!("Change {} settings", self.host),
            guidance.to_string(),
            status_label.to_string(),
            status_level,
            if self.state.is_terminal() && self.state != HostActionState::Failed {
                None
            } else if uncertainty_needs_ack {
                Some(HostWorkflowAction {
                    kind: HostWorkflowActionKind::Acknowledge,
                    label: "I verified nixcfg — allow a new request".to_string(),
                })
            } else if accepted && submitted {
                Some(HostWorkflowAction {
                    kind: HostWorkflowActionKind::Refresh,
                    label: "Check host now".to_string(),
                })
            } else {
                handoff_needs_reconciliation.then(|| HostWorkflowAction {
                    kind: HostWorkflowActionKind::Recover,
                    label: "Retry local settings save".to_string(),
                })
            },
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
                    if self.state == HostActionState::Cancelled {
                        "The pending request was withdrawn; an external proposal is unchanged."
                    } else if outcome_uncertain {
                        "Pharos cannot prove whether the repository accepted this request."
                    } else if self.state == HostActionState::Failed {
                        "The delivery workflow did not accept the request."
                    } else if submitted {
                        "The durable delivery workflow accepted the request."
                    } else if accepted {
                        "Pharos saved the request for host delivery."
                    } else {
                        "Pharos is recording the delivery request."
                    },
                )
                .at(if repository_delivery {
                    HostWorkflowExecutionLocation::Github
                } else {
                    HostWorkflowExecutionLocation::Pharos
                }),
                workflow_step(
                    "host",
                    "APPLY",
                    "Wait for the host",
                    wait_state,
                    if accepted && submitted {
                        "The nixcfg review, merge, and deployment must finish first. This run completes only after the named host reports the requested values."
                    } else {
                        "Applied state changes only after the host reports the requested values."
                    },
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
        let succeeded = self.state == HostActionState::Succeeded;
        let submitted = self.has_event(HostActionEventKind::DispatchSubmitted);
        let accepted = self
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::DispatchAccepted);
        let outcome_uncertain = self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
        let known_rejected =
            failed && self.has_event(HostActionEventKind::DispatchFailed) && !outcome_uncertain;
        let dispatch_handoff = accepted || submitted || succeeded;
        let (guidance, status_label, status_level) = match self.state {
            HostActionState::Succeeded => (
                "The update review was handed to nixcfg. Pharos did not deploy or verify any host change.",
                "review handed to nixcfg",
                "clear",
            ),
            HostActionState::Failed if outcome_uncertain => (
                "Pharos could not confirm whether nixcfg received this review request. Verify nixcfg before starting another fleet-wide proposal. No host change was deployed or verified from Pharos.",
                "dispatch outcome uncertain",
                "warning",
            ),
            HostActionState::Failed => (
                "The repository review request stopped. No host change was authorized.",
                "update review stopped",
                "warning",
            ),
            _ => (
                "The proposal is saved outside the live-change path. Repository checks and review must finish before any host action.",
                "review requested",
                "warning",
            ),
        };
        let request_state = if outcome_uncertain || known_rejected {
            WorkflowStepState::Failed
        } else if dispatch_handoff {
            WorkflowStepState::Passed
        } else {
            WorkflowStepState::Running
        };
        let downstream_state = if failed || succeeded {
            WorkflowStepState::Skipped
        } else if dispatch_handoff {
            WorkflowStepState::Waiting
        } else {
            WorkflowStepState::Queued
        };
        let request_detail = if dispatch_handoff && !outcome_uncertain {
            "The review request was handed to nixcfg."
        } else if outcome_uncertain {
            "Pharos could not confirm whether the repository dispatch completed."
        } else if known_rejected {
            "The repository dispatch did not accept the review request."
        } else {
            "Pharos is recording the review request."
        };
        let downstream_detail = if dispatch_handoff && !failed {
            "Repository checks continue in nixcfg outside Pharos."
        } else if outcome_uncertain {
            "Pharos could not confirm whether repository checks were requested."
        } else if known_rejected {
            "Repository checks were not started from Pharos."
        } else {
            "Completion is reported by the repository workflow."
        };
        let review_detail = if dispatch_handoff && !failed {
            "Review continues in nixcfg outside Pharos."
        } else if outcome_uncertain {
            "Pharos could not confirm whether repository review was requested."
        } else if known_rejected {
            "Repository review was not started from Pharos."
        } else {
            "A separate reviewed workflow is required before deployment."
        };
        (
            "Review system updates".to_string(),
            guidance.to_string(),
            status_label.to_string(),
            status_level,
            None,
            vec![
                workflow_step(
                    "request",
                    "PREPARE",
                    "Create an isolated update proposal",
                    request_state,
                    request_detail,
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "validate",
                    "VALIDATE",
                    "Run repository and all-host checks",
                    downstream_state,
                    downstream_detail,
                )
                .at(HostWorkflowExecutionLocation::Github),
                workflow_step(
                    "review",
                    "APPROVE",
                    "Review the proposal",
                    downstream_state,
                    review_detail,
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
        let intent = self.update_restart_intent();
        let applying_declared = intent == UpdateRestartIntent::ApplyDeclared;
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
                label: if applying_declared {
                    "Confirm declared apply"
                } else {
                    "Confirm update"
                }
                .to_string(),
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
                if applying_declared {
                    "applying declared configuration"
                } else {
                    "applying update"
                },
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
                if applying_declared {
                    "The declared configuration was applied and all required evidence was recorded."
                } else {
                    "The guarded update completed and all required evidence was recorded."
                },
                if applying_declared {
                    "declared configuration applied"
                } else {
                    "update completed"
                },
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
        let restart_state = if plan.is_some_and(|plan| !plan.restart_required)
            && intent != UpdateRestartIntent::RestartOnly
        {
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
            if applying_declared {
                format!("Apply declared configuration to {}", self.host)
            } else {
                format!("Update {}", self.host)
            },
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
        let outcome_uncertain = self.has_event(HostActionEventKind::DispatchOutcomeUncertain);
        let submitted = self.has_event(HostActionEventKind::DispatchSubmitted);
        let uncertainty_acknowledged =
            self.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged);
        let uncertainty_needs_ack = outcome_uncertain && !uncertainty_acknowledged;
        let declaration_pending = self
            .removal_plan
            .as_ref()
            .is_some_and(|plan| plan.declaration_pending);
        let declaration_removed = self.declaration_removed();
        let credentials_required = self.credential_retirement_required();
        let credentials_retired = self.credentials_retired();
        let credential_running = self.retirement_lease_until.is_some();
        let credential_retry_required = self.credential_retry_required();
        let primary_action = if uncertainty_needs_ack {
            Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Acknowledge,
                label: "I verified nixcfg — allow a new removal request".to_string(),
            })
        } else if preparing && submitted {
            Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Recover,
                label: "Retry local retirement save".to_string(),
            })
        } else {
            credential_retry_required.then(|| HostWorkflowAction {
                kind: HostWorkflowActionKind::Retry,
                label: "Retry credential retirement".to_string(),
            })
        };
        (
            format!("Remove {} from Pharos", self.host),
            if uncertainty_needs_ack {
                "Pharos could not confirm whether nixcfg received the removal request. Reporting access remains active. Verify nixcfg before allowing another request."
            } else if outcome_uncertain {
                "The operator recorded that nixcfg was checked. Reporting access remains active, and a fresh removal request can now be started deliberately."
            } else if failed {
                "The removal request stopped before Pharos could finish revoking this host. Review the saved failure before trying again."
            } else if preparing && submitted {
                "The repository accepted this removal request. Reporting access remains active while Pharos reconciles its local retirement record; do not resend it."
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
            if uncertainty_needs_ack {
                "dispatch outcome uncertain"
            } else if outcome_uncertain {
                "uncertainty acknowledged"
            } else if failed {
                "removal stopped"
            } else if preparing && submitted {
                "dispatch accepted"
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
                    if outcome_uncertain {
                        WorkflowStepState::Queued
                    } else if failed {
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
                    if outcome_uncertain {
                        WorkflowStepState::ActionRequired
                    } else if failed {
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
                    if outcome_uncertain {
                        "Pharos cannot prove whether the repository accepted this request. Verify nixcfg before continuing."
                    } else if declaration_pending {
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
        HostActionEventKind::DispatchSubmitted => "Repository dispatch submitted",
        HostActionEventKind::DispatchOutcomeUncertain => "Repository dispatch outcome uncertain",
        HostActionEventKind::DispatchUncertaintyAcknowledged => {
            "Dispatch uncertainty acknowledged by operator"
        }
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
    pub(crate) intent: Option<UpdateRestartIntent>,
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
        (
            HostWorkflowKind::SettingsChange,
            HostActionState::Cancelled | HostActionState::Failed,
        ) => 0,
        (HostWorkflowKind::SettingsChange, _) => 2,
        (
            HostWorkflowKind::SystemUpdateProposal,
            HostActionState::Succeeded | HostActionState::Cancelled | HostActionState::Failed,
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
            HostLifecycleSlot::Blocked
            | HostLifecycleSlot::PrefsDrift
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

pub(crate) fn active_update_restart_for_host<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Option<&'a HostActionJob> {
    dedupe_latest_workflow_jobs(jobs, host)
        .into_iter()
        .find(|job| job.workflow_kind() == HostWorkflowKind::UpdateRestart)
        .filter(|job| {
            job.state != HostActionState::Succeeded && job.state != HostActionState::Cancelled
        })
}

pub(crate) fn blocking_update_for_host<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Option<&'a HostActionJob> {
    let mut latest_by_host: BTreeMap<&str, &HostActionJob> = BTreeMap::new();
    for job in jobs
        .iter()
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
    latest_by_host.into_values().find(|job| {
        job.host != host
            && !matches!(
                job.state,
                HostActionState::Succeeded | HostActionState::Cancelled
            )
    })
}

pub(crate) fn withdrawable_settings_change_for_host<'a>(
    jobs: &'a [HostActionJob],
    host: &str,
) -> Option<&'a HostActionJob> {
    dedupe_latest_workflow_jobs(jobs, host)
        .into_iter()
        .find(|job| job.workflow_kind() == HostWorkflowKind::SettingsChange)
        .filter(|job| job.can_withdraw())
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
        update_restart_intent: (job.kind == HostActionKind::UpdateRestart)
            .then_some(job.update_restart_intent()),
        detail,
        blocked_by,
        primary_action: if job.workflow_kind() == HostWorkflowKind::SettingsChange
            && job.state == HostActionState::Cancelled
        {
            None
        } else {
            workflow.primary_action.clone()
        },
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn host_lifecycle(
    jobs: &[HostActionJob],
    host: &str,
    preferences: HostPreferencesState,
    kernel_drift: bool,
) -> HostLifecycle {
    host_lifecycle_with_apply(jobs, host, preferences, kernel_drift, false, false)
}

pub(crate) fn host_lifecycle_with_apply(
    jobs: &[HostActionJob],
    host: &str,
    preferences: HostPreferencesState,
    kernel_drift: bool,
    apply_declared_ready: bool,
    normal_update_ready: bool,
) -> HostLifecycle {
    let action = most_relevant_lifecycle_run(jobs, host);
    if let Some((job, slot)) = action
        .and_then(|job| lifecycle_run_slot(job).map(|slot| (job, slot)))
        .filter(|(_, slot)| *slot != HostLifecycleSlot::SystemUpdateProposal)
    {
        return run_lifecycle(job, slot);
    }

    let apply_declared_waiting = apply_declared_ready
        && (preferences == HostPreferencesState::DeclaredNotApplied || kernel_drift);
    if apply_declared_waiting || normal_update_ready {
        if let Some(blocker) = blocking_update_for_host(jobs, host) {
            let intent = if apply_declared_waiting {
                UpdateRestartIntent::ApplyDeclared
            } else {
                UpdateRestartIntent::Update
            };
            return HostLifecycle {
                schema: HOST_LIFECYCLE_SCHEMA,
                version: HOST_LIFECYCLE_VERSION,
                slot: HostLifecycleSlot::Blocked,
                label: format!("Blocked by {}", blocker.host),
                level: "warning",
                invoke: HostLifecycleInvoke::UpdateRestart,
                run_id: None,
                update_restart_intent: Some(intent),
                detail: format!(
                    "{} holds the fleet update lock. Finish or resolve that workflow before starting this host's guarded {}.",
                    blocker.host,
                    if intent == UpdateRestartIntent::ApplyDeclared {
                        "declared apply"
                    } else {
                        "update"
                    }
                ),
                blocked_by: vec![format!("fleet_update:{}", blocker.host)],
                primary_action: None,
            };
        }
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
                update_restart_intent: None,
                detail: "Requested preferences have not yet been observed by the host.".to_string(),
                blocked_by: vec!["host_report".to_string()],
                primary_action: None,
            };
        }
        HostPreferencesState::DeclaredNotApplied => {
            return HostLifecycle {
                schema: HOST_LIFECYCLE_SCHEMA,
                version: HOST_LIFECYCLE_VERSION,
                slot: HostLifecycleSlot::PrefsDrift,
                label: "Ready to apply".to_string(),
                level: "info",
                invoke: if apply_declared_ready {
                    HostLifecycleInvoke::UpdateRestart
                } else {
                    HostLifecycleInvoke::HostSettings
                },
                run_id: None,
                update_restart_intent: apply_declared_ready
                    .then_some(UpdateRestartIntent::ApplyDeclared),
                detail: if apply_declared_ready {
                    "Declared preferences differ from the host. Start a guarded apply with the normal backup and confirmation gates."
                } else {
                    "Declared preferences differ from the host's observed preferences."
                }
                .to_string(),
                blocked_by: Vec::new(),
                primary_action: None,
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
            invoke: if apply_declared_ready {
                HostLifecycleInvoke::UpdateRestart
            } else {
                HostLifecycleInvoke::KernelDetails
            },
            run_id: None,
            update_restart_intent: apply_declared_ready
                .then_some(UpdateRestartIntent::ApplyDeclared),
            detail: if apply_declared_ready {
                "The running kernel differs from the declared kernel. Start a guarded apply with the normal backup and confirmation gates."
            } else {
                "The running kernel differs from the kernel ready after restart."
            }
            .to_string(),
            blocked_by: vec!["planned_restart".to_string()],
            primary_action: None,
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
        update_restart_intent: None,
        detail: "No host lifecycle work is waiting.".to_string(),
        blocked_by: Vec::new(),
        primary_action: None,
    }
}

fn valid_action_jobs(jobs: &BTreeMap<String, HostActionJob>) -> bool {
    jobs.values().all(|job| {
        job.validate()
            && job.retry_of.as_ref().is_none_or(|retry_of| {
                jobs.get(retry_of).is_some_and(|prior| {
                    prior.host == job.host
                        && prior.created_at <= job.created_at
                        && match (job.kind, prior.kind) {
                            (HostActionKind::UpdateRestart, HostActionKind::UpdateRestart) => {
                                prior.state == HostActionState::Failed
                            }
                            (
                                HostActionKind::SystemUpdateProposal,
                                HostActionKind::SystemUpdateProposal,
                            ) => {
                                prior.state == HostActionState::Failed
                                    && prior
                                        .has_event(HostActionEventKind::DispatchOutcomeUncertain)
                            }
                            _ => false,
                        }
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SystemUpdateProposalBegin {
    New(HostActionJob),
    Existing(HostActionJob),
}

impl SystemUpdateProposalBegin {
    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn job(&self) -> &HostActionJob {
        match self {
            Self::New(job) | Self::Existing(job) => job,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn created(&self) -> bool {
        matches!(self, Self::New(_))
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn into_job(self) -> HostActionJob {
        match self {
            Self::New(job) | Self::Existing(job) => job,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostActionStoreError {
    ActiveJob,
    ActiveSystemUpdateProposal(Box<HostActionJob>),
    UncertaintyRequiresAcknowledgement(Box<HostActionJob>),
    FailedJobRequiresRetry,
    InvalidJob,
    NotFound,
    WrongHost,
    InvalidTransition,
    ReviewFailed,
    BlockedByFleetGate,
    Persistence,
    PersistenceCommitted,
}

impl HostActionStoreError {
    fn persistence_committed(&self) -> bool {
        matches!(self, Self::PersistenceCommitted)
    }
}

pub(crate) struct HostActionStore {
    path: Option<PathBuf>,
    jobs: RwLock<BTreeMap<String, HostActionJob>>,
    pending_durable_repair: Mutex<BTreeSet<String>>,
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
        let now = system_time_unix();
        let (jobs, migrated) = path
            .as_ref()
            .and_then(|path| read_persisted_state(path, "guarded host action"))
            .map(|jobs| {
                let mut jobs: Vec<HostActionJob> = serde_json::from_slice(&jobs)
                    .unwrap_or_else(|_| panic!("guarded host action state is malformed"));
                let mut migrated = false;
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
                    if normalize_system_update_proposal(job, now) {
                        migrated = true;
                    }
                    if reconcile_orphaned_host_dispatch(job, now) {
                        migrated = true;
                    }
                }
                let jobs: BTreeMap<_, _> =
                    jobs.into_iter().map(|job| (job.id.clone(), job)).collect();
                assert!(
                    valid_action_jobs(&jobs),
                    "guarded host action state failed validation"
                );
                (jobs, migrated)
            })
            .unwrap_or((BTreeMap::new(), false));
        let store = Self {
            path,
            jobs: RwLock::new(jobs),
            pending_durable_repair: Mutex::new(BTreeSet::new()),
        };
        if migrated {
            let jobs = store.jobs.read().expect("host action store lock");
            if let Err(error) = store.persist_jobs(&jobs) {
                if !error.persistence_committed() {
                    panic!("migrated host action state failed to persist: {:?}", error);
                }
            }
        }
        store
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
        let _ = self.reconcile_orphaned_host_dispatches_for(id, system_time_unix());
        self.jobs
            .read()
            .expect("host action store lock")
            .get(id)
            .cloned()
    }

    fn note_durable_repair_pending(&self, id: &str) {
        if self.path.is_some() {
            self.pending_durable_repair
                .lock()
                .expect("host action durable repair lock")
                .insert(id.to_string());
        }
    }

    fn remove_durable_repair_pending(&self, id: &str) {
        if self.path.is_some() {
            self.pending_durable_repair
                .lock()
                .expect("host action durable repair lock")
                .remove(id);
        }
    }

    fn pending_durable_repair_snapshot(&self) -> BTreeSet<String> {
        self.pending_durable_repair
            .lock()
            .expect("host action durable repair lock")
            .clone()
    }

    fn clear_durable_repair_for_snapshot(
        &self,
        snapshot_ids: &BTreeSet<String>,
        jobs: &BTreeMap<String, HostActionJob>,
    ) {
        if self.path.is_none() {
            return;
        }
        self.pending_durable_repair
            .lock()
            .expect("host action durable repair lock")
            .retain(|id| {
                !snapshot_ids.contains(id)
                    || jobs
                        .get(id)
                        .is_none_or(|job| !durable_repair_state_is_snapshot_durable(job))
            });
    }

    #[cfg(test)]
    fn pending_durable_repair_ids(&self) -> BTreeSet<String> {
        self.pending_durable_repair_snapshot()
    }

    pub(crate) fn reconcile_orphaned_host_dispatches(
        &self,
        now: i64,
    ) -> Result<bool, HostActionStoreError> {
        self.reconcile_orphaned_host_dispatches_for_ids(self.pending_durable_repair_snapshot(), now)
    }

    fn reconcile_orphaned_host_dispatches_for(
        &self,
        id: &str,
        now: i64,
    ) -> Result<bool, HostActionStoreError> {
        if self.path.is_none() || !self.pending_durable_repair_snapshot().contains(id) {
            return Ok(false);
        }
        let mut ids = BTreeSet::new();
        ids.insert(id.to_string());
        self.reconcile_orphaned_host_dispatches_for_ids(ids, now)
    }

    fn reconcile_orphaned_host_dispatches_for_ids(
        &self,
        pending_ids: BTreeSet<String>,
        now: i64,
    ) -> Result<bool, HostActionStoreError> {
        if self.path.is_none() || pending_ids.is_empty() {
            return Ok(false);
        }
        let mut jobs = self.jobs.write().expect("host action store lock");
        let normalized = reconcile_orphaned_host_dispatches_locked(&mut jobs, &pending_ids, now);
        match self.persist_jobs(&jobs) {
            Ok(()) => Ok(normalized || !pending_ids.is_empty()),
            Err(error) if error.persistence_committed() => Ok(true),
            Err(error) => Err(error),
        }
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

    #[cfg(test)]
    pub(crate) fn most_relevant_for_host(&self, host: &str) -> Option<HostActionJob> {
        let jobs = self.jobs.read().expect("host action store lock");
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
            .max_by_key(|job| {
                let priority = match (job.workflow_kind(), job.state) {
                    (HostWorkflowKind::RemoveHost, HostActionState::Succeeded) => 0,
                    (HostWorkflowKind::RemoveHost, HostActionState::Cancelled) => 0,
                    (HostWorkflowKind::RemoveHost, _) => 4,
                    (HostWorkflowKind::UpdateRestart, HostActionState::Succeeded) => 0,
                    (HostWorkflowKind::UpdateRestart, HostActionState::Cancelled) => 0,
                    (HostWorkflowKind::UpdateRestart, _) => 3,
                    (HostWorkflowKind::SettingsChange, HostActionState::Succeeded) => 0,
                    (HostWorkflowKind::SettingsChange, HostActionState::Cancelled) => 0,
                    (HostWorkflowKind::SettingsChange, _) => 2,
                    (HostWorkflowKind::SystemUpdateProposal, HostActionState::Succeeded) => 0,
                    (HostWorkflowKind::SystemUpdateProposal, HostActionState::Cancelled) => 0,
                    (HostWorkflowKind::SystemUpdateProposal, _) => 1,
                };
                (priority, job.updated_at, job.created_at)
            })
            .cloned()
    }

    pub(crate) fn latest_settings_change_for_host(&self, host: &str) -> Option<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .values()
            .filter(|job| {
                job.host == host && job.workflow_kind() == HostWorkflowKind::SettingsChange
            })
            .max_by_key(|job| (job.created_at, job.updated_at, &job.id))
            .cloned()
    }

    pub(crate) fn latest_removal_for_host(&self, host: &str) -> Option<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .values()
            .filter(|job| job.host == host && job.kind == HostActionKind::RemoveHost)
            .max_by_key(|job| (job.created_at, job.updated_at, &job.id))
            .cloned()
    }

    fn next_workflow_time(
        jobs: &BTreeMap<String, HostActionJob>,
        host: &str,
        kind: HostWorkflowKind,
        now: i64,
    ) -> i64 {
        jobs.values()
            .filter(|job| job.host == host && job.workflow_kind() == kind)
            .map(|job| job.created_at.max(job.updated_at))
            .max()
            .map_or(now, |latest| now.max(latest.saturating_add(1)))
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
            intent: None,
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
            requested_preferences: None,
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

    #[cfg_attr(not(test), allow(dead_code))]
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
        acknowledge_uncertainty_id: Option<&str>,
    ) -> Result<SystemUpdateProposalBegin, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let jobs_before_migrate = jobs.clone();
        let migrated = reconcile_stalled_system_update_proposals_locked(&mut jobs, now);
        if migrated {
            if let Err(error) = self.persist_jobs(&jobs) {
                if !error.persistence_committed() {
                    jobs.clear();
                    jobs.extend(jobs_before_migrate);
                }
                return Err(error);
            }
        }
        let mut pending_ack_rollback: Option<(String, HostActionJob)> = None;
        if let Some(ack_id) = acknowledge_uncertainty_id {
            if !safe_action_id(ack_id) {
                return Err(HostActionStoreError::InvalidJob);
            }
            let prior = jobs.get(ack_id).ok_or(HostActionStoreError::NotFound)?;
            if prior.host != host {
                return Err(HostActionStoreError::WrongHost);
            }
            if prior.workflow_kind() != HostWorkflowKind::SystemUpdateProposal {
                return Err(HostActionStoreError::InvalidJob);
            }
            if let Some(existing) = system_update_replacement_for_acknowledged_locked(&jobs, ack_id)
            {
                if existing.host != host
                    || existing.kind != HostActionKind::SystemUpdateProposal
                    || existing.retry_of.as_deref() != Some(ack_id)
                {
                    return Err(HostActionStoreError::InvalidJob);
                }
                return Ok(SystemUpdateProposalBegin::Existing(existing));
            }
            if prior.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged) {
                if let Some(other) = unacknowledged_uncertain_system_update_proposal(&jobs) {
                    return Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(
                        Box::new(other),
                    ));
                }
                return Ok(SystemUpdateProposalBegin::Existing(prior.clone()));
            }
            if system_update_uncertainty_requires_acknowledgement(prior) {
                let prior_snapshot = prior.clone();
                self.acknowledge_system_update_proposal_uncertainty_locked(
                    &mut jobs, ack_id, actor, now,
                )?;
                if let Some(other) = unacknowledged_uncertain_system_update_proposal(&jobs) {
                    if let Err(error) = self.persist_jobs(&jobs) {
                        if !error.persistence_committed() {
                            jobs.insert(ack_id.to_string(), prior_snapshot);
                        }
                        return Err(error);
                    }
                    return Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(
                        Box::new(other),
                    ));
                }
                pending_ack_rollback = Some((ack_id.to_string(), prior_snapshot));
            } else {
                return Err(HostActionStoreError::InvalidTransition);
            }
        }
        if pending_ack_rollback.is_none() {
            if let Some(job) = unacknowledged_uncertain_system_update_proposal(&jobs) {
                return Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(
                    Box::new(job),
                ));
            }
        }
        if let Some(active) = active_system_update_proposal_locked(&jobs) {
            if let Some((ack_id, previous)) = pending_ack_rollback {
                jobs.insert(ack_id, previous);
            }
            return Err(HostActionStoreError::ActiveSystemUpdateProposal(Box::new(
                active,
            )));
        }
        let now =
            Self::next_workflow_time(&jobs, host, HostWorkflowKind::SystemUpdateProposal, now);
        let retry_of = acknowledge_uncertainty_id.map(str::to_string);
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("system-update", host, now),
            host: host.to_string(),
            kind: HostActionKind::SystemUpdateProposal,
            intent: None,
            workflow_kind: None,
            state: HostActionState::ProposalRequested,
            requested_by: actor.to_string(),
            ticket: "PHAROS-125".to_string(),
            retry_of,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            plan: None,
            removal_plan: None,
            requested_preferences: None,
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
        if pending_ack_rollback.is_some() {
            if let Err(error) = self.prepare_insert_locked(&mut jobs, &job) {
                if let Some((ack_id, previous)) = pending_ack_rollback {
                    jobs.insert(ack_id, previous);
                }
                return Err(error);
            }
            if let Err(error) = self.persist_jobs(&jobs) {
                if error.persistence_committed() {
                    return Ok(SystemUpdateProposalBegin::New(job));
                }
                jobs.remove(&job.id);
                if let Some((ack_id, previous)) = pending_ack_rollback {
                    jobs.insert(ack_id, previous);
                }
                return Err(error);
            }
            Ok(SystemUpdateProposalBegin::New(job))
        } else {
            self.prepare_insert_locked(&mut jobs, &job)?;
            if let Err(error) = self.persist_jobs(&jobs) {
                if error.persistence_committed() {
                    return Ok(SystemUpdateProposalBegin::New(job));
                }
                jobs.remove(&job.id);
                return Err(error);
            }
            Ok(SystemUpdateProposalBegin::New(job))
        }
    }

    #[cfg(test)]
    pub(crate) fn accept_system_update_proposal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_system_update_proposal(id, now, HostActionEventKind::DispatchAccepted)
    }

    pub(crate) fn fail_system_update_proposal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_system_update_proposal(id, now, HostActionEventKind::DispatchFailed)
    }

    pub(crate) fn fail_system_update_proposal_uncertain(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_system_update_proposal(id, now, HostActionEventKind::DispatchOutcomeUncertain)
    }

    fn acknowledge_system_update_proposal_uncertainty_locked(
        &self,
        jobs: &mut BTreeMap<String, HostActionJob>,
        id: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if !system_update_uncertainty_requires_acknowledgement(job) {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let at = job.updated_at.max(now);
            job.updated_at = at;
            if !job.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged) {
                job.record_event(
                    at,
                    HostActionEventSource::Operator,
                    HostActionEventKind::DispatchUncertaintyAcknowledged,
                    Some(actor),
                );
            }
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        Ok(updated)
    }

    fn update_system_update_proposal(
        &self,
        id: &str,
        now: i64,
        failure_kind: HostActionEventKind,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let sticky_on_persist_failure =
            failure_kind == HostActionEventKind::DispatchOutcomeUncertain;
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.workflow_kind() != HostWorkflowKind::SystemUpdateProposal
                || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let at = job.updated_at.max(now);
            job.state = if failure_kind == HostActionEventKind::DispatchAccepted {
                HostActionState::Succeeded
            } else {
                HostActionState::Failed
            };
            job.updated_at = at;
            job.record_event(at, HostActionEventSource::Pharos, failure_kind, None);
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() && !sticky_on_persist_failure {
                jobs.insert(id.to_string(), previous);
                self.remove_durable_repair_pending(id);
            } else if sticky_on_persist_failure && !error.persistence_committed() {
                self.note_durable_repair_pending(id);
            }
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn record_settings_request(
        &self,
        id: &str,
        preferences: &HostPreferences,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        if preferences.validate_contract().is_err() {
            return Err(HostActionStoreError::InvalidJob);
        }
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.workflow_kind() != HostWorkflowKind::SettingsChange
                || job.state != HostActionState::ProposalRequested
                || job.has_event(HostActionEventKind::DispatchSubmitted)
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            job.updated_at = job.updated_at.max(now);
            job.requested_preferences = Some(preferences.clone());
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn mark_dispatch_submitted(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if !matches!(
                job.workflow_kind(),
                HostWorkflowKind::SettingsChange
                    | HostWorkflowKind::SystemUpdateProposal
                    | HostWorkflowKind::RemoveHost
            ) || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            if !job.has_event(HostActionEventKind::DispatchSubmitted) {
                let at = job.updated_at.max(now);
                if job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal {
                    job.state = HostActionState::Succeeded;
                }
                job.updated_at = at;
                job.record_event(
                    at,
                    HostActionEventSource::Pharos,
                    HostActionEventKind::DispatchSubmitted,
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
                self.note_durable_repair_pending(id);
            }
            return Err(error);
        }
        Ok(updated)
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) fn create_update_review(
        &self,
        host: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.create_update_review_with_intent(host, actor, UpdateRestartIntent::Update, now)
    }

    pub(crate) fn create_update_review_with_intent(
        &self,
        host: &str,
        actor: &str,
        intent: UpdateRestartIntent,
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
        let job = Self::new_update_review(host, actor, intent, now, None);
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
        let intent = existing.update_restart_intent();
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
        let job = Self::new_update_review(host, actor, intent, now, Some(id.to_string()));
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn withdraw_settings_change(
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
            if !job.can_withdraw() {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let event_at = now.max(job.updated_at);
            job.state = HostActionState::Cancelled;
            job.updated_at = event_at;
            job.lease_phase = None;
            job.lease_until = None;
            job.record_event(
                event_at,
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
        let _ = self.reconcile_orphaned_host_dispatches(now);
        let mut jobs = self.jobs.write().expect("host action store lock");
        if jobs.values().any(|job| {
            job.host == host
                && job.kind == HostActionKind::RemoveHost
                && dispatch_uncertainty_requires_acknowledgement(job)
        }) {
            return Err(HostActionStoreError::ActiveJob);
        }
        if Self::has_active(&jobs, host, HostActionKind::RemoveHost) {
            return Err(HostActionStoreError::ActiveJob);
        }
        let now = Self::next_workflow_time(&jobs, host, HostWorkflowKind::RemoveHost, now);
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("remove-host", host, now),
            host: host.to_string(),
            kind: HostActionKind::RemoveHost,
            intent: None,
            workflow_kind: None,
            state: HostActionState::ProposalRequested,
            requested_by: actor.to_string(),
            ticket: "PHAROS-127".to_string(),
            retry_of: None,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            plan: None,
            removal_plan: Some(removal_plan),
            requested_preferences: None,
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
            let event_at = now.max(job.updated_at);
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
            job.updated_at = event_at;
            job.record_event(
                event_at,
                HostActionEventSource::Pharos,
                HostActionEventKind::RemovalAccessRevoked,
                None,
            );
            if !declaration_pending && !credential_retirement_required {
                job.record_event(
                    event_at,
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn fail_removal(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.fail_removal_with_event(id, now, HostActionEventKind::RemovalFailed)
    }

    pub(crate) fn fail_removal_uncertain(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.fail_removal_with_event(id, now, HostActionEventKind::DispatchOutcomeUncertain)
    }

    fn fail_removal_with_event(
        &self,
        id: &str,
        now: i64,
        failure_kind: HostActionEventKind,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let sticky_on_persist_failure =
            failure_kind == HostActionEventKind::DispatchOutcomeUncertain;
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if job.kind != HostActionKind::RemoveHost
                || job.state != HostActionState::ProposalRequested
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            let previous = job.clone();
            let event_at = now.max(job.updated_at);
            job.state = HostActionState::Failed;
            job.updated_at = event_at;
            job.record_event(event_at, HostActionEventSource::Pharos, failure_kind, None);
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() && !sticky_on_persist_failure {
                jobs.insert(id.to_string(), previous);
                self.remove_durable_repair_pending(id);
            } else if sticky_on_persist_failure && !error.persistence_committed() {
                self.note_durable_repair_pending(id);
            }
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
        let _ = self.reconcile_orphaned_host_dispatches(now);
        let mut jobs = self.jobs.write().expect("host action store lock");
        if jobs.values().any(|job| {
            job.host == host
                && job.workflow_kind() == HostWorkflowKind::SettingsChange
                && dispatch_uncertainty_requires_acknowledgement(job)
        }) {
            return Err(HostActionStoreError::ActiveJob);
        }
        if jobs.values().any(|job| {
            job.host == host
                && job.workflow_kind() == HostWorkflowKind::SettingsChange
                && !job.state.is_terminal()
        }) {
            return Err(HostActionStoreError::ActiveJob);
        }
        let now = Self::next_workflow_time(&jobs, host, HostWorkflowKind::SettingsChange, now);
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("settings-change", host, now),
            host: host.to_string(),
            // Keep the persisted v1 action enum backward-readable. New clients
            // use workflow_kind for the precise user-facing workflow.
            kind: HostActionKind::SystemUpdateProposal,
            intent: None,
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
            requested_preferences: None,
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

    pub(crate) fn acknowledge_dispatch_uncertainty(
        &self,
        id: &str,
        actor: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        let mut jobs = self.jobs.write().expect("host action store lock");
        let (previous, updated) = {
            let job = jobs.get_mut(id).ok_or(HostActionStoreError::NotFound)?;
            if !matches!(
                job.workflow_kind(),
                HostWorkflowKind::SettingsChange | HostWorkflowKind::RemoveHost
            ) || job.state != HostActionState::Failed
                || !job.has_event(HostActionEventKind::DispatchOutcomeUncertain)
            {
                return Err(HostActionStoreError::InvalidTransition);
            }
            if job.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged) {
                return Ok(job.clone());
            }
            let previous = job.clone();
            let event_at = now.max(job.updated_at);
            job.updated_at = event_at;
            job.record_event(
                event_at,
                HostActionEventSource::Operator,
                HostActionEventKind::DispatchUncertaintyAcknowledged,
                Some(actor),
            );
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
            return Err(error);
        }
        Ok(updated)
    }

    pub(crate) fn accept_settings_change(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_settings_change(id, now, false, |job, event_at| {
            job.record_event(
                event_at,
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
        self.update_settings_change(id, now, false, |job, event_at| {
            job.state = HostActionState::Failed;
            job.record_event(
                event_at,
                HostActionEventSource::Pharos,
                HostActionEventKind::SettingsFailed,
                None,
            );
        })
    }

    pub(crate) fn fail_settings_change_uncertain(
        &self,
        id: &str,
        now: i64,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.update_settings_change(id, now, true, |job, event_at| {
            job.state = HostActionState::Failed;
            job.record_event(
                event_at,
                HostActionEventSource::Pharos,
                HostActionEventKind::DispatchOutcomeUncertain,
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
            let event_at = now.max(job.updated_at);
            job.state = HostActionState::Succeeded;
            job.updated_at = event_at;
            job.record_event(
                event_at,
                HostActionEventSource::Beacon,
                HostActionEventKind::SettingsApplied,
                None,
            );
            (previous, job.clone())
        };
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() {
                jobs.insert(id, previous);
            }
            return Err(error);
        }
        Ok(Some(updated))
    }

    fn update_settings_change(
        &self,
        id: &str,
        now: i64,
        sticky_on_persist_failure: bool,
        update: impl FnOnce(&mut HostActionJob, i64),
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
            let event_at = now.max(job.updated_at);
            job.updated_at = event_at;
            update(job, event_at);
            (previous, job.clone())
        };
        if !updated.validate() {
            jobs.insert(id.to_string(), previous);
            return Err(HostActionStoreError::InvalidJob);
        }
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() && !sticky_on_persist_failure {
                jobs.insert(id.to_string(), previous);
                self.remove_durable_repair_pending(id);
            } else if sticky_on_persist_failure && !error.persistence_committed() {
                self.note_durable_repair_pending(id);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            // The deployed nixcfg consumer requires this exact v1 six-field
            // envelope and PHAROS-126 ticket. PHAROS-216 intent/provenance is
            // control-plane state, not target-agent wire authority.
            schema: "inspr.pharos.host-action-lease.v1",
            version: 1,
            id: job.id.clone(),
            host: job.host.clone(),
            ticket: "PHAROS-126".to_string(),
            phase,
        };
        let id = job.id.clone();
        if let Err(error) = self.persist_jobs(&jobs) {
            if !error.persistence_committed() {
                jobs.insert(id, previous);
            }
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
                    let restart_expected = job.plan.as_ref().is_some_and(|plan| {
                        plan.restart_required
                            || job.update_restart_intent() == UpdateRestartIntent::RestartOnly
                    });
                    if request.result.is_some() || !restart_expected {
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
                    let restart_expected = job.plan.as_ref().is_some_and(|plan| {
                        plan.restart_required
                            || job.update_restart_intent() == UpdateRestartIntent::RestartOnly
                    });
                    if !(result.backup_validated
                        && result.switch_passed
                        && (!restart_expected || result.reboot_observed)
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id, previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
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
            if !error.persistence_committed() {
                jobs.insert(id.to_string(), previous);
            }
            return Err(error);
        }
        Ok(updated)
    }

    fn new_update_review(
        host: &str,
        actor: &str,
        intent: UpdateRestartIntent,
        now: i64,
        retry_of: Option<String>,
    ) -> HostActionJob {
        let mut job = HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("update-restart", host, now),
            host: host.to_string(),
            kind: HostActionKind::UpdateRestart,
            intent: Some(intent),
            workflow_kind: None,
            state: HostActionState::QueuedReview,
            requested_by: actor.to_string(),
            ticket: match intent {
                UpdateRestartIntent::Update => "PHAROS-126",
                UpdateRestartIntent::ApplyDeclared | UpdateRestartIntent::RestartOnly => {
                    "PHAROS-216"
                }
            }
            .to_string(),
            retry_of,
            created_at: now,
            updated_at: now,
            confirmed_at: None,
            plan: None,
            removal_plan: None,
            requested_preferences: None,
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
        let snapshot = jobs.values().cloned().collect::<Vec<_>>();
        blocking_update_for_host(&snapshot, host).is_some()
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
        self.prepare_insert_locked(jobs, &job)?;
        if let Err(error) = self.persist_jobs(jobs) {
            if !error.persistence_committed() {
                jobs.remove(&job.id);
            }
            return Err(error);
        }
        Ok(job)
    }

    fn prepare_insert_locked(
        &self,
        jobs: &mut BTreeMap<String, HostActionJob>,
        job: &HostActionJob,
    ) -> Result<(), HostActionStoreError> {
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
        Ok(())
    }

    fn persist_jobs(
        &self,
        jobs: &BTreeMap<String, HostActionJob>,
    ) -> Result<(), HostActionStoreError> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let snapshot_ids: BTreeSet<String> = jobs.keys().cloned().collect();
        let snapshot: Vec<_> = jobs.values().cloned().collect();
        let result = persist_json(path, &snapshot);
        if matches!(
            result,
            Ok(()) | Err(HostActionStoreError::PersistenceCommitted)
        ) {
            self.clear_durable_repair_for_snapshot(&snapshot_ids, jobs);
        }
        result
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
        (HostWorkflowKind::SystemUpdateProposal, HostActionState::Succeeded) => {
            HostActionEventKind::DispatchAccepted
        }
        (HostWorkflowKind::SystemUpdateProposal, HostActionState::ProposalRequested) => {
            HostActionEventKind::Requested
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
            if !error.persistence_committed() {
                match previous {
                    Some(previous) => {
                        hosts.insert(host, previous);
                    }
                    None => {
                        hosts.remove(&host);
                    }
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
            if !error.persistence_committed() {
                hosts.insert(host.to_string(), removed);
            }
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

fn system_time_unix() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

fn normalize_system_update_proposal(job: &mut HostActionJob, now: i64) -> bool {
    if job.workflow_kind() != HostWorkflowKind::SystemUpdateProposal
        || job.state != HostActionState::ProposalRequested
    {
        return false;
    }
    let accepted = job.has_event(HostActionEventKind::DispatchAccepted);
    let submitted = job.has_event(HostActionEventKind::DispatchSubmitted);
    let wall_now = system_time_unix();
    if accepted || submitted {
        let at = job.updated_at.max(now);
        job.state = HostActionState::Succeeded;
        job.updated_at = at;
        if !accepted {
            job.record_event(
                at,
                HostActionEventSource::Pharos,
                HostActionEventKind::DispatchAccepted,
                None,
            );
        }
        return true;
    }
    if wall_now
        > job
            .updated_at
            .saturating_add(SYSTEM_UPDATE_DISPATCH_STALL_SECS)
    {
        let at = job.updated_at.max(now);
        job.state = HostActionState::Failed;
        job.updated_at = at;
        if !job.has_event(HostActionEventKind::DispatchOutcomeUncertain) {
            job.record_event(
                at,
                HostActionEventSource::Pharos,
                HostActionEventKind::DispatchOutcomeUncertain,
                None,
            );
        }
        return true;
    }
    false
}

fn reconcile_orphaned_host_dispatch(job: &mut HostActionJob, now: i64) -> bool {
    if !matches!(
        job.workflow_kind(),
        HostWorkflowKind::SettingsChange | HostWorkflowKind::RemoveHost
    ) || job.state != HostActionState::ProposalRequested
        || job.has_event(HostActionEventKind::DispatchSubmitted)
    {
        return false;
    }
    match job.workflow_kind() {
        HostWorkflowKind::SettingsChange => {
            if job.has_event(HostActionEventKind::SettingsRequestAccepted)
                || job.requested_preferences.is_none()
            {
                return false;
            }
        }
        HostWorkflowKind::RemoveHost => {}
        _ => return false,
    }
    let at = job.updated_at.max(now);
    job.state = HostActionState::Failed;
    job.updated_at = at;
    if !job.has_event(HostActionEventKind::DispatchOutcomeUncertain) {
        job.record_event(
            at,
            HostActionEventSource::Pharos,
            HostActionEventKind::DispatchOutcomeUncertain,
            None,
        );
    }
    true
}

fn durable_repair_state_is_snapshot_durable(job: &HostActionJob) -> bool {
    job.has_event(HostActionEventKind::DispatchSubmitted)
        || (job.state == HostActionState::Failed
            && job.has_event(HostActionEventKind::DispatchOutcomeUncertain))
        || (job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal
            && job.state == HostActionState::Succeeded)
}

fn reconcile_orphaned_host_dispatches_locked(
    jobs: &mut BTreeMap<String, HostActionJob>,
    pending_ids: &BTreeSet<String>,
    now: i64,
) -> bool {
    let mut migrated = false;
    for id in pending_ids {
        if let Some(job) = jobs.get_mut(id) {
            if reconcile_orphaned_host_dispatch(job, now) {
                migrated = true;
            }
        }
    }
    migrated
}

fn system_update_uncertainty_requires_acknowledgement(job: &HostActionJob) -> bool {
    job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal
        && job.state == HostActionState::Failed
        && job.has_event(HostActionEventKind::DispatchOutcomeUncertain)
        && !job.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged)
}

fn dispatch_uncertainty_requires_acknowledgement(job: &HostActionJob) -> bool {
    job.state == HostActionState::Failed
        && job.has_event(HostActionEventKind::DispatchOutcomeUncertain)
        && !job.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged)
}

fn unacknowledged_uncertain_system_update_proposal(
    jobs: &BTreeMap<String, HostActionJob>,
) -> Option<HostActionJob> {
    jobs.values()
        .filter(|job| system_update_uncertainty_requires_acknowledgement(job))
        .max_by_key(|job| (job.updated_at, job.created_at, &job.id))
        .cloned()
}

fn system_update_replacement_for_acknowledged_locked(
    jobs: &BTreeMap<String, HostActionJob>,
    prior_id: &str,
) -> Option<HostActionJob> {
    jobs.values()
        .filter(|job| {
            job.kind == HostActionKind::SystemUpdateProposal
                && job.retry_of.as_deref() == Some(prior_id)
        })
        .max_by_key(|job| (job.created_at, &job.id))
        .cloned()
}

fn active_system_update_proposal_locked(
    jobs: &BTreeMap<String, HostActionJob>,
) -> Option<HostActionJob> {
    jobs.values()
        .filter(|job| {
            job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal
                && !job.state.is_terminal()
        })
        .max_by_key(|job| (job.updated_at, job.created_at, &job.id))
        .cloned()
}

fn reconcile_stalled_system_update_proposals_locked(
    jobs: &mut BTreeMap<String, HostActionJob>,
    now: i64,
) -> bool {
    let mut migrated = false;
    for job in jobs.values_mut() {
        if normalize_system_update_proposal(job, now) {
            migrated = true;
        }
    }
    migrated
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
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent).map_err(|_| HostActionStoreError::Persistence)?;
    let counter = PERSIST_COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = path.with_extension(format!("tmp-{}-{counter}", std::process::id()));
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let pre_commit = (|| -> std::io::Result<()> {
        let mut file = options.open(&tmp)?;
        file.write_all(&json)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if pre_commit.is_err() {
        let _ = std::fs::remove_file(&tmp);
        tracing::warn!("failed to durably persist guarded host action state");
        return Err(HostActionStoreError::Persistence);
    }
    #[cfg(test)]
    let parent_sync = if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("pharos-post-commit-sync-failure-"))
    {
        Err(std::io::Error::other(
            "injected parent directory sync failure",
        ))
    } else {
        std::fs::File::open(parent).and_then(|directory| directory.sync_all())
    };
    #[cfg(not(test))]
    let parent_sync = std::fs::File::open(parent).and_then(|directory| directory.sync_all());
    if parent_sync.is_err() {
        tracing::warn!(
            "guarded host action state was renamed into place but directory durability could not be confirmed"
        );
        return Err(HostActionStoreError::PersistenceCommitted);
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

pub(crate) fn system_update_uncertainty_acknowledgement_id_valid(value: &str) -> bool {
    safe_action_id(value)
}

pub(crate) fn system_update_dispatch_handed_off(job: &HostActionJob) -> bool {
    job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal
        && (job.state == HostActionState::Succeeded
            || job.has_event(HostActionEventKind::DispatchSubmitted)
            || job.has_event(HostActionEventKind::DispatchAccepted))
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
            intent: (action_kind == HostActionKind::UpdateRestart)
                .then_some(UpdateRestartIntent::Update),
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
            requested_preferences: None,
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
    fn apply_declared_intent_stays_control_plane_only_and_skips_unneeded_restart() {
        let path = std::env::temp_dir().join(format!(
            "pharos-apply-declared-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let job = store
            .create_update_review_with_intent(
                "hsb8",
                "markus",
                UpdateRestartIntent::ApplyDeclared,
                120,
            )
            .expect("declared apply created");
        assert_eq!(job.ticket, "PHAROS-216");
        assert_eq!(
            job.update_restart_intent(),
            UpdateRestartIntent::ApplyDeclared
        );
        assert_eq!(
            job.summary().intent,
            Some(UpdateRestartIntent::ApplyDeclared)
        );

        let review = store.claim("hsb8", 121).expect("claim").expect("lease");
        let actual = serde_json::to_value(&review).expect("lease serializes");
        let mut expected: serde_json::Value = serde_json::from_str(include_str!(
            "../tests/fixtures/nixcfg-host-action-lease-v1.json"
        ))
        .expect("nixcfg contract fixture parses");
        // Action IDs include a process-global counter. Normalize only that
        // value; every authority-bearing declaration and the exact key set
        // remain pinned to the deployed cross-repository consumer contract.
        expected["id"] = actual["id"].clone();
        assert_eq!(actual, expected);
        assert_eq!(actual.as_object().expect("lease object").len(), 6);
        assert_eq!(review.id, job.id);
        assert_eq!(review.ticket, "PHAROS-126");

        let mut plan = ready_plan();
        plan.restart_required = false;
        store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Review,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: Some(plan),
                    result: None,
                },
                122,
            )
            .expect("review stored");
        let confirmed = store
            .confirm_update(&job.id, "hsb8", "markus", 123)
            .expect("confirmed");
        let workflow = confirmed.summary().workflow;
        assert_eq!(workflow.title, "Apply declared configuration to hsb8");
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "restart")
                .expect("restart step")
                .state,
            WorkflowStepState::Skipped
        );

        let apply = store.claim("hsb8", 124).expect("claim").expect("lease");
        assert_eq!(apply.schema, "inspr.pharos.host-action-lease.v1");
        assert_eq!(apply.version, 1);
        assert_eq!(apply.ticket, "PHAROS-126");
        assert_eq!(
            serde_json::to_value(&apply)
                .expect("apply lease serializes")
                .as_object()
                .expect("apply lease object")
                .len(),
            6
        );
        assert_eq!(
            store.record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Rebooting,
                    plan: None,
                    result: None,
                },
                125,
            ),
            Err(HostActionStoreError::InvalidJob)
        );
        let completed = store
            .record_agent_result(
                &job.id,
                "hsb8",
                AgentActionResultRequest {
                    host: "hsb8".to_string(),
                    phase: AgentActionPhase::Apply,
                    outcome: AgentActionOutcome::Succeeded,
                    plan: None,
                    result: Some(HostActionResult {
                        backup_validated: true,
                        switch_passed: true,
                        reboot_observed: false,
                        kernel_verified: true,
                        rollback_available: true,
                        failure_gate: None,
                        recovery_mode: None,
                    }),
                },
                126,
            )
            .expect("non-restarting apply accepted");
        assert_eq!(completed.state, HostActionState::Succeeded);
        assert!(completed
            .summary()
            .workflow
            .evidence
            .iter()
            .any(|fact| fact.label == "Restart observed" && fact.value == "not required"));

        let reloaded = HostActionStore::new(Some(path.clone()));
        assert_eq!(
            reloaded
                .get(&job.id)
                .expect("declared apply reloads")
                .update_restart_intent(),
            UpdateRestartIntent::ApplyDeclared
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn declared_apply_lifecycle_names_the_host_holding_the_fleet_lock() {
        let mut blocker = lifecycle_job(
            HostWorkflowKind::UpdateRestart,
            HostActionState::QueuedReview,
            150,
        );
        blocker.host = "csb0".to_string();

        let blocked = host_lifecycle_with_apply(
            &[blocker],
            "hsb8",
            HostPreferencesState::DeclaredNotApplied,
            false,
            true,
            false,
        );
        assert_eq!(blocked.slot, HostLifecycleSlot::Blocked);
        assert_eq!(blocked.label, "Blocked by csb0");
        assert!(blocked.detail.contains("csb0 holds the fleet update lock"));
        assert_eq!(blocked.blocked_by, vec!["fleet_update:csb0"]);
        assert_eq!(
            blocked.update_restart_intent,
            Some(UpdateRestartIntent::ApplyDeclared)
        );
        assert!(blocked.primary_action.is_none());

        let ready = host_lifecycle_with_apply(
            &[],
            "hsb8",
            HostPreferencesState::DeclaredNotApplied,
            false,
            true,
            false,
        );
        assert_eq!(ready.slot, HostLifecycleSlot::PrefsDrift);
        assert_eq!(ready.invoke, HostLifecycleInvoke::UpdateRestart);
        assert_eq!(
            ready.update_restart_intent,
            Some(UpdateRestartIntent::ApplyDeclared)
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
        let workflow = accepted.summary().workflow;
        let wait = workflow
            .steps
            .iter()
            .find(|step| step.key == "host")
            .expect("host wait step");
        assert_eq!(wait.state, WorkflowStepState::Waiting);
        let request = workflow
            .ladder
            .iter()
            .find(|fact| fact.key == "requested")
            .expect("requested ladder fact");
        assert_eq!(request.fact, "Pending request saved for host delivery");
        assert_eq!(request.state, "complete");
        let send = workflow
            .steps
            .iter()
            .find(|step| step.key == "request")
            .expect("request step");
        assert_eq!(send.location, HostWorkflowExecutionLocation::Pharos);

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
    fn accepted_settings_handoff_names_missing_evidence_and_only_offers_refresh() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_settings_change("csb0", "markus", 420)
            .expect("settings workflow created");
        store
            .mark_dispatch_submitted(&job.id, 421)
            .expect("repository handoff recorded");
        let waiting = store
            .accept_settings_change(&job.id, 422)
            .expect("repository handoff accepted");
        let workflow = waiting.summary().workflow;

        assert_eq!(
            workflow.guidance,
            "The repository handoff is accepted, but no matching host report is recorded. Finish the nixcfg review, merge, and deployment first. Then csb0 must report the requested values; Pharos will not mark this run complete without that matching host evidence."
        );
        assert_eq!(workflow.current_step.as_deref(), Some("host"));
        assert_eq!(
            workflow.primary_action,
            Some(HostWorkflowAction {
                kind: HostWorkflowActionKind::Refresh,
                label: "Check host now".to_string(),
            })
        );
        assert_eq!(workflow.next.location, "Pharos");
        assert!(workflow
            .next
            .consequence
            .contains("Reads this saved run again"));
        assert!(workflow
            .next
            .consequence
            .contains("completion still requires csb0 to report the requested values"));
        assert_eq!(
            workflow.next.boundary,
            "Pharos will not close or merge a nixcfg proposal."
        );

        let unchanged = store.get(&job.id).expect("waiting run retained");
        assert_eq!(unchanged.state, HostActionState::ProposalRequested);
        assert_eq!(unchanged.updated_at, 422);
        assert_eq!(unchanged.events.len(), 3);

        let completed = store
            .complete_settings_change("csb0", 423)
            .expect("matching host report persisted")
            .expect("settings workflow completed");
        let completed_workflow = completed.summary().workflow;
        assert_eq!(completed.state, HostActionState::Succeeded);
        assert!(completed_workflow.primary_action.is_none());
        assert_eq!(completed_workflow.current_step, None);
        assert_eq!(
            completed_workflow.events.last().map(|event| event.at),
            Some(423)
        );
    }

    #[test]
    fn failed_settings_ladder_stops_the_request_instead_of_claiming_current_work() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_settings_change("hsb8", "markus", 404)
            .expect("settings workflow created");
        let failed = store
            .fail_settings_change(&job.id, 405)
            .expect("settings request stopped");
        let workflow = failed.summary().workflow;
        let requested = workflow
            .ladder
            .iter()
            .find(|fact| fact.key == "requested")
            .expect("requested ladder fact");
        assert_eq!(requested.state, "stopped");
        assert_eq!(requested.fact, "Request delivery stopped");
        assert!(workflow.primary_action.is_none());
    }

    #[test]
    fn nonterminal_settings_change_can_be_withdrawn_without_erasing_audit_facts() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_settings_change("hsb8", "markus", 410)
            .expect("settings workflow created");
        let requested = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..HostPreferences::default()
        };
        store
            .record_settings_request(&job.id, &requested, 411)
            .expect("settings request recorded");
        store
            .mark_dispatch_submitted(&job.id, 412)
            .expect("repository handoff recorded");

        let withdrawn = store
            .withdraw_settings_change(&job.id, "hsb8", "markus", 413)
            .expect("settings change withdrawn");
        assert_eq!(withdrawn.state, HostActionState::Cancelled);
        assert_eq!(withdrawn.requested_preferences(), Some(&requested));
        assert!(!withdrawn.can_withdraw());
        let workflow = withdrawn.summary().workflow;
        assert_eq!(workflow.status_label, "settings change withdrawn");
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "request")
                .expect("request step")
                .state,
            WorkflowStepState::Cancelled
        );
        assert_eq!(
            workflow.next.consequence,
            "Clears the pending request. An open nixcfg proposal stays open there."
        );
        assert!(matches!(
            store.withdraw_settings_change(&job.id, "hsb8", "markus", 414),
            Err(HostActionStoreError::InvalidTransition)
        ));
        store
            .begin_settings_change("hsb8", "markus", 415)
            .expect("a fresh settings change can start after withdrawal");
    }

    #[test]
    fn uncertain_settings_and_removal_require_durable_ack_before_a_fresh_request() {
        let store = HostActionStore::new(None);
        let settings = store
            .begin_settings_change("hsb8", "markus", 404)
            .expect("settings workflow created");
        let settings = store
            .fail_settings_change_uncertain(&settings.id, 405)
            .expect("settings uncertainty persisted");
        let settings_workflow = settings.summary().workflow;
        assert_eq!(settings_workflow.status_label, "dispatch outcome uncertain");
        assert_eq!(
            settings_workflow
                .primary_action
                .as_ref()
                .map(|action| action.kind),
            Some(HostWorkflowActionKind::Acknowledge)
        );
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 406),
            Err(HostActionStoreError::ActiveJob)
        );
        let acknowledged = store
            .acknowledge_dispatch_uncertainty(&settings.id, "markus", 407)
            .expect("settings uncertainty acknowledged");
        assert_eq!(
            acknowledged.summary().workflow.status_label,
            "uncertainty acknowledged"
        );
        store
            .begin_settings_change("hsb8", "markus", 408)
            .expect("fresh settings request allowed after acknowledgement");

        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let removal = store
            .begin_removal("gpc0", "markus", removal_plan.clone(), 409)
            .expect("removal workflow created");
        let removal = store
            .fail_removal_uncertain(&removal.id, 410)
            .expect("removal uncertainty persisted");
        let removal_workflow = removal.summary().workflow;
        assert_eq!(removal_workflow.status_label, "dispatch outcome uncertain");
        assert!(removal_workflow
            .guidance
            .contains("Reporting access remains active"));
        assert_eq!(
            removal_workflow
                .primary_action
                .as_ref()
                .map(|action| action.kind),
            Some(HostWorkflowActionKind::Acknowledge)
        );
        assert_eq!(
            store.begin_removal("gpc0", "markus", removal_plan.clone(), 411),
            Err(HostActionStoreError::ActiveJob)
        );
        store
            .acknowledge_dispatch_uncertainty(&removal.id, "markus", 412)
            .expect("removal uncertainty acknowledged");
        store
            .begin_removal("gpc0", "markus", removal_plan, 413)
            .expect("fresh removal request allowed after acknowledgement");
    }

    #[test]
    fn asynchronous_settings_and_removal_events_clamp_a_rolled_back_clock() {
        let store = HostActionStore::new(None);
        let settings = store
            .begin_settings_change("hsb8", "markus", 500)
            .expect("settings workflow created");
        let uncertain = store
            .fail_settings_change_uncertain(&settings.id, 499)
            .expect("clock rollback does not strand settings workflow");
        assert_eq!(uncertain.updated_at, 500);
        assert_eq!(uncertain.events.last().map(|event| event.at), Some(500));
        let acknowledged = store
            .acknowledge_dispatch_uncertainty(&settings.id, "markus", 498)
            .expect("clock rollback does not block acknowledgement");
        assert_eq!(acknowledged.updated_at, 500);
        assert_eq!(acknowledged.events.last().map(|event| event.at), Some(500));
        let replacement_settings = store
            .begin_settings_change("hsb8", "markus", 400)
            .expect("rolled-back clock still creates a newer settings workflow");
        assert_eq!(replacement_settings.created_at, 501);
        assert_eq!(
            store
                .latest_settings_change_for_host("hsb8")
                .map(|job| job.id),
            Some(replacement_settings.id)
        );

        let removal = store
            .begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Unmanaged,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                600,
            )
            .expect("removal workflow created");
        let failed = store
            .fail_removal_uncertain(&removal.id, 599)
            .expect("clock rollback does not strand removal workflow");
        assert_eq!(failed.updated_at, 600);
        assert_eq!(failed.events.last().map(|event| event.at), Some(600));
        store
            .acknowledge_dispatch_uncertainty(&removal.id, "markus", 598)
            .expect("removal uncertainty acknowledged after rollback");
        let replacement_removal = store
            .begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Unmanaged,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                500,
            )
            .expect("rolled-back clock still creates a newer removal workflow");
        assert_eq!(replacement_removal.created_at, 601);
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.host == "gpc0" && job.workflow_kind() == HostWorkflowKind::RemoveHost
                })
                .max_by_key(|job| (job.created_at, job.updated_at, job.id.clone()))
                .map(|job| job.id),
            Some(replacement_removal.id)
        );

        let removal = store
            .begin_removal(
                "athena",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Unmanaged,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: false,
                },
                700,
            )
            .expect("second removal workflow created");
        let pending = store
            .mark_removal_access_revoked(&removal.id, 699)
            .expect("clock rollback does not block successful removal dispatch");
        assert_eq!(pending.updated_at, 700);
        assert_eq!(pending.events.last().map(|event| event.at), Some(700));
    }

    #[test]
    fn relative_persistence_path_with_no_parent_is_durable() {
        let path = PathBuf::from(format!(
            "pharos-relative-action-store-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        assert!(path
            .parent()
            .is_some_and(|parent| parent.as_os_str().is_empty()));
        let job_id = {
            let store = HostActionStore::new(Some(path.clone()));
            store
                .begin_settings_change("hsb8", "markus", 800)
                .expect("relative action store persisted")
                .id
        };
        let reloaded = HostActionStore::new(Some(path.clone()));
        assert!(reloaded.get(&job_id).is_some());
        std::fs::remove_file(path).expect("relative action store removed");
    }

    #[test]
    fn post_commit_directory_sync_failure_keeps_memory_and_disk_in_sync() {
        let path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 900),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let started = store
            .latest_settings_change_for_host("hsb8")
            .expect("committed job retained in memory");
        assert_eq!(
            store.accept_settings_change(&started.id, 901),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let retained = store
            .latest_settings_change_for_host("hsb8")
            .expect("committed accepted job retained in memory");
        let reloaded = HostActionStore::new(Some(path.clone()));
        assert_eq!(reloaded.get(&retained.id), Some(retained));
        std::fs::remove_file(path).expect("post-commit fixture removed");

        let system_path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-system-update-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let system_store = HostActionStore::new(Some(system_path.clone()));
        let system_job = system_store
            .begin_system_update_proposal("athena", "markus", 902, None)
            .expect("final insert survives post-commit rename")
            .into_job();
        assert_eq!(
            system_store.mark_dispatch_submitted(&system_job.id, 903),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let system_retained = system_store
            .get(&system_job.id)
            .expect("committed system update handoff retained");
        assert_eq!(system_retained.state, HostActionState::Succeeded);
        assert_eq!(
            HostActionStore::new(Some(system_path.clone())).get(&system_job.id),
            Some(system_retained)
        );
        std::fs::remove_file(system_path).expect("system update post-commit fixture removed");

        let retired_path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-retired-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let retired = RetiredHost {
            host: "gpc0".to_string(),
            requested_by: "markus".to_string(),
            removal_job_id: "action-remove-host-gpc0-900-1".to_string(),
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            retired_at: 900,
        };
        let store = RetiredHostStore::new(Some(retired_path.clone()));
        assert_eq!(
            store.retire(retired),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        assert!(store.is_retired("gpc0"));
        assert!(RetiredHostStore::new(Some(retired_path.clone())).is_retired("gpc0"));
        assert_eq!(
            store.clear("gpc0"),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        assert!(!store.is_retired("gpc0"));
        assert!(!RetiredHostStore::new(Some(retired_path.clone())).is_retired("gpc0"));
        std::fs::remove_file(retired_path).expect("retired post-commit fixture removed");
    }

    #[test]
    fn concurrent_removal_begin_records_exactly_one_active_workflow() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = Arc::new(HostActionStore::new(None));
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.begin_removal(
                        "gpc0",
                        "markus",
                        HostRemovalPlan {
                            disposition: HostRetirementDisposition::Unmanaged,
                            successor: None,
                            declaration_pending: true,
                            credential_retirement_required: false,
                        },
                        420 + index,
                    )
                })
            })
            .collect();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("removal thread joined"))
            .collect();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(HostActionStoreError::ActiveJob)))
                .count(),
            1
        );
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| job.kind == HostActionKind::RemoveHost && !job.state.is_terminal())
                .count(),
            1
        );
    }

    #[test]
    fn settings_and_removal_uncertainty_acknowledgements_survive_reload() {
        let path = std::env::temp_dir().join(format!(
            "pharos-dispatch-uncertainty-ack-reload-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let (settings_id, removal_id) = {
            let store = HostActionStore::new(Some(path.clone()));
            let settings = store
                .begin_settings_change("hsb8", "markus", 430)
                .expect("settings workflow created");
            store
                .fail_settings_change_uncertain(&settings.id, 431)
                .expect("settings uncertainty persisted");
            store
                .acknowledge_dispatch_uncertainty(&settings.id, "markus", 432)
                .expect("settings acknowledgement persisted");
            let removal = store
                .begin_removal("gpc0", "markus", removal_plan.clone(), 433)
                .expect("removal workflow created");
            store
                .fail_removal_uncertain(&removal.id, 434)
                .expect("removal uncertainty persisted");
            store
                .acknowledge_dispatch_uncertainty(&removal.id, "markus", 435)
                .expect("removal acknowledgement persisted");
            (settings.id, removal.id)
        };

        let reloaded = HostActionStore::new(Some(path.clone()));
        for id in [&settings_id, &removal_id] {
            assert!(reloaded
                .get(id)
                .expect("acknowledged workflow reloaded")
                .has_event(HostActionEventKind::DispatchUncertaintyAcknowledged));
        }
        reloaded
            .begin_settings_change("hsb8", "markus", 436)
            .expect("fresh settings request allowed after reload");
        reloaded
            .begin_removal("gpc0", "markus", removal_plan, 437)
            .expect("fresh removal request allowed after reload");
        let _ = std::fs::remove_file(path);
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

        let jobs = store.list();
        let relevant =
            most_relevant_host_action(&jobs, "hsb8").expect("relevant settings workflow");
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
    fn failed_settings_wins_lifecycle_but_live_proposal_wins_host_action_selector() {
        let jobs = vec![
            lifecycle_job(
                HostWorkflowKind::SettingsChange,
                HostActionState::Failed,
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
        assert_ne!(lifecycle.run_id.as_deref(), Some(legacy.id.as_str()));
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
            .begin_system_update_proposal("hsb8", "markus", 450, None)
            .expect("proposal workflow created")
            .into_job();
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

        assert_eq!(accepted.state, HostActionState::Succeeded);
        assert_eq!(workflow.kind, HostWorkflowKind::SystemUpdateProposal);
        assert_eq!(workflow.status_label, "review handed to nixcfg");
        assert_eq!(workflow.status_level, "clear");
        assert_eq!(workflow.guidance, "The update review was handed to nixcfg. Pharos did not deploy or verify any host change.");
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "validate")
                .expect("validation step")
                .state,
            WorkflowStepState::Skipped
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
        assert_eq!(
            workflow
                .steps
                .iter()
                .find(|step| step.key == "deploy")
                .expect("deployment boundary")
                .detail,
            "This proposal workflow never deploys hosts."
        );
    }

    #[test]
    fn proposal_ladder_does_not_claim_repository_review_after_failed_handoff() {
        for (uncertain, expected) in [
            (true, "Repository receipt is unconfirmed"),
            (false, "Repository handoff was rejected"),
        ] {
            let store = HostActionStore::new(None);
            let job = store
                .begin_system_update_proposal("hsb8", "markus", 460, None)
                .expect("proposal workflow created")
                .into_job();
            let failed = if uncertain {
                store
                    .fail_system_update_proposal_uncertain(&job.id, 461)
                    .expect("uncertain handoff recorded")
            } else {
                store
                    .fail_system_update_proposal(&job.id, 461)
                    .expect("rejected handoff recorded")
            };
            let workflow = failed.summary().workflow;
            let declared = workflow
                .ladder
                .iter()
                .find(|fact| fact.key == "declared")
                .expect("declared ladder fact");
            assert_eq!(declared.fact, expected);
            assert_ne!(declared.fact, "Repository review continues outside Pharos");
        }
    }

    #[test]
    fn apply_claim_is_current_execution_not_completed_evidence() {
        let store = HostActionStore::new(None);
        let job = store
            .create_update_review("hsb8", "markus", 470)
            .expect("job created");
        store.claim("hsb8", 471).expect("claim").expect("lease");
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
                472,
            )
            .expect("review stored");
        store
            .confirm_update(&job.id, "hsb8", "markus", 473)
            .expect("confirmed");
        store.claim("hsb8", 474).expect("claim").expect("lease");

        let workflow = store.get(&job.id).expect("job retained").summary().workflow;
        let executed = workflow
            .ladder
            .iter()
            .find(|fact| fact.key == "executed")
            .expect("executed ladder fact");
        assert_eq!(executed.state, "current");
        assert_eq!(
            executed.fact,
            "Target-local execution started; completion is not recorded"
        );
    }

    #[test]
    fn system_update_proposal_rejects_a_second_fleet_wide_invoke() {
        let store = HostActionStore::new(None);
        let now = system_time_unix();
        let first = store
            .begin_system_update_proposal("hsb8", "markus", now, None)
            .expect("first proposal workflow created")
            .into_job();
        assert!(matches!(
            store.begin_system_update_proposal("gpc0", "markus", now + 1, None),
            Err(HostActionStoreError::ActiveSystemUpdateProposal(_))
        ));
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal)
                .count(),
            1
        );
        assert_eq!(first.id, store.get(&first.id).expect("job retained").id);
    }

    #[test]
    fn system_update_proposal_leaves_host_chip_after_dispatch_acceptance() {
        let store = HostActionStore::new(None);
        let job = store
            .begin_system_update_proposal("hsb8", "markus", 470, None)
            .expect("proposal workflow created")
            .into_job();
        let accepted = store
            .accept_system_update_proposal(&job.id, 471)
            .expect("proposal dispatch accepted");
        let relevant = store
            .most_relevant_for_host("hsb8")
            .expect("relevant proposal workflow");
        assert_eq!(relevant.id, accepted.id);
        assert_eq!(relevant.state, HostActionState::Succeeded);
        assert_eq!(
            relevant.summary().workflow.status_label,
            "review handed to nixcfg"
        );
    }

    #[test]
    fn system_update_proposal_allows_a_new_invoke_after_terminal_success() {
        let store = HostActionStore::new(None);
        let first = store
            .begin_system_update_proposal("hsb8", "markus", 480, None)
            .expect("first proposal workflow created")
            .into_job();
        store
            .accept_system_update_proposal(&first.id, 481)
            .expect("first proposal completed");
        let second = store
            .begin_system_update_proposal("gpc0", "markus", 482, None)
            .expect("second proposal workflow created")
            .into_job();
        assert_ne!(first.id, second.id);
        assert_eq!(second.state, HostActionState::ProposalRequested);
    }

    #[test]
    fn legacy_system_update_proposal_with_dispatch_accepted_migrates_to_succeeded() {
        let path = std::env::temp_dir().join(format!(
            "pharos-legacy-system-update-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-system-update-hsb8-100-1",
            "host": "hsb8",
            "kind": "system_update_proposal",
            "state": "proposal_requested",
            "requested_by": "markus",
            "ticket": "PHAROS-125",
            "created_at": 100,
            "updated_at": 101,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null,
            "events": [
                {
                    "at": 100,
                    "state": "proposal_requested",
                    "source": "operator",
                    "kind": "requested",
                    "actor": "markus"
                },
                {
                    "at": 101,
                    "state": "proposal_requested",
                    "source": "pharos",
                    "kind": "dispatch_accepted"
                }
            ]
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("legacy system update JSON"),
        )
        .expect("legacy system update state written");

        let store = HostActionStore::new(Some(path.clone()));
        let migrated = store
            .get("action-system-update-hsb8-100-1")
            .expect("legacy system update proposal loaded");
        assert_eq!(migrated.state, HostActionState::Succeeded);
        assert_eq!(
            migrated.summary().workflow.status_label,
            "review handed to nixcfg"
        );

        let persisted: Vec<HostActionJob> =
            serde_json::from_slice(&std::fs::read(&path).expect("migrated state readable"))
                .expect("migrated state parses");
        assert_eq!(persisted[0].state, HostActionState::Succeeded);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stalled_system_update_proposal_without_dispatch_confirmation_terminalizes_as_uncertain() {
        let path = std::env::temp_dir().join(format!(
            "pharos-stalled-system-update-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let stale_at = system_time_unix() - SYSTEM_UPDATE_DISPATCH_STALL_SECS - 30;
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-system-update-gpc0-200-1",
            "host": "gpc0",
            "kind": "system_update_proposal",
            "state": "proposal_requested",
            "requested_by": "markus",
            "ticket": "PHAROS-125",
            "created_at": stale_at,
            "updated_at": stale_at,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null,
            "events": [{
                "at": stale_at,
                "state": "proposal_requested",
                "source": "operator",
                "kind": "requested",
                "actor": "markus"
            }]
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("stalled system update JSON"),
        )
        .expect("stalled system update state written");

        let store = HostActionStore::new(Some(path.clone()));
        let reconciled = store
            .get("action-system-update-gpc0-200-1")
            .expect("stalled system update proposal loaded");
        assert_eq!(reconciled.state, HostActionState::Failed);
        assert_eq!(
            reconciled.summary().workflow.status_label,
            "dispatch outcome uncertain"
        );
        assert!(matches!(
            store.begin_system_update_proposal("hsb8", "markus", stale_at + 1, None),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(_))
        ));
        assert!(
            store
                .begin_system_update_proposal(
                    "gpc0",
                    "markus",
                    stale_at + 2,
                    Some("action-system-update-gpc0-200-1"),
                )
                .is_ok(),
            "acknowledged uncertainty clears the fleet-wide gate"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn begin_system_update_migration_persistence_committed_stays_err_with_failed_ack_replacement() {
        let path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-system-update-migrate-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let stale_at = system_time_unix() - SYSTEM_UPDATE_DISPATCH_STALL_SECS - 30;
        let uncertain_id = format!(
            "action-system-update-gpc0-migrate-rollback-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        match store.create_system_update_proposal(
            uncertain_id.clone(),
            "gpc0",
            "markus",
            stale_at.saturating_sub(200),
        ) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain proposal seeded: {error:?}"),
        }
        match store
            .fail_system_update_proposal_uncertain(&uncertain_id, stale_at.saturating_sub(199))
        {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("uncertain failure seeded: {error:?}"),
        }
        let replacement_created_at = stale_at.saturating_sub(50);
        let replacement = store
            .begin_system_update_proposal(
                "gpc0",
                "markus",
                replacement_created_at,
                Some(&uncertain_id),
            )
            .expect("ack replacement seeded")
            .into_job();
        assert_eq!(replacement.retry_of.as_deref(), Some(uncertain_id.as_str()));
        match store.fail_system_update_proposal(&replacement.id, replacement_created_at + 1) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("replacement terminalized: {error:?}"),
        }
        let stalled_id = format!(
            "action-system-update-gpc0-stalled-migrate-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        match store.create_system_update_proposal(stalled_id.clone(), "gpc0", "markus", stale_at) {
            Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
            Err(error) => panic!("stalled proposal seeded: {error:?}"),
        }
        let stalled = store
            .get(&stalled_id)
            .expect("stalled proposal retained in memory");
        assert_eq!(stalled.state, HostActionState::ProposalRequested);
        let rolled_back_now = replacement_created_at.saturating_sub(10);
        assert!(
            rolled_back_now < replacement.created_at,
            "test models wall-clock rollback below the prior replacement timestamp"
        );
        assert_eq!(
            store.begin_system_update_proposal(
                "gpc0",
                "markus",
                rolled_back_now,
                Some(&uncertain_id),
            ),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let retained = store
            .get(&replacement.id)
            .expect("failed replacement retained");
        assert_eq!(retained.state, HostActionState::Failed);
        assert!(!system_update_dispatch_handed_off(&retained));
        assert!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal
                        && job.state == HostActionState::ProposalRequested
                })
                .count()
                <= 1,
            "migration stays in memory without authorizing a fresh proposal"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stale_system_update_proposal_surfaces_uncertainty_without_redispatching() {
        let store = HostActionStore::new(None);
        let stale_at = system_time_unix() - SYSTEM_UPDATE_DISPATCH_STALL_SECS - 30;
        let stalled = store
            .create_system_update_proposal(
                "action-system-update-gpc0-900-1".to_string(),
                "gpc0",
                "markus",
                stale_at,
            )
            .expect("stalled proposal recorded");
        assert!(matches!(
            store.begin_system_update_proposal("hsb8", "markus", stale_at + 1, None),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job)) if job.id == stalled.id
        ));
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| job.workflow_kind() == HostWorkflowKind::SystemUpdateProposal)
                .count(),
            1
        );
        store
            .begin_system_update_proposal("gpc0", "markus", stale_at + 2, Some(&stalled.id))
            .expect("replacement proposal after acknowledgement");
    }

    #[test]
    fn system_update_ack_replay_returns_same_replacement_without_duplicate_link() {
        let store = HostActionStore::new(None);
        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-hsb8-ack-1".to_string(),
                "hsb8",
                "markus",
                700,
            )
            .expect("uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain.id, 701)
            .expect("uncertain failure recorded");
        let replacement = store
            .begin_system_update_proposal("hsb8", "markus", 600, Some(&uncertain.id))
            .expect("replacement survives a rolled-back clock");
        assert!(replacement.created());
        let replacement = replacement.into_job();
        assert_eq!(replacement.created_at, 702);
        assert_eq!(replacement.retry_of.as_deref(), Some(uncertain.id.as_str()));
        let accepted = store
            .accept_system_update_proposal(&replacement.id, 703)
            .expect("handoff recorded");
        assert_eq!(accepted.state, HostActionState::Succeeded);
        assert!(system_update_dispatch_handed_off(&accepted));

        let replay = store
            .begin_system_update_proposal("hsb8", "markus", 704, Some(&uncertain.id))
            .expect("idempotent replay");
        assert!(!replay.created());
        assert_eq!(replay.job().id, replacement.id);
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.kind == HostActionKind::SystemUpdateProposal
                        && job.retry_of.as_deref() == Some(uncertain.id.as_str())
                })
                .count(),
            1
        );
    }

    #[test]
    fn concurrent_ack_headers_create_one_replacement_link() {
        use std::sync::{Arc, Barrier};
        use std::thread;

        let store = HostActionStore::new(None);
        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-gpc0-ack-1".to_string(),
                "gpc0",
                "markus",
                710,
            )
            .expect("uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain.id, 711)
            .expect("uncertain failure recorded");

        let store = Arc::new(store);
        let barrier = Arc::new(Barrier::new(2));
        let prior_id = uncertain.id.clone();
        let handles: Vec<_> = (0..2)
            .map(|index| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                let prior_id = prior_id.clone();
                thread::spawn(move || {
                    barrier.wait();
                    store.begin_system_update_proposal(
                        "gpc0",
                        "markus",
                        712 + index,
                        Some(&prior_id),
                    )
                })
            })
            .collect();
        let results: Vec<Result<SystemUpdateProposalBegin, HostActionStoreError>> = handles
            .into_iter()
            .map(|handle| handle.join().expect("thread joined"))
            .collect();
        assert!(results.iter().all(|result| result.is_ok()));
        let begins: Vec<SystemUpdateProposalBegin> = results
            .into_iter()
            .map(|result| result.expect("replacement created"))
            .collect();
        assert_eq!(begins[0].job().id, begins[1].job().id);
        assert_eq!(begins.iter().filter(|begin| begin.created()).count(), 1);
        assert_eq!(begins.iter().filter(|begin| !begin.created()).count(), 1);
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.kind == HostActionKind::SystemUpdateProposal
                        && job.retry_of.as_deref() == Some(prior_id.as_str())
                })
                .count(),
            1
        );
    }

    #[test]
    fn multiple_uncertain_jobs_drain_sequentially_without_ack_rollback() {
        let store = HostActionStore::new(None);
        let uncertain_gpc0 = store
            .create_system_update_proposal(
                "action-system-update-gpc0-multi-1".to_string(),
                "gpc0",
                "markus",
                740,
            )
            .expect("gpc0 uncertain proposal created");
        let uncertain_hsb8 = store
            .create_system_update_proposal(
                "action-system-update-hsb8-multi-1".to_string(),
                "hsb8",
                "markus",
                741,
            )
            .expect("hsb8 uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain_gpc0.id, 742)
            .expect("gpc0 uncertain failure recorded");
        store
            .fail_system_update_proposal_uncertain(&uncertain_hsb8.id, 743)
            .expect("hsb8 uncertain failure recorded");

        assert!(matches!(
            store.begin_system_update_proposal("gpc0", "markus", 744, Some(&uncertain_gpc0.id)),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                if job.id == uncertain_hsb8.id
        ));
        let gpc0_after_first_ack = store.get(&uncertain_gpc0.id).expect("gpc0 prior retained");
        assert!(!system_update_uncertainty_requires_acknowledgement(
            &gpc0_after_first_ack
        ));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &store.get(&uncertain_hsb8.id).expect("hsb8 prior retained")
        ));

        let begin = store
            .begin_system_update_proposal("hsb8", "markus", 745, Some(&uncertain_hsb8.id))
            .expect("replacement after finite drain");
        assert!(begin.created());
        let replacement = begin.into_job();
        assert_eq!(
            replacement.retry_of.as_deref(),
            Some(uncertain_hsb8.id.as_str())
        );
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.kind == HostActionKind::SystemUpdateProposal
                        && job.state == HostActionState::ProposalRequested
                        && job.retry_of.is_some()
                })
                .count(),
            1
        );
    }

    #[test]
    fn replaying_a_consumed_partial_ack_returns_the_remaining_uncertainty() {
        let store = HostActionStore::new(None);
        let first = store
            .create_system_update_proposal(
                "action-system-update-gpc0-partial-lost-1".to_string(),
                "gpc0",
                "markus",
                780,
            )
            .expect("first uncertainty created");
        let remaining = store
            .create_system_update_proposal(
                "action-system-update-hsb8-partial-lost-1".to_string(),
                "hsb8",
                "markus",
                781,
            )
            .expect("remaining uncertainty created");
        store
            .fail_system_update_proposal_uncertain(&first.id, 782)
            .expect("first uncertainty persisted");
        store
            .fail_system_update_proposal_uncertain(&remaining.id, 783)
            .expect("remaining uncertainty persisted");

        for now in [784, 785] {
            let result = store.begin_system_update_proposal("gpc0", "markus", now, Some(&first.id));
            assert!(matches!(
                result,
                Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                    if job.id == remaining.id
            ));
        }
        assert!(store
            .get(&first.id)
            .expect("first uncertainty retained")
            .has_event(HostActionEventKind::DispatchUncertaintyAcknowledged));
    }

    #[test]
    fn partial_ack_replay_after_other_replacement_consumes_ack_without_new_replacement() {
        let store = HostActionStore::new(None);
        let uncertain_gpc0 = store
            .create_system_update_proposal(
                "action-system-update-gpc0-partial-replay-1".to_string(),
                "gpc0",
                "markus",
                790,
            )
            .expect("gpc0 uncertain proposal created");
        let uncertain_hsb8 = store
            .create_system_update_proposal(
                "action-system-update-hsb8-partial-replay-1".to_string(),
                "hsb8",
                "markus",
                791,
            )
            .expect("hsb8 uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain_gpc0.id, 792)
            .expect("gpc0 uncertain failure recorded");
        store
            .fail_system_update_proposal_uncertain(&uncertain_hsb8.id, 793)
            .expect("hsb8 uncertain failure recorded");

        assert!(matches!(
            store.begin_system_update_proposal("gpc0", "markus", 794, Some(&uncertain_gpc0.id)),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                if job.id == uncertain_hsb8.id
        ));

        let begin = store
            .begin_system_update_proposal("hsb8", "markus", 795, Some(&uncertain_hsb8.id))
            .expect("hsb8 replacement created");
        assert!(begin.created());
        let replacement = begin.into_job();
        store
            .accept_system_update_proposal(&replacement.id, 796)
            .expect("hsb8 replacement accepted");

        let replay = store
            .begin_system_update_proposal("gpc0", "markus", 797, Some(&uncertain_gpc0.id))
            .expect("gpc0 partial ack replay consumed");
        assert!(!replay.created());
        assert_eq!(replay.job().id, uncertain_gpc0.id);
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| {
                    job.kind == HostActionKind::SystemUpdateProposal
                        && job.retry_of.as_deref() == Some(uncertain_gpc0.id.as_str())
                })
                .count(),
            0
        );

        let replay_again = store
            .begin_system_update_proposal("gpc0", "markus", 798, Some(&uncertain_gpc0.id))
            .expect("gpc0 replay remains idempotent");
        assert!(!replay_again.created());
        assert_eq!(replay_again.job().id, uncertain_gpc0.id);
    }

    #[test]
    fn active_proposal_rejection_rolls_back_uncertainty_ack_in_memory_and_on_disk() {
        let path = std::env::temp_dir().join(format!(
            "pharos-active-uncertain-rollback-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let base = system_time_unix();
        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-gpc0-active-uncertain-1".to_string(),
                "gpc0",
                "markus",
                base,
            )
            .expect("uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain.id, base + 1)
            .expect("uncertain outcome recorded");
        let active = store
            .create_system_update_proposal(
                "action-system-update-hsb8-active-uncertain-1".to_string(),
                "hsb8",
                "markus",
                base + 2,
            )
            .expect("active proposal created");

        let result =
            store.begin_system_update_proposal("gpc0", "markus", base + 3, Some(&uncertain.id));
        assert!(
            matches!(
                &result,
                Err(HostActionStoreError::ActiveSystemUpdateProposal(job)) if job.id == active.id
            ),
            "unexpected acknowledgement result: {result:?}"
        );
        let in_memory = store.get(&uncertain.id).expect("uncertain job retained");
        assert!(system_update_uncertainty_requires_acknowledgement(
            &in_memory
        ));

        let reloaded = HostActionStore::new(Some(path.clone()));
        let on_disk = reloaded.get(&uncertain.id).expect("uncertain job reloaded");
        assert!(system_update_uncertainty_requires_acknowledgement(&on_disk));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn stalled_proposal_uncertain_state_survives_cold_reload_without_begin() {
        let path = std::env::temp_dir().join(format!(
            "pharos-stalled-reload-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let stale_at = system_time_unix() - SYSTEM_UPDATE_DISPATCH_STALL_SECS - 30;
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-system-update-gpc0-stalled-reload-1",
            "host": "gpc0",
            "kind": "system_update_proposal",
            "state": "proposal_requested",
            "requested_by": "markus",
            "ticket": "PHAROS-125",
            "created_at": stale_at,
            "updated_at": stale_at,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null,
            "events": [{
                "at": stale_at,
                "state": "proposal_requested",
                "source": "operator",
                "kind": "requested",
                "actor": "markus"
            }]
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("stalled proposal JSON"),
        )
        .expect("stalled proposal state written");

        HostActionStore::new(Some(path.clone()));

        let reloaded = HostActionStore::new(Some(path.clone()));
        let job = reloaded
            .get("action-system-update-gpc0-stalled-reload-1")
            .expect("stalled proposal reloaded");
        assert_eq!(job.state, HostActionState::Failed);
        assert_eq!(
            job.summary().workflow.status_label,
            "dispatch outcome uncertain"
        );
        assert!(system_update_uncertainty_requires_acknowledgement(&job));

        let persisted: Vec<HostActionJob> =
            serde_json::from_slice(&std::fs::read(&path).expect("persisted actions readable"))
                .expect("persisted actions parse");
        assert_eq!(persisted[0].state, HostActionState::Failed);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn reloaded_uncertain_jobs_drain_to_one_replacement() {
        let path = std::env::temp_dir().join(format!(
            "pharos-reloaded-uncertain-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let stale_at = system_time_unix() - SYSTEM_UPDATE_DISPATCH_STALL_SECS - 30;
        let document = serde_json::json!([
            {
                "schema": ACTION_SCHEMA,
                "version": ACTION_VERSION,
                "id": "action-system-update-gpc0-reload-1",
                "host": "gpc0",
                "kind": "system_update_proposal",
                "state": "proposal_requested",
                "requested_by": "markus",
                "ticket": "PHAROS-125",
                "created_at": stale_at,
                "updated_at": stale_at,
                "confirmed_at": null,
                "plan": null,
                "result": null,
                "lease_phase": null,
                "lease_until": null,
                "events": [{
                    "at": stale_at,
                    "state": "proposal_requested",
                    "source": "operator",
                    "kind": "requested",
                    "actor": "markus"
                }]
            },
            {
                "schema": ACTION_SCHEMA,
                "version": ACTION_VERSION,
                "id": "action-system-update-athena-reload-1",
                "host": "athena",
                "kind": "system_update_proposal",
                "state": "proposal_requested",
                "requested_by": "markus",
                "ticket": "PHAROS-125",
                "created_at": stale_at - 1,
                "updated_at": stale_at - 1,
                "confirmed_at": null,
                "plan": null,
                "result": null,
                "lease_phase": null,
                "lease_until": null,
                "events": [{
                    "at": stale_at - 1,
                    "state": "proposal_requested",
                    "source": "operator",
                    "kind": "requested",
                    "actor": "markus"
                }]
            }
        ]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("reloaded uncertain JSON"),
        )
        .expect("reloaded uncertain state written");

        let store = HostActionStore::new(Some(path.clone()));
        assert!(matches!(
            store.begin_system_update_proposal("gpc0", "markus", stale_at + 1, None),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(_))
        ));
        assert!(matches!(
            store.begin_system_update_proposal(
                "gpc0",
                "markus",
                stale_at + 2,
                Some("action-system-update-gpc0-reload-1"),
            ),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                if job.id == "action-system-update-athena-reload-1"
        ));
        let gpc0 = store
            .get("action-system-update-gpc0-reload-1")
            .expect("gpc0 reloaded");
        assert!(!system_update_uncertainty_requires_acknowledgement(&gpc0));

        let begin = store
            .begin_system_update_proposal(
                "athena",
                "markus",
                stale_at + 3,
                Some("action-system-update-athena-reload-1"),
            )
            .expect("replacement after reload drain");
        assert!(begin.created());
        let replacement = begin.into_job();
        assert_eq!(
            replacement.retry_of.as_deref(),
            Some("action-system-update-athena-reload-1")
        );
        let replay = store
            .begin_system_update_proposal(
                "athena",
                "markus",
                stale_at + 4,
                Some("action-system-update-athena-reload-1"),
            )
            .expect("idempotent replay");
        assert!(!replay.created());
        assert_eq!(replay.job().id, replacement.id);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cross_host_acknowledgement_rejected_without_mutation() {
        let store = HostActionStore::new(None);
        let uncertain_gpc0 = store
            .create_system_update_proposal(
                "action-system-update-gpc0-cross-1".to_string(),
                "gpc0",
                "markus",
                750,
            )
            .expect("gpc0 uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain_gpc0.id, 751)
            .expect("gpc0 uncertain failure recorded");
        let replacement = store
            .begin_system_update_proposal("gpc0", "markus", 752, Some(&uncertain_gpc0.id))
            .expect("gpc0 replacement created")
            .into_job();
        store
            .accept_system_update_proposal(&replacement.id, 753)
            .expect("gpc0 replacement accepted");

        assert_eq!(
            store.begin_system_update_proposal("hsb8", "markus", 754, Some(&uncertain_gpc0.id)),
            Err(HostActionStoreError::WrongHost)
        );
        let prior = store.get(&uncertain_gpc0.id).expect("gpc0 prior retained");
        assert!(prior.has_event(HostActionEventKind::DispatchUncertaintyAcknowledged));
        let retained_replacement = store.get(&replacement.id).expect("replacement retained");
        assert_eq!(retained_replacement.host, "gpc0");
        assert_eq!(retained_replacement.state, HostActionState::Succeeded);
    }

    #[test]
    fn system_update_ack_persistence_failure_restores_prior_and_gate() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-system-update-ack-persist-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create persistence dir");
        let actions_path = dir.join("actions.json");
        let store = HostActionStore::new(Some(actions_path.clone()));
        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-hsb8-ack-persist-1".to_string(),
                "hsb8",
                "markus",
                720,
            )
            .expect("uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain.id, 721)
            .expect("uncertain failure recorded");
        std::fs::remove_file(&actions_path).expect("remove persisted actions file");
        std::fs::create_dir(&actions_path).expect("turn actions path into a directory");

        assert_eq!(
            store.begin_system_update_proposal("hsb8", "markus", 722, Some(&uncertain.id)),
            Err(HostActionStoreError::Persistence)
        );
        let prior = store.get(&uncertain.id).expect("prior job retained");
        assert!(system_update_uncertainty_requires_acknowledgement(&prior));
        assert!(matches!(
            store.begin_system_update_proposal("hsb8", "markus", 723, None),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(_))
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_ack_persistence_failure_leaves_prior_unacknowledged_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-system-update-partial-ack-fail-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create persistence dir");
        let actions_path = dir.join("actions.json");
        let store = HostActionStore::new(Some(actions_path.clone()));
        let uncertain_gpc0 = store
            .create_system_update_proposal(
                "action-system-update-gpc0-partial-fail-1".to_string(),
                "gpc0",
                "markus",
                760,
            )
            .expect("gpc0 uncertain proposal created");
        let uncertain_hsb8 = store
            .create_system_update_proposal(
                "action-system-update-hsb8-partial-fail-1".to_string(),
                "hsb8",
                "markus",
                761,
            )
            .expect("hsb8 uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain_gpc0.id, 762)
            .expect("gpc0 uncertain failure recorded");
        store
            .fail_system_update_proposal_uncertain(&uncertain_hsb8.id, 763)
            .expect("hsb8 uncertain failure recorded");
        let disk_before = std::fs::read(&actions_path).expect("read persisted actions");
        std::fs::remove_file(&actions_path).expect("remove persisted actions file");
        std::fs::create_dir(&actions_path).expect("turn actions path into a directory");

        assert_eq!(
            store.begin_system_update_proposal("gpc0", "markus", 764, Some(&uncertain_gpc0.id)),
            Err(HostActionStoreError::Persistence)
        );
        assert!(system_update_uncertainty_requires_acknowledgement(
            &store.get(&uncertain_gpc0.id).expect("gpc0 prior retained")
        ));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &store.get(&uncertain_hsb8.id).expect("hsb8 prior retained")
        ));
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| job.retry_of.is_some())
                .count(),
            0
        );

        std::fs::remove_dir(&actions_path).expect("remove blocker directory");
        std::fs::write(&actions_path, &disk_before).expect("restore pre-failure disk snapshot");
        let reloaded = HostActionStore::new(Some(actions_path.clone()));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &reloaded.get(&uncertain_gpc0.id).expect("gpc0 reloaded")
        ));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &reloaded.get(&uncertain_hsb8.id).expect("hsb8 reloaded")
        ));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn final_ack_replacement_persist_failure_leaves_no_ack_or_replacement_on_disk() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-system-update-final-ack-fail-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create persistence dir");
        let actions_path = dir.join("actions.json");
        let store = HostActionStore::new(Some(actions_path.clone()));
        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-hsb8-final-fail-1".to_string(),
                "hsb8",
                "markus",
                770,
            )
            .expect("uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain.id, 771)
            .expect("uncertain failure recorded");
        let disk_before = std::fs::read(&actions_path).expect("read persisted actions");
        std::fs::remove_file(&actions_path).expect("remove persisted actions file");
        std::fs::create_dir(&actions_path).expect("turn actions path into a directory");

        assert_eq!(
            store.begin_system_update_proposal("hsb8", "markus", 772, Some(&uncertain.id)),
            Err(HostActionStoreError::Persistence)
        );
        assert!(system_update_uncertainty_requires_acknowledgement(
            &store.get(&uncertain.id).expect("prior retained in memory")
        ));
        assert_eq!(
            store
                .list()
                .into_iter()
                .filter(|job| job.retry_of.as_deref() == Some(uncertain.id.as_str()))
                .count(),
            0
        );

        std::fs::remove_dir(&actions_path).expect("remove blocker directory");
        std::fs::write(&actions_path, &disk_before).expect("restore pre-failure disk snapshot");
        let reloaded = HostActionStore::new(Some(actions_path.clone()));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &reloaded.get(&uncertain.id).expect("prior reloaded")
        ));
        assert_eq!(
            reloaded
                .list()
                .into_iter()
                .filter(|job| job.retry_of.as_deref() == Some(uncertain.id.as_str()))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn partial_ack_persisted_and_reloaded_before_final_replacement() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-system-update-partial-reload-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("create persistence dir");
        let actions_path = dir.join("actions.json");
        let store = HostActionStore::new(Some(actions_path.clone()));
        let uncertain_gpc0 = store
            .create_system_update_proposal(
                "action-system-update-gpc0-partial-reload-1".to_string(),
                "gpc0",
                "markus",
                780,
            )
            .expect("gpc0 uncertain proposal created");
        let uncertain_hsb8 = store
            .create_system_update_proposal(
                "action-system-update-hsb8-partial-reload-1".to_string(),
                "hsb8",
                "markus",
                781,
            )
            .expect("hsb8 uncertain proposal created");
        store
            .fail_system_update_proposal_uncertain(&uncertain_gpc0.id, 782)
            .expect("gpc0 uncertain failure recorded");
        store
            .fail_system_update_proposal_uncertain(&uncertain_hsb8.id, 783)
            .expect("hsb8 uncertain failure recorded");

        assert!(matches!(
            store.begin_system_update_proposal("gpc0", "markus", 784, Some(&uncertain_gpc0.id)),
            Err(HostActionStoreError::UncertaintyRequiresAcknowledgement(job))
                if job.id == uncertain_hsb8.id
        ));

        let reloaded = HostActionStore::new(Some(actions_path.clone()));
        let gpc0_reloaded = reloaded.get(&uncertain_gpc0.id).expect("gpc0 reloaded");
        assert!(!system_update_uncertainty_requires_acknowledgement(
            &gpc0_reloaded
        ));
        assert!(system_update_uncertainty_requires_acknowledgement(
            &reloaded.get(&uncertain_hsb8.id).expect("hsb8 reloaded")
        ));
        assert_eq!(
            reloaded
                .list()
                .into_iter()
                .filter(|job| job.retry_of.is_some())
                .count(),
            0
        );

        let begin = reloaded
            .begin_system_update_proposal("hsb8", "markus", 785, Some(&uncertain_hsb8.id))
            .expect("final replacement after reload");
        assert!(begin.created());
        let replacement = begin.into_job();
        assert_eq!(
            replacement.retry_of.as_deref(),
            Some(uncertain_hsb8.id.as_str())
        );

        let reloaded_again = HostActionStore::new(Some(actions_path.clone()));
        assert!(!system_update_uncertainty_requires_acknowledgement(
            &reloaded_again
                .get(&uncertain_gpc0.id)
                .expect("gpc0 durable ack")
        ));
        assert!(!system_update_uncertainty_requires_acknowledgement(
            &reloaded_again
                .get(&uncertain_hsb8.id)
                .expect("hsb8 durable ack")
        ));
        assert_eq!(
            reloaded_again
                .list()
                .into_iter()
                .filter(|job| job.retry_of.as_deref() == Some(uncertain_hsb8.id.as_str()))
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn system_update_rejected_and_uncertain_evidence_differ() {
        let store = HostActionStore::new(None);
        let rejected = store
            .create_system_update_proposal(
                "action-system-update-gpc0-ev-1".to_string(),
                "gpc0",
                "markus",
                730,
            )
            .expect("rejected proposal created");
        let rejected_failed = store
            .fail_system_update_proposal(&rejected.id, 731)
            .expect("known rejection recorded");
        let rejected_summary = rejected_failed.summary();
        let rejected_dispatch = rejected_summary
            .workflow
            .evidence
            .iter()
            .find(|item| item.label == "Repository dispatch")
            .expect("rejected dispatch evidence");
        assert_eq!(rejected_dispatch.value, "stopped");

        let uncertain = store
            .create_system_update_proposal(
                "action-system-update-athena-ev-1".to_string(),
                "athena",
                "markus",
                732,
            )
            .expect("uncertain proposal created");
        let uncertain_failed = store
            .fail_system_update_proposal_uncertain(&uncertain.id, 733)
            .expect("uncertain failure recorded");
        let uncertain_summary = uncertain_failed.summary();
        let uncertain_dispatch = uncertain_summary
            .workflow
            .evidence
            .iter()
            .find(|item| item.label == "Repository dispatch")
            .expect("uncertain dispatch evidence");
        assert_eq!(uncertain_dispatch.value, "outcome uncertain");
    }

    #[test]
    fn future_dated_system_update_proposal_loads_and_validates() {
        let path = std::env::temp_dir().join(format!(
            "pharos-future-system-update-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let future_at = system_time_unix() + 3600;
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-system-update-hsb8-future-1",
            "host": "hsb8",
            "kind": "system_update_proposal",
            "state": "proposal_requested",
            "requested_by": "markus",
            "ticket": "PHAROS-125",
            "created_at": future_at,
            "updated_at": future_at,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null,
            "events": [{
                "at": future_at,
                "state": "proposal_requested",
                "source": "operator",
                "kind": "requested",
                "actor": "markus"
            }]
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("future system update JSON"),
        )
        .expect("future system update state written");

        let store = HostActionStore::new(Some(path.clone()));
        let job = store
            .get("action-system-update-hsb8-future-1")
            .expect("future-dated proposal loaded");
        assert_eq!(job.state, HostActionState::ProposalRequested);
        assert_eq!(job.updated_at, future_at);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn submitted_system_update_proposal_without_accept_migrates_to_succeeded() {
        let path = std::env::temp_dir().join(format!(
            "pharos-submitted-system-update-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let document = serde_json::json!([{
            "schema": ACTION_SCHEMA,
            "version": ACTION_VERSION,
            "id": "action-system-update-hsb8-300-1",
            "host": "hsb8",
            "kind": "system_update_proposal",
            "state": "proposal_requested",
            "requested_by": "markus",
            "ticket": "PHAROS-125",
            "created_at": 300,
            "updated_at": 301,
            "confirmed_at": null,
            "plan": null,
            "result": null,
            "lease_phase": null,
            "lease_until": null,
            "events": [
                {
                    "at": 300,
                    "state": "proposal_requested",
                    "source": "operator",
                    "kind": "requested",
                    "actor": "markus"
                },
                {
                    "at": 301,
                    "state": "proposal_requested",
                    "source": "pharos",
                    "kind": "dispatch_submitted"
                }
            ]
        }]);
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&document).expect("submitted system update JSON"),
        )
        .expect("submitted system update state written");

        let store = HostActionStore::new(Some(path.clone()));
        let migrated = store
            .get("action-system-update-hsb8-300-1")
            .expect("submitted system update proposal loaded");
        assert_eq!(migrated.state, HostActionState::Succeeded);
        assert!(migrated
            .events
            .iter()
            .any(|event| event.kind == HostActionEventKind::DispatchAccepted));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn mark_dispatch_submitted_terminalizes_system_update_atomically() {
        let path = std::env::temp_dir().join(format!(
            "pharos-submitted-recovery-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let job = store
            .begin_system_update_proposal("hsb8", "markus", 510, None)
            .expect("proposal workflow created")
            .into_job();
        let submitted = store
            .mark_dispatch_submitted(&job.id, 511)
            .expect("dispatch submission recorded");
        assert_eq!(submitted.state, HostActionState::Succeeded);

        let recovered = HostActionStore::new(Some(path.clone()));
        let migrated = recovered
            .get(&job.id)
            .expect("submitted proposal recovered");
        assert_eq!(migrated.state, HostActionState::Succeeded);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn accepted_settings_and_removal_handoffs_block_redispatch_after_reload() {
        let path = std::env::temp_dir().join(format!(
            "pharos-accepted-handoffs-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let settings = store
            .begin_settings_change("hsb8", "markus", 520)
            .expect("settings workflow created");
        let requested = HostPreferences {
            accent: Some("#1f7fb5".to_string()),
            ..HostPreferences::default()
        };
        store
            .record_settings_request(&settings.id, &requested, 521)
            .expect("settings recovery payload recorded");
        let settings = store
            .mark_dispatch_submitted(&settings.id, 522)
            .expect("settings dispatch submission recorded");
        let settings_summary = settings.summary().workflow;
        assert_eq!(settings_summary.status_label, "dispatch accepted");
        assert!(settings_summary.guidance.contains("do not resend"));
        assert_eq!(
            settings_summary
                .primary_action
                .as_ref()
                .map(|action| action.kind),
            Some(HostWorkflowActionKind::Recover)
        );
        assert_eq!(
            settings_summary
                .evidence
                .iter()
                .find(|item| item.label == "Delivery")
                .expect("settings delivery evidence")
                .value,
            "accepted"
        );

        let removal = store
            .begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Destroyed,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: true,
                },
                523,
            )
            .expect("removal workflow created");
        let removal = store
            .mark_dispatch_submitted(&removal.id, 524)
            .expect("removal dispatch submission recorded");
        let removal_summary = removal.summary().workflow;
        assert_eq!(removal_summary.status_label, "dispatch accepted");
        assert!(removal_summary.guidance.contains("do not resend"));
        assert_eq!(
            removal_summary
                .primary_action
                .as_ref()
                .map(|action| action.kind),
            Some(HostWorkflowActionKind::Recover)
        );
        assert_eq!(
            removal_summary
                .evidence
                .iter()
                .find(|item| item.label == "Repository dispatch")
                .expect("removal dispatch evidence")
                .value,
            "accepted"
        );

        drop(store);
        let reloaded = HostActionStore::new(Some(path.clone()));
        assert!(matches!(
            reloaded.begin_settings_change("hsb8", "markus", 525),
            Err(HostActionStoreError::ActiveJob)
        ));
        assert!(matches!(
            reloaded.begin_removal(
                "gpc0",
                "markus",
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Destroyed,
                    successor: None,
                    declaration_pending: true,
                    credential_retirement_required: true,
                },
                526,
            ),
            Err(HostActionStoreError::ActiveJob)
        ));
        assert!(reloaded
            .get(&settings.id)
            .expect("settings handoff reloaded")
            .summary()
            .workflow
            .guidance
            .contains("do not resend"));
        assert!(reloaded
            .get(&removal.id)
            .expect("removal handoff reloaded")
            .summary()
            .workflow
            .guidance
            .contains("do not resend"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn orphaned_settings_and_removal_dispatches_reload_as_acknowledgeable_uncertainty() {
        let path = std::env::temp_dir().join(format!(
            "pharos-orphaned-dispatches-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let settings = store
            .begin_settings_change("hsb8", "markus", 530)
            .expect("settings workflow created");
        store
            .record_settings_request(
                &settings.id,
                &HostPreferences {
                    accent: Some("#48b8a8".to_string()),
                    ..HostPreferences::default()
                },
                531,
            )
            .expect("settings payload persisted before dispatch");
        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Destroyed,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: true,
        };
        let removal = store
            .begin_removal("gpc0", "markus", removal_plan.clone(), 532)
            .expect("removal workflow created");
        drop(store);

        let reloaded = HostActionStore::new(Some(path.clone()));
        for id in [&settings.id, &removal.id] {
            let job = reloaded.get(id).expect("orphaned handoff reloaded");
            assert_eq!(job.state, HostActionState::Failed);
            assert_eq!(
                job.summary()
                    .workflow
                    .primary_action
                    .as_ref()
                    .map(|action| action.kind),
                Some(HostWorkflowActionKind::Acknowledge)
            );
            assert_eq!(
                job.summary().workflow.status_label,
                "dispatch outcome uncertain"
            );
        }
        reloaded
            .acknowledge_dispatch_uncertainty(&settings.id, "markus", system_time_unix())
            .expect("settings uncertainty acknowledged");
        reloaded
            .acknowledge_dispatch_uncertainty(&removal.id, "markus", system_time_unix())
            .expect("removal uncertainty acknowledged");
        reloaded
            .begin_settings_change("hsb8", "markus", system_time_unix())
            .expect("new settings workflow allowed after verification");
        reloaded
            .begin_removal("gpc0", "markus", removal_plan, system_time_unix())
            .expect("new removal workflow allowed after verification");
        let _ = std::fs::remove_file(path);
    }

    fn dispatch_submitted_event_count(job: &HostActionJob) -> usize {
        job.events
            .iter()
            .filter(|event| event.kind == HostActionEventKind::DispatchSubmitted)
            .count()
    }

    fn uncertainty_acknowledgement_action(job: &HostActionJob) -> bool {
        job.summary()
            .workflow
            .primary_action
            .as_ref()
            .is_some_and(|action| action.kind == HostWorkflowActionKind::Acknowledge)
    }

    #[cfg(unix)]
    fn set_dir_read_only(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o555))
            .expect("directory made read-only");
    }

    #[cfg(unix)]
    fn set_dir_writable(dir: &Path) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o755))
            .expect("directory restored writable");
    }

    #[test]
    #[cfg(unix)]
    fn accepted_settings_dispatch_checkpoint_failure_recovers_in_process_without_redispatch() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-settings-checkpoint-recovery-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("checkpoint recovery directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let settings = store
            .begin_settings_change("hsb8", "markus", 600)
            .expect("settings workflow created");
        store
            .record_settings_request(
                &settings.id,
                &HostPreferences {
                    accent: Some("#48b8a8".to_string()),
                    ..HostPreferences::default()
                },
                601,
            )
            .expect("settings payload persisted before dispatch");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&settings.id, 602),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_settings_change_uncertain(&settings.id, 603),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        let recovered = store
            .get(&settings.id)
            .expect("settings workflow reconciled after storage recovery");
        assert!(uncertainty_acknowledgement_action(&recovered));
        assert_eq!(dispatch_submitted_event_count(&recovered), 0);
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 604),
            Err(HostActionStoreError::ActiveJob)
        );
        let reloaded = HostActionStore::new(Some(path.clone()));
        let durable = reloaded
            .get(&settings.id)
            .expect("uncertain settings workflow durable after recovery");
        assert!(uncertainty_acknowledgement_action(&durable));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn accepted_removal_dispatch_checkpoint_failure_recovers_in_process_without_redispatch() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-removal-checkpoint-recovery-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("checkpoint recovery directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let removal = store
            .begin_removal("gpc0", "markus", removal_plan.clone(), 610)
            .expect("removal workflow created");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&removal.id, 611),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_removal_uncertain(&removal.id, 612),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        let recovered = store
            .get(&removal.id)
            .expect("removal workflow reconciled after storage recovery");
        assert!(uncertainty_acknowledgement_action(&recovered));
        assert_eq!(dispatch_submitted_event_count(&recovered), 0);
        assert_eq!(
            store.begin_removal("gpc0", "markus", removal_plan, 613),
            Err(HostActionStoreError::ActiveJob)
        );
        let reloaded = HostActionStore::new(Some(path.clone()));
        let durable = reloaded
            .get(&removal.id)
            .expect("uncertain removal workflow durable after recovery");
        assert!(uncertainty_acknowledgement_action(&durable));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn settings_begin_persistence_committed_retains_host_lookup_for_handler_recovery() {
        let path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-settings-begin-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 620),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let active = store
            .latest_settings_change_for_host("hsb8")
            .expect("committed settings workflow retained in memory");
        assert_eq!(active.state, HostActionState::ProposalRequested);
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 621),
            Err(HostActionStoreError::ActiveJob)
        );
        let reloaded = HostActionStore::new(Some(path.clone()));
        assert_eq!(
            reloaded.latest_settings_change_for_host("hsb8"),
            Some(active)
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    #[cfg(unix)]
    fn dispatch_checkpoint_reconciliation_is_idempotent_without_redispatch() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-dispatch-reconcile-idempotent-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("reconciliation directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let settings = store
            .begin_settings_change("hsb8", "markus", 630)
            .expect("settings workflow created");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&settings.id, 631),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_settings_change_uncertain(&settings.id, 632),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        let store = std::sync::Arc::new(store);
        let settings_id = settings.id.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(4));
        let handles: Vec<_> = (0..3)
            .map(|_| {
                let store = std::sync::Arc::clone(&store);
                let barrier = std::sync::Arc::clone(&barrier);
                let settings_id = settings_id.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    store.get(&settings_id).expect("concurrent get succeeded")
                })
            })
            .collect();
        barrier.wait();
        for round in 0..5 {
            assert!(
                store
                    .reconcile_orphaned_host_dispatches(633 + round)
                    .is_ok(),
                "repeated reconciliation remains successful"
            );
        }
        for handle in handles {
            let job = handle.join().expect("concurrent get joined");
            assert!(uncertainty_acknowledgement_action(&job));
            assert_eq!(dispatch_submitted_event_count(&job), 0);
        }
        let final_job = store
            .get(&settings.id)
            .expect("settings workflow remains actionable");
        assert_eq!(dispatch_submitted_event_count(&final_job), 0);
        assert_eq!(
            final_job
                .events
                .iter()
                .filter(|event| { event.kind == HostActionEventKind::DispatchOutcomeUncertain })
                .count(),
            1
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    fn checkpoint_preferences() -> HostPreferences {
        HostPreferences {
            accent: Some("#48b8a8".to_string()),
            ..HostPreferences::default()
        }
    }

    #[test]
    #[cfg(unix)]
    fn scoped_repair_does_not_normalize_unrelated_in_flight_settings_workflow() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-settings-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let preferences = checkpoint_preferences();
        let unrelated = store
            .begin_settings_change("athena", "markus", 700)
            .expect("unrelated settings workflow created");
        store
            .record_settings_request(&unrelated.id, &preferences, 701)
            .expect("unrelated settings payload recorded");
        let failed = store
            .begin_settings_change("hsb8", "markus", 702)
            .expect("failed settings workflow created");
        store
            .record_settings_request(&failed.id, &preferences, 703)
            .expect("failed settings payload recorded");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&failed.id, 704),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_settings_change_uncertain(&failed.id, 705),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        assert_eq!(
            store.pending_durable_repair_ids(),
            [failed.id.clone()].into()
        );
        let repaired = store
            .get(&failed.id)
            .expect("failed settings workflow reconciled");
        assert!(uncertainty_acknowledgement_action(&repaired));
        assert!(store.pending_durable_repair_ids().is_empty());
        let untouched = store
            .get(&unrelated.id)
            .expect("unrelated settings workflow readable");
        assert_eq!(untouched.state, HostActionState::ProposalRequested);
        assert!(!untouched.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        store
            .accept_settings_change(&unrelated.id, 706)
            .expect("unrelated settings workflow completes normally");
        assert_eq!(
            store
                .get(&unrelated.id)
                .expect("unrelated settings workflow retained")
                .summary()
                .workflow
                .status_label,
            "change waiting"
        );
        let reloaded = HostActionStore::new(Some(path.clone()));
        let durable_failed = reloaded
            .get(&failed.id)
            .expect("failed settings uncertainty durable");
        assert!(uncertainty_acknowledgement_action(&durable_failed));
        let durable_unrelated = reloaded
            .get(&unrelated.id)
            .expect("unrelated accepted settings durable");
        assert_eq!(durable_unrelated.state, HostActionState::ProposalRequested);
        assert!(!durable_unrelated.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn scoped_repair_does_not_normalize_unrelated_in_flight_removal_workflow() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-removal-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let unrelated = store
            .begin_removal("gpc0", "markus", removal_plan.clone(), 710)
            .expect("unrelated removal workflow created");
        let failed = store
            .begin_removal("hsb8", "markus", removal_plan, 711)
            .expect("failed removal workflow created");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&failed.id, 712),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_removal_uncertain(&failed.id, 713),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        assert_eq!(
            store.pending_durable_repair_ids(),
            [failed.id.clone()].into()
        );
        let repaired = store
            .get(&failed.id)
            .expect("failed removal workflow reconciled");
        assert!(uncertainty_acknowledgement_action(&repaired));
        let untouched = store
            .get(&unrelated.id)
            .expect("unrelated removal readable");
        assert_eq!(untouched.state, HostActionState::ProposalRequested);
        assert!(!untouched.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        store
            .fail_removal(&unrelated.id, 714)
            .expect("unrelated removal records a terminal rejection");
        assert_eq!(
            store
                .get(&unrelated.id)
                .expect("unrelated removal retained")
                .state,
            HostActionState::Failed
        );
        assert_eq!(dispatch_submitted_event_count(&repaired), 0);
        assert_eq!(dispatch_submitted_event_count(&untouched), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn scoped_repair_supports_multiple_pending_workflow_ids() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-multi-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let preferences = checkpoint_preferences();
        let settings = store
            .begin_settings_change("hsb8", "markus", 720)
            .expect("settings workflow created");
        store
            .record_settings_request(&settings.id, &preferences, 721)
            .expect("settings payload recorded");
        let removal_plan = HostRemovalPlan {
            disposition: HostRetirementDisposition::Unmanaged,
            successor: None,
            declaration_pending: true,
            credential_retirement_required: false,
        };
        let removal = store
            .begin_removal("gpc0", "markus", removal_plan, 722)
            .expect("removal workflow created");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&settings.id, 723),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_settings_change_uncertain(&settings.id, 724),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.mark_dispatch_submitted(&removal.id, 725),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_removal_uncertain(&removal.id, 726),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        let pending = store.pending_durable_repair_ids();
        assert!(pending.contains(&settings.id));
        assert!(pending.contains(&removal.id));
        assert!(store
            .reconcile_orphaned_host_dispatches(727)
            .expect("multi-job reconciliation succeeds"));
        assert!(store.pending_durable_repair_ids().is_empty());
        for id in [&settings.id, &removal.id] {
            let job = store.get(id).expect("pending workflow reconciled");
            assert!(uncertainty_acknowledgement_action(&job));
            assert_eq!(dispatch_submitted_event_count(&job), 0);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn scoped_repair_clearing_preserves_ids_registered_after_snapshot_boundary() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-boundary-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let preferences = checkpoint_preferences();
        let first = store
            .begin_settings_change("hsb8", "markus", 730)
            .expect("first settings workflow created");
        store
            .record_settings_request(&first.id, &preferences, 731)
            .expect("first settings payload recorded");
        let second = store
            .begin_settings_change("athena", "markus", 732)
            .expect("second settings workflow created");
        store
            .record_settings_request(&second.id, &preferences, 733)
            .expect("second settings payload recorded");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&first.id, 734),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.mark_dispatch_submitted(&second.id, 735),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        let pending = store.pending_durable_repair_ids();
        assert!(pending.contains(&first.id));
        assert!(pending.contains(&second.id));

        store
            .get(&first.id)
            .expect("first workflow reconciliation persists snapshot");
        assert!(
            store.pending_durable_repair_ids().contains(&second.id),
            "later pending id must survive an earlier snapshot flush"
        );
        assert_eq!(
            store
                .latest_settings_change_for_host("athena")
                .expect("second workflow retained in memory")
                .state,
            HostActionState::ProposalRequested
        );
        store
            .get(&second.id)
            .expect("second workflow reconciliation persists snapshot");
        assert!(store.pending_durable_repair_ids().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn system_update_checkpoint_failure_uses_scoped_repair_tracking() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-system-update-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path.clone()));
        let preferences = checkpoint_preferences();
        let unrelated = store
            .begin_settings_change("athena", "markus", 740)
            .expect("unrelated settings workflow created");
        store
            .record_settings_request(&unrelated.id, &preferences, 741)
            .expect("unrelated settings payload recorded");
        let update = store
            .begin_system_update_proposal("gpc0", "markus", 742, None)
            .expect("system update workflow created")
            .into_job();
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&update.id, 743),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_system_update_proposal_uncertain(&update.id, 744),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        assert_eq!(
            store.pending_durable_repair_ids(),
            [update.id.clone()].into()
        );
        let repaired = store
            .get(&update.id)
            .expect("system update uncertainty reconciled");
        assert!(repaired.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        assert!(store.pending_durable_repair_ids().is_empty());
        let untouched = store
            .get(&unrelated.id)
            .expect("unrelated settings readable");
        assert_eq!(untouched.state, HostActionState::ProposalRequested);
        assert!(!untouched.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn system_update_non_sticky_failure_clears_scoped_repair_tracking() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-system-update-rollback-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = HostActionStore::new(Some(path));
        let rolled_back = store
            .begin_system_update_proposal("hsb8", "markus", 745, None)
            .expect("system update workflow created")
            .into_job();
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&rolled_back.id, 746),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_system_update_proposal(&rolled_back.id, 747),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);
        assert!(!store.pending_durable_repair_ids().contains(&rolled_back.id));
        assert_eq!(
            store
                .get(&rolled_back.id)
                .expect("rolled-back system update readable")
                .state,
            HostActionState::ProposalRequested
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    #[cfg(unix)]
    fn concurrent_scoped_repair_leaves_unrelated_workflow_completable() {
        let dir = std::env::temp_dir().join(format!(
            "pharos-scoped-repair-concurrent-{}-{}",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).expect("scoped repair directory created");
        let path = dir.join("actions.json");
        let store = std::sync::Arc::new(HostActionStore::new(Some(path.clone())));
        let preferences = checkpoint_preferences();
        let unrelated = store
            .begin_settings_change("athena", "markus", 750)
            .expect("unrelated settings workflow created");
        store
            .record_settings_request(&unrelated.id, &preferences, 751)
            .expect("unrelated settings payload recorded");
        let failed = store
            .begin_settings_change("hsb8", "markus", 752)
            .expect("failed settings workflow created");
        store
            .record_settings_request(&failed.id, &preferences, 753)
            .expect("failed settings payload recorded");
        set_dir_read_only(&dir);
        assert_eq!(
            store.mark_dispatch_submitted(&failed.id, 754),
            Err(HostActionStoreError::Persistence)
        );
        assert_eq!(
            store.fail_settings_change_uncertain(&failed.id, 755),
            Err(HostActionStoreError::Persistence)
        );
        set_dir_writable(&dir);

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let failed_id = failed.id.clone();
        let unrelated_id = unrelated.id.clone();
        let repair_store = std::sync::Arc::clone(&store);
        let repair_barrier = std::sync::Arc::clone(&barrier);
        let repair_handle = std::thread::spawn(move || {
            repair_barrier.wait();
            repair_store
                .get(&failed_id)
                .expect("failed workflow repaired concurrently")
        });
        let complete_store = std::sync::Arc::clone(&store);
        let complete_barrier = std::sync::Arc::clone(&barrier);
        let complete_handle = std::thread::spawn(move || {
            complete_barrier.wait();
            complete_store
                .accept_settings_change(&unrelated_id, 756)
                .expect("unrelated workflow completes during scoped repair");
        });
        barrier.wait();
        let repaired = repair_handle.join().expect("repair thread joined");
        complete_handle.join().expect("completion thread joined");
        assert!(uncertainty_acknowledgement_action(&repaired));
        let unrelated_job = store
            .get(&unrelated.id)
            .expect("unrelated workflow retained");
        assert_eq!(unrelated_job.state, HostActionState::ProposalRequested);
        assert!(!unrelated_job.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        assert_eq!(dispatch_submitted_event_count(&repaired), 0);
        assert_eq!(dispatch_submitted_event_count(&unrelated_job), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn post_rename_persistence_committed_on_settings_dispatch_does_not_duplicate() {
        let path = std::env::temp_dir().join(format!(
            "pharos-post-commit-sync-failure-settings-dispatch-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        assert_eq!(
            store.begin_settings_change("hsb8", "markus", 640),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let settings = store
            .latest_settings_change_for_host("hsb8")
            .expect("settings workflow retained after begin");
        assert_eq!(
            store.mark_dispatch_submitted(&settings.id, 641),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let handed_off = store
            .get(&settings.id)
            .expect("settings dispatch handoff retained");
        assert_eq!(dispatch_submitted_event_count(&handed_off), 1);
        assert_eq!(
            store.mark_dispatch_submitted(&settings.id, 642),
            Err(HostActionStoreError::PersistenceCommitted)
        );
        let idempotent = store
            .get(&settings.id)
            .expect("settings dispatch handoff still singular");
        assert_eq!(dispatch_submitted_event_count(&idempotent), 1);
        let reloaded = HostActionStore::new(Some(path.clone()));
        let durable = reloaded
            .get(&settings.id)
            .expect("settings dispatch handoff durable");
        assert_eq!(dispatch_submitted_event_count(&durable), 1);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn legacy_accepted_settings_workflow_remains_waiting_after_reload() {
        let path = std::env::temp_dir().join(format!(
            "pharos-legacy-accepted-settings-{}-{}.json",
            std::process::id(),
            ACTION_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        let store = HostActionStore::new(Some(path.clone()));
        let settings = store
            .begin_settings_change("hsb8", "markus", 540)
            .expect("legacy settings workflow created");
        store
            .accept_settings_change(&settings.id, 541)
            .expect("legacy settings request accepted without dispatch checkpoint");
        drop(store);

        let reloaded = HostActionStore::new(Some(path.clone()));
        let waiting = reloaded
            .get(&settings.id)
            .expect("legacy accepted settings workflow reloaded");
        assert_eq!(waiting.state, HostActionState::ProposalRequested);
        assert!(!waiting.has_event(HostActionEventKind::DispatchOutcomeUncertain));
        assert_eq!(waiting.summary().workflow.status_label, "change waiting");
        assert!(waiting.summary().workflow.primary_action.is_none());
        let _ = std::fs::remove_file(path);
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
        assert_eq!(job.update_restart_intent(), UpdateRestartIntent::Update);
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
            UpdateRestartIntent::Update,
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
