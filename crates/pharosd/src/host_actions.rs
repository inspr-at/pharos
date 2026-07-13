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

use serde::{Deserialize, Serialize};

const ACTION_SCHEMA: &str = "inspr.pharos.host-action.v1";
const ACTION_VERSION: u16 = 1;
const RETIRED_SCHEMA: &str = "inspr.pharos.retired-hosts.v1";
const RETIRED_VERSION: u16 = 2;
const LEASE_SECS: i64 = 180;
static ACTION_COUNTER: AtomicU64 = AtomicU64::new(1);
static PERSIST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum HostActionKind {
    SystemUpdateProposal,
    UpdateRestart,
    RemoveHost,
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
}

impl HostActionState {
    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Succeeded | Self::Failed)
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
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub(crate) struct HostActionJob {
    schema: String,
    version: u16,
    pub(crate) id: String,
    pub(crate) host: String,
    pub(crate) kind: HostActionKind,
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
    #[serde(default)]
    lease_phase: Option<AgentActionPhase>,
    lease_until: Option<i64>,
}

impl HostActionJob {
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
            && self.plan.as_ref().is_none_or(HostActionPlan::validate)
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

    pub(crate) fn summary(&self) -> HostActionSummary {
        HostActionSummary {
            id: self.id.clone(),
            kind: self.kind,
            state: self.state,
            ticket: self.ticket.clone(),
            retry_of: self.retry_of.clone(),
            retryable: self.review_retryable(),
            updated_at: self.updated_at,
            plan: self.plan.clone(),
            removal_plan: self.removal_plan.clone(),
            result: self.result.clone(),
        }
    }

    fn review_retryable(&self) -> bool {
        self.kind == HostActionKind::UpdateRestart
            && self.state == HostActionState::Failed
            && self.confirmed_at.is_none()
            && self.plan.is_none()
            && self.result.is_none()
    }
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub(crate) struct HostActionSummary {
    pub(crate) id: String,
    pub(crate) kind: HostActionKind,
    pub(crate) state: HostActionState,
    pub(crate) ticket: String,
    pub(crate) retry_of: Option<String>,
    pub(crate) retryable: bool,
    pub(crate) updated_at: i64,
    pub(crate) plan: Option<HostActionPlan>,
    pub(crate) removal_plan: Option<HostRemovalPlan>,
    pub(crate) result: Option<HostActionResult>,
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

    pub(crate) fn latest_for_host(&self, host: &str) -> Option<HostActionJob> {
        self.jobs
            .read()
            .expect("host action store lock")
            .values()
            .filter(|job| job.host == host)
            .max_by_key(|job| job.updated_at)
            .cloned()
    }

    fn record_proposal(
        &self,
        proposal: NewHostAction<'_>,
    ) -> Result<HostActionJob, HostActionStoreError> {
        self.insert(HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: proposal.id,
            host: proposal.host.to_string(),
            kind: proposal.kind,
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
            lease_phase: None,
            lease_until: None,
        })
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
            state: if removal_plan.declaration_pending {
                HostActionState::RemovalPending
            } else {
                HostActionState::Succeeded
            },
            removal_plan: Some(removal_plan),
            now,
        })
    }

    pub(crate) fn confirm_update(
        &self,
        id: &str,
        host: &str,
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
                        Some(AgentActionPhase::Review)
                    }
                    HostActionState::QueuedApply => Some(AgentActionPhase::Apply),
                    HostActionState::Applying
                        if job.lease_until.is_some_and(|until| until <= now) =>
                    {
                        Some(AgentActionPhase::Apply)
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
        job.state = match phase {
            AgentActionPhase::Review => HostActionState::Reviewing,
            AgentActionPhase::Apply | AgentActionPhase::Resume => HostActionState::Applying,
        };
        job.updated_at = now;
        job.lease_phase = Some(phase);
        job.lease_until = Some(now.saturating_add(LEASE_SECS));
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
            match (request.phase, request.outcome) {
                (AgentActionPhase::Review, AgentActionOutcome::Succeeded) => {
                    let plan = request.plan.ok_or(HostActionStoreError::InvalidJob)?;
                    if !plan.validate() {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.plan = Some(plan);
                    job.state = HostActionState::AwaitingConfirmation;
                }
                (AgentActionPhase::Review, AgentActionOutcome::Failed) => {
                    job.state = HostActionState::Failed;
                }
                (
                    AgentActionPhase::Apply | AgentActionPhase::Resume,
                    AgentActionOutcome::Rebooting,
                ) => {
                    job.state = HostActionState::Rebooting;
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
                    {
                        return Err(HostActionStoreError::InvalidJob);
                    }
                    job.result = Some(result);
                    job.state = HostActionState::Succeeded;
                }
                (_, AgentActionOutcome::Failed) => {
                    job.state = HostActionState::Failed;
                }
                _ => return Err(HostActionStoreError::InvalidTransition),
            }
            job.updated_at = now;
            job.lease_phase = None;
            job.lease_until = None;
            (previous, job.clone())
        };
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
        let previous = job.clone();
        job.state = HostActionState::Succeeded;
        job.updated_at = now;
        let updated = job.clone();
        if let Err(error) = self.persist_jobs(&jobs) {
            jobs.insert(id.to_string(), previous);
            return Err(error);
        }
        Ok(Some(updated))
    }

    fn new_update_review(
        host: &str,
        actor: &str,
        now: i64,
        retry_of: Option<String>,
    ) -> HostActionJob {
        HostActionJob {
            schema: ACTION_SCHEMA.to_string(),
            version: ACTION_VERSION,
            id: action_id("update-restart", host, now),
            host: host.to_string(),
            kind: HostActionKind::UpdateRestart,
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
            lease_phase: None,
            lease_until: None,
        }
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
        latest_by_host
            .values()
            .any(|job| job.host != host && job.state != HostActionState::Succeeded)
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
            .confirm_update(&job.id, "hsb8", 103)
            .expect("confirmed");
        assert_eq!(confirmed.state, HostActionState::QueuedApply);
        assert_eq!(
            store.claim("hsb8", 104).expect("claim").unwrap().phase,
            AgentActionPhase::Apply
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
            .confirm_update(&retry.id, "hsb8", 107)
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
            .confirm_update(&job.id, "hsb8", 203)
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
    fn removal_plan_records_lifecycle_and_rejects_invalid_lineage() {
        let store = HostActionStore::new(None);
        let removal = store
            .create_removal(
                "gpc0",
                "markus",
                None,
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: Some("stm2607".to_string()),
                    declaration_pending: true,
                },
                100,
            )
            .expect("removal recorded");
        assert_eq!(removal.state, HostActionState::RemovalPending);
        let plan = removal
            .summary()
            .removal_plan
            .expect("removal plan exposed");
        assert_eq!(plan.disposition, HostRetirementDisposition::Rebuilt);
        assert_eq!(plan.successor.as_deref(), Some("stm2607"));
        assert!(plan.declaration_pending);

        assert_eq!(
            store.create_removal(
                "hsb8",
                "markus",
                None,
                HostRemovalPlan {
                    disposition: HostRetirementDisposition::Rebuilt,
                    successor: None,
                    declaration_pending: true,
                },
                101,
            ),
            Err(HostActionStoreError::InvalidJob)
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
