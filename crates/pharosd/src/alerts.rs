//! Durable host-availability and backup-posture incidents with an at-least-once alert outbox.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

use pharos_core::{liveness, BackupObservation, BackupPostureState, Host, Liveness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::durable_file::{atomic_write_json, load_optional_json, DurableFileError};

const STORE_SCHEMA: &str = "inspr.pharos.alert-state.v2";
const PREVIOUS_STORE_SCHEMA: &str = "inspr.pharos.alert-state.v1";
const STORE_VERSION: u16 = 2;
const PREVIOUS_STORE_VERSION: u16 = 1;
const EVENT_SCHEMA: &str = "inspr.pharos.alert-event.v2";
const PREVIOUS_EVENT_SCHEMA: &str = "inspr.pharos.alert-event.v1";
const FIRST_ESCALATION_SECS: i64 = 15 * 60;
const SECOND_ESCALATION_SECS: i64 = 60 * 60;
const HISTORY_RETENTION_SECS: i64 = 90 * 24 * 60 * 60;
const MAX_RECORDS: usize = 10_000;

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(crate) struct AlertWorkerSnapshot {
    pub enabled: bool,
    pub ready: bool,
    pub running: bool,
    pub last_success_unix: Option<i64>,
    pub consecutive_failures: u64,
    pub deliveries_total: u64,
    pub delivery_failures_total: u64,
    pub restarts_total: u64,
    pub pending_events: u64,
}

#[derive(Clone)]
pub(crate) struct AlertWorkerHealth {
    inner: std::sync::Arc<AlertWorkerHealthInner>,
}

struct AlertWorkerHealthInner {
    enabled: bool,
    started_at: i64,
    stale_after_secs: i64,
    running: AtomicBool,
    last_success: AtomicI64,
    consecutive_failures: AtomicU64,
    deliveries: AtomicU64,
    delivery_failures: AtomicU64,
    restarts: AtomicU64,
    pending: AtomicU64,
}

impl AlertWorkerHealth {
    pub(crate) fn new(enabled: bool, started_at: i64, check_interval_secs: u64) -> Self {
        Self {
            inner: std::sync::Arc::new(AlertWorkerHealthInner {
                enabled,
                started_at,
                stale_after_secs: i64::try_from(check_interval_secs.saturating_mul(3).max(30))
                    .unwrap_or(i64::MAX),
                running: AtomicBool::new(false),
                last_success: AtomicI64::new(0),
                consecutive_failures: AtomicU64::new(0),
                deliveries: AtomicU64::new(0),
                delivery_failures: AtomicU64::new(0),
                restarts: AtomicU64::new(0),
                pending: AtomicU64::new(0),
            }),
        }
    }

    pub(crate) fn mark_running(&self, running: bool) {
        self.inner.running.store(running, Ordering::Release);
    }

    pub(crate) fn record_cycle(&self, now: i64, succeeded: bool, pending: usize) {
        self.inner.pending.store(
            u64::try_from(pending).unwrap_or(u64::MAX),
            Ordering::Release,
        );
        if succeeded {
            self.inner.last_success.store(now, Ordering::Release);
            self.inner.consecutive_failures.store(0, Ordering::Release);
        } else {
            self.inner
                .consecutive_failures
                .fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn record_delivery(&self, succeeded: bool) {
        if succeeded {
            self.inner.deliveries.fetch_add(1, Ordering::AcqRel);
        } else {
            self.inner.delivery_failures.fetch_add(1, Ordering::AcqRel);
        }
    }

    pub(crate) fn record_restart(&self) {
        self.inner.restarts.fetch_add(1, Ordering::AcqRel);
    }

    pub(crate) fn snapshot(&self, now: i64) -> AlertWorkerSnapshot {
        let running = self.inner.running.load(Ordering::Acquire);
        let last_success = self.inner.last_success.load(Ordering::Acquire);
        let anchor = if last_success > 0 {
            last_success
        } else {
            self.inner.started_at
        };
        let ready = !self.inner.enabled
            || (running && now.saturating_sub(anchor) <= self.inner.stale_after_secs);
        AlertWorkerSnapshot {
            enabled: self.inner.enabled,
            ready,
            running,
            last_success_unix: (last_success > 0).then_some(last_success),
            consecutive_failures: self.inner.consecutive_failures.load(Ordering::Acquire),
            deliveries_total: self.inner.deliveries.load(Ordering::Acquire),
            delivery_failures_total: self.inner.delivery_failures.load(Ordering::Acquire),
            restarts_total: self.inner.restarts.load(Ordering::Acquire),
            pending_events: self.inner.pending.load(Ordering::Acquire),
        }
    }
}

#[derive(Debug)]
pub(crate) enum AlertStoreError {
    Persistence(DurableFileError),
    InvalidState(&'static str),
    NotFound,
    InvalidTransition,
}

impl std::fmt::Display for AlertStoreError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Persistence(error) => write!(formatter, "{error}"),
            Self::InvalidState(reason) => write!(formatter, "invalid alert state: {reason}"),
            Self::NotFound => formatter.write_str("alert event not found"),
            Self::InvalidTransition => formatter.write_str("invalid alert event transition"),
        }
    }
}

impl std::error::Error for AlertStoreError {}

impl From<DurableFileError> for AlertStoreError {
    fn from(error: DurableFileError) -> Self {
        Self::Persistence(error)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) enum AlertEventKind {
    #[serde(rename = "host_down")]
    Down,
    #[serde(rename = "host_down_escalated")]
    DownEscalated,
    #[serde(rename = "host_recovered")]
    Recovered,
    #[serde(rename = "backup_stale")]
    BackupStale,
    #[serde(rename = "backup_failed")]
    BackupFailed,
    #[serde(rename = "backup_escalated")]
    BackupEscalated,
    #[serde(rename = "backup_recovered")]
    BackupRecovered,
}

impl AlertEventKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Down => "host_down",
            Self::DownEscalated => "host_down_escalated",
            Self::Recovered => "host_recovered",
            Self::BackupStale => "backup_stale",
            Self::BackupFailed => "backup_failed",
            Self::BackupEscalated => "backup_escalated",
            Self::BackupRecovered => "backup_recovered",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
enum IncidentKind {
    #[default]
    HostDown,
    Backup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct AlertEvent {
    pub schema: String,
    pub event_id: String,
    pub incident_id: String,
    pub kind: AlertEventKind,
    pub sequence: u8,
    pub level: String,
    pub host: String,
    pub role: String,
    pub last_seen: i64,
    pub age_seconds: i64,
    pub heartbeat_interval_secs: u64,
    pub occurred_at: i64,
    pub summary: String,
    pub next_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Incident {
    incident_id: String,
    #[serde(default)]
    kind: IncidentKind,
    host: String,
    role: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    backup_state: Option<BackupPostureState>,
    last_seen: i64,
    heartbeat_interval_secs: u64,
    opened_at: i64,
    highest_escalation: u8,
    active: bool,
    recovered_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OutboxRecord {
    event: AlertEvent,
    attempts: u32,
    next_attempt_at: i64,
    delivered_at: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AlertState {
    schema: String,
    version: u16,
    incidents: BTreeMap<String, Incident>,
    outbox: BTreeMap<String, OutboxRecord>,
}

impl Default for AlertState {
    fn default() -> Self {
        Self {
            schema: STORE_SCHEMA.to_string(),
            version: STORE_VERSION,
            incidents: BTreeMap::new(),
            outbox: BTreeMap::new(),
        }
    }
}

pub(crate) struct AlertStore {
    path: Option<PathBuf>,
    state: Mutex<AlertState>,
}

impl AlertStore {
    pub(crate) fn new(path: Option<PathBuf>) -> Result<Self, AlertStoreError> {
        let mut state = match path.as_deref() {
            Some(path) => load_optional_json::<AlertState>(path)?.unwrap_or_default(),
            None => AlertState::default(),
        };
        migrate_state(&mut state)?;
        validate_state(&state)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    pub(crate) fn path_for(host_store_path: Option<&Path>) -> Option<PathBuf> {
        if let Ok(path) = std::env::var("PHAROS_ALERT_DB") {
            let path = path.trim();
            if !path.is_empty() {
                return Some(PathBuf::from(path));
            }
        }
        host_store_path.map(|path| {
            let file_name = path
                .file_name()
                .and_then(|name| name.to_str())
                .filter(|name| !name.is_empty())
                .unwrap_or("pharos.json");
            path.with_file_name(format!("{file_name}.alerts.json"))
        })
    }

    pub(crate) fn is_durable(&self) -> bool {
        self.path.is_some()
    }

    pub(crate) fn reconcile_hosts(&self, hosts: &[Host], now: i64) -> Result<(), AlertStoreError> {
        self.mutate(|state| reconcile(state, hosts, now))
    }

    pub(crate) fn due_event_ids(&self, now: i64) -> Vec<String> {
        let state = self.state.lock().expect("alert state mutex poisoned");
        let mut earliest = BTreeMap::<&str, &OutboxRecord>::new();
        for record in state
            .outbox
            .values()
            .filter(|record| record.delivered_at.is_none())
        {
            earliest
                .entry(&record.event.incident_id)
                .and_modify(|current| {
                    if (
                        record.event.sequence,
                        record.event.occurred_at,
                        &record.event.event_id,
                    ) < (
                        current.event.sequence,
                        current.event.occurred_at,
                        &current.event.event_id,
                    ) {
                        *current = record;
                    }
                })
                .or_insert(record);
        }
        let mut due = earliest
            .values()
            .filter(|record| record.next_attempt_at <= now)
            .map(|record| (record.event.occurred_at, record.event.event_id.clone()))
            .collect::<Vec<_>>();
        due.sort();
        due.into_iter().map(|(_, event_id)| event_id).collect()
    }

    /// Persist the attempt and its retry deadline before any network request.
    pub(crate) fn begin_attempt(
        &self,
        event_id: &str,
        now: i64,
    ) -> Result<AlertEvent, AlertStoreError> {
        let mut event = None;
        self.mutate(|state| {
            let record = state
                .outbox
                .get_mut(event_id)
                .ok_or(AlertStoreError::NotFound)?;
            if record.delivered_at.is_some() || record.next_attempt_at > now {
                return Err(AlertStoreError::InvalidTransition);
            }
            record.attempts = record.attempts.saturating_add(1);
            record.next_attempt_at =
                now.saturating_add(retry_delay_seconds(&record.event.event_id, record.attempts));
            event = Some(record.event.clone());
            Ok(())
        })?;
        event.ok_or(AlertStoreError::InvalidTransition)
    }

    pub(crate) fn mark_delivered(&self, event_id: &str, now: i64) -> Result<(), AlertStoreError> {
        self.mutate(|state| {
            let record = state
                .outbox
                .get_mut(event_id)
                .ok_or(AlertStoreError::NotFound)?;
            if record.attempts == 0 {
                return Err(AlertStoreError::InvalidTransition);
            }
            record.delivered_at = Some(now);
            Ok(())
        })
    }

    pub(crate) fn pending_count(&self) -> usize {
        self.state
            .lock()
            .expect("alert state mutex poisoned")
            .outbox
            .values()
            .filter(|record| record.delivered_at.is_none())
            .count()
    }

    #[cfg(test)]
    fn event(&self, event_id: &str) -> Option<OutboxRecord> {
        self.state
            .lock()
            .expect("alert state mutex poisoned")
            .outbox
            .get(event_id)
            .cloned()
    }

    fn mutate(
        &self,
        operation: impl FnOnce(&mut AlertState) -> Result<(), AlertStoreError>,
    ) -> Result<(), AlertStoreError> {
        let mut state = self.state.lock().expect("alert state mutex poisoned");
        let previous = state.clone();
        if let Err(error) = operation(&mut state) {
            *state = previous;
            return Err(error);
        }
        if let Err(error) = validate_state(&state) {
            *state = previous;
            return Err(error);
        }
        if let Some(path) = &self.path {
            if let Err(error) = atomic_write_json(path, &*state) {
                // A directory-sync error occurs after the atomic rename. Keep
                // memory aligned with the new file that is already visible,
                // while still reporting that crash durability was not proven.
                if !error.final_file_replaced() {
                    *state = previous;
                }
                return Err(error.into());
            }
        }
        Ok(())
    }
}

fn migrate_state(state: &mut AlertState) -> Result<(), AlertStoreError> {
    match (state.schema.as_str(), state.version) {
        (STORE_SCHEMA, STORE_VERSION) => Ok(()),
        (PREVIOUS_STORE_SCHEMA, PREVIOUS_STORE_VERSION) => {
            state.schema = STORE_SCHEMA.to_string();
            state.version = STORE_VERSION;
            Ok(())
        }
        _ => Err(AlertStoreError::InvalidState("unsupported schema")),
    }
}

fn reconcile(state: &mut AlertState, hosts: &[Host], now: i64) -> Result<(), AlertStoreError> {
    prune_history(state, now);
    let mut seen_hosts = BTreeSet::new();
    let mut seen_backups = BTreeSet::new();
    for host in hosts {
        seen_hosts.insert(host.name.clone());
        reconcile_host_liveness(state, host, now)?;
        for observation in &host.backup_observations {
            if !seen_backups.insert((host.name.clone(), observation.id.clone())) {
                return Err(AlertStoreError::InvalidState(
                    "duplicate backup observation subject",
                ));
            }
            reconcile_backup(state, host, observation, now)?;
        }
    }

    let vanished = state
        .incidents
        .values()
        .filter(|incident| {
            incident.active
                && (!seen_hosts.contains(&incident.host)
                    || incident.kind == IncidentKind::Backup
                        && !seen_backups.contains(&(
                            incident.host.clone(),
                            incident.backup_id.clone().unwrap_or_default(),
                        )))
        })
        .map(|incident| incident.incident_id.clone())
        .collect::<Vec<_>>();
    for incident_id in vanished {
        close_incident(state, &incident_id, now)?;
    }
    Ok(())
}

fn reconcile_host_liveness(
    state: &mut AlertState,
    host: &Host,
    now: i64,
) -> Result<(), AlertStoreError> {
    let active_id = state
        .incidents
        .values()
        .find(|incident| {
            incident.active && incident.kind == IncidentKind::HostDown && incident.host == host.name
        })
        .map(|incident| incident.incident_id.clone());
    let down = host.last_seen.is_some()
        && liveness(host.last_seen, host.heartbeat_interval_secs, now) == Liveness::Down;
    if down && !host.preferences.suppresses_down_alerts() {
        let last_seen = host.last_seen.expect("down host has last_seen");
        let incident_id = match active_id {
            Some(incident_id) => incident_id,
            None => open_host_incident(state, host, last_seen, now)?,
        };
        enqueue_escalations(state, &incident_id, now)?;
    } else if let Some(incident_id) = active_id {
        if down {
            close_incident(state, &incident_id, now)?;
        } else {
            recover_incident(state, &incident_id, now)?;
        }
    }
    Ok(())
}

fn reconcile_backup(
    state: &mut AlertState,
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) -> Result<(), AlertStoreError> {
    let active_id = state
        .incidents
        .values()
        .find(|incident| {
            incident.active
                && incident.kind == IncidentKind::Backup
                && incident.host == host.name
                && incident.backup_id.as_deref() == Some(observation.id.as_str())
        })
        .map(|incident| incident.incident_id.clone());
    let alerting = matches!(
        observation.state,
        BackupPostureState::Stale | BackupPostureState::Failed
    );

    if alerting && !host.preferences.alerts.suppress_backup {
        let incident_id = match active_id {
            Some(incident_id) => {
                let was_failed = state.incidents.get(&incident_id).is_some_and(|incident| {
                    incident.backup_state == Some(BackupPostureState::Failed)
                });
                if observation.state == BackupPostureState::Failed && !was_failed {
                    record_backup_failure(state, &incident_id, now)?;
                }
                if let Some(incident) = state.incidents.get_mut(&incident_id) {
                    incident.backup_label = Some(observation.label.clone());
                }
                incident_id
            }
            None => open_backup_incident(state, host, observation, now)?,
        };
        enqueue_escalations(state, &incident_id, now)?;
    } else if let Some(incident_id) = active_id {
        if observation.state == BackupPostureState::Healthy
            && !host.preferences.alerts.suppress_backup
        {
            recover_incident(state, &incident_id, now)?;
        } else if host.preferences.alerts.suppress_backup {
            suppress_incident(state, &incident_id, now)?;
        } else {
            close_incident(state, &incident_id, now)?;
        }
    }
    Ok(())
}

fn backup_anchor(host: &Host, observation: &BackupObservation, now: i64) -> i64 {
    observation
        .last_attempt_at
        .or(observation.last_success_at)
        .or(observation.last_check_at)
        .or(host.last_seen)
        .unwrap_or(now)
        .min(now)
}

fn open_host_incident(
    state: &mut AlertState,
    host: &Host,
    last_seen: i64,
    now: i64,
) -> Result<String, AlertStoreError> {
    if state.incidents.len() >= MAX_RECORDS || state.outbox.len() >= MAX_RECORDS {
        return Err(AlertStoreError::InvalidState("record bound exceeded"));
    }
    let incident_id = stable_id(
        "incident",
        &[&host.name, &last_seen.to_string(), &now.to_string()],
    );
    let incident = Incident {
        incident_id: incident_id.clone(),
        kind: IncidentKind::HostDown,
        host: host.name.clone(),
        role: host.role.clone(),
        backup_id: None,
        backup_label: None,
        backup_state: None,
        last_seen,
        heartbeat_interval_secs: host.heartbeat_interval_secs.unwrap_or(60),
        opened_at: now,
        highest_escalation: 0,
        active: true,
        recovered_at: None,
    };
    state
        .incidents
        .insert(incident_id.clone(), incident.clone());
    enqueue_event(state, &incident, AlertEventKind::Down, 0, now)?;
    Ok(incident_id)
}

fn open_backup_incident(
    state: &mut AlertState,
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) -> Result<String, AlertStoreError> {
    if state.incidents.len() >= MAX_RECORDS || state.outbox.len() >= MAX_RECORDS {
        return Err(AlertStoreError::InvalidState("record bound exceeded"));
    }
    let anchor = backup_anchor(host, observation, now);
    let incident_id = stable_id(
        "backup-incident",
        &[
            &host.name,
            &observation.id,
            &anchor.to_string(),
            &now.to_string(),
        ],
    );
    let incident = Incident {
        incident_id: incident_id.clone(),
        kind: IncidentKind::Backup,
        host: host.name.clone(),
        role: host.role.clone(),
        backup_id: Some(observation.id.clone()),
        backup_label: Some(observation.label.clone()),
        backup_state: Some(observation.state),
        last_seen: anchor,
        heartbeat_interval_secs: host.heartbeat_interval_secs.unwrap_or(60),
        opened_at: now,
        highest_escalation: 0,
        active: true,
        recovered_at: None,
    };
    state
        .incidents
        .insert(incident_id.clone(), incident.clone());
    let kind = if observation.state == BackupPostureState::Failed {
        AlertEventKind::BackupFailed
    } else {
        AlertEventKind::BackupStale
    };
    enqueue_event(state, &incident, kind, 0, now)?;
    Ok(incident_id)
}

fn record_backup_failure(
    state: &mut AlertState,
    incident_id: &str,
    now: i64,
) -> Result<(), AlertStoreError> {
    let mut incident = state
        .incidents
        .get(incident_id)
        .cloned()
        .ok_or(AlertStoreError::NotFound)?;
    incident.backup_state = Some(BackupPostureState::Failed);
    enqueue_event(state, &incident, AlertEventKind::BackupFailed, 1, now)?;
    let incident = state
        .incidents
        .get_mut(incident_id)
        .ok_or(AlertStoreError::NotFound)?;
    incident.backup_state = Some(BackupPostureState::Failed);
    incident.highest_escalation = incident.highest_escalation.max(1);
    Ok(())
}

fn enqueue_escalations(
    state: &mut AlertState,
    incident_id: &str,
    now: i64,
) -> Result<(), AlertStoreError> {
    let incident = state
        .incidents
        .get(incident_id)
        .cloned()
        .ok_or(AlertStoreError::NotFound)?;
    let age = now.saturating_sub(incident.last_seen);
    let target = if age >= SECOND_ESCALATION_SECS {
        2
    } else if age >= FIRST_ESCALATION_SECS {
        1
    } else {
        0
    };
    let event_kind = match incident.kind {
        IncidentKind::HostDown => AlertEventKind::DownEscalated,
        IncidentKind::Backup => AlertEventKind::BackupEscalated,
    };
    for stage in (incident.highest_escalation + 1)..=target {
        enqueue_event(state, &incident, event_kind, stage, now)?;
    }
    state
        .incidents
        .get_mut(incident_id)
        .ok_or(AlertStoreError::NotFound)?
        .highest_escalation = target;
    Ok(())
}

fn recover_incident(
    state: &mut AlertState,
    incident_id: &str,
    now: i64,
) -> Result<(), AlertStoreError> {
    let incident = state
        .incidents
        .get(incident_id)
        .cloned()
        .ok_or(AlertStoreError::NotFound)?;
    if !incident.active {
        return Ok(());
    }
    let event_kind = match incident.kind {
        IncidentKind::HostDown => AlertEventKind::Recovered,
        IncidentKind::Backup => AlertEventKind::BackupRecovered,
    };
    enqueue_event(state, &incident, event_kind, 0, now)?;
    let incident = state
        .incidents
        .get_mut(incident_id)
        .ok_or(AlertStoreError::NotFound)?;
    incident.active = false;
    incident.recovered_at = Some(now);
    Ok(())
}

fn close_incident(
    state: &mut AlertState,
    incident_id: &str,
    now: i64,
) -> Result<(), AlertStoreError> {
    let incident = state
        .incidents
        .get_mut(incident_id)
        .ok_or(AlertStoreError::NotFound)?;
    incident.active = false;
    incident.recovered_at = Some(now);
    Ok(())
}

fn suppress_incident(
    state: &mut AlertState,
    incident_id: &str,
    now: i64,
) -> Result<(), AlertStoreError> {
    close_incident(state, incident_id, now)?;
    state.outbox.retain(|_, record| {
        record.event.incident_id != incident_id || record.delivered_at.is_some()
    });
    Ok(())
}

fn enqueue_event(
    state: &mut AlertState,
    incident: &Incident,
    kind: AlertEventKind,
    stage: u8,
    now: i64,
) -> Result<(), AlertStoreError> {
    if state.outbox.len() >= MAX_RECORDS {
        return Err(AlertStoreError::InvalidState("outbox bound exceeded"));
    }
    let event_id = stable_id(
        "event",
        &[&incident.incident_id, kind.label(), &stage.to_string()],
    );
    if state.outbox.contains_key(&event_id) {
        return Ok(());
    }
    let age_seconds = now.saturating_sub(incident.last_seen).max(0);
    let backup_label = incident.backup_label.as_deref().unwrap_or("Backup");
    let (level, summary, next_action) = match kind {
        AlertEventKind::Down => (
            "critical",
            format!(
                "{} has not reported to Pharos for {}.",
                incident.host,
                crate::duration_label(age_seconds)
            ),
            "Check host power, network, and pharos-beacon.".to_string(),
        ),
        AlertEventKind::DownEscalated => (
            "critical",
            format!(
                "{} remains down after {}.",
                incident.host,
                crate::duration_label(age_seconds)
            ),
            "Escalate the incident and verify the host recovery owner.".to_string(),
        ),
        AlertEventKind::Recovered => (
            "recovery",
            format!("{} is reporting to Pharos again.", incident.host),
            "Confirm the host is stable and close related incident work.".to_string(),
        ),
        AlertEventKind::BackupStale => (
            "warning",
            format!(
                "{}: {backup_label} backup evidence is stale by {}.",
                incident.host,
                crate::duration_label(age_seconds)
            ),
            "Confirm the backup schedule, runner, and latest successful snapshot.".to_string(),
        ),
        AlertEventKind::BackupFailed => (
            "critical",
            format!(
                "{}: {backup_label} backup reported failure {} ago.",
                incident.host,
                crate::duration_label(age_seconds)
            ),
            "Inspect the backup job, fix the failure, then confirm the next successful run."
                .to_string(),
        ),
        AlertEventKind::BackupEscalated => {
            let failed = incident.backup_state == Some(BackupPostureState::Failed);
            (
                if failed || stage >= 2 {
                    "critical"
                } else {
                    "warning"
                },
                format!(
                    "{}: {backup_label} backup remains {} after {}.",
                    incident.host,
                    if failed { "failed" } else { "stale" },
                    crate::duration_label(age_seconds)
                ),
                "Escalate to the backup owner and verify a fresh successful run.".to_string(),
            )
        }
        AlertEventKind::BackupRecovered => (
            "recovery",
            format!("{}: {backup_label} backup is healthy again.", incident.host),
            "Confirm the fresh backup evidence and close related incident work.".to_string(),
        ),
    };
    let event = AlertEvent {
        schema: EVENT_SCHEMA.to_string(),
        event_id: event_id.clone(),
        incident_id: incident.incident_id.clone(),
        kind,
        sequence: match kind {
            AlertEventKind::Down | AlertEventKind::BackupStale => 0,
            AlertEventKind::DownEscalated
            | AlertEventKind::BackupFailed
            | AlertEventKind::BackupEscalated => stage,
            AlertEventKind::Recovered | AlertEventKind::BackupRecovered => 3,
        },
        level: level.to_string(),
        host: incident.host.clone(),
        role: incident.role.clone(),
        last_seen: incident.last_seen,
        age_seconds,
        heartbeat_interval_secs: incident.heartbeat_interval_secs,
        occurred_at: now,
        summary,
        next_action,
    };
    state.outbox.insert(
        event_id,
        OutboxRecord {
            event,
            attempts: 0,
            next_attempt_at: now,
            delivered_at: None,
        },
    );
    Ok(())
}

fn prune_history(state: &mut AlertState, now: i64) {
    let cutoff = now.saturating_sub(HISTORY_RETENTION_SECS);
    state.outbox.retain(|_, record| {
        record
            .delivered_at
            .is_none_or(|delivered_at| delivered_at >= cutoff)
    });
    let referenced = state
        .outbox
        .values()
        .map(|record| record.event.incident_id.clone())
        .collect::<BTreeSet<_>>();
    state.incidents.retain(|incident_id, incident| {
        incident.active
            || referenced.contains(incident_id)
            || incident
                .recovered_at
                .is_none_or(|recovered_at| recovered_at >= cutoff)
    });
}

fn validate_state(state: &AlertState) -> Result<(), AlertStoreError> {
    if state.schema != STORE_SCHEMA || state.version != STORE_VERSION {
        return Err(AlertStoreError::InvalidState("unsupported schema"));
    }
    if state.incidents.len() > MAX_RECORDS || state.outbox.len() > MAX_RECORDS {
        return Err(AlertStoreError::InvalidState("record bound exceeded"));
    }
    let mut active_subjects = BTreeSet::new();
    for (incident_id, incident) in &state.incidents {
        let expected_incident_id = match incident.kind {
            IncidentKind::HostDown => stable_id(
                "incident",
                &[
                    &incident.host,
                    &incident.last_seen.to_string(),
                    &incident.opened_at.to_string(),
                ],
            ),
            IncidentKind::Backup => stable_id(
                "backup-incident",
                &[
                    &incident.host,
                    incident.backup_id.as_deref().unwrap_or_default(),
                    &incident.last_seen.to_string(),
                    &incident.opened_at.to_string(),
                ],
            ),
        };
        let valid_subject = match incident.kind {
            IncidentKind::HostDown => {
                incident.backup_id.is_none()
                    && incident.backup_label.is_none()
                    && incident.backup_state.is_none()
            }
            IncidentKind::Backup => {
                incident.backup_id.as_deref().is_some_and(|id| {
                    !id.is_empty() && id.len() <= 128 && !id.chars().any(char::is_control)
                }) && incident.backup_label.as_deref().is_some_and(|label| {
                    !label.is_empty() && label.len() <= 256 && !label.chars().any(char::is_control)
                }) && matches!(
                    incident.backup_state,
                    Some(BackupPostureState::Stale | BackupPostureState::Failed)
                )
            }
        };
        if incident_id != &incident.incident_id
            || incident_id != &expected_incident_id
            || !valid_subject
            || incident.host.is_empty()
            || incident.host.len() > 253
            || incident.role.is_empty()
            || incident.role.len() > 64
            || incident.heartbeat_interval_secs == 0
            || incident.last_seen > incident.opened_at
            || incident.highest_escalation > 2
            || (incident.active && incident.recovered_at.is_some())
            || (!incident.active && incident.recovered_at.is_none())
            || incident
                .recovered_at
                .is_some_and(|recovered_at| recovered_at < incident.opened_at)
        {
            return Err(AlertStoreError::InvalidState("invalid incident"));
        }
        let subject = incident.backup_id.clone().unwrap_or_default();
        if incident.active
            && !active_subjects.insert((incident.host.clone(), incident.kind, subject))
        {
            return Err(AlertStoreError::InvalidState(
                "multiple active incidents for subject",
            ));
        }
    }
    for (event_id, record) in &state.outbox {
        let Some(incident) = state.incidents.get(&record.event.incident_id) else {
            return Err(AlertStoreError::InvalidState("orphan outbox record"));
        };
        let stage = match record.event.kind {
            AlertEventKind::Down if record.event.sequence == 0 => 0,
            AlertEventKind::DownEscalated if matches!(record.event.sequence, 1 | 2) => {
                record.event.sequence
            }
            AlertEventKind::Recovered if record.event.sequence == 3 => 0,
            AlertEventKind::BackupStale if record.event.sequence == 0 => 0,
            AlertEventKind::BackupFailed if matches!(record.event.sequence, 0 | 1) => {
                record.event.sequence
            }
            AlertEventKind::BackupEscalated if matches!(record.event.sequence, 1 | 2) => {
                record.event.sequence
            }
            AlertEventKind::BackupRecovered if record.event.sequence == 3 => 0,
            _ => return Err(AlertStoreError::InvalidState("invalid event sequence")),
        };
        let kind_matches_incident = match record.event.kind {
            AlertEventKind::Down | AlertEventKind::DownEscalated | AlertEventKind::Recovered => {
                incident.kind == IncidentKind::HostDown
            }
            AlertEventKind::BackupStale
            | AlertEventKind::BackupFailed
            | AlertEventKind::BackupEscalated
            | AlertEventKind::BackupRecovered => incident.kind == IncidentKind::Backup,
        };
        if !kind_matches_incident {
            return Err(AlertStoreError::InvalidState(
                "event kind does not match incident",
            ));
        }
        let expected_event_id = stable_id(
            "event",
            &[
                &record.event.incident_id,
                record.event.kind.label(),
                &stage.to_string(),
            ],
        );
        let valid_level = match record.event.kind {
            AlertEventKind::Down | AlertEventKind::DownEscalated | AlertEventKind::BackupFailed => {
                record.event.level == "critical"
            }
            AlertEventKind::Recovered | AlertEventKind::BackupRecovered => {
                record.event.level == "recovery"
            }
            AlertEventKind::BackupStale => record.event.level == "warning",
            AlertEventKind::BackupEscalated => {
                matches!(record.event.level.as_str(), "warning" | "critical")
            }
        };
        let valid_event_schema = match incident.kind {
            IncidentKind::HostDown => {
                matches!(
                    record.event.schema.as_str(),
                    EVENT_SCHEMA | PREVIOUS_EVENT_SCHEMA
                )
            }
            IncidentKind::Backup => record.event.schema == EVENT_SCHEMA,
        };
        if event_id != &record.event.event_id
            || event_id != &expected_event_id
            || !valid_event_schema
            || record.event.host != incident.host
            || record.event.role != incident.role
            || record.event.last_seen != incident.last_seen
            || record.event.heartbeat_interval_secs != incident.heartbeat_interval_secs
            || !valid_level
            || record.event.occurred_at < incident.opened_at
            || record.event.age_seconds
                != record
                    .event
                    .occurred_at
                    .saturating_sub(incident.last_seen)
                    .max(0)
            || record.event.summary.is_empty()
            || record.event.summary.len() > 1_024
            || record.event.next_action.is_empty()
            || record.event.next_action.len() > 1_024
            || record.next_attempt_at < record.event.occurred_at
            || record.delivered_at.is_some() && record.attempts == 0
            || record
                .delivered_at
                .is_some_and(|delivered_at| delivered_at < record.event.occurred_at)
            || matches!(
                record.event.kind,
                AlertEventKind::Recovered | AlertEventKind::BackupRecovered
            ) && (incident.active || incident.recovered_at != Some(record.event.occurred_at))
        {
            return Err(AlertStoreError::InvalidState("invalid outbox record"));
        }
    }
    Ok(())
}

fn stable_id(domain: &str, parts: &[&str]) -> String {
    let mut digest = Sha256::new();
    digest.update(b"inspr.pharos.alert-id.v1\0");
    digest.update(domain.as_bytes());
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part.as_bytes());
    }
    let hash = digest.finalize();
    let mut encoded = String::with_capacity(64);
    for byte in hash {
        use std::fmt::Write as _;
        let _ = write!(encoded, "{byte:02x}");
    }
    format!("alert-{encoded}")
}

fn retry_delay_seconds(event_id: &str, attempts: u32) -> i64 {
    let exponent = attempts.saturating_sub(1).min(8);
    let base = 5_i64.saturating_mul(1_i64 << exponent).min(15 * 60);
    let jitter = event_id
        .as_bytes()
        .iter()
        .take(16)
        .fold(u64::from(attempts), |value, byte| {
            value.wrapping_mul(33).wrapping_add(u64::from(*byte))
        })
        % u64::try_from((base / 2).max(1)).unwrap_or(1);
    base.saturating_add(i64::try_from(jitter).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::{
        BackupConfiguredState, BackupEngine, BackupRunState, HostPreferences, NixFreshness,
        HOST_REPORT_VERSION,
    };

    fn host(last_seen: i64) -> Host {
        Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(last_seen),
            heartbeat_log: vec![last_seen],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness::default(),
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: HostPreferences::default(),
            requested_preferences: None,
        }
    }

    fn backup(id: &str, state: BackupPostureState, anchor: i64) -> BackupObservation {
        BackupObservation {
            id: id.to_string(),
            label: format!("Backup {id}"),
            engine: BackupEngine::Restic,
            state,
            configured: BackupConfiguredState::Enabled,
            summary: "sanitized backup posture".to_string(),
            target_label: Some("off-box repository".to_string()),
            repository_id: Some(format!("repository-{id}")),
            schedule: Some("hourly".to_string()),
            next_run_at: None,
            last_attempt_at: Some(anchor),
            last_attempt_state: Some(if state == BackupPostureState::Failed {
                BackupRunState::Failed
            } else {
                BackupRunState::Succeeded
            }),
            last_success_at: Some(anchor),
            snapshot_count: Some(3),
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: None,
        }
    }

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-alert-store-{}-{}-{label}.json",
            std::process::id(),
            crate::now_unix()
        ))
    }

    #[test]
    fn incident_and_outbox_survive_restart_with_stable_idempotency() {
        let path = temp_path("restart");
        let store = AlertStore::new(Some(path.clone())).unwrap();
        store.reconcile_hosts(&[host(100)], 1_000).unwrap();
        let due = store.due_event_ids(1_000);
        assert_eq!(due.len(), 1, "incident delivery is ordered");
        assert_eq!(
            store.pending_count(),
            2,
            "initial and escalation are durable"
        );
        let event_id = due[0].clone();
        let event = store.begin_attempt(&event_id, 1_000).unwrap();
        assert_eq!(event.event_id, event_id);

        let reloaded = AlertStore::new(Some(path.clone())).unwrap();
        reloaded.reconcile_hosts(&[host(100)], 1_001).unwrap();
        assert_eq!(reloaded.event(&event_id).unwrap().attempts, 1);
        assert!(!reloaded.due_event_ids(1_001).contains(&event_id));
        reloaded.mark_delivered(&event_id, 1_002).unwrap();
        let delivered = AlertStore::new(Some(path.clone())).unwrap();
        assert!(delivered.event(&event_id).unwrap().delivered_at.is_some());
        assert!(!delivered.due_event_ids(i64::MAX).contains(&event_id));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn escalation_and_recovery_events_are_enqueued_once() {
        let store = AlertStore::new(None).unwrap();
        store.reconcile_hosts(&[host(900)], 1_201).unwrap();
        assert_eq!(store.pending_count(), 1);
        store.reconcile_hosts(&[host(900)], 1_801).unwrap();
        assert_eq!(store.pending_count(), 2);
        store.reconcile_hosts(&[host(900)], 4_501).unwrap();
        assert_eq!(store.pending_count(), 3);
        store.reconcile_hosts(&[host(4_500)], 4_501).unwrap();
        assert_eq!(store.pending_count(), 4);
        store.reconcile_hosts(&[host(4_500)], 4_502).unwrap();
        assert_eq!(store.pending_count(), 4, "recovery is idempotent");
    }

    #[test]
    fn backup_incident_escalates_transitions_to_failed_and_recovers_once() {
        let store = AlertStore::new(None).unwrap();
        let mut reporting = host(1_000);
        reporting.backup_observations = vec![backup("restic-main", BackupPostureState::Stale, 100)];

        store.reconcile_hosts(&[reporting.clone()], 1_000).unwrap();
        assert_eq!(
            store.pending_count(),
            2,
            "stale incident and first escalation are queued"
        );
        store.reconcile_hosts(&[reporting.clone()], 1_000).unwrap();
        assert_eq!(store.pending_count(), 2, "stale events are idempotent");

        reporting.last_seen = Some(4_000);
        store.reconcile_hosts(&[reporting.clone()], 4_000).unwrap();
        assert_eq!(store.pending_count(), 3, "second escalation is queued once");

        reporting.backup_observations[0].state = BackupPostureState::Failed;
        reporting.backup_observations[0].last_attempt_state = Some(BackupRunState::Failed);
        reporting.last_seen = Some(4_001);
        store.reconcile_hosts(&[reporting.clone()], 4_001).unwrap();
        assert_eq!(store.pending_count(), 4, "failure raises severity once");
        reporting.last_seen = Some(4_002);
        store.reconcile_hosts(&[reporting.clone()], 4_002).unwrap();
        assert_eq!(
            store.pending_count(),
            4,
            "failure transition is deduplicated"
        );

        reporting.backup_observations[0].state = BackupPostureState::Healthy;
        reporting.backup_observations[0].last_attempt_state = Some(BackupRunState::Succeeded);
        reporting.last_seen = Some(4_003);
        store.reconcile_hosts(&[reporting.clone()], 4_003).unwrap();
        assert_eq!(store.pending_count(), 5, "healthy posture queues recovery");
        reporting.last_seen = Some(4_004);
        store.reconcile_hosts(&[reporting], 4_004).unwrap();
        assert_eq!(store.pending_count(), 5, "recovery is idempotent");

        let state = store.state.lock().unwrap();
        let kinds = state
            .outbox
            .values()
            .map(|record| record.event.kind)
            .collect::<Vec<_>>();
        assert!(kinds.contains(&AlertEventKind::BackupStale));
        assert!(kinds.contains(&AlertEventKind::BackupFailed));
        assert!(kinds.contains(&AlertEventKind::BackupRecovered));
        assert_eq!(
            kinds
                .iter()
                .filter(|kind| **kind == AlertEventKind::BackupEscalated)
                .count(),
            2
        );
        let failed = state
            .outbox
            .values()
            .find(|record| record.event.kind == AlertEventKind::BackupFailed)
            .unwrap();
        let telegram = crate::alerting::telegram_alert_text(&failed.event);
        assert!(telegram.contains("Pharos critical alert"));
        assert!(telegram.contains("Backup restic-main backup reported failure"));
    }

    #[test]
    fn backup_preferences_suppress_delivery_and_close_active_incidents_silently() {
        let store = AlertStore::new(None).unwrap();
        let mut reporting = host(1_000);
        reporting.backup_observations = vec![backup("restic-main", BackupPostureState::Stale, 995)];
        reporting.preferences.alerts.suppress_backup = true;
        store.reconcile_hosts(&[reporting.clone()], 1_000).unwrap();
        assert_eq!(store.pending_count(), 0);

        reporting.preferences.alerts.suppress_backup = false;
        store.reconcile_hosts(&[reporting.clone()], 1_001).unwrap();
        assert_eq!(store.pending_count(), 1);

        reporting.preferences.alerts.suppress_backup = true;
        store.reconcile_hosts(&[reporting.clone()], 1_002).unwrap();
        assert_eq!(
            store.pending_count(),
            0,
            "suppression drops pending delivery"
        );
        reporting.preferences.alerts.suppress_backup = false;
        reporting.backup_observations[0].state = BackupPostureState::Healthy;
        store.reconcile_hosts(&[reporting], 1_003).unwrap();
        assert_eq!(
            store.pending_count(),
            0,
            "suppression closes without a misleading recovery"
        );
    }

    #[test]
    fn host_down_and_multiple_backup_incidents_are_independent() {
        let store = AlertStore::new(None).unwrap();
        let mut reporting = host(100);
        reporting.backup_observations = vec![
            backup("restic-main", BackupPostureState::Stale, 990),
            backup("restic-secondary", BackupPostureState::Failed, 995),
        ];

        store.reconcile_hosts(&[reporting], 1_000).unwrap();
        let state = store.state.lock().unwrap();
        assert_eq!(
            state
                .incidents
                .values()
                .filter(|incident| incident.active)
                .count(),
            3
        );
        assert_eq!(
            state
                .incidents
                .values()
                .filter(|incident| incident.kind == IncidentKind::Backup)
                .count(),
            2
        );
    }

    #[test]
    fn duplicate_backup_subjects_fail_the_alert_cycle_without_partial_incidents() {
        let store = AlertStore::new(None).unwrap();
        let mut reporting = host(1_000);
        reporting.backup_observations = vec![
            backup("restic-main", BackupPostureState::Stale, 995),
            backup("restic-main", BackupPostureState::Failed, 996),
        ];

        assert!(matches!(
            store.reconcile_hosts(&[reporting], 1_000),
            Err(AlertStoreError::InvalidState(
                "duplicate backup observation subject"
            ))
        ));
        assert_eq!(store.pending_count(), 0);
        assert!(store.state.lock().unwrap().incidents.is_empty());
    }

    #[test]
    fn version_one_host_incidents_migrate_and_persist_as_version_two() {
        let path = temp_path("v1-migration");
        let store = AlertStore::new(Some(path.clone())).unwrap();
        store.reconcile_hosts(&[host(100)], 1_000).unwrap();

        let mut fixture: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        fixture["schema"] = serde_json::json!(PREVIOUS_STORE_SCHEMA);
        fixture["version"] = serde_json::json!(PREVIOUS_STORE_VERSION);
        for incident in fixture["incidents"].as_object_mut().unwrap().values_mut() {
            incident.as_object_mut().unwrap().remove("kind");
        }
        for record in fixture["outbox"].as_object_mut().unwrap().values_mut() {
            record["event"]["schema"] = serde_json::json!(PREVIOUS_EVENT_SCHEMA);
        }
        std::fs::write(&path, serde_json::to_vec(&fixture).unwrap()).unwrap();

        let migrated = AlertStore::new(Some(path.clone())).unwrap();
        migrated.reconcile_hosts(&[host(100)], 1_001).unwrap();
        let persisted: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(persisted["version"], STORE_VERSION);
        assert_eq!(persisted["schema"], STORE_SCHEMA);
        assert!(persisted["incidents"]
            .as_object()
            .unwrap()
            .values()
            .all(|incident| incident["kind"] == "host_down"));
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn failed_atomic_write_rolls_back_outbox_mutation() {
        let path = temp_path("rollback");
        let store = AlertStore::new(Some(path.clone())).unwrap();
        store.reconcile_hosts(&[host(100)], 1_000).unwrap();
        let event_id = store.due_event_ids(1_000)[0].clone();
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();

        assert!(matches!(
            store.begin_attempt(&event_id, 1_000),
            Err(AlertStoreError::Persistence(_))
        ));
        assert_eq!(store.event(&event_id).unwrap().attempts, 0);
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn retries_are_bounded_exponential_and_jittered() {
        let id = stable_id("event", &["fixture"]);
        let first = retry_delay_seconds(&id, 1);
        let second = retry_delay_seconds(&id, 2);
        let capped = retry_delay_seconds(&id, 1_000);
        assert!((5..8).contains(&first));
        assert!(second > first);
        assert!((900..1_350).contains(&capped));
    }

    #[test]
    fn worker_health_fails_readiness_when_stopped_or_stale() {
        let disabled = AlertWorkerHealth::new(false, 100, 5);
        assert!(disabled.snapshot(10_000).ready);

        let health = AlertWorkerHealth::new(true, 100, 5);
        assert!(!health.snapshot(100).ready);
        health.mark_running(true);
        assert!(health.snapshot(100).ready);
        health.record_cycle(110, true, 2);
        health.record_delivery(true);
        health.record_delivery(false);
        let healthy = health.snapshot(139);
        assert!(healthy.ready);
        assert_eq!(healthy.pending_events, 2);
        assert_eq!(healthy.deliveries_total, 1);
        assert_eq!(healthy.delivery_failures_total, 1);
        assert!(!health.snapshot(141).ready);
        health.mark_running(false);
        assert!(!health.snapshot(110).ready);
    }
}
