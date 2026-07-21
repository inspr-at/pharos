//! Durable host-availability incidents and at-least-once alert outbox.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Mutex;

use pharos_core::{liveness, Host, Liveness};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::durable_file::{atomic_write_json, load_optional_json, DurableFileError};

const STORE_SCHEMA: &str = "inspr.pharos.alert-state.v1";
const STORE_VERSION: u16 = 1;
const EVENT_SCHEMA: &str = "inspr.pharos.alert-event.v1";
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
}

impl AlertEventKind {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Down => "host_down",
            Self::DownEscalated => "host_down_escalated",
            Self::Recovered => "host_recovered",
        }
    }
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
    host: String,
    role: String,
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
        let state = match path.as_deref() {
            Some(path) => load_optional_json::<AlertState>(path)?.unwrap_or_default(),
            None => AlertState::default(),
        };
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

fn reconcile(state: &mut AlertState, hosts: &[Host], now: i64) -> Result<(), AlertStoreError> {
    prune_history(state, now);
    let mut seen_hosts = BTreeSet::new();
    for host in hosts {
        seen_hosts.insert(host.name.clone());
        let active_id = state
            .incidents
            .values()
            .find(|incident| incident.active && incident.host == host.name)
            .map(|incident| incident.incident_id.clone());
        let down = host.last_seen.is_some()
            && liveness(host.last_seen, host.heartbeat_interval_secs, now) == Liveness::Down;
        if down && !host.preferences.suppresses_down_alerts() {
            let last_seen = host.last_seen.expect("down host has last_seen");
            let incident_id = match active_id {
                Some(incident_id) => incident_id,
                None => open_incident(state, host, last_seen, now)?,
            };
            enqueue_escalations(state, &incident_id, now)?;
        } else if let Some(incident_id) = active_id {
            if down {
                close_incident(state, &incident_id, now)?;
            } else {
                recover_incident(state, &incident_id, now)?;
            }
        }
    }

    let vanished = state
        .incidents
        .values()
        .filter(|incident| incident.active && !seen_hosts.contains(&incident.host))
        .map(|incident| incident.incident_id.clone())
        .collect::<Vec<_>>();
    for incident_id in vanished {
        close_incident(state, &incident_id, now)?;
    }
    Ok(())
}

fn open_incident(
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
        host: host.name.clone(),
        role: host.role.clone(),
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
    for stage in (incident.highest_escalation + 1)..=target {
        enqueue_event(state, &incident, AlertEventKind::DownEscalated, stage, now)?;
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
    enqueue_event(state, &incident, AlertEventKind::Recovered, 0, now)?;
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
    };
    let event = AlertEvent {
        schema: EVENT_SCHEMA.to_string(),
        event_id: event_id.clone(),
        incident_id: incident.incident_id.clone(),
        kind,
        sequence: match kind {
            AlertEventKind::Down => 0,
            AlertEventKind::DownEscalated => stage,
            AlertEventKind::Recovered => 3,
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
    let mut active_hosts = BTreeSet::new();
    for (incident_id, incident) in &state.incidents {
        let expected_incident_id = stable_id(
            "incident",
            &[
                &incident.host,
                &incident.last_seen.to_string(),
                &incident.opened_at.to_string(),
            ],
        );
        if incident_id != &incident.incident_id
            || incident_id != &expected_incident_id
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
        if incident.active && !active_hosts.insert(&incident.host) {
            return Err(AlertStoreError::InvalidState(
                "multiple active incidents for host",
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
            _ => return Err(AlertStoreError::InvalidState("invalid event sequence")),
        };
        let expected_event_id = stable_id(
            "event",
            &[
                &record.event.incident_id,
                record.event.kind.label(),
                &stage.to_string(),
            ],
        );
        let expected_level = match record.event.kind {
            AlertEventKind::Down | AlertEventKind::DownEscalated => "critical",
            AlertEventKind::Recovered => "recovery",
        };
        if event_id != &record.event.event_id
            || event_id != &expected_event_id
            || record.event.schema != EVENT_SCHEMA
            || record.event.host != incident.host
            || record.event.role != incident.role
            || record.event.last_seen != incident.last_seen
            || record.event.heartbeat_interval_secs != incident.heartbeat_interval_secs
            || record.event.level != expected_level
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
            || matches!(record.event.kind, AlertEventKind::Recovered)
                && (incident.active || incident.recovered_at != Some(record.event.occurred_at))
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
    use pharos_core::{HostPreferences, NixFreshness, HOST_REPORT_VERSION};

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
