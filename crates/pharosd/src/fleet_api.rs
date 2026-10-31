//! `GET /fleet.json`: what the pages say, for the operator CLI. The words come from
//! the functions that draw the pages, so the two cannot disagree.

use axum::extract::State;
use axum::http::header;
use axum::response::{IntoResponse, Response};
use axum::Json;
use pharos_core::contact::{ContactSource, ContactState};
use pharos_core::fleet_data::{FleetCveState, KERNEL_COMPONENT};
use pharos_core::updates_due::{UpdatesSource, UpdatesState};
use serde::Serialize;

use crate::fleet_view::{short_span, span, FleetView, HostRow};
use crate::pages::{
    contact_short_label, contact_short_source, cve_title, data_age, due_text, fleet_counts,
    security_text, severity_parts, update_note_parts, watch_counts,
};
use crate::ui::fleet_view;
use crate::AppState;

const FLEET_VIEW_SCHEMA: &str = "inspr.pharos.fleet-view.v1";

#[derive(Serialize)]
struct FleetDocument {
    schema: &'static str,
    generated_at: i64,
    uptime: String,
    data_file: DataFile,
    summary: Summary,
    beacons: Beacons,
    hosts: Vec<ApiHost>,
    cves: Vec<ApiCve>,
    updates: Vec<ApiUpdate>,
}

#[derive(Serialize)]
struct DataFile {
    configured: bool,
    /// Why the file can't be trusted. The last good copy may still be in use.
    problem: Option<String>,
    schema_version: Option<u64>,
    updated_ago: Option<String>,
    hosts: usize,
    watched_cves: usize,
}

#[derive(Serialize)]
struct Summary {
    hosts: usize,
    affected: u32,
    cant_check: u32,
    reboots_due: u32,
}

#[derive(Serialize)]
struct Beacons {
    reporting: usize,
    offline: usize,
    never_reported: usize,
}

#[derive(Serialize)]
struct ApiHost {
    name: String,
    site: Option<String>,
    source: &'static str,
    contact: String,
    beacon: bool,
    last_seen: Option<String>,
    running: Option<String>,
    next_boot: Option<String>,
    security: String,
    reboot_due: bool,
    hand_declared: bool,
    stale: bool,
}

#[derive(Serialize)]
struct ApiCve {
    id: String,
    name: String,
    severity: String,
    state: &'static str,
    source: &'static str,
    hosts: String,
}

#[derive(Serialize)]
struct ApiUpdate {
    host: String,
    state: &'static str,
    due: String,
    source: &'static str,
    age: Option<String>,
    stale: bool,
}

/// A host that has reported, or that the file expects a report from.
fn is_beacon_host(row: &HostRow) -> bool {
    row.report.is_some() || row.contact.state == ContactState::NeverReported
}

fn api_host(view: &FleetView, row: &HostRow) -> ApiHost {
    let posture = row.report.as_ref().and_then(|host| host.kernel.as_ref());
    let running = posture.and_then(|posture| posture.running_version.clone());
    ApiHost {
        name: row.name.clone(),
        site: row
            .section
            .and_then(|section| view.data.as_deref()?.sections.get(section))
            .map(|section| section.name.clone()),
        source: contact_short_source(row),
        contact: contact_short_label(&row.contact),
        beacon: is_beacon_host(row),
        last_seen: row
            .report
            .as_ref()
            .and_then(|host| host.last_seen)
            .map(|at| short_span(view.now.saturating_sub(at).max(0) as u64)),
        next_boot: row
            .next_boot()
            .map(ToString::to_string)
            .or_else(|| running.clone()),
        running,
        security: security_text(view, row),
        reboot_due: row.reboot_due(),
        hand_declared: row.declared_check(view).is_some(),
        stale: update_note_parts(view, row).is_some_and(|note| note.stale),
    }
}

fn api_update(row: &HostRow) -> ApiUpdate {
    let state = match row.updates.state {
        UpdatesState::Due => "due",
        UpdatesState::UpToDate => "up_to_date",
        UpdatesState::LastKnownUpToDate => "last_known",
        UpdatesState::HandDeclared => "hand_declared",
        UpdatesState::Unknown => "unknown",
    };
    let (source, age, stale) = match &row.updates.source {
        UpdatesSource::Report {
            age_secs, stale, ..
        } => ("beacon", Some(short_span(*age_secs)), *stale),
        UpdatesSource::Declared {
            verification_stale, ..
        } => ("hand-declared", None, *verification_stale),
        UpdatesSource::Nothing => (
            match row.contact.source {
                ContactSource::Probe => "probe",
                ContactSource::Beacon => "beacon",
                ContactSource::Nothing => "nothing",
            },
            None,
            false,
        ),
    };
    ApiUpdate {
        host: row.name.clone(),
        state,
        due: due_text(row),
        source,
        age,
        stale,
    }
}

fn api_cve(view: &FleetView, index: usize) -> Option<ApiCve> {
    let cve = view.data.as_deref()?.cves.get(index)?;
    Some(ApiCve {
        id: cve.id.clone(),
        name: cve_title(cve).to_string(),
        severity: severity_parts(cve.severity).0.to_lowercase(),
        state: match cve.state {
            FleetCveState::Open => "open",
            FleetCveState::Mitigated => "mitigated",
            FleetCveState::Fixed => "fixed",
        },
        source: if cve.component == KERNEL_COMPONENT {
            "kernel"
        } else {
            "declared"
        },
        hosts: watch_counts(view, index),
    })
}

fn document(view: &FleetView, started_at: i64) -> FleetDocument {
    let data = view.data.as_deref();
    let counts = fleet_counts(view);
    let beacons_in = |states: fn(&ContactState) -> bool| {
        view.rows
            .iter()
            .filter(|row| is_beacon_host(row) && states(&row.contact.state))
            .count()
    };
    FleetDocument {
        schema: FLEET_VIEW_SCHEMA,
        generated_at: view.now,
        uptime: span(view.now.saturating_sub(started_at).max(0) as u64),
        data_file: DataFile {
            configured: view.configured,
            problem: view.problem.clone(),
            schema_version: data.map(|data| data.schema_version),
            updated_ago: data_age(view),
            hosts: data.map_or(0, |data| {
                data.sections
                    .iter()
                    .map(|section| section.hosts.len())
                    .sum()
            }),
            watched_cves: view.watchlist.len(),
        },
        summary: Summary {
            hosts: view.rows.len(),
            affected: counts.affected,
            cant_check: counts.unknown,
            reboots_due: counts.reboots,
        },
        beacons: Beacons {
            reporting: beacons_in(|state| {
                matches!(state, ContactState::Online | ContactState::Late)
            }),
            offline: beacons_in(|state| {
                !matches!(
                    state,
                    ContactState::Online | ContactState::Late | ContactState::NeverReported
                )
            }),
            never_reported: beacons_in(|state| *state == ContactState::NeverReported),
        },
        hosts: view.rows.iter().map(|row| api_host(view, row)).collect(),
        cves: view
            .watchlist
            .iter()
            .filter_map(|index| api_cve(view, *index))
            .collect(),
        updates: view.rows.iter().map(api_update).collect(),
    }
}

pub(crate) async fn fleet_json(State(state): State<AppState>) -> Response {
    let view = fleet_view(&state);
    (
        [(header::CACHE_CONTROL, "no-store")],
        Json(document(&view, state.started_at)),
    )
        .into_response()
}
