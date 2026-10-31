//! Joins the data file, beacon reports and probes into what the pages show.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use pharos_core::contact::{
    host_contact, BeaconEvidence, ContactPolicy, ContactState, ContactTone, HostContact,
    ProbeEvidence,
};
use pharos_core::cve_status::{
    declared_verification_stale, host_cve_status, CveStatus, CveStatusSource, HostCveStatus,
    KernelReport,
};
use pharos_core::fleet_data::{
    CveSeverity, FleetCve, FleetCveState, FleetData, FleetHost, HandledCves,
};
use pharos_core::updates_due::{host_updates, HostUpdates, UpdateDue, UpdatesSource};
use pharos_core::{liveness, Host, KernelPosture, KernelPostureState};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::fleet_data::FleetDataView;
use crate::host_probes::HostProbeObservation;

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// A date for reading: "24 Oct", with the year when it is not this one.
pub(crate) fn short_date(at: i64, now: i64) -> String {
    let Ok(date) = OffsetDateTime::from_unix_timestamp(at) else {
        return "unknown date".to_string();
    };
    let month = MONTHS[usize::from(u8::from(date.month())) - 1];
    let this_year = OffsetDateTime::from_unix_timestamp(now).map(|now| now.year());
    if this_year == Ok(date.year()) {
        format!("{} {month}", date.day())
    } else {
        format!("{} {month} {}", date.day(), date.year())
    }
}

/// The same for a `YYYY-MM-DD` date from the file.
pub(crate) fn short_day(day: &str, now: i64) -> String {
    OffsetDateTime::parse(&format!("{day}T00:00:00Z"), &Rfc3339)
        .map(|date| short_date(date.unix_timestamp(), now))
        .unwrap_or_else(|_| day.to_string())
}

fn verified_at(value: &str) -> Option<i64> {
    OffsetDateTime::parse(value, &Rfc3339)
        .ok()
        .map(OffsetDateTime::unix_timestamp)
}

/// A time as a length: "12 min", "5 h", "2 d".
pub(crate) fn span(seconds: u64) -> String {
    match seconds {
        seconds if seconds < 60 => "under 1 min".to_string(),
        seconds if seconds < 3_600 => format!("{} min", seconds / 60),
        seconds if seconds < 86_400 => format!("{} h", seconds / 3_600),
        seconds => format!("{} d", seconds / 86_400),
    }
}

/// The same in a table's width: "12m", "5h", "2d".
pub(crate) fn short_span(seconds: u64) -> String {
    match seconds {
        seconds if seconds < 60 => "<1m".to_string(),
        seconds if seconds < 3_600 => format!("{}m", seconds / 60),
        seconds if seconds < 86_400 => format!("{}h", seconds / 3_600),
        seconds => format!("{}d", seconds / 86_400),
    }
}

/// `major.minor` of a plain kernel version, for naming the missing fix line.
fn kernel_branch(version: &str) -> Option<String> {
    let parts: Vec<&str> = version.split('.').collect();
    let plain = parts
        .iter()
        .all(|part| !part.is_empty() && part.chars().all(|c| c.is_ascii_digit()));
    (plain && parts.len() >= 2).then(|| format!("{}.{}", parts[0], parts[1]))
}

pub(crate) struct CveOnHost {
    /// Index into the file's `cves`.
    pub(crate) index: usize,
    pub(crate) status: HostCveStatus,
}

pub(crate) struct HostRow {
    pub(crate) name: String,
    /// Index into the file's `sections`; `None` when it is not in the file.
    pub(crate) section: Option<usize>,
    pub(crate) declared: Option<FleetHost>,
    pub(crate) report: Option<Host>,
    pub(crate) contact: HostContact,
    pub(crate) updates: HostUpdates,
    pub(crate) cves: Vec<CveOnHost>,
}

/// One host's watched CVEs, counted.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct Security {
    /// Affected or waiting for a reboot, by severity, most severe first.
    pub(crate) by_severity: [u32; 4],
    pub(crate) unknown: u32,
    /// Why it cannot be checked, when every unknown CVE has the same reason.
    pub(crate) reason: Option<String>,
}

impl Security {
    pub(crate) fn affected(&self) -> u32 {
        self.by_severity.iter().sum()
    }

    pub(crate) fn critical(&self) -> bool {
        self.by_severity[CveSeverity::Critical as usize] > 0
    }
}

fn reboot_target(posture: &KernelPosture) -> Option<&str> {
    (posture.state == KernelPostureState::RebootRequired)
        .then_some(posture.expected_version.as_deref())
        .flatten()
}

impl HostRow {
    pub(crate) fn role(&self) -> Option<&str> {
        self.declared
            .as_ref()
            .and_then(|host| host.role.as_deref())
            .or_else(|| self.report.as_ref().map(|host| host.role.as_str()))
            .filter(|role| !role.is_empty())
    }

    fn report_posture(&self) -> Option<&KernelPosture> {
        self.report.as_ref().and_then(|host| host.kernel.as_ref())
    }

    fn report_decides(&self) -> bool {
        matches!(self.updates.source, UpdatesSource::Report { .. })
    }

    /// The report's posture, while the report is what Updates rests on. Once a
    /// newer check of the file replaces it, everything about the kernel follows.
    pub(crate) fn live_posture(&self) -> Option<&KernelPosture> {
        self.report_posture().filter(|_| self.report_decides())
    }

    /// The running kernel from whichever evidence Updates rests on. A report that
    /// can't name its kernel leaves none, not an older hand-written one.
    pub(crate) fn kernel(&self) -> Option<&str> {
        if self.report_decides() {
            self.reported_kernel()
        } else {
            self.declared
                .as_ref()
                .and_then(|host| host.kernel.as_deref())
        }
    }

    pub(crate) fn next_boot(&self) -> Option<&str> {
        self.live_posture().and_then(reboot_target)
    }

    /// What a computed CVE status rests on, even once the file has replaced it.
    pub(crate) fn reported_kernel(&self) -> Option<&str> {
        self.report_posture()
            .and_then(|posture| posture.running_version.as_deref())
    }

    pub(crate) fn reported_next_boot(&self) -> Option<&str> {
        self.report_posture().and_then(reboot_target)
    }

    pub(crate) fn os(&self) -> Option<&str> {
        self.declared
            .as_ref()
            .and_then(|host| host.os.as_deref())
            .or_else(|| {
                self.report
                    .as_ref()
                    .filter(|host| host.is_nix)
                    .map(|_| "NixOS")
            })
    }

    /// A report that decides speaks first. Not every report names a release, and
    /// the file's value is then all there is.
    pub(crate) fn os_version(&self) -> Option<&str> {
        let declared = self
            .declared
            .as_ref()
            .and_then(|host| host.version.as_deref());
        if self.report_decides() {
            self.nixpkgs_channel().or(declared)
        } else {
            declared.or_else(|| self.nixpkgs_channel())
        }
    }

    /// The check behind a release shown under a report that names none. A heartbeat
    /// says nothing about that value, so it keeps its own date and stale label.
    pub(crate) fn file_release_check(&self, now: i64) -> Option<(Option<&str>, bool)> {
        if !self.report_decides() || self.nixpkgs_channel().is_some() {
            return None;
        }
        let host = self
            .declared
            .as_ref()
            .filter(|host| host.version.is_some())?;
        let last_verified = host.last_verified.as_deref();
        Some((
            last_verified,
            declared_verification_stale(last_verified, now),
        ))
    }

    /// The release a report's nixpkgs follows, without its `nixos-` prefix.
    pub(crate) fn nixpkgs_channel(&self) -> Option<&str> {
        self.report
            .as_ref()
            .and_then(|host| host.freshness.nixpkgs_channel.as_deref())
            .map(|channel| channel.strip_prefix("nixos-").unwrap_or(channel))
    }

    pub(crate) fn on(&self, index: usize) -> Option<&CveOnHost> {
        self.cves.iter().find(|on| on.index == index)
    }

    pub(crate) fn declared_note(&self, cve: &FleetCve) -> Option<&str> {
        self.declared
            .as_ref()
            .and_then(|host| host.cve.get(&cve.id))
            .and_then(|status| status.note.as_deref())
    }

    /// Why this host cannot be checked for this CVE.
    pub(crate) fn unknown_reason(&self, cve: &FleetCve, on: &CveOnHost) -> String {
        match on.status.source {
            CveStatusSource::Computed { .. } => {
                match self.reported_kernel().and_then(kernel_branch) {
                    Some(branch) => format!("no fix line for {branch}"),
                    None => "kernel version not readable".to_string(),
                }
            }
            CveStatusSource::Declared { .. } => self
                .declared_note(cve)
                .unwrap_or("not checked yet")
                .to_string(),
            CveStatusSource::Nothing if self.declared.is_none() => {
                "not in the data file".to_string()
            }
            CveStatusSource::Nothing if self.contact.state == ContactState::NeverReported => {
                "never reported".to_string()
            }
            CveStatusSource::Nothing => "not declared yet".to_string(),
        }
    }

    pub(crate) fn security(&self, view: &FleetView) -> Security {
        let mut security = Security::default();
        let mut reasons = BTreeSet::new();
        // Without the file there is no list to be clear of.
        let Some(data) = view.data.as_deref() else {
            security.unknown = 1;
            security.reason = Some("no data file".to_string());
            return security;
        };
        for index in &view.watchlist {
            let (Some(cve), Some(on)) = (data.cves.get(*index), self.on(*index)) else {
                continue;
            };
            match on.status.status {
                CveStatus::Affected | CveStatus::RebootDue => {
                    security.by_severity[cve.severity as usize] += 1;
                }
                CveStatus::Unknown => {
                    security.unknown += 1;
                    reasons.insert(self.unknown_reason(cve, on));
                }
                CveStatus::Fixed | CveStatus::NotApplicable => {}
            }
        }
        if reasons.len() == 1 {
            security.reason = reasons.into_iter().next();
        }
        security
    }

    /// The oldest check of a hand-declared status on a watched CVE, and whether
    /// any of them has gone stale. `None` when no status is hand-declared.
    pub(crate) fn declared_check(&self, view: &FleetView) -> Option<(Option<i64>, bool)> {
        let mut found = false;
        let mut oldest: Option<i64> = None;
        let mut any_stale = false;
        for index in &view.watchlist {
            let Some(on) = self.on(*index) else { continue };
            if let CveStatusSource::Declared {
                last_verified,
                verification_stale,
            } = &on.status.source
            {
                found = true;
                any_stale |= *verification_stale;
                if let Some(at) = last_verified.as_deref().and_then(verified_at) {
                    oldest = Some(oldest.map_or(at, |oldest| oldest.min(at)));
                }
            }
        }
        found.then_some((oldest, any_stale))
    }

    /// How old the report behind a watched CVE is, when that report is stale.
    /// A newer hand-declared check of the versions says nothing about it.
    pub(crate) fn stale_computed_age(&self, view: &FleetView) -> Option<u64> {
        view.watchlist
            .iter()
            .filter_map(|index| self.on(*index))
            .filter_map(|on| match on.status.source {
                CveStatusSource::Computed {
                    age_secs,
                    stale: true,
                } => Some(age_secs),
                _ => None,
            })
            .max()
    }

    /// Lower needs attention sooner.
    pub(crate) fn attention_rank(&self, view: &FleetView) -> u8 {
        let security = self.security(view);
        if let Some(severity) = security.by_severity.iter().position(|count| *count > 0) {
            return severity as u8;
        }
        if self.contact.tone == ContactTone::Danger {
            return 4;
        }
        if !self.updates.due.is_empty() {
            return 5;
        }
        if self.contact.tone == ContactTone::Warn {
            return 6;
        }
        if security.unknown > 0 {
            return 7;
        }
        8
    }

    pub(crate) fn reboot_due(&self) -> bool {
        self.updates
            .due
            .iter()
            .any(|due| matches!(due, UpdateDue::Reboot { .. }))
    }

    /// What a search looks through, in lower case.
    pub(crate) fn search_text(&self) -> String {
        format!("{} {}", self.name, self.role().unwrap_or_default()).to_lowercase()
    }
}

/// Everything one page render needs, at one moment.
pub(crate) struct FleetView {
    pub(crate) data: Option<Arc<FleetData>>,
    pub(crate) problem: Option<String>,
    pub(crate) configured: bool,
    pub(crate) now: i64,
    pub(crate) rows: Vec<HostRow>,
    /// Indices into the file's `cves`, most urgent first.
    pub(crate) watchlist: Vec<usize>,
}

impl FleetView {
    pub(crate) fn build(
        fleet_data: Option<FleetDataView>,
        hosts: Vec<Host>,
        probes: BTreeMap<String, HostProbeObservation>,
        now: i64,
    ) -> Self {
        let configured = fleet_data.is_some();
        let (data, problem) = fleet_data
            .map(|view| (view.data, view.problem))
            .unwrap_or_default();
        let mut reports: BTreeMap<String, Host> = hosts
            .into_iter()
            .map(|host| (host.name.clone(), host))
            .collect();
        let mut probes = probes;
        let mut rows = Vec::new();
        if let Some(data) = data.as_deref() {
            for (section, entry) in data.sections.iter().enumerate() {
                for host in &entry.hosts {
                    let report = reports.remove(&host.name);
                    let probe = probes.remove(&host.name);
                    rows.push(host_row(
                        host.name.clone(),
                        Some(data),
                        Some(section),
                        Some(host.clone()),
                        report,
                        probe,
                        now,
                    ));
                }
            }
        }
        // Anything that reports or answers but is not in the file stays on the
        // page, in its own group, so nothing vanishes silently.
        let others: BTreeSet<String> = reports.keys().chain(probes.keys()).cloned().collect();
        for name in others {
            let report = reports.remove(&name);
            let probe = probes.remove(&name);
            rows.push(host_row(
                name,
                data.as_deref(),
                None,
                None,
                report,
                probe,
                now,
            ));
        }

        let watchlist = data
            .as_deref()
            .map(|data| watched(data, &rows, now))
            .unwrap_or_default();
        Self {
            data,
            problem,
            configured,
            now,
            rows,
            watchlist,
        }
    }

    pub(crate) fn row(&self, name: &str) -> Option<&HostRow> {
        self.rows.iter().find(|row| row.name == name)
    }

    /// The handled history, without the CVEs a host keeps on the watchlist.
    pub(crate) fn handled_history(&self) -> Vec<HandledCves> {
        let Some(data) = self.data.as_deref() else {
            return Vec::new();
        };
        let watched: Vec<&str> = self
            .watchlist
            .iter()
            .filter_map(|index| data.cves.get(*index))
            .map(|cve| cve.id.as_str())
            .collect();
        data.handled_history_without(self.now, &watched)
    }

    /// The latest report from any host.
    pub(crate) fn last_report(&self) -> Option<i64> {
        self.rows
            .iter()
            .filter_map(|row| row.report.as_ref().and_then(|host| host.last_seen))
            .max()
    }

    /// The hosts in one status for one CVE, in page order.
    pub(crate) fn hosts_with(
        &self,
        index: usize,
        statuses: &[CveStatus],
    ) -> Vec<(&HostRow, &CveOnHost)> {
        self.rows
            .iter()
            .filter_map(|row| row.on(index).map(|on| (row, on)))
            .filter(|(_, on)| statuses.contains(&on.status.status))
            .collect()
    }
}

/// The file's watchlist, plus any fixed CVE past its days that a host is still on
/// or can't answer for, so time alone cannot make it look handled. A kernel report
/// or a status in the file lets it go. A host the file doesn't list has no way to get
/// that status, so it only holds a CVE its own report can't answer.
fn watched(data: &FleetData, rows: &[HostRow], now: i64) -> Vec<usize> {
    let listed = data.watchlist(now);
    let needed = |index: usize| {
        rows.iter().any(|row| {
            row.on(index).is_some_and(|on| match on.status.status {
                CveStatus::Affected | CveStatus::RebootDue => true,
                CveStatus::Unknown => {
                    row.declared.is_some() || !matches!(on.status.source, CveStatusSource::Nothing)
                }
                CveStatus::Fixed | CveStatus::NotApplicable => false,
            })
        })
    };
    let mut watched: Vec<usize> = data
        .cves
        .iter()
        .enumerate()
        .filter(|(index, cve)| listed.iter().any(|other| other.id == cve.id) || needed(*index))
        .map(|(index, _)| index)
        .collect();
    watched.sort_by_key(|index| {
        let cve = &data.cves[*index];
        (cve.state == FleetCveState::Fixed, cve.severity)
    });
    watched
}

fn host_row(
    name: String,
    data: Option<&FleetData>,
    section: Option<usize>,
    declared: Option<FleetHost>,
    report: Option<Host>,
    probe: Option<HostProbeObservation>,
    now: i64,
) -> HostRow {
    let policy = match (data, declared.as_ref()) {
        (Some(data), Some(host)) => ContactPolicy::of(host, &data.defaults),
        _ => ContactPolicy::Unlisted,
    };
    let beacon = report.as_ref().map(|host| BeaconEvidence {
        last_seen: host.last_seen,
        liveness: liveness(host.last_seen, host.heartbeat_interval_secs, now),
    });
    let probe = probe.map(|probe| ProbeEvidence {
        reachable: probe.reachable,
        last_reachable_at: probe.last_reachable_at,
    });
    let hand_declared = declared
        .as_ref()
        .is_some_and(|host| host.version.is_some() || host.kernel.is_some());
    let contact = host_contact(policy, beacon, probe, hand_declared, now);
    let updates = host_updates(report.as_ref(), declared.as_ref(), now);
    let cves = data
        .map(|data| {
            data.cves
                .iter()
                .enumerate()
                .map(|(index, cve)| CveOnHost {
                    index,
                    status: host_cve_status(
                        cve,
                        declared.as_ref().and_then(|host| host.cve.get(&cve.id)),
                        report
                            .as_ref()
                            .and_then(|host| KernelReport::from_host(host, now)),
                        now,
                    ),
                })
                .collect()
        })
        .unwrap_or_default();
    HostRow {
        name,
        section,
        declared,
        report,
        contact,
        updates,
        cves,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 2000-03-01T00:00:00Z
    const NOW: i64 = 951_868_800;

    fn fleet() -> FleetData {
        FleetData::parse(
            &serde_json::json!({
                "schema_version": 3,
                "title": "Example fleet",
                "updated_at": "2000-02-29T00:00:00Z",
                "updated_by": "example-operator",
                "defaults": { "client": { "offline_warn_days": 30, "offline_red_days": 60 } },
                "cves": [
                    {
                        "id": "CVE-2000-0001",
                        "severity": "high",
                        "state": "fixed",
                        "component": "example-tool",
                        "eli10": "Fixed already.",
                        "tip": "Nothing to do.",
                        "fixed_in": ["1.0.0"],
                        "fixed_on": "2000-02-29",
                    },
                    {
                        "id": "CVE-2000-0002",
                        "severity": "critical",
                        "state": "open",
                        "component": "kernel",
                        "eli10": "A kernel flaw.",
                        "tip": "Update.",
                        "fixed_in": ["6.18.56"],
                    },
                    {
                        "id": "CVE-2000-0003",
                        "severity": "high",
                        "state": "open",
                        "component": "example-library",
                        "eli10": "A library flaw.",
                        "tip": "Update.",
                        "fixed_in": ["2.0.0"],
                    },
                ],
                "handled": [],
                "sections": [{
                    "id": "harbor",
                    "name": "Harbor",
                    "hosts": [
                        {
                            "name": "ares",
                            "kind": "nixos",
                            "tailnet": { "state": "none" },
                            "availability": "always_on",
                            "cve": {},
                        },
                        {
                            "name": "artemis",
                            "kind": "mac",
                            "tailnet": { "state": "none" },
                            "availability": "client",
                            "cve": {
                                "CVE-2000-0003": {
                                    "state": "affected",
                                    "last_verified": "2000-02-20T00:00:00Z",
                                },
                            },
                        },
                        {
                            "name": "apollo",
                            "kind": "mac",
                            "tailnet": { "state": "none" },
                            "availability": "client",
                            "cve": {
                                "CVE-2000-0002": {
                                    "state": "affected",
                                    "last_verified": "2000-02-20T00:00:00Z",
                                },
                                "CVE-2000-0003": {
                                    "state": "affected",
                                    "last_verified": "2000-02-10T00:00:00Z",
                                },
                            },
                        },
                    ],
                }],
            })
            .to_string(),
        )
        .expect("fixture is valid")
    }

    fn report(name: &str, running: &str) -> Host {
        serde_json::from_value(serde_json::json!({
            "name": name,
            "role": "Server",
            "is_nix": true,
            "last_seen": NOW - 60,
            "heartbeat_interval_secs": 3600,
            "freshness": {
                "applicable": true,
                "flake_lock_age_days": 1,
                "commits_behind": 0,
            },
            "kernel": {
                "schema": pharos_core::KERNEL_POSTURE_SCHEMA,
                "version": pharos_core::KERNEL_POSTURE_VERSION,
                "state": "current",
                "running_version": running,
                "expected_version": running,
                "observed_at": NOW - 60,
            },
        }))
        .expect("fixture is a host")
    }

    fn probe(reachable: Option<bool>) -> HostProbeObservation {
        HostProbeObservation {
            reachable,
            checked_at: Some(NOW),
            last_reachable_at: reachable.filter(|answered| *answered).map(|_| NOW),
        }
    }

    fn view(hosts: Vec<Host>, probes: Vec<(&str, HostProbeObservation)>) -> FleetView {
        FleetView::build(
            Some(FleetDataView {
                data: Some(Arc::new(fleet())),
                problem: None,
            }),
            hosts,
            probes
                .into_iter()
                .map(|(name, probe)| (name.to_string(), probe))
                .collect(),
            NOW,
        )
    }

    #[test]
    fn anything_that_answers_stays_on_the_page_under_its_own_name() {
        let view = view(
            vec![report("nyx", "6.18.56")],
            vec![("charon", probe(Some(true)))],
        );
        let names: Vec<&str> = view.rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["ares", "artemis", "apollo", "charon", "nyx"]);
        for name in ["charon", "nyx"] {
            let row = view.row(name).unwrap();
            assert_eq!(row.section, None);
            assert!(row.declared.is_none());
        }
    }

    #[test]
    fn a_fixed_cve_comes_after_the_open_ones_on_the_watchlist() {
        let view = view(Vec::new(), Vec::new());
        assert_eq!(view.watchlist, [1, 2, 0]);
    }

    #[test]
    fn security_counts_what_is_open_and_names_one_shared_reason() {
        let view = view(vec![report("ares", "6.18.52")], Vec::new());
        let ares = view.row("ares").unwrap().security(&view);
        assert_eq!(ares.by_severity, [1, 0, 0, 0]);
        assert_eq!(ares.affected(), 1);
        assert!(ares.critical());
        assert_eq!(ares.unknown, 2);
        assert_eq!(ares.reason.as_deref(), Some("not declared yet"));

        let artemis = view.row("artemis").unwrap().security(&view);
        assert_eq!(artemis.by_severity, [0, 1, 0, 0]);
        assert!(!artemis.critical());
    }

    #[test]
    fn a_reboot_due_still_counts_as_open() {
        let mut host = report("ares", "6.18.52");
        let kernel = host.kernel.as_mut().unwrap();
        kernel.state = KernelPostureState::RebootRequired;
        kernel.expected_version = Some("6.18.56".to_string());
        let view = view(vec![host], Vec::new());
        let row = view.row("ares").unwrap();
        assert_eq!(row.on(1).unwrap().status.status, CveStatus::RebootDue);
        assert_eq!(row.security(&view).by_severity, [1, 0, 0, 0]);
        assert_eq!(row.next_boot(), Some("6.18.56"));
        assert!(row.reboot_due());
    }

    #[test]
    fn different_reasons_are_not_collapsed_into_one() {
        let view = view(vec![report("ares", "5.4.1")], Vec::new());
        let ares = view.row("ares").unwrap().security(&view);
        assert_eq!(ares.unknown, 3);
        assert_eq!(ares.reason, None);
        let row = view.row("ares").unwrap();
        let data = view.data.as_deref().unwrap();
        assert_eq!(
            row.unknown_reason(&data.cves[1], row.on(1).unwrap()),
            "no fix line for 5.4"
        );
    }

    #[test]
    fn hosts_needing_attention_rank_first() {
        let view = view(
            vec![report("ares", "6.18.52"), report("nyx", "6.18.56")],
            Vec::new(),
        );
        let rank = |name| view.row(name).unwrap().attention_rank(&view);
        // Critical, then high, then only things that cannot be checked.
        assert_eq!(rank("ares"), 0);
        assert_eq!(rank("artemis"), 1);
        assert!(rank("nyx") > rank("artemis"));
    }

    #[test]
    fn the_oldest_hand_check_decides_how_old_a_declaration_is() {
        let view = view(Vec::new(), Vec::new());
        let artemis = view.row("artemis").unwrap();
        let (at, stale) = artemis.declared_check(&view).unwrap();
        assert_eq!(at, verified_at("2000-02-20T00:00:00Z"));
        assert!(!stale);
        assert_eq!(view.row("ares").unwrap().declared_check(&view), None);
        let (at, _) = view.row("apollo").unwrap().declared_check(&view).unwrap();
        assert_eq!(at, verified_at("2000-02-10T00:00:00Z"));
    }

    #[test]
    fn hosts_with_lists_one_status_in_page_order() {
        let view = view(
            vec![report("ares", "6.18.52"), report("nyx", "6.18.56")],
            Vec::new(),
        );
        let names = |statuses: &[CveStatus]| -> Vec<String> {
            view.hosts_with(1, statuses)
                .into_iter()
                .map(|(row, _)| row.name.clone())
                .collect()
        };
        assert_eq!(names(&[CveStatus::Affected]), ["ares", "apollo"]);
        assert_eq!(names(&[CveStatus::Fixed]), ["nyx"]);
        assert_eq!(names(&[CveStatus::Unknown]), ["artemis"]);
    }

    #[test]
    fn dates_and_lengths_read_plainly() {
        assert_eq!(short_date(NOW, NOW), "1 Mar");
        assert_eq!(short_date(NOW - 366 * 86_400, NOW), "1 Mar 1999");
        assert_eq!(short_day("2000-02-20", NOW), "20 Feb");
        assert_eq!(short_day("someday", NOW), "someday");
        assert_eq!(span(59), "under 1 min");
        assert_eq!(span(60), "1 min");
        assert_eq!(span(3_599), "59 min");
        assert_eq!(span(3_600), "1 h");
        assert_eq!(span(86_399), "23 h");
        assert_eq!(span(86_400), "1 d");
        assert_eq!(kernel_branch("6.18.52").as_deref(), Some("6.18"));
        assert_eq!(kernel_branch("Darwin 27"), None);
        assert_eq!(kernel_branch("6"), None);
    }
}
