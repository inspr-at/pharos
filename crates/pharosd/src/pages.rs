//! The pages: Fleet, Updates due, Handled, one CVE and one host.
//!
//! Server-rendered and read-only: no control here changes a host. Everything from
//! the file or a report is escaped on its way in.

use std::fmt::Write as _;

use pharos_core::contact::{ContactSource, ContactState, ContactTone, HostContact};
use pharos_core::cve_status::{CveStatus, CveStatusSource};
use pharos_core::fleet_data::{
    Availability, CveSeverity, FleetCve, FleetCveState, FleetData, FleetHostKind, HandledCves,
    TailnetState, KERNEL_COMPONENT,
};
use pharos_core::updates_due::{
    host_update_checks, UpdateCheck, UpdateChecks, UpdateDue, UpdatesSource, UpdatesState,
    OLD_NIXPKGS_AFTER_DAYS,
};
use pharos_core::PublicBasePath;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::*;
use crate::fleet_view::{short_date, short_day, short_span, span, CveOnHost, FleetView, HostRow};
use crate::icons::{icon, sprite, WAVE};

const WATCH_CARDS: usize = 4;
const HANDLED_PREVIEW: usize = 2;
const FLEET_COLUMNS: &str = r#"<colgroup><col style="width:17%"><col style="width:11%"><col style="width:12%"><col style="width:19%"><col style="width:14%"><col style="width:27%"></colgroup>"#;
const FOUR_COLUMNS: &str = r#"<colgroup><col style="width:22%"><col style="width:22%"><col style="width:22%"><col style="width:34%"></colgroup>"#;

fn e(value: &str) -> String {
    html_escape(value)
}

fn path_part(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                encoded.push(byte as char);
            }
            _ => {
                let _ = write!(encoded, "%{byte:02X}");
            }
        }
    }
    encoded
}

fn href(base: &PublicBasePath, endpoint: &str) -> String {
    e(&base.href(endpoint))
}

fn host_href(base: &PublicBasePath, name: &str) -> String {
    href(base, &format!("/hosts/{}", path_part(name)))
}

fn cve_href(base: &PublicBasePath, id: &str) -> String {
    href(base, &format!("/cves/{}", path_part(id)))
}

fn ago(seconds: u64) -> String {
    format!("{} ago", span(seconds))
}

fn stale_chip() -> String {
    format!(r#"<span class="stale">{}Stale</span>"#, icon("stale", ""))
}

fn unknown_mark() -> String {
    format!(
        r#"<span class="muted">{}<span class="sr">unknown</span></span>"#,
        icon("dash", "")
    )
}

fn none_mark() -> String {
    format!(
        r#"<span class="muted">{}<span class="sr">none</span></span>"#,
        icon("dash", "")
    )
}

fn verified_text(last_verified: Option<&str>, now: i64) -> String {
    last_verified
        .and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
        .map_or_else(
            || "not verified".to_string(),
            |at| format!("verified {}", short_date(at.unix_timestamp(), now)),
        )
}

pub(crate) fn severity_parts(severity: CveSeverity) -> (&'static str, &'static str, &'static str) {
    match severity {
        CveSeverity::Critical => ("Critical", "sev-critical", "critical"),
        CveSeverity::High => ("High", "sev-high", "high"),
        CveSeverity::Medium => ("Medium", "sev-medium", "medium"),
        CveSeverity::Low => ("Low", "sev-low", "info"),
    }
}

const SEVERITIES: [CveSeverity; 4] = [
    CveSeverity::Critical,
    CveSeverity::High,
    CveSeverity::Medium,
    CveSeverity::Low,
];

pub(crate) fn cve_title(cve: &FleetCve) -> &str {
    cve.name.as_deref().unwrap_or(&cve.id)
}

fn kind_icon(row: &HostRow) -> &'static str {
    match row.declared.as_ref().map(|host| host.kind) {
        Some(FleetHostKind::Mac) => "laptop",
        Some(FleetHostKind::Pi) => "pi",
        Some(FleetHostKind::Vm) => "vm",
        Some(FleetHostKind::Appliance) => "appliance",
        Some(FleetHostKind::Nixos) | None => "server",
    }
}

fn kind_label(row: &HostRow) -> &'static str {
    match row.declared.as_ref().map(|host| host.kind) {
        Some(FleetHostKind::Nixos) => "NixOS",
        Some(FleetHostKind::Mac) => "Mac",
        Some(FleetHostKind::Pi) => "Raspberry Pi",
        Some(FleetHostKind::Vm) => "VM",
        Some(FleetHostKind::Appliance) => "Appliance",
        None => "Unlisted",
    }
}

fn tone_class(tone: ContactTone) -> &'static str {
    match tone {
        ContactTone::Ok => "ok",
        ContactTone::Neutral => "",
        ContactTone::Warn => "warn",
        ContactTone::Danger => "danger",
    }
}

fn contact_icon(contact: &HostContact) -> &'static str {
    match contact.state {
        ContactState::Online | ContactState::Reachable => "online",
        ContactState::Late => "clock",
        ContactState::Offline | ContactState::NoAnswerYet => "offline",
        ContactState::Asleep { .. } => "moon",
        ContactState::OfflineOptional => "paused",
        ContactState::CheckUnavailable => "unknown",
        ContactState::NoContactData => "no-contact",
        ContactState::NeverReported => "never",
    }
}

pub(crate) fn contact_label(contact: &HostContact) -> String {
    let age = contact.age_secs.unwrap_or_default();
    match contact.state {
        ContactState::Online => format!("Online · {}", ago(age)),
        ContactState::Reachable => format!("Reachable · {}", ago(age)),
        ContactState::Late => format!("Late · {}", ago(age)),
        ContactState::Offline => format!("Offline {}", span(age)),
        ContactState::Asleep { over_days: None } => format!("Asleep · {}", span(age)),
        ContactState::Asleep {
            over_days: Some(days),
        } => format!("Asleep {} · over {days} d", span(age)),
        ContactState::OfflineOptional => format!("Offline {} · optional", span(age)),
        ContactState::NoAnswerYet => "No answer yet".to_string(),
        ContactState::CheckUnavailable if contact.age_secs.is_some() => {
            format!("Can't check · last contact {}", ago(age))
        }
        ContactState::CheckUnavailable => "No result yet".to_string(),
        ContactState::NoContactData => "No contact data".to_string(),
        ContactState::NeverReported => "Never reported".to_string(),
    }
}

/// A contact state in a table's width, for the CLI.
pub(crate) fn contact_short_label(contact: &HostContact) -> String {
    let age = short_span(contact.age_secs.unwrap_or_default());
    match contact.state {
        ContactState::Online => format!("online {age}"),
        ContactState::Reachable => format!("reachable {age}"),
        ContactState::Late => format!("late {age}"),
        ContactState::Offline => format!("offline {age}"),
        ContactState::Asleep { over_days: None } => format!("asleep {age}"),
        ContactState::Asleep {
            over_days: Some(days),
        } => format!("asleep {age}, over {days}d"),
        ContactState::OfflineOptional => format!("offline {age}, optional"),
        ContactState::NoAnswerYet => "no answer yet".to_string(),
        ContactState::CheckUnavailable if contact.age_secs.is_some() => {
            format!("can't check, last {age}")
        }
        ContactState::CheckUnavailable => "no result yet".to_string(),
        ContactState::NoContactData => "no contact data".to_string(),
        ContactState::NeverReported => "never".to_string(),
    }
}

/// The source line under a contact state, with its icon.
fn contact_source(row: &HostRow) -> (&'static str, &'static str) {
    match row.contact.source {
        _ if row.contact.state == ContactState::NeverReported && row.declared.is_some() => {
            ("never", "Beacon · listed, no report yet")
        }
        ContactSource::Beacon if row.declared.is_none() => {
            ("unlisted", "Beacon · not in the data file")
        }
        ContactSource::Beacon => ("beacon", "Beacon"),
        ContactSource::Probe if row.declared.is_none() => {
            ("unlisted", "Probe · not in the data file")
        }
        ContactSource::Probe => ("probe", "Probe · reachability only"),
        ContactSource::Nothing => ("hand", "Not probed, no beacon"),
    }
}

pub(crate) fn contact_short_source(row: &HostRow) -> &'static str {
    match row.contact.source {
        ContactSource::Beacon => "Beacon",
        ContactSource::Probe => "Probe",
        ContactSource::Nothing => "Hand-declared",
    }
}

pub(crate) fn data_age(view: &FleetView) -> Option<String> {
    view.data
        .as_deref()
        .and_then(FleetData::updated_at_unix)
        .map(|updated| ago(view.now.saturating_sub(updated).max(0) as u64))
}

/// One notice on every page while the file cannot be trusted or is not there.
fn data_notice(view: &FleetView) -> String {
    let (headline, detail) = match (&view.problem, data_age(view)) {
        (Some(problem), Some(age)) => (
            format!("The data file is invalid, so this page shows the last good data, from {age}."),
            format!(
                "{}. Beacon reports stay live; CVEs and hand-declared rows come from the last good file.",
                e(problem)
            ),
        ),
        (Some(problem), None) => (
            "The data file can't be used and there is no earlier copy.".to_string(),
            format!(
                "{}. Hosts that report still show, as unlisted, and there are no CVEs to compare.",
                e(problem)
            ),
        ),
        (None, None) if !view.configured => (
            "No data file is configured.".to_string(),
            "Hosts that report still show, as unlisted, and there are no CVEs to compare."
                .to_string(),
        ),
        (None, None) => (
            "The data file has not loaded yet.".to_string(),
            "Hosts that report still show, as unlisted.".to_string(),
        ),
        (None, Some(_)) => return String::new(),
    };
    format!(
        r#"<div class="notice" role="status">{}<div><strong>{headline}</strong><span class="nsub">{detail}</span></div></div>"#,
        icon("file-warning", "")
    )
}

fn data_line(view: &FleetView) -> String {
    let report = view.last_report().map(|at| {
        format!(
            "last report {}",
            ago(view.now.saturating_sub(at).max(0) as u64)
        )
    });
    let (class, icon_name, file) = match (&view.problem, data_age(view)) {
        (Some(_), Some(age)) => (
            " warn",
            "file-warning",
            format!("Data file invalid · showing the last good file from {age}"),
        ),
        (Some(_), None) => (
            "  warn",
            "file-warning",
            "Data file can't be used".to_string(),
        ),
        (None, Some(age)) => ("", "data-file", format!("Data file updated {age}")),
        (None, None) if view.configured => (
            " warn",
            "file-warning",
            "Data file not loaded yet".to_string(),
        ),
        (None, None) => (" warn", "file-warning", "No data file".to_string()),
    };
    let line = match report {
        Some(report) => format!("{} · {report}", e(&file)),
        None => e(&file),
    };
    format!(
        r#"<p class="top-meta{class}">{}<span>{line}</span></p>"#,
        icon(icon_name, "")
    )
}

struct Header<'a> {
    title: &'a str,
    back: bool,
    sub: String,
    meta: String,
}

fn header(base: &PublicBasePath, header: Header<'_>, now: i64) -> String {
    let back = if header.back {
        format!(
            r#"<a class="back" href="{}">{}Fleet</a>"#,
            href(base, "/"),
            icon("back", "")
        )
    } else {
        String::new()
    };
    let (rfc3339, clock) = OffsetDateTime::from_unix_timestamp(now).map_or_else(
        |_| (String::new(), "unknown".to_string()),
        |at| {
            (
                at.format(&Rfc3339).unwrap_or_default(),
                format!("{:02}:{:02}:{:02} UTC", at.hour(), at.minute(), at.second()),
            )
        },
    );
    format!(
        r#"<header class="top"><span class="top-art" aria-hidden="true"><span class="art-horizon"></span></span><div class="top-main">{back}<div class="top-title"><h1>{title}</h1>{WAVE}</div><p class="top-sub">{sub}</p>{meta}</div><div class="top-side"><span class="asof">as of <time datetime="{rfc3339}" data-local-time>{clock}</time></span></div></header>"#,
        title = e(header.title),
        sub = header.sub,
        meta = header.meta,
    )
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Fleet,
    Updates,
    Handled,
}

fn nav_link(base: &PublicBasePath, current: Option<Nav>, nav: Nav) -> String {
    let (endpoint, icon_name, label) = match nav {
        Nav::Fleet => ("/", "grid", "Fleet"),
        Nav::Updates => ("/updates", "updates", "Updates due"),
        Nav::Handled => ("/handled", "archive", "Handled"),
    };
    let here = if current == Some(nav) {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r#"<a class="side-link" href="{}"{here}>{}<span>{label}</span></a>"#,
        href(base, endpoint),
        icon(icon_name, "")
    )
}

fn sidebar(base: &PublicBasePath, user: Option<&AuthUser>, current: Option<Nav>) -> String {
    let account = account_html(base, user);
    format!(
        r#"<aside class="side" aria-label="Primary"><div class="side-head"><span class="side-brand"><span class="side-mark">{mark}</span><span class="side-logo">Pharos</span></span><button type="button" class="side-menu" aria-label="Menu" aria-expanded="false">{open}{close}</button></div><nav class="side-nav" aria-label="Pages">{fleet}{updates}{handled}</nav><div class="side-bottom"><div class="seg" role="group" aria-label="Theme"><button type="button" data-set-theme="light" aria-pressed="true">{sun}Light</button><button type="button" data-set-theme="dark" aria-pressed="false">{moon}Dark</button></div><span class="side-version">{clock}{release}</span>{account}</div><div class="side-anchor" aria-hidden="true"><span class="side-art"><span class="art-lighthouse"></span></span></div></aside>"#,
        mark = icon("lighthouse", ""),
        open = icon("menu", "i-open"),
        close = icon("close", "i-close"),
        fleet = nav_link(base, current, Nav::Fleet),
        updates = nav_link(base, current, Nav::Updates),
        handled = nav_link(base, current, Nav::Handled),
        sun = icon("sun", ""),
        moon = icon("moon", ""),
        clock = icon("clock", ""),
        release = release_label_html(),
    )
}

fn shell(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    title: &str,
    current: Option<Nav>,
    main: &str,
) -> String {
    format!(
        r#"{head}<body>{sprite}<noscript><style>.side-nav{{display:grid;flex:1 1 100%;padding:8px 0 4px}}</style></noscript><div class="app live">{side}<main class="main"><div class="main-in">{main}</div></main></div></body></html>"#,
        head = document_head(base, title),
        sprite = sprite(),
        side = sidebar(base, user, current),
    )
}

fn metric(class: &str, icon_name: &str, value: u32, label: &str) -> String {
    let class = if class.is_empty() {
        "metric".to_string()
    } else {
        format!("metric {class}")
    };
    format!(
        r#"<div class="{class}"><span class="metric-dot">{}</span><b>{value}</b><span class="metric-l">{label}</span></div>"#,
        icon(icon_name, "")
    )
}

/// What a security cell says, each part with the class it is drawn in.
struct SecurityCell {
    icon: &'static str,
    icon_class: &'static str,
    parts: Vec<(&'static str, String)>,
}

fn security_cell(view: &FleetView, row: &HostRow) -> SecurityCell {
    let security = row.security(view);
    let mut parts: Vec<(&'static str, String)> = SEVERITIES
        .iter()
        .filter(|severity| security.by_severity[**severity as usize] > 0)
        .map(|severity| {
            let (label, class, _) = severity_parts(*severity);
            (
                class,
                format!(
                    "{} {}",
                    security.by_severity[*severity as usize],
                    label.to_lowercase()
                ),
            )
        })
        .collect();
    if let Some(top) = SEVERITIES
        .iter()
        .find(|severity| security.by_severity[**severity as usize] > 0)
    {
        let (_, class, icon_name) = severity_parts(*top);
        if security.unknown > 0 {
            parts.push(("ink2", format!("{} can't check", security.unknown)));
        }
        return SecurityCell {
            icon: icon_name,
            icon_class: class,
            parts,
        };
    }
    if security.unknown > 0 {
        let reason = security
            .reason
            .as_deref()
            .map(|reason| format!(": {reason}"))
            .unwrap_or_default();
        return SecurityCell {
            icon: "unknown",
            icon_class: "muted",
            parts: vec![("", format!("Can't check{reason}"))],
        };
    }
    SecurityCell {
        icon: "check",
        icon_class: "ok",
        parts: vec![("", "No watched CVEs".to_string())],
    }
}

fn security_line(view: &FleetView, row: &HostRow) -> String {
    let cell = security_cell(view, row);
    let parts: Vec<String> = cell
        .parts
        .iter()
        .map(|(class, text)| match *class {
            "" => e(text),
            "ink2" => format!(r#"<span class="ink2">{}</span>"#, e(text)),
            class => format!(r#"<span class="sevc {class}">{}</span>"#, e(text)),
        })
        .collect();
    format!(
        r#"<span class="security-line">{}{}</span>"#,
        icon(cell.icon, cell.icon_class),
        parts.join(" · ")
    )
}

/// The security cell in words, for the data routes.
pub(crate) fn security_text(view: &FleetView, row: &HostRow) -> String {
    security_cell(view, row)
        .parts
        .into_iter()
        .map(|(_, text)| text)
        .collect::<Vec<_>>()
        .join(" · ")
}

/// The second line of a security cell: how current this host's picture is.
pub(crate) struct UpdateNote {
    class: &'static str,
    icon: &'static str,
    pub(crate) text: String,
    pub(crate) stale: bool,
}

pub(crate) fn update_note_parts(view: &FleetView, row: &HostRow) -> Option<UpdateNote> {
    let state = |class, icon, text, stale| {
        Some(UpdateNote {
            class,
            icon,
            text,
            stale,
        })
    };
    let report_age = match row.updates.source {
        UpdatesSource::Report {
            age_secs, stale, ..
        } => Some((age_secs, stale)),
        _ => None,
    };
    let hand = |last_verified: Option<&str>, stale: bool| {
        state(
            "",
            "hand",
            format!("Hand-declared · {}", verified_text(last_verified, view.now)),
            stale,
        )
    };
    match row.updates.state {
        UpdatesState::Due => {
            let items: Vec<String> = row
                .updates
                .due
                .iter()
                .map(|due| match due {
                    UpdateDue::Reboot { .. } => "Reboot due".to_string(),
                    UpdateDue::BehindConfig { commits } => commits_behind(*commits),
                    UpdateDue::OldNixpkgs { age_days } => format!("Updated {age_days} d ago"),
                })
                .collect();
            let icon_name = match row.updates.due.first() {
                Some(UpdateDue::Reboot { .. }) => "reboot",
                Some(UpdateDue::BehindConfig { .. }) => "commit",
                _ => "clock",
            };
            let stale = report_age.is_some_and(|(_, stale)| stale);
            state("warn", icon_name, items.join(" · "), stale)
        }
        UpdatesState::UpToDate => {
            let age = row
                .report
                .as_ref()
                .and_then(|host| host.freshness.nixpkgs_age_days_at(view.now));
            let text = match (age, report_age) {
                (Some(days), _) => format!("Updated {days} d ago"),
                (None, Some((age, _))) => format!("Report {}", ago(age)),
                (None, None) => "Up to date".to_string(),
            };
            state("", "clock", text, false)
        }
        UpdatesState::LastKnownUpToDate => {
            let age = report_age.map_or(0, |(age, _)| age);
            state("", "clock", format!("Data from {}", ago(age)), true)
        }
        UpdatesState::HandDeclared => match &row.updates.source {
            UpdatesSource::Declared {
                last_verified,
                verification_stale,
            } => hand(last_verified.as_deref(), *verification_stale),
            _ => None,
        },
        UpdatesState::Unknown => match report_age {
            Some((age, true)) => state("", "clock", format!("Data from {}", ago(age)), true),
            Some((age, false)) => state("", "clock", format!("Report {}", ago(age)), false),
            None => match row.declared_check(view) {
                Some((Some(at), stale)) => state(
                    "",
                    "hand",
                    format!("Hand-declared · verified {}", short_date(at, view.now)),
                    stale,
                ),
                Some((None, stale)) => hand(None, stale),
                None => None,
            },
        },
    }
}

fn update_note(view: &FleetView, row: &HostRow) -> String {
    let parts = update_note_parts(view, row);
    let mut html = parts.as_ref().map_or_else(String::new, |note| {
        let class = if note.class.is_empty() {
            "update-state".to_string()
        } else {
            format!("update-state {}", note.class)
        };
        let chip = if note.stale {
            stale_chip()
        } else {
            String::new()
        };
        format!(
            r#"<span class="{class}">{}{}{chip}</span>"#,
            icon(note.icon, ""),
            e(&note.text)
        )
    });
    let already_stale = parts.is_some_and(|note| note.stale);
    if !already_stale {
        if let Some(age) = row.stale_computed_age(view) {
            let _ = write!(
                html,
                r#"<span class="update-state">{}Computed from a report {}{}</span>"#,
                icon("clock", ""),
                ago(age),
                stale_chip()
            );
        }
    }
    // A fresh report says nothing about a status someone wrote down long ago.
    if !already_stale {
        if let Some((at, true)) = row.declared_check(view) {
            let _ = write!(
                html,
                r#"<span class="update-state">{}Declared CVE status, {}{}</span>"#,
                icon("hand", ""),
                at.map_or_else(
                    || "not verified".to_string(),
                    |at| format!("verified {}", short_date(at, view.now))
                ),
                stale_chip()
            );
        }
    }
    html
}

fn commits_behind(commits: u32) -> String {
    if commits == 1 {
        "1 commit behind".to_string()
    } else {
        format!("{commits} commits behind")
    }
}

fn os_html(row: &HostRow) -> String {
    match row.os() {
        Some(os) => {
            let version = row
                .os_version()
                .map(|version| format!(r#"<span class="sub mono">{}</span>"#, e(version)))
                .unwrap_or_default();
            format!("{}{version}", e(os))
        }
        None => unknown_mark(),
    }
}

fn kernel_html(row: &HostRow) -> String {
    let Some(kernel) = row.kernel() else {
        return unknown_mark();
    };
    let next = row
        .next_boot()
        .map(|next| {
            format!(
                r#"<span class="sub warn">{}next boot {}</span>"#,
                icon("reboot", ""),
                e(next)
            )
        })
        .unwrap_or_default();
    format!(r#"<span class="mono">{}</span>{next}"#, e(kernel))
}

fn address_html(row: &HostRow) -> String {
    let Some(host) = row.declared.as_ref() else {
        return unknown_mark();
    };
    let line = match (host.tailnet.state, host.tailnet.ip.as_deref()) {
        (TailnetState::Online, Some(ip)) => format!(
            r#"<span class="line">{}<span class="mono">{}</span></span>"#,
            icon("tailnet", "accent"),
            e(ip)
        ),
        (TailnetState::Offline, Some(ip)) => format!(
            r#"<span class="line">{}<span class="mono">{}</span></span>"#,
            icon("tailnet", "muted"),
            e(ip)
        ),
        _ => format!(
            r#"<span class="line muted">{}No tailnet</span>"#,
            icon("no-tailnet", "")
        ),
    };
    let other = host
        .lan
        .as_deref()
        .or(host.public.as_deref())
        .map(|address| format!(r#"<span class="sub mono">{}</span>"#, e(address)))
        .unwrap_or_default();
    format!("{line}{other}")
}

fn host_label(base: &PublicBasePath, row: &HostRow) -> String {
    format!(
        r#"<span class="host-label">{}<a class="hostname" href="{}">{}</a></span>"#,
        icon(kind_icon(row), ""),
        host_href(base, &row.name),
        e(&row.name)
    )
}

fn row_class(row: &HostRow, selected: Option<usize>) -> &'static str {
    match selected {
        None => "",
        Some(index) => match row.on(index).map(|on| on.status.status) {
            Some(CveStatus::Affected | CveStatus::RebootDue) => "hl",
            _ => "dim",
        },
    }
}

fn search_matches(row: &HostRow, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    query.is_empty() || row.search_text().contains(&query)
}

fn hidden_attr(row: &HostRow, query: &str) -> &'static str {
    if search_matches(row, query) {
        ""
    } else {
        " hidden"
    }
}

/// Site names on the flat arrangements, where the section heading is gone.
fn role_text(view: &FleetView, row: &HostRow, with_site: bool) -> String {
    let site = with_site
        .then(|| {
            row.section.and_then(|section| {
                view.data
                    .as_deref()
                    .and_then(|data| data.sections.get(section))
                    .map(|section| section.name.as_str())
            })
        })
        .flatten();
    let role = if row.declared.is_none() {
        Some("Reports, not in the data file")
    } else {
        row.role()
    };
    match (role, site) {
        (Some(role), Some(site)) => format!("{} · {}", e(role), e(site)),
        (Some(text), None) | (None, Some(text)) => e(text),
        (None, None) => String::new(),
    }
}

fn fleet_row(
    base: &PublicBasePath,
    view: &FleetView,
    row: &HostRow,
    selected: Option<usize>,
    query: &str,
    with_site: bool,
) -> String {
    let security_class = if row.security(view).critical() {
        "security critical"
    } else {
        "security"
    };
    let (source_icon, source_text) = contact_source(row);
    let class = row_class(row, selected);
    let class = if class.is_empty() {
        String::new()
    } else {
        format!(r#" class="{class}""#)
    };
    format!(
        r#"<tr{class} data-host="{search}"{hidden}><th scope="row" class="host">{label}<span class="role">{role}</span></th><td>{os}</td><td>{kernel}</td><td class="contact"><span class="line {tone}">{contact_icon}{contact}</span><span class="sub">{source_icon}{source_text}</span></td><td>{address}</td><td class="{security_class}">{security}{note}</td></tr>"#,
        search = e(&row.search_text()),
        hidden = hidden_attr(row, query),
        label = host_label(base, row),
        role = role_text(view, row, with_site),
        os = os_html(row),
        kernel = kernel_html(row),
        tone = tone_class(row.contact.tone),
        contact_icon = icon(contact_icon(&row.contact), ""),
        contact = e(&contact_label(&row.contact)),
        source_icon = icon(source_icon, ""),
        address = address_html(row),
        security = security_line(view, row),
        note = update_note(view, row),
    )
}

fn phone_item(
    base: &PublicBasePath,
    view: &FleetView,
    row: &HostRow,
    selected: Option<usize>,
    query: &str,
    with_site: bool,
) -> String {
    let mut meta: Vec<String> = Vec::new();
    let role = role_text(view, row, with_site);
    if !role.is_empty() {
        meta.push(role);
    }
    if let Some(os) = row.os() {
        meta.push(match row.os_version() {
            Some(version) => format!("{} {}", e(os), e(version)),
            None => e(os),
        });
    }
    if let Some(kernel) = row.kernel() {
        meta.push(format!("kernel {}", e(kernel)));
    }
    if let Some(next) = row.next_boot() {
        meta.push(format!("next boot {}", e(next)));
    }
    let class = row_class(row, selected);
    let security_class = if row.security(view).critical() {
        "hsec critical"
    } else {
        "hsec"
    };
    format!(
        r#"<li class="hitem {class}" data-host="{search}"{hidden}><div class="hrow">{label}</div><span class="hmeta">{meta}</span><span class="hcontact {tone}">{contact_icon}{contact} · {source}</span><div class="{security_class}">{security}{note}</div></li>"#,
        search = e(&row.search_text()),
        hidden = hidden_attr(row, query),
        label = host_label(base, row),
        meta = meta.join(" · "),
        tone = tone_class(row.contact.tone),
        contact_icon = icon(contact_icon(&row.contact), ""),
        contact = e(&contact_label(&row.contact)),
        source = contact_short_source(row),
        security = security_line(view, row),
        note = update_note(view, row),
    )
}

struct HostGroup<'a> {
    icon: &'a str,
    title: &'a str,
    count_label: &'a str,
    place: Option<&'a str>,
    right: String,
    rows: Vec<&'a HostRow>,
    with_site: bool,
}

fn hosts_count(count: usize) -> String {
    if count == 1 {
        "1 host".to_string()
    } else {
        format!("{count} hosts")
    }
}

pub(crate) struct FleetCounts {
    pub(crate) affected: u32,
    pub(crate) unknown: u32,
    pub(crate) reboots: u32,
}

/// The summary at the top of Fleet. A host with an affected CVE and one it can't
/// check counts in both.
pub(crate) fn fleet_counts(view: &FleetView) -> FleetCounts {
    let mut counts = FleetCounts {
        affected: 0,
        unknown: 0,
        reboots: 0,
    };
    for row in &view.rows {
        let security = row.security(view);
        counts.affected += u32::from(security.affected() > 0);
        counts.unknown += u32::from(security.unknown > 0);
        counts.reboots += u32::from(row.reboot_due());
    }
    counts
}

fn group_summary(view: &FleetView, rows: &[&HostRow]) -> String {
    let mut affected = 0;
    let mut unknown = 0;
    for row in rows {
        let security = row.security(view);
        affected += u32::from(security.affected() > 0);
        unknown += u32::from(security.unknown > 0);
    }
    match (affected, unknown) {
        (0, 0) => "No watched CVEs".to_string(),
        (affected, 0) => format!("{affected} affected"),
        (0, unknown) => format!("{unknown} can't check"),
        (affected, unknown) => format!("{affected} affected · {unknown} can't check"),
    }
}

fn host_group(
    base: &PublicBasePath,
    view: &FleetView,
    group: HostGroup<'_>,
    selected: Option<usize>,
    query: &str,
) -> String {
    let matching = group.rows.iter().any(|row| search_matches(row, query));
    let hidden = if matching { "" } else { " hidden" };
    let place = group
        .place
        .map(|place| format!(r#"<span class="place">{}</span>"#, e(place)))
        .unwrap_or_default();
    let rows: String = group
        .rows
        .iter()
        .map(|row| fleet_row(base, view, row, selected, query, group.with_site))
        .collect();
    let items: String = group
        .rows
        .iter()
        .map(|row| phone_item(base, view, row, selected, query, group.with_site))
        .collect();
    let title = e(group.title);
    format!(
        r#"<section class="card" data-host-group{hidden}><div class="card-head"><div class="site-title">{icon}<h2>{title}</h2><span class="count">{count}</span>{place}</div><span class="count">{right}</span></div><div class="table-scroll" tabindex="0" role="region" aria-label="{title} hosts"><table class="fleet-table"><caption class="sr">{title} hosts and CVE status</caption>{FLEET_COLUMNS}<thead><tr><th scope="col" class="host">Host</th><th scope="col">OS</th><th scope="col">Kernel</th><th scope="col">Contact</th><th scope="col">Address</th><th scope="col">Security</th></tr></thead><tbody>{rows}</tbody></table></div><ul class="hlist">{items}</ul></section>"#,
        icon = icon(group.icon, ""),
        count = group.count_label,
        right = group.right,
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) enum Arrange {
    #[default]
    Site,
    Attention,
    Name,
}

impl Arrange {
    pub(super) fn parse(value: Option<&str>) -> Self {
        match value {
            Some("attention") => Self::Attention,
            Some("name") => Self::Name,
            _ => Self::Site,
        }
    }

    fn value(self) -> &'static str {
        match self {
            Self::Site => "site",
            Self::Attention => "attention",
            Self::Name => "name",
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct FleetQuery {
    pub(super) cve: Option<String>,
    pub(super) arrange: Arrange,
    pub(super) q: String,
}

fn fleet_query_href(base: &PublicBasePath, query: &FleetQuery, cve: Option<&str>) -> String {
    let mut params = Vec::new();
    if let Some(cve) = cve {
        params.push(format!("cve={}", path_part(cve)));
    }
    if query.arrange != Arrange::Site {
        params.push(format!("arrange={}", query.arrange.value()));
    }
    if !query.q.is_empty() {
        params.push(format!("q={}", path_part(&query.q)));
    }
    if params.is_empty() {
        href(base, "/")
    } else {
        // The mount's root has no trailing slash, so this is not a path under it.
        e(&format!("{}?{}", base.home(), params.join("&")))
    }
}

fn watch_card(
    base: &PublicBasePath,
    view: &FleetView,
    data: &FleetData,
    index: usize,
    selected: Option<usize>,
    query: &FleetQuery,
) -> String {
    let Some(cve) = data.cves.get(index) else {
        return String::new();
    };
    let (severity_label, severity_class, severity_icon) = severity_parts(cve.severity);
    let state = match (cve.state, cve.fixed_on.as_deref()) {
        (FleetCveState::Open, _) => format!(
            r#"<span class="{severity_class}">{}Open</span>"#,
            icon("high", "")
        ),
        (FleetCveState::Mitigated, _) => format!(
            r#"<span class="ok">{}Mitigated</span>"#,
            icon("mitigated", "")
        ),
        (FleetCveState::Fixed, fixed_on) => format!(
            r#"<span class="ok">{}Fixed {}</span>"#,
            icon("check", ""),
            fixed_on
                .map(|day| short_day(day, view.now))
                .unwrap_or_default()
        ),
    };
    let needing = view.hosts_with(index, &[CveStatus::Affected, CveStatus::RebootDue]);
    let mut chips: String = needing
        .iter()
        .take(WATCH_CARDS)
        .map(|(row, _)| {
            format!(
                r#"<span class="chip">{}{}</span>"#,
                icon(kind_icon(row), ""),
                e(&row.name)
            )
        })
        .collect();
    if needing.len() > WATCH_CARDS {
        let _ = write!(
            chips,
            r#"<span class="chip">+{}</span>"#,
            needing.len() - WATCH_CARDS
        );
    }
    let chips = if chips.is_empty() {
        String::new()
    } else {
        format!(r#"<span class="chips">{chips}</span>"#)
    };
    let source = if cve.component == KERNEL_COMPONENT {
        format!(
            r#"<span class="wnote">{}Computed from kernel</span>"#,
            icon("beacon", "")
        )
    } else {
        format!(
            r#"<span class="wnote">{}Hand-declared</span>"#,
            icon("hand", "")
        )
    };
    let workaround = if cve.state == FleetCveState::Mitigated {
        r#"<span class="wnote">Workaround in place</span>"#
    } else {
        ""
    };
    let is_selected = selected == Some(index);
    let (class, target) = if is_selected {
        ("wcard sel", fleet_query_href(base, query, None))
    } else {
        ("wcard", fleet_query_href(base, query, Some(&cve.id)))
    };
    let current = if is_selected {
        r#" aria-current="true""#
    } else {
        ""
    };
    format!(
        r#"<a class="{class}" href="{target}"{current} data-keep-scroll data-keep-search><span class="wcard-top"><span class="{severity_class}">{severity_icon}{severity_label}</span>{state}</span><span class="wcard-name">{name}</span><span class="cve-id">{id}</span>{chips}<span class="wcard-counts">{counts}</span>{workaround}{source}</a>"#,
        severity_icon = icon(severity_icon, ""),
        name = e(cve_title(cve)),
        id = e(&cve.id),
        counts = watch_counts(view, index),
    )
}

/// One watched CVE across the fleet, in words: the card's line and the CLI's.
pub(crate) fn watch_counts(view: &FleetView, index: usize) -> String {
    let affected = view.hosts_with(index, &[CveStatus::Affected]).len();
    let reboot = view.hosts_with(index, &[CveStatus::RebootDue]).len();
    let unknown = view.hosts_with(index, &[CveStatus::Unknown]).len();
    let fixed = view.hosts_with(index, &[CveStatus::Fixed]).len();
    let mut counts = Vec::new();
    if affected > 0 {
        counts.push(format!("{affected} affected"));
    }
    if reboot > 0 {
        counts.push(format!("{reboot} reboot due"));
    }
    if affected == 0 && reboot == 0 {
        if fixed > 0 {
            counts.push(format!("{fixed} fixed"));
        }
        counts.push("none affected".to_string());
    }
    if unknown > 0 {
        counts.push(format!("{unknown} can't check"));
    }
    let stale = view
        .rows
        .iter()
        .filter_map(|row| row.on(index))
        .filter(|on| {
            matches!(
                on.status.source,
                CveStatusSource::Computed { stale: true, .. }
                    | CveStatusSource::Declared {
                        verification_stale: true,
                        ..
                    }
            )
        })
        .count();
    if stale > 0 {
        counts.push(format!("{stale} stale"));
    }
    counts.join(" · ")
}

fn watchlist_html(
    base: &PublicBasePath,
    view: &FleetView,
    selected: Option<usize>,
    query: &FleetQuery,
) -> String {
    let Some(data) = view.data.as_deref() else {
        return String::new();
    };
    let title = format!(
        r#"<div class="site-title">{}<h2 id="watchlist">Watchlist</h2>{}</div>"#,
        icon("eye", ""),
        if view.watchlist.is_empty() {
            String::new()
        } else {
            format!(
                r#"<span class="count">{} watched</span>"#,
                view.watchlist.len()
            )
        }
    );
    if view.watchlist.is_empty() {
        return format!(
            r#"<section aria-labelledby="watchlist"><div class="watch-head">{title}<div class="watch-tools"><span>Picked by hand.</span></div></div><div class="watch-empty">{}Nothing on the watchlist</div></section>"#,
            icon("check", "ok")
        );
    }
    let tools = match selected.and_then(|index| data.cves.get(index).map(|cve| (index, cve))) {
        Some((index, cve)) => {
            let hosts = view
                .hosts_with(index, &[CveStatus::Affected, CveStatus::RebootDue])
                .len();
            format!(
                r#"<span class="ink2">{count} for {name}</span><a class="btn" href="{open}">Open CVE{arrow}</a><a class="textlink" href="{all}" data-keep-scroll data-keep-search>Show all hosts</a>"#,
                count = hosts_count(hosts),
                name = e(cve_title(cve)),
                open = cve_href(base, &cve.id),
                arrow = icon("arrow-right", ""),
                all = fleet_query_href(base, query, None),
            )
        }
        None => "<span>Picked by hand. Select a card to see its hosts.</span>".to_string(),
    };
    let mut cards: String = view
        .watchlist
        .iter()
        .take(WATCH_CARDS)
        .map(|index| watch_card(base, view, data, *index, selected, query))
        .collect();
    if view.watchlist.len() > WATCH_CARDS {
        let _ = write!(
            cards,
            r#"<div class="wcard watch-overflow"><span class="wcard-name">+{} more on the watchlist</span><span class="wcard-counts">Shown in the hosts' counts</span></div>"#,
            view.watchlist.len() - WATCH_CARDS
        );
    }
    format!(
        r#"<section aria-labelledby="watchlist"><div class="watch-head">{title}<div class="watch-tools">{tools}</div></div><div class="watch-grid">{cards}</div></section>"#
    )
}

fn handled_rows(entries: &[HandledCves], now: i64, full: bool) -> String {
    entries
        .iter()
        .map(|entry| {
            let ids = entry
                .ids
                .iter()
                .map(|id| format!(r#"<span class="cve-id">{}</span>"#, e(id)))
                .collect::<Vec<_>>()
                .join("<br>");
            let what = match (entry.name.as_deref(), full) {
                (Some(name), true) => format!(
                    r#"<strong>{}</strong><span class="sub">{}</span>"#,
                    e(name),
                    e(&entry.eli10)
                ),
                (Some(name), false) => e(name),
                (None, _) => e(&entry.eli10),
            };
            let hosts = if entry.hosts.is_empty() {
                none_mark()
            } else if full {
                let chips: String = entry
                    .hosts
                    .iter()
                    .map(|host| format!(r#"<span class="chip">{}</span>"#, e(host)))
                    .collect();
                format!(r#"<span class="chips chips-flat">{chips}</span>"#)
            } else {
                format!(r#"<span class="mono">{}</span>"#, e(&entry.hosts.join(", ")))
            };
            let action = if full {
                format!(r#"<td data-label="What we did">{}</td>"#, e(&entry.action))
            } else {
                String::new()
            };
            format!(
                r#"<tr><th scope="row">{ids}</th><td data-label="What">{what}</td><td data-label="Hosts">{hosts}</td>{action}<td class="done" data-label="Done">{done}</td><td class="mono" data-label="Ticket">{ticket}</td></tr>"#,
                done = e(&short_day(&entry.done, now)),
                ticket = entry.ticket.as_deref().map_or_else(none_mark, e),
            )
        })
        .collect()
}

fn handled_summary(base: &PublicBasePath, view: &FleetView) -> String {
    if view.data.is_none() {
        return String::new();
    }
    let history = view.handled_history();
    let count = history.iter().map(|entry| entry.ids.len()).sum::<usize>();
    let summary = match history.first() {
        Some(latest) => format!(
            "{count} CVE{} · last {}",
            if count == 1 { "" } else { "s" },
            e(&short_day(&latest.done, view.now))
        ),
        None => "Nothing yet".to_string(),
    };
    let preview = &history[..history.len().min(HANDLED_PREVIEW)];
    let table = if preview.is_empty() {
        r#"<p class="none">Nothing handled yet.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="table-scroll" tabindex="0" role="region" aria-label="Recently handled"><table class="wide-table"><caption class="sr">Recently handled CVEs</caption><colgroup><col style="width:18%"><col style="width:34%"><col style="width:22%"><col style="width:12%"><col style="width:14%"></colgroup><thead><tr><th scope="col">CVE</th><th scope="col">What</th><th scope="col">Hosts</th><th scope="col">Done</th><th scope="col">Ticket</th></tr></thead><tbody>{}</tbody></table></div>"#,
            handled_rows(preview, view.now, false)
        )
    };
    format!(
        r#"<details class="card handled"><summary><span class="ok">{check}</span><h2>Handled</h2><span class="count">{summary}</span>{chevron}</summary>{table}<a class="textlink" href="{all}">See the full history{arrow}</a></details>"#,
        check = icon("check", ""),
        chevron = icon("chevron-right", "chev"),
        all = href(base, "/handled"),
        arrow = icon("arrow-right", "i16"),
    )
}

fn legend() -> String {
    let item = |icon_name: &str, class: &str, label: &str| {
        format!("<span>{}{label}</span>", icon(icon_name, class))
    };
    let row = |title: &str, items: Vec<String>| {
        format!(
            r#"<div class="legend"><b>{title}</b>{}</div>"#,
            items.join("")
        )
    };
    format!(
        r#"<footer class="legends" aria-label="Legend">{}{}{}{}</footer>"#,
        row(
            "Severity",
            vec![
                item("critical", "sev-critical", "Critical"),
                item("high", "sev-high", "High"),
                item("medium", "sev-medium", "Medium"),
                item("info", "sev-low", "Low"),
            ]
        ),
        row(
            "On a host",
            vec![
                item("high", "danger", "Affected"),
                item("reboot", "warn", "Reboot due"),
                item("check", "ok", "Fixed"),
                item("unknown", "muted", "Can't check"),
                item("dash", "muted", "Not applicable"),
                item("mitigated", "ok", "Mitigated"),
            ]
        ),
        row(
            "Contact",
            vec![
                item("online", "ok", "Online"),
                item("moon", "", "Asleep"),
                item("offline", "danger", "Offline"),
                item("paused", "", "Offline, optional"),
                item("no-contact", "", "No contact data"),
                item("never", "", "Never reported"),
            ]
        ),
        row(
            "Source",
            vec![
                item("beacon", "", "Beacon"),
                item("probe", "", "Probe"),
                item("hand", "", "Hand-declared"),
                item("unlisted", "", "Unlisted"),
                item("stale", "warn", "Stale"),
                item("tailnet", "accent", "On tailnet"),
            ]
        ),
    )
}

pub(super) fn render_fleet(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    view: &FleetView,
    query: &FleetQuery,
) -> String {
    let selected = query.cve.as_deref().and_then(|id| {
        let data = view.data.as_deref()?;
        view.watchlist
            .iter()
            .copied()
            .find(|index| data.cves.get(*index).is_some_and(|cve| cve.id == id))
    });

    let FleetCounts {
        affected,
        unknown,
        reboots,
    } = fleet_counts(view);
    let metrics = format!(
        r#"<section class="metrics" aria-label="Fleet summary">{}{}{}{}</section>"#,
        metric(
            "",
            "server",
            view.rows.len() as u32,
            if view.rows.len() == 1 {
                "host"
            } else {
                "hosts"
            }
        ),
        metric(
            if affected > 0 { "m-down" } else { "m-ok" },
            if affected > 0 { "high" } else { "check" },
            affected,
            "affected"
        ),
        metric("", "unknown", unknown, "can't check"),
        metric(
            if reboots > 0 { "m-sun" } else { "" },
            "reboot",
            reboots,
            if reboots == 1 {
                "reboot due"
            } else {
                "reboots due"
            }
        ),
    );
    let coverage = format!(
        r#"<p class="info">{}Kernel CVEs are computed from beacon reports. Every other CVE is hand-declared in the data file.</p>"#,
        icon("info", "")
    );
    let option = |value: Arrange, label: &str| {
        let chosen = if query.arrange == value {
            " selected"
        } else {
            ""
        };
        format!(
            r#"<option value="{}"{chosen}>{label}</option>"#,
            value.value()
        )
    };
    let keep_cve = selected
        .and_then(|index| view.data.as_deref().and_then(|data| data.cves.get(index)))
        .map(|cve| format!(r#"<input type="hidden" name="cve" value="{}">"#, e(&cve.id)))
        .unwrap_or_default();
    let tools = format!(
        r#"<form class="ptool" action="{action}" method="get" role="search" aria-label="Host controls">{keep_cve}<div class="ptool-l"><label class="arrange">Arrange by<select name="arrange" data-arrange>{site}{attention}{name}</select>{chevron}</label><noscript><button class="btn" type="submit">Apply</button></noscript></div><div class="ptool-r"><label class="search">{search}<input type="search" name="q" value="{q}" placeholder="Search hosts…" aria-label="Search hosts" data-host-search></label></div></form>"#,
        action = href(base, "/"),
        site = option(Arrange::Site, "Site"),
        attention = option(Arrange::Attention, "Needs attention"),
        name = option(Arrange::Name, "Name"),
        chevron = icon("chevron-down", ""),
        search = icon("search", ""),
        q = e(&query.q),
    );

    let mut groups = String::new();
    match query.arrange {
        Arrange::Site => {
            if let Some(data) = view.data.as_deref() {
                for (index, section) in data.sections.iter().enumerate() {
                    let rows: Vec<&HostRow> = view
                        .rows
                        .iter()
                        .filter(|row| row.section == Some(index))
                        .collect();
                    if rows.is_empty() {
                        continue;
                    }
                    let count = hosts_count(rows.len());
                    groups.push_str(&host_group(
                        base,
                        view,
                        HostGroup {
                            icon: "site",
                            title: &section.name,
                            count_label: &count,
                            place: section.place.as_deref(),
                            right: group_summary(view, &rows),
                            rows,
                            with_site: false,
                        },
                        selected,
                        &query.q,
                    ));
                }
            }
            let unlisted: Vec<&HostRow> = view
                .rows
                .iter()
                .filter(|row| row.declared.is_none())
                .collect();
            if !unlisted.is_empty() {
                let count = hosts_count(unlisted.len());
                groups.push_str(&host_group(
                    base,
                    view,
                    HostGroup {
                        icon: "unlisted",
                        title: "Unlisted",
                        count_label: &count,
                        place: Some("Reports, but isn't in the data file"),
                        right: "Add it to the data file to give it a site".to_string(),
                        rows: unlisted,
                        with_site: false,
                    },
                    selected,
                    &query.q,
                ));
            }
        }
        Arrange::Attention | Arrange::Name => {
            let mut rows: Vec<&HostRow> = view.rows.iter().collect();
            if query.arrange == Arrange::Attention {
                rows.sort_by_key(|row| (row.attention_rank(view), row.name.clone()));
            } else {
                rows.sort_by_key(|row| row.name.clone());
            }
            if !rows.is_empty() {
                let count = hosts_count(rows.len());
                groups.push_str(&host_group(
                    base,
                    view,
                    HostGroup {
                        icon: "server",
                        title: "All hosts",
                        count_label: &count,
                        place: None,
                        right: group_summary(view, &rows),
                        rows,
                        with_site: true,
                    },
                    selected,
                    &query.q,
                ));
            }
        }
    }
    let any_match = view.rows.iter().any(|row| search_matches(row, &query.q));
    let no_hosts = if view.rows.is_empty() {
        r#"<p class="host-empty" data-host-empty>No hosts yet.</p>"#.to_string()
    } else {
        format!(
            r#"<p class="host-empty" data-host-empty{}>No host matches this search.</p>"#,
            if any_match { " hidden" } else { "" }
        )
    };

    let main = format!(
        "{head}{notice}{metrics}{coverage}{watchlist}{tools}{groups}{no_hosts}{handled}{legend}",
        head = header(
            base,
            Header {
                title: "Fleet",
                back: false,
                sub: "All hosts at a glance".to_string(),
                meta: data_line(view),
            },
            view.now
        ),
        notice = data_notice(view),
        watchlist = watchlist_html(base, view, selected, query),
        handled = handled_summary(base, view),
        legend = legend(),
    );
    shell(base, user, "Fleet", Some(Nav::Fleet), &main)
}

/// A four-column table in a card, one per Updates due group.
struct UpdatesGroup {
    icon: &'static str,
    tone: &'static str,
    title: &'static str,
    headers: [&'static str; 3],
    rows: Vec<String>,
}

fn updates_group(group: UpdatesGroup) -> String {
    if group.rows.is_empty() {
        return String::new();
    }
    let [first, second, third] = group.headers;
    format!(
        r#"<section class="card"><div class="card-head"><div class="site-title"><span class="{tone}">{icon}</span><h2>{title}</h2><span class="count">{count}</span></div></div><div class="table-scroll" tabindex="0" role="region" aria-label="{title}"><table class="wide-table"><caption class="sr">{title}</caption>{FOUR_COLUMNS}<thead><tr><th scope="col" class="host">Host</th><th scope="col">{first}</th><th scope="col">{second}</th><th scope="col">{third}</th></tr></thead><tbody>{rows}</tbody></table></div></section>"#,
        tone = group.tone,
        icon = icon(group.icon, ""),
        title = e(group.title),
        count = hosts_count(group.rows.len()),
        rows = group.rows.join(""),
    )
}

fn updates_row(
    base: &PublicBasePath,
    view: &FleetView,
    row: &HostRow,
    headers: [&str; 3],
    cells: [String; 3],
) -> String {
    let [first, second, third] = cells;
    format!(
        r#"<tr><th scope="row" class="host">{label}<span class="role">{role}</span></th><td data-label="{a}">{first}</td><td data-label="{b}">{second}</td><td data-label="{c}">{third}</td></tr>"#,
        label = host_label(base, row),
        role = role_text(view, row, false),
        a = headers[0],
        b = headers[1],
        c = headers[2],
    )
}

/// What a host is waiting for, in the Updates page's words.
pub(crate) fn due_text(row: &HostRow) -> String {
    row.updates
        .due
        .iter()
        .map(|due| match due {
            UpdateDue::Reboot { .. } => "Reboot due".to_string(),
            UpdateDue::BehindConfig { commits } => commits_behind(*commits),
            UpdateDue::OldNixpkgs { age_days } => format!("Lock {age_days} d old"),
        })
        .collect::<Vec<_>>()
        .join(" · ")
}

fn report_age(row: &HostRow) -> Option<u64> {
    match row.updates.source {
        UpdatesSource::Report { age_secs, .. } => Some(age_secs),
        _ => None,
    }
}

fn nixpkgs_text(row: &HostRow, now: i64) -> String {
    let channel = row.nixpkgs_channel();
    let age = row
        .report
        .as_ref()
        .and_then(|host| host.freshness.nixpkgs_age_days_at(now));
    match (channel, age) {
        (Some(channel), Some(age)) => format!("nixpkgs {} · lock {age} d old", e(channel)),
        (Some(channel), None) => format!("nixpkgs {}", e(channel)),
        (None, Some(age)) => format!("Lock {age} d old"),
        (None, None) => "nixpkgs not known".to_string(),
    }
}

fn config_text(checks: Option<&UpdateChecks>) -> &'static str {
    match checks.map(|checks| &checks.config) {
        Some(UpdateCheck::Done) => "Matches the declared config",
        Some(UpdateCheck::DoesNotApply) => "No declared config",
        Some(UpdateCheck::Due(_)) => "Behind the declared config",
        _ => "Not known",
    }
}

fn declared_values(row: &HostRow) -> String {
    let Some(host) = row.declared.as_ref() else {
        return String::new();
    };
    let mut parts = Vec::new();
    match (host.os.as_deref(), host.version.as_deref()) {
        (Some(os), Some(version)) => parts.push(format!("{} {}", e(os), e(version))),
        (Some(os), None) => parts.push(e(os)),
        (None, Some(version)) => parts.push(e(version)),
        (None, None) => {}
    }
    if let Some(kernel) = host.kernel.as_deref() {
        parts.push(format!("kernel {}", e(kernel)));
    }
    parts.join(" · ")
}

fn hand_source(row: &HostRow) -> &'static str {
    match row.contact.source {
        ContactSource::Probe => "Probe · reachability only",
        ContactSource::Beacon => "Beacon · no newer report",
        ContactSource::Nothing => "No beacon, no probe",
    }
}

pub(super) fn render_updates(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    view: &FleetView,
) -> String {
    const REBOOT: [&str; 3] = ["Running", "Next boot", "What it means"];
    const BEHIND: [&str; 3] = ["Behind", "Status", "Confirmed by"];
    const NIXPKGS: [&str; 3] = ["nixpkgs", "Lock age", "What it means"];
    const DECLARED: [&str; 3] = ["Declared", "Label", "Source"];
    const UNKNOWN: [&str; 3] = ["State", "Why", "Source"];
    const CURRENT: [&str; 3] = ["Config", "nixpkgs", "Confirmed by"];

    let mut reboot = Vec::new();
    let mut behind = Vec::new();
    let mut old = Vec::new();
    let mut declared = Vec::new();
    let mut unknown = Vec::new();
    let mut current = Vec::new();
    for row in &view.rows {
        let age = report_age(row).map(ago).unwrap_or_default();
        let chip = if matches!(
            row.updates.source,
            UpdatesSource::Report { stale: true, .. }
        ) {
            stale_chip()
        } else {
            String::new()
        };
        for due in &row.updates.due {
            match due {
                UpdateDue::Reboot {
                    running_version,
                    next_boot_version,
                } => {
                    let version = |value: &Option<String>| {
                        value.as_deref().map_or_else(unknown_mark, |value| {
                            format!(r#"<span class="mono">{}</span>"#, e(value))
                        })
                    };
                    reboot.push(updates_row(
                        base,
                        view,
                        row,
                        REBOOT,
                        [
                            version(running_version),
                            version(next_boot_version),
                            format!("Reboot pending · report {age}{chip}"),
                        ],
                    ));
                }
                UpdateDue::BehindConfig { commits } => behind.push(updates_row(
                    base,
                    view,
                    row,
                    BEHIND,
                    [
                        format!(r#"<span class="warn">{}</span>"#, commits_behind(*commits)),
                        "Waiting for the next deploy".to_string(),
                        format!("Report {age}{chip}"),
                    ],
                )),
                UpdateDue::OldNixpkgs { age_days } => old.push(updates_row(
                    base,
                    view,
                    row,
                    NIXPKGS,
                    [
                        row.nixpkgs_channel().map_or_else(unknown_mark, |channel| {
                            format!(r#"<span class="mono">{}</span>"#, e(channel))
                        }),
                        format!(r#"<span class="warn">Lock {age_days} d old</span>"#),
                        format!("Older than {OLD_NIXPKGS_AFTER_DAYS} d · report {age}{chip}"),
                    ],
                )),
            }
        }
        match row.updates.state {
            UpdatesState::HandDeclared => {
                let (label, stale) = match &row.updates.source {
                    UpdatesSource::Declared {
                        last_verified,
                        verification_stale,
                    } => (
                        format!(
                            "Hand-declared · {}",
                            verified_text(last_verified.as_deref(), view.now)
                        ),
                        *verification_stale,
                    ),
                    _ => ("Hand-declared".to_string(), false),
                };
                declared.push(updates_row(
                    base,
                    view,
                    row,
                    DECLARED,
                    [
                        declared_values(row),
                        format!(
                            "{label}{}",
                            if stale { stale_chip() } else { String::new() }
                        ),
                        hand_source(row).to_string(),
                    ],
                ));
            }
            UpdatesState::LastKnownUpToDate => unknown.push(updates_row(
                base,
                view,
                row,
                UNKNOWN,
                [
                    "Last known: up to date".to_string(),
                    format!("Data from {age}{}", stale_chip()),
                    format!(
                        "Beacon · {}",
                        e(&contact_label(&row.contact)).to_lowercase()
                    ),
                ],
            )),
            UpdatesState::Unknown => {
                let (state, source) = match report_age(row) {
                    Some(_) => (
                        "Not answered by the report".to_string(),
                        if matches!(
                            row.updates.source,
                            UpdatesSource::Report { stale: true, .. }
                        ) {
                            format!("Data from {age}{}", stale_chip())
                        } else {
                            format!("Report {age}")
                        },
                    ),
                    None => (e(&contact_label(&row.contact)), e(contact_source(row).1)),
                };
                unknown.push(updates_row(
                    base,
                    view,
                    row,
                    UNKNOWN,
                    [
                        state,
                        "Unknown, never shown as up to date".to_string(),
                        source,
                    ],
                ));
            }
            UpdatesState::UpToDate => {
                let checks = row
                    .report
                    .as_ref()
                    .map(|host| host_update_checks(host, view.now));
                current.push(updates_row(
                    base,
                    view,
                    row,
                    CURRENT,
                    [
                        config_text(checks.as_ref()).to_string(),
                        nixpkgs_text(row, view.now),
                        format!("Confirmed by the report {age}"),
                    ],
                ));
            }
            UpdatesState::Due => {}
        }
    }

    let metrics = format!(
        r#"<section class="metrics" aria-label="Updates summary">{}{}{}{}</section>"#,
        metric(
            if reboot.is_empty() { "" } else { "m-sun" },
            "reboot",
            reboot.len() as u32,
            if reboot.len() == 1 {
                "reboot due"
            } else {
                "reboots due"
            }
        ),
        metric(
            if behind.is_empty() { "" } else { "m-sun" },
            "commit",
            behind.len() as u32,
            "behind config"
        ),
        metric(
            if old.is_empty() { "" } else { "m-sun" },
            "package",
            old.len() as u32,
            "old nixpkgs"
        ),
        metric("", "hand", declared.len() as u32, "hand-declared"),
    );
    let nothing_known_due = reboot.is_empty() && behind.is_empty() && old.is_empty();
    let nothing_due = if !nothing_known_due || view.rows.is_empty() {
        String::new()
    } else if unknown.is_empty() && declared.is_empty() {
        format!(
            r#"<p class="note">{}Nothing is due.</p>"#,
            icon("check", "ok")
        )
    } else {
        format!(
            r#"<p class="note">{}Nothing is known to be due, but Pharos can't tell for every host.</p>"#,
            icon("info", "")
        )
    };
    let main = format!(
        "{head}{notice}{metrics}{nothing_due}{a}{b}{c}{d}{f}{g}",
        head = header(
            base,
            Header {
                title: "Updates due",
                back: false,
                sub: "What each host is waiting for".to_string(),
                meta: format!(
                    r#"<p class="top-meta">{}<span>Pharos shows what is due. It confirms done only when a later report shows it.</span></p>"#,
                    icon("info", "")
                ),
            },
            view.now
        ),
        notice = data_notice(view),
        a = updates_group(UpdatesGroup {
            icon: "reboot",
            tone: "warn",
            title: "Reboot due",
            headers: REBOOT,
            rows: reboot,
        }),
        b = updates_group(UpdatesGroup {
            icon: "commit",
            tone: "warn",
            title: "Behind the declared config",
            headers: BEHIND,
            rows: behind,
        }),
        c = updates_group(UpdatesGroup {
            icon: "package",
            tone: "warn",
            title: "Old nixpkgs",
            headers: NIXPKGS,
            rows: old,
        }),
        d = updates_group(UpdatesGroup {
            icon: "hand",
            tone: "",
            title: "Hand-declared",
            headers: DECLARED,
            rows: declared,
        }),
        f = updates_group(UpdatesGroup {
            icon: "unknown",
            tone: "muted",
            title: "Can't tell yet",
            headers: UNKNOWN,
            rows: unknown,
        }),
        g = updates_group(UpdatesGroup {
            icon: "check",
            tone: "ok",
            title: "Up to date",
            headers: CURRENT,
            rows: current,
        }),
    );
    shell(base, user, "Updates due", Some(Nav::Updates), &main)
}

pub(super) fn render_handled(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    view: &FleetView,
) -> String {
    let history = view.handled_history();
    let count = history.iter().map(|entry| entry.ids.len()).sum::<usize>();
    let meta = match history.first() {
        Some(latest) => format!(
            "{count} CVE{} · last {} · fixed watchlist cards move here after three days",
            if count == 1 { "" } else { "s" },
            e(&short_day(&latest.done, view.now))
        ),
        None => "Fixed watchlist cards move here after three days".to_string(),
    };
    let body = if history.is_empty() {
        r#"<section class="card"><p class="none">Nothing handled yet.</p></section>"#.to_string()
    } else {
        format!(
            r#"<section class="card"><div class="table-scroll" tabindex="0" role="region" aria-label="Handled CVEs"><table class="wide-table"><caption class="sr">Handled CVEs, newest first</caption><colgroup><col style="width:15%"><col style="width:27%"><col style="width:16%"><col style="width:26%"><col style="width:8%"><col style="width:8%"></colgroup><thead><tr><th scope="col">CVE</th><th scope="col">What</th><th scope="col">Hosts</th><th scope="col">What we did</th><th scope="col">Done</th><th scope="col">Ticket</th></tr></thead><tbody>{}</tbody></table></div></section>"#,
            handled_rows(&history, view.now, true)
        )
    };
    let main = format!(
        "{head}{notice}{body}",
        head = header(
            base,
            Header {
                title: "Handled",
                back: false,
                sub: "CVEs we dealt with, newest first".to_string(),
                meta: format!(
                    r#"<p class="top-meta">{}<span>{meta}</span></p>"#,
                    icon("archive", "")
                ),
            },
            view.now
        ),
        notice = data_notice(view),
    );
    shell(base, user, "Handled", Some(Nav::Handled), &main)
}

fn capitalized(mut text: String) -> String {
    if let Some(first) = text.get_mut(0..1) {
        first.make_ascii_uppercase();
    }
    text
}

/// The note beside a host in one CVE's groups, and whether its evidence is stale.
fn cve_note(view: &FleetView, row: &HostRow, cve: &FleetCve, on: &CveOnHost) -> (String, bool) {
    let kernel = row.reported_kernel().unwrap_or("unknown kernel");
    let aged = |text: String| match on.status.source {
        CveStatusSource::Computed {
            age_secs,
            stale: true,
        } => (format!("{text} · data {} old", span(age_secs)), true),
        _ => (text, false),
    };
    match (on.status.status, &on.status.source) {
        (CveStatus::NotApplicable, _) => (
            capitalized(
                row.declared_note(cve)
                    .unwrap_or("marked in the data file")
                    .to_string(),
            ),
            false,
        ),
        (CveStatus::RebootDue, _) => aged(format!(
            "Running {} · next boot {}",
            kernel,
            row.reported_next_boot().unwrap_or("unknown")
        )),
        (
            status,
            CveStatusSource::Declared {
                last_verified,
                verification_stale,
            },
        ) => {
            let lead = row
                .declared_note(cve)
                .map(ToString::to_string)
                .or_else(|| (status == CveStatus::Unknown).then(|| "not checked yet".to_string()))
                .or_else(|| {
                    // The file's kernel: a report's may be older than this check.
                    (cve.component == KERNEL_COMPONENT)
                        .then(|| row.declared.as_ref()?.kernel.clone())
                        .flatten()
                });
            let check = format!(
                "hand-declared, {}",
                verified_text(last_verified.as_deref(), view.now)
            );
            let text = match lead {
                Some(lead) => format!("{} · {check}", capitalized(lead)),
                None => capitalized(check),
            };
            (text, *verification_stale)
        }
        (CveStatus::Affected, CveStatusSource::Computed { .. }) => {
            aged(format!("{kernel} · waiting for the next deploy"))
        }
        (CveStatus::Fixed, CveStatusSource::Computed { .. }) => aged(kernel.to_string()),
        (CveStatus::Unknown, CveStatusSource::Computed { .. }) => {
            aged(capitalized(row.unknown_reason(cve, on)))
        }
        (CveStatus::Unknown, _) => (capitalized(row.unknown_reason(cve, on)), false),
        _ => (String::new(), false),
    }
}

fn group_card(
    base: &PublicBasePath,
    view: &FleetView,
    cve: &FleetCve,
    index: usize,
    (title, icon_name, tone): (&str, &str, &str),
    statuses: &[CveStatus],
) -> String {
    let hosts = view.hosts_with(index, statuses);
    let items: String = if hosts.is_empty() {
        r#"<li><p class="none">None</p></li>"#.to_string()
    } else {
        hosts
            .iter()
            .map(|(row, on)| {
                let (note, stale) = cve_note(view, row, cve, on);
                format!(
                    r#"<li>{label}<span class="gnote">{note}{chip}</span></li>"#,
                    label = host_label(base, row),
                    note = e(&note),
                    chip = if stale { stale_chip() } else { String::new() },
                )
            })
            .collect()
    };
    format!(
        r#"<section class="card"><div class="card-head"><div class="site-title"><span class="{tone}">{icon}</span><h2>{title}</h2><span class="count">{count}</span></div></div><ul class="glist">{items}</ul></section>"#,
        icon = icon(icon_name, ""),
        count = hosts.len(),
    )
}

fn latest_declared_check(view: &FleetView, index: usize) -> Option<i64> {
    view.rows
        .iter()
        .filter_map(|row| row.on(index))
        .filter_map(|on| match &on.status.source {
            CveStatusSource::Declared {
                last_verified: Some(at),
                ..
            } => OffsetDateTime::parse(at, &Rfc3339)
                .ok()
                .map(OffsetDateTime::unix_timestamp),
            _ => None,
        })
        .max()
}

pub(super) fn render_cve(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    view: &FleetView,
    id: &str,
) -> Option<String> {
    let data = view.data.as_deref()?;
    let index = data.cves.iter().position(|cve| cve.id == id)?;
    let cve = data.cves.get(index)?;
    let (severity_label, severity_class, severity_icon) = severity_parts(cve.severity);
    let state = match cve.state {
        FleetCveState::Open => format!(
            r#"<span class="{severity_class}">{}Open</span>"#,
            icon("high", "")
        ),
        FleetCveState::Mitigated => {
            format!(
                r#"<span class="ok">{}Mitigated</span>"#,
                icon("mitigated", "")
            )
        }
        FleetCveState::Fixed => format!(
            r#"<span class="ok">{}Fixed {}</span>"#,
            icon("check", ""),
            cve.fixed_on
                .as_deref()
                .map(|day| e(&short_day(day, view.now)))
                .unwrap_or_default()
        ),
    };
    let fixed_in: String = if cve.fixed_in.is_empty() {
        r#"<span class="muted">Not known yet</span>"#.to_string()
    } else {
        cve.fixed_in
            .iter()
            .map(|line| format!(r#"<span class="chip">{}</span>"#, e(line)))
            .collect()
    };
    let source = if cve.component == KERNEL_COMPONENT {
        format!(
            "{}Computed from kernel reports. Hand-declared rows keep their own label.",
            icon("beacon", "")
        )
    } else {
        let latest = latest_declared_check(view, index)
            .map(|at| format!(" · latest check {}", short_date(at, view.now)))
            .unwrap_or_default();
        format!(
            "{}Hand-declared per host in the data file{latest}",
            icon("hand", "")
        )
    };
    let count = |statuses: &[CveStatus]| view.hosts_with(index, statuses).len();
    let on_fleet: Vec<String> = [
        (count(&[CveStatus::Affected]), "affected"),
        (count(&[CveStatus::RebootDue]), "reboot due"),
        (count(&[CveStatus::Unknown]), "can't check"),
        (count(&[CveStatus::Fixed]), "fixed"),
        (count(&[CveStatus::NotApplicable]), "not applicable"),
    ]
    .iter()
    .filter(|(count, _)| *count > 0)
    .map(|(count, label)| format!("{count} {label}"))
    .collect();
    let component = if cve.component == KERNEL_COMPONENT {
        "Linux kernel".to_string()
    } else {
        e(&cve.component)
    };
    let id_text = if cve.name.is_some() {
        format!(r#"<span class="mono">{}</span> · "#, e(&cve.id))
    } else {
        String::new()
    };
    let not_applicable: Vec<String> = view
        .hosts_with(index, &[CveStatus::NotApplicable])
        .iter()
        .map(|(row, _)| e(&row.name))
        .collect();
    let not_applicable = if not_applicable.is_empty() {
        String::new()
    } else {
        format!(
            r#"<p class="note">{}Not applicable: {}</p>"#,
            icon("dash", ""),
            not_applicable.join(", ")
        )
    };
    let main = format!(
        r#"{head}{notice}<section class="card" aria-label="About this CVE"><div class="eyebrow"><span class="{severity_class}">{severity_icon}{severity_label}</span>{state}</div><p class="eli">{eli}</p><div class="tip">{tip_icon}<span><strong>Tip:</strong> {tip}</span></div><dl class="kv"><div><dt>Fixed in</dt><dd class="fixline">{fixed_in}</dd></div><div><dt>Source</dt><dd><span class="src">{source}</span></dd></div><div><dt>On the fleet</dt><dd class="ink2">{on_fleet}</dd></div></dl></section><div class="groups">{affected}{reboot}{unknown}{fixed}</div>{not_applicable}"#,
        head = header(
            base,
            Header {
                title: cve_title(cve),
                back: true,
                sub: format!("{id_text}{component}"),
                meta: String::new(),
            },
            view.now
        ),
        notice = data_notice(view),
        severity_icon = icon(severity_icon, ""),
        eli = e(&cve.eli10),
        tip_icon = icon("tip", ""),
        tip = e(&cve.tip),
        on_fleet = on_fleet.join(" · "),
        affected = group_card(
            base,
            view,
            cve,
            index,
            ("Affected", "high", "danger"),
            &[CveStatus::Affected]
        ),
        reboot = group_card(
            base,
            view,
            cve,
            index,
            ("Reboot due", "reboot", "warn"),
            &[CveStatus::RebootDue]
        ),
        unknown = group_card(
            base,
            view,
            cve,
            index,
            ("Can't check", "unknown", "muted"),
            &[CveStatus::Unknown]
        ),
        fixed = group_card(
            base,
            view,
            cve,
            index,
            ("Fixed", "check", "ok"),
            &[CveStatus::Fixed]
        ),
    );
    Some(shell(base, user, cve_title(cve), None, &main))
}

fn on_host_status(status: CveStatus) -> (&'static str, &'static str, &'static str) {
    match status {
        CveStatus::Affected => ("Affected", "danger", "high"),
        CveStatus::RebootDue => ("Reboot due", "warn", "reboot"),
        CveStatus::Fixed => ("Fixed", "ok", "check"),
        CveStatus::Unknown => ("Can't check", "muted", "unknown"),
        CveStatus::NotApplicable => ("Not applicable", "muted", "dash"),
    }
}

/// What the patch status rests on: only what makes this host affected counts, so
/// a hand-declared fix elsewhere never colours a computed answer.
fn patch_sentence(view: &FleetView, row: &HostRow) -> String {
    let watched: Vec<&CveOnHost> = view
        .watchlist
        .iter()
        .filter_map(|index| row.on(*index))
        .collect();
    let reboot_due = watched
        .iter()
        .any(|on| on.status.status == CveStatus::RebootDue);
    let affected: Vec<&CveOnHost> = watched
        .iter()
        .copied()
        .filter(|on| on.status.status == CveStatus::Affected)
        .collect();
    let verified = |rows: &[&CveOnHost]| {
        rows.iter()
            .filter_map(|on| match &on.status.source {
                CveStatusSource::Declared {
                    last_verified: Some(at),
                    ..
                } => OffsetDateTime::parse(at, &Rfc3339)
                    .ok()
                    .map(OffsetDateTime::unix_timestamp),
                _ => None,
            })
            .min()
            .map_or_else(
                || "not verified".to_string(),
                |at| format!("verified {}", short_date(at, view.now)),
            )
    };
    if reboot_due {
        return if affected.is_empty() {
            "The next boot runs a fixed kernel. Reboot due.".to_string()
        } else {
            "The next boot fixes part of this. Reboot due.".to_string()
        };
    }
    if !affected.is_empty() {
        let computed = affected
            .iter()
            .any(|on| matches!(on.status.source, CveStatusSource::Computed { .. }));
        return if computed {
            "From the running kernel. It stays affected until a report shows a fixed one."
                .to_string()
        } else {
            format!(
                "From the data file, {}. It stays affected while the host is away.",
                verified(&affected)
            )
        };
    }
    if row.security(view).unknown > 0 {
        return "Pharos can't check every watched CVE on this host yet.".to_string();
    }
    let declared: Vec<&CveOnHost> = watched
        .iter()
        .copied()
        .filter(|on| {
            on.status.status != CveStatus::NotApplicable
                && matches!(on.status.source, CveStatusSource::Declared { .. })
        })
        .collect();
    if row.report.is_none() && !declared.is_empty() {
        return format!("From the data file, {}.", verified(&declared));
    }
    "No watched CVE is open on this host.".to_string()
}

fn availability_sentence(view: &FleetView, row: &HostRow) -> String {
    match row.contact.state {
        ContactState::NoContactData => {
            return "No beacon and no probe, so there is no offline colour. Only the hand-declared values and when they were checked.".to_string();
        }
        ContactState::NeverReported => {
            return "Listed in the data file, but no report has arrived.".to_string();
        }
        _ => {}
    }
    let last = match (row.contact.last_contact, row.contact.source) {
        (Some(at), ContactSource::Probe) => {
            format!(" Last contact {}, by probe.", short_date(at, view.now))
        }
        (Some(at), ContactSource::Beacon) => {
            format!(" Last contact {}, by beacon.", short_date(at, view.now))
        }
        _ => String::new(),
    };
    let Some(host) = row.declared.as_ref() else {
        return format!(
            "Reports, but isn't in the data file, so nothing says when it should.{last}"
        );
    };
    match host.availability {
        Availability::AlwaysOn => format!("Always on: offline is red.{last}"),
        Availability::Client => {
            let thresholds = view
                .data
                .as_deref()
                .and_then(|data| host.offline_thresholds(&data.defaults));
            match thresholds {
                Some(thresholds) => format!(
                    "Client: asleep is normal. Yellow after {} d and red after {} d without contact.{last}",
                    thresholds.offline_warn_days, thresholds.offline_red_days
                ),
                None => format!("Client: asleep is normal.{last}"),
            }
        }
        Availability::Optional => {
            format!("Optional: offline is normal and never turns yellow or red.{last}")
        }
    }
}

fn tile(label: &str, class: &str, icon_name: &str, value: &str, sub: &str) -> String {
    format!(
        r#"<div class="tile"><span class="lbl">{label}</span><div class="val {class}">{}{value}</div><span class="sub">{sub}</span></div>"#,
        icon(icon_name, "")
    )
}

fn updates_tiles(view: &FleetView, row: &HostRow) -> (String, String) {
    // A host that registered but never reported has nothing to show here yet.
    let Some(host) = row.report.as_ref().filter(|host| {
        host.last_seen.is_some() && !matches!(row.updates.state, UpdatesState::HandDeclared)
    }) else {
        let declared = row.declared.as_ref();
        let os = declared
            .map(|_| declared_os(row))
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "Not declared".to_string());
        let kernel = declared
            .and_then(|host| host.kernel.as_deref())
            .map_or_else(|| "Not declared".to_string(), e);
        let (source, updates) = match &row.updates.source {
            UpdatesSource::Declared {
                last_verified,
                verification_stale,
            } => (
                format!(
                    "{}Hand-declared · {}{}",
                    icon("hand", ""),
                    verified_text(last_verified.as_deref(), view.now),
                    if *verification_stale {
                        stale_chip()
                    } else {
                        String::new()
                    }
                ),
                "Declared values only",
            ),
            _ => (
                format!("{}No report yet", icon("never", "")),
                "Can't tell yet",
            ),
        };
        return (
            source,
            format!(
                "{}{}{}",
                tile("Declared OS", "", "data-file", &os, "Hand-declared"),
                tile("Declared kernel", "", "data-file", &kernel, "Hand-declared"),
                tile(
                    "Updates",
                    "",
                    "unknown",
                    updates,
                    "No report from this host"
                ),
            ),
        );
    };
    let checks = host_update_checks(host, view.now);
    let age = report_age(row).unwrap_or_default();
    let stale = matches!(
        row.updates.source,
        UpdatesSource::Report { stale: true, .. }
    );
    let source = format!(
        "{}Beacon · {}{}",
        icon("beacon", ""),
        ago(age),
        if stale { stale_chip() } else { String::new() }
    );
    let kernel = match &checks.kernel {
        UpdateCheck::Due(UpdateDue::Reboot {
            running_version,
            next_boot_version,
        }) => tile(
            "Kernel",
            "warn",
            "reboot",
            "Reboot due",
            &format!(
                "Running {} · next boot {}",
                e(running_version.as_deref().unwrap_or("unknown")),
                e(next_boot_version.as_deref().unwrap_or("unknown"))
            ),
        ),
        UpdateCheck::Done => tile(
            "Kernel",
            "ok",
            "check",
            "No reboot due",
            &format!("Running {}", e(row.kernel().unwrap_or("unknown"))),
        ),
        UpdateCheck::DoesNotApply => {
            tile("Kernel", "", "dash", "Does not apply", "Not a Linux report")
        }
        _ => tile(
            "Kernel",
            "",
            "unknown",
            "Can't tell yet",
            "Not in the report",
        ),
    };
    let config = match &checks.config {
        UpdateCheck::Due(UpdateDue::BehindConfig { commits }) => tile(
            "Config",
            "warn",
            "commit",
            &commits_behind(*commits),
            "Waiting for the next deploy",
        ),
        UpdateCheck::Done => tile(
            "Config",
            "ok",
            "check",
            "Matches",
            "The declared config is deployed",
        ),
        UpdateCheck::DoesNotApply => tile("Config", "", "dash", "Does not apply", "Not a Nix host"),
        _ => tile(
            "Config",
            "",
            "unknown",
            "Can't tell yet",
            "Not in the report",
        ),
    };
    let nixpkgs = match &checks.nixpkgs {
        UpdateCheck::Due(UpdateDue::OldNixpkgs { age_days }) => tile(
            "nixpkgs",
            "warn",
            "package",
            &format!("Lock {age_days} d old"),
            &format!("Older than {OLD_NIXPKGS_AFTER_DAYS} d"),
        ),
        UpdateCheck::Done => tile(
            "nixpkgs",
            "",
            "package",
            &nixpkgs_text(row, view.now),
            "From the latest report",
        ),
        UpdateCheck::DoesNotApply => {
            tile("nixpkgs", "", "dash", "Does not apply", "Not a Nix host")
        }
        _ => tile(
            "nixpkgs",
            "",
            "unknown",
            "Can't tell yet",
            "Not in the report",
        ),
    };
    (source, format!("{kernel}{config}{nixpkgs}"))
}

fn declared_os(row: &HostRow) -> String {
    let Some(host) = row.declared.as_ref() else {
        return String::new();
    };
    match (host.os.as_deref(), host.version.as_deref()) {
        (Some(os), Some(version)) => format!("{} {}", e(os), e(version)),
        (Some(os), None) => e(os),
        (None, Some(version)) => e(version),
        (None, None) => String::new(),
    }
}

fn kv(label: &str, value: String) -> String {
    format!("<div><dt>{label}</dt><dd>{value}</dd></div>")
}

fn mono_or_muted(value: Option<&str>, missing: &str) -> String {
    value.map_or_else(
        || format!(r#"<span class="muted">{missing}</span>"#),
        |value| format!(r#"<span class="mono">{}</span>"#, e(value)),
    )
}

pub(super) fn render_host(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    view: &FleetView,
    name: &str,
) -> Option<String> {
    let row = view.row(name)?;
    let data = view.data.as_deref();
    let site = row
        .section
        .and_then(|section| data.and_then(|data| data.sections.get(section)));
    let sub = match (row.role(), site) {
        (Some(role), Some(site)) => format!("{} · {}", e(role), e(&site.name)),
        (Some(role), None) if row.declared.is_some() => e(role),
        (Some(role), None) => format!("{} · Unlisted", e(role)),
        (None, Some(site)) => e(&site.name),
        (None, None) => "Unlisted".to_string(),
    };

    let mut pills = Vec::new();
    let (source_icon, source_text) = contact_source(row);
    pills.push(format!(
        r#"<span class="pill">{}{}</span>"#,
        icon(source_icon, ""),
        e(source_text)
    ));
    if let Some(host) = row.declared.as_ref() {
        let availability = match host.availability {
            Availability::AlwaysOn => "Always on",
            Availability::Client => "Client",
            Availability::Optional => "Optional",
        };
        pills.push(format!(r#"<span class="pill">{availability}</span>"#));
    }
    if let UpdatesSource::Declared {
        last_verified,
        verification_stale,
    } = &row.updates.source
    {
        pills.push(format!(
            r#"<span class="pill">{}Hand-declared · {}</span>"#,
            icon("hand", ""),
            verified_text(last_verified.as_deref(), view.now)
        ));
        if *verification_stale {
            pills.push(format!(
                r#"<span class="pill warn">{}Stale</span>"#,
                icon("stale", "")
            ));
        }
    }

    let declared = row.declared.as_ref();
    let tailnet = declared.and_then(|host| match host.tailnet.state {
        TailnetState::None => None,
        _ => host.tailnet.ip.as_deref(),
    });
    let mut about = vec![
        kv(
            "OS",
            match (row.os(), row.os_version()) {
                (Some(os), Some(version)) => format!("{} {}", e(os), e(version)),
                (Some(os), None) => e(os),
                _ => r#"<span class="muted">Not known</span>"#.to_string(),
            },
        ),
        kv("Kernel", mono_or_muted(row.kernel(), "Not known")),
        kv("Tailnet", mono_or_muted(tailnet, "No tailnet")),
        kv(
            "LAN",
            mono_or_muted(
                declared.and_then(|host| host.lan.as_deref()),
                "Not declared",
            ),
        ),
    ];
    if let Some(public) = declared.and_then(|host| host.public.as_deref()) {
        about.push(kv("Public", mono_or_muted(Some(public), "")));
    }
    about.push(kv(
        "Site",
        site.map_or_else(
            || r#"<span class="muted">Unlisted</span>"#.to_string(),
            |site| e(&site.name),
        ),
    ));

    let security = row.security(view);
    let summary = {
        let parts: Vec<String> = SEVERITIES
            .iter()
            .filter(|severity| security.by_severity[**severity as usize] > 0)
            .map(|severity| {
                let (label, class, _) = severity_parts(*severity);
                format!(
                    r#"<span class="sevc {class}">{} {}</span>"#,
                    security.by_severity[*severity as usize],
                    label.to_lowercase()
                )
            })
            .collect();
        match SEVERITIES
            .iter()
            .find(|severity| security.by_severity[**severity as usize] > 0)
        {
            Some(top) => {
                let (_, class, icon_name) = severity_parts(*top);
                format!(
                    "{}<span>{}</span>",
                    icon(icon_name, class),
                    parts.join(" · ")
                )
            }
            None if security.unknown > 0 => {
                format!("{}<span>Can't check</span>", icon("unknown", "muted"))
            }
            None => format!("{}<span>No watched CVEs</span>", icon("check", "ok")),
        }
    };

    let (updates_source, tiles) = updates_tiles(view, row);
    let cve_rows: String = data
        .map(|data| {
            view.watchlist
                .iter()
                .filter_map(|index| data.cves.get(*index).zip(row.on(*index)))
                .map(|(cve, on)| {
                    let (label, class, _) = severity_parts(cve.severity);
                    let (status, status_class, status_icon) = on_host_status(on.status.status);
                    let (note, stale) = cve_note(view, row, cve, on);
                    let note = if note.is_empty() {
                        "—".to_string()
                    } else {
                        e(&note)
                    };
                    format!(
                        r#"<tr><th scope="row"><a class="cve-id linkbtn" href="{href}">{id}</a></th><td data-label="What">{what}</td><td data-label="Severity"><span class="il {class}">{severity_icon}{label}</span></td><td data-label="On this host"><span class="il {status_class}">{status_icon}{status}</span></td><td class="muted" data-label="Detail">{note}{chip}</td></tr>"#,
                        href = cve_href(base, &cve.id),
                        id = e(&cve.id),
                        what = e(cve_title(cve)),
                        severity_icon = icon(severity_parts(cve.severity).2, "i16"),
                        status_icon = icon(status_icon, "i16"),
                        chip = if stale { stale_chip() } else { String::new() },
                    )
                })
                .collect()
        })
        .unwrap_or_default();
    let cves = if cve_rows.is_empty() {
        r#"<p class="none">Nothing on the watchlist.</p>"#.to_string()
    } else {
        format!(
            r#"<div class="table-scroll" tabindex="0" role="region" aria-label="Watched CVEs"><table class="wide-table"><caption class="sr">Watched CVEs on {name}</caption><colgroup><col style="width:16%"><col style="width:24%"><col style="width:13%"><col style="width:17%"><col style="width:30%"></colgroup><thead><tr><th scope="col">CVE</th><th scope="col">What</th><th scope="col">Severity</th><th scope="col">On this host</th><th scope="col">Detail</th></tr></thead><tbody>{cve_rows}</tbody></table></div>"#,
            name = e(&row.name),
        )
    };

    let main = format!(
        r#"{head}{notice}<section class="card" aria-label="About this host"><div class="hhead"><span class="badge">{badge}</span><span class="hkind">{kind}</span><div class="pills">{pills}</div></div><dl class="kv">{about}</dl></section><div class="two"><section class="card"><span class="lbl">Patch status</span><div class="big">{summary}</div><p>{patch}</p></section><section class="card"><span class="lbl">Availability</span><div class="big {tone}">{contact_icon}<span>{contact}</span></div><p>{availability}</p></section></div><p class="note">{info}Patch status and availability are separate. A sleeping host on a vulnerable version still shows as affected.</p><section class="card"><div class="card-head"><h2>Updates due</h2><span class="src">{updates_source}</span></div><div class="tiles">{tiles}</div></section><section class="card"><div class="card-head"><h2>Watched CVEs</h2><span class="count">{watched} on the watchlist</span></div>{cves}</section>"#,
        head = header(
            base,
            Header {
                title: &row.name,
                back: true,
                sub,
                meta: String::new(),
            },
            view.now
        ),
        notice = data_notice(view),
        badge = icon(kind_icon(row), ""),
        kind = kind_label(row),
        pills = pills.join(""),
        about = about.join(""),
        patch = e(&patch_sentence(view, row)),
        tone = tone_class(row.contact.tone),
        contact_icon = icon(contact_icon(&row.contact), ""),
        contact = e(&contact_label(&row.contact)),
        availability = e(&availability_sentence(view, row)),
        info = icon("info", ""),
        watched = view.watchlist.len(),
    );
    Some(shell(base, user, &row.name, None, &main))
}

pub(super) fn render_not_found(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    what: &str,
    now: i64,
) -> String {
    let main = format!(
        r#"{head}<section class="card"><p class="none">Nothing here by that name.</p></section>"#,
        head = header(
            base,
            Header {
                title: what,
                back: true,
                sub: "Not found".to_string(),
                meta: String::new(),
            },
            now
        ),
    );
    shell(base, user, what, None, &main)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use pharos_core::fleet_data::FleetData;

    use super::*;
    use crate::fleet_data::FleetDataView;
    use crate::host_probes::HostProbeObservation;

    /// 2000-03-01T00:00:00Z
    const NOW: i64 = 951_868_800;

    fn data(cves: serde_json::Value, hosts: serde_json::Value) -> FleetData {
        FleetData::parse(
            &serde_json::json!({
                "schema_version": 3,
                "title": "Example <fleet>",
                "updated_at": "2000-02-29T22:00:00Z",
                "updated_by": "example-operator",
                "defaults": { "client": { "offline_warn_days": 30, "offline_red_days": 60 } },
                "cves": cves,
                "handled": [],
                "sections": [{
                    "id": "harbor",
                    "name": "Harbor <b>",
                    "place": "Example City",
                    "hosts": hosts,
                }],
            })
            .to_string(),
        )
        .expect("fixture is valid")
    }

    fn kernel_cve(id: &str, fixed_in: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "severity": "critical",
            "state": "open",
            "component": "kernel",
            "eli10": "A <b>kernel</b> flaw.",
            "tip": "Update <now>.",
            "fixed_in": [fixed_in],
        })
    }

    fn library_cve(id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": id,
            "severity": "high",
            "state": "open",
            "component": "example-library",
            "eli10": "A library flaw.",
            "tip": "Update the library.",
            "fixed_in": ["2.0.0"],
        })
    }

    fn listed(name: &str, cve: serde_json::Value) -> serde_json::Value {
        serde_json::json!({
            "name": name,
            "kind": "nixos",
            "tailnet": { "state": "none" },
            "availability": "always_on",
            "cve": cve,
        })
    }

    fn report(name: &str, running: &str, next_boot: &str) -> Host {
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
                "state": if running == next_boot { "current" } else { "reboot_required" },
                "running_version": running,
                "expected_version": next_boot,
                "observed_at": NOW - 60,
            },
        }))
        .expect("fixture is a host")
    }

    fn view_of(fleet: Option<FleetData>, problem: Option<&str>, hosts: Vec<Host>) -> FleetView {
        FleetView::build(
            Some(FleetDataView {
                data: fleet.map(Arc::new),
                problem: problem.map(ToString::to_string),
            }),
            hosts,
            BTreeMap::<String, HostProbeObservation>::new(),
            NOW,
        )
    }

    fn fleet_page(view: &FleetView) -> String {
        render_fleet(&PublicBasePath::root(), None, view, &FleetQuery::default())
    }

    fn sentence(view: &FleetView, name: &str) -> String {
        patch_sentence(view, view.row(name).expect("row exists"))
    }

    #[test]
    fn everything_from_a_file_or_report_is_escaped() {
        let fleet = data(
            serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
            serde_json::json!([listed("hermes", serde_json::json!({}))]),
        );
        let hostile = report("<img src=x onerror=1>", "<script>", "<script>");
        let view = view_of(Some(fleet), Some("a <bad> file"), vec![hostile]);
        let query = FleetQuery {
            q: "\"><script>alert(1)</script>".to_string(),
            ..FleetQuery::default()
        };
        let page = render_fleet(&PublicBasePath::root(), None, &view, &query);
        assert!(!page.contains("<img src=x"));
        assert!(!page.contains("Harbor <b>"));
        assert!(!page.contains("<bad>"));
        assert!(!page.contains("<script>alert"));
        assert!(page.contains("&lt;img src=x"));
        assert!(page.contains("Harbor &lt;b&gt;"));
        assert!(page.contains("a &lt;bad&gt; file"));
        assert!(page.contains(r#"href="/hosts/%3Cimg%20src%3Dx%20onerror%3D1%3E""#));

        let cve = render_cve(&PublicBasePath::root(), None, &view, "CVE-2000-0001").unwrap();
        assert!(cve.contains("A &lt;b&gt;kernel&lt;/b&gt; flaw."));
        assert!(cve.contains("Update &lt;now&gt;."));
        assert!(!cve.contains("<now>"));
        let host = render_host(
            &PublicBasePath::root(),
            None,
            &view,
            "<img src=x onerror=1>",
        )
        .unwrap();
        assert!(!host.contains("<img src=x"));
    }

    #[test]
    fn every_link_and_asset_stays_inside_the_mount() {
        let fleet = data(
            serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
            serde_json::json!([listed("hermes", serde_json::json!({}))]),
        );
        let view = view_of(Some(fleet), None, Vec::new());
        let base = PublicBasePath::parse("/pharos").unwrap();
        let page = render_fleet(&base, None, &view, &FleetQuery::default());
        for expected in [
            r#"href="/pharos""#,
            r#"href="/pharos/updates""#,
            r#"href="/pharos/handled""#,
            r#"href="/pharos/hosts/hermes""#,
            r#"href="/pharos?cve=CVE-2000-0001""#,
            r#"href="/pharos/assets/ui/app.css""#,
            r#"src="/pharos/assets/ui/app.js""#,
            r#"action="/pharos""#,
        ] {
            assert!(page.contains(expected), "missing {expected}");
        }
        let cve = render_cve(&base, None, &view, "CVE-2000-0001").unwrap();
        assert!(cve.contains(r#"class="back" href="/pharos""#));
    }

    #[test]
    fn the_pages_change_nothing_on_a_host() {
        let fleet = data(
            serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
            serde_json::json!([listed("hermes", serde_json::json!({}))]),
        );
        let view = view_of(
            Some(fleet),
            None,
            vec![report("hermes", "6.18.52", "6.18.52")],
        );
        let user = AuthUser {
            display_name: "operator".to_string(),
        };
        let base = PublicBasePath::root();
        let pages = [
            render_fleet(&base, Some(&user), &view, &FleetQuery::default()),
            render_updates(&base, Some(&user), &view),
            render_handled(&base, Some(&user), &view),
            render_cve(&base, Some(&user), &view, "CVE-2000-0001").unwrap(),
            render_host(&base, Some(&user), &view, "hermes").unwrap(),
        ];
        for page in pages {
            assert_eq!(page.matches(r#"method="post""#).count(), 1, "only sign out");
            // scripts/live-ui-apps.mjs tells a signed-in page by this form in the sidebar.
            let start = page.find(r#"<aside class="side""#).unwrap();
            let side = &page[start..page.find("</aside>").unwrap()];
            assert!(side.contains(r#"action="/auth/logout" method="post""#));
        }
    }

    #[test]
    fn unknown_names_are_not_pages() {
        let fleet = data(serde_json::json!([]), serde_json::json!([]));
        let view = view_of(Some(fleet), None, Vec::new());
        let base = PublicBasePath::root();
        assert!(render_cve(&base, None, &view, "CVE-2000-0001").is_none());
        assert!(render_host(&base, None, &view, "hermes").is_none());
    }

    #[test]
    fn an_empty_watchlist_says_so() {
        let fleet = data(serde_json::json!([]), serde_json::json!([]));
        let page = fleet_page(&view_of(Some(fleet), None, Vec::new()));
        assert!(page.contains("Nothing on the watchlist"));
        assert!(!page.contains(r#"class="wcard"#));
    }

    #[test]
    fn the_page_always_says_what_is_wrong_with_the_file() {
        let good = || {
            data(
                serde_json::json!([]),
                serde_json::json!([listed("hermes", serde_json::json!({}))]),
            )
        };
        let page = fleet_page(&view_of(Some(good()), None, Vec::new()));
        assert!(page.contains("Data file updated 2 h ago"));
        assert!(!page.contains(r#"class="notice""#));

        let page = fleet_page(&view_of(
            Some(good()),
            Some("the file is missing"),
            Vec::new(),
        ));
        assert!(page.contains("this page shows the last good data, from 2 h ago"));
        assert!(page.contains("the file is missing."));
        assert!(page.contains("Data file invalid · showing the last good file from 2 h ago"));
        assert!(page.contains("hermes"));

        let page = fleet_page(&view_of(None, Some("the file is missing"), Vec::new()));
        assert!(page.contains("there is no earlier copy"));
        assert!(page.contains("No hosts yet."));

        let page = fleet_page(&view_of(
            None,
            None,
            vec![report("ares", "6.18.56", "6.18.56")],
        ));
        assert!(page.contains("The data file has not loaded yet."));
        assert!(page.contains("ares"));

        let unconfigured = FleetView::build(
            None,
            Vec::new(),
            BTreeMap::<String, HostProbeObservation>::new(),
            NOW,
        );
        assert!(fleet_page(&unconfigured).contains("No data file is configured."));
    }

    #[test]
    fn the_patch_sentence_rests_on_what_makes_the_host_affected() {
        let fleet = data(
            serde_json::json!([
                kernel_cve("CVE-2000-0001", "6.18.56"),
                kernel_cve("CVE-2000-0002", "6.18.60"),
                library_cve("CVE-2000-0003"),
            ]),
            serde_json::json!([
                listed(
                    "computed",
                    serde_json::json!({
                        "CVE-2000-0003": { "state": "fixed", "last_verified": "2000-02-20T00:00:00Z" },
                    })
                ),
                listed(
                    "declared",
                    serde_json::json!({
                        "CVE-2000-0003": { "state": "affected", "last_verified": "2000-02-20T00:00:00Z" },
                    })
                ),
                listed("part", serde_json::json!({})),
            ]),
        );
        let view = view_of(
            Some(fleet),
            None,
            vec![
                report("computed", "6.18.52", "6.18.52"),
                report("part", "6.18.52", "6.18.56"),
            ],
        );
        // A hand-declared fix on another CVE must not make this read as hand-declared.
        assert_eq!(
            sentence(&view, "computed"),
            "From the running kernel. It stays affected until a report shows a fixed one."
        );
        assert_eq!(
            sentence(&view, "declared"),
            "From the data file, verified 20 Feb. It stays affected while the host is away."
        );
        assert_eq!(
            sentence(&view, "part"),
            "The next boot fixes part of this. Reboot due."
        );
    }

    #[test]
    fn a_reboot_that_fixes_everything_says_so() {
        let fleet = data(
            serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
            serde_json::json!([listed("hermes", serde_json::json!({}))]),
        );
        let view = view_of(
            Some(fleet),
            None,
            vec![report("hermes", "6.18.52", "6.18.56")],
        );
        assert_eq!(
            sentence(&view, "hermes"),
            "The next boot runs a fixed kernel. Reboot due."
        );
    }

    #[test]
    fn nothing_open_never_reads_as_a_check_that_did_not_happen() {
        let fleet = data(
            serde_json::json!([
                kernel_cve("CVE-2000-0001", "6.18.56"),
                library_cve("CVE-2000-0002"),
            ]),
            serde_json::json!([
                listed(
                    "clean",
                    serde_json::json!({
                        "CVE-2000-0002": { "state": "na" },
                    })
                ),
                listed("unknown", serde_json::json!({})),
                listed(
                    "handfixed",
                    serde_json::json!({
                        "CVE-2000-0001": { "state": "fixed", "last_verified": "2000-02-20T00:00:00Z" },
                        "CVE-2000-0002": { "state": "fixed", "last_verified": "2000-02-20T00:00:00Z" },
                    })
                ),
            ]),
        );
        let view = view_of(
            Some(fleet),
            None,
            vec![
                report("clean", "6.18.56", "6.18.56"),
                report("unknown", "6.18.56", "6.18.56"),
            ],
        );
        assert_eq!(
            sentence(&view, "clean"),
            "No watched CVE is open on this host."
        );
        assert_eq!(
            sentence(&view, "unknown"),
            "Pharos can't check every watched CVE on this host yet."
        );
        assert_eq!(
            sentence(&view, "handfixed"),
            "From the data file, verified 20 Feb."
        );
    }

    #[test]
    fn a_host_marked_not_applicable_has_no_verification_to_show() {
        let fleet = data(
            serde_json::json!([library_cve("CVE-2000-0001")]),
            serde_json::json!([listed(
                "hermes",
                serde_json::json!({
                    "CVE-2000-0001": { "state": "na" },
                })
            )]),
        );
        let view = view_of(Some(fleet), None, Vec::new());
        let page = render_host(&PublicBasePath::root(), None, &view, "hermes").unwrap();
        assert!(page.contains("Marked in the data file"));
        assert!(!page.contains("not verified"));
    }

    #[test]
    fn a_probe_with_no_result_is_not_called_unprobed() {
        let fleet = data(
            serde_json::json!([]),
            serde_json::json!([listed("hermes", serde_json::json!({}))]),
        );
        let probes = BTreeMap::from([(
            "hermes".to_string(),
            HostProbeObservation {
                reachable: None,
                checked_at: Some(NOW),
                last_reachable_at: None,
            },
        )]);
        let view = FleetView::build(
            Some(FleetDataView {
                data: Some(Arc::new(fleet)),
                problem: None,
            }),
            Vec::new(),
            probes,
            NOW,
        );
        let page = fleet_page(&view);
        assert!(page.contains("No result yet"));
        assert!(page.contains("Probe · reachability only"));
        assert!(!page.contains("Not probed"));
    }

    fn fixed_long_ago(id: &str) -> serde_json::Value {
        let mut cve = kernel_cve(id, "6.18.56");
        cve["state"] = serde_json::json!("fixed");
        cve["fixed_on"] = serde_json::json!("2000-02-01");
        cve
    }

    fn old_report(running: &str, next_boot: &str) -> Host {
        let mut host = report("ares", running, next_boot);
        host.last_seen = Some(NOW - 2 * 86_400);
        host
    }

    #[test]
    fn a_fixed_cve_stays_watched_while_a_host_is_still_on_it() {
        let fleet = || {
            data(
                serde_json::json!([fixed_long_ago("CVE-2000-0001")]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )
        };
        for (running, next_boot) in [("6.18.52", "6.18.52"), ("6.18.52", "6.18.56")] {
            let view = view_of(Some(fleet()), None, vec![old_report(running, next_boot)]);
            assert_eq!(view.watchlist, [0], "{running} {next_boot}");
            assert_eq!(fleet_counts(&view).affected, 1, "{running} {next_boot}");
            assert!(view.handled_history().is_empty(), "{running} {next_boot}");
            let page = fleet_page(&view);
            assert!(page.contains(r#"<span class="cve-id">CVE-2000-0001</span>"#));
        }

        let patched = view_of(
            Some(fleet()),
            None,
            vec![report("ares", "6.18.56", "6.18.56")],
        );
        assert!(patched.watchlist.is_empty());
        assert_eq!(fleet_counts(&patched).affected, 0);
        assert_eq!(patched.handled_history().len(), 1);

        // Time alone doesn't make it handled while a host can't answer for it.
        let silent = view_of(Some(fleet()), None, Vec::new());
        assert_eq!(silent.watchlist, [0]);
        assert!(silent.handled_history().is_empty());
        assert_eq!(fleet_counts(&silent).unknown, 1);

        let unanswered = view_of(
            Some(fleet()),
            None,
            vec![report("ares", "6.12.1", "6.12.1")],
        );
        assert_eq!(unanswered.watchlist, [0]);
        assert!(unanswered.handled_history().is_empty());
        assert_eq!(fleet_counts(&unanswered).unknown, 1);
        assert!(!fleet_page(&unanswered).contains("No watched CVEs"));

        // A status in the file lets it go, which is how an unanswerable host is closed.
        let mut closed = fleet();
        closed.sections[0].hosts[0].cve.insert(
            "CVE-2000-0001".to_string(),
            serde_json::from_value(serde_json::json!({"state": "na"})).unwrap(),
        );
        let closed = view_of(Some(closed), None, Vec::new());
        assert!(closed.watchlist.is_empty());
        assert_eq!(closed.handled_history().len(), 1);

        // A host the file doesn't list only holds what its own report can't answer.
        let empty = || {
            data(
                serde_json::json!([fixed_long_ago("CVE-2000-0001")]),
                serde_json::json!([]),
            )
        };
        let unlisted = view_of(
            Some(empty()),
            None,
            vec![report("ares", "6.12.1", "6.12.1")],
        );
        assert_eq!(unlisted.watchlist, [0]);
        let mut tool = fixed_long_ago("CVE-2000-0001");
        tool["component"] = "example-library".into();
        let unlisted = view_of(
            Some(data(serde_json::json!([tool]), serde_json::json!([]))),
            None,
            vec![report("ares", "6.12.1", "6.12.1")],
        );
        assert!(unlisted.watchlist.is_empty());
    }

    #[test]
    fn stale_evidence_is_labelled_on_every_path_that_shows_it() {
        let api = |view: &FleetView| {
            serde_json::to_value(crate::fleet_api::api_host(view, &view.rows[0])).unwrap()
        };

        // A newer check of the versions doesn't freshen the report behind the CVE.
        let mut declared = listed("ares", serde_json::json!({}));
        declared["version"] = "1.0".into();
        declared["kernel"] = "6.18.56".into();
        declared["last_verified"] = "2000-02-29T20:00:00Z".into();
        let declared = view_of(
            Some(data(
                serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                serde_json::json!([declared]),
            )),
            None,
            vec![old_report("6.18.52", "6.18.52")],
        );
        let row = &declared.rows[0];
        assert_eq!(row.stale_computed_age(&declared), Some(2 * 86_400));
        let note = update_note(&declared, row);
        assert!(note.contains("Stale"), "{note}");
        assert_eq!(api(&declared)["stale"], true);

        // An unknown outcome keeps its age and its label, on the CVE page and on Updates.
        let unknown = view_of(
            Some(data(
                serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )),
            None,
            vec![old_report("5.4.1", "5.4.1")],
        );
        let row = &unknown.rows[0];
        let cve = &unknown.data.as_deref().unwrap().cves[0];
        let (note, stale) = cve_note(&unknown, row, cve, row.on(0).unwrap());
        assert!(stale, "{note}");
        assert!(note.contains("data 2 d old"), "{note}");
        let updates = render_updates(&PublicBasePath::root(), None, &unknown);
        assert!(updates.contains("Not answered by the report"), "{updates}");
        assert!(updates.contains("Data from"), "{updates}");
        assert!(updates.contains("Stale"), "{updates}");
    }

    #[test]
    fn no_data_file_is_never_shown_as_clear() {
        for problem in [None, Some("the file is missing")] {
            let view = view_of(None, problem, vec![report("ares", "6.18.56", "6.18.56")]);
            let page = fleet_page(&view);
            assert!(!page.contains("No watched CVEs"), "{page}");
            assert_eq!(
                security_text(&view, &view.rows[0]),
                "Can't check: no data file"
            );
            assert_eq!(fleet_counts(&view).unknown, 1);
        }
    }

    #[test]
    fn a_stale_computed_status_says_so_and_how_old_on_every_summary() {
        let cve = serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]);
        let hosts = serde_json::json!([listed("ares", serde_json::json!({}))]);
        for (running, next_boot, words) in [
            ("6.18.56", "6.18.56", "1 fixed · none affected · 1 stale"),
            ("6.18.52", "6.18.52", "1 affected · 1 stale"),
            ("6.18.52", "6.18.56", "1 reboot due · 1 stale"),
        ] {
            let view = view_of(
                Some(data(cve.clone(), hosts.clone())),
                None,
                vec![old_report(running, next_boot)],
            );
            assert_eq!(watch_counts(&view, 0), words);
            let row = &view.rows[0];
            let (note, stale) = cve_note(
                &view,
                row,
                &view.data.as_deref().unwrap().cves[0],
                row.on(0).unwrap(),
            );
            assert!(stale, "{note}");
            assert!(note.contains("data 2 d old"), "{note}");
        }
        let fresh = view_of(
            Some(data(cve, hosts)),
            None,
            vec![report("ares", "6.18.56", "6.18.56")],
        );
        assert_eq!(watch_counts(&fresh, 0), "1 fixed · none affected");
    }

    #[test]
    fn a_stale_declared_status_says_so_on_every_summary() {
        let row_with = |verified: &str| {
            view_of(
                Some(data(
                    serde_json::json!([library_cve("CVE-2000-0002")]),
                    serde_json::json!([listed(
                        "ares",
                        serde_json::json!({
                            "CVE-2000-0002": { "state": "fixed", "last_verified": verified }
                        })
                    )]),
                )),
                None,
                vec![report("ares", "6.18.56", "6.18.56")],
            )
        };
        assert_eq!(
            watch_counts(&row_with("2000-01-10T00:00:00Z"), 0),
            "1 fixed · none affected · 1 stale"
        );
        assert_eq!(
            watch_counts(&row_with("2000-02-25T00:00:00Z"), 0),
            "1 fixed · none affected"
        );
    }

    #[test]
    fn a_declared_note_shows_the_declared_kernel_not_an_older_report() {
        let mut host = listed(
            "ares",
            serde_json::json!({
                "CVE-2000-0001": { "state": "fixed", "last_verified": "2000-02-29T20:00:00Z" }
            }),
        );
        host["kernel"] = "6.18.56".into();
        host["last_verified"] = "2000-02-29T20:00:00Z".into();
        let view = view_of(
            Some(data(
                serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                serde_json::json!([host]),
            )),
            None,
            vec![old_report("6.18.52", "6.18.52")],
        );
        let row = &view.rows[0];
        let on = row.on(0).unwrap();
        assert_eq!(on.status.status, CveStatus::Fixed);
        let (note, _) = cve_note(&view, row, &view.data.as_deref().unwrap().cves[0], on);
        assert!(note.starts_with("6.18.56 · hand-declared"), "{note}");
        assert!(!note.contains("6.18.52"), "{note}");
    }

    #[test]
    fn a_report_a_newer_check_replaced_no_longer_speaks_for_the_kernel() {
        let view_with = |kernel: Option<&str>, cve: serde_json::Value| {
            let mut host = listed("ares", cve);
            host["version"] = "1.0".into();
            host["last_verified"] = "2000-02-29T20:00:00Z".into();
            if let Some(kernel) = kernel {
                host["kernel"] = kernel.into();
            }
            view_of(
                Some(data(
                    serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                    serde_json::json!([host]),
                )),
                None,
                vec![old_report("6.18.52", "6.18.56")],
            )
        };
        let api = |view: &FleetView| {
            serde_json::to_value(crate::fleet_api::api_host(view, &view.rows[0])).unwrap()
        };
        let declared_fixed = serde_json::json!({
            "CVE-2000-0001": { "state": "fixed", "last_verified": "2000-02-29T20:00:00Z" }
        });

        // The file's kernel, everywhere, with no sign of the report's.
        let view = view_with(Some("6.18.56"), declared_fixed.clone());
        assert_eq!(view.rows[0].kernel(), Some("6.18.56"));
        assert_eq!(view.rows[0].next_boot(), None);
        assert_eq!(api(&view)["running"], "6.18.56");
        assert!(api(&view)["next_boot"].is_null());
        assert_eq!(api(&view)["stale"], false);
        for page in [
            fleet_page(&view),
            render_host(&PublicBasePath::root(), None, &view, "ares").unwrap(),
        ] {
            assert!(!page.contains("6.18.52"), "{page}");
            assert!(page.contains("6.18.56"), "{page}");
            assert!(!page.contains("next boot"), "{page}");
        }

        // A check that names no kernel doesn't leave the old one looking current.
        let view = view_with(None, declared_fixed);
        assert_eq!(view.rows[0].kernel(), None);
        assert!(api(&view)["running"].is_null());

        // A status still computed from that report names what it was computed from.
        let view = view_with(Some("6.18.56"), serde_json::json!({}));
        let row = &view.rows[0];
        let (note, stale) = cve_note(
            &view,
            row,
            &view.data.as_deref().unwrap().cves[0],
            row.on(0).unwrap(),
        );
        assert_eq!(row.on(0).unwrap().status.status, CveStatus::RebootDue);
        assert!(stale, "{note}");
        assert!(
            note.starts_with("Running 6.18.52 · next boot 6.18.56 · data 2 d old"),
            "{note}"
        );
        assert_eq!(api(&view)["stale"], true);
    }

    #[test]
    fn a_report_that_names_no_kernel_leaves_none() {
        let mut declared = listed("ares", serde_json::json!({}));
        declared["kernel"] = "6.18.56".into();
        declared["last_verified"] = "2000-01-10T00:00:00Z".into();
        let mut unnamed = report("ares", "6.18.52", "6.18.52");
        let mut posture = serde_json::to_value(unnamed.kernel.take().unwrap()).unwrap();
        posture["state"] = "unknown".into();
        posture["running_version"] = serde_json::Value::Null;
        posture["expected_version"] = serde_json::Value::Null;
        unnamed.kernel = Some(serde_json::from_value(posture).unwrap());
        let mut absent = report("ares", "6.18.52", "6.18.52");
        absent.kernel = None;
        for host in [unnamed, absent] {
            let view = view_of(
                Some(data(serde_json::json!([]), serde_json::json!([declared]))),
                None,
                vec![host],
            );
            assert_eq!(view.rows[0].kernel(), None);
            let api =
                serde_json::to_value(crate::fleet_api::api_host(&view, &view.rows[0])).unwrap();
            assert!(api["running"].is_null(), "{api}");
            assert!(api["next_boot"].is_null(), "{api}");
            for page in [
                fleet_page(&view),
                render_host(&PublicBasePath::root(), None, &view, "ares").unwrap(),
            ] {
                assert!(!page.contains("6.18.56"), "{page}");
            }
        }
    }

    #[test]
    fn the_release_comes_from_the_evidence_that_decides() {
        let view_with = |channel: Option<&str>, reported_at: i64, verified: &str| {
            let mut declared = listed("ares", serde_json::json!({}));
            declared["version"] = "24.05".into();
            declared["last_verified"] = verified.into();
            let mut host = report("ares", "6.18.52", "6.18.52");
            host.last_seen = Some(reported_at);
            host.freshness.nixpkgs_channel = channel.map(ToString::to_string);
            view_of(
                Some(data(serde_json::json!([]), serde_json::json!([declared]))),
                None,
                vec![host],
            )
        };
        const OLD_CHECK: &str = "2000-01-10T00:00:00Z";
        const NEW_CHECK: &str = "2000-02-29T20:00:00Z";

        // A fresh report outranks an old hand-written release.
        let view = view_with(Some("nixos-25.11"), NOW, OLD_CHECK);
        assert_eq!(view.rows[0].os_version(), Some("25.11"));
        // A report that names none leaves the file's.
        let view = view_with(None, NOW, OLD_CHECK);
        assert_eq!(view.rows[0].os_version(), Some("24.05"));
        // A check after a stale report replaces what that report said.
        let view = view_with(Some("nixos-25.11"), NOW - 2 * 86_400, NEW_CHECK);
        assert_eq!(view.rows[0].os_version(), Some("24.05"));
    }

    #[test]
    fn beacon_counts_rest_on_the_beacon_and_not_on_a_probe() {
        let probed = |reachable: Option<bool>| {
            BTreeMap::from([(
                "ares".to_string(),
                HostProbeObservation {
                    reachable,
                    checked_at: Some(NOW),
                    last_reachable_at: reachable.and_then(|up| up.then_some(NOW)),
                },
            )])
        };
        let counts = |host: Host, reachable: Option<bool>| {
            let view = FleetView::build(
                Some(FleetDataView {
                    data: Some(Arc::new(data(
                        serde_json::json!([]),
                        serde_json::json!([listed("ares", serde_json::json!({}))]),
                    ))),
                    problem: None,
                }),
                vec![host],
                probed(reachable),
                NOW,
            );
            let beacons = serde_json::to_value(crate::fleet_api::document(&view, NOW)).unwrap()
                ["beacons"]
                .clone();
            (
                beacons["reporting"].as_u64().unwrap(),
                beacons["offline"].as_u64().unwrap(),
                beacons["never_reported"].as_u64().unwrap(),
            )
        };
        let mut registered = report("ares", "6.18.52", "6.18.52");
        registered.last_seen = None;
        for reachable in [None, Some(false), Some(true)] {
            assert_eq!(
                counts(registered.clone(), reachable),
                (0, 0, 1),
                "{reachable:?}"
            );
            // A probe that answers doesn't bring a silent beacon back.
            assert_eq!(
                counts(old_report("6.18.52", "6.18.52"), reachable),
                (0, 1, 0),
                "{reachable:?}"
            );
            assert_eq!(
                counts(report("ares", "6.18.52", "6.18.52"), reachable),
                (1, 0, 0),
                "{reachable:?}"
            );
        }
    }

    #[test]
    fn next_boot_is_only_what_the_report_says() {
        let next_boot = |state: &str, expected: Option<&str>| {
            let mut host = report("ares", "6.18.52", "6.18.52");
            let mut kernel = serde_json::to_value(host.kernel.take().unwrap()).unwrap();
            kernel["state"] = state.into();
            kernel["expected_version"] = expected.into();
            host.kernel = Some(serde_json::from_value(kernel).unwrap());
            let view = view_of(None, None, vec![host]);
            serde_json::to_value(crate::fleet_api::api_host(&view, &view.rows[0])).unwrap()
                ["next_boot"]
                .clone()
        };
        assert_eq!(next_boot("current", Some("6.18.52")), "6.18.52");
        assert_eq!(next_boot("reboot_required", Some("6.18.56")), "6.18.56");
        assert!(next_boot("unknown", None).is_null());
    }

    #[test]
    fn a_host_affected_by_one_cve_and_unchecked_on_another_counts_in_both() {
        let view = view_of(
            Some(data(
                serde_json::json!([
                    kernel_cve("CVE-2000-0001", "6.18.56"),
                    library_cve("CVE-2000-0002")
                ]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )),
            None,
            vec![report("ares", "6.18.52", "6.18.52")],
        );
        let counts = fleet_counts(&view);
        assert_eq!((counts.affected, counts.unknown), (1, 1));
        let rows: Vec<&HostRow> = view.rows.iter().collect();
        assert_eq!(group_summary(&view, &rows), "1 affected · 1 can't check");
    }

    #[test]
    fn nothing_is_due_only_when_pharos_can_say_so_for_every_host() {
        let updates = |hosts: serde_json::Value, reports: Vec<Host>| {
            let view = view_of(Some(data(serde_json::json!([]), hosts)), None, reports);
            render_updates(&PublicBasePath::root(), None, &view)
        };
        let ares = serde_json::json!([listed("ares", serde_json::json!({}))]);

        let mut answered = report("ares", "6.18.56", "6.18.56");
        answered.freshness.applicable = false;
        let current = updates(ares.clone(), vec![answered]);
        assert!(current.contains("Nothing is due."), "{current}");

        let never = updates(ares, Vec::new());
        assert!(!never.contains("Nothing is due."), "{never}");
        assert!(never.contains("Nothing is known to be due"), "{never}");

        let empty = updates(serde_json::json!([]), Vec::new());
        assert!(!empty.contains("Nothing is"), "{empty}");
    }

    #[test]
    fn an_old_report_is_marked_stale_wherever_it_is_used() {
        let chip = r#"class="stale""#;
        let view = view_of(
            Some(data(
                serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )),
            None,
            vec![old_report("6.18.52", "6.18.56")],
        );
        let cve = render_cve(&PublicBasePath::root(), None, &view, "CVE-2000-0001").unwrap();
        assert!(cve.contains(chip), "{cve}");
        let updates = render_updates(&PublicBasePath::root(), None, &view);
        assert!(updates.contains(chip), "{updates}");

        let fresh = view_of(
            Some(data(
                serde_json::json!([kernel_cve("CVE-2000-0001", "6.18.56")]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )),
            None,
            vec![report("ares", "6.18.52", "6.18.56")],
        );
        let cve = render_cve(&PublicBasePath::root(), None, &fresh, "CVE-2000-0001").unwrap();
        assert!(!cve.contains(chip), "{cve}");
        let updates = render_updates(&PublicBasePath::root(), None, &fresh);
        assert!(!updates.contains(chip), "{updates}");
    }

    #[test]
    fn a_fresh_report_does_not_vouch_for_an_old_declared_status() {
        let row_with = |verified: &str| {
            view_of(
                Some(data(
                    serde_json::json!([library_cve("CVE-2000-0002")]),
                    serde_json::json!([listed(
                        "ares",
                        serde_json::json!({
                            "CVE-2000-0002": { "state": "affected", "last_verified": verified }
                        })
                    )]),
                )),
                None,
                vec![report("ares", "6.18.56", "6.18.56")],
            )
        };
        let old = row_with("2000-01-10T00:00:00Z");
        let note = update_note(&old, old.row("ares").unwrap());
        assert!(
            note.contains("Declared CVE status, verified 10 Jan"),
            "{note}"
        );
        assert!(note.contains(r#"class="stale""#), "{note}");

        let recent = row_with("2000-02-25T00:00:00Z");
        let note = update_note(&recent, recent.row("ares").unwrap());
        assert!(!note.contains("Declared CVE status"), "{note}");
        assert!(!note.contains(r#"class="stale""#), "{note}");
    }

    #[test]
    fn a_host_that_never_reported_has_no_report_age() {
        let mut host = report("ares", "6.18.56", "6.18.56");
        host.last_seen = None;
        let view = view_of(
            Some(data(
                serde_json::json!([]),
                serde_json::json!([listed("ares", serde_json::json!({}))]),
            )),
            None,
            vec![host],
        );
        let page = render_host(&PublicBasePath::root(), None, &view, "ares").unwrap();
        assert!(page.contains("No report from this host"), "{page}");
        assert!(!page.contains("under 1 min ago"), "{page}");
    }
}
