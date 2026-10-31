//! The fleet data file: what an operator declares about the fleet.
//!
//! Which CVEs matter, their fixed-in lines, and the hosts that cannot report for
//! themselves all live in one versioned file outside this repository. Pharos
//! reads it and compares; it never writes it. `contracts/fleet-data-v3.json` is
//! a synthetic example of the contract these types enforce.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use serde_json::error::Category;
use time::format_description::well_known::Rfc3339;
use time::{Date, OffsetDateTime};

use crate::cve_status::plain_kernel_version;
use crate::{looks_like_secret_material, valid_canonical_hostname};

pub const FLEET_DATA_SCHEMA_VERSION: u64 = 3;
pub const MAX_FLEET_DATA_BYTES: u64 = 1024 * 1024;

const MAX_SHORT_TEXT_BYTES: usize = 200;
const MAX_LONG_TEXT_BYTES: usize = 4 * 1024;
/// The component whose fixed-in lines Pharos compares with reported versions.
pub const KERNEL_COMPONENT: &str = "kernel";
/// A fixed CVE stays on the watchlist this many days, then moves to the history.
pub const WATCH_FIXED_FOR_DAYS: i64 = 3;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FleetDataError {
    /// Not JSON, or JSON that does not match the types.
    Malformed(String),
    UnsupportedSchema(String),
    Invalid {
        path: String,
        message: &'static str,
    },
}

impl fmt::Display for FleetDataError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(reason) => write!(formatter, "not valid fleet data: {reason}"),
            Self::UnsupportedSchema(found) => write!(
                formatter,
                "unsupported schema_version {found}; this Pharos reads {FLEET_DATA_SCHEMA_VERSION}"
            ),
            Self::Invalid { path, message } => write!(formatter, "{path}: {message}"),
        }
    }
}

impl std::error::Error for FleetDataError {}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetData {
    pub schema_version: u64,
    pub title: String,
    pub updated_at: String,
    pub updated_by: String,
    pub defaults: FleetDefaults,
    pub cves: Vec<FleetCve>,
    pub handled: Vec<HandledCves>,
    pub sections: Vec<FleetSection>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetDefaults {
    pub client: OfflineThresholds,
}

/// Days without contact before a client turns yellow, then red.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OfflineThresholds {
    pub offline_warn_days: u32,
    pub offline_red_days: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CveSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FleetCveState {
    Open,
    Mitigated,
    Fixed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetCve {
    pub id: String,
    /// A plain name for the page. Without one the page shows the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub severity: CveSeverity,
    pub state: FleetCveState,
    /// What the CVE is in. Only `kernel` can be answered by reported versions;
    /// every other component takes its per-host status from this file.
    pub component: String,
    pub eli10: String,
    pub tip: String,
    pub fixed_in: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fixed_on: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandledCves {
    pub ids: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub eli10: String,
    pub hosts: Vec<String>,
    pub action: String,
    pub done: String,
    pub ticket: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetSection {
    pub id: String,
    pub name: String,
    pub place: Option<String>,
    pub hosts: Vec<FleetHost>,
}

/// Descriptive only. What offline means comes from `availability`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FleetHostKind {
    Nixos,
    Mac,
    Pi,
    Vm,
    Appliance,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    /// Offline goes red through normal liveness.
    AlwaysOn,
    /// Neutral until the warn days, yellow until the red days, then red.
    Client,
    /// Offline is always neutral.
    Optional,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TailnetState {
    Online,
    Offline,
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetTailnet {
    pub state: TailnetState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredCveState {
    Affected,
    Fixed,
    Unknown,
    /// Not applicable to this host.
    Na,
}

/// One host's status for one CVE, written by hand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredCveStatus {
    pub state: DeclaredCveState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub since: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// When someone last checked this status. Not needed for `na`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FleetHost {
    pub name: String,
    pub kind: FleetHostKind,
    pub role: Option<String>,
    pub os: Option<String>,
    pub version: Option<String>,
    pub kernel: Option<String>,
    pub tailnet: FleetTailnet,
    pub lan: Option<String>,
    pub public: Option<String>,
    pub availability: Availability,
    /// Client overrides of the default thresholds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_warn_days: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offline_red_days: Option<u32>,
    /// When someone last checked the declared `version` and `kernel`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_verified: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub cve: BTreeMap<String, DeclaredCveStatus>,
}

impl FleetHost {
    /// The thresholds that apply to this host; `None` unless it is a client.
    pub fn offline_thresholds(&self, defaults: &FleetDefaults) -> Option<OfflineThresholds> {
        (self.availability == Availability::Client).then(|| OfflineThresholds {
            offline_warn_days: self
                .offline_warn_days
                .unwrap_or(defaults.client.offline_warn_days),
            offline_red_days: self
                .offline_red_days
                .unwrap_or(defaults.client.offline_red_days),
        })
    }
}

impl FleetData {
    /// What the watchlist shows, most urgent first: every CVE not yet fixed, and a
    /// fixed one for its last few days. A severity's entries keep the file's order.
    pub fn watchlist(&self, now: i64) -> Vec<&FleetCve> {
        let mut watched: Vec<&FleetCve> = self
            .cves
            .iter()
            .filter(|cve| !cve.left_the_watchlist(now))
            .collect();
        watched.sort_by_key(|cve| (cve.state == FleetCveState::Fixed, cve.severity));
        watched
    }

    /// The handled history, newest first: the file's entries, and the fixed CVEs
    /// that have left the watchlist, so none vanishes before the file records it.
    /// A day's entries keep the file's order.
    pub fn handled_history(&self, now: i64) -> Vec<HandledCves> {
        self.handled_history_without(now, &[])
    }

    /// The same, leaving out fixed CVEs that stay watched because a host is still
    /// on them. An entry the file itself wrote always stays.
    pub fn handled_history_without(&self, now: i64, still_watched: &[&str]) -> Vec<HandledCves> {
        let mut history = self.handled.clone();
        history.extend(
            self.cves
                .iter()
                .filter(|cve| {
                    cve.left_the_watchlist(now) && !still_watched.contains(&cve.id.as_str())
                })
                .map(|cve| HandledCves {
                    ids: vec![cve.id.clone()],
                    name: cve.name.clone(),
                    eli10: cve.eli10.clone(),
                    hosts: self
                        .sections
                        .iter()
                        .flat_map(|section| &section.hosts)
                        .filter(|host| {
                            host.cve
                                .get(&cve.id)
                                .is_some_and(|status| status.state == DeclaredCveState::Fixed)
                        })
                        .map(|host| host.name.clone())
                        .collect(),
                    action: "Marked fixed in the data file.".to_string(),
                    done: cve.fixed_on.clone().unwrap_or_default(),
                    ticket: None,
                }),
        );
        // Validation guarantees YYYY-MM-DD, which sorts as text.
        history.sort_by(|left, right| right.done.cmp(&left.done));
        history
    }

    /// Parse and validate one file. Nothing is accepted partly: any problem
    /// refuses the whole file, so a caller keeps its last good data.
    pub fn parse(raw: &str) -> Result<Self, FleetDataError> {
        let value: serde_json::Value = serde_json::from_str(raw).map_err(malformed)?;
        match value.get("schema_version") {
            None => return Err(FleetDataError::UnsupportedSchema("(missing)".to_string())),
            Some(version) if version.as_u64() == Some(FLEET_DATA_SCHEMA_VERSION) => {}
            Some(serde_json::Value::Number(version)) => {
                return Err(FleetDataError::UnsupportedSchema(version.to_string()))
            }
            Some(_) => {
                return Err(FleetDataError::UnsupportedSchema(
                    "(not a number)".to_string(),
                ))
            }
        }
        let data: Self = serde_json::from_str(raw).map_err(malformed)?;
        data.validate()?;
        Ok(data)
    }

    /// `updated_at` as Unix seconds. Validation guarantees it parses.
    pub fn updated_at_unix(&self) -> Option<i64> {
        OffsetDateTime::parse(&self.updated_at, &Rfc3339)
            .ok()
            .map(OffsetDateTime::unix_timestamp)
    }

    fn validate(&self) -> Result<(), FleetDataError> {
        short_text(&self.title, "$.title")?;
        short_text(&self.updated_by, "$.updated_by")?;
        let updated = timestamp(&self.updated_at, "$.updated_at")?;
        thresholds(self.defaults.client, "$.defaults.client")?;

        let mut cve_ids = BTreeSet::new();
        for (index, cve) in self.cves.iter().enumerate() {
            let path = format!("$.cves[{index}]");
            cve.validate(&path, updated)?;
            if !cve_ids.insert(cve.id.as_str()) {
                return invalid(format!("{path}.id"), "duplicate CVE id");
            }
        }
        for (index, entry) in self.handled.iter().enumerate() {
            entry.validate(&format!("$.handled[{index}]"), &cve_ids)?;
        }
        let mut section_ids = BTreeSet::new();
        let mut host_names = BTreeSet::new();
        for (index, section) in self.sections.iter().enumerate() {
            let path = format!("$.sections[{index}]");
            if !valid_slug(&section.id) {
                return invalid(format!("{path}.id"), "expected a lowercase slug");
            }
            if !section_ids.insert(section.id.as_str()) {
                return invalid(format!("{path}.id"), "duplicate section id");
            }
            short_text(&section.name, &format!("{path}.name"))?;
            optional_short_text(section.place.as_deref(), &format!("{path}.place"))?;
            for (host_index, host) in section.hosts.iter().enumerate() {
                let host_path = format!("{path}.hosts[{host_index}]");
                host.validate(&host_path, self, updated)?;
                if !host_names.insert(host.name.as_str()) {
                    return invalid(format!("{host_path}.name"), "duplicate host");
                }
            }
        }
        Ok(())
    }
}

impl FleetCve {
    fn left_the_watchlist(&self, now: i64) -> bool {
        let (FleetCveState::Fixed, Some(fixed_on)) = (self.state, self.fixed_on.as_deref()) else {
            return false;
        };
        let Ok(fixed_on) = calendar_date(fixed_on, "fixed_on") else {
            return false;
        };
        OffsetDateTime::from_unix_timestamp(now)
            .is_ok_and(|now| (now.date() - fixed_on).whole_days() >= WATCH_FIXED_FOR_DAYS)
    }

    fn validate(&self, path: &str, updated: OffsetDateTime) -> Result<(), FleetDataError> {
        cve_id(&self.id, &format!("{path}.id"))?;
        optional_short_text(self.name.as_deref(), &format!("{path}.name"))?;
        if !valid_slug(&self.component) {
            return invalid(format!("{path}.component"), "expected a lowercase slug");
        }
        long_text(&self.eli10, &format!("{path}.eli10"))?;
        long_text(&self.tip, &format!("{path}.tip"))?;
        for (index, line) in self.fixed_in.iter().enumerate() {
            let line_path = format!("{path}.fixed_in[{index}]");
            short_text(line, &line_path)?;
            if self.component == KERNEL_COMPONENT && !valid_version_line(line) {
                return invalid(line_path, "a kernel fix line must be dotted numbers");
            }
        }
        match (self.state, self.fixed_on.as_deref()) {
            (FleetCveState::Fixed, None) => {
                return invalid(format!("{path}.fixed_on"), "required for the fixed state")
            }
            (FleetCveState::Fixed, Some(fixed_on)) => {
                let fixed_on_path = format!("{path}.fixed_on");
                if calendar_date(fixed_on, &fixed_on_path)? > updated.date() {
                    return invalid(fixed_on_path, "cannot be after updated_at");
                }
            }
            (_, Some(_)) => {
                return invalid(
                    format!("{path}.fixed_on"),
                    "only allowed for the fixed state",
                )
            }
            (_, None) => {}
        }
        Ok(())
    }
}

impl HandledCves {
    fn validate(&self, path: &str, open_ids: &BTreeSet<&str>) -> Result<(), FleetDataError> {
        if self.ids.is_empty() {
            return invalid(format!("{path}.ids"), "expected at least one CVE id");
        }
        for (index, id) in self.ids.iter().enumerate() {
            let id_path = format!("{path}.ids[{index}]");
            cve_id(id, &id_path)?;
            if open_ids.contains(id.as_str()) {
                return invalid(id_path, "a CVE cannot be in both cves and handled");
            }
        }
        optional_short_text(self.name.as_deref(), &format!("{path}.name"))?;
        if self.hosts.is_empty() {
            return invalid(format!("{path}.hosts"), "expected at least one host");
        }
        for (index, host) in self.hosts.iter().enumerate() {
            short_text(host, &format!("{path}.hosts[{index}]"))?;
        }
        long_text(&self.eli10, &format!("{path}.eli10"))?;
        long_text(&self.action, &format!("{path}.action"))?;
        calendar_date(&self.done, &format!("{path}.done"))?;
        optional_short_text(self.ticket.as_deref(), &format!("{path}.ticket"))
    }
}

impl FleetHost {
    fn validate(
        &self,
        path: &str,
        data: &FleetData,
        updated: OffsetDateTime,
    ) -> Result<(), FleetDataError> {
        if !valid_canonical_hostname(&self.name) {
            return invalid(
                format!("{path}.name"),
                "must match the name its beacon reports",
            );
        }
        for (field, value) in [
            ("role", &self.role),
            ("os", &self.os),
            ("version", &self.version),
            ("kernel", &self.kernel),
            ("lan", &self.lan),
            ("public", &self.public),
        ] {
            optional_short_text(value.as_deref(), &format!("{path}.{field}"))?;
        }
        self.tailnet.validate(&format!("{path}.tailnet"))?;
        self.validate_availability(path, data)?;
        match self.last_verified.as_deref() {
            Some(verified) => {
                verified_at(verified, &format!("{path}.last_verified"), updated)?;
            }
            None if self.version.is_some() || self.kernel.is_some() => {
                return invalid(
                    format!("{path}.last_verified"),
                    "required when version or kernel is declared",
                )
            }
            None => {}
        }
        for (id, status) in &self.cve {
            // A key that isn't a CVE id could be anything, so it stays out of the path.
            cve_id(id, &format!("{path}.cve"))?;
            let status_path = format!("{path}.cve.{id}");
            let Some(cve) = data.cves.iter().find(|cve| &cve.id == id) else {
                return invalid(status_path, "not a CVE in cves");
            };
            status.validate(&status_path, updated)?;
            if cve.state == FleetCveState::Fixed
                && !matches!(status.state, DeclaredCveState::Fixed | DeclaredCveState::Na)
            {
                return invalid(
                    format!("{status_path}.state"),
                    "a fixed CVE allows only fixed or na",
                );
            }
        }
        Ok(())
    }

    fn validate_availability(&self, path: &str, data: &FleetData) -> Result<(), FleetDataError> {
        if self.availability != Availability::Client {
            for (field, value) in [
                ("offline_warn_days", self.offline_warn_days),
                ("offline_red_days", self.offline_red_days),
            ] {
                if value.is_some() {
                    return invalid(format!("{path}.{field}"), "only a client has thresholds");
                }
            }
            return Ok(());
        }
        if let Some(effective) = self.offline_thresholds(&data.defaults) {
            thresholds(effective, path)?;
        }
        Ok(())
    }
}

impl FleetTailnet {
    fn validate(&self, path: &str) -> Result<(), FleetDataError> {
        if self.state != TailnetState::None && self.ip.is_none() {
            return invalid(format!("{path}.ip"), "required unless the state is none");
        }
        optional_short_text(self.ip.as_deref(), &format!("{path}.ip"))?;
        optional_short_text(self.note.as_deref(), &format!("{path}.note"))
    }
}

impl DeclaredCveStatus {
    fn validate(&self, path: &str, updated: OffsetDateTime) -> Result<(), FleetDataError> {
        if let Some(since) = self.since.as_deref() {
            if self.state != DeclaredCveState::Fixed {
                return invalid(format!("{path}.since"), "only allowed for the fixed state");
            }
            calendar_date(since, &format!("{path}.since"))?;
        }
        if let Some(note) = self.note.as_deref() {
            long_text(note, &format!("{path}.note"))?;
        }
        match self.last_verified.as_deref() {
            Some(verified) => verified_at(verified, &format!("{path}.last_verified"), updated),
            None if self.state == DeclaredCveState::Na => Ok(()),
            None => invalid(
                format!("{path}.last_verified"),
                "required unless the state is na",
            ),
        }
    }
}

fn invalid<T>(path: String, message: &'static str) -> Result<T, FleetDataError> {
    Err(FleetDataError::Invalid { path, message })
}

fn thresholds(value: OfflineThresholds, path: &str) -> Result<(), FleetDataError> {
    if value.offline_warn_days == 0 {
        return invalid(format!("{path}.offline_warn_days"), "must be at least 1");
    }
    if value.offline_warn_days >= value.offline_red_days {
        return invalid(
            format!("{path}.offline_warn_days"),
            "must be below offline_red_days",
        );
    }
    Ok(())
}

fn text(value: &str, path: &str, max_bytes: usize) -> Result<(), FleetDataError> {
    if value.trim().is_empty() || value.trim() != value {
        return invalid(path.to_string(), "expected text without outer whitespace");
    }
    if value.len() > max_bytes {
        return invalid(path.to_string(), "text is too long");
    }
    if value.chars().any(|c| c.is_control() && c != '\n') {
        return invalid(path.to_string(), "text has control characters");
    }
    if looks_like_secret_material(value) || has_url_credentials(value) {
        return invalid(path.to_string(), "text looks like a credential");
    }
    Ok(())
}

fn short_text(value: &str, path: &str) -> Result<(), FleetDataError> {
    if value.contains('\n') {
        return invalid(path.to_string(), "expected one line");
    }
    text(value, path, MAX_SHORT_TEXT_BYTES)
}

fn optional_short_text(value: Option<&str>, path: &str) -> Result<(), FleetDataError> {
    value.map_or(Ok(()), |value| short_text(value, path))
}

fn long_text(value: &str, path: &str) -> Result<(), FleetDataError> {
    text(value, path, MAX_LONG_TEXT_BYTES)
}

fn has_url_credentials(value: &str) -> bool {
    value.split("://").skip(1).any(|rest| {
        rest.split(|c: char| c == '/' || c.is_whitespace())
            .next()
            .is_some_and(|authority| authority.contains('@'))
    })
}

fn valid_slug(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && !value.starts_with('-')
        && !value.ends_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn valid_version_line(value: &str) -> bool {
    plain_kernel_version(value).is_some()
}

/// CVE-YYYY-NNNN with four to seven id digits.
/// The parser's own text quotes the value it choked on, and that value could be
/// anything. Where it is in the file is enough to find it.
fn malformed(error: serde_json::Error) -> FleetDataError {
    let what = match error.classify() {
        Category::Data => "a field or value doesn't fit the schema",
        Category::Syntax | Category::Eof | Category::Io => "not JSON",
    };
    FleetDataError::Malformed(format!(
        "{what}, at line {} column {}",
        error.line(),
        error.column()
    ))
}

fn cve_id(value: &str, path: &str) -> Result<(), FleetDataError> {
    let mut parts = value.split('-');
    let well_formed = parts.next() == Some("CVE")
        && parts
            .next()
            .is_some_and(|year| year.len() == 4 && year.bytes().all(|b| b.is_ascii_digit()))
        && parts.next().is_some_and(|id| {
            (4..=7).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_digit())
        })
        && parts.next().is_none();
    if well_formed {
        Ok(())
    } else {
        invalid(path.to_string(), "expected CVE-YYYY-NNNN")
    }
}

fn timestamp(value: &str, path: &str) -> Result<OffsetDateTime, FleetDataError> {
    OffsetDateTime::parse(value, &Rfc3339).or_else(|_| {
        invalid(
            path.to_string(),
            "expected an RFC 3339 timestamp with offset",
        )
    })
}

fn verified_at(value: &str, path: &str, updated: OffsetDateTime) -> Result<(), FleetDataError> {
    if timestamp(value, path)? > updated {
        return invalid(path.to_string(), "cannot be after updated_at");
    }
    Ok(())
}

fn calendar_date(value: &str, path: &str) -> Result<Date, FleetDataError> {
    let format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
        .expect("the date format is valid");
    // The parser also takes a signed year, which would not sort as text.
    if value.len() != "YYYY-MM-DD".len() {
        return invalid(path.to_string(), "expected YYYY-MM-DD");
    }
    Date::parse(value, &format).or_else(|_| invalid(path.to_string(), "expected YYYY-MM-DD"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = include_str!("../../../contracts/fleet-data-v3.json");

    fn contract() -> serde_json::Value {
        serde_json::from_str(CONTRACT).expect("contract is JSON")
    }

    /// Change the contract, then parse it; the message says why it was refused.
    fn refused(change: impl FnOnce(&mut serde_json::Value)) -> String {
        let mut value = contract();
        change(&mut value);
        FleetData::parse(&value.to_string())
            .expect_err("the changed file must be refused")
            .to_string()
    }

    #[test]
    fn the_public_contract_is_valid_and_round_trips() {
        let data = FleetData::parse(CONTRACT).expect("contract validates");
        assert_eq!(data.schema_version, FLEET_DATA_SCHEMA_VERSION);
        assert_eq!(
            serde_json::to_value(&data).expect("serializes"),
            contract(),
            "the types must carry every field of the contract"
        );
        assert!(data.updated_at_unix().is_some());
    }

    #[test]
    fn a_refused_file_never_quotes_what_it_holds() {
        let secret = "https://example-user:example-pass@example.invalid";
        let refused = |change: &dyn Fn(&mut serde_json::Value)| {
            let mut value = contract();
            change(&mut value);
            value.to_string()
        };
        for raw in [
            refused(&|value| value["cves"][0]["severity"] = secret.into()),
            refused(&|value| value["cves"][0][secret] = true.into()),
            refused(&|value| value["cves"][0]["component"] = secret.into()),
            refused(&|value| {
                value["sections"][0]["hosts"][0]["cve"][format!("{secret}\u{1b}[2J")] =
                    serde_json::json!({ "state": "na" });
            }),
            format!("{{\"schema_version\": {secret}"),
        ] {
            let problem = FleetData::parse(&raw).expect_err("refused").to_string();
            assert!(!problem.contains("example-pass"), "{problem}");
            assert!(!problem.contains('\u{1b}'), "{problem}");
        }
    }

    #[test]
    fn handled_history_is_newest_first_and_a_day_keeps_the_file_order() {
        let mut value = contract();
        let entry = value["handled"][0].clone();
        let dated = |done: &str, id: &str| {
            let mut entry = entry.clone();
            entry["done"] = done.into();
            entry["ids"][0] = id.into();
            entry
        };
        value["handled"] = serde_json::json!([
            dated("1999-12-31", "CVE-1999-0001"),
            dated("2000-01-02", "CVE-1999-0002"),
            dated("1999-02-01", "CVE-1999-0003"),
            dated("2000-01-02", "CVE-1999-0004"),
        ]);
        let data = FleetData::parse(&value.to_string()).expect("valid");
        let history = data.handled_history(0);
        let order: Vec<&str> = history.iter().map(|entry| entry.ids[0].as_str()).collect();
        assert_eq!(
            order,
            [
                "CVE-1999-0002",
                "CVE-1999-0004",
                "CVE-1999-0001",
                "CVE-1999-0003"
            ]
        );
    }

    fn watch_fixture() -> serde_json::Value {
        let mut value: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
        let cve = |id: &str, severity: &str, state: &str, fixed_on: Option<&str>| {
            let mut cve = serde_json::json!({
                "id": id, "severity": severity, "state": state, "component": "example-library",
                "eli10": "A flaw.", "tip": "Update.", "fixed_in": ["1.2.3"],
            });
            if let Some(fixed_on) = fixed_on {
                cve["fixed_on"] = serde_json::json!(fixed_on);
            }
            cve
        };
        value["cves"] = serde_json::json!([
            cve("CVE-2000-0010", "low", "open", None),
            cve("CVE-2000-0011", "critical", "fixed", Some("2000-01-02")),
            cve("CVE-2000-0012", "medium", "mitigated", None),
            cve("CVE-2000-0013", "critical", "open", None),
            cve("CVE-2000-0014", "high", "open", None),
            cve("CVE-2000-0015", "high", "open", None),
            cve("CVE-2000-0016", "low", "fixed", Some("2000-01-01")),
        ]);
        for section in value["sections"].as_array_mut().expect("sections") {
            for host in section["hosts"].as_array_mut().expect("hosts") {
                host.as_object_mut().expect("host").remove("cve");
            }
        }
        value["sections"][0]["hosts"][0]["cve"] = serde_json::json!({
            "CVE-2000-0011": { "state": "fixed", "last_verified": "2000-01-02T09:00:00Z" },
            "CVE-2000-0016": { "state": "na" },
        });
        value
    }

    /// Unix seconds at noon, UTC, on a January 2000 day.
    fn january_2000(day: i64) -> i64 {
        946_684_800 + (day - 1) * 86_400 + 43_200
    }

    #[test]
    fn the_watchlist_puts_the_most_urgent_first_and_fixed_last() {
        let data = FleetData::parse(&watch_fixture().to_string()).expect("valid");
        let order = |now: i64| -> Vec<String> {
            data.watchlist(now)
                .iter()
                .map(|cve| cve.id.clone())
                .collect()
        };
        assert_eq!(
            order(january_2000(3)),
            [
                "CVE-2000-0013",
                "CVE-2000-0014",
                "CVE-2000-0015",
                "CVE-2000-0012",
                "CVE-2000-0010",
                "CVE-2000-0011",
                "CVE-2000-0016",
            ]
        );
    }

    #[test]
    fn a_cve_a_host_is_still_on_stays_out_of_the_handled_history() {
        let data = FleetData::parse(&watch_fixture().to_string()).expect("valid");
        let now = january_2000(20);
        let has =
            |history: Vec<HandledCves>| history.iter().any(|entry| entry.ids == ["CVE-2000-0011"]);
        assert!(has(data.handled_history(now)));
        assert!(!has(data.handled_history_without(now, &["CVE-2000-0011"])));
        assert!(has(data.handled_history_without(now, &["CVE-2000-0012"])));
    }

    #[test]
    fn a_fixed_cve_leaves_the_watchlist_after_three_days_and_keeps_a_history_row() {
        let data = FleetData::parse(&watch_fixture().to_string()).expect("valid");
        let watched = |now: i64| {
            data.watchlist(now)
                .iter()
                .any(|cve| cve.id == "CVE-2000-0011")
        };
        let in_history = |now: i64| {
            data.handled_history(now)
                .iter()
                .any(|entry| entry.ids == ["CVE-2000-0011"])
        };
        // Fixed on the 2nd: the 2nd, 3rd and 4th, then history from the 5th.
        assert!(watched(january_2000(4)));
        assert!(!in_history(january_2000(4)));
        assert!(!watched(january_2000(5)));
        assert!(in_history(january_2000(5)));

        let history = data.handled_history(january_2000(5));
        let moved = history
            .iter()
            .find(|entry| entry.ids == ["CVE-2000-0011"])
            .expect("the history row");
        assert_eq!(moved.done, "2000-01-02");
        assert_eq!(moved.hosts, ["demeter"], "only hosts declared fixed");
        assert_eq!(moved.ticket, None);
    }

    #[test]
    fn a_cve_name_is_optional_and_validated_like_other_short_text() {
        let mut value: serde_json::Value = serde_json::from_str(CONTRACT).expect("contract");
        value["cves"][0]["name"] = serde_json::json!("Kernel takeover");
        value["handled"][0]["name"] = serde_json::json!("Older flaw");
        let data = FleetData::parse(&value.to_string()).expect("valid");
        assert_eq!(data.cves[0].name.as_deref(), Some("Kernel takeover"));
        assert_eq!(data.handled[0].name.as_deref(), Some("Older flaw"));

        value["cves"][0]["name"] = serde_json::json!("");
        assert!(FleetData::parse(&value.to_string()).is_err());
    }

    #[test]
    fn the_public_contract_covers_each_availability() {
        let data = FleetData::parse(CONTRACT).expect("contract validates");
        let hosts: Vec<_> = data.sections.iter().flat_map(|s| &s.hosts).collect();
        for availability in [
            Availability::AlwaysOn,
            Availability::Client,
            Availability::Optional,
        ] {
            assert!(
                hosts.iter().any(|host| host.availability == availability),
                "{availability:?}"
            );
        }
    }

    #[test]
    fn unknown_schema_versions_are_refused_with_a_clear_message() {
        for (version, shown) in [
            (serde_json::json!(2), "2"),
            (serde_json::json!(4), "4"),
            (serde_json::json!("3"), "(not a number)"),
        ] {
            let message = refused(|value| value["schema_version"] = version);
            assert_eq!(
                message,
                format!("unsupported schema_version {shown}; this Pharos reads 3")
            );
        }
        let message = refused(|value| {
            value.as_object_mut().unwrap().remove("schema_version");
        });
        assert_eq!(
            message,
            "unsupported schema_version (missing); this Pharos reads 3"
        );
    }

    #[test]
    fn a_v2_file_is_refused_for_its_version_not_its_shape() {
        let message = FleetData::parse(r#"{"schema_version":2,"sections":[]}"#)
            .expect_err("v2 is refused")
            .to_string();
        assert!(
            message.contains("unsupported schema_version 2"),
            "{message}"
        );
    }

    #[test]
    fn malformed_files_are_refused() {
        for raw in ["", "not json", "[]", "{"] {
            assert!(FleetData::parse(raw).is_err(), "{raw:?}");
        }
        let message = refused(|value| value["surprise"] = serde_json::json!(true));
        assert!(message.contains("doesn't fit the schema"), "{message}");
        assert!(message.contains("line 1 column"), "{message}");
        assert!(!message.contains("surprise"), "{message}");
    }

    fn host(value: &mut serde_json::Value, name: &str) -> serde_json::Value {
        let hosts = value["sections"][0]["hosts"].as_array().unwrap();
        hosts
            .iter()
            .find(|host| host["name"] == name)
            .unwrap_or_else(|| panic!("{name} is in the contract"))
            .clone()
    }

    fn set_host(
        value: &mut serde_json::Value,
        name: &str,
        change: impl FnOnce(&mut serde_json::Value),
    ) {
        let hosts = value["sections"][0]["hosts"].as_array_mut().unwrap();
        let host = hosts
            .iter_mut()
            .find(|host| host["name"] == name)
            .unwrap_or_else(|| panic!("{name} is in the contract"));
        change(host);
    }

    #[test]
    fn availability_is_a_closed_set() {
        let message = refused(|value| {
            set_host(value, "demeter", |host| {
                host["availability"] = "sometimes".into();
            });
        });
        assert!(message.contains("doesn't fit the schema"), "{message}");
        let message = refused(|value| {
            set_host(value, "demeter", |host| {
                host.as_object_mut().unwrap().remove("availability");
            });
        });
        assert!(message.contains("doesn't fit the schema"), "{message}");
    }

    #[test]
    fn warn_days_must_be_below_red_days() {
        for (warn, red) in [(60, 60), (61, 60), (0, 60)] {
            let message = refused(|value| {
                value["defaults"]["client"]["offline_warn_days"] = warn.into();
                value["defaults"]["client"]["offline_red_days"] = red.into();
            });
            assert!(message.starts_with("$.defaults.client"), "{message}");
        }
        // An override is judged with the default it does not replace.
        let message = refused(|value| {
            set_host(value, "hermes", |host| {
                host["offline_warn_days"] = 60.into();
            });
        });
        assert!(message.contains("offline_warn_days"), "{message}");
        let message = refused(|value| {
            set_host(value, "artemis", |host| {
                host["offline_red_days"] = 5.into();
            });
        });
        assert!(message.contains("offline_warn_days"), "{message}");
    }

    #[test]
    fn only_clients_have_thresholds_and_overrides_apply() {
        for name in ["demeter", "ares"] {
            for field in ["offline_warn_days", "offline_red_days"] {
                let message = refused(|value| {
                    set_host(value, name, |host| host[field] = 5.into());
                });
                assert!(message.contains(field), "{message}");
                assert!(message.contains("only a client"), "{message}");
            }
        }
        let data = FleetData::parse(CONTRACT).expect("contract validates");
        let find = |name: &str| {
            data.sections
                .iter()
                .flat_map(|section| &section.hosts)
                .find(|host| host.name == name)
                .expect("host is in the contract")
        };
        let defaults = OfflineThresholds {
            offline_warn_days: 30,
            offline_red_days: 60,
        };
        assert_eq!(data.defaults.client, defaults);
        assert_eq!(
            find("hermes").offline_thresholds(&data.defaults),
            Some(defaults)
        );
        assert_eq!(
            find("artemis").offline_thresholds(&data.defaults),
            Some(OfflineThresholds {
                offline_warn_days: 7,
                offline_red_days: 14,
            })
        );
        assert_eq!(find("demeter").offline_thresholds(&data.defaults), None);
        assert_eq!(find("ares").offline_thresholds(&data.defaults), None);
    }

    #[test]
    fn declared_values_need_a_last_verified_time() {
        let message = refused(|value| {
            set_host(value, "athena", |host| {
                host.as_object_mut().unwrap().remove("last_verified");
            });
        });
        assert!(message.ends_with("required when version or kernel is declared"));

        let message = refused(|value| {
            set_host(value, "athena", |host| {
                host["cve"]["CVE-2000-0002"]
                    .as_object_mut()
                    .unwrap()
                    .remove("last_verified");
            });
        });
        assert!(
            message.ends_with("required unless the state is na"),
            "{message}"
        );

        for (path, stamp) in [
            ("last_verified", "2000-01-01"),
            ("last_verified", "2999-01-01T00:00:00Z"),
        ] {
            let message = refused(|value| {
                set_host(value, "athena", |host| host[path] = stamp.into());
            });
            assert!(message.contains("last_verified"), "{message}");
        }

        // Not applicable needs no verification time.
        let mut value = contract();
        set_host(&mut value, "ares", |host| {
            assert_eq!(host["cve"]["CVE-2000-0002"]["state"], "na");
            assert!(host["cve"]["CVE-2000-0002"].get("last_verified").is_none());
        });
        assert!(FleetData::parse(&value.to_string()).is_ok());
        assert!(host(&mut value, "ares")["last_verified"].is_null());
    }

    #[test]
    fn the_file_is_refused_whole_on_any_broken_reference() {
        type Change = Box<dyn FnOnce(&mut serde_json::Value)>;
        let cases: Vec<(&str, Change)> = vec![
            (
                "duplicate host",
                Box::new(|value| {
                    let copy = host(value, "demeter");
                    value["sections"][0]["hosts"]
                        .as_array_mut()
                        .unwrap()
                        .push(copy);
                }),
            ),
            (
                "duplicate CVE id",
                Box::new(|value| {
                    let copy = value["cves"][0].clone();
                    value["cves"].as_array_mut().unwrap().push(copy);
                }),
            ),
            (
                "duplicate section id",
                Box::new(|value| {
                    let copy = value["sections"][0].clone();
                    value["sections"].as_array_mut().unwrap().push(copy);
                }),
            ),
            (
                "not a CVE in cves",
                Box::new(|value| {
                    set_host(value, "athena", |host| {
                        host["cve"]["CVE-2000-9999"] = host["cve"]["CVE-2000-0002"].clone();
                    });
                }),
            ),
            (
                "both cves and handled",
                Box::new(|value| {
                    value["handled"][0]["ids"][0] = value["cves"][0]["id"].clone();
                }),
            ),
            (
                "expected CVE-YYYY-NNNN",
                Box::new(|value| value["cves"][0]["id"] = "CVE-20-1".into()),
            ),
            (
                "a kernel fix line must be dotted numbers",
                Box::new(|value| value["cves"][0]["fixed_in"][0] = "6.18.x".into()),
            ),
            (
                "a kernel fix line must be dotted numbers",
                Box::new(|value| value["cves"][0]["fixed_in"][0] = "6".into()),
            ),
            (
                "a kernel fix line must be dotted numbers",
                Box::new(|value| value["cves"][0]["fixed_in"][0] = "6.18.56.1".into()),
            ),
            (
                "a kernel fix line must be dotted numbers",
                Box::new(|value| value["cves"][0]["fixed_in"][0] = "7.3-rc1".into()),
            ),
            (
                "expected YYYY-MM-DD",
                Box::new(|value| value["handled"][0]["done"] = "+2000-01-02".into()),
            ),
            (
                "expected YYYY-MM-DD",
                Box::new(|value| value["handled"][0]["done"] = "-2000-01-02".into()),
            ),
            (
                "must match the name its beacon reports",
                Box::new(|value| {
                    set_host(value, "demeter", |host| host["name"] = "Demeter".into());
                }),
            ),
            (
                "required unless the state is none",
                Box::new(|value| {
                    set_host(value, "demeter", |host| {
                        host["tailnet"].as_object_mut().unwrap().remove("ip");
                    });
                }),
            ),
            (
                "text looks like a credential",
                Box::new(|value| {
                    set_host(value, "demeter", |host| {
                        host["public"] = "https://user:hunter2@host.example.test/".into();
                    });
                }),
            ),
            (
                "expected at least one host",
                Box::new(|value| value["handled"][0]["hosts"] = serde_json::json!([])),
            ),
            (
                "required for the fixed state",
                Box::new(|value| value["cves"][0]["state"] = "fixed".into()),
            ),
            (
                "only allowed for the fixed state",
                Box::new(|value| value["cves"][0]["fixed_on"] = "2000-01-01".into()),
            ),
            (
                "expected an RFC 3339 timestamp with offset",
                Box::new(|value| value["updated_at"] = "yesterday".into()),
            ),
        ];
        for (expected, change) in cases {
            let message = refused(change);
            assert!(message.contains(expected), "{expected}: {message}");
        }
    }

    #[test]
    fn a_fixed_cve_allows_only_fixed_or_na() {
        let message = refused(|value| {
            value["cves"][1]["state"] = "fixed".into();
            value["cves"][1]["fixed_on"] = "2000-01-02".into();
        });
        assert!(
            message.ends_with("a fixed CVE allows only fixed or na"),
            "{message}"
        );
    }
}
