//! Each host's status for one CVE.
//!
//! Pharos compares; it never scans. Only the kernel can be answered from what
//! beacons report, so a kernel CVE compares fixed-in lines with reported versions
//! and every other CVE takes its status from the fleet data file. The one answer
//! this must never get wrong is `Fixed`: anything it cannot show is `Unknown`.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::fleet_data::{DeclaredCveState, DeclaredCveStatus, FleetCve, KERNEL_COMPONENT};
use crate::{kernel_semantic_version, liveness, Host, KernelPostureState, Liveness, UnixSeconds};

/// A hand-declared status older than this is labelled stale.
pub const DECLARED_STALE_AFTER_SECS: i64 = 30 * 24 * 60 * 60;
const NANOS_PER_SEC: i128 = 1_000_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CveStatus {
    Fixed,
    /// Not fixed in the running kernel, fixed in the next boot's.
    RebootDue,
    Affected,
    Unknown,
    NotApplicable,
}

/// Where a status came from, which the page has to say.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CveStatusSource {
    /// Compared with a beacon's report.
    Computed { age_secs: u64, stale: bool },
    /// Written by hand in the fleet data file.
    Declared {
        last_verified: Option<String>,
        verification_stale: bool,
    },
    /// No report and no declared row.
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCveStatus {
    pub status: CveStatus,
    pub source: CveStatusSource,
}

/// What a beacon said about its kernel, reduced to what a comparison needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelReport<'a> {
    pub running_version: Option<&'a str>,
    pub next_boot_version: Option<&'a str>,
    /// Server-stamped.
    pub reported_at: UnixSeconds,
    /// Fresh enough to beat a declared value outright.
    pub fresh: bool,
}

impl<'a> KernelReport<'a> {
    /// `None` when the host has no comparable kernel to report. Off NixOS the
    /// posture is not applicable: vendor kernels backport fixes without changing
    /// the version, so the number says nothing either way.
    pub fn from_host(host: &'a Host, now: UnixSeconds) -> Option<Self> {
        let posture = host.kernel.as_ref()?;
        if posture.state == KernelPostureState::NotApplicable {
            return None;
        }
        Some(Self {
            running_version: posture.running_version.as_deref(),
            next_boot_version: posture.expected_version.as_deref(),
            reported_at: host.last_seen?,
            fresh: liveness(host.last_seen, host.heartbeat_interval_secs, now) == Liveness::Live,
        })
    }
}

/// One host's status for one CVE. Rules, in order:
///
/// 1. A host the file marks not applicable stays not applicable.
/// 2. A fresh report beats the file, even when its answer is unknown. If a branch
///    has no answer, the fix belongs in the file's fix lines.
/// 3. Between a stale report and the file, the newer evidence decides, so a missed
///    heartbeat alone can never turn one answer into another.
/// 4. Whichever of them exists, else unknown.
pub fn host_cve_status(
    cve: &FleetCve,
    declared: Option<&DeclaredCveStatus>,
    report: Option<KernelReport<'_>>,
    now: UnixSeconds,
) -> HostCveStatus {
    if let Some(row) = declared.filter(|row| row.state == DeclaredCveState::Na) {
        return declared_status(row, now);
    }
    let report = report.filter(|_| cve.component == KERNEL_COMPONENT);
    match (report, declared) {
        (Some(report), Some(row))
            if !report.fresh && checked_after(row.last_verified.as_deref(), report.reported_at) =>
        {
            declared_status(row, now)
        }
        (Some(report), _) => HostCveStatus {
            status: kernel_cve_status(&cve.fixed_in, report),
            source: CveStatusSource::Computed {
                age_secs: now.saturating_sub(report.reported_at).max(0) as u64,
                stale: !report.fresh,
            },
        },
        (None, Some(row)) => declared_status(row, now),
        (None, None) => HostCveStatus {
            status: CveStatus::Unknown,
            source: CveStatusSource::Nothing,
        },
    }
}

fn declared_status(row: &DeclaredCveStatus, now: UnixSeconds) -> HostCveStatus {
    let status = match row.state {
        DeclaredCveState::Affected => CveStatus::Affected,
        DeclaredCveState::Fixed => CveStatus::Fixed,
        DeclaredCveState::Unknown => CveStatus::Unknown,
        DeclaredCveState::Na => CveStatus::NotApplicable,
    };
    // Not applicable needs no check, but one that was made can still go stale.
    let needs_check = row.state != DeclaredCveState::Na || row.last_verified.is_some();
    HostCveStatus {
        status,
        source: CveStatusSource::Declared {
            last_verified: row.last_verified.clone(),
            verification_stale: needs_check
                && declared_verification_stale(row.last_verified.as_deref(), now),
        },
    }
}

fn verified_at(last_verified: Option<&str>) -> Option<OffsetDateTime> {
    last_verified.and_then(|value| OffsetDateTime::parse(value, &Rfc3339).ok())
}

/// True when the last check is missing or past the limit.
pub(crate) fn declared_verification_stale(last_verified: Option<&str>, now: UnixSeconds) -> bool {
    !verified_at(last_verified).is_some_and(|at| {
        i128::from(now) * NANOS_PER_SEC - at.unix_timestamp_nanos()
            <= i128::from(DECLARED_STALE_AFTER_SECS) * NANOS_PER_SEC
    })
}

/// True when someone checked by hand after this report arrived. A check can carry
/// fractions of a second; a report's time cannot.
pub(crate) fn checked_after(last_verified: Option<&str>, reported_at: UnixSeconds) -> bool {
    verified_at(last_verified)
        .is_some_and(|at| at.unix_timestamp_nanos() > i128::from(reported_at) * NANOS_PER_SEC)
}

/// Compare a report with a CVE's fixed-in lines.
pub fn kernel_cve_status(fixed_in: &[String], report: KernelReport<'_>) -> CveStatus {
    // One line that does not parse could be the highest, so nothing can be
    // judged newer than all of them.
    let Some(lines) = fixed_in
        .iter()
        .map(|line| plain_kernel_version(line))
        .collect::<Option<Vec<_>>>()
    else {
        return CveStatus::Unknown;
    };
    let Some(running) = report.running_version.and_then(plain_kernel_version) else {
        return CveStatus::Unknown;
    };
    let running = verdict(running, &lines);
    if running == Verdict::Fixed {
        return CveStatus::Fixed;
    }
    let next_boot = report
        .next_boot_version
        .and_then(plain_kernel_version)
        .map(|version| verdict(version, &lines));
    match (next_boot, running) {
        (Some(Verdict::Fixed), _) => CveStatus::RebootDue,
        (_, Verdict::Affected) => CveStatus::Affected,
        _ => CveStatus::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    Fixed,
    Affected,
    Unknown,
}

type KernelVersion = (u64, u64, u64);

fn verdict(version: KernelVersion, lines: &[KernelVersion]) -> Verdict {
    let same_branch = lines
        .iter()
        .filter(|line| (line.0, line.1) == (version.0, version.1))
        .max();
    match same_branch {
        Some(line) if version >= *line => Verdict::Fixed,
        Some(_) => Verdict::Affected,
        None if lines.iter().max().is_some_and(|line| version > *line) => Verdict::Fixed,
        None => Verdict::Unknown,
    }
}

/// Only a plain upstream number can be compared. Any suffix can mean a release
/// candidate or a vendor kernel, and those share a leading number with a release
/// without sharing its fixes, in more spellings than a list could cover. The
/// fleet's NixOS kernels report plain numbers; anything else shows as unknown.
pub(crate) fn plain_kernel_version(value: &str) -> Option<KernelVersion> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || byte == b'.')
    {
        return None;
    }
    kernel_semantic_version(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_data::{CveSeverity, FleetCveState};
    use proptest::prelude::*;

    /// 2000-03-01T00:00:00Z
    const NOW: UnixSeconds = 951_868_800;
    const DAY: i64 = 86_400;
    const LINES: [&str; 3] = ["6.18.56", "7.2.10", "7.3"];
    const YESTERDAY: &str = "2000-02-29T00:00:00Z";

    fn cve(component: &str, lines: &[&str]) -> FleetCve {
        FleetCve {
            id: "CVE-2000-0001".to_string(),
            severity: CveSeverity::High,
            state: FleetCveState::Open,
            component: component.to_string(),
            eli10: "Example.".to_string(),
            tip: "Example.".to_string(),
            fixed_in: lines.iter().map(ToString::to_string).collect(),
            fixed_on: None,
        }
    }

    fn report<'a>(running: Option<&'a str>, next_boot: Option<&'a str>) -> KernelReport<'a> {
        KernelReport {
            running_version: running,
            next_boot_version: next_boot,
            reported_at: NOW - 30,
            fresh: true,
        }
    }

    fn row(state: DeclaredCveState, last_verified: Option<&str>) -> DeclaredCveStatus {
        DeclaredCveStatus {
            state,
            since: None,
            note: None,
            last_verified: last_verified.map(ToString::to_string),
        }
    }

    fn lines(values: &[&str]) -> Vec<String> {
        values.iter().map(ToString::to_string).collect()
    }

    fn computed(age_secs: u64, stale: bool) -> CveStatusSource {
        CveStatusSource::Computed { age_secs, stale }
    }

    fn declared_source(last_verified: &str, verification_stale: bool) -> CveStatusSource {
        CveStatusSource::Declared {
            last_verified: Some(last_verified.to_string()),
            verification_stale,
        }
    }

    #[test]
    fn versions_against_fix_lines() {
        use CveStatus::*;
        let table = [
            // Same branch as a line.
            ("6.18.56", Fixed),
            ("6.18.57", Fixed),
            ("6.18.55", Affected),
            ("7.2.10", Fixed),
            ("7.2.9", Affected),
            ("7.3", Fixed),
            ("7.3.0", Fixed),
            ("7.3.5", Fixed),
            // Newer than the highest line.
            ("7.4.0", Fixed),
            ("8.0.0", Fixed),
            // No line for this branch and not newer than all of them.
            ("6.12.40", Unknown),
            ("6.19.0", Unknown),
            ("7.0.14", Unknown),
            ("7.1.5", Unknown),
            ("5.4.0", Unknown),
            // A release candidate comes before its release, in any spelling.
            ("7.3.0-rc2", Unknown),
            ("7.3-rc2", Unknown),
            ("7.4.0-rc1", Unknown),
            ("7.3.0-0.rc2.24.fc46.x86_64", Unknown),
            ("7.3.0rc2", Unknown),
            // A vendor or variant kernel does not show its fixes in the number.
            ("7.3.0-1-amd64", Unknown),
            ("6.18.56-60-generic", Unknown),
            ("6.18.56-hardened1", Unknown),
            ("7.3.0+", Unknown),
            ("7.3.0_custom", Unknown),
            // Does not parse.
            ("not-a-version", Unknown),
            ("7", Unknown),
            ("7.3.0.1", Unknown),
            ("7.x.1", Unknown),
            ("7..1", Unknown),
            ("7.3.", Unknown),
            (" 7.3.0", Unknown),
            ("+7.3.0", Unknown),
            ("18446744073709551616.0.0", Unknown),
            ("", Unknown),
        ];
        for (running, expected) in table {
            assert_eq!(
                kernel_cve_status(&lines(&LINES), report(Some(running), None)),
                expected,
                "{running}"
            );
        }
    }

    #[test]
    fn next_boot_turns_a_vulnerable_host_into_reboot_due() {
        use CveStatus::*;
        let table = [
            // Below the fix, next boot at or above it.
            (Some("6.18.55"), Some("6.18.56"), RebootDue),
            (Some("6.18.55"), Some("7.3.1"), RebootDue),
            (Some("6.18.55"), Some("8.0.0"), RebootDue),
            // A running kernel no line covers is not fixed, but the reboot fixes it.
            (Some("7.1.5"), Some("7.2.10"), RebootDue),
            // The next boot does not fix it.
            (Some("6.18.55"), Some("6.18.55"), Affected),
            (Some("6.18.54"), Some("6.18.55"), Affected),
            (Some("6.18.55"), Some("7.1.5"), Affected),
            (Some("6.18.55"), Some("7.3.0-rc1"), Affected),
            (Some("6.18.55"), Some("7.3.0-0.rc2.fc46"), Affected),
            (Some("6.18.55"), Some("not-a-version"), Affected),
            (Some("6.18.55"), None, Affected),
            (Some("7.1.5"), Some("7.1.6"), Unknown),
            // What is running decides, so a staged older kernel does not undo a fix.
            (Some("6.18.56"), Some("6.18.55"), Fixed),
            // Without a comparable running version there is nothing to judge.
            (None, Some("6.18.56"), Unknown),
            (None, None, Unknown),
            (Some("not-a-version"), Some("6.18.56"), Unknown),
            (Some("6.18.55-1-amd64"), Some("6.18.56"), Unknown),
        ];
        for (running, next_boot, expected) in table {
            assert_eq!(
                kernel_cve_status(&lines(&LINES), report(running, next_boot)),
                expected,
                "{running:?} then {next_boot:?}"
            );
        }
    }

    #[test]
    fn fix_lines_that_cannot_decide_leave_it_unknown() {
        let version = report(Some("9.0.0"), Some("9.0.0"));
        for values in [
            &[][..],
            &["not-a-line"][..],
            &["6.18.56", "x"][..],
            &["7.3-rc1"][..],
            &["7"][..],
        ] {
            assert_eq!(
                kernel_cve_status(&lines(values), version),
                CveStatus::Unknown,
                "{values:?}"
            );
        }
        // Two lines on one branch: the later one decides.
        let both = lines(&["6.18.50", "6.18.56"]);
        assert_eq!(
            kernel_cve_status(&both, report(Some("6.18.52"), None)),
            CveStatus::Affected
        );
    }

    #[test]
    fn a_fresh_report_beats_a_declared_value() {
        let kernel = cve("kernel", &LINES);
        let table = [
            (DeclaredCveState::Affected, "7.3.1", CveStatus::Fixed),
            (DeclaredCveState::Fixed, "6.18.55", CveStatus::Affected),
            // Even when all it can say is unknown: a false fixed is the worst error,
            // and a branch with no line needs a line in the file.
            (DeclaredCveState::Fixed, "6.12.40", CveStatus::Unknown),
            (DeclaredCveState::Fixed, "not-a-version", CveStatus::Unknown),
        ];
        for (state, running, expected) in table {
            let declared = row(state, Some(YESTERDAY));
            let status = host_cve_status(
                &kernel,
                Some(&declared),
                Some(report(Some(running), None)),
                NOW,
            );
            assert_eq!(status.status, expected, "{running}");
            assert_eq!(status.source, computed(30, false), "{running}");
        }
    }

    #[test]
    fn a_stale_report_keeps_its_state_and_says_how_old_it_is() {
        let kernel = cve("kernel", &LINES);
        let stale = KernelReport {
            fresh: false,
            reported_at: NOW - 7_200,
            ..report(Some("6.18.55"), None)
        };
        let status = host_cve_status(&kernel, None, Some(stale), NOW);
        assert_eq!(status.status, CveStatus::Affected);
        assert_eq!(status.source, computed(7_200, true));

        for (running, next_boot, expected) in [
            ("7.3.1", None, CveStatus::Fixed),
            ("6.18.55", Some("6.18.56"), CveStatus::RebootDue),
            ("6.12.40", None, CveStatus::Unknown),
        ] {
            let reported = KernelReport {
                running_version: Some(running),
                next_boot_version: next_boot,
                ..stale
            };
            let status = host_cve_status(&kernel, None, Some(reported), NOW);
            assert_eq!(status.status, expected, "{running}");
            assert_eq!(status.source, computed(7_200, true), "{running}");
        }
    }

    #[test]
    fn between_a_stale_report_and_the_file_the_newer_evidence_decides() {
        let kernel = cve("kernel", &LINES);
        let stale = KernelReport {
            fresh: false,
            reported_at: NOW - 2 * DAY,
            ..report(Some("6.18.55"), None)
        };

        // Someone checked by hand after the host went quiet: the file's state shows,
        // whichever it is and whatever the report said.
        for (state, running, expected) in [
            (DeclaredCveState::Fixed, "6.18.55", CveStatus::Fixed),
            (DeclaredCveState::Affected, "7.3.1", CveStatus::Affected),
            (DeclaredCveState::Affected, "6.18.55", CveStatus::Affected),
            (DeclaredCveState::Unknown, "7.3.1", CveStatus::Unknown),
        ] {
            let declared = row(state, Some(YESTERDAY));
            let reported = KernelReport {
                running_version: Some(running),
                ..stale
            };
            let status = host_cve_status(&kernel, Some(&declared), Some(reported), NOW);
            assert_eq!(status.status, expected, "{state:?} over {running}");
            assert_eq!(status.source, declared_source(YESTERDAY, false));
        }
        let later = row(DeclaredCveState::Fixed, Some(YESTERDAY));

        // The host said otherwise after that check.
        let earlier = row(DeclaredCveState::Fixed, Some("2000-02-01T00:00:00Z"));
        let status = host_cve_status(&kernel, Some(&earlier), Some(stale), NOW);
        assert_eq!(status.status, CveStatus::Affected);
        assert_eq!(status.source, computed(2 * DAY as u64, true));

        // The same moment is not newer, and no check at all is not newer.
        let same = KernelReport {
            reported_at: NOW - DAY,
            ..stale
        };
        let status = host_cve_status(&kernel, Some(&later), Some(same), NOW);
        assert_eq!(status.status, CveStatus::Affected);
        let unchecked = row(DeclaredCveState::Fixed, None);
        let status = host_cve_status(&kernel, Some(&unchecked), Some(stale), NOW);
        assert_eq!(status.status, CveStatus::Affected);

        // Half a second later is later.
        let moment = KernelReport {
            running_version: Some("7.3.1"),
            reported_at: NOW - DAY,
            ..stale
        };
        let later = "2000-02-29T00:00:00.500Z";
        let declared = row(DeclaredCveState::Affected, Some(later));
        let status = host_cve_status(&kernel, Some(&declared), Some(moment), NOW);
        assert_eq!(status.status, CveStatus::Affected);
        assert_eq!(status.source, declared_source(later, false));
    }

    #[test]
    fn a_missed_heartbeat_alone_never_changes_the_answer() {
        let kernel = cve("kernel", &LINES);
        let declared = row(DeclaredCveState::Fixed, Some(YESTERDAY));
        for fresh in [true, false] {
            let status = host_cve_status(
                &kernel,
                Some(&declared),
                Some(KernelReport {
                    fresh,
                    ..report(Some("6.18.55"), None)
                }),
                NOW,
            );
            assert_eq!(status.status, CveStatus::Affected, "fresh: {fresh}");
        }
    }

    #[test]
    fn not_applicable_stays_whatever_the_report_says() {
        let declared = row(DeclaredCveState::Na, None);
        for fresh in [true, false] {
            let status = host_cve_status(
                &cve("kernel", &LINES),
                Some(&declared),
                Some(KernelReport {
                    fresh,
                    ..report(Some("6.18.55"), None)
                }),
                NOW,
            );
            assert_eq!(status.status, CveStatus::NotApplicable);
            assert_eq!(
                status.source,
                CveStatusSource::Declared {
                    last_verified: None,
                    verification_stale: false
                }
            );
        }
    }

    #[test]
    fn other_components_only_ever_take_the_file() {
        let library = cve("example-library", &["1.2.3"]);
        let matching = report(Some("9.0.0"), Some("9.0.0"));
        let status = host_cve_status(&library, None, Some(matching), NOW);
        assert_eq!(status.status, CveStatus::Unknown);
        assert_eq!(status.source, CveStatusSource::Nothing);

        for (state, expected) in [
            (DeclaredCveState::Affected, CveStatus::Affected),
            (DeclaredCveState::Fixed, CveStatus::Fixed),
            (DeclaredCveState::Unknown, CveStatus::Unknown),
        ] {
            let declared = row(state, Some(YESTERDAY));
            let status = host_cve_status(&library, Some(&declared), Some(matching), NOW);
            assert_eq!(status.status, expected);
            assert_eq!(status.source, declared_source(YESTERDAY, false));
        }
    }

    #[test]
    fn nothing_known_is_unknown() {
        let status = host_cve_status(&cve("kernel", &LINES), None, None, NOW);
        assert_eq!(status.status, CveStatus::Unknown);
        assert_eq!(status.source, CveStatusSource::Nothing);
    }

    #[test]
    fn a_declared_status_goes_stale_after_thirty_days() {
        let library = cve("example-library", &[]);
        for (state, verified, stale) in [
            (DeclaredCveState::Affected, Some(YESTERDAY), false),
            (
                DeclaredCveState::Affected,
                Some("2000-01-31T00:00:00Z"),
                false,
            ),
            (
                DeclaredCveState::Affected,
                Some("2000-01-30T23:59:59Z"),
                true,
            ),
            (DeclaredCveState::Affected, None, true),
            (DeclaredCveState::Affected, Some("not a time"), true),
            // Not applicable needs no check, but a dated one still ages.
            (DeclaredCveState::Na, None, false),
            (DeclaredCveState::Na, Some(YESTERDAY), false),
            (DeclaredCveState::Na, Some("2000-01-30T23:59:59Z"), true),
        ] {
            let declared = row(state, verified);
            assert_eq!(
                host_cve_status(&library, Some(&declared), None, NOW).source,
                CveStatusSource::Declared {
                    last_verified: verified.map(ToString::to_string),
                    verification_stale: stale,
                },
                "{state:?} {verified:?}"
            );
        }
    }

    fn host_with(
        state: KernelPostureState,
        running: Option<&str>,
        expected: Option<&str>,
        last_seen: Option<UnixSeconds>,
        interval: Option<u64>,
    ) -> Host {
        let mut host: Host = serde_json::from_value(serde_json::json!({
            "name": "demeter",
            "role": "server",
            "is_nix": true,
            "freshness": { "applicable": false },
        }))
        .expect("host");
        host.last_seen = last_seen;
        host.heartbeat_interval_secs = interval;
        host.kernel = Some(crate::KernelPosture {
            schema: crate::KERNEL_POSTURE_SCHEMA.to_string(),
            version: crate::KERNEL_POSTURE_VERSION,
            state,
            running_version: running.map(ToString::to_string),
            expected_version: expected.map(ToString::to_string),
            observed_at: 1,
        });
        host
    }

    #[test]
    fn a_host_becomes_a_report_only_with_a_comparable_kernel() {
        let host = host_with(
            KernelPostureState::RebootRequired,
            Some("6.18.55"),
            Some("6.18.56"),
            Some(NOW - 30),
            Some(60),
        );
        assert_eq!(
            KernelReport::from_host(&host, NOW),
            Some(KernelReport {
                running_version: Some("6.18.55"),
                next_boot_version: Some("6.18.56"),
                reported_at: NOW - 30,
                fresh: true
            })
        );

        let vendor = host_with(
            KernelPostureState::NotApplicable,
            Some("6.1.0-25-amd64"),
            None,
            Some(NOW - 30),
            Some(60),
        );
        assert_eq!(KernelReport::from_host(&vendor, NOW), None);

        let never = host_with(KernelPostureState::Unknown, None, None, None, Some(60));
        assert_eq!(KernelReport::from_host(&never, NOW), None);

        let mut no_kernel = host;
        no_kernel.kernel = None;
        assert_eq!(KernelReport::from_host(&no_kernel, NOW), None);
    }

    #[test]
    fn a_report_is_fresh_up_to_twice_the_host_heartbeat() {
        for (interval, age, fresh) in [
            (Some(60), 120, true),
            (Some(60), 121, false),
            (Some(300), 600, true),
            (Some(300), 601, false),
            // A host that never said its cadence is judged at the default.
            (None, 120, true),
            (None, 121, false),
        ] {
            let host = host_with(
                KernelPostureState::Current,
                Some("7.3.1"),
                Some("7.3.1"),
                Some(NOW - age),
                interval,
            );
            let report = KernelReport::from_host(&host, NOW).expect("report");
            assert_eq!(report.fresh, fresh, "{interval:?} at {age}");
            assert_eq!(report.reported_at, NOW - age);
        }
    }

    /// Versions that reach every branch of the comparison, and the spellings that
    /// must not: release candidates, vendor kernels, oversized numbers, noise.
    fn version_text() -> impl Strategy<Value = String> {
        prop_oneof![
            4 => (6u64..8, 0u64..3, 0u64..5).prop_map(|(a, b, c)| format!("{a}.{b}.{c}")),
            2 => (5u64..9, 0u64..20, 0u64..60).prop_map(|(a, b, c)| format!("{a}.{b}.{c}")),
            2 => (5u64..9, 0u64..20).prop_map(|(a, b)| format!("{a}.{b}")),
            1 => (5u64..9, 0u64..20, 0u64..60).prop_map(|(a, b, c)| format!("{a}.{b}.{c}-rc{c}")),
            1 => (5u64..9, 0u64..20, 0u64..60)
                .prop_map(|(a, b, c)| format!("{a}.{b}.{c}-0.rc{c}.24.fc46.x86_64")),
            1 => (5u64..9, 0u64..20, 0u64..60).prop_map(|(a, b, c)| format!("{a}.{b}.{c}-{c}-amd64")),
            1 => (5u64..9, 0u64..20, 0u64..60)
                .prop_map(|(a, b, c)| format!("{a}.{b}.{c}.{c}-microsoft-standard")),
            1 => (5u64..9, 0u64..20).prop_map(|(a, b)| format!("{a}.{b}.18446744073709551616")),
            1 => "[0-9.+_-]{0,16}",
            1 => "[ -~]{0,24}",
        ]
    }

    /// The version rule as a specification, written without the code it checks:
    /// digits and dots only, and two or three numbers.
    fn spec_version(value: &str) -> Option<KernelVersion> {
        let mut numbers: Vec<u64> = Vec::new();
        let mut current = String::new();
        for character in value.chars() {
            match character {
                '0'..='9' => current.push(character),
                '.' => numbers.push(std::mem::take(&mut current).parse().ok()?),
                _ => return None,
            }
        }
        numbers.push(current.parse().ok()?);
        match numbers[..] {
            [major, minor] => Some((major, minor, 0)),
            [major, minor, patch] => Some((major, minor, patch)),
            _ => None,
        }
    }

    /// At or above the fix on its own branch, or above every line when no line is
    /// on its branch.
    fn spec_fixed(version: KernelVersion, lines: &[KernelVersion]) -> bool {
        let branch: Vec<_> = lines
            .iter()
            .filter(|line| line.0 == version.0 && line.1 == version.1)
            .collect();
        if branch.is_empty() {
            !lines.is_empty() && lines.iter().all(|line| version > *line)
        } else {
            branch.iter().all(|line| version >= **line)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(8192))]

        /// No input yields fixed without a parsed version at or above a fix line,
        /// unless the status says it came from the file.
        #[test]
        fn computed_fixed_always_rests_on_a_parsed_version_at_or_above_a_fix_line(
            fix_lines in proptest::collection::vec(version_text(), 0..4),
            running in proptest::option::of(version_text()),
            next_boot in proptest::option::of(version_text()),
            age in 0i64..(90 * DAY),
            fresh in any::<bool>(),
            declared in proptest::option::of((
                prop_oneof![
                    Just(DeclaredCveState::Affected),
                    Just(DeclaredCveState::Fixed),
                    Just(DeclaredCveState::Unknown),
                    Just(DeclaredCveState::Na),
                ],
                prop_oneof![
                    Just(None),
                    Just(Some(YESTERDAY)),
                    Just(Some("2000-02-29T00:00:00.500Z")),
                    Just(Some("2000-01-01T00:00:00Z")),
                ],
            )),
        ) {
            let fix_refs: Vec<&str> = fix_lines.iter().map(String::as_str).collect();
            let kernel = cve("kernel", &fix_refs);
            let declared = declared.map(|(state, verified)| row(state, verified));
            let status = host_cve_status(
                &kernel,
                declared.as_ref(),
                Some(KernelReport {
                    running_version: running.as_deref(),
                    next_boot_version: next_boot.as_deref(),
                    reported_at: NOW - age,
                    fresh,
                }),
                NOW,
            );
            let from_file = matches!(status.source, CveStatusSource::Declared { .. });
            let file_says = declared.as_ref().map(|row| row.state);
            let spec_lines: Option<Vec<_>> =
                fix_lines.iter().map(|line| spec_version(line)).collect();
            let at_fix = |version: Option<&str>| {
                match (version.and_then(spec_version), spec_lines.as_ref()) {
                    (Some(version), Some(lines)) => spec_fixed(version, lines),
                    _ => false,
                }
            };
            if status.status == CveStatus::Fixed {
                if from_file {
                    // Only ever because the file itself says fixed.
                    prop_assert_eq!(file_says, Some(DeclaredCveState::Fixed));
                } else {
                    prop_assert!(at_fix(running.as_deref()));
                }
            }
            if status.status == CveStatus::RebootDue {
                prop_assert!(!from_file);
                prop_assert!(at_fix(next_boot.as_deref()));
                prop_assert!(!at_fix(running.as_deref()));
            }
            // A status from the file is that row's own state.
            if from_file {
                let expected = match file_says {
                    Some(DeclaredCveState::Affected) => CveStatus::Affected,
                    Some(DeclaredCveState::Fixed) => CveStatus::Fixed,
                    Some(DeclaredCveState::Unknown) => CveStatus::Unknown,
                    Some(DeclaredCveState::Na) => CveStatus::NotApplicable,
                    None => {
                        prop_assert!(false, "a status from a file with no row");
                        unreachable!()
                    }
                };
                prop_assert_eq!(status.status, expected);
            }
            // A fresh report is never set aside, except by not applicable.
            if fresh && file_says != Some(DeclaredCveState::Na) {
                prop_assert!(!from_file);
            }
        }

        /// A component other than the kernel is never decided by a version.
        #[test]
        fn only_the_kernel_is_computed(
            running in proptest::option::of(version_text()),
            next_boot in proptest::option::of(version_text()),
        ) {
            let library = cve("example-library", &["1.2.3"]);
            let status = host_cve_status(
                &library,
                None,
                Some(report(running.as_deref(), next_boot.as_deref())),
                NOW,
            );
            prop_assert_eq!(status.status, CveStatus::Unknown);
            prop_assert_eq!(status.source, CveStatusSource::Nothing);
        }
    }
}
