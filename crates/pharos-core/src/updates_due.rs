//! What each host is waiting for.
//!
//! Pharos shows what is due and confirms when done; nixcfg and the kits do the
//! work. Done is only ever a later report showing it, and a check that cannot be
//! answered keeps a host out of up to date.

use crate::cve_status::{checked_after, declared_verification_stale};
use crate::fleet_data::FleetHost;
use crate::{
    liveness, GitRevisionRelation, Host, KernelPostureState, Liveness, NixpkgsRevisionRelation,
    UnixSeconds, DEFAULT_NIXPKGS_WARN_AFTER_DAYS,
};

/// A locked nixpkgs that differs from its channel is old past this age.
pub const OLD_NIXPKGS_AFTER_DAYS: u32 = DEFAULT_NIXPKGS_WARN_AFTER_DAYS;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateDue {
    Reboot {
        running_version: Option<String>,
        next_boot_version: Option<String>,
    },
    BehindConfig {
        commits: u32,
    },
    OldNixpkgs {
        age_days: u32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UpdatesState {
    Due,
    /// A fresh report answered every check, and none is due.
    UpToDate,
    /// The same, from a report that has since gone stale. Not a current claim.
    LastKnownUpToDate,
    /// No report to judge; the file's values stand in, with their last check.
    HandDeclared,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdatesSource {
    Report {
        /// Server-stamped time of the report this rests on.
        confirmed_at: UnixSeconds,
        age_secs: u64,
        stale: bool,
    },
    Declared {
        last_verified: Option<String>,
        verification_stale: bool,
    },
    Nothing,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostUpdates {
    pub state: UpdatesState,
    pub due: Vec<UpdateDue>,
    pub source: UpdatesSource,
}

/// One host's updates. A fresh report decides. Between a stale report and the
/// file's declared values the newer evidence decides, as for a CVE's status.
pub fn host_updates(
    host: Option<&Host>,
    declared: Option<&FleetHost>,
    now: UnixSeconds,
) -> HostUpdates {
    let report = host.and_then(|host| host.last_seen.map(|last_seen| (host, last_seen)));
    let fresh = report.is_some_and(|(host, _)| {
        liveness(host.last_seen, host.heartbeat_interval_secs, now) == Liveness::Live
    });
    let declared = declared.filter(|host| host.version.is_some() || host.kernel.is_some());
    match (report, declared) {
        (Some((_, last_seen)), Some(declared))
            if !fresh && checked_after(declared.last_verified.as_deref(), last_seen) =>
        {
            declared_updates(declared, now)
        }
        (Some((host, last_seen)), _) => reported_updates(host, last_seen, fresh, now),
        (None, Some(declared)) => declared_updates(declared, now),
        (None, None) => HostUpdates {
            state: UpdatesState::Unknown,
            due: Vec::new(),
            source: UpdatesSource::Nothing,
        },
    }
}

fn declared_updates(declared: &FleetHost, now: UnixSeconds) -> HostUpdates {
    HostUpdates {
        state: UpdatesState::HandDeclared,
        due: Vec::new(),
        source: UpdatesSource::Declared {
            last_verified: declared.last_verified.clone(),
            verification_stale: declared_verification_stale(declared.last_verified.as_deref(), now),
        },
    }
}

/// The answer to one check.
enum Check {
    Due(UpdateDue),
    Done,
    NotKnown,
    /// This check says nothing about this kind of host.
    DoesNotApply,
}

fn reported_updates(
    host: &Host,
    last_seen: UnixSeconds,
    fresh: bool,
    now: UnixSeconds,
) -> HostUpdates {
    let checks = [
        kernel_check(host),
        config_check(host),
        nixpkgs_check(host, now),
    ];
    let answered = checks
        .iter()
        .any(|check| matches!(check, Check::Due(_) | Check::Done));
    let not_known = checks.iter().any(|check| matches!(check, Check::NotKnown));
    let due: Vec<UpdateDue> = checks
        .into_iter()
        .filter_map(|check| match check {
            Check::Due(item) => Some(item),
            _ => None,
        })
        .collect();
    let state = if !due.is_empty() {
        UpdatesState::Due
    } else if not_known || !answered {
        UpdatesState::Unknown
    } else if fresh {
        UpdatesState::UpToDate
    } else {
        UpdatesState::LastKnownUpToDate
    };
    HostUpdates {
        state,
        due,
        source: UpdatesSource::Report {
            confirmed_at: last_seen,
            age_secs: now.saturating_sub(last_seen).max(0) as u64,
            stale: !fresh,
        },
    }
}

fn kernel_check(host: &Host) -> Check {
    let Some(posture) = host.kernel.as_ref() else {
        return if host.freshness.applicable {
            Check::NotKnown
        } else {
            Check::DoesNotApply
        };
    };
    match posture.state {
        KernelPostureState::RebootRequired => Check::Due(UpdateDue::Reboot {
            running_version: posture.running_version.clone(),
            next_boot_version: posture.expected_version.clone(),
        }),
        KernelPostureState::Current => Check::Done,
        KernelPostureState::Unknown => Check::NotKnown,
        KernelPostureState::NotApplicable => Check::DoesNotApply,
    }
}

fn config_check(host: &Host) -> Check {
    let freshness = &host.freshness;
    if !freshness.applicable {
        return Check::DoesNotApply;
    }
    let comparison = freshness.nixcfg_comparison.as_ref();
    match comparison.map(|comparison| (comparison.relation, comparison.commits_behind)) {
        Some((GitRevisionRelation::Behind, Some(commits))) if commits > 0 => {
            Check::Due(UpdateDue::BehindConfig { commits })
        }
        Some((GitRevisionRelation::Current, _)) if freshness.deployment_evidence.is_some() => {
            Check::Done
        }
        // Ahead or diverged is not behind, and it is not the declared config either.
        _ => Check::NotKnown,
    }
}

fn nixpkgs_check(host: &Host, now: UnixSeconds) -> Check {
    let freshness = &host.freshness;
    if !freshness.applicable {
        return Check::DoesNotApply;
    }
    if freshness.deployment_evidence.is_none() {
        return Check::NotKnown;
    }
    let age_days = freshness.nixpkgs_age_days_at(now);
    match (
        freshness
            .nixpkgs_comparison
            .as_ref()
            .map(|comparison| comparison.relation),
        age_days,
    ) {
        (Some(NixpkgsRevisionRelation::Current), _) => Check::Done,
        (Some(NixpkgsRevisionRelation::Different), Some(age_days)) => {
            if age_days > OLD_NIXPKGS_AFTER_DAYS {
                Check::Due(UpdateDue::OldNixpkgs { age_days })
            } else {
                Check::Done
            }
        }
        _ => Check::NotKnown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fleet_data::FleetData;
    use crate::{
        KernelPosture, NixDeploymentEvidence, NixFreshness, NixcfgGitComparison,
        NixpkgsGitComparison, KERNEL_POSTURE_SCHEMA, KERNEL_POSTURE_VERSION,
        NIX_DEPLOYMENT_EVIDENCE_SCHEMA, NIX_DEPLOYMENT_EVIDENCE_VERSION,
    };

    /// 2000-03-01T00:00:00Z
    const NOW: UnixSeconds = 951_868_800;
    const DAY: i64 = 86_400;

    fn deployed() -> String {
        "a".repeat(40)
    }

    fn kernel(state: KernelPostureState, running: &str, next_boot: &str) -> KernelPosture {
        KernelPosture {
            schema: KERNEL_POSTURE_SCHEMA.to_string(),
            version: KERNEL_POSTURE_VERSION,
            state,
            running_version: Some(running.to_string()),
            expected_version: Some(next_boot.to_string()),
            observed_at: NOW,
        }
    }

    /// A NixOS host that a fresh report shows with nothing due.
    fn up_to_date_host() -> Host {
        let mut host: Host = serde_json::from_value(serde_json::json!({
            "name": "demeter",
            "role": "server",
            "is_nix": true,
            "freshness": { "applicable": false },
        }))
        .expect("host");
        host.last_seen = Some(NOW - 30);
        host.heartbeat_interval_secs = Some(60);
        host.kernel = Some(kernel(KernelPostureState::Current, "7.3.1", "7.3.1"));
        host.freshness = NixFreshness {
            applicable: true,
            deployment_evidence: Some(NixDeploymentEvidence {
                schema: NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
                version: NIX_DEPLOYMENT_EVIDENCE_VERSION,
                source_revision: deployed(),
                flake_lock_sha256: "b".repeat(64),
                nixpkgs_revision: "c".repeat(40),
                nixpkgs_last_modified: NOW - 74 * DAY,
                nixpkgs_channel: "nixos-unstable".to_string(),
            }),
            nixcfg_comparison: Some(NixcfgGitComparison {
                upstream_revision: deployed(),
                relation: GitRevisionRelation::Current,
                commits_behind: Some(0),
            }),
            nixpkgs_comparison: Some(NixpkgsGitComparison {
                upstream_revision: "c".repeat(40),
                relation: NixpkgsRevisionRelation::Current,
            }),
            ..NixFreshness::default()
        };
        host
    }

    fn with(change: impl FnOnce(&mut Host)) -> Host {
        let mut host = up_to_date_host();
        change(&mut host);
        host
    }

    fn behind(host: &mut Host, commits: u32) {
        host.freshness.nixcfg_comparison = Some(NixcfgGitComparison {
            upstream_revision: "d".repeat(40),
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(commits),
        });
    }

    fn nixpkgs_differs(host: &mut Host, age_days: i64) {
        host.freshness.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "e".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        host.freshness
            .deployment_evidence
            .as_mut()
            .expect("evidence")
            .nixpkgs_last_modified = NOW - age_days * DAY;
    }

    fn fresh_source() -> UpdatesSource {
        UpdatesSource::Report {
            confirmed_at: NOW - 30,
            age_secs: 30,
            stale: false,
        }
    }

    fn reboot_due() -> UpdateDue {
        UpdateDue::Reboot {
            running_version: Some("6.18.55".to_string()),
            next_boot_version: Some("6.18.56".to_string()),
        }
    }

    fn declared_host(name: &str) -> FleetHost {
        let data = FleetData::parse(include_str!("../../../contracts/fleet-data-v3.json"))
            .expect("contract validates");
        data.sections
            .into_iter()
            .flat_map(|section| section.hosts)
            .find(|host| host.name == name)
            .expect("host in the contract")
    }

    #[test]
    fn up_to_date_needs_every_check_answered_by_a_fresh_report() {
        let host = up_to_date_host();
        assert_eq!(
            host_updates(Some(&host), None, NOW),
            HostUpdates {
                state: UpdatesState::UpToDate,
                due: Vec::new(),
                source: fresh_source(),
            }
        );
    }

    #[test]
    fn each_thing_that_can_be_due() {
        let table: [(&str, Host, Vec<UpdateDue>); 5] = [
            (
                "reboot due",
                with(|host| {
                    host.kernel = Some(kernel(
                        KernelPostureState::RebootRequired,
                        "6.18.55",
                        "6.18.56",
                    ))
                }),
                vec![reboot_due()],
            ),
            (
                "behind the config",
                with(|host| behind(host, 12)),
                vec![UpdateDue::BehindConfig { commits: 12 }],
            ),
            (
                "old nixpkgs",
                with(|host| nixpkgs_differs(host, 74)),
                vec![UpdateDue::OldNixpkgs { age_days: 74 }],
            ),
            (
                "just past the cut",
                with(|host| nixpkgs_differs(host, 31)),
                vec![UpdateDue::OldNixpkgs { age_days: 31 }],
            ),
            (
                "several at once",
                with(|host| {
                    host.kernel = Some(kernel(
                        KernelPostureState::RebootRequired,
                        "6.18.55",
                        "6.18.56",
                    ));
                    behind(host, 3);
                    nixpkgs_differs(host, 40);
                }),
                vec![
                    reboot_due(),
                    UpdateDue::BehindConfig { commits: 3 },
                    UpdateDue::OldNixpkgs { age_days: 40 },
                ],
            ),
        ];
        for (name, host, due) in table {
            let updates = host_updates(Some(&host), None, NOW);
            assert_eq!(updates.state, UpdatesState::Due, "{name}");
            assert_eq!(updates.due, due, "{name}");
            assert_eq!(updates.source, fresh_source(), "{name}");
        }
    }

    #[test]
    fn a_kernel_check_that_does_not_apply_leaves_the_other_checks_to_answer() {
        let darwin = with(|host| {
            host.kernel = Some(KernelPosture {
                state: KernelPostureState::NotApplicable,
                running_version: None,
                expected_version: None,
                ..kernel(KernelPostureState::Current, "7.3.1", "7.3.1")
            })
        });
        assert_eq!(
            host_updates(Some(&darwin), None, NOW).state,
            UpdatesState::UpToDate
        );
    }

    #[test]
    fn a_differing_nixpkgs_within_the_limit_is_not_due() {
        let host = with(|host| nixpkgs_differs(host, 30));
        assert_eq!(
            host_updates(Some(&host), None, NOW).state,
            UpdatesState::UpToDate
        );
    }

    #[test]
    fn no_data_is_unknown_and_never_up_to_date() {
        let table: [(&str, Host); 10] = [
            ("no kernel posture", with(|host| host.kernel = None)),
            (
                "kernel unknown",
                with(|host| {
                    host.kernel = Some(KernelPosture {
                        state: KernelPostureState::Unknown,
                        running_version: None,
                        expected_version: None,
                        ..kernel(KernelPostureState::Unknown, "7.3.1", "7.3.1")
                    })
                }),
            ),
            (
                "no config comparison",
                with(|host| host.freshness.nixcfg_comparison = None),
            ),
            (
                "ahead of the config",
                with(|host| {
                    host.freshness.nixcfg_comparison = Some(NixcfgGitComparison {
                        upstream_revision: "d".repeat(40),
                        relation: GitRevisionRelation::Ahead,
                        commits_behind: None,
                    })
                }),
            ),
            (
                "diverged from the config",
                with(|host| {
                    host.freshness.nixcfg_comparison = Some(NixcfgGitComparison {
                        upstream_revision: "d".repeat(40),
                        relation: GitRevisionRelation::Diverged,
                        commits_behind: None,
                    })
                }),
            ),
            (
                "behind with no count",
                with(|host| {
                    host.freshness.nixcfg_comparison = Some(NixcfgGitComparison {
                        upstream_revision: "d".repeat(40),
                        relation: GitRevisionRelation::Behind,
                        commits_behind: None,
                    })
                }),
            ),
            (
                "no deployment evidence",
                with(|host| host.freshness.deployment_evidence = None),
            ),
            (
                "no nixpkgs comparison",
                with(|host| host.freshness.nixpkgs_comparison = None),
            ),
            (
                "a nixpkgs age that cannot be judged",
                with(|host| {
                    nixpkgs_differs(host, 0);
                    host.freshness
                        .deployment_evidence
                        .as_mut()
                        .expect("evidence")
                        .nixpkgs_last_modified = i64::MIN;
                }),
            ),
            (
                "a beacon off NixOS has nothing to check",
                with(|host| {
                    host.is_nix = false;
                    host.kernel = None;
                    host.freshness = NixFreshness::default();
                }),
            ),
        ];
        for (name, host) in table {
            let updates = host_updates(Some(&host), None, NOW);
            assert_eq!(updates.state, UpdatesState::Unknown, "{name}");
            assert_eq!(updates.due, Vec::new(), "{name}");
            assert_eq!(updates.source, fresh_source(), "{name}");
        }

        let never: Host = with(|host| host.last_seen = None);
        for host in [None, Some(&never)] {
            assert_eq!(
                host_updates(host, None, NOW),
                HostUpdates {
                    state: UpdatesState::Unknown,
                    due: Vec::new(),
                    source: UpdatesSource::Nothing,
                }
            );
        }
    }

    #[test]
    fn an_unverified_nixpkgs_age_is_never_called_old() {
        let host = with(|host| {
            behind(host, 5);
            nixpkgs_differs(host, 0);
            host.freshness.deployment_evidence = None;
            host.freshness.nixpkgs_age_days = Some(90);
        });
        assert_eq!(
            host_updates(Some(&host), None, NOW).due,
            vec![UpdateDue::BehindConfig { commits: 5 }]
        );
    }

    #[test]
    fn something_due_shows_even_when_another_check_has_no_answer() {
        let host = with(|host| {
            behind(host, 5);
            host.kernel = None;
        });
        let updates = host_updates(Some(&host), None, NOW);
        assert_eq!(updates.state, UpdatesState::Due);
        assert_eq!(updates.due, vec![UpdateDue::BehindConfig { commits: 5 }]);
    }

    #[test]
    fn a_stale_report_keeps_what_it_said_and_is_labelled() {
        let late = |change: fn(&mut Host)| {
            with(|host| {
                host.last_seen = Some(NOW - 2 * DAY);
                change(host);
            })
        };
        let source = UpdatesSource::Report {
            confirmed_at: NOW - 2 * DAY,
            age_secs: (2 * DAY) as u64,
            stale: true,
        };

        // Up to date is a claim about now, so it does not survive going stale.
        let quiet = host_updates(Some(&late(|_| {})), None, NOW);
        assert_eq!(quiet.state, UpdatesState::LastKnownUpToDate);
        assert_eq!(quiet.source, source);

        let due = host_updates(Some(&late(|host| behind(host, 5))), None, NOW);
        assert_eq!(due.state, UpdatesState::Due);
        assert_eq!(due.due, vec![UpdateDue::BehindConfig { commits: 5 }]);
        assert_eq!(due.source, source);

        let unknown = host_updates(Some(&late(|host| host.kernel = None)), None, NOW);
        assert_eq!(unknown.state, UpdatesState::Unknown);
        assert_eq!(unknown.source, source);
    }

    #[test]
    fn hand_declared_values_stand_in_without_a_report() {
        // The contract's athena declares a version and a kernel, checked 2000-01-03.
        let declared = declared_host("athena");
        assert_eq!(
            host_updates(None, Some(&declared), NOW),
            HostUpdates {
                state: UpdatesState::HandDeclared,
                due: Vec::new(),
                source: UpdatesSource::Declared {
                    last_verified: declared.last_verified.clone(),
                    verification_stale: true,
                },
            }
        );

        let mut checked = declared;
        checked.last_verified = Some("2000-02-29T00:00:00Z".to_string());
        assert_eq!(
            host_updates(None, Some(&checked), NOW).source,
            UpdatesSource::Declared {
                last_verified: checked.last_verified.clone(),
                verification_stale: false,
            }
        );
    }

    #[test]
    fn a_report_and_the_file_are_decided_by_freshness_then_the_newer_evidence() {
        let mut checked_yesterday = declared_host("athena");
        checked_yesterday.last_verified = Some("2000-02-29T00:00:00Z".to_string());

        // A fresh report wins, however recent the check.
        let fresh = up_to_date_host();
        let mut checked_just_now = checked_yesterday.clone();
        checked_just_now.last_verified = Some("2000-02-29T23:59:50Z".to_string());
        assert_eq!(
            host_updates(Some(&fresh), Some(&checked_just_now), NOW).state,
            UpdatesState::UpToDate
        );

        // A report that went stale before the check loses to it.
        let quiet = with(|host| {
            host.last_seen = Some(NOW - 2 * DAY);
            behind(host, 5);
        });
        assert_eq!(
            host_updates(Some(&quiet), Some(&checked_yesterday), NOW).state,
            UpdatesState::HandDeclared
        );

        // A report newer than the check keeps what it said, so a missed heartbeat
        // alone does not change the answer.
        let recent = with(|host| {
            host.last_seen = Some(NOW - 600);
            behind(host, 5);
        });
        let updates = host_updates(Some(&recent), Some(&checked_yesterday), NOW);
        assert_eq!(updates.state, UpdatesState::Due);
        assert_eq!(updates.due, vec![UpdateDue::BehindConfig { commits: 5 }]);
        assert_eq!(
            updates.source,
            UpdatesSource::Report {
                confirmed_at: NOW - 600,
                age_secs: 600,
                stale: true,
            }
        );
    }

    #[test]
    fn a_listed_host_that_declares_nothing_and_never_reported_is_unknown() {
        assert_eq!(
            host_updates(None, Some(&declared_host("demeter")), NOW),
            HostUpdates {
                state: UpdatesState::Unknown,
                due: Vec::new(),
                source: UpdatesSource::Nothing,
            }
        );
    }

    #[test]
    fn done_is_only_a_later_report_and_carries_its_time() {
        let due = with(|host| {
            host.last_seen = Some(NOW - 45);
            behind(host, 3);
        });
        let before = host_updates(Some(&due), None, NOW);
        assert_eq!(before.state, UpdatesState::Due);

        // Time passing alone changes nothing; only the age moves.
        let later = NOW + 30;
        assert_eq!(
            host_updates(Some(&due), None, later).state,
            UpdatesState::Due
        );

        // The report that shows it done is the one the page names.
        let done = with(|host| host.last_seen = Some(later - 5));
        let after = host_updates(Some(&done), None, later);
        assert_eq!(after.state, UpdatesState::UpToDate);
        assert_eq!(
            after.source,
            UpdatesSource::Report {
                confirmed_at: later - 5,
                age_secs: 5,
                stale: false,
            }
        );
    }
}
