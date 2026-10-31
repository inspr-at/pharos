//! Whether a host has been in contact, and how loudly its silence shows.
//!
//! Availability says nothing about patches: a sleeping host on a vulnerable
//! version still shows as vulnerable through `cve_status`. The colour here depends
//! on what the host is declared to be, counted from its last successful contact.

use crate::fleet_data::{Availability, FleetDefaults, FleetHost, OfflineThresholds};
use crate::{Liveness, UnixSeconds};

const SECS_PER_DAY: u64 = 86_400;

/// What a host's silence means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactPolicy {
    AlwaysOn,
    Client(OfflineThresholds),
    Optional,
    /// It reports but is not in the data file, so nothing says what it should do.
    Unlisted,
}

impl ContactPolicy {
    pub fn of(host: &FleetHost, defaults: &FleetDefaults) -> Self {
        match (host.availability, host.offline_thresholds(defaults)) {
            (Availability::Client, Some(thresholds)) => Self::Client(thresholds),
            (Availability::AlwaysOn, _) => Self::AlwaysOn,
            _ => Self::Optional,
        }
    }
}

/// What the store knows about a beacon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BeaconEvidence {
    pub last_seen: Option<UnixSeconds>,
    pub liveness: Liveness,
}

/// What the beaconless probes know.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeEvidence {
    /// `None` when the check could not run or has stopped, which says nothing
    /// about the host.
    pub reachable: Option<bool>,
    pub last_reachable_at: Option<UnixSeconds>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactState {
    /// A beacon reported within its interval.
    Online,
    /// A probe answered. It says nothing more than that.
    Reachable,
    /// An always-on beacon missed reports but is not yet down.
    Late,
    Offline,
    /// A client out of contact. `over_days` is the threshold it has passed.
    Asleep {
        over_days: Option<u32>,
    },
    OfflineOptional,
    /// A probe got no reply and the host has never answered one.
    NoAnswerYet,
    /// The only signal is a probe that has no result, so nothing is known now.
    CheckUnavailable,
    /// No beacon and no probe: only hand-declared values.
    NoContactData,
    /// A beacon is expected, or registered, and no report has arrived.
    NeverReported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactTone {
    Ok,
    Neutral,
    Warn,
    Danger,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContactSource {
    Beacon,
    Probe,
    Nothing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostContact {
    pub state: ContactState,
    pub tone: ContactTone,
    pub source: ContactSource,
    pub last_contact: Option<UnixSeconds>,
    pub age_secs: Option<u64>,
}

/// One host's contact. `hand_declared` tells a host with no signal by design from
/// one whose beacon has not shown up.
pub fn host_contact(
    policy: ContactPolicy,
    beacon: Option<BeaconEvidence>,
    probe: Option<ProbeEvidence>,
    hand_declared: bool,
    now: UnixSeconds,
) -> HostContact {
    let contact = |state, tone, source, last_contact: Option<UnixSeconds>| HostContact {
        state,
        tone,
        source,
        last_contact,
        age_secs: last_contact.map(|at| now.saturating_sub(at).max(0) as u64),
    };

    if let Some(beacon) = beacon.filter(|beacon| beacon.liveness == Liveness::Live) {
        return contact(
            ContactState::Online,
            ContactTone::Ok,
            ContactSource::Beacon,
            beacon.last_seen,
        );
    }
    if let Some(probe) = probe.filter(|probe| probe.reachable == Some(true)) {
        return contact(
            ContactState::Reachable,
            ContactTone::Ok,
            ContactSource::Probe,
            probe.last_reachable_at,
        );
    }

    let beacon_seen = beacon.and_then(|beacon| beacon.last_seen);
    let probe_seen = probe.and_then(|probe| probe.last_reachable_at);
    let last = match (beacon_seen, probe_seen) {
        (Some(seen), Some(answered)) if answered > seen => Some((answered, ContactSource::Probe)),
        (Some(seen), _) => Some((seen, ContactSource::Beacon)),
        (None, Some(answered)) => Some((answered, ContactSource::Probe)),
        (None, None) => None,
    };
    let reachable = probe.and_then(|probe| probe.reachable);

    let Some((last, source)) = last else {
        return match probe {
            Some(_) if reachable == Some(false) => contact(
                ContactState::NoAnswerYet,
                if policy == ContactPolicy::AlwaysOn {
                    ContactTone::Danger
                } else {
                    ContactTone::Neutral
                },
                ContactSource::Probe,
                None,
            ),
            Some(_) => contact(
                ContactState::CheckUnavailable,
                ContactTone::Neutral,
                ContactSource::Probe,
                None,
            ),
            None if beacon.is_none() && hand_declared => contact(
                ContactState::NoContactData,
                ContactTone::Neutral,
                ContactSource::Nothing,
                None,
            ),
            None => contact(
                ContactState::NeverReported,
                ContactTone::Neutral,
                ContactSource::Beacon,
                None,
            ),
        };
    };

    let age_secs = now.saturating_sub(last).max(0) as u64;
    let (state, tone) = match policy {
        ContactPolicy::AlwaysOn => match (beacon.map(|beacon| beacon.liveness), reachable) {
            (Some(Liveness::Stale), _) => (ContactState::Late, ContactTone::Warn),
            (Some(Liveness::Down), _) | (_, Some(false)) => {
                (ContactState::Offline, ContactTone::Danger)
            }
            _ => (ContactState::CheckUnavailable, ContactTone::Neutral),
        },
        ContactPolicy::Client(thresholds) => {
            let past = |days: u32| age_secs > u64::from(days).saturating_mul(SECS_PER_DAY);
            if past(thresholds.offline_red_days) {
                (
                    ContactState::Asleep {
                        over_days: Some(thresholds.offline_red_days),
                    },
                    ContactTone::Danger,
                )
            } else if past(thresholds.offline_warn_days) {
                (
                    ContactState::Asleep {
                        over_days: Some(thresholds.offline_warn_days),
                    },
                    ContactTone::Warn,
                )
            } else {
                (
                    ContactState::Asleep { over_days: None },
                    ContactTone::Neutral,
                )
            }
        }
        ContactPolicy::Optional => (ContactState::OfflineOptional, ContactTone::Neutral),
        ContactPolicy::Unlisted => (ContactState::Offline, ContactTone::Neutral),
    };
    contact(state, tone, source, Some(last))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: UnixSeconds = 2_000_000_000;
    const DAY: i64 = 86_400;
    const CLIENT: ContactPolicy = ContactPolicy::Client(OfflineThresholds {
        offline_warn_days: 30,
        offline_red_days: 60,
    });

    fn beacon(age: i64, liveness: Liveness) -> Option<BeaconEvidence> {
        Some(BeaconEvidence {
            last_seen: Some(NOW - age),
            liveness,
        })
    }

    fn probe(reachable: Option<bool>, age: Option<i64>) -> Option<ProbeEvidence> {
        Some(ProbeEvidence {
            reachable,
            last_reachable_at: age.map(|age| NOW - age),
        })
    }

    fn silent(policy: ContactPolicy, age: i64) -> HostContact {
        host_contact(policy, None, probe(Some(false), Some(age)), false, NOW)
    }

    #[test]
    fn a_live_beacon_is_online_under_every_policy() {
        for policy in [
            ContactPolicy::AlwaysOn,
            CLIENT,
            ContactPolicy::Optional,
            ContactPolicy::Unlisted,
        ] {
            let contact = host_contact(policy, beacon(60, Liveness::Live), None, false, NOW);
            assert_eq!(contact.state, ContactState::Online);
            assert_eq!(contact.tone, ContactTone::Ok);
            assert_eq!(contact.source, ContactSource::Beacon);
            assert_eq!(contact.age_secs, Some(60));
        }
    }

    #[test]
    fn a_probe_answer_is_reachable_even_when_the_beacon_is_down() {
        let contact = host_contact(
            ContactPolicy::AlwaysOn,
            beacon(10 * DAY, Liveness::Down),
            probe(Some(true), Some(30)),
            false,
            NOW,
        );
        assert_eq!(contact.state, ContactState::Reachable);
        assert_eq!(contact.tone, ContactTone::Ok);
        assert_eq!(contact.source, ContactSource::Probe);
        assert_eq!(contact.last_contact, Some(NOW - 30));
    }

    #[test]
    fn a_live_beacon_outranks_a_probe() {
        let contact = host_contact(
            ContactPolicy::AlwaysOn,
            beacon(30, Liveness::Live),
            probe(Some(true), Some(5)),
            false,
            NOW,
        );
        assert_eq!(contact.state, ContactState::Online);
        assert_eq!(contact.source, ContactSource::Beacon);
    }

    #[test]
    fn an_always_on_host_goes_late_then_red_with_normal_liveness() {
        let late = host_contact(
            ContactPolicy::AlwaysOn,
            beacon(300, Liveness::Stale),
            None,
            false,
            NOW,
        );
        assert_eq!(late.state, ContactState::Late);
        assert_eq!(late.tone, ContactTone::Warn);

        let down = host_contact(
            ContactPolicy::AlwaysOn,
            beacon(2 * DAY, Liveness::Down),
            None,
            false,
            NOW,
        );
        assert_eq!(down.state, ContactState::Offline);
        assert_eq!(down.tone, ContactTone::Danger);
        assert_eq!(down.age_secs, Some(2 * DAY as u64));
    }

    #[test]
    fn an_always_on_probe_with_no_reply_is_red() {
        let contact = silent(ContactPolicy::AlwaysOn, DAY);
        assert_eq!(contact.state, ContactState::Offline);
        assert_eq!(contact.tone, ContactTone::Danger);
        assert_eq!(contact.source, ContactSource::Probe);
    }

    #[test]
    fn a_probe_that_cannot_run_never_calls_an_always_on_host_offline() {
        let contact = host_contact(
            ContactPolicy::AlwaysOn,
            None,
            probe(None, Some(DAY)),
            false,
            NOW,
        );
        assert_eq!(contact.state, ContactState::CheckUnavailable);
        assert_eq!(contact.tone, ContactTone::Neutral);
        assert_eq!(contact.last_contact, Some(NOW - DAY));
    }

    #[test]
    fn a_client_is_neutral_then_yellow_then_red_after_each_threshold() {
        let at = |age: i64| {
            let contact = silent(CLIENT, age);
            (contact.state, contact.tone)
        };
        let neutral = (
            ContactState::Asleep { over_days: None },
            ContactTone::Neutral,
        );
        let yellow = (
            ContactState::Asleep {
                over_days: Some(30),
            },
            ContactTone::Warn,
        );
        let red = (
            ContactState::Asleep {
                over_days: Some(60),
            },
            ContactTone::Danger,
        );
        assert_eq!(at(2 * DAY), neutral);
        assert_eq!(at(30 * DAY), neutral, "exactly 30 days is not over 30 days");
        assert_eq!(at(30 * DAY + 1), yellow);
        assert_eq!(at(60 * DAY), yellow, "exactly 60 days is not over 60 days");
        assert_eq!(at(60 * DAY + 1), red);
    }

    #[test]
    fn a_client_counts_from_its_latest_successful_contact_whichever_signal() {
        let beacon_older = host_contact(
            CLIENT,
            beacon(90 * DAY, Liveness::Down),
            probe(Some(false), Some(DAY)),
            false,
            NOW,
        );
        assert_eq!(beacon_older.state, ContactState::Asleep { over_days: None });
        assert_eq!(beacon_older.source, ContactSource::Probe);
        assert_eq!(beacon_older.last_contact, Some(NOW - DAY));

        let probe_older = host_contact(
            CLIENT,
            beacon(DAY, Liveness::Down),
            probe(Some(false), Some(90 * DAY)),
            false,
            NOW,
        );
        assert_eq!(probe_older.state, ContactState::Asleep { over_days: None });
        assert_eq!(probe_older.source, ContactSource::Beacon);
        assert_eq!(probe_older.last_contact, Some(NOW - DAY));
    }

    #[test]
    fn an_optional_host_never_turns_yellow_or_red() {
        for age in [DAY, 45 * DAY, 400 * DAY] {
            let contact = silent(ContactPolicy::Optional, age);
            assert_eq!(contact.state, ContactState::OfflineOptional);
            assert_eq!(contact.tone, ContactTone::Neutral);
        }
    }

    #[test]
    fn an_unlisted_host_has_no_policy_to_break() {
        let contact = host_contact(
            ContactPolicy::Unlisted,
            beacon(90 * DAY, Liveness::Down),
            None,
            false,
            NOW,
        );
        assert_eq!(contact.state, ContactState::Offline);
        assert_eq!(contact.tone, ContactTone::Neutral);
    }

    #[test]
    fn a_host_with_no_signal_gets_no_offline_colour() {
        for policy in [ContactPolicy::AlwaysOn, CLIENT, ContactPolicy::Optional] {
            let contact = host_contact(policy, None, None, true, NOW);
            assert_eq!(contact.state, ContactState::NoContactData);
            assert_eq!(contact.tone, ContactTone::Neutral);
            assert_eq!(contact.source, ContactSource::Nothing);
            assert_eq!(contact.last_contact, None);
        }
    }

    #[test]
    fn a_beacon_host_that_never_reported_says_so() {
        let waiting = BeaconEvidence {
            last_seen: None,
            liveness: Liveness::AwaitingFirstHeartbeat,
        };
        for (beacon, hand_declared) in
            [(None, false), (Some(waiting), false), (Some(waiting), true)]
        {
            let contact = host_contact(ContactPolicy::AlwaysOn, beacon, None, hand_declared, NOW);
            assert_eq!(contact.state, ContactState::NeverReported);
            assert_eq!(contact.tone, ContactTone::Neutral);
            assert_eq!(contact.source, ContactSource::Beacon);
        }
    }

    #[test]
    fn a_probed_host_that_never_answered_is_red_only_when_always_on() {
        let contact =
            |policy, reachable| host_contact(policy, None, probe(reachable, None), true, NOW);
        let always_on = contact(ContactPolicy::AlwaysOn, Some(false));
        assert_eq!(always_on.state, ContactState::NoAnswerYet);
        assert_eq!(always_on.tone, ContactTone::Danger);
        assert_eq!(always_on.source, ContactSource::Probe);

        let client = contact(CLIENT, Some(false));
        assert_eq!(client.state, ContactState::NoAnswerYet);
        assert_eq!(client.tone, ContactTone::Neutral);

        let not_run = contact(ContactPolicy::AlwaysOn, None);
        assert_eq!(not_run.state, ContactState::CheckUnavailable);
        assert_eq!(not_run.tone, ContactTone::Neutral);
    }

    #[test]
    fn a_time_in_the_future_has_no_age() {
        let contact = silent(CLIENT, -DAY);
        assert_eq!(contact.age_secs, Some(0));
        assert_eq!(contact.state, ContactState::Asleep { over_days: None });
    }

    #[test]
    fn the_policy_comes_from_the_file() {
        let defaults = FleetDefaults {
            client: OfflineThresholds {
                offline_warn_days: 30,
                offline_red_days: 60,
            },
        };
        let host = |availability: &str, extra: serde_json::Value| -> FleetHost {
            let mut value = serde_json::json!({
                "name": "hermes", "kind": "mac", "role": null, "os": null, "version": null,
                "kernel": null, "tailnet": { "state": "none" }, "lan": null, "public": null,
                "availability": availability,
            });
            for (key, field) in extra.as_object().expect("an object") {
                value[key] = field.clone();
            }
            serde_json::from_value(value).expect("host fixture")
        };
        assert_eq!(
            ContactPolicy::of(&host("always_on", serde_json::json!({})), &defaults),
            ContactPolicy::AlwaysOn
        );
        assert_eq!(
            ContactPolicy::of(&host("optional", serde_json::json!({})), &defaults),
            ContactPolicy::Optional
        );
        assert_eq!(
            ContactPolicy::of(&host("client", serde_json::json!({})), &defaults),
            CLIENT
        );
        assert_eq!(
            ContactPolicy::of(
                &host(
                    "client",
                    serde_json::json!({ "offline_warn_days": 7, "offline_red_days": 14 })
                ),
                &defaults
            ),
            ContactPolicy::Client(OfflineThresholds {
                offline_warn_days: 7,
                offline_red_days: 14,
            })
        );
    }
}
