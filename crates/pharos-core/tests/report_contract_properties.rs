use pharos_core::{
    HostPreferences, HostRegistration, HostReport, NixFreshness, HOST_REGISTRATION_SCHEMA,
    HOST_REGISTRATION_VERSION, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION, MAX_HOST_REPORT_BYTES,
    PREVIOUS_HOST_REPORT_SCHEMA, PREVIOUS_HOST_REPORT_VERSION, SUPPORTED_HOST_REPORT_CONTRACTS,
};
use proptest::prelude::*;

fn report(name: String, role: String, heartbeat_interval_secs: u64) -> HostReport {
    HostReport {
        schema: HOST_REPORT_SCHEMA.to_string(),
        version: HOST_REPORT_VERSION,
        name,
        role,
        is_nix: true,
        heartbeat_interval_secs,
        freshness: NixFreshness::default(),
        kernel: None,
        service_observations: Vec::new(),
        backup_observations: Vec::new(),
        inbound_rtt_ms: None,
        location: None,
        preferences: HostPreferences::default(),
    }
}

#[test]
fn control_plane_accepts_current_and_previous_reports_for_ordered_rollouts() {
    assert_eq!(
        SUPPORTED_HOST_REPORT_CONTRACTS,
        [
            (PREVIOUS_HOST_REPORT_SCHEMA, PREVIOUS_HOST_REPORT_VERSION),
            (HOST_REPORT_SCHEMA, HOST_REPORT_VERSION),
        ]
    );
    assert_eq!(PREVIOUS_HOST_REPORT_VERSION + 1, HOST_REPORT_VERSION);

    let current = report("current.example".to_string(), "server".to_string(), 60);
    current.validate_contract().unwrap();

    let previous = HostReport {
        schema: PREVIOUS_HOST_REPORT_SCHEMA.to_string(),
        version: PREVIOUS_HOST_REPORT_VERSION,
        name: "previous.example".to_string(),
        ..current
    };
    previous.validate_contract().unwrap();

    let mismatched = HostReport {
        version: HOST_REPORT_VERSION,
        ..previous
    };
    assert!(mismatched.validate_contract().is_err());

    let v2 = HostReport {
        schema: "inspr.pharos.host-report.v2".to_string(),
        version: 2,
        ..mismatched
    };
    assert!(v2.validate_contract().is_err());

    let older = HostReport {
        schema: "inspr.pharos.host-report.v0".to_string(),
        version: 0,
        ..v2
    };
    assert!(older.validate_contract().is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn arbitrary_report_identity_and_cadence_never_bypass_round_trip_validation(
        name in ".{0,96}",
        role in ".{0,320}",
        heartbeat_interval_secs in any::<u64>(),
    ) {
        let candidate = report(name, role, heartbeat_interval_secs);
        if candidate.validate_contract().is_ok() {
            let encoded = serde_json::to_vec(&candidate).unwrap();
            prop_assert!(encoded.len() <= MAX_HOST_REPORT_BYTES);
            let decoded: HostReport = serde_json::from_slice(&encoded).unwrap();
            prop_assert_eq!(decoded, candidate);
        }
    }

    #[test]
    fn arbitrary_registration_identity_has_stable_validation_after_json_round_trip(
        name in ".{0,96}",
        role in ".{0,320}",
        heartbeat_interval_secs in any::<u64>(),
    ) {
        let candidate = HostRegistration {
            schema: HOST_REGISTRATION_SCHEMA.to_string(),
            version: HOST_REGISTRATION_VERSION,
            name,
            role,
            is_nix: false,
            heartbeat_interval_secs,
        };
        let before = candidate.validate_contract().is_ok();
        let decoded: HostRegistration =
            serde_json::from_slice(&serde_json::to_vec(&candidate).unwrap()).unwrap();
        prop_assert_eq!(decoded.validate_contract().is_ok(), before);
    }

    #[test]
    fn arbitrary_bytes_cannot_panic_contract_decoding(
        input in prop::collection::vec(any::<u8>(), 0..(MAX_HOST_REPORT_BYTES + 1024)),
    ) {
        let result = std::panic::catch_unwind(|| {
            if let Ok(candidate) = serde_json::from_slice::<HostReport>(&input) {
                let _ = candidate.validate_contract();
            }
            if let Ok(candidate) = serde_json::from_slice::<HostRegistration>(&input) {
                let _ = candidate.validate_contract();
            }
        });
        prop_assert!(result.is_ok());
    }
}
