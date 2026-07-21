use pharos_core::{
    HostPreferences, HostRegistration, HostReport, NixFreshness, HOST_REGISTRATION_SCHEMA,
    HOST_REGISTRATION_VERSION, HOST_REPORT_SCHEMA, HOST_REPORT_VERSION, MAX_HOST_REPORT_BYTES,
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
