/// Resolve a UI label from the verified, offline presentation bundle.
/// This runs during the build; no unknown scheme can reach a running server.
pub fn scheme_label<'a>(table: &'a serde_json::Value, scheme: &str) -> &'a str {
    assert_eq!(table["schema"], "inspr.version-scheme-labels.v1");
    let label = table["labels"][scheme]
        .as_str()
        .expect("release scheme must have a doctrine label in schemes.json");
    assert!(
        !label.is_empty()
            && label.len() <= 32
            && label.bytes().all(|byte| (32..=126).contains(&byte)),
        "doctrine scheme label must be 1-32 printable ASCII characters"
    );
    label
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table() -> serde_json::Value {
        serde_json::from_str(include_str!(
            "assets/vendor/calendar-version-display/schemes.json"
        ))
        .expect("pinned doctrine label table")
    }

    #[test]
    fn labels_come_from_the_pinned_doctrine_table() {
        let labels = table();
        assert_eq!(scheme_label(&labels, "inspr-calendar-v2"), "INSPR-VER2");
        assert_eq!(scheme_label(&labels, "inspr-calendar-v1"), "INSPR-VER1");
        assert_eq!(scheme_label(&labels, "legacy"), "Legacy");
    }

    #[test]
    #[should_panic(expected = "release scheme must have a doctrine label")]
    fn unknown_scheme_fails_the_build_resolver() {
        scheme_label(&table(), "unrecognized-scheme");
    }

    #[test]
    #[should_panic(expected = "release scheme must have a doctrine label")]
    fn missing_label_fails_the_build_resolver() {
        let mut labels = table();
        labels["labels"]
            .as_object_mut()
            .unwrap()
            .remove("inspr-calendar-v2");
        scheme_label(&labels, "inspr-calendar-v2");
    }
}
