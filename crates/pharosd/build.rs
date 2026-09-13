use sha2::{Digest, Sha256};
use std::{collections::BTreeSet, env, fs, path::Path, path::PathBuf, process::Command};

const DISPLAY_SOURCE: &str = "83d26aa605b21493d22805ba477e6ac279b6409d";
const DISPLAY_CONFIG_SHA256: &str =
    "7843f3515ce329277d2d576000bd60ac410d725b241d502a9a3fecb2533d956d";
const DISPLAY_MANIFEST_SHA256: &str =
    "e7052c82af0d0cdfe4a466bf3129c1de56014253247106f2670788419f118812";

fn hex_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn verify_calendar_bundle(manifest_dir: &Path) {
    let bundle = manifest_dir.join("assets/vendor/calendar-version-display");
    let expected: BTreeSet<&str> = [
        "display.json",
        "version.js",
        "presentation.js",
        "version-interaction.js",
        "auto-animate.js",
        "auto-animate-license.js",
        "package.json",
        "manifest.json",
    ]
    .into_iter()
    .collect();
    let observed: BTreeSet<String> = fs::read_dir(&bundle)
        .expect("calendar display bundle is readable")
        .map(|entry| {
            let entry = entry.expect("calendar display bundle entry is readable");
            assert!(
                entry
                    .file_type()
                    .expect("calendar display bundle entry has a type")
                    .is_file(),
                "calendar display bundle entries must be regular files"
            );
            entry
                .file_name()
                .into_string()
                .expect("calendar display bundle names are UTF-8")
        })
        .collect();
    assert_eq!(
        observed,
        expected.into_iter().map(str::to_string).collect(),
        "calendar display bundle file set drifted"
    );
    let manifest_path = bundle.join("manifest.json");
    let manifest_raw = fs::read(&manifest_path).expect("calendar display manifest is readable");
    assert_eq!(
        hex_sha256(&manifest_raw),
        DISPLAY_MANIFEST_SHA256,
        "calendar display manifest digest drifted"
    );
    let manifest: serde_json::Value =
        serde_json::from_slice(&manifest_raw).expect("calendar display manifest is valid JSON");
    assert_eq!(manifest["repository"], "inspr-at/inspr");
    assert_eq!(manifest["revision"], DISPLAY_SOURCE);
    assert_eq!(manifest["expectedConfigSha256"], DISPLAY_CONFIG_SHA256);
    assert_eq!(manifest["schema"], "inspr.calendar-version-display.v2");
    assert_eq!(manifest["mode"], "build-time-only");
    assert_eq!(manifest["consumers"], serde_json::json!([]));
    assert_eq!(manifest["runtimeConsumers"], false);
    let entries = manifest["files"]
        .as_array()
        .expect("calendar display manifest files are an array");
    assert_eq!(
        entries.len(),
        7,
        "calendar display manifest entry count drifted"
    );
    for entry in entries {
        let name = entry["outputPath"]
            .as_str()
            .expect("calendar display outputPath is a string");
        let path = bundle.join(name);
        let raw = fs::read(&path).expect("calendar display payload is readable");
        assert_eq!(
            raw.len() as u64,
            entry["size"]
                .as_u64()
                .expect("calendar display payload size is unsigned"),
            "calendar display payload size drifted: {name}"
        );
        assert_eq!(
            hex_sha256(&raw),
            entry["sha256"]
                .as_str()
                .expect("calendar display payload digest is a string"),
            "calendar display payload digest drifted: {name}"
        );
        println!("cargo:rerun-if-changed={}", path.display());
    }
    println!("cargo:rerun-if-changed={}", manifest_path.display());
}

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    verify_calendar_bundle(&manifest_dir);
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("pharosd crate lives under crates/pharosd");
    let release_path = repo_root.join("RELEASE.json");
    println!("cargo:rerun-if-changed={}", release_path.display());
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");

    let release: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&release_path).expect("RELEASE.json is readable"))
            .expect("RELEASE.json is valid JSON");
    let string = |key: &str| {
        release[key]
            .as_str()
            .unwrap_or_else(|| panic!("RELEASE.json {key} is a string"))
    };
    let version = string("version");
    let cargo_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    let mapped_cargo_version = release["ecosystem_versions"]["cargo_semver"]
        .as_str()
        .expect("RELEASE.json ecosystem_versions.cargo_semver is a string");
    if mapped_cargo_version != cargo_version {
        panic!(
            "RELEASE.json Cargo mapping ({mapped_cargo_version}) must match workspace package version ({cargo_version})"
        );
    }
    println!("cargo:rustc-env=PHAROS_APP_VERSION={version}");
    println!(
        "cargo:rustc-env=PHAROS_VERSION_SCHEME={}",
        string("version_scheme")
    );
    println!(
        "cargo:rustc-env=PHAROS_RELEASE_CHANNEL={}",
        string("release_channel")
    );
    println!(
        "cargo:rustc-env=PHAROS_RELEASE_SEQUENCE={}",
        release["release_sequence"]
            .as_u64()
            .expect("RELEASE.json release_sequence is an unsigned integer")
    );
    println!(
        "cargo:rustc-env=PHAROS_LAST_LEGACY_VERSION={}",
        release["migration_anchor"]["last_legacy_version"]
            .as_str()
            .expect("RELEASE.json migration anchor has last_legacy_version")
    );
    println!(
        "cargo:rustc-env=PHAROS_LAST_LEGACY_RELEASE_SEQUENCE={}",
        release["migration_anchor"]["last_legacy_release_sequence"]
            .as_u64()
            .expect("RELEASE.json migration anchor has last_legacy_release_sequence")
    );
    println!(
        "cargo:rustc-env=PHAROS_FIRST_CALENDAR_VERSION={}",
        release["migration_anchor"]["first_calendar_version"]
            .as_str()
            .expect("RELEASE.json migration anchor has first_calendar_version")
    );
    println!(
        "cargo:rustc-env=PHAROS_FIRST_CALENDAR_RELEASE_SEQUENCE={}",
        release["migration_anchor"]["first_calendar_release_sequence"]
            .as_u64()
            .expect("RELEASE.json migration anchor has first_calendar_release_sequence")
    );

    // PHAROS-259: the v1 → v2 anchor. Present in every v2 record; a v1 record
    // (schema v1) has no successor era yet, so these stay empty there.
    let anchor = &release["migration_anchor"];
    let optional_anchor = |key: &str| anchor[key].as_str().unwrap_or("").to_string();
    let optional_sequence = |key: &str| {
        anchor[key]
            .as_u64()
            .map(|value| value.to_string())
            .unwrap_or_default()
    };
    println!(
        "cargo:rustc-env=PHAROS_LAST_CALENDAR_V1_VERSION={}",
        optional_anchor("last_calendar_v1_version")
    );
    println!(
        "cargo:rustc-env=PHAROS_LAST_CALENDAR_V1_RELEASE_SEQUENCE={}",
        optional_sequence("last_calendar_v1_release_sequence")
    );
    println!(
        "cargo:rustc-env=PHAROS_FIRST_CALENDAR_V2_VERSION={}",
        optional_anchor("first_calendar_v2_version")
    );
    println!(
        "cargo:rustc-env=PHAROS_FIRST_CALENDAR_V2_RELEASE_SEQUENCE={}",
        optional_sequence("first_calendar_v2_release_sequence")
    );

    let git_commit = env::var("GIT_COMMIT")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or_else(|| {
            Command::new("git")
                .args(["rev-parse", "--short=12", "HEAD"])
                .current_dir(repo_root)
                .output()
                .ok()
                .and_then(|output| {
                    output
                        .status
                        .success()
                        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
                })
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "dev".to_string())
        });
    println!("cargo:rustc-env=PHAROS_GIT_COMMIT={git_commit}");
}
