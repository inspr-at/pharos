use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
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
