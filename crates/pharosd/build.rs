use std::{env, fs, path::PathBuf, process::Command};

fn main() {
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR"));
    let repo_root = manifest_dir
        .parent()
        .and_then(|path| path.parent())
        .expect("pharosd crate lives under crates/pharosd");
    let version_path = repo_root.join("VERSION");
    println!("cargo:rerun-if-changed={}", version_path.display());
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");

    let version = fs::read_to_string(&version_path)
        .expect("VERSION file is readable")
        .trim()
        .to_string();
    let cargo_version = env::var("CARGO_PKG_VERSION").expect("CARGO_PKG_VERSION");
    if version != cargo_version {
        panic!("VERSION ({version}) must match workspace package version ({cargo_version})");
    }
    println!("cargo:rustc-env=PHAROS_APP_VERSION={version}");

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
