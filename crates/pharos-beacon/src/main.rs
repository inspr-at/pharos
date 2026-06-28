//! pharos-beacon — per-host agent (PHAROS-6 scaffold stub).
//!
//! v0 just prints the report it *would* send. Self-registration, periodic
//! reporting, and on-host nix-freshness computation land in PHAROS-6 /
//! PHAROS-15; token auth (via Janus) in PHAROS-8.

use pharos_core::{HostReport, NixFreshness};

fn hostname() -> String {
    std::env::var("HOSTNAME")
        .ok()
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn main() {
    let url = std::env::var("PHAROS_URL").unwrap_or_else(|_| "https://pharos.barta.cm".into());

    // Placeholder report — real values are computed on-host in PHAROS-15.
    let report = HostReport {
        name: hostname(),
        role: "server".into(),
        is_nix: std::path::Path::new("/etc/NIXOS").exists(),
        heartbeat_interval_secs: 60,
        freshness: NixFreshness {
            applicable: std::path::Path::new("/etc/NIXOS").exists(),
            ..Default::default()
        },
    };

    println!(
        "pharos-beacon v{} — would register + report to {url}",
        env!("CARGO_PKG_VERSION")
    );
    println!("stub report: {report:?}");
    eprintln!(
        "NOTE: registration + nix-freshness reporting not yet implemented (PHAROS-6 / PHAROS-15)."
    );
}
