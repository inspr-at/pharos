//! pharos-beacon — per-host agent (PHAROS-6 / PHAROS-15).
//!
//! Computes this host's Nix freshness (flake.lock age + commits behind nixcfg)
//! and reports it to pharosd. v1 sends a single report then exits — deploy as a
//! recurring service (systemd timer / Nix module) for continuous reporting
//! (PHAROS-6/7). Token auth via Janus is PHAROS-8.
//!
//! Env: PHAROS_URL (pharosd base, default http://100.64.0.4:8088),
//!      NIXCFG_DIR (flake checkout; auto-detected otherwise),
//!      PHAROS_HOSTNAME / PHAROS_ROLE (overrides).

use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use pharos_core::{HostReport, NixFreshness};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn hostname() -> String {
    std::env::var("PHAROS_HOSTNAME")
        .ok()
        .or_else(|| std::env::var("HOSTNAME").ok())
        .or_else(|| {
            std::fs::read_to_string("/etc/hostname")
                .ok()
                .map(|s| s.trim().to_string())
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

/// Locate a flake checkout (one containing flake.lock).
fn nixcfg_dir() -> Option<String> {
    if let Ok(d) = std::env::var("NIXCFG_DIR") {
        return Some(d);
    }
    [
        "/etc/nixos",
        "/home/mba/Code/nixcfg",
        "/root/dsccfg",
        "/home/mba/dsccfg",
    ]
    .into_iter()
    .find(|d| Path::new(&format!("{d}/flake.lock")).exists())
    .map(String::from)
}

/// Days since the newest input in flake.lock (i.e. since the last `nix flake
/// update`).
fn flake_lock_age_days(dir: &str) -> Option<u32> {
    let raw = std::fs::read_to_string(format!("{dir}/flake.lock")).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let newest = v
        .get("nodes")?
        .as_object()?
        .values()
        .filter_map(|n| n.get("locked")?.get("lastModified")?.as_i64())
        .max()?;
    let days = (now_unix() - newest).max(0) / 86_400;
    u32::try_from(days).ok()
}

/// Commits the checkout is behind its upstream (best-effort fetch first).
fn commits_behind(dir: &str) -> Option<u32> {
    let _ = Command::new("git")
        .args(["-C", dir, "fetch", "--quiet"])
        .status();
    let out = Command::new("git")
        .args(["-C", dir, "rev-list", "--count", "HEAD..@{u}"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout).ok()?.trim().parse().ok()
}

fn main() {
    let base = std::env::var("PHAROS_URL").unwrap_or_else(|_| "http://100.64.0.4:8088".into());
    let endpoint = format!("{}/report", base.trim_end_matches('/'));
    let host = hostname();
    let is_nix = Path::new("/etc/NIXOS").exists();
    let dir = nixcfg_dir();

    let freshness = if is_nix {
        NixFreshness {
            applicable: true,
            flake_lock_age_days: dir.as_deref().and_then(flake_lock_age_days),
            commits_behind: dir.as_deref().and_then(commits_behind),
        }
    } else {
        NixFreshness::default()
    };

    let report = HostReport {
        name: host.clone(),
        role: std::env::var("PHAROS_ROLE").unwrap_or_else(|_| "server".into()),
        is_nix,
        heartbeat_interval_secs: 60,
        freshness,
    };

    let body = serde_json::to_string(&report).expect("serialize report");
    match ureq::post(&endpoint)
        .set("Content-Type", "application/json")
        .send_string(&body)
    {
        Ok(resp) => {
            println!(
                "pharos-beacon: reported {host} -> {endpoint} (HTTP {})",
                resp.status()
            );
            println!("  {body}");
        }
        Err(e) => {
            eprintln!("pharos-beacon: report to {endpoint} failed: {e}");
            std::process::exit(1);
        }
    }
}
