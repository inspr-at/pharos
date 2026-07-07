//! pharos-beacon — per-host agent (PHAROS-6 / PHAROS-15).
//!
//! Computes this host's Nix freshness (flake.lock age + commits behind nixcfg)
//! and reports it to pharosd. With PHAROS_INTERVAL set it loops as a recurring
//! service; otherwise it reports once and exits. Token auth via Janus is
//! PHAROS-8; the native (musl) Nix-module deployment is PHAROS-6/7.
//!
//! Env: PHAROS_URL (pharosd base, default http://100.64.0.4:8088),
//!      PHAROS_INTERVAL (secs; loop if set), NIXCFG_DIR (flake checkout;
//!      auto-detected otherwise), PHAROS_HOSTNAME / PHAROS_ROLE (overrides),
//!      PHAROS_TOKEN (per-host bearer token from /register).

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

fn freshness_log_summary(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return "nix=n/a".to_string();
    }

    let age = freshness
        .flake_lock_age_days
        .map(|days| format!("{days}d"))
        .unwrap_or_else(|| "unknown".to_string());
    let behind = freshness
        .commits_behind
        .map(|commits| commits.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    format!("flake_lock_age={age}; commits_behind={behind}")
}

fn success_log_line(host: &str, endpoint: &str, status: u16, freshness: &NixFreshness) -> String {
    format!(
        "pharos-beacon: reported {host} -> {endpoint} (HTTP {status}; {})",
        freshness_log_summary(freshness)
    )
}

fn main() {
    let base = std::env::var("PHAROS_URL").unwrap_or_else(|_| "http://100.64.0.4:8088".into());
    let endpoint = format!("{}/report", base.trim_end_matches('/'));
    let host = hostname();
    let is_nix = Path::new("/etc/NIXOS").exists();
    let dir = nixcfg_dir();
    let role = std::env::var("PHAROS_ROLE").unwrap_or_else(|_| "server".into());
    let token = std::env::var("PHAROS_TOKEN")
        .ok()
        .filter(|s| !s.trim().is_empty());

    // PHAROS_INTERVAL (secs) set => loop forever (recurring service);
    // unset => report once and exit (one-shot / timer-driven).
    let interval = std::env::var("PHAROS_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0);
    let beat = interval.unwrap_or(60);

    loop {
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
            role: role.clone(),
            is_nix,
            heartbeat_interval_secs: beat,
            freshness,
        };
        let body = serde_json::to_string(&report).expect("serialize report");
        let mut request = ureq::post(&endpoint).set("Content-Type", "application/json");
        if let Some(token) = &token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        match request.send_string(&body) {
            Ok(resp) => println!(
                "{}",
                success_log_line(&host, &endpoint, resp.status(), &report.freshness)
            ),
            Err(e) => {
                eprintln!("pharos-beacon: report to {endpoint} failed: {e}");
                if interval.is_none() {
                    std::process::exit(1);
                }
            }
        }
        match interval {
            Some(s) => std::thread::sleep(std::time::Duration::from_secs(s)),
            None => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_log_line_keeps_operational_context_without_report_body() {
        let line = success_log_line(
            "hsb8",
            "http://pharos.example/report",
            204,
            &NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(1),
                commits_behind: Some(0),
            },
        );

        assert!(line.contains("hsb8"));
        assert!(line.contains("http://pharos.example/report"));
        assert!(line.contains("HTTP 204"));
        assert!(line.contains("flake_lock_age=1d"));
        assert!(line.contains("commits_behind=0"));
        assert!(!line.contains("\"name\""));
        assert!(!line.contains("heartbeat_interval_secs"));
        assert!(!line.contains("freshness"));
    }

    #[test]
    fn success_log_line_handles_non_nix_hosts() {
        let line = success_log_line(
            "hermes",
            "http://pharos.example/report",
            204,
            &NixFreshness::default(),
        );

        assert!(line.contains("nix=n/a"));
        assert!(!line.contains("\"applicable\""));
    }
}
