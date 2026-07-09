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

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use pharos_core::{
    HostLocation, HostLocationSource, HostReport, NixFreshness, ServiceObservation,
    HOST_REPORT_SCHEMA, HOST_REPORT_VERSION, MAX_INBOUND_RTT_MS,
};

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

fn report_rtt_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis())
        .unwrap_or(MAX_INBOUND_RTT_MS)
        .clamp(1, MAX_INBOUND_RTT_MS)
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

fn bearer_token() -> Option<String> {
    std::env::var("PHAROS_TOKEN")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            let path = std::env::var("PHAROS_TOKEN_FILE")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())?;
            std::fs::read_to_string(path)
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocationMode {
    Off,
    Env,
    IpApi,
    Command,
}

impl LocationMode {
    fn from_env_value(value: Option<String>) -> Self {
        match value
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("env") => Self::Env,
            Some("ip") | Some("ip-api") | Some("ipapi") | Some("geoip") => Self::IpApi,
            Some("command") | Some("cmd") | Some("provider-command") => Self::Command,
            _ => Self::Off,
        }
    }
}

const LOCATION_COMMAND_TIMEOUT_MS: u64 = 2_000;

fn env_value(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn parse_f64(value: Option<String>) -> Option<f64> {
    value
        .and_then(|value| value.parse::<f64>().ok())
        .filter(|value| value.is_finite())
}

fn parse_location_source(value: Option<String>, default: HostLocationSource) -> HostLocationSource {
    match value
        .as_deref()
        .map(str::trim)
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("wifi") => HostLocationSource::Wifi,
        Some("ip") => HostLocationSource::Ip,
        Some("provider") => HostLocationSource::Provider,
        Some("unknown") => HostLocationSource::Unknown,
        _ => default,
    }
}

fn parse_u64(value: Option<String>) -> Option<u64> {
    value.and_then(|value| value.parse::<u64>().ok())
}

fn location_command_args_from_raw(raw: &str) -> Option<Vec<String>> {
    serde_json::from_str::<Vec<String>>(raw).ok()
}

fn location_command_args() -> Vec<String> {
    let Some(raw) = env_value("PHAROS_LOCATION_COMMAND_ARGS") else {
        return Vec::new();
    };
    match location_command_args_from_raw(&raw) {
        Some(args) => args,
        None => {
            eprintln!("pharos-beacon: location command args invalid");
            Vec::new()
        }
    }
}

fn location_command_timeout() -> Duration {
    let millis = parse_u64(env_value("PHAROS_LOCATION_COMMAND_TIMEOUT_MS"))
        .filter(|millis| (100..=30_000).contains(millis))
        .unwrap_or(LOCATION_COMMAND_TIMEOUT_MS);
    Duration::from_millis(millis)
}

fn location_from_env(now: i64) -> Option<HostLocation> {
    let location = HostLocation {
        latitude: parse_f64(env_value("PHAROS_LOCATION_LATITUDE"))?,
        longitude: parse_f64(env_value("PHAROS_LOCATION_LONGITUDE"))?,
        source: parse_location_source(
            env_value("PHAROS_LOCATION_SOURCE"),
            HostLocationSource::Unknown,
        ),
        accuracy_meters: parse_f64(env_value("PHAROS_LOCATION_ACCURACY_METERS")),
        precision_meters: parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS"))
            .or(Some(25_000.0)),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: env_value("PHAROS_LOCATION_LABEL"),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn json_f64(value: &serde_json::Value, keys: &[&str]) -> Option<f64> {
    keys.iter()
        .find_map(|key| value.get(*key)?.as_f64())
        .filter(|value| value.is_finite())
}

fn json_optional_f64(value: &serde_json::Value, key: &str) -> Option<f64> {
    value
        .get(key)
        .and_then(|value| value.as_f64())
        .filter(|value| value.is_finite())
}

fn location_from_command_json(raw: &str, now: i64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    let source = parse_location_source(
        value
            .get("source")
            .and_then(|source| source.as_str())
            .map(str::to_string),
        HostLocationSource::Provider,
    );
    let location = HostLocation {
        latitude: json_f64(&value, &["latitude", "lat"])?,
        longitude: json_f64(&value, &["longitude", "lon"])?,
        source,
        accuracy_meters: json_optional_f64(&value, "accuracy_meters"),
        precision_meters: json_optional_f64(&value, "precision_meters").or(Some(25_000.0)),
        observed_at: value
            .get("observed_at")
            .and_then(|observed_at| observed_at.as_i64())
            .or(Some(now)),
        stale: false,
        manual_override: false,
        label: value
            .get("label")
            .and_then(|label| label.as_str())
            .map(str::to_string),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn run_location_command(
    command: &str,
    args: &[String],
    timeout: Duration,
) -> Result<String, &'static str> {
    let mut child = Command::new(command)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| "spawn")?;
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_string(&mut stdout).map_err(|_| "stdout")?;
                }
                return if status.success() {
                    Ok(stdout)
                } else {
                    Err("exit")
                };
            }
            Ok(None) => {
                if started.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err("timeout");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
            Err(_) => return Err("wait"),
        }
    }
}

fn location_from_command(now: i64) -> Option<HostLocation> {
    let Some(command) = env_value("PHAROS_LOCATION_COMMAND") else {
        eprintln!("pharos-beacon: location command not configured");
        return None;
    };
    let raw = match run_location_command(
        &command,
        &location_command_args(),
        location_command_timeout(),
    ) {
        Ok(raw) => raw,
        Err(reason) => {
            eprintln!("pharos-beacon: location command failed: {reason}");
            return None;
        }
    };
    match location_from_command_json(&raw, now) {
        Some(location) => Some(location),
        None => {
            eprintln!("pharos-beacon: location command returned invalid location");
            None
        }
    }
}

fn location_label_from_parts(
    city: Option<&str>,
    region: Option<&str>,
    country: Option<&str>,
) -> Option<String> {
    let mut parts = Vec::new();
    for part in [city, region, country].into_iter().flatten() {
        let part = part.trim();
        if !part.is_empty()
            && !parts
                .iter()
                .any(|existing: &&str| existing.eq_ignore_ascii_case(part))
        {
            parts.push(part);
        }
    }
    if parts.is_empty() {
        None
    } else {
        Some(parts.join(", "))
    }
}

fn location_from_ip_api_json(raw: &str, now: i64, precision_meters: f64) -> Option<HostLocation> {
    let value: serde_json::Value = serde_json::from_str(raw).ok()?;
    if value
        .get("status")
        .and_then(|status| status.as_str())
        .is_some_and(|status| status != "success")
    {
        return None;
    }
    let location = HostLocation {
        latitude: value.get("lat")?.as_f64()?,
        longitude: value.get("lon")?.as_f64()?,
        source: HostLocationSource::Ip,
        accuracy_meters: None,
        precision_meters: Some(precision_meters),
        observed_at: Some(now),
        stale: false,
        manual_override: false,
        label: location_label_from_parts(
            value.get("city").and_then(|v| v.as_str()),
            value.get("regionName").and_then(|v| v.as_str()),
            value.get("countryCode").and_then(|v| v.as_str()),
        ),
    };
    location.validate_contract().ok()?;
    Some(location)
}

fn location_from_ip_api(now: i64) -> Option<HostLocation> {
    let url = env_value("PHAROS_LOCATION_IP_API_URL").unwrap_or_else(|| {
        "http://ip-api.com/json/?fields=status,lat,lon,city,regionName,countryCode".to_string()
    });
    let precision = parse_f64(env_value("PHAROS_LOCATION_PRECISION_METERS")).unwrap_or(50_000.0);
    let response = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(3))
        .call()
        .ok()?;
    let raw = response.into_string().ok()?;
    location_from_ip_api_json(&raw, now, precision)
}

fn collect_location(now: i64) -> Option<HostLocation> {
    match LocationMode::from_env_value(env_value("PHAROS_LOCATION_MODE")) {
        LocationMode::Off => None,
        LocationMode::Env => location_from_env(now),
        LocationMode::IpApi => location_from_ip_api(now),
        LocationMode::Command => location_from_command(now),
    }
}

fn location_log_summary(location: Option<&HostLocation>) -> String {
    let Some(location) = location else {
        return "location=off".to_string();
    };
    let source = match location.source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared
        | HostLocationSource::Fallback
        | HostLocationSource::Unknown => "unknown",
    };
    let accuracy = location
        .accuracy_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    let precision = location
        .precision_meters
        .map(|meters| format!("{meters:.0}m"))
        .unwrap_or_else(|| "unknown".to_string());
    format!("location={source}; accuracy={accuracy}; precision={precision}")
}

fn success_log_line(
    host: &str,
    endpoint: &str,
    status: u16,
    freshness: &NixFreshness,
    location: Option<&HostLocation>,
) -> String {
    format!(
        "pharos-beacon: reported {host} -> {endpoint} (HTTP {status}; {}; {})",
        freshness_log_summary(freshness),
        location_log_summary(location)
    )
}

fn main() {
    let base = std::env::var("PHAROS_URL").unwrap_or_else(|_| "http://100.64.0.4:8088".into());
    let endpoint = format!("{}/report", base.trim_end_matches('/'));
    let host = hostname();
    let is_nix = Path::new("/etc/NIXOS").exists();
    let dir = nixcfg_dir();
    let role = std::env::var("PHAROS_ROLE").unwrap_or_else(|_| "server".into());
    let token = bearer_token();

    // PHAROS_INTERVAL (secs) set => loop forever (recurring service);
    // unset => report once and exit (one-shot / timer-driven).
    let interval = std::env::var("PHAROS_INTERVAL")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|s| *s > 0);
    let beat = interval.unwrap_or(60);
    let mut last_report_rtt_ms: Option<u64> = None;

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
        let service_observations = vec![ServiceObservation::nix_freshness(&freshness)];
        let location = collect_location(now_unix());
        let report = HostReport {
            schema: HOST_REPORT_SCHEMA.to_string(),
            version: HOST_REPORT_VERSION,
            name: host.clone(),
            role: role.clone(),
            is_nix,
            heartbeat_interval_secs: beat,
            freshness,
            service_observations,
            backup_observations: vec![],
            inbound_rtt_ms: last_report_rtt_ms,
            location,
        };
        let body = serde_json::to_string(&report).expect("serialize report");
        let mut request = ureq::post(&endpoint).set("Content-Type", "application/json");
        if let Some(token) = &token {
            request = request.set("Authorization", &format!("Bearer {token}"));
        }
        let started = Instant::now();
        match request.send_string(&body) {
            Ok(resp) => {
                last_report_rtt_ms = Some(report_rtt_millis(started.elapsed()));
                println!(
                    "{}",
                    success_log_line(
                        &host,
                        &endpoint,
                        resp.status(),
                        &report.freshness,
                        report.location.as_ref()
                    )
                );
            }
            Err(e) => {
                last_report_rtt_ms = None;
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
    fn report_rtt_millis_is_protocol_bounded() {
        assert_eq!(report_rtt_millis(Duration::from_nanos(1)), 1);
        assert_eq!(report_rtt_millis(Duration::from_millis(42)), 42);
        assert_eq!(
            report_rtt_millis(Duration::from_millis(MAX_INBOUND_RTT_MS + 1)),
            MAX_INBOUND_RTT_MS
        );
    }

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
            None,
        );

        assert!(line.contains("hsb8"));
        assert!(line.contains("http://pharos.example/report"));
        assert!(line.contains("HTTP 204"));
        assert!(line.contains("flake_lock_age=1d"));
        assert!(line.contains("commits_behind=0"));
        assert!(line.contains("location=off"));
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
            None,
        );

        assert!(line.contains("nix=n/a"));
        assert!(!line.contains("\"applicable\""));
    }

    #[test]
    fn location_mode_is_disabled_by_default_and_explicitly_selected() {
        assert_eq!(LocationMode::from_env_value(None), LocationMode::Off);
        assert_eq!(
            LocationMode::from_env_value(Some(" env ".to_string())),
            LocationMode::Env
        );
        assert_eq!(
            LocationMode::from_env_value(Some("ip-api".to_string())),
            LocationMode::IpApi
        );
        assert_eq!(
            LocationMode::from_env_value(Some("command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("provider-command".to_string())),
            LocationMode::Command
        );
        assert_eq!(
            LocationMode::from_env_value(Some("wifi".to_string())),
            LocationMode::Off
        );
    }

    #[test]
    fn env_location_reports_quality_without_sensitive_log_details() {
        std::env::set_var("PHAROS_LOCATION_LATITUDE", "48.2082");
        std::env::set_var("PHAROS_LOCATION_LONGITUDE", "16.3738");
        std::env::set_var("PHAROS_LOCATION_SOURCE", "wifi");
        std::env::set_var("PHAROS_LOCATION_ACCURACY_METERS", "1200");
        std::env::set_var("PHAROS_LOCATION_PRECISION_METERS", "2500");
        std::env::set_var("PHAROS_LOCATION_LABEL", "Vienna area");

        let location = location_from_env(1_700_000_000).expect("env location");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(1200.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(summary.contains("location=wifi"));
        assert!(summary.contains("accuracy=1200m"));
        assert!(summary.contains("precision=2500m"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));

        for key in [
            "PHAROS_LOCATION_LATITUDE",
            "PHAROS_LOCATION_LONGITUDE",
            "PHAROS_LOCATION_SOURCE",
            "PHAROS_LOCATION_ACCURACY_METERS",
            "PHAROS_LOCATION_PRECISION_METERS",
            "PHAROS_LOCATION_LABEL",
        ] {
            std::env::remove_var(key);
        }
    }

    #[test]
    fn ip_api_location_uses_coarse_precision_and_not_raw_ip() {
        let raw = r#"{
            "status":"success",
            "lat":52.52,
            "lon":13.405,
            "city":"Berlin",
            "regionName":"Berlin",
            "countryCode":"DE",
            "query":"203.0.113.10"
        }"#;

        let location =
            location_from_ip_api_json(raw, 1_700_000_000, 50_000.0).expect("ip api location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Ip);
        assert_eq!(location.accuracy_meters, None);
        assert_eq!(location.precision_meters, Some(50_000.0));
        assert_eq!(location.label.as_deref(), Some("Berlin, DE"));
        assert!(!body.contains("203.0.113.10"));
        assert!(summary.contains("location=ip"));
        assert!(summary.contains("precision=50000m"));
        assert!(!summary.contains("52.52"));
        assert!(!summary.contains("13.405"));
    }

    #[test]
    fn command_location_parses_sanitized_payload_only() {
        let raw = r#"{
            "latitude": 48.2082,
            "longitude": 16.3738,
            "source": "wifi",
            "accuracy_meters": 900,
            "precision_meters": 2500,
            "observed_at": 1700000000,
            "label": "Vienna area",
            "bssid": "aa:bb:cc:dd:ee:ff",
            "ssid": "private-network"
        }"#;

        let location = location_from_command_json(raw, 1_700_000_100).expect("command location");
        let body = serde_json::to_string(&location).expect("location serializes");
        let summary = location_log_summary(Some(&location));

        assert_eq!(location.source, HostLocationSource::Wifi);
        assert_eq!(location.accuracy_meters, Some(900.0));
        assert_eq!(location.precision_meters, Some(2500.0));
        assert_eq!(location.observed_at, Some(1_700_000_000));
        assert_eq!(location.label.as_deref(), Some("Vienna area"));
        assert!(!body.contains("aa:bb"));
        assert!(!body.contains("private-network"));
        assert!(summary.contains("location=wifi"));
        assert!(!summary.contains("48.2082"));
        assert!(!summary.contains("16.3738"));
        assert!(!summary.contains("Vienna"));
    }

    #[test]
    fn command_location_rejects_malformed_or_invalid_payload() {
        assert!(location_from_command_json("not json", 1_700_000_000).is_none());
        assert!(
            location_from_command_json(r#"{"latitude":99,"longitude":16}"#, 1_700_000_000)
                .is_none()
        );
        assert!(location_from_command_json(
            r#"{"latitude":48.2,"longitude":"bad"}"#,
            1_700_000_000
        )
        .is_none());
    }

    #[test]
    fn command_location_args_are_json_array_only() {
        assert_eq!(
            location_command_args_from_raw(r#"["--format","json"]"#),
            Some(vec!["--format".to_string(), "json".to_string()])
        );
        assert!(location_command_args_from_raw("--format json").is_none());
    }

    #[test]
    fn command_runner_reports_failure_without_leaking_output() {
        let args = vec![
            "-c".to_string(),
            "printf 'BSSID=aa:bb:cc:dd:ee:ff'; exit 7".to_string(),
        ];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_secs(1)).expect_err("fails");
        assert_eq!(error, "exit");
        assert!(!error.contains("aa:bb"));
        assert!(!error.contains("BSSID"));
    }

    #[test]
    fn command_runner_times_out() {
        let args = vec!["-c".to_string(), "sleep 1".to_string()];
        let error =
            run_location_command("/bin/sh", &args, Duration::from_millis(10)).expect_err("timeout");
        assert_eq!(error, "timeout");
    }

    #[test]
    fn bearer_token_prefers_env_over_file_and_trims() {
        let temp = std::env::temp_dir().join(format!("pharos-token-test-{}", std::process::id()));
        std::fs::write(&temp, "file-token\n").expect("write token fixture");
        std::env::set_var("PHAROS_TOKEN", " env-token ");
        std::env::set_var("PHAROS_TOKEN_FILE", &temp);

        assert_eq!(bearer_token(), Some("env-token".to_string()));

        std::env::remove_var("PHAROS_TOKEN");
        assert_eq!(bearer_token(), Some("file-token".to_string()));

        std::env::remove_var("PHAROS_TOKEN_FILE");
        let _ = std::fs::remove_file(temp);
    }
}
