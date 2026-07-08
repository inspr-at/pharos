//! pharosd — the Pharos server.
//!
//! Routes: `/healthz`, `/version`, `POST /register` (token issuance, PHAROS-8),
//! `POST /report` (beacon ingestion, PHAROS-9), `/hosts.json`, and the host
//! dashboard at `/`. Hosts live in a small store (in-memory + optional JSON
//! persistence; sqlx+SQLite is PHAROS-3). The
//! dashboard is a static server render previewing the design (rounded cards,
//! accessible SVG status, the self-host lighthouse); the interactive Leptos UI
//! is PHAROS-10.

mod agora;
mod auth;
mod icons;
mod manifests;
mod store;

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse};
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::{
    liveness, Host, HostLocation, HostLocationSource, HostManifest, HostRegistration,
    HostRegistrationResponse, HostReport, Liveness, ManifestLocationMode, ManifestProbePolicy,
    ManifestService, ManifestStatusSource, NixFreshness, ServiceObservation,
    ServiceObservationState, HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::net::TcpStream;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration, MissedTickBehavior};
use url::Url;

use crate::auth::{Auth, AuthState};
use crate::manifests::{ManifestLoadIssue, ManifestRegistry};
use crate::store::Store;

const SERVER_PROBE_TIMEOUT: Duration = Duration::from_millis(1200);
const ALERT_CHECK_INTERVAL: Duration = Duration::from_secs(60);
const ALERT_WEBHOOK_TIMEOUT: Duration = Duration::from_secs(5);

/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    manifests: Arc<ManifestRegistry>,
    auth: AuthState,
    beacon_auth: BeaconAuth,
}

impl FromRef<AppState> for Arc<Store> {
    fn from_ref(s: &AppState) -> Self {
        s.store.clone()
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

impl FromRef<AppState> for Arc<ManifestRegistry> {
    fn from_ref(s: &AppState) -> Self {
        s.manifests.clone()
    }
}

#[derive(Clone)]
struct BeaconAuth {
    registration_token: Option<String>,
    require_report_token: bool,
    report_token_mode: BeaconTokenMode,
    janus_token_hash_sources: Vec<JanusTokenHashSource>,
    local_register_enabled: bool,
}

impl BeaconAuth {
    fn from_env() -> Self {
        let registration_token = env_nonempty("PHAROS_REGISTRATION_TOKEN");
        let janus_token_hash_sources = janus_token_hash_sources_from_env();
        let report_token_mode = env_nonempty("PHAROS_BEACON_TOKEN_MODE")
            .and_then(|s| parse_beacon_token_mode(&s))
            .unwrap_or({
                if !janus_token_hash_sources.is_empty() {
                    BeaconTokenMode::Dual
                } else {
                    BeaconTokenMode::Local
                }
            });
        let require_report_token = std::env::var("PHAROS_REQUIRE_BEACON_TOKEN")
            .ok()
            .and_then(|s| parse_bool(&s))
            .unwrap_or(
                registration_token.is_some()
                    || !janus_token_hash_sources.is_empty()
                    || report_token_mode == BeaconTokenMode::Janus,
            );
        let local_register_enabled = std::env::var("PHAROS_ALLOW_LOCAL_REGISTER")
            .ok()
            .and_then(|s| parse_bool(&s))
            .unwrap_or(report_token_mode != BeaconTokenMode::Janus);
        Self {
            registration_token,
            require_report_token,
            report_token_mode,
            janus_token_hash_sources,
            local_register_enabled,
        }
    }

    fn registration_status(&self, headers: &HeaderMap) -> RegistrationAuth {
        if !self.local_register_enabled {
            return RegistrationAuth::Disabled;
        }
        let Some(expected) = &self.registration_token else {
            return RegistrationAuth::NotConfigured;
        };
        match bearer_token(headers) {
            Some(actual) if constant_time_eq(actual, expected) => RegistrationAuth::Allowed,
            _ => RegistrationAuth::Denied,
        }
    }

    fn report_token_status(&self, store: &Store, host: &str, token: &str) -> ReportTokenAuth {
        let expected_hash = token_hash(token);
        match self.report_token_mode {
            BeaconTokenMode::Local => {
                if local_token_matches(store, host, &expected_hash) {
                    ReportTokenAuth::Allowed
                } else {
                    ReportTokenAuth::Denied
                }
            }
            BeaconTokenMode::Dual => {
                if local_token_matches(store, host, &expected_hash) {
                    return ReportTokenAuth::Allowed;
                }
                match self.janus_token_matches(host, &expected_hash) {
                    Ok(true) => ReportTokenAuth::Allowed,
                    Ok(false) => ReportTokenAuth::Denied,
                    Err(err) => ReportTokenAuth::Unavailable(err),
                }
            }
            BeaconTokenMode::Janus => match self.janus_token_matches(host, &expected_hash) {
                Ok(true) => ReportTokenAuth::Allowed,
                Ok(false) => ReportTokenAuth::Denied,
                Err(err) => ReportTokenAuth::Unavailable(err),
            },
        }
    }

    fn janus_token_matches(
        &self,
        host: &str,
        expected_hash: &str,
    ) -> Result<bool, JanusTokenHashError> {
        let hashes = load_janus_token_hashes(&self.janus_token_hash_sources)?;
        Ok(hashes
            .get(host)
            .is_some_and(|stored| constant_time_eq(stored, expected_hash)))
    }
}

#[derive(Clone)]
enum JanusTokenHashSource {
    File(PathBuf),
    Dir(PathBuf),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BeaconTokenMode {
    Local,
    Dual,
    Janus,
}

enum RegistrationAuth {
    Allowed,
    Denied,
    Disabled,
    NotConfigured,
}

enum ReportTokenAuth {
    Allowed,
    Denied,
    Unavailable(JanusTokenHashError),
}

#[derive(Clone)]
struct AlertNotifier {
    webhook_url: Option<String>,
    client: reqwest::Client,
    notified_down_hosts: Arc<Mutex<BTreeSet<String>>>,
    check_interval: Duration,
}

impl AlertNotifier {
    fn from_env() -> Self {
        let webhook_url = alert_webhook_url(
            std::env::var("PHAROS_ALERT_WEBHOOK_URL").ok(),
            std::env::var("WATCHTOWER_NOTIFICATION_URL").ok(),
            std::env::var("PHAROS_ALERT_WEBHOOK_ENV_FILE").ok(),
        );
        let check_interval = std::env::var("PHAROS_ALERT_CHECK_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 5)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_CHECK_INTERVAL);
        let timeout = std::env::var("PHAROS_ALERT_WEBHOOK_TIMEOUT_SECS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .filter(|seconds| *seconds >= 1)
            .map(Duration::from_secs)
            .unwrap_or(ALERT_WEBHOOK_TIMEOUT);
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        Self {
            webhook_url,
            client,
            notified_down_hosts: Arc::new(Mutex::new(BTreeSet::new())),
            check_interval,
        }
    }

    fn enabled(&self) -> bool {
        self.webhook_url.is_some()
    }

    async fn check_store(&self, store: &Store, now: i64) {
        let alerts = silent_beacon_alerts(&store.list(), now);
        let down_hosts = alerts
            .iter()
            .map(|alert| alert.host.clone())
            .collect::<BTreeSet<_>>();
        let candidates = {
            let mut notified = self
                .notified_down_hosts
                .lock()
                .expect("alert notifier mutex poisoned");
            notified.retain(|host| down_hosts.contains(host));
            alerts
                .into_iter()
                .filter(|alert| !notified.contains(&alert.host))
                .collect::<Vec<_>>()
        };

        for alert in candidates {
            if self.send(&alert).await {
                self.notified_down_hosts
                    .lock()
                    .expect("alert notifier mutex poisoned")
                    .insert(alert.host.clone());
            }
        }
    }

    async fn send(&self, alert: &SilentBeaconAlert) -> bool {
        let Some(url) = self.webhook_url.as_deref() else {
            return false;
        };
        let Ok(parsed_url) = Url::parse(url) else {
            tracing::warn!(host = %alert.host, "silent beacon alert target URL is invalid");
            return false;
        };
        match parsed_url.scheme() {
            "http" | "https" => self.send_http_alert(url, alert).await,
            "telegram" => self.send_telegram_alert(&parsed_url, alert).await,
            _ => {
                tracing::warn!(
                    host = %alert.host,
                    scheme = %parsed_url.scheme(),
                    "silent beacon alert target URL scheme is unsupported"
                );
                false
            }
        }
    }

    async fn send_http_alert(&self, url: &str, alert: &SilentBeaconAlert) -> bool {
        match self.client.post(url).json(alert).send().await {
            Ok(response) if response.status().is_success() => {
                tracing::warn!(
                    host = %alert.host,
                    age_seconds = alert.age_seconds,
                    "silent beacon alert notification sent"
                );
                true
            }
            Ok(response) => {
                tracing::warn!(
                    host = %alert.host,
                    status = %response.status(),
                    "silent beacon alert webhook returned non-success"
                );
                false
            }
            Err(_) => {
                tracing::warn!(
                    host = %alert.host,
                    "silent beacon alert webhook request failed"
                );
                false
            }
        }
    }

    async fn send_telegram_alert(&self, url: &Url, alert: &SilentBeaconAlert) -> bool {
        let Some(target) = TelegramAlertTarget::from_url(url) else {
            tracing::warn!(host = %alert.host, "silent beacon Telegram alert target is invalid");
            return false;
        };
        let endpoint = format!("https://api.telegram.org/bot{}/sendMessage", target.token);
        let text = telegram_alert_text(alert);
        let mut sent_all = true;

        for chat_id in target.chats {
            let payload = json!({
                "chat_id": chat_id,
                "text": text,
                "disable_web_page_preview": true,
            });
            match self.client.post(&endpoint).json(&payload).send().await {
                Ok(response) if response.status().is_success() => {
                    tracing::warn!(
                        host = %alert.host,
                        age_seconds = alert.age_seconds,
                        "silent beacon Telegram alert notification sent"
                    );
                }
                Ok(response) => {
                    tracing::warn!(
                        host = %alert.host,
                        status = %response.status(),
                        "silent beacon Telegram alert returned non-success"
                    );
                    sent_all = false;
                }
                Err(_) => {
                    tracing::warn!(
                        host = %alert.host,
                        "silent beacon Telegram alert request failed"
                    );
                    sent_all = false;
                }
            }
        }

        sent_all
    }
}

fn spawn_alert_loop(state: AppState, notifier: AlertNotifier) {
    if !notifier.enabled() {
        tracing::info!("silent beacon alert webhook not configured; notifications disabled");
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(notifier.check_interval);
        interval.set_missed_tick_behavior(MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            notifier.check_store(&state.store, now_unix()).await;
        }
    });
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct SilentBeaconAlert {
    schema: &'static str,
    level: &'static str,
    kind: &'static str,
    host: String,
    role: String,
    last_seen: i64,
    age_seconds: i64,
    heartbeat_interval_secs: u64,
    as_of: i64,
    summary: String,
    next_action: &'static str,
}

#[derive(Debug, PartialEq, Eq)]
struct TelegramAlertTarget {
    token: String,
    chats: Vec<String>,
}

impl TelegramAlertTarget {
    fn from_url(url: &Url) -> Option<Self> {
        if url.scheme() != "telegram" {
            return None;
        }
        let username = url.username();
        if username.is_empty() {
            return None;
        }
        let token = match url.password() {
            Some(password) if !password.is_empty() => format!("{username}:{password}"),
            _ => username.to_string(),
        };
        let chats = url
            .query_pairs()
            .find_map(|(key, value)| {
                if key == "chats" || key == "channels" {
                    Some(
                        value
                            .split(',')
                            .map(str::trim)
                            .filter(|chat| !chat.is_empty())
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    )
                } else {
                    None
                }
            })
            .filter(|chats| !chats.is_empty())?;

        Some(Self { token, chats })
    }
}

fn telegram_alert_text(alert: &SilentBeaconAlert) -> String {
    format!(
        "Pharos critical alert\nHost: {}\nProblem: {}\nAge: {}\nNext: {}",
        alert.host,
        alert.summary,
        duration_label(alert.age_seconds),
        alert.next_action
    )
}

fn silent_beacon_alerts(hosts: &[Host], now: i64) -> Vec<SilentBeaconAlert> {
    let mut alerts = hosts
        .iter()
        .filter_map(|host| {
            let last_seen = host.last_seen?;
            if liveness(host.last_seen, host.heartbeat_interval_secs, now) != Liveness::Down {
                return None;
            }
            let age_seconds = now.saturating_sub(last_seen);
            let interval = host.heartbeat_interval_secs.unwrap_or(60);
            Some(SilentBeaconAlert {
                schema: "inspr.pharos.alert.v1",
                level: "critical",
                kind: "silent_heartbeat",
                host: host.name.clone(),
                role: host.role.clone(),
                last_seen,
                age_seconds,
                heartbeat_interval_secs: interval,
                as_of: now,
                summary: format!(
                    "{} has not reported to Pharos for {}.",
                    host.name,
                    duration_label(age_seconds)
                ),
                next_action: "Check host power, network, and pharos-beacon.",
            })
        })
        .collect::<Vec<_>>();
    alerts.sort_by(|left, right| left.host.cmp(&right.host));
    alerts
}

fn non_empty_env_value(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn alert_webhook_url(
    pharos_url: Option<String>,
    watchtower_url: Option<String>,
    env_file: Option<String>,
) -> Option<String> {
    pharos_url
        .as_deref()
        .and_then(non_empty_env_value)
        .or_else(|| watchtower_url.as_deref().and_then(non_empty_env_value))
        .or_else(|| {
            env_file
                .as_deref()
                .and_then(alert_webhook_url_from_env_file)
        })
}

fn alert_webhook_url_from_env_file(path: &str) -> Option<String> {
    let path = non_empty_env_value(path)?;
    let contents = fs::read_to_string(path).ok()?;
    env_file_value(&contents, "WATCHTOWER_NOTIFICATION_URL")
        .as_deref()
        .and_then(non_empty_env_value)
}

fn env_file_value(contents: &str, key: &str) -> Option<String> {
    contents.lines().find_map(|line| {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return None;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim_start();
        let (name, value) = line.split_once('=')?;
        if name.trim() != key {
            return None;
        }
        Some(unquote_env_value(value.trim()).to_string())
    })
}

fn unquote_env_value(value: &str) -> &str {
    if value.len() < 2 {
        return value;
    }
    let bytes = value.as_bytes();
    let quoted = (bytes[0] == b'"' && bytes[value.len() - 1] == b'"')
        || (bytes[0] == b'\'' && bytes[value.len() - 1] == b'\'');
    if quoted {
        &value[1..value.len() - 1]
    } else {
        value
    }
}

const FLEET_HORIZON_PNG: &[u8] = include_bytes!("../assets/fleet-horizon.png");
const SIDEBAR_LIGHTHOUSE_PNG: &[u8] = include_bytes!("../assets/sidebar-lighthouse.png");
const FAVICON_SVG: &str = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none"><rect width="24" height="24" rx="5" fill="#f7fbfc"/><path d="M10.5 5 12 2.5 13.5 5" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><rect x="10" y="5" width="4" height="3" rx=".5" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/><path d="M10 8 8.6 20M14 8l1.4 12M9.2 13.5h5.6M7 20h10M6 22h12M16.6 6.4l2.4-1M7.4 6.4l-2.4-1" stroke="#d69b31" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>"##;

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--card:#ffffff;--card-soft:rgba(255,255,255,.82);--accent:#1f7fb5;--sea:#159e99;--sun:#d69b31;--live:#25845f;--stale:#b26a00;--down:#bf3a35;--wait:#8997a3;--side:232px}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%);min-height:100vh;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-3;background:radial-gradient(circle at 86% 5%,rgba(214,155,49,.16),transparent 12rem),radial-gradient(circle at 18% 28%,rgba(21,158,153,.08),transparent 18rem),linear-gradient(180deg,rgba(255,255,255,.94),rgba(239,249,250,.82));pointer-events:none}
.app-shell{min-height:100vh;display:grid;grid-template-columns:var(--side) minmax(0,1fr)}
.sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:24px;padding:30px 18px 18px;border-right:1px solid rgba(211,225,233,.78);background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(247,252,253,.82));box-shadow:12px 0 38px rgba(45,75,95,.05);overflow:hidden}
.sidebar:before{content:"";position:absolute;left:-18%;right:-20%;bottom:-10%;height:66%;background:url('/assets/sidebar-lighthouse.png') left bottom/118% auto no-repeat;opacity:.78;pointer-events:none;-webkit-mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%);mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%)}
.side-brand,.side-nav,.side-foot{position:relative;z-index:1}.side-brand{display:flex;align-items:center;gap:13px;padding:0 12px}.side-mark{display:grid;place-items:center;width:36px;height:50px;color:var(--sun)}.side-mark .ico{width:31px;height:31px}.side-logo{font-family:Georgia,"Times New Roman",serif;font-size:22px;letter-spacing:.18em;color:#14304b;text-transform:uppercase}
.side-nav{display:grid;gap:7px}.side-link{display:grid;grid-template-columns:23px minmax(0,1fr) auto;align-items:center;gap:11px;min-height:46px;padding:0 13px;border-radius:7px;color:#294761;text-decoration:none;font-weight:520}.side-link[aria-current="page"]{background:rgba(223,241,249,.76);color:#0f4f80}.side-link .ico{width:18px;height:18px}.side-badge{display:grid;place-items:center;min-width:24px;height:24px;border-radius:999px;background:#ffe7bb;color:#9a5b00;font-size:12px;font-weight:700}
.side-foot{margin-top:auto;display:flex;align-items:center;justify-content:space-between;gap:9px;min-height:48px;padding:7px 8px 7px 11px;border:1px solid rgba(211,225,233,.70);border-radius:999px;background:linear-gradient(180deg,rgba(255,255,255,.78),rgba(247,252,253,.62));box-shadow:0 10px 26px rgba(45,75,95,.12);-webkit-backdrop-filter:blur(10px) saturate(1.08);backdrop-filter:blur(10px) saturate(1.08);color:#294761;font-size:13px}.side-user{min-width:0;display:flex;align-items:center;gap:9px;font-weight:650;text-shadow:0 1px 0 rgba(255,255,255,.76)}.side-user:before{content:"";flex:0 0 auto;width:24px;height:24px;border-radius:50%;border:1px solid rgba(214,155,49,.38);background:radial-gradient(circle,#fff 0 33%,rgba(214,155,49,.18) 36%,transparent 68%)}.side-user span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.side-logout{display:grid;place-items:center;flex:0 0 auto;width:30px;height:30px;border-radius:50%;color:#4c6780;text-decoration:none}.side-logout:hover{background:rgba(223,241,249,.78);color:#0f4f80}.side-logout .ico{width:16px;height:16px}
main{width:min(1280px,100%);margin:0;padding:34px 34px 56px}
.ico{width:16px;height:16px;display:inline-block;vertical-align:middle;flex:0 0 auto}
.top{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:22px;min-height:118px;margin:-10px 0 20px;padding:10px 0 18px;overflow:hidden}
.top-art{position:absolute;inset:0;z-index:0;opacity:.84;pointer-events:none;--edge-fade-x:30%;--edge-fade-y:20%;-webkit-mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade-x),#000 calc(100% - var(--edge-fade-x)),transparent 100%);mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade-x),#000 calc(100% - var(--edge-fade-x)),transparent 100%)}
.top-art:before{content:"";position:absolute;inset:0;background:url('/assets/fleet-horizon.png') center center/100% auto no-repeat;-webkit-mask-image:linear-gradient(to bottom,transparent 0,#000 var(--edge-fade-y),#000 calc(100% - var(--edge-fade-y)),transparent 100%);mask-image:linear-gradient(to bottom,transparent 0,#000 var(--edge-fade-y),#000 calc(100% - var(--edge-fade-y)),transparent 100%)}
.top>:not(.top-art){position:relative;z-index:1}.top-art{z-index:0}.brand{display:flex;align-items:center;gap:12px;margin:0 0 4px}
.brand h1{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:31px;line-height:1.05;font-weight:500;letter-spacing:0;color:#12304b}
.fleet{display:flex;align-items:center;gap:10px;margin:8px 0 0;color:var(--muted);font-size:14px}
.wave{width:44px;height:10px;color:var(--sea);opacity:.78}
.asof{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:22px}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 18px}
.metric{appearance:none;position:relative;min-width:0;display:grid;grid-template-columns:50px minmax(0,1fr);align-items:center;column-gap:12px;text-align:left;background:rgba(255,255,255,.82);border:1px solid rgba(210,226,234,.78);border-radius:8px;padding:14px 16px;box-shadow:0 12px 30px rgba(54,88,108,.06);backdrop-filter:blur(10px);cursor:pointer}
.metric:before{content:"";grid-row:1/3;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--metric-color,var(--wait)) 14%,white);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--metric-color,var(--wait)) 20%,transparent)}
.metric b{display:block;font-family:Georgia,"Times New Roman",serif;font-size:29px;line-height:1;font-weight:500;color:var(--ink)}
.metric span{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.metric.live{--metric-color:var(--sea)}.metric.stale{--metric-color:var(--sun)}.metric.down{--metric-color:var(--down)}
.metric.live{border-color:rgba(37,132,95,.22)}.metric.stale{border-color:rgba(178,106,0,.24)}.metric.down{border-color:rgba(191,58,53,.24)}
.metric:hover,.metric[aria-pressed="true"]{border-color:color-mix(in srgb,var(--metric-color,var(--accent)) 38%,rgba(210,226,234,.78));box-shadow:0 14px 32px rgba(54,88,108,.08),0 0 0 3px color-mix(in srgb,var(--metric-color,var(--accent)) 9%,transparent);transform:translateY(-1px)}
.metric:focus-visible{outline:2px solid color-mix(in srgb,var(--metric-color,var(--accent)) 38%,transparent);outline-offset:3px}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 18px;padding:9px;background:rgba(255,255,255,.72);border:1px solid rgba(210,226,234,.78);border-radius:8px;box-shadow:0 12px 30px rgba(54,88,108,.05);backdrop-filter:blur(10px)}
.toolbar-left,.toolbar-right{display:flex;align-items:center;gap:10px;min-width:0}
.seg{display:inline-flex;align-items:center;padding:3px;border:1px solid rgba(210,226,234,.86);border-radius:7px;background:rgba(244,250,251,.76)}
.seg button{appearance:none;border:0;background:transparent;color:var(--muted);display:grid;place-items:center;width:30px;height:28px;border-radius:6px;cursor:pointer}
.seg button[aria-pressed="true"]{background:#fff;color:var(--accent);box-shadow:0 1px 5px rgba(45,75,95,.12)}
.seg .ico{width:16px;height:16px}
.arrange{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;white-space:nowrap}
.arrange select{appearance:none;border:0;background:transparent;color:var(--ink);font:inherit;font-weight:600;outline:none;padding-right:2px;cursor:pointer}
.search{position:relative;min-width:210px;color:var(--muted)}
.search .ico{position:absolute;left:10px;top:50%;width:15px;height:15px;transform:translateY(-50%)}
.search input{width:100%;height:34px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:13px;padding:0 10px 0 32px;outline:none}
.search input:focus{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:18px}
.card{--state:var(--wait);position:relative;min-height:264px;display:flex;flex-direction:column;background:rgba(255,255,255,.88);border:1px solid rgba(211,225,233,.86);border-radius:8px;padding:15px 16px 14px;box-shadow:0 14px 32px rgba(45,75,95,.08);overflow:hidden}
.card:before{content:"";position:absolute;left:16px;right:16px;top:58px;height:1px;background:linear-gradient(90deg,transparent,rgba(31,127,181,.16),transparent);pointer-events:none}
[data-live="live"]{--state:var(--live)}[data-live="stale"]{--state:var(--stale)}[data-live="down"]{--state:var(--down)}[data-live="awaiting_first_heartbeat"]{--state:var(--wait)}
.card.light{border-color:rgba(214,155,49,.28);box-shadow:0 14px 32px rgba(45,75,95,.08),inset 0 0 0 1px rgba(214,155,49,.08)}
.pharos-mark{position:absolute;right:10px;top:7px;z-index:0;display:grid;place-items:center;width:58px;height:58px;color:rgba(214,155,49,.14);pointer-events:none}
.pharos-mark .ico{width:50px;height:50px;stroke-width:1.35}
.card-head{position:relative;z-index:1;display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:12px}
.card-actions{position:relative;z-index:2;display:flex;align-items:center;gap:5px;flex:0 0 auto}
.host{display:flex;align-items:center;gap:9px;min-width:0}
.nix{display:grid;place-items:center;width:30px;height:30px;border:1px solid rgba(102,121,139,.18);border-radius:50%;color:var(--accent);background:rgba(241,248,250,.72);transition:border-color .2s ease,box-shadow .2s ease}
.card.has-settings .nix,.list tr.has-settings .nix{border-width:2px;border-color:var(--host-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--host-color) 13%,transparent),0 0 17px color-mix(in srgb,var(--host-color) 18%,transparent);background:linear-gradient(180deg,rgba(255,255,255,.92),color-mix(in srgb,var(--host-color) 8%,#f5fbfc))}
.name{font-weight:650;font-size:16px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.role{font-size:12px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.signal{--signal-color:var(--wait);display:inline-flex;align-items:center;justify-content:center;gap:6px;min-width:52px;min-height:24px;color:var(--signal-color);font-size:13px;font-weight:720;white-space:nowrap;text-align:center}
.signal[data-signal-level="good"]{--signal-color:var(--live)}.signal[data-signal-level="warn"]{--signal-color:var(--stale)}.signal[data-signal-level="down"]{--signal-color:var(--down)}.signal[data-signal-level="wait"]{--signal-color:var(--wait)}
.signal-window{appearance:none;border:0;background:transparent;color:var(--muted);font:inherit;font-size:11px;font-weight:700;padding:0 1px;cursor:pointer}
.signal-window:hover{color:var(--ink);text-decoration:underline;text-underline-offset:2px}.signal-window:focus-visible{outline:2px solid color-mix(in srgb,var(--signal-color) 34%,transparent);outline-offset:2px;border-radius:4px}
.signal-orb{width:12px;height:12px;border-radius:50%;background:radial-gradient(circle,#fff 0 28%,var(--signal-color) 33% 63%,transparent 66%);box-shadow:0 0 0 4px color-mix(in srgb,var(--signal-color) 12%,transparent),0 0 12px color-mix(in srgb,var(--signal-color) 18%,transparent);opacity:.92}
.status-pill{display:inline-flex;align-items:center;gap:6px;min-height:25px;max-width:150px;flex-shrink:0;padding:4px 9px;border-radius:999px;border:1px solid color-mix(in srgb,var(--state) 24%,transparent);background:color-mix(in srgb,var(--state) 10%,white);color:var(--state);font-size:12px;white-space:nowrap}
.status-pill .ico{width:14px;height:14px}.word{color:inherit;overflow:hidden;text-overflow:ellipsis}
.state-icon{display:none}[data-live="live"] .state-icon.live,[data-live="stale"] .state-icon.stale,[data-live="down"] .state-icon.down,[data-live="awaiting_first_heartbeat"] .state-icon.awaiting{display:inline-block}
.reason{--reason-color:var(--muted);display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;gap:8px;min-height:22px;margin:-2px 0 10px;color:var(--muted);font-size:12px;line-height:1.25}
.reason:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--reason-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--reason-color) 12%,transparent)}
.reason.ok{--reason-color:var(--live)}.reason.warn{--reason-color:var(--stale)}.reason.down{--reason-color:var(--down)}.reason.wait{--reason-color:var(--wait)}.reason.self{--reason-color:var(--sun)}
.reason span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fresh{min-height:52px;margin:4px 0 11px;font-size:13px;line-height:1.45;color:var(--ink)}
.fresh-row{display:grid;grid-template-columns:1fr auto;align-items:center;gap:10px;min-height:23px;border-bottom:1px solid rgba(214,226,234,.58)}
.fresh-row:last-child{border-bottom:0}
.fresh-row span{color:var(--muted);font-size:12px}
.fresh-row strong{font-size:12px;font-weight:650;color:var(--ink)}
.fresh-row strong.ok{color:var(--live)}.fresh-row strong.warn{color:var(--stale)}.fresh-row strong.na{color:var(--wait)}
.meta{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:auto;border-top:1px solid rgba(214,226,234,.72);padding-top:10px;font-size:11px;color:var(--muted)}
.meta strong{font-weight:600;color:var(--ink)}
.card-tools{display:flex;align-items:center;justify-content:center;min-height:25px;margin-top:5px}
.drag-handle{appearance:none;display:none;place-items:center;width:25px;height:25px;margin:0;border:0;border-radius:50%;background:transparent;color:var(--muted);cursor:grab}
main[data-arrange="freeform"] .drag-handle{display:grid}
.drag-handle:hover,.drag-handle:focus-visible{background:rgba(223,241,249,.78);color:var(--accent);box-shadow:0 7px 16px rgba(45,75,95,.08);outline:0}
.drag-handle:active{cursor:grabbing}
.drag-handle .ico{width:13px;height:13px}
.card[data-dragging="true"]{z-index:20;transform:scale(1.015);box-shadow:0 20px 44px rgba(45,75,95,.18);cursor:grabbing}
.grid[data-freeform-dragging="true"] .card:not([data-dragging]){transition:transform .12s ease,box-shadow .12s ease}
.settings-card{display:inline-grid;place-items:center;width:25px;height:25px;margin:0;border:0;border-radius:50%;background:transparent;color:var(--accent);text-decoration:none;box-shadow:none}
.settings-card:hover{background:rgba(223,241,249,.78);box-shadow:0 7px 16px rgba(45,75,95,.08);transform:translateY(-1px)}
.settings-card.unavailable{--host-color:#aebac3;color:var(--muted);opacity:.72;box-shadow:none}
.settings-card.unavailable:hover{background:rgba(241,247,250,.92);box-shadow:0 7px 16px rgba(45,75,95,.05);opacity:1}
.settings-card.unavailable .settings-icon{color:var(--muted)}
.settings-icon{display:grid;place-items:center;width:25px;height:25px;border:1px solid rgba(210,226,234,.76);border-radius:50%;background:rgba(255,255,255,.58);color:inherit}
.settings-icon .ico{width:13px;height:13px}
.settings-copy,.settings-swatch{display:none}
.beat{--beat-color:var(--state);--now-x:0%;--expect-x:64%;--stale-x:82%;--fill-color:var(--sea);--expect-fill:0deg;--expect-alpha:.55;--target-ring:3px;--late-alpha:.3;margin-top:10px;color:var(--beat-color)}
.beat-stage{position:relative;height:50px;overflow:visible}
.beat-floor{position:absolute;left:0;right:0;top:21px;height:4px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.16) 0 var(--expect-x),rgba(214,155,49,.16) var(--expect-x) var(--stale-x),rgba(191,58,53,.12) var(--stale-x) 100%);box-shadow:inset 0 0 0 1px rgba(137,151,163,.18)}
.beat-fill{position:absolute;left:0;top:22px;width:var(--now-x);height:2px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.18),var(--fill-color));transition:background-color .2s ease}
.beat-now{position:absolute;left:var(--now-x);top:23px;z-index:8;width:13px;height:13px;border-radius:50%;background:radial-gradient(circle,#fff 0 29%,var(--fill-color) 32% 62%,transparent 64%);box-shadow:0 0 0 5px color-mix(in srgb,var(--fill-color) 12%,transparent),0 0 14px color-mix(in srgb,var(--fill-color) 26%,transparent);transform:translate(-50%,-50%);pointer-events:none}
.beat-current{position:absolute;top:22px;left:calc(var(--now-x) - 22%);width:22%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--fill-color) 34%,transparent),transparent);animation:tide 2.8s linear infinite;opacity:.8}
.beat-marks{position:absolute;inset:0}
.beat-mark{--mark-color:var(--sea);position:absolute;left:var(--mark-x);top:23px;z-index:4;width:6px;height:6px;border-radius:50%;background:var(--mark-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--mark-color) 10%,transparent);opacity:.82;transform:translate(-50%,-50%);cursor:help}
.beat-mark[data-history-level="late"]{--mark-color:var(--sun)}.beat-mark[data-history-level="stale"]{--mark-color:var(--stale)}.beat-mark[data-history-level="down"]{--mark-color:var(--down)}.beat-mark[data-history-level="first"]{--mark-color:var(--wait)}
.beat-mark:hover,.beat-mark:focus-visible{opacity:1;box-shadow:0 0 0 5px color-mix(in srgb,var(--mark-color) 18%,transparent),0 0 14px color-mix(in srgb,var(--mark-color) 24%,transparent);outline:0}
.beat[data-count="0"] .beat-mark{display:none}
.beat-threshold{position:absolute;top:15px;bottom:15px;width:1px;background:rgba(137,151,163,.25)}
.beat-threshold.expected{left:var(--expect-x)}.beat-threshold.stale{left:var(--stale-x)}
.beat-hit{position:absolute;left:var(--hit-x,0%);top:23px;z-index:9;width:9px;height:9px;border-radius:50%;background:currentColor;opacity:0;transform:translate(-50%,-50%) scale(.7);pointer-events:none}
.beat[data-flash="true"] .beat-hit{animation:beat-hit .9s ease-out}
.beat-zones{position:absolute;left:0;right:0;bottom:0;color:var(--muted);font-size:10px}
.beat-zones span{position:absolute;bottom:0;white-space:nowrap}.beat-zones span:first-child{left:0}.beat-zones span:nth-child(2){left:var(--expect-x);transform:translateX(-50%)}.beat-zones span:nth-child(3){right:0;color:var(--stale)}
.beat[data-beat="late"]{--beat-color:var(--stale)}.beat[data-beat="stale"]{--beat-color:var(--stale)}.beat[data-beat="down"]{--beat-color:var(--down)}.beat[data-beat="waiting"]{--beat-color:var(--wait)}.beat[data-beat="lit"]{--beat-color:var(--sun)}
@keyframes beat-hit{0%{opacity:.9;transform:translate(-50%,-50%) scale(.55);box-shadow:0 0 0 0 color-mix(in srgb,currentColor 28%,transparent)}100%{opacity:0;transform:translate(-50%,-50%) scale(2.4);box-shadow:0 0 0 12px transparent}}
@keyframes tide{from{transform:translateX(-16%)}to{transform:translateX(42%)}}
.list-wrap{display:none}
main[data-view="list"] .grid{display:none}
main[data-view="list"] .list-wrap{display:block}
.list{width:100%;border-collapse:separate;border-spacing:0 8px}
.list th{padding:0 12px 6px;text-align:left;color:var(--muted);font-size:11px;font-weight:600}
.list td{padding:12px;background:rgba(255,255,255,.88);border-top:1px solid rgba(211,225,233,.86);border-bottom:1px solid rgba(211,225,233,.86);vertical-align:middle}
.list td:first-child{border-left:1px solid rgba(211,225,233,.86);border-radius:8px 0 0 8px}
.list td:last-child{border-right:1px solid rgba(211,225,233,.86);border-radius:0 8px 8px 0}
.list tr.light td{border-color:rgba(214,155,49,.34)}
.list .host{min-width:210px}.list .reason{min-width:150px;margin:0}.list .fresh{min-height:0;margin:0;white-space:nowrap}.list .fresh-row{min-height:20px}.list .status-pill{max-width:120px}.list .beat{width:230px;margin:0}.list .card-tools{margin:0}.list .settings-card{margin:0}.list .settings-icon{width:25px;height:25px}
.ops-main{width:min(1280px,100%)}
.ops-summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 18px}
.ops-metric{--metric-color:var(--wait);appearance:none;width:100%;display:grid;grid-template-columns:50px minmax(0,1fr);align-items:center;column-gap:12px;min-height:78px;padding:14px 16px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.82);box-shadow:0 12px 30px rgba(54,88,108,.06);-webkit-backdrop-filter:blur(10px);backdrop-filter:blur(10px);text-align:left;cursor:pointer}
.ops-metric:before{content:"";grid-row:1/3;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--metric-color) 14%,white);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--metric-color) 20%,transparent)}
.ops-metric b{display:block;font-family:Georgia,"Times New Roman",serif;font-size:28px;line-height:1;font-weight:500;color:var(--ink)}
.ops-metric span{display:block;color:var(--muted);font-size:12px;margin-top:2px}
.ops-metric:hover,.ops-metric:focus-visible{border-color:color-mix(in srgb,var(--metric-color) 38%,rgba(210,226,234,.86));box-shadow:0 16px 34px rgba(54,88,108,.09),0 0 0 3px color-mix(in srgb,var(--metric-color) 9%,transparent);outline:0}
.ops-metric[aria-pressed="true"]{border-color:color-mix(in srgb,var(--metric-color) 46%,rgba(210,226,234,.86));background:linear-gradient(135deg,rgba(255,255,255,.94),color-mix(in srgb,var(--metric-color) 8%,white));box-shadow:0 16px 34px rgba(54,88,108,.10),0 0 0 3px color-mix(in srgb,var(--metric-color) 12%,transparent)}
.ops-metric.critical{--metric-color:var(--down);border-color:rgba(191,58,53,.24)}.ops-metric.warning{--metric-color:var(--stale);border-color:rgba(178,106,0,.24)}.ops-metric.watch{--metric-color:var(--sun);border-color:rgba(214,155,49,.24)}.ops-metric.clear,.ops-metric.info,.ops-metric.recovery{--metric-color:var(--live);border-color:rgba(37,132,95,.22)}
.ops-toolbar{margin-bottom:18px}
.ops-layout{display:grid;grid-template-columns:minmax(0,1fr) 300px;gap:18px;align-items:start}
.ops-panel,.ops-side-panel{border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 16px 38px rgba(54,88,108,.08);overflow:hidden}
.ops-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:17px 18px;border-bottom:1px solid rgba(214,226,234,.72);background:rgba(251,253,254,.74)}
.ops-panel-head h2,.ops-side-panel h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;letter-spacing:0;color:#12304b}
.ops-panel-head p,.ops-side-panel p{margin:3px 0 0;color:var(--muted);font-size:12px}
.ops-count{display:inline-flex;align-items:center;justify-content:center;min-width:30px;height:27px;border-radius:999px;background:rgba(223,241,249,.78);color:#0f4f80;font-size:12px;font-weight:760}
.alert-list,.activity-list{display:grid}
.alert-row,.activity-row{--row-color:var(--wait);position:relative;display:grid;gap:12px;align-items:center;min-width:0;border-bottom:1px solid rgba(214,226,234,.66);background:rgba(255,255,255,.72);color:var(--ink)}
.alert-row:last-child,.activity-row:last-child{border-bottom:0}
.alert-row{grid-template-columns:minmax(116px,.58fr) auto minmax(180px,1.25fr) minmax(66px,.36fr) minmax(74px,.42fr) minmax(124px,.7fr);gap:10px;padding:13px 16px}
.activity-row{grid-template-columns:86px minmax(110px,.55fr) 92px minmax(260px,1.5fr) 94px;align-items:start;padding:14px 16px}
.alert-row.critical,.activity-row.critical{--row-color:var(--down)}.alert-row.warning,.activity-row.warning{--row-color:var(--stale)}.alert-row.watch,.activity-row.watch{--row-color:var(--sun)}.alert-row.clear,.activity-row.clear,.activity-row.recovery{--row-color:var(--live)}.activity-row.info{--row-color:var(--accent)}
.alert-host,.activity-host{display:flex;align-items:center;gap:9px;min-width:0}
.alert-dot,.activity-dot{flex:0 0 auto;width:9px;height:9px;border-radius:50%;background:var(--row-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--row-color) 12%,transparent)}
.alert-host strong,.activity-host strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:13px}
.alert-host span:last-child,.activity-host span:last-child{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--muted);font-size:11px}
.alert-status{display:flex;flex-wrap:wrap;align-items:center;gap:6px;min-width:0}
.alert-repeat{display:inline-flex;align-items:center;min-height:23px;padding:3px 8px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font-size:11px;font-weight:720}
.severity{display:inline-flex;align-items:center;justify-content:center;width:max-content;min-height:25px;padding:4px 9px;border:1px solid color-mix(in srgb,var(--row-color) 25%,transparent);border-radius:999px;background:color-mix(in srgb,var(--row-color) 9%,white);color:var(--row-color);font-size:11px;font-weight:760;text-transform:lowercase}
.alert-issue strong,.activity-copy strong{display:block;color:var(--ink);font-size:13px}
.alert-issue p,.activity-copy p{margin:2px 0 0;color:var(--muted);font-size:12px;line-height:1.35}
.ops-source,.ops-time{color:var(--muted);font-size:12px}.ops-time{white-space:nowrap}
.next-action{min-width:0;color:#0f4f80;font-size:12px;font-weight:720;line-height:1.35;overflow-wrap:anywhere}
.ops-side-panel{display:grid;gap:14px;padding:16px}
.posture-ring{--posture-color:var(--live);appearance:none;position:relative;display:grid;place-items:center;width:126px;height:126px;margin:2px auto 4px;border:0;border-radius:50%;background:conic-gradient(var(--posture-color) var(--posture-fill),rgba(214,226,234,.72) 0);box-shadow:0 0 0 10px color-mix(in srgb,var(--posture-color) 8%,transparent);cursor:pointer;text-align:center}
.posture-ring:before{content:"";position:absolute;inset:18px;border-radius:50%;background:#fff;box-shadow:inset 0 0 0 1px rgba(210,226,234,.72)}
.posture-ring:hover,.posture-ring:focus-visible{box-shadow:0 0 0 10px color-mix(in srgb,var(--posture-color) 11%,transparent),0 12px 28px rgba(45,75,95,.10);outline:0}
.posture-ring strong{position:relative;font-family:Georgia,"Times New Roman",serif;font-size:27px;font-weight:500;color:var(--ink)}
.posture-ring span{position:relative;color:var(--muted);font-size:11px}
.posture-list,.activity-filters{display:flex;flex-wrap:wrap;gap:7px}
.posture-chip,.activity-filter{appearance:none;display:inline-flex;align-items:center;gap:6px;min-height:28px;padding:5px 9px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:#fff;color:var(--muted);font:inherit;font-size:12px;font-weight:650;cursor:pointer}
.posture-chip:before,.activity-filter:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--chip-color,var(--wait));box-shadow:0 0 0 3px color-mix(in srgb,var(--chip-color,var(--wait)) 10%,transparent)}
.posture-chip.critical,.activity-filter.critical{--chip-color:var(--down)}.posture-chip.warning,.activity-filter.warning{--chip-color:var(--stale)}.posture-chip.watch,.activity-filter.watch{--chip-color:var(--sun)}.posture-chip.clear,.activity-filter.clear,.activity-filter.recovery{--chip-color:var(--live)}.posture-chip.info,.activity-filter.info{--chip-color:var(--accent)}
.posture-chip:hover,.posture-chip:focus-visible,.activity-filter:hover,.activity-filter:focus-visible{border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.58);outline:0}
.posture-chip[aria-pressed="true"],.activity-filter[aria-pressed="true"]{color:#0f4f80;border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.76)}
.ops-action{display:inline-flex;align-items:center;justify-content:center;min-height:36px;padding:8px 12px;border:1px solid rgba(103,177,196,.42);border-radius:7px;background:rgba(223,241,249,.72);color:#0f4f80;text-decoration:none;font-size:12px;font-weight:760;box-shadow:0 8px 20px rgba(45,75,95,.07)}
.ops-action:hover,.ops-action:focus-visible{background:rgba(207,235,244,.92);box-shadow:0 10px 24px rgba(45,75,95,.10);outline:0}
.ops-empty{padding:34px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(239,249,250,.78));box-shadow:0 16px 38px rgba(54,88,108,.08)}
.ops-empty h2{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:25px;font-weight:500}.ops-empty p{margin:0;color:var(--muted)}
.ops-note{padding:11px 13px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(247,252,253,.78);color:var(--muted);font-size:12px}
.ops-filter-empty{display:none;margin:0;padding:22px;border-top:1px solid rgba(214,226,234,.66);color:var(--muted);font-size:13px;background:rgba(255,255,255,.64)}
.ops-filter-empty[data-visible="true"]{display:block}
[hidden]{display:none!important}
.empty-state,.lone-state{position:relative;overflow:hidden;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(239,249,250,.78));box-shadow:0 16px 38px rgba(54,88,108,.08)}
.empty-state{min-height:430px;margin-top:18px;padding:36px;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(240px,.95fr);align-items:center;gap:30px}
.empty-state:before,.lone-state:before{content:"";position:absolute;inset:auto -8% -30% -8%;height:50%;background:repeating-linear-gradient(178deg,rgba(31,127,181,.12) 0 1px,transparent 1px 28px);opacity:.72;pointer-events:none}
.empty-copy{position:relative;max-width:440px}
.empty-kicker,.lone-kicker{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--sun);font-weight:700}
.empty-copy h2{margin:8px 0 9px;font-size:30px;line-height:1.12;letter-spacing:0}
.empty-copy p,.lone-copy p{margin:0;color:var(--muted);font-size:14px}
.onboard-command{margin-top:18px;display:inline-flex;align-items:center;gap:9px;max-width:100%;padding:10px 12px;border:1px solid rgba(210,226,234,.95);border-radius:7px;background:#fff;color:var(--ink);box-shadow:0 8px 20px rgba(45,75,95,.06);font:13px/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:normal;word-break:break-word}
.onboard-command .ico{color:var(--sea)}
.empty-visual{position:relative;min-height:285px;display:grid;place-items:center;color:var(--sun)}
.empty-sun{position:absolute;right:14%;top:8%;width:66px;height:66px;border-radius:50%;background:radial-gradient(circle,#fff 0 34%,rgba(214,155,49,.26) 36% 58%,transparent 60%);box-shadow:0 0 0 12px rgba(214,155,49,.06),0 0 42px rgba(214,155,49,.20)}
.empty-line{position:absolute;left:7%;right:7%;top:57%;height:2px;border-radius:999px;background:linear-gradient(90deg,transparent,rgba(21,158,153,.42),rgba(214,155,49,.46),transparent)}
.empty-line:after{content:"";position:absolute;left:0;top:50%;width:26%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,var(--sea),transparent);animation:tide 3.2s linear infinite;transform:translateY(-50%)}
.empty-lighthouse{position:relative;display:grid;place-items:center;width:150px;height:150px;border-radius:50%;background:radial-gradient(circle,rgba(214,155,49,.18),rgba(255,255,255,.66) 54%,transparent 70%);color:var(--sun)}
.empty-lighthouse .ico{width:68px;height:68px}
.empty-await{position:absolute;left:50%;bottom:16%;transform:translateX(-50%);font-size:11px;color:var(--muted);white-space:nowrap}
.lone-state{margin-top:14px;padding:17px 18px;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:16px}
.lone-mark{position:relative;display:grid;place-items:center;width:46px;height:46px;border-radius:50%;border:1px solid rgba(214,155,49,.28);background:rgba(255,255,255,.74);color:var(--sun)}
.lone-mark .ico{width:24px;height:24px}
.lone-copy{position:relative;min-width:0}.lone-copy strong{display:block;font-size:15px}.lone-copy p{font-size:12px}
.lone-state .onboard-command{position:relative;margin:0;font-size:12px}
.map-main{width:min(1380px,100%)}
.map-main[data-map-view="maximized"]{width:100%}
.map-layout{display:grid;grid-template-columns:minmax(0,1fr) 310px;gap:18px;align-items:stretch}
.map-panel,.site-panel{border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.84);box-shadow:0 16px 38px rgba(54,88,108,.08);overflow:hidden}
.map-panel{position:relative;display:flex;min-height:560px}
.fleet-map{flex:1 1 auto;height:100%;min-height:560px;background:linear-gradient(135deg,#f7fbfc,#edf6f7)}
.map-layout[data-mode="maximized"]{grid-template-columns:minmax(0,1fr)}
.map-layout[data-mode="maximized"] .site-panel{display:none}
.map-layout[data-mode="maximized"] .map-panel{height:calc(100vh - 258px);min-height:640px}
.map-panel:fullscreen{width:100vw;height:100vh;min-height:100vh;border:0;border-radius:0;background:#f7fbfc}
.map-panel:fullscreen .fleet-map{min-height:100vh}
.map-panel:-webkit-full-screen{width:100vw;height:100vh;min-height:100vh;border:0;border-radius:0;background:#f7fbfc}
.map-panel:-webkit-full-screen .fleet-map{min-height:100vh}
.map-mode-controls{position:absolute;right:12px;top:12px;z-index:1001;display:flex;align-items:center;gap:4px;padding:4px;border:1px solid rgba(210,226,234,.94);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 12px 28px rgba(45,75,95,.14);-webkit-backdrop-filter:blur(10px) saturate(1.06);backdrop-filter:blur(10px) saturate(1.06)}
.map-mode-control{display:grid;place-items:center;width:34px;height:34px;border:1px solid transparent;border-radius:6px;background:transparent;color:#44637f;cursor:pointer}
.map-mode-control:hover{border-color:rgba(173,205,220,.72);background:rgba(223,241,249,.56);color:#17304a}
.map-mode-control[aria-pressed="true"]{border-color:rgba(103,177,196,.52);background:rgba(223,241,249,.82);color:#187fb9;box-shadow:0 0 0 3px rgba(103,177,196,.10)}
.map-mode-control .ico{width:17px;height:17px}
.map-density-control{margin-left:5px;border-left:1px solid rgba(210,226,234,.86)}
.map-panel:fullscreen .map-mode-controls,.map-panel:-webkit-full-screen .map-mode-controls{right:14px;top:14px}
.map-fallback{display:none;position:absolute;inset:0;place-items:center;padding:28px;text-align:center;color:var(--muted);background:rgba(255,255,255,.82);z-index:2}
.map-fallback strong{display:block;color:var(--ink);font-size:18px}
.map-loading{position:absolute;inset:0;z-index:900;display:grid;place-items:center;padding:26px;pointer-events:none;background:linear-gradient(135deg,rgba(255,255,255,.82),rgba(239,249,250,.54))}
.map-panel[data-loading="false"] .map-loading{display:none;opacity:0;visibility:hidden}
.map-load-card{width:min(420px,calc(100% - 40px));padding:18px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 16px 38px rgba(54,88,108,.12);-webkit-backdrop-filter:blur(10px) saturate(1.06);backdrop-filter:blur(10px) saturate(1.06)}
.map-load-card strong{display:block;margin-bottom:5px;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;color:var(--ink)}
.map-load-card p{margin:0;color:var(--muted);font-size:12px}
.map-load-rail{position:relative;height:6px;margin-top:14px;overflow:hidden;border-radius:999px;background:rgba(214,226,234,.68)}
.map-load-rail:after{content:"";position:absolute;inset:0;width:38%;border-radius:999px;background:linear-gradient(90deg,transparent,rgba(21,158,153,.68),transparent);animation:mapShimmer 1.2s linear infinite}
.fleet-map:before{content:"";position:absolute;inset:0;background:radial-gradient(circle at 22% 42%,rgba(21,158,153,.10),transparent 20%),radial-gradient(circle at 72% 38%,rgba(214,155,49,.10),transparent 18%),linear-gradient(135deg,#f7fbfc,#edf6f7);opacity:0;transition:opacity .18s ease}
.map-panel[data-loading="true"] .fleet-map{position:relative}
.map-panel[data-loading="true"] .fleet-map:before{opacity:1}
.site-loading,.site-error{display:grid;gap:8px;padding:11px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.74)}
.site-skel-line{height:11px;border-radius:999px;background:linear-gradient(90deg,rgba(222,234,240,.58),rgba(247,252,253,.96),rgba(222,234,240,.58));background-size:220% 100%;animation:siteShimmer 1.4s linear infinite}
.site-skel-line.short{width:46%}.site-skel-line.medium{width:68%}.site-skel-line.long{width:86%}
.site-error strong{font-size:13px;color:var(--ink)}.site-error span{color:var(--muted);font-size:12px}
@keyframes mapShimmer{from{transform:translateX(-100%)}to{transform:translateX(265%)}}
@keyframes siteShimmer{from{background-position:120% 0}to{background-position:-120% 0}}
.site-panel{padding:16px;display:flex;flex-direction:column;gap:14px}
.site-panel h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:22px;font-weight:500;letter-spacing:0}
.site-panel p{margin:0;color:var(--muted);font-size:12px}
.site-list{display:grid;gap:9px;overflow:auto;padding-right:2px}
.site-item{display:grid;gap:8px;padding:11px;border:1px solid rgba(210,226,234,.78);border-radius:8px;background:rgba(255,255,255,.74)}
.site-head{display:flex;align-items:center;justify-content:space-between;gap:8px}
.site-head strong{font-size:13px}
.site-count{display:inline-flex;align-items:center;justify-content:center;min-width:24px;height:22px;border-radius:999px;background:rgba(223,241,249,.78);color:#0f4f80;font-size:12px;font-weight:700}
.site-hosts{display:flex;flex-wrap:wrap;gap:6px}
.site-host{--host-state:var(--wait);display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;column-gap:6px;min-height:42px;padding:5px 8px;border:1px solid color-mix(in srgb,var(--host-state) 22%,transparent);border-radius:8px;background:color-mix(in srgb,var(--host-state) 8%,white);color:var(--ink);font-size:12px;text-decoration:none}
.site-host:before{content:"";grid-row:1/4;width:7px;height:7px;border-radius:50%;background:var(--host-state);box-shadow:0 0 0 4px color-mix(in srgb,var(--host-state) 12%,transparent)}
.site-host-name{line-height:1.1;font-weight:650;white-space:nowrap}
.site-host-signals{display:flex;flex-wrap:wrap;gap:5px;margin-top:2px}
.site-host-ping{line-height:1.1;font-size:10px;color:var(--muted);white-space:nowrap}
.site-host-ping[data-probe-level="good"]{color:var(--live)}.site-host-ping[data-probe-level="warn"]{color:var(--stale)}.site-host-ping[data-probe-level="down"]{color:var(--down)}.site-host-ping[data-policy="blocked"]{color:var(--muted)}
.site-host-source{display:inline-flex;align-items:center;gap:4px;margin-left:auto;padding:2px 6px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:rgba(255,255,255,.78);color:#546b80;font-size:10px;line-height:1.1;white-space:nowrap}
.site-host-source:before{content:"";width:5px;height:5px;border-radius:50%;background:#8aa0b2;box-shadow:0 0 0 3px rgba(138,160,178,.10)}
.site-host-source[data-location-source="declared"]:before{background:#2d87bf}.site-host-source[data-location-source="wifi"]:before,.site-host-source[data-location-source="ip"]:before{background:var(--live)}.site-host-source[data-location-source="provider"]:before{background:var(--sea)}.site-host-source[data-location-source="fallback"]:before{background:var(--sun)}
.map-note{margin-top:auto;padding-top:8px;border-top:1px solid rgba(214,226,234,.72);color:var(--muted);font-size:11px}
.leaflet-container{height:100%;font:13px/1.4 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink)}
.leaflet-control-zoom a{color:var(--ink)!important}
.map-label-layer{position:absolute;inset:0;z-index:650;pointer-events:none;overflow:hidden}
.map-links{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.map-link{fill:none;stroke:rgba(21,158,153,.36);stroke-width:1.15;opacity:.72;vector-effect:non-scaling-stroke}
.map-link[data-inbound-level="warn"]{stroke:rgba(214,155,49,.38)}.map-link[data-inbound-level="down"]{stroke:rgba(191,58,53,.30);stroke-dasharray:4 7}.map-link[data-outbound-policy="blocked"]{stroke:rgba(137,151,163,.34);stroke-dasharray:3 6;opacity:.42}
.map-packet{r:3;opacity:.78}.map-packet.inbound{fill:var(--sea)}.map-packet.outbound{fill:var(--accent)}.map-packet[data-level="warn"]{fill:var(--sun)}.map-packet[data-level="down"]{fill:var(--down)}.map-packet[data-policy="blocked"]{fill:var(--wait);opacity:.38}
.map-leaders{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.map-leaders line{stroke:#7a8c9c;stroke-width:1.2;stroke-dasharray:2 4;opacity:.52;vector-effect:non-scaling-stroke}
.map-anchor{--node-color:var(--wait);position:absolute;width:12px;height:12px;border-radius:50%;background:radial-gradient(circle,#fff 0 27%,var(--node-color) 33% 68%,transparent 70%);box-shadow:0 0 0 5px color-mix(in srgb,var(--node-color) 11%,transparent),0 6px 12px rgba(45,75,95,.14);transform:translate(-50%,-50%);pointer-events:none}
.map-anchor.live,.map-node.live{--node-color:var(--live)}.map-anchor.stale,.map-node.stale{--node-color:var(--stale)}.map-anchor.down,.map-node.down{--node-color:var(--down)}.map-anchor.awaiting_first_heartbeat,.map-node.awaiting_first_heartbeat{--node-color:var(--wait)}
.map-node{--node-color:var(--wait);position:absolute;display:grid;grid-template-columns:9px minmax(0,1fr);column-gap:7px;align-items:start;min-width:106px;max-width:154px;padding:6px 8px 7px 7px;border:1px solid color-mix(in srgb,var(--node-color) 30%,rgba(210,226,234,.92));border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 10px 22px rgba(45,75,95,.14),0 0 0 4px color-mix(in srgb,var(--node-color) 7%,transparent);-webkit-backdrop-filter:blur(8px) saturate(1.05);backdrop-filter:blur(8px) saturate(1.05);color:var(--ink);text-decoration:none;pointer-events:auto}
.map-node:hover{box-shadow:0 14px 28px rgba(45,75,95,.18),0 0 0 5px color-mix(in srgb,var(--node-color) 12%,transparent);transform:translateY(-1px)}
.map-status-dot{grid-row:1/4;width:9px;height:9px;margin-top:4px;border-radius:50%;background:var(--node-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--node-color) 13%,transparent)}
.map-name{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:12px;line-height:1.15;font-weight:760;color:#17304a}
.map-signals{grid-column:2;display:grid;gap:2px;margin-top:2px}
.map-ping{display:flex;align-items:center;gap:4px;font-size:10px;line-height:1.15;color:var(--muted);white-space:nowrap}
.map-ping:before{content:attr(data-dir);width:17px;color:var(--muted);font-weight:700;text-transform:uppercase;font-size:8px;letter-spacing:.03em}
.map-ping[data-probe-level="good"]{color:var(--live)}.map-ping[data-probe-level="warn"]{color:var(--stale)}.map-ping[data-probe-level="down"]{color:var(--down)}.map-ping[data-policy="blocked"]{color:var(--muted)}
.map-source{grid-column:2;justify-self:start;display:inline-flex;align-items:center;gap:4px;margin-top:4px;padding:2px 6px;border:1px solid rgba(210,226,234,.86);border-radius:999px;background:rgba(255,255,255,.76);color:#546b80;font-size:10px;line-height:1.1;white-space:nowrap}
.map-source:before{content:"";width:5px;height:5px;border-radius:50%;background:#8aa0b2;box-shadow:0 0 0 3px rgba(138,160,178,.10)}
.map-source[data-location-source="declared"]:before{background:#2d87bf}.map-source[data-location-source="wifi"]:before,.map-source[data-location-source="ip"]:before{background:var(--live)}.map-source[data-location-source="provider"]:before{background:var(--sea)}.map-source[data-location-source="fallback"]:before{background:var(--sun)}
.map-panel[data-label-density="compact"] .map-node{grid-template-columns:8px max-content;align-items:center;min-width:0;max-width:132px;padding:5px 8px 5px 7px}
.map-panel[data-label-density="compact"] .map-status-dot{grid-row:auto;margin-top:0;width:8px;height:8px}
.map-panel[data-label-density="compact"] .map-name{font-size:12px}
.map-panel[data-label-density="compact"] .map-signals,.map-panel[data-label-density="compact"] .map-source{display:none}
@media (max-width:900px){.app-shell{display:block}.sidebar{position:relative;height:auto;min-height:0;display:grid;grid-template-columns:1fr;gap:14px;padding:18px;border-right:0;border-bottom:1px solid rgba(211,225,233,.78)}.sidebar:before{display:none}.side-brand{padding:0}.side-nav{grid-template-columns:repeat(3,minmax(0,1fr))}.side-link{min-height:38px;padding:0 10px}.side-foot{display:none}main{padding:28px 18px 42px}.top{display:block;min-height:112px}.asof{padding-top:10px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.toolbar{align-items:stretch;flex-direction:column}.toolbar-left,.toolbar-right{justify-content:space-between}.search{min-width:0;width:100%}.grid{grid-template-columns:1fr}.list-wrap{overflow-x:auto}.list{min-width:900px}}
@media (max-width:1100px){.map-layout{grid-template-columns:1fr}.site-panel{display:block}.site-list{grid-template-columns:repeat(auto-fit,minmax(220px,1fr));margin-top:12px}.map-note{margin-top:12px}.map-layout[data-mode="maximized"] .site-panel{display:none}}
@media (max-width:1100px){.ops-layout{grid-template-columns:1fr}.alert-row{grid-template-columns:1fr 92px}.alert-issue{grid-column:1/-1}.ops-source,.ops-time,.next-action{font-size:11px}.activity-row{grid-template-columns:78px minmax(0,1fr)}.activity-host,.activity-copy,.activity-row .severity,.activity-row .ops-source{grid-column:2}.ops-summary{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media (max-width:720px){.empty-state{grid-template-columns:1fr;min-height:0;padding:24px}.empty-copy h2{font-size:24px}.empty-visual{min-height:210px;order:-1}.lone-state{grid-template-columns:auto 1fr}.lone-state .onboard-command{grid-column:1/-1;width:100%}.map-panel{min-height:420px}.fleet-map{min-height:420px}.map-mode-controls{top:10px;right:10px}.ops-summary{grid-template-columns:1fr}.alert-row{grid-template-columns:1fr}.activity-row{grid-template-columns:1fr}.activity-host,.activity-copy,.activity-row .severity,.activity-row .ops-source{grid-column:auto}}
@media (prefers-reduced-motion:reduce){.beat-current,.beat[data-flash="true"] .beat-hit{animation:none}}
</style></head><body><div class="app-shell">"#;

const FOOT: &str = r#"</div><script>
const words={live:'live',stale:'stale',down:'down',awaiting_first_heartbeat:'awaiting'};
const HISTORY_DOTS=12;
const EXPECT_X=64;
const STALE_X=82;
const HISTORY_STEP=EXPECT_X/HISTORY_DOTS;
const SIGNAL_WINDOWS=[{key:'10m',label:'10m',secs:10*60},{key:'1h',label:'1h',secs:60*60},{key:'24h',label:'24h',secs:24*60*60}];
let signalWindow=SIGNAL_WINDOWS[0];
let activeSearch='';
let activeLiveFilter='all';
function dur(s){s=Math.max(0,s);if(s<10)return s.toFixed(1)+'s';s=Math.ceil(s);return s<60?s+'s':Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s'}
function clock(t){return new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
const ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(v){return String(v ?? '').replace(/[&<>"']/g,ch=>ESC[ch])}
function cookie(name){return document.cookie.split('; ').find(v=>v.startsWith(name+'='))?.split('=').slice(1).join('=')||''}
function setCookie(name,value){document.cookie=name+'='+encodeURIComponent(value)+'; path=/; max-age=31536000; SameSite=Lax'}
function hostSurfaces(name){return Array.from(document.querySelectorAll('[data-host-surface="runtime"]')).filter(el=>el.dataset.host===name)}
function parseBeats(v){return String(v||'').split(',').map(Number).filter(Number.isFinite).filter(n=>n>0)}
function signalWindowByKey(key){return SIGNAL_WINDOWS.find(w=>w.key===key)||SIGNAL_WINDOWS[0]}
function historyWindowMeta(samples,windowDef){
  if(samples.length<2)return {start:0,latest:0,span:1,candidates:[]};
  const latest=samples[samples.length-1];
  const start=Math.max(latest-windowDef.secs,samples[0]);
  const span=Math.max(1,latest-start);
  const candidates=samples.map((stamp,index)=>({stamp,index})).filter(item=>item.index>0&&item.stamp>=start&&item.stamp<=latest);
  return {start,latest,span,candidates};
}
function visibleHistory(samples,windowDef){
  const meta=historyWindowMeta(samples,windowDef);
  if(meta.candidates.length<=HISTORY_DOTS)return {...meta,visible:meta.candidates};
  const buckets=Array(HISTORY_DOTS).fill(null);
  for(const item of meta.candidates){
    const bucket=Math.min(HISTORY_DOTS-1,Math.max(0,Math.floor(((item.stamp-meta.start)/meta.span)*HISTORY_DOTS)));
    buckets[bucket]=item;
  }
  return {...meta,visible:buckets.filter(Boolean)};
}
function historyInfo(beats,index,interval){
  const stamp=beats[index];
  const previous=index>0?beats[index-1]:null;
  if(previous==null)return {level:'first',label:'first heartbeat',detail:'at '+clock(stamp)};
  const gap=Math.max(0,stamp-previous);
  if(gap<=interval)return {level:'ok',label:'on cadence',detail:dur(gap)+' after previous · '+clock(stamp)};
  if(gap<=interval*2)return {level:'late',label:'late heartbeat',detail:dur(gap)+' after previous · '+clock(stamp)};
  if(gap<=interval*5)return {level:'stale',label:'stale gap recovered',detail:dur(gap)+' after previous · '+clock(stamp)};
  return {level:'down',label:'offline gap recovered',detail:dur(gap)+' after previous · '+clock(stamp)};
}
function freshRow(label,value,klass){return '<div class="fresh-row"><span>'+esc(label)+'</span><strong class="'+klass+'">'+esc(value)+'</strong></div>'}
function freshValue(v,zero){
  const n=Number(v);
  if(v==null||!Number.isFinite(n))return {value:'unknown',klass:'na'};
  if(n===0)return {value:zero,klass:'ok'};
  return {value:String(n),klass:'warn'};
}
function freshHtml(f){
  if(!f||f.applicable===false)return freshRow('Flake.lock age','n/a','na')+freshRow('Commits behind','n/a','na');
  const age=freshValue(f.flake_lock_age_days,'fresh');
  const commits=freshValue(f.commits_behind,'0');
  if(age.klass==='warn')age.value=age.value+'d';
  return freshRow('Flake.lock age',age.value,age.klass)+freshRow('Commits behind',commits.value,commits.klass);
}
function freshnessAttention(f){
  if(!f||f.applicable===false)return null;
  const age=Number(f.flake_lock_age_days);
  const commits=Number(f.commits_behind);
  const hasAge=f.flake_lock_age_days!=null&&Number.isFinite(age);
  const hasCommits=f.commits_behind!=null&&Number.isFinite(commits);
  const ageWarn=hasAge&&age>0;
  const commitsWarn=hasCommits&&commits>0;
  if(ageWarn&&commitsWarn)return {label:'nix drift: '+age+'d · '+commits+' commits',level:'warn',rank:3};
  if(ageWarn)return {label:'flake.lock '+age+'d',level:'warn',rank:3};
  if(commitsWarn)return {label:commits+' commits behind',level:'warn',rank:3};
  if(!hasAge||!hasCommits)return {label:'freshness unknown',level:'wait',rank:3};
  return null;
}
function attentionFor(live,f){
  if(live==='down')return {label:'silent heartbeat',level:'down',rank:0};
  if(live==='stale')return {label:'stale heartbeat',level:'warn',rank:1};
  if(live==='awaiting_first_heartbeat')return {label:'awaiting first beat',level:'wait',rank:2};
  return freshnessAttention(f)||{label:'all clear',level:'ok',rank:4};
}
function setReason(surface,reason){
  const el=surface.querySelector('[data-reason]');
  if(!el)return;
  el.className='reason '+reason.level;
  const text=el.querySelector('span');
  if(text)text.textContent=reason.label;
}
function markHtml(beats,interval,windowDef=signalWindow){
  const kept=Array.from(new Set(beats)).sort((a,b)=>a-b);
  if(kept.length<2)return '';
  const cadence=Math.max(1,Number(interval)||60);
  const newestX=EXPECT_X-HISTORY_STEP;
  const view=visibleHistory(kept,windowDef);
  return view.visible.map(item=>{
    const x=((item.stamp-view.start)/view.span)*newestX;
    const info=historyInfo(kept,item.index,cadence);
    const title=info.label+' · '+info.detail;
    return '<span class="beat-mark" tabindex="0" data-history-level="'+esc(info.level)+'" data-history-label="'+esc(info.label)+'" data-history-detail="'+esc(info.detail)+'" title="'+esc(title)+'" aria-label="'+esc(title)+'" style="--mark-x:'+x.toFixed(1)+'%"></span>';
  }).join('');
}
function signalInfo(beats,last,interval,now,windowDef=signalWindow){
  const cadence=Math.max(1,Number(interval)||60);
  const samples=Array.from(new Set(beats.concat(Number.isFinite(last)&&last>0?[last]:[]))).filter(Number.isFinite).filter(n=>n>0).sort((a,b)=>a-b);
  if(!samples.length)return {text:'new',level:'wait',window:windowDef.label,title:'Signal over '+windowDef.label+': waiting for first heartbeat'};
  const requestedStart=now-windowDef.secs;
  const retainedStart=Math.max(requestedStart,samples[0]);
  const span=Math.max(cadence,Math.min(windowDef.secs,now-retainedStart));
  const expected=Math.max(1,Math.ceil(span/cadence));
  const received=samples.filter(stamp=>stamp>=retainedStart&&stamp<=now).length;
  let longestGap=Math.max(0,Math.min(now-samples[samples.length-1],span));
  let previous=retainedStart;
  for(const stamp of samples){
    if(stamp<retainedStart||stamp>now)continue;
    longestGap=Math.max(longestGap,stamp-previous);
    previous=stamp;
  }
  longestGap=Math.max(longestGap,now-previous);
  const percent=Math.max(0,Math.min(100,Math.round((received/expected)*100)));
  const level=percent>=95?'good':percent>=75?'warn':'down';
  const coverage=retainedStart>requestedStart?' · retained '+dur(span):'';
  return {text:percent+'%',level,window:windowDef.label,title:'Signal over '+windowDef.label+': '+received+' of '+expected+' expected heartbeats received · longest gap '+dur(longestGap)+coverage};
}
function updateSignal(surface,info){
  const signal=surface?.querySelector('[data-signal]');
  if(!signal)return;
  signal.dataset.signalLevel=info.level;
  signal.dataset.signalWindowKey=info.window;
  signal.title=info.title;
  signal.setAttribute('aria-label',info.title);
  const text=signal.querySelector('[data-signal-percent]');
  if(text)text.textContent=info.text;
  const windowLabel=signal.querySelector('[data-signal-window]');
  if(windowLabel){
    const next=SIGNAL_WINDOWS[(SIGNAL_WINDOWS.findIndex(w=>w.label===info.window)+1)%SIGNAL_WINDOWS.length]||SIGNAL_WINDOWS[0];
    windowLabel.textContent=info.window;
    windowLabel.title=info.title+'; click for '+next.label;
    windowLabel.setAttribute('aria-label',info.title+'; click for '+next.label);
  }
}
function setHistoryHint(mark,show){
  const card=mark.closest('.card');
  if(!card)return;
  const seen=card.querySelector('[data-seen]');
  const asof=card.querySelector('[data-card-asof]');
  if(!seen||!asof)return;
  if(show){
    card.dataset.historyHint='true';
    seen.textContent=mark.dataset.historyLabel||'historic heartbeat';
    asof.textContent=mark.dataset.historyDetail||'';
  }else{
    delete card.dataset.historyHint;
    seen.textContent=seen.dataset.defaultText||seen.textContent;
    asof.textContent=asof.dataset.defaultText||asof.textContent;
  }
}
function bindHistoryHints(root=document){
  root.querySelectorAll('.beat-mark').forEach(mark=>{
    if(mark.dataset.hintBound==='true')return;
    mark.dataset.hintBound='true';
    mark.addEventListener('mouseenter',()=>setHistoryHint(mark,true));
    mark.addEventListener('mouseleave',()=>setHistoryHint(mark,false));
    mark.addEventListener('focus',()=>setHistoryHint(mark,true));
    mark.addEventListener('blur',()=>setHistoryHint(mark,false));
  });
}
function setBeatHistory(beat,beats,interval){
  const all=Array.from(new Set(beats)).sort((a,b)=>a-b);
  const view=visibleHistory(all,signalWindow);
  const kept=view.visible.map(item=>item.stamp);
  const cadence=Math.max(1,Number(interval)||Number(beat.dataset.interval)||60);
  beat.dataset.signalBeats=all.join(',');
  beat.dataset.beats=kept.join(',');
  beat.dataset.count=String(kept.length);
  beat.dataset.historyWindow=signalWindow.label;
  const windowLabel=beat.querySelector('[data-history-window-label]');
  if(windowLabel)windowLabel.textContent=signalWindow.label;
  const marks=beat.querySelector('.beat-marks');
  if(marks){
    marks.innerHTML=markHtml(all,cadence,signalWindow);
    bindHistoryHints(marks);
  }
}
function flashBeat(beat){
  beat.dataset.flash='true';
  window.setTimeout(()=>{delete beat.dataset.flash},950);
}
function heartbeatX(age,interval){
  if(age<=interval)return (age/interval)*EXPECT_X;
  if(age<=interval*2)return EXPECT_X+((age-interval)/interval)*(STALE_X-EXPECT_X);
  if(age<=interval*5)return STALE_X+((age-interval*2)/(interval*3))*(100-STALE_X);
  return 100;
}
function updateBeatClock(beat,now){
  const last=Number(beat.dataset.last);
  const interval=Math.max(1,Number(beat.dataset.interval)||60);
  const surface=beat.closest('[data-host]');
  if(!Number.isFinite(last)||last<=0){
    beat.style.setProperty('--expect-alpha','.22');
    beat.style.setProperty('--now-x','0%');
    beat.style.setProperty('--fill-color','var(--wait)');
    beat.style.setProperty('--expect-fill','0deg');
    beat.style.setProperty('--target-ring','3px');
    beat.style.setProperty('--late-alpha','.3');
    beat.dataset.beat='waiting';
    updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats),last,interval,now));
    return;
  }
  const age=Math.max(0,now-last);
  const expect=Math.max(0,Math.min(1,age/interval));
  const x=heartbeatX(age,interval);
  beat.style.setProperty('--now-x',x.toFixed(2)+'%');
  beat.style.setProperty('--expect-alpha',(.34+expect*.45).toFixed(3));
  beat.style.setProperty('--expect-fill',(expect*360).toFixed(1)+'deg');
  beat.style.setProperty('--target-ring',(3+expect*5).toFixed(1)+'px');
  if(age<=interval){
    beat.style.setProperty('--fill-color',beat.dataset.self==='true'?'var(--sun)':'var(--sea)');
    beat.dataset.beat=beat.dataset.self==='true'?'lit':'tracking';
  }else if(age<=interval*2){
    beat.style.setProperty('--fill-color','var(--sun)');
    beat.style.setProperty('--expect-alpha','.79');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='late';
  }else if(age<=interval*5){
    beat.style.setProperty('--fill-color','var(--stale)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='stale';
  }else{
    beat.style.setProperty('--fill-color','var(--down)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='down';
  }
  updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats||beat.dataset.beats),last,interval,now));
}
function frame(){
  const now=Date.now()/1000;
  document.querySelectorAll('.beat').forEach(beat=>{
    updateBeatClock(beat,now);
  });
  requestAnimationFrame(frame);
}
function setSeen(card,last,now){
  const seen=card.querySelector('[data-seen]');
  if(!seen)return;
  const text=last==null?'never seen':'last seen '+dur(now-last)+' ago';
  seen.dataset.defaultText=text;
  if(card.dataset.historyHint!=='true')seen.textContent=text;
}
function setCardAsOf(card,now){
  const asof=card.querySelector('[data-card-asof]');
  if(!asof)return;
  const text='as of '+clock(now);
  asof.dataset.defaultText=text;
  if(card.dataset.historyHint!=='true')asof.textContent=text;
}
function sevFor(live){return live==='down'?0:live==='stale'?1:live==='awaiting_first_heartbeat'?2:3}
function cmp(a,b,mode){
  if(mode==='name')return a.dataset.sortName.localeCompare(b.dataset.sortName);
  if(mode==='last')return Number(b.dataset.last||0)-Number(a.dataset.last||0)||a.dataset.sortName.localeCompare(b.dataset.sortName);
  return Number(a.dataset.sev)-Number(b.dataset.sev)||a.dataset.sortName.localeCompare(b.dataset.sortName);
}
const FREEFORM_ORDER_KEY='pharos_freeform_order_v1';
function readFreeformOrder(){
  try{
    const parsed=JSON.parse(window.localStorage.getItem(FREEFORM_ORDER_KEY)||'[]');
    return Array.isArray(parsed)?parsed.filter(v=>typeof v==='string'&&v):[];
  }catch(_){return []}
}
function writeFreeformOrder(){
  const grid=document.querySelector('[data-grid]');
  if(!grid)return;
  try{
    const order=Array.from(grid.querySelectorAll('.card')).map(el=>el.dataset.host).filter(Boolean);
    window.localStorage.setItem(FREEFORM_ORDER_KEY,JSON.stringify(order));
  }catch(_){}
}
function clearFreeformOrder(){
  try{window.localStorage.removeItem(FREEFORM_ORDER_KEY)}catch(_){}
}
function sortByFreeformOrder(items,order){
  const index=new Map(order.map((name,idx)=>[name,idx]));
  return items.sort((a,b)=>{
    const ai=index.has(a.dataset.host)?index.get(a.dataset.host):Number.MAX_SAFE_INTEGER;
    const bi=index.has(b.dataset.host)?index.get(b.dataset.host):Number.MAX_SAFE_INTEGER;
    return ai-bi||a.dataset.sortName.localeCompare(b.dataset.sortName);
  });
}
function applyFreeformOrder(){
  const grid=document.querySelector('[data-grid]');
  const body=document.querySelector('[data-list-body]');
  const order=readFreeformOrder();
  if(!order.length){
    writeFreeformOrder();
    return;
  }
  if(grid)sortByFreeformOrder(Array.from(grid.querySelectorAll('.card')),order).forEach(el=>grid.appendChild(el));
  if(body)sortByFreeformOrder(Array.from(body.querySelectorAll('tr')),order).forEach(el=>body.appendChild(el));
}
function setArrangeMode(mode){
  const main=document.querySelector('main');
  if(main)main.dataset.arrange=mode;
}
function applySort(mode,write=true){
  mode=['attention','name','last','freeform'].includes(mode)?mode:'attention';
  const grid=document.querySelector('[data-grid]');
  const body=document.querySelector('[data-list-body]');
  setArrangeMode(mode);
  if(mode==='freeform'){
    applyFreeformOrder();
  }else{
    if(write)clearFreeformOrder();
    if(grid)Array.from(grid.querySelectorAll('.card')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>grid.appendChild(el));
    if(body)Array.from(body.querySelectorAll('tr')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>body.appendChild(el));
  }
  const select=document.querySelector('[data-sort]');
  if(select)select.value=mode;
  if(write)setCookie('pharos_sort',mode);
}
function applyView(view,write=true){
  view=view==='list'?'list':'grid';
  const main=document.querySelector('main');
  if(main)main.dataset.view=view;
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.setAttribute('aria-pressed',String(btn.dataset.viewButton===view)));
  if(write)setCookie('pharos_view',view);
}
function hostMatchesSurface(el,q,live){
  const text=q===''||String(el.dataset.search||'').includes(q);
  const state=live==='all'||el.dataset.live===live;
  return text&&state;
}
function updateGroupVisibility(){
  document.querySelectorAll('.site-item').forEach(site=>{
    const visible=Array.from(site.querySelectorAll('.site-host')).some(host=>!host.hidden);
    site.hidden=!visible;
  });
}
function updateSummaryFilterButtons(){
  document.querySelectorAll('[data-live-filter]').forEach(btn=>{
    const active=btn.dataset.liveFilter===activeLiveFilter;
    btn.setAttribute('aria-pressed',active?'true':'false');
  });
}
function applySurfaceFilters(write=true){
  const q=activeSearch.trim().toLowerCase();
  document.querySelectorAll('[data-host]').forEach(el=>{
    if(el.dataset.mapLayer==='managed')return;
    el.hidden=!hostMatchesSurface(el,q,activeLiveFilter);
  });
  updateGroupVisibility();
  if(typeof window.pharosMapApplyFilter==='function')window.pharosMapApplyFilter(q,activeLiveFilter);
  updateSummaryFilterButtons();
  if(write){
    setCookie('pharos_search',activeSearch);
    setCookie('pharos_live_filter',activeLiveFilter);
  }
}
function applyFilter(query,write=true){
  activeSearch=query;
  const input=document.querySelector('[data-search]');
  if(input&&input.value!==query)input.value=query;
  applySurfaceFilters(write);
}
function applyLiveFilter(filter,write=true){
  activeLiveFilter=['all','live','stale','down','awaiting_first_heartbeat'].includes(filter)?filter:'all';
  applySurfaceFilters(write);
}
function applySignalWindow(key,write=true){
  signalWindow=signalWindowByKey(key);
  document.querySelectorAll('.beat').forEach(beat=>{
    const surface=beat.closest('[data-host]');
    const last=Number(beat.dataset.last);
    const interval=Math.max(1,Number(beat.dataset.interval)||60);
    setBeatHistory(beat,parseBeats(beat.dataset.signalBeats||beat.dataset.beats),interval);
    updateSignal(surface,signalInfo(parseBeats(beat.dataset.signalBeats||beat.dataset.beats),last,interval,Date.now()/1000,signalWindow));
  });
  if(write)setCookie('pharos_signal_window',signalWindow.key);
}
function cycleSignalWindow(){
  const idx=SIGNAL_WINDOWS.findIndex(w=>w.key===signalWindow.key);
  applySignalWindow(SIGNAL_WINDOWS[(idx+1)%SIGNAL_WINDOWS.length].key);
  updateUrlState();
}
function freeformTarget(grid,x,y){
  let best=null;
  let bestDistance=Infinity;
  let bestAfter=false;
  grid.querySelectorAll('.card:not([data-dragging]):not([hidden])').forEach(card=>{
    const box=card.getBoundingClientRect();
    const cx=box.left+box.width/2;
    const cy=box.top+box.height/2;
    const distance=Math.hypot(x-cx,(y-cy)*1.35);
    if(distance<bestDistance){
      best=card;
      bestDistance=distance;
      bestAfter=y>cy||Math.abs(y-cy)<box.height*.42&&x>cx;
    }
  });
  return {card:best,after:bestAfter};
}
function bindFreeformDrag(){
  const grid=document.querySelector('[data-grid]');
  if(!grid||grid.dataset.freeformBound==='true')return;
  grid.dataset.freeformBound='true';
  let drag=null;
  function finish(){
    if(!drag)return;
    delete drag.card.dataset.dragging;
    drag.card.style.zIndex='';
    delete grid.dataset.freeformDragging;
    writeFreeformOrder();
    applyFreeformOrder();
    drag=null;
  }
  grid.addEventListener('pointerdown',event=>{
    const handle=event.target.closest('[data-drag-handle]');
    if(!handle||!grid.contains(handle))return;
    if(document.querySelector('main')?.dataset.arrange!=='freeform')return;
    if(event.button!==0)return;
    const card=handle.closest('.card');
    if(!card)return;
    event.preventDefault();
    handle.setPointerCapture?.(event.pointerId);
    drag={card,pointerId:event.pointerId};
    card.dataset.dragging='true';
    card.style.zIndex='20';
    grid.dataset.freeformDragging='true';
  });
  grid.addEventListener('pointermove',event=>{
    if(!drag||event.pointerId!==drag.pointerId)return;
    event.preventDefault();
    const target=freeformTarget(grid,event.clientX,event.clientY);
    if(!target.card){
      grid.appendChild(drag.card);
      return;
    }
    const before=target.after?target.card.nextSibling:target.card;
    if(before!==drag.card)grid.insertBefore(drag.card,before);
  });
  grid.addEventListener('pointerup',event=>{if(drag&&event.pointerId===drag.pointerId)finish()});
  grid.addEventListener('pointercancel',event=>{if(drag&&event.pointerId===drag.pointerId)finish()});
  window.addEventListener('blur',finish);
}
function updateUrlState(){
  const main=document.querySelector('main');
  const sort=document.querySelector('[data-sort]')?.value||'attention';
  const params=new URLSearchParams(location.search);
  params.set('view',main?.dataset.view||'grid');
  params.set('sort',sort);
  params.set('filter',activeLiveFilter);
  params.set('signal',signalWindow.key);
  const url=location.pathname+'?'+params.toString();
  history.replaceState(null,'',url);
}
function initControls(){
  const params=new URLSearchParams(location.search);
  const view=params.get('view')||decodeURIComponent(cookie('pharos_view'))||'grid';
  const sort=params.get('sort')||decodeURIComponent(cookie('pharos_sort'))||'attention';
  const search=decodeURIComponent(cookie('pharos_search'));
  const liveFilter=params.get('filter')||decodeURIComponent(cookie('pharos_live_filter'))||'all';
  const selectedSignalWindow=params.get('signal')||decodeURIComponent(cookie('pharos_signal_window'))||SIGNAL_WINDOWS[0].key;
  applyView(view,false);
  applySort(sort,false);
  applyFilter(search,false);
  applyLiveFilter(liveFilter,false);
  applySignalWindow(selectedSignalWindow,false);
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.addEventListener('click',()=>{applyView(btn.dataset.viewButton);updateUrlState()}));
  document.querySelector('[data-sort]')?.addEventListener('change',e=>{applySort(e.target.value);updateUrlState()});
  document.querySelector('[data-search]')?.addEventListener('input',e=>applyFilter(e.target.value));
  document.querySelectorAll('[data-live-filter]').forEach(btn=>btn.addEventListener('click',()=>{applyLiveFilter(btn.dataset.liveFilter);updateUrlState()}));
  document.querySelectorAll('[data-signal-window]').forEach(btn=>btn.addEventListener('click',cycleSignalWindow));
  bindFreeformDrag();
}
const REFRESH_MS=10000;
const HIDDEN_REFRESH_MS=60000;
const FETCH_TIMEOUT_MS=9000;
let refreshTimer=null;
let refreshPromise=null;
let refreshAbort=null;
let refreshStartedAt=0;
let refreshGeneration=0;
function clearRefreshTimer(){
  if(refreshTimer!=null){
    clearTimeout(refreshTimer);
    refreshTimer=null;
  }
}
function nextRefreshDelay(){
  return document.hidden?HIDDEN_REFRESH_MS:REFRESH_MS;
}
function scheduleRefresh(delay=nextRefreshDelay()){
  clearRefreshTimer();
  refreshTimer=setTimeout(()=>refresh('timer'),delay);
}
async function refresh(reason='manual'){
  clearRefreshTimer();
  if(refreshPromise)return refreshPromise;
  const controller=new AbortController();
  const generation=++refreshGeneration;
  refreshAbort=controller;
  refreshStartedAt=Date.now();
  const timeout=setTimeout(()=>controller.abort(),FETCH_TIMEOUT_MS);
  refreshPromise=(async()=>{
  try{
    const res=await fetch('/hosts.json?refresh='+Date.now(),{headers:{Accept:'application/json'},cache:'no-store',credentials:'same-origin',signal:controller.signal});
    if(!res.ok)return;
    const data=await res.json();
    if(generation!==refreshGeneration)return;
    const now=Number(data.as_of)||Math.floor(Date.now()/1000);
    const asof=document.querySelector('[data-as-of]');
    if(asof)asof.textContent='as of '+clock(now);
    for(const h of data.hosts||[]){
      const surfaces=hostSurfaces(h.name);
      for(const card of surfaces){
        const live=h.liveness;
        card.dataset.live=live;
        const attention=h.attention||attentionFor(h.liveness,h.freshness);
        card.dataset.sev=String(attention.rank ?? sevFor(live));
        card.dataset.last=h.last_seen ?? 0;
        card.dataset.search=(String(h.name||'')+' '+String(h.role||'')+' '+String(h.freshness_tldr||'')+' '+String(attention.label||'')).toLowerCase();
        const word=card.querySelector('[data-status-word]');
        if(word)word.textContent=words[h.liveness]||h.liveness;
        setReason(card,attention);
        const fresh=card.querySelector('[data-fresh]');
        if(fresh)fresh.innerHTML=freshHtml(h.freshness);
        setSeen(card,h.last_seen,now);
        setCardAsOf(card,now);
        const beat=card.querySelector('.beat');
        if(beat){
          const previous=Number(beat.dataset.last);
          const last=h.last_seen == null ? NaN : Number(h.last_seen);
          const interval=h.heartbeat_interval_secs || 60;
          const incoming=Array.isArray(h.heartbeat_log)?h.heartbeat_log.map(Number).filter(Number.isFinite):[];
          const beats=incoming.length?incoming:(Number.isFinite(last)?[last]:[]);
          beat.dataset.interval=interval;
          setBeatHistory(beat,beats,interval);
          updateSignal(card,signalInfo(beats,last,interval,now));
          if(beat.dataset.ready==='true'&&Number.isFinite(previous)&&Number.isFinite(last)&&last>previous){
            beat.style.setProperty('--hit-x',heartbeatX(Math.max(0,last-previous),Math.max(1,Number(interval)||60)).toFixed(2)+'%');
            flashBeat(beat);
          }
          beat.dataset.ready='true';
          beat.dataset.last=Number.isFinite(last)?String(last):'';
          beat.dataset.nextAt=Number.isFinite(last)?String(last+interval):'';
        }
      }
    }
    applySort(document.querySelector('[data-sort]')?.value||'attention',false);
    applySurfaceFilters(false);
  }catch(_){}
  finally{
    clearTimeout(timeout);
    if(generation===refreshGeneration){
      if(refreshAbort===controller)refreshAbort=null;
      refreshPromise=null;
      scheduleRefresh();
    }
  }
  })();
  return refreshPromise;
}
function resumeRefresh(reason){
  if(document.hidden){
    scheduleRefresh(HIDDEN_REFRESH_MS);
    return;
  }
  if(refreshPromise&&refreshAbort&&Date.now()-refreshStartedAt>FETCH_TIMEOUT_MS){
    refreshAbort.abort();
    refreshGeneration++;
    refreshAbort=null;
    refreshPromise=null;
  }
  refresh(reason);
}
document.addEventListener('visibilitychange',()=>resumeRefresh('visible'));
window.addEventListener('focus',()=>resumeRefresh('focus'));
window.addEventListener('pageshow',()=>resumeRefresh('pageshow'));
window.addEventListener('online',()=>resumeRefresh('online'));
document.querySelectorAll('[data-seen],[data-card-asof]').forEach(el=>{el.dataset.defaultText=el.textContent});
document.querySelectorAll('.beat').forEach(beat=>{setBeatHistory(beat,parseBeats(beat.dataset.signalBeats||beat.dataset.beats),Number(beat.dataset.interval)||60);beat.dataset.ready='true'});
initControls();
requestAnimationFrame(frame);
scheduleRefresh(3000);
</script></body></html>"#;

const HEARTBEAT_HISTORY_DOTS: usize = 12;
const HEARTBEAT_EXPECT_X: f64 = 64.0;
const HEARTBEAT_STALE_X: f64 = 82.0;
const SIGNAL_DEFAULT_WINDOW_LABEL: &str = "10m";
const SIGNAL_DEFAULT_WINDOW_SECS: i64 = 10 * 60;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The host pharosd itself runs on — gets the lighthouse treatment (PHAROS-10).
fn self_host() -> String {
    std::env::var("PHAROS_SELF").unwrap_or_else(|_| "csb1".into())
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn parse_beacon_token_mode(value: &str) -> Option<BeaconTokenMode> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" | "mvp" => Some(BeaconTokenMode::Local),
        "dual" | "migration" => Some(BeaconTokenMode::Dual),
        "janus" | "forge" | "warden" => Some(BeaconTokenMode::Janus),
        _ => None,
    }
}

fn janus_token_hash_sources_from_env() -> Vec<JanusTokenHashSource> {
    let mut sources = Vec::new();
    if let Some(value) = env_nonempty("PHAROS_BEACON_TOKEN_HASH_FILES") {
        sources.extend(
            parse_path_list(&value)
                .into_iter()
                .map(JanusTokenHashSource::File),
        );
    }
    for name in [
        "PHAROS_BEACON_TOKEN_HASH_FILE",
        "PHAROS_JANUS_BEACON_TOKEN_HASH_FILE",
    ] {
        if let Some(path) = env_nonempty(name) {
            sources.push(JanusTokenHashSource::File(PathBuf::from(path)));
        }
    }
    if let Some(path) = env_nonempty("PHAROS_BEACON_TOKEN_HASH_DIR") {
        sources.push(JanusTokenHashSource::Dir(PathBuf::from(path)));
    }
    sources
}

fn parse_path_list(value: &str) -> Vec<PathBuf> {
    value
        .split(',')
        .filter_map(|path| {
            let path = path.trim();
            if path.is_empty() {
                None
            } else {
                Some(PathBuf::from(path))
            }
        })
        .collect()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..len {
        diff |=
            usize::from(left.get(idx).copied().unwrap_or(0) ^ right.get(idx).copied().unwrap_or(0));
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn local_token_matches(store: &Store, host: &str, expected_hash: &str) -> bool {
    store
        .token_hash_for(host)
        .is_some_and(|stored| constant_time_eq(&stored, expected_hash))
}

fn new_beacon_token() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("pharos_{}", hex(&bytes)))
}

const JANUS_BEACON_TOKEN_HASH_SCHEMA: &str = "inspr.pharos.beacon-token-hashes.v1";

#[derive(Debug, Deserialize)]
struct JanusTokenHashFile {
    #[serde(default)]
    schema: Option<String>,
    #[serde(default)]
    hosts: Vec<JanusTokenHashHost>,
    #[serde(default)]
    tokens: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct JanusTokenHashHost {
    name: String,
    #[serde(alias = "tokenHash", alias = "token_hash", alias = "sha256")]
    token_sha256: String,
}

#[derive(Debug, PartialEq, Eq)]
enum JanusTokenHashError {
    NotConfigured,
    Read,
    Parse,
    UnsupportedSchema,
    EmptyHost,
    InvalidHash,
    DuplicateHost,
}

impl std::fmt::Display for JanusTokenHashError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotConfigured => write!(f, "janus token hash file is not configured"),
            Self::Read => write!(f, "janus token hash source could not be read"),
            Self::Parse => write!(f, "janus token hash file could not be parsed"),
            Self::UnsupportedSchema => write!(f, "janus token hash file schema is unsupported"),
            Self::EmptyHost => write!(f, "janus token hash file contains an empty host"),
            Self::InvalidHash => write!(f, "janus token hash file contains an invalid hash"),
            Self::DuplicateHost => write!(f, "janus token hash file contains a duplicate host"),
        }
    }
}

fn load_janus_token_hashes(
    sources: &[JanusTokenHashSource],
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    if sources.is_empty() {
        return Err(JanusTokenHashError::NotConfigured);
    }
    let mut hashes = BTreeMap::new();
    for source in sources {
        match source {
            JanusTokenHashSource::File(path) => {
                merge_janus_token_hashes(&mut hashes, load_janus_token_hash_file(path)?)?;
            }
            JanusTokenHashSource::Dir(path) => {
                for path in janus_token_hash_dir_files(path)? {
                    merge_janus_token_hashes(&mut hashes, load_janus_token_hash_file(&path)?)?;
                }
            }
        }
    }
    if hashes.is_empty() {
        return Err(JanusTokenHashError::NotConfigured);
    }
    Ok(hashes)
}

fn janus_token_hash_dir_files(path: &Path) -> Result<Vec<PathBuf>, JanusTokenHashError> {
    let mut files = Vec::new();
    for entry in fs::read_dir(path).map_err(|_| JanusTokenHashError::Read)? {
        let entry = entry.map_err(|_| JanusTokenHashError::Read)?;
        let metadata = entry.metadata().map_err(|_| JanusTokenHashError::Read)?;
        if !metadata.is_file() {
            continue;
        }
        let path = entry.path();
        let Some(file_name) = path.file_name().and_then(|name| name.to_str()) else {
            return Err(JanusTokenHashError::Read);
        };
        if file_name.starts_with('.') {
            continue;
        }
        let is_json = path
            .extension()
            .and_then(|extension| extension.to_str())
            .is_some_and(|extension| extension.eq_ignore_ascii_case("json"));
        if is_json {
            files.push(path);
        }
    }
    files.sort();
    Ok(files)
}

fn merge_janus_token_hashes(
    target: &mut BTreeMap<String, String>,
    next: BTreeMap<String, String>,
) -> Result<(), JanusTokenHashError> {
    for (host, hash) in next {
        if target.insert(host.clone(), hash).is_some() {
            return Err(JanusTokenHashError::DuplicateHost);
        }
    }
    Ok(())
}

fn load_janus_token_hash_file(
    path: &Path,
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    let contents = fs::read_to_string(path).map_err(|_| JanusTokenHashError::Read)?;
    parse_janus_token_hashes(&contents)
}

fn parse_janus_token_hashes(
    contents: &str,
) -> Result<BTreeMap<String, String>, JanusTokenHashError> {
    let payload: JanusTokenHashFile =
        serde_json::from_str(contents).map_err(|_| JanusTokenHashError::Parse)?;
    if let Some(schema) = payload.schema.as_deref() {
        if schema != JANUS_BEACON_TOKEN_HASH_SCHEMA {
            return Err(JanusTokenHashError::UnsupportedSchema);
        }
    }

    let mut hashes = BTreeMap::new();
    for (host, hash) in payload.tokens.into_iter().chain(
        payload
            .hosts
            .into_iter()
            .map(|host| (host.name, host.token_sha256)),
    ) {
        let host = host.trim().to_string();
        let hash = hash.trim().to_ascii_lowercase();
        if host.is_empty() {
            return Err(JanusTokenHashError::EmptyHost);
        }
        if !is_sha256_hex(&hash) {
            return Err(JanusTokenHashError::InvalidHash);
        }
        if hashes.insert(host.clone(), hash).is_some() {
            return Err(JanusTokenHashError::DuplicateHost);
        }
    }
    Ok(hashes)
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "name": "pharosd", "version": env!("CARGO_PKG_VERSION") }))
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rep): Json<HostReport>,
) -> StatusCode {
    if let Err(error) = rep.validate_contract() {
        tracing::warn!(
            host = %rep.name,
            schema = %rep.schema,
            version = rep.version,
            error = %error,
            "report rejected: invalid report contract"
        );
        return StatusCode::BAD_REQUEST;
    }
    if let Some(token) = bearer_token(&headers) {
        match state
            .beacon_auth
            .report_token_status(&state.store, &rep.name, token)
        {
            ReportTokenAuth::Allowed => {}
            ReportTokenAuth::Denied => {
                tracing::warn!(host = %rep.name, "report rejected: invalid bearer token");
                return StatusCode::UNAUTHORIZED;
            }
            ReportTokenAuth::Unavailable(err) => {
                tracing::error!(
                    host = %rep.name,
                    error = %err,
                    "report rejected: beacon token verifier unavailable"
                );
                return StatusCode::SERVICE_UNAVAILABLE;
            }
        }
    } else if state.beacon_auth.require_report_token {
        tracing::warn!(host = %rep.name, "report rejected: missing bearer token");
        return StatusCode::UNAUTHORIZED;
    } else {
        tracing::warn!(
            host = %rep.name,
            "accepting legacy unauthenticated report; migrate this host to PHAROS_TOKEN before enabling strict report auth"
        );
    }
    tracing::info!(host = %rep.name, "report received");
    state.store.record(rep, now_unix());
    StatusCode::NO_CONTENT
}

/// Local host registration for MVP onboarding (PHAROS-8/7). Protected by a
/// deployment-local bootstrap token; the returned beacon token is shown once.
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<HostRegistration>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.beacon_auth.registration_status(&headers) {
        RegistrationAuth::Allowed => {}
        RegistrationAuth::Disabled => {
            return (
                StatusCode::GONE,
                Json(json!({
                    "error": "local registration disabled; use Janus-managed beacon token issuance"
                })),
            );
        }
        RegistrationAuth::Denied => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "registration token invalid" })),
            );
        }
        RegistrationAuth::NotConfigured => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "PHAROS_REGISTRATION_TOKEN not configured" })),
            );
        }
    }

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("failed to generate beacon token: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "token generation failed" })),
            );
        }
    };
    let response = HostRegistrationResponse {
        name: registration.name.clone(),
        token: token.clone(),
    };
    let host = state.store.register(registration, token_hash(&token));
    tracing::info!(host = %host.name, "beacon token issued");
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(response).expect("registration response serializes")),
    )
}

async fn hosts_json(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let runtime_hosts = state.store.list();
    let manifests = manifest_by_host(state.manifests.manifests());
    let hosts: Vec<_> = runtime_hosts
        .into_iter()
        .map(|h| {
            let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
            let freshness_tldr = h.freshness.tldr();
            let attention = attention_reason(live, &h.freshness, &h.service_observations);
            let location = resolve_host_location(
                Some(&h),
                manifests.get(h.name.as_str()).copied(),
                &h.name,
                now,
            );
            json!({
                "name": h.name,
                "role": h.role,
                "is_nix": h.is_nix,
                "report_version": h.report_version,
                "last_seen": h.last_seen,
                "heartbeat_log": h.heartbeat_log,
                "heartbeat_interval_secs": h.heartbeat_interval_secs,
                "liveness": live,
                "location": location_payload(&location),
                "freshness": h.freshness,
                "freshness_tldr": freshness_tldr,
                "service_observations": h.service_observations,
                "service_observations_summary": service_observations_summary(&h.service_observations),
                "attention": {
                    "label": attention.label,
                    "level": attention.level,
                    "rank": attention.rank,
                },
            })
        })
        .collect();
    no_store_json(json!({ "as_of": now, "hosts": hosts }))
}

async fn declared_hosts_json(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let runtime_hosts = state.store.list();
    let server_probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_json(declared_hosts_payload(
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &runtime_hosts,
        &server_probes,
        now,
    ))
}

fn declared_hosts_payload(
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    runtime_hosts: &[Host],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    now: i64,
) -> serde_json::Value {
    let runtime_by_name: BTreeMap<&str, &Host> = runtime_hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let declared_hosts: Vec<_> = manifests
        .iter()
        .map(|manifest| {
            let runtime = runtime_by_name
                .get(manifest.host.name.as_str())
                .copied()
                .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
            let probes = server_probes
                .get(manifest.host.name.as_str())
                .or_else(|| server_probes.get(manifest.slug.as_str()))
                .map(Vec::as_slice)
                .unwrap_or(&[]);
            json!({
                "name": &manifest.host.name,
                "slug": &manifest.slug,
                "declared": manifest,
                "runtime": runtime_overlay(runtime, manifest, probes, now),
            })
        })
        .collect();

    json!({
        "schema": "inspr.pharos.declared-hosts.v1",
        "manifest_schema": HOST_MANIFEST_SCHEMA,
        "manifest_version": HOST_MANIFEST_VERSION,
        "as_of": now,
        "declared_hosts": declared_hosts,
        "load_errors": load_errors,
    })
}

fn runtime_overlay(
    host: Option<&Host>,
    manifest: &HostManifest,
    server_probes: &[ServerProbeObservation],
    now: i64,
) -> serde_json::Value {
    let location = resolve_host_location(host, Some(manifest), &manifest.host.name, now);
    let Some(host) = host else {
        return json!({
            "state": "pending",
            "liveness": Liveness::AwaitingFirstHeartbeat,
            "last_seen": null,
            "heartbeat_log": [],
            "heartbeat_interval_secs": null,
            "location": location_payload(&location),
            "freshness": null,
            "freshness_tldr": null,
            "service_observations": [],
            "service_observations_summary": service_observations_summary(&[]),
            "server_probes": server_probes,
            "server_probes_summary": server_probe_summary(server_probes),
        });
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    json!({
        "state": "observed",
        "report_version": host.report_version,
        "last_seen": host.last_seen,
        "heartbeat_log": host.heartbeat_log,
        "heartbeat_interval_secs": host.heartbeat_interval_secs,
        "liveness": live,
        "location": location_payload(&location),
        "freshness": host.freshness,
        "freshness_tldr": host.freshness.tldr(),
        "service_observations": host.service_observations,
        "service_observations_summary": service_observations_summary(&host.service_observations),
        "server_probes": server_probes,
        "server_probes_summary": server_probe_summary(server_probes),
    })
}

fn no_store_headers() -> [(header::HeaderName, &'static str); 3] {
    [
        (
            header::CACHE_CONTROL,
            "no-store, no-cache, max-age=0, must-revalidate",
        ),
        (header::PRAGMA, "no-cache"),
        (header::EXPIRES, "0"),
    ]
}

fn no_store_html(body: String) -> impl IntoResponse {
    (no_store_headers(), Html(body))
}

fn no_store_json(value: serde_json::Value) -> impl IntoResponse {
    (no_store_headers(), Json(value))
}

async fn home(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    no_store_html(render_home(
        &state.store.list(),
        &self_host(),
        now_unix(),
        state.manifests.manifests(),
        &user_label,
        state.auth.is_some(),
    ))
}

async fn map_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    no_store_html(render_map(
        &hosts,
        &self_host(),
        now_unix(),
        &user_label,
        state.auth.is_some(),
    ))
}

async fn map_data_json(State(state): State<AppState>) -> impl IntoResponse {
    let hosts = state.store.list();
    let now = now_unix();
    let probes = map_connectivity_probes(&hosts, state.manifests.manifests()).await;
    let payload = map_data_payload(
        &hosts,
        &self_host(),
        now,
        state.manifests.manifests(),
        &probes,
    );
    no_store_json(serde_json::to_value(payload).expect("map data serializes"))
}

async fn alerts_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    let now = now_unix();
    let probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_html(render_alerts(
        &hosts,
        &self_host(),
        now,
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &probes,
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
    ))
}

async fn activity_page(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let hosts = state.store.list();
    let now = now_unix();
    let probes = server_probe_overlays(state.manifests.manifests(), now).await;
    no_store_html(render_activity(
        &hosts,
        &self_host(),
        now,
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &probes,
        ShellContext {
            user_label: &user_label,
            logout_enabled: state.auth.is_some(),
        },
    ))
}

async fn fleet_horizon_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        FLEET_HORIZON_PNG,
    )
}

async fn sidebar_lighthouse_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SIDEBAR_LIGHTHOUSE_PNG,
    )
}

async fn favicon_svg() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn url_query_escape(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn manifest_palette_color(manifests: &[HostManifest]) -> BTreeMap<String, String> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        let Some(color) = manifest.palette.as_ref().and_then(|palette| {
            palette
                .accent
                .clone()
                .or_else(|| palette.gradient.get("primary").cloned())
        }) else {
            continue;
        };
        by_host.insert(manifest.host.name.clone(), color.clone());
        by_host.insert(manifest.slug.clone(), color);
    }
    by_host
}

fn freshness_row(label: &str, value: &str, class: &str) -> String {
    format!(
        r#"<div class="fresh-row"><span>{}</span><strong class="{}">{}</strong></div>"#,
        html_escape(label),
        html_escape(class),
        html_escape(value)
    )
}

fn freshness_value(value: Option<u32>, zero_label: &str) -> (String, &'static str) {
    match value {
        Some(0) => (zero_label.to_string(), "ok"),
        Some(v) => (v.to_string(), "warn"),
        None => ("unknown".to_string(), "na"),
    }
}

fn freshness_markup(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return format!(
            "{}{}",
            freshness_row("Flake.lock age", "n/a", "na"),
            freshness_row("Commits behind", "n/a", "na")
        );
    }

    let (mut age, age_class) = freshness_value(freshness.flake_lock_age_days, "fresh");
    if age_class == "warn" {
        age.push('d');
    }
    let (commits, commits_class) = freshness_value(freshness.commits_behind, "0");
    format!(
        "{}{}",
        freshness_row("Flake.lock age", &age, age_class),
        freshness_row("Commits behind", &commits, commits_class)
    )
}

struct AttentionReason {
    label: String,
    level: &'static str,
    rank: u8,
}

fn self_attention_reason() -> AttentionReason {
    AttentionReason {
        label: "Pharos host".to_string(),
        level: "self",
        rank: 4,
    }
}

fn freshness_attention_reason(freshness: &NixFreshness) -> Option<AttentionReason> {
    if !freshness.applicable {
        return None;
    }

    let age_warn = freshness.flake_lock_age_days.filter(|d| *d > 0);
    let commits_warn = freshness.commits_behind.filter(|c| *c > 0);
    let label = match (age_warn, commits_warn) {
        (Some(days), Some(commits)) => format!("nix drift: {days}d · {commits} commits"),
        (Some(days), None) => format!("flake.lock {days}d"),
        (None, Some(commits)) => format!("{commits} commits behind"),
        (None, None) => {
            if freshness.flake_lock_age_days.is_none() || freshness.commits_behind.is_none() {
                "freshness unknown".to_string()
            } else {
                return None;
            }
        }
    };

    Some(AttentionReason {
        label,
        level: if age_warn.is_some() || commits_warn.is_some() {
            "warn"
        } else {
            "wait"
        },
        rank: 3,
    })
}

fn service_observation_attention_reason(
    observations: &[ServiceObservation],
) -> Option<AttentionReason> {
    if observations.is_empty() {
        return None;
    }

    let warnings = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Warning)
        .count();
    if warnings > 0 {
        return Some(AttentionReason {
            label: format!(
                "{warnings} service warning{}",
                if warnings == 1 { "" } else { "s" }
            ),
            level: "warn",
            rank: 3,
        });
    }

    let stale = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Stale)
        .count();
    if stale > 0 {
        return Some(AttentionReason {
            label: format!("{stale} service stale{}", if stale == 1 { "" } else { "s" }),
            level: "warn",
            rank: 3,
        });
    }

    let unknown = observations
        .iter()
        .filter(|obs| obs.state == ServiceObservationState::Unknown)
        .count();
    if unknown > 0 {
        return Some(AttentionReason {
            label: format!("{unknown} service unknown"),
            level: "wait",
            rank: 3,
        });
    }

    None
}

fn service_observations_summary(observations: &[ServiceObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => warning += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let label = if observations.is_empty() {
        "not observed".to_string()
    } else if warning > 0 {
        format!("{warning} warning{}", if warning == 1 { "" } else { "s" })
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "healthy".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct ServerProbeObservation {
    id: String,
    service: String,
    source: &'static str,
    policy: &'static str,
    kind: &'static str,
    target: Option<String>,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    client_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
}

async fn server_probe_overlays(
    manifests: &[HostManifest],
    now: i64,
) -> BTreeMap<String, Vec<ServerProbeObservation>> {
    let mut overlays = BTreeMap::new();
    for manifest in manifests {
        let mut observations = Vec::new();
        for service in &manifest.services {
            if should_server_probe(service) {
                observations.push(server_probe_service(service, now).await);
            }
        }
        if !observations.is_empty() {
            overlays.insert(manifest.host.name.clone(), observations);
        }
    }
    overlays
}

async fn server_probe_service(service: &ManifestService, now: i64) -> ServerProbeObservation {
    let Some(raw_url) = server_probe_url(service) else {
        return server_probe_observation(
            service,
            None,
            ServiceObservationState::Unknown,
            None,
            "no server-probe URL declared".to_string(),
            now,
        );
    };

    let url = match Url::parse(&raw_url) {
        Ok(url) => url,
        Err(_) => {
            return server_probe_observation(
                service,
                Some(raw_url),
                ServiceObservationState::Unknown,
                None,
                "server-probe URL is invalid".to_string(),
                now,
            );
        }
    };
    let target = sanitized_probe_target(&url);

    if !matches!(url.scheme(), "http" | "https") {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server probe supports http/https targets only".to_string(),
            now,
        );
    }

    let Some(host) = url.host_str() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no host".to_string(),
            now,
        );
    };
    let Some(port) = url.port_or_known_default() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no port".to_string(),
            now,
        );
    };

    match timeout(SERVER_PROBE_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Healthy,
            Some(true),
            format!("server can reach {host}:{port}"),
            now,
        ),
        Ok(Err(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server cannot reach {host}:{port}"),
            now,
        ),
        Err(_) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server probe timed out for {host}:{port}"),
            now,
        ),
    }
}

fn server_probe_observation(
    service: &ManifestService,
    target: Option<String>,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
) -> ServerProbeObservation {
    ServerProbeObservation {
        id: service_probe_id(service),
        service: service.name.clone(),
        source: "server",
        policy: "pharos-runtime",
        kind: "tcp-connect",
        target,
        state,
        server_reachable,
        client_reachable: None,
        summary,
        checked_at,
    }
}

fn should_server_probe(service: &ManifestService) -> bool {
    explicit_server_probe_policy_opt(service.probe.as_ref())
        || (service.status_policy.source == ManifestStatusSource::PharosRuntime
            && !service.passive
            && server_probe_url(service).is_some())
}

fn explicit_server_probe_policy_opt(policy: Option<&ManifestProbePolicy>) -> bool {
    policy.is_some_and(explicit_server_probe_policy)
}

fn explicit_server_probe_policy(policy: &ManifestProbePolicy) -> bool {
    match policy {
        ManifestProbePolicy::Named(name) => matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "server" | "server-probe" | "pharos" | "pharos-runtime"
        ),
        ManifestProbePolicy::Enabled(_) => false,
    }
}

fn server_probe_url(service: &ManifestService) -> Option<String> {
    ["tailnet", "lanHostname", "lanIp"]
        .into_iter()
        .find_map(|key| service.urls.get(key).filter(|url| !url.is_empty()).cloned())
        .or_else(|| service.url.as_ref().filter(|url| !url.is_empty()).cloned())
}

fn sanitized_probe_target(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    format!("{}://{host}{port}{path}", url.scheme())
}

fn server_probe_summary(observations: &[ServerProbeObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => warning += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let label = if observations.is_empty() {
        "not probed".to_string()
    } else if warning > 0 {
        format!("{warning} unreachable")
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "server reachable".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

fn service_probe_id(service: &ManifestService) -> String {
    let mut id = String::new();
    for ch in service.name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            id.push(ch);
        } else if !id.ends_with('-') {
            id.push('-');
        }
    }
    id.trim_matches('-').to_string()
}

fn attention_reason(
    live: Liveness,
    freshness: &NixFreshness,
    observations: &[ServiceObservation],
) -> AttentionReason {
    match live {
        Liveness::Down => AttentionReason {
            label: "silent heartbeat".to_string(),
            level: "down",
            rank: 0,
        },
        Liveness::Stale => AttentionReason {
            label: "stale heartbeat".to_string(),
            level: "warn",
            rank: 1,
        },
        Liveness::AwaitingFirstHeartbeat => AttentionReason {
            label: "awaiting first beat".to_string(),
            level: "wait",
            rank: 2,
        },
        Liveness::Live => freshness_attention_reason(freshness)
            .or_else(|| service_observation_attention_reason(observations))
            .unwrap_or_else(|| AttentionReason {
                label: "all clear".to_string(),
                level: "ok",
                rank: 4,
            }),
    }
}

fn reason_markup(reason: &AttentionReason) -> String {
    format!(
        r#"<div class="reason {}" data-reason><span>{}</span></div>"#,
        html_escape(reason.level),
        html_escape(&reason.label)
    )
}

fn live_key(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "live",
        Liveness::Stale => "stale",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "awaiting_first_heartbeat",
    }
}

fn icon_with_class(svg: &str, class: &str) -> String {
    svg.replacen("class=\"ico\"", &format!("class=\"ico {class}\""), 1)
}

fn status_icon_stack() -> String {
    format!(
        "{}{}{}{}",
        icon_with_class(icons::status_svg(Liveness::Live), "state-icon live"),
        icon_with_class(icons::status_svg(Liveness::Stale), "state-icon stale"),
        icon_with_class(icons::status_svg(Liveness::Down), "state-icon down"),
        icon_with_class(
            icons::status_svg(Liveness::AwaitingFirstHeartbeat),
            "state-icon awaiting"
        )
    )
}

fn duration_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn clock_label(timestamp: i64) -> String {
    let seconds = timestamp.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn summary_cards(hosts: &[Host], _self_name: &str, now: i64) -> String {
    let total = hosts.len();
    let mut live = 0;
    let mut stale = 0;
    let mut down = 0;
    for h in hosts {
        let live_state = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        match live_state {
            Liveness::Live => live += 1,
            Liveness::Stale => stale += 1,
            Liveness::Down => down += 1,
            Liveness::AwaitingFirstHeartbeat => {}
        }
    }
    format!(
        r#"<section class="summary" aria-label="host summary"><button class="metric" type="button" data-live-filter="all" aria-pressed="true"><b>{total}</b><span>All hosts</span></button><button class="metric live" type="button" data-live-filter="live" aria-pressed="false"><b>{live}</b><span>Live</span></button><button class="metric stale" type="button" data-live-filter="stale" aria-pressed="false"><b>{stale}</b><span>Stale</span></button><button class="metric down" type="button" data-live-filter="down" aria-pressed="false"><b>{down}</b><span>Down</span></button></section>"#
    )
}

fn sidebar_user_label(auth: &AuthState, headers: &HeaderMap) -> String {
    auth.as_ref()
        .and_then(|auth| auth.current_user(headers))
        .map(|user| user.display_name)
        .unwrap_or_else(|| {
            if auth.is_some() {
                "signed in".to_string()
            } else {
                "local access".to_string()
            }
        })
}

fn sidebar(user_label: &str, logout_enabled: bool, active: &str) -> String {
    let logout = if logout_enabled {
        format!(
            r#"<a class="side-logout" href="/auth/logout" title="Log out of Pharos" aria-label="Log out of Pharos">{}</a>"#,
            icons::LOG_OUT
        )
    } else {
        String::new()
    };
    let fleet_current = if active == "fleet" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let map_current = if active == "map" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let alerts_current = if active == "alerts" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let activity_current = if active == "activity" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let settings_current = if active == "settings" {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r##"<aside class="sidebar" aria-label="primary navigation"><div class="side-brand"><span class="side-mark">{lighthouse}</span><span class="side-logo">PHAROS</span></div><nav class="side-nav"><a class="side-link" href="/"{fleet_current}>{fleet}<span>Fleet</span></a><a class="side-link" href="/map"{map_current}>{map}<span>Map</span></a><a class="side-link" href="/alerts"{alerts_current}>{alerts}<span>Alerts</span></a><a class="side-link" href="/activity"{activity_current}>{activity}<span>Activity</span></a><a class="side-link" href="/agora"{settings_current}>{settings}<span>Settings</span></a></nav><div class="side-foot"><span class="side-user" title="{user_title}"><span>{user_label}</span></span>{logout}</div></aside>"##,
        lighthouse = icons::LIGHTHOUSE,
        fleet = icons::GRID,
        map = icons::SERVER,
        alerts = icons::status_svg(Liveness::Stale),
        activity = icons::LIST,
        settings = icons::SLIDERS,
        fleet_current = fleet_current,
        map_current = map_current,
        alerts_current = alerts_current,
        activity_current = activity_current,
        settings_current = settings_current,
        user_label = html_escape(user_label),
        user_title = html_escape(user_label),
        logout = logout
    )
}

fn page_header(title: &str, subtitle: &str, now: i64) -> String {
    format!(
        r#"<div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>{title}</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">{subtitle}</p></div><div class="asof" data-as-of>as of {as_of}</div></div>"#,
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        as_of = clock_label(now)
    )
}

fn header(now: i64) -> String {
    page_header("Fleet", "All hosts at a glance", now)
}

#[derive(Debug, Clone, Copy)]
struct ShellContext<'a> {
    user_label: &'a str,
    logout_enabled: bool,
}

fn search_box(placeholder: &str) -> String {
    format!(
        r#"<label class="search">{search}<input data-search type="search" autocomplete="off" placeholder="{placeholder}"></label>"#,
        search = icons::SEARCH,
        placeholder = html_escape(placeholder)
    )
}

fn toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="fleet controls"><div class="toolbar-left"><div class="seg" role="group" aria-label="view"><button type="button" data-view-button="grid" aria-pressed="true" title="Grid view">{grid}</button><button type="button" data-view-button="list" aria-pressed="false" title="List view">{list}</button></div><label class="arrange">Arrange by <select data-sort aria-label="arrange by"><option value="attention">Needs attention</option><option value="name">Name</option><option value="last">Last change</option><option value="freeform">Freeform</option></select></label></div><div class="toolbar-right">{search}</div></section>"#,
        grid = icons::GRID,
        list = icons::LIST,
        search = search_box("Search hosts...")
    )
}

fn map_toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="map controls"><div class="toolbar-left"><span class="arrange">All servers stay visible unless filtered</span></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

fn onboard_command() -> String {
    format!(
        r#"<code class="onboard-command">{icon}<span>inspr onboard &lt;host&gt;</span></code>"#,
        icon = icons::TERMINAL
    )
}

fn empty_state() -> String {
    format!(
        r#"<section class="empty-state" aria-label="first run"><div class="empty-copy"><span class="empty-kicker">first light</span><h2>Waiting for the first host</h2><p>Register a host and Pharos will hold it in the grey awaiting state until the first real heartbeat arrives.</p>{command}</div><div class="empty-visual" aria-hidden="true"><span class="empty-sun"></span><span class="empty-line"></span><span class="empty-lighthouse">{lighthouse}</span><span class="empty-await">awaiting first heartbeat</span></div></section>"#,
        command = onboard_command(),
        lighthouse = icons::LIGHTHOUSE
    )
}

fn lone_host_state() -> String {
    format!(
        r#"<aside class="lone-state" aria-label="lone host state"><span class="lone-mark">{lighthouse}</span><div class="lone-copy"><span class="lone-kicker">one light</span><strong>First host is on the map</strong><p>The fleet view is ready for the next onboarded machine.</p></div>{command}</aside>"#,
        lighthouse = icons::LIGHTHOUSE,
        command = onboard_command()
    )
}

fn heartbeat_samples(log: &[i64], last_seen: Option<i64>) -> Vec<i64> {
    let mut samples = log.to_vec();
    if samples.is_empty() {
        if let Some(last) = last_seen {
            samples.push(last);
        }
    }
    samples.sort_unstable();
    samples.dedup();
    samples
}

struct HeartbeatSignal {
    text: String,
    level: &'static str,
    window: &'static str,
    title: String,
}

fn heartbeat_signal(
    log: &[i64],
    last_seen: Option<i64>,
    interval: i64,
    now: i64,
    window_label: &'static str,
    window_secs: i64,
) -> HeartbeatSignal {
    let samples = heartbeat_samples(log, last_seen);
    if samples.is_empty() {
        return HeartbeatSignal {
            text: "new".to_string(),
            level: "wait",
            window: window_label,
            title: format!("Signal over {window_label}: waiting for first heartbeat"),
        };
    };

    let interval = interval.max(1);
    let window_secs = window_secs.max(interval);
    let requested_start = now - window_secs;
    let retained_start = samples
        .first()
        .copied()
        .map(|oldest| oldest.max(requested_start))
        .unwrap_or(requested_start);
    let span = (now - retained_start).max(interval).min(window_secs);
    let expected = ((span + interval - 1) / interval).max(1) as usize;
    let received = samples
        .iter()
        .filter(|stamp| **stamp >= retained_start && **stamp <= now)
        .count();
    let mut previous = retained_start;
    let mut longest_gap = samples
        .last()
        .copied()
        .map(|latest| (now - latest).max(0).min(span))
        .unwrap_or(span);
    for stamp in samples
        .iter()
        .copied()
        .filter(|stamp| *stamp >= retained_start && *stamp <= now)
    {
        longest_gap = longest_gap.max(stamp - previous);
        previous = stamp;
    }
    longest_gap = longest_gap.max(now - previous);

    let percent = (((received * 100) + (expected / 2)) / expected).min(100);
    let level = if percent >= 95 {
        "good"
    } else if percent >= 75 {
        "warn"
    } else {
        "down"
    };
    HeartbeatSignal {
        text: format!("{percent}%"),
        level,
        window: window_label,
        title: format!(
            "Signal over {window_label}: {received} of {expected} expected heartbeats received · longest gap {}{}",
            duration_label(longest_gap),
            if retained_start > requested_start {
                format!(" · retained {}", duration_label(span))
            } else {
                String::new()
            }
        ),
    }
}

fn signal_markup(signal: &HeartbeatSignal) -> String {
    let title = html_escape(&signal.title);
    format!(
        r#"<span class="signal" data-signal data-signal-level="{level}" data-signal-window-key="{window}" title="{title}" aria-label="{title}"><span data-signal-percent>{text}</span><span class="signal-orb" aria-hidden="true"></span><button class="signal-window" type="button" data-signal-window title="{title}">{window}</button></span>"#,
        level = html_escape(signal.level),
        text = html_escape(&signal.text),
        window = html_escape(signal.window),
    )
}

fn head_with_extra(extra: &str) -> String {
    HEAD.replacen("</style></head>", &format!("</style>{extra}</head>"), 1)
}

const LOCATION_STALE_AFTER_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq)]
struct SiteLocation {
    id: String,
    label: String,
    region: String,
    lat: f64,
    lon: f64,
    source: HostLocationSource,
    mode: &'static str,
    state: &'static str,
    stale: bool,
    manual_override: bool,
    observed_at: Option<i64>,
    accuracy_meters: Option<f64>,
    precision_meters: Option<f64>,
}

impl SiteLocation {
    fn from_site(site: &str, source: HostLocationSource) -> Self {
        let (id, label, region, lat, lon) = match site {
            "cloud" | "cloud-de" => ("cloud-de", "Cloud", "Germany", 50.1109, 8.6821),
            "home" | "home-at" => ("home-at", "Home", "Austria", 48.2082, 16.3738),
            "ww87" | "parents-home" => ("ww87", "Parents' home", "Austria", 48.32, 15.92),
            "parents-in-law" => ("parents-in-law", "Parents-in-law", "Austria", 48.13, 15.18),
            "dsc" | "dsc0" | "dsc-us" | "hillsboro-or" => {
                ("dsc-us", "DSC", "Hillsboro, OR, US", 45.5229, -122.9898)
            }
            _ => ("unknown", "Unknown site", "Not declared", 46.8, 8.2),
        };
        Self {
            id: id.to_string(),
            label: label.to_string(),
            region: region.to_string(),
            lat,
            lon,
            source,
            mode: "auto",
            state: if id == "unknown" { "unknown" } else { "known" },
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }

    fn from_host_location(
        location: &HostLocation,
        fallback_label: impl Into<String>,
        fallback_region: impl Into<String>,
        mode: &'static str,
        state: &'static str,
        now: i64,
    ) -> Self {
        let stale = location_stale(location, now);
        let label = location
            .label
            .clone()
            .unwrap_or_else(|| fallback_label.into());
        let region = fallback_region.into();
        let id = format!(
            "{}:{:.4},{:.4}",
            location_source_key(location.source),
            location.latitude,
            location.longitude
        );
        Self {
            id,
            label,
            region,
            lat: location.latitude,
            lon: location.longitude,
            source: location.source,
            mode,
            state: if stale { "stale" } else { state },
            stale,
            manual_override: location.manual_override,
            observed_at: location.observed_at,
            accuracy_meters: location.accuracy_meters,
            precision_meters: location.precision_meters,
        }
    }

    fn hidden() -> Self {
        Self {
            id: "hidden".to_string(),
            label: "Location hidden".to_string(),
            region: "Not shown".to_string(),
            lat: 46.8,
            lon: 8.2,
            source: HostLocationSource::Unknown,
            mode: "hidden",
            state: "hidden",
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MapProbeTarget {
    endpoint: Option<(String, u16)>,
    kind: &'static str,
    policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct MapSignal {
    label: String,
    level: &'static str,
    title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
struct MapHost {
    name: String,
    role: String,
    live: &'static str,
    status: &'static str,
    attention: String,
    search: String,
    site_id: String,
    site_label: String,
    region: String,
    lat: f64,
    lon: f64,
    location_source: &'static str,
    location_state: &'static str,
    location_stale: bool,
    location_manual_override: bool,
    location: serde_json::Value,
    is_pharos: bool,
    inbound_label: String,
    inbound_level: &'static str,
    inbound_title: String,
    outbound_label: String,
    outbound_level: &'static str,
    outbound_title: String,
    outbound_policy: &'static str,
    settings_href: String,
}

#[derive(Debug, Clone, Serialize)]
struct MapDataPayload {
    schema: &'static str,
    as_of: i64,
    hosts: Vec<MapHost>,
}

fn site_location(site: &str) -> SiteLocation {
    SiteLocation::from_site(site, HostLocationSource::Provider)
}

fn fallback_site_location(host: &str) -> SiteLocation {
    SiteLocation::from_site(fallback_site_for_host(host), HostLocationSource::Fallback)
}

fn location_source_key(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

fn location_source_label(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi | HostLocationSource::Ip => "auto",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

fn location_stale(location: &HostLocation, now: i64) -> bool {
    if location.stale {
        return true;
    }
    location
        .observed_at
        .is_some_and(|observed| now.saturating_sub(observed) > LOCATION_STALE_AFTER_SECS)
}

fn location_payload(location: &SiteLocation) -> serde_json::Value {
    json!({
        "latitude": location.lat,
        "longitude": location.lon,
        "source": location_source_key(location.source),
        "mode": location.mode,
        "state": location.state,
        "stale": location.stale,
        "manual_override": location.manual_override,
        "observed_at": location.observed_at,
        "accuracy_meters": location.accuracy_meters,
        "precision_meters": location.precision_meters,
        "label": location.label,
        "region": location.region,
        "site_id": location.id,
    })
}

fn resolve_host_location(
    host: Option<&Host>,
    manifest: Option<&HostManifest>,
    host_name: &str,
    now: i64,
) -> SiteLocation {
    let mode = manifest
        .map(|manifest| manifest.host.location_mode)
        .unwrap_or_default();
    if mode == ManifestLocationMode::Hidden {
        return SiteLocation::hidden();
    }

    let provider = manifest
        .and_then(|manifest| {
            manifest
                .host
                .site
                .as_deref()
                .filter(|site| !site.trim().is_empty())
        })
        .map(site_location);

    let declared_location = manifest.and_then(|manifest| manifest.host.location.as_ref());

    if let Some(location) = declared_location.filter(|location| {
        mode == ManifestLocationMode::DeclaredOverride
            || (mode == ManifestLocationMode::Auto && location.manual_override)
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-override",
            "declared",
            now,
        );
    }

    if let Some(location) = host.and_then(|host| host.location.as_ref()) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "observed",
            "observed",
            now,
        );
    }

    if let Some(location) = declared_location.filter(|_| {
        matches!(
            mode,
            ManifestLocationMode::DeclaredFallback | ManifestLocationMode::Auto
        )
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-fallback",
            "declared",
            now,
        );
    }

    provider.unwrap_or_else(|| fallback_site_location(host_name))
}

fn fallback_site_for_host(host: &str) -> &'static str {
    match host {
        "csb0" | "csb1" => "cloud-de",
        "hsb0" | "hsb1" | "gpc0" => "home-at",
        "hsb8" => "ww87",
        "hsb9" => "parents-in-law",
        "dsc0" => "dsc-us",
        _ => "unknown",
    }
}

fn manifest_by_host(manifests: &[HostManifest]) -> BTreeMap<&str, &HostManifest> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        by_host.insert(manifest.host.name.as_str(), manifest);
        by_host.insert(manifest.slug.as_str(), manifest);
    }
    by_host
}

fn split_probe_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(trimmed) {
        let host = url.host_str()?.trim().to_string();
        if host.is_empty() {
            return None;
        }
        return Some((host, url.port_or_known_default().unwrap_or(default_port)));
    }
    let target = trimmed
        .trim_start_matches("//")
        .split('/')
        .next()
        .unwrap_or(trimmed)
        .trim();
    if target.is_empty() {
        return None;
    }
    if let Some((host, port)) = target.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
    }
    Some((target.to_string(), default_port))
}

fn normalize_outbound_policy(policy: &str) -> Option<&'static str> {
    match policy.trim().to_ascii_lowercase().as_str() {
        "expected" | "reachable" | "allow" | "allowed" | "required" => Some("expected"),
        "blocked" | "deny" | "denied" | "intentional-block" | "intentional_block" => {
            Some("blocked")
        }
        "unknown" | "probe" | "best-effort" | "best_effort" => Some("unknown"),
        _ => None,
    }
}

fn manifest_outbound_policy(host: &str, manifests: &[HostManifest]) -> Option<&'static str> {
    let manifests = manifest_by_host(manifests);
    let manifest = manifests.get(host)?;
    [
        "pharosOutbound",
        "pharosOutboundPolicy",
        "pharosConnectivity",
    ]
    .into_iter()
    .find_map(|key| manifest.host.access.get(key))
    .and_then(|value| normalize_outbound_policy(value))
}

fn outbound_policy_for_host(host: &Host, manifests: &[HostManifest]) -> &'static str {
    manifest_outbound_policy(&host.name, manifests).unwrap_or("unknown")
}

fn map_probe_target(host: &Host, manifests: &[HostManifest]) -> MapProbeTarget {
    let policy = outbound_policy_for_host(host, manifests);
    if policy == "blocked" {
        return MapProbeTarget {
            endpoint: None,
            kind: "tailnet ssh",
            policy,
        };
    }
    let manifests = manifest_by_host(manifests);
    if let Some(manifest) = manifests.get(host.name.as_str()) {
        if let Some(tailnet) = manifest.host.tailnet_hostname() {
            if let Some((host, port)) = split_probe_host_port(tailnet, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "tailnet ssh",
                    policy,
                };
            }
        }
        if let Some(lan) = manifest.host.lan_hostname() {
            if let Some((host, port)) = split_probe_host_port(lan, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
        if let Some(ip) = manifest.host.lan_ip() {
            if let Some((host, port)) = split_probe_host_port(ip, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
    }
    MapProbeTarget {
        endpoint: Some((format!("{}.ts.barta.cm", host.name), 2222)),
        kind: "tailnet ssh",
        policy,
    }
}

fn default_map_signal() -> MapSignal {
    MapSignal {
        label: "checking".to_string(),
        level: "wait",
        title: "Pharos reachability check is pending".to_string(),
        policy: None,
    }
}

async fn map_connectivity_probe(target: MapProbeTarget) -> MapSignal {
    let Some((host, port)) = target.endpoint else {
        return MapSignal {
            label: if target.policy == "blocked" {
                "blocked".to_string()
            } else {
                "unknown".to_string()
            },
            level: "wait",
            title: if target.policy == "blocked" {
                "Outbound access from Pharos is blocked by policy".to_string()
            } else {
                "No outbound probe endpoint declared".to_string()
            },
            policy: Some(target.policy),
        };
    };
    let started = Instant::now();
    match timeout(
        SERVER_PROBE_TIMEOUT,
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => {
            let elapsed_ms = started.elapsed().as_millis().max(1);
            MapSignal {
                label: format!("{elapsed_ms} ms"),
                level: "good",
                title: format!(
                    "Pharos {kind} check to {host}:{port} reachable in {elapsed_ms} ms",
                    kind = target.kind,
                    host = host,
                    port = port
                ),
                policy: Some(target.policy),
            }
        }
        Ok(Err(_)) => MapSignal {
            label: "no route".to_string(),
            level: if target.policy == "expected" {
                "down"
            } else {
                "warn"
            },
            title: format!(
                "Pharos {kind} check to {host}:{port} failed",
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
        Err(_) => MapSignal {
            label: "timeout".to_string(),
            level: "warn",
            title: format!(
                "Pharos {kind} check to {host}:{port} timed out after {} ms",
                SERVER_PROBE_TIMEOUT.as_millis(),
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
    }
}

async fn map_connectivity_probes(
    hosts: &[Host],
    manifests: &[HostManifest],
) -> BTreeMap<String, MapSignal> {
    let mut jobs = JoinSet::new();
    for host in hosts {
        let name = host.name.clone();
        let target = map_probe_target(host, manifests);
        jobs.spawn(async move { (name, map_connectivity_probe(target).await) });
    }
    let mut probes = BTreeMap::new();
    while let Some(result) = jobs.join_next().await {
        if let Ok((name, probe)) = result {
            probes.insert(name, probe);
        }
    }
    probes
}

fn map_inbound_signal(host: &Host, is_pharos: bool, now: i64) -> MapSignal {
    if is_pharos {
        return MapSignal {
            label: "local".to_string(),
            level: "good",
            title: "Pharos is the local control host".to_string(),
            policy: None,
        };
    }
    let Some(last_seen) = host.last_seen else {
        return MapSignal {
            label: "waiting".to_string(),
            level: "wait",
            title: "No heartbeat from this host has reached Pharos yet".to_string(),
            policy: None,
        };
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    let level = match live {
        Liveness::Live => "good",
        Liveness::Stale => "warn",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "wait",
    };
    let age = (now - last_seen).max(0);
    MapSignal {
        label: duration_label(age),
        level,
        title: format!(
            "Last heartbeat from {} reached Pharos {} ago",
            host.name,
            duration_label(age)
        ),
        policy: None,
    }
}

fn map_hosts(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
) -> Vec<MapHost> {
    let manifests = manifest_by_host(manifests);
    let mut mapped = hosts
        .iter()
        .map(|host| {
            let is_pharos = host.name == self_name;
            let mut live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
            if is_pharos {
                live = Liveness::Live;
            }
            let (_color, status) = live.badge();
            let attention = if host.name == self_name {
                self_attention_reason()
            } else {
                attention_reason(live, &host.freshness, &host.service_observations)
            };
            let site = resolve_host_location(
                Some(host),
                manifests.get(host.name.as_str()).copied(),
                &host.name,
                now,
            );
            let inbound = map_inbound_signal(host, is_pharos, now);
            let outbound = probes
                .get(&host.name)
                .cloned()
                .unwrap_or_else(default_map_signal);
            let search = format!(
                "{} {} {} {} {} {} {} {} {}",
                host.name,
                host.role,
                status,
                attention.label,
                site.label,
                site.region,
                location_source_key(site.source),
                location_source_label(site.source),
                outbound.label
            )
            .to_lowercase();
            let location = location_payload(&site);
            MapHost {
                name: host.name.clone(),
                role: host.role.clone(),
                live: live_key(live),
                status,
                attention: attention.label,
                search,
                site_id: site.id,
                site_label: site.label,
                region: site.region,
                lat: site.lat,
                lon: site.lon,
                location_source: location_source_key(site.source),
                location_state: site.state,
                location_stale: site.stale,
                location_manual_override: site.manual_override,
                location,
                is_pharos,
                inbound_label: inbound.label,
                inbound_level: inbound.level,
                inbound_title: inbound.title,
                outbound_label: outbound.label,
                outbound_level: outbound.level,
                outbound_title: outbound.title,
                outbound_policy: outbound.policy.unwrap_or("unknown"),
                settings_href: format!("/agora?host={}", url_query_escape(&host.name)),
            }
        })
        .collect::<Vec<_>>();
    mapped.sort_by(|a, b| {
        a.site_label
            .cmp(&b.site_label)
            .then_with(|| a.name.cmp(&b.name))
    });
    mapped
}

fn map_data_payload(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
) -> MapDataPayload {
    MapDataPayload {
        schema: "inspr.pharos.map-data.v1",
        as_of: now,
        hosts: map_hosts(hosts, self_name, now, manifests, probes),
    }
}

#[derive(Debug, Clone)]
struct AlertItem {
    level: &'static str,
    host: String,
    role: String,
    issue: String,
    detail: String,
    source: &'static str,
    seen: String,
    next_action: String,
    sort_time: i64,
}

#[derive(Debug, Clone)]
struct AlertGroup {
    level: &'static str,
    hosts: Vec<(String, String)>,
    issue: String,
    detail: String,
    source: &'static str,
    seen: String,
    next_action: String,
    sort_time: i64,
    count: usize,
}

#[derive(Debug, Clone)]
struct ActivityEvent {
    timestamp: i64,
    host: String,
    level: &'static str,
    kind: &'static str,
    title: String,
    detail: String,
    source: &'static str,
}

impl ActivityEvent {
    fn new(
        timestamp: i64,
        host: impl Into<String>,
        level: &'static str,
        kind: &'static str,
        title: impl Into<String>,
        detail: impl Into<String>,
        source: &'static str,
    ) -> Self {
        Self {
            timestamp,
            host: host.into(),
            level,
            kind,
            title: title.into(),
            detail: detail.into(),
            source,
        }
    }
}

fn level_rank(level: &str) -> usize {
    match level {
        "critical" => 0,
        "warning" => 1,
        "watch" => 2,
        "recovery" => 3,
        "info" => 4,
        "clear" => 5,
        _ => 6,
    }
}

fn level_label(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "warning" => "warning",
        "watch" => "watch",
        "recovery" => "recovery",
        "info" => "info",
        "clear" => "clear",
        _ => "info",
    }
}

fn seen_label(last_seen: Option<i64>, now: i64) -> String {
    match last_seen {
        Some(seen) => format!("{} ago", duration_label(now - seen)),
        None => "never".to_string(),
    }
}

fn freshness_alert(freshness: &NixFreshness) -> Option<(&'static str, String, String)> {
    if !freshness.applicable {
        return None;
    }

    let age = freshness.flake_lock_age_days;
    let commits = freshness.commits_behind;
    if age.is_none() || commits.is_none() {
        return Some((
            "watch",
            "Freshness is only partially observed".to_string(),
            "Confirm the beacon can read nixcfg freshness.".to_string(),
        ));
    }

    let days = age.unwrap_or(0);
    let behind = commits.unwrap_or(0);
    if behind > 0 || days >= 30 {
        return Some((
            "warning",
            freshness.tldr(),
            "Review nixcfg, then update or deploy when safe.".to_string(),
        ));
    }
    if days > 0 {
        return Some((
            "watch",
            freshness.tldr(),
            "Consider a normal flake update during the next maintenance window.".to_string(),
        ));
    }
    None
}

fn service_alert(host: &Host, observation: &ServiceObservation, now: i64) -> Option<AlertItem> {
    if is_nix_freshness_observation(observation) {
        return None;
    }

    let (level, action) = match observation.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning => ("warning", "Inspect the service on the host."),
        ServiceObservationState::Stale => ("warning", "Verify the service is still reporting."),
        ServiceObservationState::Unknown => {
            ("watch", "Confirm whether this service should report state.")
        }
    };
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!("{}: {}", observation.label, observation.state.label()),
        detail: observation.summary.clone(),
        source: "service",
        seen: seen_label(host.last_seen, now),
        next_action: action.to_string(),
        sort_time: host.last_seen.unwrap_or(now),
    })
}

fn is_nix_freshness_observation(observation: &ServiceObservation) -> bool {
    observation.id == "nix-freshness" || observation.label.eq_ignore_ascii_case("Nix freshness")
}

fn probe_alert(host: &str, role: &str, probe: &ServerProbeObservation) -> Option<AlertItem> {
    let (level, action) = match probe.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning => (
            "warning",
            "Check the service route, firewall, or probe target.",
        ),
        ServiceObservationState::Stale => ("warning", "Re-check the service probe path."),
        ServiceObservationState::Unknown => ("watch", "Complete the service probe declaration."),
    };
    Some(AlertItem {
        level,
        host: host.to_string(),
        role: role.to_string(),
        issue: format!("{} probe {}", probe.service, probe.state.label()),
        detail: probe.summary.clone(),
        source: "probe",
        seen: format!("as of {}", clock_label(probe.checked_at)),
        next_action: action.to_string(),
        sort_time: probe.checked_at,
    })
}

fn alert_items(
    hosts: &[Host],
    _self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
) -> Vec<AlertItem> {
    let mut alerts = Vec::new();
    let runtime_by_name: BTreeMap<&str, &Host> = hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let manifest_roles: BTreeMap<&str, &str> = manifests
        .iter()
        .map(|manifest| {
            (
                manifest.host.name.as_str(),
                manifest.host.role.as_deref().unwrap_or("declared host"),
            )
        })
        .collect();

    for issue in load_errors {
        alerts.push(AlertItem {
            level: "critical",
            host: "Pharos".to_string(),
            role: "manifest loader".to_string(),
            issue: "Declared host manifest failed to load".to_string(),
            detail: format!("{} - {}", issue.path, issue.error),
            source: "config",
            seen: format!("as of {}", clock_label(now)),
            next_action: "Fix the manifest and restart or reload Pharos.".to_string(),
            sort_time: now,
        });
    }

    for manifest in manifests {
        let runtime = runtime_by_name
            .get(manifest.host.name.as_str())
            .copied()
            .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
        if runtime.is_none() {
            alerts.push(AlertItem {
                level: "watch",
                host: manifest.host.name.clone(),
                role: manifest
                    .host
                    .role
                    .clone()
                    .unwrap_or_else(|| "declared host".to_string()),
                issue: "Declared host has not reported yet".to_string(),
                detail:
                    "The host exists in declared metadata, but no runtime heartbeat is present."
                        .to_string(),
                source: "config",
                seen: "never".to_string(),
                next_action: "Install or start pharos-beacon, or remove stale metadata."
                    .to_string(),
                sort_time: now,
            });
        }
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        match live {
            Liveness::Down => alerts.push(AlertItem {
                level: "critical",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "No heartbeat received".to_string(),
                detail: "Pharos has not received a report within the allowed heartbeat window."
                    .to_string(),
                source: "heartbeat",
                seen: seen_label(host.last_seen, now),
                next_action: "Check host power, network, and pharos-beacon.".to_string(),
                sort_time: host.last_seen.unwrap_or(now),
            }),
            Liveness::Stale => alerts.push(AlertItem {
                level: "warning",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Heartbeat is late".to_string(),
                detail: "The host checked in later than its normal cadence.".to_string(),
                source: "heartbeat",
                seen: seen_label(host.last_seen, now),
                next_action: "Verify pharos-beacon and recent host load.".to_string(),
                sort_time: host.last_seen.unwrap_or(now),
            }),
            Liveness::AwaitingFirstHeartbeat => alerts.push(AlertItem {
                level: "watch",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Waiting for first heartbeat".to_string(),
                detail: "The host is registered but has not sent a first report.".to_string(),
                source: "heartbeat",
                seen: "never".to_string(),
                next_action: "Finish onboarding or confirm the host should exist.".to_string(),
                sort_time: now,
            }),
            Liveness::Live => {}
        }

        if let Some((level, issue, action)) = freshness_alert(&host.freshness) {
            alerts.push(AlertItem {
                level,
                host: host.name.clone(),
                role: host.role.clone(),
                issue,
                detail: "Nix freshness differs from the preferred declared state.".to_string(),
                source: "freshness",
                seen: seen_label(host.last_seen, now),
                next_action: action,
                sort_time: host.last_seen.unwrap_or(now),
            });
        }

        for observation in &host.service_observations {
            if let Some(alert) = service_alert(host, observation, now) {
                alerts.push(alert);
            }
        }
    }

    for (host, probes) in server_probes {
        let role = runtime_by_name
            .get(host.as_str())
            .map(|host| host.role.as_str())
            .or_else(|| manifest_roles.get(host.as_str()).copied())
            .unwrap_or("declared service");
        for probe in probes {
            if let Some(alert) = probe_alert(host, role, probe) {
                alerts.push(alert);
            }
        }
    }

    alerts.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.source.cmp(right.source))
    });
    alerts
}

fn alert_counts(alerts: &[AlertItem], hosts: &[Host]) -> (usize, usize, usize, usize) {
    let critical = alerts
        .iter()
        .filter(|alert| alert.level == "critical")
        .count();
    let warning = alerts
        .iter()
        .filter(|alert| alert.level == "warning")
        .count();
    let watch = alerts.iter().filter(|alert| alert.level == "watch").count();
    let affected: std::collections::BTreeSet<&str> = alerts
        .iter()
        .filter(|alert| alert.host != "Pharos")
        .map(|alert| alert.host.as_str())
        .collect();
    let clear = hosts.len().saturating_sub(affected.len());
    (critical, warning, watch, clear)
}

fn alert_groups(alerts: &[AlertItem]) -> Vec<AlertGroup> {
    let mut groups: Vec<AlertGroup> = Vec::new();

    for alert in alerts {
        if let Some(group) = groups.iter_mut().find(|group| {
            group.level == alert.level
                && group.source == alert.source
                && group.issue == alert.issue
                && group.detail == alert.detail
                && group.next_action == alert.next_action
        }) {
            group.count += 1;
            if !group.hosts.iter().any(|(host, _)| host == &alert.host) {
                group.hosts.push((alert.host.clone(), alert.role.clone()));
            }
            if alert.sort_time >= group.sort_time {
                group.sort_time = alert.sort_time;
                group.seen = alert.seen.clone();
            }
        } else {
            groups.push(AlertGroup {
                level: alert.level,
                hosts: vec![(alert.host.clone(), alert.role.clone())],
                issue: alert.issue.clone(),
                detail: alert.detail.clone(),
                source: alert.source,
                seen: alert.seen.clone(),
                next_action: alert.next_action.clone(),
                sort_time: alert.sort_time,
                count: 1,
            });
        }
    }

    for group in &mut groups {
        group.hosts.sort_by(|left, right| left.0.cmp(&right.0));
    }
    groups.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.issue.cmp(&right.issue))
            .then_with(|| left.source.cmp(right.source))
    });
    groups
}

fn ops_summary_metrics(alerts: &[AlertItem], hosts: &[Host]) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    format!(
        r#"<section class="ops-summary" aria-label="alert summary"><button class="ops-metric critical" type="button" data-ops-filter="critical" aria-pressed="false"><b>{critical}</b><span>critical</span></button><button class="ops-metric warning" type="button" data-ops-filter="warning" aria-pressed="false"><b>{warning}</b><span>warning</span></button><button class="ops-metric watch" type="button" data-ops-filter="watch" aria-pressed="false"><b>{watch}</b><span>watch</span></button><button class="ops-metric clear" type="button" data-ops-filter="clear" aria-pressed="false"><b>{clear}</b><span>clear</span></button></section>"#
    )
}

fn alert_group_host_label(group: &AlertGroup) -> (String, String) {
    if group.hosts.len() == 1 {
        return group.hosts[0].clone();
    }

    let mut names = group
        .hosts
        .iter()
        .take(3)
        .map(|(host, _)| host.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if group.hosts.len() > 3 {
        names.push_str(&format!(" +{} more", group.hosts.len() - 3));
    }
    (format!("{} hosts", group.hosts.len()), names)
}

fn alert_group_host_search(group: &AlertGroup) -> String {
    let mut parts = Vec::new();
    for (host, role) in &group.hosts {
        parts.push(host.as_str());
        parts.push(role.as_str());
    }
    parts.push(group.issue.as_str());
    parts.push(group.detail.as_str());
    parts.push(group.source);
    parts.join(" ").to_lowercase()
}

fn render_alert_row(group: &AlertGroup) -> String {
    let (host_label, host_detail) = alert_group_host_label(group);
    let repeat = if group.count > 1 {
        format!(
            r#"<span class="alert-repeat">{count} alerts</span>"#,
            count = group.count
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="alert-row {level}" data-ops-row data-ops-level="{level}" data-ops-kind="{source}" data-host-search="{host_search}"><div class="alert-host"><span class="alert-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{role}</span></div></div><div class="alert-status"><span class="severity">{level_label}</span>{repeat}</div><div class="alert-issue"><strong>{issue}</strong><p>{detail}</p></div><span class="ops-source">{source}</span><span class="ops-time">{seen}</span><span class="next-action">{next_action}</span></article>"#,
        level = html_escape(group.level),
        level_label = level_label(group.level),
        repeat = repeat,
        host = html_escape(&host_label),
        role = html_escape(&host_detail),
        issue = html_escape(&group.issue),
        detail = html_escape(&group.detail),
        source = html_escape(group.source),
        seen = html_escape(&group.seen),
        next_action = html_escape(&group.next_action),
        host_search = html_escape(&alert_group_host_search(group))
    )
}

fn render_alert_rows(groups: &[AlertGroup]) -> String {
    if groups.is_empty() {
        return r#"<section class="ops-empty"><h2>All clear</h2><p>No host, freshness, service, probe, or manifest alert needs attention right now.</p></section>"#.to_string();
    }
    groups.iter().map(render_alert_row).collect()
}

fn posture_panel(alerts: &[AlertItem], hosts: &[Host]) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    let total_alerts = alerts.len().max(1);
    let (posture_label, posture_color, posture_count, posture_filter) = if critical > 0 {
        ("critical", "var(--down)", critical, "critical")
    } else if warning > 0 {
        ("warning", "var(--stale)", warning, "warning")
    } else if watch > 0 {
        ("watch", "var(--sun)", watch, "watch")
    } else {
        ("clear", "var(--live)", clear, "clear")
    };
    let posture_fill = if alerts.is_empty() {
        100
    } else {
        ((posture_count * 100) / total_alerts).clamp(8, 100)
    };
    format!(
        r#"<aside class="ops-side-panel" aria-label="operations posture"><div><h2>Operations posture</h2><p>Most important work first.</p></div><button class="posture-ring" type="button" data-ops-filter="{posture_filter}" aria-pressed="false" style="--posture-fill:{posture_fill}%;--posture-color:{posture_color}"><div><strong>{posture_count}</strong><span>{posture_label}</span></div></button><div class="posture-list"><button class="posture-chip critical" type="button" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="posture-chip warning" type="button" data-ops-filter="warning" aria-pressed="false">warning {warning}</button><button class="posture-chip watch" type="button" data-ops-filter="watch" aria-pressed="false">watch {watch}</button><button class="posture-chip clear" type="button" data-ops-filter="clear" aria-pressed="false">clear {clear}</button><button class="posture-chip info" type="button" data-ops-filter="all" aria-pressed="true">show all</button></div><div class="ops-note">Repeated alerts are grouped. Use the host search and severity controls to focus the queue.</div><a class="ops-action" href="/map">View on map</a></aside>"#
    )
}

fn render_alerts(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    let alerts = alert_items(hosts, self_name, now, manifests, load_errors, server_probes);
    let groups = alert_groups(&alerts);
    let rows = render_alert_rows(&groups);
    format!(
        r#"{HEAD}{sidebar}<main class="ops-main" data-ops-page="alerts">{header}{summary}{toolbar}<section class="ops-layout"><section class="ops-panel" aria-label="attention queue"><header class="ops-panel-head"><div><h2>Needs attention</h2><p>Plain-language queue from heartbeat, freshness, service, probe, and config state.</p></div><span class="ops-count">{count}</span></header><div class="alert-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching alerts.</section></section>{posture}</section></main>{script}</div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "alerts"),
        header = page_header("Alerts", "Needs attention", now),
        summary = ops_summary_metrics(&alerts, hosts),
        toolbar = ops_toolbar(),
        count = alerts.len(),
        posture = posture_panel(&alerts, hosts),
        script = ops_script()
    )
}

fn ops_toolbar() -> String {
    format!(
        r#"<section class="toolbar ops-toolbar" aria-label="operations filters"><div class="toolbar-left"><button class="activity-filter info" type="button" data-ops-filter="all" aria-pressed="true">Show all</button></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

fn ops_script() -> &'static str {
    r#"<script>
document.querySelectorAll('[data-ops-page]').forEach(root=>{
  const search=root.querySelector('[data-search]');
  const rows=[...root.querySelectorAll('[data-ops-row]')];
  const empty=root.querySelector('[data-ops-empty]');
  let active='all';
  function setFilter(filter){
    active=filter||'all';
    root.querySelectorAll('[data-ops-filter]').forEach(button=>{
      button.setAttribute('aria-pressed',String((button.dataset.opsFilter||'all')===active));
    });
    apply();
  }
  function apply(){
    const query=(search?.value||'').trim().toLowerCase();
    let visible=0;
    rows.forEach(row=>{
      const filterOk=active==='all'||row.dataset.opsLevel===active||row.dataset.opsKind===active;
      const haystack=(row.dataset.hostSearch||row.textContent||'').toLowerCase();
      const searchOk=!query||haystack.includes(query);
      const show=filterOk&&searchOk;
      row.hidden=!show;
      if(show)visible++;
    });
    if(empty)empty.dataset.visible=String(visible===0&&rows.length>0);
  }
  root.querySelectorAll('[data-ops-filter]').forEach(button=>{
    button.addEventListener('click',()=>setFilter(button.dataset.opsFilter||'all'));
  });
  search?.addEventListener('input',apply);
  setFilter('all');
});
</script>"#
}

fn activity_events(
    hosts: &[Host],
    _self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
) -> Vec<ActivityEvent> {
    let mut events = Vec::new();

    for issue in load_errors {
        events.push(ActivityEvent::new(
            now,
            "Pharos",
            "critical",
            "config",
            "Manifest load failed",
            format!("{} - {}", issue.path, issue.error),
            "config",
        ));
    }

    for manifest in manifests {
        events.push(ActivityEvent::new(
            now,
            manifest.host.name.clone(),
            "info",
            "config",
            "Declared host manifest loaded",
            format!("{} declared services", manifest.services.len()),
            "config",
        ));
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        match live {
            Liveness::Down => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "critical",
                "heartbeat",
                "No heartbeat received",
                format!("Last report was {}", seen_label(host.last_seen, now)),
                "heartbeat",
            )),
            Liveness::Stale => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "warning",
                "heartbeat",
                "Heartbeat lateness detected",
                format!("Last report was {}", seen_label(host.last_seen, now)),
                "heartbeat",
            )),
            Liveness::AwaitingFirstHeartbeat => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "watch",
                "heartbeat",
                "Awaiting first heartbeat",
                "Host exists but has not reported yet.",
                "heartbeat",
            )),
            Liveness::Live => {}
        }

        let samples = heartbeat_samples(&host.heartbeat_log, host.last_seen);
        for stamp in samples.iter().rev().take(4) {
            events.push(ActivityEvent::new(
                *stamp,
                host.name.clone(),
                "info",
                "heartbeat",
                "Heartbeat received",
                format!("{} checked in at {}", host.name, clock_label(*stamp)),
                "heartbeat",
            ));
        }

        if let Some((level, issue, _action)) = freshness_alert(&host.freshness) {
            events.push(ActivityEvent::new(
                host.last_seen.unwrap_or(now),
                host.name.clone(),
                level,
                "freshness",
                "Freshness drift detected",
                issue,
                "freshness",
            ));
        }

        for observation in &host.service_observations {
            if is_nix_freshness_observation(observation) {
                continue;
            }

            if observation.state == ServiceObservationState::Healthy {
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    "info",
                    "service",
                    format!("{} is healthy", observation.label),
                    observation.summary.clone(),
                    "service",
                ));
            } else {
                let level = match observation.state {
                    ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                    ServiceObservationState::Unknown => "watch",
                    ServiceObservationState::Healthy => "info",
                };
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    level,
                    "service",
                    format!("{} {}", observation.label, observation.state.label()),
                    observation.summary.clone(),
                    "service",
                ));
            }
        }
    }

    for (host, probes) in server_probes {
        for probe in probes {
            let level = match probe.state {
                ServiceObservationState::Healthy => "info",
                ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                ServiceObservationState::Unknown => "watch",
            };
            events.push(ActivityEvent::new(
                probe.checked_at,
                host.clone(),
                level,
                "service",
                format!("{} probe {}", probe.service, probe.state.label()),
                probe.summary.clone(),
                "probe",
            ));
        }
    }

    events.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| level_rank(left.level).cmp(&level_rank(right.level)))
            .then_with(|| left.host.cmp(&right.host))
    });
    events
}

fn activity_source_count(events: &[ActivityEvent], kind: &str) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

fn activity_summary_metrics(events: &[ActivityEvent]) -> String {
    let heartbeat = activity_source_count(events, "heartbeat");
    let freshness = activity_source_count(events, "freshness");
    let service = activity_source_count(events, "service");
    format!(
        r#"<section class="ops-summary" aria-label="activity summary"><button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true"><b>{total}</b><span>all events</span></button><button class="ops-metric clear" type="button" data-ops-filter="heartbeat" aria-pressed="false"><b>{heartbeat}</b><span>heartbeat</span></button><button class="ops-metric watch" type="button" data-ops-filter="freshness" aria-pressed="false"><b>{freshness}</b><span>freshness</span></button><button class="ops-metric warning" type="button" data-ops-filter="service" aria-pressed="false"><b>{service}</b><span>service</span></button></section>"#,
        total = events.len()
    )
}

fn activity_filter_bar(events: &[ActivityEvent]) -> String {
    let config = activity_source_count(events, "config");
    let critical = events
        .iter()
        .filter(|event| event.level == "critical")
        .count();
    let warning = events
        .iter()
        .filter(|event| event.level == "warning")
        .count();
    format!(
        r#"<div class="activity-filters" role="group" aria-label="activity filters"><button class="activity-filter info" type="button" data-activity-filter="all" data-ops-filter="all" aria-pressed="true">All events {total}</button><button class="activity-filter clear" type="button" data-activity-filter="heartbeat" data-ops-filter="heartbeat" aria-pressed="false">Heartbeat {heartbeat}</button><button class="activity-filter watch" type="button" data-activity-filter="freshness" data-ops-filter="freshness" aria-pressed="false">Freshness {freshness}</button><button class="activity-filter warning" type="button" data-activity-filter="service" data-ops-filter="service" aria-pressed="false">Service {service}</button><button class="activity-filter info" type="button" data-activity-filter="config" data-ops-filter="config" aria-pressed="false">Config {config}</button><button class="activity-filter critical" type="button" data-activity-filter="critical" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="activity-filter warning" type="button" data-activity-filter="warning" data-ops-filter="warning" aria-pressed="false">warning {warning}</button></div>"#,
        total = events.len(),
        heartbeat = activity_source_count(events, "heartbeat"),
        freshness = activity_source_count(events, "freshness"),
        service = activity_source_count(events, "service"),
    )
}

fn render_activity_row(event: &ActivityEvent) -> String {
    format!(
        r#"<article class="activity-row {level}" data-ops-row data-activity-kind="{kind}" data-activity-level="{level}" data-ops-kind="{kind}" data-ops-level="{level}" data-host-search="{host_search}"><span class="ops-time">{time}</span><div class="activity-host"><span class="activity-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{kind}</span></div></div><span class="severity">{level_label}</span><div class="activity-copy"><strong>{title}</strong><p>{detail}</p></div><span class="ops-source">{source}</span></article>"#,
        level = html_escape(event.level),
        kind = html_escape(event.kind),
        time = html_escape(&clock_label(event.timestamp)),
        host = html_escape(&event.host),
        level_label = level_label(event.level),
        title = html_escape(&event.title),
        detail = html_escape(&event.detail),
        source = html_escape(event.source),
        host_search = html_escape(
            &format!(
                "{} {} {} {} {}",
                event.host, event.kind, event.title, event.detail, event.source
            )
            .to_lowercase(),
        )
    )
}

fn activity_rows(events: &[ActivityEvent]) -> String {
    if events.is_empty() {
        return r#"<section class="ops-empty"><h2>No activity yet</h2><p>Once hosts report, Pharos will show heartbeats, freshness changes, service observations, and config events here.</p></section>"#.to_string();
    }
    events.iter().take(80).map(render_activity_row).collect()
}

fn activity_script() -> &'static str {
    ops_script()
}

fn render_activity(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    let events = activity_events(hosts, self_name, now, manifests, load_errors, server_probes);
    let rows = activity_rows(&events);
    format!(
        r#"{HEAD}{sidebar}<main class="ops-main" data-ops-page="activity">{header}{summary}{toolbar}<section class="ops-panel" aria-label="operational timeline"><header class="ops-panel-head"><div><h2>Operational timeline</h2><p>Reverse chronological history from heartbeat, freshness, service, and config signals.</p></div><span class="ops-count">{count}</span></header><div style="padding:14px 16px;border-bottom:1px solid rgba(214,226,234,.72)">{filters}</div><div class="activity-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching activity.</section></section><div class="ops-note" style="margin-top:14px">Activity is derived from current retained Pharos state. It is not an audit log yet; it shows the recent operational picture Pharos can prove now.</div></main>{script}</div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "activity"),
        header = page_header("Activity", "Operational timeline", now),
        summary = activity_summary_metrics(&events),
        toolbar = ops_toolbar(),
        count = events.len(),
        filters = activity_filter_bar(&events),
        script = activity_script()
    )
}

fn render_map(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    user_label: &str,
    logout_enabled: bool,
) -> String {
    let summary = summary_cards(hosts, self_name, now);
    let toolbar = map_toolbar();
    let map_script = r#"<script>
const MAP_DATA_URL='/map/data.json';
const MAP_LEAFLET_CSS='https://unpkg.com/leaflet@1.9.4/dist/leaflet.css';
const MAP_LEAFLET_JS='https://unpkg.com/leaflet@1.9.4/dist/leaflet.js';
const MAP_D3_JS='https://unpkg.com/d3@7.9.0/dist/d3.min.js';
let MAP_HOSTS=[];
let applyMapFilterNow=null;
let pendingMapFilter={q:'',live:'all'};
function escapeHtml(value){return String(value).replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]))}
function stateVar(live){return live==='awaiting_first_heartbeat'?'wait':live}
function locationSourceLabel(source){
  switch(source){
    case 'wifi':
    case 'ip':
      return 'auto';
    case 'declared':
      return 'declared';
    case 'provider':
      return 'provider';
    case 'fallback':
      return 'fallback';
    default:
      return 'unknown';
  }
}
function locationSourceTitle(host){
  const label=locationSourceLabel(host.location_source);
  const stale=host.location_stale?'stale ':'';
  const state=host.location_state&&host.location_state!=='observed'?' · '+host.location_state:'';
  return stale+label+' location'+state;
}
function loadStylesheet(href){
  if(document.querySelector('link[href="'+href+'"]'))return Promise.resolve();
  return new Promise((resolve,reject)=>{
    const tag=document.createElement('link');
    tag.rel='stylesheet';
    tag.href=href;
    tag.onload=resolve;
    tag.onerror=()=>reject(new Error('stylesheet failed'));
    document.head.appendChild(tag);
  });
}
function loadScript(src,ready){
  if(ready&&ready())return Promise.resolve();
  if(document.querySelector('script[src="'+src+'"]')){
    return new Promise(resolve=>{
      const check=()=>ready&&ready()?resolve():setTimeout(check,30);
      check();
    });
  }
  return new Promise((resolve,reject)=>{
    const tag=document.createElement('script');
    tag.src=src;
    tag.async=true;
    tag.onload=resolve;
    tag.onerror=()=>reject(new Error('script failed'));
    document.head.appendChild(tag);
  });
}
async function loadMapAssets(){
  await loadStylesheet(MAP_LEAFLET_CSS);
  await loadScript(MAP_LEAFLET_JS,()=>Boolean(window.L));
  await loadScript(MAP_D3_JS,()=>Boolean(window.d3));
}
async function loadMapData(){
  const res=await fetch(MAP_DATA_URL+'?refresh='+Date.now(),{headers:{Accept:'application/json'},cache:'no-store',credentials:'same-origin'});
  if(!res.ok)throw new Error('map data failed');
  const data=await res.json();
  if(!data||!Array.isArray(data.hosts))throw new Error('map data malformed');
  return data;
}
function setMapLoading(state,message){
  const panel=document.getElementById('map-panel');
  const sitePanel=document.querySelector('[data-site-panel]');
  const note=document.querySelector('[data-map-note]');
  const text=document.querySelector('[data-map-status-message]');
  if(panel)panel.dataset.loading=state==='loading'?'true':'false';
  if(panel)panel.dataset.mapState=state;
  if(sitePanel)sitePanel.dataset.loading=state==='loading'?'true':'false';
  if(note&&message)note.textContent=message;
  if(text&&message)text.textContent=message;
}
function siteSkeleton(){
  return '<div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line long"></span><span class="site-skel-line medium"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line medium"></span><span class="site-skel-line long"></span><span class="site-skel-line short"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line medium"></span><span class="site-skel-line long"></span></div>';
}
function siteError(message){
  return '<div class="site-error"><strong>Locations unavailable</strong><span>'+escapeHtml(message||'Map data could not be loaded. Try refreshing this view.')+'</span></div>';
}
function siteHostHtml(host){
  const style='--host-state:var(--'+escapeHtml(stateVar(host.live))+')';
  const sourceLabel=locationSourceLabel(host.location_source);
  const sourceTitle=locationSourceTitle(host);
  return '<a class="site-host" href="'+escapeHtml(host.settings_href)+'" data-host="'+escapeHtml(host.name)+'" data-live="'+escapeHtml(host.live)+'" data-search="'+escapeHtml(host.search||'')+'" style="'+style+'" title="'+escapeHtml(host.name+': '+host.attention+'; '+sourceTitle+'; '+host.inbound_title+'; '+host.outbound_title)+'"><span class="site-host-name">'+escapeHtml(host.name)+'</span><span class="site-host-signals"><span class="site-host-ping" data-probe-level="'+escapeHtml(host.inbound_level)+'">in '+escapeHtml(host.inbound_label)+'</span><span class="site-host-ping" data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">out '+escapeHtml(host.outbound_label)+'</span><span class="site-host-source" data-location-source="'+escapeHtml(host.location_source)+'" data-location-state="'+escapeHtml(host.location_state)+'" title="'+escapeHtml(sourceTitle)+'">'+escapeHtml(sourceLabel)+'</span></span></a>';
}
function renderSiteList(hosts){
  const target=document.querySelector('[data-site-list]');
  if(!target)return;
  if(!hosts.length){
    target.innerHTML='<div class="site-error"><strong>No mapped hosts</strong><span>Pharos has no host locations to show yet.</span></div>';
    return;
  }
  const bySite=new Map();
  hosts.forEach(host=>{
    const key=host.site_id||'unknown';
    if(!bySite.has(key))bySite.set(key,[]);
    bySite.get(key).push(host);
  });
  const sections=Array.from(bySite.values()).sort((a,b)=>String(a[0].site_label).localeCompare(String(b[0].site_label))).map(siteHosts=>{
    siteHosts.sort((a,b)=>String(a.name).localeCompare(String(b.name)));
    const first=siteHosts[0];
    return '<section class="site-item"><div class="site-head"><div><strong>'+escapeHtml(first.site_label)+'</strong><p>'+escapeHtml(first.region)+'</p></div><span class="site-count">'+siteHosts.length+'</span></div><div class="site-hosts">'+siteHosts.map(siteHostHtml).join('')+'</div></section>';
  });
  target.innerHTML=sections.join('');
}
function nodeHtml(host){const sourceLabel=locationSourceLabel(host.location_source);const sourceTitle=locationSourceTitle(host);return '<span class="map-status-dot" aria-hidden="true"></span><span class="map-name">'+escapeHtml(host.name)+'</span><span class="map-signals"><span class="map-ping" data-dir="in" data-probe-level="'+escapeHtml(host.inbound_level)+'">'+escapeHtml(host.inbound_label)+'</span><span class="map-ping" data-dir="out" data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">'+escapeHtml(host.outbound_label)+'</span></span><span class="map-source" data-location-source="'+escapeHtml(host.location_source)+'" data-location-state="'+escapeHtml(host.location_state)+'" title="'+escapeHtml(sourceTitle)+'">'+escapeHtml(sourceLabel)+'</span>'}
function groupOffsets(hosts){
  const groups=new Map();
  hosts.forEach(host=>{
    const key=Number(host.lat).toFixed(4)+','+Number(host.lon).toFixed(4);
    if(!groups.has(key))groups.set(key,[]);
    groups.get(key).push(host.name);
  });
  return groups;
}
function seedOffset(index,count){
  if(count<=1)return {x:34,y:-28};
  const angle=(-Math.PI/2)+(index/count)*Math.PI*2;
  const radius=42+Math.min(count,6)*6;
  return {x:Math.cos(angle)*radius,y:Math.sin(angle)*radius};
}
function clamp(value,min,max){return Math.max(min,Math.min(max,value))}
function forceBounds(nodes,width,height){
  return function(){
    for(const d of nodes){
      d.x=clamp(d.x,d.w/2+8,width-d.w/2-8);
      d.y=clamp(d.y,d.h/2+8,height-d.h/2-8);
    }
  }
}
function svgEl(name){return document.createElementNS('http://www.w3.org/2000/svg',name)}
function curvePath(a,b){
  const dx=b.ax-a.ax;
  const dy=b.ay-a.ay;
  const mx=(a.ax+b.ax)/2;
  const my=(a.ay+b.ay)/2;
  const len=Math.max(1,Math.hypot(dx,dy));
  const bend=Math.min(70,Math.max(18,len*.12));
  const cx=mx+(-dy/len)*bend;
  const cy=my+(dx/len)*bend;
  return 'M '+a.ax.toFixed(1)+' '+a.ay.toFixed(1)+' Q '+cx.toFixed(1)+' '+cy.toFixed(1)+' '+b.ax.toFixed(1)+' '+b.ay.toFixed(1);
}
function addPacket(path,id,dir,level,policy,reverse){
  const circle=svgEl('circle');
  circle.setAttribute('r','3');
  circle.classList.add('map-packet',dir);
  circle.dataset.level=level;
  circle.dataset.policy=policy||'unknown';
  const motion=svgEl('animateMotion');
  motion.setAttribute('dur',dir==='inbound'?'3.6s':'2.8s');
  motion.setAttribute('repeatCount','indefinite');
  motion.setAttribute('calcMode','linear');
  if(reverse){
    motion.setAttribute('keyPoints','1;0');
    motion.setAttribute('keyTimes','0;1');
  }
  const mpath=svgEl('mpath');
  mpath.setAttribute('href','#'+id);
  motion.appendChild(mpath);
  circle.appendChild(motion);
  path.parentNode.appendChild(circle);
  return circle;
}
function mapHostMatches(host,q,live){return (q===''||String(host.search||'').includes(q))&&(live==='all'||host.live===live)}
function buildLabels(map,el){
  const layer=document.createElement('div');
  layer.className='map-label-layer';
  const links=svgEl('svg');
  links.classList.add('map-links');
  const leaders=svgEl('svg');
  leaders.classList.add('map-leaders');
  layer.appendChild(links);
  layer.appendChild(leaders);
  el.appendChild(layer);
  const groups=groupOffsets(MAP_HOSTS);
  const seen=new Map();
  const nodes=MAP_HOSTS.map((host,idx)=>{
    const key=Number(host.lat).toFixed(4)+','+Number(host.lon).toFixed(4);
    const groupIndex=seen.get(key)||0;
    seen.set(key,groupIndex+1);
    const anchor=document.createElement('span');
    anchor.className='map-anchor '+escapeHtml(host.live);
    const link=document.createElement('a');
    link.className='map-node '+escapeHtml(host.live);
    link.href=host.settings_href;
    link.dataset.host=host.name;
    link.dataset.live=host.live;
    link.dataset.search=host.search||'';
    link.dataset.mapLayer='managed';
    link.innerHTML=nodeHtml(host);
    link.title=host.name+': '+host.status+'; '+locationSourceTitle(host)+'; '+host.inbound_title+'; '+host.outbound_title;
    link.setAttribute('aria-label',host.name+', '+host.status+', '+locationSourceTitle(host)+', inbound '+host.inbound_label+', outbound '+host.outbound_label);
    const line=svgEl('line');
    leaders.appendChild(line);
    layer.appendChild(anchor);
    layer.appendChild(link);
    return {host,idx,anchor,link,line,groupIndex,groupCount:(groups.get(key)||[]).length,visible:true,w:100,h:38,r:58,x:0,y:0,ax:0,ay:0};
  });
  const pharosNode=nodes.find(node=>node.host.is_pharos)||nodes[0];
  const linksByHost=nodes.filter(node=>node!==pharosNode).map((node,idx)=>{
    const path=svgEl('path');
    const id='map-link-'+idx;
    path.id=id;
    path.classList.add('map-link');
    path.dataset.inboundLevel=node.host.inbound_level;
    path.dataset.outboundLevel=node.host.outbound_level;
    path.dataset.outboundPolicy=node.host.outbound_policy;
    links.appendChild(path);
    const packets=[];
    if(node.host.inbound_level!=='wait')packets.push(addPacket(path,id,'inbound',node.host.inbound_level,node.host.outbound_policy,true));
    if(node.host.outbound_level==='good')packets.push(addPacket(path,id,'outbound',node.host.outbound_level,node.host.outbound_policy,false));
    return {node,path,packets};
  });
  let scheduled=false;
  function layout(){
    scheduled=false;
    const width=el.clientWidth||800;
    const height=el.clientHeight||520;
    links.setAttribute('viewBox','0 0 '+width+' '+height);
    leaders.setAttribute('viewBox','0 0 '+width+' '+height);
    const visibleNodes=nodes.filter(node=>node.visible!==false);
    nodes.filter(node=>node.visible===false).forEach(node=>{
      node.anchor.hidden=true;
      node.link.hidden=true;
      node.line.style.opacity='0';
    });
    visibleNodes.forEach(node=>{
      const point=map.latLngToContainerPoint([node.host.lat,node.host.lon]);
      const offset=seedOffset(node.groupIndex,node.groupCount);
      node.ax=point.x;
      node.ay=point.y;
      node.anchor.hidden=false;
      node.link.hidden=false;
      node.anchor.style.left=point.x+'px';
      node.anchor.style.top=point.y+'px';
      node.link.style.transform='translate(-1000px,-1000px)';
      const rect=node.link.getBoundingClientRect();
      node.w=rect.width||110;
      node.h=rect.height||54;
      node.r=Math.sqrt(node.w*node.w+node.h*node.h)/2+10;
      node.x=clamp(point.x+offset.x,node.w/2+8,width-node.w/2-8);
      node.y=clamp(point.y+offset.y,node.h/2+8,height-node.h/2-8);
    });
    if(window.d3&&d3.forceSimulation){
      const simulation=d3.forceSimulation(visibleNodes)
        .force('x',d3.forceX(d=>d.ax+seedOffset(d.groupIndex,d.groupCount).x).strength(.18))
        .force('y',d3.forceY(d=>d.ay+seedOffset(d.groupIndex,d.groupCount).y).strength(.18))
        .force('collide',d3.forceCollide(d=>d.r).strength(1))
        .force('bounds',forceBounds(visibleNodes,width,height))
        .stop();
      for(let i=0;i<90;i++)simulation.tick();
    }
    visibleNodes.forEach(node=>{
      node.x=clamp(node.x,node.w/2+8,width-node.w/2-8);
      node.y=clamp(node.y,node.h/2+8,height-node.h/2-8);
      const left=node.x-node.w/2;
      const top=node.y-node.h/2;
      node.link.style.transform='translate('+left.toFixed(1)+'px,'+top.toFixed(1)+'px)';
      const distance=Math.hypot(node.x-node.ax,node.y-node.ay);
      node.line.setAttribute('x1',node.ax);
      node.line.setAttribute('y1',node.ay);
      node.line.setAttribute('x2',node.x);
      node.line.setAttribute('y2',node.y);
      node.line.style.opacity=distance>22?'.55':'0';
    });
    if(pharosNode){
      linksByHost.forEach(link=>{
        const visible=pharosNode.visible!==false&&link.node.visible!==false;
        link.path.style.display=visible?'':'none';
        link.packets.forEach(packet=>{packet.style.display=visible?'':'none'});
        if(!visible)return;
        link.path.setAttribute('d',curvePath(pharosNode,link.node));
      });
    }
  }
  function scheduleLayout(){
    if(scheduled)return;
    scheduled=true;
    requestAnimationFrame(layout);
  }
  map.on('move zoom moveend zoomend resize viewreset',scheduleLayout);
  window.addEventListener('resize',scheduleLayout);
  applyMapFilterNow=(q='',live='all')=>{
    nodes.forEach(node=>{
      node.visible=mapHostMatches(node.host,q,live);
    });
    scheduleLayout();
  };
  window.pharosMapApplyFilter=(q='',live='all')=>{
    pendingMapFilter={q,live};
    applyMapFilterNow(q,live);
  };
  applyMapFilterNow(pendingMapFilter.q,pendingMapFilter.live);
  scheduleLayout();
  return scheduleLayout;
}
function fullscreenElement(){return document.fullscreenElement||document.webkitFullscreenElement||null}
function requestFullscreen(el){
  if(el.requestFullscreen)return el.requestFullscreen();
  if(el.webkitRequestFullscreen)return el.webkitRequestFullscreen();
  return Promise.reject(new Error('Fullscreen is not supported'));
}
function exitFullscreen(){
  if(document.exitFullscreen)return document.exitFullscreen();
  if(document.webkitExitFullscreen)return document.webkitExitFullscreen();
  return Promise.resolve();
}
const MAP_VIEWPORT_STORAGE='pharos.map.viewport.v1';
const MAP_MODE_STORAGE='pharos.map.mode.v1';
const MAP_LABEL_DENSITY_STORAGE='pharos.map.labelDensity.v1';
function storageGet(key){try{return window.localStorage.getItem(key)}catch(_){return null}}
function storageSet(key,value){try{window.localStorage.setItem(key,value)}catch(_){}}
function storedMapMode(){
  const value=storageGet(MAP_MODE_STORAGE);
  return value==='maximized'?'maximized':'standard';
}
function storeMapMode(mode){
  storageSet(MAP_MODE_STORAGE,mode==='standard'?'standard':'maximized');
}
function storedMapLabelDensity(){
  return storageGet(MAP_LABEL_DENSITY_STORAGE)==='compact'?'compact':'normal';
}
function storeMapLabelDensity(density){
  storageSet(MAP_LABEL_DENSITY_STORAGE,density==='compact'?'compact':'normal');
}
function storedViewport(){
  try{
    const raw=storageGet(MAP_VIEWPORT_STORAGE);
    if(!raw)return null;
    const parsed=JSON.parse(raw);
    const lat=Number(parsed.lat);
    const lon=Number(parsed.lon);
    const zoom=Number(parsed.zoom);
    if(!Number.isFinite(lat)||!Number.isFinite(lon)||!Number.isFinite(zoom))return null;
    if(lat<-90||lat>90||lon<-180||lon>180||zoom<0||zoom>20)return null;
    return {lat,lon,zoom};
  }catch(_){
    return null;
  }
}
function storeViewport(map){
  const center=map.getCenter();
  storageSet(MAP_VIEWPORT_STORAGE,JSON.stringify({
    lat:Number(center.lat.toFixed(5)),
    lon:Number(center.lng.toFixed(5)),
    zoom:map.getZoom()
  }));
}
function setupMapModes(map,el,relayout){
  const panel=document.getElementById('map-panel');
  const layout=document.querySelector('[data-map-layout]');
  const main=document.querySelector('[data-map-view]');
  const buttons=Array.from(document.querySelectorAll('[data-map-mode-button]'));
  const densityButton=document.querySelector('[data-map-density-button]');
  if(!panel||!layout||!main||!buttons.length)return;
  let mode='standard';
  let beforeFullscreen='standard';
  function resizeSoon(){
    const run=()=>{map.invalidateSize();relayout&&relayout()};
    requestAnimationFrame(run);
    window.setTimeout(run,90);
    window.setTimeout(run,260);
  }
  function setPressed(next){
    buttons.forEach(button=>{
      const active=button.dataset.mapModeButton===next;
      button.setAttribute('aria-pressed',active?'true':'false');
    });
  }
  function commit(next){
    mode=next;
    panel.dataset.mode=next;
    layout.dataset.mode=next==='fullscreen'?'maximized':next;
    main.dataset.mapView=next==='standard'?'standard':'maximized';
    setPressed(next);
    storeMapMode(next);
    resizeSoon();
  }
  function setMode(next){
    if(next==='fullscreen'){
      beforeFullscreen=mode==='fullscreen'?'standard':mode;
      commit('fullscreen');
      requestFullscreen(panel).catch(()=>commit('maximized'));
      return;
    }
    if(fullscreenElement()===panel){
      exitFullscreen().catch(()=>{});
    }
    commit(next);
  }
  buttons.forEach(button=>{
    button.addEventListener('click',()=>setMode(button.dataset.mapModeButton||'standard'));
  });
  function setDensity(next){
    const density=next==='compact'?'compact':'normal';
    panel.dataset.labelDensity=density;
    if(densityButton)densityButton.setAttribute('aria-pressed',density==='compact'?'true':'false');
    storeMapLabelDensity(density);
    resizeSoon();
  }
  densityButton?.addEventListener('click',()=>{
    setDensity(panel.dataset.labelDensity==='compact'?'normal':'compact');
  });
  function onFullscreenChange(){
    if(fullscreenElement()===panel){
      commit('fullscreen');
    }else if(mode==='fullscreen'){
      commit(beforeFullscreen||'standard');
    }else{
      resizeSoon();
    }
  }
  document.addEventListener('fullscreenchange',onFullscreenChange);
  document.addEventListener('webkitfullscreenchange',onFullscreenChange);
  commit(storedMapMode());
  setDensity(storedMapLabelDensity());
}
function initMap(){
  const el=document.getElementById('fleet-map');
  if(!el||!window.L){document.querySelector('[data-map-fallback]')?.style.setProperty('display','grid');return}
  const map=L.map(el,{worldCopyJump:true,scrollWheelZoom:true,zoomControl:false});
  L.control.zoom({position:'topleft'}).addTo(map);
  L.tileLayer('https://{s}.basemaps.cartocdn.com/light_all/{z}/{x}/{y}{r}.png',{subdomains:'abcd',maxZoom:20,attribution:'&copy; OpenStreetMap contributors &copy; CARTO'}).addTo(map);
  const bounds=MAP_HOSTS.map(host=>[host.lat,host.lon]);
  const saved=storedViewport();
  if(saved){map.setView([saved.lat,saved.lon],saved.zoom)}
  else if(bounds.length===1){map.setView(bounds[0],5)}
  else if(bounds.length){map.fitBounds(bounds,{padding:[64,64],maxZoom:5})}
  else{map.setView([20,0],2)}
  const relayout=buildLabels(map,el);
  setupMapModes(map,el,relayout);
  map.on('moveend zoomend',()=>storeViewport(map));
  storeViewport(map);
}
window.pharosMapApplyFilter=(q='',live='all')=>{
  pendingMapFilter={q,live};
  if(applyMapFilterNow)applyMapFilterNow(q,live);
};
async function bootMap(){
  setMapLoading('loading','Loading server locations and reachability checks.');
  const target=document.querySelector('[data-site-list]');
  if(target)target.innerHTML=siteSkeleton();
  try{
    const [data]=await Promise.all([loadMapData(),loadMapAssets()]);
    MAP_HOSTS=data.hosts;
    renderSiteList(MAP_HOSTS);
    initMap();
    setMapLoading('ready','All servers stay visible; labels are separated by D3 force layout with leader lines.');
    if(typeof applySurfaceFilters==='function')applySurfaceFilters(false);
    else window.pharosMapApplyFilter(pendingMapFilter.q,pendingMapFilter.live);
  }catch(error){
    setMapLoading('error','Map data is temporarily unavailable. The rest of Pharos remains usable.');
    const fallback=document.querySelector('[data-map-fallback]');
    if(fallback)fallback.style.display='grid';
    const target=document.querySelector('[data-site-list]');
    if(target)target.innerHTML=siteError(error&&error.message);
  }
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootMap,{once:true});
else bootMap();
</script>"#;
    format!(
        r#"{HEAD}{sidebar}<main class="map-main" data-map-view="standard"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>Map</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">Server locations</p></div><div class="asof" data-as-of>as of {as_of}</div></div>{summary}{toolbar}<section class="map-layout" data-map-layout data-mode="standard"><div id="map-panel" class="map-panel" data-mode="standard" data-label-density="normal" data-loading="true" data-map-state="loading"><div class="map-mode-controls" role="group" aria-label="Map layout"><button class="map-mode-control" type="button" data-map-mode-button="standard" aria-label="Standard layout" aria-pressed="true" title="Standard layout">{standard_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="maximized" aria-label="Maximize to window" aria-pressed="false" title="Maximize to window">{maximize_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="fullscreen" aria-label="Fullscreen" aria-pressed="false" title="Fullscreen">{fullscreen_icon}</button><button class="map-mode-control map-density-control" type="button" data-map-density-button aria-label="Compact server labels" aria-pressed="false" title="Compact server labels">{compact_icon}</button></div><div id="fleet-map" class="fleet-map" aria-label="world map with server locations"></div><div class="map-loading" data-map-loading><div class="map-load-card"><strong>Preparing map</strong><p data-map-status-message>Loading server locations and reachability checks.</p><span class="map-load-rail" aria-hidden="true"></span></div></div><div class="map-fallback" data-map-fallback><div><strong>Map unavailable</strong><p>The location list remains available when data can be loaded.</p></div></div></div><aside class="site-panel" aria-label="server locations" data-site-panel data-loading="true"><div><h2>Locations</h2><p>Approximate site-level coordinates.</p></div><div class="site-list" data-site-list><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line long"></span><span class="site-skel-line medium"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line medium"></span><span class="site-skel-line long"></span><span class="site-skel-line short"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line medium"></span><span class="site-skel-line long"></span></div></div><div class="map-note" data-map-note>Loading server locations and reachability checks.</div></aside></section></main>{map_script}{FOOT}"#,
        sidebar = sidebar(user_label, logout_enabled, "map"),
        as_of = clock_label(now),
        summary = summary,
        toolbar = toolbar,
        standard_icon = icons::PANEL_RIGHT,
        maximize_icon = icons::MAXIMIZE_2,
        fullscreen_icon = icons::FULLSCREEN,
        compact_icon = icons::LIST,
    )
}

struct HeartbeatHistoryView {
    start: i64,
    span: i64,
    visible: Vec<usize>,
}

fn heartbeat_history_view(log: &[i64], window_secs: i64) -> HeartbeatHistoryView {
    if log.len() < 2 {
        return HeartbeatHistoryView {
            start: 0,
            span: 1,
            visible: Vec::new(),
        };
    }

    let latest = log[log.len() - 1];
    let start = log[0].max(latest - window_secs.max(1));
    let span = (latest - start).max(1);
    let candidates = log
        .iter()
        .enumerate()
        .filter_map(|(idx, stamp)| {
            if idx > 0 && *stamp >= start && *stamp <= latest {
                Some(idx)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if candidates.len() <= HEARTBEAT_HISTORY_DOTS {
        return HeartbeatHistoryView {
            start,
            span,
            visible: candidates,
        };
    }

    let mut buckets = vec![None; HEARTBEAT_HISTORY_DOTS];
    for idx in candidates {
        let raw_bucket = (((log[idx] - start) as f64 / span as f64) * HEARTBEAT_HISTORY_DOTS as f64)
            .floor() as usize;
        let bucket = raw_bucket.min(HEARTBEAT_HISTORY_DOTS - 1);
        buckets[bucket] = Some(idx);
    }

    HeartbeatHistoryView {
        start,
        span,
        visible: buckets.into_iter().flatten().collect(),
    }
}

fn heartbeat_visible_log(log: &[i64], window_secs: i64) -> Vec<i64> {
    let view = heartbeat_history_view(log, window_secs);
    view.visible.into_iter().map(|idx| log[idx]).collect()
}

fn heartbeat_history(log: &[i64], idx: usize, interval: i64) -> (&'static str, String, String) {
    let stamp = log[idx];
    let Some(previous) = idx.checked_sub(1).and_then(|previous| log.get(previous)) else {
        return (
            "first",
            "first heartbeat".to_string(),
            format!("at {}", clock_label(stamp)),
        );
    };
    let gap = (stamp - previous).max(0);
    let interval = interval.max(1);
    let (level, label) = if gap <= interval {
        ("ok", "on cadence")
    } else if gap <= interval * 2 {
        ("late", "late heartbeat")
    } else if gap <= interval * 5 {
        ("stale", "stale gap recovered")
    } else {
        ("down", "offline gap recovered")
    };
    (
        level,
        label.to_string(),
        format!(
            "{} after previous · {}",
            duration_label(gap),
            clock_label(stamp)
        ),
    )
}

fn heartbeat_marks(log: &[i64], interval: i64, window_secs: i64) -> String {
    if log.len() < 2 {
        return String::new();
    }

    let interval = interval.max(1);
    let step = HEARTBEAT_EXPECT_X / HEARTBEAT_HISTORY_DOTS.max(1) as f64;
    let newest_x = HEARTBEAT_EXPECT_X - step;
    let view = heartbeat_history_view(log, window_secs);
    let mut marks = String::new();
    for idx in view.visible {
        let x = (((log[idx] - view.start).max(0) as f64 / view.span as f64) * newest_x)
            .clamp(0.0, newest_x);
        let (level, label, detail) = heartbeat_history(log, idx, interval);
        let title = format!("{label} · {detail}");
        marks.push_str(&format!(
            r#"<span class="beat-mark" tabindex="0" data-history-level="{level}" data-history-label="{label}" data-history-detail="{detail}" title="{title}" aria-label="{title}" style="--mark-x:{x:.1}%"></span>"#,
            level = html_escape(level),
            label = html_escape(&label),
            detail = html_escape(&detail),
            title = html_escape(&title)
        ));
    }
    marks
}

fn heartbeat_x(age: i64, interval: i64) -> f64 {
    let age = age.max(0) as f64;
    let interval = interval.max(1) as f64;
    if age <= interval {
        return (age / interval) * HEARTBEAT_EXPECT_X;
    }
    if age <= interval * 2.0 {
        return HEARTBEAT_EXPECT_X + ((age - interval) / interval) * 18.0;
    }
    if age <= interval * 5.0 {
        return HEARTBEAT_STALE_X + ((age - interval * 2.0) / (interval * 3.0)) * 18.0;
    }
    100.0
}

fn heartbeat_card(
    last_seen: Option<i64>,
    heartbeat_log: &[i64],
    interval_secs: Option<u64>,
    now: i64,
    is_self: bool,
) -> String {
    let interval = i64::try_from(interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    let all_beats = heartbeat_samples(heartbeat_log, last_seen);
    let visible_beats = heartbeat_visible_log(&all_beats, SIGNAL_DEFAULT_WINDOW_SECS);
    let beats_attr = visible_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let signal_beats_attr = all_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let marks = heartbeat_marks(&all_beats, interval, SIGNAL_DEFAULT_WINDOW_SECS);
    let (last_attr, next_at_attr, beat_state, now_x, fill_color, expect_fill, target_ring) =
        match last_seen {
            Some(last) => {
                let age = (now - last).max(0);
                let progress = (age as f64 / interval as f64).clamp(0.0, 1.0);
                if age <= interval {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        if is_self { "lit" } else { "tracking" },
                        heartbeat_x(age, interval),
                        if is_self { "var(--sun)" } else { "var(--sea)" },
                        progress * 360.0,
                        3.0 + progress * 5.0,
                    )
                } else if age <= interval * 2 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "late",
                        heartbeat_x(age, interval),
                        "var(--sun)",
                        360.0,
                        8.0,
                    )
                } else if age <= interval * 5 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "stale",
                        heartbeat_x(age, interval),
                        "var(--stale)",
                        360.0,
                        8.0,
                    )
                } else {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "down",
                        100.0,
                        "var(--down)",
                        360.0,
                        8.0,
                    )
                }
            }
            None => (
                "".to_string(),
                "".to_string(),
                "waiting",
                0.0,
                "var(--wait)",
                0.0,
                3.0,
            ),
        };
    let self_attr = if is_self { r#" data-self="true""# } else { "" };
    format!(
        r#"<div class="beat" data-beat="{beat_state}" data-count="{count}" data-last="{last_attr}" data-interval="{interval}" data-next-at="{next_at_attr}" data-beats="{beats_attr}" data-signal-beats="{signal_beats_attr}" data-history-window="{history_window}" style="--now-x:{now_x:.2}%;--fill-color:{fill_color};--expect-fill:{expect_fill:.1}deg;--target-ring:{target_ring:.1}px"{self_attr}><div class="beat-stage" aria-label="heartbeat timeline"><span class="beat-floor"></span><span class="beat-fill"></span><span class="beat-current"></span><span class="beat-marks">{marks}</span><span class="beat-threshold expected"></span><span class="beat-threshold stale"></span><span class="beat-now"></span><span class="beat-hit"></span><span class="beat-zones"><span data-history-window-label>{history_window}</span><span>expected</span><span>late</span></span></div></div>"#,
        count = visible_beats.len(),
        history_window = html_escape(SIGNAL_DEFAULT_WINDOW_LABEL)
    )
}

fn render_home(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    user_label: &str,
    logout_enabled: bool,
) -> String {
    if hosts.is_empty() {
        return format!(
            "{HEAD}{sidebar}<main>{header}{empty}</main>{FOOT}",
            sidebar = sidebar(user_label, logout_enabled, "fleet"),
            header = header(now),
            empty = empty_state()
        );
    }

    let palette_colors = manifest_palette_color(manifests);
    let mut sorted: Vec<&Host> = hosts.iter().collect();
    sorted.sort_by_key(|h| {
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let rank = attention_reason(live, &h.freshness, &h.service_observations).rank;
        (rank, h.name.clone())
    });

    let mut cards = String::new();
    let mut rows = String::new();
    for h in sorted {
        let is_self = h.name == self_name;
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let (_color, word) = live.badge();
        let nix_icon = if h.is_nix {
            icons::SNOWFLAKE
        } else {
            icons::SERVER
        };
        let name = html_escape(&h.name);
        let role = html_escape(&h.role);
        let fresh_tldr = h.freshness.tldr();
        let fresh = freshness_markup(&h.freshness);
        let attention = attention_reason(live, &h.freshness, &h.service_observations);
        let reason = reason_markup(&attention);
        let search = html_escape(&format!(
            "{} {} {} {}",
            h.name.to_lowercase(),
            h.role.to_lowercase(),
            fresh_tldr.to_lowercase(),
            attention.label.to_lowercase()
        ));
        let sort_name = html_escape(&h.name.to_lowercase());
        let last_sort = h.last_seen.unwrap_or(0);
        let sev = attention.rank;
        let seen = match h.last_seen {
            Some(t) => format!("last seen {} ago", duration_label(now - t)),
            None => "never seen".to_string(),
        };
        let light_cls = if is_self { " light" } else { "" };
        let self_attr = if is_self { r#" data-self="true""# } else { "" };
        let beam = if is_self {
            format!(
                r#"<span class="pharos-mark" aria-hidden="true">{}</span>"#,
                icons::LIGHTHOUSE
            )
        } else {
            String::new()
        };
        let settings_href = html_escape(&format!("/agora?host={}", url_query_escape(&h.name)));
        let settings_color = palette_colors.get(&h.name).map(|color| html_escape(color));
        let settings_cls = if settings_color.is_some() {
            " has-settings"
        } else {
            ""
        };
        let host_color_style = settings_color
            .as_ref()
            .map(|color| format!(r#" style="--host-color:{color}""#))
            .unwrap_or_default();
        let settings_action = if settings_color.is_some() {
            format!(
                r#"<a class="settings-card" href="{settings_href}" title="Open color settings for {name}" aria-label="Open color settings for {name}"><span class="settings-icon">{icon}</span></a>"#,
                icon = icons::SLIDERS
            )
        } else {
            format!(
                r#"<a class="settings-card unavailable" href="{settings_href}" title="Prepare color settings for {name}" aria-label="Prepare color settings for {name}"><span class="settings-icon">{icon}</span></a>"#,
                icon = icons::SLIDERS
            )
        };
        let drag_action = format!(
            r#"<button class="drag-handle" type="button" data-drag-handle title="Move {name}" aria-label="Move {name}">{icon}</button>"#,
            icon = icons::GRIP
        );
        let status_word = word;
        let status_icon = status_icon_stack();
        let heartbeat = heartbeat_card(
            h.last_seen,
            &h.heartbeat_log,
            h.heartbeat_interval_secs,
            now,
            is_self,
        );
        let interval = i64::try_from(h.heartbeat_interval_secs.unwrap_or(60))
            .unwrap_or(60)
            .max(1);
        let signal = signal_markup(&heartbeat_signal(
            &h.heartbeat_log,
            h.last_seen,
            interval,
            now,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        ));
        let row_cls = format!("{light_cls}{settings_cls}").trim().to_string();
        cards.push_str(&format!(
            r#"<article class="card{light_cls}{settings_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime"{self_attr}{host_color_style}>{beam}<header class="card-head"><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div><div class="card-actions">{drag_action}{settings_action}</div></header>{reason}<div class="fresh" data-fresh>{fresh}</div><div class="meta"><span data-seen>{seen}</span><span data-card-asof>as of {as_of}</span></div>{heartbeat}<div class="card-tools">{signal}</div></article>"#,
            live_key = live_key(live),
            as_of = clock_label(now)
        ));
        rows.push_str(&format!(
            r#"<tr class="{row_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime"{self_attr}{host_color_style}><td><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div></td><td><span class="status-pill" aria-label="status: {status_word}">{status_icon}<span class="word" data-status-word>{status_word}</span></span></td><td>{reason}</td><td><div class="fresh" data-fresh>{fresh}</div></td><td><span data-seen>{seen}</span></td><td>{heartbeat}</td><td>{settings_action}</td></tr>"#,
            live_key = live_key(live),
        ));
    }

    let lone = if hosts.len() == 1 {
        lone_host_state()
    } else {
        String::new()
    };

    format!(
        "{HEAD}{sidebar}<main data-view=\"grid\">{header}{summary}{toolbar}<div class=\"grid\" data-grid>{cards}</div><section class=\"list-wrap\"><table class=\"list\"><thead><tr><th>Host</th><th>Status</th><th>Attention</th><th>Freshness</th><th>Last seen</th><th>Heartbeat</th><th>Actions</th></tr></thead><tbody data-list-body>{rows}</tbody></table></section>{lone}</main>{FOOT}",
        sidebar = sidebar(user_label, logout_enabled, "fleet"),
        header = header(now),
        summary = summary_cards(hosts, self_name, now),
        toolbar = toolbar()
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let store = Arc::new(Store::new(
        std::env::var("PHAROS_DB").ok().map(PathBuf::from),
    ));
    let manifests = Arc::new(ManifestRegistry::from_env());
    let auth = Auth::from_env().await;
    let beacon_auth = BeaconAuth::from_env();
    let alert_notifier = AlertNotifier::from_env();
    let state = AppState {
        store,
        manifests,
        auth,
        beacon_auth,
    };
    spawn_alert_loop(state.clone(), alert_notifier);

    let app = Router::new()
        // Human routes — gated by OIDC when configured (open otherwise).
        .route("/", get(home))
        .route("/map", get(map_page))
        .route("/map/data.json", get(map_data_json))
        .route("/alerts", get(alerts_page))
        .route("/activity", get(activity_page))
        .route("/agora", get(agora::page))
        .route(
            "/agora/proposals/host-palette.json",
            get(agora::palette_proposal),
        )
        .route(
            "/agora/proposals/host-location.json",
            get(agora::location_proposal),
        )
        .route("/hosts.json", get(hosts_json))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        // Machine/public routes: beacon ingestion, local registration, health,
        // version, declared manifests, and the auth flow.
        .route("/declared-hosts.json", get(declared_hosts_json))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/favicon.svg", get(favicon_svg))
        .route("/assets/fleet-horizon.png", get(fleet_horizon_asset))
        .route(
            "/assets/sidebar-lighthouse.png",
            get(sidebar_lighthouse_asset),
        )
        .route("/register", post(register))
        .route("/report", post(report))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", get(auth::logout))
        .route("/auth/logged-out", get(auth::logged_out))
        .with_state(state);

    let addr = std::env::var("PHAROS_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind PHAROS_ADDR");
    tracing::info!(
        "pharosd v{} listening on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn favicon_serves_pharos_lighthouse_svg() {
        let response = favicon_svg().await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml; charset=utf-8"
        );
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("favicon body");
        let svg = std::str::from_utf8(&body).expect("favicon is utf8 svg");
        assert!(svg.contains(r#"<svg xmlns="http://www.w3.org/2000/svg""#));
        assert!(svg.contains(r##"stroke="#d69b31""##));
        assert!(svg.contains(r#"M10.5 5 12 2.5 13.5 5"#));
    }

    #[test]
    fn render_home_includes_lighthouse_and_heartbeat_markup() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
            },
            Host {
                name: "hades".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(879),
                heartbeat_log: vec![760, 819, 879],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
            },
            Host {
                name: "poseidon".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
            },
        ];

        let html = render_home(&hosts, "csb1", 1000, &[], "markus", true);

        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains(r#"<section class="toolbar""#));
        assert!(html.contains(r#"data-view-button="list""#));
        assert!(html.contains(r#"<option value="freeform">Freeform</option>"#));
        assert!(html.contains("pharos_freeform_order_v1"));
        assert!(html.contains("bindFreeformDrag();"));
        assert!(html.contains(r#"data-drag-handle title="Move poseidon""#));
        assert!(html.contains(r#"<table class="list">"#));
        assert!(
            html.contains(r#"<span class="side-user" title="markus"><span>markus</span></span>"#)
        );
        assert!(html.contains(r#"href="/" aria-current="page""#));
        assert!(html.contains(r#"href="/map""#));
        assert!(html.contains(r#"href="/auth/logout""#));
        assert!(html.contains(r#"aria-label="Log out of Pharos""#));
        assert!(!html.contains(">mba<"));
        assert!(html.contains("cache:'no-store'"));
        assert!(html.contains("'/hosts.json?refresh='+Date.now()"));
        assert!(html.contains("credentials:'same-origin'"));
        assert!(html.contains("let refreshGeneration=0;"));
        assert!(html.contains("generation!==refreshGeneration"));
        assert!(html.contains("refreshGeneration++;"));
        assert!(html.contains("document.addEventListener('visibilitychange'"));
        assert!(html.contains("window.addEventListener('focus'"));
        assert!(html.contains("window.addEventListener('pageshow'"));
        assert!(html.contains("window.addEventListener('online'"));
        assert!(html.contains("scheduleRefresh(3000);"));
        assert!(!html.contains("setInterval(refresh,10000)"));
        assert!(html.contains(r#"data-host="csb1" data-live="live""#));
        assert!(html.contains(r#"data-self="true""#));
        assert!(html.contains(r#"class="pharos-mark""#));
        assert!(!html.contains("the light is lit"));
        assert!(html.contains(r#"<th>Attention</th>"#));
        assert!(html.contains(r#"<th>Actions</th>"#));
        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(!html.contains("No settings yet"));
        assert!(!html.contains("Not set up yet"));
        assert!(!html.contains("control light"));
        assert!(!html.contains("expected beat"));
        assert!(html.contains(r#"class="signal" data-signal data-signal-level="good""#));
        assert!(html.contains(r#"<span data-signal-percent>100%</span>"#));
        assert!(html.contains(
            r#"<span data-signal-percent>100%</span><span class="signal-orb" aria-hidden="true"></span><button class="signal-window""#
        ));
        assert!(html.contains(r#"<button class="signal-window" type="button" data-signal-window"#));
        assert!(html.contains(r#"data-signal-window-key="10m""#));
        assert!(html.contains(r#"data-beats="910,970""#));
        assert!(html.contains(r#"data-signal-beats="850,910,970""#));
        assert!(html.contains(r#"data-history-window="10m""#));
        assert!(html.contains(r#"<span data-history-window-label>10m</span>"#));
        assert!(
            !html.contains(r#"<span class="beat-mark" tabindex="0" data-history-level="first""#)
        );
        assert!(html.contains(r#"data-history-level="ok""#));
        assert!(html.contains(r#"data-history-label="on cadence""#));
        assert!(html.contains(r#"--mark-x:29.3%""#));
        assert!(html.contains(r#"--mark-x:58.7%""#));
        assert!(!html.contains(r#"--mark-x:64.0%""#));
        assert!(html.contains("Flake.lock age"));
        assert!(html.contains(r#"<strong class="warn">1d</strong>"#));
        assert!(html.contains("Commits behind"));
        assert!(html.contains(r#"<strong class="warn">3</strong>"#));
        assert!(html.contains("beat-fill"));
        assert!(html.contains("beat-now"));
        assert!(html.contains("beat-current"));
        assert!(html.contains("beat-zones"));
        assert!(html.contains("nix drift: 1d"));
        assert!(html.contains("3 commits"));
        assert!(html.contains(r#"data-search="poseidon nixos host flake.lock 1d old · 3 commits behind nixcfg nix drift: 1d · 3 commits""#));
        assert!(html.contains(r#"data-host="poseidon" data-live="live" data-sev="3""#));
        assert!(html.contains(r#"data-host="hades" data-live="stale""#));
        assert!(html.contains(r#"data-sev="1""#));
        assert!(html.contains("state-icon stale"));
    }

    #[test]
    fn render_alerts_derives_actionable_attention_queue() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "control".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
            },
            Host {
                name: "poseidon".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: Some("not-rendered-token-hash".to_string()),
                last_seen: Some(500),
                heartbeat_log: vec![380, 440, 500],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
            },
            Host {
                name: "athena".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(2),
                    commits_behind: Some(3),
                },
                service_observations: vec![
                    ServiceObservation::nix_freshness(&NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(2),
                        commits_behind: Some(3),
                    }),
                    ServiceObservation {
                        id: "nginx".to_string(),
                        label: "nginx".to_string(),
                        state: ServiceObservationState::Warning,
                        summary: "response is slow".to_string(),
                    },
                ],
            },
            Host {
                name: "hermes".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(2),
                    commits_behind: Some(3),
                },
                service_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8", "role": "parents home" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let load_error = ManifestLoadIssue {
            path: "/etc/pharos/hosts/broken.json".to_string(),
            error: "failed to parse manifest JSON".to_string(),
        };
        let mut probes = BTreeMap::new();
        probes.insert(
            "hsb8".to_string(),
            vec![ServerProbeObservation {
                id: "home-assistant".to_string(),
                service: "Home Assistant".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("http://hsb8.lan:8123/".to_string()),
                state: ServiceObservationState::Warning,
                server_reachable: Some(false),
                client_reachable: None,
                summary: "server probe timed out".to_string(),
                checked_at: 995,
            }],
        );

        let html = render_alerts(
            &hosts,
            "csb1",
            1000,
            &[manifest],
            &[load_error],
            &probes,
            ShellContext {
                user_label: "markus",
                logout_enabled: true,
            },
        );

        assert!(html.contains(r#"href="/alerts" aria-current="page""#));
        assert!(html.contains(r#"<h1>Alerts</h1>"#));
        assert!(html.contains("Needs attention"));
        assert!(html.contains("Declared host manifest failed to load"));
        assert!(html.contains("No heartbeat received"));
        assert!(html.contains("Check host power, network, and pharos-beacon."));
        assert!(html.contains("3 commits behind nixcfg"));
        assert!(html.contains(r#"<span class="alert-repeat">2 alerts</span>"#));
        assert!(html.contains("athena, hermes"));
        assert!(html.contains("nginx: warning"));
        assert!(!html.contains("Nix freshness: warning"));
        assert!(html.contains("Home Assistant probe warning"));
        assert!(html.contains("Install or start pharos-beacon"));
        assert!(html.contains("Operations posture"));
        assert!(html.contains(r#"class="ops-action" href="/map">View on map</a>"#));
        assert!(html.contains(
            r#"<button class="ops-metric critical" type="button" data-ops-filter="critical""#
        ));
        assert!(html.contains(r#"data-ops-filter="warning""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-host-search="athena server hermes server"#));
        assert!(html.contains(r#"class="posture-ring" type="button" data-ops-filter="critical""#));
        assert!(html.contains(r#"<strong>2</strong><span>critical</span>"#));
        assert!(html.contains("Repeated alerts are grouped."));
        assert!(html.contains("const filterOk=active==='all'"));
        assert!(!html.contains("not-rendered-token-hash"));
    }

    #[test]
    fn render_activity_derives_operational_timeline() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "control".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(1000),
                heartbeat_log: vec![880, 940, 1000],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(0),
                    commits_behind: Some(0),
                },
                service_observations: vec![],
            },
            Host {
                name: "athena".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: Some("not-rendered-token-hash".to_string()),
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(4),
                    commits_behind: Some(1),
                },
                service_observations: vec![
                    ServiceObservation::nix_freshness(&NixFreshness {
                        applicable: true,
                        flake_lock_age_days: Some(4),
                        commits_behind: Some(1),
                    }),
                    ServiceObservation {
                        id: "ssh".to_string(),
                        label: "ssh".to_string(),
                        state: ServiceObservationState::Healthy,
                        summary: "accepting connections".to_string(),
                    },
                    ServiceObservation {
                        id: "nginx".to_string(),
                        label: "nginx".to_string(),
                        state: ServiceObservationState::Warning,
                        summary: "response is slow".to_string(),
                    },
                ],
            },
            Host {
                name: "hades".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(760),
                heartbeat_log: vec![640, 700, 760],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
                service_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "athena",
            "host": { "name": "athena", "role": "server" },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [{ "wing": "ops", "name": "ssh" }],
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let mut probes = BTreeMap::new();
        probes.insert(
            "athena".to_string(),
            vec![ServerProbeObservation {
                id: "ssh".to_string(),
                service: "ssh".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("tcp://athena:22".to_string()),
                state: ServiceObservationState::Healthy,
                server_reachable: Some(true),
                client_reachable: None,
                summary: "server can reach ssh".to_string(),
                checked_at: 990,
            }],
        );

        let html = render_activity(
            &hosts,
            "csb1",
            1000,
            &[manifest],
            &[],
            &probes,
            ShellContext {
                user_label: "markus",
                logout_enabled: true,
            },
        );

        assert!(html.contains(r#"href="/activity" aria-current="page""#));
        assert!(html.contains(r#"<h1>Activity</h1>"#));
        assert!(html.contains("Operational timeline"));
        assert!(!html.contains("Control light observed"));
        assert!(html.contains("Heartbeat received"));
        assert!(html.contains("Heartbeat lateness detected"));
        assert!(html.contains("Freshness drift detected"));
        assert!(html.contains("ssh is healthy"));
        assert!(html.contains("nginx warning"));
        assert!(!html.contains("Nix freshness warning"));
        assert!(html.contains("ssh probe healthy"));
        assert!(html.contains("Declared host manifest loaded"));
        assert!(html.contains(r#"data-activity-filter="heartbeat""#));
        assert!(html.contains(r#"data-ops-filter="heartbeat""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-host-search="athena freshness freshness drift detected"#));
        assert!(html.contains(r#"<button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true""#));
        assert!(html.contains(r#"data-activity-filter="critical""#));
        assert!(html.contains("const filterOk=active==='all'"));
        assert!(html.contains("Activity is derived from current retained Pharos state."));
        assert!(!html.contains("not-rendered-token-hash"));
    }

    #[test]
    fn render_home_sorts_self_host_like_any_other_host() {
        fn host(name: &str) -> Host {
            Host {
                name: name.to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(990),
                heartbeat_log: vec![930, 990],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness {
                    applicable: false,
                    ..Default::default()
                },
                service_observations: vec![],
            }
        }

        let html = render_home(
            &[host("csb1"), host("csb0")],
            "csb1",
            1000,
            &[],
            "markus",
            true,
        );
        let csb0 = html.find(r#"data-host="csb0""#).expect("csb0 rendered");
        let csb1 = html.find(r#"data-host="csb1""#).expect("csb1 rendered");

        assert!(csb0 < csb1, "self host must not be pinned ahead of csb0");
        assert!(html.contains(r#"<span class="pharos-mark" aria-hidden="true">"#));
        assert!(!html.contains("control light"));
        assert!(!html.contains("the light is lit"));
        assert!(!html.contains("dataset.self==='true')-Number"));
    }

    #[test]
    fn render_map_uses_visible_labels_and_site_level_locations() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
            },
            Host {
                name: "csb0".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: Some(HostLocation {
                    latitude: 50.1109,
                    longitude: 8.6821,
                    source: HostLocationSource::Wifi,
                    accuracy_meters: Some(1000.0),
                    precision_meters: Some(25_000.0),
                    observed_at: Some(990),
                    stale: false,
                    manual_override: false,
                    label: Some("Runtime wifi".to_string()),
                }),
                freshness: NixFreshness::default(),
                service_observations: vec![],
            },
            Host {
                name: "hsb8".to_string(),
                role: "parents' home".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
            },
            Host {
                name: "dsc0".to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
            },
            Host {
                name: "new-host".to_string(),
                role: "new server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen: None,
                heartbeat_log: vec![],
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
            },
        ];
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8", "site": "ww87" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let probes = BTreeMap::from([
            (
                "csb1".to_string(),
                MapSignal {
                    label: "4 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 4 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "csb0".to_string(),
                MapSignal {
                    label: "8 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 8 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "hsb8".to_string(),
                MapSignal {
                    label: "blocked".to_string(),
                    level: "wait",
                    title: "Outbound access from Pharos is blocked by policy".to_string(),
                    policy: Some("blocked"),
                },
            ),
            (
                "dsc0".to_string(),
                MapSignal {
                    label: "139 ms".to_string(),
                    level: "good",
                    title: "Pharos tailnet ssh check reachable in 139 ms".to_string(),
                    policy: Some("expected"),
                },
            ),
            (
                "new-host".to_string(),
                MapSignal {
                    label: "timeout".to_string(),
                    level: "warn",
                    title: "Pharos tailnet ssh check timed out".to_string(),
                    policy: Some("unknown"),
                },
            ),
        ]);

        let manifests = vec![manifest];
        let html = render_map(&hosts, "csb1", 1000, "markus", true);
        let payload = map_data_payload(&hosts, "csb1", 1000, &manifests, &probes);
        let data_json = serde_json::to_string(&payload).expect("map payload serializes");

        let leaflet_css = html.find("leaflet@1.9.4/dist/leaflet.css").unwrap();
        let body = html.find("</head><body>").unwrap();
        assert!(leaflet_css > body);
        assert!(html.contains(r#"href="/map" aria-current="page""#));
        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains("const MAP_DATA_URL='/map/data.json'"));
        assert!(html.contains("fetch(MAP_DATA_URL+'?refresh='"));
        assert!(html.contains("loadMapAssets()"));
        assert!(html.contains("data-map-loading"));
        assert!(html.contains("data-map-state=\"loading\""));
        assert!(html.contains("Preparing map"));
        assert!(html.contains("site-skel-line"));
        assert!(html.contains("Loading server locations and reachability checks."));
        assert!(html.contains("let MAP_HOSTS=[]"));
        assert!(!html.contains("const MAP_HOSTS=["));
        assert!(html.contains("d3@7.9.0"));
        assert!(html.contains("d3.forceSimulation"));
        assert!(html.contains("d3.forceCollide"));
        assert!(html.contains("renderSiteList(MAP_HOSTS)"));
        assert!(html.contains("function locationSourceLabel(source)"));
        assert!(html.contains("class=\"site-host-source\""));
        assert!(html.contains("class=\"map-source\""));
        assert!(html.contains("data-location-source"));
        assert!(html.contains("buildLabels(map,el)"));
        assert!(html.contains("basemaps.cartocdn.com/light_all"));
        assert!(html.contains("map.on('move zoom moveend zoomend resize viewreset'"));
        assert!(html.contains("classList.add('map-links')"));
        assert!(html.contains("animateMotion"));
        assert!(html.contains("const MAP_VIEWPORT_STORAGE='pharos.map.viewport.v1'"));
        assert!(html.contains("const MAP_MODE_STORAGE='pharos.map.mode.v1'"));
        assert!(html.contains("storedViewport()"));
        assert!(html.contains("storeViewport(map)"));
        assert!(html.contains("map.on('moveend zoomend',()=>storeViewport(map))"));
        assert!(html.contains("scrollWheelZoom:true"));
        assert!(html.contains("L.control.zoom({position:'topleft'})"));
        assert!(html.contains(r#"data-map-view="standard""#));
        assert!(html.contains(r#"data-map-layout data-mode="standard""#));
        assert!(html.contains(r#"id="map-panel" class="map-panel""#));
        assert!(html.contains(r#"data-map-mode-button="standard""#));
        assert!(html.contains(r#"data-map-mode-button="maximized""#));
        assert!(html.contains(r#"data-map-mode-button="fullscreen""#));
        assert!(html.contains(r#"data-map-density-button"#));
        assert!(html.contains("const MAP_LABEL_DENSITY_STORAGE='pharos.map.labelDensity.v1'"));
        assert!(html.contains("window.pharosMapApplyFilter"));
        assert!(html.contains("dataset.mapLayer='managed'"));
        assert!(html.contains(r#"class="toolbar" aria-label="map controls""#));
        assert!(html.contains(r#"placeholder="Search hosts...""#));
        assert!(html.contains(r#"data-live-filter="all""#));
        assert!(html.contains(r#"data-live-filter="live""#));
        assert!(html.contains("requestFullscreen(panel)"));
        assert!(html.contains("map.invalidateSize()"));
        assert!(html.contains(".fleet-map{flex:1 1 auto;height:100%;min-height:560px"));
        assert!(html.contains(".map-mode-controls{position:absolute;right:12px;top:12px"));
        assert!(html.contains(r#".map-panel[data-label-density="compact"] .map-node"#));
        assert!(html.contains("data-dir=\"in\""));
        assert!(html.contains("data-dir=\"out\""));
        assert!(!html.contains("markercluster"));
        assert!(!html.contains("L.markerClusterGroup"));
        assert!(!html.contains(r#""site_id":"cloud-de""#));
        assert!(!html.contains(r#""lon":-122.9898"#));
        assert!(html.contains(r#"data-probe-level="'+escapeHtml(host.outbound_level)+'" data-policy="'+escapeHtml(host.outbound_policy)+'">out "#));
        assert!(html.contains(r#"data-host="'+escapeHtml(host.name)+'" data-live="'+escapeHtml(host.live)+'" data-search="'+escapeHtml(host.search||'')+'" "#));
        assert!(html.contains(r#"<b>5</b><span>All hosts</span>"#));
        assert!(html.contains(r#"<b>4</b><span>Live</span>"#));
        assert!(html.contains("Approximate site-level coordinates."));
        assert!(html.contains("All servers stay visible"));

        assert!(data_json.contains(r#""schema":"inspr.pharos.map-data.v1""#));
        assert!(data_json.contains(r#""site_id":"cloud-de""#));
        assert!(data_json.contains(r#""site_id":"wifi:50.1109,8.6821""#));
        assert!(data_json.contains(r#""site_id":"ww87""#));
        assert!(data_json.contains(r#""site_id":"dsc-us""#));
        assert!(data_json.contains(r#""site_id":"unknown""#));
        assert!(data_json.contains(r#""lon":-122.9898"#));
        assert!(data_json.contains(r#""location_source":"provider""#));
        assert!(data_json.contains(r#""location_source":"wifi""#));
        assert!(data_json.contains(r#""location_source":"fallback""#));
        assert!(data_json.contains(r#""source":"provider""#));
        assert!(data_json.contains(r#""source":"wifi""#));
        assert!(data_json.contains(r#""source":"fallback""#));
        assert!(data_json.contains("Hillsboro, OR, US"));
        assert!(data_json.contains(r#""inbound_label":"30s""#));
        assert!(data_json.contains(r#""outbound_label":"blocked""#));
        assert!(data_json.contains(r#""outbound_policy":"blocked""#));
        assert!(data_json.contains(r#""search":"csb1 server live"#));
        assert!(payload.hosts.iter().any(|host| host.name == "hsb8"
            && host.live == "live"
            && host.outbound_label == "blocked"
            && host.outbound_policy == "blocked"));
        assert!(payload.hosts.iter().any(|host| host.name == "csb0"
            && host.location_source == "wifi"
            && host.location_state == "observed"
            && host.search.contains("auto")));
        assert!(payload.hosts.iter().any(|host| host.name == "new-host"
            && host.live == "awaiting_first_heartbeat"
            && host.outbound_label == "timeout"
            && host.outbound_level == "warn"
            && host.search.contains("fallback")));
    }

    #[test]
    fn host_location_resolution_defines_precedence_and_stale_state() {
        fn location(
            latitude: f64,
            longitude: f64,
            source: HostLocationSource,
            observed_at: Option<i64>,
            manual_override: bool,
            label: &str,
        ) -> HostLocation {
            HostLocation {
                latitude,
                longitude,
                source,
                accuracy_meters: Some(1000.0),
                precision_meters: None,
                observed_at,
                stale: false,
                manual_override,
                label: Some(label.to_string()),
            }
        }

        let mut host = Host {
            name: "dsc0".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(1000),
            heartbeat_log: vec![940, 1000],
            heartbeat_interval_secs: Some(60),
            location: Some(location(
                50.1109,
                8.6821,
                HostLocationSource::Wifi,
                Some(995),
                false,
                "Runtime wifi",
            )),
            freshness: NixFreshness::default(),
            service_observations: vec![],
        };
        let mut manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "dsc0",
            "host": {
                "name": "dsc0",
                "site": "dsc-us",
                "location": {
                    "latitude": 45.5229,
                    "longitude": -122.9898,
                    "source": "declared",
                    "manual_override": true,
                    "label": "Declared DSC"
                }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let declared = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared.source, HostLocationSource::Declared);
        assert_eq!(declared.label, "Declared DSC");
        assert!(declared.manual_override);

        manifest.host.location.as_mut().unwrap().manual_override = false;
        manifest.host.location_mode = ManifestLocationMode::DeclaredOverride;
        let declared_mode = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared_mode.source, HostLocationSource::Declared);
        assert_eq!(declared_mode.mode, "declared-override");
        assert_eq!(declared_mode.label, "Declared DSC");

        manifest.host.location_mode = ManifestLocationMode::DeclaredFallback;
        let runtime = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(runtime.source, HostLocationSource::Wifi);
        assert_eq!(runtime.label, "Runtime wifi");
        assert_eq!(runtime.state, "observed");

        host.location.as_mut().unwrap().observed_at = Some(1000 - LOCATION_STALE_AFTER_SECS - 1);
        let stale = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(stale.source, HostLocationSource::Wifi);
        assert_eq!(stale.state, "stale");
        assert!(stale.stale);

        host.location = None;
        let declared_fallback = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(declared_fallback.source, HostLocationSource::Declared);
        assert_eq!(declared_fallback.mode, "declared-fallback");

        manifest.host.location_mode = ManifestLocationMode::Hidden;
        let hidden = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(hidden.source, HostLocationSource::Unknown);
        assert_eq!(hidden.mode, "hidden");
        assert_eq!(hidden.state, "hidden");
        assert_eq!(hidden.id, "hidden");

        manifest.host.location_mode = ManifestLocationMode::Auto;
        manifest.host.location = None;
        let provider = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(provider.source, HostLocationSource::Provider);
        assert_eq!(provider.id, "dsc-us");

        manifest.host.site = None;
        let fallback = resolve_host_location(Some(&host), Some(&manifest), "dsc0", 1000);
        assert_eq!(fallback.source, HostLocationSource::Fallback);
        assert_eq!(fallback.id, "dsc-us");

        let unknown = resolve_host_location(None, None, "new-host", 1000);
        assert_eq!(unknown.source, HostLocationSource::Fallback);
        assert_eq!(unknown.state, "unknown");
        assert_eq!(unknown.id, "unknown");
    }

    #[test]
    fn declared_hosts_payload_exposes_sanitized_location_overlay() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "athena",
            "host": {
                "name": "athena",
                "site": "home-at"
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let runtime = Host {
            name: "athena".to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("not-rendered-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            location: Some(HostLocation {
                latitude: 48.2082,
                longitude: 16.3738,
                source: HostLocationSource::Wifi,
                accuracy_meters: Some(1500.0),
                precision_meters: None,
                observed_at: Some(970),
                stale: false,
                manual_override: false,
                label: Some("Vienna area".to_string()),
            }),
            freshness: NixFreshness::default(),
            service_observations: vec![],
        };

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            std::slice::from_ref(&runtime),
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["source"],
            "wifi"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["label"],
            "Vienna area"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["location"]["manual_override"],
            false
        );
        assert!(!payload.to_string().contains("not-rendered-token-hash"));
    }

    #[test]
    fn silent_beacon_alerts_only_previous_hosts_that_are_down() {
        fn host(name: &str, last_seen: Option<i64>) -> Host {
            Host {
                name: name.to_string(),
                role: "server".to_string(),
                is_nix: true,
                report_version: pharos_core::HOST_REPORT_VERSION,
                token_hash: None,
                last_seen,
                heartbeat_log: last_seen.into_iter().collect(),
                heartbeat_interval_secs: Some(60),
                location: None,
                freshness: NixFreshness::default(),
                service_observations: vec![],
            }
        }

        let alerts = silent_beacon_alerts(
            &[
                host("live", Some(950)),
                host("stale", Some(800)),
                host("down", Some(600)),
                host("awaiting", None),
            ],
            1000,
        );

        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].host, "down");
        assert_eq!(alerts[0].kind, "silent_heartbeat");
        assert_eq!(alerts[0].age_seconds, 400);
        assert_eq!(alerts[0].heartbeat_interval_secs, 60);
        assert!(alerts[0].summary.contains("has not reported"));
    }

    #[test]
    fn alert_webhook_prefers_pharos_specific_url() {
        let selected = alert_webhook_url(
            Some(" https://pharos-alert.example/hook ".to_string()),
            Some("https://watchtower.example/hook".to_string()),
            Some("/no/read/needed".to_string()),
        );

        assert_eq!(
            selected.as_deref(),
            Some("https://pharos-alert.example/hook")
        );
    }

    #[test]
    fn alert_webhook_reuses_watchtower_url_when_pharos_url_is_blank() {
        let selected = alert_webhook_url(
            Some("   ".to_string()),
            Some(" https://watchtower.example/hook ".to_string()),
            Some("/no/read/needed".to_string()),
        );

        assert_eq!(selected.as_deref(), Some("https://watchtower.example/hook"));
    }

    #[test]
    fn alert_webhook_can_read_watchtower_url_from_env_file() {
        let mut path = std::env::temp_dir();
        path.push(format!(
            "pharos-alert-env-{}-{}.env",
            std::process::id(),
            now_unix()
        ));
        fs::write(
            &path,
            r#"
# ignored
WATCHTOWER_HTTP_API_TOKEN=not-selected
export WATCHTOWER_NOTIFICATION_URL="https://watchtower.example/hook"
"#,
        )
        .expect("write test env file");

        let selected = alert_webhook_url(None, None, Some(path.display().to_string()));
        let _ = fs::remove_file(path);

        assert_eq!(selected.as_deref(), Some("https://watchtower.example/hook"));
    }

    #[test]
    fn telegram_alert_target_parses_shoutrrr_url() {
        let url =
            Url::parse("telegram://123456:abcDEF@telegram?chats=-100111222333,444555").unwrap();
        let target = TelegramAlertTarget::from_url(&url).expect("telegram target");

        assert_eq!(target.token, "123456:abcDEF");
        assert_eq!(target.chats, vec!["-100111222333", "444555"]);
    }

    #[test]
    fn telegram_alert_text_is_plain_and_actionable() {
        let alert = SilentBeaconAlert {
            schema: "inspr.pharos.alert.v1",
            level: "critical",
            kind: "silent_heartbeat",
            host: "gpc0".to_string(),
            role: "server".to_string(),
            last_seen: 100,
            age_seconds: 360,
            heartbeat_interval_secs: 60,
            as_of: 460,
            summary: "gpc0 has not reported for 6m 00s.".to_string(),
            next_action: "Check host power, network, and pharos-beacon.",
        };

        let text = telegram_alert_text(&alert);

        assert!(text.contains("Pharos critical alert"));
        assert!(text.contains("Host: gpc0"));
        assert!(text.contains("Check host power"));
    }

    #[test]
    fn heartbeat_history_uses_outcome_slots_before_expected_marker() {
        let marks = heartbeat_marks(&[100, 160, 220, 340], 60, SIGNAL_DEFAULT_WINDOW_SECS);

        assert!(!marks.contains(r#"data-history-level="first""#));
        assert!(marks.contains(r#"data-history-level="ok""#));
        assert!(marks.contains(r#"data-history-level="late""#));
        assert!(marks.contains(r#"--mark-x:14.7%""#));
        assert!(marks.contains(r#"--mark-x:29.3%""#));
        assert!(marks.contains(r#"--mark-x:58.7%""#));
        assert!(!marks.contains(r#"--mark-x:64.0%""#));
    }

    #[test]
    fn first_heartbeat_without_previous_sample_has_no_history_dot() {
        assert!(heartbeat_marks(&[100], 60, SIGNAL_DEFAULT_WINDOW_SECS).is_empty());
    }

    #[test]
    fn heartbeat_history_window_changes_visible_samples() {
        let log = (0..=20).map(|idx| idx * 60).collect::<Vec<_>>();

        let ten_minutes = heartbeat_visible_log(&log, 10 * 60);
        let hour = heartbeat_visible_log(&log, 60 * 60);

        assert_eq!(ten_minutes.len(), 11);
        assert_eq!(ten_minutes.first(), Some(&600));
        assert_eq!(ten_minutes.last(), Some(&1200));
        assert_eq!(hour.len(), HEARTBEAT_HISTORY_DOTS);
        assert_ne!(hour, ten_minutes);
        assert_eq!(hour.last(), Some(&1200));
    }

    #[test]
    fn heartbeat_signal_scores_expected_intervals_not_dots() {
        let steady = heartbeat_signal(
            &[100, 160, 220, 280, 340, 400, 460, 520, 580],
            Some(580),
            60,
            588,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(steady.text, "100%");
        assert_eq!(steady.level, "good");
        assert_eq!(steady.window, "10m");

        let overdue = heartbeat_signal(
            &[100, 160, 220, 280, 340, 400, 460, 520, 580],
            Some(580),
            60,
            645,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(overdue.text, "90%");
        assert_eq!(overdue.level, "warn");

        let recovered_gap = heartbeat_signal(
            &[100, 160, 220, 460],
            Some(460),
            60,
            468,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        assert_eq!(recovered_gap.text, "57%");
        assert_eq!(recovered_gap.level, "down");
    }

    #[test]
    fn heartbeat_signal_can_score_longer_windows() {
        let sparse = heartbeat_signal(&[0, 60, 120, 3600], Some(3600), 60, 3600, "1h", 3600);

        assert_eq!(sparse.text, "7%");
        assert_eq!(sparse.level, "down");
        assert_eq!(sparse.window, "1h");
        assert!(sparse.title.contains("longest gap"));
    }

    #[test]
    fn render_home_marks_declared_host_settings_as_available() {
        let host = Host {
            name: "poseidon".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(970),
            heartbeat_log: vec![850, 910, 970],
            heartbeat_interval_secs: Some(60),
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
        };
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "poseidon",
            "host": { "name": "poseidon" },
            "palette": {
                "name": "custom-poseidon",
                "accent": "#48b8a8",
                "gradient": { "primary": "#48b8a8" }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let html = render_home(&[host], "csb1", 1000, &[manifest], "markus", true);

        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(html.contains(r#"class="card has-settings""#));
        assert!(html.contains(r#"aria-label="Open color settings for poseidon""#));
        assert!(html.contains(r#"<div class="card-actions"><button class="drag-handle" type="button" data-drag-handle title="Move poseidon" aria-label="Move poseidon""#));
        assert!(html.contains(r#"<div class="card-tools"><span class="signal" data-signal"#));
        assert!(html.contains(r#"style="--host-color:#48b8a8""#));
        assert!(!html.contains("Color and access"));
        assert!(!html.contains(r#"class="settings-swatch""#));
    }

    #[test]
    fn render_home_has_deliberate_empty_and_lone_host_states() {
        let empty = render_home(&[], "csb1", 1000, &[], "local access", false);
        assert!(empty.contains(r#"<section class="empty-state""#));
        assert!(empty.contains("Waiting for the first host"));
        assert!(empty.contains("inspr onboard &lt;host&gt;"));
        assert!(empty.contains("awaiting first heartbeat"));

        let host = Host {
            name: "ares".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("hash".to_string()),
            last_seen: None,
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            location: None,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
        };
        let lone = render_home(&[host], "csb1", 1000, &[], "local access", false);
        assert!(lone.contains(r#"<aside class="lone-state""#));
        assert!(lone.contains("First host is on the map"));
        assert!(lone.contains(r#"data-live="awaiting_first_heartbeat""#));
    }

    #[test]
    fn declared_hosts_payload_keeps_declared_and_runtime_state_separate() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "access": {
                    "lanHostname": "hsb8.lan",
                    "lanIp": "192.168.1.100",
                    "tailnet": "hsb8"
                }
            },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [
                {
                    "wing": "ops",
                    "name": "pharos-beacon",
                    "passive": true,
                    "statusPolicy": { "source": "pharos-runtime" }
                }
            ],
            "policy": {
                "declaredOnly": true,
                "runtimeStateOwner": "pharos",
                "privilegedActions": { "mode": "none", "janusRequired": false }
            }
        }))
        .expect("manifest parses");
        let runtime = Host {
            name: "hsb8".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            location: None,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
            },
            service_observations: vec![ServiceObservation::nix_freshness(&NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
            })],
        };

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            std::slice::from_ref(&runtime),
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(payload["schema"], "inspr.pharos.declared-hosts.v1");
        assert_eq!(
            payload["declared_hosts"][0]["declared"]["services"][0]["statusPolicy"]["source"],
            "pharos-runtime"
        );
        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "observed");
        assert_eq!(payload["declared_hosts"][0]["runtime"]["liveness"], "live");
        assert!(payload["declared_hosts"][0]["runtime"]["token_hash"].is_null());
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes_summary"]["label"],
            "not probed"
        );
        assert!(!payload.to_string().contains("stored-token-hash"));
    }

    #[test]
    fn declared_hosts_payload_adds_server_probe_runtime_overlay() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": { "name": "hsb8" },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [
                {
                    "wing": "ops",
                    "name": "Home Assistant",
                    "url": "http://hsb8.lan:8123/",
                    "statusPolicy": { "source": "pharos-runtime" }
                }
            ],
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");
        let mut probes = BTreeMap::new();
        probes.insert(
            "hsb8".to_string(),
            vec![ServerProbeObservation {
                id: "home-assistant".to_string(),
                service: "Home Assistant".to_string(),
                source: "server",
                policy: "pharos-runtime",
                kind: "tcp-connect",
                target: Some("http://hsb8.lan:8123/".to_string()),
                state: ServiceObservationState::Healthy,
                server_reachable: Some(true),
                client_reachable: None,
                summary: "server can reach hsb8.lan:8123".to_string(),
                checked_at: 1000,
            }],
        );

        let payload =
            declared_hosts_payload(std::slice::from_ref(&manifest), &[], &[], &probes, 1000);

        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["state"],
            "healthy"
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["server_reachable"],
            true
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes"][0]["client_reachable"],
            serde_json::Value::Null
        );
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["server_probes_summary"]["label"],
            "server reachable"
        );
        assert!(payload["declared_hosts"][0]["declared"]["services"][0]
            .get("server_probes")
            .is_none());
    }

    #[test]
    fn declared_hosts_payload_marks_missing_runtime_as_pending() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "new-host",
            "host": { "name": "new-host" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            &[],
            &BTreeMap::new(),
            1000,
        );

        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "pending");
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["liveness"],
            "awaiting_first_heartbeat"
        );
    }

    #[test]
    fn server_probe_policy_is_explicitly_declared() {
        let hostdash_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Client probe",
            "url": "http://example.test/",
            "probe": true,
            "statusPolicy": { "source": "hostdash-probe" }
        }))
        .expect("service parses");
        assert!(!should_server_probe(&hostdash_service));

        let pharos_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Server probe",
            "url": "http://example.test/",
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");
        assert!(should_server_probe(&pharos_service));

        let named_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Named server probe",
            "url": "http://example.test/",
            "probe": "server"
        }))
        .expect("service parses");
        assert!(should_server_probe(&named_service));

        let passive_runtime_service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Beacon observation",
            "passive": true,
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");
        assert!(!should_server_probe(&passive_runtime_service));
    }

    #[test]
    fn sanitized_probe_target_drops_userinfo_query_and_fragment() {
        let url = Url::parse("https://user:secret@example.test:8443/path?token=secret#frag")
            .expect("valid URL");

        assert_eq!(
            sanitized_probe_target(&url),
            "https://example.test:8443/path"
        );
    }

    fn report_test_state(require_report_token: bool) -> AppState {
        report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token,
            report_token_mode: BeaconTokenMode::Local,
            janus_token_hash_sources: vec![],
            local_register_enabled: true,
        })
    }

    fn report_test_state_with_auth(beacon_auth: BeaconAuth) -> AppState {
        AppState {
            store: Arc::new(Store::new(None)),
            manifests: Arc::new(ManifestRegistry::default()),
            auth: None,
            beacon_auth,
        }
    }

    fn janus_hash_file(host: &str, token: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "pharos-janus-token-hashes-{}-{}.json",
            std::process::id(),
            nanos
        ));
        let payload = json!({
            "schema": JANUS_BEACON_TOKEN_HASH_SCHEMA,
            "hosts": [
                {
                    "name": host,
                    "token_sha256": token_hash(token)
                }
            ]
        });
        std::fs::write(&path, serde_json::to_string(&payload).unwrap()).expect("write hash file");
        path
    }

    fn janus_hash_dir(entries: &[(&str, &str)]) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moves forward")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "pharos-janus-token-hash-dir-{}-{}",
            std::process::id(),
            nanos
        ));
        std::fs::create_dir(&dir).expect("create hash dir");
        for (host, token) in entries {
            let path = dir.join(format!("{host}.json"));
            let payload = json!({
                "schema": JANUS_BEACON_TOKEN_HASH_SCHEMA,
                "hosts": [
                    {
                        "name": host,
                        "token_sha256": token_hash(token)
                    }
                ]
            });
            std::fs::write(&path, serde_json::to_string(&payload).unwrap())
                .expect("write hash file");
        }
        dir
    }

    fn test_report(host: &str) -> HostReport {
        HostReport {
            schema: pharos_core::HOST_REPORT_SCHEMA.to_string(),
            version: pharos_core::HOST_REPORT_VERSION,
            name: host.to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
            service_observations: vec![],
            location: None,
        }
    }

    fn register_test_token(state: &AppState, host: &str, token: &str) {
        state.store.register(
            HostRegistration {
                name: host.to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            },
            token_hash(token),
        );
    }

    fn bearer_headers(token: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            axum::http::HeaderValue::from_str(&format!("Bearer {token}"))
                .expect("valid bearer header"),
        );
        headers
    }

    #[tokio::test]
    async fn report_accepts_registered_host_without_token_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state.clone()),
            HeaderMap::new(),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(state
            .store
            .list()
            .into_iter()
            .find(|host| host.name == "ares")
            .and_then(|host| host.last_seen)
            .is_some());
    }

    #[tokio::test]
    async fn report_accepts_valid_token_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("valid-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_rejects_invalid_token_even_when_strict_disabled() {
        let state = report_test_state(false);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("wrong-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_rejects_missing_token_when_strict_enabled() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "valid-token");

        let status = report(State(state), HeaderMap::new(), Json(test_report("ares"))).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn report_accepts_valid_token_when_strict_enabled() {
        let state = report_test_state(true);
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state),
            bearer_headers("valid-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_accepts_janus_hash_file_token_without_local_registration() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: false,
        });

        let status = report(
            State(state.clone()),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        assert!(!state.store.has_token("ares"));
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_rejects_local_token_when_janus_mode_is_enabled() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: false,
        });
        register_test_token(&state, "ares", "local-token");

        let status = report(
            State(state),
            bearer_headers("local-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_accepts_local_or_janus_token_in_dual_mode() {
        let path = janus_hash_file("ares", "janus-token");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Dual,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(path.clone())],
            local_register_enabled: true,
        });
        register_test_token(&state, "athena", "local-token");

        let janus_status = report(
            State(state.clone()),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;
        let local_status = report(
            State(state),
            bearer_headers("local-token"),
            Json(test_report("athena")),
        )
        .await;

        assert_eq!(janus_status, StatusCode::NO_CONTENT);
        assert_eq!(local_status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_file(path);
    }

    #[tokio::test]
    async fn report_accepts_janus_hash_sidecar_directory() {
        let dir = janus_hash_dir(&[("ares", "ares-token"), ("athena", "athena-token")]);
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::Dir(dir.clone())],
            local_register_enabled: false,
        });

        let ares_status = report(
            State(state.clone()),
            bearer_headers("ares-token"),
            Json(test_report("ares")),
        )
        .await;
        let athena_status = report(
            State(state),
            bearer_headers("athena-token"),
            Json(test_report("athena")),
        )
        .await;

        assert_eq!(ares_status, StatusCode::NO_CONTENT);
        assert_eq!(athena_status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn report_ignores_janus_hash_sidecar_directory_temp_files() {
        let dir = janus_hash_dir(&[("ares", "ares-token")]);
        std::fs::write(dir.join(".ares.json.123.tmp"), "not-json").expect("write temp sidecar");
        std::fs::write(dir.join("README.txt"), "not-json").expect("write ignored text file");
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::Dir(dir.clone())],
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("ares-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::NO_CONTENT);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn report_fails_closed_when_janus_hash_file_is_unavailable() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: None,
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(PathBuf::from(
                "/no/such/pharos-token-hashes.json",
            ))],
            local_register_enabled: false,
        });

        let status = report(
            State(state),
            bearer_headers("janus-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn local_register_is_disabled_by_default_in_janus_mode() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap".to_string()),
            require_report_token: true,
            report_token_mode: BeaconTokenMode::Janus,
            janus_token_hash_sources: vec![JanusTokenHashSource::File(PathBuf::from(
                "/run/janus/pharos-token-hashes.json",
            ))],
            local_register_enabled: false,
        });

        let (status, Json(payload)) = register(
            State(state),
            bearer_headers("bootstrap"),
            Json(HostRegistration {
                name: "ares".to_string(),
                role: "server".to_string(),
                is_nix: true,
                heartbeat_interval_secs: 60,
            }),
        )
        .await;

        assert_eq!(status, StatusCode::GONE);
        assert_eq!(
            payload["error"],
            "local registration disabled; use Janus-managed beacon token issuance"
        );
    }

    #[test]
    fn janus_token_hash_contract_rejects_secret_shaped_or_invalid_hashes() {
        let err = parse_janus_token_hashes(
            r#"{
                "schema": "inspr.pharos.beacon-token-hashes.v1",
                "tokens": { "ares": "pharos_not_a_hash" }
            }"#,
        )
        .expect_err("invalid hash is rejected");

        assert_eq!(err, JanusTokenHashError::InvalidHash);
    }

    #[tokio::test]
    async fn server_probe_service_reports_reachable_tcp_target() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind test listener");
        let addr = listener.local_addr().expect("listener address");
        let service: ManifestService = serde_json::from_value(json!({
            "wing": "ops",
            "name": "Local Test",
            "url": format!("http://{addr}/"),
            "statusPolicy": { "source": "pharos-runtime" }
        }))
        .expect("service parses");

        let observation = server_probe_service(&service, 1000).await;

        assert_eq!(observation.state, ServiceObservationState::Healthy);
        assert_eq!(observation.server_reachable, Some(true));
        assert_eq!(observation.client_reachable, None);
        assert_eq!(observation.kind, "tcp-connect");
    }
}
