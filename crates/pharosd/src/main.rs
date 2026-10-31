//! pharosd — the Pharos server.
//!
//! Machine routes take beacon registrations and reports; the Fleet page and
//! its data sit behind login. Hosts live in one JSON store (`PHAROS_DB`).

mod auth;
#[cfg(test)]
#[path = "../build_support.rs"]
mod build_support;
mod durable_file;
mod fleet_api;
mod fleet_data;
mod fleet_view;
mod host_probes;
mod icons;
mod pages;
mod probe_support;
mod public_mount;
mod routes;
mod startup;
mod store;
mod ui;

use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, FromRef, Path as AxumPath, RawQuery, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::fleet_data::FleetData;
use pharos_core::{
    liveness, Host, HostRegistration, HostRegistrationResponse, HostReport, PublicBasePath,
    MAX_HOST_REGISTRATION_BYTES, MAX_HOST_REPORT_BYTES,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::{Auth, AuthConfig, AuthState, AuthUser};
use crate::fleet_api::fleet_json;
use crate::fleet_data::{spawn_fleet_data_loop, FleetDataRuntime};
use crate::host_probes::{spawn_host_probe_loop, HostProbeRuntime};
use crate::routes::build_router;
use crate::startup::*;
use crate::store::Store;
use crate::ui::*;

/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    auth: AuthState,
    beacon_auth: BeaconAuth,
    host_probes: Option<Arc<HostProbeRuntime>>,
    fleet_data: Option<Arc<FleetDataRuntime>>,
    public_base_path: PublicBasePath,
    started_at: i64,
}

impl FromRef<AppState> for AuthState {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

#[derive(Clone)]
struct BeaconAuth {
    /// Set only while an operator has registration switched on.
    registration_token: Option<String>,
}

impl BeaconAuth {
    fn from_env() -> Result<Self, String> {
        Self::validated(
            env_nonempty("PHAROS_BEACON_TOKEN_MODE").as_deref(),
            env_bool("PHAROS_REQUIRE_BEACON_TOKEN")?,
            env_bool("PHAROS_ALLOW_LOCAL_REGISTER")?.unwrap_or(false),
            env_nonempty("PHAROS_REGISTRATION_TOKEN").is_some(),
            || {
                pharos_core::secret_input::optional_secret("PHAROS_REGISTRATION_TOKEN")
                    .map_err(|error| error.to_string())
            },
        )
    }

    fn validated(
        mode: Option<&str>,
        require_report_token: Option<bool>,
        allow_register: bool,
        inline_registration_token: bool,
        registration_token_file: impl FnOnce() -> Result<Option<String>, String>,
    ) -> Result<Self, String> {
        if let Some(mode) = mode {
            validate_beacon_token_mode(mode)?;
        }
        if require_report_token == Some(false) {
            return Err(
                "PHAROS_REQUIRE_BEACON_TOKEN=false is not supported; every report needs a bearer token"
                    .to_string(),
            );
        }
        if inline_registration_token {
            return Err(
                "PHAROS_REGISTRATION_TOKEN is not supported; use PHAROS_REGISTRATION_TOKEN_FILE"
                    .to_string(),
            );
        }
        if !allow_register {
            return Ok(Self {
                registration_token: None,
            });
        }
        let registration_token = registration_token_file()?.ok_or_else(|| {
            "PHAROS_ALLOW_LOCAL_REGISTER=true requires PHAROS_REGISTRATION_TOKEN_FILE".to_string()
        })?;
        Ok(Self {
            registration_token: Some(registration_token),
        })
    }

    fn registration_status(&self, headers: &HeaderMap) -> RegistrationAuth {
        let Some(expected) = &self.registration_token else {
            return RegistrationAuth::Disabled;
        };
        match bearer_token(headers) {
            Some(actual) if constant_time_eq(actual, expected) => RegistrationAuth::Allowed,
            _ => RegistrationAuth::Denied,
        }
    }
}

enum RegistrationAuth {
    Allowed,
    Denied,
    Disabled,
}

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
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

fn env_bool(name: &str) -> Result<Option<bool>, String> {
    let Some(value) = env_nonempty(name) else {
        return Ok(None);
    };
    parse_bool(&value)
        .map(Some)
        .ok_or_else(|| format!("{name} must be one of true/false, 1/0, yes/no, or on/off"))
}

/// Report tokens are only ever checked against the store. Any other selected
/// mode refuses startup rather than silently changing who can report.
fn validate_beacon_token_mode(value: &str) -> Result<(), String> {
    match value.trim().to_ascii_lowercase().as_str() {
        "local" => Ok(()),
        _ => Err(format!(
            "unsupported PHAROS_BEACON_TOKEN_MODE value {value:?}; expected local"
        )),
    }
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

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz() -> Response {
    (no_store_headers(), Json(json!({ "ready": true }))).into_response()
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({
        "name": "pharosd",
        "version": APP_VERSION,
        "version_scheme": VERSION_SCHEME,
        "release_channel": RELEASE_CHANNEL,
        "release_sequence": RELEASE_SEQUENCE.parse::<u64>().expect("embedded release sequence"),
        "ecosystem_versions": { "cargo_semver": env!("CARGO_PKG_VERSION") },
        "migration_anchor": {
            "last_legacy_version": LAST_LEGACY_VERSION,
            "last_legacy_release_sequence": LAST_LEGACY_RELEASE_SEQUENCE.parse::<u64>().expect("embedded legacy sequence"),
            "first_calendar_version": FIRST_CALENDAR_VERSION,
            "first_calendar_release_sequence": FIRST_CALENDAR_RELEASE_SEQUENCE.parse::<u64>().expect("embedded first calendar sequence"),
            "last_calendar_v1_version": LAST_CALENDAR_V1_VERSION,
            "last_calendar_v1_release_sequence": LAST_CALENDAR_V1_RELEASE_SEQUENCE.parse::<u64>().expect("embedded last calendar v1 sequence"),
            "first_calendar_v2_version": FIRST_CALENDAR_V2_VERSION,
            "first_calendar_v2_release_sequence": FIRST_CALENDAR_V2_RELEASE_SEQUENCE.parse::<u64>().expect("embedded first calendar v2 sequence")
        },
        "git_commit": GIT_COMMIT,
        "display_version": release_label()
    }))
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rep): Json<HostReport>,
) -> Response {
    if let Err(error) = rep.validate_contract() {
        tracing::warn!(error = %error, "report rejected: invalid report contract");
        return StatusCode::BAD_REQUEST.into_response();
    }
    let Some(token) = bearer_token(&headers) else {
        tracing::warn!(host = %rep.name, "report rejected: missing bearer token");
        return StatusCode::UNAUTHORIZED.into_response();
    };
    if !local_token_matches(&state.store, &rep.name, &token_hash(token)) {
        tracing::warn!(host = %rep.name, "report rejected: invalid bearer token");
        return StatusCode::UNAUTHORIZED.into_response();
    }
    tracing::info!(host = %rep.name, "report received");
    let host_name = rep.name.clone();
    if let Err(error) = state.store.record(rep, now_unix()) {
        tracing::error!(host = %host_name, error = %error, "report could not be durably recorded");
        return StatusCode::SERVICE_UNAVAILABLE.into_response();
    }
    StatusCode::NO_CONTENT.into_response()
}

/// The one path to add a host or rotate its token. Off unless an operator
/// switches it on with a token file; the returned beacon token is shown once.
/// Registering an existing host replaces its token (see RUNBOOK.md).
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<HostRegistration>,
) -> Response {
    if let Err(error) = registration.validate_contract() {
        tracing::warn!(error = %error, "registration rejected: invalid contract");
        return register_response(
            StatusCode::BAD_REQUEST,
            json!({ "error": "invalid registration contract" }),
        );
    }
    match state.beacon_auth.registration_status(&headers) {
        RegistrationAuth::Allowed => {}
        RegistrationAuth::Disabled => {
            return register_response(
                StatusCode::GONE,
                json!({ "error": "local registration disabled" }),
            );
        }
        RegistrationAuth::Denied => {
            return register_response(
                StatusCode::UNAUTHORIZED,
                json!({ "error": "registration token invalid" }),
            );
        }
    }

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("failed to generate beacon token: {err}");
            return register_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                json!({ "error": "token generation failed" }),
            );
        }
    };
    let response = HostRegistrationResponse {
        name: registration.name.clone(),
        token: token.clone(),
    };
    let host = match state.store.register(registration, token_hash(&token)) {
        Ok(host) => host,
        Err(error) => {
            tracing::error!(error = %error, "registration could not be durably recorded");
            return register_response(
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": "registration could not be durably recorded" }),
            );
        }
    };
    tracing::info!(host = %host.name, "beacon token issued");
    register_response(
        StatusCode::CREATED,
        serde_json::to_value(response).expect("registration response serializes"),
    )
}

fn register_response(status: StatusCode, payload: serde_json::Value) -> Response {
    (status, no_store_headers(), Json(payload)).into_response()
}

/// Named fields only, so no store-side credential can ever reach this payload.
fn host_payload(host: &Host, now: i64) -> serde_json::Value {
    json!({
        "name": host.name,
        "role": host.role,
        "is_nix": host.is_nix,
        "report_version": host.report_version,
        "last_seen": host.last_seen,
        "heartbeat_interval_secs": host.heartbeat_interval_secs,
        "liveness": liveness(host.last_seen, host.heartbeat_interval_secs, now),
        "freshness": host.freshness,
        "kernel": host.kernel,
        "service_observations": host.service_observations,
    })
}

/// Whether the data file is usable, how old it is, and what is wrong with it.
fn fleet_data_payload(runtime: Option<&FleetDataRuntime>, now: i64) -> serde_json::Value {
    let Some(runtime) = runtime else {
        return json!({ "configured": false });
    };
    let view = runtime.view();
    let updated_at = view.data.as_deref().and_then(FleetData::updated_at_unix);
    json!({
        "configured": true,
        "updated_at": updated_at,
        "age_secs": updated_at.map(|updated| now.saturating_sub(updated).max(0)),
        "problem": view.problem,
    })
}

async fn hosts_json(State(state): State<AppState>) -> impl IntoResponse {
    let now = now_unix();
    let hosts: Vec<_> = state
        .store
        .list()
        .iter()
        .map(|host| host_payload(host, now))
        .collect();
    let host_probes = state
        .host_probes
        .as_deref()
        .map(|runtime| runtime.snapshot(now))
        .unwrap_or_default();
    (
        no_store_headers(),
        Json(json!({
            "as_of": now,
            "hosts": hosts,
            "host_probes": host_probes,
            "fleet_data": fleet_data_payload(state.fleet_data.as_deref(), now),
        })),
    )
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

const MAX_RENDERED_RESPONSE_BYTES: usize = 8 * 1024 * 1024;

async fn security_headers(request: axum::extract::Request, next: middleware::Next) -> Response {
    let auth_response = request.uri().path().starts_with("/auth/");
    let mut response = secure_response(next.run(request).await).await;
    if auth_response {
        for (name, value) in no_store_headers() {
            response
                .headers_mut()
                .insert(name, axum::http::HeaderValue::from_static(value));
        }
    }
    response
}

async fn secure_response(response: Response) -> Response {
    let is_html = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("text/html"));

    let nonce = if is_html {
        match content_security_nonce() {
            Ok(nonce) => Some(nonce),
            Err(()) => {
                return security_policy_failure_response();
            }
        }
    } else {
        None
    };

    let mut response = if let Some(nonce) = nonce.as_deref() {
        let (mut parts, body) = response.into_parts();
        let bytes = match axum::body::to_bytes(body, MAX_RENDERED_RESPONSE_BYTES).await {
            Ok(bytes) => bytes,
            Err(_) => return security_policy_failure_response(),
        };
        let html = match String::from_utf8(bytes.to_vec()) {
            Ok(html) => html,
            Err(_) => return security_policy_failure_response(),
        };
        let script_open = format!(r#"<script nonce="{nonce}" "#);
        let style_open = format!(r#"<style nonce="{nonce}" "#);
        let html = html
            .replace("<script", &script_open)
            .replace("<style", &style_open);
        parts.headers.remove(header::CONTENT_LENGTH);
        Response::from_parts(parts, axum::body::Body::from(html))
    } else {
        response
    };

    apply_security_headers(response.headers_mut(), nonce.as_deref());
    response
}

fn content_security_nonce() -> Result<String, ()> {
    let mut random = [0_u8; 16];
    getrandom::getrandom(&mut random).map_err(|_| ())?;
    let mut nonce = String::with_capacity(random.len() * 2);
    for byte in random {
        use std::fmt::Write as _;
        write!(nonce, "{byte:02x}").map_err(|_| ())?;
    }
    Ok(nonce)
}

fn apply_security_headers(headers: &mut HeaderMap, nonce: Option<&str>) {
    use axum::http::{HeaderName, HeaderValue};

    let csp = nonce.map_or_else(
        || "default-src 'none'; base-uri 'none'; frame-ancestors 'none'".to_string(),
        |nonce| {
            format!(
                "default-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'; script-src 'self' 'nonce-{nonce}'; script-src-attr 'none'; style-src 'self' 'nonce-{nonce}'; style-src-attr 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; media-src 'none'; frame-src 'none'; worker-src 'none'; manifest-src 'none'"
            )
        },
    );
    let csp = HeaderValue::from_str(&csp).expect("generated CSP is a valid header");
    headers.insert(HeaderName::from_static("content-security-policy"), csp);
    headers.insert(
        HeaderName::from_static("x-frame-options"),
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        HeaderName::from_static("x-content-type-options"),
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        HeaderName::from_static("referrer-policy"),
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        HeaderName::from_static("permissions-policy"),
        HeaderValue::from_static(
            "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
        ),
    );
    headers.insert(
        HeaderName::from_static("strict-transport-security"),
        HeaderValue::from_static("max-age=31536000; includeSubDomains"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-opener-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("cross-origin-resource-policy"),
        HeaderValue::from_static("same-origin"),
    );
    headers.insert(
        HeaderName::from_static("x-permitted-cross-domain-policies"),
        HeaderValue::from_static("none"),
    );
}

fn security_policy_failure_response() -> Response {
    let mut response = (
        StatusCode::INTERNAL_SERVER_ERROR,
        "response security policy unavailable",
    )
        .into_response();
    apply_security_headers(response.headers_mut(), None);
    response
}

fn no_store_html(state: &AppState, body: String) -> impl IntoResponse {
    (
        no_store_headers(),
        Html(public_mount::localize_document(
            &state.public_base_path,
            &body,
        )),
    )
}

#[tokio::main]
async fn main() {
    if std::env::args_os().nth(1).as_deref() == Some(std::ffi::OsStr::new("healthcheck")) {
        // Container probe (PHAROS-203): every verdict carries its reason so
        // `docker inspect --format '{{json .State.Health}}'` is diagnosable.
        match container_healthcheck().await {
            Ok(detail) => {
                println!("pharosd healthcheck: {detail}");
                std::process::exit(0);
            }
            Err(reason) => {
                eprintln!("pharosd healthcheck: {reason}");
                std::process::exit(1);
            }
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let startup = StartupConfig::from_env()
        .unwrap_or_else(|err| panic!("invalid Pharos startup configuration: {err}"));
    let host_store_path = std::env::var("PHAROS_DB").ok().map(PathBuf::from);
    let store = Arc::new(
        Store::new(host_store_path.clone())
            .unwrap_or_else(|error| panic!("host store startup failed: {error}")),
    );
    let auth = Auth::from_config(startup.auth, startup.public_base_path.clone())
        .await
        .unwrap_or_else(|err| panic!("Pharos authentication startup failed: {err}"));
    let host_probes = HostProbeRuntime::from_env(host_store_path.as_deref())
        .unwrap_or_else(|error| panic!("host probe startup failed: {error}"))
        .map(Arc::new);
    let state = AppState {
        store,
        auth,
        beacon_auth: startup.beacon_auth,
        host_probes: host_probes.clone(),
        fleet_data: FleetDataRuntime::from_env(),
        public_base_path: startup.public_base_path.clone(),
        started_at: now_unix(),
    };
    if let Some(runtime) = host_probes {
        spawn_host_probe_loop(runtime);
    }
    if let Some(runtime) = state.fleet_data.clone() {
        spawn_fleet_data_loop(runtime);
    }

    let app = build_router(state);

    let listener = tokio::net::TcpListener::bind(startup.addr)
        .await
        .expect("bind PHAROS_ADDR");
    tracing::info!(
        "pharosd v{} ({}) listening on http://{}",
        APP_VERSION,
        VERSION_SCHEME,
        startup.addr
    );
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::HostRegistrationResponse as RegistrationReply;
    use std::sync::atomic::{AtomicU64, Ordering};

    static TEST_PATH_SEQUENCE: AtomicU64 = AtomicU64::new(1);

    fn temp_path(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "pharos-{label}-{}-{}",
            std::process::id(),
            TEST_PATH_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    async fn json_response(response: Response) -> (StatusCode, HeaderMap, serde_json::Value) {
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .expect("response body is bounded");
        let payload = serde_json::from_slice(&bytes).expect("response body is JSON");
        (status, headers, payload)
    }

    fn report_test_state() -> AppState {
        report_test_state_with_auth(BeaconAuth {
            registration_token: None,
        })
    }

    fn report_test_state_with_auth(beacon_auth: BeaconAuth) -> AppState {
        AppState {
            store: Arc::new(Store::new(None).expect("in-memory host store starts")),
            auth: AuthState::default(),
            beacon_auth,
            host_probes: None,
            fleet_data: None,
            public_base_path: PublicBasePath::root(),
            started_at: now_unix(),
        }
    }

    async fn serve_test_app(state: AppState) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = build_router(state);
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{address}")
    }

    fn test_client() -> reqwest::Client {
        reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap()
    }

    fn test_report(host: &str) -> HostReport {
        HostReport {
            schema: pharos_core::HOST_REPORT_SCHEMA.to_string(),
            version: pharos_core::HOST_REPORT_VERSION,
            name: host.to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
            freshness: pharos_core::NixFreshness {
                applicable: true,
                ..Default::default()
            },
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            inbound_rtt_ms: None,
            location: None,
            preferences: Default::default(),
            deployed_artifact: None,
        }
    }

    fn test_registration(host: &str) -> HostRegistration {
        HostRegistration {
            schema: pharos_core::HOST_REGISTRATION_SCHEMA.to_string(),
            version: pharos_core::HOST_REGISTRATION_VERSION,
            name: host.to_string(),
            role: "server".to_string(),
            is_nix: true,
            heartbeat_interval_secs: 60,
        }
    }

    fn register_test_token(state: &AppState, host: &str, token: &str) {
        state
            .store
            .register(test_registration(host), token_hash(token))
            .expect("test registration persists");
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
    async fn version_endpoint_reports_embedded_build_metadata() {
        let Json(payload) = version().await;

        assert_eq!(payload["name"], "pharosd");
        assert_eq!(payload["version"], APP_VERSION);
        assert_eq!(payload["version_scheme"], VERSION_SCHEME);
        assert_eq!(payload["release_channel"], RELEASE_CHANNEL);
        assert_eq!(
            payload["release_sequence"],
            RELEASE_SEQUENCE
                .parse::<u64>()
                .expect("embedded release sequence")
        );
        assert_eq!(
            payload["ecosystem_versions"]["cargo_semver"],
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(
            payload["migration_anchor"]["last_legacy_version"],
            LAST_LEGACY_VERSION
        );
        assert_eq!(
            payload["migration_anchor"]["last_legacy_release_sequence"],
            0
        );
        assert_eq!(
            payload["migration_anchor"]["first_calendar_version"],
            FIRST_CALENDAR_VERSION
        );
        assert_eq!(
            payload["migration_anchor"]["first_calendar_release_sequence"],
            1
        );
        assert_eq!(payload["git_commit"], GIT_COMMIT);
        assert_eq!(payload["display_version"], release_label());
    }

    #[tokio::test]
    async fn readiness_answers_without_any_external_dependency() {
        let (status, headers, payload) = json_response(readyz().await).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(payload, json!({ "ready": true }));
        assert!(headers.contains_key(header::CACHE_CONTROL));
    }

    #[tokio::test]
    async fn rendered_html_receives_nonce_csp_and_browser_security_headers() {
        let response = secure_response(
            Html("<html><head><style>body{color:black}</style></head><body><script>window.ok=true</script></body></html>")
                .into_response(),
        )
        .await;
        let headers = response.headers().clone();
        let csp = headers
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .expect("CSP header");
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|tail| tail.split('\'').next())
            .expect("CSP nonce");

        assert_eq!(headers.get("x-frame-options").unwrap(), "DENY");
        assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
        assert_eq!(headers.get("referrer-policy").unwrap(), "no-referrer");
        assert!(headers.contains_key("permissions-policy"));
        assert!(headers.contains_key("strict-transport-security"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src-attr 'none'"));
        assert!(csp.contains("img-src 'self' data:;"));
        assert!(csp.contains("connect-src 'self';"));
        assert!(csp.contains("worker-src 'none';"));
        assert!(!csp.contains("https://"));
        assert!(!csp.contains("unsafe-eval"));
        assert!(!csp.contains("script-src 'self' 'unsafe-inline'"));

        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("secured HTML body");
        let body = std::str::from_utf8(&body).expect("secured HTML is UTF-8");
        assert!(body.contains(&format!(r#"<style nonce="{nonce}" "#)));
        assert!(body.contains(&format!(r#"<script nonce="{nonce}" "#)));
    }

    #[test]
    fn beacon_token_mode_accepts_only_store_checked_tokens() {
        assert!(validate_beacon_token_mode(" Local ").is_ok());
        for mode in ["mvp", "janus", "dual", "forge", "typo"] {
            assert!(validate_beacon_token_mode(mode).is_err(), "{mode}");
        }
    }

    #[tokio::test]
    async fn report_schemas_v6_and_v7_pass_on_a_pharos1_store_with_its_tokens() {
        let path = temp_path("pharos1-store");
        std::fs::write(&path, include_str!("testdata/pharos1-store.json"))
            .expect("store fixture written");
        let state = AppState {
            store: Arc::new(Store::new(Some(path.clone())).expect("Pharos 1 store loads")),
            ..report_test_state()
        };
        for (schema, version) in [
            (
                pharos_core::HOST_REPORT_V6_SCHEMA,
                pharos_core::HOST_REPORT_V6_VERSION,
            ),
            (
                pharos_core::HOST_REPORT_SCHEMA,
                pharos_core::HOST_REPORT_VERSION,
            ),
        ] {
            let body: HostReport = serde_json::from_value(serde_json::json!({
                "schema": schema,
                "version": version,
                "name": "demeter",
                "role": "server",
                "is_nix": true,
                "heartbeat_interval_secs": 60,
                "freshness": {"applicable": true}
            }))
            .expect("report parses");
            let response = report(
                State(state.clone()),
                bearer_headers("fixture-token-demeter"),
                Json(body),
            )
            .await;
            assert_eq!(response.status(), StatusCode::NO_CONTENT, "{schema}");
            assert_eq!(
                state.store.get("demeter").expect("host").report_version,
                version
            );
        }

        let response = report(
            State(state),
            bearer_headers("fixture-token-hermes"),
            Json(test_report("demeter")),
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        std::fs::remove_file(path).expect("store fixture removed");
    }

    #[tokio::test]
    async fn report_accepts_the_right_token() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");

        let status = report(
            State(state.clone()),
            bearer_headers("valid-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::NO_CONTENT);
        assert!(state.store.get("ares").and_then(|h| h.last_seen).is_some());
    }

    #[tokio::test]
    async fn report_rejects_a_wrong_token() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");
        let before = state.store.get("ares");

        let status = report(
            State(state.clone()),
            bearer_headers("wrong-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.store.get("ares"), before);
    }

    #[tokio::test]
    async fn report_rejects_a_missing_token() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");
        let before = state.store.get("ares");

        let status = report(
            State(state.clone()),
            HeaderMap::new(),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(state.store.get("ares"), before);
    }

    #[tokio::test]
    async fn report_rejects_an_unknown_host_and_does_not_create_it() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");

        let with_token = report(
            State(state.clone()),
            bearer_headers("valid-token"),
            Json(test_report("hermes")),
        )
        .await;
        let without_token = report(
            State(state.clone()),
            HeaderMap::new(),
            Json(test_report("hermes")),
        )
        .await;

        assert_eq!(with_token.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(without_token.status(), StatusCode::UNAUTHORIZED);
        assert!(state.store.get("hermes").is_none());
    }

    #[tokio::test]
    async fn report_rejects_a_known_host_with_no_stored_hash() {
        let state = report_test_state();
        state
            .store
            .record(test_report("ares"), 100)
            .expect("host without a hash persists");
        assert!(state.store.token_hash_for("ares").is_none());

        let status = report(
            State(state),
            bearer_headers("any-token"),
            Json(test_report("ares")),
        )
        .await;

        assert_eq!(status.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn registering_again_rotates_the_token_and_keeps_report_history() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
        });
        register_test_token(&state, "ares", "old-token");
        report(
            State(state.clone()),
            bearer_headers("old-token"),
            Json(test_report("ares")),
        )
        .await;
        let last_seen = state.store.get("ares").and_then(|h| h.last_seen);
        assert!(last_seen.is_some());

        let response = register(
            State(state.clone()),
            bearer_headers("bootstrap-fixture"),
            Json(test_registration("ares")),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::CREATED);
        let reply: RegistrationReply = serde_json::from_value(payload).unwrap();
        assert_eq!(state.store.get("ares").and_then(|h| h.last_seen), last_seen);

        let old = report(
            State(state.clone()),
            bearer_headers("old-token"),
            Json(test_report("ares")),
        )
        .await;
        assert_eq!(old.status(), StatusCode::UNAUTHORIZED);
        let new = report(
            State(state),
            bearer_headers(&reply.token),
            Json(test_report("ares")),
        )
        .await;
        assert_eq!(new.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn report_returns_unavailable_and_rolls_back_when_host_store_persistence_fails() {
        let path = temp_path("report-persistence-failure");
        let mut state = report_test_state();
        state.store = Arc::new(Store::new(None).expect("in-memory host store starts"));
        register_test_token(&state, "persistence-test", "valid-token");
        let registered = state.store.get("persistence-test");
        let hosts = state.store.list();
        state.store = Arc::new(Store::with_failing_path_for_test(path.clone(), hosts));
        std::fs::create_dir(&path).expect("rename-blocking destination created");

        let response = report(
            State(state.clone()),
            bearer_headers("valid-token"),
            Json(test_report("persistence-test")),
        )
        .await;

        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(state.store.get("persistence-test"), registered);
        std::fs::remove_dir_all(path).expect("test destination removed");
    }

    #[tokio::test]
    async fn registration_never_returns_a_credential_when_persistence_fails() {
        let path = temp_path("registration-persistence-failure");
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
        });
        state.store = Arc::new(Store::new(Some(path.clone())).expect("durable store starts"));
        std::fs::create_dir(&path).expect("rename-blocking destination created");

        let response = register(
            State(state.clone()),
            bearer_headers("bootstrap-fixture"),
            Json(test_registration("registration-test")),
        )
        .await;
        let (status, _, payload) = json_response(response).await;

        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert!(payload.get("token").is_none());
        assert!(state.store.get("registration-test").is_none());
        std::fs::remove_dir_all(path).expect("test destination removed");
    }

    #[tokio::test]
    async fn credential_bearing_registration_response_is_never_cacheable() {
        let state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
        });
        let response = register(
            State(state.clone()),
            bearer_headers("bootstrap-fixture"),
            Json(test_registration("registration-cache-test")),
        )
        .await;
        let (status, headers, payload) = json_response(response).await;

        assert_eq!(status, StatusCode::CREATED);
        let reply: RegistrationReply = serde_json::from_value(payload).unwrap();
        assert_eq!(
            state.store.token_hash_for("registration-cache-test"),
            Some(token_hash(&reply.token))
        );
        assert_eq!(
            headers
                .get(header::CACHE_CONTROL)
                .and_then(|v| v.to_str().ok()),
            Some("no-store, no-cache, max-age=0, must-revalidate")
        );
        assert_eq!(
            headers.get(header::PRAGMA).and_then(|v| v.to_str().ok()),
            Some("no-cache")
        );
    }

    #[tokio::test]
    async fn registration_is_gone_when_switched_off_and_denied_on_a_wrong_token() {
        let off = report_test_state();
        let response = register(
            State(off.clone()),
            bearer_headers("bootstrap-fixture"),
            Json(test_registration("ares")),
        )
        .await;
        let (status, _, payload) = json_response(response).await;
        assert_eq!(status, StatusCode::GONE);
        assert_eq!(payload["error"], "local registration disabled");
        assert!(off.store.get("ares").is_none());

        let on = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
        });
        for headers in [bearer_headers("wrong-fixture"), HeaderMap::new()] {
            let response =
                register(State(on.clone()), headers, Json(test_registration("ares"))).await;
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        }
        assert!(on.store.get("ares").is_none());
    }

    #[test]
    fn beacon_auth_startup_is_strict_and_registration_needs_switch_and_file() {
        let no_file = || Ok(None);
        let file = || Ok(Some("bootstrap-fixture".to_string()));
        let untouched = || -> Result<Option<String>, String> {
            panic!("the registration file is read only when switched on")
        };

        let default = BeaconAuth::validated(None, None, false, false, untouched).unwrap();
        assert!(default.registration_token.is_none());
        let required = BeaconAuth::validated(Some("local"), Some(true), false, false, untouched);
        assert!(required.unwrap().registration_token.is_none());

        let on = BeaconAuth::validated(None, None, true, false, file).unwrap();
        assert_eq!(on.registration_token.as_deref(), Some("bootstrap-fixture"));

        let cases: [(Result<BeaconAuth, String>, &str); 4] = [
            (
                BeaconAuth::validated(Some("janus"), None, false, false, untouched),
                "PHAROS_BEACON_TOKEN_MODE",
            ),
            (
                BeaconAuth::validated(None, Some(false), false, false, untouched),
                "PHAROS_REQUIRE_BEACON_TOKEN",
            ),
            (
                BeaconAuth::validated(None, None, true, true, file),
                "PHAROS_REGISTRATION_TOKEN_FILE",
            ),
            (
                BeaconAuth::validated(None, None, true, false, no_file),
                "PHAROS_REGISTRATION_TOKEN_FILE",
            ),
        ];
        for (result, names) in cases {
            let error = result.err().expect("startup refuses this configuration");
            assert!(error.contains(names), "{error}");
        }
    }

    #[tokio::test]
    async fn no_api_or_page_carries_the_stored_token_hash() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");
        let hash = token_hash("valid-token");

        let base = serve_test_app(state).await;
        let response = test_client()
            .get(format!("{base}/hosts.json"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let body = response.text().await.unwrap();

        let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(payload["hosts"][0]["name"], "ares");
        assert_eq!(payload["hosts"][0]["liveness"], "awaiting_first_heartbeat");
        assert!(!body.contains(&hash));
        assert!(!body.contains("token_hash"));

        let page = test_client()
            .get(format!("{base}/"))
            .send()
            .await
            .unwrap()
            .text()
            .await
            .unwrap();
        assert!(page.contains("ares"));
        assert!(!page.contains(&hash));
        assert!(!page.contains("token_hash"));
    }

    #[tokio::test]
    async fn bearer_credentials_are_refused_on_human_routes() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");

        let base = serve_test_app(state).await;
        let response = test_client()
            .get(format!("{base}/hosts.json"))
            .bearer_auth("valid-token")
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    const CUT_ROUTES: &[(&str, &str)] = &[
        ("GET", "/metrics"),
        ("GET", "/map"),
        ("GET", "/map/data.json"),
        ("GET", "/alerts"),
        ("GET", "/backups"),
        ("GET", "/activity"),
        ("GET", "/access/request"),
        ("GET", "/services"),
        ("GET", "/services/ares/service-one"),
        ("GET", "/settings/providers"),
        ("POST", "/settings/fleet.json"),
        ("GET", "/agora"),
        ("GET", "/hosts/ares"),
        ("GET", "/hosts/ares/settings"),
        ("GET", "/flow/shell-state.json"),
        ("POST", "/flow/intents"),
        ("GET", "/assets/vendor/flow-shell/shell.js"),
        ("GET", "/assets/flow-host-bootstrap.mjs"),
        ("GET", "/assets/fleet-horizon.png"),
        ("GET", "/assets/vendor/leaflet-1.9.4/leaflet.js"),
        ("GET", "/assets/vendor/d3-7.9.0/d3.min.js"),
        ("GET", "/setup/provider-plan.json"),
        ("POST", "/setup/provisioning-jobs"),
        ("POST", "/setup/existing-host/preflight"),
        ("POST", "/host-need-intents"),
        ("GET", "/declared-hosts.json"),
        ("GET", "/proof/ares"),
        ("GET", "/managed-service-declarations.json"),
        ("POST", "/managed-service-setup-intents"),
        ("POST", "/host-actions/system-update"),
        ("POST", "/host-actions/ares/remove"),
        ("GET", "/host-actions/jobs/one"),
        ("POST", "/agent/actions/claim"),
        ("POST", "/agent/retirements/claim"),
        ("POST", "/agent/provisioning/claim"),
        ("POST", "/agent/managed-services/claim"),
        ("GET", "/internal/managed-service-setup-intents/one"),
        ("POST", "/internal/managed-service-operations"),
    ];

    async fn assert_cut_routes_absent(base: &str, prefix: &str) {
        let client = test_client();
        for (method, path) in CUT_ROUTES {
            let url = format!("{base}{prefix}{path}");
            let request = match *method {
                "POST" => client.post(&url),
                _ => client.get(&url),
            };
            let response = request.send().await.unwrap();
            assert_eq!(
                response.status(),
                reqwest::StatusCode::NOT_FOUND,
                "{method} {prefix}{path}"
            );
        }
    }

    #[tokio::test]
    async fn fleet_data_state_is_on_the_api_and_page_without_breaking_either() {
        let path = temp_path("fleet-data");
        let mut state = report_test_state();
        state.fleet_data = Some(FleetDataRuntime::for_test(path.clone()));
        let base = serve_test_app(state.clone()).await;
        let client = reqwest::Client::new();

        let hosts: serde_json::Value = client
            .get(format!("{base}/hosts.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(hosts["fleet_data"]["configured"], true);
        assert_eq!(hosts["fleet_data"]["problem"], "the file is missing");
        assert_eq!(hosts["fleet_data"]["updated_at"], serde_json::Value::Null);
        let page = client.get(&base).send().await.unwrap();
        assert_eq!(page.status(), reqwest::StatusCode::OK);
        assert!(page.text().await.unwrap().contains("the file is missing"));

        std::fs::write(&path, fleet_data::CONTRACT).expect("file written");
        state.fleet_data.as_ref().unwrap().refresh();
        let hosts: serde_json::Value = client
            .get(format!("{base}/hosts.json"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(hosts["fleet_data"]["problem"], serde_json::Value::Null);
        assert!(hosts["fleet_data"]["age_secs"].as_i64().unwrap() > 0);
        // The file's contents stay off this API until the page needs them.
        assert_eq!(hosts["fleet_data"].get("sections"), None);
        std::fs::remove_file(path).expect("file removed");
    }

    #[tokio::test]
    async fn host_probes_are_on_the_api_without_their_targets() {
        let (runtime, _directory) = host_probes::runtime_for_test(&["hermes", "artemis"]);
        runtime.record_reachable_for_test("hermes", now_unix());
        let mut state = report_test_state();
        state.host_probes = Some(runtime);
        let hosts_json = |state: AppState| async move {
            let base = serve_test_app(state).await;
            reqwest::get(format!("{base}/hosts.json"))
                .await
                .unwrap()
                .json::<serde_json::Value>()
                .await
                .unwrap()
        };

        let hosts = hosts_json(state).await;
        assert_eq!(hosts["host_probes"]["hermes"]["reachable"], true);
        assert!(hosts["host_probes"]["hermes"]["last_reachable_at"].is_i64());
        assert_eq!(
            hosts["host_probes"]["artemis"]["reachable"],
            serde_json::Value::Null
        );
        assert!(!hosts.to_string().contains("example.test"));

        let unconfigured = hosts_json(report_test_state()).await;
        assert_eq!(unconfigured["host_probes"], serde_json::json!({}));
    }

    #[tokio::test]
    async fn no_route_can_change_the_fleet_data_file() {
        let path = temp_path("fleet-data-read-only");
        std::fs::write(&path, fleet_data::CONTRACT).expect("file written");
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("registration-fixture".to_string()),
        });
        state.fleet_data = Some(FleetDataRuntime::for_test(path.clone()));
        register_test_token(&state, "ares", "valid-token");
        let base = serve_test_app(state.clone()).await;
        let client = reqwest::Client::new();

        for route in [
            "/",
            "/hosts.json",
            "/fleet",
            "/fleet.json",
            "/fleet-data",
            "/fleet-data.json",
            "/fleet-data/fleet.json",
            "/data",
            "/cves",
            "/handled",
        ] {
            for method in [
                reqwest::Method::POST,
                reqwest::Method::PUT,
                reqwest::Method::PATCH,
                reqwest::Method::DELETE,
            ] {
                let response = client
                    .request(method.clone(), format!("{base}{route}"))
                    .json(&serde_json::json!({"schema_version": 3}))
                    .send()
                    .await
                    .unwrap();
                assert!(
                    matches!(
                        response.status(),
                        reqwest::StatusCode::NOT_FOUND | reqwest::StatusCode::METHOD_NOT_ALLOWED
                    ),
                    "{method} {route}: {}",
                    response.status()
                );
            }
        }

        // The routes that do write leave it alone too.
        let reported = client
            .post(format!("{base}/report"))
            .bearer_auth("valid-token")
            .json(&test_report("ares"))
            .send()
            .await
            .unwrap();
        assert_eq!(reported.status(), reqwest::StatusCode::NO_CONTENT);
        let registered = client
            .post(format!("{base}/register"))
            .bearer_auth("registration-fixture")
            .json(&test_registration("hermes"))
            .send()
            .await
            .unwrap();
        assert_eq!(registered.status(), reqwest::StatusCode::CREATED);

        assert_eq!(
            std::fs::read_to_string(&path).expect("file reads"),
            fleet_data::CONTRACT
        );
        std::fs::remove_file(path).expect("file removed");
    }

    #[tokio::test]
    async fn cut_route_families_are_gone() {
        let base = serve_test_app(report_test_state()).await;
        assert_cut_routes_absent(&base, "").await;

        let mut prefixed = report_test_state();
        prefixed.public_base_path = PublicBasePath::parse("/pharos").unwrap();
        let base = serve_test_app(prefixed).await;
        assert_cut_routes_absent(&base, "").await;
        assert_cut_routes_absent(&base, "/pharos").await;
    }

    #[tokio::test]
    async fn launch_routes_answer_at_root() {
        let base = serve_test_app(report_test_state()).await;
        let client = test_client();
        for path in [
            "/",
            "/hosts.json",
            "/healthz",
            "/readyz",
            "/version",
            "/favicon.svg",
            "/assets/calendar-version-bootstrap.mjs",
            "/assets/vendor/calendar-version-display/version.js",
        ] {
            let response = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(response.status(), reqwest::StatusCode::OK, "{path}");
        }
    }

    #[tokio::test]
    async fn prefixed_mount_keeps_machine_routes_at_root_and_browser_routes_under_prefix() {
        let mut state = report_test_state();
        state.public_base_path = PublicBasePath::parse("/pharos").unwrap();
        let base = serve_test_app(state).await;
        let client = test_client();

        for path in ["/healthz", "/readyz", "/version"] {
            for url in [format!("{base}{path}"), format!("{base}/pharos{path}")] {
                let response = client.get(&url).send().await.unwrap();
                assert_eq!(response.status(), reqwest::StatusCode::OK, "{url}");
            }
        }
        for path in ["/favicon.svg", "/hosts.json"] {
            let inside = client
                .get(format!("{base}/pharos{path}"))
                .send()
                .await
                .unwrap();
            assert_eq!(inside.status(), reqwest::StatusCode::OK, "{path}");
            let outside = client.get(format!("{base}{path}")).send().await.unwrap();
            assert_eq!(outside.status(), reqwest::StatusCode::NOT_FOUND, "{path}");
        }

        let trailing = client.get(format!("{base}/pharos/")).send().await.unwrap();
        assert_eq!(trailing.status(), reqwest::StatusCode::PERMANENT_REDIRECT);
        assert_eq!(trailing.headers()[header::LOCATION.as_str()], "/pharos");
    }

    /// Every route whose handler can take a write, read from the source so a new
    /// one cannot be missed.
    fn mutating_routes() -> Vec<String> {
        let mut routes: Vec<String> = include_str!("routes.rs")
            .split(".route(")
            .skip(1)
            .filter(|tail| {
                ["post(", "put(", "patch(", "delete("]
                    .iter()
                    .any(|method| tail.contains(method))
            })
            .filter_map(|tail| tail.trim_start().strip_prefix('"'))
            .filter_map(|tail| tail.split('"').next())
            .map(ToString::to_string)
            .collect();
        routes.sort();
        routes
    }

    #[tokio::test]
    async fn the_operator_token_reads_data_and_changes_nothing() {
        let mut state = report_test_state_with_auth(BeaconAuth {
            registration_token: Some("bootstrap-fixture".to_string()),
        });
        register_test_token(&state, "ares", "ares-beacon-token");
        state.auth = AuthState::for_test_operator_token("operator-read-token");
        let store = state.store.clone();
        let before = store.list();
        let base = serve_test_app(state).await;
        let client = test_client();
        let bearer = |token: &str| format!("Bearer {token}");

        for path in ["/hosts.json", "/fleet.json"] {
            let url = format!("{base}{path}");
            let read = client
                .get(&url)
                .header("authorization", bearer("operator-read-token"))
                .send()
                .await
                .unwrap();
            assert_eq!(read.status(), reqwest::StatusCode::OK, "{path}");
            assert!(read.text().await.unwrap().contains("ares"), "{path}");

            for token in ["wrong-token", "ares-beacon-token", ""] {
                let refused = client
                    .get(&url)
                    .header("authorization", bearer(token))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    refused.status(),
                    reqwest::StatusCode::UNAUTHORIZED,
                    "{path}"
                );
                assert!(!refused.text().await.unwrap().contains("ares"), "{path}");
            }

            // These routes only read: no method that writes is routed at all.
            for method in [
                reqwest::Method::POST,
                reqwest::Method::PUT,
                reqwest::Method::PATCH,
                reqwest::Method::DELETE,
            ] {
                let write = client
                    .request(method.clone(), &url)
                    .header("authorization", bearer("operator-read-token"))
                    .send()
                    .await
                    .unwrap();
                assert_eq!(
                    write.status(),
                    reqwest::StatusCode::METHOD_NOT_ALLOWED,
                    "{method} {path}"
                );
            }
        }

        // Pages are for people, and a token never opens one.
        let page = client
            .get(format!("{base}/"))
            .header("authorization", bearer("operator-read-token"))
            .send()
            .await
            .unwrap();
        assert_eq!(page.status(), reqwest::StatusCode::UNAUTHORIZED);

        // Every route that can change state refuses it, with a well-formed request.
        assert_eq!(mutating_routes(), ["/auth/logout", "/register", "/report"]);
        let report = client
            .post(format!("{base}/report"))
            .header("authorization", bearer("operator-read-token"))
            .json(&test_report("ares"))
            .send()
            .await
            .unwrap();
        assert_eq!(report.status(), reqwest::StatusCode::UNAUTHORIZED);
        let registration = json!({
            "schema": pharos_core::HOST_REGISTRATION_SCHEMA,
            "version": pharos_core::HOST_REGISTRATION_VERSION,
            "name": "new-host",
            "role": "server",
            "is_nix": true,
            "heartbeat_interval_secs": 60,
        });
        let register = |token: &'static str| {
            client
                .post(format!("{base}/register"))
                .header("authorization", bearer(token))
                .json(&registration)
                .send()
        };
        assert_eq!(
            register("operator-read-token").await.unwrap().status(),
            reqwest::StatusCode::UNAUTHORIZED
        );
        let logout = client
            .post(format!("{base}/auth/logout"))
            .header("authorization", bearer("operator-read-token"))
            .form(&[("csrf", "operator-read-token")])
            .send()
            .await
            .unwrap();
        assert_eq!(logout.status(), reqwest::StatusCode::FORBIDDEN);

        let after = store.list();
        assert_eq!(after.len(), before.len());
        assert_eq!(after[0].last_seen, before[0].last_seen);
        assert_eq!(after[0].token_hash, before[0].token_hash);

        // The same request does work with the credential that is meant for it.
        assert!(register("bootstrap-fixture")
            .await
            .unwrap()
            .status()
            .is_success());
        assert_eq!(store.list().len(), before.len() + 1);
    }

    #[test]
    fn auth_has_no_way_to_reach_janus() {
        let auth = include_str!("auth.rs").to_lowercase();
        assert!(!auth.contains("janus"));
    }

    #[tokio::test]
    async fn without_an_operator_token_configured_no_bearer_opens_data() {
        let state = report_test_state();
        let base = serve_test_app(state).await;
        let refused = test_client()
            .get(format!("{base}/fleet.json"))
            .header("authorization", "Bearer anything")
            .send()
            .await
            .unwrap();
        assert_eq!(refused.status(), reqwest::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn home_page_lists_hosts_with_csp_nonce_on_its_style() {
        let state = report_test_state();
        register_test_token(&state, "ares", "valid-token");
        let base = serve_test_app(state).await;

        let response = test_client().get(format!("{base}/")).send().await.unwrap();
        assert_eq!(response.status(), reqwest::StatusCode::OK);
        let csp = response.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .to_string();
        let nonce = csp
            .split("'nonce-")
            .nth(1)
            .and_then(|tail| tail.split('\'').next())
            .unwrap()
            .to_string();
        let body = response.text().await.unwrap();
        assert!(body.contains("ares"));
        assert!(body.contains(&format!(r#"<style nonce="{nonce}""#)));
    }
}
