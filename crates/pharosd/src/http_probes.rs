//! Owner-declared HTTP health probes (PHAROS-266).
//!
//! The registry is trusted configuration, not browser or beacon input. Probe
//! results stay deliberately coarse: status, marker match and freshness only;
//! response bodies are never retained or projected.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::{Arc, RwLock};
use std::time::Duration;

use pharos_core::{HostManifest, ServiceObservationState};
use reqwest::redirect::Policy;
use serde::Deserialize;
use tokio::time::sleep;
use url::Url;

use crate::provisioning::{read_trusted_runtime_file, valid_bootstrap_name};
use crate::ui::ServerProbeObservation;

const HTTP_PROBE_REGISTRY_ENV: &str = "PHAROS_HTTP_PROBES_PATH";
const HTTP_PROBE_REGISTRY_SCHEMA: &str = "inspr.pharos.http-probes.v1";
const HTTP_PROBE_REGISTRY_VERSION: u16 = 1;
const MAX_REGISTRY_BYTES: u64 = 64 * 1024;
const MAX_PROBES: usize = 128;
const MAX_PROBE_ID_BYTES: usize = 48;
const MAX_URL_BYTES: usize = 2_048;
const MAX_MARKER_BYTES: usize = 256;
const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const MIN_INTERVAL_SECONDS: u64 = 10;
const MAX_INTERVAL_SECONDS: u64 = 3_600;
const MIN_TIMEOUT_MILLISECONDS: u64 = 100;
const MAX_TIMEOUT_MILLISECONDS: u64 = 10_000;
const STALE_INTERVALS: u64 = 3;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HttpProbeRegistry {
    schema: String,
    version: u16,
    probes: Vec<HttpProbeDeclaration>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct HttpProbeDeclaration {
    id: String,
    host: String,
    service: String,
    url: String,
    expected_status: u16,
    #[serde(default)]
    body_marker: Option<String>,
    interval_seconds: u64,
    timeout_milliseconds: u64,
}

impl HttpProbeRegistry {
    fn validate(&self, manifests: &[HostManifest]) -> Result<(), String> {
        if self.schema != HTTP_PROBE_REGISTRY_SCHEMA || self.version != HTTP_PROBE_REGISTRY_VERSION
        {
            return Err("unsupported HTTP probe registry schema/version".to_string());
        }
        if self.probes.is_empty() || self.probes.len() > MAX_PROBES {
            return Err("HTTP probe registry must contain 1..=128 probes".to_string());
        }

        let mut ids = BTreeSet::new();
        let mut bindings = BTreeSet::new();
        for probe in &self.probes {
            probe.validate()?;
            if !ids.insert(probe.id.as_str()) {
                return Err("HTTP probe registry contains a duplicate id".to_string());
            }
            if !bindings.insert((probe.host.as_str(), probe.service.as_str())) {
                return Err(
                    "HTTP probe registry contains a duplicate host/service binding".to_string(),
                );
            }
            let manifest = manifests
                .iter()
                .find(|manifest| manifest.host.name == probe.host)
                .ok_or_else(|| {
                    format!(
                        "HTTP probe {} names a host without an exact manifest",
                        probe.id
                    )
                })?;
            if !manifest
                .services
                .iter()
                .any(|service| service.name == probe.service)
            {
                return Err(format!(
                    "HTTP probe {} names a service outside its host manifest",
                    probe.id
                ));
            }
        }
        Ok(())
    }
}

impl HttpProbeDeclaration {
    fn validate(&self) -> Result<(), String> {
        if self.id.is_empty()
            || self.id.len() > MAX_PROBE_ID_BYTES
            || !self
                .id
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
            || self.id.starts_with('-')
            || self.id.ends_with('-')
        {
            return Err("HTTP probe id must be a canonical identifier".to_string());
        }
        if !valid_bootstrap_name(&self.host)
            || self.service.trim().is_empty()
            || self.service.trim() != self.service
            || self.service.len() > 128
            || self.service.chars().any(char::is_control)
        {
            return Err("HTTP probe host/service binding is invalid".to_string());
        }
        if !(200..=599).contains(&self.expected_status) {
            return Err("HTTP probe expected_status must be between 200 and 599".to_string());
        }
        if !(MIN_INTERVAL_SECONDS..=MAX_INTERVAL_SECONDS).contains(&self.interval_seconds) {
            return Err("HTTP probe interval_seconds must be between 10 and 3600".to_string());
        }
        if !(MIN_TIMEOUT_MILLISECONDS..=MAX_TIMEOUT_MILLISECONDS)
            .contains(&self.timeout_milliseconds)
        {
            return Err(
                "HTTP probe timeout_milliseconds must be between 100 and 10000".to_string(),
            );
        }
        if self.body_marker.as_ref().is_some_and(|marker| {
            marker.is_empty()
                || marker.len() > MAX_MARKER_BYTES
                || marker.chars().any(char::is_control)
        }) {
            return Err("HTTP probe body_marker must be bounded visible text".to_string());
        }
        let url = Url::parse(&self.url).map_err(|_| "HTTP probe URL is invalid".to_string())?;
        if self.url.len() > MAX_URL_BYTES
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
        {
            return Err(
                "HTTP probe URL must be credential-free HTTP(S) without query or fragment"
                    .to_string(),
            );
        }
        Ok(())
    }

    fn target(&self) -> String {
        let url = Url::parse(&self.url).expect("validated HTTP probe URL parses");
        // The configured path is needed to perform the check, but it may be
        // operator-private routing detail. Project only the credential-free
        // authority into browser-visible status.
        url.origin().ascii_serialization()
    }

    fn initial_observation(&self) -> ServerProbeObservation {
        observation(
            self,
            ServiceObservationState::Unknown,
            None,
            "awaiting first declared HTTP probe".to_string(),
            0,
        )
    }
}

pub(crate) struct HttpProbeRuntime {
    registry: HttpProbeRegistry,
    client: reqwest::Client,
    observations: RwLock<BTreeMap<(String, String), ServerProbeObservation>>,
}

impl HttpProbeRuntime {
    pub(crate) fn from_env(manifests: &[HostManifest]) -> Result<Option<Self>, String> {
        let Some(registry_path) = std::env::var(HTTP_PROBE_REGISTRY_ENV)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
        else {
            return Ok(None);
        };
        let bytes = read_trusted_runtime_file(&registry_path, MAX_REGISTRY_BYTES, 0o022, false)
            .ok_or_else(|| "HTTP probe registry is unavailable".to_string())?;
        let registry = serde_json::from_slice::<HttpProbeRegistry>(&bytes)
            .map_err(|_| "HTTP probe registry JSON is invalid".to_string())?;
        Self::new(registry, manifests).map(Some)
    }

    fn new(registry: HttpProbeRegistry, manifests: &[HostManifest]) -> Result<Self, String> {
        registry.validate(manifests)?;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .retry(reqwest::retry::never())
            .user_agent("pharosd-declared-health-probe/1")
            .build()
            .map_err(|_| "HTTP probe client could not be built".to_string())?;
        let observations = registry
            .probes
            .iter()
            .map(|probe| {
                (
                    (probe.host.clone(), probe.service.clone()),
                    probe.initial_observation(),
                )
            })
            .collect();
        Ok(Self {
            registry,
            client,
            observations: RwLock::new(observations),
        })
    }

    pub(crate) fn declares(&self, host: &str, service: &str) -> bool {
        self.registry
            .probes
            .iter()
            .any(|probe| probe.host == host && probe.service == service)
    }

    pub(crate) fn snapshot(&self, now: i64) -> BTreeMap<String, Vec<ServerProbeObservation>> {
        let observations = self.observations.read().expect("HTTP probe lock");
        let mut by_host: BTreeMap<String, Vec<ServerProbeObservation>> = BTreeMap::new();
        for probe in &self.registry.probes {
            let key = (probe.host.clone(), probe.service.clone());
            let mut current = observations
                .get(&key)
                .cloned()
                .unwrap_or_else(|| probe.initial_observation());
            let stale_after = i64::try_from(probe.interval_seconds.saturating_mul(STALE_INTERVALS))
                .unwrap_or(i64::MAX);
            if current.checked_at > 0
                && (current.checked_at > now
                    || now.saturating_sub(current.checked_at) > stale_after)
            {
                current.state = ServiceObservationState::Stale;
                current.server_reachable = None;
                current.summary = "declared HTTP probe result is stale".to_string();
            }
            by_host.entry(probe.host.clone()).or_default().push(current);
        }
        for observations in by_host.values_mut() {
            observations.sort_by(|left, right| left.id.cmp(&right.id));
        }
        by_host
    }

    async fn probe_and_record(&self, probe: &HttpProbeDeclaration) {
        let mut current = probe_http(&self.client, probe, 0).await;
        current.checked_at = crate::now_unix().max(0);
        self.observations
            .write()
            .expect("HTTP probe lock")
            .insert((probe.host.clone(), probe.service.clone()), current);
    }
}

pub(crate) fn spawn_http_probe_loops(runtime: Arc<HttpProbeRuntime>) {
    for probe in runtime.registry.probes.clone() {
        let runtime = Arc::clone(&runtime);
        tokio::spawn(async move {
            loop {
                runtime.probe_and_record(&probe).await;
                sleep(Duration::from_secs(probe.interval_seconds)).await;
            }
        });
    }
}

async fn probe_http(
    client: &reqwest::Client,
    probe: &HttpProbeDeclaration,
    now: i64,
) -> ServerProbeObservation {
    let response = match client
        .get(&probe.url)
        .timeout(Duration::from_millis(probe.timeout_milliseconds))
        .send()
        .await
    {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return observation(
                probe,
                ServiceObservationState::Warning,
                Some(false),
                "declared HTTP probe timed out".to_string(),
                now,
            );
        }
        Err(_) => {
            return observation(
                probe,
                ServiceObservationState::Warning,
                Some(false),
                "declared HTTP probe could not reach the service".to_string(),
                now,
            );
        }
    };

    let status = response.status().as_u16();
    if status != probe.expected_status {
        return observation(
            probe,
            ServiceObservationState::Warning,
            Some(true),
            format!("HTTP {status}; expected {}", probe.expected_status),
            now,
        );
    }

    if let Some(marker) = probe.body_marker.as_deref() {
        match bounded_body_contains(response, marker.as_bytes()).await {
            Ok(true) => {}
            Ok(false) => {
                return observation(
                    probe,
                    ServiceObservationState::Warning,
                    Some(true),
                    format!("HTTP {status}; expected body marker is absent"),
                    now,
                );
            }
            Err(BodyProbeError::TooLarge) => {
                return observation(
                    probe,
                    ServiceObservationState::Warning,
                    Some(true),
                    format!("HTTP {status}; response body exceeded probe limit"),
                    now,
                );
            }
            Err(BodyProbeError::Unavailable) => {
                return observation(
                    probe,
                    ServiceObservationState::Warning,
                    Some(true),
                    format!("HTTP {status}; response body could not be read"),
                    now,
                );
            }
        }
    }

    observation(
        probe,
        ServiceObservationState::Healthy,
        Some(true),
        format!("HTTP {status}; declared health check passed"),
        now,
    )
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyProbeError {
    Unavailable,
    TooLarge,
}

async fn bounded_body_contains(
    mut response: reqwest::Response,
    marker: &[u8],
) -> Result<bool, BodyProbeError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| BodyProbeError::Unavailable)?
    {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(BodyProbeError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body.windows(marker.len()).any(|window| window == marker))
}

fn observation(
    probe: &HttpProbeDeclaration,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
) -> ServerProbeObservation {
    ServerProbeObservation {
        id: format!("http-probe-{}", probe.id),
        service: probe.service.clone(),
        source: "server",
        policy: "pharos-runtime",
        kind: "http-response",
        target: Some(probe.target()),
        state,
        server_reachable,
        client_reachable: None,
        summary,
        checked_at: checked_at.max(0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::{HostManifest, HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    const CONTRACT_FIXTURE: &str = include_str!("../../../contracts/http-probes-v1.json");

    fn manifest() -> HostManifest {
        serde_json::from_value(serde_json::json!({
            "schema": HOST_MANIFEST_SCHEMA,
            "version": HOST_MANIFEST_VERSION,
            "slug": "host-one",
            "host": { "name": "host-one" },
            "wings": [],
            "services": [{
                "wing": "core",
                "name": "Service One",
                "url": "https://service.example.test/healthz"
            }]
        }))
        .expect("test manifest parses")
    }

    fn declaration(url: String) -> HttpProbeDeclaration {
        HttpProbeDeclaration {
            id: "service-one".to_string(),
            host: "host-one".to_string(),
            service: "Service One".to_string(),
            url,
            expected_status: 200,
            body_marker: Some("ready".to_string()),
            interval_seconds: 30,
            timeout_milliseconds: 500,
        }
    }

    fn registry(probe: HttpProbeDeclaration) -> HttpProbeRegistry {
        HttpProbeRegistry {
            schema: HTTP_PROBE_REGISTRY_SCHEMA.to_string(),
            version: HTTP_PROBE_REGISTRY_VERSION,
            probes: vec![probe],
        }
    }

    async fn serve_once(status: u16, body: &'static [u8]) -> String {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 1024];
            let _ = stream.read(&mut request).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status} Test\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        format!("http://{address}/healthz")
    }

    #[test]
    fn registry_binds_exact_declared_host_and_service() {
        let valid = registry(declaration(
            "https://service.example.test/healthz".to_string(),
        ));
        assert!(valid.validate(&[manifest()]).is_ok());

        let mut missing_service = valid.clone();
        missing_service.probes[0].service = "Other Service".to_string();
        assert!(missing_service
            .validate(&[manifest()])
            .is_err_and(|error| error.contains("outside its host manifest")));

        let mut credential_url = valid.clone();
        credential_url.probes[0].url = "https://user:secret@example.test/healthz".to_string();
        assert!(credential_url
            .validate(&[manifest()])
            .is_err_and(|error| error.contains("credential-free")));
    }

    #[test]
    fn published_registry_fixture_matches_the_runtime_contract() {
        let registry: HttpProbeRegistry =
            serde_json::from_str(CONTRACT_FIXTURE).expect("HTTP probe fixture parses");
        assert!(registry.validate(&[manifest()]).is_ok());

        let mut unknown_field: serde_json::Value =
            serde_json::from_str(CONTRACT_FIXTURE).expect("fixture value parses");
        unknown_field["probes"][0]["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<HttpProbeRegistry>(unknown_field).is_err());
    }

    #[test]
    fn registry_requires_explicit_bounded_probe_policy() {
        let mut invalid = registry(declaration(
            "https://service.example.test/healthz".to_string(),
        ));
        invalid.probes[0].interval_seconds = 9;
        assert!(invalid.validate(&[manifest()]).is_err());
        invalid.probes[0].interval_seconds = 30;
        invalid.probes[0].timeout_milliseconds = 10_001;
        assert!(invalid.validate(&[manifest()]).is_err());
        invalid.probes[0].timeout_milliseconds = 500;
        invalid.probes[0].expected_status = 199;
        assert!(invalid.validate(&[manifest()]).is_err());
    }

    #[tokio::test]
    async fn probe_requires_expected_status_and_body_marker() {
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();

        let passing = declaration(serve_once(200, b"status=ready").await);
        let result = probe_http(&client, &passing, 1_000).await;
        assert_eq!(
            result.state,
            ServiceObservationState::Healthy,
            "{}",
            result.summary
        );
        assert_eq!(result.server_reachable, Some(true));
        assert_eq!(result.checked_at, 1_000);
        assert!(!result.summary.contains("ready"));

        let wrong_status = declaration(serve_once(503, b"ready").await);
        let result = probe_http(&client, &wrong_status, 1_001).await;
        assert_eq!(result.state, ServiceObservationState::Warning);
        assert!(result.summary.contains("expected 200"));

        let missing_marker = declaration(serve_once(200, b"starting").await);
        let result = probe_http(&client, &missing_marker, 1_002).await;
        assert_eq!(result.state, ServiceObservationState::Warning);
        assert!(result.summary.contains("marker is absent"));
        assert!(!result.summary.contains("starting"));

        let mut no_marker = declaration(serve_once(200, b"").await);
        no_marker.body_marker = None;
        let result = probe_http(&client, &no_marker, 1_003).await;
        assert_eq!(result.state, ServiceObservationState::Healthy);
    }

    #[tokio::test]
    async fn configured_timeout_is_enforced() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            sleep(Duration::from_millis(250)).await;
        });
        let mut probe = declaration(format!("http://{address}/healthz"));
        probe.timeout_milliseconds = 100;
        let client = reqwest::Client::builder()
            .redirect(Policy::none())
            .build()
            .unwrap();
        let result = probe_http(&client, &probe, 1_003).await;
        assert_eq!(result.state, ServiceObservationState::Warning);
        assert_eq!(result.server_reachable, Some(false));
        assert_eq!(result.summary, "declared HTTP probe timed out");
    }

    #[test]
    fn snapshot_expires_old_or_future_results() {
        let runtime = HttpProbeRuntime::new(
            registry(declaration(
                "https://service.example.test/healthz".to_string(),
            )),
            &[manifest()],
        )
        .unwrap();
        let key = ("host-one".to_string(), "Service One".to_string());
        runtime.observations.write().unwrap().insert(
            key.clone(),
            observation(
                &runtime.registry.probes[0],
                ServiceObservationState::Healthy,
                Some(true),
                "HTTP 200; declared health check passed".to_string(),
                1_000,
            ),
        );
        assert_eq!(
            runtime.snapshot(1_090)["host-one"][0].state,
            ServiceObservationState::Healthy
        );
        assert_eq!(
            runtime.snapshot(1_091)["host-one"][0].state,
            ServiceObservationState::Stale
        );

        runtime
            .observations
            .write()
            .unwrap()
            .get_mut(&key)
            .unwrap()
            .checked_at = 2_000;
        assert_eq!(
            runtime.snapshot(1_999)["host-one"][0].state,
            ServiceObservationState::Stale
        );
    }

    #[tokio::test]
    async fn declared_probe_projects_once_and_replaces_legacy_tcp_probe() {
        let manifest = manifest();
        let runtime = HttpProbeRuntime::new(
            registry(declaration(
                "https://private-route.example.test/healthz".to_string(),
            )),
            std::slice::from_ref(&manifest),
        )
        .unwrap();
        let projected = crate::ui::server_probe_overlays(&[manifest], 1_000, Some(&runtime)).await;
        assert_eq!(projected["host-one"].len(), 1);
        let probe = &projected["host-one"][0];
        assert_eq!(probe.id, "http-probe-service-one");
        assert_eq!(probe.kind, "http-response");
        assert_eq!(
            probe.target.as_deref(),
            Some("https://private-route.example.test")
        );
        assert!(crate::ui::server_probe_overlays(&[], 1_000, Some(&runtime))
            .await
            .is_empty());
    }
}
