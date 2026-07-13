//! Narrow GitHub Actions dispatch client for fixed nixcfg review workflows.
//!
//! Pharos may trigger only the compile-time allowlist below. Branch, pull-request,
//! merge, and deployment behavior remains owned by each review workflow.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pharos_core::HostPreferences;
use reqwest::header::{ACCEPT, USER_AGENT};
use serde::Serialize;

const GITHUB_API_BASE: &str = "https://api.github.com";
const DISPATCH_PATH: &str =
    "/repos/markus-barta/nixcfg/actions/workflows/pharos-host-settings.yml/dispatches";
const SYSTEM_UPDATE_DISPATCH_PATH: &str =
    "/repos/markus-barta/nixcfg/actions/workflows/pharos-system-update.yml/dispatches";
const HOST_REMOVAL_DISPATCH_PATH: &str =
    "/repos/markus-barta/nixcfg/actions/workflows/pharos-host-removal.yml/dispatches";
const WORKFLOW_REF: &str = "main";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
static REQUEST_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Debug)]
pub(crate) struct NixcfgDispatch {
    enabled: bool,
    system_update_enabled: bool,
    host_removal_enabled: bool,
    token_file: Option<PathBuf>,
    api_base: String,
    client: reqwest::Client,
}

impl Default for NixcfgDispatch {
    fn default() -> Self {
        Self::disabled()
    }
}

impl NixcfgDispatch {
    pub(crate) fn from_env() -> Self {
        let enabled = std::env::var("PHAROS_NIXCFG_DISPATCH_ENABLED")
            .ok()
            .is_some_and(|value| enabled_value(&value));
        let token_file = std::env::var("PHAROS_NIXCFG_DISPATCH_TOKEN_FILE")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .map(PathBuf::from);
        let system_update_enabled = std::env::var("PHAROS_SYSTEM_UPDATE_DISPATCH_ENABLED")
            .ok()
            .is_some_and(|value| enabled_value(&value));
        let host_removal_enabled = std::env::var("PHAROS_HOST_REMOVAL_DISPATCH_ENABLED")
            .ok()
            .is_some_and(|value| enabled_value(&value));
        Self::new(
            enabled,
            system_update_enabled,
            host_removal_enabled,
            token_file,
            GITHUB_API_BASE.to_string(),
        )
    }

    pub(crate) fn disabled() -> Self {
        Self::new(false, false, false, None, GITHUB_API_BASE.to_string())
    }

    fn new(
        enabled: bool,
        system_update_enabled: bool,
        host_removal_enabled: bool,
        token_file: Option<PathBuf>,
        api_base: String,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap_or_default();
        Self {
            enabled,
            system_update_enabled,
            host_removal_enabled,
            token_file,
            api_base,
            client,
        }
    }

    pub(crate) async fn dispatch(
        &self,
        host: &str,
        preferences: &HostPreferences,
    ) -> Result<String, NixcfgDispatchError> {
        if !self.enabled {
            return Err(NixcfgDispatchError::Disabled);
        }
        if !valid_host_name(host) {
            return Err(NixcfgDispatchError::InvalidHost);
        }
        preferences
            .validate_contract()
            .map_err(|_| NixcfgDispatchError::InvalidPreferences)?;
        let accent = preferences
            .accent
            .as_deref()
            .ok_or(NixcfgDispatchError::InvalidPreferences)?;
        let request_id = request_id("settings", host);
        let request = WorkflowDispatchRequest {
            git_ref: WORKFLOW_REF,
            inputs: WorkflowDispatchInputs {
                host,
                accent,
                kind: preferences.kind.label(),
                suppress_down: preferences.alerts.suppress_down,
                suppress_backup: preferences.alerts.suppress_backup,
                suppress_nix_freshness: preferences.alerts.suppress_nix_freshness,
                request_id: &request_id,
            },
        };
        self.send(DISPATCH_PATH, &request).await?;
        Ok(request_id)
    }

    pub(crate) async fn dispatch_system_update(
        &self,
        source_host: &str,
    ) -> Result<String, NixcfgDispatchError> {
        if !self.system_update_available() {
            return Err(NixcfgDispatchError::Disabled);
        }
        if !valid_host_name(source_host) {
            return Err(NixcfgDispatchError::InvalidHost);
        }
        let request_id = request_id("system-update", source_host);
        let request = SystemUpdateDispatchRequest {
            git_ref: WORKFLOW_REF,
            inputs: SystemUpdateDispatchInputs {
                source_host,
                request_id: &request_id,
            },
        };
        self.send(SYSTEM_UPDATE_DISPATCH_PATH, &request).await?;
        Ok(request_id)
    }

    pub(crate) async fn dispatch_host_removal(
        &self,
        host: &str,
        disposition: &str,
        successor: Option<&str>,
    ) -> Result<String, NixcfgDispatchError> {
        if !self.host_removal_available() {
            return Err(NixcfgDispatchError::Disabled);
        }
        if !valid_host_name(host) {
            return Err(NixcfgDispatchError::InvalidHost);
        }
        if !valid_removal_intent(host, disposition, successor) {
            return Err(NixcfgDispatchError::InvalidRemovalIntent);
        }
        let request_id = request_id("host-removal", host);
        let request = HostRemovalDispatchRequest {
            git_ref: WORKFLOW_REF,
            inputs: HostRemovalDispatchInputs {
                host,
                disposition,
                successor: successor.unwrap_or_default(),
                request_id: &request_id,
            },
        };
        self.send(HOST_REMOVAL_DISPATCH_PATH, &request).await?;
        Ok(request_id)
    }

    async fn send<T: Serialize>(&self, path: &str, request: &T) -> Result<(), NixcfgDispatchError> {
        let token = self.read_token()?;
        let response = self
            .client
            .post(format!("{}{}", self.api_base.trim_end_matches('/'), path))
            .header(ACCEPT, "application/vnd.github+json")
            .header(USER_AGENT, "pharosd")
            .header("X-GitHub-Api-Version", "2022-11-28")
            .bearer_auth(token)
            .json(request)
            .send()
            .await
            .map_err(|_| NixcfgDispatchError::RequestFailed)?;
        if response.status() != reqwest::StatusCode::NO_CONTENT {
            return Err(NixcfgDispatchError::Rejected(response.status().as_u16()));
        }
        Ok(())
    }

    fn read_token(&self) -> Result<String, NixcfgDispatchError> {
        let path = self
            .token_file
            .as_ref()
            .ok_or(NixcfgDispatchError::CredentialUnavailable)?;
        std::fs::read_to_string(path)
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty() && !value.contains(['\r', '\n']))
            .ok_or(NixcfgDispatchError::CredentialUnavailable)
    }

    pub(crate) fn system_update_available(&self) -> bool {
        self.enabled && self.system_update_enabled
    }

    pub(crate) fn host_removal_available(&self) -> bool {
        self.enabled && self.host_removal_enabled
    }

    #[cfg(test)]
    pub(crate) fn for_test(token_file: Option<PathBuf>, api_base: String) -> Self {
        Self::new(true, true, true, token_file, api_base)
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum NixcfgDispatchError {
    Disabled,
    CredentialUnavailable,
    InvalidHost,
    InvalidPreferences,
    InvalidRemovalIntent,
    RequestFailed,
    Rejected(u16),
}

impl NixcfgDispatchError {
    pub(crate) fn safe_message(&self) -> &'static str {
        match self {
            Self::Disabled => "Declarative Nix host settings are not enabled on this Pharos server",
            Self::CredentialUnavailable => {
                "The declarative settings credential is unavailable; no change was requested"
            }
            Self::InvalidHost => "This host name cannot be used for declarative settings",
            Self::InvalidPreferences => "Host settings do not match the supported schema",
            Self::InvalidRemovalIntent => "The host retirement details are invalid",
            Self::RequestFailed => {
                "The declarative settings workflow could not be reached; no change was requested"
            }
            Self::Rejected(_) => {
                "The declarative settings workflow rejected the request; no change was requested"
            }
        }
    }
}

#[derive(Serialize)]
struct WorkflowDispatchRequest<'a> {
    #[serde(rename = "ref")]
    git_ref: &'static str,
    inputs: WorkflowDispatchInputs<'a>,
}

#[derive(Serialize)]
struct WorkflowDispatchInputs<'a> {
    host: &'a str,
    accent: &'a str,
    kind: &'static str,
    suppress_down: bool,
    suppress_backup: bool,
    suppress_nix_freshness: bool,
    request_id: &'a str,
}

#[derive(Serialize)]
struct SystemUpdateDispatchRequest<'a> {
    #[serde(rename = "ref")]
    git_ref: &'static str,
    inputs: SystemUpdateDispatchInputs<'a>,
}

#[derive(Serialize)]
struct SystemUpdateDispatchInputs<'a> {
    source_host: &'a str,
    request_id: &'a str,
}

#[derive(Serialize)]
struct HostRemovalDispatchRequest<'a> {
    #[serde(rename = "ref")]
    git_ref: &'static str,
    inputs: HostRemovalDispatchInputs<'a>,
}

#[derive(Serialize)]
struct HostRemovalDispatchInputs<'a> {
    host: &'a str,
    disposition: &'a str,
    successor: &'a str,
    request_id: &'a str,
}

fn enabled_value(value: &str) -> bool {
    matches!(
        value.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn valid_host_name(host: &str) -> bool {
    let bytes = host.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
}

fn valid_removal_intent(host: &str, disposition: &str, successor: Option<&str>) -> bool {
    match disposition {
        "rebuilt" => successor.is_some_and(|value| valid_host_name(value) && value != host),
        "destroyed" | "unmanaged" => successor.is_none(),
        _ => false,
    }
}

fn request_id(action: &str, host: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    let counter = REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("pharos-{action}-{host}-{now}-{counter}")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;

    use pharos_core::{HostAlertPreferences, HostKind};

    use super::*;

    fn token_file() -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "pharos-nixcfg-dispatch-token-{}-{}",
            std::process::id(),
            REQUEST_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, "test-dispatch-token\n").expect("write token fixture");
        path
    }

    fn preferences() -> HostPreferences {
        HostPreferences {
            accent: Some("#48b8a8".to_string()),
            kind: HostKind::Workstation,
            alerts: HostAlertPreferences {
                suppress_down: true,
                suppress_backup: false,
                suppress_nix_freshness: true,
            },
        }
    }

    fn mock_github(status: u16) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind mock GitHub");
        let address = listener.local_addr().expect("mock address");
        let (sender, receiver) = mpsc::channel();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept request");
            let mut request = Vec::new();
            let mut buffer = [0_u8; 4096];
            loop {
                let read = stream.read(&mut buffer).expect("read request");
                if read == 0 {
                    break;
                }
                request.extend_from_slice(&buffer[..read]);
                if complete_http_request(&request) {
                    break;
                }
            }
            sender
                .send(String::from_utf8(request).expect("request is UTF-8"))
                .expect("record request");
            let reason = if status == 204 {
                "No Content"
            } else {
                "Unauthorized"
            };
            write!(
                stream,
                "HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            )
            .expect("write response");
        });
        (format!("http://{address}"), receiver)
    }

    fn complete_http_request(request: &[u8]) -> bool {
        let Some(header_end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&request[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                line.split_once(':').and_then(|(name, value)| {
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().ok())
                        .flatten()
                })
            })
            .unwrap_or(0);
        request.len() >= header_end + 4 + content_length
    }

    #[tokio::test]
    async fn dispatches_only_the_fixed_workflow_with_exact_inputs() {
        let token_path = token_file();
        let (base, request) = mock_github(204);
        let client = NixcfgDispatch::for_test(Some(token_path.clone()), base);

        let request_id = client
            .dispatch("gpc0", &preferences())
            .await
            .expect("dispatch accepted");
        let raw = request.recv().expect("request captured");
        let (head, body) = raw.split_once("\r\n\r\n").expect("request body");
        assert!(head.starts_with(&format!("POST {DISPATCH_PATH} HTTP/1.1")));
        assert!(head
            .to_ascii_lowercase()
            .contains("authorization: bearer test-dispatch-token"));
        let payload: serde_json::Value = serde_json::from_str(body).expect("JSON body");
        assert_eq!(payload["ref"], WORKFLOW_REF);
        assert_eq!(payload["inputs"]["host"], "gpc0");
        assert_eq!(payload["inputs"]["accent"], "#48b8a8");
        assert_eq!(payload["inputs"]["kind"], "workstation");
        assert_eq!(payload["inputs"]["suppress_down"], true);
        assert_eq!(payload["inputs"]["suppress_backup"], false);
        assert_eq!(payload["inputs"]["suppress_nix_freshness"], true);
        assert_eq!(payload["inputs"]["request_id"], request_id);

        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn system_update_dispatch_is_fixed_and_review_correlated() {
        let token_path = token_file();
        let (base, request) = mock_github(204);
        let client = NixcfgDispatch::for_test(Some(token_path.clone()), base);

        let request_id = client
            .dispatch_system_update("hsb8")
            .await
            .expect("dispatch accepted");
        let raw = request.recv().expect("request captured");
        let (head, body) = raw.split_once("\r\n\r\n").expect("request body");
        assert!(head.starts_with(&format!("POST {SYSTEM_UPDATE_DISPATCH_PATH} HTTP/1.1")));
        let payload: serde_json::Value = serde_json::from_str(body).expect("JSON body");
        assert_eq!(payload["ref"], WORKFLOW_REF);
        assert_eq!(payload["inputs"]["source_host"], "hsb8");
        assert_eq!(payload["inputs"]["request_id"], request_id);
        assert!(request_id.starts_with("pharos-system-update-hsb8-"));

        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn host_removal_dispatch_is_fixed_and_host_scoped() {
        let token_path = token_file();
        let (base, request) = mock_github(204);
        let client = NixcfgDispatch::for_test(Some(token_path.clone()), base);

        let request_id = client
            .dispatch_host_removal("hsb8", "rebuilt", Some("stm2607"))
            .await
            .expect("dispatch accepted");
        let raw = request.recv().expect("request captured");
        let (head, body) = raw.split_once("\r\n\r\n").expect("request body");
        assert!(head.starts_with(&format!("POST {HOST_REMOVAL_DISPATCH_PATH} HTTP/1.1")));
        let payload: serde_json::Value = serde_json::from_str(body).expect("JSON body");
        assert_eq!(payload["ref"], WORKFLOW_REF);
        assert_eq!(payload["inputs"]["host"], "hsb8");
        assert_eq!(payload["inputs"]["disposition"], "rebuilt");
        assert_eq!(payload["inputs"]["successor"], "stm2607");
        assert_eq!(payload["inputs"]["request_id"], request_id);
        assert!(request_id.starts_with("pharos-host-removal-hsb8-"));

        let _ = std::fs::remove_file(token_path);
    }

    #[tokio::test]
    async fn missing_credential_and_workflow_rejection_fail_safely() {
        let unavailable = NixcfgDispatch::for_test(None, "http://127.0.0.1:9".to_string());
        assert_eq!(
            unavailable.dispatch("../gpc0", &preferences()).await,
            Err(NixcfgDispatchError::InvalidHost)
        );
        assert_eq!(
            unavailable.dispatch("gpc0", &preferences()).await,
            Err(NixcfgDispatchError::CredentialUnavailable)
        );
        assert_eq!(
            unavailable.dispatch_system_update("../gpc0").await,
            Err(NixcfgDispatchError::InvalidHost)
        );
        assert_eq!(
            unavailable
                .dispatch_host_removal("../gpc0", "destroyed", None)
                .await,
            Err(NixcfgDispatchError::InvalidHost)
        );
        assert_eq!(
            unavailable
                .dispatch_host_removal("gpc0", "rebuilt", None)
                .await,
            Err(NixcfgDispatchError::InvalidRemovalIntent)
        );
        assert_eq!(
            unavailable
                .dispatch_host_removal("gpc0", "unmanaged", Some("stm2607"))
                .await,
            Err(NixcfgDispatchError::InvalidRemovalIntent)
        );

        let token_path = token_file();
        let (base, request) = mock_github(401);
        let rejected = NixcfgDispatch::for_test(Some(token_path.clone()), base)
            .dispatch("gpc0", &preferences())
            .await
            .expect_err("workflow rejects token");
        assert_eq!(rejected, NixcfgDispatchError::Rejected(401));
        assert!(!rejected.safe_message().contains("test-dispatch-token"));
        request.recv().expect("rejected request captured");

        let _ = std::fs::remove_file(token_path);
    }
}
