//! Pharos Flow host integration (PHAROS-257).
//!
//! Opt-in bounded `@inspr/flow-shell` host with read-only Paimos projection,
//! Pharos-issued `local_host` identity, and guarded Review/Start navigation.

use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{header, HeaderMap, StatusCode};
use reqwest::header::{ACCEPT, AUTHORIZATION, USER_AGENT};
use reqwest::{Client, StatusCode as HttpStatus};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use url::Url;

use crate::auth::{AccessGrant, AuthState, AuthUser};
use crate::ui::APP_VERSION;
use pharos_core::{Host, Liveness, liveness};

pub(crate) const FLOW_CONFIG_ENV: &str = "PHAROS_FLOW_CONFIG_FILE";
const CONFIG_SCHEMA: &str = "inspr.pharos.flow-host-config.v1";
const CONFIG_SCHEMA_VERSION: u16 = 1;
const IDENTITY_CONTRACT: &str = "inspr.flow-identity/0.1-draft";
const AUTHORITY_DISCLAIMER: &str =
    "Schema validity is not authentication. Host must issue this context from a verified principal and revalidate on every consequential intent.";
const USER_AGENT_VALUE: &str = "pharosd-flow-host/1";
const MAX_CONFIG_BYTES: u64 = 256 * 1024;
const MAX_API_KEY_BYTES: u64 = 512;
const MAX_RESPONSE_BYTES: usize = 256 * 1024;
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
const CONTEXT_TTL_SECS: i64 = 8 * 3600;
const PAIMOS_HOST_ID: &str = "paimos";
const REVIEW_FRAGMENT: &str = "#baseline-batch";

static FETCH_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
enum FlowError {
    Configuration,
    Credential,
    Transport,
    Refused(HttpStatus),
    Unavailable(&'static str),
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowConfigDocument {
    schema: String,
    schema_version: u16,
    enabled: bool,
    host_id: String,
    paimos_origin: String,
    api_key_file: PathBuf,
    instance_label: Option<String>,
    bindings: Vec<FlowBindingDocument>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowBindingDocument {
    project_id: u64,
    project_ref: Option<String>,
    label: String,
    hosts: Vec<String>,
    operator_refs: Vec<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct FlowBinding {
    pub(crate) project_id: u64,
    pub(crate) expected_project_ref: String,
    pub(crate) label: String,
    pub(crate) hosts: Vec<String>,
    pub(crate) operator_refs: HashSet<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct FlowHostConfig {
    pub(crate) enabled: bool,
    pub(crate) host_id: String,
    pub(crate) paimos_origin: Url,
    pub(crate) api_key_file: PathBuf,
    pub(crate) instance_label: String,
    pub(crate) bindings: Vec<FlowBinding>,
    pub(crate) config_digest: String,
}

#[derive(Clone)]
pub(crate) struct FlowHostService {
    config: FlowHostConfig,
    client: Client,
    cache: Arc<Mutex<ProjectionCache>>,
}

#[derive(Default)]
struct ProjectionCache {
    entries: BTreeMap<CacheKey, CachedProjection>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct CacheKey {
    project_id: u64,
    operator_ref: String,
    host: Option<String>,
}

#[derive(Clone, Debug)]
struct CachedProjection {
    generation: u64,
    fetched_at: i64,
    source_revision: String,
    shell_state: Value,
    paimos_evaluated_at: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FlowShellResponse {
    enabled: bool,
    mount_shell: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    identity_context: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    projection_meta: Option<ProjectionMeta>,
}

#[derive(Clone, Debug, Serialize)]
struct ProjectionMeta {
    evaluated_at: String,
    fresh_until: String,
    source_revision: String,
    context_revision: String,
    binding_ref: String,
    project_id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    selected_host: Option<String>,
    generation: u64,
}

#[derive(Clone, Debug, Deserialize)]
pub(crate) struct FlowIntentRequest {
    #[serde(rename = "type")]
    intent_type: String,
    identity: Option<Value>,
    detail: Option<Value>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FlowIntentResponse {
    pub(crate) executed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) routed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) location: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) notice: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) issues: Option<Vec<String>>,
}

impl FlowHostService {
    pub(crate) fn from_env() -> Result<Option<Self>, String> {
        let Some(path) = env_nonempty(FLOW_CONFIG_ENV) else {
            return Ok(None);
        };
        let config = FlowHostConfig::load(Path::new(&path))?;
        if !config.enabled {
            return Ok(None);
        }
        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| "flow host HTTP client unavailable".to_string())?;
        Ok(Some(Self {
            config,
            client,
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        }))
    }

    pub(crate) fn configured(&self) -> bool {
        true
    }

    pub(crate) fn mount_enabled(&self) -> bool {
        self.config.enabled
    }

    pub(crate) async fn shell_state(
        &self,
        auth: &AuthState,
        headers: &HeaderMap,
        access: &AccessGrant,
        hosts: &[Host],
        selected_host: Option<&str>,
        now: i64,
    ) -> FlowShellResponse {
        match self.resolve_context(auth, headers, access, selected_host) {
            Ok(context) => self.projection_response(context, hosts, selected_host, now).await,
            Err(reason) => FlowShellResponse {
                enabled: true,
                mount_shell: true,
                unavailable_reason: Some(reason),
                shell_state: None,
                identity_context: None,
                projection_meta: None,
            },
        }
    }

    pub(crate) fn handle_intent(
        &self,
        auth: &AuthState,
        headers: &HeaderMap,
        access: &AccessGrant,
        _hosts: &[Host],
        selected_host: Option<&str>,
        request: FlowIntentRequest,
        now: i64,
    ) -> (StatusCode, FlowIntentResponse) {
        let intent_type = request.intent_type.trim();
        if intent_type.is_empty() {
            return (
                StatusCode::BAD_REQUEST,
                FlowIntentResponse {
                    executed: false,
                    error: Some("invalid flow intent".to_string()),
                    ..Default::default()
                },
            );
        }
        if !human_session(auth, headers) {
            return (
                StatusCode::FORBIDDEN,
                FlowIntentResponse {
                    executed: false,
                    error: Some("A human Pharos session is required for Flow intents.".to_string()),
                    issues: Some(vec![
                        "Machine operator credentials cannot act as a Flow human.".to_string(),
                    ]),
                    ..Default::default()
                },
            );
        }
        let context = match self.resolve_context(auth, headers, access, selected_host) {
            Ok(context) => context,
            Err(reason) => {
                return (
                    StatusCode::CONFLICT,
                    FlowIntentResponse {
                        executed: false,
                        error: Some(reason),
                        ..Default::default()
                    },
                );
            }
        };
        if is_consequential(intent_type) {
            if let Some(issues) = self.validate_submitted_identity(&context, &request.identity, now)
            {
                let status = if issues.iter().any(|issue| issue.contains("human")) {
                    StatusCode::FORBIDDEN
                } else {
                    StatusCode::CONFLICT
                };
                return (
                    status,
                    FlowIntentResponse {
                        executed: false,
                        error: Some(issues[0].clone()),
                        issues: Some(issues),
                        ..Default::default()
                    },
                );
            }
        }
        let review_url = self.review_url(context.binding.project_id);
        match intent_type {
            "flow:start-intent" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: Some("paimos-project-overview-baseline".to_string()),
                    location: Some(review_url),
                    notice: Some(
                        "Start stays on the configured Paimos project overview baseline controls. Pharos does not start delivery.".to_string(),
                    ),
                    ..Default::default()
                },
            ),
            "flow:review-batch" | "flow:view-drafts" | "flow:save-proposal" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: Some("paimos-project-overview-baseline".to_string()),
                    location: Some(review_url),
                    notice: Some(
                        "Review stays on the configured Paimos project overview baseline controls.".to_string(),
                    ),
                    ..Default::default()
                },
            ),
            "flow:header-project" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: Some("paimos-project-overview".to_string()),
                    location: Some(self.project_overview_url(context.binding.project_id)),
                    notice: Some("Project navigation stays in configured Paimos.".to_string()),
                    ..Default::default()
                },
            ),
            "flow:header-account" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: None,
                    notice: Some("Account controls stay in existing Pharos session UI.".to_string()),
                    ..Default::default()
                },
            ),
            _ => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: None,
                    notice: Some(
                        "Stage navigation and header actions do not start delivery.".to_string(),
                    ),
                    ..Default::default()
                },
            ),
        }
    }

    async fn projection_response(
        &self,
        context: ResolvedContext,
        hosts: &[Host],
        selected_host: Option<&str>,
        now: i64,
    ) -> FlowShellResponse {
        match self.fetch_projection(&context, now).await {
            Ok(projection) => {
                let identity = issue_identity(&self.config, &context, &projection, now);
                let shell_state = merge_shell_state(
                    &projection.shell_state,
                    &self.config,
                    hosts,
                    selected_host,
                    now,
                );
                FlowShellResponse {
                    enabled: true,
                    mount_shell: true,
                    unavailable_reason: None,
                    shell_state: Some(shell_state),
                    identity_context: Some(identity),
                    projection_meta: Some(ProjectionMeta {
                        evaluated_at: projection.paimos_evaluated_at.clone(),
                        fresh_until: iso_timestamp(next_ten_minute_boundary(now)),
                        source_revision: projection.source_revision.clone(),
                        context_revision: context.context_revision.clone(),
                        binding_ref: context.binding_ref.clone(),
                        project_id: context.binding.project_id,
                        selected_host: selected_host.map(str::to_string),
                        generation: projection.generation,
                    }),
                }
            }
            Err(FlowError::Unavailable(reason)) => FlowShellResponse {
                enabled: true,
                mount_shell: true,
                unavailable_reason: Some(reason.to_string()),
                shell_state: None,
                identity_context: None,
                projection_meta: None,
            },
            Err(_) => FlowShellResponse {
                enabled: true,
                mount_shell: true,
                unavailable_reason: Some(
                    "Configured Paimos projection is unavailable right now.".to_string(),
                ),
                shell_state: None,
                identity_context: None,
                projection_meta: None,
            },
        }
    }

    fn resolve_context(
        &self,
        auth: &AuthState,
        headers: &HeaderMap,
        access: &AccessGrant,
        selected_host: Option<&str>,
    ) -> Result<ResolvedContext, String> {
        if !human_session(auth, headers) {
            return Err("A verified human Pharos session is required.".to_string());
        }
        let user = human_user(auth, headers)
            .ok_or_else(|| "A verified human Pharos session is required.".to_string())?;
        let binding = self
            .select_binding(&user, access, selected_host)
            .ok_or_else(|| {
                "No configured Flow binding matches this operator and host scope.".to_string()
            })?;
        let binding_ref = pharos_opaque_ref(
            &self.config.host_id,
            "bind",
            &[
                &self.config.config_digest,
                &user.operator_ref,
                &binding.project_id.to_string(),
            ],
        );
        let context_revision = pharos_opaque_ref(
            &self.config.host_id,
            "ctxrev",
            &[
                &self.config.config_digest,
                &user.operator_ref,
                &binding.project_id.to_string(),
                &binding.expected_project_ref,
            ],
        );
        Ok(ResolvedContext {
            user,
            binding,
            binding_ref,
            context_revision,
        })
    }

    fn select_binding(
        &self,
        user: &AuthUser,
        access: &AccessGrant,
        selected_host: Option<&str>,
    ) -> Option<FlowBinding> {
        let mut matches: Vec<&FlowBinding> = self
            .config
            .bindings
            .iter()
            .filter(|binding| binding.operator_refs.contains(&user.operator_ref))
            .filter(|binding| binding.hosts.iter().all(|host| access.allows_host(host)))
            .filter(|binding| {
                selected_host.is_none_or(|host| binding.hosts.iter().any(|allowed| allowed == host))
            })
            .collect();
        matches.sort_by_key(|binding| binding.project_id);
        matches.first().cloned().cloned()
    }

    async fn fetch_projection(
        &self,
        context: &ResolvedContext,
        now: i64,
    ) -> Result<CachedProjection, FlowError> {
        let key = CacheKey {
            project_id: context.binding.project_id,
            operator_ref: context.user.operator_ref.clone(),
            host: None,
        };
        let generation = FETCH_GENERATION.fetch_add(1, Ordering::Relaxed);
        let fresh_until = next_ten_minute_boundary(now);
        if let Some(cached) = self.cache.lock().expect("flow cache").entries.get(&key) {
            if cached.fetched_at >= floor_ten_minute_boundary(now)
                && cached.generation >= generation.saturating_sub(1)
            {
                return Ok(cached.clone());
            }
        }
        let fetched = self.fetch_paimos_state(context).await?;
        let evaluated_at = fetched
            .get("evaluatedAt")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| iso_timestamp(now));
        let source_revision = pharos_opaque_ref(
            &self.config.host_id,
            "src",
            &[&context.binding.expected_project_ref, &evaluated_at],
        );
        let entry = CachedProjection {
            generation,
            fetched_at: now,
            source_revision,
            shell_state: fetched,
            paimos_evaluated_at: evaluated_at,
        };
        self.cache
            .lock()
            .expect("flow cache")
            .entries
            .insert(key, entry.clone());
        let _ = fresh_until;
        Ok(entry)
    }

    async fn fetch_paimos_state(&self, context: &ResolvedContext) -> Result<Value, FlowError> {
        let api_key = read_api_key(&self.config.api_key_file)?;
        let url = self
            .config
            .paimos_origin
            .join(&format!(
                "api/projects/{}/baseline-batches/flow-state",
                context.binding.project_id
            ))
            .map_err(|_| FlowError::Configuration)?;
        let response = self
            .client
            .get(url)
            .header(ACCEPT, "application/json")
            .header(USER_AGENT, USER_AGENT_VALUE)
            .header(AUTHORIZATION, format!("Bearer {}", api_key))
            .send()
            .await
            .map_err(|_| FlowError::Transport)?;
        let status = response.status();
        let bytes = response.bytes().await.map_err(|_| FlowError::Transport)?;
        if bytes.len() > MAX_RESPONSE_BYTES {
            return Err(FlowError::Unavailable("projection response too large"));
        }
        if status == HttpStatus::NOT_FOUND || status == HttpStatus::FORBIDDEN {
            return Err(FlowError::Unavailable(
                "Configured Paimos project projection is unavailable for this binding.",
            ));
        }
        if !status.is_success() {
            return Err(FlowError::Refused(status));
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| FlowError::Transport)?;
        validate_paimos_project_ref(&payload, &context.binding.expected_project_ref)?;
        Ok(strip_paimos_identity(payload))
    }

    fn validate_submitted_identity(
        &self,
        context: &ResolvedContext,
        submitted: &Option<Value>,
        now: i64,
    ) -> Option<Vec<String>> {
        let Some(submitted) = submitted else {
            return Some(vec![
                "Host identity context is required before a consequential intent.".to_string(),
            ]);
        };
        let status = submitted
            .get("status")
            .and_then(Value::as_str)
            .unwrap_or("present");
        if status != "present" {
            return Some(vec!["Host identity context was rejected.".to_string()]);
        }
        let current = issue_identity(
            &self.config,
            context,
            &CachedProjection {
                generation: 0,
                fetched_at: now,
                source_revision: context.context_revision.clone(),
                shell_state: json!({}),
                paimos_evaluated_at: iso_timestamp(now),
            },
            now,
        );
        let mut issues = Vec::new();
        let checks = [
            (
                "principal_ref",
                current["principal_ref"].as_str(),
                ["principalRef", "principal_ref"],
            ),
            (
                "project_ref",
                current["project_ref"].as_str(),
                ["projectRef", "project_ref"],
            ),
            (
                "binding_ref",
                current["binding_ref"].as_str(),
                ["bindingRef", "binding_ref"],
            ),
            (
                "context_revision",
                current["context_revision"].as_str(),
                ["contextRevision", "context_revision"],
            ),
            (
                "actor_kind",
                Some("human"),
                ["actorKind", "actor_kind"],
            ),
        ];
        for (label, expected, fields) in checks {
            if let Some(expected) = expected {
                let submitted_value = fields
                    .iter()
                    .find_map(|field| submitted.get(*field).and_then(Value::as_str));
                if submitted_value != Some(expected) {
                    issues.push(format!("Host identity context mismatch for {label}."));
                }
            }
        }
        if parse_rfc3339(
            submitted
                .get("expiresAt")
                .or_else(|| submitted.get("expires_at")),
        )
            .is_none_or(|expires| now >= expires)
        {
            issues.push("Host identity context has expired.".to_string());
        }
        if parse_rfc3339(
            submitted
                .get("freshUntil")
                .or_else(|| submitted.get("fresh_until")),
        )
        .is_none_or(|fresh| now >= fresh)
        {
            issues.push("Host identity context is stale.".to_string());
        }
        if issues.is_empty() {
            None
        } else {
            Some(issues)
        }
    }

    fn review_url(&self, project_id: u64) -> String {
        format!(
            "{}/projects/{}?tab=overview{}",
            self.config.paimos_origin.as_str().trim_end_matches('/'),
            project_id,
            REVIEW_FRAGMENT
        )
    }

    fn project_overview_url(&self, project_id: u64) -> String {
        format!(
            "{}/projects/{}?tab=overview",
            self.config.paimos_origin.as_str().trim_end_matches('/'),
            project_id
        )
    }
}

#[derive(Clone, Debug)]
struct ResolvedContext {
    user: AuthUser,
    binding: FlowBinding,
    binding_ref: String,
    context_revision: String,
}

impl FlowHostConfig {
    fn load(path: &Path) -> Result<Self, String> {
        let bytes = read_config_file(path)?;
        let document: FlowConfigDocument =
            serde_json::from_slice(&bytes).map_err(|_| "invalid flow host configuration".to_string())?;
        if document.schema != CONFIG_SCHEMA
            || document.schema_version != CONFIG_SCHEMA_VERSION
            || !valid_host_id(&document.host_id)
            || document.bindings.is_empty()
            || document.bindings.len() > 32
        {
            return Err("invalid flow host configuration".to_string());
        }
        let paimos_origin = parse_origin(&document.paimos_origin)
            .map_err(|_| "invalid flow host configuration".to_string())?;
        if !document.api_key_file.is_absolute() {
            return Err("invalid flow host configuration".to_string());
        }
        let bindings = document
            .bindings
            .into_iter()
            .map(|binding| FlowBinding::from_document(binding))
            .collect::<Result<Vec<_>, _>>()?;
        let config_digest = hex_digest(&bytes);
        let host_id = document.host_id;
        let instance_label = document
            .instance_label
            .filter(|label| !label.trim().is_empty())
            .unwrap_or_else(|| host_id.clone());
        Ok(Self {
            enabled: document.enabled,
            host_id,
            paimos_origin,
            api_key_file: document.api_key_file,
            instance_label,
            bindings,
            config_digest,
        })
    }
}

impl FlowBinding {
    fn from_document(document: FlowBindingDocument) -> Result<Self, String> {
        if document.project_id == 0
            || document.label.trim().is_empty()
            || document.hosts.is_empty()
            || document.operator_refs.is_empty()
            || document.hosts.len() > 64
            || document.operator_refs.len() > 64
        {
            return Err("invalid flow host configuration".to_string());
        }
        let expected = document
            .project_ref
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| paimos_opaque_ref("proj", &[document.project_id.to_string()]));
        if !expected.starts_with(&format!("{PAIMOS_HOST_ID}:proj-")) {
            return Err("invalid flow host configuration".to_string());
        }
        let hosts = document
            .hosts
            .into_iter()
            .map(|host| host.trim().to_string())
            .filter(|host| !host.is_empty())
            .collect::<Vec<_>>();
        let operator_refs = document
            .operator_refs
            .into_iter()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .collect::<HashSet<_>>();
        if hosts.is_empty() || operator_refs.is_empty() {
            return Err("invalid flow host configuration".to_string());
        }
        Ok(Self {
            project_id: document.project_id,
            expected_project_ref: expected,
            label: document.label.trim().to_string(),
            hosts,
            operator_refs,
        })
    }
}

impl Default for FlowIntentResponse {
    fn default() -> Self {
        Self {
            executed: false,
            routed: None,
            location: None,
            reason: None,
            notice: None,
            error: None,
            issues: None,
        }
    }
}

pub(crate) fn inject_flow_shell(html: String, mount: bool) -> String {
    if !mount {
        return html;
    }
    let wrapped = html.replace(
        "<main",
        "<inspr-flow-shell layout-mode=\"bounded\" content-padding=\"34px\" data-flow-host><main",
    );
    let wrapped = wrapped.replace("</main>", "</main></inspr-flow-shell>");
    let bootstrap = r#"<script type="module">
import '/assets/vendor/flow-shell/src/inspr-flow-shell.js';
const shell = document.querySelector('inspr-flow-shell');
if (shell) {
  let generation = 0;
  const refresh = async () => {
    const next = generation + 1;
    generation = next;
    const response = await fetch('/flow/shell-state.json', { credentials: 'same-origin', cache: 'no-store' });
    if (!response.ok || generation !== next) return;
    const payload = await response.json();
    if (generation !== next) return;
    if (!payload.enabled) return;
    if (payload.shellState) shell.shellState = payload.shellState;
    if (payload.identityContext) shell.identityContext = payload.identityContext;
  };
  shell.addEventListener('flow-intent', async (event) => {
    const response = await fetch('/flow/intents', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: event.detail?.type, identity: event.detail?.identity, detail: event.detail }),
    });
    const result = await response.json();
    if (result.location && typeof result.location === 'string') {
      const origin = new URL(document.baseURI).origin;
      const target = new URL(result.location, origin);
      if (target.origin === origin || result.location.startsWith('http')) {
        window.location.assign(result.location);
      }
    }
  });
  document.addEventListener('visibilitychange', () => { if (!document.hidden) refresh(); });
  refresh();
  setInterval(refresh, 600000);
}
</script>"#;
    if let Some(index) = wrapped.rfind("</body>") {
        let mut output = wrapped;
        output.insert_str(index, bootstrap);
        return output;
    }
    format!("{wrapped}{bootstrap}")
}

pub(crate) fn flow_static_asset(path: &str) -> Option<(&'static [u8], &'static str)> {
    match path {
        "src/inspr-flow-shell.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/inspr-flow-shell.js"),
            "text/javascript",
        )),
        "src/flow-shell.css" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/flow-shell.css"),
            "text/css",
        )),
        "src/adapter.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/adapter.js"),
            "text/javascript",
        )),
        "src/forecast.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/forecast.js"),
            "text/javascript",
        )),
        "src/gates.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/gates.js"),
            "text/javascript",
        )),
        "src/host-layout.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/host-layout.js"),
            "text/javascript",
        )),
        "src/identity.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/identity.js"),
            "text/javascript",
        )),
        "src/intents.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/intents.js"),
            "text/javascript",
        )),
        "src/sanitize.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/sanitize.js"),
            "text/javascript",
        )),
        "src/stages.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/stages.js"),
            "text/javascript",
        )),
        "src/state.js" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/state.js"),
            "text/javascript",
        )),
        "src/assets/inspr-logo.svg" => Some((
            include_bytes!("../assets/vendor/flow-shell/src/assets/inspr-logo.svg"),
            "image/svg+xml",
        )),
        _ => None,
    }
}

fn merge_shell_state(
    upstream: &Value,
    config: &FlowHostConfig,
    hosts: &[Host],
    selected_host: Option<&str>,
    now: i64,
) -> Value {
    let mut shell = upstream.clone();
    let project_name = shell
        .get("header")
        .and_then(|value| value.get("projectName"))
        .and_then(Value::as_str)
        .unwrap_or("Project")
        .to_string();
    if let Some(header) = shell.get_mut("header").and_then(Value::as_object_mut) {
        header.insert("appName".into(), Value::String("Pharos".into()));
        header.insert(
            "instanceLabel".into(),
            Value::String(config.instance_label.clone()),
        );
        header.insert("version".into(), Value::String(format!("v{APP_VERSION}")));
        header.insert("projectName".into(), Value::String(project_name));
        header.insert(
            "projectSubtitle".into(),
            Value::String("Pharos host projection · upstream observations".into()),
        );
    }
    if let Some(health) = shell.get_mut("health").and_then(Value::as_object_mut) {
        if let Some(host_name) = selected_host {
            if let Some(host) = hosts.iter().find(|host| host.name == host_name) {
                health.insert("status".into(), Value::String(local_health_status(host, now)));
                health.insert(
                    "label".into(),
                    Value::String(format!("Pharos host {host_name}")),
                );
                health.insert(
                    "checkedLabel".into(),
                    Value::String("Local Pharos lifecycle observation".into()),
                );
            }
        }
    }
    shell
}

fn local_health_status(host: &Host, now: i64) -> String {
    match liveness(host.last_seen, host.heartbeat_interval_secs, now) {
        Liveness::Live => "live".to_string(),
        Liveness::Stale => "stale".to_string(),
        Liveness::Down => "down".to_string(),
        Liveness::AwaitingFirstHeartbeat => "awaiting".to_string(),
    }
}
fn issue_identity(
    config: &FlowHostConfig,
    context: &ResolvedContext,
    _projection: &CachedProjection,
    now: i64,
) -> Value {
    let issued = iso_timestamp(now);
    let expires = iso_timestamp(now + CONTEXT_TTL_SECS);
    let fresh_until = iso_timestamp(next_ten_minute_boundary(now));
    let principal_ref = pharos_opaque_ref(
        &config.host_id,
        "prin",
        &[&context.user.operator_ref],
    );
    let project_id = context.binding.project_id.to_string();
    let project_ref = pharos_opaque_ref(&config.host_id, "proj", &[&project_id]);
    json!({
        "contract_version": IDENTITY_CONTRACT,
        "evaluated_at": issued,
        "host_id": config.host_id,
        "principal_kind": "local_host",
        "principal_ref": principal_ref,
        "binding_ref": context.binding_ref,
        "organization_ref": null,
        "project_ref": project_ref,
        "actor_kind": "human",
        "issued_at": issued,
        "expires_at": expires,
        "fresh_until": fresh_until,
        "context_revision": context.context_revision,
        "authority_disclaimer": AUTHORITY_DISCLAIMER,
        "display": {
            "user_label": context.user.display_name,
            "user_initials": initials_from_ref(&principal_ref),
            "project_label": context.binding.label,
            "fixture_label": "Host-verified Pharos human context. Not live Paimos identity."
        }
    })
}

fn strip_paimos_identity(payload: Value) -> Value {
    if let Some(object) = payload.as_object() {
        let mut copy = object.clone();
        copy.remove("identityContext");
        return Value::Object(copy);
    }
    payload
}

fn validate_paimos_project_ref(payload: &Value, expected: &str) -> Result<(), FlowError> {
    let actual = payload
        .get("identityContext")
        .and_then(|value| value.get("project_ref"))
        .and_then(Value::as_str)
        .or_else(|| {
            payload
                .get("identityContext")
                .and_then(|value| value.get("projectRef"))
                .and_then(Value::as_str)
        });
    if actual == Some(expected) {
        Ok(())
    } else {
        Err(FlowError::Unavailable("configured project binding mismatch"))
    }
}

fn human_session(auth: &AuthState, headers: &HeaderMap) -> bool {
    auth.human_user(headers).is_some()
}

fn human_user(auth: &AuthState, headers: &HeaderMap) -> Option<AuthUser> {
    auth.human_user(headers)
}

fn is_consequential(intent_type: &str) -> bool {
    matches!(
        intent_type,
        "flow:start-intent" | "flow:review-batch" | "flow:save-proposal"
    )
}

fn paimos_opaque_ref(kind: &str, parts: &[String]) -> String {
    opaque_ref(PAIMOS_HOST_ID, kind, parts)
}

fn pharos_opaque_ref(host_id: &str, kind: &str, parts: &[&str]) -> String {
    opaque_ref(host_id, kind, &parts.iter().map(|part| part.to_string()).collect::<Vec<_>>())
}

fn opaque_ref(host_id: &str, kind: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{host_id}:{kind}:").as_bytes());
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    format!("{host_id}:{kind}-{}", hex_bytes(&hasher.finalize()))
}

fn initials_from_ref(reference: &str) -> String {
    let digest = hex_bytes(&Sha256::digest(reference.as_bytes()));
    let letters = digest
        .chars()
        .filter(|ch| ('a'..='f').contains(ch))
        .take(2)
        .collect::<String>()
        .to_uppercase();
    if letters.len() == 2 {
        letters
    } else {
        digest.chars().take(2).collect::<String>().to_uppercase()
    }
}

fn next_ten_minute_boundary(now: i64) -> i64 {
    let remainder = now % 600;
    if remainder == 0 {
        now + 600
    } else {
        now + (600 - remainder)
    }
}

fn floor_ten_minute_boundary(now: i64) -> i64 {
    now - (now % 600)
}

fn iso_timestamp(unix: i64) -> String {
    OffsetDateTime::from_unix_timestamp(unix)
        .unwrap_or_else(|_| OffsetDateTime::now_utc())
        .format(&Rfc3339)
        .unwrap_or_else(|_| "1970-01-01T00:00:00Z".to_string())
}

fn parse_rfc3339(value: Option<&Value>) -> Option<i64> {
    let text = value.and_then(Value::as_str)?;
    OffsetDateTime::parse(text, &Rfc3339)
        .ok()
        .map(|timestamp| timestamp.unix_timestamp())
}

fn valid_host_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .chars()
            .next()
            .is_some_and(|ch| ch.is_ascii_alphabetic())
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-'))
}

fn parse_origin(value: &str) -> Result<Url, FlowError> {
    let url = Url::parse(value).map_err(|_| FlowError::Configuration)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || (url.path() != "" && url.path() != "/")
    {
        return Err(FlowError::Configuration);
    }
    Ok(url)
}

#[cfg(test)]
fn loopback_origin_for_tests(value: &str) -> Url {
    let url = Url::parse(value).expect("test loopback origin parses");
    assert_eq!(url.scheme(), "http");
    match url.host() {
        Some(url::Host::Ipv4(address)) => assert!(address.is_loopback()),
        Some(url::Host::Ipv6(address)) => assert!(address.is_loopback()),
        Some(url::Host::Domain(domain)) => assert_eq!(domain, "localhost"),
        None => panic!("missing host"),
    }
    url
}

fn read_config_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .map_err(|_| "invalid flow host configuration".to_string())?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|_| "invalid flow host configuration".to_string())?;
    if bytes.is_empty() || bytes.len() as u64 > MAX_CONFIG_BYTES {
        return Err("invalid flow host configuration".to_string());
    }
    Ok(bytes)
}

fn read_api_key(path: &Path) -> Result<String, FlowError> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path).map_err(|_| FlowError::Credential)?;
    let mut bytes = Vec::new();
    file.take(MAX_API_KEY_BYTES.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FlowError::Credential)?;
    if bytes.len() < 32 || bytes.len() as u64 > MAX_API_KEY_BYTES {
        bytes.fill(0);
        return Err(FlowError::Credential);
    }
    if !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        bytes.fill(0);
        return Err(FlowError::Credential);
    }
    let key = String::from_utf8(bytes).map_err(|_| FlowError::Credential)?;
    Ok(key)
}

fn hex_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex_bytes(&Sha256::digest(bytes)))
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{AccessGrant, AuthState, AuthUser};
    use axum::http::StatusCode;
    use axum::routing::get;
    use axum::Router;
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn sample_config(origin: &Url, api_key_file: PathBuf) -> FlowHostConfig {
        FlowHostConfig {
            enabled: true,
            host_id: "pharos-test".to_string(),
            paimos_origin: origin.clone(),
            api_key_file,
            instance_label: "Pharos test".to_string(),
            bindings: vec![FlowBinding {
                project_id: 17,
                expected_project_ref: paimos_opaque_ref("proj", &["17".to_string()]),
                label: "Test project".to_string(),
                hosts: vec!["hsb8".to_string()],
                operator_refs: HashSet::from(["operator-a".to_string()]),
            }],
            config_digest: "sha256:test".to_string(),
        }
    }

    fn sample_state() -> Value {
        json!({
            "evaluatedAt": "2026-09-08T08:00:00.000Z",
            "header": {"appName": "Paimos", "projectName": "Test"},
            "health": {"status": "available"},
            "delivery": {"status": "draft"},
            "prerequisites": {},
            "progress": {},
            "executionModes": ["manual"],
            "selectedExecutionMode": "manual",
            "selectedAction": "build",
            "identityContext": {
                "project_ref": paimos_opaque_ref("proj", &["17".to_string()])
            }
        })
    }

    async fn serve_paimos(state: Value) -> (Url, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let app = Router::new().route(
                "/api/projects/17/baseline-batches/flow-state",
                get(move || async move { axum::Json(state.clone()) }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        (
            loopback_origin_for_tests(&format!("http://127.0.0.1:{}", address.port())),
            task,
        )
    }

    #[test]
    fn vendor_manifest_matches_embedded_assets() {
        let manifest = include_str!("../assets/vendor/flow-shell/manifest.json");
        let parsed: Value = serde_json::from_str(manifest).expect("manifest json");
        assert_eq!(parsed["version"], "0.1.3");
        let (bytes, _) = flow_static_asset("src/inspr-flow-shell.js").expect("shell asset");
        let digest = format!("sha256:{}", hex_bytes(&Sha256::digest(bytes)));
        let files = parsed["files"].as_array().expect("files");
        let entry = files
            .iter()
            .find(|entry| entry["path"] == "src/inspr-flow-shell.js")
            .expect("shell file entry");
        assert_eq!(entry["sha256"], digest);
    }

    #[tokio::test]
    async fn configured_projection_and_intent_navigation() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let key_path = std::env::temp_dir().join(format!("pharos-flow-key-{}", std::process::id()));
        std::fs::write(&key_path, b"01234567890123456789012345678901").unwrap();
        let service = FlowHostService {
            config: sample_config(&origin, key_path.clone()),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        };
        let auth = AuthState::for_test_human(
            AccessGrant::limited(["hsb8"], true),
            AuthUser {
                operator_ref: "operator-a".to_string(),
                managed_human_session_ref: "sess".to_string(),
                display_name: "Operator".to_string(),
            },
        );
        let headers = HeaderMap::new();
        let access = AccessGrant::limited(["hsb8"], true);
        let response = service
            .shell_state(&auth, &headers, &access, &[], None, 1_700_000_000)
            .await;
        assert!(response.shell_state.is_some());
        assert!(response.identity_context.is_some());
        let identity = response.identity_context.unwrap();
        assert_eq!(identity["principal_kind"], "local_host");
        let (status, intent) = service.handle_intent(
            &auth,
            &headers,
            &access,
            &[],
            None,
            FlowIntentRequest {
                intent_type: "flow:review-batch".to_string(),
                identity: Some(json!({
                    "status": "present",
                    "principal_ref": identity["principal_ref"],
                    "project_ref": identity["project_ref"],
                    "binding_ref": identity["binding_ref"],
                    "context_revision": identity["context_revision"],
                    "actor_kind": "human",
                    "expires_at": identity["expires_at"],
                    "fresh_until": identity["fresh_until"]
                })),
                detail: None,
            },
            1_700_000_000,
        );
        assert_eq!(status, StatusCode::OK, "intent error: {:?}", intent.error);
        assert!(!intent.executed);
        assert!(intent.location.unwrap().contains("/projects/17?tab=overview#baseline-batch"));
        server.abort();
        std::fs::remove_file(key_path).ok();
    }

    #[test]
    fn rejects_machine_authorization_header_for_flow() {
        let auth = AuthState::for_test_access(AccessGrant::full());
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            "Bearer machine-token".parse().unwrap(),
        );
        assert!(!human_session(&auth, &headers));
    }

    #[tokio::test]
    async fn rejects_wrong_paimos_project_ref() {
        let mut state = sample_state();
        state["identityContext"]["project_ref"] = json!(paimos_opaque_ref("proj", &["99".to_string()]));
        let (origin, server) = serve_paimos(state).await;
        let key_path = std::env::temp_dir().join(format!("pharos-flow-key-wrong-{}", std::process::id()));
        std::fs::write(&key_path, b"01234567890123456789012345678901").unwrap();
        let service = FlowHostService {
            config: sample_config(&origin, key_path.clone()),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        };
        let auth = AuthState::for_test_human(
            AccessGrant::limited(["hsb8"], true),
            AuthUser {
                operator_ref: "operator-a".to_string(),
                managed_human_session_ref: "sess".to_string(),
                display_name: "Operator".to_string(),
            },
        );
        let response = service
            .shell_state(
                &auth,
                &HeaderMap::new(),
                &AccessGrant::limited(["hsb8"], true),
                &[],
                None,
                1_700_000_000,
            )
            .await;
        assert!(response.shell_state.is_none());
        assert!(response
            .unavailable_reason
            .unwrap()
            .contains("project binding mismatch"));
        server.abort();
        std::fs::remove_file(key_path).ok();
    }

    #[tokio::test]
    async fn rejects_unauthorized_operator_binding() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let key_path =
            std::env::temp_dir().join(format!("pharos-flow-key-operator-{}", std::process::id()));
        std::fs::write(&key_path, b"01234567890123456789012345678901").unwrap();
        let service = FlowHostService {
            config: sample_config(&origin, key_path.clone()),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        };
        let auth = AuthState::for_test_human(
            AccessGrant::limited(["hsb8"], true),
            AuthUser {
                operator_ref: "operator-unknown".to_string(),
                managed_human_session_ref: "sess".to_string(),
                display_name: "Operator".to_string(),
            },
        );
        let response = service
            .shell_state(
                &auth,
                &HeaderMap::new(),
                &AccessGrant::limited(["hsb8"], true),
                &[],
                None,
                1_700_000_000,
            )
            .await;
        assert!(response.shell_state.is_none());
        assert!(response
            .unavailable_reason
            .unwrap()
            .contains("No configured Flow binding"));
        server.abort();
        std::fs::remove_file(key_path).ok();
    }

    #[tokio::test]
    async fn rejects_expired_identity_on_intent() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let key_path =
            std::env::temp_dir().join(format!("pharos-flow-key-expired-{}", std::process::id()));
        std::fs::write(&key_path, b"01234567890123456789012345678901").unwrap();
        let service = FlowHostService {
            config: sample_config(&origin, key_path.clone()),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        };
        let auth = AuthState::for_test_human(
            AccessGrant::limited(["hsb8"], true),
            AuthUser {
                operator_ref: "operator-a".to_string(),
                managed_human_session_ref: "sess".to_string(),
                display_name: "Operator".to_string(),
            },
        );
        let headers = HeaderMap::new();
        let access = AccessGrant::limited(["hsb8"], true);
        let response = service
            .shell_state(&auth, &headers, &access, &[], None, 1_700_000_000)
            .await;
        let identity = response.identity_context.unwrap();
        let (status, intent) = service.handle_intent(
            &auth,
            &headers,
            &access,
            &[],
            None,
            FlowIntentRequest {
                intent_type: "flow:review-batch".to_string(),
                identity: Some(json!({
                    "status": "present",
                    "principal_ref": identity["principal_ref"],
                    "project_ref": identity["project_ref"],
                    "binding_ref": identity["binding_ref"],
                    "context_revision": identity["context_revision"],
                    "actor_kind": "human",
                    "expires_at": "2020-01-01T00:00:00Z",
                    "fresh_until": identity["fresh_until"]
                })),
                detail: None,
            },
            1_700_000_000,
        );
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!intent.executed);
        assert!(intent
            .error
            .unwrap()
            .contains("expired"));
        server.abort();
        std::fs::remove_file(key_path).ok();
    }
}

