//! Pharos Flow host integration (PHAROS-257).
//!
//! Opt-in bounded `@inspr/flow-shell` host with read-only Paimos projection,
//! Pharos-issued `local_host` identity, and guarded Review/Start navigation.

use std::collections::{BTreeMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::http::{HeaderMap, StatusCode};
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
use pharos_core::{liveness, Host, Liveness, PublicBasePath};

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
const FLOW_LOOPBACK_ORIGIN_ENV: &str = "PHAROS_FLOW_ALLOW_LOOPBACK_ORIGIN";
const HOST_VERIFIED_HUMAN_LABEL: &str = "Host-verified human";
const EVALUATION_MAX_AGE_SECS: i64 = 15 * 60;
pub(crate) const FLOW_INTENT_MAX_BYTES: usize = 4 * 1024;

#[cfg(test)]
const PAIMOS_PROJECT_REF_17: &str = "paimos:proj-9b2899fb59591130607952d66fcb5607";
#[cfg(test)]
const PAIMOS_PROJECT_REF_99: &str = "paimos:proj-492d86f8b3c9707ece3f9fb96f07682a";

static FETCH_GENERATION: AtomicU64 = AtomicU64::new(1);

#[derive(Debug)]
enum FlowError {
    Configuration,
    Credential,
    Transport,
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
    #[serde(default)]
    paimos_public_url: Option<String>,
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
    pub(crate) paimos_public_url: Url,
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
#[serde(rename_all = "camelCase")]
pub(crate) struct FlowShellResponse {
    enabled: bool,
    mount_shell: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    unavailable_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shell_state: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    projection_meta: Option<ProjectionMeta>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
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
    #[serde(default)]
    detail: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Default)]
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
    pub(crate) fn from_env(loopback_dev_mode: bool) -> Result<Option<Self>, String> {
        let Some(path) = env_nonempty(FLOW_CONFIG_ENV) else {
            return Ok(None);
        };
        let config = FlowHostConfig::load(Path::new(&path), loopback_dev_mode)?;
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

    pub(crate) fn mount_enabled_for(
        &self,
        auth: &AuthState,
        headers: &HeaderMap,
        access: &AccessGrant,
        selected_host: Option<&str>,
    ) -> bool {
        if !self.config.enabled {
            return false;
        }
        self.resolve_context(auth, headers, access, selected_host)
            .is_ok()
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
            Ok(context) => {
                self.projection_response(context, access, hosts, selected_host, now)
                    .await
            }
            Err(reason) => FlowShellResponse {
                enabled: true,
                mount_shell: false,
                unavailable_reason: Some(reason),
                shell_state: None,
                projection_meta: None,
            },
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn handle_intent(
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
        let projection = if intent_type == "flow:start-intent" {
            self.fetch_projection(&context, now).await.ok()
        } else {
            None
        };
        if requires_submitted_identity(intent_type) {
            let source_revision = projection
                .as_ref()
                .map(|entry| entry.source_revision.as_str())
                .unwrap_or("");
            if let Some(issues) = self.validate_submitted_identity(
                &context,
                access,
                submitted_identity(&request),
                source_revision,
                now,
            ) {
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
        let confirmed_action = confirmed_start_action(&request)
            .or_else(|| {
                projection.as_ref().and_then(|entry| {
                    entry
                        .shell_state
                        .get("selectedAction")
                        .or_else(|| entry.shell_state.get("selected_action"))
                        .and_then(Value::as_str)
                })
            })
            .unwrap_or("build");
        let start_allowed = projection
            .as_ref()
            .map(|entry| start_permitted(&entry.shell_state, confirmed_action, now))
            .unwrap_or(false);
        match intent_type {
            "flow:start-intent" if !start_allowed => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: None,
                    notice: Some(
                        "Start stays blocked until requirements and current context are fresh. Review remains available.".to_string(),
                    ),
                    ..Default::default()
                },
            ),
            "flow:start-intent" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: Some("paimos-project-overview-baseline".to_string()),
                    location: self.valid_navigation_location(&review_url),
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
                    location: self.valid_navigation_location(&review_url),
                    notice: Some(
                        "Review stays on the configured Paimos project overview baseline controls.".to_string(),
                    ),
                    ..Default::default()
                },
            ),
            "flow:header-project" => {
                let location = self.project_overview_url(context.binding.project_id);
                (
                    StatusCode::OK,
                    FlowIntentResponse {
                        executed: false,
                        routed: Some("paimos-project-overview".to_string()),
                        location: self.valid_navigation_location(&location),
                        notice: Some("Project navigation stays in configured Paimos.".to_string()),
                        ..Default::default()
                    },
                )
            }
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
        access: &AccessGrant,
        hosts: &[Host],
        selected_host: Option<&str>,
        now: i64,
    ) -> FlowShellResponse {
        match self.fetch_projection(&context, now).await {
            Ok(projection) => {
                let context_revision = context_revision_for(
                    &self.config,
                    &context,
                    access,
                    &projection.source_revision,
                );
                let identity =
                    issue_identity(&self.config, &context, &context_revision, &projection, now);
                let shell_state = merge_shell_state(
                    &projection.shell_state,
                    &self.config,
                    &context,
                    &identity,
                    hosts,
                    selected_host,
                    now,
                );
                FlowShellResponse {
                    enabled: true,
                    mount_shell: true,
                    unavailable_reason: None,
                    shell_state: Some(shell_state),
                    projection_meta: Some(ProjectionMeta {
                        evaluated_at: projection.paimos_evaluated_at.clone(),
                        fresh_until: iso_timestamp(next_ten_minute_boundary(now)),
                        source_revision: projection.source_revision.clone(),
                        context_revision,
                        binding_ref: context.binding_ref.clone(),
                        project_id: context.binding.project_id,
                        selected_host: selected_host.map(str::to_string),
                        generation: projection.generation,
                    }),
                }
            }
            Err(FlowError::Unavailable(reason)) => FlowShellResponse {
                enabled: true,
                mount_shell: false,
                unavailable_reason: Some(reason.to_string()),
                shell_state: None,
                projection_meta: None,
            },
            Err(_) => FlowShellResponse {
                enabled: true,
                mount_shell: false,
                unavailable_reason: Some(
                    "Configured Paimos projection is unavailable right now.".to_string(),
                ),
                shell_state: None,
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
            .map_err(|reason| reason.to_string())?;
        let binding_ref = pharos_opaque_ref(
            &self.config.host_id,
            "bind",
            &[
                &self.config.config_digest,
                &user.operator_ref,
                &binding.project_id.to_string(),
            ],
        );
        Ok(ResolvedContext {
            user,
            binding,
            binding_ref,
        })
    }

    fn select_binding(
        &self,
        user: &AuthUser,
        access: &AccessGrant,
        selected_host: Option<&str>,
    ) -> Result<FlowBinding, &'static str> {
        let matches: Vec<&FlowBinding> = self
            .config
            .bindings
            .iter()
            .filter(|binding| binding.operator_refs.contains(&user.operator_ref))
            .filter(|binding| binding.hosts.iter().any(|host| access.allows_host(host)))
            .filter(|binding| {
                selected_host.is_none_or(|host| binding.hosts.iter().any(|allowed| allowed == host))
            })
            .collect();
        if matches.is_empty() {
            return Err("No configured Flow binding matches this operator and host scope.");
        }
        if matches.len() > 1 {
            return Err("Multiple configured Flow bindings match; host scope is required.");
        }
        Ok(matches[0].clone())
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
        if let Some(cached) = self.cache.lock().expect("flow cache").entries.get(&key) {
            if cached.fetched_at >= floor_ten_minute_boundary(now) {
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
            generation: FETCH_GENERATION.fetch_add(1, Ordering::Relaxed),
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
        Ok(entry)
    }

    async fn fetch_paimos_state(&self, context: &ResolvedContext) -> Result<Value, FlowError> {
        let api_key = read_api_key(&self.config.api_key_file)?;
        let url = join_origin_path(
            &self.config.paimos_origin,
            &format!(
                "/api/projects/{}/baseline-batches/flow-state",
                context.binding.project_id
            ),
        )?;
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
        let bytes = bounded_response_bytes(response).await?;
        if status == HttpStatus::NOT_FOUND || status == HttpStatus::FORBIDDEN {
            return Err(FlowError::Unavailable(
                "Configured Paimos project projection is unavailable for this binding.",
            ));
        }
        if !status.is_success() {
            return Err(FlowError::Unavailable(
                "Configured Paimos projection refused the upstream request.",
            ));
        }
        let payload: Value = serde_json::from_slice(&bytes).map_err(|_| FlowError::Transport)?;
        validate_paimos_project_ref(&payload, &context.binding.expected_project_ref)?;
        Ok(strip_paimos_identity(payload))
    }

    fn validate_submitted_identity(
        &self,
        context: &ResolvedContext,
        access: &AccessGrant,
        submitted: Option<Value>,
        source_revision: &str,
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
        let context_revision = context_revision_for(&self.config, context, access, source_revision);
        let current = issue_identity(
            &self.config,
            context,
            &context_revision,
            &CachedProjection {
                generation: 0,
                fetched_at: now,
                source_revision: source_revision.to_string(),
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
            ("actor_kind", Some("human"), ["actorKind", "actor_kind"]),
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
        let mut url = join_origin_path(
            &self.config.paimos_public_url,
            &format!("/projects/{project_id}"),
        )
        .expect("review path is app-relative");
        url.set_query(Some("tab=overview"));
        url.set_fragment(Some(REVIEW_FRAGMENT.trim_start_matches('#')));
        url.to_string()
    }

    fn project_overview_url(&self, project_id: u64) -> String {
        let mut url = join_origin_path(
            &self.config.paimos_public_url,
            &format!("/projects/{project_id}"),
        )
        .expect("overview path is app-relative");
        url.set_query(Some("tab=overview"));
        url.to_string()
    }

    fn valid_navigation_location(&self, location: &str) -> Option<String> {
        let parsed = Url::parse(location).ok()?;
        if parsed.origin() != self.config.paimos_public_url.origin() {
            return None;
        }
        let base = url_public_base(&self.config.paimos_public_url).ok()?;
        let local = base.strip(parsed.path())?;
        if !local.strip_prefix("/projects/").is_some_and(|tail| {
            !tail.is_empty() && !tail.contains('/') && tail.parse::<u64>().is_ok()
        }) {
            return None;
        }
        let query_ok = parsed
            .query()
            .is_some_and(|query| query.split('&').any(|part| part == "tab=overview"));
        if !query_ok || !parsed.username().is_empty() || parsed.password().is_some() {
            return None;
        }
        Some(location.to_string())
    }
}

#[derive(Clone, Debug)]
struct ResolvedContext {
    user: AuthUser,
    binding: FlowBinding,
    binding_ref: String,
}

impl FlowHostConfig {
    fn load(path: &Path, loopback_dev_mode: bool) -> Result<Self, String> {
        let bytes = read_config_file(path)?;
        let document: FlowConfigDocument = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid flow host configuration".to_string())?;
        if document.schema != CONFIG_SCHEMA
            || document.schema_version != CONFIG_SCHEMA_VERSION
            || !valid_host_id(&document.host_id)
            || document.bindings.is_empty()
            || document.bindings.len() > 32
        {
            return Err("invalid flow host configuration".to_string());
        }
        let allow_loopback_origin = matches!(env_bool(FLOW_LOOPBACK_ORIGIN_ENV), Ok(Some(true)));
        let paimos_origin = parse_origin(
            &document.paimos_origin,
            loopback_dev_mode,
            allow_loopback_origin,
        )
        .map_err(|_| "invalid flow host configuration".to_string())?;
        let paimos_public_url = match document.paimos_public_url.as_deref() {
            None => paimos_origin.clone(),
            Some(value) => parse_origin(value, loopback_dev_mode, allow_loopback_origin)
                .map_err(|_| "invalid flow host configuration".to_string())?,
        };
        if !document.api_key_file.is_absolute() {
            return Err("invalid flow host configuration".to_string());
        }
        let bindings = document
            .bindings
            .into_iter()
            .map(FlowBinding::from_document)
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
            paimos_public_url,
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

pub(crate) fn inject_flow_shell(
    html: String,
    mount: bool,
    selected_host: Option<&str>,
    flow: Option<&FlowHostService>,
) -> String {
    if !mount {
        return html;
    }
    let host_attr = selected_host
        .map(|host| format!(" data-flow-host-scope=\"{}\"", html_escape_attr(host)))
        .unwrap_or_default();
    let origin_attr = flow
        .map(|service| {
            format!(
                " data-flow-paimos-origin=\"{}\"",
                html_escape_attr(service.config.paimos_public_url.as_str())
            )
        })
        .unwrap_or_default();
    let wrapped = html.replace(
        "<main",
        &format!(
            "<inspr-flow-shell layout-mode=\"bounded\" content-padding=\"34px\" data-flow-host{host_attr}{origin_attr}><main"
        ),
    );
    let wrapped = wrapped.replace("</main>", "</main></inspr-flow-shell>");
    let bootstrap = r#"<script type="module" src="/assets/flow-host-bootstrap.mjs"></script>"#;
    if let Some(index) = wrapped.rfind("</body>") {
        let mut output = wrapped;
        output.insert_str(index, bootstrap);
        return output;
    }
    format!("{wrapped}{bootstrap}")
}

pub(crate) fn flow_bootstrap_asset() -> (&'static [u8], &'static str) {
    (
        include_bytes!("../assets/flow-host-bootstrap.mjs"),
        "text/javascript",
    )
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
    context: &ResolvedContext,
    identity: &Value,
    hosts: &[Host],
    selected_host: Option<&str>,
    now: i64,
) -> Value {
    let mut shell = upstream.clone();
    if let Some(object) = shell.as_object_mut() {
        object.remove("identityContext");
    }
    let project_name = context.binding.label.clone();
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
        header.insert(
            "userLabel".into(),
            Value::String(context.user.display_name.clone()),
        );
        if let Some(display) = identity.get("display").and_then(Value::as_object) {
            if let Some(initials) = display.get("user_initials").and_then(Value::as_str) {
                header.insert("userInitials".into(), Value::String(initials.to_string()));
            }
        }
    }
    if let Some(health) = shell.get_mut("health").and_then(Value::as_object_mut) {
        if let Some(host_name) = selected_host {
            if let Some(host) = hosts.iter().find(|host| host.name == host_name) {
                let (health_status, health_label) = local_health_status(host, now);
                health.insert("status".into(), Value::String(health_status));
                health.insert("label".into(), Value::String(health_label));
                health.insert(
                    "checkedLabel".into(),
                    Value::String("Local Pharos lifecycle observation".into()),
                );
            }
        }
    }
    if let Some(object) = shell.as_object_mut() {
        object.insert("identityContext".into(), identity.clone());
    }
    shell
}

fn local_health_status(host: &Host, now: i64) -> (String, String) {
    let label = format!("Pharos host {}", host.name);
    let status = match liveness(host.last_seen, host.heartbeat_interval_secs, now) {
        Liveness::Live => "available",
        Liveness::Stale | Liveness::Down => "degraded",
        Liveness::AwaitingFirstHeartbeat => "unknown",
    };
    (status.to_string(), label)
}

fn issue_identity(
    config: &FlowHostConfig,
    context: &ResolvedContext,
    context_revision: &str,
    _projection: &CachedProjection,
    now: i64,
) -> Value {
    let issued = iso_timestamp(now);
    let expires = iso_timestamp(now + CONTEXT_TTL_SECS);
    let fresh_until = iso_timestamp(next_ten_minute_boundary(now));
    let principal_ref = pharos_opaque_ref(&config.host_id, "prin", &[&context.user.operator_ref]);
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
        "context_revision": context_revision,
        "authority_disclaimer": AUTHORITY_DISCLAIMER,
        "display": {
            "user_label": HOST_VERIFIED_HUMAN_LABEL,
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
        Err(FlowError::Unavailable(
            "configured project binding mismatch",
        ))
    }
}

fn human_session(auth: &AuthState, headers: &HeaderMap) -> bool {
    auth.human_user(headers).is_some()
}

fn human_user(auth: &AuthState, headers: &HeaderMap) -> Option<AuthUser> {
    auth.human_user(headers)
}

fn requires_submitted_identity(intent_type: &str) -> bool {
    intent_type == "flow:start-intent"
}

fn submitted_identity(request: &FlowIntentRequest) -> Option<Value> {
    request.identity.clone().or_else(|| {
        request.detail.as_ref().and_then(|detail| {
            detail.get("identity").cloned().or_else(|| {
                detail
                    .get("detail")
                    .and_then(|nested| nested.get("identity"))
                    .cloned()
            })
        })
    })
}

fn confirmed_start_action(request: &FlowIntentRequest) -> Option<&str> {
    request.detail.as_ref().and_then(|detail| {
        detail
            .get("detail")
            .and_then(|nested| nested.get("action"))
            .or_else(|| detail.get("action"))
            .and_then(Value::as_str)
    })
}

fn context_revision_for(
    config: &FlowHostConfig,
    context: &ResolvedContext,
    access: &AccessGrant,
    source_revision: &str,
) -> String {
    pharos_opaque_ref(
        &config.host_id,
        "ctxrev",
        &[
            &config.config_digest,
            &context.user.operator_ref,
            &context.user.managed_human_session_ref,
            &access.revision_material(),
            &context.binding.project_id.to_string(),
            &context.binding.expected_project_ref,
            source_revision,
        ],
    )
}

fn paimos_opaque_ref(kind: &str, parts: &[String]) -> String {
    opaque_ref(PAIMOS_HOST_ID, kind, parts)
}

fn pharos_opaque_ref(host_id: &str, kind: &str, parts: &[&str]) -> String {
    opaque_ref(
        host_id,
        kind,
        &parts
            .iter()
            .map(|part| part.to_string())
            .collect::<Vec<_>>(),
    )
}

fn opaque_ref(host_id: &str, kind: &str, parts: &[String]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(format!("{host_id}:{kind}:").as_bytes());
    for part in parts {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    format!("{host_id}:{kind}-{}", hex_bytes(&digest[..16]))
}

fn start_permitted(shell_state: &Value, action: &str, now: i64) -> bool {
    let delivery = shell_state.get("delivery").and_then(Value::as_object);
    let status = delivery
        .and_then(|value| value.get("status"))
        .and_then(Value::as_str)
        .unwrap_or("draft");
    if status != "draft" && status != "authorized" {
        return false;
    }
    if delivery
        .and_then(|value| value.get("batchRef").or_else(|| value.get("batch_ref")))
        .is_none()
    {
        return false;
    }
    if delivery
        .and_then(|value| {
            value
                .get("baselineRef")
                .or_else(|| value.get("baseline_ref"))
        })
        .is_none()
    {
        return false;
    }
    if delivery
        .and_then(|value| {
            value
                .get("baselineDigest")
                .or_else(|| value.get("baseline_digest"))
        })
        .is_none()
    {
        return false;
    }
    if !matches!(
        action,
        "build" | "deploy" | "verify" | "janus_prepare" | "janus_apply"
    ) {
        return false;
    }
    if !evaluation_usable(
        shell_state
            .get("evaluatedAt")
            .or_else(|| shell_state.get("evaluated_at"))
            .and_then(Value::as_str),
        now,
    ) {
        return false;
    }
    let prerequisites = shell_state.get("prerequisites").and_then(Value::as_object);
    let requirements = prerequisites
        .and_then(|value| value.get("requirementsBaseline"))
        .or_else(|| prerequisites.and_then(|value| value.get("requirements_baseline")));
    if !required_gate_pass(requirements, now) {
        return false;
    }
    let pharos = prerequisites
        .and_then(|value| value.get("pharosTarget"))
        .or_else(|| prerequisites.and_then(|value| value.get("pharos_target")));
    if matches!(action, "deploy" | "verify") {
        let artifact = prerequisites
            .and_then(|value| value.get("deployArtifact"))
            .or_else(|| prerequisites.and_then(|value| value.get("deploy_artifact")));
        if !required_gate_pass(artifact, now) {
            return false;
        }
        if !required_target_pass(pharos, &["ready", "live"], now) {
            return false;
        }
    } else if action == "janus_prepare" {
        if !required_target_pass(pharos, &["preliminary", "ready", "live"], now) {
            return false;
        }
    } else if action == "janus_apply" {
        if !required_target_pass(pharos, &["ready", "live"], now) {
            return false;
        }
        let janus = prerequisites
            .and_then(|value| value.get("janusGate"))
            .or_else(|| prerequisites.and_then(|value| value.get("janus_gate")));
        if !required_gate_pass(janus, now) {
            return false;
        }
    }
    true
}

fn evaluation_usable(evaluated_at: Option<&str>, now: i64) -> bool {
    let Some(evaluated_at) = evaluated_at else {
        return false;
    };
    let Some(evaluated) = parse_rfc3339(Some(&Value::String(evaluated_at.to_string()))) else {
        return false;
    };
    if evaluated > now + 5 {
        return false;
    }
    now - evaluated <= EVALUATION_MAX_AGE_SECS
}

fn required_gate_pass(entry: Option<&Value>, now: i64) -> bool {
    let Some(entry) = entry.and_then(Value::as_object) else {
        return false;
    };
    if entry.get("status").and_then(Value::as_str) != Some("pass") {
        return false;
    }
    if entry
        .get("evidenceRef")
        .or_else(|| entry.get("evidence_ref"))
        .is_none()
    {
        return false;
    }
    if entry
        .get("observedAt")
        .or_else(|| entry.get("observed_at"))
        .is_none()
    {
        return false;
    }
    !gate_stale(entry, now)
}

fn required_target_pass(entry: Option<&Value>, allowed: &[&str], now: i64) -> bool {
    if !required_gate_pass(entry, now) {
        return false;
    }
    entry
        .and_then(Value::as_object)
        .and_then(|value| value.get("readiness"))
        .and_then(Value::as_str)
        .is_some_and(|readiness| allowed.contains(&readiness))
}

fn gate_stale(entry: &serde_json::Map<String, Value>, now: i64) -> bool {
    let fresh_until = entry
        .get("freshUntil")
        .or_else(|| entry.get("fresh_until"))
        .and_then(Value::as_str);
    match fresh_until {
        None => false,
        Some(value) => {
            parse_rfc3339(Some(&Value::String(value.to_string()))).is_none_or(|fresh| now > fresh)
        }
    }
}

fn html_escape_attr(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

async fn bounded_response_bytes(response: reqwest::Response) -> Result<Vec<u8>, FlowError> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_RESPONSE_BYTES as u64)
    {
        return Err(FlowError::Unavailable("projection response too large"));
    }
    let mut body = Vec::new();
    let mut stream = response;
    while let Some(chunk) = stream.chunk().await.map_err(|_| FlowError::Transport)? {
        if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BYTES {
            return Err(FlowError::Unavailable("projection response too large"));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

pub(crate) fn resolve_flow_host_scope(
    host: Option<&str>,
    access: &AccessGrant,
    hosts: &[Host],
) -> Result<Option<String>, String> {
    match host.map(str::trim).filter(|value| !value.is_empty()) {
        None => Ok(None),
        Some(host) => {
            if !access.allows_host(host) {
                return Err("access denied for requested host scope".to_string());
            }
            if !hosts.iter().any(|entry| entry.name == host) {
                return Err("requested host is not in current fleet".to_string());
            }
            Ok(Some(host.to_string()))
        }
    }
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

fn parse_origin(
    value: &str,
    loopback_dev_mode: bool,
    allow_loopback_origin: bool,
) -> Result<Url, FlowError> {
    let mut url = Url::parse(value).map_err(|_| FlowError::Configuration)?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(FlowError::Configuration);
    }
    let base = url_public_base(&url)?;
    url.set_path(base.home());
    match url.scheme() {
        "https" => Ok(url),
        "http" if loopback_dev_mode && allow_loopback_origin && is_loopback_url(&url) => Ok(url),
        _ => Err(FlowError::Configuration),
    }
}

fn url_public_base(url: &Url) -> Result<PublicBasePath, FlowError> {
    let path = url.path();
    if path.is_empty() || path == "/" {
        Ok(PublicBasePath::root())
    } else {
        PublicBasePath::parse(path.trim_end_matches('/')).map_err(|_| FlowError::Configuration)
    }
}

fn join_origin_path(base: &Url, endpoint: &str) -> Result<Url, FlowError> {
    let path = url_public_base(base)?
        .join(endpoint)
        .map_err(|_| FlowError::Configuration)?;
    let mut url = base.clone();
    url.set_path(&path);
    url.set_query(None);
    url.set_fragment(None);
    Ok(url)
}

fn is_loopback_url(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Domain(domain)) => domain == "localhost",
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        None => false,
    }
}

fn env_bool(name: &str) -> Result<Option<bool>, ()> {
    match std::env::var(name) {
        Ok(value) => {
            let value = value.trim();
            if value == "1" || value.eq_ignore_ascii_case("true") {
                Ok(Some(true))
            } else if value == "0" || value.eq_ignore_ascii_case("false") {
                Ok(Some(false))
            } else {
                Err(())
            }
        }
        Err(_) => Ok(None),
    }
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
    read_bounded_private_file(path, MAX_CONFIG_BYTES)
        .map_err(|_| "invalid flow host configuration".to_string())
}

fn read_api_key(path: &Path) -> Result<String, FlowError> {
    let mut bytes =
        read_bounded_private_file(path, MAX_API_KEY_BYTES).map_err(|_| FlowError::Credential)?;
    if bytes.len() < 32 || bytes.len() as u64 > MAX_API_KEY_BYTES {
        bytes.fill(0);
        return Err(FlowError::Credential);
    }
    if !bytes.iter().all(|byte| (0x21..=0x7e).contains(byte)) {
        bytes.fill(0);
        return Err(FlowError::Credential);
    }
    String::from_utf8(bytes).map_err(|err| {
        err.into_bytes().fill(0);
        FlowError::Credential
    })
}

fn read_bounded_private_file(path: &Path, max_bytes: u64) -> Result<Vec<u8>, FlowError> {
    if let Some(parent) = path.parent() {
        validate_parent_directory(parent)?;
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| FlowError::Credential)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(FlowError::Credential);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.nlink() != 1 {
            return Err(FlowError::Credential);
        }
    }
    validate_private_file_metadata(&metadata, max_bytes)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(path).map_err(|_| FlowError::Credential)?;
    let opened_metadata = file.metadata().map_err(|_| FlowError::Credential)?;
    validate_private_file_metadata(&opened_metadata, max_bytes)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.dev() != opened_metadata.dev() || metadata.ino() != opened_metadata.ino() {
            return Err(FlowError::Credential);
        }
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| FlowError::Credential)?;
    if bytes.len() as u64 > max_bytes {
        return Err(FlowError::Credential);
    }
    Ok(bytes)
}

#[cfg(unix)]
fn validate_parent_directory(parent: &Path) -> Result<(), FlowError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = fs::metadata(parent).map_err(|_| FlowError::Credential)?;
    if !metadata.is_dir() {
        return Err(FlowError::Credential);
    }
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid || metadata.mode() & 0o077 != 0 {
        return Err(FlowError::Credential);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_parent_directory(_parent: &Path) -> Result<(), FlowError> {
    Ok(())
}

#[cfg(unix)]
fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    max_bytes: u64,
) -> Result<(), FlowError> {
    use std::os::unix::fs::MetadataExt;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(FlowError::Credential);
    }
    let expected_uid = unsafe { libc::geteuid() };
    if metadata.uid() != expected_uid || metadata.mode() & 0o077 != 0 {
        return Err(FlowError::Credential);
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_private_file_metadata(
    metadata: &fs::Metadata,
    max_bytes: u64,
) -> Result<(), FlowError> {
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > max_bytes {
        return Err(FlowError::Credential);
    }
    Ok(())
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
    use axum::http::{header, StatusCode};
    use axum::routing::get;
    use axum::Router;
    use pharos_core::{Host, NixFreshness};
    use serde_json::json;
    use std::sync::Arc;
    use tokio::net::TcpListener;

    fn write_private_key(path: &Path, content: &[u8]) {
        #[cfg(unix)]
        {
            use std::io::Write;
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(path)
                .expect("private key file");
            file.write_all(content).expect("private key bytes");
        }
        #[cfg(not(unix))]
        {
            std::fs::write(path, content).expect("private key bytes");
        }
    }

    fn sample_config(origin: &Url, api_key_file: PathBuf) -> FlowHostConfig {
        FlowHostConfig {
            enabled: true,
            host_id: "pharos-test".to_string(),
            paimos_origin: origin.clone(),
            paimos_public_url: origin.clone(),
            api_key_file,
            instance_label: "Pharos test".to_string(),
            bindings: vec![FlowBinding {
                project_id: 17,
                expected_project_ref: PAIMOS_PROJECT_REF_17.to_string(),
                label: "Test project".to_string(),
                hosts: vec!["hsb8".to_string()],
                operator_refs: HashSet::from(["operator-a".to_string()]),
            }],
            config_digest: "sha256:test".to_string(),
        }
    }

    fn private_fixture_dir(label: &str) -> (PathBuf, PathBuf) {
        let parent = std::env::temp_dir().join(format!(
            "pharos-flow-fixture-{}-{}",
            label,
            std::process::id()
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let _ = std::fs::remove_dir_all(&parent);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&parent)
                .expect("fixture parent");
        }
        #[cfg(not(unix))]
        {
            let _ = std::fs::remove_dir_all(&parent);
            std::fs::create_dir_all(&parent).expect("fixture parent");
        }
        let key = parent.join("api.key");
        write_private_key(&key, b"01234567890123456789012345678901");
        (parent, key)
    }

    fn cleanup_fixture_dir(parent: &Path) {
        let _ = std::fs::remove_file(parent.join("api.key"));
        let _ = std::fs::remove_dir(parent);
    }

    fn sample_gate(now: i64) -> Value {
        json!({
            "status": "pass",
            "gateKind": "requirements_baseline",
            "evidenceRef": "paimos:ev-test",
            "observedAt": iso_timestamp(now),
            "freshUntil": iso_timestamp(now + 600)
        })
    }

    fn sample_state() -> Value {
        let now = 1_700_000_000_i64;
        json!({
            "evaluatedAt": iso_timestamp(now),
            "header": {"appName": "Paimos", "projectName": "Upstream", "userLabel": "Machine", "userInitials": "MC"},
            "health": {"status": "available"},
            "delivery": {
                "status": "draft",
                "batchRef": "batch-test",
                "baselineRef": "baseline-test",
                "baselineDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "prerequisites": {
                "requirementsBaseline": sample_gate(now)
            },
            "progress": {},
            "executionModes": ["manual"],
            "selectedExecutionMode": "manual",
            "selectedAction": "build",
            "identityContext": {
                "project_ref": PAIMOS_PROJECT_REF_17
            }
        })
    }

    fn sample_host(name: &str, last_seen: i64) -> Host {
        Host {
            name: name.to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: None,
            last_seen: Some(last_seen),
            heartbeat_log: vec![last_seen],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness::default(),
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
            deployed_artifact: None,
        }
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
    fn paimos_opaque_ref_matches_literal_fixture() {
        assert_eq!(
            paimos_opaque_ref("proj", &["17".to_string()]),
            PAIMOS_PROJECT_REF_17
        );
        assert_eq!(
            paimos_opaque_ref("proj", &["99".to_string()]),
            PAIMOS_PROJECT_REF_99
        );
    }

    #[test]
    fn wire_response_uses_camel_case_and_embedded_identity() {
        let shell_state = json!({
            "evaluatedAt": "2023-11-14T22:13:20.000Z",
            "identityContext": {"project_ref": "pharos:proj-test"},
            "header": {"userLabel": "Operator"}
        });
        let response = FlowShellResponse {
            enabled: true,
            mount_shell: true,
            unavailable_reason: None,
            shell_state: Some(shell_state),
            projection_meta: None,
        };
        let wire = serde_json::to_value(response).expect("wire json");
        assert!(wire.get("shellState").is_some());
        assert!(wire.get("shell_state").is_none());
        assert!(wire.get("identityContext").is_none());
        assert_eq!(wire["mountShell"], true);
    }

    #[test]
    fn bootstrap_is_external_module_with_host_scope() {
        let html = inject_flow_shell(
            "<body><main></main></body>".to_string(),
            true,
            Some("hsb8"),
            None,
        );
        assert!(html.contains("data-flow-host-scope=\"hsb8\""));
        assert!(html.contains("/assets/flow-host-bootstrap.mjs"));
    }

    #[test]
    fn vendor_manifest_matches_embedded_assets() {
        let manifest = include_str!("../assets/vendor/flow-shell/manifest.json");
        let parsed: Value = serde_json::from_str(manifest).expect("manifest json");
        assert_eq!(parsed["version"], "0.1.3");
        let vendor_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/vendor/flow-shell");
        for entry in parsed["files"].as_array().expect("files") {
            let path = entry["path"].as_str().expect("path");
            let expected = entry["sha256"].as_str().expect("sha256");
            let bytes = std::fs::read(vendor_root.join(path)).expect("vendor file");
            let digest = format!("sha256:{}", hex_bytes(&Sha256::digest(bytes)));
            assert_eq!(digest, expected, "digest mismatch for {path}");
        }
    }

    #[test]
    fn submitted_identity_reads_nested_start_detail() {
        let nested = json!({
            "status": "present",
            "principal_ref": "pharos-test:prin-abc",
            "project_ref": "pharos-test:proj-17"
        });
        let request = FlowIntentRequest {
            intent_type: "flow:start-intent".to_string(),
            identity: None,
            detail: Some(json!({
                "type": "flow:start-intent",
                "detail": { "identity": nested }
            })),
        };
        let extracted = submitted_identity(&request).expect("nested identity");
        assert_eq!(extracted["principal_ref"], "pharos-test:prin-abc");
    }

    #[test]
    fn wire_intent_request_deserializes_bootstrap_body() {
        let body = json!({
            "type": "flow:review-batch",
            "identity": null,
            "detail": {
                "type": "flow:review-batch",
                "detail": { "batchRef": "batch-test", "executes": false }
            }
        });
        let request: FlowIntentRequest = serde_json::from_value(body).expect("bootstrap body");
        assert_eq!(request.intent_type, "flow:review-batch");
        assert!(submitted_identity(&request).is_none());
    }

    #[tokio::test]
    async fn configured_projection_and_intent_navigation() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let (fixture_dir, key_path) = private_fixture_dir("projection");
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
        let hosts = [sample_host("hsb8", 1_700_000_000)];
        let response = service
            .shell_state(
                &auth,
                &headers,
                &access,
                &hosts,
                Some("hsb8"),
                1_700_000_000,
            )
            .await;
        let wire = serde_json::to_value(&response).expect("wire json");
        let shell_state = response.shell_state.expect("shell state");
        assert!(wire.get("shellState").is_some());
        let identity = shell_state
            .get("identityContext")
            .expect("embedded identity");
        assert_eq!(identity["principal_kind"], "local_host");
        assert_eq!(identity["display"]["user_label"], HOST_VERIFIED_HUMAN_LABEL);
        assert_eq!(shell_state["header"]["userLabel"], "Operator");
        assert_eq!(shell_state["health"]["status"], "available");
        let (status, intent) = service
            .handle_intent(
                &auth,
                &headers,
                &access,
                &hosts,
                Some("hsb8"),
                FlowIntentRequest {
                    intent_type: "flow:review-batch".to_string(),
                    identity: None,
                    detail: Some(json!({
                        "type": "flow:review-batch",
                        "detail": {
                            "batchRef": "batch-test",
                            "executes": false
                        }
                    })),
                },
                1_700_000_000,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "intent error: {:?}", intent.error);
        assert!(!intent.executed);
        assert!(intent
            .location
            .unwrap()
            .contains("/projects/17?tab=overview#baseline-batch"));
        server.abort();
        cleanup_fixture_dir(&fixture_dir);
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
        state["identityContext"]["project_ref"] = json!(PAIMOS_PROJECT_REF_99);
        let (origin, server) = serve_paimos(state).await;
        let (fixture_dir, key_path) = private_fixture_dir("wrong-ref");
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
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn rejects_unauthorized_operator_binding() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let (fixture_dir, key_path) = private_fixture_dir("operator");
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
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn rejects_expired_identity_on_intent() {
        let (origin, server) = serve_paimos(sample_state()).await;
        let (fixture_dir, key_path) = private_fixture_dir("expired");
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
        let identity = response
            .shell_state
            .and_then(|shell| shell.get("identityContext").cloned())
            .expect("embedded identity");
        let (status, intent) = service
            .handle_intent(
                &auth,
                &headers,
                &access,
                &[],
                Some("hsb8"),
                FlowIntentRequest {
                    intent_type: "flow:start-intent".to_string(),
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
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
        assert!(!intent.executed);
        assert!(intent.error.unwrap().contains("expired"));
        server.abort();
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn blocks_start_when_requirements_gate_is_missing() {
        let mut state = sample_state();
        state["prerequisites"] = json!({});
        let (origin, server) = serve_paimos(state).await;
        let (fixture_dir, key_path) = private_fixture_dir("start-blocked");
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
            .shell_state(&auth, &headers, &access, &[], Some("hsb8"), 1_700_000_000)
            .await;
        let identity = response
            .shell_state
            .and_then(|shell| shell.get("identityContext").cloned())
            .expect("embedded identity");
        let (status, intent) = service
            .handle_intent(
                &auth,
                &headers,
                &access,
                &[],
                Some("hsb8"),
                FlowIntentRequest {
                    intent_type: "flow:start-intent".to_string(),
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
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        assert!(!intent.executed);
        assert!(intent.location.is_none());
        assert!(intent.notice.unwrap().contains("Start stays blocked"));
        server.abort();
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn start_intent_identity_survives_time_forward() {
        let shell_now = 1_700_000_000_i64;
        let intent_now = shell_now + 60;
        let (origin, server) = serve_paimos(sample_state()).await;
        let (fixture_dir, key_path) = private_fixture_dir("time-forward");
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
        let hosts = [sample_host("hsb8", shell_now)];
        let response = service
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), shell_now)
            .await;
        let identity = response
            .shell_state
            .and_then(|shell| shell.get("identityContext").cloned())
            .expect("embedded identity");
        let (status, intent) = service
            .handle_intent(
                &auth,
                &headers,
                &access,
                &hosts,
                Some("hsb8"),
                FlowIntentRequest {
                    intent_type: "flow:start-intent".to_string(),
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
                intent_now,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "intent error: {:?}", intent.error);
        assert!(
            intent.error.is_none(),
            "identity must remain valid after time forward: {:?}",
            intent.error
        );
        assert!(!intent.executed);
        server.abort();
        cleanup_fixture_dir(&fixture_dir);
    }

    #[test]
    fn rejects_api_key_in_world_writable_parent() {
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            let parent = std::env::temp_dir().join(format!(
                "pharos-flow-writable-parent-{}",
                std::process::id()
            ));
            let _ = std::fs::remove_dir_all(&parent);
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o1777)
                .create(&parent)
                .expect("writable parent");
            let key_path = parent.join("api.key");
            write_private_key(&key_path, b"01234567890123456789012345678901");
            assert!(read_api_key(&key_path).is_err());
            let _ = std::fs::remove_file(&key_path);
            let _ = std::fs::remove_dir(&parent);
        }
    }

    #[test]
    fn loopback_paimos_origin_requires_listener_and_flag() {
        assert!(parse_origin("https://paimos.example", false, false).is_ok());
        assert!(parse_origin("https://apps.example/paimos", false, false).is_ok());
        assert_eq!(
            parse_origin("https://apps.example/paimos/", false, false)
                .expect("trailing slash is canonicalized")
                .as_str(),
            "https://apps.example/paimos"
        );
        assert!(parse_origin("http://127.0.0.1:9", true, true).is_ok());
        assert!(parse_origin("http://127.0.0.1:9", true, false).is_err());
        assert!(parse_origin("http://127.0.0.1:9", false, false).is_err());
        assert!(parse_origin("http://evil.example", true, true).is_err());
    }

    #[test]
    fn select_binding_requires_host_scope_when_multiple_bindings_match() {
        let service = FlowHostService {
            config: FlowHostConfig {
                enabled: true,
                host_id: "pharos-test".to_string(),
                paimos_origin: Url::parse("https://paimos.example").expect("origin"),
                paimos_public_url: Url::parse("https://paimos.example").expect("origin"),
                api_key_file: PathBuf::from("/tmp/pharos-flow-test.key"),
                instance_label: "Pharos test".to_string(),
                bindings: vec![
                    FlowBinding {
                        project_id: 17,
                        expected_project_ref: PAIMOS_PROJECT_REF_17.to_string(),
                        label: "Project A".to_string(),
                        hosts: vec!["host-a".to_string()],
                        operator_refs: HashSet::from(["operator-a".to_string()]),
                    },
                    FlowBinding {
                        project_id: 18,
                        expected_project_ref: PAIMOS_PROJECT_REF_99.to_string(),
                        label: "Project B".to_string(),
                        hosts: vec!["host-b".to_string()],
                        operator_refs: HashSet::from(["operator-a".to_string()]),
                    },
                ],
                config_digest: "sha256:test".to_string(),
            },
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .expect("client"),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        };
        let user = AuthUser {
            operator_ref: "operator-a".to_string(),
            managed_human_session_ref: "sess".to_string(),
            display_name: "Operator".to_string(),
        };
        let access = AccessGrant::limited(["host-a", "host-b"], true);
        let err = service
            .select_binding(&user, &access, None)
            .expect_err("ambiguous binding");
        assert_eq!(
            err,
            "Multiple configured Flow bindings match; host scope is required."
        );
        let binding = service
            .select_binding(&user, &access, Some("host-a"))
            .expect("host-a binding");
        assert_eq!(binding.project_id, 17);
        let err = service
            .select_binding(&user, &access, Some("host-unknown"))
            .expect_err("unknown host");
        assert_eq!(
            err,
            "No configured Flow binding matches this operator and host scope."
        );
    }

    #[test]
    fn start_permitted_uses_confirmed_action_from_detail() {
        let now = 1_700_000_000_i64;
        let shell = json!({
            "evaluatedAt": iso_timestamp(now),
            "delivery": {
                "status": "draft",
                "batchRef": "batch-test",
                "baselineRef": "baseline-test",
                "baselineDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "prerequisites": {
                "requirementsBaseline": sample_gate(now),
                "deployArtifact": sample_gate(now),
                "pharosTarget": {
                    "status": "pass",
                    "evidenceRef": "paimos:ev-target",
                    "observedAt": iso_timestamp(now),
                    "freshUntil": iso_timestamp(now + 600),
                    "readiness": "ready"
                }
            }
        });
        let minimal = json!({
            "evaluatedAt": iso_timestamp(now),
            "delivery": shell["delivery"].clone(),
            "prerequisites": {
                "requirementsBaseline": sample_gate(now)
            }
        });
        assert!(start_permitted(&minimal, "build", now));
        assert!(!start_permitted(&minimal, "deploy", now));
        assert!(start_permitted(&shell, "deploy", now));
    }

    #[test]
    fn janus_apply_requires_janus_gate() {
        let now = 1_700_000_000_i64;
        let shell = json!({
            "evaluatedAt": iso_timestamp(now),
            "delivery": {
                "status": "draft",
                "batchRef": "batch-test",
                "baselineRef": "baseline-test",
                "baselineDigest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            },
            "prerequisites": {
                "requirementsBaseline": sample_gate(now),
                "pharosTarget": {
                    "status": "pass",
                    "evidenceRef": "paimos:ev-target",
                    "observedAt": iso_timestamp(now),
                    "freshUntil": iso_timestamp(now + 600),
                    "readiness": "live"
                }
            }
        });
        assert!(!start_permitted(&shell, "janus_apply", now));
        let gated = json!({
            "evaluatedAt": iso_timestamp(now),
            "delivery": shell["delivery"].clone(),
            "prerequisites": {
                "requirementsBaseline": sample_gate(now),
                "pharosTarget": shell["prerequisites"]["pharosTarget"].clone(),
                "janusGate": sample_gate(now)
            }
        });
        assert!(start_permitted(&gated, "janus_apply", now));
    }

    #[test]
    fn resolve_flow_host_scope_rejects_unauthorized_host() {
        let access = AccessGrant::limited(["other"], true);
        let err = resolve_flow_host_scope(Some("hsb8"), &access, &[]).unwrap_err();
        assert!(err.contains("access denied"));
    }
}
