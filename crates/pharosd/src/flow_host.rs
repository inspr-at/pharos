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
/// PHAROS-313: schema v2 selects the Aeon upstream (journey read, `/p/{key}`
/// links). v1 stays the classic Paimos contract; the two never mix.
const CONFIG_SCHEMA_V2: &str = "inspr.pharos.flow-host-config.v2";
const CONFIG_SCHEMA_VERSION_V2: u16 = 2;
const AEON_UPSTREAM: &str = "aeon";
const AEON_HOST_ID: &str = "aeon";
const AEON_REVIEW_QUERY: &str = "view=journey";
const AEON_STAGES: [&str; 8] = [
    "inspire",
    "shape",
    "requirements",
    "plan",
    "build",
    "deploy",
    "access",
    "live",
];
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

#[derive(Clone, Debug, Deserialize)]
struct ConfigVersionProbe {
    schema: String,
    schema_version: u16,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FlowConfigDocumentV2 {
    schema: String,
    schema_version: u16,
    enabled: bool,
    host_id: String,
    upstream: String,
    aeon_origin: String,
    #[serde(default)]
    aeon_public_url: Option<String>,
    api_key_file: PathBuf,
    instance_label: Option<String>,
    tenant_slug: String,
    bindings: Vec<AeonBindingDocument>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AeonBindingDocument {
    project_node_id: String,
    project_key: String,
    label: String,
    hosts: Vec<String>,
    operator_refs: Vec<String>,
}

/// Which control plane a binding points at. The operator config is the only
/// authority for these values; an upstream response is checked against them,
/// never the other way round.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BindingTarget {
    Classic {
        project_id: u64,
        expected_project_ref: String,
    },
    Aeon {
        project_node_id: String,
        project_key: String,
    },
}

impl BindingTarget {
    /// Stable identity string mixed into opaque refs and revisions.
    fn identity(&self) -> String {
        match self {
            Self::Classic {
                expected_project_ref,
                ..
            } => expected_project_ref.clone(),
            Self::Aeon {
                project_node_id,
                project_key,
            } => format!("{AEON_HOST_ID}:proj:{project_node_id}:{project_key}"),
        }
    }

    /// The upstream project selector as configured.
    fn material(&self) -> String {
        match self {
            Self::Classic { project_id, .. } => project_id.to_string(),
            Self::Aeon {
                project_node_id, ..
            } => project_node_id.clone(),
        }
    }

    fn classic_project_id(&self) -> Option<u64> {
        match self {
            Self::Classic { project_id, .. } => Some(*project_id),
            Self::Aeon { .. } => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct FlowBinding {
    pub(crate) target: BindingTarget,
    pub(crate) label: String,
    pub(crate) hosts: Vec<String>,
    pub(crate) operator_refs: HashSet<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum FlowUpstream {
    Classic,
    Aeon { tenant_slug: String },
}

#[derive(Clone, Debug)]
pub(crate) struct FlowHostConfig {
    pub(crate) enabled: bool,
    pub(crate) host_id: String,
    pub(crate) upstream: FlowUpstream,
    pub(crate) upstream_origin: Url,
    pub(crate) upstream_public_url: Url,
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
    project: String,
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
    /// Aeon journey revision (0 for classic). A later fetch that reports a
    /// lower revision is refused as a stale stage.
    upstream_revision: u64,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    project_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    project_key: Option<String>,
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
        // Every routed intent carries the mounted projection so the review
        // link can retain the stage Aeon returned and the allow-list can pin it.
        let projection = if matches!(
            intent_type,
            "flow:start-intent"
                | "flow:review-batch"
                | "flow:view-drafts"
                | "flow:save-proposal"
                | "flow:header-project"
        ) {
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
        let projected_stage = projection
            .as_ref()
            .and_then(|entry| entry.shell_state.get("progress"))
            .and_then(|progress| progress.get("stage"))
            .and_then(Value::as_str)
            .map(str::to_string);
        let review_url = self.review_url(&context.binding, projected_stage.as_deref());
        let (review_route, overview_route, upstream_name) = match self.config.upstream {
            FlowUpstream::Classic => (
                "paimos-project-overview-baseline",
                "paimos-project-overview",
                "Paimos",
            ),
            FlowUpstream::Aeon { .. } => ("aeon-project-journey", "aeon-project-journey", "Aeon"),
        };
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
                    routed: Some(review_route.to_string()),
                    location: self.valid_navigation_location(
                        &review_url,
                        &context.binding,
                        projected_stage.as_deref(),
                    ),
                    notice: Some(format!(
                        "Start stays on the configured {upstream_name} project controls. Pharos does not start delivery."
                    )),
                    ..Default::default()
                },
            ),
            "flow:review-batch" | "flow:view-drafts" | "flow:save-proposal" => (
                StatusCode::OK,
                FlowIntentResponse {
                    executed: false,
                    routed: Some(review_route.to_string()),
                    location: self.valid_navigation_location(
                        &review_url,
                        &context.binding,
                        projected_stage.as_deref(),
                    ),
                    notice: Some(format!(
                        "Review stays on the configured {upstream_name} project controls."
                    )),
                    ..Default::default()
                },
            ),
            "flow:header-project" => {
                let location = self.project_overview_url(&context.binding);
                (
                    StatusCode::OK,
                    FlowIntentResponse {
                        executed: false,
                        routed: Some(overview_route.to_string()),
                        location: self.valid_navigation_location(&location, &context.binding, None),
                        notice: Some(format!(
                            "Project navigation stays in configured {upstream_name}."
                        )),
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
                        project_id: context.binding.target.classic_project_id(),
                        project_node_id: match &context.binding.target {
                            BindingTarget::Aeon {
                                project_node_id, ..
                            } => Some(project_node_id.clone()),
                            BindingTarget::Classic { .. } => None,
                        },
                        project_key: match &context.binding.target {
                            BindingTarget::Aeon { project_key, .. } => Some(project_key.clone()),
                            BindingTarget::Classic { .. } => None,
                        },
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
                unavailable_reason: Some(format!(
                    "Configured {} projection is unavailable right now.",
                    self.upstream_name()
                )),
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
                &binding.target.material(),
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
        // The cache is keyed by the full binding identity (classic ref, or
        // Aeon project node plus key) and operator, so two bindings can never
        // share a validated journey.
        let key = CacheKey {
            project: context.binding.target.identity(),
            operator_ref: context.user.operator_ref.clone(),
            host: None,
        };
        if let Some(cached) = self.cache.lock().expect("flow cache").entries.get(&key) {
            if cached.fetched_at >= floor_ten_minute_boundary(now) {
                return Ok(cached.clone());
            }
        }
        let (fetched, upstream_revision) = match &self.config.upstream {
            FlowUpstream::Classic => (self.fetch_paimos_state(context).await?, 0),
            FlowUpstream::Aeon { tenant_slug } => {
                self.fetch_aeon_journey(context, tenant_slug, now).await?
            }
        };
        let evaluated_at = fetched
            .get("evaluatedAt")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| iso_timestamp(now));
        // Classic keeps its exact source-revision material; only Aeon mixes
        // the journey revision in.
        let mut revision_parts = vec![context.binding.target.identity(), evaluated_at.clone()];
        if matches!(self.config.upstream, FlowUpstream::Aeon { .. }) {
            revision_parts.push(upstream_revision.to_string());
        }
        let source_revision = pharos_opaque_ref(
            &self.config.host_id,
            "src",
            &revision_parts
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
        );
        let entry = CachedProjection {
            generation: FETCH_GENERATION.fetch_add(1, Ordering::Relaxed),
            fetched_at: now,
            source_revision,
            shell_state: fetched,
            paimos_evaluated_at: evaluated_at,
            upstream_revision,
        };
        // Compare against the entry that is current at insert time, not a
        // pre-fetch snapshot: a slower response carrying an older journey
        // can neither overwrite nor be served over a newer accepted one.
        let mut cache = self.cache.lock().expect("flow cache");
        if let Some(current) = cache.entries.get(&key) {
            if upstream_revision < current.upstream_revision {
                return Err(FlowError::Unavailable(
                    "Configured Aeon journey reported an older revision than the last accepted one.",
                ));
            }
        }
        cache.entries.insert(key, entry.clone());
        Ok(entry)
    }

    async fn fetch_paimos_state(&self, context: &ResolvedContext) -> Result<Value, FlowError> {
        let BindingTarget::Classic {
            project_id,
            expected_project_ref,
        } = &context.binding.target
        else {
            return Err(FlowError::Configuration);
        };
        let api_key = read_api_key(&self.config.api_key_file)?;
        let url = join_origin_path(
            &self.config.upstream_origin,
            &format!("/api/projects/{project_id}/baseline-batches/flow-state"),
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
        validate_paimos_project_ref(&payload, expected_project_ref)?;
        Ok(strip_paimos_identity(payload))
    }

    /// PHAROS-313: read the Aeon journey for the bound project and project it
    /// onto the Flow shell state. The response must name exactly the
    /// configured project node, project key and tenant; anything else is a
    /// binding mismatch, never a fallback.
    async fn fetch_aeon_journey(
        &self,
        context: &ResolvedContext,
        tenant_slug: &str,
        now: i64,
    ) -> Result<(Value, u64), FlowError> {
        let BindingTarget::Aeon {
            project_node_id,
            project_key,
        } = &context.binding.target
        else {
            return Err(FlowError::Configuration);
        };
        let api_key = read_api_key(&self.config.api_key_file)?;
        let url = join_origin_path(
            &self.config.upstream_origin,
            &format!("/api/projects/{project_node_id}/journey"),
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
        if status == HttpStatus::UNAUTHORIZED || status == HttpStatus::FORBIDDEN {
            return Err(FlowError::Unavailable(
                "Configured Aeon key cannot read this project journey.",
            ));
        }
        if status == HttpStatus::NOT_FOUND {
            return Err(FlowError::Unavailable(
                "Configured Aeon project journey is unavailable for this binding.",
            ));
        }
        if !status.is_success() {
            return Err(FlowError::Unavailable(
                "Configured Aeon journey refused the upstream request.",
            ));
        }
        let journey: Value = serde_json::from_slice(&bytes).map_err(|_| FlowError::Transport)?;
        validate_aeon_binding(&journey, project_node_id, project_key, tenant_slug)?;
        let revision = journey
            .get("revision")
            .and_then(Value::as_u64)
            .filter(|revision| *revision >= 1)
            .ok_or(FlowError::Unavailable(
                "Configured Aeon journey has no usable revision.",
            ))?;
        Ok((aeon_shell_state(&journey, &context.binding, now), revision))
    }

    fn upstream_name(&self) -> &'static str {
        match self.config.upstream {
            FlowUpstream::Classic => "Paimos",
            FlowUpstream::Aeon { .. } => "Aeon",
        }
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
                upstream_revision: 0,
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

    /// Review target for the bound project. Classic: the project overview
    /// baseline controls. Aeon: `/p/{project_key}?view=journey`, with the
    /// stage retained only when the Aeon journey returned one.
    fn review_url(&self, binding: &FlowBinding, stage: Option<&str>) -> String {
        match &binding.target {
            BindingTarget::Classic { project_id, .. } => {
                let mut url = join_origin_path(
                    &self.config.upstream_public_url,
                    &format!("/projects/{project_id}"),
                )
                .expect("review path is app-relative");
                url.set_query(Some("tab=overview"));
                url.set_fragment(Some(REVIEW_FRAGMENT.trim_start_matches('#')));
                url.to_string()
            }
            BindingTarget::Aeon { project_key, .. } => {
                let mut url = join_origin_path(
                    &self.config.upstream_public_url,
                    &format!("/p/{project_key}"),
                )
                .expect("journey path is app-relative");
                match stage.filter(|value| AEON_STAGES.contains(value)) {
                    Some(stage) => {
                        url.set_query(Some(&format!("{AEON_REVIEW_QUERY}&stage={stage}")))
                    }
                    None => url.set_query(Some(AEON_REVIEW_QUERY)),
                }
                url.to_string()
            }
        }
    }

    fn project_overview_url(&self, binding: &FlowBinding) -> String {
        match &binding.target {
            BindingTarget::Classic { project_id, .. } => {
                let mut url = join_origin_path(
                    &self.config.upstream_public_url,
                    &format!("/projects/{project_id}"),
                )
                .expect("overview path is app-relative");
                url.set_query(Some("tab=overview"));
                url.to_string()
            }
            BindingTarget::Aeon { .. } => self.review_url(binding, None),
        }
    }

    /// Exact allow-list for browser navigation: the configured public origin
    /// and, per upstream, exactly one route shape. Classic keeps
    /// `/projects/{id}?tab=overview`; Aeon allows only `/p/{project_key}` for a
    /// configured binding with `view=journey` and at most a known stage.
    fn valid_navigation_location(
        &self,
        location: &str,
        binding: &FlowBinding,
        projected_stage: Option<&str>,
    ) -> Option<String> {
        let parsed = Url::parse(location).ok()?;
        if parsed.origin() != self.config.upstream_public_url.origin() {
            return None;
        }
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return None;
        }
        let base = url_public_base(&self.config.upstream_public_url).ok()?;
        let local = base.strip(parsed.path())?;
        match self.config.upstream {
            FlowUpstream::Classic => {
                if !local.strip_prefix("/projects/").is_some_and(|tail| {
                    !tail.is_empty() && !tail.contains('/') && tail.parse::<u64>().is_ok()
                }) {
                    return None;
                }
                let query_ok = parsed
                    .query()
                    .is_some_and(|query| query.split('&').any(|part| part == "tab=overview"));
                if !query_ok {
                    return None;
                }
            }
            FlowUpstream::Aeon { .. } => {
                // Exactly the mounted binding's key, exactly one view=journey,
                // and at most one stage that equals what the validated journey
                // reported. Nothing else, no fragment.
                let key = local.strip_prefix("/p/")?;
                let BindingTarget::Aeon { project_key, .. } = &binding.target else {
                    return None;
                };
                if key != project_key || parsed.fragment().is_some() {
                    return None;
                }
                let query = parsed.query()?;
                let mut views = 0;
                let mut stages = 0;
                for part in query.split('&') {
                    if part == AEON_REVIEW_QUERY {
                        views += 1;
                    } else if let Some(stage) = part.strip_prefix("stage=") {
                        if !AEON_STAGES.contains(&stage) || projected_stage != Some(stage) {
                            return None;
                        }
                        stages += 1;
                    } else {
                        return None;
                    }
                }
                if views != 1 || stages > 1 {
                    return None;
                }
            }
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
        let probe: ConfigVersionProbe = serde_json::from_slice(&bytes)
            .map_err(|_| "invalid flow host configuration".to_string())?;
        if probe.schema == CONFIG_SCHEMA_V2 && probe.schema_version == CONFIG_SCHEMA_VERSION_V2 {
            return Self::load_aeon(&bytes, loopback_dev_mode);
        }
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
            upstream: FlowUpstream::Classic,
            upstream_origin: paimos_origin,
            upstream_public_url: paimos_public_url,
            api_key_file: document.api_key_file,
            instance_label,
            bindings,
            config_digest,
        })
    }

    /// Schema v2 (PHAROS-313): the Aeon upstream. Same file-permission and
    /// origin rules as v1; bindings carry the project node UUID and the route
    /// key instead of a numeric id and an opaque ref.
    fn load_aeon(bytes: &[u8], loopback_dev_mode: bool) -> Result<Self, String> {
        let document: FlowConfigDocumentV2 = serde_json::from_slice(bytes)
            .map_err(|_| "invalid flow host configuration".to_string())?;
        if document.schema != CONFIG_SCHEMA_V2
            || document.schema_version != CONFIG_SCHEMA_VERSION_V2
            || document.upstream != AEON_UPSTREAM
            || !valid_host_id(&document.host_id)
            || !valid_tenant_slug(&document.tenant_slug)
            || document.bindings.is_empty()
            || document.bindings.len() > 32
        {
            return Err("invalid flow host configuration".to_string());
        }
        let allow_loopback_origin = matches!(env_bool(FLOW_LOOPBACK_ORIGIN_ENV), Ok(Some(true)));
        let aeon_origin = parse_origin(
            &document.aeon_origin,
            loopback_dev_mode,
            allow_loopback_origin,
        )
        .map_err(|_| "invalid flow host configuration".to_string())?;
        let aeon_public_url = match document.aeon_public_url.as_deref() {
            None => aeon_origin.clone(),
            Some(value) => parse_origin(value, loopback_dev_mode, allow_loopback_origin)
                .map_err(|_| "invalid flow host configuration".to_string())?,
        };
        if !document.api_key_file.is_absolute() {
            return Err("invalid flow host configuration".to_string());
        }
        let bindings = document
            .bindings
            .into_iter()
            .map(FlowBinding::from_aeon_document)
            .collect::<Result<Vec<_>, _>>()?;
        // One binding per project: neither a route key nor a project node
        // may appear twice, so a projection can never be shared across bindings.
        for pick in [0usize, 1usize] {
            let mut values: Vec<&str> = bindings
                .iter()
                .filter_map(|binding| match &binding.target {
                    BindingTarget::Aeon {
                        project_node_id,
                        project_key,
                    } => Some(if pick == 0 {
                        project_key.as_str()
                    } else {
                        project_node_id.as_str()
                    }),
                    BindingTarget::Classic { .. } => None,
                })
                .collect();
            values.sort_unstable();
            values.dedup();
            if values.len() != bindings.len() {
                return Err("invalid flow host configuration".to_string());
            }
        }
        let config_digest = hex_digest(bytes);
        let host_id = document.host_id;
        let instance_label = document
            .instance_label
            .filter(|label| !label.trim().is_empty())
            .unwrap_or_else(|| host_id.clone());
        Ok(Self {
            enabled: document.enabled,
            host_id,
            upstream: FlowUpstream::Aeon {
                tenant_slug: document.tenant_slug,
            },
            upstream_origin: aeon_origin,
            upstream_public_url: aeon_public_url,
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
            target: BindingTarget::Classic {
                project_id: document.project_id,
                expected_project_ref: expected,
            },
            label: document.label.trim().to_string(),
            hosts,
            operator_refs,
        })
    }

    fn from_aeon_document(document: AeonBindingDocument) -> Result<Self, String> {
        let project_node_id = document.project_node_id.trim().to_ascii_lowercase();
        let project_key = document.project_key.trim().to_string();
        if !valid_uuid(&project_node_id)
            || !valid_project_key(&project_key)
            || document.label.trim().is_empty()
            || document.hosts.is_empty()
            || document.operator_refs.is_empty()
            || document.hosts.len() > 64
            || document.operator_refs.len() > 64
        {
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
            target: BindingTarget::Aeon {
                project_node_id,
                project_key,
            },
            label: document.label.trim().to_string(),
            hosts,
            operator_refs,
        })
    }
}

fn valid_uuid(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 36
        && bytes.iter().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => *byte == b'-',
            _ => byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase(),
        })
}

fn valid_project_key(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 32
        && bytes[0].is_ascii_uppercase()
        && bytes.iter().all(|byte| {
            byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_' || *byte == b'-'
        })
}

fn valid_tenant_slug(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 64
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}

/// The Aeon response must name exactly the configured project node, project
/// key and tenant. A missing field is a mismatch: an older Aeon that does not
/// echo the binding is not a fallback.
fn validate_aeon_binding(
    journey: &Value,
    project_node_id: &str,
    project_key: &str,
    tenant_slug: &str,
) -> Result<(), FlowError> {
    let field = |name: &str| journey.get(name).and_then(Value::as_str);
    if field("project_node_id")
        .map(str::to_ascii_lowercase)
        .as_deref()
        != Some(project_node_id)
        || field("project_key") != Some(project_key)
    {
        return Err(FlowError::Unavailable(
            "configured project binding mismatch",
        ));
    }
    if field("tenant_slug") != Some(tenant_slug) {
        return Err(FlowError::Unavailable("configured tenant binding mismatch"));
    }
    Ok(())
}

/// Project the Aeon journey onto the Flow shell state the vendored shell
/// renders. Nothing here starts delivery: `delivery` only describes the stage,
/// `selectedAction` mirrors Aeon's next action, and the raw journey stays under
/// `progress` for the browser.
fn aeon_shell_state(journey: &Value, binding: &FlowBinding, now: i64) -> Value {
    let stage = journey.get("stage").and_then(Value::as_str).unwrap_or("");
    let stages = journey
        .get("stages")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let stage_state = |key: &str| {
        stages
            .iter()
            .find(|entry| entry.get("key").and_then(Value::as_str) == Some(key))
            .and_then(|entry| entry.get("state"))
            .and_then(Value::as_str)
            .unwrap_or("later")
            .to_string()
    };
    let requirements_done = stage_state("requirements") == "done";
    let can_admit = journey
        .get("launch_readiness")
        .and_then(|value| value.get("can_admit"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let next_action = journey.get("next_action").cloned().unwrap_or(Value::Null);
    let action_available = next_action
        .get("available")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    // The vendored shell only knows draft, authorized, in_progress, blocked and
    // completed, and a 0..3 stage rail (define, build, deliver, access).
    let delivery_status = match stage {
        "live" => "completed",
        "deploy" | "access" if action_available && can_admit => "authorized",
        "plan" | "build" | "deploy" | "access" if action_available => "draft",
        "plan" | "build" | "deploy" | "access" => "blocked",
        _ => "blocked",
    };
    // Same folding as the Janus shell: inspire/shape/requirements form the
    // define stage, plan/build the build stage, deploy delivers, access is last.
    let active_stage = match stage {
        "plan" | "build" => 1,
        "deploy" => 2,
        "access" | "live" => 3,
        _ => 0,
    };
    let folded = [
        &["inspire", "shape", "requirements"][..],
        &["plan", "build"][..],
        &["deploy"][..],
        &["access", "live"][..],
    ];
    let stage_evidence: Vec<&str> = folded
        .iter()
        .map(|keys| {
            let states: Vec<String> = keys.iter().map(|key| stage_state(key)).collect();
            if states.iter().all(|state| state == "done") {
                "performed"
            } else if states.iter().any(|state| state == "skipped") {
                "not_in_batch"
            } else {
                "unknown"
            }
        })
        .collect();
    let action_label = next_action
        .get("label")
        .and_then(Value::as_str)
        .unwrap_or("No action available")
        .to_string();
    // The vendored shell's reference grammar needs a leading letter; a bare
    // UUID release id would be dropped and the start gate would close.
    let release = journey
        .get("current_release_id")
        .and_then(Value::as_str)
        .filter(|value| valid_uuid(&value.to_ascii_lowercase()))
        .map(|value| Value::String(format!("release:{}", value.to_ascii_lowercase())))
        .unwrap_or(Value::Null);
    let requirements_revision = journey
        .get("requirements_revision")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let requirements_digest = journey
        .get("requirements_digest_sha256")
        .and_then(Value::as_str)
        .filter(|digest| digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit()));
    let evaluated_at = iso_timestamp(now);
    let fresh_until = iso_timestamp(next_ten_minute_boundary(now));
    let selected_action = match next_action.get("stage").and_then(Value::as_str) {
        Some("deploy") => "deploy",
        Some("access") => "janus_apply",
        _ => "build",
    };
    let (project_node_id, project_key) = match &binding.target {
        BindingTarget::Aeon {
            project_node_id,
            project_key,
        } => (project_node_id.as_str(), project_key.as_str()),
        BindingTarget::Classic { .. } => ("", ""),
    };
    json!({
        "evaluatedAt": evaluated_at,
        "header": {
            "appName": "Aeon",
            "projectName": binding.label,
            "userLabel": "",
            "userInitials": ""
        },
        "health": {"status": "available", "label": "Aeon journey"},
        "delivery": {
            "status": delivery_status,
            "activeStage": active_stage,
            "stageEvidence": stage_evidence,
            "liveReleaseLabel": "Aeon journey",
            "batchTitle": match &release { Value::String(_) => "Current release", _ => "No open release" },
            "batchStatusLabel": action_label,
            "batchRef": release,
            "baselineRef": format!("requirements:{requirements_revision}"),
            "baselineDigest": requirements_digest
                .map(|digest| Value::String(format!("sha256:{digest}")))
                .unwrap_or(Value::Null)
        },
        "prerequisites": {
            "requirementsBaseline": {
                "status": if requirements_done && requirements_digest.is_some() { "pass" } else { "pending" },
                "gateKind": "requirements_baseline",
                "evidenceRef": requirements_digest
                    .map(|digest| Value::String(format!("aeon:req-{}", &digest[..16])))
                    .unwrap_or(Value::Null),
                "observedAt": evaluated_at,
                "freshUntil": fresh_until
            }
        },
        "progress": {
            "stage": stage,
            "stageSource": journey.get("stage_source").cloned().unwrap_or(Value::Null),
            "imported": journey.get("imported").cloned().unwrap_or(Value::Bool(false)),
            "stages": stages,
            "nextAction": next_action,
            "launchReadiness": journey.get("launch_readiness").cloned().unwrap_or(Value::Null),
            "revision": journey.get("revision").cloned().unwrap_or(Value::Null),
            "projectNodeId": project_node_id,
            "projectKey": project_key
        },
        "executionModes": ["manual"],
        "selectedExecutionMode": "manual",
        "selectedAction": selected_action
    })
}

pub(crate) fn inject_flow_shell(
    html: String,
    mount: bool,
    selected_host: Option<&str>,
    flow: Option<&FlowHostService>,
    public_base_path: &PublicBasePath,
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
                " data-flow-paimos-origin=\"{}\" data-flow-upstream=\"{}\"",
                html_escape_attr(service.config.upstream_public_url.as_str()),
                match service.config.upstream {
                    FlowUpstream::Classic => "classic",
                    FlowUpstream::Aeon { .. } => "aeon",
                }
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
    let bootstrap = format!(
        r#"<script type="module" src="{src}"></script>"#,
        src = html_escape_attr(&public_base_path.href("/assets/flow-host-bootstrap.mjs")),
    );
    if let Some(index) = wrapped.rfind("</body>") {
        let mut output = wrapped;
        output.insert_str(index, &bootstrap);
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
    let project_id = context.binding.target.material();
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
            &context.binding.target.material(),
            &context.binding.target.identity(),
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
            upstream: FlowUpstream::Classic,
            upstream_origin: origin.clone(),
            upstream_public_url: origin.clone(),
            api_key_file,
            instance_label: "Pharos test".to_string(),
            bindings: vec![FlowBinding {
                target: BindingTarget::Classic {
                    project_id: 17,
                    expected_project_ref: PAIMOS_PROJECT_REF_17.to_string(),
                },
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
            &PublicBasePath::ROOT,
        );
        assert!(html.contains("data-flow-host-scope=\"hsb8\""));
        assert!(html.contains("/assets/flow-host-bootstrap.mjs"));
    }

    #[test]
    fn vendor_manifest_matches_embedded_assets() {
        let manifest = include_str!("../assets/vendor/flow-shell/manifest.json");
        let parsed: Value = serde_json::from_str(manifest).expect("manifest json");
        assert_eq!(parsed["version"], "0.1.5");
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

    const AEON_PROJECT_NODE_ID: &str = "f9e96f2b-80d9-441f-8369-ba24fcf0acf4";

    fn sample_aeon_config(origin: &Url, api_key_file: PathBuf) -> FlowHostConfig {
        FlowHostConfig {
            enabled: true,
            host_id: "pharos-test".to_string(),
            upstream: FlowUpstream::Aeon {
                tenant_slug: "inspr".to_string(),
            },
            upstream_origin: origin.clone(),
            upstream_public_url: origin.clone(),
            api_key_file,
            instance_label: "Pharos test".to_string(),
            bindings: vec![FlowBinding {
                target: BindingTarget::Aeon {
                    project_node_id: AEON_PROJECT_NODE_ID.to_string(),
                    project_key: "PHAROS".to_string(),
                },
                label: "Pharos journey".to_string(),
                hosts: vec!["hsb8".to_string()],
                operator_refs: HashSet::from(["operator-a".to_string()]),
            }],
            config_digest: "sha256:aeon-test".to_string(),
        }
    }

    fn sample_journey(revision: u64) -> Value {
        json!({
            "project_node_id": AEON_PROJECT_NODE_ID,
            "project_key": "PHAROS",
            "node_key": "PRJ-17",
            "tenant_slug": "inspr",
            "profile": "professional",
            "revision": revision,
            "stage": "build",
            "stage_source": "journey",
            "imported": true,
            "stages": [
                {"key": "inspire", "state": "done"},
                {"key": "shape", "state": "done"},
                {"key": "requirements", "state": "done", "gate_approval_id": "1d2c3b4a-0000-4000-8000-000000000001"},
                {"key": "plan", "state": "done"},
                {"key": "build", "state": "current"},
                {"key": "deploy", "state": "later"},
                {"key": "access", "state": "later"},
                {"key": "live", "state": "later"}
            ],
            "next_action": {"key": "start_build", "label": "Start build", "stage": "build", "available": true, "reason": ""},
            "requirements_revision": 3,
            "requirements_digest_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "requirements_approval_scope": "approvals.decide",
            "launch_readiness": {"can_admit": false, "reason": "build not finished"},
            "current_release_id": "5e6f7a8b-0000-4000-8000-00000000000a"
        })
    }

    /// Serves one Aeon journey response (status + body) at the journey route
    /// for the configured project node, counting requests.
    /// The fixture key `private_fixture_dir` writes; the mock Aeon refuses
    /// any other bearer with 401, so a revoked or wrong key is exercised.
    const FIXTURE_KEY: &str = "01234567890123456789012345678901";

    async fn serve_aeon(
        status: StatusCode,
        body: Value,
    ) -> (
        Url,
        tokio::task::JoinHandle<()>,
        Arc<std::sync::atomic::AtomicUsize>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().unwrap();
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = hits.clone();
        let task = tokio::spawn(async move {
            let app = Router::new().route(
                &format!("/api/projects/{AEON_PROJECT_NODE_ID}/journey"),
                get(move |headers: HeaderMap| {
                    let body = body.clone();
                    let counter = counter.clone();
                    async move {
                        counter.fetch_add(1, Ordering::Relaxed);
                        let authorized = headers
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok())
                            == Some(&format!("Bearer {FIXTURE_KEY}"));
                        if !authorized {
                            return (
                                StatusCode::UNAUTHORIZED,
                                axum::Json(json!({"error": "unauthorized"})),
                            );
                        }
                        (status, axum::Json(body))
                    }
                }),
            );
            axum::serve(listener, app).await.unwrap();
        });
        (
            loopback_origin_for_tests(&format!("http://127.0.0.1:{}", address.port())),
            task,
            hits,
        )
    }

    fn aeon_service(origin: &Url, key_path: PathBuf) -> FlowHostService {
        FlowHostService {
            config: sample_aeon_config(origin, key_path),
            client: Client::builder()
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap(),
            cache: Arc::new(Mutex::new(ProjectionCache::default())),
        }
    }

    fn operator_a() -> (AuthState, AccessGrant, [Host; 1]) {
        (
            AuthState::for_test_human(
                AccessGrant::limited(["hsb8"], true),
                AuthUser {
                    operator_ref: "operator-a".to_string(),
                    managed_human_session_ref: "sess".to_string(),
                    display_name: "Operator".to_string(),
                },
            ),
            AccessGrant::limited(["hsb8"], true),
            [sample_host("hsb8", 1_700_000_000)],
        )
    }

    #[test]
    fn aeon_config_v2_loads_and_rejects_bad_bindings() {
        let (fixture_dir, key_path) = private_fixture_dir("aeon-config");
        let config_path = fixture_dir.join("flow.json");
        let document = |bindings: Value, upstream: &str| {
            json!({
                "schema": CONFIG_SCHEMA_V2,
                "schema_version": CONFIG_SCHEMA_VERSION_V2,
                "enabled": true,
                "host_id": "pharos-test",
                "upstream": upstream,
                "aeon_origin": "https://aeon.example",
                "api_key_file": key_path,
                "instance_label": "Pharos test",
                "tenant_slug": "inspr",
                "bindings": bindings
            })
        };
        let good = json!([{
            "project_node_id": AEON_PROJECT_NODE_ID,
            "project_key": "PHAROS",
            "label": "Pharos journey",
            "hosts": ["hsb8"],
            "operator_refs": ["operator-a"]
        }]);
        write_private_key(
            &config_path,
            document(good.clone(), "aeon").to_string().as_bytes(),
        );
        let config = FlowHostConfig::load(&config_path, false).expect("v2 config loads");
        assert_eq!(
            config.upstream,
            FlowUpstream::Aeon {
                tenant_slug: "inspr".to_string()
            }
        );
        assert_eq!(
            config.bindings[0].target,
            BindingTarget::Aeon {
                project_node_id: AEON_PROJECT_NODE_ID.to_string(),
                project_key: "PHAROS".to_string(),
            }
        );
        assert_eq!(
            config.upstream_public_url.origin().ascii_serialization(),
            "https://aeon.example"
        );

        for (bindings, upstream) in [
            (good.clone(), "paimos"),
            (
                json!([{"project_node_id": "not-a-uuid", "project_key": "PHAROS", "label": "x", "hosts": ["hsb8"], "operator_refs": ["operator-a"]}]),
                "aeon",
            ),
            (
                json!([{"project_node_id": AEON_PROJECT_NODE_ID, "project_key": "pharos", "label": "x", "hosts": ["hsb8"], "operator_refs": ["operator-a"]}]),
                "aeon",
            ),
            (
                json!([{"project_node_id": AEON_PROJECT_NODE_ID, "project_id": 17, "project_key": "PHAROS", "label": "x", "hosts": ["hsb8"], "operator_refs": ["operator-a"]}]),
                "aeon",
            ),
            (
                json!([
                    {"project_node_id": AEON_PROJECT_NODE_ID, "project_key": "PHAROS", "label": "a", "hosts": ["hsb8"], "operator_refs": ["operator-a"]},
                    {"project_node_id": "0e6c3b2a-1111-4000-8000-000000000002", "project_key": "PHAROS", "label": "b", "hosts": ["hsb9"], "operator_refs": ["operator-a"]}
                ]),
                "aeon",
            ),
        ] {
            write_private_key(
                &config_path,
                document(bindings, upstream).to_string().as_bytes(),
            );
            assert!(
                FlowHostConfig::load(&config_path, false).is_err(),
                "upstream={upstream} must be refused"
            );
        }
        let _ = std::fs::remove_file(&config_path);
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn aeon_journey_projects_shell_state_and_routes_to_the_journey_view() {
        let (origin, server, hits) = serve_aeon(StatusCode::OK, sample_journey(7)).await;
        let (fixture_dir, key_path) = private_fixture_dir("aeon-projection");
        let service = aeon_service(&origin, key_path);
        let (auth, access, hosts) = operator_a();
        let headers = HeaderMap::new();
        let now = 1_700_000_000;
        let response = service
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now)
            .await;
        assert!(response.mount_shell, "{:?}", response.unavailable_reason);
        let shell_state = response.shell_state.expect("shell state");
        assert_eq!(shell_state["header"]["appName"], "Pharos");
        assert_eq!(shell_state["header"]["projectName"], "Pharos journey");
        assert_eq!(shell_state["progress"]["stage"], "build");
        assert_eq!(shell_state["progress"]["revision"], 7);
        assert_eq!(shell_state["progress"]["projectKey"], "PHAROS");
        assert_eq!(shell_state["delivery"]["status"], "draft");
        assert_eq!(shell_state["delivery"]["activeStage"], 1);
        assert_eq!(
            shell_state["delivery"]["stageEvidence"],
            json!(["performed", "unknown", "unknown", "unknown"])
        );
        assert_eq!(shell_state["delivery"]["batchStatusLabel"], "Start build");
        assert_eq!(
            shell_state["delivery"]["batchRef"],
            "release:5e6f7a8b-0000-4000-8000-00000000000a"
        );
        assert_eq!(
            shell_state["prerequisites"]["requirementsBaseline"]["status"],
            "pass"
        );
        assert_eq!(shell_state["selectedAction"], "build");
        assert!(shell_state.get("identityContext").is_some());
        let meta = serde_json::to_value(response.projection_meta.expect("meta")).unwrap();
        assert_eq!(meta["projectNodeId"], AEON_PROJECT_NODE_ID);
        assert_eq!(meta["projectKey"], "PHAROS");
        assert!(meta.get("projectId").is_none());

        // Cached inside the ten-minute bucket: one upstream request.
        service
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now + 1)
            .await;
        assert_eq!(hits.load(Ordering::Relaxed), 1);

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
                    detail: Some(
                        json!({"type": "flow:review-batch", "detail": {"executes": false}}),
                    ),
                },
                now,
            )
            .await;
        assert_eq!(status, StatusCode::OK, "intent error: {:?}", intent.error);
        assert!(!intent.executed);
        assert_eq!(intent.routed.as_deref(), Some("aeon-project-journey"));
        // Review carries the stage the validated journey reported.
        assert_eq!(
            intent.location.as_deref(),
            Some(
                format!(
                    "{}/p/PHAROS?view=journey&stage=build",
                    origin.as_str().trim_end_matches('/')
                )
                .as_str()
            )
        );
        let (_, header) = service
            .handle_intent(
                &auth,
                &headers,
                &access,
                &hosts,
                Some("hsb8"),
                FlowIntentRequest {
                    intent_type: "flow:header-project".to_string(),
                    identity: None,
                    detail: None,
                },
                now,
            )
            .await;
        assert_eq!(header.routed.as_deref(), Some("aeon-project-journey"));
        assert!(header.location.unwrap().ends_with("/p/PHAROS?view=journey"));

        // A journey whose next action is unavailable projects a blocked delivery.
        let mut blocked = sample_journey(8);
        blocked["next_action"]["available"] = json!(false);
        let projected = aeon_shell_state(&blocked, &service.config.bindings[0], now);
        assert_eq!(projected["delivery"]["status"], "blocked");
        let mut live = sample_journey(8);
        live["stage"] = json!("live");
        let projected = aeon_shell_state(&live, &service.config.bindings[0], now);
        assert_eq!(projected["delivery"]["status"], "completed");
        assert_eq!(projected["delivery"]["activeStage"], 3);
        server.abort();
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn aeon_journey_binding_mismatches_and_revoked_key_are_denied() {
        let (fixture_dir, key_path) = private_fixture_dir("aeon-denial");
        let (auth, access, hosts) = operator_a();
        let headers = HeaderMap::new();
        let now = 1_700_000_000;
        let mut wrong_project = sample_journey(1);
        wrong_project["project_node_id"] = json!("0e6c3b2a-1111-4000-8000-000000000002");
        let mut wrong_key = sample_journey(1);
        wrong_key["project_key"] = json!("OTHER");
        let mut wrong_tenant = sample_journey(1);
        wrong_tenant["tenant_slug"] = json!("someone-else");
        let mut missing_binding = sample_journey(1);
        missing_binding
            .as_object_mut()
            .unwrap()
            .remove("project_key");
        let mut no_revision = sample_journey(1);
        no_revision.as_object_mut().unwrap().remove("revision");
        let cases = [
            (
                StatusCode::OK,
                wrong_project,
                "configured project binding mismatch",
            ),
            (
                StatusCode::OK,
                wrong_key,
                "configured project binding mismatch",
            ),
            (
                StatusCode::OK,
                wrong_tenant,
                "configured tenant binding mismatch",
            ),
            (
                StatusCode::OK,
                missing_binding,
                "configured project binding mismatch",
            ),
            (StatusCode::OK, no_revision, "no usable revision"),
            (
                StatusCode::FORBIDDEN,
                json!({"error": "revoked"}),
                "cannot read this project journey",
            ),
            (
                StatusCode::NOT_FOUND,
                json!({"error": "gone"}),
                "unavailable for this binding",
            ),
        ];
        for (status, body, expected) in cases {
            let (origin, server, _) = serve_aeon(status, body).await;
            let service = aeon_service(&origin, key_path.clone());
            let response = service
                .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now)
                .await;
            assert!(!response.mount_shell, "{status} must not mount");
            assert!(response.shell_state.is_none());
            let reason = response.unavailable_reason.unwrap_or_default();
            assert!(reason.contains(expected), "{status}: {reason}");
            server.abort();
        }
        // A rotated key: the file no longer matches what Aeon accepts, and the
        // mock answers 401 like a revoked key would.
        let rotated = fixture_dir.join("rotated.key");
        write_private_key(&rotated, b"ffffffffffffffffffffffffffffffff");
        let (origin, server, hits) = serve_aeon(StatusCode::OK, sample_journey(1)).await;
        let service = aeon_service(&origin, rotated.clone());
        let response = service
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now)
            .await;
        assert!(!response.mount_shell);
        assert!(response
            .unavailable_reason
            .unwrap_or_default()
            .contains("cannot read this project journey"));
        assert_eq!(
            hits.load(Ordering::Relaxed),
            1,
            "the request reached Aeon and was refused"
        );
        server.abort();
        let _ = std::fs::remove_file(&rotated);
        cleanup_fixture_dir(&fixture_dir);
    }

    #[tokio::test]
    async fn aeon_journey_that_moves_backwards_is_refused_as_stale() {
        let (fixture_dir, key_path) = private_fixture_dir("aeon-stale");
        let (auth, access, hosts) = operator_a();
        let headers = HeaderMap::new();
        let now = 1_700_000_000;
        let (origin, server, _) = serve_aeon(StatusCode::OK, sample_journey(9)).await;
        let service = aeon_service(&origin, key_path.clone());
        let first = service
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now)
            .await;
        assert!(first.mount_shell, "{:?}", first.unavailable_reason);
        server.abort();
        // A later fetch (next ten-minute bucket) against the same origin now
        // reports an older revision: refused, the shell does not mount.
        let (older_origin, older_server, _) = serve_aeon(StatusCode::OK, sample_journey(8)).await;
        let stale = FlowHostService {
            config: FlowHostConfig {
                upstream_origin: older_origin.clone(),
                upstream_public_url: older_origin,
                ..service.config.clone()
            },
            client: service.client.clone(),
            cache: service.cache.clone(),
        };
        let response = stale
            .shell_state(&auth, &headers, &access, &hosts, Some("hsb8"), now + 600)
            .await;
        assert!(!response.mount_shell);
        assert!(response
            .unavailable_reason
            .unwrap_or_default()
            .contains("older revision"));
        older_server.abort();
        cleanup_fixture_dir(&fixture_dir);
    }

    #[test]
    fn aeon_navigation_allow_list_is_exact() {
        let origin = Url::parse("https://aeon.example").unwrap();
        let service = aeon_service(&origin, PathBuf::from("/tmp/pharos-flow-aeon.key"));
        let binding = service.config.bindings[0].clone();
        assert_eq!(
            service.review_url(&binding, Some("deploy")),
            "https://aeon.example/p/PHAROS?view=journey&stage=deploy"
        );
        assert_eq!(
            service.review_url(&binding, Some("not-a-stage")),
            "https://aeon.example/p/PHAROS?view=journey"
        );
        for (allowed, stage) in [
            ("https://aeon.example/p/PHAROS?view=journey", None),
            ("https://aeon.example/p/PHAROS?view=journey", Some("build")),
            (
                "https://aeon.example/p/PHAROS?view=journey&stage=build",
                Some("build"),
            ),
        ] {
            assert_eq!(
                service
                    .valid_navigation_location(allowed, &binding, stage)
                    .as_deref(),
                Some(allowed),
                "{allowed}"
            );
        }
        let other = FlowBinding {
            target: BindingTarget::Aeon {
                project_node_id: "0e6c3b2a-1111-4000-8000-000000000002".to_string(),
                project_key: "OTHER".to_string(),
            },
            ..binding.clone()
        };
        for (denied, stage) in [
            ("https://aeon.example/p/OTHER?view=journey", None),
            ("https://aeon.example/p/PHAROS", None),
            ("https://aeon.example/p/PHAROS?view=settings", None),
            (
                "https://aeon.example/p/PHAROS?view=journey&view=settings",
                None,
            ),
            (
                "https://aeon.example/p/PHAROS?view=journey&stage=nope",
                Some("nope"),
            ),
            (
                "https://aeon.example/p/PHAROS?view=journey&stage=deploy",
                Some("build"),
            ),
            (
                "https://aeon.example/p/PHAROS?view=journey&stage=build",
                None,
            ),
            (
                "https://aeon.example/p/PHAROS?view=journey&stage=build&stage=build",
                Some("build"),
            ),
            (
                "https://aeon.example/p/PHAROS?view=journey&redirect=https://evil.example",
                None,
            ),
            ("https://aeon.example/p/PHAROS?view=journey#fragment", None),
            ("https://aeon.example/projects/17?tab=overview", None),
            ("https://evil.example/p/PHAROS?view=journey", None),
            ("https://user:pw@aeon.example/p/PHAROS?view=journey", None),
        ] {
            assert!(
                service
                    .valid_navigation_location(denied, &binding, stage)
                    .is_none(),
                "{denied} must be refused"
            );
        }
        // The other binding's own key is fine for that binding, never for this one.
        assert!(service
            .valid_navigation_location("https://aeon.example/p/OTHER?view=journey", &other, None)
            .is_some());
        assert!(service
            .valid_navigation_location("https://aeon.example/p/PHAROS?view=journey", &other, None)
            .is_none());
    }

    #[test]
    fn aeon_config_rejects_one_project_under_two_keys_and_classic_source_revision_is_unchanged() {
        let (fixture_dir, key_path) = private_fixture_dir("aeon-dup");
        let config_path = fixture_dir.join("flow.json");
        let document = json!({
            "schema": CONFIG_SCHEMA_V2,
            "schema_version": CONFIG_SCHEMA_VERSION_V2,
            "enabled": true,
            "host_id": "pharos-test",
            "upstream": "aeon",
            "aeon_origin": "https://aeon.example",
            "api_key_file": key_path,
            "tenant_slug": "inspr",
            "bindings": [
                {"project_node_id": AEON_PROJECT_NODE_ID, "project_key": "PHAROS", "label": "a", "hosts": ["hsb8"], "operator_refs": ["operator-a"]},
                {"project_node_id": AEON_PROJECT_NODE_ID, "project_key": "PHAROS2", "label": "b", "hosts": ["hsb9"], "operator_refs": ["operator-a"]}
            ]
        });
        write_private_key(&config_path, document.to_string().as_bytes());
        assert!(FlowHostConfig::load(&config_path, false).is_err());
        let _ = std::fs::remove_file(&config_path);
        cleanup_fixture_dir(&fixture_dir);

        // Classic source revisions are computed from exactly the material they
        // used before the Aeon upstream existed.
        let expected = pharos_opaque_ref(
            "pharos-test",
            "src",
            &[PAIMOS_PROJECT_REF_17, "2023-11-14T22:13:20.000Z"],
        );
        let with_zero = pharos_opaque_ref(
            "pharos-test",
            "src",
            &[PAIMOS_PROJECT_REF_17, "2023-11-14T22:13:20.000Z", "0"],
        );
        assert_ne!(expected, with_zero);
        assert_eq!(
            expected,
            "pharos-test:src-".to_string() + &expected["pharos-test:src-".len()..]
        );
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
                upstream: FlowUpstream::Classic,
                upstream_origin: Url::parse("https://paimos.example").expect("origin"),
                upstream_public_url: Url::parse("https://paimos.example").expect("origin"),
                api_key_file: PathBuf::from("/tmp/pharos-flow-test.key"),
                instance_label: "Pharos test".to_string(),
                bindings: vec![
                    FlowBinding {
                        target: BindingTarget::Classic {
                            project_id: 17,
                            expected_project_ref: PAIMOS_PROJECT_REF_17.to_string(),
                        },
                        label: "Project A".to_string(),
                        hosts: vec!["host-a".to_string()],
                        operator_refs: HashSet::from(["operator-a".to_string()]),
                    },
                    FlowBinding {
                        target: BindingTarget::Classic {
                            project_id: 18,
                            expected_project_ref: PAIMOS_PROJECT_REF_99.to_string(),
                        },
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
        assert_eq!(binding.target.classic_project_id(), Some(17));
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
