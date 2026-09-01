//! Per-host settings surface.
//!
//! Operator changes are persisted as pending requests. Applied state remains
//! host-owned and changes only after a host reports the accepted preferences.

use std::collections::BTreeMap;

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::Json;
use pharos_core::{
    Host, HostLocation, HostLocationSource, HostManifest, HostPreferences, ManifestLocationMode,
    ManifestPalette,
};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{
    auth::{access_for_headers, AccessGrant},
    host_actions::host_lifecycle,
    host_actions::HostActionStoreError,
    html_escape,
    nixcfg_dispatch::NixcfgDispatchError,
    store::StoreError,
    AppState, ShellContext,
};

const DEFAULT_ACCENT: &str = "#1f7fb5";
const TARGET_PATH: &str = "modules/pharos-host-preferences.json";
const LOCATION_TARGET_PATH: &str = "modules/uzumaki/hosts/host-settings.nix";

const AGORA_CSS: &str = r#"<style>
.settings-main{width:min(1280px,100%)}
.preset-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.preset{width:28px;height:28px;border:1px solid rgba(210,226,234,.92);border-radius:50%;background:var(--preset-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--preset-color) 10%,transparent);cursor:pointer}
.preset:hover,.preset:focus-visible{outline:0;box-shadow:0 0 0 5px color-mix(in srgb,var(--preset-color) 18%,transparent),0 7px 16px rgba(45,75,95,.08)}
.primary-action{min-height:42px;border:1px solid #17304a;border-radius:7px;background:#17304a;color:#fff;font:inherit;font-weight:720;cursor:pointer;padding:0 16px}
.primary-action:hover{background:#10273d}.primary-action:disabled{opacity:.58;cursor:not-allowed}
.review-output{min-height:180px;max-height:360px;overflow:auto;margin:0;border:1px solid rgba(210,226,234,.92);border-radius:8px;background:#10202d;color:#dce9ef;padding:13px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.empty-settings{padding:34px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.86)}
.empty-settings h2{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:25px;font-weight:500}.empty-settings p{margin:0;color:var(--muted)}
.host-settings-toolbar{min-height:58px;padding:9px 12px}
.host-picker{width:100%;display:grid;grid-template-columns:52px minmax(0,1fr);align-items:center;gap:12px;color:var(--ink);font-size:12px;font-weight:720}
.host-picker-control{position:relative;display:grid;grid-template-columns:36px minmax(0,1fr) 18px;align-items:center;gap:10px;min-width:0;height:40px;padding:0 11px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink)}
.host-picker-badge{display:grid;place-items:center;width:26px;height:26px;border:2px solid var(--picker-color);border-radius:50%;background:#fff;color:var(--accent);box-shadow:0 0 0 4px color-mix(in srgb,var(--picker-color) 11%,transparent)}
.host-picker-badge .ico{width:14px;height:14px}
.host-picker-control select{position:absolute;inset:0;width:100%;height:100%;appearance:none;border:0;background:transparent;color:transparent;cursor:pointer;outline:0}
.host-picker-control select option{color:var(--ink);background:#fff}
.host-picker-copy{min-width:0;pointer-events:none}.host-picker-copy strong,.host-picker-copy span{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.host-picker-copy strong{font-size:14px}.host-picker-copy span{margin-top:1px;color:var(--muted);font-size:11px;font-weight:520}
.host-picker-control>.ico{width:16px;height:16px;color:var(--muted);pointer-events:none}
.host-picker-control:focus-within{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}
.host-settings-surface{width:min(840px,100%);margin:26px auto 0;color:var(--ink)}
.host-settings-identity{display:flex;align-items:center;gap:16px;padding:0 14px 22px;border-bottom:1px solid rgba(210,226,234,.86)}
.host-settings-badge{display:grid;place-items:center;flex:0 0 auto;width:48px;height:48px;border:3px solid var(--picked-color);border-radius:50%;background:#fff;color:var(--accent);box-shadow:0 0 0 7px color-mix(in srgb,var(--picked-color) 13%,transparent),0 0 22px color-mix(in srgb,var(--picked-color) 18%,transparent)}
.host-settings-badge .ico{width:23px;height:23px}.host-settings-identity h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:27px;font-weight:500;letter-spacing:0}.host-settings-identity p{margin:3px 0 0;color:var(--muted);font-size:12px}
.host-color-task{padding:28px 14px 30px}.host-color-task h3{margin:0;font-size:16px}.host-color-task>p{margin:5px 0 0;color:var(--muted);font-size:13px}
.host-color-choice{display:flex;align-items:center;flex-wrap:wrap;gap:15px;margin-top:20px}.host-color-well{width:48px;height:48px;flex:0 0 auto;padding:0;border:0;border-radius:50%;background:var(--picked-color);box-shadow:0 0 0 6px color-mix(in srgb,var(--picked-color) 12%,transparent),0 9px 22px color-mix(in srgb,var(--picked-color) 18%,transparent);cursor:pointer}.host-color-well::-webkit-color-swatch-wrapper{padding:0}.host-color-well::-webkit-color-swatch{border:0;border-radius:50%}
.host-color-choice .preset-row{gap:13px}.host-color-choice .preset{width:31px;height:31px;box-shadow:0 0 0 3px color-mix(in srgb,var(--preset-color) 9%,transparent)}.host-color-choice .preset[aria-pressed="true"]{box-shadow:0 0 0 3px #fff,0 0 0 5px color-mix(in srgb,var(--preset-color) 58%,transparent)}
.host-color-actions{display:flex;align-items:center;gap:12px;margin-top:22px}.settings-status{min-width:0;color:var(--muted);font-size:12px}.settings-status[data-state="draft"]{color:#9a5b00}.settings-status[data-state="pending"]{color:#9a5b00}.settings-status[data-state="applied"]{color:var(--live)}.settings-status[data-state="error"]{color:var(--down)}
.host-setup-note{margin-top:18px;padding:10px 12px;border-left:3px solid var(--sun);background:rgba(255,248,234,.62);color:var(--muted);font-size:12px}.host-setup-note strong{display:block;margin-bottom:2px;color:var(--ink)}
.settings-disclosures{border-top:1px solid rgba(210,226,234,.86);border-bottom:1px solid rgba(210,226,234,.86)}.settings-disclosure+.settings-disclosure{border-top:1px solid rgba(210,226,234,.86)}
.settings-disclosure>summary{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:14px;min-height:58px;padding:0 14px;list-style:none;cursor:pointer}.settings-disclosure>summary::-webkit-details-marker{display:none}.settings-disclosure-title,.settings-disclosure-meta{display:flex;align-items:center;gap:10px;min-width:0}.settings-disclosure-title>.ico{width:17px;height:17px;color:#315d7c}.settings-disclosure-title strong{font-size:13px}.settings-disclosure-meta{color:var(--muted);font-size:12px}.settings-disclosure-meta>.ico{width:15px;height:15px;transition:transform .16s ease}.settings-disclosure[open] .settings-disclosure-meta>.ico{transform:rotate(180deg)}
.settings-disclosure-body{padding:0 14px 20px}.preference-list{display:grid}.preference-row{display:flex;align-items:center;justify-content:space-between;gap:18px;min-height:54px;border-top:1px solid rgba(214,226,234,.62)}.preference-row:first-child{border-top:0}.preference-row strong{display:block;font-size:13px}.preference-row span{display:block;margin-top:2px;color:var(--muted);font-size:11px}.preference-switch{position:relative;flex:0 0 auto;width:38px;height:22px}.preference-switch input{position:absolute;opacity:0;pointer-events:none}.preference-switch i{position:absolute;inset:0;border:1px solid rgba(137,151,163,.38);border-radius:999px;background:#edf2f4;transition:.16s}.preference-switch i:after{content:"";position:absolute;top:3px;left:3px;width:14px;height:14px;border-radius:50%;background:#fff;box-shadow:0 1px 4px rgba(45,75,95,.18);transition:.16s}.preference-switch input:checked+i{border-color:rgba(37,132,95,.36);background:rgba(37,132,95,.78)}.preference-switch input:checked+i:after{transform:translateX(16px)}.preference-switch input:focus-visible+i{outline:2px solid rgba(31,127,181,.42);outline-offset:2px}.preference-switch input:disabled+i{opacity:.52;cursor:not-allowed}
.host-advanced{display:grid;gap:12px}.host-advanced-note{margin:0;color:var(--muted);font-size:12px}.host-advanced-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.host-advanced-meta div{min-width:0;padding:9px 10px;border:1px solid rgba(210,226,234,.82);border-radius:7px;background:rgba(247,252,253,.72)}.host-advanced-meta span,.host-advanced-meta strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.host-advanced-meta span{color:var(--muted);font-size:10px}.host-advanced-meta strong{margin-top:2px;font-size:11px}.host-advanced .review-output{min-height:120px;max-height:260px}
.host-kind-row{display:grid;grid-template-columns:minmax(0,1fr) 180px;align-items:center;gap:12px;padding:11px 0;border-top:1px solid rgba(214,226,234,.62);border-bottom:1px solid rgba(214,226,234,.62)}.host-kind-copy strong,.host-kind-copy span{display:block}.host-kind-copy strong{font-size:13px}.host-kind-copy span{margin-top:2px;color:var(--muted);font-size:11px}.host-kind-row select{height:38px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:12px;padding:0 10px}
.settings-draft-actions{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:18px 14px}.settings-draft-copy strong,.settings-draft-copy span{display:block}.settings-draft-copy strong{font-size:13px}.settings-draft-copy span{margin-top:2px;color:var(--muted);font-size:11px}.settings-draft-buttons{display:flex;align-items:center;gap:9px}.settings-draft-buttons button{min-height:38px}.settings-draft-buttons .secondary-action{border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-weight:680;padding:0 13px;cursor:pointer}.settings-draft-buttons .secondary-action:disabled{opacity:.48;cursor:not-allowed}
.settings-draft-review{display:grid;gap:12px;padding:13px 0;border-top:1px solid rgba(214,226,234,.72);border-bottom:1px solid rgba(214,226,234,.72)}.settings-draft-review h3,.settings-draft-review p{margin:0}.settings-draft-review h3{font-size:13px}.settings-draft-review p{color:var(--muted);font-size:11px;line-height:1.45}.settings-draft-review ul{display:grid;gap:7px;margin:0;padding:0;list-style:none}.settings-draft-review li{padding:8px 10px;border:1px solid rgba(210,226,234,.76);border-radius:7px;background:rgba(247,252,253,.72);font-size:11px}.settings-draft-review dl{display:grid;grid-template-columns:54px minmax(0,1fr);gap:5px 9px;margin:0;font-size:10px}.settings-draft-review dt{color:var(--muted)}.settings-draft-review dd{margin:0;color:#294761}
.empty-settings{width:min(840px,100%);margin:26px auto 0;box-shadow:none}
@media (max-width:640px){.host-picker{grid-template-columns:1fr;gap:6px}.host-settings-surface{margin-top:18px}.host-settings-identity,.host-color-task,.settings-disclosure>summary,.settings-disclosure-body,.settings-draft-actions{padding-left:4px;padding-right:4px}.host-color-choice{gap:13px}.host-advanced-meta,.host-kind-row{grid-template-columns:1fr}.settings-draft-actions,.settings-draft-buttons{align-items:stretch;flex-direction:column}.settings-draft-buttons{width:100%}.settings-draft-buttons button{width:100%}}
</style>"#;

#[derive(Debug, Clone, Serialize)]
struct AgoraHostView {
    name: String,
    slug: String,
    role: String,
    is_nix: bool,
    declared_accent: String,
    has_reported: bool,
    settings_ready: bool,
    target_path: String,
    target_attribute: String,
    preferences: HostPreferences,
    declared_preferences: Option<HostPreferences>,
    requested_preferences: Option<HostPreferences>,
}

#[derive(Debug, Default, Deserialize)]
pub(crate) struct AgoraPageQuery {
    host: Option<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct PaletteProposalQuery {
    host: String,
    accent: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct LocationProposalQuery {
    host: String,
    mode: String,
    label: Option<String>,
    latitude: Option<String>,
    longitude: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostPreferencesRequest {
    host: String,
    preferences: HostPreferences,
}

#[derive(Debug, Clone, Serialize)]
struct PaletteProposal {
    schema: &'static str,
    status: &'static str,
    host: String,
    slug: String,
    change: ProposalChange,
    target: ProposalTarget,
    janus: ProposalJanus,
    safety: ProposalSafety,
    patch: ProposalPatch,
}

#[derive(Debug, Clone, Serialize)]
struct LocationProposal {
    schema: &'static str,
    status: &'static str,
    host: String,
    slug: String,
    change: LocationProposalChange,
    target: LocationProposalTarget,
    janus: ProposalJanus,
    safety: ProposalSafety,
    patch: ProposalPatch,
}

#[derive(Debug, Clone, Serialize)]
struct LocationProposalChange {
    setting: &'static str,
    declared: String,
    proposed: String,
}

#[derive(Debug, Clone, Serialize)]
struct LocationProposalTarget {
    repo: &'static str,
    path: &'static str,
    attribute: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalChange {
    setting: &'static str,
    declared: String,
    proposed: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalTarget {
    repo: &'static str,
    path: &'static str,
    palette: String,
    attribute: String,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalJanus {
    required: bool,
    mode: String,
    reason: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalSafety {
    applies_change: bool,
    deploys_host: bool,
    next_gate: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct ProposalPatch {
    format: &'static str,
    value: String,
}

pub(crate) async fn page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AgoraPageQuery>,
) -> Html<String> {
    let user_label = crate::sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora()
        || query.host.as_deref().is_some_and(|host| {
            !access_allows_host_request(&access, state.manifests.manifests(), host)
        })
    {
        return Html(crate::render_no_access_page(
            "Host settings",
            "Color and alerts per host",
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
            },
            "settings",
        ));
    }
    let manifests: Vec<_> = state
        .manifests
        .manifests()
        .iter()
        .filter(|manifest| {
            access.allows_host(&manifest.host.name) || access.allows_host(&manifest.slug)
        })
        .cloned()
        .collect();
    let declared_preferences: BTreeMap<_, _> = state
        .manifests
        .declared_preferences()
        .iter()
        .filter(|(host, _)| access.allows_host(host))
        .map(|(host, preferences)| (host.clone(), preferences.clone()))
        .collect();
    let runtime_hosts: Vec<_> = state
        .store
        .list()
        .into_iter()
        .filter(|host| access.allows_host(&host.name))
        .collect();
    Html(render_page_with_access(
        &manifests,
        &declared_preferences,
        &runtime_hosts,
        query.host.as_deref(),
        &user_label,
        state.auth.is_some(),
        access.can_manage_fleet(),
    ))
}

/// Stable, host-scoped entry point for the durable operator workspace.
///
/// The settings editor remains on Agora because it owns the existing draft,
/// review, and guarded-apply contract. This page deliberately links to that
/// concrete task (or a saved workflow) instead of implying that refreshing an
/// observation will advance host work.
pub(crate) async fn host_workspace_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(host_ref): Path<String>,
) -> Html<String> {
    let user_label = crate::sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    let manifests: Vec<_> = state
        .manifests
        .manifests()
        .iter()
        .filter(|manifest| {
            access.allows_host(&manifest.host.name) || access.allows_host(&manifest.slug)
        })
        .cloned()
        .collect();
    let declared_preferences: BTreeMap<_, _> = state
        .manifests
        .declared_preferences()
        .iter()
        .filter(|(host, _)| access.allows_host(host))
        .map(|(host, preferences)| (host.clone(), preferences.clone()))
        .collect();
    let runtime_hosts: Vec<_> = state
        .store
        .list()
        .into_iter()
        .filter(|host| access.allows_host(&host.name))
        .collect();
    let views = host_views(&manifests, &declared_preferences, &runtime_hosts);
    let selected = views
        .iter()
        .find(|host| host.name == host_ref || host.slug == host_ref);

    if !access.can_agora() || selected.is_none() {
        return Html(crate::render_no_access_page(
            "Host workspace",
            "A durable view of one host",
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
            },
            "fleet",
        ));
    }

    let selected = selected.expect("checked above");
    let runtime = runtime_hosts.iter().find(|host| host.name == selected.name);
    let observed = runtime
        .map(|host| host.preferences.clone())
        .unwrap_or_else(HostPreferences::default);
    let requested = runtime.and_then(|host| host.requested_preferences.as_ref());
    let declared = declared_preferences.get(&selected.name);
    let settings_state = crate::host_preferences_state(&observed, declared, requested);
    let action_jobs: Vec<_> = state
        .host_actions
        .list()
        .into_iter()
        .filter(|job| job.host == selected.name)
        .collect();
    let lifecycle = host_lifecycle(&action_jobs, &selected.name, settings_state, false);

    Html(render_host_workspace(
        selected,
        runtime,
        &lifecycle,
        settings_state,
        &user_label,
        state.auth.is_some(),
        access.can_manage_fleet(),
    ))
}

fn render_host_workspace(
    host: &AgoraHostView,
    runtime: Option<&Host>,
    lifecycle: &crate::HostLifecycle,
    settings_state: crate::HostPreferencesState,
    user_label: &str,
    logout_enabled: bool,
    can_manage_fleet: bool,
) -> String {
    let extra_css = format!(
        r#"{AGORA_CSS}<style>
.host-workspace{{width:min(1320px,100%);display:grid;grid-template-columns:310px minmax(0,1fr);gap:22px;align-items:start}}
.host-workspace-main{{display:grid;gap:16px}}.host-workspace-identity,.host-workspace-section,.host-task-rail{{border:1px solid rgba(210,226,234,.92);border-radius:10px;background:rgba(255,255,255,.9);box-shadow:0 10px 30px rgba(45,75,95,.05)}}
.host-workspace-identity{{padding:22px;display:flex;gap:15px;align-items:center}}.host-workspace-identity h2,.host-workspace-section h2,.host-task-rail h2{{margin:0;font-family:Georgia,"Times New Roman",serif;font-weight:500}}.host-workspace-identity p,.host-workspace-section p,.host-task-rail p{{margin:5px 0 0;color:var(--muted)}}
.host-workspace-mark{{display:grid;place-items:center;width:48px;height:48px;border:3px solid {accent};border-radius:50%;color:var(--accent);background:#fff;box-shadow:0 0 0 7px color-mix(in srgb,{accent} 13%,transparent)}}
.host-workspace-section{{padding:18px}}.host-workspace-section h2{{font-size:18px}}.host-workspace-facts{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:9px;margin-top:14px}}.host-workspace-facts div{{padding:10px;border-radius:7px;background:#f7fcfd}}.host-workspace-facts span,.host-workspace-facts strong{{display:block}}.host-workspace-facts span{{font-size:11px;color:var(--muted)}}.host-workspace-facts strong{{margin-top:3px;font-size:13px;overflow-wrap:anywhere}}
.host-task-rail{{position:sticky;top:18px;padding:18px}}.host-task-rail[data-manager="false"]{{border-style:dashed}}.host-task-rail .primary-action{{display:flex;align-items:center;justify-content:center;text-decoration:none;margin-top:16px}}.host-task-rail .task-kind{{display:inline-block;margin-top:11px;color:var(--muted);font-size:12px}}.host-task-rail .task-note{{font-size:12px;line-height:1.45}}.host-workspace-link{{color:#1e668f;font-weight:700}}
@media(max-width:780px){{.host-workspace{{grid-template-columns:1fr}}.host-task-rail{{position:static;order:0}}.host-workspace-main{{order:1}}.host-workspace-facts{{grid-template-columns:1fr}}}}
</style>"#,
        accent = html_escape(&host.declared_accent),
    );
    let host_path = crate::url_query_escape(&host.name);
    let settings_href = format!("/agora?host={host_path}");
    let (primary_href, primary_label, task_kind) = if let Some(run_id) = lifecycle.run_id.as_deref()
    {
        (
            format!(
                "/?host={host_path}&workflow={}",
                crate::url_query_escape(run_id)
            ),
            lifecycle
                .primary_action
                .as_ref()
                .map(|action| action.label.as_str())
                .unwrap_or("Open saved workflow"),
            "Saved workflow",
        )
    } else {
        (
            settings_href.clone(),
            if settings_state == crate::HostPreferencesState::Applied {
                "Open settings task"
            } else {
                "Continue settings task"
            },
            "Settings task",
        )
    };
    let report = runtime
        .and_then(|host| host.last_seen)
        .map(|seen| seen.to_string())
        .unwrap_or_else(|| "No host report yet".to_string());
    let services = runtime
        .map(|host| host.service_observations.len().to_string())
        .unwrap_or_else(|| "No observation yet".to_string());
    let protection = runtime
        .map(|host| host.backup_observations.len().to_string())
        .unwrap_or_else(|| "No protection observation yet".to_string());
    let manager_note = if can_manage_fleet {
        "You can make guarded changes after the existing review and confirmation gates."
    } else {
        "Viewer access: this workspace is read-only; open the owner task to inspect the saved state."
    };
    let blocked_by = if lifecycle.blocked_by.is_empty() {
        "Nothing recorded".to_string()
    } else {
        lifecycle.blocked_by.join(", ")
    };
    format!(
        r#"{head}{sidebar}<main class="host-workspace" data-host-workspace data-host="{host_name}" data-can-manage-fleet="{can_manage}"><aside class="host-task-rail" data-host-task-rail data-manager="{can_manage}" aria-label="Next safe action"><span class="task-kind">{task_kind}</span><h2>{lifecycle_label}</h2><p>{lifecycle_detail}</p><a class="primary-action" data-host-workspace-primary href="{primary_href}">{primary_label}</a><p class="task-note">{manager_note}</p><a class="host-workspace-link" href="{settings_href}">Open full settings and review</a></aside><div class="host-workspace-main"><header class="host-workspace-identity"><span class="host-workspace-mark">{badge}</span><div><h1>{host_name}</h1><p>{role} · stable workspace</p></div></header><section class="host-workspace-section" data-host-workspace-lifecycle><h2>Lifecycle</h2><p>{lifecycle_detail}</p><div class="host-workspace-facts"><div><span>State</span><strong>{lifecycle_label}</strong></div><div><span>Blocked by</span><strong>{blocked_by}</strong></div></div></section><section class="host-workspace-section" data-host-workspace-settings><h2>Settings</h2><p>Observed, declared, and requested settings continue through the existing Agora review and guarded-apply workflow.</p><div class="host-workspace-facts"><div><span>Settings state</span><strong>{settings_state}</strong></div><div><span>Target</span><strong>{target}</strong></div></div></section><section class="host-workspace-section" data-host-workspace-protection><h2>Protection</h2><p>Backup evidence remains host-reported; Pharos does not claim progress from a refresh.</p><div class="host-workspace-facts"><div><span>Backup observations</span><strong>{protection}</strong></div><div><span>Details</span><strong><a class="host-workspace-link" href="/backups?host={host_path}">Open backup evidence</a></strong></div></div></section><section class="host-workspace-section" data-host-workspace-services><h2>Services</h2><p>Non-secret service observations stay linked to this host.</p><div class="host-workspace-facts"><div><span>Observed services</span><strong>{services}</strong></div><div><span>Details</span><strong><a class="host-workspace-link" href="/services">Open services</a></strong></div></div></section><section class="host-workspace-section" data-host-workspace-activity><h2>Activity</h2><p>The recorded host report is evidence, not an action.</p><div class="host-workspace-facts"><div><span>Last report</span><strong>{report}</strong></div><div><span>Details</span><strong><a class="host-workspace-link" href="/activity">Open activity</a></strong></div></div></section><section class="host-workspace-section" data-host-workspace-technical><h2>Technical context</h2><div class="host-workspace-facts"><div><span>Host reference</span><strong>{host_name}</strong></div><div><span>Configuration target</span><strong>{target}</strong></div></div></section></div></main>{foot}"#,
        head = crate::head_with_extra(&extra_css),
        sidebar = crate::sidebar(user_label, logout_enabled, "fleet"),
        foot = crate::FOOT,
        host_name = html_escape(&host.name),
        role = html_escape(&host.role),
        badge = if host.is_nix {
            crate::icons::SNOWFLAKE
        } else {
            crate::icons::SERVER
        },
        can_manage = can_manage_fleet,
        task_kind = task_kind,
        lifecycle_label = html_escape(&lifecycle.label),
        lifecycle_detail = html_escape(&lifecycle.detail),
        primary_href = html_escape(&primary_href),
        primary_label = html_escape(primary_label),
        manager_note = html_escape(manager_note),
        settings_href = html_escape(&settings_href),
        blocked_by = html_escape(&blocked_by),
        settings_state = settings_state.key(),
        target = html_escape(&host.target_attribute),
        host_path = html_escape(&host_path),
        protection = html_escape(&protection),
        services = html_escape(&services),
        report = html_escape(&report),
    )
}

pub(crate) async fn palette_proposal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PaletteProposalQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora()
        || !access_allows_host_request(&access, state.manifests.manifests(), &query.host)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Agora access is not granted for this host" })),
        );
    }
    let manifest = find_manifest(state.manifests.manifests(), &query.host);
    let declared = state.manifests.declared_preferences_for(&query.host);
    if manifest.is_none() && declared.is_none() {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "host is not present in declared settings" })),
        );
    }

    let proposed = match normalize_hex_color(&query.accent) {
        Ok(color) => color,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
        }
    };

    let proposal = if let Some(manifest) = manifest {
        build_palette_proposal(manifest, declared, &proposed)
    } else {
        build_registry_palette_proposal(&query.host, declared.expect("checked above"), &proposed)
    };
    match proposal {
        Ok(proposal) => (
            StatusCode::OK,
            Json(serde_json::to_value(proposal).expect("proposal serializes")),
        ),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
    }
}

pub(crate) async fn request_host_preferences(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(mut request): Json<HostPreferencesRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    let host_name = request.host.trim();
    if host_name.is_empty()
        || !access.can_manage_fleet()
        || !access_allows_host_request(&access, state.manifests.manifests(), host_name)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Host settings access is not granted for this host" })),
        );
    }

    let manifest = find_manifest(state.manifests.manifests(), host_name);
    let canonical_host = manifest
        .map(|manifest| manifest.host.name.as_str())
        .unwrap_or(host_name);
    let declared_preferences = state.manifests.declared_preferences_for(canonical_host);
    let Some(runtime_host) = state
        .store
        .list()
        .into_iter()
        .find(|host| host.name == canonical_host)
    else {
        return (
            StatusCode::CONFLICT,
            Json(json!({ "error": "The host must report once before settings can be requested" })),
        );
    };

    if let Some(accent) = request.preferences.accent.as_deref() {
        request.preferences.accent = match normalize_hex_color(accent) {
            Ok(accent) => Some(accent),
            Err(error) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
            }
        };
    } else {
        request.preferences.accent = declared_preferences
            .and_then(|preferences| preferences.accent.clone())
            .or_else(|| manifest.and_then(|manifest| manifest.host.preferences.accent.clone()))
            .or_else(|| runtime_host.preferences.accent.clone())
            .or_else(|| {
                manifest
                    .and_then(|manifest| manifest.palette.as_ref())
                    .and_then(palette_accent)
            })
            .or_else(|| Some(DEFAULT_ACCENT.to_string()));
    }
    if let Err(error) = request.preferences.validate_contract() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
    }

    // PHAROS-215: keep repository dispatch, the local pending write, and any
    // concurrent withdrawal in one total order.
    let _settings_change_guard = state.settings_change_lock.lock().await;
    let now = crate::now_unix();
    let actor = crate::action_actor(&state.auth, &headers);
    let workflow = match state
        .host_actions
        .begin_settings_change(canonical_host, &actor, now)
    {
        Ok(workflow) => workflow,
        Err(HostActionStoreError::ActiveJob) => {
            let active = state
                .host_actions
                .latest_settings_change_for_host(canonical_host);
            let summary = active.as_ref().map(|job| {
                job.summary_with_settings_context(
                    declared_preferences,
                    runtime_host.requested_preferences.as_ref(),
                    runtime_host.is_nix,
                )
            });
            let workflow_html = summary
                .as_ref()
                .map(|summary| crate::host_workflow_markup(&summary.workflow));
            return (
                StatusCode::CONFLICT,
                Json(json!({
                    "error": "A settings change is already waiting for this host",
                    "message": "Review the saved settings workflow before sending another request.",
                    "job": summary,
                    "workflow_html": workflow_html,
                })),
            );
        }
        Err(HostActionStoreError::PersistenceCommitted) => {
            match state
                .host_actions
                .latest_settings_change_for_host(canonical_host)
            {
                Some(workflow) => workflow,
                None => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": "The settings workflow could not be recorded" })),
                    );
                }
            }
        }
        Err(_) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "The settings workflow could not be recorded" })),
            );
        }
    };
    let workflow = if runtime_host.is_nix {
        match state.host_actions.record_settings_request(
            &workflow.id,
            &request.preferences,
            crate::now_unix(),
        ) {
            Ok(job) => job,
            Err(HostActionStoreError::PersistenceCommitted) => state
                .host_actions
                .get(&workflow.id)
                .unwrap_or_else(|| workflow.clone()),
            Err(_) => {
                let failed = state
                    .host_actions
                    .fail_settings_change(&workflow.id, crate::now_unix())
                    .unwrap_or(workflow);
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(json!({
                        "error": "The settings request could not be saved before repository dispatch",
                        "job": failed.summary(),
                        "workflow_html": crate::host_workflow_markup(&failed.summary().workflow),
                    })),
                );
            }
        }
    } else {
        workflow
    };

    let workflow = if runtime_host.is_nix {
        match state
            .host_actions
            .prepare_repository_dispatch(&workflow.id, &workflow.id)
        {
            Ok(job) => job,
            Err(HostActionStoreError::PersistenceCommitted) => state
                .host_actions
                .get(&workflow.id)
                .unwrap_or_else(|| workflow.clone()),
            Err(_) => {
                let failed = state
                    .host_actions
                    .fail_settings_change(&workflow.id, crate::now_unix())
                    .ok()
                    .unwrap_or(workflow);
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "The settings dispatch coordinate could not be saved before repository dispatch",
                        "job": failed.summary(),
                        "workflow_html": crate::host_workflow_markup(&failed.summary().workflow),
                    })),
                );
            }
        }
    } else {
        workflow
    };

    let dispatch_request_id = if runtime_host.is_nix {
        match state
            .nixcfg_dispatch
            .dispatch_settings_with_key(canonical_host, &request.preferences, &workflow.id)
            .await
        {
            Ok(request_id) => {
                match state.host_actions.mark_settings_dispatch_submitted(
                    &workflow.id,
                    &request_id,
                    crate::now_unix(),
                ) {
                    Ok(_) | Err(HostActionStoreError::PersistenceCommitted) => {}
                    Err(_) => {
                        let current = state
                            .host_actions
                            .fail_settings_change_uncertain(&workflow.id, crate::now_unix())
                            .ok()
                            .or_else(|| state.host_actions.get(&workflow.id))
                            .unwrap_or_else(|| workflow.clone());
                        return (
                            StatusCode::CONFLICT,
                            Json(json!({
                                "error": "nixcfg accepted the settings request, but Pharos could not save that handoff. Verify nixcfg before any retry.",
                                "job": current.summary(),
                                "workflow_html": crate::host_workflow_markup(&current.summary().workflow),
                            })),
                        );
                    }
                }
                Some(request_id)
            }
            Err(error) => {
                let failed = match error {
                    NixcfgDispatchError::OutcomeUncertain => state
                        .host_actions
                        .fail_settings_change_uncertain(&workflow.id, crate::now_unix())
                        .ok(),
                    _ => state
                        .host_actions
                        .fail_settings_change(&workflow.id, crate::now_unix())
                        .ok(),
                };
                let status = match &error {
                    NixcfgDispatchError::Disabled | NixcfgDispatchError::CredentialUnavailable => {
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                    NixcfgDispatchError::InvalidHost
                    | NixcfgDispatchError::InvalidPreferences
                    | NixcfgDispatchError::InvalidRemovalIntent => StatusCode::BAD_REQUEST,
                    NixcfgDispatchError::OutcomeUncertain => StatusCode::CONFLICT,
                    NixcfgDispatchError::Rejected(_) => StatusCode::BAD_GATEWAY,
                };
                return (
                    status,
                    Json(json!({
                        "error": error.safe_message(),
                        "job": failed.as_ref().map(|job| job.summary()),
                        "workflow_html": failed
                            .as_ref()
                            .map(|job| crate::host_workflow_markup(&job.summary().workflow)),
                    })),
                );
            }
        }
    } else {
        None
    };

    match state
        .store
        .request_preferences(canonical_host, request.preferences)
    {
        Ok(host) => {
            let accepted = match state
                .host_actions
                .accept_settings_change(&workflow.id, crate::now_unix())
            {
                Ok(workflow) => workflow,
                Err(HostActionStoreError::PersistenceCommitted) => state
                    .host_actions
                    .get(&workflow.id)
                    .unwrap_or(workflow.clone()),
                Err(_) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(
                            json!({ "error": "The settings request was sent, but its checklist could not be updated" }),
                        ),
                    );
                }
            };
            let workflow = if host.requested_preferences.is_none() {
                match state
                    .host_actions
                    .complete_settings_change(canonical_host, crate::now_unix())
                {
                    Ok(Some(workflow)) => workflow,
                    Ok(None) => accepted,
                    Err(_) => {
                        return (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": "The applied settings could not be recorded" })),
                        );
                    }
                }
            } else {
                accepted
            };
            let summary = workflow.summary_with_declared_preferences(
                declared_preferences
                    .or_else(|| manifest.map(|manifest| &manifest.host.preferences)),
            );
            let workflow_html = crate::host_workflow_markup(&summary.workflow);
            let status = if dispatch_request_id.is_some() {
                "dispatch_accepted"
            } else if host.requested_preferences.is_some() {
                "pending_host"
            } else {
                "applied"
            };
            let delivery = if host.is_nix {
                "nixcfg_workflow"
            } else {
                "beacon_pull"
            };
            (
                StatusCode::OK,
                Json(json!({
                    "status": status,
                    "host": host.name,
                    "delivery": delivery,
                    "applied": host.preferences,
                    "declared": declared_preferences
                        .or_else(|| manifest.map(|manifest| &manifest.host.preferences)),
                    "requested": host.requested_preferences,
                    "job": summary,
                    "workflow_html": workflow_html,
                })),
            )
        }
        Err(StoreError::HostNotFound) => {
            unreachable!("runtime host checked before workflow dispatch")
        }
        Err(error) => {
            if dispatch_request_id.is_some() {
                let submitted = state
                    .host_actions
                    .get(&workflow.id)
                    .unwrap_or_else(|| workflow.clone());
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({
                        "error": "nixcfg accepted the settings request, but Pharos could not persist the local pending record; do not resend it",
                        "job": submitted.summary(),
                        "workflow_html": crate::host_workflow_markup(&submitted.summary().workflow),
                    })),
                );
            }
            let failed = state
                .host_actions
                .fail_settings_change(&workflow.id, crate::now_unix())
                .ok();
            let status = match error {
                StoreError::InvalidPreferences | StoreError::InvalidContract => {
                    StatusCode::BAD_REQUEST
                }
                StoreError::Persistence(_) | StoreError::InvalidState(_) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                StoreError::HostNotFound => unreachable!("handled above"),
            };
            (
                status,
                Json(json!({
                    "error": error.safe_message(),
                    "job": failed.as_ref().map(|job| job.summary()),
                    "workflow_html": failed
                        .as_ref()
                        .map(|job| crate::host_workflow_markup(&job.summary().workflow)),
                })),
            )
        }
    }
}

pub(crate) async fn location_proposal(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<LocationProposalQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let access = access_for_headers(&state.auth, &headers);
    if !access.can_agora()
        || !access_allows_host_request(&access, state.manifests.manifests(), &query.host)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Agora access is not granted for this host" })),
        );
    }
    let Some(manifest) = find_manifest(state.manifests.manifests(), &query.host) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "host is not declared in the manifest registry" })),
        );
    };

    let mode = match parse_location_mode(&query.mode) {
        Ok(mode) => mode,
        Err(error) => return (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
    };

    match build_location_proposal(
        manifest,
        mode,
        query.label.as_deref(),
        query.latitude.as_deref(),
        query.longitude.as_deref(),
    ) {
        Ok(proposal) => (
            StatusCode::OK,
            Json(serde_json::to_value(proposal).expect("proposal serializes")),
        ),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
    }
}

#[cfg(test)]
fn render_page(
    manifests: &[HostManifest],
    declared_preferences: &BTreeMap<String, HostPreferences>,
    runtime_hosts: &[Host],
    requested_host: Option<&str>,
    user_label: &str,
    logout_enabled: bool,
) -> String {
    render_page_with_access(
        manifests,
        declared_preferences,
        runtime_hosts,
        requested_host,
        user_label,
        logout_enabled,
        true,
    )
}

fn render_page_with_access(
    manifests: &[HostManifest],
    declared_preferences: &BTreeMap<String, HostPreferences>,
    runtime_hosts: &[Host],
    requested_host: Option<&str>,
    user_label: &str,
    logout_enabled: bool,
    can_manage_fleet: bool,
) -> String {
    let mut hosts = host_views(manifests, declared_preferences, runtime_hosts);
    let requested_host = requested_host
        .map(str::trim)
        .filter(|requested| !requested.is_empty());

    let selected_index = requested_host.and_then(|requested| {
        hosts
            .iter()
            .position(|host| host.name == requested || host.slug == requested)
    });

    let selected_index = match (selected_index, requested_host) {
        (Some(index), _) => index,
        (None, Some(requested)) => {
            hosts.push(setup_host_view(
                requested,
                "host",
                false,
                false,
                HostPreferences::default(),
                None,
                None,
            ));
            hosts.len() - 1
        }
        (None, None) => 0,
    };

    let head = crate::head_with_extra(AGORA_CSS);
    let sidebar = crate::sidebar(user_label, logout_enabled, "settings");
    let access_path = if can_manage_fleet {
        String::new()
    } else {
        crate::viewer_access_path("settings")
    };

    if hosts.is_empty() {
        return format!(
            r#"{head}{sidebar}<main class="settings-main" data-can-manage-fleet="{can_manage_fleet}">{header}{access_path}<section class="empty-settings"><h2>No hosts yet</h2><p>Once a host reports to Pharos, its settings will appear here.</p></section></main></div></body></html>"#,
            header = crate::page_header(
                "Host settings",
                "Color and alerts per host",
                crate::now_unix()
            ),
        );
    }

    let selected = &hosts[selected_index];
    let host_table = render_host_table(&hosts, selected_index);
    let content = if selected.settings_ready {
        render_ready_content(selected, can_manage_fleet)
    } else {
        render_setup_content(selected, can_manage_fleet)
    };

    format!(
        r##"{head}{sidebar}<main class="settings-main" data-can-manage-fleet="{can_manage_fleet}">{header}{access_path}{host_table}{content}</main>{action_dialog}<script>
document.querySelector('[data-host-picker]')?.addEventListener('change',event=>{{
  window.location.assign('/agora?host='+encodeURIComponent(event.target.value));
}});
const root=document.querySelector('[data-color-root]');
const settingsWorkflow={{timer:null,controller:null,id:null,lastRevision:'',failures:0,terminal:false,mode:null,confirming:false}};
function settingsCanManageFleet(){{return document.querySelector('.settings-main')?.dataset.canManageFleet==='true'}}
function settingsWorkflowRevision(data){{
  const job=data?.job||{{}};
  const workflow=job.workflow||{{}};
  const action=workflow.primary_action||{{}};
  return JSON.stringify([job.id,job.state,job.updated_at,workflow.updated_at,workflow.status_label,workflow.current_step,action.kind,action.target_run_id,data?.workflow_html||'']);
}}
function replaceSettingsWorkflowHtml(root,workflowHtml){{
  if(!root)return;
  const advanced=root.querySelector('.host-workflow-advanced');
  const summary=advanced?.querySelector('summary');
  const keepAdvancedOpen=advanced?.open===true;
  const restoreSummaryFocus=document.activeElement===summary;
  root.innerHTML=workflowHtml||'';
  const nextAdvanced=root.querySelector('.host-workflow-advanced');
  if(nextAdvanced&&keepAdvancedOpen)nextAdvanced.open=true;
  if(restoreSummaryFocus)nextAdvanced?.querySelector('summary')?.focus({{preventScroll:true}});
}}
function settingsApplyConfirmationReady(){{
  const dialog=document.querySelector('[data-host-action-dialog]');
  const confirmation=dialog?.querySelector('[data-host-remove-input]')?.value||'';
  const attended=dialog?.querySelector('[data-host-attended-input]')?.checked===true;
  return confirmation===root?.dataset.host&&attended;
}}
function setSettingsWorkflowSuspended(suspended){{
  const overlay=document.querySelector('[data-host-action-overlay]');
  if(overlay)overlay.dataset.suspended=suspended?'true':'false';
}}
function pauseSettingsWorkflowPoll(){{
  if(settingsWorkflow.timer!=null)clearTimeout(settingsWorkflow.timer);
  settingsWorkflow.timer=null;
  settingsWorkflow.controller?.abort();
  settingsWorkflow.controller=null;
  setSettingsWorkflowSuspended(true);
}}
function stopSettingsWorkflowPoll(){{
  pauseSettingsWorkflowPoll();
  settingsWorkflow.failures=0;
}}
function closeSettingsWorkflow(){{
  stopSettingsWorkflowPoll();
  settingsWorkflow.id=null;
  settingsWorkflow.lastRevision='';
  settingsWorkflow.terminal=false;
  settingsWorkflow.mode=null;
  settingsWorkflow.confirming=false;
  const overlay=document.querySelector('[data-host-action-overlay]');
  const confirmation=overlay?.querySelector('[data-host-remove-confirm]');
  const confirmationInput=overlay?.querySelector('[data-host-remove-input]');
  const attended=overlay?.querySelector('[data-host-attended-confirm]');
  const attendedInput=overlay?.querySelector('[data-host-attended-input]');
  if(confirmation)confirmation.hidden=true;
  if(confirmationInput)confirmationInput.value='';
  if(attended)attended.hidden=true;
  if(attendedInput)attendedInput.checked=false;
  if(overlay)overlay.hidden=true;
  document.body.removeAttribute('data-host-action-dialog-open');
}}
function scheduleSettingsWorkflowPoll(id,delay=2000){{
  if(settingsWorkflow.terminal)return;
  if(settingsWorkflow.timer!=null)clearTimeout(settingsWorkflow.timer);
  settingsWorkflow.timer=null;
  settingsWorkflow.id=id;
  const suspended=document.hidden||!navigator.onLine;
  setSettingsWorkflowSuspended(suspended);
  if(suspended)return;
  settingsWorkflow.timer=setTimeout(()=>{{
    settingsWorkflow.timer=null;
    pollSettingsWorkflow(id);
  }},delay);
}}
function renderSettingsWorkflow(data){{
  const job=data?.job;
  if(!job)return;
  const workflow=job.workflow||{{}};
  const primaryAction=workflow.primary_action||null;
  const overlay=document.querySelector('[data-host-action-overlay]');
  const dialog=overlay?.querySelector('[data-host-action-dialog]');
  if(!overlay||!dialog)return;
  const initialWorkflowOpen=overlay.hidden||settingsWorkflow.mode!=='workflow';
  dialog.dataset.workflow='true';
  dialog.dataset.action='settings-change';
  dialog.querySelectorAll('[data-action-icon]').forEach(icon=>{{icon.hidden=icon.dataset.actionIcon!=='settings-change'}});
  const title=dialog.querySelector('[data-host-action-title]');
  const copy=dialog.querySelector('[data-host-action-copy]');
  if(title)title.textContent=workflow.title||'Host settings';
  if(copy)copy.textContent=workflow.guidance||data.message||'The settings workflow is recorded.';
  const info=dialog.querySelector('[data-host-action-info]');
  const facts=dialog.querySelector('[data-host-action-facts]');
  const technical=dialog.querySelector('[data-host-action-technical]');
  const checklist=dialog.querySelector('[data-host-workflow]');
  const primary=dialog.querySelector('[data-host-action-primary]');
  const cancelRequest=dialog.querySelector('[data-host-action-cancel]');
  const cancel=dialog.querySelector('.host-action-dialog-buttons [data-host-action-close]');
  const status=dialog.querySelector('[data-host-action-status]');
  const safe=dialog.querySelector('[data-host-action-safe-note]');
  const confirmation=dialog.querySelector('[data-host-remove-confirm]');
  const confirmationName=dialog.querySelector('[data-host-remove-name]');
  const confirmationInput=dialog.querySelector('[data-host-remove-input]');
  const attended=dialog.querySelector('[data-host-attended-confirm]');
  const attendedInput=dialog.querySelector('[data-host-attended-input]');
  const terminal=['succeeded','failed','cancelled'].includes(job.state);
  const actionKind=primaryAction?.kind||'';
  const guardedAction=['apply_declared','confirm','retry'].includes(actionKind)||(actionKind==='recover'&&Boolean(primaryAction?.target_run_id));
  const actionRequired=['acknowledge','apply_declared','confirm','retry','recover','continue','restart'].includes(actionKind);
  settingsWorkflow.mode='workflow';
  settingsWorkflow.confirming=false;
  settingsWorkflow.terminal=terminal;
  if(info)info.hidden=true;
  if(facts)facts.hidden=true;
  if(technical)technical.hidden=true;
  if(checklist){{checklist.hidden=false;replaceSettingsWorkflowHtml(checklist,data.workflow_html)}}
  if(confirmation)confirmation.hidden=actionKind!=='confirm';
  if(confirmationName)confirmationName.textContent=root?.dataset.host||job.host||'';
  if(attended)attended.hidden=actionKind!=='confirm';
  if(actionKind!=='confirm'){{
    if(confirmationInput)confirmationInput.value='';
    if(attendedInput)attendedInput.checked=false;
  }}
  if(primary){{
    primary.hidden=!actionRequired;
    primary.disabled=guardedAction&&!settingsCanManageFleet()
      ?true
      :actionKind==='confirm'?!settingsApplyConfirmationReady():false;
    primary.dataset.workflowAction=actionKind;
    primary.dataset.workflowTargetRunId=primaryAction?.target_run_id||'';
    primary.textContent=primaryAction?.label||'Continue';
  }}
  if(cancelRequest){{cancelRequest.hidden=true;cancelRequest.disabled=false}}
  if(cancel)cancel.textContent='Close';
  if(status)status.textContent=data.message||'';
  if(safe){{
    safe.dataset.workflowLive=terminal||actionRequired?'false':'true';
    safe.textContent=guardedAction&&!settingsCanManageFleet()?'Fleet operator access is required for this guarded action'
      :terminal?'Run complete and saved'
      :primaryAction?.kind==='continue'?'Ready to continue the saved request'
      :primaryAction?.kind==='restart'?'Operator action required'
      :primaryAction?.kind==='apply_declared'?'Ready to prepare the guarded apply'
      :primaryAction?.kind==='confirm'?'Attended confirmation required'
      :primaryAction?.kind==='retry'?'Ready to retry the guarded review'
      :primaryAction?.kind==='recover'?'Ready to run guarded recovery checks'
      :'Watching for recorded host evidence';
  }}
  overlay.hidden=false;
  document.body.dataset.hostActionDialogOpen='true';
  settingsWorkflow.id=settingsWorkflow.id||job.id;
  settingsWorkflow.lastRevision=settingsWorkflowRevision(data);
  if(terminal){{
    if(settingsWorkflow.timer!=null)clearTimeout(settingsWorkflow.timer);
    settingsWorkflow.timer=null;
    setSettingsWorkflowSuspended(false);
  }}else if(!actionRequired)scheduleSettingsWorkflowPoll(settingsWorkflow.id);
  if(initialWorkflowOpen)requestAnimationFrame(()=>dialog.querySelector('[data-host-action-close]')?.focus());
}}
async function pollSettingsWorkflow(id){{
  settingsWorkflow.timer=null;
  if(settingsWorkflow.id!==id||settingsWorkflow.terminal)return;
  if(document.hidden||!navigator.onLine){{setSettingsWorkflowSuspended(true);return}}
  setSettingsWorkflowSuspended(false);
  settingsWorkflow.controller?.abort();
  const controller=new AbortController();
  settingsWorkflow.controller=controller;
  try{{
    const response=await fetch('/host-actions/jobs/'+encodeURIComponent(id),{{credentials:'same-origin',cache:'no-store',signal:controller.signal}});
    const data=await response.json().catch(()=>({{}}));
    if(!response.ok)throw new Error(data.error||'Could not refresh the settings workflow.');
    settingsWorkflow.failures=0;
    const revision=settingsWorkflowRevision(data);
    if(revision!==settingsWorkflow.lastRevision)renderSettingsWorkflow(data);
    else scheduleSettingsWorkflowPoll(id);
  }}catch(error){{
    if(error?.name!=='AbortError'){{
      settingsWorkflow.failures=Math.min(settingsWorkflow.failures+1,3);
      scheduleSettingsWorkflowPoll(id,Math.min(60000,10000*(2**settingsWorkflow.failures)));
    }}
  }}finally{{
    if(settingsWorkflow.controller===controller)settingsWorkflow.controller=null;
  }}
}}
document.querySelector('[data-host-action-overlay]')?.addEventListener('click',event=>{{
  if(event.target.closest('[data-host-action-close]')){{event.preventDefault();closeSettingsWorkflow()}}
  const primary=event.target.closest('[data-host-action-primary]');
  if(primary&&settingsWorkflow.id&&settingsWorkflow.mode==='workflow'){{
    event.preventDefault();
    const action=primary.dataset.workflowAction||'';
    const targetRunId=primary.dataset.workflowTargetRunId||'';
    const guardedAction=['apply_declared','confirm','retry'].includes(action)||(action==='recover'&&Boolean(targetRunId));
    if(guardedAction&&!settingsCanManageFleet())return;
    if(action==='confirm'&&!settingsApplyConfirmationReady())return;
    if(['confirm','retry'].includes(action)&&!targetRunId)return;
    primary.disabled=true;
    const requestRunId=targetRunId||settingsWorkflow.id;
    const endpoint=action==='apply_declared'?'apply-declared'
      :action==='confirm'?'confirm'
      :action==='retry'?'retry'
      :action==='recover'&&targetRunId?'recover'
      :action==='recover'?'reconcile-accepted-dispatch'
      :action==='continue'?'continue-settings-dispatch'
      :action==='restart'?'withdraw'
      :'acknowledge-dispatch-uncertainty';
    const body=action==='confirm'
      ?JSON.stringify({{confirmation:root.dataset.host,attended:true}})
      :'{{}}';
    const status=document.querySelector('[data-host-action-status]');
    if(status)status.textContent=action==='apply_declared'
      ?'Preparing the guarded apply review…'
      :action==='confirm'?'Recording attended confirmation…'
      :action==='retry'?'Retrying the guarded review…'
      :action==='recover'&&targetRunId?'Queueing target-local recovery checks…'
      :action==='continue'?'Continuing the saved request through nixcfg…'
      :action==='restart'?'Clearing the incomplete request…'
      :'Reconciling the saved workflow…';
    fetch('/host-actions/jobs/'+encodeURIComponent(requestRunId)+'/'+endpoint,{{
      method:'POST',
      credentials:'same-origin',
      headers:{{'Content-Type':'application/json','X-Pharos-Action':'1'}},
      body,
    }}).then(async response=>{{
      const data=await response.json().catch(()=>({{}}));
      if(!response.ok)throw new Error(data.error||'Could not reconcile the saved workflow.');
      if(data.job?.id===settingsWorkflow.id)renderSettingsWorkflow(data);
      else scheduleSettingsWorkflowPoll(settingsWorkflow.id,0);
    }}).catch(error=>{{
      if(status)status.textContent=error.message||'Could not reconcile the saved workflow.';
      if(primary.isConnected)primary.disabled=guardedAction&&!settingsCanManageFleet()||action==='confirm'&&!settingsApplyConfirmationReady();
    }});
  }}
}});
document.querySelector('[data-host-action-overlay]')?.addEventListener('input',event=>{{
  if(!event.target.matches('[data-host-remove-input]'))return;
  const primary=document.querySelector('[data-host-action-primary]');
  if(primary&&settingsWorkflow.mode==='workflow'&&primary.dataset.workflowAction==='confirm')primary.disabled=!settingsCanManageFleet()||!settingsApplyConfirmationReady();
}});
document.querySelector('[data-host-action-overlay]')?.addEventListener('change',event=>{{
  if(!event.target.matches('[data-host-attended-input]'))return;
  const primary=document.querySelector('[data-host-action-primary]');
  if(primary&&settingsWorkflow.mode==='workflow'&&primary.dataset.workflowAction==='confirm')primary.disabled=!settingsCanManageFleet()||!settingsApplyConfirmationReady();
}});
document.addEventListener('keydown',event=>{{if(event.key==='Escape'&&(settingsWorkflow.id||settingsWorkflow.mode==='confirm')){{event.preventDefault();closeSettingsWorkflow()}}}});
document.addEventListener('visibilitychange',()=>{{
  if(document.hidden){{pauseSettingsWorkflowPoll();return}}
  if(settingsWorkflow.id&&!settingsWorkflow.terminal)scheduleSettingsWorkflowPoll(settingsWorkflow.id,0);
}});
window.addEventListener('focus',()=>{{if(settingsWorkflow.id&&!settingsWorkflow.terminal)scheduleSettingsWorkflowPoll(settingsWorkflow.id,0)}});
window.addEventListener('online',()=>{{if(settingsWorkflow.id&&!settingsWorkflow.terminal)scheduleSettingsWorkflowPoll(settingsWorkflow.id,0)}});
window.addEventListener('offline',()=>{{pauseSettingsWorkflowPoll()}});
window.addEventListener('pagehide',stopSettingsWorkflowPoll);
if(root){{
  const color=root.querySelector('[data-color]');
  const output=root.querySelector('[data-review-output]');
  const status=root.querySelector('[data-settings-status]');
  const alertSummary=root.querySelector('[data-alert-summary]');
  const down=root.querySelector('[data-alert-down]');
  const backup=root.querySelector('[data-alert-backup]');
  const nix=root.querySelector('[data-alert-nix]');
  const kind=root.querySelector('[data-host-kind]');
  const downCopy=root.querySelector('[data-alert-down-copy]');
  let manualDownSuppressed=root.dataset.manualDownSuppressed==='true';
  let savedPreferences=null;
  let persistedStatusText=status?.textContent||'';
  let persistedStatusState=status?.dataset.state||'idle';
  function setStatus(state,text){{if(!status)return;status.dataset.state=state;status.textContent=text}}
  function setPressed(value){{root.querySelectorAll('[data-preset]').forEach(button=>button.setAttribute('aria-pressed',String((button.dataset.preset||'').toLowerCase()===value.toLowerCase())))}}
  function setPicked(value){{
    let next=String(value||'').trim();
    if(!next.startsWith('#'))next='#'+next;
    next=next.slice(0,7);
    if(/^#[0-9a-fA-F]{{6}}$/.test(next)){{
      root.style.setProperty('--picked-color',next);
      if(color)color.value=next;
      setPressed(next);
    }}
  }}
  function updateAlertSummary(){{
    const enabled=[down,backup,nix].filter(input=>input?.checked).length;
    if(alertSummary)alertSummary.textContent=enabled+' on';
  }}
  function syncDownAlertPolicy(){{
    if(!down)return;
    const workstation=(kind?.value||root.dataset.kind)==='workstation';
    down.disabled=root.dataset.hostReported!=='true'||workstation;
    down.checked=workstation?false:!manualDownSuppressed;
    if(downCopy)downCopy.textContent=workstation?'Off automatically for workstations.':'Warn when this host stops reporting.';
    updateAlertSummary();
  }}
  function draftPreferences(){{
    return {{
      accent:color?.value||null,
      kind:kind?.value||root.dataset.kind||'server',
      alerts:{{
        suppress_down:manualDownSuppressed,
        suppress_backup:!backup?.checked,
        suppress_nix_freshness:!nix?.checked,
      }},
    }};
  }}
  function preferenceChanges(before,after){{
    const changes=[];
    if(before.accent!==after.accent)changes.push('Host color: '+(before.accent||'default')+' → '+(after.accent||'default'));
    if(before.kind!==after.kind)changes.push('Host type: '+before.kind+' → '+after.kind);
    const alertLabels={{suppress_down:'Down alerts',suppress_backup:'Backup warnings',suppress_nix_freshness:'Nix freshness warnings'}};
    Object.entries(alertLabels).forEach(([key,label])=>{{
      if(before.alerts[key]!==after.alerts[key])changes.push(label+': '+(after.alerts[key]?'off':'on'));
    }});
    return changes;
  }}
  function updateDraftState(){{
    if(!savedPreferences)return;
    const changes=preferenceChanges(savedPreferences,draftPreferences());
    const dirty=changes.length>0;
    const summary=root.querySelector('[data-draft-summary]');
    const review=root.querySelector('[data-review-settings]');
    const discard=root.querySelector('[data-discard-settings]');
    if(summary)summary.textContent=dirty?(changes.length+' unsent '+(changes.length===1?'change':'changes')):'Change a setting to prepare a review.';
    if(review)review.disabled=!dirty||settingsWorkflow.confirming;
    if(discard)discard.disabled=!dirty||settingsWorkflow.confirming;
    if(dirty)setStatus('draft','Draft only — no request sent.');
    else setStatus(persistedStatusState,persistedStatusText);
  }}
  function applyPreferences(preferences){{
    setPicked(preferences.accent||'{accent}');
    if(kind)kind.value=preferences.kind||'server';
    manualDownSuppressed=preferences.alerts?.suppress_down===true;
    if(backup)backup.checked=preferences.alerts?.suppress_backup!==true;
    if(nix)nix.checked=preferences.alerts?.suppress_nix_freshness!==true;
    syncDownAlertPolicy();
    updateAlertSummary();
  }}
  function draftReviewSection(changes){{
    const section=document.createElement('section');
    section.className='settings-draft-review';
    section.dataset.settingsDraftReview='true';
    const heading=document.createElement('h3');
    heading.textContent='What will be requested';
    const list=document.createElement('ul');
    changes.forEach(change=>{{const item=document.createElement('li');item.textContent=change;list.append(item)}});
    const details=document.createElement('dl');
    const addDetail=(label,value)=>{{const term=document.createElement('dt');term.textContent=label;const detail=document.createElement('dd');detail.textContent=value;details.append(term,detail)}};
    const where=root.dataset.isNix==='true'
      ? 'nixcfg · '+root.dataset.targetPath+' · '+root.dataset.targetAttribute
      : 'Pharos pending preferences for '+root.dataset.host;
    addDetail('Where',where);
    addDetail('Will not','Pharos will not close or merge a nixcfg proposal.');
    const note=document.createElement('p');
    note.textContent='Confirmation creates one saved SettingsChange run. Applied state changes only after matching host evidence.';
    section.append(heading,list,details,note);
    return section;
  }}
  function openDraftConfirmation(){{
    const changes=preferenceChanges(savedPreferences,draftPreferences());
    if(!changes.length)return;
    stopSettingsWorkflowPoll();
    settingsWorkflow.id=null;
    settingsWorkflow.lastRevision='';
    settingsWorkflow.terminal=false;
    settingsWorkflow.mode='confirm';
    settingsWorkflow.confirming=false;
    const overlay=document.querySelector('[data-host-action-overlay]');
    const dialog=overlay?.querySelector('[data-host-action-dialog]');
    if(!overlay||!dialog)return;
    dialog.dataset.workflow='true';
    dialog.dataset.action='settings-change';
    dialog.querySelectorAll('[data-action-icon]').forEach(icon=>{{icon.hidden=icon.dataset.actionIcon!=='settings-change'}});
    const title=dialog.querySelector('[data-host-action-title]');
    const copy=dialog.querySelector('[data-host-action-copy]');
    const info=dialog.querySelector('[data-host-action-info]');
    const facts=dialog.querySelector('[data-host-action-facts]');
    const technical=dialog.querySelector('[data-host-action-technical]');
    const checklist=dialog.querySelector('[data-host-workflow]');
    const primary=dialog.querySelector('[data-host-action-primary]');
    const discard=dialog.querySelector('[data-host-action-cancel]');
    const close=dialog.querySelector('.host-action-dialog-buttons [data-host-action-close]');
    const sheetStatus=dialog.querySelector('[data-host-action-status]');
    const safe=dialog.querySelector('[data-host-action-safe-note]');
    const confirmation=dialog.querySelector('[data-host-remove-confirm]');
    const confirmationInput=dialog.querySelector('[data-host-remove-input]');
    const attended=dialog.querySelector('[data-host-attended-confirm]');
    const attendedInput=dialog.querySelector('[data-host-attended-input]');
    if(title)title.textContent='Confirm changes for '+root.dataset.host;
    if(copy)copy.textContent='Review the draft before Pharos creates a saved settings workflow.';
    if(info)info.hidden=true;
    if(facts)facts.hidden=true;
    if(technical)technical.hidden=true;
    if(checklist){{checklist.hidden=false;checklist.replaceChildren(draftReviewSection(changes))}}
    if(confirmation)confirmation.hidden=true;
    if(confirmationInput)confirmationInput.value='';
    if(attended)attended.hidden=true;
    if(attendedInput)attendedInput.checked=false;
    if(primary){{primary.hidden=false;primary.disabled=false;primary.dataset.workflowAction='confirm-settings';primary.textContent='Confirm change request'}}
    if(discard){{discard.hidden=false;discard.disabled=false;discard.textContent='Discard draft'}}
    if(close)close.textContent='Keep editing';
    if(sheetStatus)sheetStatus.textContent='No request has been sent.';
    if(safe){{safe.dataset.workflowLive='false';safe.textContent='Draft only — confirmation required'}}
    overlay.hidden=false;
    document.body.dataset.hostActionDialogOpen='true';
    requestAnimationFrame(()=>primary?.focus());
  }}
  function discardDraft(){{
    if(!savedPreferences)return;
    applyPreferences(savedPreferences);
    updateDraftState();
    closeSettingsWorkflow();
  }}
  async function loadReview(){{
    if(!output||root.dataset.ready!=='true')return;
    output.textContent='Preparing declarative details...';
    try{{
      const res=await fetch('/agora/proposals/host-palette.json?host='+encodeURIComponent(root.dataset.host)+'&accent='+encodeURIComponent(color.value),{{headers:{{Accept:'application/json'}}}});
      const data=await res.json();
      output.textContent=res.ok?data.patch.value:(data.error||'Details unavailable');
    }}catch(_){{output.textContent='Details unavailable'}}
  }}
  async function confirmSettingsDraft(button){{
    if(settingsWorkflow.mode!=='confirm'||settingsWorkflow.confirming)return;
    settingsWorkflow.confirming=true;
    button.disabled=true;
    root.querySelector('[data-discard-settings]')?.setAttribute('disabled','');
    const discard=document.querySelector('[data-host-action-cancel]');
    if(discard)discard.disabled=true;
    const sheetStatus=document.querySelector('[data-host-action-status]');
    if(sheetStatus)sheetStatus.textContent='Creating one saved settings request…';
    try{{
      const res=await fetch('/agora/requests/host-preferences.json',{{
        method:'POST',
        headers:{{Accept:'application/json','Content-Type':'application/json'}},
        body:JSON.stringify({{host:root.dataset.host,preferences:draftPreferences()}}),
      }});
      const data=await res.json();
      if(!res.ok){{
        if(data.job){{renderSettingsWorkflow(data);setStatus('error',data.error||'Request already exists.');return}}
        throw new Error(data.error||'Request failed');
      }}
      savedPreferences=draftPreferences();
      if(data.status==='applied')persistedStatusText='Already active on this host.';
      else if(data.status==='dispatch_accepted')persistedStatusText='Change requested. Validation is running.';
      else persistedStatusText='Saved. Waiting for the host.';
      persistedStatusState=data.status==='applied'?'applied':'pending';
      setStatus(persistedStatusState,persistedStatusText);
      const summary=root.querySelector('[data-draft-summary]');
      if(summary)summary.textContent='Request confirmed. Continue in the workflow sheet.';
      root.querySelector('[data-review-settings]')?.setAttribute('disabled','');
      root.querySelector('[data-discard-settings]')?.setAttribute('disabled','');
      await loadReview();
      if(data.job)renderSettingsWorkflow(data);
    }}catch(error){{
      settingsWorkflow.confirming=false;
      setStatus('error',error.message||'Request failed');
      if(sheetStatus)sheetStatus.textContent=error.message||'Request failed';
      button.disabled=false;
      if(discard)discard.disabled=false;
      updateDraftState();
    }}
  }}
  color?.addEventListener('input',event=>{{setPicked(event.target.value);updateDraftState()}});
  root.querySelectorAll('[data-preset]').forEach(button=>button.addEventListener('click',()=>{{setPicked(button.dataset.preset);updateDraftState()}}));
  root.querySelector('[data-review-settings]')?.addEventListener('click',openDraftConfirmation);
  root.querySelector('[data-discard-settings]')?.addEventListener('click',discardDraft);
  down?.addEventListener('change',()=>{{manualDownSuppressed=!down.checked;updateAlertSummary();updateDraftState()}});
  [backup,nix].forEach(input=>input?.addEventListener('change',()=>{{updateAlertSummary();updateDraftState()}}));
  kind?.addEventListener('change',()=>{{syncDownAlertPolicy();updateDraftState()}});
  document.querySelector('[data-host-action-overlay]')?.addEventListener('click',event=>{{
    const primary=event.target.closest('[data-host-action-primary]');
    if(primary&&settingsWorkflow.mode==='confirm'){{event.preventDefault();confirmSettingsDraft(primary);return}}
    const discard=event.target.closest('[data-host-action-cancel]');
    if(discard&&settingsWorkflow.mode==='confirm'){{event.preventDefault();discardDraft()}}
  }});
  setPicked(color?.value||'{accent}');
  syncDownAlertPolicy();
  savedPreferences=draftPreferences();
  const incomingDraft=new URLSearchParams(window.location.search);
  if(settingsCanManageFleet()&&incomingDraft.get('draft')==='fleet-drawer'&&incomingDraft.get('host')===root.dataset.host){{
    const incomingAccent=incomingDraft.get('draft_accent')||'';
    const incomingKind=incomingDraft.get('draft_kind')||'';
    const boolValue=name=>incomingDraft.get(name)==='true';
    if(/^#[0-9a-fA-F]{{6}}$/.test(incomingAccent)&&['server','workstation'].includes(incomingKind)){{
      applyPreferences({{
        accent:incomingAccent,
        kind:incomingKind,
        alerts:{{
          suppress_down:boolValue('draft_suppress_down'),
          suppress_backup:boolValue('draft_suppress_backup'),
          suppress_nix_freshness:boolValue('draft_suppress_nix'),
        }},
      }});
      const cleanUrl=new URL(window.location.href);
      ['draft','draft_accent','draft_kind','draft_suppress_down','draft_suppress_backup','draft_suppress_nix'].forEach(key=>cleanUrl.searchParams.delete(key));
      window.history.replaceState(null,'',cleanUrl.pathname+(cleanUrl.searchParams.size?'?'+cleanUrl.searchParams.toString():''));
    }}
  }}
  updateDraftState();
}}
</script></div></body></html>"##,
        header = crate::page_header(
            "Host settings",
            "Color and alerts per host",
            crate::now_unix()
        ),
        host_table = host_table,
        access_path = access_path,
        action_dialog = crate::host_action_dialog(),
        accent = html_escape(&selected.declared_accent),
        can_manage_fleet = can_manage_fleet,
    )
}

fn render_ready_content(host: &AgoraHostView, can_manage_fleet: bool) -> String {
    render_color_panel(host, true, can_manage_fleet)
}

fn render_setup_content(host: &AgoraHostView, can_manage_fleet: bool) -> String {
    render_color_panel(host, false, can_manage_fleet)
}

fn render_host_table(hosts: &[AgoraHostView], selected_index: usize) -> String {
    let options = hosts
        .iter()
        .enumerate()
        .map(|(idx, host)| render_host_row(host, idx == selected_index))
        .collect::<String>();
    let selected = &hosts[selected_index];
    let accent = displayed_preferences(selected)
        .and_then(|preferences| preferences.accent.as_deref())
        .unwrap_or(&selected.declared_accent);
    let badge = if selected.is_nix {
        crate::icons::SNOWFLAKE
    } else {
        crate::icons::SERVER
    };
    format!(
        r#"<section class="toolbar host-settings-toolbar" aria-label="host settings controls"><label class="host-picker"><span>Host</span><span class="host-picker-control" style="--picker-color:{accent}"><span class="host-picker-badge">{badge}</span><span class="host-picker-copy"><strong>{name}</strong><span>{role}</span></span>{chevron}<select data-host-picker aria-label="Choose host">{options}</select></span></label></section>"#,
        accent = html_escape(accent),
        badge = badge,
        name = html_escape(&selected.name),
        role = html_escape(&selected.role),
        chevron = crate::icons::CHEVRON_DOWN,
        options = options,
    )
}

fn render_host_row(host: &AgoraHostView, selected: bool) -> String {
    let current = if selected { " selected" } else { "" };
    format!(
        r#"<option value="{name}"{current}>{name} - {role}</option>"#,
        current = current,
        name = html_escape(&host.name),
        role = html_escape(&host.role),
    )
}

fn displayed_preferences(host: &AgoraHostView) -> Option<&HostPreferences> {
    host.requested_preferences
        .as_ref()
        .or(host.declared_preferences.as_ref())
        .or(Some(&host.preferences))
}

fn render_color_panel(host: &AgoraHostView, ready: bool, can_manage_fleet: bool) -> String {
    let shown_preferences = displayed_preferences(host).unwrap_or(&host.preferences);
    let accent = shown_preferences
        .accent
        .as_deref()
        .unwrap_or(&host.declared_accent);
    let presets = preset_buttons(accent, !can_manage_fleet);
    let setup_note = if ready {
        String::new()
    } else if host.has_reported {
        format!(
            r#"<div class="host-setup-note"><strong>Prepare host settings</strong>Editing creates a local draft for {name}. Only the confirmation sheet sends a request, and it becomes active only after the host applies and reports it.</div>"#,
            name = html_escape(&host.name)
        )
    } else {
        format!(
            r#"<div class="host-setup-note"><strong>Waiting for first report</strong>{name} must report once before settings can be requested.</div>"#,
            name = html_escape(&host.name)
        )
    };
    let enabled_alerts = [
        !shown_preferences.suppresses_down_alerts(),
        !shown_preferences.alerts.suppress_backup,
        !shown_preferences.alerts.suppress_nix_freshness,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();
    let declared_waiting = host
        .declared_preferences
        .as_ref()
        .is_some_and(|declared| declared != &host.preferences);
    let request_pending = host
        .requested_preferences
        .as_ref()
        .is_some_and(|requested| {
            host.declared_preferences.as_ref() != Some(requested) && requested != &host.preferences
        });
    let pending = request_pending || declared_waiting;
    let pending_copy = if request_pending && host.is_nix {
        "Change requested. Validation is running."
    } else if pending {
        "Change declared. Waiting for the host."
    } else {
        ""
    };
    let status_state = if pending { "pending" } else { "idle" };
    let role_copy = if host
        .role
        .eq_ignore_ascii_case(shown_preferences.kind.label())
    {
        host.role.clone()
    } else {
        format!("{} - {}", host.role, shown_preferences.kind.label())
    };
    let badge = if host.is_nix {
        crate::icons::SNOWFLAKE
    } else {
        crate::icons::SERVER
    };
    let checked = |enabled: bool| if enabled { " checked" } else { "" };
    let advanced_note = if declared_waiting {
        "The declaration is saved, but this host has not reported the same settings yet."
            .to_string()
    } else if ready {
        "Declared details stay separate from the host-reported applied state.".to_string()
    } else if !host.has_reported {
        "Settings become available after the first host report.".to_string()
    } else if host.is_nix {
        "The pending request is delivered through nixcfg and becomes active only after the host reports it.".to_string()
    } else {
        "The pending request is pulled by pharos-beacon and becomes active only after the host reports it.".to_string()
    };
    let server_selected = if shown_preferences.kind.label() == "server" {
        " selected"
    } else {
        ""
    };
    let workstation_selected = if shown_preferences.kind.label() == "workstation" {
        " selected"
    } else {
        ""
    };
    format!(
        r##"<section class="host-settings-surface" data-color-root data-host="{host_name}" data-ready="{ready}" data-host-reported="{has_reported}" data-is-nix="{is_nix}" data-kind="{kind}" data-manual-down-suppressed="{manual_down_suppressed}" data-target-path="{target_path}" data-target-attribute="{target_attribute}" style="--picked-color:{accent}"><header class="host-settings-identity"><span class="host-settings-badge">{badge}</span><div><h2>{host_name}</h2><p>{role}</p></div></header><section class="host-color-task"><h3>Host color</h3><p>Used to identify this host across Pharos.</p>{setup_note}<div class="host-color-choice"><input class="host-color-well" data-color type="color" value="{accent}" aria-label="Choose a custom host color"{disabled}><div class="preset-row" aria-label="Preset host colors">{presets}</div></div><div class="host-color-actions"><span class="settings-status" data-settings-status data-state="{status_state}" role="status" aria-live="polite">{pending_copy}</span></div></section><section class="settings-disclosures"><details class="settings-disclosure"><summary><span class="settings-disclosure-title">{bell}<strong>Alert preferences</strong></span><span class="settings-disclosure-meta"><span data-alert-summary>{enabled_alerts} on</span>{chevron}</span></summary><div class="settings-disclosure-body"><div class="preference-list"><label class="preference-row"><span><strong>Down alerts</strong><span data-alert-down-copy>{down_copy}</span></span><span class="preference-switch"><input data-alert-down type="checkbox"{down_checked}{down_disabled}><i aria-hidden="true"></i></span></label><label class="preference-row"><span><strong>Backup warnings</strong><span>Warn when backup evidence needs attention.</span></span><span class="preference-switch"><input data-alert-backup type="checkbox"{backup_checked}{disabled}><i aria-hidden="true"></i></span></label><label class="preference-row"><span><strong>Nix freshness warnings</strong><span>Warn when this host falls behind nixcfg.</span></span><span class="preference-switch"><input data-alert-nix type="checkbox"{nix_checked}{disabled}><i aria-hidden="true"></i></span></label></div></div></details><details class="settings-disclosure" data-advanced><summary><span class="settings-disclosure-title">{sliders}<strong>Advanced</strong></span><span class="settings-disclosure-meta"><span>Declarative details</span>{chevron}</span></summary><div class="settings-disclosure-body host-advanced"><p class="host-advanced-note">{advanced_note}</p><div class="host-kind-row"><span class="host-kind-copy"><strong>Host type</strong><span>Controls whether continuous availability is expected.</span></span><select data-host-kind aria-label="Host type"{disabled}><option value="server"{server_selected}>Server</option><option value="workstation"{workstation_selected}>Workstation</option></select></div><div class="host-advanced-meta"><div><span>nixcfg target</span><strong>{target_path}</strong></div><div><span>Attribute</span><strong>{target_attribute}</strong></div></div><pre class="review-output" data-review-output>{initial_output}</pre></div></details></section><footer class="settings-draft-actions"><span class="settings-draft-copy"><strong>Draft changes</strong><span data-draft-summary>Change a setting to prepare a review.</span></span><span class="settings-draft-buttons"><button class="secondary-action" type="button" data-discard-settings disabled>Discard draft</button><button class="primary-action" type="button" data-review-settings disabled{disabled}>Review changes</button></span></footer></section>"##,
        host_name = html_escape(&host.name),
        ready = if ready { "true" } else { "false" },
        has_reported = if host.has_reported { "true" } else { "false" },
        is_nix = if host.is_nix { "true" } else { "false" },
        disabled = if host.has_reported && can_manage_fleet {
            ""
        } else {
            " disabled"
        },
        kind = shown_preferences.kind.label(),
        manual_down_suppressed = shown_preferences.alerts.suppress_down,
        role = html_escape(&role_copy),
        accent = html_escape(accent),
        badge = badge,
        setup_note = setup_note,
        presets = presets,
        status_state = status_state,
        pending_copy = html_escape(pending_copy),
        bell = crate::icons::BELL,
        enabled_alerts = enabled_alerts,
        chevron = crate::icons::CHEVRON_DOWN,
        down_checked = checked(!shown_preferences.suppresses_down_alerts()),
        down_disabled = if !host.has_reported
            || !can_manage_fleet
            || shown_preferences.kind == pharos_core::HostKind::Workstation
        {
            " disabled"
        } else {
            ""
        },
        down_copy = if shown_preferences.kind == pharos_core::HostKind::Workstation {
            "Off automatically for workstations."
        } else {
            "Warn when this host stops reporting."
        },
        backup_checked = checked(!shown_preferences.alerts.suppress_backup),
        nix_checked = checked(!shown_preferences.alerts.suppress_nix_freshness),
        sliders = crate::icons::SLIDERS,
        server_selected = server_selected,
        workstation_selected = workstation_selected,
        advanced_note = html_escape(&advanced_note),
        target_path = html_escape(&host.target_path),
        target_attribute = html_escape(&host.target_attribute),
        initial_output = if ready {
            "No declarative details loaded yet."
        } else {
            "Host preparation has not been delivered yet."
        },
    )
}

fn preset_buttons(current: &str, disabled: bool) -> String {
    let colors = vec![
        current.to_string(),
        "#1f7fb5".to_string(),
        "#25845f".to_string(),
        "#48b8a8".to_string(),
        "#d45d5d".to_string(),
        "#d69b31".to_string(),
    ];
    colors.into_iter().fold(Vec::new(), |mut unique, color| {
        if !unique.iter().any(|existing| existing == &color) {
            unique.push(color);
        }
        unique
    })
        .into_iter()
        .map(|color| {
            let pressed = if color.eq_ignore_ascii_case(current) {
                "true"
            } else {
                "false"
            };
            let disabled = if disabled { " disabled" } else { "" };
            format!(
                r#"<button class="preset" type="button" data-preset="{color}" title="Use {color}" aria-label="Use {color}" aria-pressed="{pressed}" style="--preset-color:{color}"{disabled}></button>"#,
                color = html_escape(&color)
            )
        })
        .collect()
}

fn host_views(
    manifests: &[HostManifest],
    declared_preferences: &BTreeMap<String, HostPreferences>,
    runtime_hosts: &[Host],
) -> Vec<AgoraHostView> {
    let runtime_by_name: BTreeMap<&str, &Host> = runtime_hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let mut views: BTreeMap<String, AgoraHostView> = BTreeMap::new();

    for host in runtime_hosts {
        views.insert(
            host.name.clone(),
            setup_host_view(
                &host.name,
                &host.role,
                host.is_nix,
                true,
                host.preferences.clone(),
                declared_preferences.get(&host.name).cloned(),
                host.requested_preferences.clone(),
            ),
        );
    }

    for manifest in manifests {
        let runtime = runtime_by_name
            .get(manifest.host.name.as_str())
            .copied()
            .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
        let role = manifest
            .host
            .role
            .clone()
            .or_else(|| runtime.map(|host| host.role.clone()))
            .unwrap_or_else(|| "host".to_string());
        let palette = manifest.palette.as_ref();
        let declared = declared_preferences
            .get(&manifest.host.name)
            .cloned()
            .unwrap_or_else(|| manifest.host.preferences.clone());
        let accent = declared
            .accent
            .clone()
            .or_else(|| palette.and_then(palette_accent));
        let settings_ready = accent.is_some();
        let declared_accent = accent.unwrap_or_else(|| DEFAULT_ACCENT.to_string());
        let preferences = runtime
            .map(|host| host.preferences.clone())
            .unwrap_or_default();
        let requested_preferences = runtime.and_then(|host| host.requested_preferences.clone());
        let is_nix = runtime.map(|host| host.is_nix).unwrap_or_else(|| {
            manifest
                .host
                .os
                .as_deref()
                .is_some_and(|os| os.eq_ignore_ascii_case("nixos"))
        });
        views.insert(
            manifest.host.name.clone(),
            AgoraHostView {
                name: manifest.host.name.clone(),
                slug: manifest.slug.clone(),
                role,
                is_nix,
                declared_accent,
                has_reported: runtime.is_some(),
                settings_ready,
                target_path: TARGET_PATH.to_string(),
                target_attribute: format!("hosts.{}", manifest.host.name),
                preferences,
                declared_preferences: Some(declared),
                requested_preferences,
            },
        );
    }

    for (host, declared) in declared_preferences {
        views.entry(host.clone()).or_insert_with(|| {
            setup_host_view(
                host,
                declared.kind.label(),
                true,
                false,
                HostPreferences::default(),
                Some(declared.clone()),
                None,
            )
        });
    }

    views.into_values().collect()
}

fn setup_host_view(
    name: &str,
    role: &str,
    is_nix: bool,
    has_reported: bool,
    preferences: HostPreferences,
    declared_preferences: Option<HostPreferences>,
    requested_preferences: Option<HostPreferences>,
) -> AgoraHostView {
    let slug = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() {
                ch.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>();
    AgoraHostView {
        name: name.to_string(),
        slug,
        role: role.to_string(),
        is_nix,
        declared_accent: declared_preferences
            .as_ref()
            .and_then(|preferences| preferences.accent.clone())
            .unwrap_or_else(|| DEFAULT_ACCENT.to_string()),
        has_reported,
        settings_ready: declared_preferences.is_some(),
        target_path: TARGET_PATH.to_string(),
        target_attribute: format!("hosts.{name}"),
        preferences,
        declared_preferences,
        requested_preferences,
    }
}

fn find_manifest<'a>(manifests: &'a [HostManifest], host: &str) -> Option<&'a HostManifest> {
    manifests
        .iter()
        .find(|manifest| manifest.host.name == host || manifest.slug == host)
}

fn access_allows_host_request(
    access: &AccessGrant,
    manifests: &[HostManifest],
    requested: &str,
) -> bool {
    access.allows_host(requested)
        || find_manifest(manifests, requested).is_some_and(|manifest| {
            access.allows_host(&manifest.host.name) || access.allows_host(&manifest.slug)
        })
}

fn normalize_hex_color(value: &str) -> Result<String, &'static str> {
    let mut value = value.trim();
    if let Some(stripped) = value.strip_prefix('#') {
        value = stripped;
    }
    if value.len() != 6 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err("accent must be a six-digit hex color");
    }
    Ok(format!("#{value}").to_ascii_lowercase())
}

fn palette_accent(palette: &ManifestPalette) -> Option<String> {
    palette
        .accent
        .clone()
        .or_else(|| palette.gradient.get("primary").cloned())
        .map(|value| value.to_ascii_lowercase())
}

fn format_coordinate(value: f64) -> String {
    let mut text = format!("{value:.6}");
    while text.contains('.') && text.ends_with('0') {
        text.pop();
    }
    if text.ends_with('.') {
        text.pop();
    }
    text
}

fn location_mode_key(mode: ManifestLocationMode) -> &'static str {
    match mode {
        ManifestLocationMode::Auto => "auto",
        ManifestLocationMode::DeclaredOverride => "declared-override",
        ManifestLocationMode::DeclaredFallback => "declared-fallback",
        ManifestLocationMode::Hidden => "hidden",
    }
}

fn parse_location_mode(value: &str) -> Result<ManifestLocationMode, &'static str> {
    match value.trim().to_ascii_lowercase().as_str() {
        "auto" | "detected" | "use-detected" => Ok(ManifestLocationMode::Auto),
        "declared-override" | "override" | "manual" | "always-manual" => {
            Ok(ManifestLocationMode::DeclaredOverride)
        }
        "declared-fallback" | "fallback" | "manual-fallback" => {
            Ok(ManifestLocationMode::DeclaredFallback)
        }
        "hidden" | "hide" | "disabled" => Ok(ManifestLocationMode::Hidden),
        _ => Err("location mode must be auto, declared-fallback, declared-override, or hidden"),
    }
}

fn build_palette_proposal(
    manifest: &HostManifest,
    declared: Option<&HostPreferences>,
    proposed: &str,
) -> Result<PaletteProposal, &'static str> {
    let palette = manifest.palette.as_ref();
    let Some(current) = declared
        .and_then(|preferences| preferences.accent.clone())
        .or_else(|| {
            manifest
                .host
                .preferences
                .accent
                .clone()
                .or_else(|| palette.and_then(palette_accent))
        })
    else {
        return Err("host has no declared accent");
    };
    build_palette_proposal_parts(
        &manifest.host.name,
        &manifest.slug,
        palette
            .map(|palette| palette.name.clone())
            .unwrap_or_else(|| format!("custom-{}", manifest.slug)),
        current,
        proposed,
    )
}

fn build_registry_palette_proposal(
    host: &str,
    declared: &HostPreferences,
    proposed: &str,
) -> Result<PaletteProposal, &'static str> {
    let Some(current) = declared.accent.clone() else {
        return Err("host has no declared accent");
    };
    build_palette_proposal_parts(host, host, format!("custom-{host}"), current, proposed)
}

fn build_palette_proposal_parts(
    host: &str,
    slug: &str,
    palette: String,
    current: String,
    proposed: &str,
) -> Result<PaletteProposal, &'static str> {
    let normalized = normalize_hex_color(proposed)?;
    let attribute = format!("hosts.{host}.accent");
    let patch = render_palette_patch(TARGET_PATH, host, &current, &normalized);
    Ok(PaletteProposal {
        schema: "inspr.pharos.agora.palette-proposal.v1",
        status: if current == normalized {
            "no_change"
        } else {
            "draft"
        },
        host: host.to_string(),
        slug: slug.to_string(),
        change: ProposalChange {
            setting: "host.preferences.accent",
            declared: current,
            proposed: normalized,
        },
        target: ProposalTarget {
            repo: "nixcfg",
            path: TARGET_PATH,
            palette,
            attribute,
        },
        janus: ProposalJanus {
            required: false,
            mode: "none".to_string(),
            reason: "declarative metadata proposal only; no privileged host action is executed by Pharos",
        },
        safety: ProposalSafety {
            applies_change: false,
            deploys_host: false,
            next_gate: "dispatch the guarded nixcfg workflow and wait for repository checks",
        },
        patch: ProposalPatch {
            format: "unified-diff",
            value: patch,
        },
    })
}

fn render_palette_patch(target_path: &str, host: &str, current: &str, proposed: &str) -> String {
    format!(
        "diff --git a/{target_path} b/{target_path}\n--- a/{target_path}\n+++ b/{target_path}\n@@ hosts.{host}.accent @@\n-    \"accent\": \"{current}\"\n+    \"accent\": \"{proposed}\"\n"
    )
}

fn build_location_proposal(
    manifest: &HostManifest,
    proposed_mode: ManifestLocationMode,
    label: Option<&str>,
    latitude: Option<&str>,
    longitude: Option<&str>,
) -> Result<LocationProposal, String> {
    let proposed_location = proposed_location(proposed_mode, label, latitude, longitude)?;
    let current = location_summary(manifest.host.location_mode, manifest.host.location.as_ref());
    let proposed = location_summary(proposed_mode, proposed_location.as_ref());
    let status = if manifest.host.location_mode == proposed_mode
        && manifest.host.location == proposed_location
    {
        "no_change"
    } else {
        "draft"
    };
    let patch = render_location_patch(manifest, proposed_mode, proposed_location.as_ref());
    Ok(LocationProposal {
        schema: "inspr.pharos.agora.location-proposal.v1",
        status,
        host: manifest.host.name.clone(),
        slug: manifest.slug.clone(),
        change: LocationProposalChange {
            setting: "host.location",
            declared: current,
            proposed,
        },
        target: LocationProposalTarget {
            repo: "nixcfg",
            path: LOCATION_TARGET_PATH,
            attribute: format!("hosts.{}.location", manifest.slug),
        },
        janus: ProposalJanus {
            required: false,
            mode: "none".to_string(),
            reason: "declarative metadata proposal only; no privileged host action is executed by Pharos",
        },
        safety: ProposalSafety {
            applies_change: false,
            deploys_host: false,
            next_gate: "review and apply in nixcfg, then run nixcfg QA/backup/deploy gates",
        },
        patch: ProposalPatch {
            format: "unified-diff",
            value: patch,
        },
    })
}

fn proposed_location(
    mode: ManifestLocationMode,
    label: Option<&str>,
    latitude: Option<&str>,
    longitude: Option<&str>,
) -> Result<Option<HostLocation>, String> {
    let label = label.and_then(non_empty);
    let latitude = latitude.and_then(non_empty);
    let longitude = longitude.and_then(non_empty);

    match mode {
        ManifestLocationMode::Auto | ManifestLocationMode::Hidden => {
            if latitude.is_some() || longitude.is_some() || label.is_some() {
                return Err("auto and hidden location modes do not accept coordinates".to_string());
            }
            Ok(None)
        }
        ManifestLocationMode::DeclaredOverride | ManifestLocationMode::DeclaredFallback => {
            let (Some(latitude), Some(longitude)) = (latitude, longitude) else {
                return Err("manual location modes require both latitude and longitude".to_string());
            };
            let location = HostLocation {
                latitude: parse_coordinate(latitude, "latitude")?,
                longitude: parse_coordinate(longitude, "longitude")?,
                source: HostLocationSource::Declared,
                accuracy_meters: None,
                precision_meters: None,
                observed_at: None,
                stale: false,
                manual_override: mode == ManifestLocationMode::DeclaredOverride,
                label: label.map(str::to_string),
            };
            location.validate_contract()?;
            Ok(Some(location))
        }
    }
}

fn non_empty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn parse_coordinate(value: &str, label: &'static str) -> Result<f64, String> {
    value
        .parse::<f64>()
        .map_err(|_| format!("{label} must be a decimal number"))
}

fn location_summary(mode: ManifestLocationMode, location: Option<&HostLocation>) -> String {
    let mut summary = location_mode_key(mode).to_string();
    if let Some(location) = location {
        summary.push_str(&format!(
            " ({}, {})",
            format_coordinate(location.latitude),
            format_coordinate(location.longitude)
        ));
        if let Some(label) = location.label.as_deref().and_then(non_empty) {
            summary.push_str(&format!(" {label}"));
        }
    }
    summary
}

fn render_location_patch(
    manifest: &HostManifest,
    proposed_mode: ManifestLocationMode,
    location: Option<&HostLocation>,
) -> String {
    let target_path = LOCATION_TARGET_PATH;
    let slug = &manifest.slug;
    let mode = location_mode_key(proposed_mode);
    let body = if let Some(location) = location {
        let label = location
            .label
            .as_deref()
            .and_then(non_empty)
            .map(|label| format!("\n      label = \"{}\";", escape_nix_string(label)))
            .unwrap_or_default();
        format!(
            "    locationMode = \"{mode}\";\n    location = {{\n      latitude = {};\n      longitude = {};\n      source = \"declared\";\n      manual_override = {};{label}\n    }};",
            format_coordinate(location.latitude),
            format_coordinate(location.longitude),
            if location.manual_override { "true" } else { "false" },
        )
    } else {
        format!("    locationMode = \"{mode}\";\n    location = null;")
    };
    let added_body = body
        .lines()
        .map(|line| format!("+{line}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "diff --git a/{target_path} b/{target_path}\n--- a/{target_path}\n+++ b/{target_path}\n@@\n   {slug} = {{\n{body}\n   }};\n",
        body = added_body
    )
}

fn escape_nix_string(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::{
        Host, HostAlertPreferences, HostKind, ManifestHost, ManifestLocationMode, ManifestPalette,
        ManifestPolicy, NixFreshness, PrivilegedActionMode, PrivilegedActions, RuntimeStateOwner,
        HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION,
    };

    fn manifest() -> HostManifest {
        HostManifest {
            schema: HOST_MANIFEST_SCHEMA.to_string(),
            version: HOST_MANIFEST_VERSION,
            generated_by: Some("nixcfg".to_string()),
            slug: "hsb8".to_string(),
            storage_key: Some("hostdash.hsb8".to_string()),
            host: ManifestHost {
                name: "hsb8".to_string(),
                role: Some("parents' home".to_string()),
                os: Some("NixOS".to_string()),
                fqdn: Some("hsb8.lan".to_string()),
                ip: Some("192.168.1.100".to_string()),
                site: None,
                preferences: Default::default(),
                location_mode: ManifestLocationMode::Auto,
                location: None,
                title: None,
                heading: None,
                eyebrow: None,
                subtitle: None,
                access: BTreeMap::new(),
            },
            meta: vec![],
            palette: Some(ManifestPalette {
                name: "custom-hsb8".to_string(),
                display_name: Some("Custom (hsb8)".to_string()),
                category: Some("custom".to_string()),
                description: Some("User-defined color for hsb8".to_string()),
                accent: Some("#e09051".to_string()),
                gradient: BTreeMap::from([("primary".to_string(), "#e09051".to_string())]),
                text: json!({}),
                zellij: json!({ "bg": "#e09051", "frame": "#e09051" }),
            }),
            wings: vec![],
            services: vec![],
            policy: ManifestPolicy {
                declared_only: true,
                runtime_state_owner: RuntimeStateOwner::Pharos,
                privileged_actions: PrivilegedActions {
                    mode: PrivilegedActionMode::None,
                    janus_required: false,
                },
            },
        }
    }

    fn runtime_host(name: &str) -> Host {
        Host {
            name: name.to_string(),
            role: "server".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(crate::now_unix()),
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            inbound_rtt: None,
            location: None,
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
                nixpkgs_age_days: None,
                nixpkgs_channel: None,
                secondary_nixpkgs: None,
                deployment_evidence: None,
                nixcfg_comparison: None,
                nixpkgs_comparison: None,
            },
            kernel: None,
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
        }
    }

    #[test]
    fn palette_proposal_generates_reviewable_nixcfg_patch() {
        let proposal = build_palette_proposal(&manifest(), None, "#48b8a8").expect("proposal");

        assert_eq!(proposal.schema, "inspr.pharos.agora.palette-proposal.v1");
        assert_eq!(proposal.status, "draft");
        assert_eq!(proposal.target.repo, "nixcfg");
        assert_eq!(proposal.target.path, TARGET_PATH);
        assert_eq!(proposal.target.attribute, "hosts.hsb8.accent");
        assert!(!proposal.janus.required);
        assert!(!proposal.safety.applies_change);
        assert!(proposal
            .patch
            .value
            .contains("-    \"accent\": \"#e09051\""));
        assert!(proposal
            .patch
            .value
            .contains("+    \"accent\": \"#48b8a8\""));
    }

    #[test]
    fn registry_only_declaration_drives_settings_and_review() {
        let declared = HostPreferences {
            accent: Some("#9868d0".to_string()),
            kind: HostKind::Workstation,
            alerts: HostAlertPreferences::default(),
        };
        let declarations = BTreeMap::from([("gpc0".to_string(), declared.clone())]);
        let runtime = runtime_host("gpc0");

        let views = host_views(&[], &declarations, std::slice::from_ref(&runtime));
        assert_eq!(views.len(), 1);
        assert_eq!(views[0].declared_preferences.as_ref(), Some(&declared));
        assert!(views[0].settings_ready);

        let html = render_page(&[], &declarations, &[runtime], Some("gpc0"), "markus", true);
        assert!(html.contains(r#"data-host="gpc0" data-ready="true""#));
        assert!(html.contains("Change declared. Waiting for the host."));
        assert!(!html.contains("Prepare host settings"));

        let proposal = build_registry_palette_proposal("gpc0", &declared, "#48b8a8")
            .expect("registry proposal");
        assert_eq!(proposal.target.attribute, "hosts.gpc0.accent");
        assert!(proposal
            .patch
            .value
            .contains("-    \"accent\": \"#9868d0\""));
    }

    #[test]
    fn location_proposal_generates_reviewable_nixcfg_patch() {
        let proposal = build_location_proposal(
            &manifest(),
            ManifestLocationMode::DeclaredFallback,
            Some("Parents' home"),
            Some("48.32"),
            Some("15.92"),
        )
        .expect("proposal");

        assert_eq!(proposal.schema, "inspr.pharos.agora.location-proposal.v1");
        assert_eq!(proposal.status, "draft");
        assert_eq!(proposal.target.repo, "nixcfg");
        assert_eq!(proposal.target.path, LOCATION_TARGET_PATH);
        assert_eq!(proposal.target.attribute, "hosts.hsb8.location");
        assert!(!proposal.janus.required);
        assert!(!proposal.safety.applies_change);
        assert!(proposal
            .patch
            .value
            .contains("+    locationMode = \"declared-fallback\";"));
        assert!(proposal.patch.value.contains("+      latitude = 48.32;"));
        assert!(proposal.patch.value.contains("+      longitude = 15.92;"));
        assert!(proposal
            .patch
            .value
            .contains("+      manual_override = false;"));
    }

    #[test]
    fn location_proposal_rejects_ambiguous_coordinates() {
        let error = build_location_proposal(
            &manifest(),
            ManifestLocationMode::DeclaredOverride,
            Some("Parents' home"),
            Some("48.32"),
            None,
        )
        .expect_err("partial coordinates rejected");
        assert_eq!(
            error,
            "manual location modes require both latitude and longitude"
        );

        let error = build_location_proposal(
            &manifest(),
            ManifestLocationMode::Hidden,
            None,
            Some("48.32"),
            Some("15.92"),
        )
        .expect_err("hidden coordinates rejected");
        assert_eq!(
            error,
            "auto and hidden location modes do not accept coordinates"
        );
    }

    #[test]
    fn settings_page_uses_shared_shell_and_simple_color_task() {
        let runtime = runtime_host("hsb8");
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime],
            None,
            "markus",
            true,
        );

        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains(r#"<aside class="sidebar" aria-label="primary navigation""#));
        assert!(html.contains(r#"href="/agora" aria-current="page""#));
        assert!(html.contains(r#"<div class="top">"#));
        assert!(html.contains(r#"<div class="brand"><h1>Host settings</h1>"#));
        assert!(html.contains("Color and alerts per host"));
        assert!(html.contains(r#"class="asof" data-as-of"#));
        assert!(html.contains(r#"<select data-host-picker aria-label="Choose host">"#));
        assert!(html.contains(r#"<option value="hsb8" selected>"#));
        assert_eq!(html.matches(r#"type="color""#).count(), 1);
        assert!(html.contains("Review changes"));
        assert!(html.contains("Discard draft"));
        assert!(html.contains("Draft only — no request sent."));
        assert!(html.contains("Alert preferences"));
        assert!(html.contains("Down alerts"));
        assert!(html.contains("Backup warnings"));
        assert!(html.contains("Nix freshness warnings"));
        assert_eq!(html.matches(r#"class="preference-switch""#).count(), 3);
        assert!(html.contains(r#"<details class="settings-disclosure" data-advanced>"#));
        assert!(!html.contains(r#"<details class="settings-disclosure" open"#));
        assert!(html.contains("hosts.hsb8"));
        assert!(html.contains(r#"<select data-host-kind aria-label="Host type""#));
        assert!(html.contains(r#"data-review-settings"#));
        assert!(html.contains(r#"data-discard-settings"#));
        assert!(!html.contains(r#"data-save-color"#));
        assert!(!html.contains(r#"data-save-alerts"#));
        assert!(!html.contains(r#"data-save-kind"#));
        assert!(html.contains("Pharos will not close or merge a nixcfg proposal."));
        assert!(!html.contains(r#"class="settings-ia""#));
        assert!(!html.contains(r#"class="settings-workspace""#));
        assert!(!html.contains(r#"class="settings-host-table""#));
        assert!(!html.contains(r#"class="preview-card""#));
        assert!(!html.contains("data-hex"));
        assert!(!html.contains("Color code"));
        assert!(!html.contains("Advanced review"));
        assert!(!html.contains("Host colors</"));
        assert!(!html.contains(r#"class="rail""#));
        assert!(!html.contains("Services</button>"));
        assert!(!html.contains("Access</button>"));
        assert!(!html.contains("stored-token-hash"));
    }

    #[test]
    fn workstation_settings_explain_automatic_down_policy_and_preserve_manual_choice() {
        let mut declaration = manifest();
        declaration.host.preferences.kind = HostKind::Workstation;
        let mut runtime = runtime_host("hsb8");
        runtime.preferences.kind = HostKind::Workstation;

        let html = render_page(
            &[declaration],
            &BTreeMap::new(),
            &[runtime],
            Some("hsb8"),
            "markus",
            true,
        );

        assert!(html.contains(r#"data-kind="workstation" data-manual-down-suppressed="false""#));
        assert!(html.contains("Off automatically for workstations."));
        assert!(html.contains(r#"<input data-alert-down type="checkbox" disabled>"#));
        assert!(html.contains(r#"<span data-alert-summary>2 on</span>"#));
        assert!(
            html.contains("let manualDownSuppressed=root.dataset.manualDownSuppressed==='true'")
        );
        assert!(html.contains("suppress_down:manualDownSuppressed"));
        assert!(html.contains(
            "kind?.addEventListener('change',()=>{syncDownAlertPolicy();updateDraftState()})"
        ));

        let server_html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime_host("hsb8")],
            Some("hsb8"),
            "markus",
            true,
        );
        assert!(server_html.contains(r#"<input data-alert-down type="checkbox" checked>"#));
        assert!(server_html.contains("Warn when this host stops reporting."));
        assert!(server_html.contains(r#"<span data-alert-summary>3 on</span>"#));
    }

    #[test]
    fn settings_workflow_poll_pauses_and_resumes_without_multiplying() {
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime_host("hsb8")],
            Some("hsb8"),
            "markus",
            true,
        );

        assert!(html.contains("function pauseSettingsWorkflowPoll()"));
        assert!(html.contains("function stopSettingsWorkflowPoll()"));
        assert!(html.contains("function replaceSettingsWorkflowHtml(root,workflowHtml)"));
        assert!(html.contains("if(nextAdvanced&&keepAdvancedOpen)nextAdvanced.open=true;"));
        assert!(html.contains(
            "if(restoreSummaryFocus)nextAdvanced?.querySelector('summary')?.focus({preventScroll:true});"
        ));
        assert!(html.contains(
            "if(initialWorkflowOpen)requestAnimationFrame(()=>dialog.querySelector('[data-host-action-close]')?.focus())"
        ));
        assert!(html.contains("function scheduleSettingsWorkflowPoll(id,delay=2000)"));
        assert!(html.contains("if(settingsWorkflow.terminal)return"));
        assert!(html.contains("settingsWorkflow.timer=null;\n    pollSettingsWorkflow(id);"));
        assert!(html.contains("if(document.hidden){pauseSettingsWorkflowPoll();return}"));
        assert!(html.contains(
            "window.addEventListener('focus',()=>{if(settingsWorkflow.id&&!settingsWorkflow.terminal)scheduleSettingsWorkflowPoll(settingsWorkflow.id,0)})"
        ));
        assert!(
            html.contains("window.addEventListener('offline',()=>{pauseSettingsWorkflowPoll()})")
        );
        assert!(html.contains("window.addEventListener('pagehide',stopSettingsWorkflowPoll)"));
        assert!(!html.contains("setInterval("));
    }

    #[test]
    fn settings_workflow_requires_an_explicit_legacy_continuation() {
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime_host("hsb8")],
            Some("hsb8"),
            "markus",
            true,
        );

        assert!(html.contains(
            "const actionRequired=['acknowledge','apply_declared','confirm','retry','recover','continue','restart']"
        ));
        assert!(html
            .contains("else if(!actionRequired)scheduleSettingsWorkflowPoll(settingsWorkflow.id)"));
        assert!(html.contains(":action==='continue'?'continue-settings-dispatch'"));
        assert!(html.contains("'Continuing the saved request through nixcfg…'"));
        assert!(html.contains("'Ready to continue the saved request'"));
    }

    #[test]
    fn settings_workflow_drives_linked_apply_without_losing_the_parent_run() {
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime_host("hsb8")],
            Some("hsb8"),
            "markus",
            true,
        );

        assert!(html.contains("action.target_run_id"));
        assert!(html.contains("primary.dataset.workflowTargetRunId"));
        assert!(html.contains("settingsWorkflow.id=settingsWorkflow.id||job.id"));
        assert!(html.contains(
            "action==='apply_declared'?'apply-declared'\n      :action==='confirm'?'confirm'\n      :action==='retry'?'retry'"
        ));
        assert!(html.contains("action==='recover'&&targetRunId?'recover'"));
        assert!(html.contains("JSON.stringify({confirmation:root.dataset.host,attended:true})"));
        assert!(html.contains(
            "if(data.job?.id===settingsWorkflow.id)renderSettingsWorkflow(data);\n      else scheduleSettingsWorkflowPoll(settingsWorkflow.id,0)"
        ));
        assert!(html.contains("const revision=settingsWorkflowRevision(data)"));
        assert!(html.contains("data?.workflow_html||''"));
        assert!(html.contains(
            "primary.disabled=!settingsCanManageFleet()||!settingsApplyConfirmationReady()"
        ));
        assert!(html.contains("guardedAction&&!settingsCanManageFleet()"));
    }

    #[test]
    fn guarded_settings_controls_are_read_only_without_fleet_operator_access() {
        let html = render_page_with_access(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime_host("hsb8")],
            Some("hsb8"),
            "viewer",
            true,
            false,
        );

        assert!(html.contains(r#"data-can-manage-fleet="false""#));
        assert!(html.contains("Fleet operator access is required for this guarded action"));
        assert!(html.contains("if(guardedAction&&!settingsCanManageFleet())return"));
        assert!(html.contains("action==='recover'&&Boolean(targetRunId)"));
        assert!(html.contains(r#"data-access-path data-scope="settings""#));
        assert!(html.contains("Fleet manager access required"));
        assert!(html.contains("Pharos administrator"));
        assert!(html.contains(
            r##"data-color type="color" value="#e09051" aria-label="Choose a custom host color" disabled"##
        ));
        assert!(html.contains(r##"data-preset="#1f7fb5""##));
        assert!(html.contains(r##"style="--preset-color:#1f7fb5" disabled"##));
    }

    #[test]
    fn settings_page_selects_requested_host() {
        let mut other = manifest();
        other.slug = "csb1".to_string();
        other.host.name = "csb1".to_string();
        other.host.role = Some("control server".to_string());
        if let Some(palette) = other.palette.as_mut() {
            palette.name = "custom-csb1".to_string();
            palette.accent = Some("#48b8a8".to_string());
            palette
                .gradient
                .insert("primary".to_string(), "#48b8a8".to_string());
        }

        let html = render_page(
            &[other, manifest()],
            &BTreeMap::new(),
            &[],
            Some("hsb8"),
            "markus",
            true,
        );

        assert!(html.contains(r#"<option value="hsb8" selected>"#));
        assert!(!html.contains(r#"<option value="csb1" selected>"#));
        assert!(html.contains(r#"data-host="hsb8""#));
        assert!(html.contains("--picked-color:#e09051"));
    }

    #[test]
    fn settings_page_keeps_shared_shell_empty_state() {
        let html = render_page(&[], &BTreeMap::new(), &[], None, "markus", true);

        assert!(html.contains(r#"<div class="brand"><h1>Host settings</h1>"#));
        assert!(html.contains(r#"href="/agora" aria-current="page""#));
        assert!(html.contains(r#"<section class="empty-settings">"#));
        assert!(html.contains("No hosts yet"));
        assert!(html.contains("Once a host reports to Pharos"));
        assert!(!html.contains("data-host-picker"));
        assert!(!html.contains("data-color-root"));
    }

    #[test]
    fn runtime_host_without_declared_settings_gets_setup_flow() {
        let runtime = runtime_host("csb0");
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[runtime],
            Some("csb0"),
            "markus",
            true,
        );

        assert!(html.contains("Prepare host settings"));
        assert!(html.contains("Editing creates a local draft for csb0"));
        assert!(html.contains(r#"<option value="csb0" selected>"#));
        assert!(html.contains(r#"data-ready="false""#));
        assert!(html.contains(r#"data-host-reported="true""#));
        assert!(html.contains(r#"data-host="csb0""#));
        assert!(!html.contains("must report once"));
        assert!(html.contains(r#"data-review-settings disabled"#));
    }

    #[test]
    fn agora_access_allows_declared_host_name_or_slug_only_when_granted() {
        let manifest = manifest();
        let hsb8_only = AccessGrant::limited(["hsb8"], true);
        let csb1_only = AccessGrant::limited(["csb1"], true);
        let no_agora = AccessGrant::limited(["hsb8"], false);

        assert!(access_allows_host_request(
            &hsb8_only,
            std::slice::from_ref(&manifest),
            "hsb8"
        ));
        assert!(access_allows_host_request(
            &hsb8_only,
            std::slice::from_ref(&manifest),
            &manifest.slug
        ));
        assert!(!access_allows_host_request(
            &csb1_only,
            std::slice::from_ref(&manifest),
            "hsb8"
        ));
        assert!(!no_agora.can_agora());
    }

    #[test]
    fn unknown_requested_host_gets_setup_placeholder() {
        let html = render_page(
            &[manifest()],
            &BTreeMap::new(),
            &[],
            Some("csb0"),
            "markus",
            true,
        );

        assert!(html.contains("Waiting for first report"));
        assert!(html.contains("csb0 must report once before settings can be requested"));
        assert!(html.contains(r#"<option value="csb0" selected>"#));
        assert!(html.contains(r#"data-host-reported="false""#));
        assert!(html.contains(r#"data-review-settings disabled"#));
    }

    #[test]
    fn host_preferences_request_rejects_unknown_fields() {
        let valid: HostPreferencesRequest = serde_json::from_value(json!({
            "host": "hsb8",
            "preferences": {
                "accent": "#48b8a8",
                "kind": "server",
                "alerts": {
                    "suppress_down": false,
                    "suppress_backup": true,
                    "suppress_nix_freshness": false
                }
            }
        }))
        .expect("known request fields parse");
        assert_eq!(valid.host, "hsb8");
        assert!(valid.preferences.alerts.suppress_backup);

        assert!(serde_json::from_value::<HostPreferencesRequest>(json!({
            "host": "hsb8",
            "preferences": {},
            "unexpected": true
        }))
        .is_err());
        assert!(serde_json::from_value::<HostPreferencesRequest>(json!({
            "host": "hsb8",
            "preferences": {
                "alerts": { "unexpected": true }
            }
        }))
        .is_err());
    }

    #[test]
    fn invalid_accent_is_rejected() {
        assert!(normalize_hex_color("#48b8a8").is_ok());
        assert!(normalize_hex_color("48B8A8").is_ok());
        assert!(normalize_hex_color("#nothex").is_err());
        assert!(normalize_hex_color("#12345").is_err());
    }
}
