//! Per-host settings surface.
//!
//! Operator changes are persisted as pending requests. Applied state remains
//! host-owned and changes only after a host reports the accepted preferences.

use std::collections::BTreeMap;

use axum::extract::{Query, State};
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
    html_escape, AppState, ShellContext,
};

const DEFAULT_ACCENT: &str = "#1f7fb5";
const TARGET_PATH: &str = "modules/uzumaki/theme/theme-palettes.nix";
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
.host-color-actions{display:flex;align-items:center;gap:12px;margin-top:22px}.host-color-actions .primary-action{min-width:126px}.settings-status{min-width:0;color:var(--muted);font-size:12px}.settings-status[data-state="pending"]{color:#9a5b00}.settings-status[data-state="applied"]{color:var(--live)}.settings-status[data-state="error"]{color:var(--down)}
.host-setup-note{margin-top:18px;padding:10px 12px;border-left:3px solid var(--sun);background:rgba(255,248,234,.62);color:var(--muted);font-size:12px}.host-setup-note strong{display:block;margin-bottom:2px;color:var(--ink)}
.settings-disclosures{border-top:1px solid rgba(210,226,234,.86);border-bottom:1px solid rgba(210,226,234,.86)}.settings-disclosure+.settings-disclosure{border-top:1px solid rgba(210,226,234,.86)}
.settings-disclosure>summary{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:14px;min-height:58px;padding:0 14px;list-style:none;cursor:pointer}.settings-disclosure>summary::-webkit-details-marker{display:none}.settings-disclosure-title,.settings-disclosure-meta{display:flex;align-items:center;gap:10px;min-width:0}.settings-disclosure-title>.ico{width:17px;height:17px;color:#315d7c}.settings-disclosure-title strong{font-size:13px}.settings-disclosure-meta{color:var(--muted);font-size:12px}.settings-disclosure-meta>.ico{width:15px;height:15px;transition:transform .16s ease}.settings-disclosure[open] .settings-disclosure-meta>.ico{transform:rotate(180deg)}
.settings-disclosure-body{padding:0 14px 20px}.preference-list{display:grid}.preference-row{display:flex;align-items:center;justify-content:space-between;gap:18px;min-height:54px;border-top:1px solid rgba(214,226,234,.62)}.preference-row:first-child{border-top:0}.preference-row strong{display:block;font-size:13px}.preference-row span{display:block;margin-top:2px;color:var(--muted);font-size:11px}.preference-switch{position:relative;flex:0 0 auto;width:38px;height:22px}.preference-switch input{position:absolute;opacity:0;pointer-events:none}.preference-switch i{position:absolute;inset:0;border:1px solid rgba(137,151,163,.38);border-radius:999px;background:#edf2f4;transition:.16s}.preference-switch i:after{content:"";position:absolute;top:3px;left:3px;width:14px;height:14px;border-radius:50%;background:#fff;box-shadow:0 1px 4px rgba(45,75,95,.18);transition:.16s}.preference-switch input:checked+i{border-color:rgba(37,132,95,.36);background:rgba(37,132,95,.78)}.preference-switch input:checked+i:after{transform:translateX(16px)}.preference-switch input:focus-visible+i{outline:2px solid rgba(31,127,181,.42);outline-offset:2px}
.preference-actions{display:flex;align-items:center;gap:12px;margin-top:14px}.preference-actions .primary-action{min-height:38px;background:#fff;color:var(--ink)}.preference-actions .primary-action:hover{background:#f4fafb}
.host-advanced{display:grid;gap:12px}.host-advanced-note{margin:0;color:var(--muted);font-size:12px}.host-advanced-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}.host-advanced-meta div{min-width:0;padding:9px 10px;border:1px solid rgba(210,226,234,.82);border-radius:7px;background:rgba(247,252,253,.72)}.host-advanced-meta span,.host-advanced-meta strong{display:block;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.host-advanced-meta span{color:var(--muted);font-size:10px}.host-advanced-meta strong{margin-top:2px;font-size:11px}.host-advanced .review-output{min-height:120px;max-height:260px}
.empty-settings{width:min(840px,100%);margin:26px auto 0;box-shadow:none}
@media (max-width:640px){.host-picker{grid-template-columns:1fr;gap:6px}.host-settings-surface{margin-top:18px}.host-settings-identity,.host-color-task,.settings-disclosure>summary,.settings-disclosure-body{padding-left:4px;padding-right:4px}.host-color-choice{gap:13px}.host-color-actions,.preference-actions{align-items:stretch;flex-direction:column}.host-color-actions .primary-action,.preference-actions .primary-action{width:100%}.host-advanced-meta{grid-template-columns:1fr}}
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
    let runtime_hosts: Vec<_> = state
        .store
        .list()
        .into_iter()
        .filter(|host| access.allows_host(&host.name))
        .collect();
    Html(render_page(
        &manifests,
        &runtime_hosts,
        query.host.as_deref(),
        &user_label,
        state.auth.is_some(),
    ))
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
    let Some(manifest) = find_manifest(state.manifests.manifests(), &query.host) else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "host is not declared in the manifest registry" })),
        );
    };

    let proposed = match normalize_hex_color(&query.accent) {
        Ok(color) => color,
        Err(error) => {
            return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
        }
    };

    match build_palette_proposal(manifest, &proposed) {
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
        || !access.can_agora()
        || !access_allows_host_request(&access, state.manifests.manifests(), host_name)
    {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "Host settings access is not granted for this host" })),
        );
    }

    if let Some(accent) = request.preferences.accent.as_deref() {
        request.preferences.accent = match normalize_hex_color(accent) {
            Ok(accent) => Some(accent),
            Err(error) => {
                return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
            }
        };
    }
    if let Err(error) = request.preferences.validate_contract() {
        return (StatusCode::BAD_REQUEST, Json(json!({ "error": error })));
    }

    match state
        .store
        .request_preferences(host_name, request.preferences)
    {
        Ok(host) => {
            let status = if host.requested_preferences.is_some() {
                "pending_host"
            } else {
                "applied"
            };
            let delivery = if host.is_nix { "nixcfg" } else { "beacon_pull" };
            (
                StatusCode::OK,
                Json(json!({
                    "status": status,
                    "host": host.name,
                    "delivery": delivery,
                    "applied": host.preferences,
                    "requested": host.requested_preferences,
                })),
            )
        }
        Err("host not found") => (
            StatusCode::CONFLICT,
            Json(json!({ "error": "The host must report once before settings can be requested" })),
        ),
        Err(error) => (StatusCode::BAD_REQUEST, Json(json!({ "error": error }))),
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

fn render_page(
    manifests: &[HostManifest],
    runtime_hosts: &[Host],
    requested_host: Option<&str>,
    user_label: &str,
    logout_enabled: bool,
) -> String {
    let mut hosts = host_views(manifests, runtime_hosts);
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
            ));
            hosts.len() - 1
        }
        (None, None) => 0,
    };

    let head = crate::head_with_extra(AGORA_CSS);
    let sidebar = crate::sidebar(user_label, logout_enabled, "settings");

    if hosts.is_empty() {
        return format!(
            r#"{head}{sidebar}<main class="settings-main">{header}<section class="empty-settings"><h2>No hosts yet</h2><p>Once a host reports to Pharos, its settings will appear here.</p></section></main></div></body></html>"#,
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
        render_ready_content(selected)
    } else {
        render_setup_content(selected)
    };

    format!(
        r##"{head}{sidebar}<main class="settings-main">{header}{host_table}{content}</main><script>
document.querySelector('[data-host-picker]')?.addEventListener('change',event=>{{
  window.location.assign('/agora?host='+encodeURIComponent(event.target.value));
}});
const root=document.querySelector('[data-color-root]');
if(root){{
  const color=root.querySelector('[data-color]');
  const output=root.querySelector('[data-review-output]');
  const status=root.querySelector('[data-settings-status]');
  const alertSummary=root.querySelector('[data-alert-summary]');
  const down=root.querySelector('[data-alert-down]');
  const backup=root.querySelector('[data-alert-backup]');
  const nix=root.querySelector('[data-alert-nix]');
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
  function requestedPreferences(){{
    return {{
      accent:color?.value||null,
      kind:root.dataset.kind||'server',
      alerts:{{
        suppress_down:!down?.checked,
        suppress_backup:!backup?.checked,
        suppress_nix_freshness:!nix?.checked,
      }},
    }};
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
  async function savePreferences(button){{
    button.disabled=true;
    setStatus('pending','Saving request...');
    try{{
      const res=await fetch('/agora/requests/host-preferences.json',{{
        method:'POST',
        headers:{{Accept:'application/json','Content-Type':'application/json'}},
        body:JSON.stringify({{host:root.dataset.host,preferences:requestedPreferences()}}),
      }});
      const data=await res.json();
      if(!res.ok)throw new Error(data.error||'Request failed');
      if(data.status==='applied')setStatus('applied','Already active on this host.');
      else setStatus('pending',data.delivery==='nixcfg'?'Saved. Waiting for nixcfg delivery.':'Saved. Waiting for the host.');
      await loadReview();
    }}catch(error){{setStatus('error',error.message||'Request failed')}}
    finally{{button.disabled=false}}
  }}
  color?.addEventListener('input',event=>setPicked(event.target.value));
  root.querySelectorAll('[data-preset]').forEach(button=>button.addEventListener('click',()=>setPicked(button.dataset.preset)));
  root.querySelector('[data-save-color]')?.addEventListener('click',event=>savePreferences(event.currentTarget));
  root.querySelector('[data-save-alerts]')?.addEventListener('click',event=>savePreferences(event.currentTarget));
  [down,backup,nix].forEach(input=>input?.addEventListener('change',updateAlertSummary));
  setPicked(color?.value||'{accent}');
  updateAlertSummary();
}}
</script></div></body></html>"##,
        header = crate::page_header(
            "Host settings",
            "Color and alerts per host",
            crate::now_unix()
        ),
        host_table = host_table,
        accent = html_escape(&selected.declared_accent)
    )
}

fn render_ready_content(host: &AgoraHostView) -> String {
    render_color_panel(host, true)
}

fn render_setup_content(host: &AgoraHostView) -> String {
    render_color_panel(host, false)
}

fn render_host_table(hosts: &[AgoraHostView], selected_index: usize) -> String {
    let options = hosts
        .iter()
        .enumerate()
        .map(|(idx, host)| render_host_row(host, idx == selected_index))
        .collect::<String>();
    let selected = &hosts[selected_index];
    let accent = selected
        .requested_preferences
        .as_ref()
        .and_then(|preferences| preferences.accent.as_deref())
        .or(selected.preferences.accent.as_deref())
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

fn render_color_panel(host: &AgoraHostView, ready: bool) -> String {
    let shown_preferences = host
        .requested_preferences
        .as_ref()
        .unwrap_or(&host.preferences);
    let accent = shown_preferences
        .accent
        .as_deref()
        .unwrap_or(&host.declared_accent);
    let presets = preset_buttons(accent);
    let setup_note = if ready {
        String::new()
    } else if host.has_reported {
        format!(
            r#"<div class="host-setup-note"><strong>Prepare host settings</strong>Saving creates a pending request for {name}. It becomes active only after the host applies and reports it.</div>"#,
            name = html_escape(&host.name)
        )
    } else {
        format!(
            r#"<div class="host-setup-note"><strong>Waiting for first report</strong>{name} must report once before settings can be requested.</div>"#,
            name = html_escape(&host.name)
        )
    };
    let enabled_alerts = [
        !shown_preferences.alerts.suppress_down,
        !shown_preferences.alerts.suppress_backup,
        !shown_preferences.alerts.suppress_nix_freshness,
    ]
    .into_iter()
    .filter(|enabled| *enabled)
    .count();
    let pending = host.requested_preferences.is_some();
    let pending_copy = if pending {
        if host.is_nix {
            "Saved. Waiting for nixcfg delivery."
        } else {
            "Saved. Waiting for the host."
        }
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
    let advanced_note = if ready {
        "Declared details stay separate from the host-reported applied state.".to_string()
    } else if !host.has_reported {
        "Settings become available after the first host report.".to_string()
    } else if host.is_nix {
        "The pending request is delivered through nixcfg and becomes active only after the host reports it.".to_string()
    } else {
        "The pending request is pulled by pharos-beacon and becomes active only after the host reports it.".to_string()
    };
    format!(
        r##"<section class="host-settings-surface" data-color-root data-host="{host_name}" data-ready="{ready}" data-host-reported="{has_reported}" data-kind="{kind}" style="--picked-color:{accent}"><header class="host-settings-identity"><span class="host-settings-badge">{badge}</span><div><h2>{host_name}</h2><p>{role}</p></div></header><section class="host-color-task"><h3>Host color</h3><p>Used to identify this host across Pharos.</p>{setup_note}<div class="host-color-choice"><input class="host-color-well" data-color type="color" value="{accent}" aria-label="Choose a custom host color"{disabled}><div class="preset-row" aria-label="Preset host colors">{presets}</div></div><div class="host-color-actions"><button class="primary-action" type="button" data-save-color{disabled}>{color_action}</button><span class="settings-status" data-settings-status data-state="{status_state}" role="status" aria-live="polite">{pending_copy}</span></div></section><section class="settings-disclosures"><details class="settings-disclosure"><summary><span class="settings-disclosure-title">{bell}<strong>Alert preferences</strong></span><span class="settings-disclosure-meta"><span data-alert-summary>{enabled_alerts} on</span>{chevron}</span></summary><div class="settings-disclosure-body"><div class="preference-list"><label class="preference-row"><span><strong>Down alerts</strong><span>Warn when this host stops reporting.</span></span><span class="preference-switch"><input data-alert-down type="checkbox"{down_checked}{disabled}><i aria-hidden="true"></i></span></label><label class="preference-row"><span><strong>Backup warnings</strong><span>Warn when backup evidence needs attention.</span></span><span class="preference-switch"><input data-alert-backup type="checkbox"{backup_checked}{disabled}><i aria-hidden="true"></i></span></label><label class="preference-row"><span><strong>Nix freshness warnings</strong><span>Warn when this host falls behind nixcfg.</span></span><span class="preference-switch"><input data-alert-nix type="checkbox"{nix_checked}{disabled}><i aria-hidden="true"></i></span></label></div><div class="preference-actions"><button class="primary-action" type="button" data-save-alerts{disabled}>Save alert preferences</button></div></div></details><details class="settings-disclosure" data-advanced><summary><span class="settings-disclosure-title">{sliders}<strong>Advanced</strong></span><span class="settings-disclosure-meta"><span>Declarative details</span>{chevron}</span></summary><div class="settings-disclosure-body host-advanced"><p class="host-advanced-note">{advanced_note}</p><div class="host-advanced-meta"><div><span>nixcfg target</span><strong>{target_path}</strong></div><div><span>Attribute</span><strong>{target_attribute}</strong></div></div><pre class="review-output" data-review-output>{initial_output}</pre></div></details></section></section>"##,
        host_name = html_escape(&host.name),
        ready = if ready { "true" } else { "false" },
        has_reported = if host.has_reported { "true" } else { "false" },
        disabled = if host.has_reported { "" } else { " disabled" },
        kind = shown_preferences.kind.label(),
        role = html_escape(&role_copy),
        accent = html_escape(accent),
        badge = badge,
        setup_note = setup_note,
        presets = presets,
        color_action = if ready {
            "Save color"
        } else if host.has_reported {
            "Prepare host settings"
        } else {
            "Waiting for host"
        },
        status_state = status_state,
        pending_copy = html_escape(pending_copy),
        bell = crate::icons::BELL,
        enabled_alerts = enabled_alerts,
        chevron = crate::icons::CHEVRON_DOWN,
        down_checked = checked(!shown_preferences.alerts.suppress_down),
        backup_checked = checked(!shown_preferences.alerts.suppress_backup),
        nix_checked = checked(!shown_preferences.alerts.suppress_nix_freshness),
        sliders = crate::icons::SLIDERS,
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

fn preset_buttons(current: &str) -> String {
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
            format!(
                r#"<button class="preset" type="button" data-preset="{color}" title="Use {color}" aria-label="Use {color}" aria-pressed="{pressed}" style="--preset-color:{color}"></button>"#,
                color = html_escape(&color)
            )
        })
        .collect()
}

fn host_views(manifests: &[HostManifest], runtime_hosts: &[Host]) -> Vec<AgoraHostView> {
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
        let accent = palette.and_then(palette_accent);
        let settings_ready = accent.is_some();
        let declared_accent = accent.unwrap_or_else(|| DEFAULT_ACCENT.to_string());
        let palette_name = palette
            .map(|palette| palette.name.clone())
            .unwrap_or_else(|| format!("custom-{}", manifest.slug));
        let preferences = runtime
            .map(|host| host.preferences.clone())
            .unwrap_or_else(|| manifest.host.preferences.clone());
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
                target_attribute: format!("palettes.{palette_name}.gradient.primary"),
                preferences,
                requested_preferences,
            },
        );
    }

    views.into_values().collect()
}

fn setup_host_view(
    name: &str,
    role: &str,
    is_nix: bool,
    has_reported: bool,
    preferences: HostPreferences,
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
    let palette_name = format!("custom-{slug}");
    AgoraHostView {
        name: name.to_string(),
        slug,
        role: role.to_string(),
        is_nix,
        declared_accent: DEFAULT_ACCENT.to_string(),
        has_reported,
        settings_ready: false,
        target_path: TARGET_PATH.to_string(),
        target_attribute: format!("palettes.{palette_name}.gradient.primary"),
        preferences,
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
    proposed: &str,
) -> Result<PaletteProposal, &'static str> {
    let Some(palette) = &manifest.palette else {
        return Err("host manifest has no palette");
    };
    let Some(current) = palette_accent(palette) else {
        return Err("host palette has no declared accent");
    };
    let normalized = normalize_hex_color(proposed)?;
    let attribute = format!("palettes.{}.gradient.primary", palette.name);
    let patch = render_palette_patch(TARGET_PATH, &current, &normalized, palette);
    Ok(PaletteProposal {
        schema: "inspr.pharos.agora.palette-proposal.v1",
        status: if current == normalized {
            "no_change"
        } else {
            "draft"
        },
        host: manifest.host.name.clone(),
        slug: manifest.slug.clone(),
        change: ProposalChange {
            setting: "host.palette.accent",
            declared: current,
            proposed: normalized,
        },
        target: ProposalTarget {
            repo: "nixcfg",
            path: TARGET_PATH,
            palette: palette.name.clone(),
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
            next_gate: "review and apply in nixcfg, then run nixcfg QA/backup/deploy gates",
        },
        patch: ProposalPatch {
            format: "unified-diff",
            value: patch,
        },
    })
}

fn render_palette_patch(
    target_path: &str,
    current: &str,
    proposed: &str,
    palette: &ManifestPalette,
) -> String {
    let zellij_bg = palette
        .zellij
        .get("bg")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(current);
    let zellij_frame = palette
        .zellij
        .get("frame")
        .and_then(serde_json::Value::as_str)
        .unwrap_or(current);
    format!(
        "diff --git a/{target_path} b/{target_path}\n--- a/{target_path}\n+++ b/{target_path}\n@@\n-        primary = \"{current}\";\n+        primary = \"{proposed}\";\n@@\n-        bg = \"{zellij_bg}\";\n+        bg = \"{proposed}\";\n@@\n-        frame = \"{zellij_frame}\";\n+        frame = \"{proposed}\";\n"
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
        Host, ManifestHost, ManifestLocationMode, ManifestPalette, ManifestPolicy, NixFreshness,
        PrivilegedActionMode, PrivilegedActions, RuntimeStateOwner, HOST_MANIFEST_SCHEMA,
        HOST_MANIFEST_VERSION,
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
            },
            service_observations: vec![],
            backup_observations: vec![],
            preferences: Default::default(),
            requested_preferences: None,
        }
    }

    #[test]
    fn palette_proposal_generates_reviewable_nixcfg_patch() {
        let proposal = build_palette_proposal(&manifest(), "#48b8a8").expect("proposal");

        assert_eq!(proposal.schema, "inspr.pharos.agora.palette-proposal.v1");
        assert_eq!(proposal.status, "draft");
        assert_eq!(proposal.target.repo, "nixcfg");
        assert_eq!(proposal.target.path, TARGET_PATH);
        assert_eq!(
            proposal.target.attribute,
            "palettes.custom-hsb8.gradient.primary"
        );
        assert!(!proposal.janus.required);
        assert!(!proposal.safety.applies_change);
        assert!(proposal
            .patch
            .value
            .contains("-        primary = \"#e09051\";"));
        assert!(proposal
            .patch
            .value
            .contains("+        primary = \"#48b8a8\";"));
        assert!(proposal
            .patch
            .value
            .contains("+        frame = \"#48b8a8\";"));
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
        let html = render_page(&[manifest()], &[runtime], None, "markus", true);

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
        assert!(html.contains("Save color"));
        assert!(html.contains("Alert preferences"));
        assert!(html.contains("Down alerts"));
        assert!(html.contains("Backup warnings"));
        assert!(html.contains("Nix freshness warnings"));
        assert_eq!(html.matches(r#"class="preference-switch""#).count(), 3);
        assert!(html.contains(r#"<details class="settings-disclosure" data-advanced>"#));
        assert!(!html.contains(r#"<details class="settings-disclosure" open"#));
        assert!(html.contains("palettes.custom-hsb8.gradient.primary"));
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

        let html = render_page(&[other, manifest()], &[], Some("hsb8"), "markus", true);

        assert!(html.contains(r#"<option value="hsb8" selected>"#));
        assert!(!html.contains(r#"<option value="csb1" selected>"#));
        assert!(html.contains(r#"data-host="hsb8""#));
        assert!(html.contains("--picked-color:#e09051"));
    }

    #[test]
    fn settings_page_keeps_shared_shell_empty_state() {
        let html = render_page(&[], &[], None, "markus", true);

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
        let html = render_page(&[manifest()], &[runtime], Some("csb0"), "markus", true);

        assert!(html.contains("Prepare host settings"));
        assert!(html.contains("Saving creates a pending request for csb0"));
        assert!(html.contains(r#"<option value="csb0" selected>"#));
        assert!(html.contains(r#"data-ready="false""#));
        assert!(html.contains(r#"data-host-reported="true""#));
        assert!(html.contains(r#"data-host="csb0""#));
        assert!(!html.contains("must report once"));
        assert!(!html.contains(r#"data-save-color disabled"#));
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
        let html = render_page(&[manifest()], &[], Some("csb0"), "markus", true);

        assert!(html.contains("Waiting for first report"));
        assert!(html.contains("csb0 must report once before settings can be requested"));
        assert!(html.contains(r#"<option value="csb0" selected>"#));
        assert!(html.contains(r#"data-host-reported="false""#));
        assert!(html.contains(r#"data-save-color disabled"#));
        assert!(html.contains("Waiting for host"));
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
