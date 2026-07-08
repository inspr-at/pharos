//! Agora operator surface for declared host settings.
//!
//! This is intentionally proposal-only: Pharos can explain the declarative
//! nixcfg change, but it must not write nixcfg or mutate a host from here.

use std::collections::BTreeMap;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::Html;
use axum::Json;
use pharos_core::{liveness, Host, HostManifest, Liveness, ManifestPalette};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{html_escape, AppState};

const AGORA_HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Host settings · Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
:root{--ink:#172c3d;--muted:#647687;--line:#dce6ec;--soft:#f5f8fa;--panel:#fff;--accent:#1f7fb5;--teal:#159e99;--amber:#c98224;--green:#25845f;--red:#bf3a35;--code:#0f1720;--shadow:0 18px 42px rgba(45,75,95,.07)}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:linear-gradient(180deg,#fbfdfe 0%,#f4f9fb 58%,#edf6f7 100%);color:var(--ink);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;overflow-x:hidden}
button,input{font:inherit}
a{color:inherit}
.shell{width:min(1320px,100%);margin:0 auto;padding:26px 22px 42px}
.topbar{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;margin-bottom:18px}
.crumbs{display:flex;align-items:center;gap:7px;color:var(--muted);font-size:12px;margin-bottom:8px}.crumbs a{text-decoration:none;color:var(--accent);font-weight:650}.crumbs span{white-space:nowrap}
.brand{display:flex;align-items:center;gap:11px;min-width:0}.mark{display:grid;place-items:center;width:36px;height:36px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--amber);box-shadow:0 8px 18px rgba(45,75,95,.05)}.mark .ico{width:20px;height:20px}
h1{margin:0;font-size:25px;line-height:1.12;font-weight:700;letter-spacing:0}.subtitle{margin:3px 0 0;color:var(--muted);font-size:12px}
.nav{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.nav a,.action{min-height:36px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink);text-decoration:none;padding:8px 12px;cursor:pointer;font-weight:650}.action.primary{background:var(--ink);border-color:var(--ink);color:#fff}.action:disabled{cursor:not-allowed;opacity:.62}
.layout{display:grid;grid-template-columns:minmax(220px,270px) minmax(0,1fr);gap:14px;align-items:start}
.rail,.workspace{border:1px solid var(--line);border-radius:8px;background:var(--panel);box-shadow:var(--shadow)}
.rail{padding:10px;position:sticky;top:14px}.rail-title{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:6px 7px 10px;color:var(--muted);font-size:12px;font-weight:700;text-transform:uppercase;letter-spacing:.06em}.rail-count{color:var(--ink);font-weight:700}
.host-button{width:100%;display:grid;grid-template-columns:10px minmax(0,1fr) auto;align-items:center;gap:10px;min-height:58px;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--ink);text-align:left;text-decoration:none;padding:9px;cursor:pointer}
.host-button[aria-pressed="true"],.host-button[aria-current="true"]{background:var(--soft);border-color:var(--line);box-shadow:inset 3px 0 0 var(--host-color,var(--accent))}.host-button.missing{--host-color:var(--amber);cursor:default;background:#fffaf3}.host-dot{width:10px;height:10px;border-radius:50%;background:var(--host-color,var(--accent));box-shadow:0 0 0 4px color-mix(in srgb,var(--host-color,var(--accent)) 13%,transparent)}.host-name{display:block;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.host-role{display:block;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.host-live{font-size:11px;color:var(--muted);white-space:nowrap}
.workspace{min-width:0;overflow:hidden}.workspace-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:18px 20px;border-bottom:1px solid var(--line);background:#fbfdfe}.host-title{margin:2px 0 0;font-size:26px;font-weight:740}.kicker{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:700}.state-stack{display:flex;align-items:center;gap:8px;flex-wrap:wrap;justify-content:flex-end}.state-pill{display:inline-flex;align-items:center;gap:7px;min-height:30px;border:1px solid var(--line);border-radius:999px;background:#fff;color:var(--green);padding:5px 10px;font-size:12px;font-weight:700;white-space:nowrap}.state-pill[data-live="down"]{color:var(--red)}.state-pill[data-live="stale"]{color:var(--amber)}.state-pill[data-live="awaiting_first_heartbeat"]{color:var(--muted)}.state-pill.neutral{color:var(--muted)}
.tabs{display:flex;gap:4px;padding:10px 14px;border-bottom:1px solid var(--line);background:#fff}.tab{border:0;background:transparent;color:var(--muted);min-height:32px;border-radius:7px;padding:6px 11px;cursor:pointer;font-weight:650}.tab[aria-selected="true"]{background:var(--soft);color:var(--accent);box-shadow:inset 0 0 0 1px var(--line)}
.content{display:grid;grid-template-columns:minmax(0,1fr) minmax(330px,.72fr);gap:0;min-height:620px}.editor{min-width:0;padding:20px;border-right:1px solid var(--line)}.proposal{min-width:0;padding:20px;background:#fbfdfe}.proposal-inner{position:sticky;top:16px}
.section-title{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 12px}.section-title h2{margin:0;font-size:16px}.section-title span{color:var(--muted);font-size:12px}
.matrix{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff;margin-bottom:14px}.cell{min-width:0;padding:13px;border-right:1px solid var(--line)}.cell:last-child{border-right:0}.cell span{display:block;color:var(--muted);font-size:12px}.cell strong{display:block;margin-top:6px;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.swatch-line{display:flex;align-items:center;gap:8px;min-width:0}.swatch{width:23px;height:23px;border-radius:6px;border:1px solid rgba(0,0,0,.12);background:var(--swatch,#999);flex:0 0 auto}
.controls{display:grid;grid-template-columns:minmax(0,1fr) minmax(200px,.45fr);gap:14px;align-items:stretch;margin-bottom:14px}.form{display:grid;grid-template-columns:70px minmax(120px,1fr);gap:10px;align-content:start;border:1px solid var(--line);border-radius:8px;background:#fff;padding:13px}.control label{display:block;color:var(--muted);font-size:12px;margin-bottom:5px}.color{width:64px;height:38px;padding:2px;border:1px solid var(--line);border-radius:7px;background:#fff}.hex{height:38px;width:100%;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink);padding:0 10px;text-transform:uppercase}.form .action{grid-column:1/-1;width:100%;margin-top:2px}
.preview{display:grid;grid-template-rows:auto 1fr;gap:10px;border:1px solid var(--line);border-radius:8px;background:#fff;padding:13px}.preview-label{color:var(--muted);font-size:12px}.preview-pane{border-radius:7px;border:1px solid var(--line);background:linear-gradient(135deg,var(--preview-color,#999),#f7fbfc 62%);min-height:122px;display:flex;align-items:flex-end;justify-content:space-between;gap:10px;padding:13px;color:#fff;overflow:hidden}.preview-pane strong{font-size:18px;text-shadow:0 1px 8px rgba(0,0,0,.18)}.preview-pill{border:1px solid rgba(255,255,255,.58);border-radius:999px;padding:4px 8px;font-size:11px;background:rgba(255,255,255,.18);backdrop-filter:blur(6px)}
.meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.kv{border:1px solid var(--line);border-radius:8px;background:#fff;padding:11px}.kv span{display:block;color:var(--muted);font-size:12px}.kv strong{display:block;margin-top:4px;font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.proposal h2{margin:0 0 12px;font-size:17px}.change-summary{display:grid;gap:9px;margin-bottom:12px}.safe-line{display:flex;align-items:center;gap:9px;min-height:42px;border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px;color:var(--ink);font-weight:700}.safe-dot{width:10px;height:10px;border-radius:50%;background:var(--green);box-shadow:0 0 0 4px rgba(37,132,95,.12)}.safe-line span:last-child{color:var(--muted);font-weight:650}.status-strip{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}.status{border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px}.status span{display:block;color:var(--muted);font-size:12px}.status strong{display:block;margin-top:3px;font-size:13px}.status.ok strong{color:var(--green)}.technical{border:1px solid var(--line);border-radius:8px;background:#fff;padding:0;overflow:hidden}.technical summary{cursor:pointer;list-style:none;padding:12px 13px;font-weight:700}.technical summary::-webkit-details-marker{display:none}.technical .meta-grid{padding:0 12px 12px}.technical pre{border-radius:0;border-left:0;border-right:0;border-bottom:0}
pre{min-height:300px;max-height:440px;overflow:auto;margin:0;border:1px solid var(--line);border-radius:8px;background:var(--code);color:#dce9ef;padding:13px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}.notice,.empty{padding:14px 16px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--muted);margin-bottom:14px}.empty{padding:38px;margin:0}.unavailable-state{display:grid;align-content:start;justify-items:start;gap:12px;min-height:430px;padding:28px}.unavailable-state h2{margin:0;font-size:20px;line-height:1.2}.unavailable-state p{margin:0;max-width:560px;color:var(--muted)}.unavailable-state .action{display:inline-flex;align-items:center;margin-top:4px}
@media (max-width:980px){.layout,.content,.controls{grid-template-columns:1fr}.rail{position:static}.editor{border-right:0;border-bottom:1px solid var(--line)}.proposal-inner{position:static}.matrix,.meta-grid,.status-strip{grid-template-columns:1fr}.cell{border-right:0;border-bottom:1px solid var(--line)}.cell:last-child{border-bottom:0}}
@media (max-width:640px){.shell{padding:20px 14px 32px}.topbar,.workspace-head{display:block}.nav{justify-content:flex-start;margin-top:12px}.state-stack{justify-content:flex-start;margin-top:12px}.form{grid-template-columns:70px minmax(0,1fr)}}
</style></head><body>"#;

const AGORA_FOOT: &str = r#"</body></html>"#;

#[derive(Debug, Clone, Serialize)]
struct AgoraHostView {
    name: String,
    slug: String,
    role: String,
    palette_name: String,
    declared_accent: String,
    runtime_accent: String,
    liveness: String,
    runtime_state: String,
    freshness_tldr: String,
    services_count: usize,
    target_path: String,
    target_attribute: String,
    janus_required: bool,
    janus_mode: String,
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
    Query(query): Query<AgoraPageQuery>,
) -> Html<String> {
    Html(render_page(
        state.manifests.manifests(),
        &state.store.list(),
        query.host.as_deref(),
    ))
}

pub(crate) async fn palette_proposal(
    State(state): State<AppState>,
    Query(query): Query<PaletteProposalQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
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

fn render_page(
    manifests: &[HostManifest],
    runtime_hosts: &[Host],
    requested_host: Option<&str>,
) -> String {
    let hosts = host_views(manifests, runtime_hosts);
    if hosts.is_empty() {
        return format!(
            "{AGORA_HEAD}<main class=\"shell\"><header class=\"topbar\"><div><nav class=\"crumbs\" aria-label=\"breadcrumb\"><a href=\"/\">Pharos</a><span>/</span><span>Settings</span></nav><div class=\"brand\"><span class=\"mark\">{mark}</span><div><h1>Host settings</h1><p class=\"subtitle\">per-host controls</p></div></div></div><nav class=\"nav\"><a href=\"/\">Fleet</a></nav></header><section class=\"empty\">No declared host manifests loaded.</section></main>{AGORA_FOOT}",
            mark = crate::icons::LIGHTHOUSE
        );
    }

    let requested_host = requested_host
        .map(str::trim)
        .filter(|requested| !requested.is_empty());
    let selected_index = requested_host.and_then(|requested| {
        hosts
            .iter()
            .position(|host| host.name == requested || host.slug == requested)
    });
    if let Some(requested) = requested_host {
        if selected_index.is_none() {
            return render_unavailable_page(&hosts, requested);
        }
    }

    let selected_index = selected_index.unwrap_or(0);
    let selected_host = &hosts[selected_index];
    let host_buttons = hosts
        .iter()
        .enumerate()
        .map(|(idx, host)| {
            format!(
                r#"<button class="host-button" type="button" data-host-index="{idx}" aria-pressed="{pressed}" style="--host-color:{accent}"><span class="host-dot"></span><span><span class="host-name">{name}</span><span class="host-role">{role}</span></span><span class="host-live">{live}</span></button>"#,
                pressed = idx == selected_index,
                accent = html_escape(&host.declared_accent),
                name = html_escape(&host.name),
                role = html_escape(&host.role),
                live = html_escape(&host.liveness)
            )
        })
        .collect::<String>();
    let hosts_json = serde_json::to_string(&hosts).expect("host view JSON serializes");

    format!(
        r#"{AGORA_HEAD}<main class="shell"><header class="topbar"><div><nav class="crumbs" aria-label="breadcrumb"><a href="/">Pharos</a><span>/</span><span data-breadcrumb-host>{name}</span><span>/</span><span>Settings</span></nav><div class="brand"><span class="mark">{mark}</span><div><h1>Host settings</h1><p class="subtitle">per-host controls</p></div></div></div><nav class="nav"><a href="/">Fleet</a></nav></header><section class="layout"><aside class="rail"><div class="rail-title"><span>Hosts</span><span class="rail-count">{host_count}</span></div>{host_buttons}</aside><section class="workspace"><header class="workspace-head"><div><span class="kicker" data-host-slug>{slug}</span><div class="host-title"><span data-host-name>{name}</span> settings</div><p class="subtitle" data-host-role>{role}</p></div><div class="state-stack"><span class="state-pill" data-runtime-pill data-live="{live_key}">Live state: {live}</span><span class="state-pill neutral" data-runtime-state>Settings state: {runtime_state}</span></div></header><div class="tabs" role="tablist"><button class="tab" type="button" aria-selected="true">Color</button><button class="tab" type="button" aria-selected="false" disabled>Services</button><button class="tab" type="button" aria-selected="false" disabled>Access</button></div><div class="content"><section class="editor"><div class="section-title"><h2>Host color</h2><span data-palette-name>{palette_name}</span></div><div class="matrix" aria-label="color comparison"><div class="cell"><span>Current</span><strong class="swatch-line"><i class="swatch" data-declared-swatch style="--swatch:{declared}"></i><span data-declared>{declared}</span></strong></div><div class="cell"><span>New</span><strong class="swatch-line"><i class="swatch" data-proposed-swatch style="--swatch:{declared}"></i><span data-proposed>{declared}</span></strong></div><div class="cell"><span>Live</span><strong class="swatch-line"><i class="swatch" data-runtime-swatch style="--swatch:{runtime}"></i><span data-runtime>{runtime}</span></strong></div></div><div class="controls"><div class="form"><div class="control"><label for="accent-color">Color</label><input class="color" id="accent-color" data-color type="color" value="{declared}"></div><div class="control"><label for="accent-hex">Color code</label><input class="hex" id="accent-hex" data-hex maxlength="7" spellcheck="false" value="{declared}"></div><button class="action primary" type="button" data-review>Review color change</button></div><div class="preview"><span class="preview-label">Preview</span><div class="preview-pane" data-preview style="--preview-color:{declared}"><strong data-preview-name>{name}</strong><span class="preview-pill" data-preview-accent>{declared}</span></div></div></div></section><aside class="proposal"><div class="proposal-inner"><h2>Next step</h2><div class="change-summary"><div class="safe-line"><span class="safe-dot"></span><strong>Safe change</strong><span>No direct deploy from Pharos</span></div></div><details class="technical" data-technical><summary>Technical review</summary><div class="meta-grid"><div class="kv"><span>nixcfg target</span><strong data-target-path>{target_path}</strong></div><div class="kv"><span>Attribute</span><strong data-target-attribute>{target_attribute}</strong></div><div class="kv"><span>Services</span><strong data-services>{services}</strong></div><div class="kv"><span>Freshness</span><strong data-freshness>{freshness}</strong></div><div class="kv"><span>Janus mode</span><strong data-janus-mode>{janus_mode}</strong></div><div class="kv"><span>Deploy</span><strong>Pharos disabled</strong></div></div><div class="status-strip"><div class="status ok"><span>Janus</span><strong data-janus>Janus: not required</strong></div><div class="status"><span>Deploy</span><strong>disabled in Pharos</strong></div></div><pre data-patch>No color change reviewed yet.</pre></details></div></aside></div></section></section></main><script>
const HOSTS={hosts_json};
let selected={selected_index};
const $=sel=>document.querySelector(sel);
function esc(v){{return String(v ?? '')}}
function host(){{return HOSTS[selected]}}
function setSwatch(sel,color){{const el=$(sel);if(el)el.style.setProperty('--swatch',color)}}
function setPreview(color){{const preview=$('[data-preview]');if(preview)preview.style.setProperty('--preview-color',color);$('[data-preview-accent]').textContent=color.toUpperCase()}}
function validHex(v){{return /^#[0-9a-fA-F]{{6}}$/.test(v)}}
function renderHost(writeUrl=false){{const h=host();document.querySelectorAll('[data-host-index]').forEach((btn,idx)=>btn.setAttribute('aria-pressed',String(idx===selected)));$('[data-breadcrumb-host]').textContent=h.name;$('[data-host-slug]').textContent=h.slug;$('[data-host-name]').textContent=h.name;$('[data-host-role]').textContent=h.role;$('[data-preview-name]').textContent=h.name;$('[data-palette-name]').textContent=h.palette_name;const pill=$('[data-runtime-pill]');pill.dataset.live=h.liveness;pill.textContent='Live state: '+h.liveness;$('[data-runtime-state]').textContent='Settings state: '+h.runtime_state;$('[data-declared]').textContent=h.declared_accent;$('[data-proposed]').textContent=h.declared_accent;$('[data-runtime]').textContent=h.runtime_accent;$('[data-color]').value=h.declared_accent;$('[data-hex]').value=h.declared_accent.toUpperCase();setSwatch('[data-declared-swatch]',h.declared_accent);setSwatch('[data-proposed-swatch]',h.declared_accent);setSwatch('[data-runtime-swatch]',h.runtime_accent);setPreview(h.declared_accent);$('[data-target-path]').textContent=h.target_path;$('[data-target-attribute]').textContent=h.target_attribute;$('[data-services]').textContent=String(h.services_count);$('[data-freshness]').textContent=h.freshness_tldr;$('[data-janus]').textContent=h.janus_required?'Janus: required':'Janus: not required';$('[data-janus-mode]').textContent=h.janus_mode;$('[data-patch]').textContent='No color change reviewed yet.';const tech=$('[data-technical]');if(tech)tech.open=false;if(writeUrl){{const url=new URL(location.href);url.searchParams.set('host',h.name);history.replaceState(null,'',url)}}}}
function sync(value){{let v=value.trim();if(!v.startsWith('#'))v='#'+v;v=v.slice(0,7);$('[data-hex]').value=v.toUpperCase();if(validHex(v)){{$('[data-color]').value=v;$('[data-proposed]').textContent=v.toUpperCase();setSwatch('[data-proposed-swatch]',v);setPreview(v)}}}}
document.querySelectorAll('[data-host-index]').forEach(btn=>btn.addEventListener('click',()=>{{selected=Number(btn.dataset.hostIndex)||0;renderHost(true)}}));
$('[data-color]').addEventListener('input',e=>sync(e.target.value));
$('[data-hex]').addEventListener('input',e=>sync(e.target.value));
$('[data-review]').addEventListener('click',async()=>{{const h=host();const accent=$('[data-hex]').value;const patch=$('[data-patch]');const tech=$('[data-technical]');if(tech)tech.open=true;patch.textContent='Preparing technical review...';try{{const res=await fetch('/agora/proposals/host-palette.json?host='+encodeURIComponent(h.name)+'&accent='+encodeURIComponent(accent),{{headers:{{Accept:'application/json'}}}});const data=await res.json();if(!res.ok){{patch.textContent=data.error||'review failed';return}}patch.textContent=data.patch.value;}}catch(_){{patch.textContent='review failed'}}}});
</script>{AGORA_FOOT}"#,
        mark = crate::icons::LIGHTHOUSE,
        host_count = hosts.len(),
        selected_index = selected_index,
        slug = html_escape(&selected_host.slug),
        name = html_escape(&selected_host.name),
        role = html_escape(&selected_host.role),
        palette_name = html_escape(&selected_host.palette_name),
        live = html_escape(&selected_host.liveness),
        live_key = html_escape(&selected_host.liveness),
        runtime_state = html_escape(&selected_host.runtime_state),
        declared = html_escape(&selected_host.declared_accent),
        runtime = html_escape(&selected_host.runtime_accent),
        target_path = html_escape(&selected_host.target_path),
        target_attribute = html_escape(&selected_host.target_attribute),
        services = selected_host.services_count,
        freshness = html_escape(&selected_host.freshness_tldr),
        janus_mode = html_escape(&selected_host.janus_mode),
    )
}

fn render_unavailable_page(hosts: &[AgoraHostView], requested_host: &str) -> String {
    let requested = html_escape(requested_host);
    let missing_button = format!(
        r#"<div class="host-button missing" aria-current="true"><span class="host-dot"></span><span><span class="host-name">{requested}</span><span class="host-role">visible in fleet</span></span><span class="host-live">not set up</span></div>"#
    );
    let host_links = hosts
        .iter()
        .map(|host| {
            format!(
                r#"<a class="host-button" href="/agora?host={href}" style="--host-color:{accent}"><span class="host-dot"></span><span><span class="host-name">{name}</span><span class="host-role">{role}</span></span><span class="host-live">editable</span></a>"#,
                href = html_escape(&crate::url_query_escape(&host.name)),
                accent = html_escape(&host.declared_accent),
                name = html_escape(&host.name),
                role = html_escape(&host.role)
            )
        })
        .collect::<String>();

    format!(
        r#"{AGORA_HEAD}<main class="shell"><header class="topbar"><div><nav class="crumbs" aria-label="breadcrumb"><a href="/">Pharos</a><span>/</span><span>{requested}</span><span>/</span><span>Settings</span></nav><div class="brand"><span class="mark">{mark}</span><div><h1>Host settings</h1><p class="subtitle">per-host controls</p></div></div></div><nav class="nav"><a href="/">Fleet</a></nav></header><section class="layout"><aside class="rail"><div class="rail-title"><span>Editable hosts</span><span class="rail-count">{host_count}</span></div>{missing_button}{host_links}</aside><section class="workspace"><header class="workspace-head"><div><span class="kicker">not set up</span><div class="host-title">{requested} settings</div><p class="subtitle">This host is visible in the fleet, but has no editable settings yet.</p></div><div class="state-stack"><span class="state-pill neutral">Settings unavailable</span></div></header><div class="unavailable-state"><h2>No settings are declared for this host yet</h2><p>Pharos will not show or edit another host's values here. Add this host to the declared settings registry first, then the color and access controls can appear for {requested}.</p><a class="action primary" href="/">Back to Fleet</a></div></section></section></main>{AGORA_FOOT}"#,
        mark = crate::icons::LIGHTHOUSE,
        host_count = hosts.len(),
        requested = requested,
        missing_button = missing_button,
        host_links = host_links,
    )
}

fn host_views(manifests: &[HostManifest], runtime_hosts: &[Host]) -> Vec<AgoraHostView> {
    let runtime_by_name: BTreeMap<&str, &Host> = runtime_hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let mut views: Vec<_> = manifests
        .iter()
        .filter_map(|manifest| {
            let palette = manifest.palette.as_ref()?;
            let declared_accent = palette_accent(palette)?;
            let runtime = runtime_by_name
                .get(manifest.host.name.as_str())
                .copied()
                .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
            let live = runtime
                .map(|host| {
                    liveness(
                        host.last_seen,
                        host.heartbeat_interval_secs,
                        crate::now_unix(),
                    )
                })
                .unwrap_or(Liveness::AwaitingFirstHeartbeat);
            let role = manifest
                .host
                .role
                .clone()
                .or_else(|| runtime.map(|host| host.role.clone()))
                .unwrap_or_else(|| "declared host".to_string());
            let freshness_tldr = runtime
                .map(|host| host.freshness.tldr())
                .unwrap_or_else(|| "not observed".to_string());
            let target_attribute = format!("palettes.{}.gradient.primary", palette.name);
            Some(AgoraHostView {
                name: manifest.host.name.clone(),
                slug: manifest.slug.clone(),
                role,
                palette_name: palette.name.clone(),
                declared_accent: declared_accent.clone(),
                runtime_accent: declared_accent,
                liveness: live_key(live).to_string(),
                runtime_state: runtime
                    .map(|_| "observed".to_string())
                    .unwrap_or_else(|| "pending".to_string()),
                freshness_tldr,
                services_count: manifest.services.len(),
                target_path: "modules/uzumaki/theme/theme-palettes.nix".to_string(),
                target_attribute,
                janus_required: manifest.policy.privileged_actions.janus_required,
                janus_mode: format!("{:?}", manifest.policy.privileged_actions.mode)
                    .to_ascii_lowercase(),
            })
        })
        .collect();
    views.sort_by(|left, right| left.name.cmp(&right.name));
    views
}

fn find_manifest<'a>(manifests: &'a [HostManifest], host: &str) -> Option<&'a HostManifest> {
    manifests
        .iter()
        .find(|manifest| manifest.host.name == host || manifest.slug == host)
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
    let target_path = "modules/uzumaki/theme/theme-palettes.nix";
    let attribute = format!("palettes.{}.gradient.primary", palette.name);
    let patch = render_palette_patch(target_path, &current, &normalized, palette);
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
            path: target_path,
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

fn live_key(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "live",
        Liveness::Stale => "stale",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "awaiting_first_heartbeat",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::{
        Host, ManifestHost, ManifestPalette, ManifestPolicy, NixFreshness, PrivilegedActionMode,
        PrivilegedActions, RuntimeStateOwner, HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION,
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

    #[test]
    fn palette_proposal_generates_reviewable_nixcfg_patch() {
        let proposal = build_palette_proposal(&manifest(), "#48b8a8").expect("proposal");

        assert_eq!(proposal.schema, "inspr.pharos.agora.palette-proposal.v1");
        assert_eq!(proposal.status, "draft");
        assert_eq!(proposal.target.repo, "nixcfg");
        assert_eq!(
            proposal.target.path,
            "modules/uzumaki/theme/theme-palettes.nix"
        );
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
    fn agora_page_separates_declared_proposed_runtime_and_boundary() {
        let runtime = Host {
            name: "hsb8".to_string(),
            role: "parents' home".to_string(),
            is_nix: true,
            report_version: pharos_core::HOST_REPORT_VERSION,
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(crate::now_unix()),
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            },
            service_observations: vec![],
        };

        let html = render_page(&[manifest()], &[runtime], None);

        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains("Host settings"));
        assert!(html.contains("Host color"));
        assert!(html.contains("Current"));
        assert!(html.contains("New"));
        assert!(html.contains("Live"));
        assert!(html.contains("Technical review"));
        assert!(html.contains("Safe change"));
        assert!(html.contains("Janus: not required"));
        assert!(html.contains("Review color change"));
        assert!(html.contains("Preview"));
        assert!(html.contains(r#"data-breadcrumb-host>hsb8"#));
        assert!(html.contains("palettes.custom-hsb8.gradient.primary"));
        assert!(!html.contains("stored-token-hash"));
    }

    #[test]
    fn agora_page_selects_requested_host() {
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

        let html = render_page(&[other, manifest()], &[], Some("hsb8"));

        assert!(html.contains(r#"data-host-index="1" aria-pressed="true""#));
        assert!(html.contains("let selected=1;"));
        assert!(html.contains(r#"data-breadcrumb-host>hsb8"#));
        assert!(!html.contains("No declared Agora settings"));
    }

    #[test]
    fn agora_page_does_not_fallback_for_unknown_requested_host() {
        let html = render_page(&[manifest()], &[], Some("csb0"));

        assert!(html.contains("csb0 settings"));
        assert!(html.contains("Settings unavailable"));
        assert!(html.contains("No settings are declared for this host yet"));
        assert!(html.contains("Pharos will not show or edit another host's values here"));
        assert!(html.contains(r#"class="host-button missing" aria-current="true""#));
        assert!(!html.contains(r#"data-host-name>hsb8"#));
        assert!(!html.contains("Review color change"));
        assert!(!html.contains("No declared Agora settings"));
    }

    #[test]
    fn invalid_accent_is_rejected() {
        assert!(normalize_hex_color("#48b8a8").is_ok());
        assert!(normalize_hex_color("48B8A8").is_ok());
        assert!(normalize_hex_color("#nothex").is_err());
        assert!(normalize_hex_color("#12345").is_err());
    }
}
