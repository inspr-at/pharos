//! Host color settings surface.
//!
//! This stays proposal-only: Pharos can explain the declarative nixcfg change,
//! but it must not write nixcfg or mutate a host from here.

use std::collections::BTreeMap;

use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::Html;
use axum::Json;
use pharos_core::{liveness, Host, HostManifest, Liveness, ManifestPalette};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::{html_escape, AppState};

const DEFAULT_ACCENT: &str = "#1f7fb5";
const TARGET_PATH: &str = "modules/uzumaki/theme/theme-palettes.nix";

const AGORA_CSS: &str = r#"<style>
.settings-main{width:min(1180px,100%)}
.settings-bar{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:0 0 18px;padding:11px;background:rgba(255,255,255,.72);border:1px solid rgba(210,226,234,.78);border-radius:8px;box-shadow:0 12px 30px rgba(54,88,108,.05);backdrop-filter:blur(10px)}
.host-picker{display:flex;align-items:center;gap:10px;min-width:0;flex:1}
.host-picker label{color:var(--muted);font-size:12px;font-weight:650}
.host-select-wrap{position:relative;min-width:220px;max-width:360px;flex:1}
.host-select{width:100%;height:38px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-weight:650;padding:0 34px 0 12px;outline:none;appearance:none}
.host-select-wrap:after{content:"";position:absolute;right:13px;top:50%;width:7px;height:7px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:translateY(-65%) rotate(45deg);pointer-events:none}
.host-context{display:flex;align-items:center;gap:8px;min-width:0;color:var(--muted);font-size:12px}
.host-status-dot{width:9px;height:9px;border-radius:50%;background:var(--state);box-shadow:0 0 0 4px color-mix(in srgb,var(--state) 13%,transparent)}
.settings-actions{display:flex;align-items:center;gap:8px;flex:0 0 auto}
.settings-link{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 13px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);text-decoration:none;font-weight:650}
.settings-panel{overflow:hidden;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 16px 38px rgba(54,88,108,.08)}
.settings-panel-head{display:flex;align-items:flex-start;justify-content:space-between;gap:16px;padding:22px 24px;border-bottom:1px solid rgba(214,226,234,.72)}
.settings-kicker{display:block;margin-bottom:5px;color:var(--sun);font-size:12px;text-transform:uppercase;letter-spacing:.08em;font-weight:720}
.settings-panel h2{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:27px;font-weight:500;letter-spacing:0;color:#12304b}
.settings-panel p{margin:5px 0 0;color:var(--muted);font-size:13px}
.settings-state{display:flex;align-items:center;gap:8px;min-height:30px;border:1px solid rgba(210,226,234,.92);border-radius:999px;background:#fff;padding:5px 10px;color:var(--muted);font-size:12px;font-weight:700;white-space:nowrap}
.settings-state[data-ready="true"]{color:var(--live)}
.color-layout{display:grid;grid-template-columns:minmax(0,1fr) 320px;gap:0}
.color-editor{padding:24px;border-right:1px solid rgba(214,226,234,.72)}
.preview-zone{padding:24px;background:linear-gradient(180deg,rgba(247,252,253,.72),rgba(255,255,255,.78))}
.setup-banner{display:flex;align-items:center;justify-content:space-between;gap:14px;margin:0 0 18px;padding:12px 14px;border:1px solid rgba(214,155,49,.28);border-radius:8px;background:linear-gradient(90deg,rgba(255,247,232,.88),rgba(255,255,255,.72));color:var(--ink)}
.setup-banner strong{display:block;font-size:13px}
.setup-banner span{display:block;color:var(--muted);font-size:12px}
.color-controls{display:grid;grid-template-columns:126px minmax(0,1fr);gap:18px;align-items:start}
.color-well-wrap{display:grid;justify-items:center;gap:10px}
.color-well{width:112px;height:112px;border-radius:50%;border:0;background:var(--picked-color);box-shadow:0 0 0 9px color-mix(in srgb,var(--picked-color) 14%,transparent),0 16px 34px color-mix(in srgb,var(--picked-color) 22%,transparent);cursor:pointer}
.color-well::-webkit-color-swatch-wrapper{padding:0}.color-well::-webkit-color-swatch{border:0;border-radius:50%}
.color-well-label{color:var(--muted);font-size:12px}
.color-fields{display:grid;gap:14px;align-content:start}
.field label{display:block;margin-bottom:6px;color:var(--muted);font-size:12px;font-weight:650}
.hex-input{width:100%;height:40px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-weight:700;padding:0 12px;text-transform:uppercase;outline:none}
.preset-row{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.preset{width:28px;height:28px;border:1px solid rgba(210,226,234,.92);border-radius:50%;background:var(--preset-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--preset-color) 10%,transparent);cursor:pointer}
.preset:hover,.preset:focus-visible{outline:0;box-shadow:0 0 0 5px color-mix(in srgb,var(--preset-color) 18%,transparent),0 7px 16px rgba(45,75,95,.08)}
.primary-action{min-height:42px;border:1px solid #17304a;border-radius:7px;background:#17304a;color:#fff;font:inherit;font-weight:720;cursor:pointer;padding:0 16px}
.primary-action:hover{background:#10273d}
.primary-action:disabled{opacity:.58;cursor:not-allowed}
.preview-card{position:relative;min-height:248px;display:flex;flex-direction:column;border:1px solid rgba(211,225,233,.86);border-radius:8px;background:rgba(255,255,255,.92);box-shadow:0 14px 32px rgba(45,75,95,.08);padding:16px;overflow:hidden}
.preview-card:before{content:"";position:absolute;inset:-84px -74px auto auto;width:190px;height:190px;background:radial-gradient(circle,color-mix(in srgb,var(--picked-color) 22%,transparent),rgba(21,158,153,.08) 42%,transparent 70%);pointer-events:none}
.preview-host{position:relative;display:flex;align-items:flex-start;gap:10px}
.preview-badge{display:grid;place-items:center;width:34px;height:34px;border:3px solid var(--picked-color);border-radius:50%;color:var(--accent);background:linear-gradient(180deg,rgba(255,255,255,.92),color-mix(in srgb,var(--picked-color) 8%,#f5fbfc));box-shadow:0 0 0 6px color-mix(in srgb,var(--picked-color) 14%,transparent),0 0 20px color-mix(in srgb,var(--picked-color) 20%,transparent)}
.preview-badge .ico{width:17px;height:17px}
.preview-name{font-weight:760;font-size:17px;line-height:1.2;color:var(--ink)}
.preview-role{margin-top:2px;color:var(--muted);font-size:12px}
.preview-line{height:1px;margin:18px 0;background:linear-gradient(90deg,transparent,rgba(31,127,181,.16),transparent)}
.preview-reason{display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;gap:8px;color:var(--muted);font-size:12px}
.preview-reason:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--picked-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--picked-color) 12%,transparent)}
.preview-meta{margin-top:auto;display:grid;gap:9px;color:var(--muted);font-size:12px}
.preview-meta div{display:flex;align-items:center;justify-content:space-between;gap:10px;border-bottom:1px solid rgba(214,226,234,.58);padding-bottom:6px}
.preview-meta div:last-child{border-bottom:0;padding-bottom:0}
.preview-meta strong{color:var(--ink)}
.advanced{border-top:1px solid rgba(214,226,234,.72);background:rgba(255,255,255,.82)}
.advanced details{padding:0}
.advanced summary{display:flex;align-items:center;justify-content:space-between;gap:12px;min-height:48px;padding:0 24px;cursor:pointer;font-weight:720;color:var(--ink);list-style:none}
.advanced summary::-webkit-details-marker{display:none}
.advanced summary:after{content:"";width:8px;height:8px;border-right:1.5px solid var(--muted);border-bottom:1.5px solid var(--muted);transform:rotate(45deg)}
.advanced details[open] summary:after{transform:rotate(225deg)}
.advanced-body{display:grid;gap:12px;padding:0 24px 22px}
.review-note{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px}
.review-note:before{content:"";width:8px;height:8px;border-radius:50%;background:var(--live);box-shadow:0 0 0 4px rgba(37,132,95,.12)}
.advanced-meta{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:8px}
.advanced-meta div{min-width:0;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:#fff;padding:9px 10px}
.advanced-meta span{display:block;color:var(--muted);font-size:11px;font-weight:650}
.advanced-meta strong{display:block;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;color:var(--ink);font-size:12px}
.review-output{min-height:180px;max-height:360px;overflow:auto;margin:0;border:1px solid rgba(210,226,234,.92);border-radius:8px;background:#10202d;color:#dce9ef;padding:13px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}
.empty-settings{padding:34px;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 16px 38px rgba(54,88,108,.08)}
.empty-settings h2{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:25px;font-weight:500}
.empty-settings p{margin:0;color:var(--muted)}
@media (max-width:900px){.settings-bar{align-items:stretch;flex-direction:column}.settings-actions{justify-content:flex-start}.color-layout,.color-controls{grid-template-columns:1fr}.color-editor{border-right:0;border-bottom:1px solid rgba(214,226,234,.72)}.preview-zone{padding:20px}.setup-banner{align-items:flex-start;flex-direction:column}}
@media (max-width:640px){.advanced-meta{grid-template-columns:1fr}}
</style>"#;

#[derive(Debug, Clone, Serialize)]
struct AgoraHostView {
    name: String,
    slug: String,
    role: String,
    palette_name: String,
    declared_accent: String,
    runtime_accent: String,
    liveness: String,
    state_color: String,
    settings_ready: bool,
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
    headers: HeaderMap,
    Query(query): Query<AgoraPageQuery>,
) -> Html<String> {
    let user_label = crate::sidebar_user_label(&state.auth, &headers);
    Html(render_page(
        state.manifests.manifests(),
        &state.store.list(),
        query.host.as_deref(),
        &user_label,
        state.auth.is_some(),
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
            hosts.push(setup_host_view(requested, "host", None, None));
            hosts.len() - 1
        }
        (None, None) => 0,
    };

    let head = crate::head_with_extra(AGORA_CSS);
    let sidebar = crate::sidebar(user_label, logout_enabled, "settings");
    let as_of = crate::clock_label(crate::now_unix());

    if hosts.is_empty() {
        return format!(
            r#"{head}{sidebar}<main class="settings-main"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>Settings</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">Host color</p></div><div class="asof">as of {as_of}</div></div><section class="empty-settings"><h2>No hosts yet</h2><p>Once a host reports to Pharos, its color settings will appear here.</p></section></main></div></body></html>"#
        );
    }

    let selected = &hosts[selected_index];
    let options = host_options(&hosts, selected_index);
    let content = if selected.settings_ready {
        render_ready_content(selected)
    } else {
        render_setup_content(selected)
    };

    format!(
        r##"{head}{sidebar}<main class="settings-main"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>Settings</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">Host color</p></div><div class="asof">as of {as_of}</div></div><section class="settings-bar" aria-label="host settings selector"><div class="host-picker"><label for="host-select">Host</label><span class="host-select-wrap"><select id="host-select" class="host-select" data-host-select>{options}</select></span><span class="host-context" style="--state:{state_color}"><span class="host-status-dot"></span><span>{role}</span></span></div><div class="settings-actions"><a class="settings-link" href="/">Fleet</a></div></section>{content}</main><script>
const hostSelect=document.querySelector('[data-host-select]');
hostSelect?.addEventListener('change',event=>{{location.href='/agora?host='+encodeURIComponent(event.target.value)}});
const root=document.querySelector('[data-color-root]');
if(root){{
  const color=root.querySelector('[data-color]');
  const hex=root.querySelector('[data-hex]');
  const output=root.querySelector('[data-review-output]');
  const advanced=root.querySelector('[data-advanced]');
  const setupPlan=root.querySelector('[data-setup-plan]');
  function validHex(value){{return /^#[0-9a-fA-F]{{6}}$/.test(value)}}
  function setPicked(value){{
    let next=String(value||'').trim();
    if(!next.startsWith('#'))next='#'+next;
    next=next.slice(0,7);
    if(hex)hex.value=next.toUpperCase();
    if(validHex(next)){{
      root.style.setProperty('--picked-color',next);
      if(color)color.value=next;
    }}
  }}
  color?.addEventListener('input',event=>setPicked(event.target.value));
  hex?.addEventListener('input',event=>setPicked(event.target.value));
  root.querySelectorAll('[data-preset]').forEach(button=>button.addEventListener('click',()=>setPicked(button.dataset.preset)));
  root.querySelector('[data-review]')?.addEventListener('click',async()=>{{
    if(!output)return;
    if(advanced)advanced.open=true;
    output.textContent='Preparing review...';
    try{{
      const res=await fetch('/agora/proposals/host-palette.json?host='+encodeURIComponent(root.dataset.host)+'&accent='+encodeURIComponent(hex.value),{{headers:{{Accept:'application/json'}}}});
      const data=await res.json();
      output.textContent=res.ok?data.patch.value:(data.error||'review failed');
    }}catch(_){{output.textContent='review failed'}}
  }});
  root.querySelector('[data-prepare]')?.addEventListener('click',()=>{{
    if(advanced)advanced.open=true;
    if(output){{
      const plan=(setupPlan?.textContent||'').replaceAll('__ACCENT__',hex?.value||'{accent}');
      output.textContent=plan;
    }}
  }});
}}
</script></div></body></html>"##,
        role = html_escape(&selected.role),
        state_color = html_escape(&selected.state_color),
        accent = html_escape(&selected.declared_accent)
    )
}

fn render_ready_content(host: &AgoraHostView) -> String {
    render_color_panel(
        host,
        None,
        "Review color change",
        r#"<span class="review-note">Pharos only prepares a review. Applying it still happens in nixcfg.</span>"#,
        "No color change reviewed yet.",
        true,
    )
}

fn render_setup_content(host: &AgoraHostView) -> String {
    let banner = format!(
        r#"<div class="setup-banner"><div><strong>Color settings are not prepared yet</strong><span>{name} can be prepared first, then normal color reviews are available.</span></div><button class="primary-action" type="button" data-prepare>Prepare color settings</button></div>"#,
        name = html_escape(&host.name)
    );
    let plan = setup_plan(host).replace(&host.declared_accent, "__ACCENT__");
    render_color_panel(
        host,
        Some(&banner),
        "Prepare color settings",
        r#"<span class="review-note">This prepares the declarative setup path; Pharos does not deploy it directly.</span>"#,
        &plan,
        false,
    )
}

fn render_color_panel(
    host: &AgoraHostView,
    banner: Option<&str>,
    primary_label: &str,
    review_note: &str,
    review_output: &str,
    ready: bool,
) -> String {
    let presets = preset_buttons(&host.declared_accent);
    let action = if ready {
        format!(
            r#"<button class="primary-action" type="button" data-review>{}</button>"#,
            html_escape(primary_label)
        )
    } else {
        String::new()
    };
    let setup_template = if ready {
        String::new()
    } else {
        format!(
            r#"<template data-setup-plan>{}</template>"#,
            html_escape(review_output)
        )
    };
    format!(
        r##"<section class="settings-panel" data-color-root data-host="{host_name}" data-ready="{ready}" style="--picked-color:{accent}"><header class="settings-panel-head"><div><span class="settings-kicker">{slug}</span><h2>Choose color</h2><p>{copy}</p></div><span class="settings-state" data-ready="{ready}">{state}</span></header><div class="color-layout"><section class="color-editor">{banner}<div class="color-controls"><div class="color-well-wrap"><input class="color-well" data-color type="color" value="{accent}" aria-label="Host color"><span class="color-well-label">{accent_upper}</span></div><div class="color-fields"><div class="field"><label for="accent-hex">Color code</label><input class="hex-input" id="accent-hex" data-hex maxlength="7" spellcheck="false" value="{accent_upper}"></div><div class="preset-row" aria-label="preset colors">{presets}</div>{action}</div></div></section><aside class="preview-zone"><article class="preview-card" aria-label="host card preview"><div class="preview-host"><span class="preview-badge">{badge}</span><div><div class="preview-name">{host_name}</div><div class="preview-role">{role}</div></div></div><div class="preview-line"></div><div class="preview-reason"><span>{reason}</span></div><div class="preview-meta"><div><span>Flake.lock age</span><strong>{freshness}</strong></div><div><span>Settings</span><strong>{settings}</strong></div></div></article></aside></div><section class="advanced"><details data-advanced><summary>Advanced review</summary><div class="advanced-body">{review_note}<div class="advanced-meta"><div><span>nixcfg target</span><strong>{target_path}</strong></div><div><span>Attribute</span><strong>{target_attribute}</strong></div></div><pre class="review-output" data-review-output>{initial_output}</pre>{setup_template}</div></details></section></section>"##,
        host_name = html_escape(&host.name),
        slug = html_escape(&host.slug),
        role = html_escape(&host.role),
        accent = html_escape(&host.declared_accent),
        accent_upper = html_escape(&host.declared_accent.to_ascii_uppercase()),
        copy = if ready {
            "Pick the color used for this host across Pharos."
        } else {
            "Pick the first color, then prepare this host for normal settings."
        },
        state = if ready { "Ready" } else { "Needs setup" },
        banner = banner.unwrap_or(""),
        presets = presets,
        action = action,
        badge = crate::icons::SNOWFLAKE,
        reason = if ready { "color ready" } else { "setup needed" },
        freshness = html_escape(&host.freshness_tldr),
        settings = if ready { "prepared" } else { "not prepared" },
        target_path = html_escape(&host.target_path),
        target_attribute = html_escape(&host.target_attribute),
        review_note = review_note,
        initial_output = if ready {
            html_escape(review_output)
        } else {
            "No setup reviewed yet.".to_string()
        },
        setup_template = setup_template,
    )
}

fn host_options(hosts: &[AgoraHostView], selected_index: usize) -> String {
    hosts
        .iter()
        .enumerate()
        .map(|(idx, host)| {
            let selected = if idx == selected_index { " selected" } else { "" };
            let suffix = if host.settings_ready { "" } else { " - needs setup" };
            format!(
                r#"<option value="{value}"{selected}>{name} - {role}{suffix}</option>"#,
                value = html_escape(&host.name),
                name = html_escape(&host.name),
                role = html_escape(&host.role),
                suffix = suffix
            )
        })
        .collect()
}

fn preset_buttons(current: &str) -> String {
    let mut colors = vec![
        current.to_string(),
        "#48b8a8".to_string(),
        "#1f7fb5".to_string(),
        "#25845f".to_string(),
        "#d69b31".to_string(),
        "#b66d94".to_string(),
    ];
    colors.sort();
    colors.dedup();
    colors
        .into_iter()
        .take(6)
        .map(|color| {
            format!(
                r#"<button class="preset" type="button" data-preset="{color}" title="{color}" aria-label="Use {color}" style="--preset-color:{color}"></button>"#,
                color = html_escape(&color)
            )
        })
        .collect()
}

fn setup_plan(host: &AgoraHostView) -> String {
    format!(
        "Prepare color settings for {name}\n\n1. Add {name} to the nixcfg host settings registry.\n2. Create palette {palette} with accent {accent}.\n3. Export the updated host manifest so Pharos can review future color changes.\n4. Run nixcfg QA, backup, deploy, and verify Pharos after the host reports again.",
        name = host.name,
        palette = host.palette_name,
        accent = host.declared_accent
    )
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
                Some(liveness(
                    host.last_seen,
                    host.heartbeat_interval_secs,
                    crate::now_unix(),
                )),
                Some(host.freshness.tldr()),
            ),
        );
    }

    for manifest in manifests {
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
            .unwrap_or_else(|| "host".to_string());
        let freshness_tldr = runtime
            .map(|host| host.freshness.tldr())
            .unwrap_or_else(|| "not observed".to_string());
        let palette = manifest.palette.as_ref();
        let accent = palette.and_then(palette_accent);
        let settings_ready = accent.is_some();
        let declared_accent = accent.unwrap_or_else(|| DEFAULT_ACCENT.to_string());
        let palette_name = palette
            .map(|palette| palette.name.clone())
            .unwrap_or_else(|| format!("custom-{}", manifest.slug));
        views.insert(
            manifest.host.name.clone(),
            AgoraHostView {
                name: manifest.host.name.clone(),
                slug: manifest.slug.clone(),
                role,
                palette_name: palette_name.clone(),
                declared_accent: declared_accent.clone(),
                runtime_accent: declared_accent,
                liveness: live_key(live).to_string(),
                state_color: state_color(live).to_string(),
                settings_ready,
                freshness_tldr,
                services_count: manifest.services.len(),
                target_path: TARGET_PATH.to_string(),
                target_attribute: format!("palettes.{palette_name}.gradient.primary"),
                janus_required: manifest.policy.privileged_actions.janus_required,
                janus_mode: format!("{:?}", manifest.policy.privileged_actions.mode)
                    .to_ascii_lowercase(),
            },
        );
    }

    views.into_values().collect()
}

fn setup_host_view(
    name: &str,
    role: &str,
    live: Option<Liveness>,
    freshness_tldr: Option<String>,
) -> AgoraHostView {
    let live = live.unwrap_or(Liveness::AwaitingFirstHeartbeat);
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
        palette_name: palette_name.clone(),
        declared_accent: DEFAULT_ACCENT.to_string(),
        runtime_accent: DEFAULT_ACCENT.to_string(),
        liveness: live_key(live).to_string(),
        state_color: state_color(live).to_string(),
        settings_ready: false,
        freshness_tldr: freshness_tldr.unwrap_or_else(|| "not observed".to_string()),
        services_count: 0,
        target_path: TARGET_PATH.to_string(),
        target_attribute: format!("palettes.{palette_name}.gradient.primary"),
        janus_required: false,
        janus_mode: "none".to_string(),
    }
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

fn live_key(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "live",
        Liveness::Stale => "stale",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "awaiting_first_heartbeat",
    }
}

fn state_color(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "var(--live)",
        Liveness::Stale => "var(--stale)",
        Liveness::Down => "var(--down)",
        Liveness::AwaitingFirstHeartbeat => "var(--wait)",
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
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            },
            service_observations: vec![],
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
    fn settings_page_uses_shared_shell_and_simple_color_task() {
        let runtime = runtime_host("hsb8");
        let html = render_page(&[manifest()], &[runtime], None, "markus", true);

        assert!(html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
        assert!(html.contains(r#"<aside class="sidebar" aria-label="primary navigation""#));
        assert!(html.contains(r#"href="/agora" aria-current="page""#));
        assert!(html.contains("<h1>Settings</h1>"));
        assert!(html.contains("Host color"));
        assert!(html.contains("Choose color"));
        assert!(html.contains("Review color change"));
        assert!(html.contains("Advanced review"));
        assert!(html.contains("preview-card"));
        assert!(html.contains("palettes.custom-hsb8.gradient.primary"));
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

        assert!(html.contains(r#"<option value="hsb8" selected>hsb8 - parents&#39; home</option>"#));
        assert!(html.contains(r#"data-host="hsb8""#));
        assert!(html.contains("#E09051"));
    }

    #[test]
    fn runtime_host_without_declared_settings_gets_setup_flow() {
        let runtime = runtime_host("csb0");
        let html = render_page(&[manifest()], &[runtime], Some("csb0"), "markus", true);

        assert!(html.contains("Color settings are not prepared yet"));
        assert!(html.contains("Prepare color settings"));
        assert!(html.contains("Prepare color settings for csb0"));
        assert!(html.contains(r#"<option value="csb0" selected>csb0 - server - needs setup</option>"#));
        assert!(html.contains(r#"data-host="csb0""#));
        assert!(!html.contains(r#"data-host="hsb8""#));
        assert!(!html.contains("Settings unavailable"));
    }

    #[test]
    fn unknown_requested_host_gets_setup_placeholder() {
        let html = render_page(&[manifest()], &[], Some("csb0"), "markus", true);

        assert!(html.contains("Color settings are not prepared yet"));
        assert!(html.contains("Prepare color settings for csb0"));
        assert!(html.contains(r#"<option value="csb0" selected>csb0 - host - needs setup</option>"#));
        assert!(!html.contains("Pharos will not show or edit another host"));
    }

    #[test]
    fn invalid_accent_is_rejected() {
        assert!(normalize_hex_color("#48b8a8").is_ok());
        assert!(normalize_hex_color("48B8A8").is_ok());
        assert!(normalize_hex_color("#nothex").is_err());
        assert!(normalize_hex_color("#12345").is_err());
    }
}
