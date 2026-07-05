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

const AGORA_HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Agora · Pharos</title><style>
:root{--ink:#172c3d;--muted:#647687;--line:#dce6ec;--soft:#f5f8fa;--panel:#fff;--accent:#1f7fb5;--teal:#159e99;--amber:#c98224;--green:#25845f;--red:#bf3a35;--blue:#496c91}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;background:#f6fafb;color:var(--ink);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;overflow-x:hidden}
button,input{font:inherit}
.shell{width:min(1240px,100%);margin:0 auto;padding:28px 22px 40px}
.topbar{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:18px}
.brand{display:flex;align-items:center;gap:10px;min-width:0}.mark{display:grid;place-items:center;width:34px;height:34px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--amber)}.mark .ico{width:20px;height:20px}
h1{margin:0;font-size:22px;line-height:1.15;font-weight:680;letter-spacing:0}.subtitle{margin:2px 0 0;color:var(--muted);font-size:12px}
.nav{display:flex;align-items:center;gap:8px}.nav a,.action{min-height:34px;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink);text-decoration:none;padding:7px 11px;cursor:pointer}.action.primary{background:var(--ink);border-color:var(--ink);color:#fff}.action:disabled{cursor:not-allowed;opacity:.62}
.layout{display:grid;grid-template-columns:minmax(210px,260px) minmax(0,1fr);gap:14px;align-items:start}
.rail,.workspace{border:1px solid var(--line);border-radius:8px;background:var(--panel)}
.rail{padding:9px}.rail-title{padding:6px 7px 10px;color:var(--muted);font-size:12px;font-weight:650;text-transform:uppercase;letter-spacing:.06em}
.host-button{width:100%;display:grid;grid-template-columns:10px minmax(0,1fr) auto;align-items:center;gap:9px;min-height:54px;border:1px solid transparent;border-radius:7px;background:transparent;color:var(--ink);text-align:left;padding:8px;cursor:pointer}
.host-button[aria-pressed="true"]{background:var(--soft);border-color:var(--line)}.host-dot{width:10px;height:10px;border-radius:50%;background:var(--host-color,var(--accent));box-shadow:0 0 0 4px color-mix(in srgb,var(--host-color,var(--accent)) 13%,transparent)}.host-name{display:block;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.host-role{display:block;color:var(--muted);font-size:12px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.host-live{font-size:11px;color:var(--muted);white-space:nowrap}
.workspace{min-width:0;overflow:hidden}.tabs{display:flex;gap:4px;padding:10px;border-bottom:1px solid var(--line);background:#fbfdfe}.tab{border:0;background:transparent;color:var(--muted);min-height:31px;border-radius:7px;padding:6px 10px;cursor:pointer}.tab[aria-selected="true"]{background:#fff;color:var(--accent);box-shadow:inset 0 0 0 1px var(--line)}
.content{display:grid;grid-template-columns:minmax(0,.95fr) minmax(300px,.75fr);gap:0;min-height:620px}.editor{padding:18px;border-right:1px solid var(--line)}.proposal{padding:18px;background:#fbfdfe}
.host-head{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;margin-bottom:16px}.kicker{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.06em;font-weight:650}.host-title{margin:2px 0 0;font-size:24px;font-weight:700}.state-pill{display:inline-flex;align-items:center;gap:7px;min-height:30px;border:1px solid var(--line);border-radius:999px;background:#fff;color:var(--green);padding:5px 10px;font-size:12px;font-weight:650;white-space:nowrap}.state-pill[data-live="down"]{color:var(--red)}.state-pill[data-live="stale"]{color:var(--amber)}.state-pill[data-live="awaiting_first_heartbeat"]{color:var(--muted)}
.matrix{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));border:1px solid var(--line);border-radius:8px;overflow:hidden;background:#fff;margin-bottom:14px}.cell{min-width:0;padding:13px;border-right:1px solid var(--line)}.cell:last-child{border-right:0}.cell span{display:block;color:var(--muted);font-size:12px}.cell strong{display:block;margin-top:5px;font-size:16px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}.swatch-line{display:flex;align-items:center;gap:8px;min-width:0}.swatch{width:22px;height:22px;border-radius:6px;border:1px solid rgba(0,0,0,.12);background:var(--swatch,#999);flex:0 0 auto}
.form{display:grid;grid-template-columns:70px minmax(120px,180px) auto;gap:10px;align-items:end;margin:14px 0 16px}.control label{display:block;color:var(--muted);font-size:12px;margin-bottom:5px}.color{width:64px;height:38px;padding:2px;border:1px solid var(--line);border-radius:7px;background:#fff}.hex{height:38px;width:100%;border:1px solid var(--line);border-radius:7px;background:#fff;color:var(--ink);padding:0 10px;text-transform:uppercase}.meta-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.kv{border:1px solid var(--line);border-radius:8px;background:#fff;padding:11px}.kv span{display:block;color:var(--muted);font-size:12px}.kv strong{display:block;margin-top:4px;font-weight:650;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.proposal h2{margin:0 0 12px;font-size:16px}.status-strip{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:12px}.status{border:1px solid var(--line);border-radius:8px;background:#fff;padding:10px}.status span{display:block;color:var(--muted);font-size:12px}.status strong{display:block;margin-top:3px;font-size:13px}.status.ok strong{color:var(--green)}
pre{min-height:330px;max-height:430px;overflow:auto;margin:0;border:1px solid var(--line);border-radius:8px;background:#101820;color:#dce9ef;padding:13px;font:12px/1.5 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:pre-wrap;word-break:break-word}.empty{padding:38px;border:1px solid var(--line);border-radius:8px;background:#fff;color:var(--muted)}
@media (max-width:860px){.shell{padding:20px 14px 32px}.layout,.content{grid-template-columns:1fr}.editor{border-right:0;border-bottom:1px solid var(--line)}.matrix,.meta-grid,.status-strip{grid-template-columns:1fr}.cell{border-right:0;border-bottom:1px solid var(--line)}.cell:last-child{border-bottom:0}.form{grid-template-columns:70px minmax(0,1fr)}.form .action{grid-column:1/-1}}
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

pub(crate) async fn page(State(state): State<AppState>) -> Html<String> {
    Html(render_page(
        state.manifests.manifests(),
        &state.store.list(),
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

fn render_page(manifests: &[HostManifest], runtime_hosts: &[Host]) -> String {
    let hosts = host_views(manifests, runtime_hosts);
    if hosts.is_empty() {
        return format!(
            "{AGORA_HEAD}<main class=\"shell\"><div class=\"topbar\"><div class=\"brand\"><span class=\"mark\">{mark}</span><div><h1>Agora</h1><p class=\"subtitle\">declared host settings</p></div></div><nav class=\"nav\"><a href=\"/\">Fleet</a></nav></div><section class=\"empty\">No declared host manifests loaded.</section></main>{AGORA_FOOT}",
            mark = crate::icons::LIGHTHOUSE
        );
    }

    let first = &hosts[0];
    let host_buttons = hosts
        .iter()
        .enumerate()
        .map(|(idx, host)| {
            format!(
                r#"<button class="host-button" type="button" data-host-index="{idx}" aria-pressed="{pressed}" style="--host-color:{accent}"><span class="host-dot"></span><span><span class="host-name">{name}</span><span class="host-role">{role}</span></span><span class="host-live">{live}</span></button>"#,
                pressed = idx == 0,
                accent = html_escape(&host.declared_accent),
                name = html_escape(&host.name),
                role = html_escape(&host.role),
                live = html_escape(&host.liveness)
            )
        })
        .collect::<String>();
    let hosts_json = serde_json::to_string(&hosts).expect("host view JSON serializes");

    format!(
        r#"{AGORA_HEAD}<main class="shell"><div class="topbar"><div class="brand"><span class="mark">{mark}</span><div><h1>Agora</h1><p class="subtitle">declared host settings</p></div></div><nav class="nav"><a href="/">Fleet</a><a href="/declared-hosts.json">Declared JSON</a></nav></div><section class="layout"><aside class="rail"><div class="rail-title">Hosts</div>{host_buttons}</aside><section class="workspace"><div class="tabs" role="tablist"><button class="tab" type="button" aria-selected="true">Palette</button><button class="tab" type="button" aria-selected="false" disabled>Services</button><button class="tab" type="button" aria-selected="false" disabled>Access</button></div><div class="content"><section class="editor"><header class="host-head"><div><span class="kicker" data-host-slug>{slug}</span><div class="host-title" data-host-name>{name}</div></div><span class="state-pill" data-runtime-pill data-live="{live_key}">Runtime: {live}</span></header><div class="matrix" aria-label="palette comparison"><div class="cell"><span>Declared</span><strong class="swatch-line"><i class="swatch" data-declared-swatch style="--swatch:{declared}"></i><span data-declared>{declared}</span></strong></div><div class="cell"><span>Proposed</span><strong class="swatch-line"><i class="swatch" data-proposed-swatch style="--swatch:{declared}"></i><span data-proposed>{declared}</span></strong></div><div class="cell"><span>Runtime</span><strong class="swatch-line"><i class="swatch" data-runtime-swatch style="--swatch:{runtime}"></i><span data-runtime>{runtime}</span></strong></div></div><div class="form"><div class="control"><label for="accent-color">Palette</label><input class="color" id="accent-color" data-color type="color" value="{declared}"></div><div class="control"><label for="accent-hex">Accent</label><input class="hex" id="accent-hex" data-hex maxlength="7" spellcheck="false" value="{declared}"></div><button class="action primary" type="button" data-review>Review proposal</button></div><div class="meta-grid"><div class="kv"><span>nixcfg target</span><strong data-target-path>{target_path}</strong></div><div class="kv"><span>Attribute</span><strong data-target-attribute>{target_attribute}</strong></div><div class="kv"><span>Services</span><strong data-services>{services}</strong></div><div class="kv"><span>Freshness</span><strong data-freshness>{freshness}</strong></div></div></section><aside class="proposal"><h2>nixcfg patch</h2><div class="status-strip"><div class="status ok"><span>Janus</span><strong data-janus>Janus: not required</strong></div><div class="status"><span>Deploy</span><strong>disabled in Pharos</strong></div></div><pre data-patch>No proposal loaded.</pre></aside></div></section></section></main><script>
const HOSTS={hosts_json};
let selected=0;
const $=sel=>document.querySelector(sel);
function esc(v){{return String(v ?? '')}}
function host(){{return HOSTS[selected]}}
function setSwatch(sel,color){{const el=$(sel);if(el)el.style.setProperty('--swatch',color)}}
function renderHost(){{const h=host();document.querySelectorAll('[data-host-index]').forEach((btn,idx)=>btn.setAttribute('aria-pressed',String(idx===selected)));$('[data-host-slug]').textContent=h.slug;$('[data-host-name]').textContent=h.name;const pill=$('[data-runtime-pill]');pill.dataset.live=h.liveness;pill.textContent='Runtime: '+h.liveness;$('[data-declared]').textContent=h.declared_accent;$('[data-proposed]').textContent=h.declared_accent;$('[data-runtime]').textContent=h.runtime_accent;$('[data-color]').value=h.declared_accent;$('[data-hex]').value=h.declared_accent;setSwatch('[data-declared-swatch]',h.declared_accent);setSwatch('[data-proposed-swatch]',h.declared_accent);setSwatch('[data-runtime-swatch]',h.runtime_accent);$('[data-target-path]').textContent=h.target_path;$('[data-target-attribute]').textContent=h.target_attribute;$('[data-services]').textContent=String(h.services_count);$('[data-freshness]').textContent=h.freshness_tldr;$('[data-janus]').textContent=h.janus_required?'Janus: required':'Janus: not required';$('[data-patch]').textContent='No proposal loaded.'}}
function sync(value){{let v=value.trim();if(!v.startsWith('#'))v='#'+v;v=v.slice(0,7);$('[data-hex]').value=v.toUpperCase();if(/^#[0-9a-fA-F]{{6}}$/.test(v)){{$('[data-color]').value=v;$('[data-proposed]').textContent=v.toUpperCase();setSwatch('[data-proposed-swatch]',v)}}}}
document.querySelectorAll('[data-host-index]').forEach(btn=>btn.addEventListener('click',()=>{{selected=Number(btn.dataset.hostIndex)||0;renderHost()}}));
$('[data-color]').addEventListener('input',e=>sync(e.target.value));
$('[data-hex]').addEventListener('input',e=>sync(e.target.value));
$('[data-review]').addEventListener('click',async()=>{{const h=host();const accent=$('[data-hex]').value;const patch=$('[data-patch]');patch.textContent='Generating proposal...';try{{const res=await fetch('/agora/proposals/host-palette.json?host='+encodeURIComponent(h.name)+'&accent='+encodeURIComponent(accent),{{headers:{{Accept:'application/json'}}}});const data=await res.json();if(!res.ok){{patch.textContent=data.error||'proposal failed';return}}patch.textContent=data.patch.value;}}catch(_){{patch.textContent='proposal failed'}}}});
</script>{AGORA_FOOT}"#,
        mark = crate::icons::LIGHTHOUSE,
        slug = html_escape(&first.slug),
        name = html_escape(&first.name),
        live = html_escape(&first.liveness),
        live_key = html_escape(&first.liveness),
        declared = html_escape(&first.declared_accent),
        runtime = html_escape(&first.runtime_accent),
        target_path = html_escape(&first.target_path),
        target_attribute = html_escape(&first.target_attribute),
        services = first.services_count,
        freshness = html_escape(&first.freshness_tldr),
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
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(crate::now_unix()),
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(0),
            },
        };

        let html = render_page(&[manifest()], &[runtime]);

        assert!(html.contains("Agora"));
        assert!(html.contains("Declared"));
        assert!(html.contains("Proposed"));
        assert!(html.contains("Runtime"));
        assert!(html.contains("nixcfg patch"));
        assert!(html.contains("Janus: not required"));
        assert!(html.contains("Review proposal"));
        assert!(html.contains("palettes.custom-hsb8.gradient.primary"));
        assert!(!html.contains("stored-token-hash"));
    }

    #[test]
    fn invalid_accent_is_rejected() {
        assert!(normalize_hex_color("#48b8a8").is_ok());
        assert!(normalize_hex_color("48B8A8").is_ok());
        assert!(normalize_hex_color("#nothex").is_err());
        assert!(normalize_hex_color("#12345").is_err());
    }
}
