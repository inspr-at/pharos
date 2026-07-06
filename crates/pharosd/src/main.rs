//! pharosd — the Pharos server.
//!
//! Routes: `/healthz`, `/version`, `POST /register` (token issuance, PHAROS-8),
//! `POST /report` (beacon ingestion, PHAROS-9), `/hosts.json`, and the host
//! dashboard at `/`. Hosts live in a small store (in-memory + optional JSON
//! persistence; sqlx+SQLite is PHAROS-3). The
//! dashboard is a static server render previewing the design (rounded cards,
//! accessible SVG status, the self-host lighthouse); the interactive Leptos UI
//! is PHAROS-10.

mod agora;
mod auth;
mod icons;
mod manifests;
mod store;

use std::collections::BTreeMap;
use std::io::Read;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::{
    liveness, Host, HostManifest, HostRegistration, HostRegistrationResponse, HostReport, Liveness,
    NixFreshness, HOST_MANIFEST_SCHEMA, HOST_MANIFEST_VERSION,
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::auth::{Auth, AuthState};
use crate::manifests::{ManifestLoadIssue, ManifestRegistry};
use crate::store::Store;

/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    manifests: Arc<ManifestRegistry>,
    auth: AuthState,
    beacon_auth: BeaconAuth,
}

impl FromRef<AppState> for Arc<Store> {
    fn from_ref(s: &AppState) -> Self {
        s.store.clone()
    }
}

impl FromRef<AppState> for AuthState {
    fn from_ref(s: &AppState) -> Self {
        s.auth.clone()
    }
}

impl FromRef<AppState> for Arc<ManifestRegistry> {
    fn from_ref(s: &AppState) -> Self {
        s.manifests.clone()
    }
}

#[derive(Clone)]
struct BeaconAuth {
    registration_token: Option<String>,
    require_report_token: bool,
}

impl BeaconAuth {
    fn from_env() -> Self {
        let registration_token = std::env::var("PHAROS_REGISTRATION_TOKEN")
            .ok()
            .filter(|s| !s.trim().is_empty());
        let require_report_token = std::env::var("PHAROS_REQUIRE_BEACON_TOKEN")
            .ok()
            .and_then(|s| parse_bool(&s))
            .unwrap_or(registration_token.is_some());
        Self {
            registration_token,
            require_report_token,
        }
    }

    fn registration_status(&self, headers: &HeaderMap) -> RegistrationAuth {
        let Some(expected) = &self.registration_token else {
            return RegistrationAuth::NotConfigured;
        };
        match bearer_token(headers) {
            Some(actual) if constant_time_eq(actual, expected) => RegistrationAuth::Allowed,
            _ => RegistrationAuth::Denied,
        }
    }
}

enum RegistrationAuth {
    Allowed,
    Denied,
    NotConfigured,
}

const FLEET_HORIZON_PNG: &[u8] = include_bytes!("../assets/fleet-horizon.png");
const SIDEBAR_LIGHTHOUSE_PNG: &[u8] = include_bytes!("../assets/sidebar-lighthouse.png");

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><style>
:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--card:#ffffff;--card-soft:rgba(255,255,255,.82);--accent:#1f7fb5;--sea:#159e99;--sun:#d69b31;--live:#25845f;--stale:#b26a00;--down:#bf3a35;--wait:#8997a3;--side:232px}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%);min-height:100vh;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-3;background:radial-gradient(circle at 86% 5%,rgba(214,155,49,.16),transparent 12rem),radial-gradient(circle at 18% 28%,rgba(21,158,153,.08),transparent 18rem),linear-gradient(180deg,rgba(255,255,255,.94),rgba(239,249,250,.82));pointer-events:none}
.app-shell{min-height:100vh;display:grid;grid-template-columns:var(--side) minmax(0,1fr)}
.sidebar{position:sticky;top:0;height:100vh;display:flex;flex-direction:column;gap:24px;padding:30px 18px 18px;border-right:1px solid rgba(211,225,233,.78);background:linear-gradient(180deg,rgba(255,255,255,.92),rgba(247,252,253,.82));box-shadow:12px 0 38px rgba(45,75,95,.05);overflow:hidden}
.sidebar:before{content:"";position:absolute;left:-18%;right:-20%;bottom:-10%;height:66%;background:url('/assets/sidebar-lighthouse.png') left bottom/118% auto no-repeat;opacity:.78;pointer-events:none;-webkit-mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%);mask-image:radial-gradient(ellipse at 35% 76%,#000 0 24%,rgba(0,0,0,.82) 39%,rgba(0,0,0,.30) 61%,transparent 82%)}
.side-brand,.side-nav,.side-foot{position:relative;z-index:1}.side-brand{display:flex;align-items:center;gap:13px;padding:0 12px}.side-mark{display:grid;place-items:center;width:36px;height:50px;color:var(--sun)}.side-mark .ico{width:31px;height:31px}.side-logo{font-family:Georgia,"Times New Roman",serif;font-size:22px;letter-spacing:.18em;color:#14304b;text-transform:uppercase}
.side-nav{display:grid;gap:7px}.side-link{display:grid;grid-template-columns:23px minmax(0,1fr) auto;align-items:center;gap:11px;min-height:46px;padding:0 13px;border-radius:7px;color:#294761;text-decoration:none;font-weight:520}.side-link[aria-current="page"]{background:rgba(223,241,249,.76);color:#0f4f80}.side-link .ico{width:18px;height:18px}.side-badge{display:grid;place-items:center;min-width:24px;height:24px;border-radius:999px;background:#ffe7bb;color:#9a5b00;font-size:12px;font-weight:700}
.side-foot{margin-top:auto;display:flex;align-items:center;justify-content:space-between;padding:10px 13px;color:#294761;font-size:13px}.side-user{display:flex;align-items:center;gap:9px}.side-user:before{content:"";width:24px;height:24px;border-radius:50%;border:1px solid rgba(214,155,49,.38);background:radial-gradient(circle,#fff 0 33%,rgba(214,155,49,.18) 36%,transparent 68%)}
main{width:min(1280px,100%);margin:0;padding:34px 34px 56px}
.ico{width:16px;height:16px;display:inline-block;vertical-align:middle;flex:0 0 auto}
.top{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:22px;min-height:118px;margin:-10px 0 20px;padding:10px 0 18px;overflow:hidden}
.top:before{content:"";position:absolute;left:0;right:0;top:-52px;height:270px;background:url('/assets/fleet-horizon.png') center center/100% auto no-repeat;opacity:.84;pointer-events:none;--edge-fade:30%;-webkit-mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade),#000 calc(100% - var(--edge-fade)),transparent 100%),linear-gradient(to bottom,transparent 0,#000 var(--edge-fade),#000 calc(100% - var(--edge-fade)),transparent 100%);-webkit-mask-composite:source-in;mask-image:linear-gradient(to right,transparent 0,#000 var(--edge-fade),#000 calc(100% - var(--edge-fade)),transparent 100%),linear-gradient(to bottom,transparent 0,#000 var(--edge-fade),#000 calc(100% - var(--edge-fade)),transparent 100%);mask-composite:intersect}
.top>*{position:relative;z-index:1}.brand{display:flex;align-items:center;gap:12px;margin:0 0 4px}
.brand h1{margin:0;font-family:Georgia,"Times New Roman",serif;font-size:31px;line-height:1.05;font-weight:500;letter-spacing:0;color:#12304b}
.fleet{display:flex;align-items:center;gap:10px;margin:8px 0 0;color:var(--muted);font-size:14px}
.wave{width:44px;height:10px;color:var(--sea);opacity:.78}
.asof{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:22px}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 18px}
.metric{position:relative;min-width:0;display:grid;grid-template-columns:50px minmax(0,1fr);align-items:center;column-gap:12px;background:rgba(255,255,255,.82);border:1px solid rgba(210,226,234,.78);border-radius:8px;padding:14px 16px;box-shadow:0 12px 30px rgba(54,88,108,.06);backdrop-filter:blur(10px)}
.metric:before{content:"";grid-row:1/3;width:38px;height:38px;border-radius:50%;background:color-mix(in srgb,var(--metric-color,var(--wait)) 14%,white);box-shadow:inset 0 0 0 1px color-mix(in srgb,var(--metric-color,var(--wait)) 20%,transparent)}
.metric b{display:block;font-family:Georgia,"Times New Roman",serif;font-size:29px;line-height:1;font-weight:500;color:var(--ink)}
.metric span{display:block;font-size:12px;color:var(--muted);margin-top:2px}
.metric.live{--metric-color:var(--sea)}.metric.stale{--metric-color:var(--sun)}.metric.down{--metric-color:var(--down)}
.metric.live{border-color:rgba(37,132,95,.22)}.metric.stale{border-color:rgba(178,106,0,.24)}.metric.down{border-color:rgba(191,58,53,.24)}
.toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:0 0 18px;padding:9px;background:rgba(255,255,255,.72);border:1px solid rgba(210,226,234,.78);border-radius:8px;box-shadow:0 12px 30px rgba(54,88,108,.05);backdrop-filter:blur(10px)}
.toolbar-left,.toolbar-right{display:flex;align-items:center;gap:10px;min-width:0}
.seg{display:inline-flex;align-items:center;padding:3px;border:1px solid rgba(210,226,234,.86);border-radius:7px;background:rgba(244,250,251,.76)}
.seg button{appearance:none;border:0;background:transparent;color:var(--muted);display:grid;place-items:center;width:30px;height:28px;border-radius:6px;cursor:pointer}
.seg button[aria-pressed="true"]{background:#fff;color:var(--accent);box-shadow:0 1px 5px rgba(45,75,95,.12)}
.seg .ico{width:16px;height:16px}
.arrange{display:flex;align-items:center;gap:8px;color:var(--muted);font-size:12px;white-space:nowrap}
.arrange select{appearance:none;border:0;background:transparent;color:var(--ink);font:inherit;font-weight:600;outline:none;padding-right:2px;cursor:pointer}
.search{position:relative;min-width:210px;color:var(--muted)}
.search .ico{position:absolute;left:10px;top:50%;width:15px;height:15px;transform:translateY(-50%)}
.search input{width:100%;height:34px;border:1px solid rgba(210,226,234,.92);border-radius:7px;background:#fff;color:var(--ink);font:inherit;font-size:13px;padding:0 10px 0 32px;outline:none}
.search input:focus{border-color:rgba(31,127,181,.45);box-shadow:0 0 0 3px rgba(31,127,181,.08)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(270px,1fr));gap:18px}
.card{--state:var(--wait);position:relative;min-height:264px;display:flex;flex-direction:column;background:rgba(255,255,255,.88);border:1px solid rgba(211,225,233,.86);border-radius:8px;padding:15px 16px 14px;box-shadow:0 14px 32px rgba(45,75,95,.08);overflow:hidden}
.card:before{content:"";position:absolute;left:16px;right:16px;top:58px;height:1px;background:linear-gradient(90deg,transparent,rgba(31,127,181,.16),transparent);pointer-events:none}
[data-live="live"]{--state:var(--live)}[data-live="stale"]{--state:var(--stale)}[data-live="down"]{--state:var(--down)}[data-live="awaiting_first_heartbeat"]{--state:var(--wait)}
.card.light{border-color:rgba(214,155,49,.48);box-shadow:0 16px 34px rgba(150,103,28,.12)}
.halo{position:absolute;inset:-84px -74px auto auto;width:190px;height:190px;background:radial-gradient(circle,rgba(214,155,49,.20),rgba(21,158,153,.08) 42%,transparent 70%);pointer-events:none}
.lh{position:absolute;top:14px;right:14px;color:var(--sun)}
.lh .ico{width:22px;height:22px}
.card-head{position:relative;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;margin-bottom:10px}
.host{display:flex;align-items:center;gap:9px;min-width:0}
.nix{display:grid;place-items:center;width:30px;height:30px;border:1px solid rgba(102,121,139,.18);border-radius:50%;color:var(--accent);background:rgba(241,248,250,.72)}
.name{font-weight:650;font-size:16px;line-height:1.25;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.role{font-size:12px;color:var(--muted);margin-top:2px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.status-pill{display:inline-flex;align-items:center;gap:6px;min-height:25px;max-width:150px;flex-shrink:0;padding:4px 9px;border-radius:999px;border:1px solid color-mix(in srgb,var(--state) 24%,transparent);background:color-mix(in srgb,var(--state) 10%,white);color:var(--state);font-size:12px;white-space:nowrap}
.status-pill .ico{width:14px;height:14px}.word{color:inherit;overflow:hidden;text-overflow:ellipsis}
.state-icon{display:none}[data-live="live"] .state-icon.live,[data-live="stale"] .state-icon.stale,[data-live="down"] .state-icon.down,[data-live="awaiting_first_heartbeat"] .state-icon.awaiting{display:inline-block}
.reason{--reason-color:var(--muted);display:grid;grid-template-columns:7px minmax(0,1fr);align-items:center;gap:8px;min-height:22px;margin:-2px 0 10px;color:var(--muted);font-size:12px;line-height:1.25}
.reason:before{content:"";width:7px;height:7px;border-radius:50%;background:var(--reason-color);box-shadow:0 0 0 4px color-mix(in srgb,var(--reason-color) 12%,transparent)}
.reason.ok{--reason-color:var(--live)}.reason.warn{--reason-color:var(--stale)}.reason.down{--reason-color:var(--down)}.reason.wait{--reason-color:var(--wait)}.reason.self{--reason-color:var(--sun)}
.reason span{min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.fresh{min-height:52px;margin:4px 0 11px;font-size:13px;line-height:1.45;color:var(--ink)}
.fresh-row{display:grid;grid-template-columns:1fr auto;align-items:center;gap:10px;min-height:23px;border-bottom:1px solid rgba(214,226,234,.58)}
.fresh-row:last-child{border-bottom:0}
.fresh-row span{color:var(--muted);font-size:12px}
.fresh-row strong{font-size:12px;font-weight:650;color:var(--ink)}
.fresh-row strong.ok{color:var(--live)}.fresh-row strong.warn{color:var(--stale)}.fresh-row strong.na{color:var(--wait)}
.meta{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:auto;border-top:1px solid rgba(214,226,234,.72);padding-top:10px;font-size:11px;color:var(--muted)}
.meta strong{font-weight:600;color:var(--ink)}
.settings-card{display:inline-grid;grid-template-columns:22px minmax(0,auto) 16px;align-items:center;gap:8px;align-self:flex-start;max-width:100%;min-height:31px;margin:-2px 0 10px 39px;padding:4px 8px;border:1px solid rgba(210,226,234,.94);border-radius:999px;background:linear-gradient(180deg,rgba(255,255,255,.96),rgba(248,252,253,.88));color:var(--ink);text-decoration:none;box-shadow:0 7px 16px rgba(45,75,95,.055)}
.settings-card:hover{border-color:rgba(31,127,181,.34);box-shadow:0 9px 20px rgba(45,75,95,.09);transform:translateY(-1px)}
.settings-card.unavailable{--host-color:#aebac3;background:rgba(251,253,254,.82);color:var(--muted);box-shadow:none}
.settings-card.unavailable:hover{border-color:rgba(137,151,163,.34);box-shadow:0 8px 18px rgba(45,75,95,.05)}
.settings-card.unavailable .settings-icon{color:var(--muted)}
.settings-card.unavailable .settings-swatch{background:repeating-linear-gradient(135deg,#eef4f6 0 6px,#fff 6px 12px)}
.settings-icon{display:grid;place-items:center;width:22px;height:22px;border:1px solid rgba(210,226,234,.92);border-radius:50%;background:rgba(244,250,251,.82);color:var(--accent)}
.settings-icon .ico{width:13px;height:13px}
.settings-copy{min-width:0}.settings-copy strong{display:block;font-size:12px;line-height:1.1}.settings-copy span{display:none}
.settings-swatch{width:16px;height:16px;border-radius:50%;border:1px solid rgba(0,0,0,.12);background:var(--host-color,var(--sun));box-shadow:inset 0 0 0 2px rgba(255,255,255,.54)}
.beat{--beat-color:var(--state);--now-x:0%;--expect-x:64%;--stale-x:82%;--fill-color:var(--sea);--expect-fill:0deg;--expect-alpha:.55;--target-ring:3px;--late-alpha:.3;margin-top:10px;color:var(--beat-color)}
.beat-stage{position:relative;height:50px;overflow:hidden}
.beat-floor{position:absolute;left:0;right:0;top:21px;height:4px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.16) 0 var(--expect-x),rgba(214,155,49,.16) var(--expect-x) var(--stale-x),rgba(191,58,53,.12) var(--stale-x) 100%);box-shadow:inset 0 0 0 1px rgba(137,151,163,.18)}
.beat-fill{position:absolute;left:0;top:22px;width:var(--now-x);height:2px;border-radius:999px;background:linear-gradient(90deg,rgba(21,158,153,.18),var(--fill-color));transition:background-color .2s ease}
.beat-now{position:absolute;left:var(--now-x);top:23px;width:13px;height:13px;border-radius:50%;background:radial-gradient(circle,#fff 0 29%,var(--fill-color) 32% 62%,transparent 64%);box-shadow:0 0 0 5px color-mix(in srgb,var(--fill-color) 12%,transparent),0 0 14px color-mix(in srgb,var(--fill-color) 26%,transparent);transform:translate(-50%,-50%)}
.beat-current{position:absolute;top:22px;left:calc(var(--now-x) - 22%);width:22%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,color-mix(in srgb,var(--fill-color) 34%,transparent),transparent);animation:tide 2.8s linear infinite;opacity:.8}
.beat-marks{position:absolute;inset:0}
.beat-mark{position:absolute;left:var(--mark-x);top:23px;width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 0 4px color-mix(in srgb,currentColor 10%,transparent);opacity:.78;transform:translate(-50%,-50%)}
.beat[data-count="0"] .beat-mark{display:none}
.beat-expected{position:absolute;left:var(--expect-x);top:23px;width:18px;height:18px;border-radius:50%;border:1px solid #aebac3;background:conic-gradient(color-mix(in srgb,var(--beat-color) 72%,var(--sun)) var(--expect-fill),rgba(222,232,237,.9) 0),radial-gradient(circle,#fff 0 43%,transparent 45%);box-shadow:0 0 0 var(--target-ring) rgba(137,151,163,.12),0 0 16px rgba(214,155,49,.12);opacity:var(--expect-alpha);transform:translate(-50%,-50%)}
.beat-expected:before,.beat-expected:after{content:"";position:absolute;left:50%;top:50%;width:28px;height:1px;background:#aebac3;opacity:.5;transform:translate(-50%,-50%)}
.beat-expected:after{transform:translate(-50%,-50%) rotate(90deg)}
.beat-threshold{position:absolute;top:15px;bottom:15px;width:1px;background:rgba(137,151,163,.25)}
.beat-threshold.expected{left:var(--expect-x)}.beat-threshold.stale{left:var(--stale-x)}
.beat-hit{position:absolute;left:var(--hit-x,0%);top:23px;width:9px;height:9px;border-radius:50%;background:currentColor;opacity:0;transform:translate(-50%,-50%) scale(.7)}
.beat[data-flash="true"] .beat-hit{animation:beat-hit .9s ease-out}
.beat-zones{position:absolute;left:0;right:0;bottom:0;color:var(--muted);font-size:10px}
.beat-zones span{position:absolute;bottom:0;white-space:nowrap}.beat-zones span:first-child{left:0}.beat-zones span:nth-child(2){left:var(--expect-x);transform:translateX(-50%)}.beat-zones span:nth-child(3){right:0;color:var(--stale)}
.beat[data-beat="late"]{--beat-color:var(--stale)}.beat[data-beat="stale"]{--beat-color:var(--stale)}.beat[data-beat="down"]{--beat-color:var(--down)}.beat[data-beat="late"] .beat-expected,.beat[data-beat="stale"] .beat-expected,.beat[data-beat="down"] .beat-expected{opacity:.86}.beat[data-beat="waiting"]{--beat-color:var(--wait)}.beat[data-beat="waiting"] .beat-expected{opacity:.22}.beat[data-beat="lit"]{--beat-color:var(--sun)}
.beat-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:2px;font-size:11px;color:var(--muted)}
.beat-meta strong{font-size:12px;color:var(--beat-color);font-weight:650}
@keyframes beat-hit{0%{opacity:.9;transform:translate(-50%,-50%) scale(.55);box-shadow:0 0 0 0 color-mix(in srgb,currentColor 28%,transparent)}100%{opacity:0;transform:translate(-50%,-50%) scale(2.4);box-shadow:0 0 0 12px transparent}}
@keyframes tide{from{transform:translateX(-16%)}to{transform:translateX(42%)}}
.list-wrap{display:none}
main[data-view="list"] .grid{display:none}
main[data-view="list"] .list-wrap{display:block}
.list{width:100%;border-collapse:separate;border-spacing:0 8px}
.list th{padding:0 12px 6px;text-align:left;color:var(--muted);font-size:11px;font-weight:600}
.list td{padding:12px;background:rgba(255,255,255,.88);border-top:1px solid rgba(211,225,233,.86);border-bottom:1px solid rgba(211,225,233,.86);vertical-align:middle}
.list td:first-child{border-left:1px solid rgba(211,225,233,.86);border-radius:8px 0 0 8px}
.list td:last-child{border-right:1px solid rgba(211,225,233,.86);border-radius:0 8px 8px 0}
.list tr.light td{border-color:rgba(214,155,49,.34)}
.list .host{min-width:210px}.list .reason{min-width:150px;margin:0}.list .fresh{min-height:0;margin:0;white-space:nowrap}.list .fresh-row{min-height:20px}.list .status-pill{max-width:120px}.list .beat{width:230px;margin:0}.list .beat-meta{display:none}.list .settings-card{display:inline-flex;min-height:30px;margin:0;padding:5px 9px}.list .settings-icon{width:22px;height:22px}.list .settings-copy span,.list .settings-swatch{display:none}.list .settings-copy strong{font-size:12px}
[hidden]{display:none!important}
.empty-state,.lone-state{position:relative;overflow:hidden;border:1px solid rgba(210,226,234,.86);border-radius:8px;background:linear-gradient(135deg,rgba(255,255,255,.94),rgba(239,249,250,.78));box-shadow:0 16px 38px rgba(54,88,108,.08)}
.empty-state{min-height:430px;margin-top:18px;padding:36px;display:grid;grid-template-columns:minmax(0,1.05fr) minmax(240px,.95fr);align-items:center;gap:30px}
.empty-state:before,.lone-state:before{content:"";position:absolute;inset:auto -8% -30% -8%;height:50%;background:repeating-linear-gradient(178deg,rgba(31,127,181,.12) 0 1px,transparent 1px 28px);opacity:.72;pointer-events:none}
.empty-copy{position:relative;max-width:440px}
.empty-kicker,.lone-kicker{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:var(--sun);font-weight:700}
.empty-copy h2{margin:8px 0 9px;font-size:30px;line-height:1.12;letter-spacing:0}
.empty-copy p,.lone-copy p{margin:0;color:var(--muted);font-size:14px}
.onboard-command{margin-top:18px;display:inline-flex;align-items:center;gap:9px;max-width:100%;padding:10px 12px;border:1px solid rgba(210,226,234,.95);border-radius:7px;background:#fff;color:var(--ink);box-shadow:0 8px 20px rgba(45,75,95,.06);font:13px/1.3 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;white-space:normal;word-break:break-word}
.onboard-command .ico{color:var(--sea)}
.empty-visual{position:relative;min-height:285px;display:grid;place-items:center;color:var(--sun)}
.empty-sun{position:absolute;right:14%;top:8%;width:66px;height:66px;border-radius:50%;background:radial-gradient(circle,#fff 0 34%,rgba(214,155,49,.26) 36% 58%,transparent 60%);box-shadow:0 0 0 12px rgba(214,155,49,.06),0 0 42px rgba(214,155,49,.20)}
.empty-line{position:absolute;left:7%;right:7%;top:57%;height:2px;border-radius:999px;background:linear-gradient(90deg,transparent,rgba(21,158,153,.42),rgba(214,155,49,.46),transparent)}
.empty-line:after{content:"";position:absolute;left:0;top:50%;width:26%;height:3px;border-radius:999px;background:linear-gradient(90deg,transparent,var(--sea),transparent);animation:tide 3.2s linear infinite;transform:translateY(-50%)}
.empty-lighthouse{position:relative;display:grid;place-items:center;width:150px;height:150px;border-radius:50%;background:radial-gradient(circle,rgba(214,155,49,.18),rgba(255,255,255,.66) 54%,transparent 70%);color:var(--sun)}
.empty-lighthouse .ico{width:68px;height:68px}
.empty-await{position:absolute;left:50%;bottom:16%;transform:translateX(-50%);font-size:11px;color:var(--muted);white-space:nowrap}
.lone-state{margin-top:14px;padding:17px 18px;display:grid;grid-template-columns:auto 1fr auto;align-items:center;gap:16px}
.lone-mark{position:relative;display:grid;place-items:center;width:46px;height:46px;border-radius:50%;border:1px solid rgba(214,155,49,.28);background:rgba(255,255,255,.74);color:var(--sun)}
.lone-mark .ico{width:24px;height:24px}
.lone-copy{position:relative;min-width:0}.lone-copy strong{display:block;font-size:15px}.lone-copy p{font-size:12px}
.lone-state .onboard-command{position:relative;margin:0;font-size:12px}
@media (max-width:900px){.app-shell{display:block}.sidebar{position:relative;height:auto;min-height:0;display:grid;grid-template-columns:1fr;gap:14px;padding:18px;border-right:0;border-bottom:1px solid rgba(211,225,233,.78)}.sidebar:before{display:none}.side-brand{padding:0}.side-nav{grid-template-columns:repeat(3,minmax(0,1fr))}.side-link{min-height:38px;padding:0 10px}.side-foot{display:none}main{padding:28px 18px 42px}.top{display:block;min-height:112px}.asof{padding-top:10px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.toolbar{align-items:stretch;flex-direction:column}.toolbar-left,.toolbar-right{justify-content:space-between}.search{min-width:0;width:100%}.grid{grid-template-columns:1fr}.list-wrap{overflow-x:auto}.list{min-width:900px}}
@media (max-width:720px){.empty-state{grid-template-columns:1fr;min-height:0;padding:24px}.empty-copy h2{font-size:24px}.empty-visual{min-height:210px;order:-1}.lone-state{grid-template-columns:auto 1fr}.lone-state .onboard-command{grid-column:1/-1;width:100%}}
@media (prefers-reduced-motion:reduce){.beat-current,.beat[data-flash="true"] .beat-hit{animation:none}}
</style></head><body><div class="app-shell">"#;

const FOOT: &str = r#"</div><script>
const words={live:'live',stale:'stale',down:'down',awaiting_first_heartbeat:'awaiting'};
const MAX_BEATS=8;
const EXPECT_X=64;
const STALE_X=82;
function dur(s){s=Math.max(0,s);if(s<10)return s.toFixed(1)+'s';s=Math.ceil(s);return s<60?s+'s':Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s'}
function clock(t){return new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
const ESC={'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'};
function esc(v){return String(v ?? '').replace(/[&<>"']/g,ch=>ESC[ch])}
function cookie(name){return document.cookie.split('; ').find(v=>v.startsWith(name+'='))?.split('=').slice(1).join('=')||''}
function setCookie(name,value){document.cookie=name+'='+encodeURIComponent(value)+'; path=/; max-age=31536000; SameSite=Lax'}
function hostSurfaces(name){return Array.from(document.querySelectorAll('[data-host]')).filter(el=>el.dataset.host===name)}
function parseBeats(v){return String(v||'').split(',').map(Number).filter(Number.isFinite).filter(n=>n>0)}
function freshRow(label,value,klass){return '<div class="fresh-row"><span>'+esc(label)+'</span><strong class="'+klass+'">'+esc(value)+'</strong></div>'}
function freshValue(v,zero){
  const n=Number(v);
  if(v==null||!Number.isFinite(n))return {value:'unknown',klass:'na'};
  if(n===0)return {value:zero,klass:'ok'};
  return {value:String(n),klass:'warn'};
}
function freshHtml(f){
  if(!f||f.applicable===false)return freshRow('Flake.lock age','n/a','na')+freshRow('Commits behind','n/a','na');
  const age=freshValue(f.flake_lock_age_days,'fresh');
  const commits=freshValue(f.commits_behind,'0');
  if(age.klass==='warn')age.value=age.value+'d';
  return freshRow('Flake.lock age',age.value,age.klass)+freshRow('Commits behind',commits.value,commits.klass);
}
function freshnessAttention(f){
  if(!f||f.applicable===false)return null;
  const age=Number(f.flake_lock_age_days);
  const commits=Number(f.commits_behind);
  const hasAge=f.flake_lock_age_days!=null&&Number.isFinite(age);
  const hasCommits=f.commits_behind!=null&&Number.isFinite(commits);
  const ageWarn=hasAge&&age>0;
  const commitsWarn=hasCommits&&commits>0;
  if(ageWarn&&commitsWarn)return {label:'nix drift: '+age+'d · '+commits+' commits',level:'warn',rank:3};
  if(ageWarn)return {label:'flake.lock '+age+'d',level:'warn',rank:3};
  if(commitsWarn)return {label:commits+' commits behind',level:'warn',rank:3};
  if(!hasAge||!hasCommits)return {label:'freshness unknown',level:'wait',rank:3};
  return null;
}
function attentionFor(live,f){
  if(live==='down')return {label:'silent heartbeat',level:'down',rank:0};
  if(live==='stale')return {label:'stale heartbeat',level:'warn',rank:1};
  if(live==='awaiting_first_heartbeat')return {label:'awaiting first beat',level:'wait',rank:2};
  return freshnessAttention(f)||{label:'all clear',level:'ok',rank:4};
}
function selfAttention(){return {label:'control light',level:'self',rank:4}}
function setReason(surface,reason){
  const el=surface.querySelector('[data-reason]');
  if(!el)return;
  el.className='reason '+reason.level;
  const text=el.querySelector('span');
  if(text)text.textContent=reason.label;
}
function markHtml(beats){
  const kept=beats.slice(-MAX_BEATS);
  if(!kept.length)return '';
  const start=4,end=28;
  const step=kept.length===1?0:(end-start)/(kept.length-1);
  return kept.map((_,i)=>{
    const x=kept.length===1?end:start+i*step;
    return '<span class="beat-mark" style="--mark-x:'+x.toFixed(1)+'%"></span>';
  }).join('');
}
function setBeatHistory(beat,beats){
  const kept=Array.from(new Set(beats)).sort((a,b)=>a-b).slice(-MAX_BEATS);
  beat.dataset.beats=kept.join(',');
  beat.dataset.count=String(kept.length);
  const marks=beat.querySelector('.beat-marks');
  if(marks)marks.innerHTML=markHtml(kept);
}
function flashBeat(beat){
  beat.dataset.flash='true';
  window.setTimeout(()=>{delete beat.dataset.flash},950);
}
function heartbeatX(age,interval){
  if(age<=interval)return (age/interval)*EXPECT_X;
  if(age<=interval*2)return EXPECT_X+((age-interval)/interval)*(STALE_X-EXPECT_X);
  if(age<=interval*5)return STALE_X+((age-interval*2)/(interval*3))*(100-STALE_X);
  return 100;
}
function cadenceLabel(age,interval){
  if(age<interval*.66)return 'on cadence';
  if(age<interval*.92)return 'approaching';
  return 'due now';
}
function updateBeatClock(beat,now){
  const last=Number(beat.dataset.last);
  const interval=Math.max(1,Number(beat.dataset.interval)||60);
  const next=beat.querySelector('[data-next]');
  if(!Number.isFinite(last)||last<=0){
    beat.style.setProperty('--expect-alpha','.22');
    beat.style.setProperty('--now-x','0%');
    beat.style.setProperty('--fill-color','var(--wait)');
    beat.style.setProperty('--expect-fill','0deg');
    beat.style.setProperty('--target-ring','3px');
    beat.style.setProperty('--late-alpha','.3');
    beat.dataset.beat='waiting';
    if(next)next.textContent='waiting';
    return;
  }
  const age=Math.max(0,now-last);
  const expect=Math.max(0,Math.min(1,age/interval));
  const x=heartbeatX(age,interval);
  beat.style.setProperty('--now-x',x.toFixed(2)+'%');
  beat.style.setProperty('--expect-alpha',(.34+expect*.45).toFixed(3));
  beat.style.setProperty('--expect-fill',(expect*360).toFixed(1)+'deg');
  beat.style.setProperty('--target-ring',(3+expect*5).toFixed(1)+'px');
  if(age<=interval){
    beat.style.setProperty('--fill-color',beat.dataset.self==='true'?'var(--sun)':'var(--sea)');
    beat.dataset.beat=beat.dataset.self==='true'?'lit':'tracking';
    if(next)next.textContent=cadenceLabel(age,interval);
  }else if(age<=interval*2){
    beat.style.setProperty('--fill-color','var(--sun)');
    beat.style.setProperty('--expect-alpha','.79');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='late';
    if(next)next.textContent='late';
  }else if(age<=interval*5){
    beat.style.setProperty('--fill-color','var(--stale)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='stale';
    if(next)next.textContent='stale';
  }else{
    beat.style.setProperty('--fill-color','var(--down)');
    beat.style.setProperty('--expect-alpha','.86');
    beat.style.setProperty('--expect-fill','360deg');
    beat.style.setProperty('--target-ring','8px');
    beat.dataset.beat='down';
    if(next)next.textContent='silent';
  }
}
function frame(){
  const now=Date.now()/1000;
  document.querySelectorAll('.beat').forEach(beat=>{
    updateBeatClock(beat,now);
  });
  requestAnimationFrame(frame);
}
function setSeen(card,last,now){
  const seen=card.querySelector('[data-seen]');
  if(!seen)return;
  if(last==null){seen.textContent='never seen';return}
  seen.textContent='last seen '+dur(now-last)+' ago';
}
function sevFor(live){return live==='down'?0:live==='stale'?1:live==='awaiting_first_heartbeat'?2:3}
function cmp(a,b,mode){
  const self=Number(b.dataset.self==='true')-Number(a.dataset.self==='true');
  if(self)return self;
  if(mode==='name')return a.dataset.sortName.localeCompare(b.dataset.sortName);
  if(mode==='last')return Number(b.dataset.last||0)-Number(a.dataset.last||0)||a.dataset.sortName.localeCompare(b.dataset.sortName);
  return Number(a.dataset.sev)-Number(b.dataset.sev)||a.dataset.sortName.localeCompare(b.dataset.sortName);
}
function applySort(mode,write=true){
  mode=['attention','name','last'].includes(mode)?mode:'attention';
  const grid=document.querySelector('[data-grid]');
  const body=document.querySelector('[data-list-body]');
  if(grid)Array.from(grid.querySelectorAll('.card')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>grid.appendChild(el));
  if(body)Array.from(body.querySelectorAll('tr')).sort((a,b)=>cmp(a,b,mode)).forEach(el=>body.appendChild(el));
  const select=document.querySelector('[data-sort]');
  if(select)select.value=mode;
  if(write)setCookie('pharos_sort',mode);
}
function applyView(view,write=true){
  view=view==='list'?'list':'grid';
  const main=document.querySelector('main');
  if(main)main.dataset.view=view;
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.setAttribute('aria-pressed',String(btn.dataset.viewButton===view)));
  if(write)setCookie('pharos_view',view);
}
function applyFilter(query,write=true){
  const q=query.trim().toLowerCase();
  document.querySelectorAll('[data-host]').forEach(el=>{el.hidden=q!==''&&!el.dataset.search.includes(q)});
  const input=document.querySelector('[data-search]');
  if(input&&input.value!==query)input.value=query;
  if(write)setCookie('pharos_search',query);
}
function updateUrlState(){
  const main=document.querySelector('main');
  const sort=document.querySelector('[data-sort]')?.value||'attention';
  const params=new URLSearchParams(location.search);
  params.set('view',main?.dataset.view||'grid');
  params.set('sort',sort);
  const url=location.pathname+'?'+params.toString();
  history.replaceState(null,'',url);
}
function initControls(){
  const params=new URLSearchParams(location.search);
  const view=params.get('view')||decodeURIComponent(cookie('pharos_view'))||'grid';
  const sort=params.get('sort')||decodeURIComponent(cookie('pharos_sort'))||'attention';
  const search=decodeURIComponent(cookie('pharos_search'));
  applyView(view,false);
  applySort(sort,false);
  applyFilter(search,false);
  document.querySelectorAll('[data-view-button]').forEach(btn=>btn.addEventListener('click',()=>{applyView(btn.dataset.viewButton);updateUrlState()}));
  document.querySelector('[data-sort]')?.addEventListener('change',e=>{applySort(e.target.value);updateUrlState()});
  document.querySelector('[data-search]')?.addEventListener('input',e=>applyFilter(e.target.value));
}
async function refresh(){
  try{
    const res=await fetch('/hosts.json',{headers:{Accept:'application/json'}});
    if(!res.ok)return;
    const data=await res.json();
    const now=Number(data.as_of)||Math.floor(Date.now()/1000);
    const asof=document.querySelector('[data-as-of]');
    if(asof)asof.textContent='as of '+clock(now);
    for(const h of data.hosts||[]){
      const surfaces=hostSurfaces(h.name);
      for(const card of surfaces){
        const live=card.dataset.self==='true'?'live':h.liveness;
        card.dataset.live=live;
        const attention=card.dataset.self==='true'?selfAttention():(h.attention||attentionFor(h.liveness,h.freshness));
        card.dataset.sev=String(attention.rank ?? sevFor(live));
        card.dataset.last=h.last_seen ?? 0;
        card.dataset.search=(String(h.name||'')+' '+String(h.role||'')+' '+String(h.freshness_tldr||'')+' '+String(attention.label||'')).toLowerCase();
        const word=card.querySelector('[data-status-word]');
        if(word&&card.dataset.self!=='true')word.textContent=words[h.liveness]||h.liveness;
        setReason(card,attention);
        const fresh=card.querySelector('[data-fresh]');
        if(fresh)fresh.innerHTML=freshHtml(h.freshness);
        setSeen(card,h.last_seen,now);
        const beat=card.querySelector('.beat');
        if(beat){
          const previous=Number(beat.dataset.last);
          const last=h.last_seen == null ? NaN : Number(h.last_seen);
          const interval=h.heartbeat_interval_secs || 60;
          const incoming=Array.isArray(h.heartbeat_log)?h.heartbeat_log.map(Number).filter(Number.isFinite):[];
          const beats=incoming.length?incoming:(Number.isFinite(last)?[last]:[]);
          setBeatHistory(beat,beats);
          if(beat.dataset.ready==='true'&&Number.isFinite(previous)&&Number.isFinite(last)&&last>previous){
            beat.style.setProperty('--hit-x',heartbeatX(Math.max(0,last-previous),Math.max(1,Number(interval)||60)).toFixed(2)+'%');
            flashBeat(beat);
          }
          beat.dataset.ready='true';
          beat.dataset.last=Number.isFinite(last)?String(last):'';
          beat.dataset.interval=interval;
          beat.dataset.nextAt=Number.isFinite(last)?String(last+interval):'';
        }
      }
    }
    applySort(document.querySelector('[data-sort]')?.value||'attention',false);
  }catch(_){}
}
document.querySelectorAll('.beat').forEach(beat=>{setBeatHistory(beat,parseBeats(beat.dataset.beats));beat.dataset.ready='true'});
initControls();
requestAnimationFrame(frame);
setInterval(refresh,10000);
setTimeout(refresh,3000);
</script></body></html>"#;

const HEARTBEAT_UI_EVENTS: usize = 8;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// The host pharosd itself runs on — gets the lighthouse treatment (PHAROS-10).
fn self_host() -> String {
    std::env::var("PHAROS_SELF").unwrap_or_else(|_| "csb1".into())
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => None,
    }
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
        .filter(|s| !s.is_empty())
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let len = left.len().max(right.len());
    let mut diff = left.len() ^ right.len();
    for idx in 0..len {
        diff |=
            usize::from(left.get(idx).copied().unwrap_or(0) ^ right.get(idx).copied().unwrap_or(0));
    }
    diff == 0
}

fn hex(bytes: &[u8]) -> String {
    const CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(CHARS[(b >> 4) as usize] as char);
        out.push(CHARS[(b & 0x0f) as usize] as char);
    }
    out
}

fn token_hash(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

fn new_beacon_token() -> std::io::Result<String> {
    let mut bytes = [0_u8; 32];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(format!("pharos_{}", hex(&bytes)))
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "name": "pharosd", "version": env!("CARGO_PKG_VERSION") }))
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(rep): Json<HostReport>,
) -> StatusCode {
    let host_has_token = state.store.has_token(&rep.name);
    if host_has_token || state.beacon_auth.require_report_token {
        let Some(token) = bearer_token(&headers) else {
            tracing::warn!(host = %rep.name, "report rejected: missing bearer token");
            return StatusCode::UNAUTHORIZED;
        };
        let expected_hash = token_hash(token);
        let valid = state
            .store
            .token_hash_for(&rep.name)
            .is_some_and(|stored| constant_time_eq(&stored, &expected_hash));
        if !valid {
            tracing::warn!(host = %rep.name, "report rejected: invalid bearer token");
            return StatusCode::UNAUTHORIZED;
        }
    } else {
        tracing::warn!(
            host = %rep.name,
            "accepting legacy unauthenticated report; register a per-host token to enforce PHAROS-8"
        );
    }
    tracing::info!(host = %rep.name, "report received");
    state.store.record(rep, now_unix());
    StatusCode::NO_CONTENT
}

/// Local host registration for MVP onboarding (PHAROS-8/7). Protected by a
/// deployment-local bootstrap token; the returned beacon token is shown once.
async fn register(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(registration): Json<HostRegistration>,
) -> (StatusCode, Json<serde_json::Value>) {
    match state.beacon_auth.registration_status(&headers) {
        RegistrationAuth::Allowed => {}
        RegistrationAuth::Denied => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "registration token invalid" })),
            )
        }
        RegistrationAuth::NotConfigured => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "error": "PHAROS_REGISTRATION_TOKEN not configured" })),
            )
        }
    }

    let token = match new_beacon_token() {
        Ok(token) => token,
        Err(err) => {
            tracing::error!("failed to generate beacon token: {err}");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "token generation failed" })),
            );
        }
    };
    let response = HostRegistrationResponse {
        name: registration.name.clone(),
        token: token.clone(),
    };
    let host = state.store.register(registration, token_hash(&token));
    tracing::info!(host = %host.name, "beacon token issued");
    (
        StatusCode::CREATED,
        Json(serde_json::to_value(response).expect("registration response serializes")),
    )
}

async fn hosts_json(State(store): State<Arc<Store>>) -> Json<serde_json::Value> {
    let now = now_unix();
    let hosts: Vec<_> = store
        .list()
        .into_iter()
        .map(|h| {
            let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
            let freshness_tldr = h.freshness.tldr();
            let attention = attention_reason(live, &h.freshness);
            json!({
                "name": h.name,
                "role": h.role,
                "is_nix": h.is_nix,
                "last_seen": h.last_seen,
                "heartbeat_log": h.heartbeat_log,
                "heartbeat_interval_secs": h.heartbeat_interval_secs,
                "liveness": live,
                "freshness": h.freshness,
                "freshness_tldr": freshness_tldr,
                "attention": {
                    "label": attention.label,
                    "level": attention.level,
                    "rank": attention.rank,
                },
            })
        })
        .collect();
    Json(json!({ "as_of": now, "hosts": hosts }))
}

async fn declared_hosts_json(State(state): State<AppState>) -> Json<serde_json::Value> {
    let now = now_unix();
    let runtime_hosts = state.store.list();
    Json(declared_hosts_payload(
        state.manifests.manifests(),
        state.manifests.load_errors(),
        &runtime_hosts,
        now,
    ))
}

fn declared_hosts_payload(
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    runtime_hosts: &[Host],
    now: i64,
) -> serde_json::Value {
    let runtime_by_name: BTreeMap<&str, &Host> = runtime_hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let declared_hosts: Vec<_> = manifests
        .iter()
        .map(|manifest| {
            let runtime = runtime_by_name
                .get(manifest.host.name.as_str())
                .copied()
                .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
            json!({
                "name": &manifest.host.name,
                "slug": &manifest.slug,
                "declared": manifest,
                "runtime": runtime_overlay(runtime, now),
            })
        })
        .collect();

    json!({
        "schema": "inspr.pharos.declared-hosts.v1",
        "manifest_schema": HOST_MANIFEST_SCHEMA,
        "manifest_version": HOST_MANIFEST_VERSION,
        "as_of": now,
        "declared_hosts": declared_hosts,
        "load_errors": load_errors,
    })
}

fn runtime_overlay(host: Option<&Host>, now: i64) -> serde_json::Value {
    let Some(host) = host else {
        return json!({
            "state": "pending",
            "liveness": Liveness::AwaitingFirstHeartbeat,
            "last_seen": null,
            "heartbeat_log": [],
            "heartbeat_interval_secs": null,
            "freshness": null,
            "freshness_tldr": null,
        });
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    json!({
        "state": "observed",
        "last_seen": host.last_seen,
        "heartbeat_log": host.heartbeat_log,
        "heartbeat_interval_secs": host.heartbeat_interval_secs,
        "liveness": live,
        "freshness": host.freshness,
        "freshness_tldr": host.freshness.tldr(),
    })
}

async fn home(State(state): State<AppState>) -> Html<String> {
    Html(render_home(
        &state.store.list(),
        &self_host(),
        now_unix(),
        state.manifests.manifests(),
    ))
}

async fn fleet_horizon_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        FLEET_HORIZON_PNG,
    )
}

async fn sidebar_lighthouse_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SIDEBAR_LIGHTHOUSE_PNG,
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

fn url_query_escape(s: &str) -> String {
    let mut encoded = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(byte as char);
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn manifest_palette_color(manifests: &[HostManifest]) -> BTreeMap<String, String> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        let Some(color) = manifest.palette.as_ref().and_then(|palette| {
            palette
                .accent
                .clone()
                .or_else(|| palette.gradient.get("primary").cloned())
        }) else {
            continue;
        };
        by_host.insert(manifest.host.name.clone(), color.clone());
        by_host.insert(manifest.slug.clone(), color);
    }
    by_host
}

fn freshness_row(label: &str, value: &str, class: &str) -> String {
    format!(
        r#"<div class="fresh-row"><span>{}</span><strong class="{}">{}</strong></div>"#,
        html_escape(label),
        html_escape(class),
        html_escape(value)
    )
}

fn freshness_value(value: Option<u32>, zero_label: &str) -> (String, &'static str) {
    match value {
        Some(0) => (zero_label.to_string(), "ok"),
        Some(v) => (v.to_string(), "warn"),
        None => ("unknown".to_string(), "na"),
    }
}

fn freshness_markup(freshness: &NixFreshness) -> String {
    if !freshness.applicable {
        return format!(
            "{}{}",
            freshness_row("Flake.lock age", "n/a", "na"),
            freshness_row("Commits behind", "n/a", "na")
        );
    }

    let (mut age, age_class) = freshness_value(freshness.flake_lock_age_days, "fresh");
    if age_class == "warn" {
        age.push('d');
    }
    let (commits, commits_class) = freshness_value(freshness.commits_behind, "0");
    format!(
        "{}{}",
        freshness_row("Flake.lock age", &age, age_class),
        freshness_row("Commits behind", &commits, commits_class)
    )
}

struct AttentionReason {
    label: String,
    level: &'static str,
    rank: u8,
}

fn self_attention_reason() -> AttentionReason {
    AttentionReason {
        label: "control light".to_string(),
        level: "self",
        rank: 4,
    }
}

fn freshness_attention_reason(freshness: &NixFreshness) -> Option<AttentionReason> {
    if !freshness.applicable {
        return None;
    }

    let age_warn = freshness.flake_lock_age_days.filter(|d| *d > 0);
    let commits_warn = freshness.commits_behind.filter(|c| *c > 0);
    let label = match (age_warn, commits_warn) {
        (Some(days), Some(commits)) => format!("nix drift: {days}d · {commits} commits"),
        (Some(days), None) => format!("flake.lock {days}d"),
        (None, Some(commits)) => format!("{commits} commits behind"),
        (None, None) => {
            if freshness.flake_lock_age_days.is_none() || freshness.commits_behind.is_none() {
                "freshness unknown".to_string()
            } else {
                return None;
            }
        }
    };

    Some(AttentionReason {
        label,
        level: if age_warn.is_some() || commits_warn.is_some() {
            "warn"
        } else {
            "wait"
        },
        rank: 3,
    })
}

fn attention_reason(live: Liveness, freshness: &NixFreshness) -> AttentionReason {
    match live {
        Liveness::Down => AttentionReason {
            label: "silent heartbeat".to_string(),
            level: "down",
            rank: 0,
        },
        Liveness::Stale => AttentionReason {
            label: "stale heartbeat".to_string(),
            level: "warn",
            rank: 1,
        },
        Liveness::AwaitingFirstHeartbeat => AttentionReason {
            label: "awaiting first beat".to_string(),
            level: "wait",
            rank: 2,
        },
        Liveness::Live => {
            freshness_attention_reason(freshness).unwrap_or_else(|| AttentionReason {
                label: "all clear".to_string(),
                level: "ok",
                rank: 4,
            })
        }
    }
}

fn reason_markup(reason: &AttentionReason) -> String {
    format!(
        r#"<div class="reason {}" data-reason><span>{}</span></div>"#,
        html_escape(reason.level),
        html_escape(&reason.label)
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

fn icon_with_class(svg: &str, class: &str) -> String {
    svg.replacen("class=\"ico\"", &format!("class=\"ico {class}\""), 1)
}

fn status_icon_stack() -> String {
    format!(
        "{}{}{}{}",
        icon_with_class(icons::status_svg(Liveness::Live), "state-icon live"),
        icon_with_class(icons::status_svg(Liveness::Stale), "state-icon stale"),
        icon_with_class(icons::status_svg(Liveness::Down), "state-icon down"),
        icon_with_class(
            icons::status_svg(Liveness::AwaitingFirstHeartbeat),
            "state-icon awaiting"
        )
    )
}

fn duration_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

fn clock_label(timestamp: i64) -> String {
    let seconds = timestamp.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

fn summary_cards(hosts: &[Host], self_name: &str, now: i64) -> String {
    let mut live = 0;
    let mut stale = 0;
    let mut down = 0;
    let mut awaiting = 0;
    for h in hosts {
        let live_state = if h.name == self_name {
            Liveness::Live
        } else {
            liveness(h.last_seen, h.heartbeat_interval_secs, now)
        };
        match live_state {
            Liveness::Live => live += 1,
            Liveness::Stale => stale += 1,
            Liveness::Down => down += 1,
            Liveness::AwaitingFirstHeartbeat => awaiting += 1,
        }
    }
    format!(
        r#"<section class="summary" aria-label="fleet summary"><div class="metric live"><b>{live}</b><span>Live</span></div><div class="metric stale"><b>{stale}</b><span>Stale</span></div><div class="metric down"><b>{down}</b><span>Down</span></div><div class="metric"><b>{awaiting}</b><span>Awaiting</span></div></section>"#
    )
}

fn sidebar() -> String {
    format!(
        r##"<aside class="sidebar" aria-label="primary navigation"><div class="side-brand"><span class="side-mark">{lighthouse}</span><span class="side-logo">PHAROS</span></div><nav class="side-nav"><a class="side-link" href="/" aria-current="page">{fleet}<span>Fleet</span></a><a class="side-link" href="/">{map}<span>Map</span></a><a class="side-link" href="/">{alerts}<span>Alerts</span></a><a class="side-link" href="/">{activity}<span>Activity</span></a><a class="side-link" href="/agora">{settings}<span>Settings</span></a></nav><div class="side-foot"><span class="side-user">mba</span><span aria-hidden="true">v</span></div></aside>"##,
        lighthouse = icons::LIGHTHOUSE,
        fleet = icons::GRID,
        map = icons::SERVER,
        alerts = icons::status_svg(Liveness::Stale),
        activity = icons::LIST,
        settings = icons::SLIDERS
    )
}

fn header(now: i64) -> String {
    format!(
        r#"<div class="top"><div><div class="brand"><h1>Fleet</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">All hosts at a glance</p></div><div class="asof" data-as-of>as of {as_of}</div></div>"#,
        as_of = clock_label(now)
    )
}

fn toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="fleet controls"><div class="toolbar-left"><div class="seg" role="group" aria-label="view"><button type="button" data-view-button="grid" aria-pressed="true" title="Grid view">{grid}</button><button type="button" data-view-button="list" aria-pressed="false" title="List view">{list}</button></div><label class="arrange">Arrange by <select data-sort aria-label="arrange by"><option value="attention">Needs attention</option><option value="name">Name</option><option value="last">Last change</option></select></label></div><div class="toolbar-right"><label class="search">{search}<input data-search type="search" autocomplete="off" placeholder="Search hosts..."></label></div></section>"#,
        grid = icons::GRID,
        list = icons::LIST,
        search = icons::SEARCH
    )
}

fn onboard_command() -> String {
    format!(
        r#"<code class="onboard-command">{icon}<span>inspr onboard &lt;host&gt;</span></code>"#,
        icon = icons::TERMINAL
    )
}

fn empty_state() -> String {
    format!(
        r#"<section class="empty-state" aria-label="first run"><div class="empty-copy"><span class="empty-kicker">first light</span><h2>Waiting for the first host</h2><p>Register a host and Pharos will hold it in the grey awaiting state until the first real heartbeat arrives.</p>{command}</div><div class="empty-visual" aria-hidden="true"><span class="empty-sun"></span><span class="empty-line"></span><span class="empty-lighthouse">{lighthouse}</span><span class="empty-await">awaiting first heartbeat</span></div></section>"#,
        command = onboard_command(),
        lighthouse = icons::LIGHTHOUSE
    )
}

fn lone_host_state() -> String {
    format!(
        r#"<aside class="lone-state" aria-label="lone host state"><span class="lone-mark">{lighthouse}</span><div class="lone-copy"><span class="lone-kicker">one light</span><strong>First host is on the map</strong><p>The fleet view is ready for the next onboarded machine.</p></div>{command}</aside>"#,
        lighthouse = icons::LIGHTHOUSE,
        command = onboard_command()
    )
}

fn recent_heartbeat_log(log: &[i64], last_seen: Option<i64>) -> Vec<i64> {
    let mut recent = log.to_vec();
    if recent.is_empty() {
        if let Some(last) = last_seen {
            recent.push(last);
        }
    }
    recent.sort_unstable();
    recent.dedup();
    if recent.len() > HEARTBEAT_UI_EVENTS {
        recent.drain(0..recent.len() - HEARTBEAT_UI_EVENTS);
    }
    recent
}

fn heartbeat_marks(log: &[i64]) -> String {
    if log.is_empty() {
        return String::new();
    }

    let start = 4.0;
    let end = 28.0;
    let step = if log.len() == 1 {
        0.0
    } else {
        (end - start) / (log.len() - 1) as f64
    };
    let mut marks = String::new();
    for idx in 0..log.len() {
        let x = if log.len() == 1 {
            end
        } else {
            start + idx as f64 * step
        };
        marks.push_str(&format!(
            r#"<span class="beat-mark" style="--mark-x:{x:.1}%"></span>"#
        ));
    }
    marks
}

fn heartbeat_x(age: i64, interval: i64) -> f64 {
    let age = age.max(0) as f64;
    let interval = interval.max(1) as f64;
    if age <= interval {
        return (age / interval) * 64.0;
    }
    if age <= interval * 2.0 {
        return 64.0 + ((age - interval) / interval) * 18.0;
    }
    if age <= interval * 5.0 {
        return 82.0 + ((age - interval * 2.0) / (interval * 3.0)) * 18.0;
    }
    100.0
}

fn heartbeat_cadence_label(age: i64, interval: i64) -> &'static str {
    let age = age.max(0) as f64;
    let interval = interval.max(1) as f64;
    if age < interval * 0.66 {
        "on cadence"
    } else if age < interval * 0.92 {
        "approaching"
    } else {
        "due now"
    }
}

fn heartbeat_card(
    last_seen: Option<i64>,
    heartbeat_log: &[i64],
    interval_secs: Option<u64>,
    now: i64,
    is_self: bool,
) -> String {
    let interval = i64::try_from(interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    let recent = recent_heartbeat_log(heartbeat_log, last_seen);
    let beats_attr = recent
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let marks = heartbeat_marks(&recent);
    let (last_attr, next_at_attr, beat_state, next, now_x, fill_color, expect_fill, target_ring) =
        match last_seen {
            Some(last) => {
                let age = (now - last).max(0);
                let progress = (age as f64 / interval as f64).clamp(0.0, 1.0);
                if age <= interval {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        if is_self { "lit" } else { "tracking" },
                        heartbeat_cadence_label(age, interval).to_string(),
                        heartbeat_x(age, interval),
                        if is_self { "var(--sun)" } else { "var(--sea)" },
                        progress * 360.0,
                        3.0 + progress * 5.0,
                    )
                } else if age <= interval * 2 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "late",
                        "late".to_string(),
                        heartbeat_x(age, interval),
                        "var(--sun)",
                        360.0,
                        8.0,
                    )
                } else if age <= interval * 5 {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "stale",
                        "stale".to_string(),
                        heartbeat_x(age, interval),
                        "var(--stale)",
                        360.0,
                        8.0,
                    )
                } else {
                    (
                        last.to_string(),
                        (last + interval).to_string(),
                        "down",
                        "silent".to_string(),
                        100.0,
                        "var(--down)",
                        360.0,
                        8.0,
                    )
                }
            }
            None => (
                "".to_string(),
                "".to_string(),
                "waiting",
                "waiting".to_string(),
                0.0,
                "var(--wait)",
                0.0,
                3.0,
            ),
        };
    let self_attr = if is_self { r#" data-self="true""# } else { "" };
    format!(
        r#"<div class="beat" data-beat="{beat_state}" data-count="{count}" data-last="{last_attr}" data-interval="{interval}" data-next-at="{next_at_attr}" data-beats="{beats_attr}" style="--now-x:{now_x:.2}%;--fill-color:{fill_color};--expect-fill:{expect_fill:.1}deg;--target-ring:{target_ring:.1}px"{self_attr}><div class="beat-stage" aria-label="heartbeat timeline"><span class="beat-floor"></span><span class="beat-fill"></span><span class="beat-current"></span><span class="beat-marks">{marks}</span><span class="beat-threshold expected"></span><span class="beat-threshold stale"></span><span class="beat-expected"></span><span class="beat-now"></span><span class="beat-hit"></span><span class="beat-zones"><span>last</span><span>expected</span><span>late</span></span></div><div class="beat-meta"><span>expected beat</span><strong data-next>{next}</strong></div></div>"#,
        count = recent.len()
    )
}

fn render_home(hosts: &[Host], self_name: &str, now: i64, manifests: &[HostManifest]) -> String {
    if hosts.is_empty() {
        return format!(
            "{HEAD}{sidebar}<main>{header}{empty}</main>{FOOT}",
            sidebar = sidebar(),
            header = header(now),
            empty = empty_state()
        );
    }

    let palette_colors = manifest_palette_color(manifests);
    let mut sorted: Vec<&Host> = hosts.iter().collect();
    // self/lighthouse first, then by severity (needs-attention first), then name.
    sorted.sort_by_key(|h| {
        let is_self = u8::from(h.name != self_name);
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let rank = attention_reason(live, &h.freshness).rank;
        (is_self, rank, h.name.clone())
    });

    let mut cards = String::new();
    let mut rows = String::new();
    for h in sorted {
        let is_self = h.name == self_name;
        let mut live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        if is_self {
            live = Liveness::Live;
        }
        let (_color, word) = live.badge();
        let nix_icon = if h.is_nix {
            icons::SNOWFLAKE
        } else {
            icons::SERVER
        };
        let name = html_escape(&h.name);
        let role = html_escape(&h.role);
        let fresh_tldr = h.freshness.tldr();
        let fresh = freshness_markup(&h.freshness);
        let attention = if is_self {
            self_attention_reason()
        } else {
            attention_reason(live, &h.freshness)
        };
        let reason = reason_markup(&attention);
        let search = html_escape(&format!(
            "{} {} {} {}",
            h.name.to_lowercase(),
            h.role.to_lowercase(),
            fresh_tldr.to_lowercase(),
            attention.label.to_lowercase()
        ));
        let sort_name = html_escape(&h.name.to_lowercase());
        let last_sort = h.last_seen.unwrap_or(0);
        let sev = attention.rank;
        let seen = match h.last_seen {
            Some(t) => format!("last seen {} ago", duration_label(now - t)),
            None => "never seen".to_string(),
        };
        let light_cls = if is_self { " light" } else { "" };
        let self_attr = if is_self { r#" data-self="true""# } else { "" };
        let beam = if is_self {
            format!(
                "<div class=\"halo\"></div><span class=\"lh\">{}</span>",
                icons::LIGHTHOUSE
            )
        } else {
            String::new()
        };
        let settings_href = html_escape(&format!("/agora?host={}", url_query_escape(&h.name)));
        let settings_action = if let Some(settings_color) = palette_colors.get(&h.name) {
            let settings_color = html_escape(settings_color);
            format!(
                r#"<a class="settings-card" href="{settings_href}" title="Open settings for {name}" style="--host-color:{settings_color}"><span class="settings-icon">{icon}</span><span class="settings-copy"><strong>Settings</strong><span>Color and access</span></span><span class="settings-swatch" aria-hidden="true"></span></a>"#,
                icon = icons::SLIDERS
            )
        } else {
            format!(
                r#"<a class="settings-card unavailable" href="{settings_href}" title="Settings are not set up for {name}"><span class="settings-icon">{icon}</span><span class="settings-copy"><strong>No settings yet</strong><span>Not set up yet</span></span><span class="settings-swatch" aria-hidden="true"></span></a>"#,
                icon = icons::SLIDERS
            )
        };
        // pharosd cannot honestly heartbeat itself; the host gets the lighthouse cue.
        let status_word = if is_self { "the light is lit" } else { word };
        let status_icon = if is_self {
            icons::LIGHTHOUSE.to_string()
        } else {
            status_icon_stack()
        };
        let heartbeat = heartbeat_card(
            h.last_seen,
            &h.heartbeat_log,
            h.heartbeat_interval_secs,
            now,
            is_self,
        );
        cards.push_str(&format!(
            r#"<article class="card{light_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}"{self_attr}>{beam}<header class="card-head"><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div><span class="status-pill" aria-label="status: {status_word}">{status_icon}<span class="word" data-status-word>{status_word}</span></span></header>{settings_action}{reason}<div class="fresh" data-fresh>{fresh}</div><div class="meta"><span data-seen>{seen}</span><span>as of {as_of}</span></div>{heartbeat}</article>"#,
            live_key = live_key(live),
            as_of = clock_label(now)
        ));
        rows.push_str(&format!(
            r#"<tr class="{light_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}"{self_attr}><td><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div></td><td><span class="status-pill" aria-label="status: {status_word}">{status_icon}<span class="word" data-status-word>{status_word}</span></span></td><td>{reason}</td><td><div class="fresh" data-fresh>{fresh}</div></td><td><span data-seen>{seen}</span></td><td>{heartbeat}</td><td>{settings_action}</td></tr>"#,
            live_key = live_key(live),
            light_cls = light_cls.trim()
        ));
    }

    let lone = if hosts.len() == 1 {
        lone_host_state()
    } else {
        String::new()
    };

    format!(
        "{HEAD}{sidebar}<main data-view=\"grid\">{header}{summary}{toolbar}<div class=\"grid\" data-grid>{cards}</div><section class=\"list-wrap\"><table class=\"list\"><thead><tr><th>Host</th><th>Status</th><th>Attention</th><th>Freshness</th><th>Last seen</th><th>Heartbeat</th><th>Actions</th></tr></thead><tbody data-list-body>{rows}</tbody></table></section>{lone}</main>{FOOT}",
        sidebar = sidebar(),
        header = header(now),
        summary = summary_cards(hosts, self_name, now),
        toolbar = toolbar()
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let store = Arc::new(Store::new(
        std::env::var("PHAROS_DB").ok().map(PathBuf::from),
    ));
    let manifests = Arc::new(ManifestRegistry::from_env());
    let auth = Auth::from_env().await;
    let beacon_auth = BeaconAuth::from_env();
    let state = AppState {
        store,
        manifests,
        auth,
        beacon_auth,
    };

    let app = Router::new()
        // Human routes — gated by OIDC when configured (open otherwise).
        .route("/", get(home))
        .route("/agora", get(agora::page))
        .route(
            "/agora/proposals/host-palette.json",
            get(agora::palette_proposal),
        )
        .route("/hosts.json", get(hosts_json))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        // Machine/public routes: beacon ingestion, local registration, health,
        // version, declared manifests, and the auth flow.
        .route("/declared-hosts.json", get(declared_hosts_json))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/assets/fleet-horizon.png", get(fleet_horizon_asset))
        .route(
            "/assets/sidebar-lighthouse.png",
            get(sidebar_lighthouse_asset),
        )
        .route("/register", post(register))
        .route("/report", post(report))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", get(auth::logout))
        .with_state(state);

    let addr = std::env::var("PHAROS_ADDR").unwrap_or_else(|_| "127.0.0.1:8080".into());
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind PHAROS_ADDR");
    tracing::info!(
        "pharosd v{} listening on http://{addr}",
        env!("CARGO_PKG_VERSION")
    );
    axum::serve(listener, app).await.expect("serve");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_home_includes_lighthouse_and_heartbeat_markup() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                freshness: NixFreshness {
                    applicable: true,
                    ..Default::default()
                },
            },
            Host {
                name: "hades".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                token_hash: None,
                last_seen: Some(879),
                heartbeat_log: vec![760, 819, 879],
                heartbeat_interval_secs: Some(60),
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
            },
            Host {
                name: "poseidon".to_string(),
                role: "NixOS Host".to_string(),
                is_nix: true,
                token_hash: None,
                last_seen: Some(970),
                heartbeat_log: vec![850, 910, 970],
                heartbeat_interval_secs: Some(60),
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
            },
        ];

        let html = render_home(&hosts, "csb1", 1000, &[]);

        assert!(html.contains(r#"<section class="toolbar""#));
        assert!(html.contains(r#"data-view-button="list""#));
        assert!(html.contains(r#"<table class="list">"#));
        assert!(html.contains(r#"data-host="csb1" data-live="live""#));
        assert!(html.contains(r#"data-self="true""#));
        assert!(html.contains("the light is lit"));
        assert!(html.contains(r#"<th>Attention</th>"#));
        assert!(html.contains(r#"<th>Actions</th>"#));
        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(html.contains("No settings yet"));
        assert!(html.contains("Not set up yet"));
        assert!(html
            .contains(r#"<div class="reason self" data-reason><span>control light</span></div>"#));
        assert!(html.contains("expected beat"));
        assert!(html.contains(r#"data-next>on cadence"#));
        assert!(html.contains(r#"data-beats="850,910,970""#));
        assert!(html.contains("Flake.lock age"));
        assert!(html.contains(r#"<strong class="warn">1d</strong>"#));
        assert!(html.contains("Commits behind"));
        assert!(html.contains(r#"<strong class="warn">3</strong>"#));
        assert!(html.contains("beat-fill"));
        assert!(html.contains("beat-now"));
        assert!(html.contains("beat-current"));
        assert!(html.contains("beat-expected"));
        assert!(html.contains("beat-zones"));
        assert!(html.contains("nix drift: 1d"));
        assert!(html.contains("3 commits"));
        assert!(html.contains(r#"data-search="poseidon nixos host flake.lock 1d old · 3 commits behind nixcfg nix drift: 1d · 3 commits""#));
        assert!(html.contains(r#"data-host="poseidon" data-live="live" data-sev="3""#));
        assert!(html.contains(r#"data-host="hades" data-live="stale""#));
        assert!(html.contains(r#"data-sev="1""#));
        assert!(html.contains("state-icon stale"));
    }

    #[test]
    fn render_home_marks_declared_host_settings_as_available() {
        let host = Host {
            name: "poseidon".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            token_hash: None,
            last_seen: Some(970),
            heartbeat_log: vec![850, 910, 970],
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
        };
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "poseidon",
            "host": { "name": "poseidon" },
            "palette": {
                "name": "custom-poseidon",
                "accent": "#48b8a8",
                "gradient": { "primary": "#48b8a8" }
            },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let html = render_home(&[host], "csb1", 1000, &[manifest]);

        assert!(html.contains(r#"href="/agora?host=poseidon""#));
        assert!(html.contains("Settings"));
        assert!(html.contains("Color and access"));
        assert!(html.contains(r#"style="--host-color:#48b8a8""#));
        assert!(!html.contains("Settings unavailable"));
    }

    #[test]
    fn render_home_has_deliberate_empty_and_lone_host_states() {
        let empty = render_home(&[], "csb1", 1000, &[]);
        assert!(empty.contains(r#"<section class="empty-state""#));
        assert!(empty.contains("Waiting for the first host"));
        assert!(empty.contains("inspr onboard &lt;host&gt;"));
        assert!(empty.contains("awaiting first heartbeat"));

        let host = Host {
            name: "ares".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            token_hash: Some("hash".to_string()),
            last_seen: None,
            heartbeat_log: vec![],
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
        };
        let lone = render_home(&[host], "csb1", 1000, &[]);
        assert!(lone.contains(r#"<aside class="lone-state""#));
        assert!(lone.contains("First host is on the map"));
        assert!(lone.contains(r#"data-live="awaiting_first_heartbeat""#));
    }

    #[test]
    fn declared_hosts_payload_keeps_declared_and_runtime_state_separate() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "hsb8",
            "host": {
                "name": "hsb8",
                "access": {
                    "lanHostname": "hsb8.lan",
                    "lanIp": "192.168.1.100",
                    "tailnet": "hsb8"
                }
            },
            "wings": [{ "id": "ops", "name": "Ops" }],
            "services": [
                {
                    "wing": "ops",
                    "name": "pharos-beacon",
                    "passive": true,
                    "statusPolicy": { "source": "pharos-runtime" }
                }
            ],
            "policy": {
                "declaredOnly": true,
                "runtimeStateOwner": "pharos",
                "privilegedActions": { "mode": "none", "janusRequired": false }
            }
        }))
        .expect("manifest parses");
        let runtime = Host {
            name: "hsb8".to_string(),
            role: "NixOS Host".to_string(),
            is_nix: true,
            token_hash: Some("stored-token-hash".to_string()),
            last_seen: Some(970),
            heartbeat_log: vec![910, 970],
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(0),
                commits_behind: Some(1),
            },
        };

        let payload = declared_hosts_payload(
            std::slice::from_ref(&manifest),
            &[],
            std::slice::from_ref(&runtime),
            1000,
        );

        assert_eq!(payload["schema"], "inspr.pharos.declared-hosts.v1");
        assert_eq!(
            payload["declared_hosts"][0]["declared"]["services"][0]["statusPolicy"]["source"],
            "pharos-runtime"
        );
        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "observed");
        assert_eq!(payload["declared_hosts"][0]["runtime"]["liveness"], "live");
        assert!(payload["declared_hosts"][0]["runtime"]["token_hash"].is_null());
        assert!(!payload.to_string().contains("stored-token-hash"));
    }

    #[test]
    fn declared_hosts_payload_marks_missing_runtime_as_pending() {
        let manifest: HostManifest = serde_json::from_value(json!({
            "schema": "inspr.hostdash.config.v1",
            "version": 1,
            "slug": "new-host",
            "host": { "name": "new-host" },
            "policy": { "declaredOnly": true }
        }))
        .expect("manifest parses");

        let payload = declared_hosts_payload(std::slice::from_ref(&manifest), &[], &[], 1000);

        assert_eq!(payload["declared_hosts"][0]["runtime"]["state"], "pending");
        assert_eq!(
            payload["declared_hosts"][0]["runtime"]["liveness"],
            "awaiting_first_heartbeat"
        );
    }
}
