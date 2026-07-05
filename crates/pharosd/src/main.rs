//! pharosd — the Pharos server.
//!
//! Routes: `/healthz`, `/version`, `POST /report` (beacon ingestion, PHAROS-9),
//! `/hosts.json`, and the host dashboard at `/`. Hosts live in a small store
//! (in-memory + optional JSON persistence; sqlx+SQLite is PHAROS-3). The
//! dashboard is a static server render previewing the design (rounded cards,
//! accessible SVG status, the self-host lighthouse); the interactive Leptos UI
//! is PHAROS-10.

mod auth;
mod icons;
mod store;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{FromRef, State};
use axum::http::StatusCode;
use axum::middleware;
use axum::response::Html;
use axum::routing::{get, post};
use axum::{Json, Router};
use pharos_core::{liveness, Host, HostReport, Liveness};
use serde_json::json;

use crate::auth::{Auth, AuthState};
use crate::store::Store;

/// Combined app state. Handlers extract `Arc<Store>` or `AuthState` via `FromRef`.
#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    auth: AuthState,
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

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><style>
:root{--ink:#19324a;--muted:#66798b;--line:#dfe9ef;--card:#ffffff;--card-soft:rgba(255,255,255,.82);--accent:#1f7fb5;--sea:#159e99;--sun:#d69b31;--live:#25845f;--stale:#b26a00;--down:#bf3a35;--wait:#8997a3}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f6fbfc 48%,#edf6f7 100%);min-height:100vh;overflow-x:hidden}
body:before{content:"";position:fixed;inset:0;z-index:-2;background:radial-gradient(circle at 78% 9%,rgba(214,155,49,.18),transparent 13rem),radial-gradient(circle at 14% 20%,rgba(21,158,153,.10),transparent 18rem),linear-gradient(180deg,rgba(255,255,255,.92),rgba(239,249,250,.82));pointer-events:none}
body:after{content:"";position:fixed;left:0;right:0;bottom:0;height:34vh;z-index:-1;background:linear-gradient(180deg,transparent,rgba(255,255,255,.64)),repeating-linear-gradient(178deg,rgba(31,127,181,.10) 0 1px,transparent 1px 38px);opacity:.9;pointer-events:none}
main{width:min(1080px,100%);margin:0 auto;padding:42px 24px 56px}
.ico{width:16px;height:16px;display:inline-block;vertical-align:middle;flex:0 0 auto}
.top{display:flex;align-items:flex-start;justify-content:space-between;gap:22px;margin-bottom:22px}
.brand{display:flex;align-items:center;gap:10px;margin:0 0 2px}
.brand .ico{width:26px;height:26px;color:var(--sun)}
.brand h1{margin:0;font-size:24px;font-weight:650;letter-spacing:0}
.fleet{display:flex;align-items:center;gap:10px;margin:4px 0 0;color:var(--muted);font-size:13px}
.wave{width:44px;height:10px;color:var(--sea)}
.asof{font-size:12px;color:var(--muted);white-space:nowrap;padding-top:9px}
.summary{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:10px;margin:0 0 18px}
.metric{min-width:0;background:var(--card-soft);border:1px solid rgba(210,226,234,.78);border-radius:8px;padding:12px 13px;box-shadow:0 12px 30px rgba(54,88,108,.06);backdrop-filter:blur(8px)}
.metric b{display:block;font-size:22px;line-height:1.1;font-weight:650;color:var(--ink)}
.metric span{display:block;font-size:12px;color:var(--muted);margin-top:3px}
.metric.live{border-color:rgba(37,132,95,.22)}.metric.stale{border-color:rgba(178,106,0,.24)}.metric.down{border-color:rgba(191,58,53,.24)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(245px,1fr));gap:14px}
.card{--state:var(--wait);position:relative;min-height:232px;display:flex;flex-direction:column;background:rgba(255,255,255,.88);border:1px solid rgba(211,225,233,.86);border-radius:8px;padding:15px 16px 14px;box-shadow:0 14px 32px rgba(45,75,95,.08);overflow:hidden}
.card:before{content:"";position:absolute;left:16px;right:16px;top:58px;height:1px;background:linear-gradient(90deg,transparent,rgba(31,127,181,.16),transparent);pointer-events:none}
.card[data-live="live"]{--state:var(--live)}.card[data-live="stale"]{--state:var(--stale)}.card[data-live="down"]{--state:var(--down)}.card[data-live="awaiting_first_heartbeat"]{--state:var(--wait)}
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
.state-icon{display:none}.card[data-live="live"] .state-icon.live,.card[data-live="stale"] .state-icon.stale,.card[data-live="down"] .state-icon.down,.card[data-live="awaiting_first_heartbeat"] .state-icon.awaiting{display:inline-block}
.fresh{min-height:38px;margin:4px 0 11px;font-size:13px;line-height:1.45;color:var(--ink)}
.meta{display:grid;grid-template-columns:1fr auto;gap:8px;margin-top:auto;border-top:1px solid rgba(214,226,234,.72);padding-top:10px;font-size:11px;color:var(--muted)}
.meta strong{font-weight:600;color:var(--ink)}
.beat{--beat-pct:0;--beat-color:var(--state);margin-top:10px;color:var(--beat-color)}
.beat-wave{position:relative;height:34px;overflow:hidden}
.beat-wave svg{display:block;width:100%;height:34px}
.beat-base{fill:none;stroke:#d8e6ed;stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.beat-signal{fill:none;stroke:currentColor;stroke-width:2.4;stroke-linecap:round;stroke-linejoin:round;stroke-dasharray:100;stroke-dashoffset:calc(100 - var(--beat-pct));filter:drop-shadow(0 0 4px color-mix(in srgb,currentColor 28%,transparent));transition:stroke-dashoffset .35s ease}
.beat-dot{position:absolute;top:15px;left:calc(var(--beat-pct) * 1%);width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 0 5px color-mix(in srgb,currentColor 14%,transparent);transform:translateX(-3px);transition:left .35s ease}
.beat[data-beat="overdue"]{--beat-color:var(--down)}.beat[data-beat="waiting"]{--beat-color:var(--wait)}.beat[data-beat="lit"]{--beat-color:var(--sun)}
.beat-meta{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-top:2px;font-size:11px;color:var(--muted)}
.beat-meta strong{font-size:12px;color:var(--beat-color);font-weight:650}
.empty{margin-top:18px;padding:18px 20px;border:1px dashed #c5d7e0;border-radius:8px;background:rgba(255,255,255,.74);color:var(--muted)}
.empty code{background:#edf6f7;padding:2px 7px;border-radius:6px;color:var(--ink)}
@media (max-width:720px){main{padding:28px 16px 42px}.top{display:block}.asof{padding-top:6px}.summary{grid-template-columns:repeat(2,minmax(0,1fr))}.grid{grid-template-columns:1fr}}
@media (prefers-reduced-motion:reduce){.beat-signal,.beat-dot{transition:none}}
</style></head><body>"#;

const FOOT: &str = r#"<script>
const words={live:'live',stale:'stale',down:'down',awaiting_first_heartbeat:'awaiting'};
function dur(s){s=Math.max(0,Math.floor(s));return s<60?s+'s':Math.floor(s/60)+'m '+String(s%60).padStart(2,'0')+'s'}
function clock(t){return new Date(t*1000).toLocaleTimeString([], {hour:'2-digit',minute:'2-digit',second:'2-digit'})}
function cardFor(name){return Array.from(document.querySelectorAll('[data-host]')).find(card=>card.dataset.host===name)}
function tick(){
  const now=Math.floor(Date.now()/1000);
  document.querySelectorAll('.beat').forEach(beat=>{
    const last=Number(beat.dataset.last);
    const interval=Math.max(1,Number(beat.dataset.interval)||60);
    const next=beat.querySelector('[data-next]');
    if(!Number.isFinite(last)||last<=0){
      beat.style.setProperty('--beat-pct',0);
      beat.dataset.beat='waiting';
      if(next)next.textContent='waiting';
      return;
    }
    const remaining=last+interval-now;
    const elapsed=Math.max(0,Math.min(interval,now-last));
    beat.style.setProperty('--beat-pct',String((elapsed/interval*100).toFixed(1)));
    if(remaining>=0){
      if(beat.dataset.self==='true')beat.dataset.beat='lit';else beat.dataset.beat='ok';
      if(next)next.textContent='in '+dur(remaining);
    }else{
      beat.style.setProperty('--beat-pct',100);
      beat.dataset.beat='overdue';
      if(next)next.textContent='overdue '+dur(-remaining);
    }
  });
}
function setSeen(card,last,now){
  const seen=card.querySelector('[data-seen]');
  if(!seen)return;
  if(last==null){seen.textContent='never seen';return}
  seen.textContent='last seen '+dur(now-last)+' ago';
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
      const card=cardFor(h.name);
      if(!card)continue;
      if(card.dataset.self==='true')card.dataset.live='live';else card.dataset.live=h.liveness;
      const word=card.querySelector('[data-status-word]');
      if(word&&card.dataset.self!=='true')word.textContent=words[h.liveness]||h.liveness;
      const fresh=card.querySelector('[data-fresh]');
      if(fresh)fresh.textContent=h.freshness_tldr;
      setSeen(card,h.last_seen,now);
      const beat=card.querySelector('.beat');
      if(beat){
        beat.dataset.last=h.last_seen ?? '';
        beat.dataset.interval=h.heartbeat_interval_secs || 60;
      }
    }
    tick();
  }catch(_){}
}
tick();
setInterval(tick,1000);
setInterval(refresh,30000);
setTimeout(refresh,3000);
</script></body></html>"#;

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

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "name": "pharosd", "version": env!("CARGO_PKG_VERSION") }))
}

/// Beacon ingestion (PHAROS-9): upsert the host, stamping server receive time.
async fn report(State(store): State<Arc<Store>>, Json(rep): Json<HostReport>) -> StatusCode {
    tracing::info!(host = %rep.name, "report received");
    store.record(rep, now_unix());
    StatusCode::NO_CONTENT
}

async fn hosts_json(State(store): State<Arc<Store>>) -> Json<serde_json::Value> {
    let now = now_unix();
    let hosts: Vec<_> = store
        .list()
        .into_iter()
        .map(|h| {
            let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
            json!({
                "name": h.name,
                "role": h.role,
                "is_nix": h.is_nix,
                "last_seen": h.last_seen,
                "heartbeat_interval_secs": h.heartbeat_interval_secs,
                "liveness": live,
                "freshness_tldr": h.freshness.tldr(),
            })
        })
        .collect();
    Json(json!({ "as_of": now, "hosts": hosts }))
}

async fn home(State(store): State<Arc<Store>>) -> Html<String> {
    Html(render_home(&store.list(), &self_host(), now_unix()))
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
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

fn header(now: i64) -> String {
    format!(
        r#"<div class="top"><div><div class="brand">{lh}<h1>Pharos</h1></div><p class="fleet">host fleet <svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></p></div><div class="asof" data-as-of>as of {as_of}</div></div>"#,
        lh = icons::LIGHTHOUSE,
        as_of = clock_label(now)
    )
}

fn heartbeat_card(
    last_seen: Option<i64>,
    interval_secs: Option<u64>,
    now: i64,
    is_self: bool,
) -> String {
    let interval = i64::try_from(interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    let (last_attr, pct, beat_state, next) = match last_seen {
        Some(last) => {
            let elapsed = (now - last).clamp(0, interval);
            let remaining = last + interval - now;
            let pct = (elapsed as f64 / interval as f64) * 100.0;
            if remaining >= 0 {
                (
                    last.to_string(),
                    pct,
                    if is_self { "lit" } else { "ok" },
                    format!("in {}", duration_label(remaining)),
                )
            } else {
                (
                    last.to_string(),
                    100.0,
                    "overdue",
                    format!("overdue {}", duration_label(-remaining)),
                )
            }
        }
        None => ("".to_string(), 0.0, "waiting", "waiting".to_string()),
    };
    let self_attr = if is_self { r#" data-self="true""# } else { "" };
    format!(
        r#"<div class="beat" data-beat="{beat_state}" data-last="{last_attr}" data-interval="{interval}"{self_attr} style="--beat-pct:{pct:.1}"><div class="beat-wave"><svg viewBox="0 0 220 34" preserveAspectRatio="none" aria-hidden="true"><path class="beat-base" pathLength="100" d="M1 21H31l6-13 8 25 7-17 7 5h35l5-9 7 18 8-17 5 8h101"/><path class="beat-signal" pathLength="100" d="M1 21H31l6-13 8 25 7-17 7 5h35l5-9 7 18 8-17 5 8h101"/></svg><span class="beat-dot"></span></div><div class="beat-meta"><span>next heartbeat</span><strong data-next>{next}</strong></div></div>"#
    )
}

fn render_home(hosts: &[Host], self_name: &str, now: i64) -> String {
    if hosts.is_empty() {
        return format!(
            "{HEAD}<main>{header}<div class=\"empty\">No hosts yet. Onboard one:<br><br><code>inspr onboard &lt;host&gt;</code></div></main>{FOOT}",
            header = header(now)
        );
    }

    let mut sorted: Vec<&Host> = hosts.iter().collect();
    // self/lighthouse first, then by severity (needs-attention first), then name.
    sorted.sort_by_key(|h| {
        let is_self = u8::from(h.name != self_name);
        let sev = match liveness(h.last_seen, h.heartbeat_interval_secs, now) {
            Liveness::Down => 0u8,
            Liveness::Stale => 1,
            Liveness::AwaitingFirstHeartbeat => 2,
            Liveness::Live => 3,
        };
        (is_self, sev, h.name.clone())
    });

    let mut cards = String::new();
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
        let fresh = html_escape(&h.freshness.tldr());
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
        // pharosd cannot honestly heartbeat itself; the host gets the lighthouse cue.
        let status_word = if is_self { "the light is lit" } else { word };
        let status_icon = if is_self {
            icons::LIGHTHOUSE.to_string()
        } else {
            status_icon_stack()
        };
        let heartbeat = heartbeat_card(h.last_seen, h.heartbeat_interval_secs, now, is_self);
        cards.push_str(&format!(
            r#"<article class="card{light_cls}" data-host="{name}" data-live="{live_key}"{self_attr}>{beam}<header class="card-head"><div class="host"><span class="nix">{nix_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div><span class="status-pill" aria-label="status: {status_word}">{status_icon}<span class="word" data-status-word>{status_word}</span></span></header><div class="fresh" data-fresh>{fresh}</div><div class="meta"><span data-seen>{seen}</span><span>as of {as_of}</span></div>{heartbeat}</article>"#,
            live_key = live_key(live),
            as_of = clock_label(now)
        ));
    }

    format!(
        "{HEAD}<main>{header}{summary}<div class=\"grid\">{cards}</div></main>{FOOT}",
        header = header(now),
        summary = summary_cards(hosts, self_name, now)
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
    let auth = Auth::from_env().await;
    let state = AppState { store, auth };

    let app = Router::new()
        // Human routes — gated by OIDC when configured (open otherwise).
        .route("/", get(home))
        .route("/hosts.json", get(hosts_json))
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        // Open routes: beacon ingestion, health, version, and the auth flow.
        .route("/healthz", get(healthz))
        .route("/version", get(version))
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
    use pharos_core::NixFreshness;

    #[test]
    fn render_home_includes_lighthouse_and_heartbeat_markup() {
        let hosts = vec![
            Host {
                name: "csb1".to_string(),
                role: "Control Server".to_string(),
                is_nix: true,
                last_seen: Some(970),
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
                last_seen: Some(879),
                heartbeat_interval_secs: Some(60),
                freshness: NixFreshness {
                    applicable: true,
                    flake_lock_age_days: Some(1),
                    commits_behind: Some(3),
                },
            },
        ];

        let html = render_home(&hosts, "csb1", 1000);

        assert!(html.contains(r#"data-host="csb1" data-live="live" data-self="true""#));
        assert!(html.contains("the light is lit"));
        assert!(html.contains("next heartbeat"));
        assert!(html.contains(r#"data-next>in 30s"#));
        assert!(html.contains(r#"data-host="hades" data-live="stale""#));
        assert!(html.contains("state-icon stale"));
    }
}
