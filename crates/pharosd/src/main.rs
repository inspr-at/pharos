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
:root{--ink:#1b1f24;--muted:#6b7480;--accent:#1565c0}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(160deg,#fff 0%,#eef1f4 60%,#e7ebef 100%);min-height:100vh}
main{max-width:880px;margin:0 auto;padding:48px 24px}
.ico{width:16px;height:16px;display:inline-block;vertical-align:middle}
.brand{display:flex;align-items:center;gap:9px;margin:0 0 2px}
.brand .ico{width:24px;height:24px;color:var(--accent)}
.brand h1{margin:0;font-size:22px;letter-spacing:-.01em}
.sub{margin:0 0 28px;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.card{position:relative;background:#fff;border:1px solid #e6e9ed;border-radius:16px;padding:16px 18px;box-shadow:0 1px 2px rgba(20,30,50,.04);overflow:hidden}
.card.light{border-color:#cfe0f5}
.halo{position:absolute;inset:-40% -30% auto auto;width:180px;height:180px;background:radial-gradient(circle,rgba(21,101,192,.16),transparent 70%);pointer-events:none}
.lh{position:absolute;top:12px;right:12px;color:var(--accent)}
.lh .ico{width:20px;height:20px}
.row{display:flex;align-items:center;gap:8px}
.nix{color:var(--muted);display:inline-flex}
.name{font-weight:600}
.status{margin:10px 0 6px}
.st{display:inline-flex;align-items:center;gap:6px;font-size:12px}
.word{color:var(--muted)}
.fresh{font-size:13px}
.seen{font-size:11px;color:var(--muted);margin-top:6px}
.empty{margin-top:18px;padding:18px 20px;border:1px dashed #cdd3da;border-radius:12px;color:var(--muted)}
.empty code{background:#eef1f4;padding:2px 7px;border-radius:6px;color:var(--ink)}
</style></head><body>"#;

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

fn render_home(hosts: &[Host], self_name: &str, now: i64) -> String {
    if hosts.is_empty() {
        return format!(
            "{HEAD}<main><div class=\"brand\">{lh}<h1>Pharos</h1></div><p class=\"sub\">host fleet</p><div class=\"empty\">No hosts yet. Onboard one:<br><br><code>inspr onboard &lt;host&gt;</code></div></main></body></html>",
            lh = icons::LIGHTHOUSE
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
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let (color, word) = live.badge();
        let nix_icon = if h.is_nix {
            icons::SNOWFLAKE
        } else {
            icons::SERVER
        };
        let name = &h.name;
        let fresh = h.freshness.tldr();
        let seen = match h.last_seen {
            Some(t) => format!("last seen {}s ago", (now - t).max(0)),
            None => "never seen".to_string(),
        };
        let light_cls = if is_self { " light" } else { "" };
        let beam = if is_self {
            format!(
                "<div class=\"halo\"></div><span class=\"lh\">{}</span>",
                icons::LIGHTHOUSE
            )
        } else {
            String::new()
        };
        // pharosd can't honestly heartbeat itself → "the light is lit" (PHAROS-10, point 6).
        let status = if is_self {
            format!(
                "<span class=\"st\" style=\"color:var(--accent)\">{}<span class=\"word\">the light is lit</span></span>",
                icons::LIGHTHOUSE
            )
        } else {
            format!(
                "<span class=\"st\" style=\"color:{color}\">{icon}<span class=\"word\">{word}</span></span>",
                icon = icons::status_svg(live)
            )
        };
        cards.push_str(&format!(
            r#"<div class="card{light_cls}">{beam}<div class="row"><span class="nix">{nix_icon}</span><span class="name">{name}</span></div><div class="status">{status}</div><div class="fresh">{fresh}</div><div class="seen">{seen}</div></div>"#
        ));
    }

    format!(
        "{HEAD}<main><div class=\"brand\">{lh}<h1>Pharos</h1></div><p class=\"sub\">host fleet — as of {now}</p><div class=\"grid\">{cards}</div></main></body></html>",
        lh = icons::LIGHTHOUSE
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
