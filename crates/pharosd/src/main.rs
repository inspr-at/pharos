//! pharosd — the Pharos server (PHAROS-2 scaffold).
//!
//! Routes: `/healthz`, `/version`, `/hosts.json`, and a minimal host
//! dashboard at `/`. The dashboard is a static placeholder render that
//! previews the intended design (rounded cards, accessible status, the dsc0
//! "lighthouse"); the real interactive UI is built in Leptos in PHAROS-10,
//! and the SQLite-backed host store replaces the sample data in PHAROS-3/9.

use std::time::{SystemTime, UNIX_EPOCH};

use axum::{response::Html, routing::get, Json, Router};
use pharos_core::{liveness, Host, NixFreshness};
use serde_json::json;

const HEAD: &str = r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><style>
:root{--ink:#1b1f24;--muted:#6b7480}
*{box-sizing:border-box}
body{margin:0;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(160deg,#fff 0%,#eef1f4 60%,#e7ebef 100%);min-height:100vh}
main{max-width:880px;margin:0 auto;padding:48px 24px}
h1{margin:0 0 2px;font-size:22px;letter-spacing:-.01em}
.sub{margin:0 0 28px;color:var(--muted);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:16px}
.card{position:relative;background:#fff;border:1px solid #e6e9ed;border-radius:16px;padding:16px 18px;box-shadow:0 1px 2px rgba(20,30,50,.04);overflow:hidden}
.card.light{border-color:#cfe0f5}
.halo{position:absolute;inset:-40% -30% auto auto;width:180px;height:180px;background:radial-gradient(circle,rgba(21,101,192,.16),transparent 70%);pointer-events:none}
.lh{position:absolute;top:12px;right:14px;font-size:18px;opacity:.9}
.row{display:flex;align-items:center;gap:8px}
.nix{color:var(--muted)}
.name{font-weight:600}
.status{display:flex;align-items:center;gap:7px;margin:10px 0 6px}
.dot{display:inline-grid;place-items:center;width:14px;height:14px;border-radius:50%;color:#fff;font-size:9px;line-height:1}
.word{font-size:12px;color:var(--muted)}
.fresh{font-size:13px}
.seen{font-size:11px;color:var(--muted);margin-top:6px}
</style></head><body>"#;

fn now_unix() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Stub host list — replaced by the SQLite store in PHAROS-3 / PHAROS-9.
fn sample_hosts() -> Vec<Host> {
    let now = now_unix();
    vec![
        Host {
            name: "dsc0".into(),
            role: "pharos host".into(),
            is_nix: true,
            last_seen: Some(now - 30),
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(2),
                commits_behind: Some(0),
            },
        },
        Host {
            name: "csb1".into(),
            role: "server".into(),
            is_nix: true,
            last_seen: Some(now - 400),
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                flake_lock_age_days: Some(12),
                commits_behind: Some(3),
            },
        },
        Host {
            name: "hsb8".into(),
            role: "server".into(),
            is_nix: true,
            last_seen: None,
            heartbeat_interval_secs: Some(60),
            freshness: NixFreshness {
                applicable: true,
                ..Default::default()
            },
        },
    ]
}

async fn healthz() -> &'static str {
    "ok"
}

async fn version() -> Json<serde_json::Value> {
    Json(json!({ "name": "pharosd", "version": env!("CARGO_PKG_VERSION") }))
}

async fn hosts_json() -> Json<serde_json::Value> {
    let now = now_unix();
    let hosts: Vec<_> = sample_hosts()
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

async fn home() -> Html<String> {
    Html(render_home())
}

fn render_home() -> String {
    let now = now_unix();
    let mut hosts = sample_hosts();
    // dsc0 (the Pharos host) pinned first, regardless of sort (PHAROS-10).
    hosts.sort_by_key(|h| u8::from(h.name != "dsc0"));

    let mut cards = String::new();
    for h in &hosts {
        let is_light = h.name == "dsc0";
        let (color, glyph, word) = liveness(h.last_seen, h.heartbeat_interval_secs, now).badge();
        let nix_icon = if h.is_nix { "❄" } else { "▢" };
        let name = &h.name;
        let fresh = h.freshness.tldr();
        let seen = match h.last_seen {
            Some(t) => format!("last seen {}s ago", (now - t).max(0)),
            None => "never seen".to_string(),
        };
        let light_cls = if is_light { " light" } else { "" };
        let beam = if is_light {
            "<div class=\"halo\"></div><span class=\"lh\" aria-hidden=\"true\">🔦</span>"
        } else {
            ""
        };
        // pharosd can't honestly heartbeat itself → "the light is lit" (PHAROS-10, point 6).
        let status = if is_light {
            "<span class=\"dot\" style=\"background:#1565c0\"></span><span class=\"word\">the light is lit</span>".to_string()
        } else {
            format!("<span class=\"dot\" style=\"background:{color}\" aria-hidden=\"true\">{glyph}</span><span class=\"word\">{word}</span>")
        };
        cards.push_str(&format!(
            r#"<div class="card{light_cls}">{beam}<div class="row"><span class="nix" aria-hidden="true">{nix_icon}</span><span class="name">{name}</span></div><div class="status">{status}</div><div class="fresh">{fresh}</div><div class="seen">{seen}</div></div>"#
        ));
    }

    format!(
        "{HEAD}<main><h1>🔦 Pharos</h1><p class=\"sub\">host fleet — as of {now} · sample data (PHAROS-2 scaffold)</p><div class=\"grid\">{cards}</div></main></body></html>"
    )
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let app = Router::new()
        .route("/", get(home))
        .route("/healthz", get(healthz))
        .route("/version", get(version))
        .route("/hosts.json", get(hosts_json));

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
