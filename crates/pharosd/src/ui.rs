//! Release identity, browser assets and the Fleet page.

use super::*;

pub(super) const FAVICON_SVG: &str = include_str!("../assets/ui/favicon.svg");
pub(super) const APP_VERSION: &str = env!("PHAROS_APP_VERSION");
pub(super) const VERSION_SCHEME: &str = env!("PHAROS_VERSION_SCHEME");
pub(super) const RELEASE_CHANNEL: &str = env!("PHAROS_RELEASE_CHANNEL");
pub(super) const RELEASE_SEQUENCE: &str = env!("PHAROS_RELEASE_SEQUENCE");
pub(super) const LAST_LEGACY_VERSION: &str = env!("PHAROS_LAST_LEGACY_VERSION");
pub(super) const LAST_LEGACY_RELEASE_SEQUENCE: &str = env!("PHAROS_LAST_LEGACY_RELEASE_SEQUENCE");
pub(super) const FIRST_CALENDAR_VERSION: &str = env!("PHAROS_FIRST_CALENDAR_VERSION");
pub(super) const FIRST_CALENDAR_RELEASE_SEQUENCE: &str =
    env!("PHAROS_FIRST_CALENDAR_RELEASE_SEQUENCE");
pub(super) const LAST_CALENDAR_V1_VERSION: &str = env!("PHAROS_LAST_CALENDAR_V1_VERSION");
pub(super) const LAST_CALENDAR_V1_RELEASE_SEQUENCE: &str =
    env!("PHAROS_LAST_CALENDAR_V1_RELEASE_SEQUENCE");
pub(super) const FIRST_CALENDAR_V2_VERSION: &str = env!("PHAROS_FIRST_CALENDAR_V2_VERSION");
pub(super) const FIRST_CALENDAR_V2_RELEASE_SEQUENCE: &str =
    env!("PHAROS_FIRST_CALENDAR_V2_RELEASE_SEQUENCE");
pub(super) const GIT_COMMIT: &str = env!("PHAROS_GIT_COMMIT");
const LOGOUT_CSRF_RUNTIME: &str = include_str!("../assets/ui/logout-csrf.html");
pub(super) const CALENDAR_VERSION_BOOTSTRAP_JS: &str =
    include_str!("../assets/calendar-version-bootstrap.mjs");
pub(super) const CALENDAR_VERSION_JS: &str =
    include_str!("../assets/vendor/calendar-version-display/version.js");
pub(super) const CALENDAR_VERSION_PRESENTATION_JS: &str =
    include_str!("../assets/vendor/calendar-version-display/presentation.js");
pub(super) const CALENDAR_VERSION_INTERACTION_JS: &str =
    include_str!("../assets/vendor/calendar-version-display/version-interaction.js");
pub(super) const CALENDAR_VERSION_AUTO_ANIMATE_JS: &str =
    include_str!("../assets/vendor/calendar-version-display/auto-animate.js");
pub(super) const CALENDAR_VERSION_AUTO_ANIMATE_LICENSE_JS: &str =
    include_str!("../assets/vendor/calendar-version-display/auto-animate-license.js");

/// Calendar v2 display settings from the complete, pinned INSPR renderer bundle.
/// The check script and build script verify every local module and its license.
pub(super) const CALENDAR_VERSION_DISPLAY_JSON: &str =
    include_str!("../assets/vendor/calendar-version-display/display.json");

const CALENDAR_VERSION_BRAND: &str = "#1f7fb5";

pub(super) fn release_label() -> String {
    format!("v{APP_VERSION}")
}

pub(super) fn release_label_html() -> String {
    format!(
        r#"<span data-calendar-display data-canonical="{version}" data-version="v{version}" data-scheme="{scheme}" data-brand="{brand}">v{version}</span>"#,
        version = html_escape(APP_VERSION),
        scheme = html_escape(VERSION_SCHEME),
        brand = CALENDAR_VERSION_BRAND,
    )
}

fn app_href(base: &PublicBasePath, endpoint: &str) -> String {
    html_escape(&base.href(endpoint))
}

fn document_head(base: &PublicBasePath) -> String {
    format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pharos</title><link rel="icon" href="{favicon}"><style>body{{font:15px/1.5 system-ui,sans-serif;margin:2rem auto;max-width:60rem;padding:0 1rem}}table{{border-collapse:collapse;width:100%}}th,td{{border-bottom:1px solid #8884;padding:.4rem .6rem;text-align:left}}</style><meta name="inspr-calendar-version-display" content="{display}"><script type="module" src="{bootstrap}"></script></head>"#,
        favicon = app_href(base, "/favicon.svg"),
        display = html_escape(CALENDAR_VERSION_DISPLAY_JSON),
        bootstrap = app_href(base, "/assets/calendar-version-bootstrap.mjs"),
    )
}

/// Double-submit logout: the runtime copies the CSRF cookie into the form.
fn account_html(base: &PublicBasePath, user: Option<&AuthUser>) -> String {
    let Some(user) = user else {
        return String::new();
    };
    format!(
        r#"<p>{name} <form action="{logout}" method="post" data-logout-form><input type="hidden" name="csrf" value="" data-logout-csrf><button type="submit">Log out</button></form></p>{LOGOUT_CSRF_RUNTIME}"#,
        name = html_escape(&user.display_name),
        logout = app_href(base, "/auth/logout"),
    )
}

/// One plain line on the data file: how old it is and what is wrong with it.
fn fleet_data_status_html(view: Option<&FleetDataView>, now: i64) -> String {
    let Some(view) = view else {
        return "<p role=\"status\">Fleet data file: not configured.</p>".to_string();
    };
    let age = view
        .data
        .as_deref()
        .and_then(FleetData::updated_at_unix)
        .map(|updated| format!("Data from {}.", age_text(now.saturating_sub(updated))));
    let line = match (&view.problem, age) {
        (Some(problem), Some(age)) => format!(
            "Fleet data problem: {}. {age} This is the last good copy.",
            html_escape(problem)
        ),
        (Some(problem), None) => {
            format!("Fleet data problem: {}. No data yet.", html_escape(problem))
        }
        (None, Some(age)) => format!("Fleet data file loaded. {age}"),
        (None, None) => "Fleet data file: no data yet.".to_string(),
    };
    format!("<p role=\"status\">{line}</p>")
}

fn age_text(seconds: i64) -> String {
    match seconds.max(0) {
        seconds if seconds < 3_600 => format!("{} min ago", seconds / 60),
        seconds if seconds < 86_400 => format!("{} h ago", seconds / 3_600),
        seconds => format!("{} d ago", seconds / 86_400),
    }
}

fn render_home(
    base: &PublicBasePath,
    user: Option<&AuthUser>,
    hosts: &[Host],
    fleet_data: Option<&FleetDataView>,
    now: i64,
) -> String {
    let rows: String = hosts
        .iter()
        .map(|host| {
            let last_seen = host.last_seen.map_or_else(
                || "never".to_string(),
                |seen| format!("{}s ago", now.saturating_sub(seen).max(0)),
            );
            format!(
                "<tr><td>{name}</td><td>{liveness}</td><td>{last_seen}</td></tr>",
                name = html_escape(&host.name),
                liveness = liveness(host.last_seen, host.heartbeat_interval_secs, now)
                    .badge()
                    .1,
            )
        })
        .collect();
    format!(
        "{head}<body><main><h1>Fleet</h1>{fleet_data}<table><thead><tr><th>Host</th><th>Status</th><th>Last report</th></tr></thead><tbody>{rows}</tbody></table></main><footer>{release}{account}</footer></body></html>",
        head = document_head(base),
        fleet_data = fleet_data_status_html(fleet_data, now),
        release = release_label_html(),
        account = account_html(base, user),
    )
}

pub(super) async fn home(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    let hosts = filter_hosts_by_access(state.store.list(), &access);
    no_store_html(
        &state,
        render_home(
            &state.public_base_path,
            state.auth.human_user(&headers).as_ref(),
            &hosts,
            state
                .fleet_data
                .as_deref()
                .map(FleetDataRuntime::view)
                .as_ref(),
            now_unix(),
        ),
    )
}

pub(super) async fn calendar_version_bootstrap_asset() -> impl IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-cache, must-revalidate"),
        ],
        CALENDAR_VERSION_BOOTSTRAP_JS,
    )
}

pub(super) async fn calendar_version_bundle_asset(AxumPath(name): AxumPath<String>) -> Response {
    let source = match name.as_str() {
        "version.js" => CALENDAR_VERSION_JS,
        "presentation.js" => CALENDAR_VERSION_PRESENTATION_JS,
        "version-interaction.js" => CALENDAR_VERSION_INTERACTION_JS,
        "auto-animate.js" => CALENDAR_VERSION_AUTO_ANIMATE_JS,
        "auto-animate-license.js" => CALENDAR_VERSION_AUTO_ANIMATE_LICENSE_JS,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "no-cache, must-revalidate"),
        ],
        source,
    )
        .into_response()
}

pub(super) async fn favicon_svg() -> impl IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/svg+xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=86400"),
        ],
        FAVICON_SVG,
    )
}

pub(super) fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text_content(html: &str) -> String {
        let mut text = String::new();
        let mut in_tag = false;
        for ch in html.chars() {
            match ch {
                '<' => in_tag = true,
                '>' => in_tag = false,
                _ if !in_tag => text.push(ch),
                _ => {}
            }
        }
        text
    }

    #[test]
    fn calendar_version_display_embeds_the_pinned_pretty_contract() {
        let data: serde_json::Value =
            serde_json::from_str(CALENDAR_VERSION_DISPLAY_JSON).expect("display configuration");
        assert_eq!(data["schema"], "inspr.calendar-version-display.v2");
        assert_eq!(data["scheme"], "inspr-calendar-v2");
        assert_eq!(data["design_revision"], 3);
        assert_eq!(data["weights"]["v"], 0.05);
        assert_eq!(data["weights"]["tail"], 0.05);
        assert!(data["pretty"]["separators"].is_object());
    }

    #[test]
    fn release_label_keeps_canonical_fallback_and_declared_scheme() {
        let html = release_label_html();
        assert!(html.contains(r#"data-calendar-display"#));
        assert!(html.contains(&format!(r#"data-canonical="{APP_VERSION}""#)));
        assert!(html.contains(&format!(r#"data-version="v{APP_VERSION}""#)));
        assert!(html.contains(&format!(r#"data-scheme="{VERSION_SCHEME}""#)));
        assert!(html.contains(r##"data-brand="#1f7fb5""##));
        assert_eq!(text_content(&html), release_label());
    }

    #[test]
    fn document_head_carries_one_embedded_config_and_base_aware_bootstrap() {
        let head = document_head(&PublicBasePath::parse("/pharos").unwrap());
        assert_eq!(head.matches("inspr-calendar-version-display").count(), 1);
        assert!(head.contains("inspr.calendar-version-display.v2"));
        assert!(head.contains(r#"src="/pharos/assets/calendar-version-bootstrap.mjs""#));
        assert!(head.contains(r#"href="/pharos/favicon.svg""#));
    }

    #[test]
    fn home_escapes_host_names() {
        let host: Host = serde_json::from_value(json!({
            "name": "<ares>",
            "role": "server",
            "is_nix": true,
            "last_seen": null,
            "heartbeat_interval_secs": null,
            "freshness": pharos_core::NixFreshness::default(),
        }))
        .expect("host fixture");
        let html = render_home(&PublicBasePath::root(), None, &[host], None, 100);
        assert!(html.contains("&lt;ares&gt;"));
        assert!(!html.contains("<ares>"));
        assert!(!html.contains("data-logout-form"));
    }

    #[test]
    fn home_always_says_how_old_the_fleet_data_is_and_what_is_wrong() {
        let good = Arc::new(FleetData::parse(fleet_data::CONTRACT).expect("contract"));
        let updated = good.updated_at_unix().expect("contract has a time");
        let now = updated + 3 * 86_400;
        let line = |data: Option<Arc<FleetData>>, problem: Option<&str>| {
            let view = FleetDataView {
                data,
                problem: problem.map(str::to_string),
            };
            render_home(&PublicBasePath::root(), None, &[], Some(&view), now)
        };

        let html = line(Some(good.clone()), None);
        assert!(html.contains("Fleet data file loaded. Data from 3 d ago."));

        let html = line(Some(good), Some("the file is <missing>"));
        assert!(html.contains(
            "Fleet data problem: the file is &lt;missing&gt;. Data from 3 d ago. \
             This is the last good copy."
        ));
        assert!(html.contains("<h1>Fleet</h1>"), "never a blank page");

        let html = line(None, Some("the file is missing"));
        assert!(html.contains("Fleet data problem: the file is missing. No data yet."));
        assert!(html.contains("<h1>Fleet</h1>"), "never a blank page");

        let html = render_home(&PublicBasePath::root(), None, &[], None, now);
        assert!(html.contains("Fleet data file: not configured."));
    }

    #[test]
    fn data_age_reads_in_minutes_hours_and_days() {
        assert_eq!(age_text(-5), "0 min ago");
        assert_eq!(age_text(59), "0 min ago");
        assert_eq!(age_text(3_599), "59 min ago");
        assert_eq!(age_text(3_600), "1 h ago");
        assert_eq!(age_text(86_399), "23 h ago");
        assert_eq!(age_text(86_400), "1 d ago");
    }

    #[test]
    fn signed_in_home_offers_a_mount_aware_logout() {
        let user = AuthUser {
            display_name: "<operator>".to_string(),
        };
        let html = render_home(
            &PublicBasePath::parse("/pharos").unwrap(),
            Some(&user),
            &[],
            None,
            100,
        );
        assert!(html.contains("&lt;operator&gt;"));
        assert!(html.contains(r#"action="/pharos/auth/logout""#));
        assert!(html.contains("data-logout-csrf"));
    }

    #[tokio::test]
    async fn calendar_renderer_assets_are_local_revalidated_modules() {
        let bootstrap = calendar_version_bootstrap_asset().await.into_response();
        assert_eq!(bootstrap.status(), StatusCode::OK);
        assert_eq!(
            bootstrap.headers().get(header::CACHE_CONTROL).unwrap(),
            "no-cache, must-revalidate"
        );
        let bootstrap = axum::body::to_bytes(bootstrap.into_body(), usize::MAX)
            .await
            .expect("bootstrap body");
        assert!(bootstrap.starts_with(b"import { renderVersion }"));

        let renderer = calendar_version_bundle_asset(AxumPath("version.js".to_string())).await;
        assert_eq!(renderer.status(), StatusCode::OK);
        let missing = calendar_version_bundle_asset(AxumPath("other.js".to_string())).await;
        assert_eq!(missing.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn favicon_is_an_svg() {
        assert!(FAVICON_SVG.starts_with("<svg"));
        let response = favicon_svg().await.into_response();
        assert_eq!(
            response.headers().get(header::CONTENT_TYPE).unwrap(),
            "image/svg+xml; charset=utf-8"
        );
    }
}
