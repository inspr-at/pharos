//! Release identity, browser assets and the Fleet page.

use axum::extract::Query;

use super::*;
use crate::fleet_view::FleetView;
use crate::pages::{
    render_cve, render_fleet, render_handled, render_host, render_not_found, render_updates,
    Arrange, FleetQuery,
};

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
const APP_CSS: &str = include_str!("../assets/ui/app.css");
const APP_JS: &str = include_str!("../assets/ui/app.js");
const FLEET_HORIZON_WEBP: &[u8] = include_bytes!("../assets/ui/fleet-horizon.webp");
const SIDEBAR_LIGHTHOUSE_WEBP: &[u8] = include_bytes!("../assets/ui/sidebar-lighthouse.webp");
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

pub(super) fn document_head(base: &PublicBasePath, title: &str) -> String {
    format!(
        r#"<!doctype html><html lang="en" class="fl" data-theme="light"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>{title} · Pharos</title><link rel="icon" href="{favicon}"><link rel="stylesheet" href="{stylesheet}"><meta name="inspr-calendar-version-display" content="{display}"><script src="{script}"></script><script type="module" src="{bootstrap}"></script></head>"#,
        title = html_escape(title),
        favicon = app_href(base, "/favicon.svg"),
        stylesheet = app_href(base, "/assets/ui/app.css"),
        script = app_href(base, "/assets/ui/app.js"),
        display = html_escape(CALENDAR_VERSION_DISPLAY_JSON),
        bootstrap = app_href(base, "/assets/calendar-version-bootstrap.mjs"),
    )
}

/// Double-submit logout: the runtime copies the CSRF cookie into the form.
pub(super) fn account_html(base: &PublicBasePath, user: Option<&AuthUser>) -> String {
    let Some(user) = user else {
        return String::new();
    };
    format!(
        r#"<div class="side-foot"><span class="side-user"><span class="side-avatar" aria-hidden="true"></span><span class="side-name">{name}</span></span><form class="side-logout-form" action="{logout}" method="post" data-logout-form><input type="hidden" name="csrf" value="" data-logout-csrf><button class="side-logout" type="submit" aria-label="Sign out" title="Sign out">{sign_out}</button></form></div>{LOGOUT_CSRF_RUNTIME}"#,
        name = html_escape(&user.display_name),
        logout = app_href(base, "/auth/logout"),
        sign_out = crate::icons::icon("sign-out", ""),
    )
}

#[derive(Default, serde::Deserialize)]
pub(super) struct FleetParams {
    cve: Option<String>,
    arrange: Option<String>,
    q: Option<String>,
}

/// Everything a page shows at this moment.
pub(super) fn fleet_view(state: &AppState) -> FleetView {
    let now = now_unix();
    let probes = state
        .host_probes
        .as_deref()
        .map(|runtime| runtime.snapshot(now))
        .unwrap_or_default();
    FleetView::build(
        state.fleet_data.as_deref().map(FleetDataRuntime::view),
        state.store.list(),
        probes,
        now,
    )
}

pub(super) async fn home(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(params): Query<FleetParams>,
) -> impl IntoResponse {
    let query = FleetQuery {
        cve: params.cve,
        arrange: Arrange::parse(params.arrange.as_deref()),
        q: params.q.unwrap_or_default(),
    };
    no_store_html(
        &state,
        render_fleet(
            &state.public_base_path,
            state.auth.human_user(&headers).as_ref(),
            &fleet_view(&state),
            &query,
        ),
    )
}

pub(super) async fn updates_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    no_store_html(
        &state,
        render_updates(
            &state.public_base_path,
            state.auth.human_user(&headers).as_ref(),
            &fleet_view(&state),
        ),
    )
}

pub(super) async fn handled_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    no_store_html(
        &state,
        render_handled(
            &state.public_base_path,
            state.auth.human_user(&headers).as_ref(),
            &fleet_view(&state),
        ),
    )
}

fn found_or_404(
    state: &AppState,
    headers: &HeaderMap,
    page: Option<String>,
    what: &str,
) -> Response {
    match page {
        Some(page) => no_store_html(state, page).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            no_store_html(
                state,
                render_not_found(
                    &state.public_base_path,
                    state.auth.human_user(headers).as_ref(),
                    what,
                    now_unix(),
                ),
            ),
        )
            .into_response(),
    }
}

pub(super) async fn cve_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(id): AxumPath<String>,
) -> Response {
    let page = render_cve(
        &state.public_base_path,
        state.auth.human_user(&headers).as_ref(),
        &fleet_view(&state),
        &id,
    );
    found_or_404(&state, &headers, page, &id)
}

pub(super) async fn host_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(name): AxumPath<String>,
) -> Response {
    let page = render_host(
        &state.public_base_path,
        state.auth.human_user(&headers).as_ref(),
        &fleet_view(&state),
        &name,
    );
    found_or_404(&state, &headers, page, &name)
}

/// The page's stylesheet, script and art. Nothing here says anything about a host.
pub(super) async fn ui_asset(AxumPath(name): AxumPath<String>) -> Response {
    let (content_type, body): (&str, &[u8]) = match name.as_str() {
        "app.css" => ("text/css; charset=utf-8", APP_CSS.as_bytes()),
        "app.js" => ("application/javascript; charset=utf-8", APP_JS.as_bytes()),
        "fleet-horizon.webp" => ("image/webp", FLEET_HORIZON_WEBP),
        "sidebar-lighthouse.webp" => ("image/webp", SIDEBAR_LIGHTHOUSE_WEBP),
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache, must-revalidate"),
        ],
        body,
    )
        .into_response()
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
    fn document_head_carries_one_embedded_config_and_base_aware_assets() {
        let head = document_head(&PublicBasePath::parse("/pharos").unwrap(), "Fleet");
        assert_eq!(head.matches("inspr-calendar-version-display").count(), 1);
        assert!(head.contains("inspr.calendar-version-display.v2"));
        assert!(head.contains(r#"src="/pharos/assets/calendar-version-bootstrap.mjs""#));
        assert!(head.contains(r#"href="/pharos/favicon.svg""#));
        assert!(head.contains(r#"href="/pharos/assets/ui/app.css""#));
        assert!(head.contains(r#"src="/pharos/assets/ui/app.js""#));
        assert!(head.contains("<title>Fleet · Pharos</title>"));
    }

    #[test]
    fn signed_in_pages_offer_a_mount_aware_logout() {
        let user = AuthUser {
            display_name: "<operator>".to_string(),
        };
        let html = account_html(&PublicBasePath::parse("/pharos").unwrap(), Some(&user));
        assert!(html.contains("&lt;operator&gt;"));
        assert!(html.contains(r#"action="/pharos/auth/logout""#));
        assert!(html.contains("data-logout-csrf"));
        assert!(account_html(&PublicBasePath::root(), None).is_empty());
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
