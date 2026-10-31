//! HTTP route composition and the explicit human/machine security boundary.

use super::*;

fn human_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/updates", get(updates_page))
        .route("/handled", get(handled_page))
        .route("/cves/{id}", get(cve_page))
        .route("/hosts/{name}", get(host_page))
}

/// What the read-only operator token opens. Nothing here may change state.
fn data_routes() -> Router<AppState> {
    Router::new()
        .route("/hosts.json", get(hosts_json))
        .route("/fleet.json", get(fleet_json))
}

/// Stable machine surface. With a configured browser prefix these routes are
/// mounted both there and at origin root for existing beacon clients.
fn machine_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/version", get(version))
        .route(
            "/register",
            post(register).layer(DefaultBodyLimit::max(MAX_HOST_REGISTRATION_BYTES)),
        )
        .route(
            "/report",
            post(report).layer(DefaultBodyLimit::max(MAX_HOST_REPORT_BYTES)),
        )
}

/// Browser support and account routes follow the configured public mount only.
fn browser_public_routes() -> Router<AppState> {
    Router::new()
        .route("/favicon.svg", get(favicon_svg))
        .route("/assets/ui/{name}", get(ui_asset))
        .route(
            "/assets/calendar-version-bootstrap.mjs",
            get(calendar_version_bootstrap_asset),
        )
        .route(
            "/assets/vendor/calendar-version-display/{name}",
            get(calendar_version_bundle_asset),
        )
        .route("/auth/sign-in", get(auth::sign_in))
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/recover", get(auth::recover))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/logged-out", get(auth::logged_out))
}

fn machine_and_public_routes() -> Router<AppState> {
    machine_routes().merge(browser_public_routes())
}

pub(super) fn build_router(state: AppState) -> Router {
    let mut state = state;
    state.auth.public_base_path = state.public_base_path.clone();
    let public_base_path = state.public_base_path.clone();
    let inner = human_routes()
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        .merge(data_routes().route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::data_guard,
        )))
        .merge(machine_and_public_routes());
    if public_base_path.is_root() {
        inner
            .with_state(state)
            .layer(middleware::from_fn(security_headers))
    } else {
        let trailing_public_root = format!("{}/", public_base_path.as_str());
        Router::new()
            .merge(machine_routes())
            .route(&trailing_public_root, get(canonicalize_public_root))
            .nest(public_base_path.as_str(), inner)
            .fallback(outside_public_mount)
            .with_state(state)
            .layer(middleware::from_fn(security_headers))
    }
}

async fn canonicalize_public_root(
    State(state): State<AppState>,
    RawQuery(query): RawQuery,
) -> Redirect {
    let mut location = state.public_base_path.home().to_string();
    if let Some(query) = query {
        location.push('?');
        location.push_str(&query);
    }
    Redirect::permanent(&location)
}

async fn outside_public_mount() -> StatusCode {
    StatusCode::NOT_FOUND
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_and_public_route_groups_build_independently() {
        assert!(human_routes().has_routes());
        assert!(data_routes().has_routes());
        assert!(machine_routes().has_routes());
        assert!(browser_public_routes().has_routes());
        assert!(machine_and_public_routes().has_routes());
    }
}
