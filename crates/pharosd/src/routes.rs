//! HTTP route composition and the explicit human/machine security boundary.

use super::*;

fn human_routes() -> Router<AppState> {
    Router::new()
        .route("/", get(home))
        .route("/map", get(map_page))
        .route("/map/data.json", get(map_data_json))
        .route("/alerts", get(alerts_page))
        .route("/backups", get(backups_page))
        .route("/activity", get(activity_page))
        .route("/services", get(managed_service_ui::services_page))
        .route(
            "/services/{host_ref}/{service_ref}",
            get(managed_service_ui::service_detail_page),
        )
        .route("/settings/providers", get(provider_settings_page))
        .route("/settings/providers.json", get(provider_connections_json))
        .route(
            "/settings/providers/{provider}",
            get(provider_settings_detail_page),
        )
        .route(
            "/settings/providers/hetzner-cloud/test",
            post(test_hetzner_provider_connection),
        )
        .route(
            "/settings/providers/hetzner-cloud/preferences",
            post(update_hetzner_provider_preferences),
        )
        .route(
            "/settings/providers/hetzner-cloud/disconnect",
            post(disconnect_hetzner_provider),
        )
        .route("/agora", get(agora::page))
        .route(
            "/agora/proposals/host-palette.json",
            get(agora::palette_proposal),
        )
        .route(
            "/agora/requests/host-preferences.json",
            post(agora::request_host_preferences),
        )
        .route(
            "/agora/proposals/host-location.json",
            get(agora::location_proposal),
        )
        .route("/hosts.json", get(hosts_json))
        .route("/setup/provider-plan.json", get(setup_provider_plan_json))
        .route("/setup/provisioning-jobs", post(create_provisioning_job))
        .route("/setup/provisioning-jobs/{id}", get(provisioning_job_json))
        .route(
            "/setup/provisioning-jobs/{id}/confirm",
            post(confirm_paid_provisioning_job),
        )
        .route(
            "/setup/provisioning-jobs/{id}/create",
            post(create_paid_provisioning_job),
        )
        .route(
            "/setup/provisioning-jobs/{id}/cleanup",
            post(cleanup_provisioning_job),
        )
        .route(
            "/setup/provisioning-jobs/{id}/host-key",
            post(attest_provisioning_host_key),
        )
        .route(
            "/setup/provisioning-jobs/{id}/retry-bootstrap",
            post(retry_provisioning_bootstrap),
        )
        .route(
            "/setup/existing-host/preflight",
            post(existing_host_preflight_json),
        )
        .route("/declared-hosts.json", get(declared_hosts_json))
        .route(
            "/managed-service-declarations.json",
            get(managed_service_declarations_json),
        )
        .route(
            "/managed-service-setup-intents",
            post(create_managed_setup_intent).layer(DefaultBodyLimit::max(4 * 1024)),
        )
        .route(
            "/managed-service-setup-intents/{intent_ref}/cancel",
            post(cancel_managed_setup_intent),
        )
        .route("/host-actions/system-update", post(request_system_update))
        .route(
            "/host-actions/{host}/update-restart/review",
            post(request_update_restart_review),
        )
        .route("/host-actions/jobs/{id}", get(host_action_job_json))
        .route(
            "/host-actions/jobs/{id}/retry",
            post(retry_update_restart_review),
        )
        .route(
            "/host-actions/jobs/{id}/cancel",
            post(cancel_update_restart_review),
        )
        .route(
            "/host-actions/jobs/{id}/confirm",
            post(confirm_update_restart),
        )
        .route(
            "/host-actions/jobs/{id}/recover",
            post(recover_update_restart),
        )
        .route("/host-actions/{host}/remove", post(request_host_removal))
        .route(
            "/host-actions/jobs/{id}/retry-retirement",
            post(retry_host_retirement),
        )
        .route(
            "/host-actions/{host}/allow-reonboarding",
            post(allow_host_reonboarding),
        )
}

fn machine_and_public_routes() -> Router<AppState> {
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/version", get(version))
        .route("/favicon.svg", get(favicon_svg))
        .route("/assets/fleet-horizon.png", get(fleet_horizon_asset))
        .route(
            "/assets/sidebar-lighthouse.png",
            get(sidebar_lighthouse_asset),
        )
        .route(
            "/assets/sidebar-lighthouse-motion-v1.mp4",
            get(sidebar_lighthouse_motion_asset),
        )
        .route(
            "/assets/vendor/leaflet-1.9.4/leaflet.css",
            get(leaflet_css_asset),
        )
        .route(
            "/assets/vendor/leaflet-1.9.4/leaflet.js",
            get(leaflet_js_asset),
        )
        .route(
            "/assets/vendor/leaflet-1.9.4/images/{name}",
            get(leaflet_image_asset),
        )
        .route("/assets/vendor/d3-7.9.0/d3.min.js", get(d3_js_asset))
        .route(
            "/register",
            post(register).layer(DefaultBodyLimit::max(MAX_HOST_REGISTRATION_BYTES)),
        )
        .route(
            "/report",
            post(report).layer(DefaultBodyLimit::max(MAX_HOST_REPORT_BYTES)),
        )
        .route("/agent/actions/claim", post(claim_host_action))
        .route(
            "/agent/actions/{id}/result",
            post(record_host_action_result),
        )
        .route("/agent/retirements/claim", post(claim_retirement_action))
        .route(
            "/agent/retirements/{id}/result",
            post(record_retirement_action_result),
        )
        .route(
            "/agent/provisioning/claim",
            post(claim_managed_provisioning_action),
        )
        .route(
            "/agent/provisioning/{id}/result",
            post(record_managed_provisioning_result),
        )
        .route(
            "/agent/managed-services/claim",
            post(claim_managed_service_operation)
                .layer(DefaultBodyLimit::max(MAX_MANAGED_OPERATION_REQUEST_BYTES)),
        )
        .route(
            "/agent/managed-services/{operation_ref}/result",
            post(record_managed_service_operation_result)
                .layer(DefaultBodyLimit::max(MAX_MANAGED_OPERATION_REQUEST_BYTES)),
        )
        .route(
            "/agent/managed-services/{operation_ref}",
            get(retrieve_managed_service_operation_for_host),
        )
        .route(
            "/internal/managed-service-setup-intents/{intent_ref}",
            get(retrieve_managed_setup_intent),
        )
        .route(
            "/internal/managed-service-operations",
            post(register_managed_service_operation)
                .layer(DefaultBodyLimit::max(MAX_MANAGED_OPERATION_REQUEST_BYTES)),
        )
        .route(
            "/internal/managed-service-operations/{operation_ref}",
            get(retrieve_managed_service_operation),
        )
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route("/auth/logged-out", get(auth::logged_out))
}

pub(super) fn build_router(state: AppState) -> Router {
    human_routes()
        .route_layer(middleware::from_fn_with_state(state.clone(), auth::guard))
        .merge(machine_and_public_routes())
        .with_state(state)
        .layer(middleware::from_fn(security_headers))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protected_and_public_route_groups_build_independently() {
        assert!(human_routes().has_routes());
        assert!(machine_and_public_routes().has_routes());
    }
}
