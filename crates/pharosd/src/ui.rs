//! Server-rendered UI, static assets, presentation models, and view probes.

use super::*;

pub(super) const FLEET_HORIZON_PNG: &[u8] = include_bytes!("../assets/fleet-horizon.png");
pub(super) const SIDEBAR_LIGHTHOUSE_PNG: &[u8] = include_bytes!("../assets/sidebar-lighthouse.png");
pub(super) const SIDEBAR_LIGHTHOUSE_MOTION_MP4: &[u8] =
    include_bytes!("../assets/sidebar-lighthouse-motion-v1.mp4");
pub(super) const LEAFLET_CSS: &str = include_str!("../assets/vendor/leaflet-1.9.4/leaflet.css");
pub(super) const LEAFLET_JS: &str = include_str!("../assets/vendor/leaflet-1.9.4/leaflet.js");
pub(super) const LEAFLET_LAYERS_PNG: &[u8] =
    include_bytes!("../assets/vendor/leaflet-1.9.4/images/layers.png");
pub(super) const LEAFLET_LAYERS_2X_PNG: &[u8] =
    include_bytes!("../assets/vendor/leaflet-1.9.4/images/layers-2x.png");
pub(super) const LEAFLET_MARKER_ICON_PNG: &[u8] =
    include_bytes!("../assets/vendor/leaflet-1.9.4/images/marker-icon.png");
pub(super) const LEAFLET_MARKER_ICON_2X_PNG: &[u8] =
    include_bytes!("../assets/vendor/leaflet-1.9.4/images/marker-icon-2x.png");
pub(super) const LEAFLET_MARKER_SHADOW_PNG: &[u8] =
    include_bytes!("../assets/vendor/leaflet-1.9.4/images/marker-shadow.png");
pub(super) const D3_JS: &str = include_str!("../assets/vendor/d3-7.9.0/d3.min.js");
pub(super) const MAPLIBRE_CSS: &str =
    include_str!("../assets/vendor/maplibre-gl-5.24.0/maplibre-gl.css");
pub(super) const MAPLIBRE_JS: &str =
    include_str!("../assets/vendor/maplibre-gl-5.24.0/maplibre-gl-csp.js");
pub(super) const MAPLIBRE_WORKER_JS: &str =
    include_str!("../assets/vendor/maplibre-gl-5.24.0/maplibre-gl-csp-worker.js");
pub(super) const MAPLIBRE_LEAFLET_JS: &str =
    include_str!("../assets/vendor/maplibre-gl-leaflet-0.1.3/leaflet-maplibre-gl.js");
// Only the vendored worker response receives this narrow fetch policy.
#[derive(Clone, Copy)]
pub(super) struct MapWorkerAsset;
pub(super) const MAP_WORKER_CSP: &str =
    "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; connect-src https://tiles.openfreemap.org";
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
pub(super) const CHANGELOG_MD: &str = include_str!("../../../docs/CHANGELOG.md");
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

pub(super) const HEAD: &str = include_str!("../assets/ui/head.html");

pub(super) const FOOT: &str = include_str!("../assets/ui/foot.html");

/// Calendar v2 display settings from the complete, pinned INSPR renderer bundle.
/// The check script and build script verify every local module and its license.
pub(super) const CALENDAR_VERSION_DISPLAY_JSON: &str =
    include_str!("../assets/vendor/calendar-version-display/display.json");

const CALENDAR_VERSION_BRAND: &str = "#1f7fb5";

pub(super) fn release_label_html(interactive: bool) -> String {
    let interactive = if interactive {
        ""
    } else {
        r#" data-calendar-interactive="false""#
    };
    format!(
        r#"<span data-calendar-display data-canonical="{version}" data-version="v{version}" data-scheme="{scheme}" data-brand="{brand}"{interactive}>v{version}</span>"#,
        version = html_escape(APP_VERSION),
        scheme = html_escape(VERSION_SCHEME),
        brand = CALENDAR_VERSION_BRAND,
    )
}

pub(super) fn app_href(base: &PublicBasePath, endpoint: &str) -> String {
    html_escape(&base.href(endpoint))
}

const HETZNER_ASSISTANT_ENDPOINT: &str =
    "/?setup=add-server&setup_path=new&setup_provider=hetzner-cloud&setup_stage=template";

pub(super) fn document_head(base: &PublicBasePath) -> String {
    HEAD.replace(
        "</head>",
        &format!(
            r#"<meta name="inspr-calendar-version-display" content="{}"><script type="module" src="{}"></script></head>"#,
            html_escape(CALENDAR_VERSION_DISPLAY_JSON),
            app_href(base, "/assets/calendar-version-bootstrap.mjs")
        ),
    )
    .replace(
        r#"href="/favicon.svg""#,
        &format!(r#"href="{}""#, app_href(base, "/favicon.svg")),
    )
    .replace(
        "url('/assets/sidebar-lighthouse.png')",
        &format!("url('{}')", base.href("/assets/sidebar-lighthouse.png")),
    )
    .replace(
        "url('/assets/fleet-horizon.png')",
        &format!("url('{}')", base.href("/assets/fleet-horizon.png")),
    )
}

pub(super) const HEARTBEAT_HISTORY_DOTS: usize = 12;
pub(super) const HEARTBEAT_EXPECT_X: f64 = 64.0;
pub(super) const HEARTBEAT_STALE_X: f64 = 82.0;
pub(super) const SIGNAL_DEFAULT_WINDOW_LABEL: &str = "10m";
pub(super) const SIGNAL_DEFAULT_WINDOW_SECS: i64 = 10 * 60;

pub(super) fn release_label() -> String {
    format!("v{APP_VERSION}")
}

pub(super) fn release_scheme_label() -> &'static str {
    env!("PHAROS_VERSION_SCHEME_LABEL")
}

pub(super) fn release_set_url() -> String {
    format!(
        "https://github.com/inspr-at/pharos/releases/download/{}/release-set.json",
        release_label()
    )
}

pub(super) fn changelog_html() -> String {
    let mut html = String::new();
    let mut in_list = false;
    let mut in_unreleased = false;
    let date_format = time::format_description::parse_borrowed::<2>("[year]-[month]-[day]")
        .expect("release date format");
    for line in CHANGELOG_MD.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            continue;
        }
        if let Some(text) = trimmed.strip_prefix("## ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            in_unreleased = text.eq_ignore_ascii_case("Unreleased");
            if in_unreleased {
                continue;
            }
            if let Some((version, date)) = text
                .rsplit_once(" - ")
                .filter(|(_, date)| time::Date::parse(date, &date_format).is_ok())
            {
                html.push_str(&format!(
                    r#"<h3 class="release-entry-heading" title="{date}"><span class="release-entry-version">{version}</span> <time class="release-age" datetime="{date}" title="{date}">{date}</time></h3>"#,
                    version = html_escape(version),
                    date = html_escape(date),
                ));
            } else {
                html.push_str(&format!("<h3>{}</h3>", html_escape(text)));
            }
        } else if in_unreleased {
            continue;
        } else if let Some(text) = trimmed.strip_prefix("# ") {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str(&format!("<h2>{}</h2>", html_escape(text)));
        } else if let Some(text) = trimmed.strip_prefix("- ") {
            if !in_list {
                html.push_str("<ul>");
                in_list = true;
            }
            html.push_str(&format!("<li>{}</li>", html_escape(text)));
        } else {
            if in_list {
                html.push_str("</ul>");
                in_list = false;
            }
            html.push_str(&format!("<p>{}</p>", html_escape(trimmed)));
        }
    }
    if in_list {
        html.push_str("</ul>");
    }
    html
}

pub(super) fn release_dialog() -> String {
    format!(
        r#"<section class="release-overlay" data-release-modal hidden aria-label="release history"><div class="release-backdrop" data-release-close></div><div class="release-sheet" role="dialog" aria-modal="true" aria-labelledby="release-history-title"><header class="release-head"><div class="release-title"><h2 id="release-history-title">Release history</h2><p>Running {version} · build {commit}</p></div><button class="release-close" type="button" data-release-close>Close</button><div class="release-meta"><dl class="release-identity" data-release-identity><div><dt>Scheme</dt><dd>{scheme}</dd></div><div><dt>Channel</dt><dd>{channel}</dd></div><div><dt>Sequence</dt><dd>#{sequence}</dd></div></dl><a class="release-set-link" data-release-set href="{release_set}" download="release-set.json" target="_blank" rel="noopener noreferrer" aria-label="Download release details (JSON)" title="Download release details (JSON): exact artifact versions and checksums."><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M5 16v4h14v-4"/></svg><span>Release details</span></a></div></header><div class="release-body">{history}</div></div></section>"#,
        version = release_label_html(true),
        commit = html_escape(GIT_COMMIT),
        scheme = html_escape(release_scheme_label()),
        channel = html_escape(RELEASE_CHANNEL),
        sequence = html_escape(RELEASE_SEQUENCE),
        release_set = html_escape(&release_set_url()),
        history = changelog_html()
    )
}

pub(super) const RELEASE_HISTORY_PORTAL: &str = include_str!("../assets/ui/release-history.html");

pub(super) const LOGOUT_CSRF_RUNTIME: &str = include_str!("../assets/ui/logout-csrf.html");

pub(super) const SIDEBAR_MOTION_RUNTIME: &str = include_str!("../assets/ui/sidebar-motion.html");
pub(super) const SETUP_ASSISTANT_TEMPLATE: &str = include_str!("../assets/ui/setup-assistant.html");
pub(super) const OPS_RUNTIME: &str = include_str!("../assets/ui/ops.html");
pub(super) const MAP_RUNTIME: &str = include_str!("../assets/ui/map.html");

#[cfg(test)]
mod module_tests {
    use super::*;
    use crate::host_actions::{HostLifecycle, HostLifecycleInvoke, HostLifecycleSlot};

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
        let html = release_label_html(true);
        assert!(html.contains(r#"data-calendar-display"#));
        assert!(html.contains(&format!(r#"data-canonical="{APP_VERSION}""#)));
        assert!(html.contains(&format!(r#"data-version="v{APP_VERSION}""#)));
        assert!(html.contains(&format!(r#"data-scheme="{VERSION_SCHEME}""#)));
        assert!(html.contains(r##"data-brand="#1f7fb5""##));
        assert!(!html.contains("data-calendar-interactive"));
        assert_eq!(text_content(&html), release_label());
    }

    #[test]
    fn nested_sidebar_label_disables_its_own_copy_control() {
        assert!(release_label_html(false).contains(r#"data-calendar-interactive="false""#));
    }

    #[test]
    fn document_head_carries_one_embedded_config_and_base_aware_bootstrap() {
        let head = document_head(&PublicBasePath::parse("/pharos").unwrap());
        assert_eq!(head.matches("inspr-calendar-version-display").count(), 1);
        assert!(head.contains("inspr.calendar-version-display.v2"));
        assert!(head.contains(r#"src="/pharos/assets/calendar-version-bootstrap.mjs""#));
        assert!(
            head.ends_with(r#"<body><div class="app-shell">"#) || head.contains("</head><body>")
        );
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
        assert_eq!(
            renderer.headers().get(header::CONTENT_TYPE).unwrap(),
            "application/javascript; charset=utf-8"
        );
        assert_eq!(
            calendar_version_bundle_asset(AxumPath("display.json".to_string()))
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }

    fn proven_current(channel: &str) -> NixFreshness {
        let source_revision = "1".repeat(40);
        let nixpkgs_revision = "2".repeat(40);
        NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(0),
            commits_behind: Some(0),
            nixpkgs_age_days: Some(0),
            nixpkgs_channel: Some(channel.to_string()),
            secondary_nixpkgs: None,
            deployment_evidence: Some(NixDeploymentEvidence {
                schema: pharos_core::NIX_DEPLOYMENT_EVIDENCE_SCHEMA.to_string(),
                version: pharos_core::NIX_DEPLOYMENT_EVIDENCE_VERSION,
                source_revision: source_revision.clone(),
                flake_lock_sha256: "3".repeat(64),
                nixpkgs_revision: nixpkgs_revision.clone(),
                nixpkgs_last_modified: 1_700_000_000,
                nixpkgs_channel: channel.to_string(),
            }),
            nixcfg_comparison: Some(NixcfgGitComparison {
                upstream_revision: source_revision,
                relation: GitRevisionRelation::Current,
                commits_behind: Some(0),
            }),
            nixpkgs_comparison: Some(NixpkgsGitComparison {
                upstream_revision: nixpkgs_revision,
                relation: NixpkgsRevisionRelation::Current,
            }),
        }
    }

    #[test]
    fn external_ui_assets_are_embedded_and_html_escaping_is_safe() {
        assert!(HEAD.contains("<style"));
        for action in [
            "continue",
            "retry",
            "reconcile",
            "recover",
            "recheck",
            "refresh",
            "withdraw",
            "cancel",
            "escalate",
        ] {
            assert!(
                HEAD.contains(&format!("{action}:Object.freeze({{")),
                "missing action taxonomy entry for {action}"
            );
        }
        for field in ["effect:", "idempotency:", "owner:", "outcome:"] {
            assert!(
                HEAD.contains(field),
                "missing action taxonomy field {field}"
            );
        }
        assert!(FOOT.contains("<script"));
        assert!(FAVICON_SVG.starts_with("<svg"));
        assert!(RELEASE_HISTORY_PORTAL.contains("data-release"));
        assert!(SETUP_ASSISTANT_TEMPLATE.contains("data-setup-assistant"));
        assert_eq!(html_escape("<&\"'>"), "&lt;&amp;&quot;&#39;&gt;");
    }

    fn forbidden_runtime_host(source: &str) -> Option<&'static str> {
        const HOSTS: [&str; 10] = [
            "googletagmanager.com",
            "google-analytics.com",
            "gstatic.com",
            "fonts.googleapis.com",
            "youtube.com",
            "youtube-nocookie.com",
            "doubleclick.net",
            "facebook.com",
            "hotjar.com",
            "cdn.",
        ];
        let lower = source.to_ascii_lowercase();
        HOSTS.into_iter().find(|host| {
            lower.match_indices(host).any(|(index, _)| {
                let tag_start = lower[..index].rfind('<').unwrap_or(index);
                let tag_end = lower[index..]
                    .find('>')
                    .map(|offset| index + offset + 1)
                    .unwrap_or(index + host.len());
                let context = &lower[tag_start..tag_end];
                !(context.starts_with("<a ") && context.contains("href="))
            })
        })
    }

    #[test]
    fn ui_runtime_host_guard_blocks_trackers_but_allows_plain_links() {
        let sources = [
            ("head", HEAD),
            ("foot", FOOT),
            ("map", MAP_RUNTIME),
            ("ops", OPS_RUNTIME),
            ("logout-csrf", LOGOUT_CSRF_RUNTIME),
            ("sidebar-motion", SIDEBAR_MOTION_RUNTIME),
            ("setup-assistant", SETUP_ASSISTANT_TEMPLATE),
            ("release-history", RELEASE_HISTORY_PORTAL),
        ];
        for (name, source) in sources {
            assert_eq!(
                forbidden_runtime_host(source),
                None,
                "{name} contains a blocked runtime host"
            );
        }

        let shell = ShellContext {
            user_label: "Runtime host fixture",
            logout_enabled: false,
            public_base_path: &PublicBasePath::ROOT,
        };
        let rendered_shells = [
            (
                "rendered-fleet",
                render_home(
                    RuntimeSnapshot {
                        nixpkgs_warn_after_days: 30,
                        hosts: &[],
                        jobs: &[],
                        action_jobs: &[],
                        declared_preferences: None,
                        janus_managed_hosts: None,
                    },
                    "pharos",
                    1_700_000_000,
                    &[],
                    shell,
                    true,
                ),
            ),
            (
                "rendered-map",
                render_map(
                    &[],
                    "pharos",
                    1_700_000_000,
                    "Runtime host fixture",
                    false,
                    &PublicBasePath::ROOT,
                ),
            ),
        ];
        for (name, source) in rendered_shells {
            assert_eq!(
                forbidden_runtime_host(&source),
                None,
                "{name} contains a blocked runtime host"
            );
        }

        assert!(FOOT.contains("max-age=0; SameSite=Lax"));
        assert!(!FOOT.contains("max-age=31536000"));
        assert!(FOOT.contains("const UI_PREFERENCE_TTL_MS=180*24*60*60*1000"));
        assert!(MAP_RUNTIME.contains("const MAP_PREFERENCE_TTL_MS=180*24*60*60*1000"));

        let tracker_fixture = r#"<script src="https://www.googletagmanager.com/gtm.js"></script>"#;
        assert_eq!(
            forbidden_runtime_host(tracker_fixture),
            Some("googletagmanager.com")
        );
        let dynamic_tracker_fixture = format!(
            r#"{head}<main><img src="https://{host}/tracker.gif"></main>{foot}"#,
            head = HEAD,
            host = "google-analytics.com",
            foot = FOOT,
        );
        assert_eq!(
            forbidden_runtime_host(&dynamic_tracker_fixture),
            Some("google-analytics.com")
        );
        let link_fixture = r#"<a href="https://youtube.com/watch?v=fixture">Open video</a>"#;
        assert_eq!(forbidden_runtime_host(link_fixture), None);
    }

    #[test]
    fn release_dialog_exposes_discriminated_identity_and_exact_manifest_link() {
        let dialog = release_dialog();
        assert!(dialog.contains(">INSPR-VER2<"));
        assert!(dialog.contains(">stable<"));
        assert!(dialog.contains(&format!(">#{RELEASE_SEQUENCE}<")));
        assert!(dialog.contains(&format!(
            "href=\"https://github.com/inspr-at/pharos/releases/download/v{APP_VERSION}/release-set.json\""
        )));
        assert!(dialog.contains("rel=\"noopener noreferrer\""));
    }

    #[test]
    fn activity_focus_resolves_only_an_exact_authorized_host_and_workflow() {
        let job = HostActionStore::new(None)
            .create_system_update_proposal(
                "activity-workflow-known".to_string(),
                "athena",
                "markus",
                1_000,
            )
            .expect("action fixture");
        let exact: ActivityQuery = serde_json::from_value(serde_json::json!({
            "host": "athena",
            "workflow": "activity-workflow-known"
        }))
        .expect("activity query");
        assert_eq!(
            activity_focus(&exact, std::slice::from_ref(&job)),
            ActivityFocus::Workflow {
                host: "athena".to_string(),
                workflow_id: "activity-workflow-known".to_string(),
            }
        );

        for unavailable in [
            serde_json::json!({
                "host": "other-host",
                "workflow": "activity-workflow-known"
            }),
            serde_json::json!({
                "host": "athena",
                "workflow": "activity-workflow-unknown"
            }),
            serde_json::json!({"workflow": "activity-workflow-known"}),
        ] {
            let query: ActivityQuery = serde_json::from_value(unavailable).expect("activity query");
            assert_eq!(
                activity_focus(&query, std::slice::from_ref(&job)),
                ActivityFocus::Unavailable
            );
        }

        let recovery = activity_focus_path(&PublicBasePath::ROOT, &ActivityFocus::Unavailable);
        assert!(recovery.contains("Workflow activity unavailable"));
        assert!(recovery.contains(r#"href="/activity""#));
        assert!(!recovery.contains("activity-workflow-known"));
    }

    #[test]
    fn focused_activity_renders_the_exact_anchored_row_beyond_the_history_limit() {
        let mut events: Vec<_> = (0..80)
            .map(|index| {
                ActivityEvent::new(
                    2_000 - index,
                    format!("host-{index}"),
                    "info",
                    "heartbeat",
                    "Heartbeat received",
                    "Host checked in.",
                    "heartbeat",
                )
            })
            .collect();
        events.push(
            ActivityEvent::new(
                1,
                "athena",
                "recovery",
                "action",
                "Guarded host update completed",
                "PHAROS-251 · requested by operator.",
                "guarded action",
            )
            .with_workflow("activity-workflow-oldest"),
        );

        assert!(!activity_rows(&PublicBasePath::ROOT, &events).contains("activity-workflow-oldest"));
        let focus = ActivityFocus::Workflow {
            host: "athena".to_string(),
            workflow_id: "activity-workflow-oldest".to_string(),
        };
        let focused = focus_activity_events(events, &focus);
        assert_eq!(focused.len(), 1);
        let rows = activity_rows(&PublicBasePath::ROOT, &focused);
        assert!(rows.contains(r#"id="workflow-activity-workflow-oldest""#));
        assert!(rows.contains(r#"data-workflow-id="activity-workflow-oldest""#));
        assert!(rows.contains(r#"data-host="athena""#));
    }

    #[test]
    fn viewer_access_path_names_role_owner_and_get_only_help_route() {
        for scope in ["fleet", "settings", "provider", "managed-service"] {
            let html = viewer_access_path(&PublicBasePath::ROOT, scope);
            assert!(html.contains("Fleet manager access required"), "{html}");
            assert!(html.contains("Pharos administrator"), "{html}");
            assert!(
                html.contains(&format!(r#"href="/access/request?scope={scope}""#)),
                "{html}"
            );
            assert!(!html.contains("<form"), "{html}");
            assert!(!html.contains("data-method"), "{html}");
        }
    }

    #[test]
    fn age_policy_owns_attention_even_with_a_legacy_beacon_service_warning() {
        let now = 1_800_000_000;
        let mut freshness = proven_current("nixos-unstable");
        freshness
            .deployment_evidence
            .as_mut()
            .unwrap()
            .nixpkgs_last_modified = now - 30 * 86_400;
        freshness.nixpkgs_comparison.as_mut().unwrap().relation =
            NixpkgsRevisionRelation::Different;
        freshness
            .nixpkgs_comparison
            .as_mut()
            .unwrap()
            .upstream_revision = "4".repeat(40);
        let observations = [ServiceObservation::nix_freshness(&freshness)];
        assert_eq!(observations[0].state, ServiceObservationState::Warning);
        let mut prefs = HostPreferences::default();
        let reason = |freshness: &NixFreshness, prefs: &HostPreferences, limit| {
            attention_reason(
                Liveness::Live,
                freshness,
                None,
                &observations,
                prefs,
                now,
                limit,
            )
        };
        assert_eq!(reason(&freshness, &prefs, 30).level, "ok");
        assert_eq!(reason(&freshness, &prefs, 29).rank, 2);
        assert!(freshness_alert(&freshness, now, 30).is_none());
        assert!(freshness_alert(&freshness, now, 29).is_some());
        prefs.alerts.nixpkgs_warn_after_days = Some(31);
        assert_eq!(reason(&freshness, &prefs, 7).level, "ok");
        prefs.alerts.nixpkgs_warn_after_days = Some(7);
        assert_eq!(reason(&freshness, &prefs, 31).level, "warn");
        prefs.alerts.suppress_nix_freshness = true;
        assert_eq!(reason(&freshness, &prefs, 30).level, "ok");
        prefs.alerts.suppress_nix_freshness = false;
        freshness.nixpkgs_comparison = None;
        assert_eq!(
            reason(&freshness, &prefs, 30).label,
            "nixpkgs comparison unknown"
        );
        freshness
            .deployment_evidence
            .as_mut()
            .unwrap()
            .nixpkgs_channel = "nixos-25.05".to_string();
        assert!(reason(&freshness, &prefs, 3650)
            .label
            .contains("end of life"));
        let actual_service = ServiceObservation {
            id: "web".to_string(),
            label: "Web".to_string(),
            state: ServiceObservationState::Warning,
            summary: "response slow".to_string(),
        };
        assert_eq!(
            service_observation_attention_reason(&[actual_service])
                .unwrap()
                .rank,
            3
        );
    }

    /// PHAROS-193: the fleet showed a reassuring `0d` while nixpkgs was frozen
    /// on an expired channel. The operator-visible signal must say so.
    #[test]
    fn frozen_nixpkgs_is_visible_instead_of_the_newest_input_age() {
        let now = 1_786_310_400;
        let mut frozen = proven_current("nixos-25.05");
        frozen.nixpkgs_age_days = Some(218);
        frozen
            .deployment_evidence
            .as_mut()
            .expect("proof fixture")
            .nixpkgs_last_modified = now - 218 * 86_400;
        frozen.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "4".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });

        let markup = freshness_markup(&frozen, false, now, 30);
        assert!(
            markup.contains("218d"),
            "nixpkgs age must be shown: {markup}"
        );
        assert!(
            markup.contains("EOL"),
            "expired channel must be shown: {markup}"
        );
        assert!(
            markup.contains("nixpkgs lock"),
            "the label must name the value it shows: {markup}"
        );

        let reason = freshness_attention_reason(&frozen, now_unix(), 30)
            .expect("frozen nixpkgs needs attention");
        assert!(reason.label.contains("end of life"), "{}", reason.label);
        assert_eq!(reason.level, "warn");
        assert_eq!(reason.rank, 1, "an expired channel outranks age drift");
    }

    #[test]
    fn lifecycle_chip_is_button_without_agora_navigation() {
        let quiet = HostLifecycle {
            schema: "inspr.pharos.host-lifecycle.v1",
            version: 1,
            slot: HostLifecycleSlot::Quiet,
            label: "No pending changes".to_string(),
            level: "clear",
            invoke: HostLifecycleInvoke::HostSettings,
            run_id: None,
            update_restart_intent: None,
            detail: "No pending work is waiting.".to_string(),
            blocked_by: Vec::new(),
            primary_action: None,
        };
        let chip = host_lifecycle_chip_markup(&quiet, HostPreferencesState::Applied, true, None);
        assert!(chip.contains("data-host-lifecycle-chip"));
        assert!(chip.contains("<button"));
        assert!(!chip.contains("/agora"));
        assert!(chip.contains("No pending changes"));

        let drift = HostLifecycle {
            schema: "inspr.pharos.host-lifecycle.v1",
            version: 1,
            slot: HostLifecycleSlot::PrefsDrift,
            label: "Change requested".to_string(),
            level: "warning",
            invoke: HostLifecycleInvoke::HostSettings,
            run_id: None,
            update_restart_intent: None,
            detail: "Requested preferences have not yet been observed by the host.".to_string(),
            blocked_by: vec!["host_report".to_string()],
            primary_action: None,
        };
        let drift_chip =
            host_lifecycle_chip_markup(&drift, HostPreferencesState::RequestPending, true, None);
        assert!(drift_chip.contains("Change requested"));
        assert!(!drift_chip.contains("Continue:"));
        assert!(drift_chip.contains("data-lifecycle-blocked-by=\"host_report\""));

        let inert = host_lifecycle_chip_markup(&quiet, HostPreferencesState::Applied, false, None);
        assert!(inert.contains("disabled"));
        assert!(inert.contains("aria-disabled=\"true\""));
        assert!(inert.contains("tabindex=\"-1\""));
        assert!(!inert.contains(" hidden"));
    }

    #[test]
    fn requested_workflow_passes_the_query_job_id_without_host_action_fallback() {
        let opener = FOOT
            .split("function openRequestedWorkflow()")
            .nth(1)
            .and_then(|rest| rest.split("function parseBeats").next())
            .expect("openRequestedWorkflow");
        assert!(opener.contains(
            "openHostActionDialog('workflow',root,root.querySelector('[data-host-actions-trigger]'),workflowId)"
        ));
        assert!(!opener.contains("host_action"));
        assert!(!opener.contains("storedMatches"));
    }

    #[test]
    fn host_quick_drawer_is_a_local_draft_with_an_explicit_workspace_exit() {
        let drawer = host_quick_drawer(&PublicBasePath::ROOT, true);
        assert!(drawer.contains(r#"role="dialog" aria-modal="true""#));
        let reasons_at = drawer
            .find("data-host-drawer-reasons")
            .expect("observations list");
        let history_at = drawer
            .find("data-host-drawer-history")
            .expect("heartbeat history");
        let workspace_at = drawer.find("Open full host page").expect("host page link");
        assert!(reasons_at < history_at, "observations lead the heartbeat");
        assert!(
            history_at < workspace_at,
            "heartbeat leads the host page link"
        );
        assert!(drawer.matches("data-host-drawer-history").count() == 1);
        assert!(drawer.contains("data-host-drawer-workspace"));
        assert!(drawer.contains("Prepare a local draft"));
        assert!(drawer.contains("Closing or discarding removes the draft completely"));
        assert!(drawer.contains("Review settings"));
        assert!(drawer.contains("it does not send or apply changes"));
        assert!(drawer.contains("data-host-grace"));
        assert!(drawer.contains("Use fleet default"));
        assert!(drawer.contains("inherit the fleet grace"));
        assert!(!drawer.contains("send null"));
        assert!(drawer.contains("Open full host page"));
        assert_eq!(drawer.matches("data-restore-instant-label").count(), 1);
        assert!(!drawer.contains("awaiting-policy"));
        assert!(!drawer.contains("data-grace-reset disabled"));
        assert!(
            FOOT.contains("paintDrawerAssurance"),
            "drawer must paint health from the card summary"
        );
        assert!(
            !FOOT.contains("[data-host-drawer-trigger] .nix"),
            "drawer mark must not copy the hidden preview icon"
        );

        let runtime = FOOT
            .split("function initHostDrawer()")
            .nth(1)
            .and_then(|rest| rest.split("let openHostActionsRoot").next())
            .expect("host drawer runtime");
        assert!(runtime.contains("closeHostDrawer()"));
        assert!(runtime.contains("reviewHostDrawerDraft()"));
        assert!(
            !runtime.contains("fetch("),
            "drawer drafts must not dispatch"
        );

        let viewer = host_quick_drawer(&PublicBasePath::ROOT, false);
        assert!(viewer.contains(r#"data-can-manage="false""#));
        assert!(viewer.contains("Fleet operator access is required"));
    }

    #[test]
    fn lifecycle_sheet_hides_every_workflow_only_section() {
        let sheet = FOOT
            .split("function openHostLifecycleSheet")
            .nth(1)
            .and_then(|rest| rest.split("function updateSettingsLinkSurfaces").next())
            .expect("openHostLifecycleSheet");
        assert!(sheet.contains("if(confirm)confirm.hidden=true"));
        assert!(sheet.contains("if(dispositionField)dispositionField.hidden=true"));
        assert!(sheet.contains("if(successorField)successorField.hidden=true"));
        assert!(sheet.contains("if(attendedConfirm)attendedConfirm.hidden=true"));
        assert!(sheet.contains("[data-host-remove-confirm]"));
        assert!(sheet.contains("[data-host-remove-disposition-field]"));
        assert!(sheet.contains("[data-host-remove-successor]"));
        assert!(sheet.contains("[data-host-attended-confirm]"));
    }

    #[test]
    fn preferences_summary_matches_safe_fleet_fact_format() {
        let prefs = HostPreferences {
            accent: Some("#48b8a8".to_string()),
            kind: HostKind::Workstation,
            alerts: pharos_core::HostAlertPreferences {
                suppress_backup: true,
                ..Default::default()
            },
        };
        assert_eq!(
            preferences_summary(&prefs),
            "accent #48b8a8 · workstation · mute backup"
        );
        assert_eq!(preferences_summary(&HostPreferences::default()), "defaults");
    }

    #[test]
    fn a_current_nixpkgs_raises_no_attention_and_keeps_the_lock_label() {
        let current = proven_current("nixos-26.05");
        assert!(freshness_attention_reason(&current, now_unix(), 30).is_none());
        assert!(!freshness_markup(&current, false, 1_700_000_000, 30).contains("EOL"));

        // A beacon that has not rolled yet may report old numeric fields, but
        // those cannot prove the active generation and must remain unverified.
        let legacy = NixFreshness {
            applicable: true,
            flake_lock_age_days: Some(3),
            commits_behind: Some(0),
            nixpkgs_age_days: None,
            nixpkgs_channel: None,
            secondary_nixpkgs: None,
            deployment_evidence: None,
            nixcfg_comparison: None,
            nixpkgs_comparison: None,
        };
        let markup = freshness_markup(&legacy, false, 1_700_000_000, 30);
        assert!(markup.contains("unverified"), "{markup}");
        assert!(!markup.contains("EOL"));
    }

    #[test]
    fn stale_side_nixpkgs_is_secondary_context_not_host_attention() {
        let mut current = proven_current("nixos-unstable");
        current.secondary_nixpkgs = Some(pharos_core::NixpkgsInputFreshness {
            input: "nixpkgs-stable".to_string(),
            age_days: 218,
            channel: Some("nixos-25.05".to_string()),
        });

        let markup = freshness_markup(&current, false, 1_700_000_000, 30);
        assert!(markup.contains("Other root nixpkgs"), "{markup}");
        assert!(markup.contains("nixpkgs-stable"), "{markup}");
        assert!(markup.contains("nixos-25.05"), "{markup}");
        assert!(markup.contains("218d"), "{markup}");
        assert!(
            !markup.contains("218d · EOL"),
            "a side input must not look like host patch posture: {markup}"
        );
        assert!(freshness_attention_reason(&current, now_unix(), 30).is_none());
        assert_eq!(
            ServiceObservation::nix_freshness_at(&current, Some((2026, 8))).state,
            ServiceObservationState::Healthy
        );
    }

    #[test]
    fn card_freshness_rail_contains_only_actionable_exceptions() {
        let now = 1_786_310_400;
        let current = proven_current("nixos-unstable");
        let mut healthy_backup = backup_ui_summary(&[], now);
        healthy_backup.state = "healthy";
        healthy_backup.level = "clear";
        healthy_backup.label = "Protected".to_string();

        let (quiet, quiet_visible) =
            card_freshness_fault_markup(&current, &healthy_backup, None, now, 30);
        assert!(!quiet_visible, "{quiet}");
        assert_eq!(quiet.matches(" hidden").count(), 6, "{quiet}");
        assert!(!quiet.contains("deployed-sha"), "{quiet}");
        assert!(!quiet.contains("nixcfg-sha"), "{quiet}");
        assert!(!quiet.contains("nixpkgs-sha"), "{quiet}");
        assert!(!quiet.contains(&"1".repeat(40)), "{quiet}");
        assert!(!quiet.contains(&"2".repeat(40)), "{quiet}");

        let mut drift = proven_current("nixos-25.05");
        drift.nixcfg_comparison = Some(NixcfgGitComparison {
            upstream_revision: "4".repeat(40),
            relation: GitRevisionRelation::Behind,
            commits_behind: Some(12),
        });
        drift.commits_behind = Some(12);
        drift.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "5".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        let failed_backup = BackupUiSummary {
            state: "failed",
            level: "critical",
            label: "Backup failed".to_string(),
            ..healthy_backup
        };
        let (faults, faults_visible) =
            card_freshness_fault_markup(&drift, &failed_backup, None, now, 30);
        assert!(faults_visible, "{faults}");
        assert!(faults.contains("nixos-25.05 end of life"), "{faults}");
        assert!(
            faults.contains("nixpkgs differs from nixos-25.05"),
            "{faults}"
        );
        assert!(faults.contains("12 commits behind"), "{faults}");
        assert!(faults.contains("Backup failed"), "{faults}");
        let backup_row = faults
            .split(r#"data-fresh-kind="backup-fault""#)
            .nth(1)
            .expect("backup row");
        assert!(
            backup_row
                .split('>')
                .next()
                .unwrap_or("")
                .contains("hidden"),
            "the protection fact already shows backup state: {backup_row}"
        );
        assert!(!faults.contains("+N"), "{faults}");
    }

    fn backup_observation(
        state: BackupPostureState,
        schedule: Option<&str>,
        last_success_at: Option<i64>,
        validation: Option<pharos_core::BackupValidationObservation>,
    ) -> BackupObservation {
        BackupObservation {
            id: "restic-main".to_string(),
            label: "Restic main".to_string(),
            engine: pharos_core::BackupEngine::Restic,
            state,
            configured: pharos_core::BackupConfiguredState::Enabled,
            summary: "backup evidence".to_string(),
            target_label: None,
            repository_id: None,
            schedule: schedule.map(str::to_string),
            next_run_at: None,
            last_attempt_at: last_success_at,
            last_attempt_state: None,
            last_success_at,
            snapshot_count: None,
            total_bytes: None,
            latest_snapshot_bytes: None,
            last_check_at: None,
            last_check_state: None,
            restore_validation: validation,
        }
    }

    fn restore_sample(
        state: pharos_core::BackupValidationState,
        checked_at: Option<i64>,
    ) -> pharos_core::BackupValidationObservation {
        pharos_core::BackupValidationObservation {
            level: pharos_core::BackupValidationLevel::RestoreSample,
            state,
            checked_at,
            evidence_label: Some("one file".to_string()),
            summary: None,
        }
    }

    fn health_for(
        protection: &FleetProtectionView,
        freshness: &NixFreshness,
        now: i64,
    ) -> HostHealthView {
        host_health_view(HostHealthQuery {
            live: Liveness::Live,
            preferences: &HostPreferences::default(),
            freshness,
            kernel: None,
            services: &[],
            protection,
            now,
            nixpkgs_threshold: 30,
        })
    }

    #[test]
    fn selective_restore_is_overdue_only_after_thirty_days() {
        let now = 2_000_000_000;
        let on_time = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - SELECTIVE_RESTORE_OVERDUE_AFTER_SECS),
            )),
        );
        let current = fleet_protection_view(std::slice::from_ref(&on_time), now);
        assert_eq!(current.run.tone, "good");
        assert_eq!(current.run.label, "Daily OK");
        assert_eq!(current.restore.state, "passed");
        assert!(!current.restore_overdue);

        let late = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - SELECTIVE_RESTORE_OVERDUE_AFTER_SECS - 1),
            )),
        );
        let overdue = fleet_protection_view(std::slice::from_ref(&late), now);
        assert_eq!(overdue.run.tone, "good");
        assert_eq!(overdue.restore.state, "overdue");
        assert_eq!(overdue.restore.tone, "amber");
        assert!(overdue.restore_overdue);
        let health = health_for(&overdue, &proven_current("nixos-unstable"), now);
        assert_eq!(health.tone, "amber");
        assert_eq!(health.label, "Needs attention");
        let markup = protection_markup(&overdue, "poseidon", &PublicBasePath::ROOT);
        assert!(markup.contains(r#"data-daily-backup-tone="good""#));
        assert!(markup.contains(r#"data-restore-overdue="true""#));
        assert!(markup.contains(r#"data-restore-state="overdue""#));
    }

    #[test]
    fn same_host_restore_from_another_job_does_not_make_daily_green() {
        let now = 2_000_000_000;
        let mut failed = backup_observation(
            BackupPostureState::Failed,
            Some("daily"),
            Some(now - 3 * 86_400),
            None,
        );
        failed.id = "job-a".to_string();
        failed.repository_id = Some("repo-a".to_string());
        let mut restored = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now - 10),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - 10),
            )),
        );
        restored.id = "job-b".to_string();
        restored.repository_id = Some("repo-b".to_string());
        let view = fleet_protection_view(&[failed, restored], now);
        assert_eq!(view.run.state, "failed");
        assert_eq!(view.run.tone, "bad");
        assert_ne!(view.run.label, "Daily OK");
        assert_eq!(view.restore.state, "passed");
        assert_eq!(view.restore.tone, "good");

        let only_failed = backup_observation(
            BackupPostureState::Failed,
            Some("daily"),
            Some(now - 3 * 86_400),
            None,
        );
        let alone = fleet_protection_view(std::slice::from_ref(&only_failed), now);
        assert_eq!(alone.restore.state, "unknown");
        assert_ne!(alone.restore.tone, "good");
    }

    fn attr_value<'a>(tag: &'a str, name: &str) -> &'a str {
        let key = format!("{name}=\"");
        let start = tag
            .find(&key)
            .unwrap_or_else(|| panic!("missing {name} in {tag}"));
        let rest = &tag[start + key.len()..];
        let end = rest.find('"').unwrap_or_else(|| panic!("unclosed {name}"));
        &rest[..end]
    }

    fn rendered_history_marks(html: &str) -> Vec<(i64, String, String, f64)> {
        let mut marks = Vec::new();
        let mut rest = html;
        while let Some(start) = rest.find("<span class=\"beat-mark\"") {
            let tag = &rest[start..];
            let end = tag
                .find("</span>")
                .unwrap_or_else(|| panic!("unclosed mark in {tag}"));
            let tag = &tag[..end];
            let stamp: i64 = attr_value(tag, "data-history-stamp")
                .parse()
                .expect("stamp");
            let key = attr_value(tag, "data-history-key");
            assert_eq!(key, format!("sample:{stamp}"));
            let level = attr_value(tag, "data-history-level").to_string();
            let label = attr_value(tag, "data-history-label").to_string();
            let style = attr_value(tag, "style");
            let x = style
                .split("--mark-x:")
                .nth(1)
                .and_then(|value| value.trim_end_matches('%').parse::<f64>().ok())
                .expect("mark x");
            assert!(tag.contains("after previous") || level == "first");
            marks.push((stamp, level, label, x));
            rest = &rest[start + end..];
        }
        marks
    }

    #[test]
    fn history_buckets_keep_the_worst_event_from_the_shared_fixture() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/fixtures/history-worst-bucket.json"
        ))
        .expect("history fixture");
        let empty = heartbeat_card(HeartbeatCard {
            last_seen: None,
            heartbeat_log: &[],
            interval_secs: Some(60),
            now: 1_000_000,
            is_self: false,
            window_control: false,
            list_caption: false,
            grace_secs: 15,
            grace_source: "default",
            late_after_secs: 75,
        });
        assert!(empty.contains("--now-x:100%"));
        assert!(empty.contains("--history-start-x:100.0%"));
        assert!(!empty.contains("class=\"beat-mark\""));

        for case in fixture["cases"].as_array().expect("cases") {
            let name = case["name"].as_str().unwrap_or("case");
            let samples = case["samples"]
                .as_array()
                .expect(name)
                .iter()
                .map(|stamp| stamp.as_i64().expect(name))
                .collect::<Vec<_>>();
            let (html, start_x) = heartbeat_marks_with_grace(
                &samples,
                case["interval"].as_i64().expect(name),
                case["windowSecs"].as_i64().expect(name),
                case["grace"].as_u64().expect(name),
                case["now"].as_i64().expect(name),
            );
            assert!((start_x - 100.0).abs() < f64::EPSILON, "{name}");
            let rendered = rendered_history_marks(&html);
            let expected = case["expect"]["marks"].as_array().expect(name);
            assert_eq!(rendered.len(), expected.len(), "{name}");
            for (got, want) in rendered.iter().zip(expected) {
                let stamp = want["stamp"].as_i64().expect(name);
                assert_eq!(got.0, stamp, "{name}");
                assert_eq!(got.1, want["level"].as_str().expect(name), "{name}");
                assert_eq!(got.2, want["label"].as_str().expect(name), "{name}");
                let x = want["x"].as_f64().expect(name);
                assert!(
                    (got.3 - x).abs() < 0.051,
                    "{name} stamp {stamp} x {} expected {x}",
                    got.3
                );
                assert!(html.contains(&format!("data-history-key=\"sample:{stamp}\"")));
            }
            for hidden in case["expect"]["hiddenStamps"].as_array().expect(name) {
                let stamp = hidden.as_i64().expect(name);
                assert!(
                    !html.contains(&format!("data-history-stamp=\"{stamp}\"")),
                    "{name} hid {stamp}"
                );
            }
            if name == "worst-in-bucket" {
                assert!(html.contains("offline gap recovered"));
                assert!(html.contains("after previous"));
            }
        }
    }

    #[test]
    fn observed_time_uses_utc_civil_date() {
        let (iso, visible) = utc_stamp(1_700_000_000).expect("civil date");
        assert_eq!(iso, "2023-11-14T22:13:20Z");
        assert_eq!(visible, "2023-11-14 22:13:20 UTC");
        assert!(utc_stamp(-1).is_none());
        assert!(utc_stamp(0).is_none());
    }

    #[test]
    fn unknown_backup_evidence_does_not_become_the_epoch() {
        let now = 1_700_000_000;
        let unknown = backup_observation(BackupPostureState::Unknown, None, None, None);
        let missing = protection_markup(
            &fleet_protection_view(std::slice::from_ref(&unknown), now),
            "qa-harbor",
            &PublicBasePath::ROOT,
        );
        assert!(
            missing.contains(r#"data-protection-evidence hidden"#),
            "{missing}"
        );
        assert!(!missing.contains("1970"));
        assert!(!missing.contains("data-daily-backup-date"));
        assert!(!missing.contains("data-restore-date"));
        assert!(missing.contains(r#"data-daily-backup-at="""#));

        let zero = backup_observation(BackupPostureState::Unknown, None, Some(0), None);
        let coerced = protection_markup(
            &fleet_protection_view(std::slice::from_ref(&zero), now),
            "qa-harbor",
            &PublicBasePath::ROOT,
        );
        assert!(!coerced.contains("1970"), "{coerced}");
        assert!(!coerced.contains("data-daily-backup-date"));
        assert!(coerced.contains(r#"data-daily-backup-at="""#));

        let known = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - 10 * 86_400),
            )),
        );
        let dated = protection_markup(
            &fleet_protection_view(std::slice::from_ref(&known), now),
            "qa-harbor",
            &PublicBasePath::ROOT,
        );
        assert!(
            dated.contains(r#"datetime="2023-11-14T22:13:20Z""#),
            "{dated}"
        );
        assert!(dated.contains("2023-11-14 22:13:20 UTC"));
        assert_eq!(dated.matches("data-daily-backup-date").count(), 1);
        assert!(dated.contains(r#"data-protection-evidence><summary>Exact times</summary>"#));
        assert!(dated.contains(
            r#"data-daily-backup-instant><span class="protection-instant-label" data-daily-backup-instant-label>Backup last success</span> <time datetime="2023-11-14T22:13:20Z" data-daily-backup-date>2023-11-14 22:13:20 UTC</time>"#
        ));
        assert!(dated.contains(
            r#"<span class="protection-instant-label" data-restore-instant-label>Selective restore last success</span> <time"#
        ));
        assert!(!dated.contains(r#"data-protection-evidence open"#));
        assert!(!dated.contains("data-due-instant"));
        assert!(!missing.contains("protection-instant"));
        assert!(!missing.contains("Backup last success"));
        assert!(!coerced.contains("protection-instant"));
        assert!(dated.contains("Daily OK"));
        assert!(dated.contains("Passed"));
        assert!(!dated.contains("1970"));
    }

    #[test]
    fn generic_all_clear_is_hidden_on_every_scan_surface() {
        assert!(scan_attention_hidden("all clear", false, false));
        assert!(scan_attention_hidden("silent heartbeat", true, false));
        assert!(scan_attention_hidden("nixpkgs differs", false, true));
        assert!(!scan_attention_hidden("silent heartbeat", false, false));
        assert!(!scan_attention_hidden("Backup failed", false, false));
    }

    #[test]
    fn partial_delivery_keeps_the_percent_and_names_incomplete_coverage() {
        let first = heartbeat_signal(&[1_000], None, 60, 1_000, "10m", 600);
        assert_eq!(first.text, "100%");
        assert_eq!(first.level, "good");
        assert_eq!(first.coverage, "partial");
        assert!(first.title.contains("Partial retention"));
        assert!(first.title.contains("1 of 1 expected reports"));
        let first_markup = availability_markup(&first);
        assert!(first_markup.contains(r#"data-signal-coverage="partial""#));
        assert!(first_markup.contains(">partial<"));
        assert!(first_markup.contains(">100%<"));

        let covered = heartbeat_signal(
            &[400, 460, 520, 580, 640, 700, 760, 820, 880, 940, 1_000],
            None,
            60,
            1_000,
            "10m",
            600,
        );
        assert_eq!(covered.text, "100%");
        assert_eq!(covered.coverage, "full");
        assert!(!covered.title.contains("Partial retention"));
        let covered_markup = signal_markup(&covered);
        assert!(covered_markup.contains(r#"data-signal-coverage="full" hidden"#));
        assert!(!covered_markup.contains(">partial<"));

        let empty = heartbeat_signal(&[0, -1], Some(0), 60, 1_000, "10m", 600);
        assert_eq!(empty.text, "—");
        assert_eq!(empty.coverage, "none");
        assert!(availability_markup(&empty).contains(r#"data-signal-coverage="none" hidden"#));
    }

    #[test]
    fn stale_daily_backup_is_not_green_and_restore_does_not_cancel_it() {
        let now = 2_000_000_000;
        let fresh = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now - BACKUP_RUN_STALE_AFTER_SECS),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - 10 * 86_400),
            )),
        );
        let current = fleet_protection_view(std::slice::from_ref(&fresh), now);
        assert_eq!(current.run.label, "Daily OK");
        assert_eq!(current.run.tone, "good");
        assert_eq!(current.restore.tone, "good");
        assert!(!current.restore_overdue);

        let aged = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now - 3 * 86_400),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - 10 * 86_400),
            )),
        );
        let view = fleet_protection_view(std::slice::from_ref(&aged), now);
        assert_eq!(view.run.state, "stale");
        assert_eq!(view.run.tone, "amber");
        assert_ne!(view.run.label, "Daily OK");
        assert!(!view.daily_ok);
        assert_eq!(view.restore.state, "passed");
        assert_eq!(view.restore.tone, "good");
        assert!(!view.restore_overdue);
        let health = health_for(&view, &proven_current("nixos-unstable"), now);
        assert_eq!(health.tone, "amber");
        assert_eq!(health.summary, "Backup Stale");
        assert_ne!(health.summary, "No action needed");
        assert!(health.reasons.iter().all(|reason| reason.tone != "good"));
        let health_html = health_markup(&health);
        assert!(health_html.contains("data-health-disclosure"));
        assert!(health_html.contains("data-health-count"));
        assert!(!health_html.contains("Daily OK"));
        assert!(!health_html.contains("data-daily-backup"));
        let protection = protection_markup(&view, "qa-harbor", &PublicBasePath::ROOT);
        assert_eq!(protection.matches("data-daily-backup-label").count(), 1);
        assert_eq!(protection.matches("data-restore-label").count(), 1);
        assert!(protection.contains("data-daily-backup-date"));
        assert!(protection.contains("datetime=\""));
        assert!(protection.contains(" UTC</time>"));
        assert!(!protection.contains("Daily OK"));
        assert!(protection.contains("data-protection-more"));
    }

    #[test]
    fn scan_card_keeps_detail_off_the_expanding_surface() {
        let now = 2_000_000_000;
        let aged = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now - 3 * 86_400),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now - 10 * 86_400),
            )),
        );
        let view = fleet_protection_view(std::slice::from_ref(&aged), now);
        let card = protection_card_markup(&view, "qa-harbor", &PublicBasePath::ROOT);
        assert!(card.contains("Daily backup"));
        assert!(card.contains("Monthly restore test"));
        assert!(card.contains(r#"class="scan-store" data-protection-evidence hidden"#));
        assert!(!card.contains("<summary>Exact times</summary>"));
        assert!(!card.contains("<summary>Repository check</summary>"));
        assert!(card.contains("data-daily-backup-date"));
        assert!(card.contains("data-daily-backup-note"));
        assert!(!card.contains(r#"class="fact-age""#));
        let health = health_for(&view, &proven_current("nixos-unstable"), now);
        let attention = card_attention_block(&health, "", "", "", "");
        assert!(!attention.contains("data-health-disclosure"));
        assert!(attention.contains("data-health-summary"));
        assert!(attention.contains(r#"data-health-reasons hidden"#));
        assert!(attention.contains("data-health-reason"));
        let beat = heartbeat_card(HeartbeatCard {
            last_seen: Some(now - 30),
            heartbeat_log: &[now - 90, now - 30],
            interval_secs: Some(60),
            now,
            is_self: false,
            window_control: true,
            list_caption: false,
            grace_secs: 15,
            grace_source: "fleet",
            late_after_secs: 75,
        });
        assert!(beat.contains("beat-cadence"));
        assert!(beat.contains("data-history-zones"));
        assert!(beat.contains("expected 60s"));
        assert!(beat.contains("late 75s"));
        assert!(beat.contains("60s plus 15s grace"));
        assert!(beat.contains("--interval-x:51.20%"));
        assert!(beat.contains("--expect-x:64%"));
        assert!(!beat.contains(">expected<"));
        assert!(!beat.contains(">late<"));
        assert!(!beat.contains(">History<"));
        assert!(beat.contains("beat-history"));
        assert!(beat.contains("data-beat-live=\"true\""));
        assert!(!beat.contains("arrival-track"));
        assert!(beat.contains(r#"data-history-axis="time""#));
        assert!(beat.contains("--now-x:100%"));
        assert!(card.contains(r#"data-restore-note"#));
        assert!(!card.contains("backup-chip"));
    }

    #[test]
    fn protection_pair_tone_follows_posture() {
        let now = 1_700_000_120;
        let cases = [
            (
                BackupPostureState::Healthy,
                Some("daily"),
                Some(now - 120),
                "good",
                "Daily OK",
            ),
            (
                BackupPostureState::Unknown,
                None,
                None,
                "neutral",
                "Unknown",
            ),
            (
                BackupPostureState::Stale,
                Some("daily"),
                Some(now - 3 * 86_400),
                "amber",
                "Stale",
            ),
            (
                BackupPostureState::Failed,
                Some("daily"),
                Some(now - 120),
                "bad",
                "Failed",
            ),
        ];
        let mut tones = Vec::new();
        for (state, schedule, at, tone, label) in cases {
            let observation = backup_observation(state, schedule, at, None);
            let view = fleet_protection_view(std::slice::from_ref(&observation), now);
            let card = protection_card_markup(&view, "athena", &PublicBasePath::ROOT);
            assert!(
                card.contains(&format!(r#"class="protection-fact {tone}""#)),
                "{state:?} card missing tone {tone}"
            );
            assert!(
                card.contains(&format!(r#"data-daily-backup-label>{label}</strong>"#)),
                "{state:?} card missing label {label}"
            );
            assert!(!card.contains("backup-chip"));
            tones.push(tone);
        }
        tones.sort_unstable();
        tones.dedup();
        assert_eq!(tones, ["amber", "bad", "good", "neutral"]);
    }

    #[test]
    fn unverified_chip_repeats_only_the_same_health_summary() {
        let chip = r#"<div class="fresh-row fresh-row-compact" data-fresh-kind="freshness-unverified"><strong class="na" data-fresh-value>unverified</strong></div>"#;
        assert!(mark_scan_duplicate_chip(chip, "freshness unverified").contains("scan-duplicate"));
        assert!(!mark_scan_duplicate_chip(chip, "Backup Failed").contains("scan-duplicate"));
    }

    #[test]
    fn card_backup_fact_names_its_state_and_configuration_stays_off_freshness() {
        let now = 2_000_000_000;
        let failed = backup_observation(BackupPostureState::Failed, None, None, None);
        let view = fleet_protection_view(std::slice::from_ref(&failed), now);
        let card = protection_card_markup(&view, "beacon", &PublicBasePath::ROOT);
        assert!(card.contains(r#"href="/backups?host=beacon""#));
        assert!(card.contains(r#"aria-label="Backup failed for beacon""#));
        assert!(card.contains(r#"class="protection-fact bad""#));
        assert!(!card.contains("backup-chip"));
        assert_eq!(
            configuration_face_label(&proven_current("nixos-unstable")),
            "Configuration exact"
        );
        let mut differs = proven_current("nixos-unstable");
        differs.nixpkgs_comparison.as_mut().unwrap().relation = NixpkgsRevisionRelation::Different;
        assert_eq!(configuration_face_label(&differs), "Configuration differs");
        let mut missing = proven_current("nixos-unstable");
        missing.applicable = false;
        assert_eq!(
            configuration_face_label(&missing),
            "Configuration not observed"
        );
        assert!(!configuration_face_label(&missing).contains("nix: n/a"));
        assert!(!configuration_face_label(&missing).contains("freshness"));
        let failed_list = list_protection_markup(&view, "beacon", &PublicBasePath::ROOT, now);
        assert!(failed_list.contains(r#"href="/backups?host=beacon""#));
        assert!(failed_list.contains(r#"aria-label="Backup failed for beacon""#));
        assert!(failed_list.contains(r#"<span class="row-fact-k">Daily:</span>"#));
        assert!(failed_list.contains(r#"data-daily-backup-label>Failed</strong>"#));
        assert!(failed_list.contains(r#"<span class="row-fact-k">Restore:</span>"#));
        assert!(!failed_list.contains("backup-chip"));
        let passed = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now - 7_200),
            Some(pharos_core::BackupValidationObservation {
                level: pharos_core::BackupValidationLevel::RestoreSample,
                state: pharos_core::BackupValidationState::Passed,
                checked_at: Some(now - 6 * 86_400),
                evidence_label: Some("one file".to_string()),
                summary: None,
            }),
        );
        let passed_view = fleet_protection_view(std::slice::from_ref(&passed), now);
        let passed_list = list_protection_markup(&passed_view, "atlas", &PublicBasePath::ROOT, now);
        assert!(passed_list.contains(r#"data-daily-backup-label>OK · 2h</strong>"#));
        assert!(passed_list.contains(r#"data-restore-label>Passed · 6d</strong>"#));
        assert!(!passed_list.contains("1 file"));
        let mut one_file = passed_view.clone();
        one_file.restore_file_count = Some(1);
        let one_list = list_protection_markup(&one_file, "atlas", &PublicBasePath::ROOT, now);
        assert!(one_list.contains(r#"data-restore-label>1 file · 6d</strong>"#));
        let mut several = passed_view.clone();
        several.restore_file_count = Some(4);
        let several_list = list_protection_markup(&several, "atlas", &PublicBasePath::ROOT, now);
        assert!(several_list.contains(r#"data-restore-label>4 files · 6d</strong>"#));
        assert!(passed_list.contains(r#"aria-label="Backup healthy for atlas""#));
        let exact = r#"<div class="fresh-row fresh-row-compact" data-fresh-kind="nixpkgs-drift"><strong class="warn" data-fresh-value>nixpkgs differs from nixos-unstable</strong></div>"#;
        assert!(
            mark_scan_duplicate_chip(exact, "nixpkgs differs from nixos-unstable")
                .contains("scan-duplicate")
        );
    }

    #[test]
    fn disabled_backup_is_not_an_exemption() {
        let now = 2_000_000_000;
        let mut observation =
            backup_observation(BackupPostureState::Healthy, Some("daily"), Some(now), None);
        observation.configured = pharos_core::BackupConfiguredState::Disabled;
        let view = fleet_protection_view(std::slice::from_ref(&observation), now);
        assert_eq!(view.run.state, "disabled");
        assert_eq!(view.run.tone, "amber");
        assert_eq!(view.run.label, "Disabled");
        assert_ne!(view.restore.state, "not-required");
        let health = health_for(&view, &proven_current("nixos-unstable"), now);
        assert_ne!(health.tone, "good");
        assert_eq!(health.summary, "Backup Disabled");
        assert_ne!(health.summary, "No action needed");
    }

    fn daily_job(
        id: &str,
        state: BackupPostureState,
        last_success_at: Option<i64>,
        validation: Option<pharos_core::BackupValidationObservation>,
    ) -> BackupObservation {
        let mut observation = backup_observation(state, Some("daily"), last_success_at, validation);
        observation.id = id.to_string();
        observation
    }

    fn assert_run_both_orders(
        left: &BackupObservation,
        right: &BackupObservation,
        now: i64,
        state: &str,
        tone: &str,
        at: Option<i64>,
        case: &str,
    ) {
        for (order, jobs) in [
            ("forward", [left.clone(), right.clone()]),
            ("reverse", [right.clone(), left.clone()]),
        ] {
            let view = fleet_protection_view(&jobs, now);
            assert_eq!(view.run.state, state, "{case} {order}");
            assert_eq!(view.run.tone, tone, "{case} {order}");
            assert_eq!(view.run.at, at, "{case} {order}");
            assert_ne!(view.run.tone, "good", "{case} {order}");
            assert!(!view.daily_ok, "{case} {order}");
        }
    }

    #[test]
    fn protection_review_daily_projects_before_rank() {
        let now = 1_700_000_000;
        let fresh_at = now - 60;
        let stale_at = now - BACKUP_RUN_STALE_AFTER_SECS - 1;
        let fresh = daily_job("fresh", BackupPostureState::Healthy, Some(fresh_at), None);
        let stale = daily_job("stale", BackupPostureState::Healthy, Some(stale_at), None);
        assert_run_both_orders(
            &fresh,
            &stale,
            now,
            "stale",
            "amber",
            Some(stale_at),
            "fresh+stale",
        );
        let forward = fleet_protection_view(&[fresh.clone(), stale.clone()], now);
        assert_eq!(forward.run.label, "Stale");
        assert_ne!(forward.run.label, "Daily OK");

        let missing_time = daily_job("missing-time", BackupPostureState::Healthy, None, None);
        assert_run_both_orders(
            &fresh,
            &missing_time,
            now,
            "unknown",
            "neutral",
            None,
            "healthy+missing-time",
        );
        assert_eq!(
            fleet_protection_view(&[missing_time.clone(), fresh.clone()], now)
                .run
                .label,
            "Success time unknown"
        );

        let mut disabled = daily_job(
            "disabled",
            BackupPostureState::Healthy,
            Some(fresh_at),
            None,
        );
        disabled.configured = pharos_core::BackupConfiguredState::Disabled;
        assert_run_both_orders(
            &fresh,
            &disabled,
            now,
            "disabled",
            "amber",
            Some(fresh_at),
            "healthy+disabled",
        );
        assert_eq!(
            fleet_protection_view(&[disabled.clone(), fresh.clone()], now)
                .run
                .label,
            "Disabled"
        );

        let future = daily_job(
            "future",
            BackupPostureState::Healthy,
            Some(now + 86_400),
            None,
        );
        assert_run_both_orders(
            &fresh,
            &future,
            now,
            "stale",
            "amber",
            Some(now + 86_400),
            "future-success",
        );

        let failed = daily_job("failed", BackupPostureState::Failed, Some(now - 400), None);
        let missing = daily_job("missing", BackupPostureState::Missing, Some(now - 50), None);
        assert_run_both_orders(
            &failed,
            &missing,
            now,
            "failed",
            "bad",
            Some(now - 400),
            "failed+missing",
        );
        let warning = daily_job("warning", BackupPostureState::Warning, Some(fresh_at), None);
        assert_run_both_orders(
            &missing,
            &stale,
            now,
            "missing",
            "bad",
            Some(now - 50),
            "missing+stale",
        );
        assert_run_both_orders(
            &stale,
            &warning,
            now,
            "stale",
            "amber",
            Some(stale_at),
            "stale+warning",
        );
        let unknown = daily_job("unknown", BackupPostureState::Unknown, None, None);
        assert_run_both_orders(
            &warning,
            &unknown,
            now,
            "warning",
            "amber",
            Some(fresh_at),
            "warning+unknown",
        );
        assert_run_both_orders(
            &disabled,
            &unknown,
            now,
            "disabled",
            "amber",
            Some(fresh_at),
            "disabled+unknown",
        );
        let not_configured = daily_job(
            "not-configured",
            BackupPostureState::NotConfigured,
            None,
            None,
        );
        assert_run_both_orders(
            &unknown,
            &not_configured,
            now,
            "unknown",
            "neutral",
            None,
            "unknown+not-configured",
        );
        assert_run_both_orders(
            &not_configured,
            &fresh,
            now,
            "not-configured",
            "neutral",
            None,
            "not-configured+ok",
        );

        let exactly = fleet_protection_view(
            std::slice::from_ref(&daily_job(
                "boundary",
                BackupPostureState::Healthy,
                Some(now - BACKUP_RUN_STALE_AFTER_SECS),
                None,
            )),
            now,
        );
        assert_eq!(exactly.run.state, "ok");
        assert_eq!(exactly.run.tone, "good");
        assert_eq!(exactly.run.label, "Daily OK");
    }

    #[allow(clippy::too_many_arguments)]
    fn assert_restore_both_orders(
        left: &BackupObservation,
        right: &BackupObservation,
        now: i64,
        state: &str,
        tone: &str,
        label: &str,
        at: Option<i64>,
        case: &str,
    ) {
        for (order, jobs) in [
            ("forward", [left.clone(), right.clone()]),
            ("reverse", [right.clone(), left.clone()]),
        ] {
            let view = fleet_protection_view(&jobs, now);
            assert_eq!(view.restore.state, state, "{case} {order}");
            assert_eq!(view.restore.tone, tone, "{case} {order}");
            assert_eq!(view.restore.label, label, "{case} {order}");
            assert_eq!(view.restore.at, at, "{case} {order}");
        }
    }

    #[test]
    fn protection_review_restore_uses_eligible_latest_evidence() {
        let now = 1_700_000_000;
        let fresh_at = now - 60;
        let passed = |id: &str, at: Option<i64>| {
            daily_job(
                id,
                BackupPostureState::Healthy,
                Some(fresh_at),
                Some(restore_sample(
                    pharos_core::BackupValidationState::Passed,
                    at,
                )),
            )
        };
        let sample = |id: &str, state: pharos_core::BackupValidationState, at: Option<i64>| {
            daily_job(
                id,
                BackupPostureState::Healthy,
                Some(fresh_at),
                Some(restore_sample(state, at)),
            )
        };

        for (case, at) in [
            ("future-day", Some(now + 86_400)),
            ("beyond-skew", Some(now + BACKUP_CLOCK_SKEW_SECS + 1)),
            ("zero", Some(0)),
            ("missing", None),
            ("negative", Some(-1)),
            ("out-of-range", Some(i64::MAX)),
        ] {
            let view = fleet_protection_view(std::slice::from_ref(&passed(case, at)), now);
            assert_eq!(view.restore.state, "unknown", "{case}");
            assert_eq!(view.restore.tone, "neutral", "{case}");
            assert_eq!(view.restore.label, "Not observed", "{case}");
            assert_eq!(view.restore.at, None, "{case}");
            assert_ne!(view.restore.state, "passed", "{case}");
        }

        let skew_at = now + BACKUP_CLOCK_SKEW_SECS;
        let within_skew =
            fleet_protection_view(std::slice::from_ref(&passed("skew", Some(skew_at))), now);
        assert_eq!(within_skew.restore.state, "passed");
        assert_eq!(within_skew.restore.tone, "good");
        assert_eq!(within_skew.restore.at, Some(skew_at));

        let valid_at = now - 10;
        let valid = passed("valid", Some(valid_at));
        let future = passed("future", Some(now + 86_400));
        assert_restore_both_orders(
            &valid,
            &future,
            now,
            "passed",
            "good",
            "Passed",
            Some(valid_at),
            "valid+future-passed",
        );
        let future_failed = sample(
            "future-failed",
            pharos_core::BackupValidationState::Failed,
            Some(now + 86_400),
        );
        assert_restore_both_orders(
            &valid,
            &future_failed,
            now,
            "passed",
            "good",
            "Passed",
            Some(valid_at),
            "valid+future-failed",
        );
        let zero = passed("zero-pass", Some(0));
        assert_restore_both_orders(
            &valid,
            &zero,
            now,
            "passed",
            "good",
            "Passed",
            Some(valid_at),
            "valid+zero",
        );

        let success_at = now - 1_000;
        let newer_at = now - 100;
        let success = passed("success", Some(success_at));
        for (case, state) in [
            ("newer-stale", pharos_core::BackupValidationState::Stale),
            ("newer-unknown", pharos_core::BackupValidationState::Unknown),
        ] {
            let newer = sample(case, state, Some(newer_at));
            assert_restore_both_orders(
                &success,
                &newer,
                now,
                "unknown",
                "neutral",
                "Unknown",
                Some(success_at),
                case,
            );
            let view = fleet_protection_view(&[success.clone(), newer], now);
            assert!(!view.restore_overdue, "{case}");
            assert_ne!(view.restore.state, "passed", "{case}");
        }

        let failed = sample(
            "failed",
            pharos_core::BackupValidationState::Failed,
            Some(newer_at),
        );
        assert_restore_both_orders(
            &success,
            &failed,
            now,
            "failed",
            "bad",
            "Failed",
            Some(success_at),
            "newer-failed",
        );

        let tied_at = now - 100;
        let tied_pass = passed("tied-pass", Some(tied_at));
        for (case, state) in [
            ("tied-failed", pharos_core::BackupValidationState::Failed),
            ("tied-stale", pharos_core::BackupValidationState::Stale),
            ("tied-unknown", pharos_core::BackupValidationState::Unknown),
        ] {
            let adverse = sample(case, state, Some(tied_at));
            assert_restore_both_orders(
                &tied_pass,
                &adverse,
                now,
                "unknown",
                "neutral",
                "Unknown",
                Some(tied_at),
                case,
            );
        }

        let exact_at = now - SELECTIVE_RESTORE_OVERDUE_AFTER_SECS;
        let exact = fleet_protection_view(
            std::slice::from_ref(&passed("exact-30", Some(exact_at))),
            now,
        );
        assert_eq!(exact.restore.state, "passed");
        assert_eq!(exact.restore.tone, "good");
        assert_eq!(exact.restore.at, Some(exact_at));
        assert!(!exact.restore_overdue);

        let late_at = exact_at - 1;
        let late =
            fleet_protection_view(std::slice::from_ref(&passed("late-30", Some(late_at))), now);
        assert_eq!(late.restore.state, "overdue");
        assert_eq!(late.restore.tone, "amber");
        assert_eq!(late.restore.label, "Overdue");
        assert_eq!(late.restore.at, Some(late_at));
        assert!(late.restore_overdue);
        let newer_than_overdue = sample(
            "newer-than-overdue",
            pharos_core::BackupValidationState::Stale,
            Some(now - 100),
        );
        assert_restore_both_orders(
            &passed("old", Some(late_at)),
            &newer_than_overdue,
            now,
            "overdue",
            "amber",
            "Overdue",
            Some(late_at),
            "overdue+newer-stale",
        );

        let repo_at = now - 5;
        let repo = daily_job(
            "repo",
            BackupPostureState::Healthy,
            Some(fresh_at),
            Some(pharos_core::BackupValidationObservation {
                level: pharos_core::BackupValidationLevel::RepositoryCheck,
                state: pharos_core::BackupValidationState::Passed,
                checked_at: Some(repo_at),
                evidence_label: Some("repo check".to_string()),
                summary: None,
            }),
        );
        let repo_view = fleet_protection_view(&[repo.clone(), valid.clone()], now);
        assert_eq!(repo_view.restore.state, "passed");
        assert_eq!(repo_view.restore.tone, "good");
        assert_eq!(repo_view.restore.at, Some(valid_at));
        assert_eq!(
            repo_view.check.as_ref().and_then(|fact| fact.at),
            Some(repo_at)
        );
        let repo_only = fleet_protection_view(std::slice::from_ref(&repo), now);
        assert_eq!(repo_only.restore.state, "unknown");
        assert_eq!(repo_only.restore.label, "Not observed");
        assert_ne!(repo_only.restore.tone, "good");
    }

    #[test]
    fn suppress_down_does_not_paint_a_down_server_healthy() {
        let now = 2_000_000_000;
        let mut preferences = HostPreferences::default();
        preferences.alerts.suppress_down = true;
        let protection = fleet_protection_view(&[], now);
        let health = host_health_view(HostHealthQuery {
            live: Liveness::Down,
            preferences: &preferences,
            freshness: &NixFreshness::default(),
            kernel: None,
            services: &[],
            protection: &protection,
            now,
            nixpkgs_threshold: 30,
        });
        assert_eq!(health.tone, "bad");
        assert!(health
            .reasons
            .iter()
            .any(|reason| reason.label == "Not reporting"));
        assert!(!health
            .reasons
            .iter()
            .any(|reason| reason.label == "Offline as expected"));
        let attention = attention_reason(
            Liveness::Down,
            &NixFreshness::default(),
            None,
            &[],
            &preferences,
            now,
            30,
        );
        assert_eq!(attention.label, "silent heartbeat");
        assert_eq!(attention.level, "down");

        preferences.kind = HostKind::Workstation;
        let workstation = attention_reason(
            Liveness::Down,
            &NixFreshness::default(),
            None,
            &[],
            &preferences,
            now,
            30,
        );
        assert_eq!(workstation.label, "offline as expected");
    }

    #[test]
    fn repository_check_and_non_sample_levels_do_not_paint_restore_green() {
        let now = 2_000_000_000;
        let check_only = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(pharos_core::BackupValidationObservation {
                level: pharos_core::BackupValidationLevel::RepositoryCheck,
                state: pharos_core::BackupValidationState::Passed,
                checked_at: Some(now),
                evidence_label: Some("repo check".to_string()),
                summary: None,
            }),
        );
        let checked = fleet_protection_view(std::slice::from_ref(&check_only), now);
        assert_eq!(checked.restore.tone, "neutral");
        assert!(!checked.restore_overdue);
        assert!(checked.missing_restore_producer);
        assert_ne!(checked.check.as_ref().map(|fact| fact.tone), Some("bad"));

        for level in [
            pharos_core::BackupValidationLevel::DiffHash,
            pharos_core::BackupValidationLevel::OperatorTest,
        ] {
            let observation = backup_observation(
                BackupPostureState::Healthy,
                Some("daily"),
                Some(now),
                Some(pharos_core::BackupValidationObservation {
                    level,
                    state: pharos_core::BackupValidationState::Passed,
                    checked_at: Some(now),
                    evidence_label: None,
                    summary: None,
                }),
            );
            let view = fleet_protection_view(std::slice::from_ref(&observation), now);
            assert_ne!(view.restore.tone, "good");
            assert!(view.missing_restore_producer);
        }

        let stale_without_pass = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(restore_sample(
                pharos_core::BackupValidationState::Stale,
                Some(now),
            )),
        );
        let stale = fleet_protection_view(std::slice::from_ref(&stale_without_pass), now);
        assert_eq!(stale.restore.tone, "neutral");
        assert!(!stale.restore_overdue);

        let empty = fleet_protection_view(&[], now);
        assert_ne!(empty.run.tone, "good");
        assert_ne!(empty.restore.tone, "good");
    }

    #[test]
    fn fresh_nixpkgs_mismatch_does_not_make_health_amber() {
        let now = 1_700_000_000;
        let mut freshness = proven_current("nixos-unstable");
        freshness.nixpkgs_comparison = Some(NixpkgsGitComparison {
            upstream_revision: "9".repeat(40),
            relation: NixpkgsRevisionRelation::Different,
        });
        if let Some(evidence) = freshness.deployment_evidence.as_mut() {
            evidence.nixpkgs_last_modified = now;
        }
        let observation = backup_observation(
            BackupPostureState::Healthy,
            Some("daily"),
            Some(now),
            Some(restore_sample(
                pharos_core::BackupValidationState::Passed,
                Some(now),
            )),
        );
        let protection = fleet_protection_view(std::slice::from_ref(&observation), now);
        let health = health_for(&protection, &freshness, now);
        assert!(freshness_attention_reason(&freshness, now, 30).is_none());
        assert_eq!(health.tone, "good");
        assert_eq!(health.label, "Healthy");
    }

    #[test]
    fn extra_head_inserts_before_close_without_the_old_style_anchor() {
        assert!(HEAD.contains("<!--pharos-extra-head-->"));
        assert!(!HEAD.contains("</style></head>"));
        let html = head_with_extra(&PublicBasePath::ROOT, "<style id=\"agora-css\"></style>");
        let extra_at = html
            .find("<style id=\"agora-css\"></style>")
            .expect("inserted extra");
        let head_at = html.rfind("</head>").expect("head close");
        assert!(extra_at < head_at);
        assert_eq!(html.matches("<style id=\"agora-css\"></style>").count(), 1);
        assert!(!html.contains("<!--pharos-extra-head-->"));
    }

    #[test]
    fn fleet_grace_control_uses_the_saved_value() {
        let markup = heartbeat_grace_settings_markup(40, true);
        assert!(markup.contains(r#"name="heartbeat_grace_secs""#));
        assert!(markup.contains(r#"value="40""#));
        assert!(markup.contains(r#"data-grace-saved="40""#));
        assert!(!markup.contains("awaiting-policy"));
        assert!(!markup.contains("disabled"));
        let viewer = heartbeat_grace_settings_markup(15, false);
        assert!(viewer.contains("disabled"));
        assert!(viewer.contains(r#"value="15""#));
    }
}

pub(super) fn render_no_access_page(
    title: &str,
    subtitle: &str,
    shell: ShellContext<'_>,
    active: &str,
) -> String {
    let scope = match active {
        "settings" => "settings",
        "platform-settings" => "provider",
        "services" => "managed-service",
        _ => "fleet",
    };
    let access_path = viewer_access_path(shell.public_base_path, scope);
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="ops-main"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>{title}</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">{subtitle}</p></div><div class="asof">as of {as_of}</div></div>{access_path}<section class="ops-empty"><h2>No access yet</h2><p>Your login works, but this Pharos account has not been granted any hosts or settings yet.</p></section></main></div></body></html>"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            active
        ),
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        as_of = clock_label(now_unix()),
    )
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct AccessRequestQuery {
    #[serde(default)]
    scope: Option<String>,
}

fn access_scope(value: Option<&str>) -> (&'static str, &'static str) {
    match value {
        Some("settings") => ("Host settings", "review and change host settings"),
        Some("provider") => ("Provider connections", "connect or change a provider"),
        Some("managed-service") => (
            "Managed services",
            "create, replace, or remove a managed secret",
        ),
        _ => ("Fleet operations", "run guarded fleet actions"),
    }
}

/// One consistent, non-mutating access path for every guarded product surface.
pub(super) fn viewer_access_path(base: &PublicBasePath, scope: &str) -> String {
    let (surface, task) = access_scope(Some(scope));
    format!(
        r#"<aside class="access-path" data-access-path data-scope="{scope}"><span class="access-path-icon" aria-hidden="true">{shield}</span><span class="access-path-copy"><strong>Fleet manager access required</strong><span>You can keep viewing {surface}. A Pharos administrator owns access for people who need to {task}.</span></span><a class="access-path-action" href="{href}">Request access</a></aside>"#,
        scope = html_escape(scope),
        surface = html_escape(surface),
        task = html_escape(task),
        shield = icons::SHIELD_CHECK,
        href = app_href(base, &format!("/access/request?scope={scope}")),
    )
}

pub(super) async fn access_request_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<AccessRequestQuery>,
) -> Response {
    if let Some(target) = state.access_request.target.as_deref() {
        return Redirect::temporary(target).into_response();
    }
    let user_label = sidebar_user_label(&state.auth, &headers);
    let (surface, task) = access_scope(query.scope.as_deref());
    let request_text =
        format!("Please ask a Pharos administrator for the Fleet manager role so I can {task}.");
    let head = document_head(&state.public_base_path);
    no_store_html(&state,format!(
        r#"{head}{sidebar}<main class="ops-main access-request-page"><div class="top"><div><div class="brand"><h1>Request access</h1></div><p class="fleet">{surface}</p></div></div><section class="ops-empty"><h2>Send this to your Pharos administrator</h2><p>The required role is <strong>Fleet manager</strong>. The responsible access owner is your <strong>Pharos administrator</strong>.</p><div class="access-request-copy"><code data-access-request-text>{request_text}</code><button class="access-path-action" type="button" data-copy-access-request>Copy access request</button></div><p class="access-request-status" role="status" aria-live="polite" data-access-request-status>Copy the request, send it through your normal help channel, then return here after access is granted.</p></section></main><script>document.querySelector('[data-copy-access-request]')?.addEventListener('click',async event=>{{const text=document.querySelector('[data-access-request-text]')?.textContent||'';const status=document.querySelector('[data-access-request-status]');try{{await navigator.clipboard.writeText(text);event.currentTarget.textContent='Copied';if(status)status.textContent='Access request copied. Send it to your Pharos administrator.'}}catch(error){{if(status)status.textContent='Copy was unavailable. Select the request text above and copy it manually.'}}}});</script></div></body></html>"#,
        sidebar = sidebar(&state.public_base_path, &user_label, state.auth.is_some(), ""),
        surface = html_escape(surface),
        request_text = html_escape(&request_text),
    ))
    .into_response()
}

pub(super) async fn provider_settings_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    no_store_html(
        &state,
        render_provider_connections_page(
            &provider_connections(
                &state.provider_runtime,
                &state.provider_connections,
                now_unix(),
            ),
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
                public_base_path: &state.public_base_path,
            },
            access.can_manage_fleet(),
            state.fleet_settings.get(),
        ),
    )
}

pub(super) async fn provider_settings_detail_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(provider_key): AxumPath<String>,
    Query(query): Query<ProviderSettingsQuery>,
) -> Response {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    let shell = ShellContext {
        user_label: &user_label,
        logout_enabled: state.auth.is_some(),
        public_base_path: &state.public_base_path,
    };
    let Some(provider) = provider_connection(
        &state.provider_runtime,
        &state.provider_connections,
        &provider_key,
        now_unix(),
    ) else {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Html(render_no_access_page(
                "Provider not found",
                "Return to Provider connections and choose an available path.",
                shell,
                "platform-settings",
            )),
        )
            .into_response();
    };
    let return_path = safe_provider_return_path(query.return_path.as_deref());
    let body = if provider.key == "hetzner-cloud" {
        render_hetzner_connection_page(
            &state.provider_runtime,
            &state.provider_connections,
            shell,
            access.can_manage_fleet(),
            return_path.as_deref(),
        )
    } else {
        render_guided_provider_page(
            &provider,
            shell,
            access.can_manage_fleet(),
            return_path.as_deref(),
        )
    };
    no_store_html(&state, body).into_response()
}

pub(super) async fn provider_connections_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    let catalog = provider_connections(
        &state.provider_runtime,
        &state.provider_connections,
        now_unix(),
    );
    no_store_json(json!({
        "schema": catalog.schema,
        "version": catalog.version,
        "can_manage": access.can_manage_fleet(),
        "providers": catalog.providers,
    }))
}

pub(super) async fn home(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if access.is_empty() {
        return no_store_html(
            &state,
            render_no_access_page(
                "Fleet",
                "All hosts at a glance",
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                "fleet",
            ),
        );
    }
    let all_hosts = state.store.list();
    reconcile_provisioning_jobs_with_runtime(&state.provisioning_jobs, &all_hosts, now_unix());
    let hosts = filter_hosts_by_access(all_hosts, &access);
    let jobs = filter_jobs_by_access(state.provisioning_jobs.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let declared_preferences =
        filter_declared_preferences_by_access(state.manifests.declared_preferences(), &access);
    let action_jobs: Vec<_> = state
        .host_actions
        .list()
        .into_iter()
        .filter(|job| access.allows_host(&job.host))
        .collect();
    // PHAROS-194: the removal dialog must name credential retirement before the
    // operator confirms. An unavailable generation is reported as unmanaged here;
    // the removal endpoint still fails closed on the same lookup.
    let janus_managed_hosts: BTreeSet<String> = hosts
        .iter()
        .filter(|host| {
            state
                .beacon_auth
                .janus_manages_host(&host.name)
                .unwrap_or(false)
        })
        .map(|host| host.name.clone())
        .collect();
    no_store_html(
        &state,
        crate::flow_host::inject_flow_shell(
            render_home_with_grace(
                RuntimeSnapshot {
                    nixpkgs_warn_after_days: state.fleet_settings.get().nixpkgs_warn_after_days,
                    hosts: &hosts,
                    jobs: &jobs,
                    action_jobs: &action_jobs,
                    declared_preferences: Some(&declared_preferences),
                    janus_managed_hosts: Some(&janus_managed_hosts),
                },
                &self_host(),
                now_unix(),
                &manifests,
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                FleetCapabilities {
                    can_manage_fleet: access.can_manage_fleet(),
                    system_update_available: state.nixcfg_dispatch.system_update_available(),
                    host_removal_available: state.nixcfg_dispatch.host_removal_available()
                        && (state.beacon_auth.report_token_mode == BeaconTokenMode::Local
                            || state.retirement_owner.configured()),
                },
                Some(state.fleet_settings.get().heartbeat_grace_secs),
            ),
            crate::flow_mount_enabled(&state, &state.auth, &headers, &access, None),
            None,
            state.flow_host.as_deref(),
            &state.public_base_path,
        ),
    )
}

pub(super) async fn map_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if access.is_empty() {
        return no_store_html(
            &state,
            render_no_access_page(
                "Map",
                "Server locations",
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                "map",
            ),
        );
    }
    let hosts = filter_hosts_by_access(state.store.list(), &access);
    no_store_html(
        &state,
        render_map(
            &hosts,
            &self_host(),
            now_unix(),
            &user_label,
            state.auth.is_some(),
            &state.public_base_path,
        ),
    )
}

pub(super) async fn map_data_json(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let access = access_for_headers(&state.auth, &headers);
    let hosts = filter_hosts_by_access(state.store.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let now = now_unix();
    let probes = map_connectivity_probes(&hosts, &manifests).await;
    let payload = {
        let mut payload = map_data_payload(
            &hosts,
            &self_host(),
            now,
            &manifests,
            &probes,
            state.fleet_settings.get().nixpkgs_warn_after_days,
        );
        for host in &mut payload.hosts {
            host.settings_href = state.public_base_path.href(&host.settings_href);
        }
        payload
    };
    no_store_json(serde_json::to_value(payload).expect("map data serializes"))
}

pub(super) async fn alerts_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if access.is_empty() {
        return no_store_html(
            &state,
            render_no_access_page(
                "Alerts",
                "Needs attention",
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                "alerts",
            ),
        );
    }
    let now = now_unix();
    let all_hosts = state.store.list();
    reconcile_provisioning_jobs_with_runtime(&state.provisioning_jobs, &all_hosts, now);
    let hosts = filter_hosts_by_access(all_hosts, &access);
    let jobs = filter_jobs_by_access(state.provisioning_jobs.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let probes = server_probe_overlays(&manifests, now, state.http_probes.as_deref()).await;
    let load_errors: &[ManifestLoadIssue] = if access.can_agora() {
        state.manifests.load_errors()
    } else {
        &[]
    };
    no_store_html(
        &state,
        render_alerts(
            RuntimeSnapshot {
                nixpkgs_warn_after_days: state.fleet_settings.get().nixpkgs_warn_after_days,
                hosts: &hosts,
                jobs: &jobs,
                action_jobs: &[],
                declared_preferences: None,
                janus_managed_hosts: None,
            },
            &self_host(),
            now,
            &manifests,
            load_errors,
            &probes,
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
                public_base_path: &state.public_base_path,
            },
        ),
    )
}

pub(super) async fn activity_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<ActivityQuery>,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if access.is_empty() {
        return no_store_html(
            &state,
            render_no_access_page(
                "Activity",
                "Operational timeline",
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                "activity",
            ),
        );
    }
    let now = now_unix();
    let all_hosts = state.store.list();
    reconcile_provisioning_jobs_with_runtime(&state.provisioning_jobs, &all_hosts, now);
    let hosts = filter_hosts_by_access(all_hosts, &access);
    let jobs = filter_jobs_by_access(state.provisioning_jobs.list(), &access);
    let manifests = filter_manifests_by_access(state.manifests.manifests(), &access);
    let probes = server_probe_overlays(&manifests, now, state.http_probes.as_deref()).await;
    let load_errors: &[ManifestLoadIssue] = if access.can_agora() {
        state.manifests.load_errors()
    } else {
        &[]
    };
    let action_jobs: Vec<_> = state
        .host_actions
        .list()
        .into_iter()
        .filter(|job| access.allows_host(&job.host))
        .collect();
    let focus = activity_focus(&query, &action_jobs);
    no_store_html(
        &state,
        render_activity_with_focus(
            RuntimeSnapshot {
                nixpkgs_warn_after_days: state.fleet_settings.get().nixpkgs_warn_after_days,
                hosts: &hosts,
                jobs: &jobs,
                action_jobs: &action_jobs,
                declared_preferences: None,
                janus_managed_hosts: None,
            },
            &self_host(),
            now,
            ActivitySources {
                manifests: &manifests,
                load_errors,
                server_probes: &probes,
                action_jobs: &action_jobs,
            },
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
                public_base_path: &state.public_base_path,
            },
            focus,
        ),
    )
}

pub(super) async fn backups_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    if access.is_empty() {
        return no_store_html(
            &state,
            render_no_access_page(
                "Backups",
                "Protection at a glance",
                ShellContext {
                    user_label: &user_label,
                    logout_enabled: state.auth.is_some(),
                    public_base_path: &state.public_base_path,
                },
                "backups",
            ),
        );
    }
    let hosts = filter_hosts_by_access(state.store.list(), &access);
    no_store_html(
        &state,
        render_backups(
            &hosts,
            now_unix(),
            ShellContext {
                user_label: &user_label,
                logout_enabled: state.auth.is_some(),
                public_base_path: &state.public_base_path,
            },
        ),
    )
}

pub(super) async fn fleet_horizon_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        FLEET_HORIZON_PNG,
    )
}

pub(super) async fn sidebar_lighthouse_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        SIDEBAR_LIGHTHOUSE_PNG,
    )
}

pub(super) async fn sidebar_lighthouse_motion_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "video/mp4"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        SIDEBAR_LIGHTHOUSE_MOTION_MP4,
    )
}

pub(super) async fn calendar_version_bootstrap_asset() -> impl axum::response::IntoResponse {
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

pub(super) async fn leaflet_css_asset() -> impl axum::response::IntoResponse {
    (
        [
            (header::CONTENT_TYPE, "text/css; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        LEAFLET_CSS,
    )
}

pub(super) async fn leaflet_js_asset() -> impl axum::response::IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        LEAFLET_JS,
    )
}

pub(super) async fn d3_js_asset() -> impl axum::response::IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        D3_JS,
    )
}

pub(super) async fn maplibre_asset(AxumPath(name): AxumPath<String>) -> Response {
    let (source, content_type) = match name.as_str() {
        "maplibre-gl.css" => (MAPLIBRE_CSS, "text/css; charset=utf-8"),
        "maplibre-gl-csp.js" => (MAPLIBRE_JS, "application/javascript; charset=utf-8"),
        "maplibre-gl-csp-worker.js" => {
            (MAPLIBRE_WORKER_JS, "application/javascript; charset=utf-8")
        }
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let mut response = (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        source,
    )
        .into_response();
    if name == "maplibre-gl-csp-worker.js" {
        response.extensions_mut().insert(MapWorkerAsset);
    }
    response
}

pub(super) async fn maplibre_leaflet_asset() -> impl axum::response::IntoResponse {
    (
        [
            (
                header::CONTENT_TYPE,
                "application/javascript; charset=utf-8",
            ),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        MAPLIBRE_LEAFLET_JS,
    )
}

pub(super) async fn leaflet_image_asset(AxumPath(name): AxumPath<String>) -> Response {
    let bytes = match name.as_str() {
        "layers.png" => LEAFLET_LAYERS_PNG,
        "layers-2x.png" => LEAFLET_LAYERS_2X_PNG,
        "marker-icon.png" => LEAFLET_MARKER_ICON_PNG,
        "marker-icon-2x.png" => LEAFLET_MARKER_ICON_2X_PNG,
        "marker-shadow.png" => LEAFLET_MARKER_SHADOW_PNG,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    (
        [
            (header::CONTENT_TYPE, "image/png"),
            (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
        ],
        bytes,
    )
        .into_response()
}

pub(super) async fn favicon_svg() -> impl axum::response::IntoResponse {
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

pub(super) fn url_query_escape(s: &str) -> String {
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

pub(super) fn freshness_row(
    kind: &str,
    label: &str,
    value: &str,
    class: &str,
    icon: &str,
    compact: bool,
) -> String {
    let label = html_escape(label);
    let value = html_escape(value);
    let class = html_escape(class);
    let kind = html_escape(kind);
    if compact {
        format!(
            r#"<div class="fresh-row fresh-row-compact" data-fresh-kind="{kind}" tabindex="0" title="{label}: {value}" aria-label="{label}: {value}"><span class="fresh-row-icon" aria-hidden="true">{icon}</span><span class="fresh-row-label">{label}</span><strong class="{class}" data-fresh-value>{value}</strong></div>"#,
        )
    } else {
        format!(
            r#"<div class="fresh-row" data-fresh-kind="{kind}"><span class="fresh-row-label">{label}</span><strong class="{class}" data-fresh-value>{value}</strong></div>"#,
        )
    }
}

pub(super) fn freshness_markup(
    freshness: &NixFreshness,
    compact: bool,
    now: i64,
    threshold: u32,
) -> String {
    if !freshness.applicable {
        return format!(
            "{}{}{}{}{}{}",
            freshness_row(
                "flake-lock-age",
                "Flake.lock age",
                "n/a",
                "na",
                icons::PACKAGE_CALENDAR,
                compact,
            ),
            freshness_row(
                "commits-behind",
                "Commits behind",
                "n/a",
                "na",
                icons::GIT_COMMIT_HORIZONTAL,
                compact,
            ),
            freshness_row(
                "deployed-sha",
                "Deployed SHA",
                "n/a",
                "na",
                icons::GIT_COMMIT_HORIZONTAL,
                compact,
            ),
            freshness_row(
                "nixcfg-sha",
                "nixcfg SHA",
                "n/a",
                "na",
                icons::GIT_COMMIT_HORIZONTAL,
                compact,
            ),
            freshness_row(
                "nixpkgs-sha",
                "nixpkgs SHA",
                "n/a",
                "na",
                icons::GIT_COMMIT_HORIZONTAL,
                compact,
            ),
            freshness_row(
                "secondary-nixpkgs",
                "Other root nixpkgs",
                "n/a",
                "na",
                icons::PACKAGE_CALENDAR,
                compact,
            )
        );
    }

    // PHAROS-202: age is context, not proof of currency. Only an exact
    // generation-owned revision compared with a freshly observed channel tip
    // can say `exact`; every missing link renders unknown.
    let server_age = freshness.nixpkgs_age_days_at(now);
    let (age, age_class) = match (
        freshness.deployment_evidence.as_ref(),
        freshness.nixpkgs_comparison.as_ref(),
        server_age,
    ) {
        (Some(_), Some(comparison), Some(days)) => {
            let suffix = match comparison.relation {
                NixpkgsRevisionRelation::Current => "exact",
                NixpkgsRevisionRelation::Different => "differs",
            };
            let class = if comparison.relation == NixpkgsRevisionRelation::Current {
                "ok"
            } else if freshness.nixpkgs_age_warning_at(now, threshold) {
                "warn"
            } else {
                "na"
            };
            (format!("{days}d · {suffix}"), class)
        }
        (Some(_), None, Some(days)) => (format!("{days}d · unknown"), "na"),
        _ => ("unverified".to_string(), "na"),
    };
    let (year, month) = pharos_core::utc_year_month(now);
    let end_of_life =
        freshness.channel_state(year, month) == Some(pharos_core::NixChannelState::EndOfLife);
    let (age, age_class) = if end_of_life {
        (format!("{age} · EOL"), "warn")
    } else {
        (age, age_class)
    };
    let (commits, commits_class) = match freshness.nixcfg_comparison.as_ref() {
        Some(comparison) => match comparison.relation {
            GitRevisionRelation::Current => ("exact".to_string(), "ok"),
            GitRevisionRelation::Behind => (
                format!("{} behind", comparison.commits_behind.unwrap_or(0)),
                "warn",
            ),
            GitRevisionRelation::Ahead => ("ahead".to_string(), "warn"),
            GitRevisionRelation::Diverged => ("diverged".to_string(), "warn"),
        },
        None => ("unknown".to_string(), "na"),
    };
    // The label has to name whichever value is shown; a nixpkgs age under a
    // "Flake.lock age" label is the same misreading PHAROS-193 set out to fix.
    let age_label = match (
        freshness.nixpkgs_age_days,
        freshness.nixpkgs_channel.as_deref(),
    ) {
        (Some(_), Some(channel)) => format!("nixpkgs lock ({channel})"),
        (Some(_), None) => "nixpkgs age".to_string(),
        (None, _) => "nixpkgs lock".to_string(),
    };
    let (deployed_sha, nixcfg_sha, nixpkgs_sha, evidence_class) =
        match freshness.deployment_evidence.as_ref() {
            Some(evidence) => {
                let deployed = evidence
                    .source_revision
                    .chars()
                    .take(12)
                    .collect::<String>();
                let nixcfg_upstream = freshness
                    .nixcfg_comparison
                    .as_ref()
                    .map(|comparison| {
                        comparison
                            .upstream_revision
                            .chars()
                            .take(12)
                            .collect::<String>()
                    })
                    .unwrap_or_else(|| "unknown".to_string());
                let nixpkgs = evidence
                    .nixpkgs_revision
                    .chars()
                    .take(12)
                    .collect::<String>();
                (deployed, nixcfg_upstream, nixpkgs, "ok")
            }
            None => (
                "n/a".to_string(),
                "n/a".to_string(),
                "n/a".to_string(),
                "na",
            ),
        };
    let (secondary_label, secondary_age) = match &freshness.secondary_nixpkgs {
        Some(secondary) => {
            let label = match secondary.channel.as_deref() {
                Some(channel) => format!("Other root nixpkgs · {} ({channel})", secondary.input),
                None => format!("Other root nixpkgs · {}", secondary.input),
            };
            (label, format!("{}d", secondary.age_days))
        }
        None => ("Other root nixpkgs".to_string(), "not reported".to_string()),
    };
    format!(
        "{}{}{}{}{}{}",
        freshness_row(
            "flake-lock-age",
            &age_label,
            &age,
            age_class,
            icons::PACKAGE_CALENDAR,
            compact,
        ),
        freshness_row(
            "commits-behind",
            "nixcfg revision",
            &commits,
            commits_class,
            icons::GIT_COMMIT_HORIZONTAL,
            compact,
        ),
        freshness_row(
            "deployed-sha",
            "Deployed SHA",
            &deployed_sha,
            evidence_class,
            icons::GIT_COMMIT_HORIZONTAL,
            compact,
        ),
        freshness_row(
            "nixcfg-sha",
            "nixcfg SHA",
            &nixcfg_sha,
            evidence_class,
            icons::GIT_COMMIT_HORIZONTAL,
            compact,
        ),
        freshness_row(
            "nixpkgs-sha",
            "nixpkgs SHA",
            &nixpkgs_sha,
            evidence_class,
            icons::GIT_COMMIT_HORIZONTAL,
            compact,
        ),
        freshness_row(
            "secondary-nixpkgs",
            &secondary_label,
            &secondary_age,
            "na",
            icons::PACKAGE_CALENDAR,
            compact,
        )
    )
}

fn freshness_fault_row(
    kind: &str,
    label: &str,
    value: &str,
    class: &str,
    icon: &str,
    visible: bool,
) -> String {
    let hidden = if visible { "" } else { " hidden" };
    format!(
        r#"<div class="fresh-row fresh-row-compact" data-fresh-kind="{kind}" tabindex="0" title="{label}: {value}" aria-label="{label}: {value}"{hidden}><span class="fresh-row-icon" aria-hidden="true">{icon}</span><span class="fresh-row-label">{label}</span><strong class="{class}" data-fresh-value>{value}</strong></div>"#,
        kind = html_escape(kind),
        label = html_escape(label),
        value = html_escape(value),
        class = html_escape(class),
    )
}

pub(super) fn card_freshness_fault_markup(
    freshness: &NixFreshness,
    backup: &BackupUiSummary,
    kernel: Option<&KernelPosture>,
    now: i64,
    threshold: u32,
) -> (String, bool) {
    let evidence_missing = freshness.applicable && freshness.deployment_evidence.is_none();
    let (year, month) = pharos_core::utc_year_month(now);
    let channel = freshness
        .deployment_evidence
        .as_ref()
        .map(|evidence| evidence.nixpkgs_channel.as_str())
        .or(freshness.nixpkgs_channel.as_deref())
        .unwrap_or("nixpkgs");
    let channel_eol = freshness.applicable
        && !evidence_missing
        && freshness.channel_state(year, month) == Some(pharos_core::NixChannelState::EndOfLife);
    let (nixpkgs_value, nixpkgs_class, nixpkgs_visible) =
        if !freshness.applicable || evidence_missing {
            (String::new(), "na", false)
        } else {
            match freshness.nixpkgs_comparison.as_ref() {
                Some(comparison) if comparison.relation == NixpkgsRevisionRelation::Current => {
                    (String::new(), "ok", false)
                }
                Some(_) if freshness.nixpkgs_age_warning_at(now, threshold) => {
                    (format!("nixpkgs differs from {channel}"), "warn", true)
                }
                Some(_) => (String::new(), "na", false),
                None => ("nixpkgs comparison unknown".to_string(), "na", true),
            }
        };
    let (nixcfg_value, nixcfg_class, nixcfg_visible) = if !freshness.applicable || evidence_missing
    {
        (String::new(), "na", false)
    } else {
        match freshness.nixcfg_comparison.as_ref() {
            Some(comparison) if comparison.relation == GitRevisionRelation::Current => {
                (String::new(), "ok", false)
            }
            Some(comparison) if comparison.relation == GitRevisionRelation::Behind => (
                format!("{} commits behind", comparison.commits_behind.unwrap_or(0)),
                "warn",
                true,
            ),
            Some(comparison) if comparison.relation == GitRevisionRelation::Ahead => {
                ("deployed revision ahead".to_string(), "warn", true)
            }
            Some(_) => ("deployed revision diverged".to_string(), "warn", true),
            None => ("nixcfg comparison unknown".to_string(), "na", true),
        }
    };
    // Fleet cards already show this in the protection fact and backup chip.
    let backup_visible = false;
    let backup_class = match backup.level {
        "critical" => "down",
        "warning" => "warn",
        _ => "na",
    };
    let kernel_visible = kernel_reboot_required(kernel).is_some();
    let any_visible = evidence_missing
        || channel_eol
        || nixpkgs_visible
        || nixcfg_visible
        || backup_visible
        || kernel_visible;
    let markup = format!(
        "{}{}{}{}{}{}",
        freshness_fault_row(
            "freshness-unverified",
            "Freshness",
            "unverified",
            "na",
            icons::PACKAGE_SEARCH,
            evidence_missing,
        ),
        freshness_fault_row(
            "nixpkgs-eol",
            "nixpkgs",
            &format!("{channel} end of life"),
            "warn",
            icons::PACKAGE_CALENDAR,
            channel_eol,
        ),
        freshness_fault_row(
            "nixpkgs-drift",
            "nixpkgs",
            &nixpkgs_value,
            nixpkgs_class,
            icons::PACKAGE_CALENDAR,
            nixpkgs_visible,
        ),
        freshness_fault_row(
            "nixcfg-drift",
            "nixcfg",
            &nixcfg_value,
            nixcfg_class,
            icons::GIT_COMMIT_HORIZONTAL,
            nixcfg_visible,
        ),
        freshness_fault_row(
            "backup-fault",
            "Backup",
            &backup.label,
            backup_class,
            icons::SHIELD_ALERT,
            backup_visible,
        ),
        freshness_fault_row(
            "kernel-restart",
            "Kernel",
            "restart required",
            "warn",
            icons::POWER,
            kernel_visible,
        ),
    );
    (markup, any_visible)
}

fn fresh_chip_value(row: &str) -> Option<&str> {
    let marker = "data-fresh-value>";
    let start = row.find(marker)? + marker.len();
    let rest = row.get(start..)?;
    let end = rest.find("</strong>")?;
    Some(rest[..end].trim())
}

fn scan_texts_repeat(summary: &str, value: &str) -> bool {
    let summary = summary.trim().to_ascii_lowercase();
    let value = value.trim().to_ascii_lowercase();
    if summary.is_empty() || value.is_empty() {
        return false;
    }
    summary == value || (value == "unverified" && summary == "freshness unverified")
}

fn mark_scan_duplicate_chip(markup: &str, summary: &str) -> String {
    if summary.trim().is_empty() {
        return markup.to_string();
    }
    let mut out = String::new();
    for row in markup.split_inclusive("</div>") {
        let repeats = fresh_chip_value(row).is_some_and(|value| scan_texts_repeat(summary, value));
        if repeats && !row.contains(" hidden") {
            out.push_str(&row.replacen(
                r#"class="fresh-row fresh-row-compact""#,
                r#"class="fresh-row fresh-row-compact scan-duplicate""#,
                1,
            ));
        } else {
            out.push_str(row);
        }
    }
    out
}

fn scan_rail_shows_chip(markup: &str) -> bool {
    markup.split("fresh-row-compact").skip(1).any(|row| {
        let head = row.split('>').next().unwrap_or("");
        !head.contains("hidden") && !head.contains("scan-duplicate")
    })
}

pub(super) fn kernel_reboot_required(kernel: Option<&KernelPosture>) -> Option<&KernelPosture> {
    kernel.filter(|posture| posture.state == KernelPostureState::RebootRequired)
}

pub(super) struct AttentionReason {
    pub(super) label: String,
    pub(super) level: &'static str,
    pub(super) rank: u8,
}

pub(super) fn self_attention_reason() -> AttentionReason {
    AttentionReason {
        label: "Pharos host".to_string(),
        level: "self",
        rank: 4,
    }
}

pub(super) fn freshness_attention_reason(
    freshness: &NixFreshness,
    now: i64,
    threshold: u32,
) -> Option<AttentionReason> {
    if !freshness.applicable {
        return None;
    }

    let Some(evidence) = freshness.deployment_evidence.as_ref() else {
        return Some(AttentionReason {
            label: "freshness unverified".to_string(),
            level: "wait",
            rank: 1,
        });
    };

    // PHAROS-193: an end-of-life channel outranks every age number, because no
    // age is small enough to make an unsupported release safe. The control
    // plane owns this calendar so an expiring release needs no beacon roll.
    let (year, month) = pharos_core::utc_year_month(now);
    if freshness.channel_state(year, month) == Some(pharos_core::NixChannelState::EndOfLife) {
        let channel = evidence.nixpkgs_channel.as_str();
        return Some(AttentionReason {
            label: format!("{channel} end of life"),
            level: "warn",
            rank: 1,
        });
    }

    match freshness.nixpkgs_comparison.as_ref() {
        Some(_) if freshness.nixpkgs_age_warning_at(now, threshold) => {
            return Some(AttentionReason {
                label: format!("nixpkgs differs from {}", evidence.nixpkgs_channel),
                level: "warn",
                rank: 2,
            });
        }
        None => {
            return Some(AttentionReason {
                label: "nixpkgs comparison unknown".to_string(),
                level: "wait",
                rank: 2,
            });
        }
        _ => {}
    }

    match freshness.nixcfg_comparison.as_ref() {
        Some(comparison) if comparison.relation == GitRevisionRelation::Current => None,
        Some(comparison) if comparison.relation == GitRevisionRelation::Behind => {
            Some(AttentionReason {
                label: format!("{} commits behind", comparison.commits_behind.unwrap_or(0)),
                level: "warn",
                rank: 3,
            })
        }
        Some(comparison) if comparison.relation == GitRevisionRelation::Ahead => {
            Some(AttentionReason {
                label: "deployed revision ahead".to_string(),
                level: "warn",
                rank: 3,
            })
        }
        Some(_) => Some(AttentionReason {
            label: "deployed revision diverged".to_string(),
            level: "warn",
            rank: 3,
        }),
        None => Some(AttentionReason {
            label: "nixcfg comparison unknown".to_string(),
            level: "wait",
            rank: 3,
        }),
    }
}

pub(super) fn service_observation_attention_reason(
    observations: &[ServiceObservation],
) -> Option<AttentionReason> {
    if observations.is_empty() {
        return None;
    }

    let warnings = observations
        .iter()
        .filter(|observation| !is_nix_freshness_observation(observation))
        .filter(|obs| obs.state == ServiceObservationState::Warning)
        .count();
    if warnings > 0 {
        return Some(AttentionReason {
            label: format!(
                "{warnings} service warning{}",
                if warnings == 1 { "" } else { "s" }
            ),
            level: "warn",
            rank: 3,
        });
    }

    let stale = observations
        .iter()
        .filter(|observation| !is_nix_freshness_observation(observation))
        .filter(|obs| obs.state == ServiceObservationState::Stale)
        .count();
    if stale > 0 {
        return Some(AttentionReason {
            label: format!("{stale} service stale{}", if stale == 1 { "" } else { "s" }),
            level: "warn",
            rank: 3,
        });
    }

    let unknown = observations
        .iter()
        .filter(|observation| !is_nix_freshness_observation(observation))
        .filter(|observation| {
            !appliance_probes::is_appliance_observation(observation)
                || !observation
                    .summary
                    .starts_with("online; allowing SSH startup")
        })
        .filter(|obs| obs.state == ServiceObservationState::Unknown)
        .count();
    if unknown > 0 {
        return Some(AttentionReason {
            label: format!("{unknown} service unknown"),
            level: "wait",
            rank: 3,
        });
    }

    None
}

pub(super) fn service_observations_summary(
    observations: &[ServiceObservation],
) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => warning += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let label = if observations.is_empty() {
        "not observed".to_string()
    } else if warning > 0 {
        format!("{warning} warning{}", if warning == 1 { "" } else { "s" })
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "healthy".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

pub(super) fn backup_observations_summary(observations: &[BackupObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut stale = 0;
    let mut failed = 0;
    let mut unknown = 0;
    let mut missing = 0;
    let mut not_configured = 0;
    for observation in observations {
        match observation.state {
            BackupPostureState::Healthy => healthy += 1,
            BackupPostureState::Warning => warning += 1,
            BackupPostureState::Stale => stale += 1,
            BackupPostureState::Failed => failed += 1,
            BackupPostureState::Unknown => unknown += 1,
            BackupPostureState::Missing => missing += 1,
            BackupPostureState::NotConfigured => not_configured += 1,
        }
    }
    let (state, label) = if observations.is_empty() {
        ("unknown", "not observed".to_string())
    } else if failed > 0 {
        ("failed", format!("{failed} failed"))
    } else if missing > 0 {
        ("missing", format!("{missing} missing"))
    } else if stale > 0 {
        ("stale", format!("{stale} stale"))
    } else if warning > 0 {
        (
            "warning",
            format!("{warning} warning{}", if warning == 1 { "" } else { "s" }),
        )
    } else if unknown > 0 {
        ("unknown", format!("{unknown} unknown"))
    } else if not_configured > 0 {
        ("not-configured", format!("{not_configured} not configured"))
    } else {
        ("healthy", "healthy".to_string())
    };
    json!({
        "state": state,
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "failed": failed,
        "unknown": unknown,
        "missing": missing,
        "not_configured": not_configured,
        "total": observations.len(),
    })
}

#[derive(Debug, Clone)]
pub(super) struct BackupUiSummary {
    state: &'static str,
    level: &'static str,
    label: String,
    detail: String,
    last_success: String,
    schedule: String,
    target: String,
    validation: String,
    total: usize,
    rank: usize,
}

pub(super) fn backup_posture_rank(state: BackupPostureState) -> usize {
    match state {
        BackupPostureState::Failed => 0,
        BackupPostureState::Missing => 1,
        BackupPostureState::Stale => 2,
        BackupPostureState::Warning => 3,
        BackupPostureState::Unknown => 4,
        BackupPostureState::NotConfigured => 5,
        BackupPostureState::Healthy => 6,
    }
}

pub(super) fn backup_level(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Failed | BackupPostureState::Missing => "critical",
        BackupPostureState::Stale | BackupPostureState::Warning => "warning",
        BackupPostureState::Unknown | BackupPostureState::NotConfigured => "watch",
        BackupPostureState::Healthy => "clear",
    }
}

pub(super) fn backup_state_key(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Healthy => "healthy",
        BackupPostureState::Warning => "warning",
        BackupPostureState::Stale => "stale",
        BackupPostureState::Failed => "failed",
        BackupPostureState::Unknown => "unknown",
        BackupPostureState::Missing => "missing",
        BackupPostureState::NotConfigured => "not-configured",
    }
}

pub(super) fn backup_state_label(state: BackupPostureState) -> &'static str {
    match state {
        BackupPostureState::Healthy => "Protected",
        BackupPostureState::Warning => "Review backup",
        BackupPostureState::Stale => "Backup stale",
        BackupPostureState::Failed => "Backup failed",
        BackupPostureState::Unknown => "Backup pending",
        BackupPostureState::Missing => "Backup missing",
        BackupPostureState::NotConfigured => "No backup",
    }
}

pub(super) fn backup_run_label(state: pharos_core::BackupRunState) -> &'static str {
    match state {
        pharos_core::BackupRunState::Succeeded => "succeeded",
        pharos_core::BackupRunState::Failed => "failed",
        pharos_core::BackupRunState::Running => "running",
        pharos_core::BackupRunState::Unknown => "unknown",
    }
}

pub(super) fn backup_validation_state_label(
    state: pharos_core::BackupValidationState,
) -> &'static str {
    match state {
        pharos_core::BackupValidationState::Passed => "passed",
        pharos_core::BackupValidationState::Failed => "failed",
        pharos_core::BackupValidationState::Stale => "stale",
        pharos_core::BackupValidationState::Unknown => "unknown",
    }
}

pub(super) fn backup_validation_level_label(
    level: pharos_core::BackupValidationLevel,
) -> &'static str {
    match level {
        pharos_core::BackupValidationLevel::SnapshotExists => "snapshot",
        pharos_core::BackupValidationLevel::RepositoryCheck => "repo check",
        pharos_core::BackupValidationLevel::MountList => "mount/list",
        pharos_core::BackupValidationLevel::RestoreSample => "restore sample",
        pharos_core::BackupValidationLevel::DiffHash => "diff/hash",
        pharos_core::BackupValidationLevel::OperatorTest => "operator test",
    }
}

pub(super) fn backup_last_success_label(observation: &BackupObservation, now: i64) -> String {
    observation
        .last_success_at
        .map(|timestamp| format!("{} ago", duration_label(now - timestamp)))
        .unwrap_or_else(|| "not yet".to_string())
}

pub(super) fn backup_validation_label(observation: &BackupObservation, now: i64) -> String {
    if let Some(restore) = &observation.restore_validation {
        let label = restore
            .evidence_label
            .as_deref()
            .unwrap_or_else(|| backup_validation_level_label(restore.level));
        return restore
            .checked_at
            .map(|timestamp| {
                format!(
                    "{} {} · {} ago",
                    label,
                    backup_validation_state_label(restore.state),
                    duration_label(now - timestamp)
                )
            })
            .unwrap_or_else(|| {
                format!("{} {}", label, backup_validation_state_label(restore.state))
            });
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_check_at, observation.last_check_state)
    {
        return format!(
            "check {} · {} ago",
            backup_validation_state_label(state),
            duration_label(now - timestamp)
        );
    }

    "not checked".to_string()
}

pub(super) fn backup_attempt_detail(observation: &BackupObservation, now: i64) -> String {
    if observation.state == BackupPostureState::Healthy {
        return observation
            .last_success_at
            .map(|timestamp| format!("last success {} ago", duration_label(now - timestamp)))
            .unwrap_or_else(|| observation.summary.clone());
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_attempt_at, observation.last_attempt_state)
    {
        return format!(
            "{} · {} ago",
            backup_run_label(state),
            duration_label(now - timestamp)
        );
    }

    observation.summary.clone()
}

pub(super) fn backup_ui_summary(observations: &[BackupObservation], now: i64) -> BackupUiSummary {
    let Some(primary) = observations
        .iter()
        .min_by_key(|observation| backup_posture_rank(observation.state))
    else {
        return BackupUiSummary {
            state: "unknown",
            level: "watch",
            label: "Not observed".to_string(),
            detail: "No backup signal yet".to_string(),
            last_success: "not observed".to_string(),
            schedule: "not declared".to_string(),
            target: "not declared".to_string(),
            validation: "not checked".to_string(),
            total: 0,
            rank: backup_posture_rank(BackupPostureState::Unknown),
        };
    };

    BackupUiSummary {
        state: backup_state_key(primary.state),
        level: backup_level(primary.state),
        label: backup_state_label(primary.state).to_string(),
        detail: backup_attempt_detail(primary, now),
        last_success: backup_last_success_label(primary, now),
        schedule: primary
            .schedule
            .clone()
            .unwrap_or_else(|| "not declared".to_string()),
        target: primary
            .target_label
            .clone()
            .unwrap_or_else(|| "not declared".to_string()),
        validation: backup_validation_label(primary, now),
        total: observations.len(),
        rank: backup_posture_rank(primary.state),
    }
}

/// Seconds after a qualifying selective-restore success before it is overdue.
/// Exactly this age is still current; only a strictly greater age is overdue.
pub(super) const SELECTIVE_RESTORE_OVERDUE_AFTER_SECS: i64 = 30 * 24 * 60 * 60;

/// Same cut as pharos-beacon `DEFAULT_BACKUP_STALE_AFTER_SECS` (36h).
/// Exactly this age is still fresh; only a strictly greater age is stale.
pub(super) const BACKUP_RUN_STALE_AFTER_SECS: i64 = 36 * 60 * 60;

/// Matches the browser clock-skew allowance. A success time further ahead is not fresh.
const BACKUP_CLOCK_SKEW_SECS: i64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ProtectionFact {
    pub(super) state: &'static str,
    pub(super) tone: &'static str,
    pub(super) label: String,
    pub(super) note: String,
    pub(super) at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FleetProtectionView {
    pub(super) run: ProtectionFact,
    pub(super) check: Option<ProtectionFact>,
    pub(super) restore: ProtectionFact,
    pub(super) daily_ok: bool,
    pub(super) missing_restore_producer: bool,
    pub(super) restore_overdue: bool,
    /// Set only when the host reports a restored-file count. The observation
    /// contract has no count field, so production leaves this empty.
    pub(super) restore_file_count: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HealthReason {
    pub(super) label: String,
    pub(super) tone: &'static str,
    pub(super) at: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostHealthView {
    pub(super) tone: &'static str,
    pub(super) label: &'static str,
    pub(super) summary: String,
    pub(super) problem_count: usize,
    pub(super) reasons: Vec<HealthReason>,
}

fn schedule_is_daily(schedule: &str) -> bool {
    let lowered = schedule.to_ascii_lowercase();
    let mut words = Vec::new();
    let mut token = String::new();
    for ch in lowered.chars() {
        if ch.is_ascii_alphanumeric() {
            token.push(ch);
        } else if !token.is_empty() {
            words.push(std::mem::take(&mut token));
        }
    }
    if !token.is_empty() {
        words.push(token);
    }
    words
        .iter()
        .any(|word| matches!(word.as_str(), "daily" | "day" | "nightly"))
        || lowered.contains("24h")
        || lowered.contains("every day")
}

fn is_selective_restore(level: pharos_core::BackupValidationLevel) -> bool {
    level == pharos_core::BackupValidationLevel::RestoreSample
}

fn ago_note(at: Option<i64>, now: i64, prefix: &str) -> String {
    match positive_instant(at) {
        Some(at) => format!("{prefix} {}", backup_age_text(at, now)),
        None => format!("{prefix} not recorded"),
    }
}

fn backup_age_text(at: i64, now: i64) -> String {
    if at > now.saturating_add(BACKUP_CLOCK_SKEW_SECS) {
        return "time is in the future".to_string();
    }
    let seconds = now.saturating_sub(at).max(0);
    if seconds >= 86_400 {
        let days = seconds / 86_400;
        return format!("{days}d ago");
    }
    format!("{} ago", duration_label(seconds))
}

fn backup_success_is_stale(success_at: Option<i64>, now: i64) -> bool {
    let Some(at) = success_at else {
        return false;
    };
    if at > now.saturating_add(BACKUP_CLOCK_SKEW_SECS) {
        return true;
    }
    now.saturating_sub(at) > BACKUP_RUN_STALE_AFTER_SECS
}

fn positive_instant(at: Option<i64>) -> Option<i64> {
    at.filter(|stamp| *stamp > 0)
}

/// Recorded positive seconds at or before now plus the shared 2s clock skew.
/// Missing, zero, negative, and future times are not eligible restore evidence.
fn eligible_restore_instant(at: Option<i64>, now: i64) -> Option<i64> {
    let at = positive_instant(at)?;
    if at > now.saturating_add(BACKUP_CLOCK_SKEW_SECS) {
        return None;
    }
    Some(at)
}

/// Higher is more adverse. Equal timestamps use this so input order cannot
/// prefer a pass over a tied failure, stale, or unknown record.
fn restore_state_adversity(state: pharos_core::BackupValidationState) -> u8 {
    match state {
        pharos_core::BackupValidationState::Failed => 3,
        pharos_core::BackupValidationState::Stale => 2,
        pharos_core::BackupValidationState::Unknown => 1,
        pharos_core::BackupValidationState::Passed => 0,
    }
}

fn run_fact(observation: &BackupObservation, now: i64) -> ProtectionFact {
    let success_at = positive_instant(observation.last_success_at);
    let mut state = observation.state;
    if matches!(
        state,
        BackupPostureState::Healthy | BackupPostureState::Warning
    ) && backup_success_is_stale(success_at, now)
    {
        state = BackupPostureState::Stale;
    }
    if observation.configured == pharos_core::BackupConfiguredState::Disabled
        && !matches!(
            state,
            BackupPostureState::Failed
                | BackupPostureState::Missing
                | BackupPostureState::Stale
                | BackupPostureState::Warning
        )
    {
        return ProtectionFact {
            state: "disabled",
            tone: "amber",
            label: "Disabled".to_string(),
            note: "Backup is disabled and is not an exemption from backup policy".to_string(),
            at: success_at.filter(|at| *at > 0),
        };
    }
    let success = backup_last_success_label(observation, now);
    match state {
        BackupPostureState::Healthy if success_at.is_none() => ProtectionFact {
            state: "unknown",
            tone: "neutral",
            label: "Success time unknown".to_string(),
            note: "No successful-run time was recorded".to_string(),
            at: None,
        },
        BackupPostureState::Healthy => {
            let schedule = observation
                .schedule
                .as_deref()
                .unwrap_or("schedule not declared");
            let daily = observation
                .schedule
                .as_deref()
                .is_some_and(schedule_is_daily);
            ProtectionFact {
                state: "ok",
                tone: "good",
                label: if daily {
                    "Daily OK".to_string()
                } else {
                    "Successful".to_string()
                },
                note: format!("last success {success} · {schedule}"),
                at: success_at,
            }
        }
        BackupPostureState::Failed => ProtectionFact {
            state: "failed",
            tone: "bad",
            label: "Failed".to_string(),
            note: ago_note(success_at, now, "last success"),
            at: success_at,
        },
        BackupPostureState::Missing => ProtectionFact {
            state: "missing",
            tone: "bad",
            label: "Missing".to_string(),
            note: ago_note(success_at, now, "last success"),
            at: success_at,
        },
        BackupPostureState::Stale => ProtectionFact {
            state: "stale",
            tone: "amber",
            label: "Stale".to_string(),
            note: ago_note(success_at, now, "last success"),
            at: success_at,
        },
        BackupPostureState::Warning => ProtectionFact {
            state: "warning",
            tone: "amber",
            label: "Review".to_string(),
            note: ago_note(success_at, now, "last success"),
            at: success_at,
        },
        BackupPostureState::Unknown => ProtectionFact {
            state: "unknown",
            tone: "neutral",
            label: "Unknown".to_string(),
            note: "Backup evidence is unknown".to_string(),
            at: success_at,
        },
        BackupPostureState::NotConfigured => ProtectionFact {
            state: "not-configured",
            tone: "neutral",
            label: "Not configured".to_string(),
            note: "No backup is configured".to_string(),
            at: success_at,
        },
    }
}

fn check_fact(observations: &[BackupObservation], now: i64) -> Option<ProtectionFact> {
    let validation = observations
        .iter()
        .filter_map(|observation| observation.restore_validation.as_ref())
        .filter(|validation| !is_selective_restore(validation.level))
        .max_by_key(|validation| validation.checked_at.unwrap_or(i64::MIN));
    if let Some(validation) = validation {
        return Some(validation_check_fact(validation, now));
    }
    let check = observations
        .iter()
        .filter(|observation| observation.last_check_state.is_some())
        .max_by_key(|observation| observation.last_check_at.unwrap_or(i64::MIN))?;
    let state = check.last_check_state?;
    Some(check_state_fact(
        state,
        check.last_check_at,
        "Repository check",
        now,
    ))
}

fn validation_check_fact(
    validation: &pharos_core::BackupValidationObservation,
    now: i64,
) -> ProtectionFact {
    let name = validation
        .evidence_label
        .as_deref()
        .unwrap_or_else(|| backup_validation_level_label(validation.level));
    check_state_fact(validation.state, validation.checked_at, name, now)
}

fn check_state_fact(
    state: pharos_core::BackupValidationState,
    at: Option<i64>,
    name: &str,
    now: i64,
) -> ProtectionFact {
    let (key, tone, label) = match state {
        pharos_core::BackupValidationState::Passed => ("passed", "good", "Check passed"),
        pharos_core::BackupValidationState::Failed => ("failed", "bad", "Check failed"),
        pharos_core::BackupValidationState::Stale => ("stale", "amber", "Check stale"),
        pharos_core::BackupValidationState::Unknown => ("unknown", "neutral", "Check unknown"),
    };
    let at = positive_instant(at);
    ProtectionFact {
        state: key,
        tone,
        label: label.to_string(),
        note: match at {
            Some(at) => format!("{name} · {}", backup_age_text(at, now)),
            None => format!("{name} · time not recorded"),
        },
        at,
    }
}

fn restore_fact(
    observations: &[BackupObservation],
    run_not_required: bool,
    now: i64,
) -> (ProtectionFact, bool, bool) {
    if run_not_required {
        return (
            ProtectionFact {
                state: "not-required",
                tone: "neutral",
                label: "Not required".to_string(),
                note: "No selective restore is required".to_string(),
                at: None,
            },
            false,
            false,
        );
    }
    let validations: Vec<&pharos_core::BackupValidationObservation> = observations
        .iter()
        .filter_map(|observation| observation.restore_validation.as_ref())
        .filter(|validation| is_selective_restore(validation.level))
        .collect();
    if validations.is_empty() {
        return (
            ProtectionFact {
                state: "unknown",
                tone: "neutral",
                label: "Not observed".to_string(),
                note: "No selective restore evidence from the backup source".to_string(),
                at: None,
            },
            true,
            false,
        );
    }
    let last_success = validations
        .iter()
        .copied()
        .filter(|validation| {
            validation.state == pharos_core::BackupValidationState::Passed
                && eligible_restore_instant(validation.checked_at, now).is_some()
        })
        .max_by_key(|validation| validation.checked_at.unwrap_or(i64::MIN));
    let latest = validations
        .iter()
        .copied()
        .filter(|validation| eligible_restore_instant(validation.checked_at, now).is_some())
        .max_by(|left, right| {
            left.checked_at.cmp(&right.checked_at).then_with(|| {
                restore_state_adversity(left.state).cmp(&restore_state_adversity(right.state))
            })
        });
    let newer_failed = match (latest, last_success) {
        (Some(latest), Some(success)) => {
            latest.state == pharos_core::BackupValidationState::Failed
                && latest.checked_at > success.checked_at
        }
        (Some(latest), None) => latest.state == pharos_core::BackupValidationState::Failed,
        _ => false,
    };
    if newer_failed {
        let at = positive_instant(last_success.and_then(|validation| validation.checked_at));
        return (
            ProtectionFact {
                state: "failed",
                tone: "bad",
                label: "Failed".to_string(),
                note: ago_note(at, now, "last successful selective restore"),
                at,
            },
            false,
            false,
        );
    }
    let Some(success) = last_success else {
        return (
            ProtectionFact {
                state: "unknown",
                tone: "neutral",
                label: "Not observed".to_string(),
                note: "No successful selective restore is recorded".to_string(),
                at: None,
            },
            false,
            false,
        );
    };
    let at = positive_instant(success.checked_at);
    let age = now.saturating_sub(at.unwrap_or(now));
    if age > SELECTIVE_RESTORE_OVERDUE_AFTER_SECS {
        return (
            ProtectionFact {
                state: "overdue",
                tone: "amber",
                label: "Overdue".to_string(),
                note: ago_note(at, now, "last successful selective restore"),
                at,
            },
            false,
            true,
        );
    }
    let latest_is_success = latest.is_some_and(|validation| {
        validation.state == pharos_core::BackupValidationState::Passed
            && validation.checked_at == at
    });
    if latest_is_success {
        return (
            ProtectionFact {
                state: "passed",
                tone: "good",
                label: "Passed".to_string(),
                note: ago_note(at, now, "selective restore"),
                at,
            },
            false,
            false,
        );
    }
    (
        ProtectionFact {
            state: "unknown",
            tone: "neutral",
            label: "Unknown".to_string(),
            note: ago_note(at, now, "last successful selective restore"),
            at,
        },
        false,
        false,
    )
}

/// Lower is worse. `not-required` ranks after every real job so it cannot hide one.
fn projected_run_rank(fact: &ProtectionFact) -> usize {
    match fact.state {
        "failed" => 0,
        "missing" => 1,
        "stale" => 2,
        "warning" | "disabled" => 3,
        "unknown" => 4,
        "not-configured" => 5,
        "ok" => 6,
        "not-required" => 7,
        _ => 4,
    }
}

pub(super) fn fleet_protection_view(
    observations: &[BackupObservation],
    now: i64,
) -> FleetProtectionView {
    // Project freshness and configuration before ranking. Producer posture alone
    // would keep a fresh healthy job ahead of another healthy job that is stale.
    let run = observations
        .iter()
        .map(|observation| run_fact(observation, now))
        .min_by_key(projected_run_rank)
        .unwrap_or(ProtectionFact {
            state: "unknown",
            tone: "neutral",
            label: "Not observed".to_string(),
            note: "No backup signal yet".to_string(),
            at: None,
        });
    let not_required = run.state == "not-required";
    let (restore, missing_restore_producer, restore_overdue) =
        restore_fact(observations, not_required, now);
    let daily_ok = run.tone == "good" && run.label == "Daily OK";
    FleetProtectionView {
        run,
        check: check_fact(observations, now),
        restore,
        daily_ok,
        missing_restore_producer,
        restore_overdue,
        restore_file_count: None,
    }
}

fn push_reason(
    reasons: &mut Vec<HealthReason>,
    label: impl Into<String>,
    tone: &'static str,
    at: Option<i64>,
) {
    reasons.push(HealthReason {
        label: label.into(),
        tone,
        at,
    });
}

fn expected_offline(
    preferences: &HostPreferences,
    services: &[ServiceObservation],
    live: Liveness,
) -> bool {
    if live != Liveness::Down {
        return false;
    }
    if preferences.kind == HostKind::Workstation {
        return true;
    }
    services.iter().any(|observation| {
        appliance_probes::is_appliance_observation(observation)
            && observation.summary == "powered off as expected"
    })
}

fn headline_reason(reasons: &[HealthReason]) -> String {
    for tone in ["bad", "amber", "neutral"] {
        if let Some(reason) = reasons.iter().find(|reason| reason.tone == tone) {
            return reason.label.clone();
        }
    }
    "No action needed".to_string()
}

fn worst_health_tone(reasons: &[HealthReason]) -> &'static str {
    if reasons.iter().any(|reason| reason.tone == "bad") {
        "bad"
    } else if reasons.iter().any(|reason| reason.tone == "amber") {
        "amber"
    } else if reasons.iter().any(|reason| reason.tone == "neutral") {
        "neutral"
    } else {
        "good"
    }
}

pub(super) struct HostHealthQuery<'a> {
    pub(super) live: Liveness,
    pub(super) preferences: &'a HostPreferences,
    pub(super) freshness: &'a NixFreshness,
    pub(super) kernel: Option<&'a KernelPosture>,
    pub(super) services: &'a [ServiceObservation],
    pub(super) protection: &'a FleetProtectionView,
    pub(super) now: i64,
    pub(super) nixpkgs_threshold: u32,
}

pub(super) fn host_health_view(query: HostHealthQuery<'_>) -> HostHealthView {
    let HostHealthQuery {
        live,
        preferences,
        freshness,
        kernel,
        services,
        protection,
        now,
        nixpkgs_threshold,
    } = query;
    let mut reasons = Vec::new();
    if expected_offline(preferences, services, live) {
        push_reason(&mut reasons, "Offline as expected", "good", None);
    } else {
        match live {
            Liveness::Down => push_reason(&mut reasons, "Not reporting", "bad", None),
            Liveness::Stale => push_reason(&mut reasons, "Stale heartbeat", "amber", None),
            Liveness::AwaitingFirstHeartbeat => {
                push_reason(&mut reasons, "Awaiting first heartbeat", "neutral", None);
            }
            Liveness::Live => {}
        }
    }

    if protection.run.tone != "good" && protection.run.state != "not-required" {
        push_reason(
            &mut reasons,
            format!("Backup {}", protection.run.label),
            protection.run.tone,
            protection.run.at,
        );
    }
    if let Some(check) = &protection.check {
        if check.tone != "good" {
            push_reason(&mut reasons, check.label.clone(), check.tone, check.at);
        }
    }
    if protection.restore.tone != "good" && protection.restore.state != "not-required" {
        push_reason(
            &mut reasons,
            format!("Restore {}", protection.restore.label),
            protection.restore.tone,
            protection.restore.at,
        );
    }

    let mut warnings = 0usize;
    let mut stale = 0usize;
    let mut unknown = 0usize;
    for observation in services {
        if is_nix_freshness_observation(observation)
            || appliance_probes::is_appliance_observation(observation)
        {
            continue;
        }
        match observation.state {
            ServiceObservationState::Warning => warnings += 1,
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
            ServiceObservationState::Healthy => {}
        }
    }
    if warnings > 0 {
        push_reason(
            &mut reasons,
            format!(
                "{warnings} service warning{}",
                if warnings == 1 { "" } else { "s" }
            ),
            "amber",
            None,
        );
    }
    if stale > 0 {
        push_reason(
            &mut reasons,
            format!("{stale} service stale{}", if stale == 1 { "" } else { "s" }),
            "amber",
            None,
        );
    }
    if unknown > 0 {
        push_reason(&mut reasons, "Service state unknown", "neutral", None);
    }
    if kernel_reboot_required(kernel).is_some() {
        push_reason(&mut reasons, "Restart needed", "amber", None);
    }
    if let Some(freshness_reason) = freshness_attention_reason(freshness, now, nixpkgs_threshold) {
        let tone = if freshness_reason.level == "warn" {
            "amber"
        } else {
            "neutral"
        };
        push_reason(&mut reasons, freshness_reason.label, tone, None);
    }

    let tone = worst_health_tone(&reasons);
    let down = reasons.iter().any(|reason| reason.label == "Not reporting");
    let label = match tone {
        "bad" if down => "Not reporting",
        "bad" => "Problem",
        "amber" => "Needs attention",
        "neutral" => "Unknown",
        _ => "Healthy",
    };
    let summary = headline_reason(&reasons);
    let problem_count = reasons
        .iter()
        .filter(|reason| reason.tone != "good")
        .count();
    HostHealthView {
        tone,
        label,
        summary,
        problem_count,
        reasons,
    }
}

fn utc_stamp(timestamp: i64) -> Option<(String, String)> {
    if timestamp <= 0 {
        return None;
    }
    let days = timestamp.div_euclid(86_400);
    let secs = timestamp.rem_euclid(86_400) as u32;
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    if month <= 2 {
        year += 1;
    }
    let hour = secs / 3600;
    let minute = (secs % 3600) / 60;
    let second = secs % 60;
    let iso = format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z");
    let visible = format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC");
    Some((iso, visible))
}

fn observed_time_markup(at: Option<i64>, kind: &str) -> String {
    let Some((iso, visible)) = positive_instant(at).and_then(utc_stamp) else {
        return String::new();
    };
    format!(
        r#"<time datetime="{iso}" data-{kind}-date>{visible}</time>"#,
        iso = html_escape(&iso),
        visible = html_escape(&visible),
        kind = kind,
    )
}

fn evidence_caption(kind: &str) -> Option<&'static str> {
    match kind {
        "daily-backup" => Some("Backup last success"),
        "restore" => Some("Selective restore last success"),
        _ => None,
    }
}

fn evidence_time_markup(at: Option<i64>, kind: &str) -> String {
    let Some(caption) = evidence_caption(kind) else {
        return String::new();
    };
    let Some((iso, visible)) = positive_instant(at).and_then(utc_stamp) else {
        return String::new();
    };
    format!(
        r#"<span class="protection-instant" data-{kind}-instant><span class="protection-instant-label" data-{kind}-instant-label>{caption}</span> <time datetime="{iso}" data-{kind}-date>{visible}</time></span>"#,
        kind = kind,
        caption = caption,
        iso = html_escape(&iso),
        visible = html_escape(&visible),
    )
}

fn fact_instant_attr(at: Option<i64>) -> String {
    positive_instant(at)
        .map(|stamp| stamp.to_string())
        .unwrap_or_default()
}

fn scan_age_label(note: &str) -> String {
    if note.contains("time is in the future") {
        return "time is in the future".to_string();
    }
    if let Some(pos) = note.find(" ago") {
        let tokens: Vec<&str> = note[..pos].split_whitespace().collect();
        let mut keep = 0usize;
        for token in tokens.iter().rev() {
            let starts_digit = token.chars().next().is_some_and(|c| c.is_ascii_digit());
            let unit = token
                .chars()
                .last()
                .is_some_and(|c| matches!(c, 'd' | 'h' | 'm' | 's'));
            if starts_digit && unit && token.len() >= 2 {
                keep += 1;
            } else {
                break;
            }
        }
        if keep > 0 {
            let from = tokens.len() - keep;
            return format!("{} ago", tokens[from..].join(" "));
        }
    }
    if note.contains("not yet") {
        return "not yet".to_string();
    }
    if note.contains("not recorded") || note.contains("No successful") {
        return "not recorded".to_string();
    }
    String::new()
}

fn fact_kind_label(kind: &str, card_face: bool) -> String {
    let text = match (card_face, kind) {
        (true, "daily-backup") => "Daily backup",
        (true, "restore") => "Monthly restore test",
        (_, "daily-backup") => "Backup run",
        (_, "restore") => "Selective restore",
        _ => "Repository check",
    };
    if !card_face {
        return text.to_string();
    }
    let icon = match kind {
        "daily-backup" => icons::SHIELD_CHECK,
        "restore" => icons::HISTORY,
        _ => "",
    };
    format!("{icon}{text}")
}

fn backup_aria_state(fact: &ProtectionFact) -> &'static str {
    match fact.state {
        "ok" | "healthy" => "healthy",
        "failed" => "failed",
        "stale" => "stale",
        "warning" => "warning",
        "disabled" => "disabled",
        _ => "not observed",
    }
}

fn fact_markup(
    fact: &ProtectionFact,
    kind: &str,
    href: Option<&str>,
    include_time: bool,
    scan: bool,
    card_face: bool,
    aria_label: Option<&str>,
) -> String {
    let compact = scan && !card_face;
    let at = fact_instant_attr(fact.at);
    let time = if include_time {
        observed_time_markup(fact.at, kind)
    } else {
        String::new()
    };
    let age = if compact {
        format!(
            r#"<span class="fact-age" data-{kind}-age>{age}</span>"#,
            kind = kind,
            age = html_escape(&scan_age_label(&fact.note)),
        )
    } else {
        String::new()
    };
    let note_hidden = if compact { " hidden" } else { "" };
    let body = format!(
        r#"<span class="fact-label">{label_kind}</span><strong class="fact-value {tone}" data-{kind}-label>{label}</strong>{age}<span class="fact-note" data-{kind}-note{note_hidden} title="{note}">{note}</span>{time}"#,
        label_kind = fact_kind_label(kind, card_face),
        tone = html_escape(fact.tone),
        kind = kind,
        label = html_escape(&fact.label),
        age = age,
        note_hidden = note_hidden,
        note = html_escape(&fact.note),
        time = time,
    );
    let attrs = format!(
        r#"data-{kind} data-{kind}-state="{state}" data-{kind}-tone="{tone}" data-{kind}-at="{at}""#,
        kind = kind,
        state = html_escape(fact.state),
        tone = html_escape(fact.tone),
        at = html_escape(&at),
    );
    let aria = aria_label
        .map(|label| format!(r#" aria-label="{}""#, html_escape(label)))
        .unwrap_or_default();
    match href {
        Some(href) => format!(
            r#"<a class="protection-fact {tone}" {attrs} href="{href}"{aria}>{body}</a>"#,
            tone = html_escape(fact.tone),
        ),
        None => format!(r#"<div class="protection-fact" {attrs}>{body}</div>"#),
    }
}

pub(super) fn protection_markup(
    view: &FleetProtectionView,
    host: &str,
    base: &PublicBasePath,
) -> String {
    protection_markup_surface(view, host, base, false, false)
}

/// Grid cards show the two protection facts and their short notes. Exact times
/// and the repository check stay in the hidden store the drawer already reads.
pub(super) fn protection_card_markup(
    view: &FleetProtectionView,
    host: &str,
    base: &PublicBasePath,
) -> String {
    protection_markup_surface(view, host, base, true, true)
}

fn list_age_token(at: Option<i64>, now: i64) -> String {
    let Some(at) = positive_instant(at) else {
        return String::new();
    };
    if at > now.saturating_add(BACKUP_CLOCK_SKEW_SECS) {
        return "future".to_string();
    }
    let seconds = now.saturating_sub(at).max(0);
    if seconds >= 86_400 {
        return format!("{}d", seconds / 86_400);
    }
    if seconds >= 3_600 {
        let hours = seconds / 3_600;
        let mins = (seconds % 3_600) / 60;
        return if mins == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {mins}m")
        };
    }
    if seconds >= 60 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        return if secs == 0 {
            format!("{mins}m")
        } else {
            format!("{mins}m {secs}s")
        };
    }
    format!("{seconds}s")
}

fn with_list_age(word: &str, age: &str) -> String {
    if age.is_empty() {
        word.to_string()
    } else {
        format!("{word} · {age}")
    }
}

fn list_daily_value(fact: &ProtectionFact, now: i64) -> String {
    let age = list_age_token(fact.at, now);
    match fact.state {
        "ok" => with_list_age("OK", &age),
        "failed" => "Failed".to_string(),
        "missing" => "Missing".to_string(),
        "stale" => with_list_age("Stale", &age),
        "warning" => with_list_age("Review", &age),
        "disabled" => "Disabled".to_string(),
        _ => "Not observed".to_string(),
    }
}

fn restore_passed_word(file_count: Option<u64>) -> String {
    match file_count {
        None => "Passed".to_string(),
        Some(1) => "1 file".to_string(),
        Some(count) => format!("{count} files"),
    }
}

fn list_restore_value(fact: &ProtectionFact, file_count: Option<u64>, now: i64) -> String {
    let age = list_age_token(fact.at, now);
    match fact.state {
        "passed" => with_list_age(&restore_passed_word(file_count), &age),
        "overdue" => "Overdue".to_string(),
        "failed" => "Failed".to_string(),
        "not-required" => "Not required".to_string(),
        _ => "Not observed".to_string(),
    }
}

fn list_protection_note(view: &FleetProtectionView) -> String {
    let restore_needs_note =
        view.restore_overdue || (view.restore.tone != "good" && view.run.tone == "good");
    if restore_needs_note {
        view.restore.note.clone()
    } else {
        view.run.note.clone()
    }
}

/// List rows show the same two facts as the card, in one short line each.
/// Exact times and the repository check stay in the hidden stores the drawer reads.
fn list_protection_markup(
    view: &FleetProtectionView,
    host: &str,
    base: &PublicBasePath,
    now: i64,
) -> String {
    let href = app_href(base, &format!("/backups?host={}", url_query_escape(host)));
    let check_fact = match &view.check {
        Some(check) => fact_markup(check, "backup-check", Some(&href), true, true, false, None),
        None => {
            r#"<div class="protection-fact protection-check" data-backup-check data-backup-check-state="" data-backup-check-tone="" data-backup-check-at="" hidden><span class="fact-label">Repository check</span><strong class="fact-value neutral" data-backup-check-label></strong><span class="fact-note" data-backup-check-note></span></div>"#.to_string()
        }
    };
    let backup_time = evidence_time_markup(view.run.at, "daily-backup");
    let restore_time = evidence_time_markup(view.restore.at, "restore");
    let note = list_protection_note(view);
    let daily = list_daily_value(&view.run, now);
    let restore = list_restore_value(&view.restore, view.restore_file_count, now);
    let run_at = fact_instant_attr(view.run.at);
    let restore_at = fact_instant_attr(view.restore.at);
    let producer = if view.restore.state == "not-required" {
        "not-required"
    } else if view.missing_restore_producer {
        "missing"
    } else {
        "present"
    };
    format!(
        r#"<div class="row-protection" data-protection data-selective-restore-overdue-after-secs="{overdue_after}"><a class="row-fact protection-fact {run_tone}" data-daily-backup data-daily-backup-state="{run_state}" data-daily-backup-tone="{run_tone}" data-daily-backup-at="{run_at}" href="{href}" aria-label="{aria}"><span class="row-fact-k">Daily:</span> <strong class="fact-value {run_tone}" data-daily-backup-label>{daily}</strong><span class="fact-note" data-daily-backup-note hidden title="{run_note}">{run_note}</span></a><div class="row-fact {restore_tone}" data-restore data-restore-state="{restore_state}" data-restore-tone="{restore_tone}" data-restore-at="{restore_at}" data-restore-producer="{producer}" data-restore-overdue="{overdue}"><span class="row-fact-k">Restore:</span> <strong class="fact-value {restore_tone}" data-restore-label>{restore}</strong><span class="fact-note" data-restore-note hidden title="{restore_note}">{restore_note}</span></div><small class="row-protection-note" data-row-protection-note title="{note}">{note}</small><div class="scan-store" data-protection-evidence hidden>{backup_time}{restore_time}</div><div class="scan-store" data-protection-more hidden>{check_fact}</div></div>"#,
        overdue_after = SELECTIVE_RESTORE_OVERDUE_AFTER_SECS,
        run_tone = html_escape(view.run.tone),
        run_state = html_escape(view.run.state),
        run_at = html_escape(&run_at),
        href = href,
        aria = html_escape(&format!(
            "Backup {} for {host}",
            backup_aria_state(&view.run)
        )),
        daily = html_escape(&daily),
        run_note = html_escape(&view.run.note),
        restore_tone = html_escape(view.restore.tone),
        restore_state = html_escape(view.restore.state),
        restore_at = html_escape(&restore_at),
        producer = producer,
        overdue = if view.restore_overdue {
            "true"
        } else {
            "false"
        },
        restore = html_escape(&restore),
        restore_note = html_escape(&view.restore.note),
        note = html_escape(&note),
        backup_time = backup_time,
        restore_time = restore_time,
        check_fact = check_fact,
    )
}

fn protection_markup_surface(
    view: &FleetProtectionView,
    host: &str,
    base: &PublicBasePath,
    scan: bool,
    card_face: bool,
) -> String {
    let href = app_href(base, &format!("/backups?host={}", url_query_escape(host)));
    let check_fact = match &view.check {
        Some(check) => fact_markup(
            check,
            "backup-check",
            Some(&href),
            true,
            scan,
            card_face,
            None,
        ),
        None => {
            r#"<div class="protection-fact protection-check" data-backup-check data-backup-check-state="" data-backup-check-tone="" data-backup-check-at="" hidden><span class="fact-label">Repository check</span><strong class="fact-value neutral" data-backup-check-label></strong><span class="fact-note" data-backup-check-note></span></div>"#.to_string()
        }
    };
    let check_hidden = if view.check.is_some() { "" } else { " hidden" };
    let check = if scan {
        format!(r#"<div class="scan-store" data-protection-more hidden>{check_fact}</div>"#)
    } else {
        format!(
            r#"<details class="protection-more" data-protection-more{check_hidden}><summary>Repository check</summary>{check_fact}</details>"#
        )
    };
    let producer = if view.restore.state == "not-required" {
        "not-required"
    } else if view.missing_restore_producer {
        "missing"
    } else {
        "present"
    };
    let restore_at = fact_instant_attr(view.restore.at);
    let backup_time = evidence_time_markup(view.run.at, "daily-backup");
    let restore_time = evidence_time_markup(view.restore.at, "restore");
    let evidence_hidden = if backup_time.is_empty() && restore_time.is_empty() {
        " hidden"
    } else {
        ""
    };
    let compact = scan && !card_face;
    let restore_age = if compact {
        format!(
            r#"<span class="fact-age" data-restore-age>{}</span>"#,
            html_escape(&scan_age_label(&view.restore.note))
        )
    } else {
        String::new()
    };
    let restore_note_hidden = if compact { " hidden" } else { "" };
    let restore_caption = fact_kind_label("restore", card_face);
    let evidence = if scan {
        format!(
            r#"<div class="scan-store" data-protection-evidence hidden>{backup_time}{restore_time}</div>"#
        )
    } else {
        format!(
            r#"<details class="protection-evidence" data-protection-evidence{evidence_hidden}><summary>Exact times</summary>{backup_time}{restore_time}</details>"#
        )
    };
    format!(
        r#"<div class="protection-pair" data-protection data-selective-restore-overdue-after-secs="{overdue_after}">{run}<div class="protection-fact" data-restore data-restore-state="{restore_state}" data-restore-tone="{restore_tone}" data-restore-at="{restore_at}" data-restore-producer="{producer}" data-restore-overdue="{overdue}"><span class="fact-label">{restore_caption}</span><strong class="fact-value {restore_tone}" data-restore-label>{restore_label}</strong>{restore_age}<span class="fact-note" data-restore-note{restore_note_hidden} title="{restore_note}">{restore_note}</span></div>{evidence}{check}</div>"#,
        overdue_after = SELECTIVE_RESTORE_OVERDUE_AFTER_SECS,
        run = fact_markup(
            &view.run,
            "daily-backup",
            Some(&href),
            false,
            scan,
            card_face,
            Some(&format!(
                "Backup {} for {host}",
                backup_aria_state(&view.run)
            )),
        ),
        restore_caption = restore_caption,
        restore_age = restore_age,
        restore_note_hidden = restore_note_hidden,
        check = check,
        restore_state = html_escape(view.restore.state),
        restore_tone = html_escape(view.restore.tone),
        restore_at = html_escape(&restore_at),
        producer = producer,
        overdue = if view.restore_overdue {
            "true"
        } else {
            "false"
        },
        restore_label = html_escape(&view.restore.label),
        restore_note = html_escape(&view.restore.note),
        evidence = evidence,
    )
}

pub(super) fn health_markup(health: &HostHealthView) -> String {
    let reasons = health
        .reasons
        .iter()
        .map(|reason| {
            let at = reason.at.map(|at| at.to_string()).unwrap_or_default();
            format!(
                r#"<li data-health-reason data-health-tone="{tone}" data-health-at="{at}">{label}{time}</li>"#,
                tone = html_escape(reason.tone),
                at = html_escape(&at),
                label = html_escape(&reason.label),
                time = observed_time_markup(reason.at, "health"),
            )
        })
        .collect::<String>();
    let icon = if health.problem_count == 0 {
        icons::SHIELD_CHECK
    } else {
        icons::BELL
    };
    let count_label = if health.problem_count == 1 {
        "1 reason".to_string()
    } else {
        format!("{} reasons", health.problem_count)
    };
    let scan = if health.problem_count == 0 {
        format!(
            r#"<div class="attention-line"><span class="attention-icon" aria-hidden="true">{icon}</span><span data-health-summary>{summary}</span><span class="health-count" data-health-count hidden>0</span></div><ul class="health-reasons" data-health-reasons hidden></ul>"#,
            summary = html_escape(&health.summary),
        )
    } else {
        format!(
            r#"<details class="health-disclosure" data-health-disclosure><summary class="attention-line"><span class="attention-icon" aria-hidden="true">{icon}</span><span data-health-summary>{summary}</span><span class="health-count" data-health-count>{count}</span></summary><ul class="health-reasons" data-health-reasons>{reasons}</ul></details>"#,
            summary = html_escape(&health.summary),
            count = html_escape(&count_label),
        )
    };
    format!(
        r#"<div class="harbor-health" data-health-block data-health-tone="{tone}"><span class="health-label" data-health-label data-health-tone="{tone}" hidden>{label}</span>{scan}</div>"#,
        tone = html_escape(health.tone),
        label = html_escape(health.label),
        scan = scan,
    )
}

fn card_attention_summary(health: &HostHealthView, extra: &str) -> String {
    let mut parts: Vec<String> = health
        .reasons
        .iter()
        .filter(|reason| reason.tone != "good")
        .map(|reason| reason.label.clone())
        .collect();
    if !extra.is_empty() && !parts.iter().any(|part| part == extra) {
        parts.insert(0, extra.to_string());
    }
    if parts.is_empty() {
        "No action needed".to_string()
    } else {
        parts.join(" · ")
    }
}

fn card_attention_block(
    health: &HostHealthView,
    lifecycle_chip: &str,
    chip_label: &str,
    extra: &str,
    mute: &str,
) -> String {
    let summary = card_attention_summary(health, extra);
    let title = if chip_label.is_empty() {
        summary.clone()
    } else {
        format!("{chip_label} · {summary}")
    };
    let icon = if health.problem_count == 0 && extra.is_empty() {
        icons::SHIELD_CHECK
    } else {
        icons::BELL
    };
    let reasons = health
        .reasons
        .iter()
        .map(|reason| {
            let at = reason.at.map(|at| at.to_string()).unwrap_or_default();
            format!(
                r#"<li data-health-reason data-health-tone="{tone}" data-health-at="{at}">{label}{time}</li>"#,
                tone = html_escape(reason.tone),
                at = html_escape(&at),
                label = html_escape(&reason.label),
                time = observed_time_markup(reason.at, "health"),
            )
        })
        .collect::<String>();
    let count_label = if health.problem_count == 1 {
        "1 reason".to_string()
    } else {
        format!("{} reasons", health.problem_count)
    };
    format!(
        r#"<div class="harbor-health" data-health-block data-health-tone="{tone}"><div class="attention-line" title="{title}"><span class="attention-icon" aria-hidden="true">{icon}</span>{chip}<span class="attention-sep" aria-hidden="true"> · </span><span data-health-summary>{summary}</span>{mute}<span class="health-count" data-health-count hidden>{count}</span></div><ul class="health-reasons" data-health-reasons hidden>{reasons}</ul></div>"#,
        tone = html_escape(health.tone),
        title = html_escape(&title),
        summary = html_escape(&summary),
        chip = lifecycle_chip,
        mute = mute,
        count = html_escape(&count_label),
        reasons = reasons,
    )
}

fn card_role_line(kind: HostKind, role: &str) -> String {
    let kind_label = match kind {
        HostKind::Server => "Server",
        HostKind::Workstation => "Workstation",
    };
    let role = role.trim();
    if role.is_empty()
        || role.eq_ignore_ascii_case(kind.label())
        || role.eq_ignore_ascii_case(kind_label)
    {
        return kind_label.to_string();
    }
    let lower = role.to_ascii_lowercase();
    if lower.starts_with(&kind.label().to_ascii_lowercase())
        || lower.starts_with(&kind_label.to_ascii_lowercase())
    {
        role.to_string()
    } else {
        format!("{kind_label} · {role}")
    }
}

fn ping_age_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        let mins = seconds / 60;
        let secs = seconds % 60;
        if secs == 0 {
            format!("{mins}m")
        } else {
            format!("{mins}m {secs}s")
        }
    } else {
        let hours = seconds / 3600;
        let mins = (seconds % 3600) / 60;
        if mins == 0 {
            format!("{hours}h")
        } else {
            format!("{hours}h {mins}m")
        }
    }
}

struct HeartbeatFace {
    status: String,
    tone: &'static str,
    explain: String,
}

fn heartbeat_face(
    last_seen: Option<i64>,
    now: i64,
    interval: i64,
    grace_secs: u64,
) -> HeartbeatFace {
    let Some(last) = last_seen.filter(|stamp| *stamp > 0) else {
        return HeartbeatFace {
            status: "No observations".to_string(),
            tone: "neutral",
            explain: "Awaiting first heartbeat".to_string(),
        };
    };
    let age = (now - last).max(0);
    let age_text = ping_age_label(age);
    let timing = pharos_core::heartbeat_timing(age as u64, interval.max(1) as u64, grace_secs);
    let explain = format!("Expected {interval}s + {grace_secs}s grace · last ping {age_text} ago");
    match timing {
        pharos_core::HeartbeatTiming::Down => HeartbeatFace {
            status: format!("No ping · {age_text}"),
            tone: "bad",
            explain: "Host not reporting; current state unverified".to_string(),
        },
        pharos_core::HeartbeatTiming::Late => HeartbeatFace {
            status: format!("Late · {age_text}"),
            tone: "amber",
            explain,
        },
        pharos_core::HeartbeatTiming::Stale => HeartbeatFace {
            status: format!("Stale · {age_text}"),
            tone: "amber",
            explain,
        },
        pharos_core::HeartbeatTiming::OnTime => HeartbeatFace {
            status: format!("On time · {age_text}"),
            tone: "neutral",
            explain,
        },
    }
}

pub(super) fn os_badge_markup(icon: &str, health: &HostHealthView) -> String {
    format!(
        r#"<span class="os-badge" data-health-badge data-health-tone="{tone}" role="img" aria-label="{label}"><span class="os-badge-icon" aria-hidden="true">{icon}</span></span>"#,
        tone = html_escape(health.tone),
        label = html_escape(health.label),
    )
}

pub(super) fn quick_preview_markup(name: &str, nix_icon: &str) -> String {
    format!(
        r#"<button class="preview-button" type="button" data-host-drawer-trigger aria-haspopup="dialog" aria-controls="host-quick-drawer" aria-expanded="false" title="Quick preview of {name}" aria-label="Quick preview of {name}"><span class="nix" hidden>{nix_icon}</span>{icon}<span>Quick preview</span></button>"#,
        icon = icons::PANEL_RIGHT,
    )
}

fn configuration_face_label(freshness: &NixFreshness) -> String {
    if !freshness.applicable || freshness.deployment_evidence.is_none() {
        return "Configuration not observed".to_string();
    }
    let nixpkgs_exact = matches!(
        freshness
            .nixpkgs_comparison
            .as_ref()
            .map(|comparison| comparison.relation),
        Some(NixpkgsRevisionRelation::Current)
    );
    let nixcfg_exact = matches!(
        freshness
            .nixcfg_comparison
            .as_ref()
            .map(|comparison| comparison.relation),
        Some(GitRevisionRelation::Current)
    );
    if nixpkgs_exact && nixcfg_exact {
        "Configuration exact".to_string()
    } else if freshness.nixpkgs_comparison.is_some() || freshness.nixcfg_comparison.is_some() {
        "Configuration differs".to_string()
    } else {
        "Configuration not observed".to_string()
    }
}

pub(super) fn revision_evidence_markup(freshness: &NixFreshness) -> String {
    let summary = freshness.tldr();
    let (deployed, nixcfg, nixpkgs) = match freshness.deployment_evidence.as_ref() {
        Some(evidence) => {
            let deployed: String = evidence.source_revision.chars().take(12).collect();
            let nixpkgs: String = evidence.nixpkgs_revision.chars().take(12).collect();
            let nixcfg = freshness
                .nixcfg_comparison
                .as_ref()
                .map(|comparison| comparison.upstream_revision.chars().take(12).collect())
                .unwrap_or_else(|| "unknown".to_string());
            (deployed, nixcfg, nixpkgs)
        }
        None => ("n/a".to_string(), "n/a".to_string(), "n/a".to_string()),
    };
    format!(
        r#"<div class="scan-store" data-revision-evidence hidden><span data-config-summary>{summary}</span><span data-deployed-sha>{deployed}</span><span data-nixcfg-sha>{nixcfg}</span><span data-nixpkgs-sha>{nixpkgs}</span></div>"#,
        summary = html_escape(&summary),
        deployed = html_escape(&deployed),
        nixcfg = html_escape(&nixcfg),
        nixpkgs = html_escape(&nixpkgs),
    )
}

pub(super) fn heartbeat_grace_settings_markup(fleet_grace_secs: u64, can_manage: bool) -> String {
    let disabled = if can_manage { "" } else { " disabled" };
    format!(
        r#"<div data-heartbeat-grace-settings data-grace-seconds="{seconds}" data-grace-source="fleet"><h3 class="settings-section-title" id="heartbeat-grace-title">Heartbeat grace</h3><label class="appearance-row"><span class="appearance-copy"><strong>Extra grace after expected heartbeat</strong><span id="heartbeat-grace-note">The default applies to every host without an override. Late begins after the expected interval plus this grace. Stale and down stay at two times and five times the interval.</span></span><input name="heartbeat_grace_secs" data-grace-seconds-input data-grace-saved="{seconds}" aria-label="Extra grace after expected heartbeat" aria-describedby="heartbeat-grace-note" type="number" min="0" max="3600" step="1" required value="{seconds}"{disabled}></label></div>"#,
        seconds = fleet_grace_secs,
        disabled = disabled,
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct HostGracePresentation {
    pub(super) attrs: String,
    pub(super) effective_secs: u64,
    pub(super) source: String,
    pub(super) late_after_secs: u64,
}

pub(super) fn host_grace_presentation(
    preferences: &HostPreferences,
    requested: Option<&HostPreferences>,
    fleet_grace_secs: Option<u64>,
    interval_secs: Option<u64>,
) -> HostGracePresentation {
    let policy = preferences.heartbeat_grace_policy(fleet_grace_secs, interval_secs);
    let requested_override = requested.map(|prefs| prefs.alerts.heartbeat_grace_secs);
    let pending = match requested_override {
        Some(value) if value != policy.override_secs => match value {
            Some(secs) => secs.to_string(),
            None => "inherit".to_string(),
        },
        _ => String::new(),
    };
    let override_secs = policy
        .override_secs
        .map(|secs| secs.to_string())
        .unwrap_or_default();
    let source_line = match policy.source {
        pharos_core::HeartbeatGraceSource::Host => "Override for this host".to_string(),
        pharos_core::HeartbeatGraceSource::Fleet => {
            format!("Fleet default · {} seconds", policy.fleet_secs)
        }
    };
    let rule = pharos_core::heartbeat_late_rule_copy(policy.interval_secs, policy.effective_secs);
    let pending_line = match pending.as_str() {
        "" => String::new(),
        "inherit" => "Requested change: inherit the fleet default. The live clock stays on the applied grace until the host reports it."
            .to_string(),
        secs => format!(
            "Requested override: {secs} seconds. The live clock stays on the applied grace until the host reports it."
        ),
    };
    let attrs = format!(
        r#" data-grace="{effective}" data-grace-source="{source}" data-grace-override="{override_secs}" data-grace-fleet="{fleet}" data-late-after="{late_after}" data-grace-pending="{pending}" data-grace-source-line="{source_line}" data-grace-rule="{rule}" data-grace-pending-line="{pending_line}""#,
        effective = policy.effective_secs,
        source = policy.source.as_str(),
        override_secs = html_escape(&override_secs),
        fleet = policy.fleet_secs,
        late_after = policy.late_after_secs,
        pending = html_escape(&pending),
        source_line = html_escape(&source_line),
        rule = html_escape(&rule),
        pending_line = html_escape(&pending_line),
    );
    HostGracePresentation {
        attrs,
        effective_secs: policy.effective_secs,
        source: policy.source.as_str().to_string(),
        late_after_secs: policy.late_after_secs,
    }
}

pub(super) fn host_actions_markup(
    host: &Host,
    context: HostActionRenderContext<'_>,
    action: Option<&HostActionJob>,
    lifecycle: &HostLifecycle,
) -> String {
    let capabilities = context.capabilities;
    if !capabilities.can_manage_fleet {
        return String::new();
    }
    let name = html_escape(&host.name);
    let role = html_escape(&host.role);
    let menu_id = html_escape(&format!("host-actions-{}-{}", host.name, context.surface));
    let title = html_escape(&format!("Actions for {}", host.name));
    let settings_href = html_escape(context.settings_href);
    let settings_link_title = html_escape(&format!("Open host workspace for {}", host.name));
    let settings_state_key = context.settings_state.key();
    let settings_menu_item = if context.surface == "card" {
        format!(
            r#"<a class="host-action-item" role="menuitem" tabindex="-1" data-host-action="host-settings" data-settings-state="{settings_state_key}" href="{settings_href}" title="{settings_link_title}" aria-label="{settings_link_title}">{icon}<span><strong>Open host workspace</strong><span>Settings, next action, and saved evidence</span></span></a>"#,
            icon = icons::SLIDERS,
        )
    } else {
        String::new()
    };
    let withdrawable_settings =
        withdrawable_settings_change_for_host(context.action_jobs, &host.name);
    let withdraw_settings_visible = withdrawable_settings.is_some();
    let withdraw_settings_item = withdrawable_settings
        .map_or_else(
            || {
                format!(
                    r#"<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="withdraw-settings" hidden>{history}<span><strong>Withdraw settings request</strong><span>Stops this Pharos run; it does not close an open nixcfg proposal.</span></span></button>"#,
                    history = icons::HISTORY,
                )
            },
            |job| {
                format!(
                    r#"<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="withdraw-settings" data-lifecycle-run-id="{run_id}">{history}<span><strong>Withdraw settings request</strong><span>Stops this Pharos run; it does not close an open nixcfg proposal.</span></span></button>"#,
                    run_id = html_escape(&job.id),
                    history = icons::HISTORY,
                )
            },
        );
    let update_hidden =
        if host.is_nix && capabilities.can_manage_fleet && capabilities.system_update_available {
            ""
        } else {
            " hidden"
        };
    let janus_ready = context.manifest.is_some_and(|manifest| {
        manifest.policy.privileged_actions.mode == PrivilegedActionMode::Janus
            && manifest.policy.privileged_actions.janus_required
    });
    let reboot = kernel_reboot_required(host.kernel.as_ref());
    let update_pending = reboot.is_some() || host.freshness.has_proven_deployable_update();
    let update_restart_active =
        active_update_restart_for_host(context.action_jobs, &host.name).is_some();
    let update_job_active = update_restart_active;
    let restart_hidden = if host.is_nix
        && capabilities.can_manage_fleet
        && janus_ready
        && update_pending
        && !update_job_active
        && lifecycle.slot != HostLifecycleSlot::Blocked
    {
        ""
    } else {
        " hidden"
    };
    // PHAROS-197: a removal needs the nixcfg proposal whenever it must remove a
    // declaration or record a retirement intent. Offering it without a working
    // dispatch would only produce a refusal.
    let needs_removal_proposal = context.declared || context.credential_retirement_required;
    let remove_hidden = if capabilities.can_manage_fleet
        && (!needs_removal_proposal || capabilities.host_removal_available)
    {
        ""
    } else {
        " hidden"
    };
    let lifecycle_continue = if let Some((action, run_id)) = lifecycle
        .primary_action
        .as_ref()
        .zip(lifecycle.run_id.as_ref())
    {
        format!(
            r#"<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="lifecycle-continue" data-lifecycle-run-id="{run_id}" data-lifecycle-invoke="{invoke}">{history}<span><strong>{label}</strong><span>Opens the saved workflow; only the named action advances it.</span></span></button>"#,
            run_id = html_escape(run_id),
            invoke = lifecycle.invoke.key(),
            label = html_escape(&action.label),
            history = icons::HISTORY,
        )
    } else {
        r#"<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="lifecycle-continue" hidden><span><strong>Open saved workflow</strong><span>Shows the recorded next action and its exact effect.</span></span></button>"#.to_string()
    };
    let primary_separator_hidden = if !settings_menu_item.is_empty()
        || lifecycle.primary_action.is_some() && lifecycle.run_id.is_some()
        || withdraw_settings_visible
        || update_hidden.is_empty()
        || restart_hidden.is_empty()
    {
        ""
    } else {
        " hidden"
    };
    let dot_hidden = if lifecycle.slot != HostLifecycleSlot::Quiet {
        ""
    } else {
        " hidden"
    };
    let action_attributes = action.map_or_else(String::new, |job| {
        format!(
            r#" data-action-job-id="{}" data-action-kind="{}" data-action-state="{}""#,
            html_escape(&job.id),
            job.workflow_kind().key(),
            job.state.key(),
        )
    });
    let kernel_state = host
        .kernel
        .as_ref()
        .map(|kernel| match kernel.state {
            KernelPostureState::Current => "current",
            KernelPostureState::RebootRequired => "reboot_required",
            KernelPostureState::Unknown => "unknown",
            KernelPostureState::NotApplicable => "not_applicable",
        })
        .unwrap_or("unknown");
    let running_kernel = host
        .kernel
        .as_ref()
        .and_then(|kernel| kernel.running_version.as_deref())
        .unwrap_or("not reported");
    let expected_kernel = host
        .kernel
        .as_ref()
        .and_then(|kernel| kernel.expected_version.as_deref())
        .unwrap_or("not reported");
    let deployed_revision = host
        .freshness
        .deployment_evidence
        .as_ref()
        .map(|evidence| evidence.source_revision.as_str())
        .unwrap_or("");
    let nixcfg_revision = host
        .freshness
        .nixcfg_comparison
        .as_ref()
        .map(|comparison| comparison.upstream_revision.as_str())
        .unwrap_or("");
    let nixpkgs_revision = host
        .freshness
        .deployment_evidence
        .as_ref()
        .map(|evidence| evidence.nixpkgs_revision.as_str())
        .unwrap_or("");

    format!(
        r#"<span class="host-actions" data-host-actions data-host="{name}" data-role="{role}" data-is-nix="{is_nix}" data-declared="{declared}" data-credential-retirement="{credential_retirement}" data-janus-ready="{janus_ready}" data-can-manage="{can_manage_fleet}" data-system-update-available="{system_update_available}" data-host-removal-available="{host_removal_available}" data-update-pending="{update_pending}" data-update-restart-active="{update_restart_active}" data-settings-state="{settings_state}" data-backup-state="{backup_state}" data-backup-label="{backup_label}" data-kernel-state="{kernel_state}" data-kernel-running="{running_kernel}" data-kernel-expected="{expected_kernel}" data-deployed-revision="{deployed_revision}" data-nixcfg-revision="{nixcfg_revision}" data-nixpkgs-revision="{nixpkgs_revision}"{action_attributes}><button class="header-chip host-actions-trigger" type="button" data-host-actions-trigger aria-haspopup="menu" aria-expanded="false" aria-controls="{menu_id}" title="{title}" aria-label="{title}">{ellipsis}<span class="header-chip-label" aria-hidden="true">Actions</span><span class="host-action-dot" data-host-action-dot aria-hidden="true"{dot_hidden}></span></button><span class="host-actions-menu" id="{menu_id}" role="menu" aria-label="{title}" data-host-actions-menu hidden><strong class="host-actions-title">{name}</strong>{settings_menu_item}{lifecycle_continue}{withdraw_settings_item}<button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="system-update"{update_hidden}>{package}<span><strong>Review system updates</strong><span>Builds a fleet-wide review; it does not apply or restart.</span></span></button><button class="host-action-item restart" type="button" role="menuitem" tabindex="-1" data-host-action="update-restart"{restart_hidden}>{power}<span><strong>Review update and restart</strong><span>Opens backup and validation gates before confirmation.</span></span></button><span class="host-actions-separator" data-primary-separator aria-hidden="true"{primary_separator_hidden}></span><button class="host-action-item" type="button" role="menuitem" tabindex="-1" data-host-action="technical">{file}<span><strong>View technical details</strong><span>Reads safe runtime and configuration facts only.</span></span></button><span class="host-actions-separator" data-remove-separator aria-hidden="true"{remove_hidden}></span><button class="host-action-item remove" type="button" role="menuitem" tabindex="-1" data-host-action="remove"{remove_hidden}>{trash}<span><strong>Review host removal</strong><span>Stops Pharos management; it never deletes the server.</span></span></button><span class="host-actions-safety">{shield}<span>Privileged changes always open a review first</span></span></span></span>"#,
        is_nix = host.is_nix,
        declared = context.declared,
        credential_retirement = context.credential_retirement_required,
        janus_ready = janus_ready,
        can_manage_fleet = capabilities.can_manage_fleet,
        system_update_available = capabilities.system_update_available,
        host_removal_available = capabilities.host_removal_available,
        update_pending = update_pending,
        update_restart_active = update_restart_active,
        settings_state = context.settings_state.key(),
        backup_state = html_escape(context.backup.state),
        backup_label = html_escape(&context.backup.label),
        kernel_state = html_escape(kernel_state),
        running_kernel = html_escape(running_kernel),
        expected_kernel = html_escape(expected_kernel),
        deployed_revision = html_escape(deployed_revision),
        nixcfg_revision = html_escape(nixcfg_revision),
        nixpkgs_revision = html_escape(nixpkgs_revision),
        action_attributes = action_attributes,
        withdraw_settings_item = withdraw_settings_item,
        ellipsis = icons::ELLIPSIS,
        package = icons::PACKAGE_SEARCH,
        power = icons::POWER,
        file = icons::FILE_TEXT,
        trash = icons::TRASH_2,
        shield = icons::SHIELD_CHECK,
    )
}

fn host_quick_drawer(base: &PublicBasePath, can_manage_fleet: bool) -> String {
    format!(
        r#"<div class="host-drawer-layer" data-host-drawer-layer hidden><button class="host-drawer-scrim" type="button" data-host-drawer-close tabindex="-1" aria-label="Close host overview"></button><aside class="host-drawer" id="host-quick-drawer" data-host-drawer role="dialog" aria-modal="true" aria-labelledby="host-drawer-title" aria-describedby="host-drawer-guidance" data-can-manage="{can_manage}"><header class="host-drawer-head"><span class="host-drawer-mark" data-host-drawer-mark data-health-tone="neutral">{server}</span><div class="host-title"><h2 id="host-drawer-title" data-host-drawer-title>Host</h2><p class="role" data-host-drawer-role>Not recorded</p><span class="health-label" data-host-drawer-health-label data-health-tone="neutral">Not recorded</span></div><button class="host-drawer-close" type="button" data-host-drawer-close aria-label="Close host overview">{close}</button></header><div class="host-drawer-scroll"><section class="panel host-drawer-posture" aria-labelledby="host-drawer-posture-title"><h2 id="host-drawer-posture-title" data-host-drawer-posture-title>Current observations</h2><p class="host-drawer-guidance" id="host-drawer-guidance" data-host-drawer-guidance>Not recorded</p><ul class="host-drawer-reasons" data-host-drawer-reasons><li>Not recorded</li></ul><dl class="evidence-list"><div><dt>Attention</dt><dd data-host-drawer-attention>Not recorded</dd></div><div><dt>Health</dt><dd data-host-drawer-health>Not recorded</dd></div><div><dt>Current owner</dt><dd data-host-drawer-owner>Not recorded</dd></div><div><dt>Next action</dt><dd data-host-drawer-next>Not recorded</dd></div><div><dt>Settings</dt><dd data-host-drawer-settings-state>Not recorded</dd></div><div><dt>State</dt><dd data-host-drawer-state>Not recorded</dd></div></dl></section><section class="panel" aria-label="Protection"><h2>Protection</h2><div class="protection-pair"><div class="protection-fact"><span class="fact-label">Daily backup</span><strong class="fact-value" data-host-drawer-backup>Not recorded</strong><span class="fact-note" data-host-drawer-backup-time><span data-host-drawer-backup-label data-daily-backup-instant-label>Backup last success</span> <span data-host-drawer-backup-clock>Not recorded</span></span></div><div class="protection-fact"><span class="fact-label">Monthly restore test</span><strong class="fact-value" data-host-drawer-restore>Not recorded</strong><span class="fact-note" data-host-drawer-restore-time><span data-host-drawer-restore-label data-restore-instant-label>Selective restore last success</span> <span data-host-drawer-restore-clock>Not recorded</span></span></div></div></section><section class="panel" aria-labelledby="host-drawer-heartbeat-title"><h2 id="host-drawer-heartbeat-title">Heartbeat history</h2><div class="host-drawer-history" data-host-drawer-history><p>Not recorded</p></div></section><section class="panel" aria-label="Configuration"><h2>Configuration</h2><dl class="evidence-list"><div><dt>Deployed revision</dt><dd data-host-drawer-deployed>Not recorded</dd></div><div><dt>nixpkgs</dt><dd data-host-drawer-nixpkgs>Not recorded</dd></div><div><dt>nixcfg</dt><dd data-host-drawer-nixcfg>Not recorded</dd></div><div><dt>Summary</dt><dd data-host-drawer-config>Not recorded</dd></div><div><dt>Late-ping grace</dt><dd data-host-drawer-grace>Not recorded</dd></div></dl></section><form class="panel host-drawer-draft" data-host-drawer-draft><div class="host-drawer-section-head"><div><span class="host-drawer-kicker">Quick settings</span><h3>Prepare a local draft</h3></div><span class="host-drawer-local">Not sent</span></div><p>These values stay in this drawer until you choose review. Closing or discarding removes the draft completely.</p><div class="host-drawer-fields"><label class="host-drawer-color"><span>Host color</span><input type="color" data-host-drawer-color aria-label="Draft host color"></label><label><span>Host type</span><select data-host-drawer-kind><option value="server">Server</option><option value="workstation">Workstation</option></select></label></div><fieldset class="host-drawer-alerts"><legend>Alert preferences</legend><label><span><strong>Down alerts</strong><small>Warn when the host stops reporting.</small></span><input type="checkbox" data-host-drawer-alert="down"></label><label><span><strong>Backup warnings</strong><small>Warn when backup evidence needs attention.</small></span><input type="checkbox" data-host-drawer-alert="backup"></label><label><span><strong>Nix freshness</strong><small>Warn when the host falls behind nixcfg.</small></span><input type="checkbox" data-host-drawer-alert="nix"></label></fieldset><p class="host-drawer-draft-status" data-host-drawer-draft-status role="status" aria-live="polite">Change a setting to prepare a review.</p><div class="host-drawer-buttons"><button class="secondary-action" type="button" data-host-drawer-discard disabled>Discard draft</button><button class="primary-action" type="submit" data-host-drawer-review disabled>Review settings</button></div><p class="host-drawer-effect">Opens the draft in this host workspace; it does not send or apply changes.</p><section class="host-drawer-grace" data-host-grace aria-label="Heartbeat grace"><h3>Heartbeat grace</h3><p data-grace-source-line>Not recorded</p><p data-grace-rule>Not recorded</p><p data-grace-pending hidden>Not recorded</p><div class="host-drawer-grace-controls"><label>Source <select data-grace-mode{grace_disabled}><option value="inherit">Fleet default</option><option value="override">Override for this host</option></select></label><label>Extra grace after expected heartbeat <input data-grace-seconds-input type="number" min="0" max="3600" step="1" inputmode="numeric"{grace_disabled}></label><button type="button" data-grace-reset{grace_disabled}>Use fleet default</button></div><p>Use fleet default asks this host to inherit the fleet grace. Review that change with the other settings, then apply it. Until the host reports the result, the clock keeps the grace already in effect. A chosen number is an override for this host only.</p></section><p class="host-drawer-viewer" data-host-drawer-viewer{viewer_hidden}>Fleet operator access is required to prepare a settings draft.</p></form><a class="host-drawer-workspace" data-host-drawer-workspace href="{home}">Open full host page {arrow}</a><section class="panel host-drawer-evidence" aria-label="Repository check"><h2>Repository check</h2><p data-host-drawer-check>Not recorded</p></section></div></aside></div>"#,
        can_manage = can_manage_fleet,
        grace_disabled = if can_manage_fleet { "" } else { " disabled" },
        server = icons::SERVER,
        close = icons::X,
        arrow = icons::ARROW_RIGHT,
        home = app_href(base, "/"),
        viewer_hidden = if can_manage_fleet { " hidden" } else { "" },
    )
}

pub(crate) fn host_action_dialog() -> String {
    format!(
        r#"<section class="host-action-overlay" data-host-action-overlay hidden><span class="host-action-backdrop" data-host-action-close aria-hidden="true"></span><section class="host-action-dialog" data-host-action-dialog role="dialog" aria-modal="true" aria-labelledby="host-action-title" aria-describedby="host-action-copy"><header class="host-action-dialog-head"><div class="host-action-heading"><span data-action-icon="system-update">{package}</span><span data-action-icon="update-restart" hidden>{power}</span><span data-action-icon="settings-change" hidden>{sliders}</span><span data-action-icon="technical" hidden>{file}</span><span data-action-icon="remove" hidden>{trash}</span><div><h2 id="host-action-title" data-host-action-title>Host action</h2></div></div><button class="host-action-dialog-close" type="button" data-host-action-close aria-label="Close host action">{close}</button></header><div class="host-action-dialog-body"><p id="host-action-copy" data-host-action-copy></p><div class="host-action-info" data-host-action-info>{shield}<strong data-host-action-info-title>Review first</strong><span data-host-action-info-copy>No privileged or destructive work happens from the menu click.</span></div><div class="host-action-facts" data-host-action-facts><div class="host-action-fact"><span>Host</span><strong data-host-action-fact="host"></strong></div><div class="host-action-fact" data-host-action-fact-row="state"><span>Status</span><strong data-host-action-fact="state"></strong></div><div class="host-action-fact" data-host-action-fact-row="declared"><span>Declared</span><strong data-host-action-fact="declared"></strong></div><div class="host-action-fact" data-host-action-fact-row="observed"><span>Observed</span><strong data-host-action-fact="observed"></strong></div><div class="host-action-fact" data-host-action-fact-row="backup"><span>Backup</span><strong data-host-action-fact="backup"></strong></div><div class="host-action-fact" data-host-action-fact-row="kernel"><span>Kernel</span><strong data-host-action-fact="kernel"></strong></div><div class="host-action-fact" data-host-action-fact-row="scope"><span>Scope</span><strong data-host-action-fact="scope"></strong></div></div><div class="host-workflow" data-host-workflow hidden></div><pre class="host-action-technical" data-host-action-technical hidden></pre><label class="host-remove-disposition" data-host-remove-disposition-field hidden><span>What happened to this host?</span><select data-host-remove-disposition><option value="">Choose one</option><option value="destroyed">It no longer exists</option><option value="unmanaged">It still exists; stop managing it</option><option value="rebuilt">It was replaced by another host</option></select></label><label class="host-remove-successor" data-host-remove-successor hidden><span>Successor host name</span><input type="text" autocomplete="off" spellcheck="false" data-host-remove-successor-input><small>Onboard the successor in Pharos first.</small></label><label class="host-remove-confirm" data-host-remove-confirm hidden><span data-host-confirm-copy>Type <strong data-host-remove-name></strong> to confirm</span><input type="text" autocomplete="off" spellcheck="false" data-host-remove-input></label><label class="host-attended-confirm" data-host-attended-confirm hidden><input type="checkbox" data-host-attended-input><span>I am near this host or its recovery console and can intervene if it does not return.</span></label><p class="host-action-status" data-host-action-status role="status" aria-live="polite"></p></div><footer class="host-action-dialog-foot"><span class="host-action-safe-note">{shield}<span data-host-action-safe-note>Reviewable and recorded</span></span><span class="host-action-dialog-buttons"><button class="host-action-dialog-button primary" type="button" data-host-action-primary>Review action</button><button class="host-action-dialog-button" type="button" data-host-action-cancel hidden>Withdraw run</button><button class="host-action-dialog-button" type="button" data-host-action-close>Close</button></span></footer></section></section>"#,
        package = icons::PACKAGE_SEARCH,
        power = icons::POWER,
        sliders = icons::SLIDERS,
        file = icons::FILE_TEXT,
        trash = icons::TRASH_2,
        close = icons::X,
        shield = icons::SHIELD_CHECK,
    )
}

pub(super) fn backup_search_text(summary: &BackupUiSummary) -> Option<String> {
    (summary.total > 0).then(|| {
        format!(
            "{} {} {} {} {} {}",
            summary.label,
            summary.detail,
            summary.last_success,
            summary.schedule,
            summary.target,
            summary.validation
        )
    })
}

pub(super) const FIRST_BACKUP_PENDING_GRACE_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone)]
pub(super) struct ProtectionOnboardingStatus {
    state: &'static str,
    level: &'static str,
    label: String,
    detail: String,
    sort_time: i64,
}

impl ProtectionOnboardingStatus {
    fn search_text(&self) -> String {
        format!("{} {} {}", self.state, self.label, self.detail)
    }
}

pub(super) fn protection_setup_job_for_host<'a>(
    host_name: &str,
    jobs: &'a [ProvisioningJob],
) -> Option<&'a ProvisioningJob> {
    jobs.iter()
        .filter(|job| {
            !matches!(
                job.state,
                ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded
            ) && !provisioning_job_rolled_back(job)
                && provisioning_job_host_name(job).is_some_and(|name| name == host_name)
        })
        .max_by_key(|job| job.updated_at)
}

pub(super) fn first_runtime_seen_at(host: &Host, job: &ProvisioningJob) -> i64 {
    host.heartbeat_log
        .iter()
        .copied()
        .filter(|stamp| *stamp >= job.created_at)
        .min()
        .or(host.last_seen)
        .unwrap_or(job.updated_at)
}

pub(super) fn backup_observation_success_at(observation: &BackupObservation) -> Option<i64> {
    if observation.state == BackupPostureState::Healthy
        || observation.last_attempt_state == Some(pharos_core::BackupRunState::Succeeded)
        || observation.last_success_at.is_some()
    {
        return observation
            .last_success_at
            .or(observation.last_attempt_at)
            .or(observation.last_check_at);
    }
    None
}

pub(super) fn protection_onboarding_status(
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) -> Option<ProtectionOnboardingStatus> {
    let job = protection_setup_job_for_host(&host.name, jobs)?;
    let intent = provisioning_job_setup_intent(job);
    let first_seen = first_runtime_seen_at(host, job);

    if let Some(failed) = host.backup_observations.iter().find(|observation| {
        matches!(
            observation.state,
            BackupPostureState::Failed | BackupPostureState::Missing
        ) || observation.last_attempt_state == Some(pharos_core::BackupRunState::Failed)
    }) {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-failed",
            level: "critical",
            label: "First backup failed".to_string(),
            detail: failed.summary.clone(),
            sort_time: failed
                .last_attempt_at
                .or(failed.last_check_at)
                .unwrap_or(now),
        });
    }

    if let Some(review) = host.backup_observations.iter().find(|observation| {
        matches!(
            observation.state,
            BackupPostureState::Stale | BackupPostureState::Warning
        )
    }) {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-review",
            level: "warning",
            label: "First backup needs review".to_string(),
            detail: review.summary.clone(),
            sort_time: backup_sort_time(host, review, now),
        });
    }

    if let Some(success_at) = host
        .backup_observations
        .iter()
        .filter_map(backup_observation_success_at)
        .max()
    {
        return Some(ProtectionOnboardingStatus {
            state: "first-backup-succeeded",
            level: "clear",
            label: "First backup succeeded".to_string(),
            detail: format!(
                "Successful backup observed {} ago",
                duration_label(now - success_at)
            ),
            sort_time: success_at,
        });
    }

    match intent.backup {
        BackupSetupIntent::Required => {
            let age = now.saturating_sub(first_seen);
            if age > FIRST_BACKUP_PENDING_GRACE_SECS {
                Some(ProtectionOnboardingStatus {
                    state: "first-backup-overdue",
                    level: "warning",
                    label: "First backup overdue".to_string(),
                    detail: format!(
                        "No successful backup after {} from first heartbeat",
                        duration_label(FIRST_BACKUP_PENDING_GRACE_SECS)
                    ),
                    sort_time: first_seen + FIRST_BACKUP_PENDING_GRACE_SECS,
                })
            } else {
                Some(ProtectionOnboardingStatus {
                    state: "first-backup-pending",
                    level: "watch",
                    label: "First backup pending".to_string(),
                    detail: "First heartbeat seen; waiting for backup evidence".to_string(),
                    sort_time: first_seen,
                })
            }
        }
        BackupSetupIntent::Optional => Some(ProtectionOnboardingStatus {
            state: "backup-optional",
            level: "clear",
            label: "Backup optional".to_string(),
            detail: "Not required to finish onboarding".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::External => Some(ProtectionOnboardingStatus {
            state: "backup-external",
            level: "watch",
            label: "Managed elsewhere".to_string(),
            detail: "External evidence will appear when detected".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::EnrollLater => Some(ProtectionOnboardingStatus {
            state: "backup-enroll-later",
            level: "watch",
            label: "Backup enrollment queued".to_string(),
            detail: "Follow up after onboarding is stable".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::Absent => Some(ProtectionOnboardingStatus {
            state: "backup-absent",
            level: "clear",
            label: "Backups intentionally absent".to_string(),
            detail: "Host is recorded as intentionally unprotected".to_string(),
            sort_time: job.updated_at,
        }),
        BackupSetupIntent::Deferred => Some(ProtectionOnboardingStatus {
            state: "backup-deferred",
            level: "watch",
            label: "Backup decision pending".to_string(),
            detail: "Ask again before closing onboarding".to_string(),
            sort_time: job.updated_at,
        }),
    }
}

pub(super) fn protection_onboarding_markup(
    status: &ProtectionOnboardingStatus,
    extra_class: &str,
) -> String {
    let extra_class = if extra_class.is_empty() {
        String::new()
    } else {
        format!(" {}", html_escape(extra_class))
    };
    format!(
        r#"<div class="protection-onboard{extra_class} {level}" data-protection-state="{state}" title="{title}"><strong>{label}</strong><span>{detail}</span></div>"#,
        extra_class = extra_class,
        level = html_escape(status.level),
        state = html_escape(status.state),
        title = html_escape(&format!(
            "Protection onboarding: {} - {}",
            status.label, status.detail
        )),
        label = html_escape(&status.label),
        detail = html_escape(&status.detail)
    )
}

pub(super) fn protection_onboarding_alert(
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) -> Option<AlertItem> {
    let status = protection_onboarding_status(host, jobs, now)?;
    if status.level == "clear" {
        return None;
    }
    let action = match status.state {
        "first-backup-overdue" => "Inspect backup enrollment and run or observe the first backup.",
        "first-backup-failed" => "Fix the backup job, then confirm the next successful run.",
        "first-backup-review" => "Review backup evidence before closing onboarding.",
        "first-backup-pending" => "Keep onboarding open until the first backup is observed.",
        "backup-deferred" => "Choose whether this host should be protected.",
        "backup-enroll-later" => "Schedule or start backup enrollment after the host is stable.",
        "backup-external" => "Confirm external backup evidence can be observed when available.",
        _ => "Review protection onboarding.",
    };
    Some(AlertItem {
        level: status.level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: status.label,
        detail: status.detail,
        source: "setup",
        seen: format!("as of {}", clock_label(now)),
        next_action: action.to_string(),
        sort_time: status.sort_time,
    })
}

pub(super) fn push_protection_onboarding_activity(
    events: &mut Vec<ActivityEvent>,
    host: &Host,
    jobs: &[ProvisioningJob],
    now: i64,
) {
    let Some(status) = protection_onboarding_status(host, jobs, now) else {
        return;
    };
    let level = match status.level {
        "clear" => "recovery",
        level => level,
    };
    events.push(ActivityEvent::new(
        status.sort_time,
        host.name.clone(),
        level,
        "setup",
        status.label,
        status.detail,
        "setup",
    ));
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub(super) struct ServerProbeObservation {
    pub(super) id: String,
    pub(super) service: String,
    pub(super) source: &'static str,
    pub(super) policy: &'static str,
    pub(super) kind: &'static str,
    pub(super) target: Option<String>,
    pub(super) state: ServiceObservationState,
    pub(super) server_reachable: Option<bool>,
    pub(super) client_reachable: Option<bool>,
    pub(super) summary: String,
    pub(super) checked_at: i64,
}

pub(super) async fn server_probe_overlays(
    manifests: &[HostManifest],
    now: i64,
    http_probes: Option<&HttpProbeRuntime>,
) -> BTreeMap<String, Vec<ServerProbeObservation>> {
    let mut overlays = http_probes
        .map(|runtime| runtime.snapshot(now))
        .unwrap_or_default();
    let allowed_hosts: BTreeSet<&str> = manifests
        .iter()
        .map(|manifest| manifest.host.name.as_str())
        .collect();
    overlays.retain(|host, _| allowed_hosts.contains(host.as_str()));
    for manifest in manifests {
        let observations = overlays.entry(manifest.host.name.clone()).or_default();
        for service in &manifest.services {
            let is_declared_http_probe = http_probes
                .is_some_and(|runtime| runtime.declares(&manifest.host.name, &service.name));
            if !is_declared_http_probe && should_server_probe(service) {
                observations.push(server_probe_service(service, now).await);
            }
        }
        observations.sort_by(|left, right| left.id.cmp(&right.id));
    }
    overlays.retain(|_, observations| !observations.is_empty());
    overlays
}

pub(super) async fn server_probe_service(
    service: &ManifestService,
    now: i64,
) -> ServerProbeObservation {
    let Some(raw_url) = server_probe_url(service) else {
        return server_probe_observation(
            service,
            None,
            ServiceObservationState::Unknown,
            None,
            "no server-probe URL declared".to_string(),
            now,
        );
    };

    let url = match Url::parse(&raw_url) {
        Ok(url) => url,
        Err(_) => {
            return server_probe_observation(
                service,
                Some(raw_url),
                ServiceObservationState::Unknown,
                None,
                "server-probe URL is invalid".to_string(),
                now,
            );
        }
    };
    let target = sanitized_probe_target(&url);

    if !matches!(url.scheme(), "http" | "https") {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server probe supports http/https targets only".to_string(),
            now,
        );
    }

    let Some(host) = url.host_str() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no host".to_string(),
            now,
        );
    };
    let Some(port) = url.port_or_known_default() else {
        return server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Unknown,
            None,
            "server-probe URL has no port".to_string(),
            now,
        );
    };

    match timeout(SERVER_PROBE_TIMEOUT, TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Healthy,
            Some(true),
            format!("server can reach {host}:{port}"),
            now,
        ),
        Ok(Err(_)) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server cannot reach {host}:{port}"),
            now,
        ),
        Err(_) => server_probe_observation(
            service,
            Some(target),
            ServiceObservationState::Warning,
            Some(false),
            format!("server probe timed out for {host}:{port}"),
            now,
        ),
    }
}

pub(super) fn server_probe_observation(
    service: &ManifestService,
    target: Option<String>,
    state: ServiceObservationState,
    server_reachable: Option<bool>,
    summary: String,
    checked_at: i64,
) -> ServerProbeObservation {
    ServerProbeObservation {
        id: service_probe_id(service),
        service: service.name.clone(),
        source: "server",
        policy: "pharos-runtime",
        kind: "tcp-connect",
        target,
        state,
        server_reachable,
        client_reachable: None,
        summary,
        checked_at,
    }
}

pub(super) fn should_server_probe(service: &ManifestService) -> bool {
    explicit_server_probe_policy_opt(service.probe.as_ref())
        || (service.status_policy.source == ManifestStatusSource::PharosRuntime
            && !service.passive
            && server_probe_url(service).is_some())
}

pub(super) fn explicit_server_probe_policy_opt(policy: Option<&ManifestProbePolicy>) -> bool {
    policy.is_some_and(explicit_server_probe_policy)
}

pub(super) fn explicit_server_probe_policy(policy: &ManifestProbePolicy) -> bool {
    match policy {
        ManifestProbePolicy::Named(name) => matches!(
            name.trim().to_ascii_lowercase().as_str(),
            "server" | "server-probe" | "pharos" | "pharos-runtime"
        ),
        ManifestProbePolicy::Enabled(_) => false,
    }
}

pub(super) fn server_probe_url(service: &ManifestService) -> Option<String> {
    ["tailnet", "lanHostname", "lanIp"]
        .into_iter()
        .find_map(|key| service.urls.get(key).filter(|url| !url.is_empty()).cloned())
        .or_else(|| service.url.as_ref().filter(|url| !url.is_empty()).cloned())
}

pub(super) fn sanitized_probe_target(url: &Url) -> String {
    let host = url.host_str().unwrap_or("unknown");
    let port = url
        .port()
        .map(|port| format!(":{port}"))
        .unwrap_or_default();
    let path = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    format!("{}://{host}{port}{path}", url.scheme())
}

pub(super) fn server_probe_summary(observations: &[ServerProbeObservation]) -> serde_json::Value {
    let mut healthy = 0;
    let mut warning = 0;
    let mut unreachable = 0;
    let mut stale = 0;
    let mut unknown = 0;
    for observation in observations {
        match observation.state {
            ServiceObservationState::Healthy => healthy += 1,
            ServiceObservationState::Warning => {
                warning += 1;
                if observation.server_reachable == Some(false) {
                    unreachable += 1;
                }
            }
            ServiceObservationState::Stale => stale += 1,
            ServiceObservationState::Unknown => unknown += 1,
        }
    }
    let unhealthy = warning - unreachable;
    let label = if observations.is_empty() {
        "not probed".to_string()
    } else if unreachable > 0 && unhealthy > 0 {
        format!("{unreachable} unreachable, {unhealthy} unhealthy")
    } else if unreachable > 0 {
        format!("{unreachable} unreachable")
    } else if unhealthy > 0 {
        format!("{unhealthy} unhealthy")
    } else if stale > 0 {
        format!("{stale} stale")
    } else if unknown > 0 {
        format!("{unknown} unknown")
    } else {
        "server reachable".to_string()
    };
    json!({
        "label": label,
        "healthy": healthy,
        "warning": warning,
        "stale": stale,
        "unknown": unknown,
    })
}

pub(super) fn service_probe_id(service: &ManifestService) -> String {
    let mut id = String::new();
    for ch in service.name.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_alphanumeric() {
            id.push(ch);
        } else if !id.ends_with('-') {
            id.push('-');
        }
    }
    id.trim_matches('-').to_string()
}

pub(super) fn attention_reason(
    live: Liveness,
    freshness: &NixFreshness,
    kernel: Option<&KernelPosture>,
    observations: &[ServiceObservation],
    preferences: &HostPreferences,
    now: i64,
    fleet_threshold: u32,
) -> AttentionReason {
    // The observation can only be published after startup validates the
    // server-owned appliance registry against an existing host record and its
    // declared workstation preference. Beacon reports cannot claim this ID.
    let appliance = observations
        .iter()
        .find(|observation| appliance_probes::is_appliance_observation(observation));
    // Appliance hosts intentionally have no beacon. Their fixed server-side
    // presence/convergence observation owns operational liveness, so a missing
    // heartbeat must not mask a real un-converged warning or create noise while
    // the appliance is powered off.
    let heartbeat_live = if appliance.is_some() {
        Liveness::Live
    } else {
        live
    };
    match heartbeat_live {
        Liveness::Down if preferences.kind != HostKind::Workstation => AttentionReason {
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
        Liveness::Down | Liveness::Live => kernel_reboot_required(kernel)
            .map(|_| AttentionReason {
                label: "restart needed".to_string(),
                level: "warn",
                rank: 2,
            })
            .or_else(|| {
                (!preferences.alerts.suppress_nix_freshness)
                    .then(|| {
                        freshness_attention_reason(
                            freshness,
                            now,
                            preferences.nixpkgs_warn_after_days(Some(fleet_threshold)),
                        )
                    })
                    .flatten()
            })
            .or_else(|| {
                // The dedicated freshness policy already handled this signal.
                // Old beacons also emit a coarse binary freshness observation;
                // counting it as a service fault would bypass the age threshold.
                service_observation_attention_reason(observations)
            })
            .unwrap_or_else(|| AttentionReason {
                label: if appliance
                    .is_some_and(|observation| observation.summary == "powered off as expected")
                {
                    "offline as expected"
                } else if appliance.is_some_and(|observation| {
                    observation
                        .summary
                        .starts_with("online; allowing SSH startup")
                }) {
                    "starting normally"
                } else if live == Liveness::Down {
                    if preferences.kind == HostKind::Workstation {
                        "offline as expected"
                    } else {
                        "silent heartbeat"
                    }
                } else {
                    "all clear"
                }
                .to_string(),
                level: "ok",
                rank: 4,
            }),
    }
}

fn scan_attention_hidden(label: &str, kernel_required: bool, duplicate_freshness: bool) -> bool {
    kernel_required || duplicate_freshness || label == "all clear"
}

pub(super) fn reason_markup(reason: &AttentionReason, hidden: bool) -> String {
    let hidden = if hidden { " hidden" } else { "" };
    format!(
        r#"<div class="reason {}" data-reason{hidden}><span>{}</span></div>"#,
        html_escape(reason.level),
        html_escape(&reason.label),
    )
}

pub(super) fn muted_preferences_markup(preferences: &HostPreferences) -> String {
    let mut muted = Vec::new();
    let workstation = preferences.kind == HostKind::Workstation;
    if !workstation && preferences.alerts.suppress_down {
        muted.push("down");
    }
    if preferences.alerts.suppress_backup {
        muted.push("backup");
    }
    if preferences.alerts.suppress_nix_freshness {
        muted.push("Nix freshness");
    }
    let label = if workstation {
        if muted.is_empty() {
            "down alerts off for workstation".to_string()
        } else {
            format!(
                "down alerts off for workstation · {} muted",
                muted.join(", ")
            )
        }
    } else if muted.is_empty() {
        String::new()
    } else {
        format!("{} muted", muted.join(", "))
    };
    format!(
        r#"<div class="mute-note" data-mute-note title="{label}"{hidden}>{icon}<span>{label}</span></div>"#,
        label = html_escape(&label),
        hidden = if label.is_empty() { " hidden" } else { "" },
        icon = icons::BELL_OFF,
    )
}

pub(super) fn live_key(live: Liveness) -> &'static str {
    match live {
        Liveness::Live => "live",
        Liveness::Stale => "stale",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "awaiting_first_heartbeat",
    }
}

pub(super) fn duration_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, (seconds % 3600) / 60)
    }
}

pub(super) fn clock_label(timestamp: i64) -> String {
    let seconds = timestamp.rem_euclid(86_400);
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        (seconds % 3600) / 60,
        seconds % 60
    )
}

pub(super) fn summary_cards(hosts: &[Host], _self_name: &str, now: i64) -> String {
    let total = hosts.len();
    let mut live = 0;
    let mut stale = 0;
    let mut down = 0;
    for h in hosts {
        let live_state = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        match live_state {
            Liveness::Live => live += 1,
            Liveness::Stale => stale += 1,
            Liveness::Down => down += 1,
            Liveness::AwaitingFirstHeartbeat => {}
        }
    }
    format!(
        r#"<section class="summary" aria-label="host summary"><button class="metric" type="button" data-live-filter="all" aria-pressed="true"><b data-summary-count="all">{total}</b><span>All hosts</span></button><button class="metric live" type="button" data-live-filter="live" aria-pressed="false"><b data-summary-count="live">{live}</b><span>Live</span></button><button class="metric stale" type="button" data-live-filter="stale" aria-pressed="false"><b data-summary-count="stale">{stale}</b><span>Stale</span></button><button class="metric down" type="button" data-live-filter="down" aria-pressed="false"><b data-summary-count="down">{down}</b><span>Down</span></button></section>"#
    )
}

pub(super) fn sidebar_user_label(auth: &AuthState, headers: &HeaderMap) -> String {
    auth.current_user(headers)
        .map(|user| user.display_name)
        .unwrap_or_else(|| {
            if auth.human_configured() {
                "signed in".to_string()
            } else {
                "local access".to_string()
            }
        })
}

pub(super) fn sidebar(
    base: &PublicBasePath,
    user_label: &str,
    logout_enabled: bool,
    active: &str,
) -> String {
    let logout = if logout_enabled {
        format!(
            r#"<form class="side-logout-form" action="{logout}" method="post" data-logout-form><input type="hidden" name="csrf" value="" data-logout-csrf><button class="side-logout" type="submit" title="Log out of Pharos" aria-label="Log out of Pharos">{}</button></form>"#,
            icons::LOG_OUT,
            logout = app_href(base, "/auth/logout"),
        )
    } else {
        String::new()
    };
    let fleet_current = if active == "fleet" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let map_current = if active == "map" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let alerts_current = if active == "alerts" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let backups_current = if active == "backups" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let activity_current = if active == "activity" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let services_current = if active == "services" {
        r#" aria-current="page""#
    } else {
        ""
    };
    let platform_settings_current = if active == "platform-settings" {
        r#" aria-current="page""#
    } else {
        ""
    };
    format!(
        r##"<aside class="sidebar" aria-label="primary navigation" data-sidebar data-sidebar-still="true"><div class="sidebar-motion" aria-hidden="true"><video data-sidebar-motion data-src="{motion}" muted loop playsinline preload="none" tabindex="-1"></video></div><div class="side-brand"><span class="side-mark">{lighthouse}</span><span class="side-logo">PHAROS</span></div><nav class="side-nav"><a class="side-link" href="{home}"{fleet_current}>{fleet}<span>Fleet</span></a><a class="side-link" href="{map_href}"{map_current}>{map}<span>Map</span></a><a class="side-link" href="{alerts_href}"{alerts_current}>{alerts}<span>Alerts</span></a><a class="side-link" href="{backups_href}"{backups_current}>{backups}<span>Backups</span></a><a class="side-link" href="{services_href}"{services_current}>{services}<span>Services</span></a><a class="side-link" href="{activity_href}"{activity_current}>{activity}<span>Activity</span></a><a class="side-link" href="{settings_href}"{platform_settings_current}>{platform_settings}<span>Settings</span></a></nav><div class="side-bottom"><button class="side-version" type="button" data-release-open title="Open release history" aria-label="Open release history">{history}<span>{version}</span></button><div class="side-foot"><span class="side-user" title="{user_title}"><span>{user_label}</span></span>{logout}</div></div></aside>{release_dialog}{release_portal}{logout_csrf}{sidebar_motion}"##,
        lighthouse = icons::LIGHTHOUSE,
        fleet = icons::GRID,
        map = icons::SERVER,
        alerts = icons::status_svg(Liveness::Stale),
        backups = icons::SHIELD_CHECK,
        services = icons::KEY_ROUND,
        activity = icons::LIST,
        platform_settings = icons::SETTINGS,
        history = icons::HISTORY,
        version = release_label_html(false),
        release_dialog = release_dialog(),
        release_portal = RELEASE_HISTORY_PORTAL,
        logout_csrf = LOGOUT_CSRF_RUNTIME,
        sidebar_motion = SIDEBAR_MOTION_RUNTIME,
        fleet_current = fleet_current,
        map_current = map_current,
        alerts_current = alerts_current,
        backups_current = backups_current,
        services_current = services_current,
        activity_current = activity_current,
        platform_settings_current = platform_settings_current,
        user_label = html_escape(user_label),
        user_title = html_escape(user_label),
        logout = logout,
        motion = app_href(base, "/assets/sidebar-lighthouse-motion-v1.mp4"),
        home = app_href(base, "/"),
        map_href = app_href(base, "/map"),
        alerts_href = app_href(base, "/alerts"),
        backups_href = app_href(base, "/backups"),
        services_href = app_href(base, "/services"),
        activity_href = app_href(base, "/activity"),
        settings_href = app_href(base, "/settings/providers"),
    )
}

pub(super) fn page_header(title: &str, subtitle: &str, now: i64) -> String {
    format!(
        r#"<div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>{title}</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">{subtitle}</p></div><div class="asof" data-as-of>as of {as_of}</div></div>"#,
        title = html_escape(title),
        subtitle = html_escape(subtitle),
        as_of = clock_label(now)
    )
}

pub(super) fn provider_icon(key: &str) -> &'static str {
    match key {
        "hetzner-cloud" => icons::CLOUD,
        "netcup" => icons::SHOPPING_CART,
        "aws" => icons::BOX,
        "google-cloud" => icons::HEXAGON,
        "oracle-cloud" => icons::DATABASE,
        _ => icons::SERVER,
    }
}

pub(super) fn render_provider_connection_row(
    provider: &ProviderConnectionSummary,
    can_manage: bool,
    base: &PublicBasePath,
) -> String {
    let action = if can_manage {
        format!(
            r#"<a class="provider-action" href="{href}">{label}</a>"#,
            href = app_href(base, provider.detail_href),
            label = html_escape(provider.action_label),
        )
    } else {
        r#"<span class="provider-action-muted">Ask an administrator</span>"#.to_string()
    };
    format!(
        r#"<article class="provider-row" data-provider="{key}" data-provider-state="{state}"><span class="provider-mark" aria-hidden="true">{icon}</span><span class="provider-copy"><strong>{name}</strong><span>{description}</span></span><span class="provider-capability">{capability}</span><span class="provider-state" title="{note}">{state_label}</span>{action}</article>"#,
        key = html_escape(provider.key),
        state = match provider.state {
            ProviderConnectionState::Ready => "ready",
            ProviderConnectionState::NeedsAttention => "needs-attention",
            ProviderConnectionState::NotConnected => "not-connected",
            ProviderConnectionState::Guided => "guided",
        },
        icon = provider_icon(provider.key),
        name = html_escape(provider.name),
        description = html_escape(provider.description),
        capability = html_escape(provider.capability.label()),
        state_label = html_escape(provider.state_label),
        note = html_escape(&provider.note),
        action = action,
    )
}

pub(super) fn render_provider_connections_page(
    providers: &ProviderConnectionsPayload,
    shell: ShellContext<'_>,
    can_manage: bool,
    fleet_settings: fleet_settings::FleetSettings,
) -> String {
    let access_path = if can_manage {
        String::new()
    } else {
        viewer_access_path(shell.public_base_path, "provider")
    };
    let rows = providers
        .providers
        .iter()
        .map(|provider| {
            render_provider_connection_row(provider, can_manage, shell.public_base_path)
        })
        .collect::<String>();
    let disabled = if can_manage { "" } else { " disabled" };
    let grace = heartbeat_grace_settings_markup(fleet_settings.heartbeat_grace_secs, can_manage);
    let fleet_policy = format!(
        r#"<section class="appearance-settings" aria-labelledby="fleet-freshness-title"><h2 class="settings-section-title" id="fleet-freshness-title">Fleet freshness</h2><form data-fleet-settings><label class="appearance-row"><span class="appearance-copy"><strong>nixpkgs warning threshold (days)</strong><span id="fleet-threshold-note">Warn when deployed nixpkgs differs from its channel and is older than this limit. Host overrides take precedence.</span></span><input name="nixpkgs_warn_after_days" aria-label="nixpkgs warning threshold (days)" aria-describedby="fleet-threshold-note" type="number" min="1" max="3650" step="1" required value="{days}"{disabled}></label>{grace}<button class="provider-secondary" type="submit"{disabled}>Save freshness settings</button><span data-fleet-settings-status role="status" aria-live="polite"></span></form></section>"#,
        days = fleet_settings.nixpkgs_warn_after_days,
        disabled = disabled,
        grace = grace,
    );
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="providers-main">{header}{access_path}{fleet_policy}<section class="appearance-settings" aria-labelledby="appearance-settings-title"><h2 class="settings-section-title" id="appearance-settings-title">Appearance</h2><div class="appearance-row"><span class="appearance-copy"><strong>Still sidebar image</strong><span id="sidebar-still-note" data-sidebar-still-note>Gentle motion is on.</span></span><label class="appearance-toggle"><input type="checkbox" data-sidebar-still-toggle aria-label="Use a still sidebar image" aria-describedby="sidebar-still-note"><span class="appearance-switch" aria-hidden="true"></span></label></div></section><h2 class="settings-section-title">Provider connections</h2><section class="provider-list" aria-label="provider connections">{rows}</section><p class="providers-footnote">Managed creation unlocks only after every readiness check passes.</p></main>{FOOT}"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "platform-settings"
        ),
        header = page_header(
            "Settings",
            "Fleet freshness, appearance and provider connections. Heartbeat grace is shown beside freshness.",
            now_unix(),
        ),
        rows = rows,
        access_path = access_path,
    )
}

pub(super) fn safe_provider_return_path(value: Option<&str>) -> Option<String> {
    let value = value?.trim();
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value.contains('\\')
        || value.chars().any(char::is_control)
    {
        return None;
    }
    Some(value.to_string())
}

pub(super) fn guided_provider_import_href(provider: &str) -> String {
    format!(
        "/?setup=add-server&setup_path=existing&setup_stage=existing&setup_source={}",
        provider
    )
}

pub(super) fn render_guided_provider_page(
    provider: &ProviderConnectionSummary,
    shell: ShellContext<'_>,
    can_manage: bool,
    return_path: Option<&str>,
) -> String {
    let access_path = if can_manage {
        String::new()
    } else {
        viewer_access_path(shell.public_base_path, "provider")
    };
    let (external_label, external_url) = provider_official_destination(provider.key)
        .unwrap_or(("Open provider", "https://pharos.barta.cm/"));
    let external_action = if can_manage {
        format!(
            r#"<a class="provider-primary" href="{url}" target="_blank" rel="noopener noreferrer">{label}{external}</a>"#,
            url = html_escape(external_url),
            label = html_escape(external_label),
            external = icons::EXTERNAL_LINK,
        )
    } else {
        r#"<span class="provider-action-muted">Ask an administrator</span>"#.to_string()
    };
    let import_action = if can_manage {
        format!(
            r#"<a class="provider-secondary" href="{href}">Continue in Pharos{arrow}</a>"#,
            href = app_href(
                shell.public_base_path,
                &guided_provider_import_href(provider.key)
            ),
            arrow = icons::ARROW_RIGHT,
        )
    } else {
        String::new()
    };
    let back_href = app_href(
        shell.public_base_path,
        &safe_provider_return_path(return_path)
            .unwrap_or_else(|| "/settings/providers".to_string()),
    );
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="providers-main provider-detail"><a class="provider-back" href="{back_href}">{back} Back</a>{access_path}<header class="provider-detail-head"><span class="provider-detail-mark" aria-hidden="true">{icon}</span><div><h1>Set up {name}</h1><p>{description}</p></div></header><section class="provider-step-list" aria-label="guided provider setup"><article class="provider-step"><span>1</span><div><strong>Choose the server with {name}</strong><p>{note}</p></div>{external_action}</article><article class="provider-step"><span>2</span><div><strong>Connect it to Pharos</strong><p>Return after the server exists. Pharos checks access before making any change.</p></div>{import_action}</article></section><p class="providers-footnote">No provider password or API token is entered into Pharos for this path.</p></main>{FOOT}"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "platform-settings"
        ),
        back_href = back_href,
        back = icons::ARROW_LEFT,
        icon = provider_icon(provider.key),
        name = html_escape(provider.name),
        description = html_escape(provider.description),
        note = html_escape(&provider.note),
        external_action = external_action,
        import_action = import_action,
        access_path = access_path,
    )
}

pub(super) fn provider_connection_check(
    icon: &str,
    label: &str,
    detail: &str,
    state: &str,
    state_label: &str,
) -> String {
    format!(
        r#"<div class="provider-check" data-state="{state}"><span class="provider-check-icon" aria-hidden="true">{icon}</span><span class="provider-check-copy"><strong>{label}</strong><small>{detail}</small></span><span class="provider-check-state"><i aria-hidden="true"></i>{state_label}</span></div>"#,
        icon = icon,
        label = html_escape(label),
        detail = html_escape(detail),
        state = html_escape(state),
        state_label = html_escape(state_label),
    )
}

pub(super) fn provider_select_option(value: &str, label: &str, selected: Option<&str>) -> String {
    format!(
        r#"<option value="{value}"{selected}>{label}</option>"#,
        value = html_escape(value),
        label = html_escape(label),
        selected = if selected == Some(value) {
            " selected"
        } else {
            ""
        },
    )
}

#[derive(Debug, Clone, Copy)]
pub(super) struct HetznerSetupHelpState {
    pub(super) api_ready: bool,
    pub(super) ssh_available: bool,
    pub(super) firewall_available: bool,
    pub(super) choices_ready: bool,
    pub(super) execution_enabled: bool,
}

pub(super) fn render_hetzner_setup_help(
    can_manage: bool,
    secure_setup_url: Option<&str>,
    state: HetznerSetupHelpState,
    base: &PublicBasePath,
) -> String {
    let HetznerSetupHelpState {
        api_ready,
        ssh_available,
        firewall_available,
        choices_ready,
        execution_enabled,
    } = state;
    let secure_setup = if can_manage {
        secure_setup_url
            .map(|url| {
                format!(
                    r#"<a class="provider-secondary" href="{url}" target="_blank" rel="noopener noreferrer">Open secure credential setup{external}</a>"#,
                    url = html_escape(url),
                    external = icons::EXTERNAL_LINK,
                )
            })
            .unwrap_or_else(|| {
                r#"<span class="provider-help-secret-note">Use the secure secret-management workflow documented by this installation before returning here.</span>"#.to_string()
            })
    } else {
        r#"<span class="provider-help-secret-note">An administrator must complete the installation's secure credential workflow.</span>"#.to_string()
    };
    let initial_step = if !api_ready {
        "api"
    } else if !ssh_available {
        "ssh"
    } else if !firewall_available {
        "firewall"
    } else {
        "finish"
    };
    let api_action = if api_ready {
        r#"<button class="provider-primary" type="button" data-guide-next="ssh">Continue to SSH key</button>"#.to_string()
    } else if can_manage {
        format!(
            r#"{secure_setup}<button class="provider-primary" type="button" data-guide-provider-test>Test connection</button>"#
        )
    } else {
        secure_setup.clone()
    };
    let (finish_title, finish_intro, finish_tasks, finish_followup) = if choices_ready {
        if execution_enabled {
            (
                "Provider setup complete",
                "The connection is ready. Continue in the server assistant; it keeps every paid action behind its own review and confirmation.",
                r#"<li class="provider-guide-task"><strong>Open the server assistant.</strong><p>Choose Continue to server assistant below. No server is created by opening it.</p></li><li class="provider-guide-task"><strong>Choose a starting point.</strong><p>The assistant loads current regions, plans, and prices before it prepares an exact review.</p></li><li class="provider-guide-task"><strong>Review before any paid action.</strong><p>Review, authorization, and creation remain separate attended steps. Billing can begin only after the final create step is separately approved and accepted.</p></li>"#,
                r#"<div class="provider-guide-finish"><strong>Next: prepare the first server</strong><p>The Hetzner project work is complete. Continue in Pharos; do not create the server manually in the provider portal.</p></div>"#,
            )
        } else {
            (
                "Provider setup complete",
                "The connection is ready. One installation-level safety lock remains before the paid server assistant can continue.",
                r#"<li class="provider-guide-task"><strong>No more provider-portal work is needed.</strong><p>The API connection, location, SSH public key, and firewall are verified.</p></li><li class="provider-guide-task"><strong>Enable managed creation in this Pharos installation.</strong><p>An installation administrator must enable managed provider creation in the deployment configuration and redeploy Pharos.</p></li><li class="provider-guide-task"><strong>Return to the server assistant.</strong><p>Enabling the capability does not create a server or start billing. The assistant still requires an exact current review, separate authorization, and a separate create action.</p></li>"#,
                r#"<div class="provider-guide-finish"><strong>Next: installation activation</strong><p>This provider connection is complete. Managed server creation is still locked by the Pharos deployment, so the next action belongs to the installation administrator—not the provider portal.</p></div>"#,
            )
        }
    } else {
        (
            "Refresh and select the resources",
            "This final check reads the current Hetzner catalog. It does not create a server or start billing.",
            r#"<li class="provider-guide-task"><strong>Refresh provider choices.</strong><p>Choose Test connection below. Pharos reloads the page after the safe read-only check.</p></li><li class="provider-guide-task"><strong>Open Connection details above.</strong><p>Choose a default location, the SSH key you added, and the firewall you created.</p></li><li class="provider-guide-task"><strong>Choose Save and test.</strong><p>The three checks above should read API connection: Connected, SSH key: Ready, and Firewall: Ready. Paid execution remains a separate approval.</p></li>"#,
            r#"<div class="provider-guide-finish"><strong>If a dropdown is empty</strong><p>Confirm the resource was created in the same Hetzner project as the API token, then choose Test connection again.</p></div>"#,
        )
    };
    let finish_actions = if choices_ready && can_manage {
        format!(
            r#"<button class="provider-secondary" type="button" data-guide-provider-test>Test connection</button><a class="provider-primary" href="{href}">Continue to server assistant</a>"#,
            href = app_href(base, HETZNER_ASSISTANT_ENDPOINT),
        )
    } else if choices_ready {
        r#"<span class="provider-help-secret-note">Ask an installation administrator to continue.</span>"#.to_string()
    } else {
        r#"<button class="provider-secondary" type="button" data-guide-provider-test>Test connection</button><button class="provider-primary" type="button" data-guide-open-details>Open Connection details</button>"#.to_string()
    };
    let guide_open = if choices_ready { "" } else { " open" };
    let guide_summary = if choices_ready {
        "Provider setup complete — expand for details and next steps"
    } else {
        "Prepare the Hetzner project — expand or collapse this guide"
    };
    format!(
        r#"<details class="provider-help" data-provider-setup-guide data-initial-step="{initial_step}"{guide_open}><summary class="provider-help-toggle"><span><strong>Guided setup</strong><small>{guide_summary}</small></span>{chevron}</summary><div class="provider-help-body"><header class="provider-help-head"><span class="provider-help-kicker">Guided setup</span><h2 id="hetzner-setup-help-title">Prepare the Hetzner project</h2><p>Follow one small task at a time. This assistant never asks for a token, private key, passphrase, or IP address, and it sends none of them to Pharos.</p></header><div class="provider-guide-language"><strong>Hetzner portal language / Portal-Sprache</strong><div class="provider-guide-language-options" role="group" aria-label="Hetzner portal language"><button type="button" data-guide-language="en" aria-pressed="true">English</button><button type="button" data-guide-language="de" aria-pressed="false">Deutsch</button></div><p data-guide-text-en="The portal paths, button names, and official guide links below follow your selection." data-guide-text-de="Die Portal-Pfade, Schaltflächen und offiziellen Anleitungen unten folgen deiner Auswahl.">The portal paths, button names, and official guide links below follow your selection.</p></div><ol class="provider-guide-progress" aria-label="Hetzner setup progress"><li><button type="button" data-guide-nav="api" data-complete="{api_ready}"><i aria-hidden="true">1</i>API connection</button></li><li><button type="button" data-guide-nav="ssh" data-complete="{ssh_available}"><i aria-hidden="true">2</i>SSH key</button></li><li><button type="button" data-guide-nav="firewall" data-complete="{firewall_available}"><i aria-hidden="true">3</i>Firewall</button></li><li><button type="button" data-guide-nav="finish" data-complete="{choices_ready}"><i aria-hidden="true">4</i>Finish</button></li></ol>

<section class="provider-guide-panel" data-guide-panel="api" tabindex="-1"><header class="provider-guide-panel-head"><span>Step 1 of 4</span><h3>Connect the Hetzner API</h3><p>The token lets Pharos read this project and, only after a separate paid approval, create or remove its tracked server.</p></header><div class="provider-guide-state" data-ready="{api_ready}"><i aria-hidden="true"></i>{api_state}</div><p class="provider-guide-route-note" data-guide-text-en="Hetzner puts the project number inside exact console URLs. Pharos intentionally does not store that identifier, so the console link opens Projects; choose the project, then follow the bold path." data-guide-text-de="Hetzner verwendet die Projektnummer in exakten Console-URLs. Pharos speichert diese Kennung bewusst nicht. Der Console-Link öffnet deshalb Projekte; wähle das Projekt und folge dann dem fett gedruckten Pfad.">Hetzner puts the project number inside exact console URLs. Pharos intentionally does not store that identifier, so the console link opens Projects; choose the project, then follow the bold path.</p><ol class="provider-guide-tasks"><li class="provider-guide-task"><strong data-guide-text-en="Open the correct Hetzner project." data-guide-text-de="Öffne das richtige Hetzner-Projekt.">Open the correct Hetzner project.</strong><p><a href="https://console.hetzner.com/projects" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Open Hetzner projects" data-guide-text-de="Hetzner-Projekte öffnen">Open Hetzner projects</span>{external}</a></p></li><li class="provider-guide-task"><strong data-guide-text-en="Open Security → API tokens." data-guide-text-de="Öffne Sicherheit → API-Tokens.">Open Security → API tokens.</strong><p data-guide-text-en="Choose Generate API token. Use a recognizable name such as “Pharos provider access.”" data-guide-text-de="Wähle API-Token hinzufügen. Verwende einen erkennbaren Namen wie „Pharos provider access“.">Choose Generate API token. Use a recognizable name such as “Pharos provider access.”</p></li><li class="provider-guide-task"><strong data-guide-text-en="Select Read &amp; Write, then generate the token." data-guide-text-de="Wähle Lesen &amp; Schreiben und erstelle dann den Token.">Select Read &amp; Write, then generate the token.</strong><p>Read-only access cannot perform a separately approved server create or cleanup.</p></li><li class="provider-guide-task"><strong>Move it directly into secure setup.</strong><p>The token is shown once. Copy it straight into this installation's approved credential workflow, then close the Hetzner token screen.</p></li></ol><div class="provider-guide-secret"><strong>Stop if you are about to paste the token into Pharos, chat, a ticket, Terminal, source code, or logs.</strong> If it was exposed or lost, revoke it in Hetzner and make a replacement.</div><div class="provider-guide-links"><a href="https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/" data-guide-href-en="https://docs.hetzner.com/cloud/api/getting-started/generating-api-token/" data-guide-href-de="https://docs.hetzner.com/de/cloud/api/getting-started/generating-api-token/" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Official API-token guide" data-guide-text-de="Offizielle API-Token-Anleitung">Official API-token guide</span>{external}</a></div><div class="provider-guide-actions">{api_action}</div></section>

<section class="provider-guide-panel" data-guide-panel="ssh" tabindex="-1" hidden><header class="provider-guide-panel-head"><span>Step 2 of 4</span><h3>Add an SSH public key</h3><p>An SSH key pair has two halves: Hetzner receives the public <code>.pub</code> half; the private half never leaves the computer or automation executor that will make the first login.</p></header><div class="provider-guide-state" data-ready="{ssh_available}"><i aria-hidden="true"></i>{ssh_state}</div><div><p><strong>Where will the first server login come from?</strong></p><div class="provider-guide-platforms" role="group" aria-label="SSH key computer"><button type="button" data-guide-platform="macos" aria-pressed="false">My Mac</button><button type="button" data-guide-platform="linux" aria-pressed="false">Linux or automation executor</button></div></div>
<section class="provider-guide-platform-panel" data-guide-platform-panel="macos" tabindex="-1" hidden><ol class="provider-guide-tasks"><li class="provider-guide-task"><strong>Open Terminal on the Mac.</strong><p>Press Command-Space, type Terminal, and press Return. Every copied snippet starts Bash itself, so it also works when your normal shell is Fish or Zsh.</p></li><li class="provider-guide-task"><strong>Check for the normal Ed25519 key pair.</strong><p>Copy and run this safe command. It copies only the public <code>.pub</code> file when both halves exist and prints only a result message.</p><div class="provider-guide-command"><code id="provider-command-mac-check">bash -c 'if test -f "$HOME/.ssh/id_ed25519" &amp;&amp; test -f "$HOME/.ssh/id_ed25519.pub"; then pbcopy &lt; "$HOME/.ssh/id_ed25519.pub"; echo "PUBLIC KEY COPIED"; else echo "NO KEY FOUND"; fi'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-mac-check">Copy command</button></div></li><li class="provider-guide-task"><strong>If it says NO KEY FOUND, create a dedicated key.</strong><p>Run the first command and choose a strong passphrase when asked. Then run the second command to copy only its public half.</p><div class="provider-guide-command"><code id="provider-command-mac-create">bash -c 'ssh-keygen -t ed25519 -a 100 -f "$HOME/.ssh/pharos_bootstrap_ed25519" -C "Pharos bootstrap"'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-mac-create">Copy command</button></div><div class="provider-guide-command"><code id="provider-command-mac-copy">bash -c 'pbcopy &lt; "$HOME/.ssh/pharos_bootstrap_ed25519.pub" &amp;&amp; echo "PUBLIC KEY COPIED"'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-mac-copy">Copy command</button></div></li></ol></section>
<section class="provider-guide-platform-panel" data-guide-platform-panel="linux" tabindex="-1" hidden><ol class="provider-guide-tasks"><li class="provider-guide-task"><strong>Open a terminal on the Linux computer or executor.</strong><p>Use the machine that will actually connect to and bootstrap the new server. Every copied snippet starts Bash itself, so the login shell can be Fish, Zsh, or Bash.</p></li><li class="provider-guide-task"><strong>Check for the normal Ed25519 key pair.</strong><div class="provider-guide-command"><code id="provider-command-linux-check">bash -c 'if test -f "$HOME/.ssh/id_ed25519" &amp;&amp; test -f "$HOME/.ssh/id_ed25519.pub"; then echo "KEY FOUND"; else echo "NO KEY FOUND"; fi'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-linux-check">Copy command</button></div></li><li class="provider-guide-task"><strong>If needed, create a dedicated key.</strong><p>Follow the installation's key-store and passphrase policy. Never place the private file in Pharos.</p><div class="provider-guide-command"><code id="provider-command-linux-create">bash -c 'ssh-keygen -t ed25519 -a 100 -f "$HOME/.ssh/pharos_bootstrap_ed25519" -C "Pharos bootstrap"'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-linux-create">Copy command</button></div></li><li class="provider-guide-task"><strong>Copy only the public line.</strong><p>The command displays only the public <code>.pub</code> half. Copy that one line locally. Never run it without the <code>.pub</code> suffix.</p><div class="provider-guide-command"><code id="provider-command-linux-public">bash -c 'if test -f "$HOME/.ssh/id_ed25519" &amp;&amp; test -f "$HOME/.ssh/id_ed25519.pub"; then cat "$HOME/.ssh/id_ed25519.pub"; else cat "$HOME/.ssh/pharos_bootstrap_ed25519.pub"; fi'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-linux-public">Copy command</button></div></li></ol></section>
<p class="provider-guide-copy-status" data-guide-copy-status aria-live="polite"></p><ol class="provider-guide-tasks"><li class="provider-guide-task"><strong data-guide-text-en="Return to the same Hetzner project." data-guide-text-de="Kehre zum selben Hetzner-Projekt zurück.">Return to the same Hetzner project.</strong><p data-guide-text-en="Open Security → SSH Keys → Add SSH key." data-guide-text-de="Öffne Sicherheit → SSH-Keys → SSH-Key hinzufügen.">Open Security → SSH Keys → Add SSH key.</p></li><li class="provider-guide-task"><strong data-guide-text-en="Name and add the public key." data-guide-text-de="Benenne und füge den öffentlichen Schlüssel hinzu.">Name and add the public key.</strong><p data-guide-text-en="Use a recognizable non-secret name such as “pharos-bootstrap,” paste the copied public line into Public key, and choose Add SSH key." data-guide-text-de="Verwende einen erkennbaren, nicht geheimen Namen wie „pharos-bootstrap“, füge die kopierte öffentliche Zeile in Öffentlicher Schlüssel ein und wähle SSH-Key hinzufügen.">Use a recognizable non-secret name such as “pharos-bootstrap,” paste the copied public line into Public key, and choose Add SSH key.</p></li></ol><div class="provider-guide-secret">A public key normally begins with <code>ssh-ed25519</code>. A private key file has no <code>.pub</code> suffix and must never be opened, pasted, uploaded, or sent to Pharos.</div><div class="provider-guide-links"><a href="https://console.hetzner.com/projects" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Open Hetzner projects — then Security → SSH Keys" data-guide-text-de="Hetzner-Projekte öffnen — dann Sicherheit → SSH-Keys">Open Hetzner projects — then Security → SSH Keys</span>{external}</a><a href="https://docs.hetzner.com/cloud/servers/getting-started/connecting-to-the-server/" data-guide-href-en="https://docs.hetzner.com/cloud/servers/getting-started/connecting-to-the-server/" data-guide-href-de="https://docs.hetzner.com/de/cloud/servers/getting-started/connecting-to-the-server/" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Official SSH guide" data-guide-text-de="Offizielle SSH-Anleitung">Official SSH guide</span>{external}</a></div><div class="provider-guide-actions"><button class="provider-secondary" type="button" data-guide-next="api">Back</button><button class="provider-primary" type="button" data-guide-next="firewall">SSH key added — continue</button></div></section>

<section class="provider-guide-panel" data-guide-panel="firewall" tabindex="-1" hidden>
<header class="provider-guide-panel-head"><span>Step 3 of 4</span><h3>Create the bootstrap firewall</h3><p>The firewall admits SSH only from the trusted computer or executor you just chose. Pharos stores the firewall name, not its source address.</p></header>
<div class="provider-guide-state" data-ready="{firewall_available}"><i aria-hidden="true"></i>{firewall_state}</div>
<p class="provider-guide-route-note" data-guide-text-en="Firewalls is a separate item in the left Cloud menu, directly below Floating IPs. It is not inside Security." data-guide-text-de="Firewalls ist links ein eigener Punkt im Menü Cloud, direkt unter Floating IPs. Er befindet sich nicht unter Sicherheit.">Firewalls is a separate item in the left Cloud menu, directly below Floating IPs. It is not inside Security.</p>
<div><p><strong data-guide-text-en="Choose the network path that will make the first SSH connection." data-guide-text-de="Wähle den Netzwerkweg für die erste SSH-Verbindung.">Choose the network path that will make the first SSH connection.</strong></p><div class="provider-guide-platforms" role="group" aria-label="Bootstrap network path"><button type="button" data-guide-network="fixed" aria-pressed="false"><span data-guide-text-en="Static IP / executor" data-guide-text-de="Statische IP / Executor">Static IP / executor</span></button><button type="button" data-guide-network="dynamic" aria-pressed="false"><span data-guide-text-en="Dynamic IP" data-guide-text-de="Dynamische IP">Dynamic IP</span></button><button type="button" data-guide-network="tailscale" aria-pressed="false"><span data-guide-text-en="Tailscale goal" data-guide-text-de="Tailscale als Ziel">Tailscale goal</span></button></div></div>
<section class="provider-guide-platform-panel" data-guide-network-panel="fixed" tabindex="-1" hidden><strong data-guide-text-en="Recommended for unattended or later bootstrap" data-guide-text-de="Empfohlen für unbeaufsichtigtes oder späteres Bootstrap">Recommended for unattended or later bootstrap</strong><p data-guide-text-en="Use the public egress range of the approved Linux executor that will actually run the bootstrap. That executor must also be able to use the private half of the SSH key selected in Hetzner. A stable /32 can remain valid between project setup and the later paid server approval." data-guide-text-de="Verwende den öffentlichen Ausgangsbereich des freigegebenen Linux-Executors, der das Bootstrap tatsächlich ausführt. Dieser Executor muss auch den privaten Teil des in Hetzner ausgewählten SSH-Schlüssels verwenden können. Eine feste /32 kann zwischen Projekteinrichtung und späterer kostenpflichtiger Serverfreigabe gültig bleiben.">Use the public egress range of the approved Linux executor that will actually run the bootstrap. That executor must also be able to use the private half of the SSH key selected in Hetzner. A stable /32 can remain valid between project setup and the later paid server approval.</p></section>
<section class="provider-guide-platform-panel" data-guide-network-panel="dynamic" tabindex="-1" hidden><strong data-guide-text-en="Temporary, attended bootstrap only" data-guide-text-de="Nur für temporäres, begleitetes Bootstrap">Temporary, attended bootstrap only</strong><p data-guide-text-en="A connection without a static public IP can change its public egress address. The current /32 can allow an outbound SSH connection now, even behind CGNAT, but it may stop matching without warning and can represent a shared provider egress. Re-copy and replace the source immediately before server creation and bootstrap. Keep the SSH key mandatory, and never replace the source with Any IPv4 or Any IPv6." data-guide-text-de="Ein Anschluss ohne statische öffentliche IP kann seine öffentliche Ausgangsadresse ändern. Die aktuelle /32 kann jetzt eine ausgehende SSH-Verbindung erlauben, auch hinter CGNAT; sie kann aber ohne Warnung nicht mehr passen und einen gemeinsam genutzten Provider-Ausgang darstellen. Kopiere die Quelle unmittelbar vor Server-Erstellung und Bootstrap erneut und ersetze sie bei Bedarf. Der SSH-Schlüssel bleibt Pflicht; ersetze die Quelle niemals durch Any IPv4 oder Any IPv6.">A connection without a static public IP can change its public egress address. The current /32 can allow an outbound SSH connection now, even behind CGNAT, but it may stop matching without warning and can represent a shared provider egress. Re-copy and replace the source immediately before server creation and bootstrap. Keep the SSH key mandatory, and never replace the source with Any IPv4 or Any IPv6.</p></section>
<section class="provider-guide-platform-panel" data-guide-network-panel="tailscale" tabindex="-1" hidden><strong data-guide-text-en="Tailscale is the safer end state, not the initial Hetzner source" data-guide-text-de="Tailscale ist das sicherere Ziel, aber nicht die anfängliche Hetzner-Quelle">Tailscale is the safer end state, not the initial Hetzner source</strong><p data-guide-text-en="Do not enter a Tailscale 100.x address in Hetzner Source IPs. It is private to the tailnet and will not arrive as the source of traffic on the server's public interface. The new server must join the tailnet before that address works." data-guide-text-de="Trage keine Tailscale-Adresse mit 100.x bei Hetzner unter Quell-IPs ein. Sie ist nur im Tailnet gültig und kommt nicht als Quelle am öffentlichen Interface des Servers an. Der neue Server muss zuerst dem Tailnet beitreten.">Do not enter a Tailscale 100.x address in Hetzner Source IPs. It is private to the tailnet and will not arrive as the source of traffic on the server's public interface. The new server must join the tailnet before that address works.</p><p data-guide-text-en="Current Pharos provisioning needs an initial SSH bootstrap before Tailscale is available. Select Static IP / executor above, or select Dynamic IP for an immediate attended bootstrap. After the reviewed system configuration joins Tailscale, verify tailnet SSH and then delete the public TCP port 22 rule. Stop here if your policy requires Tailscale-first provisioning with no public SSH; that path is not implemented yet." data-guide-text-de="Die aktuelle Pharos-Bereitstellung benötigt ein anfängliches SSH-Bootstrap, bevor Tailscale verfügbar ist. Wähle oben Statische IP / Executor oder Dynamische IP für ein sofortiges begleitetes Bootstrap. Nachdem die geprüfte Systemkonfiguration Tailscale beigetreten ist, prüfe SSH im Tailnet und lösche danach die öffentliche TCP-Regel für Port 22. Stoppe hier, falls deine Richtlinie Tailscale-first ohne öffentliches SSH verlangt; dieser Weg ist noch nicht implementiert.">Current Pharos provisioning needs an initial SSH bootstrap before Tailscale is available. Select Static IP / executor above, or select Dynamic IP for an immediate attended bootstrap. After the reviewed system configuration joins Tailscale, verify tailnet SSH and then delete the public TCP port 22 rule. Stop here if your policy requires Tailscale-first provisioning with no public SSH; that path is not implemented yet.</p><div class="provider-guide-links"><a href="https://tailscale.com/docs/concepts/tailscale-ip-addresses" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Why Tailscale 100.x is private" data-guide-text-de="Warum Tailscale 100.x privat ist">Why Tailscale 100.x is private</span>{external}</a><a href="https://tailscale.com/docs/reference/faq/firewall-ports" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Official Tailscale firewall guide" data-guide-text-de="Offizielle Tailscale-Firewall-Anleitung">Official Tailscale firewall guide</span>{external}</a></div></section>
<div data-guide-network-workflow hidden>
<ol class="provider-guide-tasks">
<li class="provider-guide-task"><strong data-guide-text-en="Copy the public IPv4 range from the exact SSH origin you chose." data-guide-text-de="Kopiere den öffentlichen IPv4-Bereich genau von der gewählten SSH-Quelle.">Copy the public IPv4 range from the exact SSH origin you chose.</strong><p data-guide-text-en="Run the lookup on the computer or Linux executor that will make the first SSH connection—not on a different device. If your organization provides an approved egress CIDR, use that instead of the lookup." data-guide-text-de="Führe die Abfrage auf genau dem Computer oder Linux-Executor aus, der die erste SSH-Verbindung herstellt — nicht auf einem anderen Gerät. Falls deine Organisation einen freigegebenen Ausgangs-CIDR vorgibt, verwende diesen statt der Abfrage.">Run the lookup on the computer or Linux executor that will make the first SSH connection—not on a different device. If your organization provides an approved egress CIDR, use that instead of the lookup.</p><p data-guide-text-en="On macOS, copy the command, paste it into Terminal, and press Return. Terminal prints only PUBLIC IPv4 RANGE COPIED; the address ending in /32 stays in your clipboard. The command starts Bash itself, so it works from Fish or Zsh." data-guide-text-de="Unter macOS: Kopiere den Befehl, füge ihn in Terminal ein und drücke Return. Terminal zeigt nur PUBLIC IPv4 RANGE COPIED; die Adresse mit /32 am Ende bleibt in deiner Zwischenablage. Der Befehl startet Bash selbst und funktioniert deshalb auch aus Fish oder Zsh.">On macOS, copy the command, paste it into Terminal, and press Return. Terminal prints only PUBLIC IPv4 RANGE COPIED; the address ending in /32 stays in your clipboard. The command starts Bash itself, so it works from Fish or Zsh.</p><div class="provider-guide-command"><code id="provider-command-firewall-mac">bash -c 'printf "%s/32" "$(curl -4fsS https://icanhazip.com)" | pbcopy &amp;&amp; echo "PUBLIC IPv4 RANGE COPIED"'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-firewall-mac"><span data-guide-text-en="Copy macOS command" data-guide-text-de="macOS-Befehl kopieren">Copy macOS command</span></button></div><p data-guide-text-en="On Linux, run the command locally and copy its one result without putting it into chat, a ticket, or logs. The lookup goes directly to icanhazip.com." data-guide-text-de="Unter Linux: Führe den Befehl lokal aus und kopiere das einzelne Ergebnis, ohne es in Chat, Tickets oder Logs einzufügen. Die Abfrage geht direkt an icanhazip.com.">On Linux, run the command locally and copy its one result without putting it into chat, a ticket, or logs. The lookup goes directly to icanhazip.com.</p><div class="provider-guide-command"><code id="provider-command-firewall-linux">bash -c 'printf "%s/32\n" "$(curl -4fsS https://icanhazip.com)"'</code><button class="provider-guide-copy" type="button" data-copy-command="provider-command-firewall-linux"><span data-guide-text-en="Copy Linux command" data-guide-text-de="Linux-Befehl kopieren">Copy Linux command</span></button></div></li>
<li class="provider-guide-task"><strong data-guide-text-en="In the left Cloud menu, open Firewalls → Create Firewall." data-guide-text-de="Öffne links im Menü Cloud: Firewalls → Firewall erstellen.">In the left Cloud menu, open Firewalls → Create Firewall.</strong><p data-guide-text-en="Use a recognizable name such as “pharos-bootstrap.”" data-guide-text-de="Verwende einen erkennbaren Namen wie „pharos-bootstrap“.">Use a recognizable name such as “pharos-bootstrap.”</p></li>
<li class="provider-guide-task"><strong data-guide-text-en="Set the first incoming rule exactly." data-guide-text-de="Stelle die erste eingehende Regel genau ein.">Set the first incoming rule exactly.</strong><div class="provider-guide-screen-help"><strong data-guide-text-en="On Hetzner's Create Firewall screen" data-guide-text-de="Auf der Hetzner-Seite „Firewall erstellen“">On Hetzner's Create Firewall screen</strong><ol><li data-guide-text-en="Keep Protocol set to TCP and Port set to 22. TCP is the connection type; port 22 is the door used by SSH." data-guide-text-de="Lass Protokoll auf TCP und Port auf 22. TCP ist die Verbindungsart; Port 22 ist die von SSH verwendete Tür.">Keep Protocol set to TCP and Port set to 22. TCP is the connection type; port 22 is the door used by SSH.</li><li data-guide-text-en="Click inside Source IPs. Hetzner initially shows the gray entries Any IPv4 and Any IPv6. Press Backspace until both are gone. If a selection menu opens, click both entries there to deselect them." data-guide-text-de="Klicke in das Feld Quell-IPs. Hetzner zeigt dort anfangs die grauen Einträge Any IPv4 und Any IPv6. Drücke die Rückschritttaste, bis beide entfernt sind. Falls sich ein Auswahlmenü öffnet, klicke dort beide Einträge an, um sie abzuwählen.">Click inside Source IPs. Hetzner initially shows the gray entries Any IPv4 and Any IPv6. Press Backspace until both are gone. If a selection menu opens, click both entries there to deselect them.</li><li data-guide-text-en="Paste from the clipboard and press Return. One gray entry ending in /32 should appear. A shape such as x.x.x.x/32 means exactly one IPv4 address; the x text is only an illustration and must not be entered." data-guide-text-de="Füge aus der Zwischenablage ein und drücke Return. Es soll ein einzelner grauer Eintrag mit /32 am Ende erscheinen. Die Form x.x.x.x/32 bedeutet genau eine IPv4-Adresse; der Text mit den x ist nur ein Beispiel und darf nicht eingegeben werden.">Paste from the clipboard and press Return. One gray entry ending in /32 should appear. A shape such as x.x.x.x/32 means exactly one IPv4 address; the x text is only an illustration and must not be entered.</li><li data-guide-text-en="If Hetzner shows a second ICMP rule, remove that entire row with its × button at the upper right. Finish with exactly one incoming rule." data-guide-text-de="Falls Hetzner eine zweite ICMP-Regel zeigt, entferne die ganze Zeile mit ihrem × oben rechts. Am Ende darf genau eine eingehende Regel übrig sein.">If Hetzner shows a second ICMP rule, remove that entire row with its × button at the upper right. Finish with exactly one incoming rule.</li><li data-guide-text-en="Stop if Any IPv4 or Any IPv6 is still visible. Those choices expose SSH to connection attempts from the whole internet." data-guide-text-de="Stoppe, falls Any IPv4 oder Any IPv6 noch sichtbar ist. Diese Auswahl erlaubt SSH-Verbindungsversuche aus dem gesamten Internet.">Stop if Any IPv4 or Any IPv6 is still visible. Those choices expose SSH to connection attempts from the whole internet.</li></ol></div><div class="provider-guide-ready-check" data-guide-text-en="Ready check: one source entry ending in /32 · TCP · port 22 · no second incoming rule. Do not paste or send the real source address anywhere else." data-guide-text-de="Bereit-Check: ein Quell-Eintrag mit /32 am Ende · TCP · Port 22 · keine zweite eingehende Regel. Füge die echte Quelladresse nirgendwo anders ein und sende sie nicht weiter.">Ready check: one source entry ending in /32 · TCP · port 22 · no second incoming rule. Do not paste or send the real source address anywhere else.</div><div class="provider-guide-secret" data-guide-text-en="Dynamic IP: this ready check is temporary. Repeat the lookup and replace the source immediately before the later paid creation and SSH bootstrap. If Tailscale is your goal, remove this public SSH rule only after tailnet access has been verified." data-guide-text-de="Dynamische IP: Dieser Bereit-Check gilt nur vorübergehend. Wiederhole die Abfrage unmittelbar vor der späteren kostenpflichtigen Erstellung und dem SSH-Bootstrap und ersetze die Quelle bei Bedarf. Wenn Tailscale dein Ziel ist, entferne diese öffentliche SSH-Regel erst, nachdem der Zugriff im Tailnet geprüft wurde.">Dynamic IP: this ready check is temporary. Repeat the lookup and replace the source immediately before the later paid creation and SSH bootstrap. If Tailscale is your goal, remove this public SSH rule only after tailnet access has been verified.</div></li>
<li class="provider-guide-task"><strong data-guide-text-en="Keep outbound access available." data-guide-text-de="Lass ausgehenden Zugriff verfügbar.">Keep outbound access available.</strong><p data-guide-text-en="Leave outbound rules empty when unrestricted outbound traffic is intended; initial setup needs package sources and the Pharos endpoint." data-guide-text-de="Lass ausgehende Regeln leer, wenn ausgehender Datenverkehr erlaubt sein soll; die Ersteinrichtung benötigt Paketquellen und den Pharos-Endpunkt.">Leave outbound rules empty when unrestricted outbound traffic is intended; initial setup needs package sources and the Pharos endpoint.</p></li>
<li class="provider-guide-task"><strong data-guide-text-en="Create it without attaching a resource." data-guide-text-de="Erstelle sie, ohne eine Ressource zuzuweisen.">Create it without attaching a resource.</strong><p data-guide-text-en="The firewall can remain unattached. Pharos attaches the selected firewall during the separately approved server create." data-guide-text-de="Die Firewall darf ohne zugewiesene Ressource bleiben. Pharos weist sie erst bei der separat genehmigten Server-Erstellung zu.">The firewall can remain unattached. Pharos attaches the selected firewall during the separately approved server create.</p></li>
</ol>
</div>
<p class="provider-guide-copy-status" data-guide-copy-status aria-live="polite"></p><div class="provider-guide-links"><a href="https://console.hetzner.com/projects" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Open Hetzner projects — then Firewalls" data-guide-text-de="Hetzner-Projekte öffnen — dann Firewalls">Open Hetzner projects — then Firewalls</span>{external}</a><a href="https://docs.hetzner.com/cloud/firewalls/getting-started/creating-a-firewall/" data-guide-href-en="https://docs.hetzner.com/cloud/firewalls/getting-started/creating-a-firewall/" data-guide-href-de="https://docs.hetzner.com/de/cloud/firewalls/getting-started/creating-a-firewall/" target="_blank" rel="noopener noreferrer"><span data-guide-text-en="Official Firewall guide" data-guide-text-de="Offizielle Firewall-Anleitung">Official Firewall guide</span>{external}</a></div><div class="provider-guide-actions"><button class="provider-secondary" type="button" data-guide-next="ssh">Back</button><button class="provider-primary" type="button" data-guide-firewall-finish data-guide-next="finish" disabled>Firewall created — finish</button></div>
</section>

<section class="provider-guide-panel" data-guide-panel="finish" tabindex="-1" hidden><header class="provider-guide-panel-head"><span>Step 4 of 4</span><h3>{finish_title}</h3><p>{finish_intro}</p></header><div class="provider-guide-state" data-ready="{choices_ready}"><i aria-hidden="true"></i>{finish_state}</div><div class="provider-guide-route-note"><strong>How the SSH-key dropdown works</strong><p>Pharos asks the Hetzner API for the names of public SSH keys already stored in this project. It never uploads or reads a private key. Selecting a name tells Hetzner which existing public key to place on a later, separately approved server.</p></div><ol class="provider-guide-tasks">{finish_tasks}</ol>{finish_followup}<div class="provider-guide-actions"><button class="provider-secondary" type="button" data-guide-next="firewall">Back</button>{finish_actions}</div></section></div></details>"#,
        external = icons::EXTERNAL_LINK,
        chevron = icons::CHEVRON_DOWN,
        initial_step = initial_step,
        guide_open = guide_open,
        guide_summary = guide_summary,
        api_ready = api_ready,
        ssh_available = ssh_available,
        firewall_available = firewall_available,
        choices_ready = choices_ready,
        finish_title = finish_title,
        finish_intro = finish_intro,
        finish_tasks = finish_tasks,
        finish_followup = finish_followup,
        finish_actions = finish_actions,
        api_state = if api_ready {
            "Pharos already detects a working API connection. Do not replace its token."
        } else {
            "No working API connection is currently detected."
        },
        ssh_state = if ssh_available {
            "At least one SSH public key is available in this Hetzner project."
        } else {
            "No SSH public key is currently available in the refreshed project catalog."
        },
        firewall_state = if firewall_available {
            "At least one firewall is available in this Hetzner project."
        } else {
            "No firewall is currently available in the refreshed project catalog."
        },
        finish_state = if choices_ready {
            "The location, SSH key, and firewall selections have been verified."
        } else {
            "Refresh the catalog, then select and verify all three choices."
        },
        api_action = api_action,
    )
}

pub(super) fn render_hetzner_connection_page(
    runtime: &ProviderRuntimeConfig,
    store: &ProviderConnectionStore,
    shell: ShellContext<'_>,
    can_manage: bool,
    return_path: Option<&str>,
) -> String {
    let now = now_unix();
    let readiness = hetzner_runtime_readiness(&runtime.hetzner_cloud, store, now);
    let effective = effective_hetzner_runtime(&runtime.hetzner_cloud, store);
    let attempt = store.last_attempt();
    let catalog = store.catalog_if_fresh(now, effective.evidence_ttl_secs);
    let api_ready = readiness.api_access && readiness.evidence_fresh;
    let ssh_ready = api_ready && attempt.as_ref().is_some_and(|item| item.ssh_key_ready);
    let firewall_ready = api_ready && attempt.as_ref().is_some_and(|item| item.firewall_ready);
    let location_ready = api_ready
        && attempt
            .as_ref()
            .is_some_and(|item| item.default_location_ready);
    let connection_ready = readiness.connection_ready;
    let ssh_available = api_ready
        && catalog
            .as_ref()
            .is_some_and(|catalog| !catalog.ssh_keys.is_empty());
    let firewall_available = api_ready
        && catalog
            .as_ref()
            .is_some_and(|catalog| !catalog.firewalls.is_empty());
    let tested_label = readiness
        .tested_at
        .map(|tested_at| {
            format!(
                "Tested {} ago",
                duration_label(now.saturating_sub(tested_at))
            )
        })
        .unwrap_or_else(|| "Not tested yet".to_string());
    let ssh_detail = if can_manage {
        effective
            .default_ssh_key_ref
            .clone()
            .unwrap_or_else(|| "Choose after connecting".to_string())
    } else if readiness.default_ssh_key_configured {
        "Configured".to_string()
    } else {
        "Administrator setup required".to_string()
    };
    let firewall_detail = if can_manage {
        effective
            .firewall_ref
            .clone()
            .unwrap_or_else(|| "Choose after connecting".to_string())
    } else if readiness.firewall_configured {
        "Configured".to_string()
    } else {
        "Administrator setup required".to_string()
    };
    let checks = [
        provider_connection_check(
            icons::LINK,
            "API connection",
            if readiness.credential_configured {
                &tested_label
            } else {
                "Secure credential needed"
            },
            if api_ready { "ready" } else { "attention" },
            if api_ready {
                "Connected"
            } else if readiness.credential_configured {
                "Test"
            } else {
                "Set up"
            },
        ),
        provider_connection_check(
            icons::KEY_ROUND,
            "SSH key",
            &ssh_detail,
            if ssh_ready { "ready" } else { "attention" },
            if ssh_ready { "Ready" } else { "Choose" },
        ),
        provider_connection_check(
            icons::SHIELD_CHECK,
            "Firewall",
            &firewall_detail,
            if firewall_ready { "ready" } else { "attention" },
            if firewall_ready { "Ready" } else { "Choose" },
        ),
    ]
    .join("");
    let back_href = app_href(
        shell.public_base_path,
        &safe_provider_return_path(return_path)
            .unwrap_or_else(|| "/settings/providers".to_string()),
    );
    let janus_url = hetzner_janus_setup_url(runtime, &self_host());
    let setup_link = janus_url.as_ref().map(|url| {
        format!(
            r#"<a class="provider-primary" href="{url}" target="_blank" rel="noopener noreferrer">Open secure setup{external}</a>"#,
            url = html_escape(url),
            external = icons::EXTERNAL_LINK,
        )
    });
    let primary_action = if !can_manage {
        r#"<p class="provider-admin-note">Ask a Pharos administrator to connect this provider.</p>"#
            .to_string()
    } else if connection_ready {
        format!(
            r#"<a class="provider-primary" href="{href}">Continue to server assistant<svg class="ico" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M5 12h14"/><path d="m13 6 6 6-6 6"/></svg></a>"#,
            href = app_href(shell.public_base_path, HETZNER_ASSISTANT_ENDPOINT),
        )
    } else if !readiness.credential_configured || !readiness.credential_boundary_ready {
        setup_link.unwrap_or_else(|| {
            r#"<p class="provider-admin-note">Secure setup is not connected to Janus on this Pharos installation.</p>"#.to_string()
        })
    } else if !readiness.execution_enabled {
        format!(
            r#"<button class="provider-primary" type="button" data-provider-test>{refresh}Test connection</button>"#,
            refresh = icons::REFRESH_CW,
        )
    } else if api_ready && catalog.is_some() && !(ssh_ready && firewall_ready && location_ready) {
        r#"<button class="provider-primary" type="button" data-provider-open-details>Finish setup</button>"#
            .to_string()
    } else {
        format!(
            r#"<button class="provider-primary" type="button" data-provider-test>{refresh}Test connection</button>"#,
            refresh = icons::REFRESH_CW,
        )
    };
    let secondary_action = if can_manage && readiness.credential_configured {
        format!(
            r#"<button class="provider-secondary" type="button" data-provider-test>{refresh}Test connection</button>"#,
            refresh = icons::REFRESH_CW,
        )
    } else {
        String::new()
    };
    let menu = if can_manage && (readiness.credential_configured || readiness.connection_tested) {
        format!(
            r#"<details class="provider-menu"><summary aria-label="Connection actions" title="Connection actions">{ellipsis}</summary><div><button type="button" data-provider-disconnect>Disconnect</button></div></details>"#,
            ellipsis = icons::ELLIPSIS,
        )
    } else {
        String::new()
    };
    let details = can_manage
        .then_some(catalog.as_ref())
        .flatten()
        .map(|catalog| {
            let current_location = effective.default_location.as_deref();
            let current_ssh_key = effective.default_ssh_key_ref.as_deref();
            let current_firewall = effective.firewall_ref.as_deref();
            let location_options = catalog
                .locations
                .iter()
                .filter(|location| catalog.supports_location(&location.name))
                .map(|location| {
                    provider_select_option(
                        &location.name,
                        &format!("{} ({})", location.city, location.name),
                        current_location,
                    )
                })
                .collect::<String>();
            let ssh_key_options = catalog
                .ssh_keys
                .iter()
                .map(|value| provider_select_option(value, value, current_ssh_key))
                .collect::<String>();
            let firewall_options = catalog
                .firewalls
                .iter()
                .map(|value| provider_select_option(value, value, current_firewall))
                .collect::<String>();
            let open = if connection_ready {
                ""
            } else {
                " open"
            };
            format!(
                r#"<details class="provider-details" data-provider-details{open}><summary><span>Connection details</span>{chevron}</summary><form data-provider-preferences><div class="provider-fields"><label><span>Default location</span><select name="default_location" required><option value="">Choose a location</option>{location_options}</select></label><label><span>SSH key</span><select name="ssh_key_ref" required><option value="">Choose an SSH key</option>{ssh_key_options}</select></label><label><span>Firewall</span><select name="firewall_ref" required><option value="">Choose a firewall</option>{firewall_options}</select></label></div><div class="provider-details-action"><button class="provider-secondary" type="submit">Save and test</button><span data-provider-action-status aria-live="polite"></span></div></form><p>Only names and current provider catalog data are stored here. The token stays in the Janus and agenix boundary.</p></details>"#,
                open = open,
                chevron = icons::CHEVRON_DOWN,
                location_options = location_options,
                ssh_key_options = ssh_key_options,
                firewall_options = firewall_options,
            )
        })
        .unwrap_or_default();
    let setup_note = if readiness.credential_boundary_ready {
        "The provider token is never displayed or persisted in this UI."
    } else {
        "Janus and agenix must mount the provider token before Pharos can test it."
    };
    let setup_help = render_hetzner_setup_help(
        can_manage,
        janus_url.as_deref(),
        HetznerSetupHelpState {
            api_ready,
            ssh_available,
            firewall_available,
            choices_ready: ssh_ready && firewall_ready && location_ready,
            execution_enabled: readiness.execution_enabled,
        },
        shell.public_base_path,
    );
    let connection_message = if connection_ready && !readiness.execution_enabled {
        "Provider setup is complete. Continue below for the installation-level activation step; no more provider-portal work is needed."
    } else {
        &readiness.message
    };
    let access_path = if can_manage {
        String::new()
    } else {
        viewer_access_path(shell.public_base_path, "provider")
    };
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="providers-main provider-detail"><a class="provider-back" href="{back_href}">{back} Provider connections</a>{access_path}<header class="provider-detail-head provider-connection-head"><span class="provider-detail-mark" aria-hidden="true">{cloud}</span><div><h1>Hetzner Cloud</h1><p>Connect once, then add servers.</p></div><span class="provider-head-state" data-ready="{ready}"><i aria-hidden="true"></i>{status}</span></header><section class="provider-connection-card" data-provider-ready="{ready}"><div class="provider-connection-copy"><div><strong>{headline}</strong><p>{message}</p></div><div class="provider-connection-actions">{primary_action}{secondary_action}{menu}</div></div><div class="provider-checks">{checks}</div>{details}<p class="provider-action-feedback" data-provider-action-status aria-live="polite"></p></section>{setup_help}<p class="providers-footnote">{setup_note} Paid server creation always has its own review and confirmation.</p></main>{FOOT}"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "platform-settings"
        ),
        back_href = back_href,
        back = icons::ARROW_LEFT,
        cloud = icons::CLOUD,
        ready = connection_ready,
        status = if connection_ready {
            "Connected"
        } else if api_ready {
            "Setup needed"
        } else {
            "Not connected"
        },
        headline = if connection_ready {
            "Provider setup complete"
        } else if api_ready {
            "Finish the connection"
        } else {
            "Connect Hetzner Cloud"
        },
        message = html_escape(connection_message),
        checks = checks,
        primary_action = primary_action,
        secondary_action = if connection_ready {
            secondary_action
        } else {
            String::new()
        },
        menu = menu,
        details = details,
        setup_help = setup_help,
        access_path = access_path,
        setup_note = html_escape(setup_note),
    )
}

pub(super) fn header(now: i64) -> String {
    page_header("Fleet", "All hosts at a glance", now)
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ShellContext<'a> {
    pub(super) user_label: &'a str,
    pub(super) logout_enabled: bool,
    pub(super) public_base_path: &'a PublicBasePath,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct RuntimeSnapshot<'a> {
    pub(super) nixpkgs_warn_after_days: u32,
    pub(super) hosts: &'a [Host],
    pub(super) jobs: &'a [ProvisioningJob],
    pub(super) action_jobs: &'a [HostActionJob],
    pub(super) declared_preferences: Option<&'a BTreeMap<String, HostPreferences>>,
    /// PHAROS-194: hosts whose beacon credential Janus owns, so removal must also
    /// retire that credential. Independent of whether the host is declared.
    pub(super) janus_managed_hosts: Option<&'a BTreeSet<String>>,
}

#[derive(Debug, Clone, Copy)]
pub(super) struct FleetCapabilities {
    pub(super) can_manage_fleet: bool,
    pub(super) system_update_available: bool,
    pub(super) host_removal_available: bool,
}

pub(super) struct HostActionRenderContext<'a> {
    pub(super) manifest: Option<&'a HostManifest>,
    pub(super) declared: bool,
    pub(super) credential_retirement_required: bool,
    pub(super) settings_state: HostPreferencesState,
    pub(super) settings_href: &'a str,
    pub(super) backup: &'a BackupUiSummary,
    pub(super) surface: &'a str,
    pub(super) capabilities: FleetCapabilities,
    pub(super) action_jobs: &'a [HostActionJob],
}

#[derive(Debug, Clone, Copy)]
pub(super) struct ActivitySources<'a> {
    pub(super) manifests: &'a [HostManifest],
    pub(super) load_errors: &'a [ManifestLoadIssue],
    pub(super) server_probes: &'a BTreeMap<String, Vec<ServerProbeObservation>>,
    pub(super) action_jobs: &'a [HostActionJob],
}

#[derive(Debug, Default, Deserialize)]
pub(super) struct ActivityQuery {
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    workflow: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ActivityFocus {
    All,
    Workflow { host: String, workflow_id: String },
    Unavailable,
}

pub(super) fn activity_focus(
    query: &ActivityQuery,
    authorized_action_jobs: &[HostActionJob],
) -> ActivityFocus {
    match (query.host.as_deref(), query.workflow.as_deref()) {
        (None, None) => ActivityFocus::All,
        (Some(host), Some(workflow_id))
            if authorized_action_jobs
                .iter()
                .any(|job| job.host == host && job.id == workflow_id) =>
        {
            ActivityFocus::Workflow {
                host: host.to_string(),
                workflow_id: workflow_id.to_string(),
            }
        }
        _ => ActivityFocus::Unavailable,
    }
}

pub(super) fn search_box(placeholder: &str) -> String {
    format!(
        r#"<label class="search">{search}<input data-search type="search" autocomplete="off" placeholder="{placeholder}"></label>"#,
        search = icons::SEARCH,
        placeholder = html_escape(placeholder)
    )
}

pub(super) fn toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="fleet controls"><div class="toolbar-left"><div class="seg" role="group" aria-label="view"><button type="button" data-view-button="grid" aria-pressed="true" title="Grid view">{grid}</button><button type="button" data-view-button="list" aria-pressed="false" title="List view">{list}</button></div><label class="arrange">Arrange by <select data-sort aria-label="arrange by"><option value="attention">Needs attention</option><option value="name">Name</option><option value="last">Last change</option><option value="freeform">Freeform</option></select></label></div><div class="toolbar-right">{search}</div></section>"#,
        grid = icons::GRID,
        list = icons::LIST,
        search = search_box("Search hosts...")
    )
}

pub(super) fn map_toolbar() -> String {
    format!(
        r#"<section class="toolbar" aria-label="map controls"><div class="toolbar-left"><span class="arrange">All servers stay visible unless filtered</span></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

pub(super) fn onboard_primary(label: &str) -> String {
    format!(
        r#"<button class="onboard-primary" type="button" data-onboard-open>{icon}<span>{label}</span></button>"#,
        icon = icons::PLUS,
        label = html_escape(label)
    )
}

pub(super) fn onboard_tile() -> String {
    format!(
        r#"<button class="onboard-tile" type="button" data-onboard-open data-onboard-tile aria-label="Add server"><span class="onboard-mark">{icon}</span><span class="onboard-copy"><strong>Add server</strong><span>Provision or onboard</span></span><span class="onboard-foot">Open setup assistant</span></button>"#,
        icon = icons::PLUS
    )
}

pub(super) fn onboard_row() -> String {
    format!(
        r#"<tr class="onboard-row" data-sev="9" data-sort-name="zzzz-onboard" data-last="0"><td colspan="6"><button type="button" data-onboard-open aria-label="Add server"><span class="onboard-mark">{icon}</span><span><strong>Add server</strong><span>Provision a new host or onboard an existing one.</span></span></button></td></tr>"#,
        icon = icons::PLUS
    )
}

pub(super) fn setup_assistant() -> String {
    let replacements = [
        ("{plus}", icons::PLUS),
        ("{server}", icons::SERVER),
        ("{close}", icons::X),
        ("{arrow_left}", icons::ARROW_LEFT),
        ("{arrow_right}", icons::ARROW_RIGHT),
        ("{chevron}", icons::CHEVRON_DOWN),
        ("{setup}", icons::SLIDERS),
        ("{after}", icons::SHIELD_CHECK),
        ("{link}", icons::LINK),
        ("{map_pin}", icons::MAP_PIN),
        ("{warning}", icons::TRIANGLE_ALERT),
        ("{trash}", icons::TRASH_2),
    ];
    replacements.iter().fold(
        SETUP_ASSISTANT_TEMPLATE.to_string(),
        |rendered, (placeholder, value)| rendered.replace(placeholder, value),
    )
}
pub(super) fn empty_state(can_onboard: bool) -> String {
    let action = if can_onboard {
        onboard_primary("Add first server")
    } else {
        String::new()
    };
    format!(
        r#"<section class="empty-state" aria-label="first run"><div class="empty-copy"><span class="empty-kicker">first light</span><h2>Waiting for the first host</h2><p>Register a host and Pharos will hold it in the grey awaiting state until the first real heartbeat arrives.</p>{action}</div><div class="empty-visual" aria-hidden="true"><span class="empty-sun"></span><span class="empty-line"></span><span class="empty-lighthouse">{lighthouse}</span><span class="empty-await">awaiting first heartbeat</span></div></section>"#,
        action = action,
        lighthouse = icons::LIGHTHOUSE
    )
}

pub(super) fn lone_host_state(can_onboard: bool) -> String {
    let action = if can_onboard {
        onboard_primary("Add server")
    } else {
        String::new()
    };
    format!(
        r#"<aside class="lone-state" aria-label="lone host state"><span class="lone-mark">{lighthouse}</span><div class="lone-copy"><span class="lone-kicker">one light</span><strong>First host is on the map</strong><p>The fleet view is ready for the next onboarded machine.</p></div>{action}</aside>"#,
        lighthouse = icons::LIGHTHOUSE,
        action = action
    )
}

pub(super) fn provisioning_job_host_name(job: &ProvisioningJob) -> Option<&str> {
    job.host_name
        .as_deref()
        .map(str::trim)
        .filter(|host| !host.is_empty())
}

pub(super) fn provisioning_job_rolled_back(job: &ProvisioningJob) -> bool {
    job.state == ProvisioningJobState::Complete
        && job.terminal_outcome == Some(ProvisioningTerminalOutcome::RolledBack)
}

pub(super) fn provisioning_job_role(job: &ProvisioningJob) -> &str {
    job.role
        .as_deref()
        .map(str::trim)
        .filter(|role| !role.is_empty())
        .unwrap_or("server")
}

pub(super) fn provisioning_job_visible_in_fleet(job: &ProvisioningJob) -> bool {
    matches!(
        job.state,
        ProvisioningJobState::Planning
            | ProvisioningJobState::Provisioning
            | ProvisioningJobState::Bootstrapping
            | ProvisioningJobState::WaitingForHeartbeat
            | ProvisioningJobState::BackupPending
            | ProvisioningJobState::CleanupNeeded
    )
}

pub(super) fn first_heartbeat_timeout_secs(job: &ProvisioningJob) -> i64 {
    let interval = i64::try_from(job.heartbeat_interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    (interval * 5).clamp(300, 1800)
}

pub(super) fn provisioning_job_first_heartbeat_overdue(job: &ProvisioningJob, now: i64) -> bool {
    job.state == ProvisioningJobState::WaitingForHeartbeat
        && now.saturating_sub(job.updated_at) > first_heartbeat_timeout_secs(job)
}

pub(super) fn provisioning_job_fleet_status(
    job: &ProvisioningJob,
    now: i64,
) -> (&'static str, &'static str, &'static str, u8, String) {
    if provisioning_job_rolled_back(job) {
        return ("unknown", "clear", "ok", 4, "setup rolled back".to_string());
    }
    if provisioning_job_first_heartbeat_overdue(job, now) {
        return (
            "stale",
            "warning",
            "warn",
            1,
            "first heartbeat overdue".to_string(),
        );
    }

    match job.state {
        ProvisioningJobState::Planning
        | ProvisioningJobState::Provisioning
        | ProvisioningJobState::Bootstrapping => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            format!("setup {}", job.state.label()),
        ),
        ProvisioningJobState::WaitingForHeartbeat => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            "waiting for first heartbeat".to_string(),
        ),
        ProvisioningJobState::BackupPending => (
            "awaiting_first_heartbeat",
            "watch",
            "wait",
            2,
            "backup pending".to_string(),
        ),
        ProvisioningJobState::Complete => ("live", "clear", "ok", 4, "setup complete".to_string()),
        ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded => {
            ("down", "critical", "down", 0, job.state.label().to_string())
        }
    }
}

pub(super) fn provisioning_job_setup_intent(job: &ProvisioningJob) -> ProvisioningSetupIntent {
    job.setup_intent.clone().unwrap_or(ProvisioningSetupIntent {
        backup: BackupSetupIntent::Deferred,
        location: LocationSetupIntent::Auto,
        access: AccessSetupIntent::OperatorOnly,
    })
}

pub(super) fn provisioning_job_latest_message(job: &ProvisioningJob) -> String {
    job.progress
        .last()
        .map(|entry| entry.message.clone())
        .unwrap_or_else(|| "Setup job is waiting for progress.".to_string())
}

pub(super) fn setup_intent_markup(intent: &ProvisioningSetupIntent) -> String {
    format!(
        r#"<div class="setup-intent"><span class="setup-chip backup">{backup}</span><span class="setup-chip location">{location}</span><span class="setup-chip access">{access}</span></div>"#,
        backup = html_escape(intent.backup_label()),
        location = html_escape(intent.location_label()),
        access = html_escape(intent.access_label())
    )
}

pub(super) fn setup_intent_search_text(intent: &ProvisioningSetupIntent) -> String {
    format!(
        "{} {} {} {} {} {}",
        intent.backup_label(),
        intent.backup_next_action(),
        intent.location_label(),
        intent.location_next_action(),
        intent.access_label(),
        intent.access_next_action()
    )
}

pub(super) fn pending_setup_jobs<'a>(
    hosts: &[Host],
    jobs: &'a [ProvisioningJob],
) -> Vec<&'a ProvisioningJob> {
    let runtime_names: BTreeSet<&str> = hosts.iter().map(|host| host.name.as_str()).collect();
    let mut latest_by_host: BTreeMap<&str, &ProvisioningJob> = BTreeMap::new();
    for job in jobs {
        let Some(host_name) = provisioning_job_host_name(job) else {
            continue;
        };
        if runtime_names.contains(host_name) || !provisioning_job_visible_in_fleet(job) {
            continue;
        }
        let replace = latest_by_host
            .get(host_name)
            .is_none_or(|existing| job.updated_at >= existing.updated_at);
        if replace {
            latest_by_host.insert(host_name, job);
        }
    }
    let mut jobs: Vec<&ProvisioningJob> = latest_by_host.into_values().collect();
    jobs.sort_by(|left, right| {
        right
            .updated_at
            .cmp(&left.updated_at)
            .then_with(|| provisioning_job_host_name(left).cmp(&provisioning_job_host_name(right)))
    });
    jobs
}

pub(super) fn reconcile_provisioning_jobs_with_runtime(
    provisioning_jobs: &ProvisioningJobStore,
    hosts: &[Host],
    now: i64,
) {
    let runtime_by_name: BTreeMap<&str, &Host> = hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    for job in provisioning_jobs.list() {
        let Some(host_name) = provisioning_job_host_name(&job) else {
            continue;
        };
        let Some(host) = runtime_by_name.get(host_name) else {
            continue;
        };
        match job.state {
            ProvisioningJobState::WaitingForHeartbeat
                if job.managed_identity.as_ref().is_some_and(|identity| {
                    identity.state == ProvisioningManagedIdentityState::AwaitingHeartbeat
                        && identity.bootstrap_completed_at.is_some_and(|completed_at| {
                            host.last_seen
                                .is_some_and(|last_seen| last_seen >= completed_at)
                        })
                }) =>
            {
                let setup = provisioning_job_setup_intent(&job);
                let next_state = if matches!(
                    setup.backup,
                    BackupSetupIntent::External | BackupSetupIntent::Absent
                ) {
                    ProvisioningJobState::Complete
                } else {
                    ProvisioningJobState::BackupPending
                };
                let message = if next_state == ProvisioningJobState::Complete {
                    "First authenticated heartbeat observed after bootstrap; onboarding is complete for the selected backup policy."
                } else {
                    "First authenticated heartbeat observed after bootstrap; backup decision or enrollment remains pending."
                };
                if let Some(observed_at) = host.last_seen {
                    let _ = provisioning_jobs.record_managed_first_heartbeat(
                        &job.id,
                        next_state,
                        message,
                        observed_at,
                        now,
                    );
                }
            }
            ProvisioningJobState::WaitingForHeartbeat
                if job.managed_identity.is_none()
                    && host
                        .last_seen
                        .is_some_and(|last_seen| last_seen >= job.updated_at) =>
            {
                let setup = provisioning_job_setup_intent(&job);
                let next_state = if matches!(
                    setup.backup,
                    BackupSetupIntent::External | BackupSetupIntent::Absent
                ) {
                    ProvisioningJobState::Complete
                } else {
                    ProvisioningJobState::BackupPending
                };
                let message = if next_state == ProvisioningJobState::Complete {
                    "First heartbeat observed; onboarding is complete for the selected backup policy."
                } else {
                    "First heartbeat observed; backup decision or enrollment remains pending."
                };
                let _ = provisioning_jobs.append_progress(&job.id, next_state, message, now);
            }
            ProvisioningJobState::CleanupNeeded
                if job.provider == "existing-host"
                    && host
                        .last_seen
                        .is_some_and(|last_seen| last_seen >= job.updated_at) =>
            {
                let setup = provisioning_job_setup_intent(&job);
                let next_state = if matches!(
                    setup.backup,
                    BackupSetupIntent::External | BackupSetupIntent::Absent
                ) {
                    ProvisioningJobState::Complete
                } else {
                    ProvisioningJobState::BackupPending
                };
                let message = if next_state == ProvisioningJobState::Complete {
                    "Authenticated heartbeat received after an uncertain install result; onboarding is complete for the selected backup policy."
                } else {
                    "Authenticated heartbeat received after an uncertain install result; backup decision or enrollment remains pending."
                };
                let _ = provisioning_jobs.append_progress(&job.id, next_state, message, now);
            }
            ProvisioningJobState::BackupPending if !host.backup_observations.is_empty() => {
                if job.managed_identity.is_some() {
                    let _ = provisioning_jobs.complete_managed_backup(&job.id, now);
                } else {
                    let _ = provisioning_jobs.append_progress(
                        &job.id,
                        ProvisioningJobState::Complete,
                        "Backup observation received; setup job complete.",
                        now,
                    );
                }
            }
            _ => {}
        }
    }
}

pub(super) fn render_setup_card(
    job: &ProvisioningJob,
    now: i64,
    can_manage_fleet: bool,
    base: &PublicBasePath,
) -> String {
    let Some(raw_name) = provisioning_job_host_name(job) else {
        return String::new();
    };
    let name = html_escape(raw_name);
    let role = html_escape(provisioning_job_role(job));
    let is_nix = job.is_nix.unwrap_or(false);
    let host_icon = if is_nix {
        icons::SNOWFLAKE
    } else {
        icons::SERVER
    };
    let (live_key, level, reason_level, sev, reason) = provisioning_job_fleet_status(job, now);
    let intent = provisioning_job_setup_intent(job);
    let intent_markup = setup_intent_markup(&intent);
    let search = html_escape(&format!(
        "{} {} setup provisioning {} {} {}",
        raw_name.to_lowercase(),
        provisioning_job_role(job).to_lowercase(),
        reason.to_lowercase(),
        job.state.label(),
        setup_intent_search_text(&intent).to_lowercase()
    ));
    let detail = if provisioning_job_first_heartbeat_overdue(job, now) {
        format!(
            "No first heartbeat after {}. Check beacon install, network, and host power.",
            duration_label(now.saturating_sub(job.updated_at))
        )
    } else {
        provisioning_job_latest_message(job)
    };
    let started = format!("setup started {} ago", duration_label(now - job.created_at));
    let header_action = if can_manage_fleet {
        format!(
            r#"<div class="card-actions"><a class="header-chip settings-card" href="{href}" title="Continue setup for {name}" aria-label="Continue setup for {name}"><span class="settings-icon">{settings}</span><span class="header-chip-label" aria-hidden="true">Setup</span></a></div>"#,
            href = app_href(base, &format!("/?setup=add-server&setup_job={}", job.id)),
            settings = icons::SLIDERS,
        )
    } else {
        String::new()
    };
    let continue_action = if can_manage_fleet {
        format!(
            r#"<div class="card-tools"><a class="setup-action" href="{href}">Continue setup</a></div>"#,
            href = app_href(base, &format!("/?setup=add-server&setup_job={}", job.id)),
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="card setup-card" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{updated_at}" data-search="{search}" data-host-surface="setup" data-setup-level="{level}"><header class="card-head"><div class="host"><span class="nix">{host_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div>{header_action}</header><div class="reason {reason_level}" data-reason><span>{reason}</span></div>{intent_markup}<div class="setup-detail">{detail}</div><div class="meta"><span>{started}</span><span>as of {as_of}</span></div>{continue_action}</article>"#,
        sort_name = html_escape(&raw_name.to_lowercase()),
        updated_at = job.updated_at,
        reason = html_escape(&reason),
        detail = html_escape(&detail),
        started = html_escape(&started),
        as_of = clock_label(now)
    )
}

pub(super) fn render_setup_row(
    job: &ProvisioningJob,
    now: i64,
    can_manage_fleet: bool,
    base: &PublicBasePath,
) -> String {
    let Some(raw_name) = provisioning_job_host_name(job) else {
        return String::new();
    };
    let name = html_escape(raw_name);
    let role = html_escape(provisioning_job_role(job));
    let is_nix = job.is_nix.unwrap_or(false);
    let host_icon = if is_nix {
        icons::SNOWFLAKE
    } else {
        icons::SERVER
    };
    let (live_key, level, reason_level, sev, reason) = provisioning_job_fleet_status(job, now);
    let intent = provisioning_job_setup_intent(job);
    let search = html_escape(&format!(
        "{} {} setup provisioning {} {} {}",
        raw_name.to_lowercase(),
        provisioning_job_role(job).to_lowercase(),
        reason.to_lowercase(),
        job.state.label(),
        setup_intent_search_text(&intent).to_lowercase()
    ));
    let started = format!("setup started {} ago", duration_label(now - job.created_at));
    let action = if can_manage_fleet {
        format!(
            r#"<a class="setup-action" href="{href}">Continue setup</a>"#,
            href = app_href(base, &format!("/?setup=add-server&setup_job={}", job.id)),
        )
    } else {
        String::new()
    };
    format!(
        r#"<tr class="setup-row" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-sort-name="{sort_name}" data-last="{updated_at}" data-search="{search}" data-host-surface="setup" data-setup-level="{level}"><td><div class="host"><span class="nix">{host_icon}</span><div><div class="name">{name}</div><div class="role">{role}</div></div></div></td><td><div class="list-attention"><div class="reason {reason_level}" data-reason><span>{reason}</span></div></div></td><td><div class="list-setup-intent"><span class="setup-chip backup">{backup}</span><span class="setup-chip location">{location}</span></div></td><td><span class="list-setup-state">{job_state}</span></td><td><div class="list-seen"><span>{started}</span></div></td><td><div class="list-actions">{action}</div></td></tr>"#,
        sort_name = html_escape(&raw_name.to_lowercase()),
        updated_at = job.updated_at,
        reason = html_escape(&reason),
        backup = html_escape(intent.backup_label()),
        location = html_escape(intent.location_label()),
        started = html_escape(&started),
        job_state = html_escape(job.state.label())
    )
}

pub(super) fn heartbeat_samples(log: &[i64], last_seen: Option<i64>) -> Vec<i64> {
    let mut samples = log.to_vec();
    if samples.is_empty() {
        if let Some(last) = last_seen {
            samples.push(last);
        }
    }
    samples.sort_unstable();
    samples.dedup();
    samples
}

pub(super) struct HeartbeatSignal {
    pub(super) text: String,
    pub(super) level: &'static str,
    pub(super) window: &'static str,
    pub(super) title: String,
    /// `full` covers the requested window, `partial` is still collecting, `none` has no usable reports.
    pub(super) coverage: &'static str,
}

fn delivery_samples(log: &[i64], last_seen: Option<i64>) -> Vec<i64> {
    let mut samples: Vec<i64> = log.iter().copied().filter(|stamp| *stamp > 0).collect();
    if let Some(last) = last_seen.filter(|stamp| *stamp > 0) {
        samples.push(last);
    }
    samples.sort_unstable();
    samples.dedup();
    samples
}

fn delivery_gap_label(seconds: i64) -> String {
    let seconds = seconds.max(0);
    if seconds < 10 {
        return format!("{seconds:.1}s");
    }
    if seconds < 60 {
        format!("{seconds}s")
    } else {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    }
}

fn delivery_window_tip(window_label: &str) -> String {
    let next = match window_label {
        "10m" => "1h",
        "1h" => "24h",
        _ => "10m",
    };
    format!("Heartbeat delivery window {window_label}; click for {next}. Not measured uptime.")
}

fn delivery_percent(received: usize, expected: usize) -> i64 {
    let expected = (expected.max(1)) as i64;
    let scaled = (received as i64).saturating_mul(100);
    ((scaled + expected / 2) / expected).clamp(0, 100)
}

pub(super) fn heartbeat_signal(
    log: &[i64],
    last_seen: Option<i64>,
    interval: i64,
    now: i64,
    window_label: &'static str,
    window_secs: i64,
) -> HeartbeatSignal {
    const UPTIME: &str = " Not measured host or service uptime.";
    let base = format!("Heartbeat delivery over {window_label}: ");
    let samples = delivery_samples(log, last_seen);
    if samples.is_empty() {
        return HeartbeatSignal {
            text: "—".to_string(),
            level: "wait",
            window: window_label,
            title: format!("{base}no reports yet.{UPTIME}"),
            coverage: "none",
        };
    }

    let cadence = if interval > 0 { interval } else { 60 };
    let window_secs = window_secs.max(cadence);
    let requested_start = now.saturating_sub(window_secs);
    let skew_limit = now.saturating_add(BACKUP_CLOCK_SKEW_SECS);
    let future_count = samples.iter().filter(|stamp| **stamp > skew_limit).count();
    let usable: Vec<i64> = samples
        .into_iter()
        .filter(|stamp| *stamp <= skew_limit)
        .collect();
    if usable.is_empty() {
        return HeartbeatSignal {
            text: "—".to_string(),
            level: "wait",
            window: window_label,
            title: format!("{base}reports are ahead of Pharos and were not counted.{UPTIME}"),
            coverage: "none",
        };
    }

    let retained_start = requested_start.max(usable[0]);
    let span = cadence.max(window_secs.min(now.saturating_sub(retained_start)));
    let expected = ((span + cadence - 1) / cadence).max(1) as usize;
    let received = usable
        .iter()
        .filter(|stamp| **stamp >= retained_start && **stamp <= now)
        .count();
    let mut previous = retained_start;
    let mut longest_gap = 0;
    for stamp in usable
        .iter()
        .copied()
        .filter(|stamp| *stamp >= retained_start && *stamp <= now)
    {
        longest_gap = longest_gap.max(stamp - previous);
        previous = stamp;
    }
    longest_gap = longest_gap.max(now.saturating_sub(previous));

    let percent = delivery_percent(received, expected);
    let level = if percent >= 95 {
        "good"
    } else if percent >= 75 {
        "warn"
    } else {
        "down"
    };
    let partial_window = usable[0] > requested_start + 1;
    let partial = if partial_window {
        format!(" Partial retention from {}.", clock_label(usable[0]))
    } else {
        String::new()
    };
    let coverage = if partial_window { "partial" } else { "full" };
    let skew = if future_count == 0 {
        String::new()
    } else {
        let noun = if future_count == 1 {
            "report"
        } else {
            "reports"
        };
        format!(" {future_count} clock-skewed {noun} ignored.")
    };
    HeartbeatSignal {
        text: format!("{percent}%"),
        level,
        window: window_label,
        title: format!(
            "{base}{received} of {expected} expected reports after duplicate collapse.{partial}{skew} Longest gap {}.{UPTIME}",
            delivery_gap_label(longest_gap),
        ),
        coverage,
    }
}

fn signal_coverage_markup(coverage: &str) -> String {
    if coverage == "partial" {
        r#"<span class="signal-coverage" data-signal-coverage="partial">partial</span>"#.to_string()
    } else {
        format!(r#"<span class="signal-coverage" data-signal-coverage="{coverage}" hidden></span>"#)
    }
}

pub(super) fn signal_markup(signal: &HeartbeatSignal) -> String {
    let title = html_escape(&signal.title);
    let window_tip = html_escape(&delivery_window_tip(signal.window));
    format!(
        r#"<span class="signal" data-signal data-signal-level="{level}" data-signal-window-key="{window}" data-signal-kind="delivery" title="{title}" aria-label="{title}"><span data-signal-percent>{text}</span><span class="signal-orb" aria-hidden="true"></span><button class="signal-window" type="button" data-signal-window title="{window_tip}" aria-label="{window_tip}">{window}</button>{coverage}</span>"#,
        level = html_escape(signal.level),
        text = html_escape(&signal.text),
        window = html_escape(signal.window),
        coverage = signal_coverage_markup(signal.coverage),
    )
}

pub(super) fn availability_markup(signal: &HeartbeatSignal) -> String {
    let title = html_escape(&signal.title);
    format!(
        r#"<span class="signal availability" data-signal data-signal-level="{level}" data-signal-window-key="{window}" data-signal-kind="delivery" title="{title}" aria-label="{title}"><span data-signal-percent>{text}</span><span class="signal-label">delivery</span>{coverage}</span>"#,
        level = html_escape(signal.level),
        text = html_escape(&signal.text),
        window = html_escape(signal.window),
        coverage = signal_coverage_markup(signal.coverage),
    )
}

pub(super) const EXTRA_HEAD_MARKER: &str = "<!--pharos-extra-head-->";

pub(super) fn head_with_extra(base: &PublicBasePath, extra: &str) -> String {
    let head = document_head(base);
    if let Some((before, after)) = head.split_once(EXTRA_HEAD_MARKER) {
        return format!("{before}{extra}{after}");
    }
    if let Some(index) = head.rfind("</head>") {
        let mut out = String::with_capacity(head.len() + extra.len());
        out.push_str(&head[..index]);
        out.push_str(extra);
        out.push_str(&head[index..]);
        return out;
    }
    format!("{head}{extra}")
}

pub(super) const LOCATION_STALE_AFTER_SECS: i64 = 24 * 3600;

#[derive(Debug, Clone, PartialEq)]
pub(super) struct SiteLocation {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) region: String,
    pub(super) lat: f64,
    pub(super) lon: f64,
    pub(super) source: HostLocationSource,
    pub(super) mode: &'static str,
    pub(super) state: &'static str,
    pub(super) stale: bool,
    pub(super) manual_override: bool,
    pub(super) observed_at: Option<i64>,
    pub(super) accuracy_meters: Option<f64>,
    pub(super) precision_meters: Option<f64>,
}

impl SiteLocation {
    fn from_site(site: &str, source: HostLocationSource) -> Self {
        let (id, label, region, lat, lon) = match site {
            "cloud" | "cloud-de" => ("cloud-de", "Cloud", "Germany", 50.1109, 8.6821),
            "home" | "home-at" => ("home-at", "Home", "Austria", 48.2082, 16.3738),
            "ww87" | "parents-home" => ("ww87", "Parents' home", "Austria", 48.32, 15.92),
            "parents-in-law" => ("parents-in-law", "Parents-in-law", "Austria", 48.13, 15.18),
            "dsc" | "dsc0" | "dsc-us" | "hillsboro-or" => {
                ("dsc-us", "DSC", "Hillsboro, OR, US", 45.5229, -122.9898)
            }
            _ => ("unknown", "Unknown site", "Not declared", 46.8, 8.2),
        };
        Self {
            id: id.to_string(),
            label: label.to_string(),
            region: region.to_string(),
            lat,
            lon,
            source,
            mode: "auto",
            state: if id == "unknown" { "unknown" } else { "known" },
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }

    fn from_host_location(
        location: &HostLocation,
        fallback_label: impl Into<String>,
        fallback_region: impl Into<String>,
        mode: &'static str,
        state: &'static str,
        now: i64,
    ) -> Self {
        let stale = location_stale(location, now);
        let label = location
            .label
            .clone()
            .unwrap_or_else(|| fallback_label.into());
        let region = fallback_region.into();
        let id = format!(
            "{}:{:.4},{:.4}",
            location_source_key(location.source),
            location.latitude,
            location.longitude
        );
        Self {
            id,
            label,
            region,
            lat: location.latitude,
            lon: location.longitude,
            source: location.source,
            mode,
            state: if stale { "stale" } else { state },
            stale,
            manual_override: location.manual_override,
            observed_at: location.observed_at,
            accuracy_meters: location.accuracy_meters,
            precision_meters: location.precision_meters,
        }
    }

    fn hidden() -> Self {
        Self {
            id: "hidden".to_string(),
            label: "Location hidden".to_string(),
            region: "Not shown".to_string(),
            lat: 46.8,
            lon: 8.2,
            source: HostLocationSource::Unknown,
            mode: "hidden",
            state: "hidden",
            stale: false,
            manual_override: false,
            observed_at: None,
            accuracy_meters: None,
            precision_meters: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct MapProbeTarget {
    endpoint: Option<(String, u16)>,
    kind: &'static str,
    policy: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MapSignal {
    pub(super) label: String,
    pub(super) level: &'static str,
    pub(super) title: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(super) policy: Option<&'static str>,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MapHost {
    pub(super) name: String,
    pub(super) role: String,
    pub(super) live: &'static str,
    pub(super) status: &'static str,
    pub(super) attention: String,
    pub(super) search: String,
    pub(super) site_id: String,
    pub(super) site_label: String,
    pub(super) region: String,
    pub(super) lat: f64,
    pub(super) lon: f64,
    pub(super) location_source: &'static str,
    pub(super) location_state: &'static str,
    pub(super) location_stale: bool,
    pub(super) location_manual_override: bool,
    pub(super) location: serde_json::Value,
    pub(super) is_pharos: bool,
    pub(super) inbound_label: String,
    pub(super) inbound_level: &'static str,
    pub(super) inbound_title: String,
    pub(super) outbound_label: String,
    pub(super) outbound_level: &'static str,
    pub(super) outbound_title: String,
    pub(super) outbound_policy: &'static str,
    pub(super) settings_href: String,
}

#[derive(Debug, Clone, Serialize)]
pub(super) struct MapDataPayload {
    pub(super) schema: &'static str,
    pub(super) as_of: i64,
    pub(super) hosts: Vec<MapHost>,
}

pub(super) fn site_location(site: &str) -> SiteLocation {
    SiteLocation::from_site(site, HostLocationSource::Provider)
}

pub(super) fn fallback_site_location(host: &str) -> SiteLocation {
    SiteLocation::from_site(fallback_site_for_host(host), HostLocationSource::Fallback)
}

pub(super) fn location_source_key(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi => "wifi",
        HostLocationSource::Ip => "ip",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

pub(super) fn location_source_label(source: HostLocationSource) -> &'static str {
    match source {
        HostLocationSource::Wifi | HostLocationSource::Ip => "auto",
        HostLocationSource::Provider => "provider",
        HostLocationSource::Declared => "declared",
        HostLocationSource::Fallback => "fallback",
        HostLocationSource::Unknown => "unknown",
    }
}

pub(super) fn location_stale(location: &HostLocation, now: i64) -> bool {
    if location.stale {
        return true;
    }
    location
        .observed_at
        .is_some_and(|observed| now.saturating_sub(observed) > LOCATION_STALE_AFTER_SECS)
}

pub(super) fn location_payload(location: &SiteLocation) -> serde_json::Value {
    json!({
        "latitude": location.lat,
        "longitude": location.lon,
        "source": location_source_key(location.source),
        "mode": location.mode,
        "state": location.state,
        "stale": location.stale,
        "manual_override": location.manual_override,
        "observed_at": location.observed_at,
        "accuracy_meters": location.accuracy_meters,
        "precision_meters": location.precision_meters,
        "label": location.label,
        "region": location.region,
        "site_id": location.id,
    })
}

pub(super) fn resolve_host_location(
    host: Option<&Host>,
    manifest: Option<&HostManifest>,
    host_name: &str,
    now: i64,
) -> SiteLocation {
    let mode = manifest
        .map(|manifest| manifest.host.location_mode)
        .unwrap_or_default();
    if mode == ManifestLocationMode::Hidden {
        return SiteLocation::hidden();
    }

    let provider = manifest
        .and_then(|manifest| {
            manifest
                .host
                .site
                .as_deref()
                .filter(|site| !site.trim().is_empty())
        })
        .map(site_location);

    let declared_location = manifest.and_then(|manifest| manifest.host.location.as_ref());

    if let Some(location) = declared_location.filter(|location| {
        mode == ManifestLocationMode::DeclaredOverride
            || (mode == ManifestLocationMode::Auto && location.manual_override)
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-override",
            "declared",
            now,
        );
    }

    if let Some(location) = host.and_then(|host| host.location.as_ref()) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "observed",
            "observed",
            now,
        );
    }

    if let Some(location) = declared_location.filter(|_| {
        matches!(
            mode,
            ManifestLocationMode::DeclaredFallback | ManifestLocationMode::Auto
        )
    }) {
        let fallback = provider
            .as_ref()
            .cloned()
            .unwrap_or_else(|| fallback_site_location(host_name));
        return SiteLocation::from_host_location(
            location,
            fallback.label,
            fallback.region,
            "declared-fallback",
            "declared",
            now,
        );
    }

    provider.unwrap_or_else(|| fallback_site_location(host_name))
}

pub(super) fn fallback_site_for_host(host: &str) -> &'static str {
    match host {
        "csb0" | "csb1" => "cloud-de",
        "hsb0" | "hsb1" | "gpc0" => "home-at",
        "hsb8" => "ww87",
        "hsb9" => "parents-in-law",
        "dsc0" => "dsc-us",
        _ => "unknown",
    }
}

pub(super) fn manifest_by_host(manifests: &[HostManifest]) -> BTreeMap<&str, &HostManifest> {
    let mut by_host = BTreeMap::new();
    for manifest in manifests {
        by_host.insert(manifest.host.name.as_str(), manifest);
        by_host.insert(manifest.slug.as_str(), manifest);
    }
    by_host
}

pub(super) fn preferences_summary(prefs: &HostPreferences) -> String {
    let mut parts = Vec::new();
    if let Some(days) = prefs.alerts.nixpkgs_warn_after_days {
        parts.push(format!("nixpkgs warning after {days}d"));
    }
    if let Some(secs) = prefs.alerts.heartbeat_grace_secs {
        parts.push(format!("heartbeat grace {secs}s"));
    }
    if let Some(accent) = prefs.accent.as_deref() {
        parts.push(format!("accent {}", accent));
    }
    if prefs.kind != HostKind::default() {
        parts.push(prefs.kind.label().to_string());
    }
    let mut muted = Vec::new();
    if prefs.alerts.suppress_down {
        muted.push("down");
    }
    if prefs.alerts.suppress_backup {
        muted.push("backup");
    }
    if prefs.alerts.suppress_nix_freshness {
        muted.push("nix freshness");
    }
    if !muted.is_empty() {
        parts.push(format!("mute {}", muted.join(", ")));
    }
    if parts.is_empty() {
        "defaults".to_string()
    } else {
        parts.join(" · ")
    }
}

pub(super) fn host_lifecycle_chip_markup(
    lifecycle: &HostLifecycle,
    settings_state: HostPreferencesState,
    interactive: bool,
    prefs_facts: Option<(String, String)>,
) -> String {
    let label = lifecycle.label.clone();
    let inert = if interactive {
        ""
    } else {
        " disabled aria-disabled=\"true\" tabindex=\"-1\""
    };
    let run_id_attr = lifecycle
        .run_id
        .as_ref()
        .map(|id| format!(r#" data-lifecycle-run-id="{}""#, html_escape(id)))
        .unwrap_or_default();
    let intent_attr = lifecycle
        .update_restart_intent
        .map_or(String::new(), |intent| {
            format!(
                r#" data-lifecycle-update-restart-intent="{}""#,
                intent.key()
            )
        });
    let blocked_by_attr = if lifecycle.blocked_by.is_empty() {
        String::new()
    } else {
        format!(
            r#" data-lifecycle-blocked-by="{}""#,
            html_escape(&lifecycle.blocked_by.join(","))
        )
    };
    let fact_attrs = prefs_facts.map_or(String::new(), |(declared, observed)| {
        format!(
            r#" data-lifecycle-declared-summary="{declared}" data-lifecycle-observed-summary="{observed}""#,
            declared = html_escape(&declared),
            observed = html_escape(&observed),
        )
    });
    let title = html_escape(&label);
    format!(
        r#"<button class="settings-wait-note host-lifecycle-chip" type="button" data-host-lifecycle-chip data-settings-state="{state}" data-lifecycle-slot="{slot}" data-lifecycle-level="{level}" data-lifecycle-invoke="{invoke}" data-lifecycle-detail="{detail}"{run_id_attr}{intent_attr}{blocked_by_attr}{fact_attrs}{inert} title="{title}" aria-label="{title}"><span class="settings-state-icon requested" aria-hidden="true">{requested_icon}</span><span class="settings-state-icon ready" aria-hidden="true">{ready_icon}</span><span class="settings-state-icon workflow" aria-hidden="true">{workflow_icon}</span><span data-host-lifecycle-chip-copy>{label}</span></button>"#,
        state = settings_state.key(),
        slot = lifecycle.slot.key(),
        level = lifecycle.level,
        invoke = lifecycle.invoke.key(),
        detail = html_escape(&lifecycle.detail),
        run_id_attr = run_id_attr,
        intent_attr = intent_attr,
        blocked_by_attr = blocked_by_attr,
        fact_attrs = fact_attrs,
        inert = inert,
        title = title,
        label = html_escape(&label),
        requested_icon = icons::CLOCK_3,
        ready_icon = icons::DOWNLOAD,
        workflow_icon = icons::HISTORY,
    )
}

pub(super) fn pending_preference_color<'a>(
    state: HostPreferencesState,
    declared: Option<&'a HostPreferences>,
    requested: Option<&'a HostPreferences>,
) -> Option<&'a str> {
    match state {
        HostPreferencesState::Applied => None,
        HostPreferencesState::RequestPending => requested.and_then(|value| value.accent.as_deref()),
        HostPreferencesState::DeclaredNotApplied => declared
            .and_then(|value| value.accent.as_deref())
            .or_else(|| requested.and_then(|value| value.accent.as_deref())),
    }
}

pub(super) fn valid_preference_accent(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.len() == 7 && bytes.first() == Some(&b'#') && bytes[1..].iter().all(u8::is_ascii_hexdigit)
}

pub(super) fn split_probe_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Ok(url) = Url::parse(trimmed) {
        let host = url.host_str()?.trim().to_string();
        if host.is_empty() {
            return None;
        }
        return Some((host, url.port_or_known_default().unwrap_or(default_port)));
    }
    let target = trimmed
        .trim_start_matches("//")
        .split('/')
        .next()
        .unwrap_or(trimmed)
        .trim();
    if target.is_empty() {
        return None;
    }
    let target = target.rsplit('@').next().unwrap_or(target).trim();
    if target.is_empty() {
        return None;
    }
    if let Some((host, port)) = target.rsplit_once(':') {
        if !host.contains(':') {
            if let Ok(port) = port.parse::<u16>() {
                return Some((host.to_string(), port));
            }
        }
    }
    Some((target.to_string(), default_port))
}

pub(super) fn normalize_outbound_policy(policy: &str) -> Option<&'static str> {
    match policy.trim().to_ascii_lowercase().as_str() {
        "expected" | "reachable" | "allow" | "allowed" | "required" => Some("expected"),
        "blocked" | "deny" | "denied" | "intentional-block" | "intentional_block" => {
            Some("blocked")
        }
        "unknown" | "probe" | "best-effort" | "best_effort" => Some("unknown"),
        _ => None,
    }
}

pub(super) fn manifest_outbound_policy(
    host: &str,
    manifests: &[HostManifest],
) -> Option<&'static str> {
    let manifests = manifest_by_host(manifests);
    let manifest = manifests.get(host)?;
    [
        "pharosOutbound",
        "pharosOutboundPolicy",
        "pharosConnectivity",
    ]
    .into_iter()
    .find_map(|key| manifest.host.access.get(key))
    .and_then(|value| normalize_outbound_policy(value))
}

pub(super) fn outbound_policy_for_host(host: &Host, manifests: &[HostManifest]) -> &'static str {
    manifest_outbound_policy(&host.name, manifests).unwrap_or("unknown")
}

pub(super) fn map_probe_target(host: &Host, manifests: &[HostManifest]) -> MapProbeTarget {
    let policy = outbound_policy_for_host(host, manifests);
    if policy == "blocked" {
        return MapProbeTarget {
            endpoint: None,
            kind: "tailnet ssh",
            policy,
        };
    }
    let manifests = manifest_by_host(manifests);
    if let Some(manifest) = manifests.get(host.name.as_str()) {
        if let Some(tailnet) = manifest.host.tailnet_hostname() {
            if let Some((host, port)) = split_probe_host_port(tailnet, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "tailnet ssh",
                    policy,
                };
            }
        }
        if let Some(lan) = manifest.host.lan_hostname() {
            if let Some((host, port)) = split_probe_host_port(lan, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
        if let Some(ip) = manifest.host.lan_ip() {
            if let Some((host, port)) = split_probe_host_port(ip, 2222) {
                return MapProbeTarget {
                    endpoint: Some((host, port)),
                    kind: "lan ssh",
                    policy,
                };
            }
        }
    }
    MapProbeTarget {
        endpoint: Some((format!("{}.ts.barta.cm", host.name), 2222)),
        kind: "tailnet ssh",
        policy,
    }
}

pub(super) fn default_map_signal() -> MapSignal {
    MapSignal {
        label: "checking".to_string(),
        level: "wait",
        title: "Pharos reachability check is pending".to_string(),
        policy: None,
    }
}

pub(super) async fn map_connectivity_probe(target: MapProbeTarget) -> MapSignal {
    let Some((host, port)) = target.endpoint else {
        return MapSignal {
            label: if target.policy == "blocked" {
                "blocked".to_string()
            } else {
                "unknown".to_string()
            },
            level: "wait",
            title: if target.policy == "blocked" {
                "Outbound access from Pharos is blocked by policy".to_string()
            } else {
                "No outbound probe endpoint declared".to_string()
            },
            policy: Some(target.policy),
        };
    };
    let started = Instant::now();
    match timeout(
        SERVER_PROBE_TIMEOUT,
        TcpStream::connect((host.as_str(), port)),
    )
    .await
    {
        Ok(Ok(_)) => {
            let elapsed_ms = started.elapsed().as_millis().max(1);
            MapSignal {
                label: format!("{elapsed_ms} ms"),
                level: "good",
                title: format!(
                    "Pharos {kind} check to {host}:{port} reachable in {elapsed_ms} ms",
                    kind = target.kind,
                    host = host,
                    port = port
                ),
                policy: Some(target.policy),
            }
        }
        Ok(Err(_)) => MapSignal {
            label: "no route".to_string(),
            level: if target.policy == "expected" {
                "down"
            } else {
                "warn"
            },
            title: format!(
                "Pharos {kind} check to {host}:{port} failed",
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
        Err(_) => MapSignal {
            label: "timeout".to_string(),
            level: "warn",
            title: format!(
                "Pharos {kind} check to {host}:{port} timed out after {} ms",
                SERVER_PROBE_TIMEOUT.as_millis(),
                kind = target.kind,
                host = host,
                port = port
            ),
            policy: Some(target.policy),
        },
    }
}

pub(super) async fn map_connectivity_probes(
    hosts: &[Host],
    manifests: &[HostManifest],
) -> BTreeMap<String, MapSignal> {
    let mut jobs = JoinSet::new();
    for host in hosts {
        let name = host.name.clone();
        let target = map_probe_target(host, manifests);
        jobs.spawn(async move { (name, map_connectivity_probe(target).await) });
    }
    let mut probes = BTreeMap::new();
    while let Some(result) = jobs.join_next().await {
        if let Ok((name, probe)) = result {
            probes.insert(name, probe);
        }
    }
    probes
}

pub(super) fn map_inbound_signal(host: &Host, is_pharos: bool, now: i64) -> MapSignal {
    if is_pharos {
        return MapSignal {
            label: "local".to_string(),
            level: "good",
            title: "Pharos is the local control host".to_string(),
            policy: None,
        };
    }
    if let Some(rtt) = host.inbound_rtt {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        let level = match live {
            Liveness::Live => {
                if rtt.millis <= 500 {
                    "good"
                } else {
                    "warn"
                }
            }
            Liveness::Stale => "warn",
            Liveness::Down => "down",
            Liveness::AwaitingFirstHeartbeat => "wait",
        };
        let observed_age = (now - rtt.observed_at).max(0);
        return MapSignal {
            label: format!("{} ms", rtt.millis),
            level,
            title: format!(
                "Host-to-Pharos report submit RTT from {} was {} ms, observed {} ago",
                host.name,
                rtt.millis,
                duration_label(observed_age)
            ),
            policy: None,
        };
    }
    let Some(last_seen) = host.last_seen else {
        return MapSignal {
            label: "waiting".to_string(),
            level: "wait",
            title: "No heartbeat from this host has reached Pharos yet".to_string(),
            policy: None,
        };
    };
    let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
    let level = match live {
        Liveness::Live => "good",
        Liveness::Stale => "warn",
        Liveness::Down => "down",
        Liveness::AwaitingFirstHeartbeat => "wait",
    };
    let age = (now - last_seen).max(0);
    MapSignal {
        label: format!("beat {}", duration_label(age)),
        level,
        title: format!(
            "No measured inbound RTT yet; last heartbeat from {} reached Pharos {} ago",
            host.name,
            duration_label(age)
        ),
        policy: None,
    }
}

pub(super) fn map_hosts(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
    fleet_threshold: u32,
) -> Vec<MapHost> {
    let manifests = manifest_by_host(manifests);
    let mut mapped = hosts
        .iter()
        .map(|host| {
            let is_pharos = host.name == self_name;
            let mut live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
            if is_pharos {
                live = Liveness::Live;
            }
            let (_color, status) = live.badge();
            let attention = if host.name == self_name {
                self_attention_reason()
            } else {
                attention_reason(
                    live,
                    &host.freshness,
                    host.kernel.as_ref(),
                    &host.service_observations,
                    &host.preferences,
                    now,
                    fleet_threshold,
                )
            };
            let site = resolve_host_location(
                Some(host),
                manifests.get(host.name.as_str()).copied(),
                &host.name,
                now,
            );
            let inbound = map_inbound_signal(host, is_pharos, now);
            let outbound = probes
                .get(&host.name)
                .cloned()
                .unwrap_or_else(default_map_signal);
            let search = format!(
                "{} {} {} {} {} {} {} {} {} {}",
                host.name,
                host.role,
                status,
                attention.label,
                site.label,
                site.region,
                location_source_key(site.source),
                location_source_label(site.source),
                inbound.label,
                outbound.label
            )
            .to_lowercase();
            let location = location_payload(&site);
            MapHost {
                name: host.name.clone(),
                role: host.role.clone(),
                live: live_key(live),
                status,
                attention: attention.label,
                search,
                site_id: site.id,
                site_label: site.label,
                region: site.region,
                lat: site.lat,
                lon: site.lon,
                location_source: location_source_key(site.source),
                location_state: site.state,
                location_stale: site.stale,
                location_manual_override: site.manual_override,
                location,
                is_pharos,
                inbound_label: inbound.label,
                inbound_level: inbound.level,
                inbound_title: inbound.title,
                outbound_label: outbound.label,
                outbound_level: outbound.level,
                outbound_title: outbound.title,
                outbound_policy: outbound.policy.unwrap_or("unknown"),
                settings_href: format!("/hosts/{}", url_query_escape(&host.name)),
            }
        })
        .collect::<Vec<_>>();
    mapped.sort_by(|a, b| {
        a.site_label
            .cmp(&b.site_label)
            .then_with(|| a.name.cmp(&b.name))
    });
    mapped
}

pub(super) fn map_data_payload(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    probes: &BTreeMap<String, MapSignal>,
    fleet_threshold: u32,
) -> MapDataPayload {
    MapDataPayload {
        schema: "inspr.pharos.map-data.v1",
        as_of: now,
        hosts: map_hosts(hosts, self_name, now, manifests, probes, fleet_threshold),
    }
}

#[derive(Debug, Clone)]
pub(super) struct AlertItem {
    pub(super) level: &'static str,
    pub(super) host: String,
    pub(super) role: String,
    pub(super) issue: String,
    pub(super) detail: String,
    pub(super) source: &'static str,
    pub(super) seen: String,
    pub(super) next_action: String,
    pub(super) sort_time: i64,
}

#[derive(Debug, Clone)]
pub(super) struct AlertGroup {
    level: &'static str,
    hosts: Vec<(String, String)>,
    issue: String,
    detail: String,
    source: &'static str,
    seen: String,
    next_action: String,
    sort_time: i64,
    count: usize,
}

#[derive(Debug, Clone)]
pub(super) struct ActivityEvent {
    pub(super) timestamp: i64,
    pub(super) host: String,
    pub(super) level: &'static str,
    pub(super) kind: &'static str,
    pub(super) title: String,
    pub(super) detail: String,
    pub(super) source: &'static str,
    pub(super) workflow_id: Option<String>,
}

impl ActivityEvent {
    fn new(
        timestamp: i64,
        host: impl Into<String>,
        level: &'static str,
        kind: &'static str,
        title: impl Into<String>,
        detail: impl Into<String>,
        source: &'static str,
    ) -> Self {
        Self {
            timestamp,
            host: host.into(),
            level,
            kind,
            title: title.into(),
            detail: detail.into(),
            source,
            workflow_id: None,
        }
    }

    fn with_workflow(mut self, workflow_id: impl Into<String>) -> Self {
        self.workflow_id = Some(workflow_id.into());
        self
    }
}

pub(super) fn level_rank(level: &str) -> usize {
    match level {
        "critical" => 0,
        "warning" => 1,
        "watch" => 2,
        "recovery" => 3,
        "info" => 4,
        "clear" => 5,
        _ => 6,
    }
}

pub(super) fn level_label(level: &str) -> &'static str {
    match level {
        "critical" => "critical",
        "warning" => "warning",
        "watch" => "watch",
        "recovery" => "recovery",
        "info" => "info",
        "clear" => "clear",
        _ => "info",
    }
}

pub(super) fn seen_label(last_seen: Option<i64>, now: i64) -> String {
    match last_seen {
        Some(seen) => format!("{} ago", duration_label(now - seen)),
        None => "never".to_string(),
    }
}

pub(super) fn freshness_alert(
    freshness: &NixFreshness,
    now: i64,
    threshold: u32,
) -> Option<(&'static str, String, String)> {
    if !freshness.applicable {
        return None;
    }
    if freshness.deployment_evidence.is_none() {
        return Some((
            "watch",
            "Active-generation freshness is unverified".to_string(),
            "Install generation-owned deployment evidence; do not infer state from the checkout."
                .to_string(),
        ));
    }
    let (year, month) = pharos_core::utc_year_month(now);
    if freshness.channel_state(year, month) == Some(pharos_core::NixChannelState::EndOfLife) {
        let channel = freshness
            .deployment_evidence
            .as_ref()
            .map(|evidence| evidence.nixpkgs_channel.as_str())
            .unwrap_or("nixpkgs");
        return Some((
            "warning",
            format!("{channel} is end of life"),
            "Move the active generation to a supported nixpkgs channel before calling it current."
                .to_string(),
        ));
    }
    if freshness.nixcfg_comparison.is_none() || freshness.nixpkgs_comparison.is_none() {
        return Some((
            "watch",
            "Authoritative freshness comparison is unavailable".to_string(),
            "Restore the bounded Git comparison; unknown must never be treated as current."
                .to_string(),
        ));
    }
    if freshness.nixpkgs_age_warning_at(now, threshold)
        || freshness
            .nixcfg_comparison
            .as_ref()
            .is_some_and(|comparison| comparison.relation != GitRevisionRelation::Current)
    {
        return Some((
            "warning",
            freshness.tldr(),
            "Review the exact deployed, nixcfg, and nixpkgs revisions before updating.".to_string(),
        ));
    }
    None
}

pub(super) fn kernel_alert(host: &Host, now: i64) -> Option<AlertItem> {
    let kernel = kernel_reboot_required(host.kernel.as_ref())?;
    let running = kernel.running_version.as_deref()?;
    let expected = kernel.expected_version.as_deref()?;
    Some(AlertItem {
        level: "warning",
        host: host.name.clone(),
        role: host.role.clone(),
        issue: "Restart needed".to_string(),
        detail: format!(
            "Running kernel {running}; kernel {expected} is ready after the next planned restart."
        ),
        source: "kernel",
        seen: format!(
            "{} ago",
            duration_label(now.saturating_sub(kernel.observed_at))
        ),
        next_action: "Plan a controlled restart when the host's workload allows it.".to_string(),
        sort_time: kernel.observed_at,
    })
}

pub(super) fn service_alert(
    host: &Host,
    observation: &ServiceObservation,
    now: i64,
) -> Option<AlertItem> {
    if is_nix_freshness_observation(observation) {
        return None;
    }

    if appliance_probes::is_appliance_observation(observation)
        && observation.state == ServiceObservationState::Unknown
        && observation
            .summary
            .starts_with("online; allowing SSH startup")
    {
        return None;
    }

    let (level, action) = match observation.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning
            if appliance_probes::is_appliance_observation(observation) =>
        {
            (
                "warning",
                "Restore appliance convergence locally; Pharos will not remediate it.",
            )
        }
        ServiceObservationState::Warning => ("warning", "Inspect the service on the host."),
        ServiceObservationState::Stale => ("warning", "Verify the service is still reporting."),
        ServiceObservationState::Unknown => {
            ("watch", "Confirm whether this service should report state.")
        }
    };
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!("{}: {}", observation.label, observation.state.label()),
        detail: observation.summary.clone(),
        source: "service",
        seen: seen_label(host.last_seen, now),
        next_action: action.to_string(),
        sort_time: host.last_seen.unwrap_or(now),
    })
}

pub(super) fn backup_sort_time(host: &Host, observation: &BackupObservation, now: i64) -> i64 {
    observation
        .last_attempt_at
        .or(observation.last_success_at)
        .or(observation.last_check_at)
        .or(host.last_seen)
        .unwrap_or(now)
}

pub(super) fn backup_alert(
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) -> Option<AlertItem> {
    let (level, action) = match observation.state {
        BackupPostureState::Healthy => return None,
        BackupPostureState::Failed => (
            "critical",
            "Inspect the backup job, fix the failure, then confirm the next successful run.",
        ),
        BackupPostureState::Missing => (
            "critical",
            "Restore or declare the expected backup job for this host.",
        ),
        BackupPostureState::Stale => (
            "warning",
            "Confirm the backup schedule, runner, and latest successful snapshot.",
        ),
        BackupPostureState::Warning => (
            "warning",
            "Review backup evidence and schedule before the next maintenance window.",
        ),
        BackupPostureState::Unknown => (
            "watch",
            "Confirm the backup collector can observe this job.",
        ),
        BackupPostureState::NotConfigured => (
            "watch",
            "Decide whether this host should be protected or intentionally unprotected.",
        ),
    };
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!(
            "{}: {}",
            observation.label,
            backup_state_label(observation.state)
        ),
        detail: observation.summary.clone(),
        source: "backup",
        seen: format!(
            "{} ago",
            duration_label((now - backup_sort_time(host, observation, now)).max(0))
        ),
        next_action: action.to_string(),
        sort_time: backup_sort_time(host, observation, now),
    })
}

pub(super) fn backup_validation_alert(
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) -> Option<AlertItem> {
    let restore = observation.restore_validation.as_ref();
    let (state, checked_at, label, detail) = if let Some(restore) = restore {
        (
            restore.state,
            restore.checked_at,
            restore
                .evidence_label
                .as_deref()
                .unwrap_or_else(|| backup_validation_level_label(restore.level))
                .to_string(),
            restore
                .summary
                .clone()
                .unwrap_or_else(|| backup_validation_label(observation, now)),
        )
    } else {
        let state = observation.last_check_state?;
        (
            state,
            observation.last_check_at,
            "backup check".to_string(),
            backup_validation_label(observation, now),
        )
    };

    let (level, issue, action) = match state {
        pharos_core::BackupValidationState::Failed => (
            "critical",
            "Restore validation failed",
            "Inspect validation evidence and run a clean restore or repository check.",
        ),
        pharos_core::BackupValidationState::Stale => (
            "warning",
            "Restore validation overdue",
            "Run a restore validation or repository check and let Pharos observe it.",
        ),
        pharos_core::BackupValidationState::Passed
        | pharos_core::BackupValidationState::Unknown => return None,
    };

    let sort_time = checked_at.unwrap_or_else(|| backup_sort_time(host, observation, now));
    Some(AlertItem {
        level,
        host: host.name.clone(),
        role: host.role.clone(),
        issue: format!("{}: {}", observation.label, issue),
        detail: label + " - " + &detail,
        source: "backup",
        seen: format!("{} ago", duration_label((now - sort_time).max(0))),
        next_action: action.to_string(),
        sort_time,
    })
}

pub(super) fn is_nix_freshness_observation(observation: &ServiceObservation) -> bool {
    observation.id == "nix-freshness" || observation.label.eq_ignore_ascii_case("Nix freshness")
}

pub(super) fn probe_alert(
    host: &str,
    role: &str,
    probe: &ServerProbeObservation,
) -> Option<AlertItem> {
    let (level, action) = match probe.state {
        ServiceObservationState::Healthy => return None,
        ServiceObservationState::Warning => (
            "warning",
            "Check the service route, firewall, or probe target.",
        ),
        ServiceObservationState::Stale => ("warning", "Re-check the service probe path."),
        ServiceObservationState::Unknown => ("watch", "Complete the service probe declaration."),
    };
    Some(AlertItem {
        level,
        host: host.to_string(),
        role: role.to_string(),
        issue: format!("{} probe {}", probe.service, probe.state.label()),
        detail: probe.summary.clone(),
        source: "probe",
        seen: format!("as of {}", clock_label(probe.checked_at)),
        next_action: action.to_string(),
        sort_time: probe.checked_at,
    })
}

pub(super) fn provisioning_job_alert(
    job: &ProvisioningJob,
    runtime_names: &BTreeSet<&str>,
    now: i64,
) -> Option<AlertItem> {
    let host = provisioning_job_host_name(job)?;
    if runtime_names.contains(host) && !matches!(job.state, ProvisioningJobState::BackupPending) {
        return None;
    }

    let latest = provisioning_job_latest_message(job);
    let (level, issue, detail, action) = match job.state {
        ProvisioningJobState::Planning
        | ProvisioningJobState::Provisioning
        | ProvisioningJobState::Bootstrapping => (
            "watch",
            "Setup in progress",
            latest,
            "Continue setup and wait for the first valid beacon heartbeat.",
        ),
        ProvisioningJobState::WaitingForHeartbeat => {
            if provisioning_job_first_heartbeat_overdue(job, now) {
                (
                    "warning",
                    "First heartbeat overdue",
                    format!(
                        "No first heartbeat after {}.",
                        duration_label(now.saturating_sub(job.updated_at))
                    ),
                    "Check beacon install, network, and host power.",
                )
            } else {
                (
                    "watch",
                    "Waiting for first heartbeat",
                    latest,
                    "Finish the beacon handoff and keep onboarding open.",
                )
            }
        }
        ProvisioningJobState::BackupPending => (
            "watch",
            "Backup enrollment pending",
            latest,
            "Record backup posture or wait for the first backup observation.",
        ),
        ProvisioningJobState::Failed => (
            "critical",
            "Setup failed",
            latest,
            "Open the setup assistant, correct the blocker, and retry.",
        ),
        ProvisioningJobState::CleanupNeeded => (
            "critical",
            "Setup cleanup needed",
            latest,
            "Review provider state before retrying or removing the job.",
        ),
        ProvisioningJobState::Complete => return None,
    };

    Some(AlertItem {
        level,
        host: host.to_string(),
        role: provisioning_job_role(job).to_string(),
        issue: issue.to_string(),
        detail,
        source: "setup",
        seen: format!("as of {}", clock_label(job.updated_at)),
        next_action: action.to_string(),
        sort_time: job.updated_at,
    })
}

pub(super) fn alert_items(
    hosts: &[Host],
    jobs: &[ProvisioningJob],
    fleet_threshold: u32,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
) -> Vec<AlertItem> {
    let mut alerts = Vec::new();
    let runtime_by_name: BTreeMap<&str, &Host> = hosts
        .iter()
        .map(|host| (host.name.as_str(), host))
        .collect();
    let runtime_names: BTreeSet<&str> = runtime_by_name.keys().copied().collect();
    let manifest_roles: BTreeMap<&str, &str> = manifests
        .iter()
        .map(|manifest| {
            (
                manifest.host.name.as_str(),
                manifest.host.role.as_deref().unwrap_or("declared host"),
            )
        })
        .collect();

    for issue in load_errors {
        alerts.push(AlertItem {
            level: "critical",
            host: "Pharos".to_string(),
            role: "manifest loader".to_string(),
            issue: "Declared host manifest failed to load".to_string(),
            detail: format!("{} - {}", issue.path, issue.error),
            source: "config",
            seen: format!("as of {}", clock_label(now)),
            next_action: "Fix the manifest and restart or reload Pharos.".to_string(),
            sort_time: now,
        });
    }

    for manifest in manifests {
        let runtime = runtime_by_name
            .get(manifest.host.name.as_str())
            .copied()
            .or_else(|| runtime_by_name.get(manifest.slug.as_str()).copied());
        if runtime.is_none() {
            alerts.push(AlertItem {
                level: "watch",
                host: manifest.host.name.clone(),
                role: manifest
                    .host
                    .role
                    .clone()
                    .unwrap_or_else(|| "declared host".to_string()),
                issue: "Declared host has not reported yet".to_string(),
                detail:
                    "The host exists in declared metadata, but no runtime heartbeat is present."
                        .to_string(),
                source: "config",
                seen: "never".to_string(),
                next_action: "Install or start pharos-beacon, or remove stale metadata."
                    .to_string(),
                sort_time: now,
            });
        }
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        let appliance_observed = host
            .service_observations
            .iter()
            .any(appliance_probes::is_appliance_observation);
        match live {
            _ if appliance_observed => {}
            Liveness::Down if !host.preferences.suppresses_down_alerts() => {
                alerts.push(AlertItem {
                    level: "critical",
                    host: host.name.clone(),
                    role: host.role.clone(),
                    issue: "No heartbeat received".to_string(),
                    detail: "Pharos has not received a report within the allowed heartbeat window."
                        .to_string(),
                    source: "heartbeat",
                    seen: seen_label(host.last_seen, now),
                    next_action: "Check host power, network, and pharos-beacon.".to_string(),
                    sort_time: host.last_seen.unwrap_or(now),
                })
            }
            Liveness::Down => {}
            Liveness::Stale => alerts.push(AlertItem {
                level: "warning",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Heartbeat is late".to_string(),
                detail: "The host checked in later than its normal cadence.".to_string(),
                source: "heartbeat",
                seen: seen_label(host.last_seen, now),
                next_action: "Verify pharos-beacon and recent host load.".to_string(),
                sort_time: host.last_seen.unwrap_or(now),
            }),
            Liveness::AwaitingFirstHeartbeat => alerts.push(AlertItem {
                level: "watch",
                host: host.name.clone(),
                role: host.role.clone(),
                issue: "Waiting for first heartbeat".to_string(),
                detail: "The host is registered but has not sent a first report.".to_string(),
                source: "heartbeat",
                seen: "never".to_string(),
                next_action: "Finish onboarding or confirm the host should exist.".to_string(),
                sort_time: now,
            }),
            Liveness::Live => {}
        }

        if !host.preferences.alerts.suppress_nix_freshness {
            if let Some((level, issue, action)) = freshness_alert(
                &host.freshness,
                now,
                host.preferences
                    .nixpkgs_warn_after_days(Some(fleet_threshold)),
            ) {
                alerts.push(AlertItem {
                    level,
                    host: host.name.clone(),
                    role: host.role.clone(),
                    issue,
                    detail: "Nix freshness differs from the preferred declared state.".to_string(),
                    source: "freshness",
                    seen: seen_label(host.last_seen, now),
                    next_action: action,
                    sort_time: host.last_seen.unwrap_or(now),
                });
            }
        }

        if let Some(alert) = kernel_alert(host, now) {
            alerts.push(alert);
        }

        for observation in &host.service_observations {
            if let Some(alert) = service_alert(host, observation, now) {
                alerts.push(alert);
            }
        }

        if !host.preferences.alerts.suppress_backup {
            for observation in &host.backup_observations {
                if let Some(alert) = backup_alert(host, observation, now) {
                    alerts.push(alert);
                }
                if let Some(alert) = backup_validation_alert(host, observation, now) {
                    alerts.push(alert);
                }
            }

            if let Some(alert) = protection_onboarding_alert(host, jobs, now) {
                alerts.push(alert);
            }
        }
    }

    for job in jobs {
        if let Some(alert) = provisioning_job_alert(job, &runtime_names, now) {
            alerts.push(alert);
        }
    }

    for (host, probes) in server_probes {
        let role = runtime_by_name
            .get(host.as_str())
            .map(|host| host.role.as_str())
            .or_else(|| manifest_roles.get(host.as_str()).copied())
            .unwrap_or("declared service");
        for probe in probes {
            if let Some(alert) = probe_alert(host, role, probe) {
                alerts.push(alert);
            }
        }
    }

    alerts.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.host.cmp(&right.host))
            .then_with(|| left.source.cmp(right.source))
    });
    alerts
}

pub(super) fn alert_counts(alerts: &[AlertItem], hosts: &[Host]) -> (usize, usize, usize, usize) {
    let critical = alerts
        .iter()
        .filter(|alert| alert.level == "critical")
        .count();
    let warning = alerts
        .iter()
        .filter(|alert| alert.level == "warning")
        .count();
    let watch = alerts.iter().filter(|alert| alert.level == "watch").count();
    let affected: std::collections::BTreeSet<&str> = alerts
        .iter()
        .filter(|alert| alert.host != "Pharos")
        .map(|alert| alert.host.as_str())
        .collect();
    let clear = hosts.len().saturating_sub(affected.len());
    (critical, warning, watch, clear)
}

pub(super) fn alert_groups(alerts: &[AlertItem]) -> Vec<AlertGroup> {
    let mut groups: Vec<AlertGroup> = Vec::new();

    for alert in alerts {
        if let Some(group) = groups.iter_mut().find(|group| {
            group.level == alert.level
                && group.source == alert.source
                && group.issue == alert.issue
                && group.detail == alert.detail
                && group.next_action == alert.next_action
        }) {
            group.count += 1;
            if !group.hosts.iter().any(|(host, _)| host == &alert.host) {
                group.hosts.push((alert.host.clone(), alert.role.clone()));
            }
            if alert.sort_time >= group.sort_time {
                group.sort_time = alert.sort_time;
                group.seen = alert.seen.clone();
            }
        } else {
            groups.push(AlertGroup {
                level: alert.level,
                hosts: vec![(alert.host.clone(), alert.role.clone())],
                issue: alert.issue.clone(),
                detail: alert.detail.clone(),
                source: alert.source,
                seen: alert.seen.clone(),
                next_action: alert.next_action.clone(),
                sort_time: alert.sort_time,
                count: 1,
            });
        }
    }

    for group in &mut groups {
        group.hosts.sort_by(|left, right| left.0.cmp(&right.0));
    }
    groups.sort_by(|left, right| {
        level_rank(left.level)
            .cmp(&level_rank(right.level))
            .then_with(|| right.sort_time.cmp(&left.sort_time))
            .then_with(|| left.issue.cmp(&right.issue))
            .then_with(|| left.source.cmp(right.source))
    });
    groups
}

pub(super) fn ops_summary_metrics(alerts: &[AlertItem], hosts: &[Host]) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    format!(
        r#"<section class="ops-summary" aria-label="alert summary"><button class="ops-metric critical" type="button" data-ops-filter="critical" aria-pressed="false"><b>{critical}</b><span>critical</span></button><button class="ops-metric warning" type="button" data-ops-filter="warning" aria-pressed="false"><b>{warning}</b><span>warning</span></button><button class="ops-metric watch" type="button" data-ops-filter="watch" aria-pressed="false"><b>{watch}</b><span>watch</span></button><button class="ops-metric clear" type="button" data-ops-filter="clear" aria-pressed="false"><b>{clear}</b><span>clear</span></button></section>"#
    )
}

pub(super) fn alert_group_host_label(group: &AlertGroup) -> (String, String) {
    if group.hosts.len() == 1 {
        return group.hosts[0].clone();
    }

    let mut names = group
        .hosts
        .iter()
        .take(3)
        .map(|(host, _)| host.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    if group.hosts.len() > 3 {
        names.push_str(&format!(" +{} more", group.hosts.len() - 3));
    }
    (format!("{} hosts", group.hosts.len()), names)
}

pub(super) fn alert_group_host_search(group: &AlertGroup) -> String {
    let mut parts = Vec::new();
    for (host, role) in &group.hosts {
        parts.push(host.as_str());
        parts.push(role.as_str());
    }
    parts.push(group.issue.as_str());
    parts.push(group.detail.as_str());
    parts.push(group.source);
    parts.join(" ").to_lowercase()
}

pub(super) fn render_alert_row(group: &AlertGroup) -> String {
    let (host_label, host_detail) = alert_group_host_label(group);
    let repeat = if group.count > 1 {
        format!(
            r#"<span class="alert-repeat">{count} alerts</span>"#,
            count = group.count
        )
    } else {
        String::new()
    };
    format!(
        r#"<article class="alert-row {level}" data-ops-row data-ops-level="{level}" data-ops-kind="{source}" data-host-search="{host_search}"><div class="alert-host"><span class="alert-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{role}</span></div></div><div class="alert-status"><span class="severity">{level_label}</span>{repeat}</div><div class="alert-issue"><strong>{issue}</strong><p>{detail}</p></div><span class="ops-source">{source}</span><span class="ops-time">{seen}</span><span class="next-action">{next_action}</span></article>"#,
        level = html_escape(group.level),
        level_label = level_label(group.level),
        repeat = repeat,
        host = html_escape(&host_label),
        role = html_escape(&host_detail),
        issue = html_escape(&group.issue),
        detail = html_escape(&group.detail),
        source = html_escape(group.source),
        seen = html_escape(&group.seen),
        next_action = html_escape(&group.next_action),
        host_search = html_escape(&alert_group_host_search(group))
    )
}

pub(super) fn render_alert_rows(groups: &[AlertGroup]) -> String {
    if groups.is_empty() {
        return r#"<section class="ops-empty"><h2>All clear</h2><p>No host, backup, freshness, kernel, service, probe, or manifest alert needs attention right now.</p></section>"#.to_string();
    }
    groups.iter().map(render_alert_row).collect()
}

pub(super) fn posture_panel(alerts: &[AlertItem], hosts: &[Host], base: &PublicBasePath) -> String {
    let (critical, warning, watch, clear) = alert_counts(alerts, hosts);
    let total_alerts = alerts.len().max(1);
    let (posture_label, posture_color, posture_count, posture_filter) = if critical > 0 {
        ("critical", "var(--down)", critical, "critical")
    } else if warning > 0 {
        ("warning", "var(--stale)", warning, "warning")
    } else if watch > 0 {
        ("watch", "var(--sun)", watch, "watch")
    } else {
        ("clear", "var(--live)", clear, "clear")
    };
    let posture_fill = if alerts.is_empty() {
        100
    } else {
        ((posture_count * 100) / total_alerts).clamp(8, 100)
    };
    format!(
        r#"<aside class="ops-side-panel" aria-label="operations posture"><div><h2>Operations posture</h2><p>Most important work first.</p></div><button class="posture-ring" type="button" data-ops-filter="{posture_filter}" aria-pressed="false" style="--posture-fill:{posture_fill}%;--posture-color:{posture_color}"><div><strong>{posture_count}</strong><span>{posture_label}</span></div></button><div class="posture-list"><button class="posture-chip critical" type="button" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="posture-chip warning" type="button" data-ops-filter="warning" aria-pressed="false">warning {warning}</button><button class="posture-chip watch" type="button" data-ops-filter="watch" aria-pressed="false">watch {watch}</button><button class="posture-chip clear" type="button" data-ops-filter="clear" aria-pressed="false">clear {clear}</button><button class="posture-chip info" type="button" data-ops-filter="all" aria-pressed="true">show all</button></div><div class="ops-note">Repeated alerts are grouped. Use the host search and severity controls to focus the queue.</div><a class="ops-action" href="{map_href}">View on map</a></aside>"#,
        map_href = app_href(base, "/map"),
    )
}

pub(super) fn render_alerts(
    runtime: RuntimeSnapshot<'_>,
    _self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    let alerts = alert_items(
        runtime.hosts,
        runtime.jobs,
        runtime.nixpkgs_warn_after_days,
        now,
        manifests,
        load_errors,
        server_probes,
    );
    let groups = alert_groups(&alerts);
    let rows = render_alert_rows(&groups);
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="ops-main" data-ops-page="alerts">{header}{summary}{toolbar}<section class="ops-layout"><section class="ops-panel" aria-label="attention queue"><header class="ops-panel-head"><div><h2>Needs attention</h2><p>Plain-language queue from heartbeat, backup, freshness, kernel, service, probe, and config state.</p></div><span class="ops-count">{count}</span></header><div class="alert-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching alerts.</section></section>{posture}</section></main>{script}</div></body></html>"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "alerts"
        ),
        header = page_header("Alerts", "Needs attention", now),
        summary = ops_summary_metrics(&alerts, runtime.hosts),
        toolbar = ops_toolbar(),
        count = alerts.len(),
        posture = posture_panel(&alerts, runtime.hosts, shell.public_base_path),
        script = ops_script()
    )
}

pub(super) fn ops_toolbar() -> String {
    format!(
        r#"<section class="toolbar ops-toolbar" aria-label="operations filters"><div class="toolbar-left"><button class="activity-filter info" type="button" data-ops-filter="all" aria-pressed="true">Show all</button></div><div class="toolbar-right">{search}</div></section>"#,
        search = search_box("Search hosts...")
    )
}

pub(super) fn backup_summary_metrics(hosts: &[Host], now: i64) -> String {
    let mut protected = 0;
    let mut review = 0;
    let mut failed = 0;
    let mut unknown = 0;

    for host in hosts {
        match backup_ui_summary(&host.backup_observations, now).level {
            "clear" => protected += 1,
            "warning" => review += 1,
            "critical" => failed += 1,
            _ => unknown += 1,
        }
    }

    format!(
        r#"<section class="ops-summary backup-summary" aria-label="backup summary"><button class="ops-metric clear" type="button" data-ops-filter="clear" aria-pressed="false"><b>{protected}</b><span>Protected</span></button><button class="ops-metric warning" type="button" data-ops-filter="warning" aria-pressed="false"><b>{review}</b><span>Review</span></button><button class="ops-metric critical" type="button" data-ops-filter="critical" aria-pressed="false"><b>{failed}</b><span>Failed or missing</span></button><button class="ops-metric watch" type="button" data-ops-filter="watch" aria-pressed="false"><b>{unknown}</b><span>Unknown</span></button></section>"#
    )
}

pub(super) fn render_backup_rows(hosts: &[Host], now: i64) -> String {
    if hosts.is_empty() {
        return r#"<section class="ops-empty"><h2>No hosts yet</h2><p>Once hosts report, Pharos will show backup posture here.</p></section>"#.to_string();
    }

    let mut rows: Vec<(&Host, BackupUiSummary)> = hosts
        .iter()
        .map(|host| (host, backup_ui_summary(&host.backup_observations, now)))
        .collect();
    rows.sort_by(|(left_host, left), (right_host, right)| {
        left.rank
            .cmp(&right.rank)
            .then_with(|| left_host.name.cmp(&right_host.name))
    });

    rows.into_iter()
        .map(|(host, backup)| {
            let count = if backup.total > 1 {
                format!(
                    r#"<span class="backup-count">{count} jobs</span>"#,
                    count = backup.total
                )
            } else {
                String::new()
            };
            let search = html_escape(
                &format!(
                    "{} {} {} {} {} {} {} {}",
                    host.name,
                    host.role,
                    backup.label,
                    backup.detail,
                    backup.last_success,
                    backup.schedule,
                    backup.target,
                    backup.validation
                )
                .to_lowercase(),
            );
            format!(
                r#"<article class="backup-row {level}" data-ops-row data-ops-level="{level}" data-host="{host}" data-host-search="{search}"><div class="backup-host"><div><strong>{host}</strong><span>{role}</span></div></div><div class="backup-state"><span class="severity">{label}</span>{count}</div><div class="backup-issue"><strong>{detail}</strong><p>{state}</p></div><div class="backup-field"><span>Last success</span><strong>{last_success}</strong></div><div class="backup-field"><span>Schedule</span><strong>{schedule}</strong></div><div class="backup-field"><span>Target</span><strong>{target}</strong></div><div class="backup-field"><span>Validation</span><strong>{validation}</strong></div></article>"#,
                level = html_escape(backup.level),
                search = search,
                host = html_escape(&host.name),
                role = html_escape(&host.role),
                label = html_escape(&backup.label),
                count = count,
                detail = html_escape(&backup.detail),
                state = html_escape(backup.state),
                last_success = html_escape(&backup.last_success),
                schedule = html_escape(&backup.schedule),
                target = html_escape(&backup.target),
                validation = html_escape(&backup.validation)
            )
        })
        .collect()
}

pub(super) fn render_backups(hosts: &[Host], now: i64, shell: ShellContext<'_>) -> String {
    let rows = render_backup_rows(hosts, now);
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="ops-main backup-page" data-ops-page="backups">{header}{summary}{toolbar}<section class="ops-panel" aria-label="backup posture"><header class="ops-panel-head"><div><h2>Backup posture</h2><p>Sanitized runtime evidence from backup jobs. No logs, paths, repositories, or credentials are shown.</p></div><span class="ops-count">{count}</span></header><div class="backup-list-full">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching backup rows.</section></section><div class="ops-note" style="margin-top:14px">A protected state means the latest reported backup source is healthy. Restore validation is tracked separately from last backup success when evidence exists.</div></main>{script}</div></body></html>"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "backups"
        ),
        header = page_header("Backups", "Protection at a glance", now),
        summary = backup_summary_metrics(hosts, now),
        toolbar = ops_toolbar(),
        count = hosts.len(),
        rows = rows,
        script = ops_script()
    )
}

pub(super) fn ops_script() -> &'static str {
    OPS_RUNTIME
}

pub(super) fn backup_engine_label(engine: pharos_core::BackupEngine) -> &'static str {
    match engine {
        pharos_core::BackupEngine::Restic => "Restic",
        pharos_core::BackupEngine::Borg => "Borg",
        pharos_core::BackupEngine::Kopia => "Kopia",
        pharos_core::BackupEngine::ProviderSnapshot => "provider snapshot",
        pharos_core::BackupEngine::Other => "backup",
        pharos_core::BackupEngine::Unknown => "backup",
    }
}

pub(super) fn backup_activity_level(state: BackupPostureState) -> &'static str {
    match backup_level(state) {
        "clear" => "info",
        level => level,
    }
}

pub(super) fn backup_activity_detail(observation: &BackupObservation) -> String {
    let mut parts = vec![backup_engine_label(observation.engine).to_string()];
    if let Some(schedule) = &observation.schedule {
        parts.push(format!("schedule {}", schedule));
    }
    if let Some(target) = &observation.target_label {
        parts.push(format!("target {}", target));
    }
    parts.join(" · ")
}

pub(super) fn push_backup_activity_events(
    events: &mut Vec<ActivityEvent>,
    host: &Host,
    observation: &BackupObservation,
    now: i64,
) {
    let observed_at = backup_sort_time(host, observation, now);
    events.push(ActivityEvent::new(
        host.last_seen.unwrap_or(observed_at),
        host.name.clone(),
        "info",
        "backup",
        "Backup source observed",
        backup_activity_detail(observation),
        "backup",
    ));

    if let Some(timestamp) = observation.last_success_at {
        events.push(ActivityEvent::new(
            timestamp,
            host.name.clone(),
            "info",
            "backup",
            format!("{} succeeded", observation.label),
            backup_activity_detail(observation),
            "backup",
        ));
    }

    if let (Some(timestamp), Some(state)) =
        (observation.last_attempt_at, observation.last_attempt_state)
    {
        match state {
            pharos_core::BackupRunState::Succeeded => {}
            pharos_core::BackupRunState::Failed => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "critical",
                "backup",
                format!("{} failed", observation.label),
                observation.summary.clone(),
                "backup",
            )),
            pharos_core::BackupRunState::Running => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "watch",
                "backup",
                format!("{} running", observation.label),
                observation.summary.clone(),
                "backup",
            )),
            pharos_core::BackupRunState::Unknown => events.push(ActivityEvent::new(
                timestamp,
                host.name.clone(),
                "watch",
                "backup",
                format!("{} state unknown", observation.label),
                observation.summary.clone(),
                "backup",
            )),
        }
    }

    if observation.state != BackupPostureState::Healthy {
        events.push(ActivityEvent::new(
            observed_at,
            host.name.clone(),
            backup_activity_level(observation.state),
            "backup",
            format!(
                "{}: {}",
                observation.label,
                backup_state_label(observation.state)
            ),
            observation.summary.clone(),
            "backup",
        ));
    }

    if let Some(restore) = &observation.restore_validation {
        let level = match restore.state {
            pharos_core::BackupValidationState::Passed => "info",
            pharos_core::BackupValidationState::Failed => "critical",
            pharos_core::BackupValidationState::Stale => "warning",
            pharos_core::BackupValidationState::Unknown => "watch",
        };
        let checked_at = restore.checked_at.unwrap_or(observed_at);
        let label = restore
            .evidence_label
            .as_deref()
            .unwrap_or_else(|| backup_validation_level_label(restore.level));
        events.push(ActivityEvent::new(
            checked_at,
            host.name.clone(),
            level,
            "backup",
            format!(
                "{} validation {}",
                observation.label,
                backup_validation_state_label(restore.state)
            ),
            format!(
                "{} - {}",
                label,
                restore
                    .summary
                    .clone()
                    .unwrap_or_else(|| backup_validation_label(observation, now))
            ),
            "backup",
        ));
    } else if let (Some(timestamp), Some(state)) =
        (observation.last_check_at, observation.last_check_state)
    {
        let level = match state {
            pharos_core::BackupValidationState::Passed => "info",
            pharos_core::BackupValidationState::Failed => "critical",
            pharos_core::BackupValidationState::Stale => "warning",
            pharos_core::BackupValidationState::Unknown => "watch",
        };
        events.push(ActivityEvent::new(
            timestamp,
            host.name.clone(),
            level,
            "backup",
            format!(
                "{} validation {}",
                observation.label,
                backup_validation_state_label(state)
            ),
            backup_validation_label(observation, now),
            "backup",
        ));
    }
}

pub(super) fn activity_events(
    runtime: RuntimeSnapshot<'_>,
    _self_name: &str,
    now: i64,
    sources: ActivitySources<'_>,
) -> Vec<ActivityEvent> {
    let hosts = runtime.hosts;
    let jobs = runtime.jobs;
    let ActivitySources {
        manifests,
        load_errors,
        server_probes,
        action_jobs,
    } = sources;
    let mut events = Vec::new();
    let runtime_names: BTreeSet<&str> = hosts.iter().map(|host| host.name.as_str()).collect();

    for issue in load_errors {
        events.push(ActivityEvent::new(
            now,
            "Pharos",
            "critical",
            "config",
            "Manifest load failed",
            format!("{} - {}", issue.path, issue.error),
            "config",
        ));
    }

    for job in action_jobs {
        let (level, title) = match (job.workflow_kind(), job.state) {
            (HostWorkflowKind::SettingsChange, HostActionState::ProposalRequested) => {
                ("watch", "Host settings change waiting")
            }
            (HostWorkflowKind::SettingsChange, HostActionState::Succeeded) => {
                ("recovery", "Host settings applied")
            }
            (HostWorkflowKind::SettingsChange, HostActionState::Failed) => {
                ("warning", "Host settings request stopped")
            }
            (HostWorkflowKind::SystemUpdateProposal, HostActionState::ProposalRequested) => {
                ("info", "System update review requested")
            }
            (HostWorkflowKind::SystemUpdateProposal, HostActionState::Succeeded) => {
                ("recovery", "System update review handed to nixcfg")
            }
            (HostWorkflowKind::SystemUpdateProposal, HostActionState::Failed) => {
                ("warning", "System update review stopped")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::QueuedReview) => {
                ("watch", "Guarded update review queued")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Reviewing) => {
                ("watch", "Guarded update review running")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::AwaitingConfirmation) => {
                ("watch", "Update review ready for confirmation")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::QueuedApply) => {
                ("warning", "Update and restart confirmed")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Applying)
                if job.recovery_started_at.is_some() =>
            {
                ("warning", "Recovery verification running")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Applying) => {
                ("warning", "Target-local update running")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Rebooting)
                if job.recovery_started_at.is_some() =>
            {
                ("warning", "Recovery verification queued")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Rebooting) => {
                ("warning", "Host restart in progress")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Succeeded)
                if job.recovery_started_at.is_some() =>
            {
                ("recovery", "Guarded update recovered and verified")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Succeeded) => {
                ("recovery", "Guarded host update completed")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Cancelled) => {
                ("info", "Guarded update review cancelled safely")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Failed)
                if job.recovery_started_at.is_some() =>
            {
                ("warning", "Recovery verification needs attention")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Failed)
                if job.confirmed_at.is_none() =>
            {
                ("warning", "Guarded update review stopped")
            }
            (HostWorkflowKind::UpdateRestart, HostActionState::Failed) => {
                ("warning", "Guarded update needs verification")
            }
            (HostWorkflowKind::RemoveHost, HostActionState::ProposalRequested) => {
                ("watch", "Host removal preparing")
            }
            (HostWorkflowKind::RemoveHost, HostActionState::RemovalPending) => {
                ("warning", "Host removal pending")
            }
            (HostWorkflowKind::RemoveHost, HostActionState::Succeeded) => {
                ("recovery", "Host removed from Pharos")
            }
            (HostWorkflowKind::RemoveHost, HostActionState::Failed) => {
                ("warning", "Host removal stopped")
            }
            _ => ("info", "Host action recorded"),
        };
        let removal_detail = job.removal_plan.as_ref().map(|plan| {
            let disposition = plan.disposition.key();
            let successor = plan
                .successor
                .as_deref()
                .map(|successor| format!(" · successor {successor}"))
                .unwrap_or_default();
            let cleanup = if plan.declaration_pending {
                " · nixcfg cleanup pending"
            } else {
                " · runtime registration only"
            };
            let credentials = if plan.credential_retirement_required {
                " · Janus credential retirement required"
            } else {
                ""
            };
            format!(" Disposition: {disposition}{successor}{cleanup}{credentials}.")
        });
        events.push(
            ActivityEvent::new(
                job.updated_at,
                job.host.clone(),
                level,
                "action",
                title,
                format!(
                    "{} · requested by {}. {}{}",
                    job.ticket,
                    job.requested_by,
                    action_message(job),
                    removal_detail.as_deref().unwrap_or_default()
                ),
                "guarded action",
            )
            .with_workflow(job.id.clone()),
        );
    }

    for manifest in manifests {
        events.push(ActivityEvent::new(
            now,
            manifest.host.name.clone(),
            "info",
            "config",
            "Declared host manifest loaded",
            format!("{} declared services", manifest.services.len()),
            "config",
        ));
    }

    for job in jobs {
        let Some(host) = provisioning_job_host_name(job) else {
            continue;
        };
        if provisioning_job_first_heartbeat_overdue(job, now) && !runtime_names.contains(host) {
            events.push(ActivityEvent::new(
                now,
                host.to_string(),
                "warning",
                "setup",
                "First heartbeat overdue",
                format!(
                    "No first heartbeat after {}.",
                    duration_label(now.saturating_sub(job.updated_at))
                ),
                "setup",
            ));
        }
        for entry in &job.progress {
            let level = match entry.state {
                ProvisioningJobState::Failed | ProvisioningJobState::CleanupNeeded => "critical",
                ProvisioningJobState::WaitingForHeartbeat
                | ProvisioningJobState::BackupPending
                | ProvisioningJobState::Planning
                | ProvisioningJobState::Provisioning
                | ProvisioningJobState::Bootstrapping => "watch",
                ProvisioningJobState::Complete => "recovery",
            };
            events.push(ActivityEvent::new(
                entry.observed_at,
                host.to_string(),
                level,
                "setup",
                if provisioning_job_rolled_back(job)
                    && entry.state == ProvisioningJobState::Complete
                {
                    "Setup rolled back".to_string()
                } else {
                    format!("Setup {}", entry.state.label())
                },
                entry.message.clone(),
                "setup",
            ));
        }
    }

    for host in hosts {
        let live = liveness(host.last_seen, host.heartbeat_interval_secs, now);
        let appliance_observed = host
            .service_observations
            .iter()
            .any(appliance_probes::is_appliance_observation);
        let heartbeat_live = if appliance_observed {
            Liveness::Live
        } else {
            live
        };
        match heartbeat_live {
            Liveness::Down if !host.preferences.suppresses_down_alerts() => {
                events.push(ActivityEvent::new(
                    now,
                    host.name.clone(),
                    "critical",
                    "heartbeat",
                    "No heartbeat received",
                    format!("Last report was {}", seen_label(host.last_seen, now)),
                    "heartbeat",
                ))
            }
            Liveness::Down => {}
            Liveness::Stale => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "warning",
                "heartbeat",
                "Heartbeat lateness detected",
                format!("Last report was {}", seen_label(host.last_seen, now)),
                "heartbeat",
            )),
            Liveness::AwaitingFirstHeartbeat => events.push(ActivityEvent::new(
                now,
                host.name.clone(),
                "watch",
                "heartbeat",
                "Awaiting first heartbeat",
                "Host exists but has not reported yet.",
                "heartbeat",
            )),
            Liveness::Live => {}
        }

        let samples = heartbeat_samples(&host.heartbeat_log, host.last_seen);
        for stamp in samples.iter().rev().take(4) {
            events.push(ActivityEvent::new(
                *stamp,
                host.name.clone(),
                "info",
                "heartbeat",
                "Heartbeat received",
                format!("{} checked in at {}", host.name, clock_label(*stamp)),
                "heartbeat",
            ));
        }

        if !host.preferences.alerts.suppress_nix_freshness {
            if let Some((level, issue, _action)) = freshness_alert(
                &host.freshness,
                now,
                host.preferences
                    .nixpkgs_warn_after_days(Some(runtime.nixpkgs_warn_after_days)),
            ) {
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    level,
                    "freshness",
                    "Freshness drift detected",
                    issue,
                    "freshness",
                ));
            }
        }

        if let Some(kernel) = kernel_reboot_required(host.kernel.as_ref()) {
            if let (Some(running), Some(expected)) = (
                kernel.running_version.as_deref(),
                kernel.expected_version.as_deref(),
            ) {
                events.push(ActivityEvent::new(
                    kernel.observed_at,
                    host.name.clone(),
                    "warning",
                    "kernel",
                    "Restart needed",
                    format!(
                        "Running kernel {running}; kernel {expected} is ready after restart. Pharos will not restart this host."
                    ),
                    "kernel",
                ));
            }
        }

        for observation in &host.service_observations {
            if is_nix_freshness_observation(observation) {
                continue;
            }
            if appliance_probes::is_appliance_observation(observation)
                && (observation.state == ServiceObservationState::Healthy
                    || (observation.state == ServiceObservationState::Unknown
                        && observation
                            .summary
                            .starts_with("online; allowing SSH startup")))
            {
                continue;
            }

            if observation.state == ServiceObservationState::Healthy {
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    "info",
                    "service",
                    format!("{} is healthy", observation.label),
                    observation.summary.clone(),
                    "service",
                ));
            } else {
                let level = match observation.state {
                    ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                    ServiceObservationState::Unknown => "watch",
                    ServiceObservationState::Healthy => "info",
                };
                events.push(ActivityEvent::new(
                    host.last_seen.unwrap_or(now),
                    host.name.clone(),
                    level,
                    "service",
                    format!("{} {}", observation.label, observation.state.label()),
                    observation.summary.clone(),
                    "service",
                ));
            }
        }

        if !host.preferences.alerts.suppress_backup {
            for observation in &host.backup_observations {
                push_backup_activity_events(&mut events, host, observation, now);
            }

            push_protection_onboarding_activity(&mut events, host, jobs, now);
        }
    }

    for (host, probes) in server_probes {
        for probe in probes {
            let level = match probe.state {
                ServiceObservationState::Healthy => "info",
                ServiceObservationState::Warning | ServiceObservationState::Stale => "warning",
                ServiceObservationState::Unknown => "watch",
            };
            events.push(ActivityEvent::new(
                probe.checked_at,
                host.clone(),
                level,
                "service",
                format!("{} probe {}", probe.service, probe.state.label()),
                probe.summary.clone(),
                "probe",
            ));
        }
    }

    events.sort_by(|left, right| {
        right
            .timestamp
            .cmp(&left.timestamp)
            .then_with(|| level_rank(left.level).cmp(&level_rank(right.level)))
            .then_with(|| left.host.cmp(&right.host))
    });
    events
}

pub(super) fn activity_source_count(events: &[ActivityEvent], kind: &str) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

pub(super) fn activity_summary_metrics(events: &[ActivityEvent]) -> String {
    let heartbeat = activity_source_count(events, "heartbeat");
    let freshness = activity_source_count(events, "freshness");
    let service = activity_source_count(events, "service");
    let backup = activity_source_count(events, "backup");
    let setup = activity_source_count(events, "setup");
    let kernel = activity_source_count(events, "kernel");
    let actions = activity_source_count(events, "action");
    format!(
        r#"<section class="ops-summary" aria-label="activity summary"><button class="ops-metric info" type="button" data-ops-filter="all" aria-pressed="true"><b>{total}</b><span>all events</span></button><button class="ops-metric clear" type="button" data-ops-filter="heartbeat" aria-pressed="false"><b>{heartbeat}</b><span>heartbeat</span></button><button class="ops-metric watch" type="button" data-ops-filter="setup" aria-pressed="false"><b>{setup}</b><span>setup</span></button><button class="ops-metric warning" type="button" data-ops-filter="action" aria-pressed="false"><b>{actions}</b><span>actions</span></button><button class="ops-metric watch" type="button" data-ops-filter="freshness" aria-pressed="false"><b>{freshness}</b><span>freshness</span></button><button class="ops-metric warning" type="button" data-ops-filter="kernel" aria-pressed="false"><b>{kernel}</b><span>kernel</span></button><button class="ops-metric warning" type="button" data-ops-filter="service" aria-pressed="false"><b>{service}</b><span>service</span></button><button class="ops-metric recovery" type="button" data-ops-filter="backup" aria-pressed="false"><b>{backup}</b><span>backup</span></button></section>"#,
        total = events.len()
    )
}

pub(super) fn activity_filter_bar(events: &[ActivityEvent]) -> String {
    let config = activity_source_count(events, "config");
    let setup = activity_source_count(events, "setup");
    let actions = activity_source_count(events, "action");
    let critical = events
        .iter()
        .filter(|event| event.level == "critical")
        .count();
    let warning = events
        .iter()
        .filter(|event| event.level == "warning")
        .count();
    format!(
        r#"<div class="activity-filters" role="group" aria-label="activity filters"><button class="activity-filter info" type="button" data-activity-filter="all" data-ops-filter="all" aria-pressed="true">All events {total}</button><button class="activity-filter clear" type="button" data-activity-filter="heartbeat" data-ops-filter="heartbeat" aria-pressed="false">Heartbeat {heartbeat}</button><button class="activity-filter watch" type="button" data-activity-filter="setup" data-ops-filter="setup" aria-pressed="false">Setup {setup}</button><button class="activity-filter warning" type="button" data-activity-filter="action" data-ops-filter="action" aria-pressed="false">Actions {actions}</button><button class="activity-filter watch" type="button" data-activity-filter="freshness" data-ops-filter="freshness" aria-pressed="false">Freshness {freshness}</button><button class="activity-filter warning" type="button" data-activity-filter="kernel" data-ops-filter="kernel" aria-pressed="false">Kernel {kernel}</button><button class="activity-filter warning" type="button" data-activity-filter="service" data-ops-filter="service" aria-pressed="false">Service {service}</button><button class="activity-filter recovery" type="button" data-activity-filter="backup" data-ops-filter="backup" aria-pressed="false">Backup {backup}</button><button class="activity-filter info" type="button" data-activity-filter="config" data-ops-filter="config" aria-pressed="false">Config {config}</button><button class="activity-filter critical" type="button" data-activity-filter="critical" data-ops-filter="critical" aria-pressed="false">critical {critical}</button><button class="activity-filter warning" type="button" data-activity-filter="warning" data-ops-filter="warning" aria-pressed="false">warning {warning}</button></div>"#,
        total = events.len(),
        heartbeat = activity_source_count(events, "heartbeat"),
        freshness = activity_source_count(events, "freshness"),
        service = activity_source_count(events, "service"),
        backup = activity_source_count(events, "backup"),
        kernel = activity_source_count(events, "kernel"),
    )
}

pub(super) fn render_activity_row(event: &ActivityEvent, base: &PublicBasePath) -> String {
    let (tag, workflow_attributes, href) = event.workflow_id.as_deref().map_or_else(
        || ("article", String::new(), String::new()),
        |workflow_id| {
            (
                "a",
                format!(
                    r#" id="workflow-{workflow}" data-workflow-id="{workflow}""#,
                    workflow = html_escape(workflow_id),
                ),
                format!(
                    r#" href="{href}" aria-label="Open saved workflow for {host_label}" title="Open saved workflow""#,
                    href = app_href(
                        base,
                        &format!(
                            "/?host={}&workflow={}",
                            url_query_escape(&event.host),
                            url_query_escape(workflow_id)
                        ),
                    ),
                    host_label = html_escape(&event.host),
                ),
            )
        },
    );
    format!(
        r#"<{tag} class="activity-row {level}" data-ops-row data-activity-kind="{kind}" data-activity-level="{level}" data-ops-kind="{kind}" data-ops-level="{level}" data-host="{host}" data-host-search="{host_search}"{workflow_attributes}{href}><span class="ops-time">{time}</span><div class="activity-host"><span class="activity-dot" aria-hidden="true"></span><div><strong>{host}</strong><span>{kind}</span></div></div><span class="severity">{level_label}</span><div class="activity-copy"><strong>{title}</strong><p>{detail}</p></div><span class="ops-source">{source}</span></{tag}>"#,
        tag = tag,
        workflow_attributes = workflow_attributes,
        href = href,
        level = html_escape(event.level),
        kind = html_escape(event.kind),
        time = html_escape(&clock_label(event.timestamp)),
        host = html_escape(&event.host),
        level_label = level_label(event.level),
        title = html_escape(&event.title),
        detail = html_escape(&event.detail),
        source = html_escape(event.source),
        host_search = html_escape(
            &format!(
                "{} {} {} {} {}",
                event.host, event.kind, event.title, event.detail, event.source
            )
            .to_lowercase(),
        )
    )
}

pub(super) fn activity_rows(base: &PublicBasePath, events: &[ActivityEvent]) -> String {
    if events.is_empty() {
        return r#"<section class="ops-empty"><h2>No activity yet</h2><p>Once hosts report, Pharos will show heartbeats, backup changes, freshness changes, kernel posture, service observations, and config events here.</p></section>"#.to_string();
    }
    events
        .iter()
        .take(80)
        .map(|event| render_activity_row(event, base))
        .collect()
}

pub(super) fn focus_activity_events(
    events: Vec<ActivityEvent>,
    focus: &ActivityFocus,
) -> Vec<ActivityEvent> {
    match focus {
        ActivityFocus::All => events,
        ActivityFocus::Workflow { host, workflow_id } => events
            .into_iter()
            .filter(|event| {
                event.host == *host && event.workflow_id.as_deref() == Some(workflow_id.as_str())
            })
            .collect(),
        ActivityFocus::Unavailable => Vec::new(),
    }
}

pub(super) fn activity_focus_path(base: &PublicBasePath, focus: &ActivityFocus) -> String {
    match focus {
        ActivityFocus::All => String::new(),
        ActivityFocus::Workflow { host, .. } => format!(
            r#"<aside class="ops-note" data-activity-workflow-focus role="status"><strong>Saved workflow activity</strong><span>Showing the exact recorded workflow for {host}.</span><a class="ops-action" href="{href}">Show all activity</a></aside>"#,
            host = html_escape(host),
            href = app_href(base, "/activity"),
        ),
        ActivityFocus::Unavailable => format!(
            r#"<section class="ops-empty" data-activity-workflow-unavailable><h2>Workflow activity unavailable</h2><p>This workflow is unknown, belongs to another host, or is not available to your account.</p><a class="ops-action" href="{href}">Show all activity</a></section>"#,
            href = app_href(base, "/activity"),
        ),
    }
}

pub(super) fn activity_script() -> &'static str {
    ops_script()
}

#[cfg(test)]
pub(super) fn render_activity(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    load_errors: &[ManifestLoadIssue],
    server_probes: &BTreeMap<String, Vec<ServerProbeObservation>>,
    shell: ShellContext<'_>,
) -> String {
    render_activity_with_actions(
        runtime,
        self_name,
        now,
        ActivitySources {
            manifests,
            load_errors,
            server_probes,
            action_jobs: &[],
        },
        shell,
    )
}

#[cfg(test)]
pub(super) fn render_activity_with_actions(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    sources: ActivitySources<'_>,
    shell: ShellContext<'_>,
) -> String {
    render_activity_with_focus(runtime, self_name, now, sources, shell, ActivityFocus::All)
}

pub(super) fn render_activity_with_focus(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    sources: ActivitySources<'_>,
    shell: ShellContext<'_>,
    focus: ActivityFocus,
) -> String {
    let events = focus_activity_events(activity_events(runtime, self_name, now, sources), &focus);
    let focus_path = activity_focus_path(shell.public_base_path, &focus);
    let rows = if focus == ActivityFocus::Unavailable {
        String::new()
    } else {
        activity_rows(shell.public_base_path, &events)
    };
    let head = document_head(shell.public_base_path);
    format!(
        r#"{head}{sidebar}<main class="ops-main" data-ops-page="activity">{header}{focus_path}{summary}{toolbar}<section class="ops-panel" aria-label="operational timeline"><header class="ops-panel-head"><div><h2>Operational timeline</h2><p>Reverse chronological history from heartbeat, backup, freshness, kernel, service, config, and guarded action signals.</p></div><span class="ops-count">{count}</span></header><div style="padding:14px 16px;border-bottom:1px solid rgba(214,226,234,.72)">{filters}</div><div class="activity-list">{rows}</div><section class="ops-filter-empty" data-ops-empty>No matching activity.</section></section><div class="ops-note" style="margin-top:14px">Guarded action requests and results are persisted. Other operational events are derived from the current retained state.</div></main>{script}</div></body></html>"#,
        sidebar = sidebar(
            shell.public_base_path,
            shell.user_label,
            shell.logout_enabled,
            "activity"
        ),
        header = page_header("Activity", "Operational timeline", now),
        focus_path = focus_path,
        summary = activity_summary_metrics(&events),
        toolbar = ops_toolbar(),
        count = events.len(),
        filters = activity_filter_bar(&events),
        script = activity_script()
    )
}

pub(super) fn render_map(
    hosts: &[Host],
    self_name: &str,
    now: i64,
    user_label: &str,
    logout_enabled: bool,
    base: &PublicBasePath,
) -> String {
    let summary = summary_cards(hosts, self_name, now);
    let toolbar = map_toolbar();
    let map_script = MAP_RUNTIME;
    let head = document_head(base);
    format!(
        r#"{head}{sidebar}<main class="map-main" data-map-view="standard"><div class="top"><span class="top-art" aria-hidden="true"></span><div><div class="brand"><h1>Map</h1><svg class="wave" viewBox="0 0 48 12" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><path d="M1 7c5-7 11 7 16 0s11 7 16 0 10 3 14 0"/></svg></div><p class="fleet">Server locations</p></div><div class="asof" data-as-of>as of {as_of}</div></div>{summary}{toolbar}<section class="map-layout" data-map-layout data-mode="standard"><div id="map-panel" class="map-panel" data-mode="standard" data-label-density="normal" data-loading="true" data-map-state="loading"><div class="map-mode-controls" role="group" aria-label="Map layout"><button class="map-mode-control" type="button" data-map-mode-button="standard" aria-label="Standard layout" aria-pressed="true" title="Standard layout">{standard_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="maximized" aria-label="Maximize to window" aria-pressed="false" title="Maximize to window">{maximize_icon}</button><button class="map-mode-control" type="button" data-map-mode-button="fullscreen" aria-label="Fullscreen" aria-pressed="false" title="Fullscreen">{fullscreen_icon}</button><button class="map-mode-control map-density-control" type="button" data-map-density-button aria-label="Compact server labels" aria-pressed="false" title="Compact server labels">{compact_icon}</button></div><div id="fleet-map" class="fleet-map" aria-label="world map with server locations"></div><aside class="map-basemap-consent" data-basemap-consent aria-label="Optional external basemap"><strong>Street basemap is off</strong><p>Loading OpenFreeMap shares your IP address and requested map area with <code>tiles.openfreemap.org</code>. Permission applies once to this page and is not stored.</p><div><button type="button" data-basemap-load>Load external basemap</button><a href="https://openfreemap.org/" target="_blank" rel="noopener noreferrer">About OpenFreeMap</a></div></aside><div class="map-loading" data-map-loading><div class="map-load-card"><strong>Preparing map</strong><p data-map-status-message>Loading server locations and reachability checks.</p><span class="map-load-rail" aria-hidden="true"></span></div></div><div class="map-fallback" data-map-fallback><div><strong>Map unavailable</strong><p>The location list remains available when data can be loaded.</p></div></div></div><aside class="site-panel" aria-label="server locations" data-site-panel data-loading="true"><div><h2>Locations</h2><p>Approximate site-level coordinates.</p></div><div class="site-list" data-site-list><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line long"></span><span class="site-skel-line medium"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line medium"></span><span class="site-skel-line long"></span><span class="site-skel-line short"></span></div><div class="site-loading" data-site-skeleton><span class="site-skel-line short"></span><span class="site-skel-line medium"></span><span class="site-skel-line long"></span></div></div><div class="map-note" data-map-note>Loading server locations and reachability checks.</div></aside></section></main>{map_script}{FOOT}"#,
        sidebar = sidebar(base, user_label, logout_enabled, "map"),
        as_of = clock_label(now),
        summary = summary,
        toolbar = toolbar,
        standard_icon = icons::PANEL_RIGHT,
        maximize_icon = icons::MAXIMIZE_2,
        fullscreen_icon = icons::FULLSCREEN,
        compact_icon = icons::LIST,
    )
}

#[cfg(test)]
pub(super) struct HeartbeatHistoryView {
    visible: Vec<usize>,
}

#[cfg(test)]
pub(super) fn heartbeat_history_view(log: &[i64], window_secs: i64) -> HeartbeatHistoryView {
    if log.len() < 2 {
        return HeartbeatHistoryView {
            visible: Vec::new(),
        };
    }

    let latest = log[log.len() - 1];
    let start = log[0].max(latest - window_secs.max(1));
    let span = (latest - start).max(1);
    let candidates = log
        .iter()
        .enumerate()
        .filter_map(|(idx, stamp)| {
            if idx > 0 && *stamp >= start && *stamp <= latest {
                Some(idx)
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    if candidates.len() <= HEARTBEAT_HISTORY_DOTS {
        return HeartbeatHistoryView {
            visible: candidates,
        };
    }

    let mut buckets = vec![None; HEARTBEAT_HISTORY_DOTS];
    for idx in candidates {
        let raw_bucket = (((log[idx] - start) as f64 / span as f64) * HEARTBEAT_HISTORY_DOTS as f64)
            .floor() as usize;
        let bucket = raw_bucket.min(HEARTBEAT_HISTORY_DOTS - 1);
        buckets[bucket] = Some(idx);
    }

    HeartbeatHistoryView {
        visible: buckets.into_iter().flatten().collect(),
    }
}

#[cfg(test)]
pub(super) fn heartbeat_visible_log(log: &[i64], window_secs: i64) -> Vec<i64> {
    let view = heartbeat_history_view(log, window_secs);
    view.visible.into_iter().map(|idx| log[idx]).collect()
}

pub(super) fn heartbeat_history(
    log: &[i64],
    idx: usize,
    interval: i64,
    grace_secs: u64,
) -> (&'static str, String, String) {
    let stamp = log[idx];
    let previous = idx.checked_sub(1).and_then(|previous| log.get(previous));
    let gap = previous.map(|previous| (stamp - previous).max(0) as u64);
    let level = pharos_core::heartbeat_history_level(gap, interval.max(1) as u64, grace_secs);
    let detail = match gap {
        Some(gap) => format!(
            "{} after previous · {}",
            duration_label(gap as i64),
            clock_label(stamp)
        ),
        None => format!("at {}", clock_label(stamp)),
    };
    (
        pharos_core::heartbeat_history_level_key(level),
        pharos_core::heartbeat_history_label(level).to_string(),
        detail,
    )
}

#[cfg(test)]
pub(super) fn heartbeat_marks(log: &[i64], interval: i64, window_secs: i64) -> (String, f64) {
    let now = log.last().copied().unwrap_or(0);
    heartbeat_marks_with_grace(log, interval, window_secs, 0, now)
}

fn collapsed_history_log(log: &[i64]) -> Vec<i64> {
    let mut samples: Vec<i64> = log.iter().copied().filter(|stamp| *stamp > 0).collect();
    samples.sort_unstable();
    samples.dedup();
    samples
}

fn history_event_rank(level: &str) -> u8 {
    match level {
        "down" => 0,
        "stale" => 1,
        "late" => 2,
        "unknown" => 3,
        "first" => 4,
        _ => 5,
    }
}

struct HistoryBucketChoice {
    index: usize,
    rank: u8,
    gap: i64,
    stamp: i64,
}

/// Worst event wins. Equal severity keeps the larger gap, then the earlier
/// stamp, then the lower index.
fn history_choice_is_worse(candidate: &HistoryBucketChoice, current: &HistoryBucketChoice) -> bool {
    if candidate.rank != current.rank {
        return candidate.rank < current.rank;
    }
    if candidate.gap != current.gap {
        return candidate.gap > current.gap;
    }
    if candidate.stamp != current.stamp {
        return candidate.stamp < current.stamp;
    }
    candidate.index < current.index
}

fn time_axis_mark_indexes(
    log: &[i64],
    interval: i64,
    window_secs: i64,
    grace_secs: u64,
    now: i64,
) -> Vec<usize> {
    if log.len() < 2 {
        return Vec::new();
    }
    let window = window_secs.max(1);
    let start = now.saturating_sub(window);
    let end = now.saturating_add(BACKUP_CLOCK_SKEW_SECS);
    let candidates = (1..log.len())
        .filter(|idx| log[*idx] >= start && log[*idx] <= end)
        .collect::<Vec<_>>();
    if candidates.len() <= HEARTBEAT_HISTORY_DOTS {
        return candidates;
    }
    let mut buckets: Vec<Option<HistoryBucketChoice>> =
        (0..HEARTBEAT_HISTORY_DOTS).map(|_| None).collect();
    for idx in candidates {
        let stamp = log[idx];
        let gap = stamp.saturating_sub(log[idx - 1]);
        let (level, _, _) = heartbeat_history(log, idx, interval, grace_secs);
        let raw_bucket = (((stamp - start).max(0) as f64 / window as f64)
            * HEARTBEAT_HISTORY_DOTS as f64)
            .floor() as usize;
        let bucket = raw_bucket.min(HEARTBEAT_HISTORY_DOTS - 1);
        let choice = HistoryBucketChoice {
            index: idx,
            rank: history_event_rank(level),
            gap,
            stamp,
        };
        let replace = match &buckets[bucket] {
            None => true,
            Some(current) => history_choice_is_worse(&choice, current),
        };
        if replace {
            buckets[bucket] = Some(choice);
        }
    }
    buckets
        .into_iter()
        .flatten()
        .map(|choice| choice.index)
        .collect()
}

pub(super) fn heartbeat_marks_with_grace(
    log: &[i64],
    interval: i64,
    window_secs: i64,
    grace_secs: u64,
    now: i64,
) -> (String, f64) {
    let log = collapsed_history_log(log);
    let interval = interval.max(1);
    let window = window_secs.max(1);
    let start = now.saturating_sub(window);
    let mut marks = String::new();
    for idx in time_axis_mark_indexes(&log, interval, window, grace_secs, now) {
        let stamp = log[idx];
        let x = ((stamp - start).max(0) as f64 / window as f64) * 100.0;
        let x = x.clamp(0.0, 100.0);
        let (level, label, detail) = heartbeat_history(&log, idx, interval, grace_secs);
        let title = format!("{label} · {detail}");
        marks.push_str(&format!(
            r#"<span class="beat-mark" role="img" tabindex="0" data-history-key="sample:{stamp}" data-history-stamp="{stamp}" data-history-level="{level}" data-history-label="{label}" data-history-detail="{detail}" title="{title}" aria-label="{title}" style="--mark-x:{x:.1}%"></span>"#,
            level = html_escape(level),
            label = html_escape(&label),
            detail = html_escape(&detail),
            title = html_escape(&title)
        ));
    }
    (marks, 100.0)
}

pub(super) fn heartbeat_x_with_grace(age: i64, interval: i64, grace_secs: u64) -> f64 {
    pharos_core::heartbeat_timeline_x(
        age.max(0) as u64,
        interval.max(1) as u64,
        grace_secs,
        HEARTBEAT_EXPECT_X,
        HEARTBEAT_STALE_X,
    )
}

pub(super) struct HeartbeatCard<'a> {
    last_seen: Option<i64>,
    heartbeat_log: &'a [i64],
    interval_secs: Option<u64>,
    now: i64,
    is_self: bool,
    window_control: bool,
    list_caption: bool,
    grace_secs: u64,
    grace_source: &'a str,
    late_after_secs: u64,
}

pub(super) fn heartbeat_card(card: HeartbeatCard<'_>) -> String {
    let HeartbeatCard {
        last_seen,
        heartbeat_log,
        interval_secs,
        now,
        is_self,
        window_control,
        list_caption,
        grace_secs,
        grace_source,
        late_after_secs,
    } = card;
    let interval = i64::try_from(interval_secs.unwrap_or(60))
        .unwrap_or(60)
        .max(1);
    let all_beats = heartbeat_samples(heartbeat_log, last_seen);
    let history_log = collapsed_history_log(&all_beats);
    let mark_beats: Vec<i64> = time_axis_mark_indexes(
        &history_log,
        interval,
        SIGNAL_DEFAULT_WINDOW_SECS,
        grace_secs,
        now,
    )
    .into_iter()
    .map(|idx| history_log[idx])
    .collect();
    let beats_attr = mark_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let signal_beats_attr = all_beats
        .iter()
        .map(i64::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let (marks, history_start_x) = heartbeat_marks_with_grace(
        &all_beats,
        interval,
        SIGNAL_DEFAULT_WINDOW_SECS,
        grace_secs,
        now,
    );
    let (last_attr, next_at_attr, beat_state, timing, now_x, fill_color, expect_fill, target_ring) =
        match last_seen {
            Some(last) => {
                let age = (now - last).max(0);
                let timing = pharos_core::heartbeat_timing(age as u64, interval as u64, grace_secs);
                let now_x = heartbeat_x_with_grace(age, interval, grace_secs);
                let on_time_through = (late_after_secs as f64).min(interval as f64 * 2.0).max(1.0);
                let progress = (age as f64 / on_time_through).clamp(0.0, 1.0);
                let (state, color, fill, ring) = match timing {
                    pharos_core::HeartbeatTiming::OnTime => (
                        if is_self { "lit" } else { "tracking" },
                        if is_self { "var(--sun)" } else { "var(--sea)" },
                        progress * 360.0,
                        3.0 + progress * 5.0,
                    ),
                    pharos_core::HeartbeatTiming::Late => ("late", "var(--sun)", 360.0, 8.0),
                    pharos_core::HeartbeatTiming::Stale => ("stale", "var(--stale)", 360.0, 8.0),
                    pharos_core::HeartbeatTiming::Down => ("down", "var(--down)", 360.0, 8.0),
                };
                (
                    last.to_string(),
                    (last + interval).to_string(),
                    state,
                    timing.as_str(),
                    now_x,
                    color,
                    fill,
                    ring,
                )
            }
            None => (
                "".to_string(),
                "".to_string(),
                "waiting",
                "",
                0.0,
                "var(--wait)",
                0.0,
                3.0,
            ),
        };
    let self_attr = if is_self { r#" data-self="true""# } else { "" };
    let history_window_label = html_escape(SIGNAL_DEFAULT_WINDOW_LABEL);
    let history_window_control = if window_control {
        format!(
            r#"<button class="beat-window" type="button" data-signal-window data-history-window-label title="Change delivery window" aria-label="Change delivery window; currently {history_window_label}">{history_window_label}</button>"#,
        )
    } else {
        format!(r#"<span data-history-window-label>{history_window_label}</span>"#)
    };
    let arrival_label = match timing {
        "on_time" => "On time",
        "late" => "Late",
        "stale" => "Stale",
        "down" => "Down",
        _ => "No heartbeat yet",
    };
    let arrival_state = if timing.is_empty() { "waiting" } else { timing };
    let live_motion = if timing == "on_time" { "true" } else { "false" };
    let age_text = match last_seen {
        Some(last) => {
            let age = (now - last).max(0);
            if age < 60 {
                format!("{age}s")
            } else {
                duration_label(age)
            }
        }
        None => String::new(),
    };
    let caption = if timing.is_empty() {
        format!("No heartbeat yet · late {late_after_secs}s")
    } else {
        format!("{arrival_label} · {age_text} · expected {interval}s · late {late_after_secs}s")
    };
    let visible_caption = if list_caption {
        if timing.is_empty() || age_text.is_empty() {
            arrival_label.to_string()
        } else {
            format!("{arrival_label} · {age_text} ago")
        }
    } else {
        caption.clone()
    };
    let caption_mode = if list_caption {
        r#" data-caption-mode="list""#
    } else {
        ""
    };
    let stale_after = interval.saturating_mul(2).max(1);
    let down_after = interval.saturating_mul(5).max(1);
    let interval_x = ((interval as f64) / (late_after_secs.max(1) as f64) * HEARTBEAT_EXPECT_X)
        .clamp(0.0, HEARTBEAT_EXPECT_X);
    let policy = format!(
        "Expected every {interval}s. Late after {late_after_secs}s ({interval}s plus {grace_secs}s grace). Stale after {stale_after}s. Down after {down_after}s."
    );
    format!(
        r#"<div class="beat" data-history-axis="time" data-beat="{beat_state}" data-heartbeat-timing="{timing}" data-beat-live="{live_motion}" data-count="{count}" data-last="{last_attr}" data-interval="{interval}" data-grace="{grace_secs}" data-grace-source="{grace_source}" data-late-after="{late_after_secs}" data-next-at="{next_at_attr}" data-beats="{beats_attr}" data-signal-beats="{signal_beats_attr}" data-history-window="{history_window_label}" style="--cadence-x:{cadence_x:.2}%;--interval-x:{interval_x:.2}%;--now-x:100%;--history-start-x:{history_start_x:.1}%;--expect-x:64%;--stale-x:82%;--fill-color:{fill_color};--expect-fill:{expect_fill:.1}deg;--target-ring:{target_ring:.1}px"{self_attr}{caption_mode}><div class="beat-readout" data-arrival data-arrival-state="{arrival_state}" title="{caption}"><span data-arrival-label title="{caption}">{visible_caption}</span></div><div class="beat-cadence" aria-label="{caption}" title="{caption}"><span class="beat-floor"></span><span class="beat-fill"></span><span class="beat-current"></span><span class="beat-threshold interval" title="Expected every {interval}s"></span><span class="beat-threshold late" title="Late after {late_after_secs}s"></span><span class="beat-threshold stale" title="Stale after twice the interval"></span><span class="beat-now"></span><span class="beat-hit"></span></div><div class="beat-history"><p class="beat-policy">{policy}</p><div class="beat-stage" aria-label="{history_window_label} heartbeat history by time"><span class="beat-floor"></span><span class="beat-marks">{marks}</span><span class="beat-zones" data-history-zones>{history_window_control}<span data-history-anchor="now">now</span></span></div></div></div>"#,
        count = mark_beats.len(),
        cadence_x = now_x,
        interval_x = interval_x,
        caption = html_escape(&caption),
        visible_caption = html_escape(&visible_caption),
        caption_mode = caption_mode,
        policy = html_escape(&policy),
        arrival_state = arrival_state,
        live_motion = live_motion,
    )
}

#[cfg(test)]
pub(super) fn render_home(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    shell: ShellContext<'_>,
    can_onboard: bool,
) -> String {
    render_home_with_capabilities(
        runtime,
        self_name,
        now,
        manifests,
        shell,
        FleetCapabilities {
            can_manage_fleet: can_onboard,
            system_update_available: true,
            host_removal_available: true,
        },
    )
}

#[cfg(test)]
pub(super) fn render_home_with_capabilities(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    shell: ShellContext<'_>,
    capabilities: FleetCapabilities,
) -> String {
    render_home_with_grace(
        runtime,
        self_name,
        now,
        manifests,
        shell,
        capabilities,
        None,
    )
}

pub(super) fn render_home_with_grace(
    runtime: RuntimeSnapshot<'_>,
    self_name: &str,
    now: i64,
    manifests: &[HostManifest],
    shell: ShellContext<'_>,
    capabilities: FleetCapabilities,
    fleet_heartbeat_grace_secs: Option<u64>,
) -> String {
    let can_onboard = capabilities.can_manage_fleet;
    let access_path = if capabilities.can_manage_fleet {
        String::new()
    } else {
        viewer_access_path(shell.public_base_path, "fleet")
    };
    let hosts = runtime.hosts;
    let setup_jobs = pending_setup_jobs(runtime.hosts, runtime.jobs);
    if runtime.hosts.is_empty() && setup_jobs.is_empty() {
        let assistant = if can_onboard {
            setup_assistant()
        } else {
            String::new()
        };
        let head = document_head(shell.public_base_path);
        return format!(
            "{head}{sidebar}<main>{header}{access_path}{empty}</main>{assistant}{FOOT}",
            sidebar = sidebar(
                shell.public_base_path,
                shell.user_label,
                shell.logout_enabled,
                "fleet"
            ),
            header = header(now),
            empty = empty_state(can_onboard),
            access_path = access_path,
            assistant = assistant
        );
    }

    let manifests_by_host = manifest_by_host(manifests);
    let mut sorted: Vec<&Host> = hosts.iter().collect();
    sorted.sort_by_key(|h| {
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let rank = attention_reason(
            live,
            &h.freshness,
            h.kernel.as_ref(),
            &h.service_observations,
            &h.preferences,
            now,
            runtime.nixpkgs_warn_after_days,
        )
        .rank;
        (rank, h.name.clone())
    });

    let mut cards = String::new();
    let mut rows = String::new();
    for h in sorted {
        let is_self = h.name == self_name;
        let live = liveness(h.last_seen, h.heartbeat_interval_secs, now);
        let nix_icon = if h.is_nix {
            icons::SNOWFLAKE
        } else {
            icons::SERVER
        };
        let name = html_escape(&h.name);
        let fresh_tldr = h.freshness.tldr();
        let list_fresh = freshness_markup(
            &h.freshness,
            false,
            now,
            h.preferences
                .nixpkgs_warn_after_days(Some(runtime.nixpkgs_warn_after_days)),
        );
        let attention = attention_reason(
            live,
            &h.freshness,
            h.kernel.as_ref(),
            &h.service_observations,
            &h.preferences,
            now,
            runtime.nixpkgs_warn_after_days,
        );
        let kernel_required = kernel_reboot_required(h.kernel.as_ref()).is_some();
        let freshness_is_attention = freshness_attention_reason(
            &h.freshness,
            now,
            h.preferences
                .nixpkgs_warn_after_days(Some(runtime.nixpkgs_warn_after_days)),
        )
        .is_some_and(|freshness| freshness.label == attention.label);
        let attention_hidden =
            scan_attention_hidden(&attention.label, kernel_required, freshness_is_attention);
        let card_reason = reason_markup(&attention, attention_hidden);
        let muted = muted_preferences_markup(&h.preferences);
        let backup = backup_ui_summary(&h.backup_observations, now);
        let (card_fresh, card_fresh_visible) = card_freshness_fault_markup(
            &h.freshness,
            &backup,
            h.kernel.as_ref(),
            now,
            h.preferences
                .nixpkgs_warn_after_days(Some(runtime.nixpkgs_warn_after_days)),
        );
        let protection = protection_onboarding_status(h, runtime.jobs, now);
        let protection_card = protection
            .as_ref()
            .map(|status| protection_onboarding_markup(status, ""))
            .unwrap_or_default();
        let mut search_parts = vec![format!(
            "{} {} {} {}",
            h.name.to_lowercase(),
            h.role.to_lowercase(),
            fresh_tldr.to_lowercase(),
            attention.label.to_lowercase()
        )];
        if let Some(backup_text) = backup_search_text(&backup) {
            search_parts.push(backup_text.to_lowercase());
        }
        if let Some(status) = &protection {
            search_parts.push(status.search_text().to_lowercase());
        }
        if kernel_required {
            search_parts.push("restart required restart needed kernel reboot required".to_string());
        }
        if h.preferences.suppresses_down_alerts()
            || h.preferences.alerts.suppress_backup
            || h.preferences.alerts.suppress_nix_freshness
        {
            search_parts.push(if h.preferences.kind == HostKind::Workstation {
                "workstation expected offline down alerts suppressed muted alert preferences"
                    .to_string()
            } else {
                "muted alert preferences".to_string()
            });
        }
        let sort_name = html_escape(&h.name.to_lowercase());
        let last_sort = h.last_seen.unwrap_or(0);
        let sev = attention.rank;
        let seen_card = match h.last_seen {
            Some(t) => format!("Seen {} ago", duration_label(now - t)),
            None => "Never seen".to_string(),
        };
        let seen_compact = match h.last_seen {
            Some(t) => format!("{} ago", duration_label(now - t)),
            None => "never".to_string(),
        };
        let as_of = clock_label(now);
        let as_of_short = as_of.get(..5).unwrap_or(&as_of);
        let light_cls = if is_self { " light" } else { "" };
        let self_attr = if is_self { r#" data-self="true""# } else { "" };
        let beam = if is_self {
            format!(
                r#"<span class="pharos-mark" aria-hidden="true">{}</span>"#,
                icons::LIGHTHOUSE
            )
        } else {
            String::new()
        };
        let manifest = manifests_by_host.get(h.name.as_str()).copied();
        let declared_preferences = runtime
            .declared_preferences
            .and_then(|preferences| preferences.get(&h.name))
            .or_else(|| manifest.map(|manifest| &manifest.host.preferences));
        let settings_state = host_preferences_state(
            &h.preferences,
            declared_preferences,
            h.requested_preferences.as_ref(),
        );
        let relevant_action = most_relevant_host_action(runtime.action_jobs, &h.name);
        let apply_declared_ready = h.is_nix
            && runtime
                .janus_managed_hosts
                .is_some_and(|hosts| hosts.contains(&h.name))
            && manifest.is_some_and(|manifest| {
                manifest.policy.privileged_actions.mode == PrivilegedActionMode::Janus
                    && manifest.policy.privileged_actions.janus_required
            });
        let normal_update_ready =
            apply_declared_ready && (kernel_required || h.freshness.has_proven_deployable_update());
        let lifecycle = host_lifecycle_with_apply(
            runtime.action_jobs,
            &h.name,
            settings_state,
            kernel_required,
            apply_declared_ready,
            normal_update_ready,
            HostSettingsContext {
                declared_preferences,
                pending_preferences: h.requested_preferences.as_ref(),
                legacy_nix_host: h.is_nix,
                apply_declared_unavailable_reason: (!apply_declared_ready)
                    .then_some(crate::SETTINGS_APPLY_UNAVAILABLE_REASON),
                ..HostSettingsContext::default()
            },
        );
        if lifecycle.slot != HostLifecycleSlot::Quiet {
            search_parts.push(lifecycle.label.to_lowercase());
        }
        let assurance = fleet_protection_view(&h.backup_observations, now);
        let health = host_health_view(HostHealthQuery {
            live,
            preferences: &h.preferences,
            freshness: &h.freshness,
            kernel: h.kernel.as_ref(),
            services: &h.service_observations,
            protection: &assurance,
            now,
            nixpkgs_threshold: h
                .preferences
                .nixpkgs_warn_after_days(Some(runtime.nixpkgs_warn_after_days)),
        });
        search_parts.push(health.summary.to_lowercase());
        for reason in &health.reasons {
            search_parts.push(reason.label.to_lowercase());
        }
        search_parts.push(format!(
            "{} {} {} {}",
            assurance.run.label,
            assurance.run.note,
            assurance.restore.label,
            assurance.restore.note
        ));
        let search = html_escape(&search_parts.join(" "));
        let settings_href_raw = shell
            .public_base_path
            .href(&format!("/hosts/{}", url_query_escape(&h.name)));
        let settings_href = html_escape(&settings_href_raw);
        let settings_color = h
            .preferences
            .accent
            .as_deref()
            .filter(|color| valid_preference_accent(color))
            .map(html_escape);
        let pending_color = pending_preference_color(
            settings_state,
            declared_preferences,
            h.requested_preferences.as_ref(),
        )
        .filter(|color| valid_preference_accent(color))
        .map(html_escape);
        let settings_cls = if settings_color.is_some() {
            " has-settings"
        } else {
            ""
        };
        let mut host_color_vars = Vec::new();
        if let Some(color) = settings_color.as_ref() {
            host_color_vars.push(format!("--host-color:{color}"));
        }
        if let Some(color) = pending_color.as_ref() {
            host_color_vars.push(format!("--pending-color:{color}"));
        }
        let host_color_style = if host_color_vars.is_empty() {
            String::new()
        } else {
            format!(r#" style="{}""#, host_color_vars.join(";"))
        };
        let settings_state_key = settings_state.key();
        let drawer_accent = settings_color.as_deref().unwrap_or("#1f7fb5");
        let lifecycle_owner = if lifecycle.primary_action.is_some() {
            "Operator"
        } else if lifecycle
            .blocked_by
            .iter()
            .any(|blocker| blocker == "host_report")
        {
            "Host agent"
        } else if lifecycle.blocked_by.is_empty() {
            "No action owner"
        } else {
            "Recorded dependency"
        };
        let drawer_next = lifecycle
            .primary_action
            .as_ref()
            .map(|action| action.label.as_str())
            .unwrap_or_else(|| match lifecycle.slot {
                HostLifecycleSlot::Quiet => "Review host settings",
                HostLifecycleSlot::PrefsDrift
                    if lifecycle
                        .blocked_by
                        .iter()
                        .any(|blocker| blocker == "host_report") =>
                {
                    "Wait for the next host report"
                }
                HostLifecycleSlot::Blocked => "Open the blocking workflow",
                _ => "Open the host workspace",
            });
        let workspace_href = shell
            .public_base_path
            .href(&format!("/hosts/{}", url_query_escape(&h.name)));
        let drawer_attrs = format!(
            r#" data-drawer-accent="{}" data-drawer-kind="{}" data-drawer-suppress-down="{}" data-drawer-suppress-backup="{}" data-drawer-suppress-nix="{}" data-drawer-settings-state="{}" data-drawer-lifecycle-label="{}" data-drawer-lifecycle-detail="{}" data-drawer-lifecycle-owner="{}" data-drawer-next-action="{}" data-drawer-workspace-href="{}" data-drawer-can-manage="{}""#,
            html_escape(drawer_accent),
            h.preferences.kind.label(),
            h.preferences.alerts.suppress_down,
            h.preferences.alerts.suppress_backup,
            h.preferences.alerts.suppress_nix_freshness,
            settings_state_key,
            html_escape(&lifecycle.label),
            html_escape(&lifecycle.detail),
            lifecycle_owner,
            html_escape(drawer_next),
            html_escape(&workspace_href),
            capabilities.can_manage_fleet,
        );
        let settings_title = format!("Open host workspace for {name}");
        let settings_action = format!(
            r#"<a class="header-chip settings-card" data-settings-state="{settings_state_key}" href="{settings_href}" title="{settings_title}" aria-label="{settings_title}"><span class="settings-icon">{settings_icon}</span><span class="header-chip-label" aria-hidden="true">Settings</span><span class="settings-swatch" aria-hidden="true"></span></a>"#,
            settings_icon = icons::SLIDERS,
            settings_title = html_escape(&settings_title),
        );
        let declared = manifest.is_some() || declared_preferences.is_some();
        let credential_retirement_required = runtime
            .janus_managed_hosts
            .is_some_and(|managed| managed.contains(&h.name));
        let card_host_actions = if can_onboard {
            host_actions_markup(
                h,
                HostActionRenderContext {
                    manifest,
                    declared,
                    credential_retirement_required,
                    settings_state,
                    settings_href: &settings_href_raw,
                    backup: &backup,
                    surface: "card",
                    capabilities,
                    action_jobs: runtime.action_jobs,
                },
                relevant_action,
                &lifecycle,
            )
        } else {
            String::new()
        };
        let row_host_actions = if can_onboard {
            host_actions_markup(
                h,
                HostActionRenderContext {
                    manifest,
                    declared,
                    credential_retirement_required,
                    settings_state,
                    settings_href: &settings_href_raw,
                    backup: &backup,
                    surface: "row",
                    action_jobs: runtime.action_jobs,
                    capabilities,
                },
                relevant_action,
                &lifecycle,
            )
        } else {
            String::new()
        };
        let chip = host_lifecycle_chip_markup(
            &lifecycle,
            settings_state,
            can_onboard,
            if lifecycle.slot == HostLifecycleSlot::PrefsDrift {
                let declared_source = match settings_state {
                    HostPreferencesState::RequestPending => {
                        h.requested_preferences.as_ref().or(declared_preferences)
                    }
                    HostPreferencesState::DeclaredNotApplied => {
                        declared_preferences.or(h.requested_preferences.as_ref())
                    }
                    HostPreferencesState::Applied => None,
                };
                let observed_summary = preferences_summary(&h.preferences);
                let declared_summary =
                    preferences_summary(declared_source.unwrap_or(&h.preferences));
                Some((declared_summary, observed_summary))
            } else {
                None
            },
        );
        let lifecycle_chip = chip;
        let drag_action = format!(
            r#"<button class="drag-handle" type="button" data-drag-handle title="Move {name}" aria-label="Move {name}">{icon}</button>"#,
            icon = icons::GRIP
        );
        let health_tone = health.tone;
        let health_count = health.problem_count;
        let card_fresh = mark_scan_duplicate_chip(&card_fresh, &health.summary);
        let list_fresh = mark_scan_duplicate_chip(&list_fresh, &health.summary);
        let card_fresh_visible = card_fresh_visible && scan_rail_shows_chip(&card_fresh);
        let card_fresh_hidden = if card_fresh_visible { "" } else { " hidden" };
        let badge = os_badge_markup(nix_icon, &health);
        let preview = quick_preview_markup(&name, nix_icon);
        let card_revision = revision_evidence_markup(&h.freshness);
        let configuration_label = html_escape(&configuration_face_label(&h.freshness));
        let grace_view = host_grace_presentation(
            &h.preferences,
            h.requested_preferences.as_ref(),
            fleet_heartbeat_grace_secs,
            h.heartbeat_interval_secs,
        );
        let card_heartbeat = heartbeat_card(HeartbeatCard {
            last_seen: h.last_seen,
            heartbeat_log: &h.heartbeat_log,
            interval_secs: h.heartbeat_interval_secs,
            now,
            is_self,
            window_control: true,
            list_caption: false,
            grace_secs: grace_view.effective_secs,
            grace_source: grace_view.source.as_str(),
            late_after_secs: grace_view.late_after_secs,
        });
        let list_heartbeat = heartbeat_card(HeartbeatCard {
            last_seen: h.last_seen,
            heartbeat_log: &h.heartbeat_log,
            interval_secs: h.heartbeat_interval_secs,
            now,
            is_self,
            window_control: false,
            list_caption: true,
            grace_secs: grace_view.effective_secs,
            grace_source: grace_view.source.as_str(),
            late_after_secs: grace_view.late_after_secs,
        });
        let grace_attrs = grace_view.attrs;
        let interval = i64::try_from(h.heartbeat_interval_secs.unwrap_or(60))
            .unwrap_or(60)
            .max(1);
        let heartbeat_signal = heartbeat_signal(
            &h.heartbeat_log,
            h.last_seen,
            interval,
            now,
            SIGNAL_DEFAULT_WINDOW_LABEL,
            SIGNAL_DEFAULT_WINDOW_SECS,
        );
        let availability = availability_markup(&heartbeat_signal);
        let signal = signal_markup(&heartbeat_signal);
        let row_cls = format!("{light_cls}{settings_cls} harbor-host")
            .trim()
            .to_string();
        let role_line = html_escape(&card_role_line(h.preferences.kind, &h.role));
        let health_label_text = html_escape(health.label);
        let onboarding_extra = protection
            .as_ref()
            .filter(|status| status.level != "clear")
            .map(|status| status.label.clone())
            .unwrap_or_default();
        let attention_extra = html_escape(&onboarding_extra);
        let attention_html = card_attention_block(
            &health,
            &lifecycle_chip,
            &lifecycle.label,
            &onboarding_extra,
            &muted,
        );
        let protection_html = protection_card_markup(&assurance, &h.name, shell.public_base_path);
        let list_protection =
            list_protection_markup(&assurance, &h.name, shell.public_base_path, now);
        let face = heartbeat_face(h.last_seen, now, interval, grace_view.effective_secs);
        let heartbeat_status = html_escape(&face.status);
        let heartbeat_explain = html_escape(&face.explain);
        let heartbeat_tone = face.tone;
        let window_start = format!("{} ago", SIGNAL_DEFAULT_WINDOW_LABEL);
        let delivery_text = html_escape(&if heartbeat_signal.text == "—" {
            "No delivery data".to_string()
        } else {
            format!(
                "{} delivered · {}",
                heartbeat_signal.text, SIGNAL_DEFAULT_WINDOW_LABEL
            )
        });
        cards.push_str(&format!(
            r#"<article class="card{light_cls}{settings_cls} harbor-host" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-health="{health_tone}" data-health-count="{health_count}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime" data-attention-extra="{attention_extra}"{self_attr}{host_color_style}{drawer_attrs}{grace_attrs}>{beam}<header class="card-head host-heading">{badge}<div class="host-title"><h2><a class="host-name name" href="{settings_href}" title="{name}">{name}</a></h2><p class="role">{role_line}</p></div><span class="health-label" data-health-label data-health-tone="{health_tone}">{health_label_text}</span><div class="card-actions">{drag_action}{card_host_actions}</div></header>{attention_html}{protection_html}<div class="heartbeat"><div class="heartbeat-heading"><span>Heartbeat</span><strong class="{heartbeat_tone}" data-heartbeat-status data-heartbeat-tone="{heartbeat_tone}">{heartbeat_status}</strong></div>{card_heartbeat}<p class="heartbeat-explain" data-heartbeat-explain title="{heartbeat_explain}">{heartbeat_explain}</p><div class="heartbeat-axis"><span data-heartbeat-window-start>{window_start}</span><span class="delivery" data-heartbeat-delivery>{delivery_text}</span><span>Now</span></div></div><div class="harbor-card-foot"><a class="configuration" href="{settings_href}" data-configuration-label>{configuration_label}</a>{preview}</div><div class="scan-store" hidden>{card_reason}{protection_card}<div class="fresh freshness-rail" data-fresh role="group" aria-label="Host faults"{card_fresh_hidden}>{card_fresh}</div><div class="meta card-meta" title="Snapshot as of {as_of}" aria-label="{seen_card}; snapshot as of {as_of}"><span data-seen data-seen-card>{seen_card}</span><span class="meta-separator" aria-hidden="true">·</span><span data-card-asof data-card-asof-compact>{as_of_short}</span></div><div class="availability-head">{availability}</div>{card_revision}</div></article>"#,
            live_key = live_key(live),
        ));
        rows.push_str(&format!(
            r#"<tr class="{row_cls}" data-host="{name}" data-live="{live_key}" data-sev="{sev}" data-health="{health_tone}" data-health-count="{health_count}" data-sort-name="{sort_name}" data-last="{last_sort}" data-search="{search}" data-host-surface="runtime" data-attention-extra="{attention_extra}"{self_attr}{host_color_style}{drawer_attrs}{grace_attrs}><td><div class="host-heading list-host">{badge}<div class="host-title"><h2><a class="host-name name" href="{settings_href}" title="{name}">{name}</a></h2><p class="role">{role_line}</p><span class="health-label" data-health-label data-health-tone="{health_tone}">{health_label_text}</span></div></div></td><td><div class="list-attention">{attention_html}</div></td><td>{list_protection}</td><td class="list-heartbeat">{list_heartbeat}<div class="scan-store" hidden>{card_reason}<div class="fresh" data-fresh>{list_fresh}</div>{signal}{card_revision}</div></td><td><div class="list-seen"><span data-seen data-seen-compact>{seen_compact}</span><span class="list-seen-detail" data-card-asof>as of {as_of}</span></div></td><td><div class="list-actions">{preview}{row_host_actions}{settings_action}</div></td></tr>"#,
            live_key = live_key(live),
        ));
    }
    for job in setup_jobs {
        cards.push_str(&render_setup_card(
            job,
            now,
            capabilities.can_manage_fleet,
            shell.public_base_path,
        ));
        rows.push_str(&render_setup_row(
            job,
            now,
            capabilities.can_manage_fleet,
            shell.public_base_path,
        ));
    }

    let lone = if hosts.len() == 1 {
        lone_host_state(can_onboard)
    } else {
        String::new()
    };
    if can_onboard {
        cards.push_str(&onboard_tile());
        rows.push_str(&onboard_row());
    }
    let assistant = if can_onboard {
        setup_assistant()
    } else {
        String::new()
    };
    let action_dialog = if can_onboard {
        host_action_dialog()
    } else {
        String::new()
    };
    let host_drawer = host_quick_drawer(shell.public_base_path, capabilities.can_manage_fleet);

    let head = document_head(shell.public_base_path);
    format!(
        "{head}{sidebar}<main data-view=\"grid\" data-fleet-sync-state=\"current\" data-fleet-snapshot-at=\"{now}\">{header}{access_path}{summary}{toolbar}<div class=\"grid\" data-grid>{cards}</div><section class=\"list-wrap\" role=\"region\" aria-label=\"Host list, scroll horizontally on small screens\" tabindex=\"0\"><table class=\"list\"><caption class=\"list-caption\">Fleet health, attention, backup and restore, heartbeat, last seen, and actions</caption><colgroup><col class=\"host-col\"><col class=\"attention-col\"><col class=\"protection-col\"><col class=\"heartbeat-col\"><col class=\"seen-col\"><col class=\"actions-col\"></colgroup><thead><tr><th scope=\"col\">Host and health</th><th scope=\"col\">Attention</th><th scope=\"col\">Backup and restore</th><th scope=\"col\">Heartbeat</th><th scope=\"col\">Last seen</th><th scope=\"col\">Actions</th></tr></thead><tbody data-list-body>{rows}</tbody></table></section><p class=\"table-scroll-note\">Scroll the list horizontally for more columns. Cards fit smaller screens.</p>{lone}</main>{assistant}{host_drawer}{action_dialog}{FOOT}",
        sidebar = sidebar(shell.public_base_path, shell.user_label, shell.logout_enabled, "fleet"),
        header = header(now),
        summary = summary_cards(hosts, self_name, now),
        access_path = access_path,
        toolbar = toolbar(),
        assistant = assistant,
        host_drawer = host_drawer,
        action_dialog = action_dialog,
        now = now,
    )
}
