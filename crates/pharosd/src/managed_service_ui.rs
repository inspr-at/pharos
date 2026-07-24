//! Value-free managed-service secret pages.
//!
//! The browser may choose only a declared service slot. Source selection and
//! secret custody remain in Janus after Pharos issues a short-lived signed
//! setup intent.

use super::*;
use crate::managed_service_operations::ManagedOperationPhase;

const MANAGED_SETUP_RUNTIME: &str = r#"
document.querySelectorAll('[data-managed-secret-add]').forEach(button=>button.addEventListener('click',async()=>{
  if(button.disabled)return;
  const status=button.closest('.managed-slot-card')?.querySelector('[data-managed-action-status]');
  const original=button.textContent;
  button.disabled=true;button.textContent='Opening Janus…';
  if(status)status.textContent='Creating a short-lived, value-free setup request…';
  try{
    const response=await fetch('/managed-service-setup-intents',{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-Pharos-Action':'1'},
      body:JSON.stringify({
        operation_kind:'create',
        host_ref:button.dataset.hostRef,
        service_ref:button.dataset.serviceRef,
        slot_ref:button.dataset.slotRef
      })
    });
    const contentType=response.headers.get('content-type')||'';
    if(!contentType.includes('application/json'))throw new Error('invalid_response');
    const data=await response.json();
    if(!response.ok||typeof data.continue_url!=='string')throw new Error(data.reason_code||'setup_unavailable');
    const target=new URL(data.continue_url);
    if(target.protocol!=='https:'&&!(target.protocol==='http:'&&(target.hostname==='localhost'||target.hostname==='127.0.0.1'||target.hostname==='::1')))throw new Error('unsafe_target');
    window.location.assign(target.href);
  }catch(error){
    button.disabled=false;button.textContent=original;
    if(status)status.textContent=!navigator.onLine
      ?'You are offline. Reconnect, then try again.'
      :error.message==='managed_intent_declaration_drift'
        ?'This declaration changed. Refresh the page before trying again.'
        :'Janus setup is unavailable right now. Nothing changed; try again.';
  }
}));"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedSecretSlotState {
    Missing,
    Installing,
    Active,
    ActionNeeded,
    Replacing,
    Removing,
}

impl ManagedSecretSlotState {
    fn from_operation(operation_kind: Option<&str>, phase: Option<&str>) -> Self {
        match (operation_kind, phase) {
            (_, Some("active" | "healthy")) => Self::Active,
            (_, Some("failed" | "rolled_back")) => Self::ActionNeeded,
            (Some("remove"), Some(_)) => Self::Removing,
            (Some("replace"), Some(_)) => Self::Replacing,
            (Some("create"), Some(_)) => Self::Installing,
            _ => Self::Missing,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Missing => "Missing",
            Self::Installing => "Installing",
            Self::Active => "Active",
            Self::ActionNeeded => "Action needed",
            Self::Replacing => "Replacing",
            Self::Removing => "Removing",
        }
    }

    fn tone(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Installing | Self::Replacing | Self::Removing => "working",
            Self::Active => "active",
            Self::ActionNeeded => "attention",
        }
    }

    fn guidance(self) -> &'static str {
        match self {
            Self::Missing => "No managed value has been recorded for this declared slot.",
            Self::Installing => {
                "The value is encrypted. Delivery and the service check are running."
            }
            Self::Active => {
                "The declared service accepted this secret and its health check passed."
            }
            Self::ActionNeeded => {
                "The last safe attempt stopped. Open the details before trying again."
            }
            Self::Replacing => "A replacement is being delivered and checked.",
            Self::Removing => "Removal is in progress and the service is being checked.",
        }
    }
}

pub(super) async fn services_page(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    let shell = ShellContext {
        user_label: &user_label,
        logout_enabled: state.auth.is_some(),
    };
    if !access.can_agora() {
        return no_store_html(render_no_access_page(
            "Services",
            "Managed service secrets",
            shell,
            "services",
        ));
    }
    no_store_html(render_services_page(
        state.manifests.managed_service_manifests(),
        state.manifests.managed_service_load_errors(),
        shell,
        &state.managed_service_operations,
        now_unix(),
    ))
}

pub(super) async fn service_detail_page(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath((host_ref, service_ref)): AxumPath<(String, String)>,
) -> Response {
    let user_label = sidebar_user_label(&state.auth, &headers);
    let access = access_for_headers(&state.auth, &headers);
    let shell = ShellContext {
        user_label: &user_label,
        logout_enabled: state.auth.is_some(),
    };
    if !access.can_agora() {
        return no_store_html(render_no_access_page(
            "Service secrets",
            "Managed service secrets",
            shell,
            "services",
        ))
        .into_response();
    }
    if !state.manifests.managed_service_load_errors().is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            no_store_headers(),
            Html(render_services_error(shell)),
        )
            .into_response();
    }
    let selected = state
        .manifests
        .managed_service_manifests()
        .iter()
        .find(|manifest| manifest.host_ref == host_ref)
        .and_then(|manifest| {
            manifest
                .services
                .iter()
                .find(|service| service.service_ref == service_ref)
                .map(|service| (manifest, service))
        });
    let Some((manifest, service)) = selected else {
        return (
            StatusCode::NOT_FOUND,
            no_store_headers(),
            Html(render_no_access_page(
                "Service not found",
                "Return to Services and choose a declared service.",
                shell,
                "services",
            )),
        )
            .into_response();
    };
    no_store_html(render_service_detail(
        manifest,
        service,
        shell,
        state.managed_setup_intents.is_some(),
        &state.managed_service_operations,
        now_unix(),
    ))
    .into_response()
}

fn render_services_page(
    manifests: &[ManagedServiceManifestV1],
    load_errors: &[ManifestLoadIssue],
    shell: ShellContext<'_>,
    operations: &ManagedServiceOperationStore,
    now: i64,
) -> String {
    if !load_errors.is_empty() {
        return render_services_error(shell);
    }
    let sidebar = sidebar(shell.user_label, shell.logout_enabled, "services");
    let header = page_header(
        "Services",
        "Add and maintain declared service secrets without exposing their values",
        now_unix(),
    );
    let mut cards = String::new();
    for manifest in manifests {
        for service in &manifest.services {
            let (tone, state_label) = service_state(manifest, service, operations, now);
            let slot_count = service.slots.len();
            cards.push_str(&format!(
                r#"<a class="managed-service-card" href="/services/{host_ref}/{service_ref}"><span class="managed-service-icon">{icon}</span><span class="managed-service-copy"><b>{service_label}</b><small>{host_label}</small></span><span class="managed-service-count">{slot_count} {slot_word}</span><span class="managed-state {tone}">{state_label}</span></a>"#,
                host_ref = html_escape(&manifest.host_ref),
                service_ref = html_escape(&service.service_ref),
                icon = icons::KEY_ROUND,
                service_label = html_escape(&service.safe_label),
                host_label = html_escape(&managed_host_label(&manifest.host_ref)),
                slot_word = if slot_count == 1 { "secret" } else { "secrets" },
            ));
        }
    }
    let content = if cards.is_empty() {
        r#"<section class="managed-empty"><span class="managed-empty-icon">+</span><h2>No managed services yet</h2><p>When nixcfg declares a service secret slot, it will appear here ready for safe setup.</p><small>Managed services come first; this space can grow to other declared consumers later.</small></section>"#.to_string()
    } else {
        format!(
            r#"<section class="managed-service-list" aria-label="Declared managed services">{cards}</section><p class="managed-future-note">Managed services are shown first. Other declared secret consumers can fit here later.</p>"#
        )
    };
    format!(
        r#"{HEAD}{sidebar}<main class="managed-services-main">{header}{content}</main></div></body></html>"#
    )
}

fn service_state(
    manifest: &ManagedServiceManifestV1,
    service: &pharos_core::managed_services::ManagedServiceDeclarationV1,
    operations: &ManagedServiceOperationStore,
    now: i64,
) -> (&'static str, &'static str) {
    let phases = service.slots.iter().map(|slot| {
        operations
            .latest_for_slot(
                &manifest.host_ref,
                &service.service_ref,
                &slot.slot_ref,
                now,
            )
            .map(|operation| operation.phase)
    });
    let phases: Vec<_> = phases.collect();
    if phases
        .iter()
        .any(|phase| matches!(phase, Some(ManagedOperationPhase::Failed)))
    {
        ("attention", "Action needed")
    } else if phases
        .iter()
        .all(|phase| matches!(phase, Some(ManagedOperationPhase::Active)))
        && !phases.is_empty()
    {
        ("active", "Active")
    } else if phases.iter().any(|phase| {
        matches!(
            phase,
            Some(
                ManagedOperationPhase::InstallPending
                    | ManagedOperationPhase::Installing
                    | ManagedOperationPhase::ReloadPending
                    | ManagedOperationPhase::Reloading
                    | ManagedOperationPhase::VerifyPending
                    | ManagedOperationPhase::Verifying
            )
        )
    }) {
        ("working", "Setup running")
    } else {
        ("missing", "Needs setup")
    }
}

fn render_services_error(shell: ShellContext<'_>) -> String {
    format!(
        r#"{HEAD}{sidebar}<main class="managed-services-main">{header}<section class="managed-empty managed-error" role="alert"><span class="managed-empty-icon">!</span><h2>Declarations need attention</h2><p>Pharos could not safely read the current managed-service declaration. No setup action is available until it is fixed.</p><a class="managed-secondary" href="/services">Try again</a></section></main></div></body></html>"#,
        sidebar = sidebar(shell.user_label, shell.logout_enabled, "services"),
        header = page_header(
            "Services",
            "Managed service secrets are temporarily unavailable",
            now_unix()
        ),
    )
}

fn render_service_detail(
    manifest: &ManagedServiceManifestV1,
    service: &pharos_core::managed_services::ManagedServiceDeclarationV1,
    shell: ShellContext<'_>,
    setup_enabled: bool,
    operations: &ManagedServiceOperationStore,
    now: i64,
) -> String {
    let sidebar = sidebar(shell.user_label, shell.logout_enabled, "services");
    let mut slots = String::new();
    for slot in &service.slots {
        let operation = operations.latest_for_slot(
            &manifest.host_ref,
            &service.service_ref,
            &slot.slot_ref,
            now,
        );
        let operation_kind = operation
            .as_ref()
            .map(|operation| match operation.operation_kind {
                pharos_core::managed_operations::ManagedOperationKind::Create => "create",
                pharos_core::managed_operations::ManagedOperationKind::Replace => "replace",
            });
        let phase = operation.as_ref().map(|operation| operation.phase.name());
        slots.push_str(&render_slot(
            manifest,
            service,
            slot,
            ManagedSecretSlotState::from_operation(operation_kind, phase),
            operation.as_ref(),
            setup_enabled,
        ));
    }
    format!(
        r#"{HEAD}{sidebar}<main class="managed-services-main managed-service-detail"><a class="managed-back" href="/services">{back} Services</a><div class="top managed-detail-top"><div><span class="managed-kicker">Managed service</span><div class="brand"><h1>{service_label}</h1></div><p class="fleet">{host_label} · {slot_count}</p></div><span class="managed-lock">{lock} Declared target</span></div><section class="managed-slot-list" aria-label="Secret slots">{slots}</section><details class="managed-service-details"><summary>Technical details</summary><dl><div><dt>Host reference</dt><dd><code>{host_ref}</code></dd></div><div><dt>Service reference</dt><dd><code>{service_ref}</code></dd></div><div><dt>Runtime</dt><dd>Managed Compose service</dd></div></dl></details><script>{runtime}</script></main></div></body></html>"#,
        back = icons::ARROW_LEFT,
        service_label = html_escape(&service.safe_label),
        host_label = html_escape(&managed_host_label(&manifest.host_ref)),
        slot_count = if service.slots.len() == 1 {
            "1 secret slot".to_string()
        } else {
            format!("{} secret slots", service.slots.len())
        },
        lock = icons::SHIELD_CHECK,
        host_ref = html_escape(&manifest.host_ref),
        service_ref = html_escape(&service.service_ref),
        runtime = MANAGED_SETUP_RUNTIME,
    )
}

fn render_slot(
    manifest: &ManagedServiceManifestV1,
    service: &pharos_core::managed_services::ManagedServiceDeclarationV1,
    slot: &pharos_core::managed_services::ManagedSecretSlotDeclarationV1,
    state: ManagedSecretSlotState,
    operation: Option<&crate::managed_service_operations::ManagedOperationSummary>,
    setup_enabled: bool,
) -> String {
    let action = if state == ManagedSecretSlotState::Missing && setup_enabled {
        format!(
            r#"<button class="managed-primary" type="button" data-managed-secret-add data-host-ref="{host_ref}" data-service-ref="{service_ref}" data-slot-ref="{slot_ref}">Add missing secret</button>"#,
            host_ref = html_escape(&manifest.host_ref),
            service_ref = html_escape(&service.service_ref),
            slot_ref = html_escape(&slot.slot_ref),
        )
    } else if state == ManagedSecretSlotState::Missing {
        r#"<button class="managed-primary" type="button" disabled>Setup unavailable</button>"#
            .to_string()
    } else {
        r#"<button class="managed-secondary" type="button" disabled>View operation details</button>"#
            .to_string()
    };
    let progress = operation
        .map(|operation| render_operation_progress(operation.phase.name()))
        .unwrap_or_default();
    let separation = render_operation_separation(operation);
    format!(
        r#"<article class="managed-slot-card"><div class="managed-slot-head"><div><span class="managed-kicker">Service secret</span><h2>{slot_label}</h2></div><span class="managed-state {tone}">{state_label}</span></div><p class="managed-slot-guidance">{guidance}</p><dl class="managed-slot-facts"><div><dt>Consumer</dt><dd>{service_label}</dd></div><div><dt>Delivery</dt><dd>Private environment file</dd></div><div><dt>Reveal</dt><dd>Never</dd></div></dl>{separation}{progress}<div class="managed-slot-action">{action}<p role="status" aria-live="polite" data-managed-action-status>{availability}</p></div></article>"#,
        slot_label = html_escape(&slot.safe_label),
        tone = state.tone(),
        state_label = state.label(),
        guidance = state.guidance(),
        service_label = html_escape(&service.safe_label),
        separation = separation,
        progress = progress,
        action = action,
        availability = if setup_enabled {
            "Janus will confirm the exact target and ask how to create the value."
        } else {
            "Managed setup is not configured on this Pharos instance."
        },
    )
}

fn render_operation_separation(
    operation: Option<&crate::managed_service_operations::ManagedOperationSummary>,
) -> String {
    let (delivery, execution, health) = match operation.map(|operation| operation.phase) {
        None => ("Not delivered", "Not started", "Not observed"),
        Some(ManagedOperationPhase::InstallPending | ManagedOperationPhase::Installing) => (
            "Encrypted in Janus",
            "Waiting for host install",
            "Not observed",
        ),
        Some(ManagedOperationPhase::ReloadPending | ManagedOperationPhase::Reloading) => (
            "Installed on host",
            "Reloading declared service",
            "Not observed",
        ),
        Some(ManagedOperationPhase::VerifyPending | ManagedOperationPhase::Verifying) => (
            "Installed on host",
            "Declared reload completed",
            "Checking fresh evidence",
        ),
        Some(ManagedOperationPhase::Active) => (
            "Installed on host",
            "Declared reload completed",
            "Fresh generation healthy",
        ),
        Some(ManagedOperationPhase::Failed) => {
            ("Delivery recorded", "Action stopped safely", "Not accepted")
        }
        Some(ManagedOperationPhase::Superseded) => {
            ("Newer operation exists", "Superseded", "Not accepted")
        }
    };
    format!(
        r#"<dl class="managed-operation-lanes" aria-label="Operation boundaries"><div><dt>Declaration</dt><dd>Locked by nixcfg</dd></div><div><dt>Janus delivery</dt><dd>{delivery}</dd></div><div><dt>Host execution</dt><dd>{execution}</dd></div><div><dt>Observed health</dt><dd>{health}</dd></div></dl>"#
    )
}

fn render_operation_progress(phase: &str) -> String {
    let achieved = match phase {
        "install_pending" | "installing" | "encrypted" => Some(0),
        "reload_pending" | "reloading" | "materialized" => Some(1),
        "verify_pending" | "verifying" | "reloaded" => Some(2),
        "healthy" | "active" => Some(3),
        _ => None,
    };
    let labels = [
        "Encrypted",
        "Installed",
        "Service reloaded",
        "Service healthy",
    ];
    let mut items = String::new();
    for (index, label) in labels.iter().enumerate() {
        let state = match achieved {
            Some(last) if index <= last => "complete",
            Some(last) if index == last + 1 => "current",
            None if index == 0 => "current",
            _ => "pending",
        };
        items.push_str(&format!(
            r#"<li data-progress-state="{state}"><span aria-hidden="true">{marker}</span><b>{label}</b></li>"#,
            marker = if state == "complete" { "✓" } else { "·" },
        ));
    }
    format!(
        r#"<section class="managed-operation-progress" aria-label="Secret setup progress"><h3>Setup progress</h3><ol>{items}</ol><p>Technical references and evidence stay under Details.</p></section>"#
    )
}

fn managed_host_label(host_ref: &str) -> String {
    let suffix = host_ref
        .strip_prefix("host_")
        .unwrap_or(host_ref)
        .chars()
        .rev()
        .take(12)
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    format!("Managed host · {suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use pharos_core::managed_operations::{
        ManagedOperationKind, ManagedOperationReadyV1, MANAGED_OPERATION_CONTRACT_VERSION,
        MANAGED_OPERATION_READY_SCHEMA,
    };

    fn fixture() -> ManagedServiceManifestV1 {
        serde_json::from_str(include_str!(
            "../../../contracts/managed-service-declarations-v1.json"
        ))
        .expect("fixture parses")
    }

    fn shell() -> ShellContext<'static> {
        ShellContext {
            user_label: "markus",
            logout_enabled: true,
        }
    }

    #[test]
    fn every_plain_language_slot_state_has_a_stable_tone_and_guidance() {
        let states = [
            ManagedSecretSlotState::Missing,
            ManagedSecretSlotState::Installing,
            ManagedSecretSlotState::Active,
            ManagedSecretSlotState::ActionNeeded,
            ManagedSecretSlotState::Replacing,
            ManagedSecretSlotState::Removing,
        ];
        assert_eq!(
            states.map(ManagedSecretSlotState::label),
            [
                "Missing",
                "Installing",
                "Active",
                "Action needed",
                "Replacing",
                "Removing"
            ]
        );
        for state in states {
            assert!(!state.tone().is_empty());
            assert!(state.guidance().ends_with('.'));
        }
        assert_eq!(
            ManagedSecretSlotState::from_operation(Some("create"), Some("encrypted")),
            ManagedSecretSlotState::Installing
        );
        assert_eq!(
            ManagedSecretSlotState::from_operation(Some("replace"), Some("reloaded")),
            ManagedSecretSlotState::Replacing
        );
        assert_eq!(
            ManagedSecretSlotState::from_operation(Some("remove"), Some("revoked")),
            ManagedSecretSlotState::Removing
        );
        assert_eq!(
            ManagedSecretSlotState::from_operation(Some("create"), Some("healthy")),
            ManagedSecretSlotState::Active
        );
        assert_eq!(
            ManagedSecretSlotState::from_operation(Some("create"), Some("failed")),
            ManagedSecretSlotState::ActionNeeded
        );
    }

    #[test]
    fn detail_locks_declared_target_and_exposes_no_value_or_source_input() {
        let manifest = fixture();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let html = render_service_detail(
            &manifest,
            &manifest.services[0],
            shell(),
            true,
            &operations,
            1_800_000_000,
        );
        for expected in [
            "Add missing secret",
            "Declared target",
            "Service secret",
            "Private environment file",
            "Reveal</dt><dd>Never",
            "Operation boundaries",
            "Declaration",
            "Janus delivery",
            "Host execution",
            "Observed health",
            "data-host-ref=",
            "data-service-ref=",
            "data-slot-ref=",
            "X-Pharos-Action",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        for forbidden in [
            "secret_value",
            r#"name="source""#,
            r#"name="host_ref""#,
            r#"name="service_ref""#,
            r#"name="slot_ref""#,
            "return_url",
            "callback_url",
        ] {
            assert!(!html.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn operation_progress_uses_plain_phases_and_keeps_evidence_out_of_the_summary() {
        let html = render_operation_progress("reloaded");
        for expected in [
            "Encrypted",
            "Installed",
            "Service reloaded",
            "Service healthy",
            "Technical references and evidence stay under Details.",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        assert_eq!(html.matches(r#"data-progress-state="complete""#).count(), 3);
        assert!(!html.contains("operation_ref"));
        assert!(!html.contains("evidence_ref"));
    }

    #[test]
    fn service_list_reports_running_work_instead_of_claiming_every_slot_is_missing() {
        let manifest = fixture();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        operations
            .register(
                &ManagedOperationReadyV1 {
                    schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
                    schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
                    operation_ref: "op_20000001".to_string(),
                    operation_kind: ManagedOperationKind::Create,
                    host_ref: manifest.host_ref.clone(),
                    service_ref: manifest.services[0].service_ref.clone(),
                    slot_ref: manifest.services[0].slots[0].slot_ref.clone(),
                    declaration_fingerprint: manifest.declaration_fingerprint.clone(),
                    generation: 1,
                    value_returned: false,
                },
                &manifest.services[0].slots[0],
                1_800_000_000,
            )
            .unwrap();
        let html = render_services_page(
            std::slice::from_ref(&manifest),
            &[],
            shell(),
            &operations,
            1_800_000_001,
        );
        assert!(html.contains("Setup running"));
        assert!(!html.contains(">Needs setup</span>"));
    }

    #[test]
    fn service_labels_are_escaped_and_empty_and_failure_states_are_actionable() {
        let mut manifest = fixture();
        manifest.services[0].safe_label = "<Canary & service>".to_string();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let detail = render_service_detail(
            &manifest,
            &manifest.services[0],
            shell(),
            false,
            &operations,
            1_800_000_000,
        );
        assert!(detail.contains("&lt;Canary &amp; service&gt;"));
        assert!(detail.contains("Setup unavailable"));

        let empty = render_services_page(&[], &[], shell(), &operations, 1_800_000_000);
        assert!(empty.contains("No managed services yet"));
        assert!(empty.contains("other declared consumers"));

        let failed = render_services_page(
            &[],
            &[ManifestLoadIssue {
                path: "/opaque/test".to_string(),
                error: "invalid".to_string(),
            }],
            shell(),
            &operations,
            1_800_000_000,
        );
        assert!(failed.contains("Declarations need attention"));
        assert!(!failed.contains("/opaque/test"));
    }
}
