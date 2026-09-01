//! Value-free managed-service secret pages.
//!
//! The browser may choose only a declared service slot. Source selection and
//! secret custody remain in Janus after Pharos issues a short-lived signed
//! setup intent.

use super::*;
use crate::managed_service_operations::ManagedOperationPhase;

const MANAGED_SETUP_RUNTIME: &str = r#"
document.querySelectorAll('[data-managed-secret-action]').forEach(button=>button.addEventListener('click',async()=>{
  if(button.disabled)return;
  const status=button.closest('.managed-slot-card')?.querySelector('[data-managed-action-status]');
  const original=button.textContent;
  button.disabled=true;button.textContent='Opening Janus…';
  const replacing=button.dataset.operationKind==='replace';
  const removing=button.dataset.operationKind==='remove';
  if(status)status.textContent=removing
    ?'Creating a short-lived, value-free removal request…'
    :replacing
      ?'Creating a short-lived, value-free replacement request…'
      :'Creating a short-lived, value-free setup request…';
  try{
    const response=await fetch('/managed-service-setup-intents',{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json','X-Pharos-Action':'1'},
      body:JSON.stringify({
        operation_kind:button.dataset.operationKind,
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
        :removing
          ?'Janus removal is unavailable right now. The encrypted generations remain recoverable; try again.'
        :replacing
          ?'Janus replacement is unavailable right now. The current secret is unchanged; try again.'
      :'Janus setup is unavailable right now. Nothing changed; try again.';
  }
}));
document.querySelectorAll('[data-managed-verification-retry]').forEach(button=>button.addEventListener('click',async()=>{
  if(button.disabled)return;
  const status=button.closest('.managed-slot-card')?.querySelector('[data-managed-action-status]');
  const original=button.textContent;
  button.disabled=true;button.textContent='Requesting fresh check…';
  if(status)status.textContent='Asking the declared host for fresh exact-generation health evidence…';
  try{
    const operationRef=button.dataset.operationRef||'';
    const response=await fetch(`/managed-service-operations/${encodeURIComponent(operationRef)}/retry-verification`,{
      method:'POST',
      credentials:'same-origin',
      headers:{'X-Pharos-Action':'1'}
    });
    const contentType=response.headers.get('content-type')||'';
    if(!contentType.includes('application/json'))throw new Error('invalid_response');
    const data=await response.json();
    if(!response.ok
      ||data.value_returned!==false
      ||data.operation?.operation_ref!==operationRef
      ||!['verify_pending','verifying','active'].includes(data.operation?.phase)
    )throw new Error(data.reason_code||'verification_retry_unavailable');
    if(status)status.textContent='Fresh verification requested. Waiting for the declared host…';
    window.location.reload();
  }catch(error){
    button.disabled=false;button.textContent=original;
    if(status)status.textContent=!navigator.onLine
      ?'You are offline. Reconnect, then try again.'
      :error.message==='managed_operation_declaration_drift'
        ?'This declaration changed. Refresh the page before trying again.'
        :'Fresh verification could not be requested. Nothing changed; try again.';
  }
}));
document.querySelectorAll('[data-managed-removal-retry]').forEach(button=>button.addEventListener('click',async()=>{
  if(button.disabled)return;
  const status=button.closest('.managed-slot-card')?.querySelector('[data-managed-action-status]');
  const original=button.textContent;
  button.disabled=true;button.textContent='Retrying safe removal…';
  if(status)status.textContent='Requesting the same declared removal again; no secret is created or revealed…';
  try{
    const operationRef=button.dataset.operationRef||'';
    const response=await fetch(`/managed-service-operations/${encodeURIComponent(operationRef)}/retry-verification`,{
      method:'POST',
      credentials:'same-origin',
      headers:{'X-Pharos-Action':'1'}
    });
    const contentType=response.headers.get('content-type')||'';
    if(!contentType.includes('application/json'))throw new Error('invalid_response');
    const data=await response.json();
    if(!response.ok
      ||data.value_returned!==false
      ||data.operation?.operation_ref!==operationRef
      ||!['removal_pending','removing','removed'].includes(data.operation?.phase)
    )throw new Error(data.reason_code||'removal_retry_unavailable');
    if(status)status.textContent='Safe removal retry requested. Waiting for fresh exact absence evidence from the declared host…';
    window.location.reload();
  }catch(error){
    button.disabled=false;button.textContent=original;
    if(status)status.textContent=!navigator.onLine
      ?'You are offline. Reconnect, then retry safe removal.'
      :error.message==='managed_operation_declaration_drift'
        ?'This declaration changed. Refresh the page and complete the current nixcfg review first.'
        :'Safe removal could not be requested. Encrypted recovery material remains protected; try again.';
  }
}));
document.querySelectorAll('[data-managed-details-target]').forEach(button=>button.addEventListener('click',()=>{
  const details=document.getElementById(button.dataset.managedDetailsTarget||'');
  if(details){details.open=true;details.scrollIntoView({block:'nearest'});}
}));"#;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ManagedSecretSlotState {
    Missing,
    Installing,
    Active,
    ActionNeeded,
    RollbackRestored,
    Replacing,
    Removing,
    Removed,
    RemovalFinalizing,
}

impl ManagedSecretSlotState {
    fn from_operation(operation_kind: Option<&str>, phase: Option<&str>) -> Self {
        match (operation_kind, phase) {
            (Some("replace"), Some("rolled_back")) => Self::RollbackRestored,
            (Some("remove"), Some("removed")) => Self::Removed,
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
            Self::RollbackRestored => "Active · replacement undone",
            Self::Replacing => "Replacing",
            Self::Removing => "Removing",
            Self::Removed => "Removed · recovery window",
            Self::RemovalFinalizing => "Removed · final cleanup",
        }
    }

    fn tone(self) -> &'static str {
        match self {
            Self::Missing => "missing",
            Self::Installing | Self::Replacing | Self::Removing | Self::RemovalFinalizing => {
                "working"
            }
            Self::Removed => "missing",
            Self::Active => "active",
            Self::RollbackRestored => "active",
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
            Self::ActionNeeded => "The last safe attempt stopped safely.",
            Self::RollbackRestored => {
                "The replacement did not pass every check, so the previous healthy secret was restored."
            }
            Self::Replacing => "A replacement is being delivered and checked.",
            Self::Removing => "Removal is in progress and the service is being checked.",
            Self::Removed => {
                "The service is stopped and encrypted generations are quarantined until the recovery window ends."
            }
            Self::RemovalFinalizing => {
                "The recovery window ended. Final encrypted cleanup is being retried safely."
            }
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
                    | ManagedOperationPhase::RemovalPending
                    | ManagedOperationPhase::Removing
            )
        )
    }) {
        ("working", "Setup running")
    } else if phases
        .iter()
        .any(|phase| matches!(phase, Some(ManagedOperationPhase::Removed)))
    {
        ("missing", "Removed")
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
                pharos_core::managed_operations::ManagedOperationKind::Remove => "remove",
            });
        let phase = operation.as_ref().map(|operation| operation.phase.name());
        let mut state = ManagedSecretSlotState::from_operation(operation_kind, phase);
        if state == ManagedSecretSlotState::Removed
            && operation
                .as_ref()
                .and_then(|operation| operation.purge_not_before_unix_secs)
                .is_some_and(|deadline| now >= deadline)
        {
            state = ManagedSecretSlotState::RemovalFinalizing;
        }
        slots.push_str(&render_slot(
            manifest,
            service,
            slot,
            state,
            operation.as_ref(),
            setup_enabled,
            now,
        ));
    }
    format!(
        r#"{HEAD}{sidebar}<main class="managed-services-main managed-service-detail"><a class="managed-back" href="/services">{back} Services</a><div class="top managed-detail-top"><div><span class="managed-kicker">Managed service</span><div class="brand"><h1>{service_label}</h1></div><p class="fleet">{host_label} · {slot_count}</p></div><span class="managed-lock">{lock} Declared target</span></div><section class="managed-slot-list" aria-label="Secret slots">{slots}</section><details class="managed-service-details" id="managed-setup-configuration"><summary>Managed setup requirements</summary><p>Pharos never holds a secret value. A fleet operator must configure the reviewed Janus setup integration before create, replace, or removal requests can be issued.</p><p>After that configuration is present, refresh this declared service and use the enabled action for the current state.</p></details><details class="managed-service-details"><summary>Technical details</summary><dl><div><dt>Host reference</dt><dd><code>{host_ref}</code></dd></div><div><dt>Service reference</dt><dd><code>{service_ref}</code></dd></div><div><dt>Runtime</dt><dd>Managed Compose service</dd></div></dl></details><script>{runtime}</script></main></div></body></html>"#,
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
    now: i64,
) -> String {
    let operation_details_action = operation
        .map(|operation| {
            format!(
                r##"<a class="managed-secondary" href="#managed-operation-{operation_ref}" data-managed-details-target="managed-operation-{operation_ref}">View operation details</a>"##,
                operation_ref = html_escape(&operation.operation_ref),
            )
        })
        .unwrap_or_else(|| {
            r##"<a class="managed-secondary" href="#managed-setup-configuration" data-managed-details-target="managed-setup-configuration">Check managed setup requirements</a>"##.to_string()
        });
    let action = if state == ManagedSecretSlotState::Missing && setup_enabled {
        format!(
            r#"<button class="managed-primary" type="button" data-managed-secret-action data-operation-kind="create" data-host-ref="{host_ref}" data-service-ref="{service_ref}" data-slot-ref="{slot_ref}">Add missing secret</button>"#,
            host_ref = html_escape(&manifest.host_ref),
            service_ref = html_escape(&service.service_ref),
            slot_ref = html_escape(&slot.slot_ref),
        )
    } else if state == ManagedSecretSlotState::ActionNeeded
        && setup_enabled
        && operation.is_some_and(|operation| operation.verification_retryable)
    {
        format!(
            r#"<button class="managed-primary" type="button" data-managed-verification-retry data-operation-ref="{operation_ref}">Recheck recovered service</button>"#,
            operation_ref = html_escape(
                &operation
                    .expect("retryable verification has an operation")
                    .operation_ref
            ),
        )
    } else if state == ManagedSecretSlotState::ActionNeeded
        && operation.is_some_and(|operation| operation.removal_retryable)
    {
        format!(
            r#"<button class="managed-primary managed-danger" type="button" data-managed-removal-retry data-operation-ref="{operation_ref}">Retry safe removal</button>"#,
            operation_ref = html_escape(
                &operation
                    .expect("retryable removal has an operation")
                    .operation_ref
            ),
        )
    } else if state == ManagedSecretSlotState::ActionNeeded
        && setup_enabled
        && operation.is_some_and(|operation| {
            operation.operation_kind
                == pharos_core::managed_operations::ManagedOperationKind::Create
        })
    {
        format!(
            r#"<button class="managed-primary" type="button" data-managed-secret-action data-operation-kind="create" data-host-ref="{host_ref}" data-service-ref="{service_ref}" data-slot-ref="{slot_ref}">Try setup again</button>"#,
            host_ref = html_escape(&manifest.host_ref),
            service_ref = html_escape(&service.service_ref),
            slot_ref = html_escape(&slot.slot_ref),
        )
    } else if state == ManagedSecretSlotState::Missing {
        operation_details_action.clone()
    } else if matches!(
        state,
        ManagedSecretSlotState::Active | ManagedSecretSlotState::RollbackRestored
    ) && setup_enabled
        && slot.binding_state == pharos_core::managed_services::ManagedBindingState::Detached
    {
        format!(
            r#"<button class="managed-secondary managed-danger" type="button" data-managed-secret-action data-operation-kind="remove" data-host-ref="{host_ref}" data-service-ref="{service_ref}" data-slot-ref="{slot_ref}">Remove secret safely</button>"#,
            host_ref = html_escape(&manifest.host_ref),
            service_ref = html_escape(&service.service_ref),
            slot_ref = html_escape(&slot.slot_ref),
        )
    } else if matches!(
        state,
        ManagedSecretSlotState::Active | ManagedSecretSlotState::RollbackRestored
    ) && setup_enabled
    {
        format!(
            r##"<button class="managed-secondary" type="button" data-managed-secret-action data-operation-kind="replace" data-host-ref="{host_ref}" data-service-ref="{service_ref}" data-slot-ref="{slot_ref}">Replace / rotate secret</button><a class="managed-link-danger" href="#managed-detach-{slot_ref}" data-managed-details-target="managed-detach-{slot_ref}">Prepare nixcfg detachment review</a>"##,
            host_ref = html_escape(&manifest.host_ref),
            service_ref = html_escape(&service.service_ref),
            slot_ref = html_escape(&slot.slot_ref),
        )
    } else {
        operation_details_action
    };
    let progress = operation
        .map(|operation| {
            render_operation_progress(
                operation.phase.name(),
                operation.purge_not_before_unix_secs,
                now,
            )
        })
        .unwrap_or_default();
    let separation = render_operation_separation(operation, now);
    let operation_details = render_operation_details(operation);
    let detachment_task = render_detachment_owner_task(manifest, service, slot);
    format!(
        r#"<article class="managed-slot-card"><div class="managed-slot-head"><div><span class="managed-kicker">Service secret</span><h2>{slot_label}</h2></div><span class="managed-state {tone}">{state_label}</span></div><p class="managed-slot-guidance">{guidance}</p><dl class="managed-slot-facts"><div><dt>Consumer</dt><dd>{service_label}</dd></div><div><dt>Delivery</dt><dd>Private environment file</dd></div><div><dt>Reveal</dt><dd>Never</dd></div></dl>{separation}{progress}{operation_details}{detachment_task}<div class="managed-slot-action">{action}<p role="status" aria-live="polite" data-managed-action-status>{availability}</p></div></article>"#,
        slot_label = html_escape(&slot.safe_label),
        tone = state.tone(),
        state_label = state.label(),
        guidance = state.guidance(),
        service_label = html_escape(&service.safe_label),
        separation = separation,
        progress = progress,
        operation_details = operation_details,
        detachment_task = detachment_task,
        action = action,
        availability = if setup_enabled
            && matches!(
                state,
                ManagedSecretSlotState::Active | ManagedSecretSlotState::RollbackRestored
            )
            && slot.binding_state == pharos_core::managed_services::ManagedBindingState::Detached
        {
            "The reviewed binding is detached. Janus will stop and verify the exact service, revoke delivery, remove runtime material, and quarantine encrypted generations before destruction."
        } else if setup_enabled
            && matches!(
                state,
                ManagedSecretSlotState::Active | ManagedSecretSlotState::RollbackRestored
            )
        {
            "Janus will stage a new generation and keep the previous working generation recoverable until every check passes."
        } else if state == ManagedSecretSlotState::Removing {
            "The exact service stop, runtime absence check, and encrypted quarantine are still in progress."
        } else if state == ManagedSecretSlotState::Removed {
            "Active use has ended. Encrypted quarantine remains recoverable until the displayed recovery window closes."
        } else if state == ManagedSecretSlotState::RemovalFinalizing {
            "Active use remains stopped while exact encrypted cleanup is retried."
        } else if setup_enabled
            && state == ManagedSecretSlotState::ActionNeeded
            && operation.is_some_and(|operation| operation.verification_retryable)
        {
            "The encrypted generation is already installed. Pharos will request fresh exact-generation health evidence; no secret is created or revealed."
        } else if state == ManagedSecretSlotState::ActionNeeded
            && operation.is_some_and(|operation| operation.removal_retryable)
        {
            "Pharos will retry the same declared removal generation and detach profile. The host must provide fresh exact absence evidence; no secret is created or revealed."
        } else if setup_enabled
            && state == ManagedSecretSlotState::ActionNeeded
            && operation.is_some_and(|operation| {
                operation.operation_kind
                    == pharos_core::managed_operations::ManagedOperationKind::Create
            })
        {
            "Nothing from the previous attempt is active. Trying again starts a fresh passkey-confirmed operation."
        } else if setup_enabled {
            "Janus will confirm the exact target and ask how to create the value."
        } else {
            "Managed setup is not configured on this Pharos instance."
        },
    )
}

fn render_detachment_owner_task(
    manifest: &ManagedServiceManifestV1,
    service: &pharos_core::managed_services::ManagedServiceDeclarationV1,
    slot: &pharos_core::managed_services::ManagedSecretSlotDeclarationV1,
) -> String {
    if slot.binding_state != pharos_core::managed_services::ManagedBindingState::Required {
        return String::new();
    }
    format!(
        r#"<details class="managed-service-details" id="managed-detach-{slot_ref}"><summary>nixcfg detachment review</summary><p>Owner: nixcfg. Prepare a reviewed declaration change for this exact declared slot, then merge and deploy it before requesting removal.</p><dl><div><dt>Host</dt><dd><code>{host_ref}</code></dd></div><div><dt>Service</dt><dd><code>{service_ref}</code></dd></div><div><dt>Slot</dt><dd><code>{slot_ref}</code></dd></div><div><dt>Required evidence</dt><dd>Current declaration reports Detached and supplies its declared detach profile.</dd></div><div><dt>Resume</dt><dd>Refresh this page after the deployed declaration is observed; Pharos enables the value-free removal request only then.</dd></div></dl></details>"#,
        host_ref = html_escape(&manifest.host_ref),
        service_ref = html_escape(&service.service_ref),
        slot_ref = html_escape(&slot.slot_ref),
    )
}

fn render_operation_details(
    operation: Option<&crate::managed_service_operations::ManagedOperationSummary>,
) -> String {
    let Some(operation) = operation else {
        return String::new();
    };
    let kind = match operation.operation_kind {
        pharos_core::managed_operations::ManagedOperationKind::Create => "Create",
        pharos_core::managed_operations::ManagedOperationKind::Replace => "Replace",
        pharos_core::managed_operations::ManagedOperationKind::Remove => "Remove",
    };
    let reason = operation
        .reason_code
        .map(|reason| format!("{reason:?}"))
        .unwrap_or_else(|| "Awaiting host result".to_string());
    let retry = if operation.verification_retryable {
        "A fresh exact-generation verification can be requested; it does not create or reveal a secret."
    } else if operation.removal_retryable {
        "The same declared removal can be retried. It reuses the generation and detach profile, and requires fresh exact absence evidence without creating or revealing a secret."
    } else if operation.phase == ManagedOperationPhase::Removed {
        "No browser retry is needed. Final encrypted cleanup remains an idempotent owner task after the recovery window."
    } else if operation.phase.terminal() {
        "This terminal record is retained as evidence. Start a new reviewed operation only from the enabled next step."
    } else {
        "The declared host owns the next leased phase. Refresh to observe new evidence; Pharos will not replay it from the browser."
    };
    let terminal_evidence = if let Some(health) = &operation.health {
        format!(
            "Healthy generation {} accepted at {}.",
            health.generation,
            clock_label(health.accepted_at_unix_secs),
        )
    } else if let Some(rollback) = &operation.rollback {
        format!(
            "Previous generation {} was restored and accepted at {}.",
            rollback.restored_generation,
            clock_label(rollback.accepted_at_unix_secs),
        )
    } else if let Some(removal) = &operation.removal {
        format!(
            "Generation {} was stopped with runtime absence evidence accepted at {}.",
            removal.generation,
            clock_label(removal.accepted_at_unix_secs),
        )
    } else {
        "No terminal health or removal evidence has been accepted yet.".to_string()
    };
    let recovery = operation
        .purge_not_before_unix_secs
        .map(|deadline| {
            format!(
                "Recovery window closes no earlier than {}.",
                clock_label(deadline)
            )
        })
        .unwrap_or_else(|| "No removal recovery window applies.".to_string());
    format!(
        r#"<details class="managed-service-details" id="managed-operation-{operation_ref}"><summary>Operation details</summary><dl><div><dt>Operation</dt><dd><code>{operation_ref}</code> · {kind}</dd></div><div><dt>Owner</dt><dd>nixcfg declares; Janus keeps custody; the declared host executes.</dd></div><div><dt>Progress</dt><dd>{phase}</dd></div><div><dt>Reason</dt><dd>{reason}</dd></div><div><dt>Started</dt><dd>{created}</dd></div><div><dt>Last updated</dt><dd>{updated}</dd></div><div><dt>Current phase deadline</dt><dd>{deadline}</dd></div><div><dt>Retry</dt><dd>{retry}</dd></div><div><dt>Terminal evidence</dt><dd>{terminal_evidence}</dd></div><div><dt>Recovery</dt><dd>{recovery}</dd></div></dl></details>"#,
        operation_ref = html_escape(&operation.operation_ref),
        kind = kind,
        phase = html_escape(operation.phase.name()),
        reason = html_escape(&reason),
        created = html_escape(&clock_label(operation.created_at_unix_secs)),
        updated = html_escape(&clock_label(operation.updated_at_unix_secs)),
        deadline = html_escape(&clock_label(operation.deadline_unix_secs)),
        retry = html_escape(retry),
        terminal_evidence = html_escape(&terminal_evidence),
        recovery = html_escape(&recovery),
    )
}

fn render_operation_separation(
    operation: Option<&crate::managed_service_operations::ManagedOperationSummary>,
    now: i64,
) -> String {
    if operation.is_some_and(|operation| {
        operation.phase == ManagedOperationPhase::Removed
            && operation
                .purge_not_before_unix_secs
                .is_some_and(|deadline| now >= deadline)
    }) {
        return r#"<dl class="managed-operation-lanes" aria-label="Operation boundaries"><div><dt>Declaration</dt><dd>Locked by nixcfg</dd></div><div><dt>Janus delivery</dt><dd>Final encrypted cleanup due</dd></div><div><dt>Host execution</dt><dd>Declared service stopped</dd></div><div><dt>Observed health</dt><dd>Runtime material absent</dd></div></dl>"#.to_string();
    }
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
        Some(ManagedOperationPhase::RemovalPending | ManagedOperationPhase::Removing) => (
            "Delivery revoked",
            "Stopping exact declared service",
            "Verifying absence",
        ),
        Some(ManagedOperationPhase::Active) => (
            "Installed on host",
            "Declared reload completed",
            "Fresh generation healthy",
        ),
        Some(ManagedOperationPhase::Removed) => (
            "Encrypted generations quarantined",
            "Declared service stopped",
            "Runtime material absent",
        ),
        Some(ManagedOperationPhase::RolledBack) => (
            "Replacement withdrawn",
            "Previous generation restored",
            "Previous generation healthy",
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

fn render_operation_progress(
    phase: &str,
    purge_not_before_unix_secs: Option<i64>,
    now: i64,
) -> String {
    if phase == "rolled_back" {
        return r#"<section class="managed-operation-progress" aria-label="Replacement recovery"><h3>Replacement safely undone</h3><p>The previous generation was restored and passed the declared service health check. The replacement value is not active.</p></section>"#.to_string();
    }
    if matches!(phase, "removal_pending" | "removing") {
        return r#"<section class="managed-operation-progress" aria-label="Secret removal"><h3>Removing safely</h3><p>Delivery is revoked. The declared service must stop and the host must prove runtime material is absent before encrypted generations enter quarantine.</p></section>"#.to_string();
    }
    if phase == "removed" {
        if purge_not_before_unix_secs.is_some_and(|deadline| now >= deadline) {
            return r#"<section class="managed-operation-progress" aria-label="Secret removal"><h3>Recovery window ended</h3><p>The service remains stopped. Janus and the host will keep retrying exact, idempotent destruction of their encrypted quarantine copies until final cleanup succeeds.</p></section>"#.to_string();
        }
        return r#"<section class="managed-operation-progress" aria-label="Secret removal"><h3>Removed from active use</h3><p>The declared service is stopped, runtime material is absent, and encrypted generations are quarantined for the recovery window.</p></section>"#.to_string();
    }
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
        ManagedOperationAgentOutcome, ManagedOperationKind, ManagedOperationLeaseV1,
        ManagedOperationReadyV1, ManagedOperationReason, ManagedOperationResultV1,
        MANAGED_OPERATION_CONTRACT_VERSION, MANAGED_OPERATION_READY_SCHEMA,
        MANAGED_OPERATION_RESULT_SCHEMA,
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

    fn operation_result(
        lease: &ManagedOperationLeaseV1,
        outcome: ManagedOperationAgentOutcome,
        reason_code: ManagedOperationReason,
    ) -> ManagedOperationResultV1 {
        ManagedOperationResultV1 {
            schema: MANAGED_OPERATION_RESULT_SCHEMA.to_string(),
            schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
            lease_ref: lease.lease_ref.clone(),
            operation_ref: lease.operation_ref.clone(),
            host_ref: lease.host_ref.clone(),
            phase: lease.phase,
            outcome,
            reason_code,
            generation: lease.generation,
            health_evidence: None,
            rollback_evidence: None,
            removal_evidence: None,
            value_returned: false,
        }
    }

    #[test]
    fn every_plain_language_slot_state_has_a_stable_tone_and_guidance() {
        let states = [
            ManagedSecretSlotState::Missing,
            ManagedSecretSlotState::Installing,
            ManagedSecretSlotState::Active,
            ManagedSecretSlotState::ActionNeeded,
            ManagedSecretSlotState::RollbackRestored,
            ManagedSecretSlotState::Replacing,
            ManagedSecretSlotState::Removing,
            ManagedSecretSlotState::Removed,
            ManagedSecretSlotState::RemovalFinalizing,
        ];
        assert_eq!(
            states.map(ManagedSecretSlotState::label),
            [
                "Missing",
                "Installing",
                "Active",
                "Action needed",
                "Active · replacement undone",
                "Replacing",
                "Removing",
                "Removed · recovery window",
                "Removed · final cleanup"
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
            ManagedSecretSlotState::from_operation(Some("remove"), Some("removed")),
            ManagedSecretSlotState::Removed
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
    fn remove_action_appears_only_after_reviewed_detach_and_explains_recovery() {
        let mut manifest = fixture();
        let service = manifest.services[0].clone();
        let required = render_slot(
            &manifest,
            &service,
            &service.slots[0],
            ManagedSecretSlotState::Active,
            None,
            true,
            1_800_000_000,
        );
        assert!(required.contains("Replace / rotate secret"));
        assert!(required.contains("Prepare nixcfg detachment review"));
        assert!(required.contains("nixcfg detachment review"));
        assert!(required.contains("Current declaration reports Detached"));
        assert!(required.contains(r#"data-operation-kind="replace""#));
        assert!(!required.contains(r#"data-operation-kind="remove""#));

        manifest.services[0].slots[0].binding_state =
            pharos_core::managed_services::ManagedBindingState::Detached;
        let detached_service = manifest.services[0].clone();
        let detached = render_slot(
            &manifest,
            &detached_service,
            &detached_service.slots[0],
            ManagedSecretSlotState::Active,
            None,
            true,
            1_800_000_000,
        );
        for expected in [
            "Remove secret safely",
            r#"data-operation-kind="remove""#,
            "reviewed binding is detached",
            "stop and verify the exact service",
            "quarantine encrypted generations",
        ] {
            assert!(detached.contains(expected), "missing {expected}");
        }
        for forbidden in [
            "Replace / rotate secret",
            r#"name="secret_value""#,
            r#"name="source""#,
        ] {
            assert!(!detached.contains(forbidden), "found {forbidden}");
        }

        let removed = render_operation_progress("removed", Some(1_800_086_400), 1_800_000_000);
        assert!(removed.contains("Removed from active use"));
        assert!(removed.contains("recovery window"));
        let finalizing = render_operation_progress("removed", Some(1_800_086_400), 1_800_086_400);
        assert!(finalizing.contains("Recovery window ended"));
        assert!(finalizing.contains("keep retrying"));
        assert!(HEAD.contains(".managed-danger"));
        assert!(MANAGED_SETUP_RUNTIME.contains("value-free removal request"));
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
    fn failed_create_offers_a_fresh_retry_without_hiding_the_safe_failure() {
        let manifest = fixture();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        operations
            .register(
                &ManagedOperationReadyV1 {
                    schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
                    schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
                    operation_ref: "op_retrycreate01".to_string(),
                    operation_kind: ManagedOperationKind::Create,
                    host_ref: manifest.host_ref.clone(),
                    service_ref: manifest.services[0].service_ref.clone(),
                    slot_ref: manifest.services[0].slots[0].slot_ref.clone(),
                    declaration_fingerprint: manifest.declaration_fingerprint.clone(),
                    generation: 1,
                    purge_not_before_unix_secs: None,
                    value_returned: false,
                },
                &manifest.services[0].slots[0],
                1_800_000_000,
            )
            .unwrap();
        let html = render_service_detail(
            &manifest,
            &manifest.services[0],
            shell(),
            true,
            &operations,
            1_800_001_800,
        );
        for expected in [
            "Action needed",
            "The last safe attempt stopped safely",
            "Try setup again",
            r#"data-operation-kind="create""#,
            "Nothing from the previous attempt is active",
            "fresh passkey-confirmed operation",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        assert!(!html.contains("View operation details"));
        assert!(!html.contains("secret_value"));
    }

    #[test]
    fn failed_removal_offers_the_same_safe_removal_retry_with_recovery_evidence() {
        let manifest = fixture();
        let operation = crate::managed_service_operations::ManagedOperationSummary {
            operation_ref: "op_retryremove_ui".to_string(),
            operation_kind: ManagedOperationKind::Remove,
            host_ref: manifest.host_ref.clone(),
            service_ref: manifest.services[0].service_ref.clone(),
            slot_ref: manifest.services[0].slots[0].slot_ref.clone(),
            declaration_fingerprint: manifest.declaration_fingerprint.clone(),
            generation: 1,
            purge_not_before_unix_secs: Some(1_800_086_400),
            phase: ManagedOperationPhase::Failed,
            reason_code: Some(ManagedOperationReason::RemovalFailed),
            created_at_unix_secs: 1_800_000_000,
            updated_at_unix_secs: 1_800_000_010,
            deadline_unix_secs: 1_800_001_800,
            health: None,
            rollback: None,
            removal: None,
            value_returned: false,
            verification_retryable: false,
            removal_retryable: true,
        };
        let html = render_slot(
            &manifest,
            &manifest.services[0],
            &manifest.services[0].slots[0],
            ManagedSecretSlotState::ActionNeeded,
            Some(&operation),
            false,
            1_800_000_020,
        );
        for expected in [
            "Retry safe removal",
            "data-managed-removal-retry",
            "op_retryremove_ui",
            "same declared removal generation and detach profile",
            "The same declared removal can be retried",
            "Operation details",
            "Terminal evidence",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        for forbidden in [
            "data-managed-secret-action",
            "secret_value",
            "name=\"source\"",
            "callback_url",
        ] {
            assert!(!html.contains(forbidden), "found {forbidden}");
        }
        assert!(MANAGED_SETUP_RUNTIME.contains("Safe removal retry requested"));
    }

    #[test]
    fn completed_delivery_failure_offers_only_exact_generation_recheck() {
        const NOW: i64 = 1_800_000_000;
        let manifest = fixture();
        let operations = ManagedServiceOperationStore::new(None).unwrap();
        let operation_ref = "op_retry_verify_ui";
        operations
            .register(
                &ManagedOperationReadyV1 {
                    schema: MANAGED_OPERATION_READY_SCHEMA.to_string(),
                    schema_version: MANAGED_OPERATION_CONTRACT_VERSION,
                    operation_ref: operation_ref.to_string(),
                    operation_kind: ManagedOperationKind::Create,
                    host_ref: manifest.host_ref.clone(),
                    service_ref: manifest.services[0].service_ref.clone(),
                    slot_ref: manifest.services[0].slots[0].slot_ref.clone(),
                    declaration_fingerprint: manifest.declaration_fingerprint.clone(),
                    generation: 1,
                    purge_not_before_unix_secs: None,
                    value_returned: false,
                },
                &manifest.services[0].slots[0],
                NOW,
            )
            .unwrap();
        for completed_at in [NOW + 2, NOW + 4] {
            let lease = operations
                .claim(&manifest.host_ref, completed_at - 1)
                .unwrap()
                .unwrap();
            operations
                .record_result(
                    &operation_result(
                        &lease,
                        ManagedOperationAgentOutcome::Succeeded,
                        ManagedOperationReason::PhaseSucceeded,
                    ),
                    completed_at,
                )
                .unwrap();
        }
        let verify = operations
            .claim(&manifest.host_ref, NOW + 5)
            .unwrap()
            .unwrap();
        operations
            .record_result(
                &operation_result(
                    &verify,
                    ManagedOperationAgentOutcome::Failed,
                    ManagedOperationReason::VerificationFailed,
                ),
                NOW + 6,
            )
            .unwrap();

        let html = render_service_detail(
            &manifest,
            &manifest.services[0],
            shell(),
            true,
            &operations,
            NOW + 7,
        );
        for expected in [
            "Action needed",
            "Recheck recovered service",
            "data-managed-verification-retry",
            operation_ref,
            "already installed",
            "fresh exact-generation health evidence",
            "no secret is created or revealed",
            "Operation details",
            "Owner",
            "Current phase deadline",
            "Terminal evidence",
            "A fresh exact-generation verification can be requested",
        ] {
            assert!(html.contains(expected), "missing {expected}");
        }
        for forbidden in [
            "Try setup again",
            "data-managed-secret-action data-operation-kind",
            "fresh passkey-confirmed operation",
            "secret_value",
        ] {
            assert!(!html.contains(forbidden), "found {forbidden}");
        }
    }

    #[test]
    fn operation_progress_uses_plain_phases_and_keeps_evidence_out_of_the_summary() {
        let html = render_operation_progress("reloaded", None, 1_800_000_000);
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
    fn active_slot_offers_only_replace_and_rollback_copy_preserves_confidence() {
        let manifest = fixture();
        let service = &manifest.services[0];
        let slot = &service.slots[0];
        let active = render_slot(
            &manifest,
            service,
            slot,
            ManagedSecretSlotState::Active,
            None,
            true,
            1_800_000_000,
        );
        for expected in [
            "Replace / rotate secret",
            r#"data-operation-kind="replace""#,
            "keep the previous working generation recoverable",
            "Reveal</dt><dd>Never",
        ] {
            assert!(active.contains(expected), "missing {expected}");
        }
        for forbidden in ["Edit secret", "Reveal secret", "secret_value"] {
            assert!(!active.contains(forbidden), "found {forbidden}");
        }

        let rolled_back = render_operation_progress("rolled_back", None, 1_800_000_000);
        for expected in [
            "Replacement safely undone",
            "previous generation was restored",
            "replacement value is not active",
        ] {
            assert!(rolled_back.contains(expected), "missing {expected}");
        }
        assert!(!rolled_back.contains("rollback_id"));
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
                    purge_not_before_unix_secs: None,
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
        assert!(detail.contains("Check managed setup requirements"));
        assert!(detail.contains("Managed setup requirements"));
        assert!(!detail.contains("Setup unavailable"));

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
