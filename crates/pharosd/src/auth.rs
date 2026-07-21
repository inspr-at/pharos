//! OIDC (Authorization Code + PKCE) auth against Zitadel (PHAROS-4).
//!
//! Startup is fail closed: the OIDC variables are all-or-nothing. Open human
//! routes require an explicit `PHAROS_ALLOW_OPEN=true` opt-in and a loopback
//! listener, so a partial or drifted production configuration cannot silently
//! disable authentication.
//!
//! Public client (PKCE, no client secret). The human routes (`/`, `/hosts.json`)
//! are gated; machine routes (`POST /register`, `POST /report`) use the
//! PHAROS-8 beacon token flow instead of browser login, while `/healthz` and
//! `/version` stay open.
//!
//! Sessions and in-flight logins are in-memory (single-instance pharosd). A
//! restart drops them — the dashboard reloads from disk, the user just logs in
//! again.

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata,
    CoreUserInfoClaims,
};
use openidconnect::reqwest;
use openidconnect::{
    AccessToken, AuthorizationCode, ClaimsVerificationError, ClientId, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, RedirectUrl, Scope, SubjectIdentifier, TokenResponse,
};
use sha2::{Digest, Sha256};

const SESSION_COOKIE: &str = "__Host-pharos_session";
const FLOW_COOKIE: &str = "__Host-pharos_flow";
const LOGOUT_CSRF_COOKIE: &str = "__Host-pharos_logout_csrf";
const SESSION_TTL_SECS: i64 = 8 * 3600;
const FLOW_TTL_SECS: i64 = 600;
const RATE_WINDOW_SECS: i64 = 60;
const MAX_PENDING_FLOWS: usize = 512;
const MAX_SESSIONS: usize = 4_096;
const MAX_LOGIN_STARTS_PER_WINDOW: u32 = 120;
const MAX_SESSION_CREATES_PER_WINDOW: u32 = 120;
const ALLOWED_OPERATORS_ENV: &str = "PHAROS_ALLOWED_OPERATORS";
const ACCESS_POLICY_FILE_ENV: &str = "PHAROS_ACCESS_POLICY_FILE";
const ALLOW_OPEN_ENV: &str = "PHAROS_ALLOW_OPEN";
const OPERATOR_REF_DOMAIN: &str = "pharos:oidc-principal:operator-ref:v2:";
const VERIFIED_EMAIL_REF_DOMAIN: &str = "pharos:oidc-principal:verified-email-ref:v1:";

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// One in-flight login, between `/auth/login` and `/auth/callback`. The IdP
/// echoes the CSRF state; a separate hashed flow cookie binds that state to the
/// browser that initiated it.
struct Pending {
    verifier: PkceCodeVerifier,
    nonce: Nonce,
    flow_cookie_hash: [u8; 32],
    created: i64,
}

#[derive(Default)]
struct RateWindow {
    started_at: i64,
    count: u32,
}

impl RateWindow {
    fn allow(&mut self, current: i64, limit: u32) -> bool {
        if self.started_at == 0
            || current < self.started_at
            || current.saturating_sub(self.started_at) >= RATE_WINDOW_SECS
        {
            self.started_at = current;
            self.count = 0;
        }
        if self.count >= limit {
            return false;
        }
        self.count = self.count.saturating_add(1);
        true
    }
}

#[derive(Clone)]
pub struct AuthUser {
    pub operator_ref: String,
    pub display_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccessGrant {
    all_hosts: bool,
    hosts: BTreeSet<String>,
    agora: bool,
}

impl AccessGrant {
    pub fn full() -> Self {
        Self {
            all_hosts: true,
            hosts: BTreeSet::new(),
            agora: true,
        }
    }

    pub fn empty() -> Self {
        Self {
            all_hosts: false,
            hosts: BTreeSet::new(),
            agora: false,
        }
    }

    pub fn limited<I, S>(hosts: I, agora: bool) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            all_hosts: false,
            hosts: hosts.into_iter().map(Into::into).collect(),
            agora,
        }
    }

    pub fn allows_host(&self, host: &str) -> bool {
        self.all_hosts || self.hosts.contains(host)
    }

    pub fn can_agora(&self) -> bool {
        self.agora
    }

    pub fn can_manage_fleet(&self) -> bool {
        self.agora && self.all_hosts
    }

    pub fn is_empty(&self) -> bool {
        !self.all_hosts && self.hosts.is_empty() && !self.agora
    }
}

struct LoginIdentity {
    subject: SubjectIdentifier,
    display_name: String,
    identifiers: Vec<String>,
}

struct Session {
    #[allow(dead_code)]
    subject: String,
    display_name: String,
    identifiers: Vec<String>,
    expires: i64,
}

pub struct Auth {
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect: RedirectUrl,
    http_client: reqwest::Client,
    client: Mutex<OidcClient>,
    operator_policy: OperatorPolicy,
    access_policy_file: Option<PathBuf>,
    pending: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, Session>>,
    login_rate: Mutex<RateWindow>,
    session_rate: Mutex<RateWindow>,
}

/// `None` = auth disabled (open). `Some` = OIDC enforced.
pub type AuthState = Option<Arc<Auth>>;

/// Fully validated human-authentication startup configuration.
pub(crate) struct AuthConfig {
    mode: AuthConfigMode,
}

enum AuthConfigMode {
    Open,
    Oidc(Box<OidcAuthConfig>),
}

struct OidcAuthConfig {
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect: RedirectUrl,
    operator_policy: OperatorPolicy,
    access_policy_file: Option<PathBuf>,
}

impl AuthConfig {
    pub fn from_env(listener_is_loopback: bool) -> Result<Self, String> {
        let issuer = env_nonempty("PHAROS_OIDC_ISSUER");
        let client_id = env_nonempty("PHAROS_OIDC_CLIENT_ID");
        let redirect = env_nonempty("PHAROS_OIDC_REDIRECT_URI");
        let allow_open = env_bool(ALLOW_OPEN_ENV)?.unwrap_or(false);
        let operator_policy = OperatorPolicy::from_env()?;
        Self::from_values(
            listener_is_loopback,
            issuer,
            client_id,
            redirect,
            allow_open,
            operator_policy,
            access_policy_file_from_env(),
        )
    }

    fn from_values(
        listener_is_loopback: bool,
        issuer: Option<String>,
        client_id: Option<String>,
        redirect: Option<String>,
        allow_open: bool,
        operator_policy: OperatorPolicy,
        access_policy_file: Option<PathBuf>,
    ) -> Result<Self, String> {
        let configured = [issuer.is_some(), client_id.is_some(), redirect.is_some()];

        if configured.iter().any(|configured| *configured)
            && !configured.iter().all(|configured| *configured)
        {
            return Err(
                "PHAROS_OIDC_ISSUER, PHAROS_OIDC_CLIENT_ID, and PHAROS_OIDC_REDIRECT_URI must be configured together"
                    .to_string(),
            );
        }

        let (Some(issuer), Some(client_id), Some(redirect)) = (issuer, client_id, redirect) else {
            if !allow_open {
                return Err(format!(
                    "OIDC is not configured; set {ALLOW_OPEN_ENV}=true only for an intentional loopback-only development instance"
                ));
            }
            if !listener_is_loopback {
                return Err(format!(
                    "{ALLOW_OPEN_ENV}=true is only permitted for an explicitly loopback-bound public address"
                ));
            }
            return Ok(Self {
                mode: AuthConfigMode::Open,
            });
        };

        if allow_open {
            return Err(format!(
                "{ALLOW_OPEN_ENV}=true cannot be combined with OIDC configuration"
            ));
        }

        let issuer = IssuerUrl::new(issuer)
            .map_err(|err| format!("PHAROS_OIDC_ISSUER is invalid: {err}"))?;
        let client_id = ClientId::new(client_id);
        let redirect = RedirectUrl::new(redirect)
            .map_err(|err| format!("PHAROS_OIDC_REDIRECT_URI is invalid: {err}"))?;
        if !listener_is_loopback && !operator_policy.is_enforced() && access_policy_file.is_none() {
            return Err(format!(
                "OIDC on a non-loopback listener requires {ALLOWED_OPERATORS_ENV} or {ACCESS_POLICY_FILE_ENV}"
            ));
        }

        Ok(Self {
            mode: AuthConfigMode::Oidc(Box::new(OidcAuthConfig {
                issuer,
                client_id,
                redirect,
                operator_policy,
                access_policy_file,
            })),
        })
    }
}

fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn env_bool(name: &str) -> Result<Option<bool>, String> {
    let Some(value) = env_nonempty(name) else {
        return Ok(None);
    };
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(Some(true)),
        "0" | "false" | "no" | "off" => Ok(Some(false)),
        _ => Err(format!(
            "{name} must be one of true/false, 1/0, yes/no, or on/off"
        )),
    }
}

impl Auth {
    /// Build from a validated startup configuration and discover provider
    /// metadata. Configuration and discovery errors are returned to the caller
    /// so startup can fail visibly.
    pub(crate) async fn from_config(config: AuthConfig) -> Result<AuthState, String> {
        let AuthConfigMode::Oidc(config) = config.mode else {
            tracing::warn!("human routes are open on an explicitly allowed loopback listener");
            return Ok(None);
        };
        let OidcAuthConfig {
            issuer: issuer_url,
            client_id,
            redirect,
            operator_policy,
            access_policy_file,
        } = *config;
        let http_client = reqwest::ClientBuilder::new()
            // OIDC 4 requires a stateful client; redirects must stay disabled
            // to avoid SSRF through provider-controlled endpoints.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|err| format!("OIDC HTTP client could not be built: {err}"))?;
        let client = discover_client(
            issuer_url.clone(),
            client_id.clone(),
            redirect.clone(),
            &http_client,
        )
        .await
        .map_err(|err| format!("OIDC discovery failed: {err}"))?;
        tracing::info!(issuer = %issuer_url.as_str(), "OIDC auth enabled");
        if operator_policy.is_enforced() {
            tracing::info!("Pharos operator authorization enabled");
        }
        if let Some(path) = &access_policy_file {
            tracing::info!(path = %path.display(), "Pharos access policy file enabled");
        }
        if !operator_policy.is_enforced() && access_policy_file.is_none() {
            tracing::warn!(
                "OIDC authorization policy is absent on a loopback listener; all authenticated users are allowed"
            );
        }
        Ok(Some(Arc::new(Auth {
            issuer: issuer_url,
            client_id,
            redirect,
            http_client,
            client: Mutex::new(client),
            operator_policy,
            access_policy_file,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
            login_rate: Mutex::new(RateWindow::default()),
            session_rate: Mutex::new(RateWindow::default()),
        })))
    }

    fn client(&self) -> OidcClient {
        self.client.lock().expect("client lock").clone()
    }

    /// Refresh OIDC discovery/JWKS metadata. Zitadel can rotate signing keys
    /// while pharosd is running; retrying with a refreshed verifier avoids a
    /// manual restart without weakening token validation.
    async fn refresh_client(&self) -> Result<(), String> {
        let client = discover_client(
            self.issuer.clone(),
            self.client_id.clone(),
            self.redirect.clone(),
            &self.http_client,
        )
        .await
        .map_err(|e| e.to_string())?;
        *self.client.lock().expect("client lock") = client;
        Ok(())
    }

    fn verify_id_token_identity(
        &self,
        client: &OidcClient,
        id_token: &CoreIdToken,
        nonce: &Nonce,
    ) -> Result<LoginIdentity, ClaimsVerificationError> {
        let verifier = client
            .id_token_verifier()
            // Zitadel adds the project id to the id_token audience alongside our
            // client_id; accept the extra audience (client_id presence,
            // signature, issuer, and nonce are still enforced).
            .set_other_audience_verifier_fn(|_aud| true);
        let claims = id_token.claims(&verifier, nonce)?;
        let subject = claims.subject().clone();
        let mut identity = LoginIdentity {
            display_name: display_name_from_claims(claims, subject.as_str()),
            subject,
            identifiers: Vec::new(),
        };
        identity.add_principal(self.issuer.as_str());
        if claims.email_verified() == Some(true) {
            if let Some(email) = claims.email() {
                identity.add_verified_email(email.as_str());
            }
        }
        Ok(identity)
    }

    fn sweep(&self) {
        let n = now();
        self.pending
            .lock()
            .expect("pending lock")
            .retain(|_, flow| n >= flow.created && n.saturating_sub(flow.created) < FLOW_TTL_SECS);
        self.sessions
            .lock()
            .expect("sessions lock")
            .retain(|_, s| s.expires > n);
    }

    fn take_pending(
        &self,
        state: &str,
        flow_cookie_hash: &[u8; 32],
        current: i64,
    ) -> Option<Pending> {
        take_pending_flow(&self.pending, state, flow_cookie_hash, current)
    }

    fn is_authed(&self, headers: &HeaderMap) -> bool {
        let Some(sid) = cookie(headers, SESSION_COOKIE) else {
            return false;
        };
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(&sid)
            .is_some_and(|s| s.expires > now())
    }

    pub fn current_user(&self, headers: &HeaderMap) -> Option<AuthUser> {
        let sid = cookie(headers, SESSION_COOKIE)?;
        self.sessions
            .lock()
            .expect("sessions lock")
            .get(&sid)
            .filter(|s| s.expires > now())
            .map(|session| AuthUser::from_session(session, self.issuer.as_str()))
    }

    pub fn current_access(&self, headers: &HeaderMap) -> AccessGrant {
        let Some(sid) = cookie(headers, SESSION_COOKIE) else {
            return AccessGrant::empty();
        };
        let identifiers = self
            .sessions
            .lock()
            .expect("sessions lock")
            .get(&sid)
            .filter(|s| s.expires > now())
            .map(|s| s.identifiers.clone());
        identifiers
            .as_deref()
            .map(|identifiers| self.access_for_identifiers(identifiers))
            .unwrap_or_else(AccessGrant::empty)
    }

    fn access_for_identifiers(&self, identifiers: &[String]) -> AccessGrant {
        if !self.operator_policy.is_enforced() && self.access_policy_file.is_none() {
            return AccessGrant::full();
        }
        if self.operator_policy.matches_identifiers(identifiers) {
            return AccessGrant::full();
        }
        let Some(path) = &self.access_policy_file else {
            return AccessGrant::empty();
        };
        match std::fs::read_to_string(path)
            .map_err(|err| err.to_string())
            .and_then(|raw| {
                AccessPolicyDocument::from_json(&raw).map(|policy| policy.grant_for(identifiers))
            }) {
            Ok(grant) => grant,
            Err(err) => {
                tracing::warn!(path = %path.display(), error = %err, "could not read Pharos access policy; denying non-operator access");
                AccessGrant::empty()
            }
        }
    }
}

fn take_pending_flow(
    pending: &Mutex<HashMap<String, Pending>>,
    state: &str,
    flow_cookie_hash: &[u8; 32],
    current: i64,
) -> Option<Pending> {
    let mut pending_flows = pending.lock().expect("pending lock");
    let flow = pending_flows.get(state)?;
    if current < flow.created || current.saturating_sub(flow.created) >= FLOW_TTL_SECS {
        pending_flows.remove(state);
        return None;
    }
    if !constant_time_equal(&flow.flow_cookie_hash, flow_cookie_hash) {
        return None;
    }
    pending_flows.remove(state)
}

fn bounded_insert<K, V>(
    entries: &mut HashMap<K, V>,
    key: K,
    value: V,
    maximum: usize,
) -> Result<(), ()>
where
    K: Eq + std::hash::Hash,
{
    if entries.len() >= maximum || entries.contains_key(&key) {
        return Err(());
    }
    entries.insert(key, value);
    Ok(())
}

impl AuthUser {
    fn from_session(session: &Session, issuer: &str) -> Self {
        Self {
            operator_ref: operator_ref_from_principal(issuer, &session.subject),
            display_name: session.display_name.clone(),
        }
    }
}

fn operator_ref_from_principal(issuer: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(OPERATOR_REF_DOMAIN.as_bytes());
    hasher.update(issuer.as_bytes());
    hasher.update([0]);
    hasher.update(subject.as_bytes());
    format!("{:x}", hasher.finalize())
}

fn verified_email_ref_from_email(email: &str) -> Option<String> {
    let email = normalize_email(email)?;
    let mut hasher = Sha256::new();
    hasher.update(VERIFIED_EMAIL_REF_DOMAIN.as_bytes());
    hasher.update(email.as_bytes());
    Some(format!("{:x}", hasher.finalize()))
}

#[derive(Clone)]
struct OperatorPolicy {
    allowed: Vec<String>,
}

impl OperatorPolicy {
    fn from_env() -> Result<Self, String> {
        Self::from_raw(std::env::var(ALLOWED_OPERATORS_ENV).ok().as_deref())
    }

    fn from_raw(raw: Option<&str>) -> Result<Self, String> {
        let mut allowed = Vec::new();
        for value in raw
            .into_iter()
            .flat_map(|value| value.split([',', ' ', '\n', '\t']))
            .filter(|value| !value.trim().is_empty())
        {
            let identifier = normalize_policy_identifier(value)?;
            if !allowed.contains(&identifier) {
                allowed.push(identifier);
            }
        }
        Ok(Self { allowed })
    }

    fn is_enforced(&self) -> bool {
        !self.allowed.is_empty()
    }

    fn matches_identifiers(&self, identifiers: &[String]) -> bool {
        self.is_enforced()
            && identifiers
                .iter()
                .any(|identifier| self.allowed.contains(identifier))
    }
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessPolicyDocument {
    #[serde(default)]
    grants: Vec<AccessPolicyEntry>,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct AccessPolicyEntry {
    #[serde(default, alias = "users")]
    identifiers: Vec<String>,
    #[serde(default)]
    hosts: Vec<String>,
    #[serde(default)]
    agora: bool,
}

impl AccessPolicyDocument {
    fn from_json(raw: &str) -> Result<Self, String> {
        let mut document: Self = serde_json::from_str(raw).map_err(|err| err.to_string())?;
        if document.grants.len() > 4_096 {
            return Err("access policy has too many grants".to_string());
        }
        for grant in &mut document.grants {
            if grant.identifiers.len() > 128 || grant.hosts.len() > 4_096 {
                return Err("access policy grant exceeds bounds".to_string());
            }
            grant.identifiers = grant
                .identifiers
                .iter()
                .map(|identifier| normalize_policy_identifier(identifier))
                .collect::<Result<Vec<_>, _>>()?;
        }
        Ok(document)
    }

    fn grant_for(&self, identifiers: &[String]) -> AccessGrant {
        let mut grant = AccessGrant::empty();
        for entry in &self.grants {
            if entry.identifiers.is_empty()
                || !identifiers
                    .iter()
                    .any(|identifier| entry.identifiers.contains(identifier))
            {
                continue;
            }
            if entry.agora {
                grant.agora = true;
            }
            for host in &entry.hosts {
                let host = host.trim();
                if host.is_empty() {
                    continue;
                }
                if host == "*" || host.eq_ignore_ascii_case("all") {
                    grant.all_hosts = true;
                } else {
                    grant.hosts.insert(host.to_string());
                }
            }
        }
        grant
    }
}

fn access_policy_file_from_env() -> Option<PathBuf> {
    std::env::var(ACCESS_POLICY_FILE_ENV)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

pub fn access_for_headers(auth: &AuthState, headers: &HeaderMap) -> AccessGrant {
    match auth {
        None => AccessGrant::full(),
        Some(auth) => auth.current_access(headers),
    }
}

impl LoginIdentity {
    fn add_principal(&mut self, issuer: &str) {
        self.add_authorization_identifier(format!(
            "operator-ref:{}",
            operator_ref_from_principal(issuer, self.subject.as_str())
        ));
    }

    fn add_verified_email(&mut self, value: &str) {
        if let Some(email) = normalize_email(value) {
            if let Some(reference) = verified_email_ref_from_email(&email) {
                self.add_authorization_identifier(format!("verified-email-ref:{reference}"));
            }
            self.add_authorization_identifier(format!("email:{email}"));
        }
    }

    fn add_authorization_identifier(&mut self, value: String) {
        if !self.identifiers.contains(&value) {
            self.identifiers.push(value);
        }
    }
}

fn normalize_email(value: &str) -> Option<String> {
    let value = value.trim();
    let normalized = value.to_ascii_lowercase();
    (normalized.len() <= 320
        && !normalized.starts_with('@')
        && !normalized.ends_with('@')
        && normalized.matches('@').count() == 1)
        .then_some(normalized)
}

fn normalize_policy_identifier(value: &str) -> Result<String, String> {
    let value = value.trim();
    for prefix in ["operator-ref:", "verified-email-ref:"] {
        let Some(reference) = value.strip_prefix(prefix) else {
            continue;
        };
        if reference.len() == 64
            && reference
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Ok(format!("{prefix}{reference}"));
        }
        return Err(format!(
            "{} authorization identifiers require 64 lowercase hex characters",
            prefix.trim_end_matches(':')
        ));
    }
    if let Some(email) = value.strip_prefix("email:").and_then(normalize_email) {
        return Ok(format!("email:{email}"));
    }
    Err("authorization identifiers must use operator-ref:<sha256>, \
         verified-email-ref:<sha256>, or email:<verified-address>"
        .to_string())
}

fn clean_display_name(value: &str) -> Option<String> {
    let value = value.trim();
    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

fn display_name_from_claims(claims: &CoreIdTokenClaims, subject: &str) -> String {
    claims
        .preferred_username()
        .and_then(|name| clean_display_name(name.as_str()))
        .or_else(|| {
            claims
                .email()
                .and_then(|email| clean_display_name(email.as_str()))
        })
        .or_else(|| {
            claims
                .name()
                .and_then(|name| name.get(None))
                .and_then(|name| clean_display_name(name.as_str()))
        })
        .unwrap_or_else(|| subject.to_string())
}

fn display_name_from_user_info(claims: &CoreUserInfoClaims) -> Option<String> {
    claims
        .preferred_username()
        .and_then(|name| clean_display_name(name.as_str()))
        .or_else(|| {
            claims
                .email()
                .and_then(|email| clean_display_name(email.as_str()))
        })
        .or_else(|| {
            claims
                .name()
                .and_then(|name| name.get(None))
                .and_then(|name| clean_display_name(name.as_str()))
        })
}

fn add_user_info_identifiers(claims: &CoreUserInfoClaims, identity: &mut LoginIdentity) {
    if claims.email_verified() == Some(true) {
        if let Some(email) = claims.email() {
            identity.add_verified_email(email.as_str());
        }
    }
}

async fn enrich_identity_from_user_info(
    client: &OidcClient,
    http_client: &reqwest::Client,
    access_token: AccessToken,
    identity: &mut LoginIdentity,
) {
    let request = match client.user_info(access_token, Some(identity.subject.clone())) {
        Ok(request) => request,
        Err(err) => {
            tracing::debug!("OIDC userinfo endpoint unavailable: {err}");
            return;
        }
    };

    match request.request_async(http_client).await {
        Ok(user_info) => {
            add_user_info_identifiers(&user_info, identity);
            if let Some(display_name) = display_name_from_user_info(&user_info) {
                identity.display_name = display_name;
            }
        }
        Err(err) => {
            tracing::warn!("OIDC userinfo request failed; using id_token claims: {err}");
        }
    }
}

async fn discover_client(
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect: RedirectUrl,
    http_client: &reqwest::Client,
) -> Result<OidcClient, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = CoreProviderMetadata::discover_async(issuer, http_client).await?;
    Ok(CoreClient::from_provider_metadata(metadata, client_id, None).set_redirect_uri(redirect))
}

fn cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            (k.trim() == name).then(|| v.trim().to_string())
        })
}

fn secret_hash(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn constant_time_equal(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn set_cookie(name: &str, value: &str, max_age: i64, http_only: bool, same_site: &str) -> String {
    let http_only = if http_only { "; HttpOnly" } else { "" };
    format!("{name}={value}; Path=/; Secure{http_only}; SameSite={same_site}; Max-Age={max_age}")
}

fn rate_limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, RATE_WINDOW_SECS.to_string())],
        "authentication rate limit exceeded; retry shortly",
    )
        .into_response()
}

/// Middleware gating the human routes. Open when auth is disabled; otherwise
/// requires a valid session cookie, else redirects to the login.
pub async fn guard(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    match &auth {
        None => next.run(req).await,
        Some(a) if a.is_authed(req.headers()) => next.run(req).await,
        Some(_) => Redirect::temporary("/auth/login").into_response(),
    }
}

/// `GET /auth/login` — start the PKCE flow, redirect to the IdP.
pub async fn login(State(auth): State<AuthState>) -> Response {
    let Some(auth) = auth else {
        return Redirect::temporary("/").into_response();
    };
    auth.sweep();
    let current = now();
    if !auth
        .login_rate
        .lock()
        .expect("login rate lock")
        .allow(current, MAX_LOGIN_STARTS_PER_WINDOW)
    {
        return rate_limited_response();
    }
    if auth.pending.lock().expect("pending lock").len() >= MAX_PENDING_FLOWS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many login flows are active; retry shortly",
        )
            .into_response();
    }

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let flow_cookie = CsrfToken::new_random().secret().clone();
    let client = auth.client();
    let (url, csrf, nonce) = client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        // openidconnect adds "openid" automatically.
        .add_scope(Scope::new("profile".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .set_pkce_challenge(challenge)
        .url();

    let mut pending = auth.pending.lock().expect("pending lock");
    if pending.len() >= MAX_PENDING_FLOWS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many login flows are active; retry shortly",
        )
            .into_response();
    }
    if bounded_insert(
        &mut pending,
        csrf.secret().clone(),
        Pending {
            verifier,
            nonce,
            flow_cookie_hash: secret_hash(&flow_cookie),
            created: current,
        },
        MAX_PENDING_FLOWS,
    )
    .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many login flows are active; retry shortly",
        )
            .into_response();
    }
    drop(pending);
    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        set_cookie(FLOW_COOKIE, &flow_cookie, FLOW_TTL_SECS, true, "Lax")
            .parse()
            .expect("flow cookie header"),
    );
    (headers, Redirect::temporary(url.as_str())).into_response()
}

#[derive(serde::Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /auth/callback` — verify state, exchange the code (with the PKCE
/// verifier), validate the ID token, and start a session.
pub async fn callback(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    Query(p): Query<CallbackParams>,
) -> Response {
    let Some(auth) = auth else {
        return Redirect::temporary("/").into_response();
    };
    let (Some(code), Some(state)) = (p.code, p.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    let Some(flow_cookie) = cookie(&headers, FLOW_COOKIE) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };
    let flow_cookie_hash = secret_hash(&flow_cookie);
    let current = now();
    let Some(pending) = auth.take_pending(&state, &flow_cookie_hash, current) else {
        return (StatusCode::BAD_REQUEST, "unknown or expired login").into_response();
    };

    let client = auth.client();
    let token_request = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(request) => request,
        Err(e) => {
            tracing::warn!("OIDC token endpoint unavailable: {e}");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "login temporarily unavailable; please retry",
            )
                .into_response();
        }
    };
    let token = match token_request
        .set_pkce_verifier(pending.verifier)
        .request_async(&auth.http_client)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            tracing::warn!("token exchange failed: {e}");
            return (StatusCode::UNAUTHORIZED, "token exchange failed").into_response();
        }
    };
    let Some(id_token) = token.id_token() else {
        return (StatusCode::UNAUTHORIZED, "no id_token").into_response();
    };
    let mut identity = match auth.verify_id_token_identity(&client, id_token, &pending.nonce) {
        Ok(identity) => identity,
        Err(ClaimsVerificationError::SignatureVerification(e)) => {
            tracing::warn!(
                "id_token signature verification failed; refreshing OIDC metadata and retrying: {e}"
            );
            if let Err(refresh_err) = auth.refresh_client().await {
                tracing::warn!("OIDC metadata refresh failed: {refresh_err}");
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "login verification temporarily unavailable; please retry",
                )
                    .into_response();
            }
            let refreshed = auth.client();
            match auth.verify_id_token_identity(&refreshed, id_token, &pending.nonce) {
                Ok(identity) => {
                    tracing::info!("id_token verified after OIDC metadata refresh");
                    identity
                }
                Err(e) => {
                    tracing::warn!("id_token verification failed after OIDC metadata refresh: {e}");
                    return (
                        StatusCode::UNAUTHORIZED,
                        "login verification failed; please retry",
                    )
                        .into_response();
                }
            }
        }
        Err(e) => {
            tracing::warn!("id_token verification failed: {e}");
            return (
                StatusCode::UNAUTHORIZED,
                "login verification failed; please retry",
            )
                .into_response();
        }
    };
    enrich_identity_from_user_info(
        &client,
        &auth.http_client,
        token.access_token().to_owned(),
        &mut identity,
    )
    .await;
    auth.sweep();
    if !auth
        .session_rate
        .lock()
        .expect("session rate lock")
        .allow(now(), MAX_SESSION_CREATES_PER_WINDOW)
    {
        return rate_limited_response();
    }
    if auth.sessions.lock().expect("sessions lock").len() >= MAX_SESSIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many sessions are active; retry after an existing session expires",
        )
            .into_response();
    }
    let sid = CsrfToken::new_random().secret().clone();
    let logout_csrf = CsrfToken::new_random().secret().clone();
    let mut sessions = auth.sessions.lock().expect("sessions lock");
    if sessions.len() >= MAX_SESSIONS {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many sessions are active; retry after an existing session expires",
        )
            .into_response();
    }
    if bounded_insert(
        &mut sessions,
        sid.clone(),
        Session {
            subject: identity.subject.as_str().to_string(),
            display_name: identity.display_name,
            identifiers: identity.identifiers,
            expires: now() + SESSION_TTL_SECS,
        },
        MAX_SESSIONS,
    )
    .is_err()
    {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "too many sessions are active; retry after an existing session expires",
        )
            .into_response();
    }
    drop(sessions);

    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, &sid, SESSION_TTL_SECS, true, "Lax")
            .parse()
            .expect("cookie header"),
    );
    headers.append(
        header::SET_COOKIE,
        set_cookie(
            LOGOUT_CSRF_COOKIE,
            &logout_csrf,
            SESSION_TTL_SECS,
            false,
            "Strict",
        )
        .parse()
        .expect("logout CSRF cookie header"),
    );
    headers.append(
        header::SET_COOKIE,
        set_cookie(FLOW_COOKIE, "", 0, true, "Lax")
            .parse()
            .expect("flow cookie clearing header"),
    );
    (headers, Redirect::temporary("/")).into_response()
}

#[cfg(test)]
fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        [
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, max-age=0, must-revalidate",
            ),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        Html(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Access denied · Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--accent:#1f7fb5}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%)}main{width:min(420px,calc(100% - 40px));padding:30px;border:1px solid rgba(211,225,233,.88);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 18px 42px rgba(45,75,95,.10);text-align:center}h1{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:28px;font-weight:500;color:#12304b}p{margin:0 0 20px;color:var(--muted)}a{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 16px;border-radius:7px;background:var(--accent);color:white;text-decoration:none;font-weight:650}</style></head><body><main><h1>Access denied</h1><p>Your login succeeded, but this Pharos instance has not granted you operator access.</p><a href="/">Return to Pharos</a></main></body></html>"#,
        ),
    )
        .into_response()
}

#[derive(serde::Deserialize)]
pub struct LogoutForm {
    csrf: String,
}

/// `POST /auth/logout` — verify the double-submit CSRF value, drop the session,
/// and clear the host-only cookies.
pub async fn logout(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    Form(form): Form<LogoutForm>,
) -> Response {
    let Some(cookie_csrf) = cookie(&headers, LOGOUT_CSRF_COOKIE) else {
        return (StatusCode::FORBIDDEN, "logout CSRF check failed").into_response();
    };
    if form.csrf.is_empty()
        || !constant_time_equal(&secret_hash(&form.csrf), &secret_hash(&cookie_csrf))
    {
        return (StatusCode::FORBIDDEN, "logout CSRF check failed").into_response();
    }
    if let Some(auth) = &auth {
        if let Some(sid) = cookie(&headers, SESSION_COOKIE) {
            auth.sessions.lock().expect("sessions lock").remove(&sid);
        }
    }
    let mut out = HeaderMap::new();
    out.append(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, "", 0, true, "Lax")
            .parse()
            .expect("cookie header"),
    );
    out.append(
        header::SET_COOKIE,
        set_cookie(LOGOUT_CSRF_COOKIE, "", 0, false, "Strict")
            .parse()
            .expect("logout CSRF clearing header"),
    );
    (out, Redirect::temporary("/auth/logged-out")).into_response()
}

/// `GET /auth/logged-out` — neutral landing page after local Pharos logout.
pub async fn logged_out() -> impl IntoResponse {
    (
        [
            (
                header::CACHE_CONTROL,
                "no-store, no-cache, max-age=0, must-revalidate",
            ),
            (header::PRAGMA, "no-cache"),
            (header::EXPIRES, "0"),
        ],
        Html(
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Logged out · Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--accent:#1f7fb5;--sun:#d69b31}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%)}main{width:min(420px,calc(100% - 40px));padding:30px;border:1px solid rgba(211,225,233,.88);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 18px 42px rgba(45,75,95,.10);text-align:center}h1{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:28px;font-weight:500;color:#12304b}p{margin:0 0 20px;color:var(--muted)}a{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 16px;border-radius:7px;background:var(--accent);color:white;text-decoration:none;font-weight:650}</style></head><body><main><h1>Logged out</h1><p>Your Pharos session has ended.</p><a href="/auth/login">Sign in</a></main></body></html>"#,
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::{get, post};
    use axum::{Json, Router};
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use rand::rngs::OsRng;
    use rsa::pkcs1v15::SigningKey;
    use rsa::signature::{SignatureEncoding as _, Signer as _};
    use rsa::traits::PublicKeyParts as _;
    use rsa::RsaPrivateKey;
    use url::Url;

    #[derive(Clone)]
    struct MockOidcProvider {
        issuer: String,
        signing_key: Arc<RsaPrivateKey>,
        nonce: Arc<Mutex<Option<String>>>,
    }

    async fn mock_discovery(State(provider): State<MockOidcProvider>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "issuer": provider.issuer,
            "authorization_endpoint": format!("{}/authorize", provider.issuer),
            "token_endpoint": format!("{}/token", provider.issuer),
            "userinfo_endpoint": format!("{}/userinfo", provider.issuer),
            "jwks_uri": format!("{}/jwks", provider.issuer),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["openid", "profile", "email"],
            "claims_supported": ["sub", "nonce", "preferred_username", "email", "email_verified"]
        }))
    }

    async fn mock_jwks(State(provider): State<MockOidcProvider>) -> Json<serde_json::Value> {
        let public = provider.signing_key.to_public_key();
        Json(serde_json::json!({
            "keys": [{
                "kty": "RSA",
                "kid": "pharos-oidc-e2e",
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode(public.n().to_bytes_be()),
                "e": URL_SAFE_NO_PAD.encode(public.e().to_bytes_be())
            }]
        }))
    }

    fn mock_id_token(provider: &MockOidcProvider) -> String {
        let header = serde_json::json!({
            "alg": "RS256",
            "kid": "pharos-oidc-e2e",
            "typ": "JWT"
        });
        let nonce = provider
            .nonce
            .lock()
            .expect("mock nonce lock")
            .clone()
            .expect("login nonce captured");
        let issued_at = now();
        let claims = serde_json::json!({
            "iss": provider.issuer,
            "sub": "oidc-e2e-subject",
            "aud": "pharos-oidc-e2e",
            "exp": issued_at + 300,
            "iat": issued_at,
            "nonce": nonce,
            "preferred_username": "oidc-e2e-user",
            "email": "oidc-e2e@example.invalid",
            "email_verified": true
        });
        let encoded_header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap());
        let encoded_claims = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{encoded_header}.{encoded_claims}");
        let signer = SigningKey::<Sha256>::new(provider.signing_key.as_ref().clone());
        let signature = signer.sign(signing_input.as_bytes());
        format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(signature.to_bytes())
        )
    }

    async fn mock_token(State(provider): State<MockOidcProvider>) -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "access_token": "opaque-test-access-token",
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": mock_id_token(&provider)
        }))
    }

    async fn mock_userinfo() -> Json<serde_json::Value> {
        Json(serde_json::json!({
            "sub": "oidc-e2e-subject",
            "preferred_username": "oidc-e2e-user",
            "email": "oidc-e2e@example.invalid",
            "email_verified": true
        }))
    }

    async fn start_mock_oidc() -> (MockOidcProvider, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let issuer = format!("http://{}", listener.local_addr().unwrap());
        let provider = MockOidcProvider {
            issuer,
            signing_key: Arc::new(RsaPrivateKey::new(&mut OsRng, 2048).unwrap()),
            nonce: Arc::new(Mutex::new(None)),
        };
        let app = Router::new()
            .route("/.well-known/openid-configuration", get(mock_discovery))
            .route("/jwks", get(mock_jwks))
            .route("/token", post(mock_token))
            .route("/userinfo", get(mock_userinfo).post(mock_userinfo))
            .with_state(provider.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        (provider, task)
    }

    fn response_cookie(response: &Response, name: &str) -> Option<String> {
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find_map(|value| {
                value
                    .split(';')
                    .next()
                    .filter(|pair| pair.starts_with(&format!("{name}=")))
                    .map(ToString::to_string)
            })
    }

    #[tokio::test]
    async fn oidc_authorization_code_pkce_flow_creates_a_browser_bound_session() {
        let (provider, server) = start_mock_oidc().await;
        let config = AuthConfig::from_values(
            true,
            Some(provider.issuer.clone()),
            Some("pharos-oidc-e2e".to_string()),
            Some("https://pharos.example.test/auth/callback".to_string()),
            false,
            OperatorPolicy::from_raw(None).unwrap(),
            None,
        )
        .unwrap();
        let auth_state = Auth::from_config(config).await.unwrap();

        let login_response = login(State(auth_state.clone())).await;
        assert_eq!(login_response.status(), StatusCode::TEMPORARY_REDIRECT);
        let authorization_url = Url::parse(
            login_response
                .headers()
                .get(header::LOCATION)
                .unwrap()
                .to_str()
                .unwrap(),
        )
        .unwrap();
        let parameters = authorization_url
            .query_pairs()
            .into_owned()
            .collect::<HashMap<_, _>>();
        let state = parameters.get("state").cloned().unwrap();
        *provider.nonce.lock().unwrap() = parameters.get("nonce").cloned();
        assert_eq!(
            parameters.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
        let flow_cookie = response_cookie(&login_response, FLOW_COOKIE).unwrap();

        let mut callback_headers = HeaderMap::new();
        callback_headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        let callback_response = callback(
            State(auth_state.clone()),
            callback_headers,
            Query(CallbackParams {
                code: Some("single-use-code".to_string()),
                state: Some(state),
            }),
        )
        .await;

        assert_eq!(callback_response.status(), StatusCode::TEMPORARY_REDIRECT);
        let session_cookie = response_cookie(&callback_response, SESSION_COOKIE).unwrap();
        let mut session_headers = HeaderMap::new();
        session_headers.insert(header::COOKIE, session_cookie.parse().unwrap());
        let user = auth_state
            .as_ref()
            .unwrap()
            .current_user(&session_headers)
            .expect("OIDC callback creates a session");
        assert_eq!(user.display_name, "oidc-e2e-user");
        assert_eq!(user.operator_ref.len(), 64);

        server.abort();
        let _ = server.await;
    }

    fn pending_flow(flow_cookie: &str, created: i64) -> Pending {
        let (_, verifier) = PkceCodeChallenge::new_random_sha256();
        Pending {
            verifier,
            nonce: Nonce::new("nonce-fixture".to_string()),
            flow_cookie_hash: secret_hash(flow_cookie),
            created,
        }
    }

    #[test]
    fn pending_flow_is_browser_bound_expiring_and_single_use() {
        let pending = Mutex::new(HashMap::from([(
            "state-fixture".to_string(),
            pending_flow("browser-a", 100),
        )]));

        assert!(
            take_pending_flow(&pending, "state-fixture", &secret_hash("browser-b"), 101).is_none()
        );
        assert_eq!(
            pending.lock().unwrap().len(),
            1,
            "wrong browser cannot consume flow"
        );
        assert!(
            take_pending_flow(&pending, "state-fixture", &secret_hash("browser-a"), 101).is_some()
        );
        assert!(
            take_pending_flow(&pending, "state-fixture", &secret_hash("browser-a"), 101).is_none()
        );

        pending
            .lock()
            .unwrap()
            .insert("expired".to_string(), pending_flow("browser-a", 100));
        assert!(take_pending_flow(
            &pending,
            "expired",
            &secret_hash("browser-a"),
            100 + FLOW_TTL_SECS
        )
        .is_none());
        assert!(
            pending.lock().unwrap().is_empty(),
            "expired flow is removed"
        );
    }

    #[test]
    fn auth_maps_and_creation_rates_are_strictly_bounded() {
        let mut entries = HashMap::new();
        for index in 0..MAX_PENDING_FLOWS {
            assert!(bounded_insert(&mut entries, index, (), MAX_PENDING_FLOWS).is_ok());
        }
        assert!(bounded_insert(&mut entries, MAX_PENDING_FLOWS, (), MAX_PENDING_FLOWS).is_err());
        assert_eq!(entries.len(), MAX_PENDING_FLOWS);

        let mut sessions = HashMap::new();
        for index in 0..MAX_SESSIONS {
            assert!(bounded_insert(&mut sessions, index, (), MAX_SESSIONS).is_ok());
        }
        assert!(bounded_insert(&mut sessions, MAX_SESSIONS, (), MAX_SESSIONS).is_err());
        assert_eq!(sessions.len(), MAX_SESSIONS);

        let mut rate = RateWindow::default();
        for _ in 0..MAX_LOGIN_STARTS_PER_WINDOW {
            assert!(rate.allow(100, MAX_LOGIN_STARTS_PER_WINDOW));
        }
        assert!(!rate.allow(100, MAX_LOGIN_STARTS_PER_WINDOW));
        assert!(rate.allow(100 + RATE_WINDOW_SECS, MAX_LOGIN_STARTS_PER_WINDOW));
    }

    #[test]
    fn host_prefixed_session_cookie_has_required_scope_and_flags() {
        let session = set_cookie(SESSION_COOKIE, "fixture", 60, true, "Lax");
        assert!(session.starts_with("__Host-pharos_session="));
        assert!(session.contains("; Path=/"));
        assert!(session.contains("; HttpOnly"));
        assert!(session.contains("; Secure"));
        assert!(!session.to_ascii_lowercase().contains("domain="));
    }

    #[tokio::test]
    async fn logout_requires_matching_double_submit_csrf_value() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            format!("{LOGOUT_CSRF_COOKIE}=csrf-fixture")
                .parse()
                .unwrap(),
        );
        let denied = logout(
            State(None),
            headers.clone(),
            Form(LogoutForm {
                csrf: "wrong".to_string(),
            }),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let accepted = logout(
            State(None),
            headers,
            Form(LogoutForm {
                csrf: "csrf-fixture".to_string(),
            }),
        )
        .await;
        assert!(accepted.status().is_redirection());
        let cleared = accepted.headers().get_all(header::SET_COOKIE);
        assert_eq!(cleared.iter().count(), 2);
    }

    #[tokio::test]
    async fn auth_pages_link_pharos_favicon() {
        let denied = forbidden().into_response();
        let denied_body = axum::body::to_bytes(denied.into_body(), usize::MAX)
            .await
            .expect("denied body");
        let denied_html = std::str::from_utf8(&denied_body).expect("denied html");
        assert!(
            denied_html.contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#)
        );

        let logged_out = logged_out().await.into_response();
        let logged_out_body = axum::body::to_bytes(logged_out.into_body(), usize::MAX)
            .await
            .expect("logged out body");
        let logged_out_html = std::str::from_utf8(&logged_out_body).expect("logged out html");
        assert!(logged_out_html
            .contains(r#"<link rel="icon" type="image/svg+xml" href="/favicon.svg">"#));
    }

    fn claims(json: &str) -> CoreIdTokenClaims {
        serde_json::from_str(json).expect("valid id token claims")
    }

    fn user_info(json: &str) -> CoreUserInfoClaims {
        CoreUserInfoClaims::from_json::<std::io::Error>(json.as_bytes(), None)
            .expect("valid userinfo claims")
    }

    #[test]
    fn display_name_prefers_zitadel_username_claim() {
        let claims = claims(
            r#"{
                "iss": "https://auth.inspr.at",
                "sub": "opaque-subject",
                "aud": "pharos",
                "exp": 4102444800,
                "iat": 1700000000,
                "preferred_username": "markus",
                "email": "markus@example.invalid",
                "name": "Markus Barta"
            }"#,
        );

        assert_eq!(
            display_name_from_claims(&claims, "opaque-subject"),
            "markus"
        );
    }

    #[test]
    fn display_name_falls_back_without_username_claim() {
        let claims = claims(
            r#"{
                "iss": "https://auth.inspr.at",
                "sub": "opaque-subject",
                "aud": "pharos",
                "exp": 4102444800,
                "iat": 1700000000,
                "email": "markus@example.invalid",
                "name": "Markus Barta"
            }"#,
        );

        assert_eq!(
            display_name_from_claims(&claims, "opaque-subject"),
            "markus@example.invalid"
        );
    }

    #[test]
    fn display_name_reads_userinfo_claims() {
        let user_info = user_info(
            r#"{
                "sub": "opaque-subject",
                "preferred_username": "markus"
            }"#,
        );

        assert_eq!(
            display_name_from_user_info(&user_info),
            Some("markus".to_string())
        );
    }

    #[test]
    fn operator_ref_is_stable_domain_separated_lowercase_hex() {
        let operator_ref =
            operator_ref_from_principal("https://issuer.example.test", "opaque-subject");

        assert_eq!(
            operator_ref,
            "6672d3b0e81375008a36d203936aeec654db7566abda3451e7a672be5d36170d"
        );
        assert_eq!(operator_ref.len(), 64);
        assert!(operator_ref
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert!(!operator_ref.contains("opaque-subject"));
        assert_ne!(
            operator_ref,
            operator_ref_from_principal("https://other-issuer.example.test", "opaque-subject")
        );
    }

    #[test]
    fn auth_user_derives_operator_ref_from_private_session_subject() {
        let session = Session {
            subject: "opaque-subject".to_string(),
            display_name: "Markus".to_string(),
            identifiers: vec!["markus".to_string()],
            expires: i64::MAX,
        };

        let user = AuthUser::from_session(&session, "https://issuer.example.test");

        assert_eq!(
            user.operator_ref,
            "6672d3b0e81375008a36d203936aeec654db7566abda3451e7a672be5d36170d"
        );
        assert_eq!(user.display_name, "Markus");
    }

    #[test]
    fn operator_policy_allows_when_not_configured() {
        assert!(!OperatorPolicy::from_raw(None).unwrap().is_enforced());
    }

    #[test]
    fn operator_policy_allows_immutable_principal_or_verified_email() {
        let mut identity = LoginIdentity {
            subject: SubjectIdentifier::new("subject-1".to_string()),
            display_name: "markus".to_string(),
            identifiers: Vec::new(),
        };
        identity.add_principal("https://issuer.example.test");
        identity.add_verified_email("Markus@Example.Invalid");
        let reference = operator_ref_from_principal("https://issuer.example.test", "subject-1");
        let email_reference =
            verified_email_ref_from_email("markus@example.invalid").expect("valid email");

        assert!(
            OperatorPolicy::from_raw(Some(&format!("operator-ref:{reference}")))
                .unwrap()
                .matches_identifiers(&identity.identifiers)
        );
        assert!(
            OperatorPolicy::from_raw(Some(&format!("verified-email-ref:{email_reference}")))
                .unwrap()
                .matches_identifiers(&identity.identifiers)
        );
        assert!(
            OperatorPolicy::from_raw(Some("email:markus@example.invalid"))
                .unwrap()
                .matches_identifiers(&identity.identifiers)
        );
    }

    #[test]
    fn operator_policy_rejects_mutable_or_malformed_identifiers() {
        assert!(OperatorPolicy::from_raw(Some("markus")).is_err());
        assert!(OperatorPolicy::from_raw(Some("markus@example.invalid")).is_err());
        assert!(OperatorPolicy::from_raw(Some("operator-ref:not-a-hash")).is_err());
        assert!(OperatorPolicy::from_raw(Some("verified-email-ref:not-a-hash")).is_err());
        assert!(OperatorPolicy::from_raw(Some("email:not-an-email")).is_err());
    }

    #[test]
    fn access_policy_grants_hosts_and_agora_by_identifier() {
        let policy = AccessPolicyDocument::from_json(
            r#"{
                "grants": [
                    {
                        "identifiers": ["email:dad@example.invalid"],
                        "hosts": ["hsb8"],
                        "agora": false
                    },
                    {
                        "identifiers": ["operator-ref:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
                        "hosts": ["*"],
                        "agora": true
                    }
                ]
            }"#,
        )
        .expect("policy parses");

        let dad = policy.grant_for(&["email:dad@example.invalid".to_string()]);
        assert!(dad.allows_host("hsb8"));
        assert!(!dad.allows_host("csb1"));
        assert!(!dad.can_agora());

        let markus = policy.grant_for(&[format!("operator-ref:{}", "a".repeat(64))]);
        assert!(markus.allows_host("csb1"));
        assert!(markus.allows_host("hsb8"));
        assert!(markus.can_agora());
    }

    #[test]
    fn access_policy_is_deny_by_default_for_unknown_users() {
        let policy = AccessPolicyDocument::from_json(
            r#"{
                "grants": [
                    {
                        "identifiers": ["email:markus@example.invalid"],
                        "hosts": ["*"],
                        "agora": true
                    }
                ]
            }"#,
        )
        .expect("policy parses");

        let unknown = policy.grant_for(&["email:new-user@example.invalid".to_string()]);
        assert!(unknown.is_empty());
        assert!(!unknown.allows_host("csb1"));
        assert!(!unknown.can_agora());
    }

    #[test]
    fn userinfo_authorizes_only_verified_email_and_never_username() {
        let mut identity = LoginIdentity {
            subject: SubjectIdentifier::new("opaque-subject".to_string()),
            display_name: "opaque-subject".to_string(),
            identifiers: Vec::new(),
        };
        identity.add_principal("https://issuer.example.test");
        let verified_claims = user_info(
            r#"{
                "sub": "opaque-subject",
                "preferred_username": "markus",
                "email": "markus@example.invalid",
                "email_verified": true
            }"#,
        );

        add_user_info_identifiers(&verified_claims, &mut identity);

        assert!(identity
            .identifiers
            .contains(&"email:markus@example.invalid".to_string()));
        assert!(identity
            .identifiers
            .iter()
            .any(|identifier| identifier.starts_with("verified-email-ref:")));
        assert!(!identity.identifiers.contains(&"markus".to_string()));

        let unverified = user_info(
            r#"{
                "sub": "opaque-subject",
                "email": "other@example.invalid",
                "email_verified": false
            }"#,
        );
        add_user_info_identifiers(&unverified, &mut identity);
        assert!(!identity
            .identifiers
            .contains(&"email:other@example.invalid".to_string()));
        assert!(!identity.identifiers.iter().any(|identifier| {
            identifier
                == &format!(
                    "verified-email-ref:{}",
                    verified_email_ref_from_email("other@example.invalid").expect("valid email")
                )
        }));
    }

    fn policy(raw: Option<&str>) -> OperatorPolicy {
        OperatorPolicy::from_raw(raw).expect("test authorization policy is valid")
    }

    fn oidc_values() -> (Option<String>, Option<String>, Option<String>) {
        (
            Some("https://issuer.example.test".to_string()),
            Some("pharos".to_string()),
            Some("https://pharos.example.test/auth/callback".to_string()),
        )
    }

    #[test]
    fn open_auth_requires_explicit_loopback_opt_in() {
        let denied_without_opt_in =
            AuthConfig::from_values(true, None, None, None, false, policy(None), None);
        assert!(denied_without_opt_in.is_err());

        let denied_non_loopback =
            AuthConfig::from_values(false, None, None, None, true, policy(None), None);
        assert!(denied_non_loopback.is_err());

        let allowed = AuthConfig::from_values(true, None, None, None, true, policy(None), None)
            .expect("explicit loopback-only open mode is valid");
        assert!(matches!(allowed.mode, AuthConfigMode::Open));
    }

    #[test]
    fn partial_oidc_configuration_is_rejected() {
        let result = AuthConfig::from_values(
            true,
            Some("https://issuer.example.test".to_string()),
            None,
            None,
            false,
            policy(None),
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn non_loopback_oidc_requires_authorization_policy() {
        let (issuer, client_id, redirect) = oidc_values();
        let denied = AuthConfig::from_values(
            false,
            issuer.clone(),
            client_id.clone(),
            redirect.clone(),
            false,
            policy(None),
            None,
        );
        assert!(denied.is_err());

        let allowed = AuthConfig::from_values(
            false,
            issuer,
            client_id,
            redirect,
            false,
            policy(Some("email:operator@example.invalid")),
            None,
        )
        .expect("operator policy makes non-loopback OIDC fail closed");
        assert!(matches!(allowed.mode, AuthConfigMode::Oidc(_)));
    }

    #[test]
    fn oidc_cannot_be_combined_with_open_mode() {
        let (issuer, client_id, redirect) = oidc_values();
        let result =
            AuthConfig::from_values(true, issuer, client_id, redirect, true, policy(None), None);
        assert!(result.is_err());
    }
}
