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
use std::error::Error as StdError;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Form, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::middleware::Next;
use axum::response::{Html, IntoResponse, Redirect, Response};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreErrorResponseType, CoreIdToken, CoreIdTokenClaims,
    CoreProviderMetadata, CoreRequestTokenError, CoreUserInfoClaims,
};
use openidconnect::reqwest;
use openidconnect::{
    AccessToken, AuthorizationCode, ClaimsVerificationError, ClientId, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, HttpClientError, IssuerUrl, Nonce, OAuth2TokenResponse,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, RequestTokenError, Scope, SubjectIdentifier,
    TokenResponse,
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
const MAX_RETURN_TO_BYTES: usize = 2_048;
const ALLOWED_OPERATORS_ENV: &str = "PHAROS_ALLOWED_OPERATORS";
const ACCESS_POLICY_FILE_ENV: &str = "PHAROS_ACCESS_POLICY_FILE";
const ALLOW_OPEN_ENV: &str = "PHAROS_ALLOW_OPEN";
const OPERATOR_REF_DOMAIN: &str = "pharos:oidc-principal:operator-ref:v2:";
const VERIFIED_EMAIL_REF_DOMAIN: &str = "pharos:oidc-principal:verified-email-ref:v1:";
const MANAGED_HUMAN_SESSION_REF_DOMAIN: &str = "inspr.managed-service-human-session.v1";

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
    return_to: String,
    created: i64,
}

enum PendingFlowOutcome {
    Matched(Pending),
    Missing,
    Expired(String),
    BrowserMismatch(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OidcTransportClass {
    Dns,
    Connection,
    Tls,
    Timeout,
    Request,
}

impl OidcTransportClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Connection => "connection",
            Self::Tls => "tls",
            Self::Timeout => "timeout",
            Self::Request => "request",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LoginRecovery {
    FlowUnavailable,
    ProviderRejected,
    ProviderUnavailable,
    MalformedProviderResponse,
    VerificationFailed,
}

impl LoginRecovery {
    fn status(self) -> StatusCode {
        match self {
            Self::FlowUnavailable => StatusCode::BAD_REQUEST,
            Self::ProviderRejected | Self::VerificationFailed => StatusCode::UNAUTHORIZED,
            Self::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Self::MalformedProviderResponse => StatusCode::BAD_GATEWAY,
        }
    }

    fn message(self) -> &'static str {
        match self {
            Self::FlowUnavailable => {
                "This sign-in is no longer active. It may have expired, Pharos may have restarted, or another tab may have started a newer sign-in."
            }
            Self::ProviderRejected => {
                "The identity provider did not accept this sign-in. Start again when you are ready."
            }
            Self::ProviderUnavailable => {
                "Pharos could not reach the identity provider safely. Try again in a moment."
            }
            Self::MalformedProviderResponse => {
                "The identity provider returned an unexpected response. Start a fresh sign-in to continue."
            }
            Self::VerificationFailed => {
                "Pharos could not verify this sign-in safely. Start again to get a fresh verification."
            }
        }
    }
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
    pub managed_human_session_ref: String,
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
    async fn refresh_client(&self) -> Result<(), OidcTransportClass> {
        let client = discover_client(
            self.issuer.clone(),
            self.client_id.clone(),
            self.redirect.clone(),
            &self.http_client,
        )
        .await
        .map_err(|error| classify_error_chain(error.as_ref()))?;
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
        flow_cookie_hash: Option<&[u8; 32]>,
        current: i64,
    ) -> PendingFlowOutcome {
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
    flow_cookie_hash: Option<&[u8; 32]>,
    current: i64,
) -> PendingFlowOutcome {
    let mut pending_flows = pending.lock().expect("pending lock");
    let Some(flow) = pending_flows.remove(state) else {
        return PendingFlowOutcome::Missing;
    };
    if current < flow.created || current.saturating_sub(flow.created) >= FLOW_TTL_SECS {
        return PendingFlowOutcome::Expired(flow.return_to);
    }
    if !flow_cookie_hash.is_some_and(|flow_cookie_hash| {
        constant_time_equal(&flow.flow_cookie_hash, flow_cookie_hash)
    }) {
        return PendingFlowOutcome::BrowserMismatch(flow.return_to);
    }
    PendingFlowOutcome::Matched(flow)
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
            managed_human_session_ref: managed_human_session_ref(issuer, &session.subject),
            display_name: session.display_name.clone(),
        }
    }
}

fn managed_human_session_ref(issuer: &str, subject: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(MANAGED_HUMAN_SESSION_REF_DOMAIN.as_bytes());
    hasher.update([0]);
    hasher.update(issuer.trim_end_matches('/').as_bytes());
    hasher.update([0]);
    hasher.update(subject.as_bytes());
    format!("hsn_{:x}", hasher.finalize())
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
        Err(_) => {
            tracing::debug!(
                category = "userinfo_endpoint_unavailable",
                "OIDC userinfo enrichment skipped safely"
            );
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
        Err(_) => {
            tracing::warn!(
                category = "userinfo_request_failed",
                "OIDC userinfo enrichment failed; using verified id_token claims"
            );
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

fn new_flow_cookie(return_to: &str) -> String {
    let secret = CsrfToken::new_random().secret().clone();
    let encoded_return = URL_SAFE_NO_PAD.encode(return_to.as_bytes());
    format!("{secret}.{encoded_return}")
}

fn return_to_from_flow_cookie(value: Option<&str>) -> String {
    let Some((_, encoded_return)) = value.and_then(|value| value.split_once('.')) else {
        return "/".to_string();
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded_return) else {
        return "/".to_string();
    };
    let Ok(return_to) = String::from_utf8(decoded) else {
        return "/".to_string();
    };
    validated_return_to(Some(&return_to))
}

fn validated_return_to(candidate: Option<&str>) -> String {
    let Some(candidate) = candidate else {
        return "/".to_string();
    };
    if candidate.is_empty()
        || candidate.len() > MAX_RETURN_TO_BYTES
        || !candidate.starts_with('/')
        || candidate.starts_with("//")
        || candidate.contains('\\')
        || candidate.contains('#')
        || candidate.chars().any(char::is_control)
    {
        return "/".to_string();
    }
    let Ok(uri) = candidate.parse::<Uri>() else {
        return "/".to_string();
    };
    if uri.scheme().is_some() || uri.authority().is_some() {
        return "/".to_string();
    }
    let path = uri.path();
    if path == "/auth" || path.starts_with("/auth/") {
        return "/".to_string();
    }
    candidate.to_string()
}

fn login_location(return_to: &str) -> String {
    if return_to == "/" {
        return "/auth/login".to_string();
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("return_to", return_to);
    format!("/auth/login?{}", query.finish())
}

fn classify_transport_signals(
    timeout: bool,
    connect: bool,
    diagnostic: &str,
) -> OidcTransportClass {
    if timeout {
        return OidcTransportClass::Timeout;
    }
    let diagnostic = diagnostic.to_ascii_lowercase();
    if diagnostic.contains("dns")
        || diagnostic.contains("name resolution")
        || diagnostic.contains("failed to lookup address")
    {
        return OidcTransportClass::Dns;
    }
    if diagnostic.contains("tls")
        || diagnostic.contains("certificate")
        || diagnostic.contains("rustls")
        || diagnostic.contains("handshake")
    {
        return OidcTransportClass::Tls;
    }
    if connect {
        return OidcTransportClass::Connection;
    }
    OidcTransportClass::Request
}

fn error_chain_diagnostic(error: &(dyn StdError + 'static)) -> String {
    let mut diagnostic = String::new();
    let mut current = Some(error);
    while let Some(error) = current {
        if !diagnostic.is_empty() {
            diagnostic.push(' ');
        }
        diagnostic.push_str(&error.to_string());
        current = error.source();
    }
    diagnostic
}

fn classify_reqwest_error(error: &reqwest::Error) -> OidcTransportClass {
    classify_transport_signals(
        error.is_timeout(),
        error.is_connect(),
        &error_chain_diagnostic(error),
    )
}

fn classify_error_chain(error: &(dyn StdError + 'static)) -> OidcTransportClass {
    let mut current = Some(error);
    while let Some(error) = current {
        if let Some(reqwest_error) = error.downcast_ref::<reqwest::Error>() {
            return classify_reqwest_error(reqwest_error);
        }
        current = error.source();
    }
    classify_transport_signals(false, false, &error_chain_diagnostic(error))
}

fn classify_http_client_error(error: &HttpClientError<reqwest::Error>) -> OidcTransportClass {
    match error {
        HttpClientError::Reqwest(error) => classify_reqwest_error(error),
        HttpClientError::Io(_) => OidcTransportClass::Connection,
        HttpClientError::Http(_) | HttpClientError::Other(_) => OidcTransportClass::Request,
        _ => OidcTransportClass::Request,
    }
}

fn provider_response_class(error: &CoreErrorResponseType) -> &'static str {
    match error {
        CoreErrorResponseType::InvalidClient => "invalid_client",
        CoreErrorResponseType::InvalidGrant => "invalid_grant",
        CoreErrorResponseType::InvalidRequest => "invalid_request",
        CoreErrorResponseType::InvalidScope => "invalid_scope",
        CoreErrorResponseType::UnauthorizedClient => "unauthorized_client",
        CoreErrorResponseType::UnsupportedGrantType => "unsupported_grant_type",
        CoreErrorResponseType::Extension(_) => "extension",
    }
}

fn classify_token_exchange_error(
    error: &CoreRequestTokenError<HttpClientError<reqwest::Error>>,
) -> (LoginRecovery, &'static str) {
    match error {
        RequestTokenError::ServerResponse(response) => (
            LoginRecovery::ProviderRejected,
            provider_response_class(response.error()),
        ),
        RequestTokenError::Request(error) => {
            let class = classify_http_client_error(error);
            (LoginRecovery::ProviderUnavailable, class.as_str())
        }
        RequestTokenError::Parse(_, _) => (
            LoginRecovery::MalformedProviderResponse,
            "malformed_response",
        ),
        RequestTokenError::Other(_) => (
            LoginRecovery::MalformedProviderResponse,
            "unexpected_response",
        ),
    }
}

fn login_recovery_response(recovery: LoginRecovery, return_to: &str) -> Response {
    let return_to = validated_return_to(Some(return_to));
    let login = login_location(&return_to);
    let html = format!(
        r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Sign-in recovery · Pharos</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>:root{{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--accent:#17658f;--sun:#d69b31}}*{{box-sizing:border-box}}body{{min-height:100vh;margin:0;display:grid;place-items:center;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%)}}main{{width:min(440px,calc(100% - 40px));padding:30px;border:1px solid rgba(211,225,233,.88);border-radius:8px;background:rgba(255,255,255,.88);box-shadow:0 18px 42px rgba(45,75,95,.10);text-align:center}}.mark{{display:grid;place-items:center;width:44px;height:44px;margin:0 auto 16px;border:1px solid #f0d49f;border-radius:50%;background:#fff9ef;color:#b87808;font-size:22px}}h1{{margin:0 0 8px;font-family:Georgia,"Times New Roman",serif;font-size:28px;font-weight:500;color:#12304b}}p{{margin:0 0 22px;color:var(--muted)}}a{{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 17px;border-radius:7px;background:var(--accent);color:white;text-decoration:none;font-weight:650}}a:focus-visible{{outline:3px solid rgba(23,101,143,.28);outline-offset:3px}}</style></head><body><main data-auth-recovery><span class="mark" aria-hidden="true">↻</span><h1>Start sign-in again</h1><p>{}</p><a href="{}">Try signing in again</a></main></body></html>"#,
        recovery.message(),
        login,
    );
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        set_cookie(FLOW_COOKIE, "", 0, true, "Lax")
            .parse()
            .expect("flow cookie clearing header"),
    );
    (recovery.status(), headers, Html(html)).into_response()
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
        Some(_) => {
            let return_to = if matches!(*req.method(), Method::GET | Method::HEAD) {
                validated_return_to(req.uri().path_and_query().map(|value| value.as_str()))
            } else {
                "/".to_string()
            };
            Redirect::to(&login_location(&return_to)).into_response()
        }
    }
}

#[derive(Default, serde::Deserialize)]
pub struct LoginParams {
    return_to: Option<String>,
}

/// `GET /auth/login` — start the PKCE flow, redirect to the IdP.
pub async fn login(State(auth): State<AuthState>, Query(params): Query<LoginParams>) -> Response {
    let return_to = validated_return_to(params.return_to.as_deref());
    let Some(auth) = auth else {
        return Redirect::to(&return_to).into_response();
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
    let flow_cookie = new_flow_cookie(&return_to);
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
            return_to,
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
    error: Option<String>,
}

/// `GET /auth/callback` — verify state, exchange the code (with the PKCE
/// verifier), validate the ID token, and start a session.
pub async fn callback(
    State(auth): State<AuthState>,
    headers: HeaderMap,
    Query(p): Query<CallbackParams>,
) -> Response {
    let Some(auth) = auth else {
        return Redirect::to("/").into_response();
    };
    let flow_cookie = cookie(&headers, FLOW_COOKIE);
    let cookie_return_to = return_to_from_flow_cookie(flow_cookie.as_deref());
    let Some(state) = p.state else {
        tracing::info!(
            category = "missing_state",
            "OIDC callback requires a fresh login"
        );
        return login_recovery_response(LoginRecovery::FlowUnavailable, &cookie_return_to);
    };
    let flow_cookie_hash = flow_cookie.as_deref().map(secret_hash);
    let pending = match auth.take_pending(&state, flow_cookie_hash.as_ref(), now()) {
        PendingFlowOutcome::Matched(pending) => pending,
        PendingFlowOutcome::Missing => {
            tracing::info!(
                category = "unknown_or_replayed_state",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(LoginRecovery::FlowUnavailable, &cookie_return_to);
        }
        PendingFlowOutcome::Expired(return_to) => {
            tracing::info!(
                category = "expired_state",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(LoginRecovery::FlowUnavailable, &return_to);
        }
        PendingFlowOutcome::BrowserMismatch(return_to) => {
            tracing::info!(
                category = "superseded_or_wrong_browser",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(LoginRecovery::FlowUnavailable, &return_to);
        }
    };
    let return_to = pending.return_to.clone();
    if p.error.is_some() {
        tracing::warn!(
            category = "authorization_provider_rejection",
            "OIDC provider rejected the authorization request"
        );
        return login_recovery_response(LoginRecovery::ProviderRejected, &return_to);
    }
    let Some(code) = p.code else {
        tracing::warn!(
            category = "authorization_response_malformed",
            "OIDC provider response omitted the authorization code"
        );
        return login_recovery_response(LoginRecovery::MalformedProviderResponse, &return_to);
    };

    let client = auth.client();
    let token_request = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(request) => request,
        Err(_) => {
            tracing::warn!(
                category = "token_endpoint_unavailable",
                "OIDC token exchange could not be started"
            );
            return login_recovery_response(LoginRecovery::ProviderUnavailable, &return_to);
        }
    };
    let token = match token_request
        .set_pkce_verifier(pending.verifier)
        .request_async(&auth.http_client)
        .await
    {
        Ok(t) => t,
        Err(error) => {
            let (recovery, source) = classify_token_exchange_error(&error);
            tracing::warn!(
                category = "token_exchange_failed",
                source,
                "OIDC token exchange failed safely"
            );
            return login_recovery_response(recovery, &return_to);
        }
    };
    let Some(id_token) = token.id_token() else {
        tracing::warn!(
            category = "token_response_missing_id_token",
            "OIDC token response was malformed"
        );
        return login_recovery_response(LoginRecovery::MalformedProviderResponse, &return_to);
    };
    let mut identity = match auth.verify_id_token_identity(&client, id_token, &pending.nonce) {
        Ok(identity) => identity,
        Err(ClaimsVerificationError::SignatureVerification(_)) => {
            tracing::warn!(
                category = "signature_metadata_stale",
                "OIDC id_token signature requires a metadata refresh"
            );
            if let Err(source) = auth.refresh_client().await {
                tracing::warn!(
                    category = "metadata_refresh_failed",
                    source = source.as_str(),
                    "OIDC metadata refresh failed safely"
                );
                return login_recovery_response(LoginRecovery::ProviderUnavailable, &return_to);
            }
            let refreshed = auth.client();
            match auth.verify_id_token_identity(&refreshed, id_token, &pending.nonce) {
                Ok(identity) => {
                    tracing::info!("id_token verified after OIDC metadata refresh");
                    identity
                }
                Err(_) => {
                    tracing::warn!(
                        category = "id_token_verification_failed_after_refresh",
                        "OIDC id_token verification failed safely"
                    );
                    return login_recovery_response(LoginRecovery::VerificationFailed, &return_to);
                }
            }
        }
        Err(_) => {
            tracing::warn!(
                category = "id_token_verification_failed",
                "OIDC id_token verification failed safely"
            );
            return login_recovery_response(LoginRecovery::VerificationFailed, &return_to);
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
    (headers, Redirect::to(&return_to)).into_response()
}

/// `GET /auth/recover` — stable recovery surface for stale browser auth state.
pub async fn recover(Query(params): Query<LoginParams>) -> Response {
    let return_to = validated_return_to(params.return_to.as_deref());
    login_recovery_response(LoginRecovery::FlowUnavailable, &return_to)
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
    (out, Redirect::to("/auth/logged-out")).into_response()
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
    use axum::{middleware, Json, Router};
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
        token_mode: Arc<Mutex<MockTokenMode>>,
    }

    #[derive(Clone, Copy, Default)]
    enum MockTokenMode {
        #[default]
        Success,
        ProviderReject,
        Malformed,
        MissingIdToken,
        InvalidIdToken,
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

    fn mock_id_token_with_nonce(provider: &MockOidcProvider, nonce: String) -> String {
        let header = serde_json::json!({
            "alg": "RS256",
            "kid": "pharos-oidc-e2e",
            "typ": "JWT"
        });
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

    fn mock_id_token(provider: &MockOidcProvider) -> String {
        let nonce = provider
            .nonce
            .lock()
            .expect("mock nonce lock")
            .clone()
            .expect("login nonce captured");
        mock_id_token_with_nonce(provider, nonce)
    }

    async fn mock_token(State(provider): State<MockOidcProvider>) -> Response {
        let mode = *provider.token_mode.lock().expect("mock token mode lock");
        match mode {
            MockTokenMode::Success => Json(serde_json::json!({
                "access_token": "opaque-test-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": mock_id_token(&provider)
            }))
            .into_response(),
            MockTokenMode::ProviderReject => (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({
                    "error": "invalid_grant",
                    "error_description": "fixture rejection"
                })),
            )
                .into_response(),
            MockTokenMode::Malformed => (StatusCode::OK, "not a token response").into_response(),
            MockTokenMode::MissingIdToken => Json(serde_json::json!({
                "access_token": "opaque-test-access-token",
                "token_type": "Bearer",
                "expires_in": 300
            }))
            .into_response(),
            MockTokenMode::InvalidIdToken => Json(serde_json::json!({
                "access_token": "opaque-test-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": mock_id_token_with_nonce(&provider, "wrong-nonce".to_string())
            }))
            .into_response(),
        }
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
            token_mode: Arc::new(Mutex::new(MockTokenMode::Success)),
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

    async fn auth_for_provider(provider: &MockOidcProvider) -> AuthState {
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
        Auth::from_config(config).await.unwrap()
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

    fn login_params(return_to: Option<&str>) -> Query<LoginParams> {
        Query(LoginParams {
            return_to: return_to.map(ToString::to_string),
        })
    }

    fn callback_params(
        code: Option<&str>,
        state: Option<String>,
        error: Option<&str>,
    ) -> Query<CallbackParams> {
        Query(CallbackParams {
            code: code.map(ToString::to_string),
            state,
            error: error.map(ToString::to_string),
        })
    }

    fn authorization_parameters(
        response: &Response,
        provider: &MockOidcProvider,
    ) -> HashMap<String, String> {
        let authorization_url = Url::parse(
            response
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
        *provider.nonce.lock().unwrap() = parameters.get("nonce").cloned();
        parameters
    }

    async fn response_html(response: Response) -> String {
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("response body");
        String::from_utf8(body.to_vec()).expect("response html")
    }

    async fn begin_login(
        auth_state: &AuthState,
        provider: &MockOidcProvider,
        return_to: &str,
    ) -> (String, String) {
        let response = login(State(auth_state.clone()), login_params(Some(return_to))).await;
        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        let parameters = authorization_parameters(&response, provider);
        (
            parameters.get("state").cloned().unwrap(),
            response_cookie(&response, FLOW_COOKIE).unwrap(),
        )
    }

    #[tokio::test]
    async fn oidc_authorization_code_pkce_flow_creates_a_browser_bound_session() {
        let (provider, server) = start_mock_oidc().await;
        let auth_state = auth_for_provider(&provider).await;

        let login_response = login(
            State(auth_state.clone()),
            login_params(Some("/services?view=managed")),
        )
        .await;
        assert_eq!(login_response.status(), StatusCode::TEMPORARY_REDIRECT);
        let parameters = authorization_parameters(&login_response, &provider);
        let state = parameters.get("state").cloned().unwrap();
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
            callback_params(Some("single-use-code"), Some(state), None),
        )
        .await;

        assert_eq!(callback_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            callback_response.headers().get(header::LOCATION).unwrap(),
            "/services?view=managed"
        );
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

        let logout_csrf_cookie = response_cookie(&callback_response, LOGOUT_CSRF_COOKIE).unwrap();
        let logout_csrf = logout_csrf_cookie
            .split_once('=')
            .map(|(_, value)| value)
            .unwrap();
        let mut logout_headers = HeaderMap::new();
        logout_headers.insert(
            header::COOKIE,
            format!("{session_cookie}; {logout_csrf_cookie}")
                .parse()
                .unwrap(),
        );
        let rejected_logout = logout(
            State(auth_state.clone()),
            logout_headers.clone(),
            Form(LogoutForm {
                csrf: "wrong".to_string(),
            }),
        )
        .await;
        assert_eq!(rejected_logout.status(), StatusCode::FORBIDDEN);
        assert!(auth_state
            .as_ref()
            .unwrap()
            .current_user(&session_headers)
            .is_some());

        let logout_response = logout(
            State(auth_state.clone()),
            logout_headers,
            Form(LogoutForm {
                csrf: logout_csrf.to_string(),
            }),
        )
        .await;
        assert_eq!(logout_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            logout_response.headers().get(header::LOCATION).unwrap(),
            "/auth/logged-out"
        );
        assert_eq!(
            logout_response
                .headers()
                .get_all(header::SET_COOKIE)
                .iter()
                .count(),
            2
        );
        assert!(auth_state
            .as_ref()
            .unwrap()
            .current_user(&session_headers)
            .is_none());

        server.abort();
        let _ = server.await;
    }

    fn pending_flow(flow_cookie: &str, created: i64) -> Pending {
        let (_, verifier) = PkceCodeChallenge::new_random_sha256();
        Pending {
            verifier,
            nonce: Nonce::new("nonce-fixture".to_string()),
            flow_cookie_hash: secret_hash(flow_cookie),
            return_to: "/services".to_string(),
            created,
        }
    }

    #[test]
    fn pending_flow_is_browser_bound_expiring_single_use_and_deterministically_superseded() {
        let pending = Mutex::new(HashMap::from([(
            "state-fixture".to_string(),
            pending_flow("browser-a", 100),
        )]));

        let browser_b_hash = secret_hash("browser-b");
        assert!(matches!(
            take_pending_flow(&pending, "state-fixture", Some(&browser_b_hash), 101),
            PendingFlowOutcome::BrowserMismatch(return_to) if return_to == "/services"
        ));
        assert!(
            pending.lock().unwrap().is_empty(),
            "superseded flow is consumed into recovery"
        );

        pending
            .lock()
            .unwrap()
            .insert("matched".to_string(), pending_flow("browser-a", 100));
        let browser_a_hash = secret_hash("browser-a");
        assert!(matches!(
            take_pending_flow(&pending, "matched", Some(&browser_a_hash), 101),
            PendingFlowOutcome::Matched(_)
        ));
        assert!(matches!(
            take_pending_flow(&pending, "matched", Some(&browser_a_hash), 101),
            PendingFlowOutcome::Missing
        ));

        pending
            .lock()
            .unwrap()
            .insert("expired".to_string(), pending_flow("browser-a", 100));
        assert!(matches!(
            take_pending_flow(
                &pending,
                "expired",
                Some(&browser_a_hash),
                100 + FLOW_TTL_SECS
            ),
            PendingFlowOutcome::Expired(return_to) if return_to == "/services"
        ));
        assert!(
            pending.lock().unwrap().is_empty(),
            "expired flow is removed"
        );
    }

    #[test]
    fn return_destinations_are_local_bounded_and_never_reenter_auth() {
        assert_eq!(
            validated_return_to(Some("/services?view=managed")),
            "/services?view=managed"
        );
        for unsafe_target in [
            "https://attacker.invalid/",
            "//attacker.invalid/",
            "/\\attacker.invalid/",
            "/auth/login",
            "/auth/callback?code=fixture",
            "/auth/recover",
            "services",
            "/fleet#fragment",
        ] {
            assert_eq!(validated_return_to(Some(unsafe_target)), "/");
        }
        assert_eq!(
            validated_return_to(Some(&format!("/{}", "a".repeat(MAX_RETURN_TO_BYTES)))),
            "/"
        );
        assert_eq!(
            login_location("/services?view=managed"),
            "/auth/login?return_to=%2Fservices%3Fview%3Dmanaged"
        );
        let flow_cookie = new_flow_cookie("/services?view=managed");
        assert_eq!(
            return_to_from_flow_cookie(Some(&flow_cookie)),
            "/services?view=managed"
        );
        assert_eq!(return_to_from_flow_cookie(Some("tampered")), "/");
        assert_eq!(return_to_from_flow_cookie(Some("fixture.%%%")), "/");
    }

    #[test]
    fn transport_failures_have_only_fixed_value_free_classes() {
        assert_eq!(
            classify_transport_signals(false, true, "dns error while resolving a private host"),
            OidcTransportClass::Dns
        );
        assert_eq!(
            classify_transport_signals(false, true, "certificate verify failed"),
            OidcTransportClass::Tls
        );
        assert_eq!(
            classify_transport_signals(true, true, "request timed out"),
            OidcTransportClass::Timeout
        );
        assert_eq!(
            classify_transport_signals(false, true, "connection refused"),
            OidcTransportClass::Connection
        );
        assert_eq!(
            classify_transport_signals(false, false, "opaque internal failure"),
            OidcTransportClass::Request
        );
        assert_eq!(
            [
                OidcTransportClass::Dns,
                OidcTransportClass::Connection,
                OidcTransportClass::Tls,
                OidcTransportClass::Timeout,
                OidcTransportClass::Request,
            ]
            .map(OidcTransportClass::as_str),
            ["dns", "connection", "tls", "timeout", "request"]
        );
    }

    #[tokio::test]
    async fn stale_missing_and_replayed_callbacks_render_one_safe_recovery_action() {
        let (provider, server) = start_mock_oidc().await;
        let auth_state = auth_for_provider(&provider).await;

        let missing_state = callback(
            State(auth_state.clone()),
            HeaderMap::new(),
            callback_params(Some("unused"), None, None),
        )
        .await;
        assert_eq!(missing_state.status(), StatusCode::BAD_REQUEST);
        assert!(response_cookie(&missing_state, FLOW_COOKIE)
            .unwrap()
            .ends_with('='));
        let missing_html = response_html(missing_state).await;
        assert!(missing_html.contains("data-auth-recovery"));
        assert_eq!(missing_html.matches("<a href=").count(), 1);
        assert!(missing_html.contains(r#"href="/auth/login""#));
        assert!(!missing_html.contains("unknown or expired login"));

        let (state, flow_cookie) = begin_login(&auth_state, &provider, "/services").await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        let accepted = callback(
            State(auth_state.clone()),
            headers.clone(),
            callback_params(Some("single-use"), Some(state.clone()), None),
        )
        .await;
        assert_eq!(accepted.status(), StatusCode::SEE_OTHER);

        let replay = callback(
            State(auth_state.clone()),
            headers,
            callback_params(Some("single-use"), Some(state), None),
        )
        .await;
        assert_eq!(replay.status(), StatusCode::BAD_REQUEST);
        assert!(response_html(replay).await.contains("Start sign-in again"));

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn concurrent_tabs_supersede_deterministically_without_breaking_the_newer_flow() {
        let (provider, server) = start_mock_oidc().await;
        let auth_state = auth_for_provider(&provider).await;
        let (older_state, _older_cookie) = begin_login(&auth_state, &provider, "/services").await;
        let (newer_state, newer_cookie) = begin_login(&auth_state, &provider, "/backups").await;

        let mut newer_headers = HeaderMap::new();
        newer_headers.insert(header::COOKIE, newer_cookie.parse().unwrap());
        let superseded = callback(
            State(auth_state.clone()),
            newer_headers.clone(),
            callback_params(Some("older-code"), Some(older_state), None),
        )
        .await;
        assert_eq!(superseded.status(), StatusCode::BAD_REQUEST);
        let superseded_html = response_html(superseded).await;
        assert!(superseded_html.contains(r#"href="/auth/login?return_to=%2Fservices""#));

        let newer = callback(
            State(auth_state.clone()),
            newer_headers,
            callback_params(Some("newer-code"), Some(newer_state), None),
        )
        .await;
        assert_eq!(newer.status(), StatusCode::SEE_OTHER);
        assert_eq!(newer.headers().get(header::LOCATION).unwrap(), "/backups");

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn restart_during_login_recovers_instead_of_dead_ending() {
        let (provider, server) = start_mock_oidc().await;
        let before_restart = auth_for_provider(&provider).await;
        let (state, flow_cookie) = begin_login(&before_restart, &provider, "/settings").await;
        let after_restart = auth_for_provider(&provider).await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());

        let response = callback(
            State(after_restart),
            headers,
            callback_params(Some("unused-after-restart"), Some(state), None),
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let html = response_html(response).await;
        assert!(html.contains("Pharos may have restarted"));
        assert!(html.contains(r#"href="/auth/login?return_to=%2Fsettings""#));

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn missing_session_uses_get_recovery_without_replaying_post_routes() {
        let (provider, oidc_server) = start_mock_oidc().await;
        let auth_state = auth_for_provider(&provider).await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route(
                "/services",
                get(|| async { "services" }).post(|| async { "changed" }),
            )
            .route_layer(middleware::from_fn_with_state(auth_state, guard));
        let app_server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::ClientBuilder::new()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();

        let get_response = client
            .get(format!("http://{address}/services?view=managed"))
            .send()
            .await
            .unwrap();
        assert_eq!(get_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            get_response.headers().get(header::LOCATION).unwrap(),
            "/auth/login?return_to=%2Fservices%3Fview%3Dmanaged"
        );

        let post_response = client
            .post(format!("http://{address}/services"))
            .send()
            .await
            .unwrap();
        assert_eq!(post_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            post_response.headers().get(header::LOCATION).unwrap(),
            "/auth/login"
        );

        app_server.abort();
        let _ = app_server.await;
        oidc_server.abort();
        let _ = oidc_server.await;
    }

    #[tokio::test]
    async fn provider_failures_are_classified_and_keep_a_one_click_recovery_path() {
        let (provider, server) = start_mock_oidc().await;
        let auth_state = auth_for_provider(&provider).await;

        for (mode, expected_status, expected_copy) in [
            (
                MockTokenMode::ProviderReject,
                StatusCode::UNAUTHORIZED,
                "identity provider did not accept",
            ),
            (
                MockTokenMode::Malformed,
                StatusCode::BAD_GATEWAY,
                "unexpected response",
            ),
            (
                MockTokenMode::MissingIdToken,
                StatusCode::BAD_GATEWAY,
                "unexpected response",
            ),
            (
                MockTokenMode::InvalidIdToken,
                StatusCode::UNAUTHORIZED,
                "could not verify",
            ),
        ] {
            *provider.token_mode.lock().unwrap() = mode;
            let (state, flow_cookie) =
                begin_login(&auth_state, &provider, "/settings/providers").await;
            let mut headers = HeaderMap::new();
            headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
            let response = callback(
                State(auth_state.clone()),
                headers,
                callback_params(Some("fixture-code"), Some(state), None),
            )
            .await;
            assert_eq!(response.status(), expected_status);
            let html = response_html(response).await;
            assert!(html.contains(expected_copy));
            assert!(html.contains(r#"href="/auth/login?return_to=%2Fsettings%2Fproviders""#));
            assert_eq!(html.matches("<a href=").count(), 1);
        }

        *provider.token_mode.lock().unwrap() = MockTokenMode::Success;
        let (state, flow_cookie) = begin_login(&auth_state, &provider, "/").await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        let authorization_rejection = callback(
            State(auth_state.clone()),
            headers,
            callback_params(None, Some(state), Some("access_denied")),
        )
        .await;
        assert_eq!(authorization_rejection.status(), StatusCode::UNAUTHORIZED);

        let (state, flow_cookie) = begin_login(&auth_state, &provider, "/").await;
        server.abort();
        let _ = server.await;
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        let transport_failure = callback(
            State(auth_state),
            headers,
            callback_params(Some("fixture-code"), Some(state), None),
        )
        .await;
        assert_eq!(transport_failure.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(response_html(transport_failure)
            .await
            .contains("could not reach the identity provider"));
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
        let missing = logout(
            State(None),
            HeaderMap::new(),
            Form(LogoutForm {
                csrf: "csrf-fixture".to_string(),
            }),
        )
        .await;
        assert_eq!(missing.status(), StatusCode::FORBIDDEN);

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
        assert_eq!(accepted.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            accepted.headers().get(header::LOCATION).unwrap(),
            "/auth/logged-out"
        );
        let cleared = accepted.headers().get_all(header::SET_COOKIE);
        assert_eq!(cleared.iter().count(), 2);
    }

    #[tokio::test]
    async fn logout_form_redirects_to_the_get_only_landing_page() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/auth/logout", post(logout))
            .route("/auth/logged-out", get(logged_out))
            .with_state(None::<Arc<Auth>>);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let response = reqwest::Client::new()
            .post(format!("http://{address}/auth/logout"))
            .header(
                reqwest::header::COOKIE,
                format!("{LOGOUT_CSRF_COOKIE}=csrf-fixture"),
            )
            .form(&[("csrf", "csrf-fixture")])
            .send()
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.url().path(), "/auth/logged-out");
        assert!(response
            .text()
            .await
            .unwrap()
            .contains("<h1>Logged out</h1>"));

        server.abort();
        let _ = server.await;
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
    fn managed_human_session_binding_matches_janus_and_normalizes_issuer_slash() {
        let expected = "hsn_9faf4f59563351db0902dcb553e34717e3d37497b11422efcbd54d9b367c415a";
        assert_eq!(
            managed_human_session_ref("https://issuer.example.test", "subject-1"),
            expected
        );
        assert_eq!(
            managed_human_session_ref("https://issuer.example.test/", "subject-1"),
            expected
        );
        assert_ne!(
            managed_human_session_ref("https://issuer.example.test", "subject-2"),
            expected
        );
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
