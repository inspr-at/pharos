//! OIDC (Authorization Code + PKCE) auth against Zitadel (PHAROS-4).
//!
//! Startup is fail closed: the OIDC variables are all-or-nothing. Open human
//! routes require an explicit `PHAROS_ALLOW_OPEN=true` opt-in and a loopback
//! listener, so a partial or drifted production configuration cannot silently
//! disable authentication.
//!
//! Public client (PKCE, no client secret). Every page needs a browser session,
//! and the data routes take that session or the one read-only operator token.
//! Machine routes (`POST /register`, `POST /report`) use the PHAROS-8 beacon token
//! flow instead of browser login, while `/healthz` and `/version` stay open.
//!
//! Sessions and in-flight logins are in-memory (single-instance pharosd). A
//! restart drops them — the dashboard reloads from disk, the user just logs in
//! again.

use std::collections::HashMap;
use std::error::Error as StdError;
use std::io::Read;
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

use pharos_core::PublicBasePath;

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
const OPERATOR_TOKEN_HASH_FILE_ENV: &str = "PHAROS_OPERATOR_TOKEN_HASH_FILE";
const MAX_OPERATOR_TOKEN_HASH_FILE_BYTES: u64 = 128;
/// A session cookie outlives its session, so a browser coming back can be told
/// that it ended instead of being asked to sign in as if for the first time.
const ENDED_SESSION_COOKIE_SECS: i64 = 30 * 24 * 3600;
const OIDC_CA_FILE_ENV: &str = "PHAROS_OIDC_CA_FILE";
const MAX_OIDC_CA_FILE_BYTES: u64 = 256 * 1024;
const MAX_OIDC_CA_CERTIFICATES: usize = 32;
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

#[derive(Clone, Debug)]
pub struct AuthUser {
    pub display_name: String,
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
    expires: i64,
}

pub struct Auth {
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect: RedirectUrl,
    http_client: reqwest::Client,
    client: Mutex<OidcClient>,
    operator_policy: OperatorPolicy,
    pending: Mutex<HashMap<String, Pending>>,
    sessions: Mutex<HashMap<String, Session>>,
    login_rate: Mutex<RateWindow>,
    session_rate: Mutex<RateWindow>,
}

/// Human OIDC login state.
#[derive(Clone, Default)]
pub struct AuthState {
    human: Option<Arc<Auth>>,
    pub(crate) public_base_path: pharos_core::PublicBasePath,
    /// SHA-256 of the one operator token. It reads data and nothing else.
    operator_token_hash: Option<[u8; 32]>,
}

/// Fully validated human-authentication startup configuration.
pub(crate) struct AuthConfig {
    mode: AuthConfigMode,
    operator_token_hash: Option<[u8; 32]>,
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
    oidc_ca_file: Option<PathBuf>,
}

impl AuthConfig {
    pub fn from_env(
        listener_is_loopback: bool,
        public_base_path: &pharos_core::PublicBasePath,
        public_origin: Option<&pharos_core::PublicOrigin>,
    ) -> Result<Self, String> {
        let issuer = env_nonempty("PHAROS_OIDC_ISSUER");
        let client_id = env_nonempty("PHAROS_OIDC_CLIENT_ID");
        let redirect = env_nonempty("PHAROS_OIDC_REDIRECT_URI");
        let oidc_ca_file = env_nonempty(OIDC_CA_FILE_ENV).map(PathBuf::from);
        let allow_open = env_bool(ALLOW_OPEN_ENV)?.unwrap_or(false);
        let operator_policy = OperatorPolicy::from_env()?;
        let mut config = Self::from_values(
            listener_is_loopback,
            issuer,
            client_id,
            redirect,
            allow_open,
            operator_policy,
        )?;
        config.operator_token_hash = env_nonempty(OPERATOR_TOKEN_HASH_FILE_ENV)
            .map(|path| load_operator_token_hash(std::path::Path::new(&path)))
            .transpose()
            .map_err(|error| format!("{OPERATOR_TOKEN_HASH_FILE_ENV}: {error}"))?;
        match (&config.mode, oidc_ca_file.as_ref()) {
            (AuthConfigMode::Oidc(oidc), _) => {
                crate::public_mount::validate_oidc_redirect_uri(
                    oidc.redirect.as_str(),
                    public_base_path,
                    public_origin,
                )?;
            }
            (AuthConfigMode::Open, Some(_)) => {
                return Err(format!("{OIDC_CA_FILE_ENV} requires OIDC configuration"));
            }
            (AuthConfigMode::Open, None) => {}
        }
        if let AuthConfigMode::Oidc(oidc) = &mut config.mode {
            oidc.oidc_ca_file = oidc_ca_file;
        }
        Ok(config)
    }

    fn from_values(
        listener_is_loopback: bool,
        issuer: Option<String>,
        client_id: Option<String>,
        redirect: Option<String>,
        allow_open: bool,
        operator_policy: OperatorPolicy,
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
                operator_token_hash: None,
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
        if !listener_is_loopback && !operator_policy.is_enforced() {
            return Err(format!(
                "OIDC on a non-loopback listener requires {ALLOWED_OPERATORS_ENV}"
            ));
        }

        Ok(Self {
            mode: AuthConfigMode::Oidc(Box::new(OidcAuthConfig {
                issuer,
                client_id,
                redirect,
                operator_policy,
                oidc_ca_file: None,
            })),
            operator_token_hash: None,
        })
    }
}

/// The file holds the token's SHA-256 as 64 lowercase hex digits and nothing else.
/// Pharos never sees the token until someone presents it.
fn load_operator_token_hash(path: &std::path::Path) -> Result<[u8; 32], String> {
    let bytes = crate::probe_support::read_trusted_runtime_file(
        path,
        MAX_OPERATOR_TOKEN_HASH_FILE_BYTES,
        0o022,
        false,
    )
    .ok_or_else(|| {
        "must be a regular file owned by root or this user, not writable by group or others"
            .to_string()
    })?;
    let text = std::str::from_utf8(&bytes).map_err(|_| "is not text".to_string())?;
    let hex = text.strip_suffix('\n').unwrap_or(text);
    let digest_error = || "must hold one SHA-256 as 64 lowercase hex digits".to_string();
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(digest_error());
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte =
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| digest_error())?;
    }
    Ok(digest)
}

fn load_oidc_ca_certificates(path: &std::path::Path) -> Result<Vec<reqwest::Certificate>, String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .map_err(|_| "CA file is unavailable".to_string())?;
    let metadata = file
        .metadata()
        .map_err(|_| "CA file metadata is unavailable".to_string())?;
    if !metadata.is_file() || metadata.len() == 0 {
        return Err("CA file is not a regular file".to_string());
    }
    if metadata.len() > MAX_OIDC_CA_FILE_BYTES {
        return Err("CA file is too large".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.nlink() != 1 {
            return Err("CA file must have one link".to_string());
        }
        // A CA bundle is public material, so root-owned read-only mounts are
        // valid for an unprivileged pharosd process. Never accept a writable
        // group/other file or a file owned by an unrelated unprivileged user.
        let uid = metadata.uid();
        let effective_uid = unsafe { libc::geteuid() };
        if (uid != 0 && uid != effective_uid) || metadata.permissions().mode() & 0o022 != 0 {
            return Err("CA file custody is unsafe".to_string());
        }
    }
    let mut bytes = Vec::new();
    file.take(MAX_OIDC_CA_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "CA file is unreadable".to_string())?;
    if bytes.len() as u64 != metadata.len() {
        bytes.fill(0);
        return Err("CA file changed while reading".to_string());
    }
    let result = parse_oidc_ca_certificates(&bytes);
    bytes.fill(0);
    result
}

fn parse_oidc_ca_certificates(bytes: &[u8]) -> Result<Vec<reqwest::Certificate>, String> {
    const BEGIN: &str = "-----BEGIN CERTIFICATE-----";
    const END: &str = "-----END CERTIFICATE-----";
    let text = std::str::from_utf8(bytes).map_err(|_| "CA file is not PEM".to_string())?;
    if !text.is_ascii() {
        return Err("CA file is not ASCII PEM".to_string());
    }
    let mut in_certificate = false;
    let mut payload_line_seen = false;
    let mut block_count = 0usize;
    for line in text.lines() {
        if !in_certificate {
            if line.is_empty() {
                continue;
            }
            if line != BEGIN {
                return Err("CA file contains non-certificate material".to_string());
            }
            in_certificate = true;
            payload_line_seen = false;
            continue;
        }
        if line == END {
            if !payload_line_seen {
                return Err("CA certificate is empty".to_string());
            }
            block_count += 1;
            if block_count > MAX_OIDC_CA_CERTIFICATES {
                return Err("CA file contains too many certificates".to_string());
            }
            in_certificate = false;
            continue;
        }
        if line.is_empty()
            || line.len() > 76
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err("CA certificate PEM is malformed".to_string());
        }
        payload_line_seen = true;
    }
    if in_certificate || block_count == 0 {
        return Err("CA file contains no complete certificate".to_string());
    }
    let certificates = reqwest::Certificate::from_pem_bundle(bytes)
        .map_err(|_| "CA certificate PEM is invalid".to_string())?;
    if certificates.len() != block_count {
        return Err("CA certificate count is inconsistent".to_string());
    }
    Ok(certificates)
}

fn build_oidc_http_client(
    oidc_ca_file: Option<&std::path::Path>,
) -> Result<reqwest::Client, String> {
    let oidc_ca_certificates = oidc_ca_file
        .map(load_oidc_ca_certificates)
        .transpose()
        .map_err(|error| format!("OIDC CA configuration failed: {error}"))?
        .unwrap_or_default();
    let mut builder = reqwest::ClientBuilder::new()
        // OIDC provider traffic must never use cleartext HTTP.
        .https_only(true)
        // OIDC 4 requires a stateful client; redirects must stay disabled
        // to avoid SSRF through provider-controlled endpoints.
        .redirect(reqwest::redirect::Policy::none());
    for certificate in oidc_ca_certificates {
        builder = builder.add_root_certificate(certificate);
    }
    builder
        .build()
        .map_err(|err| format!("OIDC HTTP client could not be built: {err}"))
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
    pub(crate) async fn from_config(
        config: AuthConfig,
        public_base_path: pharos_core::PublicBasePath,
    ) -> Result<AuthState, String> {
        let operator_token_hash = config.operator_token_hash;
        if operator_token_hash.is_some() {
            tracing::info!("read-only operator token enabled");
        }
        let AuthConfigMode::Oidc(config) = config.mode else {
            tracing::warn!("human routes are open on an explicitly allowed loopback listener");
            return Ok(AuthState {
                human: None,
                public_base_path,
                operator_token_hash,
            });
        };
        let OidcAuthConfig {
            issuer: issuer_url,
            client_id,
            redirect,
            operator_policy,
            oidc_ca_file,
        } = *config;
        let http_client = build_oidc_http_client(oidc_ca_file.as_deref())?;
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
        if !operator_policy.is_enforced() {
            tracing::warn!(
                "OIDC authorization policy is absent on a loopback listener; all authenticated users are allowed"
            );
        }
        Ok(AuthState {
            human: Some(Arc::new(Auth {
                issuer: issuer_url,
                client_id,
                redirect,
                http_client,
                client: Mutex::new(client),
                operator_policy,
                pending: Mutex::new(HashMap::new()),
                sessions: Mutex::new(HashMap::new()),
                login_rate: Mutex::new(RateWindow::default()),
                session_rate: Mutex::new(RateWindow::default()),
            })),
            public_base_path,
            operator_token_hash,
        })
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
            .map(|session| AuthUser {
                display_name: session.display_name.clone(),
            })
    }
}

impl AuthState {
    #[cfg(test)]
    pub(crate) fn for_test_operator_token(token: &str) -> Self {
        Self {
            operator_token_hash: Some(secret_hash(token)),
            ..Self::default()
        }
    }

    fn operator_token_matches(&self, headers: &HeaderMap) -> bool {
        let Some(expected) = &self.operator_token_hash else {
            return false;
        };
        crate::bearer_token(headers)
            .is_some_and(|token| constant_time_equal(&secret_hash(token), expected))
    }

    fn human(&self) -> Option<&Arc<Auth>> {
        self.human.as_ref()
    }

    pub(crate) fn human_user(&self, headers: &HeaderMap) -> Option<AuthUser> {
        if headers.contains_key(header::AUTHORIZATION) {
            return None;
        }
        self.human
            .as_ref()
            .and_then(|auth| auth.current_user(headers))
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

    /// Startup refuses a non-loopback listener without a list, so only a loopback
    /// development instance ever lets everyone through here.
    fn allows(&self, identifiers: &[String]) -> bool {
        !self.is_enforced()
            || identifiers
                .iter()
                .any(|identifier| self.allowed.contains(identifier))
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

fn return_to_from_flow_cookie(value: Option<&str>, public_base_path: &PublicBasePath) -> String {
    let Some((_, encoded_return)) = value.and_then(|value| value.split_once('.')) else {
        return public_base_path.home().to_string();
    };
    let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded_return) else {
        return public_base_path.home().to_string();
    };
    let Ok(return_to) = String::from_utf8(decoded) else {
        return public_base_path.home().to_string();
    };
    validated_return_to(public_base_path, Some(&return_to))
}

fn validated_return_to(public_base_path: &PublicBasePath, candidate: Option<&str>) -> String {
    let home = public_base_path.home().to_string();
    let Some(candidate) = candidate else {
        return home;
    };
    if candidate.is_empty()
        || candidate.len() > MAX_RETURN_TO_BYTES
        || !candidate.starts_with('/')
        || candidate.starts_with("//")
        || candidate.contains('\\')
        || candidate.contains('#')
        || candidate.chars().any(char::is_control)
    {
        return home;
    }
    let Ok(uri) = candidate.parse::<Uri>() else {
        return home;
    };
    if uri.scheme().is_some() || uri.authority().is_some() {
        return home;
    }
    let path = uri.path();
    let local = public_base_path
        .strip(path)
        .unwrap_or_else(|| path.to_string());
    if local == "/auth" || local.starts_with("/auth/") {
        return home;
    }
    let Ok(joined) = public_base_path.join(&local) else {
        return home;
    };
    match uri.query() {
        Some(query)
            if query.split('&').any(|part| {
                let value = part.split_once('=').map(|(_, value)| value).unwrap_or("");
                value.contains("://") || value.starts_with("//")
            }) =>
        {
            home
        }
        Some(query) => format!("{joined}?{query}"),
        None => joined,
    }
}

fn sign_in_location(public_base_path: &PublicBasePath, return_to: &str, ended: bool) -> String {
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    if return_to != public_base_path.home() {
        query.append_pair("return_to", return_to);
    }
    if ended {
        query.append_pair("ended", "1");
    }
    let page = public_base_path.href("/auth/sign-in");
    match query.finish() {
        query if query.is_empty() => page,
        query => format!("{page}?{query}"),
    }
}

fn login_location(public_base_path: &PublicBasePath, return_to: &str) -> String {
    let login = public_base_path.href("/auth/login");
    if return_to == public_base_path.home() {
        return login;
    }
    let mut query = url::form_urlencoded::Serializer::new(String::new());
    query.append_pair("return_to", return_to);
    format!("{login}?{}", query.finish())
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

fn login_recovery_response(
    recovery: LoginRecovery,
    public_base_path: &PublicBasePath,
    return_to: &str,
) -> Response {
    let return_to = validated_return_to(public_base_path, Some(return_to));
    let login = login_location(public_base_path, &return_to);
    let html = auth_page(
        public_base_path,
        AuthPage {
            title: "Sign-in recovery",
            status: Some(recovery.message()),
            lead: PHAROS_LEAD,
            action_href: &login,
            action: "Sign in again",
            note: None,
        },
    );
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        set_cookie(FLOW_COOKIE, "", 0, true, "Lax")
            .parse()
            .expect("flow cookie clearing header"),
    );
    (recovery.status(), headers, no_store_headers(), Html(html)).into_response()
}

const PHAROS_LEAD: &str = "Every host, its CVEs and what is due, on one page.";
const OPERATOR_LIST_NOTE: &str = "For people on the fleet's operator list.";

const fn no_store_headers() -> [(header::HeaderName, &'static str); 3] {
    [
        (
            header::CACHE_CONTROL,
            "no-store, no-cache, max-age=0, must-revalidate",
        ),
        (header::PRAGMA, "no-cache"),
        (header::EXPIRES, "0"),
    ]
}

struct AuthPage<'a> {
    title: &'a str,
    status: Option<&'a str>,
    lead: &'a str,
    action_href: &'a str,
    action: &'a str,
    note: Option<&'a str>,
}

/// The card around every step of signing in. It says nothing about a host.
fn auth_page(public_base_path: &PublicBasePath, page: AuthPage<'_>) -> String {
    use crate::icons::{icon, sprite};
    use crate::ui::{document_head, html_escape};
    let status = page
        .status
        .map(|text| {
            format!(
                r#"<div class="expired" role="status">{}<span>{}</span></div>"#,
                icon("clock", ""),
                html_escape(text)
            )
        })
        .unwrap_or_default();
    let note = page
        .note
        .map(|text| format!(r#"<p class="lfor">{}</p>"#, html_escape(text)))
        .unwrap_or_default();
    crate::public_mount::localize_document(
        public_base_path,
        &format!(
            r#"{head}<body>{sprite}<div class="login"><span class="login-art" aria-hidden="true"><span class="art-horizon"></span></span><main class="login-main"><div class="lcard">{status}<div class="lbrand"><span class="side-mark">{mark}</span><h1 class="lword">Pharos</h1></div><p class="lead">{lead}</p><a class="btn btn-primary" href="{href}">{action}</a>{note}</div></main></div></body></html>"#,
            head = document_head(public_base_path, page.title),
            sprite = sprite(),
            mark = icon("lighthouse", ""),
            lead = html_escape(page.lead),
            href = html_escape(page.action_href),
            action = html_escape(page.action),
        ),
    )
}

#[derive(Default, serde::Deserialize)]
pub struct SignInParams {
    return_to: Option<String>,
    ended: Option<String>,
}

/// `GET /auth/sign-in` — the page in front of the identity provider.
pub async fn sign_in(
    State(auth): State<AuthState>,
    Query(params): Query<SignInParams>,
) -> Response {
    let public_base_path = &auth.public_base_path;
    let return_to = validated_return_to(public_base_path, params.return_to.as_deref());
    let login = login_location(public_base_path, &return_to);
    let html = auth_page(
        public_base_path,
        AuthPage {
            title: "Sign in",
            status: params
                .ended
                .is_some()
                .then_some("Your session has ended. Sign in again to see the fleet."),
            lead: PHAROS_LEAD,
            action_href: &login,
            action: "Sign in",
            note: Some(OPERATOR_LIST_NOTE),
        },
    );
    (no_store_headers(), Html(html)).into_response()
}

fn rate_limited_response() -> Response {
    (
        StatusCode::TOO_MANY_REQUESTS,
        [(header::RETRY_AFTER, RATE_WINDOW_SECS.to_string())],
        "authentication rate limit exceeded; retry shortly",
    )
        .into_response()
}

/// Middleware gating the pages. A bearer credential is never accepted here and
/// never falls back to a cookie or open mode.
pub async fn guard(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    if req.headers().contains_key(header::AUTHORIZATION) {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match auth.human() {
        None => next.run(req).await,
        Some(human) if human.is_authed(req.headers()) => next.run(req).await,
        Some(_) => {
            let return_to = if matches!(*req.method(), Method::GET | Method::HEAD) {
                validated_return_to(
                    &auth.public_base_path,
                    req.uri().path_and_query().map(|value| value.as_str()),
                )
            } else {
                auth.public_base_path.home().to_string()
            };
            let ended = cookie(req.headers(), SESSION_COOKIE).is_some();
            Redirect::to(&sign_in_location(&auth.public_base_path, &return_to, ended))
                .into_response()
        }
    }
}

/// Middleware gating the data routes, which only read. The operator token opens
/// them, as does a browser session. Anything else gets a plain 401, never a page.
pub async fn data_guard(State(auth): State<AuthState>, req: Request, next: Next) -> Response {
    let allowed = if req.headers().contains_key(header::AUTHORIZATION) {
        auth.operator_token_matches(req.headers())
    } else {
        auth.human()
            .is_none_or(|human| human.is_authed(req.headers()))
    };
    if allowed {
        next.run(req).await
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Bearer")],
        )
            .into_response()
    }
}

#[derive(Default, serde::Deserialize)]
pub struct LoginParams {
    return_to: Option<String>,
}

/// `GET /auth/login` — start the PKCE flow, redirect to the IdP.
pub async fn login(State(auth): State<AuthState>, Query(params): Query<LoginParams>) -> Response {
    let return_to = validated_return_to(&auth.public_base_path, params.return_to.as_deref());
    let Some(auth) = auth.human().cloned() else {
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
    let public_base_path = auth.public_base_path.clone();
    let Some(auth) = auth.human().cloned() else {
        return Redirect::to(public_base_path.home()).into_response();
    };
    let flow_cookie = cookie(&headers, FLOW_COOKIE);
    let cookie_return_to = return_to_from_flow_cookie(flow_cookie.as_deref(), &public_base_path);
    let Some(state) = p.state else {
        tracing::info!(
            category = "missing_state",
            "OIDC callback requires a fresh login"
        );
        return login_recovery_response(
            LoginRecovery::FlowUnavailable,
            &public_base_path,
            &cookie_return_to,
        );
    };
    let flow_cookie_hash = flow_cookie.as_deref().map(secret_hash);
    let pending = match auth.take_pending(&state, flow_cookie_hash.as_ref(), now()) {
        PendingFlowOutcome::Matched(pending) => pending,
        PendingFlowOutcome::Missing => {
            tracing::info!(
                category = "unknown_or_replayed_state",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(
                LoginRecovery::FlowUnavailable,
                &public_base_path,
                &cookie_return_to,
            );
        }
        PendingFlowOutcome::Expired(return_to) => {
            tracing::info!(
                category = "expired_state",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(
                LoginRecovery::FlowUnavailable,
                &public_base_path,
                &return_to,
            );
        }
        PendingFlowOutcome::BrowserMismatch(return_to) => {
            tracing::info!(
                category = "superseded_or_wrong_browser",
                "OIDC callback requires a fresh login"
            );
            return login_recovery_response(
                LoginRecovery::FlowUnavailable,
                &public_base_path,
                &return_to,
            );
        }
    };
    let return_to = pending.return_to.clone();
    if p.error.is_some() {
        tracing::warn!(
            category = "authorization_provider_rejection",
            "OIDC provider rejected the authorization request"
        );
        return login_recovery_response(
            LoginRecovery::ProviderRejected,
            &public_base_path,
            &return_to,
        );
    }
    let Some(code) = p.code else {
        tracing::warn!(
            category = "authorization_response_malformed",
            "OIDC provider response omitted the authorization code"
        );
        return login_recovery_response(
            LoginRecovery::MalformedProviderResponse,
            &public_base_path,
            &return_to,
        );
    };

    let client = auth.client();
    let token_request = match client.exchange_code(AuthorizationCode::new(code)) {
        Ok(request) => request,
        Err(_) => {
            tracing::warn!(
                category = "token_endpoint_unavailable",
                "OIDC token exchange could not be started"
            );
            return login_recovery_response(
                LoginRecovery::ProviderUnavailable,
                &public_base_path,
                &return_to,
            );
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
            return login_recovery_response(recovery, &public_base_path, &return_to);
        }
    };
    let Some(id_token) = token.id_token() else {
        tracing::warn!(
            category = "token_response_missing_id_token",
            "OIDC token response was malformed"
        );
        return login_recovery_response(
            LoginRecovery::MalformedProviderResponse,
            &public_base_path,
            &return_to,
        );
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
                return login_recovery_response(
                    LoginRecovery::ProviderUnavailable,
                    &public_base_path,
                    &return_to,
                );
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
                    return login_recovery_response(
                        LoginRecovery::VerificationFailed,
                        &public_base_path,
                        &return_to,
                    );
                }
            }
        }
        Err(_) => {
            tracing::warn!(
                category = "id_token_verification_failed",
                "OIDC id_token verification failed safely"
            );
            return login_recovery_response(
                LoginRecovery::VerificationFailed,
                &public_base_path,
                &return_to,
            );
        }
    };
    enrich_identity_from_user_info(
        &client,
        &auth.http_client,
        token.access_token().to_owned(),
        &mut identity,
    )
    .await;
    if !auth.operator_policy.allows(&identity.identifiers) {
        tracing::warn!(
            category = "operator_not_allowed",
            "sign-in refused: this account is not on the operator list"
        );
        return forbidden(&public_base_path);
    }
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
        set_cookie(
            SESSION_COOKIE,
            &sid,
            SESSION_TTL_SECS + ENDED_SESSION_COOKIE_SECS,
            true,
            "Lax",
        )
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
pub async fn recover(State(auth): State<AuthState>, Query(params): Query<LoginParams>) -> Response {
    let return_to = validated_return_to(&auth.public_base_path, params.return_to.as_deref());
    login_recovery_response(
        LoginRecovery::FlowUnavailable,
        &auth.public_base_path,
        &return_to,
    )
}

/// Signed in at the provider, but not someone this fleet lets in: no session.
fn forbidden(public_base_path: &PublicBasePath) -> Response {
    let html = auth_page(
        public_base_path,
        AuthPage {
            title: "Access denied",
            status: Some("This account is not on the fleet's operator list."),
            lead: "Ask the fleet's operator to add it, then sign in again.",
            action_href: &public_base_path.href("/auth/login"),
            action: "Sign in again",
            note: None,
        },
    );
    let mut headers = HeaderMap::new();
    headers.append(
        header::SET_COOKIE,
        set_cookie(FLOW_COOKIE, "", 0, true, "Lax")
            .parse()
            .expect("flow cookie clearing header"),
    );
    (
        StatusCode::FORBIDDEN,
        headers,
        no_store_headers(),
        Html(html),
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
    if let Some(auth) = auth.human() {
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
    (
        out,
        Redirect::to(&auth.public_base_path.href("/auth/logged-out")),
    )
        .into_response()
}

/// `GET /auth/logged-out` — neutral landing page after local Pharos logout.
pub async fn logged_out(State(auth): State<AuthState>) -> impl IntoResponse {
    let public_base_path = &auth.public_base_path;
    let html = auth_page(
        public_base_path,
        AuthPage {
            title: "Signed out",
            status: Some("You have signed out of Pharos."),
            lead: PHAROS_LEAD,
            action_href: &public_base_path.href("/auth/login"),
            action: "Sign in",
            note: Some(OPERATOR_LIST_NOTE),
        },
    );
    (no_store_headers(), Html(html)).into_response()
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
        ca_path: std::path::PathBuf,
        signing_key: Arc<RsaPrivateKey>,
        nonce: Arc<Mutex<Option<String>>>,
        token_mode: Arc<Mutex<MockTokenMode>>,
    }

    struct MockOidcServer {
        task: tokio::task::JoinHandle<()>,
        tls_root: std::path::PathBuf,
    }

    impl MockOidcServer {
        async fn shutdown(self) {
            self.task.abort();
            let _ = self.task.await;
            std::fs::remove_dir_all(self.tls_root).expect("mock OIDC TLS directory removed");
        }
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

    async fn start_mock_oidc() -> (MockOidcProvider, MockOidcServer) {
        let material = generate_test_tls_material("mock-issuer");
        let listener = TestTlsListener::bind(
            material.certificate_der.clone(),
            material.private_key_der.clone(),
        )
        .await;
        let issuer = format!("https://localhost:{}", listener.local_addr().port());
        let provider = MockOidcProvider {
            issuer,
            ca_path: material.ca_path.clone(),
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
        (
            provider,
            MockOidcServer {
                task,
                tls_root: material.root,
            },
        )
    }

    async fn auth_for_provider(provider: &MockOidcProvider) -> AuthState {
        let mut config = AuthConfig::from_values(
            true,
            Some(provider.issuer.clone()),
            Some("pharos-oidc-e2e".to_string()),
            Some("https://pharos.example.test/auth/callback".to_string()),
            false,
            OperatorPolicy::from_raw(None).unwrap(),
        )
        .unwrap();
        let AuthConfigMode::Oidc(oidc) = &mut config.mode else {
            unreachable!("mock OIDC configuration is complete");
        };
        oidc.oidc_ca_file = Some(provider.ca_path.clone());
        Auth::from_config(config, PublicBasePath::root())
            .await
            .unwrap()
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

    /// What only a signed-in person may read: (route, a path that matches it).
    const HUMAN_ROUTES: [(&str, &str); 5] = [
        ("/", "/"),
        ("/updates", "/updates"),
        ("/handled", "/handled"),
        ("/cves/{id}", "/cves/CVE-2000-0001"),
        ("/hosts/{name}", "/hosts/route-walk-host"),
    ];
    /// The same for what a session or the operator token may read.
    const DATA_ROUTES: [(&str, &str); 2] = [
        ("/hosts.json", "/hosts.json"),
        ("/fleet.json", "/fleet.json"),
    ];
    /// Open by design: (route, method, a path that matches it). None of them may
    /// say anything about a host.
    const OPEN_ROUTES: [(&str, Method, &str); 18] = [
        ("/auth/sign-in", Method::GET, "/auth/sign-in"),
        ("/healthz", Method::GET, "/healthz"),
        ("/readyz", Method::GET, "/readyz"),
        ("/version", Method::GET, "/version"),
        ("/register", Method::POST, "/register"),
        ("/report", Method::POST, "/report"),
        ("/favicon.svg", Method::GET, "/favicon.svg"),
        ("/assets/ui/{name}", Method::GET, "/assets/ui/app.css"),
        (
            "/assets/calendar-version-bootstrap.mjs",
            Method::GET,
            "/assets/calendar-version-bootstrap.mjs",
        ),
        (
            "/assets/vendor/calendar-version-display/{name}",
            Method::GET,
            "/assets/vendor/calendar-version-display/version.js",
        ),
        ("/auth/login", Method::GET, "/auth/login"),
        ("/auth/callback", Method::GET, "/auth/callback"),
        ("/auth/recover", Method::GET, "/auth/recover"),
        ("/auth/logout", Method::POST, "/auth/logout"),
        ("/auth/logged-out", Method::GET, "/auth/logged-out"),
        ("/assets/ui/{name}", Method::GET, "/assets/ui/app.js"),
        (
            "/assets/ui/{name}",
            Method::GET,
            "/assets/ui/fleet-horizon.webp",
        ),
        (
            "/assets/ui/{name}",
            Method::GET,
            "/assets/ui/sidebar-lighthouse.webp",
        ),
    ];

    /// Every route written in routes.rs, read from the source so a new one cannot
    /// be left out of this walk.
    fn declared_routes() -> std::collections::BTreeSet<String> {
        include_str!("routes.rs")
            .split(".route(")
            .skip(1)
            .filter_map(|tail| tail.trim_start().strip_prefix('"'))
            .filter_map(|tail| tail.split('"').next())
            .map(ToString::to_string)
            .collect()
    }

    async fn signed_in_cookie(auth: &AuthState, provider: &MockOidcProvider) -> String {
        let login_response = login(State(auth.clone()), login_params(None)).await;
        let parameters = authorization_parameters(&login_response, provider);
        let state = parameters.get("state").cloned().unwrap();
        let flow_cookie = response_cookie(&login_response, FLOW_COOKIE).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        let callback_response = callback(
            State(auth.clone()),
            headers,
            callback_params(Some("single-use-code"), Some(state), None),
        )
        .await;
        response_cookie(&callback_response, SESSION_COOKIE).unwrap()
    }

    #[tokio::test]
    async fn without_a_login_no_route_says_anything_about_a_host() {
        let (provider, server) = start_mock_oidc().await;
        let auth = auth_for_provider(&provider).await;

        let directory =
            std::env::temp_dir().join(format!("pharos-route-walk-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let store_path = directory.join("hosts.json");
        std::fs::write(
            &store_path,
            serde_json::json!([{
                "name": "route-walk-host",
                "role": "Server",
                "is_nix": true,
                "last_seen": crate::now_unix(),
                "heartbeat_interval_secs": 3600,
                "freshness": {
                    "applicable": true,
                    "flake_lock_age_days": 1,
                    "commits_behind": 0,
                },
            }])
            .to_string(),
        )
        .unwrap();
        let data_path = directory.join("fleet.json");
        std::fs::write(&data_path, crate::fleet_data::CONTRACT).unwrap();
        let fleet_data = crate::fleet_data::FleetDataRuntime::for_test(data_path);
        fleet_data.refresh();

        let state = crate::AppState {
            started_at: crate::now_unix(),
            store: Arc::new(crate::store::Store::new(Some(store_path)).unwrap()),
            auth: auth.clone(),
            beacon_auth: crate::BeaconAuth {
                registration_token: None,
            },
            http_probes: None,
            host_probes: None,
            fleet_data: Some(fleet_data),
            public_base_path: PublicBasePath::root(),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = crate::routes::build_router(state);
        let app_task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        let says_something = |body: &str| {
            ["route-walk-host", "demeter", "hermes", "CVE-2000-"]
                .iter()
                .any(|needle| body.contains(needle))
        };

        // The walk covers exactly what the router declares.
        let walked: std::collections::BTreeSet<String> = HUMAN_ROUTES
            .iter()
            .chain(DATA_ROUTES.iter())
            .map(|(route, _)| route.to_string())
            .chain(OPEN_ROUTES.iter().map(|(route, _, _)| route.to_string()))
            .collect();
        assert_eq!(walked, declared_routes());

        for (route, path) in HUMAN_ROUTES {
            let url = format!("{base}{path}");
            let anonymous = client.get(&url).send().await.unwrap();
            assert_eq!(anonymous.status(), StatusCode::SEE_OTHER, "{route}");
            let location = anonymous.headers()[header::LOCATION.as_str()]
                .to_str()
                .unwrap()
                .to_string();
            assert!(location.starts_with("/auth/sign-in"), "{route}: {location}");
            assert!(!says_something(&anonymous.text().await.unwrap()), "{route}");

            let with_token = client
                .get(&url)
                .bearer_auth("not-a-browser-session")
                .send()
                .await
                .unwrap();
            assert_eq!(with_token.status(), StatusCode::UNAUTHORIZED, "{route}");
            assert!(
                !says_something(&with_token.text().await.unwrap()),
                "{route}"
            );
        }

        for (route, path) in DATA_ROUTES {
            let url = format!("{base}{path}");
            let anonymous = client.get(&url).send().await.unwrap();
            assert_eq!(anonymous.status(), StatusCode::UNAUTHORIZED, "{route}");
            assert_eq!(
                anonymous.headers()[header::WWW_AUTHENTICATE.as_str()],
                "Bearer",
                "{route}"
            );
            assert!(!says_something(&anonymous.text().await.unwrap()), "{route}");

            let wrong_token = client
                .get(&url)
                .bearer_auth("not-the-operator-token")
                .send()
                .await
                .unwrap();
            assert_eq!(wrong_token.status(), StatusCode::UNAUTHORIZED, "{route}");
            assert!(
                !says_something(&wrong_token.text().await.unwrap()),
                "{route}"
            );
        }

        for (route, method, path) in &OPEN_ROUTES {
            let response = client
                .request(method.clone(), format!("{base}{path}"))
                .send()
                .await
                .unwrap();
            let status = response.status();
            assert_ne!(status, StatusCode::NOT_FOUND, "{route}: {path}");
            assert!(!status.is_server_error(), "{route}: {path}: {status}");
            let body = response.bytes().await.unwrap();
            assert!(
                !says_something(&String::from_utf8_lossy(&body)),
                "{route}: {path}"
            );
        }

        // The same routes do open for a person who signed in, so the walk above
        // proves the login is what stood in the way.
        let cookie = signed_in_cookie(&auth, &provider).await;
        for (route, path) in HUMAN_ROUTES.iter().chain(DATA_ROUTES.iter()) {
            let response = client
                .get(format!("{base}{path}"))
                .header(header::COOKIE, &cookie)
                .send()
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK, "{route}");
            assert!(says_something(&response.text().await.unwrap()), "{route}");
        }

        app_task.abort();
        drop(server);
        std::fs::remove_dir_all(directory).unwrap();
    }

    async fn auth_with_policy(provider: &MockOidcProvider, allowed: &str) -> AuthState {
        let mut config = AuthConfig::from_values(
            false,
            Some(provider.issuer.clone()),
            Some("pharos-oidc-e2e".to_string()),
            Some("https://pharos.example.test/auth/callback".to_string()),
            false,
            OperatorPolicy::from_raw(Some(allowed)).unwrap(),
        )
        .unwrap();
        let AuthConfigMode::Oidc(oidc) = &mut config.mode else {
            unreachable!("mock OIDC configuration is complete");
        };
        oidc.oidc_ca_file = Some(provider.ca_path.clone());
        Auth::from_config(config, PublicBasePath::root())
            .await
            .unwrap()
    }

    async fn sign_in_through_provider(auth: &AuthState, provider: &MockOidcProvider) -> Response {
        let login_response = login(State(auth.clone()), login_params(None)).await;
        let parameters = authorization_parameters(&login_response, provider);
        let state = parameters.get("state").cloned().unwrap();
        let flow_cookie = response_cookie(&login_response, FLOW_COOKIE).unwrap();
        let mut headers = HeaderMap::new();
        headers.insert(header::COOKIE, flow_cookie.parse().unwrap());
        callback(
            State(auth.clone()),
            headers,
            callback_params(Some("single-use-code"), Some(state), None),
        )
        .await
    }

    #[tokio::test]
    async fn the_login_allow_list_refuses_anyone_else_with_no_session() {
        let (provider, server) = start_mock_oidc().await;

        let listed = auth_with_policy(&provider, "email:oidc-e2e@example.invalid").await;
        let welcome = sign_in_through_provider(&listed, &provider).await;
        assert_eq!(welcome.status(), StatusCode::SEE_OTHER);
        assert!(response_cookie(&welcome, SESSION_COOKIE).is_some());
        // The cookie outlives the session, so a return visit can say it ended.
        let max_age = welcome
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .find(|value| value.starts_with(SESSION_COOKIE))
            .and_then(|value| value.split("Max-Age=").nth(1))
            .and_then(|tail| tail.split(';').next())
            .and_then(|value| value.parse::<i64>().ok())
            .unwrap();
        assert!(max_age > SESSION_TTL_SECS, "{max_age}");

        let other = auth_with_policy(&provider, "email:someone-else@example.invalid").await;
        let refused = sign_in_through_provider(&other, &provider).await;
        assert_eq!(refused.status(), StatusCode::FORBIDDEN);
        assert!(response_cookie(&refused, SESSION_COOKIE).is_none());
        assert_eq!(
            other.human().unwrap().sessions.lock().unwrap().len(),
            0,
            "no session may exist on the server either"
        );
        let body = axum::body::to_bytes(refused.into_body(), usize::MAX)
            .await
            .unwrap();
        let page = String::from_utf8_lossy(&body);
        assert!(page.contains("operator list"), "{page}");
        assert!(!page.contains("oidc-e2e@example.invalid"), "{page}");

        drop(server);
    }

    #[test]
    fn the_operator_token_hash_must_be_a_safe_file_with_one_digest() {
        use std::os::unix::fs::PermissionsExt;
        let directory =
            std::env::temp_dir().join(format!("pharos-token-hash-{}", std::process::id()));
        std::fs::create_dir_all(&directory).unwrap();
        let digest = "ab".repeat(32);
        let write = |name: &str, content: &str, mode: u32| {
            let path = directory.join(name);
            std::fs::write(&path, content).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
            path
        };

        assert_eq!(
            load_operator_token_hash(&write("good", &digest, 0o600)).unwrap(),
            [0xab; 32]
        );
        assert_eq!(
            load_operator_token_hash(&write("newline", &format!("{digest}\n"), 0o440)).unwrap(),
            [0xab; 32]
        );
        for (name, content, mode) in [
            ("short", "abcd".to_string(), 0o600),
            ("upper", digest.to_uppercase(), 0o600),
            ("two-lines", format!("{digest}\n\n"), 0o600),
            ("not-hex", "zz".repeat(32), 0o600),
            ("empty", String::new(), 0o600),
            ("group-writable", digest.clone(), 0o620),
            ("world-writable", digest.clone(), 0o602),
        ] {
            assert!(
                load_operator_token_hash(&write(name, &content, mode)).is_err(),
                "{name}"
            );
        }
        assert!(load_operator_token_hash(&directory.join("missing")).is_err());
        let link = directory.join("link");
        std::os::unix::fs::symlink(directory.join("good"), &link).unwrap();
        assert!(load_operator_token_hash(&link).is_err());
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn sign_in_says_when_a_session_ended_and_keeps_where_you_were_going() {
        let auth = AuthState::default();
        let page = |params: SignInParams| {
            let auth = auth.clone();
            async move {
                let response = sign_in(State(auth), Query(params)).await;
                assert_eq!(response.status(), StatusCode::OK);
                let body = axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap();
                String::from_utf8_lossy(&body).to_string()
            }
        };
        let first = page(SignInParams::default()).await;
        assert!(!first.contains("Your session has ended"), "{first}");
        assert!(first.contains(r#"href="/auth/login""#), "{first}");

        let ended = page(SignInParams {
            return_to: Some("/updates".to_string()),
            ended: Some("1".to_string()),
        })
        .await;
        assert!(ended.contains("Your session has ended"), "{ended}");
        assert!(ended.contains("return_to=%2Fupdates"), "{ended}");

        let foreign = page(SignInParams {
            return_to: Some("https://example.invalid/".to_string()),
            ended: None,
        })
        .await;
        assert!(!foreign.contains("example.invalid"), "{foreign}");
    }

    #[test]
    fn a_page_redirect_names_the_sign_in_page_and_stays_on_the_mount() {
        let root = PublicBasePath::root();
        assert_eq!(sign_in_location(&root, "/", false), "/auth/sign-in");
        assert_eq!(
            sign_in_location(&root, "/updates", true),
            "/auth/sign-in?return_to=%2Fupdates&ended=1"
        );
        let mount = PublicBasePath::parse("/pharos").unwrap();
        assert_eq!(
            sign_in_location(&mount, "/pharos", false),
            "/pharos/auth/sign-in"
        );
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
            .human_user(&session_headers)
            .expect("OIDC callback creates a session");
        assert_eq!(user.display_name, "oidc-e2e-user");

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
        assert!(auth_state.human_user(&session_headers).is_some());

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
        assert!(auth_state.human_user(&session_headers).is_none());

        server.shutdown().await;
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
        let root = PublicBasePath::root();
        assert_eq!(
            validated_return_to(&root, Some("/services?view=managed")),
            "/services?view=managed"
        );
        assert_eq!(
            validated_return_to(&root, Some("/services?view=managed&flow_project=17")),
            "/services?view=managed&flow_project=17"
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
            assert_eq!(validated_return_to(&root, Some(unsafe_target)), "/");
        }
        assert_eq!(
            validated_return_to(
                &root,
                Some(&format!("/{}", "a".repeat(MAX_RETURN_TO_BYTES)))
            ),
            "/"
        );
        assert_eq!(
            login_location(&root, "/services?view=managed"),
            "/auth/login?return_to=%2Fservices%3Fview%3Dmanaged"
        );
        let flow_cookie = new_flow_cookie("/services?view=managed");
        assert_eq!(
            return_to_from_flow_cookie(Some(&flow_cookie), &root),
            "/services?view=managed"
        );
        assert_eq!(return_to_from_flow_cookie(Some("tampered"), &root), "/");
        assert_eq!(return_to_from_flow_cookie(Some("fixture.%%%"), &root), "/");

        let mounted = PublicBasePath::parse("/pharos").unwrap();
        assert_eq!(
            validated_return_to(&mounted, Some("/services?flow_project=17")),
            "/pharos/services?flow_project=17"
        );
        assert_eq!(
            validated_return_to(&mounted, Some("/pharos/services?view=managed")),
            "/pharos/services?view=managed"
        );
        assert_eq!(
            validated_return_to(&mounted, Some("/pharos/auth/callback")),
            "/pharos"
        );
        assert_eq!(login_location(&mounted, "/pharos"), "/pharos/auth/login");
        assert_eq!(
            login_location(&mounted, "/pharos/services?flow_project=17"),
            "/pharos/auth/login?return_to=%2Fpharos%2Fservices%3Fflow_project%3D17"
        );
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
        assert!(missing_html.contains("Sign in again"));
        assert_eq!(missing_html.matches("<a ").count(), 1);
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
        assert!(response_html(replay).await.contains("Sign in again"));

        server.shutdown().await;
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

        server.shutdown().await;
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

        server.shutdown().await;
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
            "/auth/sign-in?return_to=%2Fservices%3Fview%3Dmanaged"
        );

        // A cookie whose session is gone gets told, not just asked to sign in.
        let ended_response = client
            .get(format!("http://{address}/services"))
            .header(header::COOKIE, format!("{SESSION_COOKIE}=gone"))
            .send()
            .await
            .unwrap();
        assert_eq!(
            ended_response.headers().get(header::LOCATION).unwrap(),
            "/auth/sign-in?return_to=%2Fservices&ended=1"
        );

        let post_response = client
            .post(format!("http://{address}/services"))
            .send()
            .await
            .unwrap();
        assert_eq!(post_response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            post_response.headers().get(header::LOCATION).unwrap(),
            "/auth/sign-in"
        );

        app_server.abort();
        let _ = app_server.await;
        oidc_server.shutdown().await;
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
            assert_eq!(html.matches("<a ").count(), 1);
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
        server.shutdown().await;
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
            State(AuthState::default()),
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
            State(AuthState::default()),
            headers.clone(),
            Form(LogoutForm {
                csrf: "wrong".to_string(),
            }),
        )
        .await;
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);

        let accepted = logout(
            State(AuthState::default()),
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
            .with_state(AuthState::default());
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
            .contains("You have signed out of Pharos."));

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn auth_pages_link_pharos_favicon() {
        let denied = forbidden(&PublicBasePath::root()).into_response();
        let denied_body = axum::body::to_bytes(denied.into_body(), usize::MAX)
            .await
            .expect("denied body");
        let denied_html = std::str::from_utf8(&denied_body).expect("denied html");
        assert!(denied_html.contains(r#"href="/favicon.svg""#));

        let logged_out = logged_out(State(AuthState::default()))
            .await
            .into_response();
        let logged_out_body = axum::body::to_bytes(logged_out.into_body(), usize::MAX)
            .await
            .expect("logged out body");
        let logged_out_html = std::str::from_utf8(&logged_out_body).expect("logged out html");
        assert!(logged_out_html.contains(r#"href="/favicon.svg""#));
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
                .allows(&identity.identifiers)
        );
        assert!(
            OperatorPolicy::from_raw(Some(&format!("verified-email-ref:{email_reference}")))
                .unwrap()
                .allows(&identity.identifiers)
        );
        assert!(
            OperatorPolicy::from_raw(Some("email:markus@example.invalid"))
                .unwrap()
                .allows(&identity.identifiers)
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

    fn generate_test_ca(label: &str) -> (std::path::PathBuf, std::path::PathBuf) {
        use std::sync::atomic::{AtomicU64, Ordering};

        static SEQUENCE: AtomicU64 = AtomicU64::new(1);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "pharos-auth-oidc-ca-{label}-{}-{}-{sequence}",
            std::process::id(),
            now()
        ));
        std::fs::create_dir(&root).expect("test CA directory created");
        let ca_path = root.join("ca.pem");
        let key_path = root.join("ca.key");
        let status = std::process::Command::new("openssl")
            .current_dir(&root)
            .args([
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                key_path.to_str().expect("key path is UTF-8"),
                "-out",
                ca_path.to_str().expect("CA path is UTF-8"),
                "-subj",
                "/CN=Pharos ephemeral OIDC test CA",
                "-days",
                "2",
                "-sha256",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("openssl is available for TLS fixtures");
        assert!(status.success());
        (root, ca_path)
    }

    struct TestTlsMaterial {
        root: std::path::PathBuf,
        ca_path: std::path::PathBuf,
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
    }

    struct TestTlsListener {
        listener: tokio::net::TcpListener,
        acceptor: tokio_rustls::TlsAcceptor,
    }

    impl TestTlsListener {
        async fn bind(certificate_der: Vec<u8>, private_key_der: Vec<u8>) -> Self {
            Self {
                listener: tokio::net::TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("bind ephemeral OIDC TLS server"),
                acceptor: test_tls_acceptor(certificate_der, private_key_der),
            }
        }

        fn local_addr(&self) -> std::net::SocketAddr {
            self.listener
                .local_addr()
                .expect("ephemeral OIDC TLS server address")
        }
    }

    fn test_tls_acceptor(
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
    ) -> tokio_rustls::TlsAcceptor {
        use tokio_rustls::rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};

        let server_config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(certificate_der)],
                PrivatePkcs8KeyDer::from(private_key_der).into(),
            )
            .expect("ephemeral OIDC TLS server configuration");
        tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
    }

    impl axum::serve::Listener for TestTlsListener {
        type Io = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
        type Addr = std::net::SocketAddr;

        async fn accept(&mut self) -> (Self::Io, Self::Addr) {
            loop {
                let (stream, address) = self
                    .listener
                    .accept()
                    .await
                    .expect("accept ephemeral OIDC TLS connection");
                if let Ok(stream) = self.acceptor.accept(stream).await {
                    return (stream, address);
                }
            }
        }

        fn local_addr(&self) -> std::io::Result<Self::Addr> {
            self.listener.local_addr()
        }
    }

    fn run_test_openssl(directory: &std::path::Path, arguments: &[&str]) {
        let status = std::process::Command::new("openssl")
            .current_dir(directory)
            .args(arguments)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("OpenSSL is required for ephemeral OIDC TLS fixtures");
        assert!(
            status.success(),
            "ephemeral TLS certificate generation failed"
        );
    }

    fn generate_test_tls_material(label: &str) -> TestTlsMaterial {
        let (root, ca_path) = generate_test_ca(label);
        let ca_key_path = root.join("ca.key");
        run_test_openssl(
            &root,
            &[
                "req",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-keyout",
                "server.key",
                "-out",
                "server.csr",
                "-subj",
                "/CN=localhost",
            ],
        );
        std::fs::write(
            root.join("server.ext"),
            b"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:localhost\n",
        )
        .expect("write ephemeral OIDC server extensions");
        run_test_openssl(
            &root,
            &[
                "x509",
                "-req",
                "-in",
                "server.csr",
                "-CA",
                ca_path.to_str().expect("test CA path is UTF-8"),
                "-CAkey",
                ca_key_path.to_str().expect("test CA key path is UTF-8"),
                "-CAcreateserial",
                "-out",
                "server.pem",
                "-days",
                "2",
                "-sha256",
                "-extfile",
                "server.ext",
            ],
        );
        run_test_openssl(
            &root,
            &[
                "x509",
                "-in",
                "server.pem",
                "-outform",
                "DER",
                "-out",
                "server.der",
            ],
        );
        run_test_openssl(
            &root,
            &[
                "pkcs8",
                "-topk8",
                "-nocrypt",
                "-in",
                "server.key",
                "-outform",
                "DER",
                "-out",
                "server-key.der",
            ],
        );
        TestTlsMaterial {
            certificate_der: std::fs::read(root.join("server.der"))
                .expect("read ephemeral OIDC server certificate"),
            private_key_der: std::fs::read(root.join("server-key.der"))
                .expect("read ephemeral OIDC server key"),
            root,
            ca_path,
        }
    }

    async fn serve_test_https(
        certificate_der: Vec<u8>,
        private_key_der: Vec<u8>,
        request_hostname: &str,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let acceptor = test_tls_acceptor(certificate_der, private_key_der);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral OIDC TLS server");
        let port = listener.local_addr().expect("TLS listener address").port();
        let task = tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let Ok(mut stream) = acceptor.accept(stream).await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while request.len() <= 16 * 1024 {
                let Ok(read) = stream.read(&mut buffer).await else {
                    return;
                };
                if read == 0 {
                    return;
                }
                request.extend_from_slice(&buffer[..read]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
        });
        (format!("https://{request_hostname}:{port}/"), task)
    }

    async fn wait_for_test_https_server(server: &mut tokio::task::JoinHandle<()>, case: &str) {
        match tokio::time::timeout(std::time::Duration::from_secs(5), &mut *server).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("{case} OIDC TLS server exits: {error}"),
            Err(_) => {
                server.abort();
                let _ = server.await;
                panic!("{case} OIDC TLS server did not exit");
            }
        }
    }

    #[test]
    fn oidc_ca_parser_rejects_non_certificate_material_and_private_keys() {
        assert!(parse_oidc_ca_certificates(
            b"-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
        )
        .is_err());
        assert!(parse_oidc_ca_certificates(
            b"-----BEGIN CERTIFICATE-----\nnot base64!\n-----END CERTIFICATE-----\n"
        )
        .is_err());
        assert!(parse_oidc_ca_certificates(
            b"-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n-----BEGIN PRIVATE KEY-----\nZmFrZQ==\n-----END PRIVATE KEY-----\n"
        )
        .is_err());
        assert!(parse_oidc_ca_certificates(b"issuer.example.test\n").is_err());
    }

    #[test]
    fn oidc_ca_file_accepts_a_valid_owner_readable_certificate() {
        let (root, ca_path) = generate_test_ca("valid");
        let certificates = load_oidc_ca_certificates(&ca_path).expect("CA is accepted");
        assert_eq!(certificates.len(), 1);
        std::fs::remove_dir_all(root).expect("test CA directory removed");
    }

    #[cfg(unix)]
    #[test]
    fn oidc_ca_file_rejects_writable_custody_with_valid_pem() {
        use std::os::unix::fs::PermissionsExt;
        let (root, ca_path) = generate_test_ca("writable");
        std::fs::set_permissions(&ca_path, std::fs::Permissions::from_mode(0o664))
            .expect("test CA permissions set");
        assert!(load_oidc_ca_certificates(&ca_path).is_err());
        std::fs::remove_dir_all(root).expect("test CA directory removed");
    }

    #[cfg(unix)]
    #[test]
    fn oidc_ca_file_rejects_symlink_with_valid_pem() {
        let (root, ca_path) = generate_test_ca("symlink");
        let link = root.join("ca-link.pem");
        std::os::unix::fs::symlink(&ca_path, &link).expect("test CA symlink created");
        assert!(load_oidc_ca_certificates(&link).is_err());
        std::fs::remove_dir_all(root).expect("test CA directory removed");
    }

    #[test]
    fn oidc_ca_file_rejects_oversized_input_before_pem_parse() {
        let (root, ca_path) = generate_test_ca("oversized");
        std::fs::write(&ca_path, vec![b'x'; (MAX_OIDC_CA_FILE_BYTES + 1) as usize])
            .expect("oversized CA fixture written");
        assert!(load_oidc_ca_certificates(&ca_path).is_err());
        std::fs::remove_dir_all(root).expect("test CA directory removed");
    }

    #[test]
    fn oidc_ca_parser_rejects_more_than_the_certificate_bound() {
        let block = "-----BEGIN CERTIFICATE-----\nZmFrZQ==\n-----END CERTIFICATE-----\n";
        let bundle = block.repeat(MAX_OIDC_CA_CERTIFICATES + 1);
        assert!(parse_oidc_ca_certificates(bundle.as_bytes()).is_err());
    }

    #[tokio::test]
    async fn oidc_http_client_rejects_http_without_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cleartext HTTP listener");
        let address = listener
            .local_addr()
            .expect("cleartext HTTP listener address");

        assert!(build_oidc_http_client(None)
            .expect("OIDC HTTP client builds")
            .get(format!("http://{address}/"))
            .send()
            .await
            .is_err());
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err(),
            "OIDC client connected to a cleartext HTTP listener"
        );
    }

    #[tokio::test]
    async fn oidc_ca_https_preserves_chain_and_hostname_verification() {
        let material = generate_test_tls_material("https");
        let (_, wrong_ca_path) = generate_test_ca("wrong-https");

        let (url, mut server) = serve_test_https(
            material.certificate_der.clone(),
            material.private_key_der.clone(),
            "localhost",
        )
        .await;
        let trusted_client = build_oidc_http_client(Some(&material.ca_path)).unwrap();
        assert_eq!(
            trusted_client.get(&url).send().await.unwrap().status(),
            StatusCode::OK
        );
        wait_for_test_https_server(&mut server, "matching-CA").await;

        let (url, mut server) = serve_test_https(
            material.certificate_der.clone(),
            material.private_key_der.clone(),
            "localhost",
        )
        .await;
        assert!(build_oidc_http_client(None)
            .unwrap()
            .get(&url)
            .send()
            .await
            .is_err());
        wait_for_test_https_server(&mut server, "default-root").await;

        let (url, mut server) = serve_test_https(
            material.certificate_der.clone(),
            material.private_key_der.clone(),
            "localhost",
        )
        .await;
        assert!(build_oidc_http_client(Some(&wrong_ca_path))
            .unwrap()
            .get(&url)
            .send()
            .await
            .is_err());
        wait_for_test_https_server(&mut server, "wrong-CA").await;

        let (url, mut server) = serve_test_https(
            material.certificate_der.clone(),
            material.private_key_der.clone(),
            "127.0.0.1",
        )
        .await;
        assert!(trusted_client.get(&url).send().await.is_err());
        wait_for_test_https_server(&mut server, "hostname-mismatch").await;

        std::fs::remove_dir_all(material.root).expect("test TLS directory removed");
        std::fs::remove_dir_all(
            wrong_ca_path
                .parent()
                .expect("wrong test CA has a parent directory"),
        )
        .expect("wrong test CA directory removed");
    }

    #[test]
    fn open_auth_requires_explicit_loopback_opt_in() {
        let denied_without_opt_in =
            AuthConfig::from_values(true, None, None, None, false, policy(None));
        assert!(denied_without_opt_in.is_err());

        let denied_non_loopback =
            AuthConfig::from_values(false, None, None, None, true, policy(None));
        assert!(denied_non_loopback.is_err());

        let allowed = AuthConfig::from_values(true, None, None, None, true, policy(None))
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
        );
        assert!(denied.is_err());

        let allowed = AuthConfig::from_values(
            false,
            issuer,
            client_id,
            redirect,
            false,
            policy(Some("email:operator@example.invalid")),
        )
        .expect("operator policy makes non-loopback OIDC fail closed");
        assert!(matches!(allowed.mode, AuthConfigMode::Oidc(_)));
    }

    #[test]
    fn oidc_cannot_be_combined_with_open_mode() {
        let (issuer, client_id, redirect) = oidc_values();
        let result = AuthConfig::from_values(true, issuer, client_id, redirect, true, policy(None));
        assert!(result.is_err());
    }
}
