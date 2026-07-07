//! OIDC (Authorization Code + PKCE) auth against Zitadel (PHAROS-4).
//!
//! Config-gated: enabled only when the `PHAROS_OIDC_ISSUER`,
//! `PHAROS_OIDC_CLIENT_ID`, and `PHAROS_OIDC_REDIRECT_URI` env vars are all set;
//! otherwise pharosd runs open (the current tailnet behaviour), so this ships
//! without affecting the fleet until the env is wired in.
//!
//! Public client (PKCE, no client secret). The human routes (`/`, `/hosts.json`)
//! are gated; machine routes (`POST /register`, `POST /report`) use the
//! PHAROS-8 beacon token flow instead of browser login, while `/healthz` and
//! `/version` stay open.
//!
//! Sessions and in-flight logins are in-memory (single-instance pharosd). A
//! restart drops them — the dashboard reloads from disk, the user just logs in
//! again.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, Request, State};
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

const SESSION_COOKIE: &str = "pharos_session";
const SESSION_TTL_SECS: i64 = 8 * 3600;
const FLOW_TTL_SECS: i64 = 600;
const ALLOWED_OPERATORS_ENV: &str = "PHAROS_ALLOWED_OPERATORS";

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

/// One in-flight login, between `/auth/login` and `/auth/callback`. Keyed by the
/// CSRF state (which the IdP echoes back), so no client-side flow cookie.
struct Pending {
    verifier: PkceCodeVerifier,
    nonce: Nonce,
    created: i64,
}

#[derive(Clone)]
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
}

/// `None` = auth disabled (open). `Some` = OIDC enforced.
pub type AuthState = Option<Arc<Auth>>;

impl Auth {
    /// Build from env, discovering the provider metadata. Returns `None` (auth
    /// disabled) when not configured; panics (fail fast) if configured but the
    /// issuer is unreachable or the values are malformed.
    pub async fn from_env() -> AuthState {
        let issuer = std::env::var("PHAROS_OIDC_ISSUER").ok()?;
        let client_id = std::env::var("PHAROS_OIDC_CLIENT_ID").ok()?;
        let redirect = std::env::var("PHAROS_OIDC_REDIRECT_URI").ok()?;

        let issuer_url = IssuerUrl::new(issuer.clone()).expect("PHAROS_OIDC_ISSUER is not a URL");
        let client_id = ClientId::new(client_id);
        let redirect = RedirectUrl::new(redirect).expect("PHAROS_OIDC_REDIRECT_URI is not a URL");
        let http_client = reqwest::ClientBuilder::new()
            // OIDC 4 requires a stateful client; redirects must stay disabled
            // to avoid SSRF through provider-controlled endpoints.
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .expect("OIDC HTTP client builds");
        let operator_policy = OperatorPolicy::from_env();
        let client = discover_client(
            issuer_url.clone(),
            client_id.clone(),
            redirect.clone(),
            &http_client,
        )
        .await
        .expect("OIDC discovery failed (issuer unreachable?)");
        tracing::info!("OIDC auth enabled (issuer {issuer})");
        if operator_policy.is_enforced() {
            tracing::info!("Pharos operator authorization enabled");
        } else {
            tracing::warn!(
                "{ALLOWED_OPERATORS_ENV} is not configured; all authenticated OIDC users are allowed"
            );
        }
        Some(Arc::new(Auth {
            issuer: issuer_url,
            client_id,
            redirect,
            http_client,
            client: Mutex::new(client),
            operator_policy,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }))
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
        let subject_identifier = identity.subject.as_str().to_string();
        identity.add_identifier(&subject_identifier);
        if let Some(username) = claims.preferred_username() {
            identity.add_identifier(username.as_str());
        }
        if let Some(email) = claims.email() {
            identity.add_identifier(email.as_str());
        }
        Ok(identity)
    }

    fn sweep(&self) {
        let n = now();
        self.pending
            .lock()
            .expect("pending lock")
            .retain(|_, p| n - p.created < FLOW_TTL_SECS);
        self.sessions
            .lock()
            .expect("sessions lock")
            .retain(|_, s| s.expires > n);
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
            .map(|s| AuthUser {
                display_name: s.display_name.clone(),
            })
    }
}

#[derive(Clone)]
struct OperatorPolicy {
    allowed: Vec<String>,
}

impl OperatorPolicy {
    fn from_env() -> Self {
        Self::from_raw(std::env::var(ALLOWED_OPERATORS_ENV).ok().as_deref())
    }

    fn from_raw(raw: Option<&str>) -> Self {
        let allowed = raw
            .into_iter()
            .flat_map(|value| value.split([',', ' ', '\n', '\t']))
            .filter_map(normalize_identifier)
            .fold(Vec::new(), |mut acc, item| {
                if !acc.contains(&item) {
                    acc.push(item);
                }
                acc
            });
        Self { allowed }
    }

    fn is_enforced(&self) -> bool {
        !self.allowed.is_empty()
    }

    fn allows(&self, identity: &LoginIdentity) -> bool {
        !self.is_enforced()
            || identity
                .identifiers
                .iter()
                .any(|identifier| self.allowed.contains(identifier))
    }
}

impl LoginIdentity {
    fn add_identifier(&mut self, value: &str) {
        let Some(value) = normalize_identifier(value) else {
            return;
        };
        if !self.identifiers.contains(&value) {
            self.identifiers.push(value);
        }
    }
}

fn normalize_identifier(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()).then(|| value.to_ascii_lowercase())
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
    identity.add_identifier(claims.subject().as_str());
    if let Some(username) = claims.preferred_username() {
        identity.add_identifier(username.as_str());
    }
    if let Some(email) = claims.email() {
        identity.add_identifier(email.as_str());
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

fn set_cookie(name: &str, value: &str, max_age: i64) -> String {
    format!("{name}={value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age={max_age}")
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

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
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

    auth.pending.lock().expect("pending lock").insert(
        csrf.secret().clone(),
        Pending {
            verifier,
            nonce,
            created: now(),
        },
    );
    Redirect::temporary(url.as_str()).into_response()
}

#[derive(serde::Deserialize)]
pub struct CallbackParams {
    code: Option<String>,
    state: Option<String>,
}

/// `GET /auth/callback` — verify state, exchange the code (with the PKCE
/// verifier), validate the ID token, and start a session.
pub async fn callback(State(auth): State<AuthState>, Query(p): Query<CallbackParams>) -> Response {
    let Some(auth) = auth else {
        return Redirect::temporary("/").into_response();
    };
    let (Some(code), Some(state)) = (p.code, p.state) else {
        return (StatusCode::BAD_REQUEST, "missing code/state").into_response();
    };
    let Some(pending) = auth.pending.lock().expect("pending lock").remove(&state) else {
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
    if !auth.operator_policy.allows(&identity) {
        tracing::warn!("OIDC login denied by Pharos operator policy");
        return forbidden().into_response();
    }

    let sid = CsrfToken::new_random().secret().clone();
    auth.sessions.lock().expect("sessions lock").insert(
        sid.clone(),
        Session {
            subject: identity.subject.as_str().to_string(),
            display_name: identity.display_name,
            expires: now() + SESSION_TTL_SECS,
        },
    );

    let mut headers = HeaderMap::new();
    headers.insert(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, &sid, SESSION_TTL_SECS)
            .parse()
            .expect("cookie header"),
    );
    (headers, Redirect::temporary("/")).into_response()
}

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
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Access denied · Pharos</title><style>:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--accent:#1f7fb5}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%)}main{width:min(420px,calc(100% - 40px));padding:30px;border:1px solid rgba(211,225,233,.88);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 18px 42px rgba(45,75,95,.10);text-align:center}h1{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:28px;font-weight:500;color:#12304b}p{margin:0 0 20px;color:var(--muted)}a{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 16px;border-radius:7px;background:var(--accent);color:white;text-decoration:none;font-weight:650}</style></head><body><main><h1>Access denied</h1><p>Your login succeeded, but this Pharos instance has not granted you operator access.</p><a href="/auth/logout">Sign out</a></main></body></html>"#,
        ),
    )
        .into_response()
}

/// `GET /auth/logout` — drop the session and clear the cookie.
pub async fn logout(State(auth): State<AuthState>, headers: HeaderMap) -> Response {
    if let Some(auth) = &auth {
        if let Some(sid) = cookie(&headers, SESSION_COOKIE) {
            auth.sessions.lock().expect("sessions lock").remove(&sid);
        }
    }
    let mut out = HeaderMap::new();
    out.insert(
        header::SET_COOKIE,
        set_cookie(SESSION_COOKIE, "", 0)
            .parse()
            .expect("cookie header"),
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
            r#"<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Logged out · Pharos</title><style>:root{--ink:#17304a;--muted:#64778a;--line:#dfe9ef;--accent:#1f7fb5;--sun:#d69b31}*{box-sizing:border-box}body{min-height:100vh;margin:0;display:grid;place-items:center;font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;color:var(--ink);background:linear-gradient(180deg,#fff 0%,#f7fbfc 46%,#edf6f7 100%)}main{width:min(420px,calc(100% - 40px));padding:30px;border:1px solid rgba(211,225,233,.88);border-radius:8px;background:rgba(255,255,255,.86);box-shadow:0 18px 42px rgba(45,75,95,.10);text-align:center}h1{margin:0 0 6px;font-family:Georgia,"Times New Roman",serif;font-size:28px;font-weight:500;color:#12304b}p{margin:0 0 20px;color:var(--muted)}a{display:inline-flex;align-items:center;justify-content:center;min-height:38px;padding:0 16px;border-radius:7px;background:var(--accent);color:white;text-decoration:none;font-weight:650}</style></head><body><main><h1>Logged out</h1><p>Your Pharos session has ended.</p><a href="/auth/login">Sign in</a></main></body></html>"#,
        ),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn operator_policy_allows_when_not_configured() {
        let identity = LoginIdentity {
            subject: SubjectIdentifier::new("subject-1".to_string()),
            display_name: "markus".to_string(),
            identifiers: vec!["subject-1".to_string()],
        };

        assert!(OperatorPolicy::from_raw(None).allows(&identity));
    }

    #[test]
    fn operator_policy_allows_configured_username_or_email() {
        let mut identity = LoginIdentity {
            subject: SubjectIdentifier::new("subject-1".to_string()),
            display_name: "markus".to_string(),
            identifiers: Vec::new(),
        };
        identity.add_identifier("subject-1");
        identity.add_identifier("Markus");
        identity.add_identifier("markus@example.invalid");

        assert!(OperatorPolicy::from_raw(Some("markus")).allows(&identity));
        assert!(OperatorPolicy::from_raw(Some("other, markus@example.invalid")).allows(&identity));
    }

    #[test]
    fn operator_policy_denies_unknown_operator() {
        let mut identity = LoginIdentity {
            subject: SubjectIdentifier::new("subject-1".to_string()),
            display_name: "markus".to_string(),
            identifiers: Vec::new(),
        };
        identity.add_identifier("subject-1");
        identity.add_identifier("markus");

        assert!(!OperatorPolicy::from_raw(Some("athena")).allows(&identity));
    }

    #[test]
    fn userinfo_extends_operator_identifiers() {
        let mut identity = LoginIdentity {
            subject: SubjectIdentifier::new("opaque-subject".to_string()),
            display_name: "opaque-subject".to_string(),
            identifiers: vec!["opaque-subject".to_string()],
        };
        let user_info = user_info(
            r#"{
                "sub": "opaque-subject",
                "preferred_username": "markus",
                "email": "markus@example.invalid"
            }"#,
        );

        add_user_info_identifiers(&user_info, &mut identity);

        assert!(OperatorPolicy::from_raw(Some("markus")).allows(&identity));
        assert!(OperatorPolicy::from_raw(Some("markus@example.invalid")).allows(&identity));
    }
}
