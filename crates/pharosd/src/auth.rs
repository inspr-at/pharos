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
use axum::response::{IntoResponse, Redirect, Response};
use openidconnect::core::{
    CoreAuthenticationFlow, CoreClient, CoreIdToken, CoreIdTokenClaims, CoreProviderMetadata,
};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClaimsVerificationError, ClientId, CsrfToken, IssuerUrl, Nonce,
    PkceCodeChallenge, PkceCodeVerifier, RedirectUrl, Scope, TokenResponse,
};

const SESSION_COOKIE: &str = "pharos_session";
const SESSION_TTL_SECS: i64 = 8 * 3600;
const FLOW_TTL_SECS: i64 = 600;

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
    subject: String,
    display_name: String,
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
    client: Mutex<CoreClient>,
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
        let client = discover_client(issuer_url.clone(), client_id.clone(), redirect.clone())
            .await
            .expect("OIDC discovery failed (issuer unreachable?)");
        tracing::info!("OIDC auth enabled (issuer {issuer})");
        Some(Arc::new(Auth {
            issuer: issuer_url,
            client_id,
            redirect,
            client: Mutex::new(client),
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }))
    }

    fn client(&self) -> CoreClient {
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
        )
        .await
        .map_err(|e| e.to_string())?;
        *self.client.lock().expect("client lock") = client;
        Ok(())
    }

    fn verify_id_token_identity(
        &self,
        client: &CoreClient,
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
        let subject = claims.subject().as_str().to_string();
        Ok(LoginIdentity {
            display_name: display_name_from_claims(claims, &subject),
            subject,
        })
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

async fn discover_client(
    issuer: IssuerUrl,
    client_id: ClientId,
    redirect: RedirectUrl,
) -> Result<CoreClient, Box<dyn std::error::Error + Send + Sync>> {
    let metadata = CoreProviderMetadata::discover_async(issuer, async_http_client).await?;
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
    let token = match client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pending.verifier)
        .request_async(async_http_client)
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
    let identity = match auth.verify_id_token_identity(&client, id_token, &pending.nonce) {
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

    let sid = CsrfToken::new_random().secret().clone();
    auth.sessions.lock().expect("sessions lock").insert(
        sid.clone(),
        Session {
            subject: identity.subject,
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
    (out, Redirect::temporary("/")).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims(json: &str) -> CoreIdTokenClaims {
        serde_json::from_str(json).expect("valid id token claims")
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
}
