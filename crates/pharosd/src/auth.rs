//! OIDC (Authorization Code + PKCE) auth against Zitadel (PHAROS-4).
//!
//! Config-gated: enabled only when the `PHAROS_OIDC_ISSUER`,
//! `PHAROS_OIDC_CLIENT_ID`, and `PHAROS_OIDC_REDIRECT_URI` env vars are all set;
//! otherwise pharosd runs open (the current tailnet behaviour), so this ships
//! without affecting the fleet until the env is wired in.
//!
//! Public client (PKCE, no client secret). The human routes (`/`, `/hosts.json`)
//! are gated; the beacon `POST /report` + `/healthz` + `/version` stay open so
//! agents keep reporting without a browser login.
//!
//! Sessions and in-flight logins are in-memory (single-instance pharosd). A
//! restart drops them — the dashboard reloads from disk, the user just logs in
//! again. Token-based machine auth is PHAROS-8.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Query, Request, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::reqwest::async_http_client;
use openidconnect::{
    AuthorizationCode, ClientId, CsrfToken, IssuerUrl, Nonce, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
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

struct Session {
    #[allow(dead_code)]
    subject: String,
    expires: i64,
}

pub struct Auth {
    client: CoreClient,
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
        let metadata = CoreProviderMetadata::discover_async(issuer_url, async_http_client)
            .await
            .expect("OIDC discovery failed (issuer unreachable?)");
        let client = CoreClient::from_provider_metadata(metadata, ClientId::new(client_id), None)
            .set_redirect_uri(
                RedirectUrl::new(redirect).expect("PHAROS_OIDC_REDIRECT_URI is not a URL"),
            );
        tracing::info!("OIDC auth enabled (issuer {issuer})");
        Some(Arc::new(Auth {
            client,
            pending: Mutex::new(HashMap::new()),
            sessions: Mutex::new(HashMap::new()),
        }))
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
    let (url, csrf, nonce) = auth
        .client
        .authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("openid".to_string()))
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

    let token = match auth
        .client
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
    let claims = match id_token.claims(&auth.client.id_token_verifier(), &pending.nonce) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("id_token verification failed: {e}");
            return (StatusCode::UNAUTHORIZED, "id_token invalid").into_response();
        }
    };
    let subject = claims.subject().as_str().to_string();

    let sid = CsrfToken::new_random().secret().clone();
    auth.sessions.lock().expect("sessions lock").insert(
        sid.clone(),
        Session {
            subject,
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
