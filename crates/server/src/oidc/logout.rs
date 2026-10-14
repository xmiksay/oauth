//! OIDC RP-Initiated Logout 1.0.
//!
//! `GET /oauth2/logout` ends the browser session only when a valid
//! `id_token_hint` (signature + issuer verified, expiry ignored as the spec
//! allows) names the session's own user — otherwise any site could log users
//! out with an `<img>` tag. In every other case (no / invalid hint, hint for
//! another user) the browser is sent to the SPA confirmation page
//! `/logout`, which signs out with `POST /oauth2/logout` (JSON +
//! `Origin`, the login API's CSRF rules). A `post_logout_redirect_uri` is
//! honoured only with a valid hint of a client that registered it; without
//! one, a hint-authorized logout lands on `/logout?signed_out=1`.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{RawQuery, State},
    http::{HeaderMap, HeaderValue, header},
    response::{IntoResponse, Response},
};
use entity::{applications, sessions};
use serde_json::{Value, json};

use super::{
    client_auth::find_client,
    error::{OAuthError, OAuthResult, no_store},
    params, redirect,
};
use crate::{
    app::AppState,
    authn::{
        cookie::{self, Kind},
        session,
    },
    tenancy::Tenant,
    tokens::jwt::{self, VerifyError},
};

pub async fn logout(
    State(state): State<AppState>,
    tenant: Tenant,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    match handle(&state, &tenant, query.as_deref().unwrap_or(""), &headers).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

/// `POST /oauth2/logout` from the confirmation page (CSRF-checked by
/// `authn::csrf` on the route).
pub async fn sign_out(
    State(state): State<AppState>,
    tenant: Tenant,
    headers: HeaderMap,
) -> Response {
    let ended = async {
        let current = session::from_cookie(&state.db, &state.config, &tenant, &headers).await?;
        end_session(&state, current.as_ref()).await
    };
    match ended.await {
        Ok(clear) => {
            let mut response = no_store(Json(json!({ "signed_out": true })).into_response());
            response.headers_mut().append(header::SET_COOKIE, clear);
            response
        }
        Err(err) => err.into_response(),
    }
}

/// A valid hint: its client and subject.
struct Hint {
    client: Option<applications::Model>,
    sub: String,
}

async fn verified_hint(
    state: &AppState,
    tenant: &Tenant,
    params: &HashMap<String, String>,
) -> OAuthResult<Option<Hint>> {
    let Some(raw) = params.get("id_token_hint") else {
        return Ok(None);
    };
    let issuer = state.config.issuer(&tenant.slug);
    let claims =
        match jwt::verify(&state.db, tenant.id, &issuer, raw, jwt::TYP_ID_TOKEN, false).await {
            Ok(claims) => claims,
            Err(VerifyError::Invalid) => return Ok(None),
            Err(VerifyError::Internal(err)) => return Err(err.into()),
        };
    let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
    let (Some(aud), Some(sub)) = (text("aud"), text("sub")) else {
        return Ok(None);
    };
    if params.get("client_id").is_some_and(|c| *c != aud) {
        return Err(OAuthError::invalid_request(
            "client_id does not match id_token_hint",
        ));
    }
    Ok(Some(Hint {
        client: find_client(&state.db, tenant.id, &aud).await?,
        sub,
    }))
}

async fn handle(
    state: &AppState,
    tenant: &Tenant,
    query: &str,
    headers: &HeaderMap,
) -> OAuthResult<Response> {
    let params = params::parse_unique(query.as_bytes()).map_err(OAuthError::invalid_request)?;
    let hint = verified_hint(state, tenant, &params).await?;
    let current = session::from_cookie(&state.db, &state.config, tenant, headers).await?;
    let confirm = || {
        redirect::found(&format!(
            "{}/logout",
            state.config.tenant_origin(&tenant.slug)
        ))
    };
    let Some(hint) = hint else {
        return Ok(confirm());
    };
    if current
        .as_ref()
        .is_some_and(|s| s.user_id.to_string() != hint.sub)
    {
        return Ok(confirm());
    }
    let target = match params.get("post_logout_redirect_uri") {
        None => None,
        Some(uri) => {
            let registered = hint
                .client
                .as_ref()
                .is_some_and(|c| c.post_logout_redirect_uris.iter().any(|r| r == uri));
            if !registered {
                return Err(OAuthError::invalid_request(
                    "post_logout_redirect_uri is not registered for the client of id_token_hint",
                ));
            }
            Some(match params.get("state") {
                Some(st) => redirect::with_params(uri, &[("state", st)]),
                None => uri.clone(),
            })
        }
    };
    // Without a client target the browser lands on the SPA page, which
    // shows "signed out" (a navigation must never end on raw JSON).
    let url = target.unwrap_or_else(|| {
        format!(
            "{}/logout?signed_out=1",
            state.config.tenant_origin(&tenant.slug)
        )
    });
    let mut response = redirect::found(&url);
    let clear = end_session(state, current.as_ref()).await?;
    response.headers_mut().append(header::SET_COOKIE, clear);
    Ok(response)
}

/// Deletes `current` (if any); returns the `Set-Cookie` clearing the
/// session cookie.
async fn end_session(
    state: &AppState,
    current: Option<&sessions::Model>,
) -> OAuthResult<HeaderValue> {
    if let Some(current) = current {
        session::delete(&state.db, current.id).await?;
        tracing::info!(session = %current.id, "session ended by logout");
    }
    Ok(cookie::clear(&state.config, Kind::Session)?)
}
