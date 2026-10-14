//! `GET /oauth2/authorize` — authorization code flow with mandatory
//! PKCE S256. Until `client_id` and `redirect_uri` are validated, errors are
//! rendered (400 JSON) and never redirected (RFC 6749 §4.1.2.1).

use std::collections::HashMap;

use axum::{
    extract::{RawQuery, State},
    http::{HeaderMap, header},
    response::{IntoResponse, Response},
};
use entity::{applications, enums::LoginStage, sessions};
use sea_orm::ConnectionTrait;

use super::{
    client_auth::find_client,
    error::{ErrorCode, OAuthError, OAuthResult},
    params::{self, AuthRequest, Prompt},
    pkce, redirect, scope,
};
use crate::{
    app::AppState,
    authn::{
        self, AuthnError,
        cookie::{self, Kind},
        ip::ClientIp,
        rate_limit, session, tx,
    },
    consent::Decision,
    tenancy::Tenant,
    tokens,
};

const MAX_STATE_LEN: usize = 2048;
const MAX_NONCE_LEN: usize = 512;

type Rejection = (ErrorCode, String);

/// The request as seen by the helpers below.
struct Env<'a> {
    state: &'a AppState,
    tenant: &'a Tenant,
    headers: &'a HeaderMap,
    ip: ClientIp,
}

pub async fn authorize(
    State(state): State<AppState>,
    tenant: Tenant,
    ip: ClientIp,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Response {
    let env = Env {
        state: &state,
        tenant: &tenant,
        headers: &headers,
        ip,
    };
    match handle(&env, query.as_deref().unwrap_or("")).await {
        Ok(response) => response,
        Err(err) => err.into_response(),
    }
}

async fn handle(env: &Env<'_>, query: &str) -> OAuthResult<Response> {
    let (state, tenant, headers) = (env.state, env.tenant, env.headers);
    let conn = &state.db;
    let params = params::parse_unique(query.as_bytes()).map_err(OAuthError::invalid_request)?;
    let client_id = params
        .get("client_id")
        .ok_or_else(|| OAuthError::invalid_request("client_id is required"))?;
    let client = find_client(conn, tenant.id, client_id)
        .await?
        .ok_or_else(|| OAuthError::invalid_request("unknown client_id"))?;
    let redirect_uri = params
        .get("redirect_uri")
        .ok_or_else(|| OAuthError::invalid_request("redirect_uri is required"))?;
    if !redirect::matches_registered(&client.redirect_uris, redirect_uri) {
        return Err(OAuthError::invalid_request(
            "redirect_uri is not registered for this client",
        ));
    }

    // From here on errors go back to the client.
    let issuer = state.config.issuer(&tenant.slug);
    let state_param = params.get("state").filter(|s| s.len() <= MAX_STATE_LEN);
    let fail = |code: ErrorCode, description: &str| {
        redirect::found(&redirect::error_url(
            redirect_uri,
            code,
            description,
            state_param.map(String::as_str),
            &issuer,
        ))
    };
    let req = match validate(conn, &client, &params, redirect_uri).await? {
        Ok(req) => req,
        Err((code, description)) => return Ok(fail(code, &description)),
    };

    let current = session::current(conn, &state.config, tenant, headers).await?;
    let now = chrono::Utc::now().fixed_offset();
    // `max_age=0` always re-authenticates (like `prompt=login`), even when
    // the last sign-in happened within the same second.
    let fresh_enough = |s: &sessions::Model| {
        req.max_age
            .is_none_or(|max| max > 0 && (now - s.auth_time).num_seconds() <= max)
    };
    let current = current.filter(|(s, _)| req.prompt != Some(Prompt::Login) && fresh_enough(s));
    let Some((session, user)) = current else {
        if req.prompt == Some(Prompt::None) {
            return Ok(fail(ErrorCode::LoginRequired, "the user is not signed in"));
        }
        return to_login(env, &client, &req, LoginStage::Password, None).await;
    };

    let force = authn::force_consent(&req);
    let eval = authn::evaluate_consent(conn, &client, &req, user.id, force).await?;
    let none = req.prompt == Some(Prompt::None);
    match eval.decision {
        Decision::Granted => {
            let url =
                tokens::code::issue_redirect(conn, &issuer, client.id, &req, &session).await?;
            Ok(redirect::found(&url))
        }
        Decision::NeedsAdmin(values) => {
            let code = if none {
                ErrorCode::ConsentRequired
            } else {
                ErrorCode::AccessDenied
            };
            let description = format!("admin approval required for: {}", values.join(" "));
            Ok(fail(code, &description))
        }
        Decision::NeedsUser(_) if none => Ok(fail(
            ErrorCode::ConsentRequired,
            "the user has not consented",
        )),
        Decision::NeedsUser(_) => {
            to_login(env, &client, &req, LoginStage::Consent, Some(&session)).await
        }
    }
}

/// Starts a login transaction bound to this browser and sends it to the
/// login page. Rate limited per IP: these rows are created unauthenticated.
async fn to_login(
    env: &Env<'_>,
    client: &applications::Model,
    req: &AuthRequest,
    stage: LoginStage,
    session: Option<&sessions::Model>,
) -> OAuthResult<Response> {
    let (state, tenant) = (env.state, env.tenant);
    let key = format!("authorize:{}", rate_limit::ip_key(env.ip.0));
    let now = chrono::Utc::now();
    if let Err(retry_after) = rate_limit::hit(
        &state.db,
        tenant.id,
        &key,
        rate_limit::AUTHORIZE_PER_IP,
        now,
    )
    .await?
    {
        return Ok(AuthnError::RateLimited { retry_after }.into_response());
    }
    // Reuse the browser's existing binding so parallel tabs keep working.
    let binding =
        match cookie::read(env.headers, &state.config, Kind::TxBinding).find(|v| v.len() == 43) {
            Some(existing) => existing.to_owned(),
            None => crate::secret::random_token()?,
        };
    let id = tx::create(
        &state.db,
        tx::NewTx {
            tenant_id: tenant.id,
            client_app_id: client.id,
            req,
            stage,
            session,
            binding: &binding,
        },
    )
    .await?;
    let url = format!("{}/login?tx={id}", state.config.tenant_origin(&tenant.slug));
    let mut response = redirect::found(&url);
    let set = cookie::set(&state.config, Kind::TxBinding, &binding)?;
    response.headers_mut().append(header::SET_COOKIE, set);
    Ok(response)
}

/// Everything after client + redirect URI. `Ok(Err(..))` = redirect error.
async fn validate(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    params: &HashMap<String, String>,
    redirect_uri: &str,
) -> anyhow::Result<Result<AuthRequest, Rejection>> {
    let reject = |code: ErrorCode, msg: &str| Ok(Err((code, msg.to_owned())));
    let get = |key: &str| params.get(key).map(String::as_str);
    if get("request").is_some() || get("request_uri").is_some() {
        return reject(
            ErrorCode::RequestNotSupported,
            "request objects are not supported",
        );
    }
    if get("response_type") != Some("code") {
        return reject(
            ErrorCode::UnsupportedResponseType,
            "only response_type=code is supported",
        );
    }
    if get("response_mode").is_some_and(|m| m != "query") {
        return reject(
            ErrorCode::InvalidRequest,
            "only response_mode=query is supported",
        );
    }
    let Some(challenge) = get("code_challenge").filter(|c| pkce::valid_challenge(c)) else {
        return reject(
            ErrorCode::InvalidRequest,
            "a valid PKCE code_challenge is required",
        );
    };
    if get("code_challenge_method") != Some("S256") {
        return reject(
            ErrorCode::InvalidRequest,
            "code_challenge_method must be S256",
        );
    }
    if get("state").is_some_and(|s| s.len() > MAX_STATE_LEN)
        || get("nonce").is_some_and(|n| n.len() > MAX_NONCE_LEN)
    {
        return reject(ErrorCode::InvalidRequest, "state or nonce too long");
    }
    let prompt = match get("prompt").map(Prompt::parse).transpose() {
        Ok(prompt) => prompt.flatten(),
        Err(msg) => return reject(ErrorCode::InvalidRequest, &msg),
    };
    let max_age = match get("max_age").map(str::parse::<i64>) {
        None => None,
        Some(Ok(age)) if age >= 0 => Some(age),
        Some(_) => {
            return reject(
                ErrorCode::InvalidRequest,
                "max_age must be a non-negative integer",
            );
        }
    };
    let requested = match scope::parse(get("scope").unwrap_or_default()) {
        Ok(r) if r.oidc.is_empty() && r.resource.is_none() => {
            return reject(ErrorCode::InvalidScope, "scope is required");
        }
        Ok(r) => r,
        Err(msg) => return reject(ErrorCode::InvalidScope, &msg),
    };
    let (resource_id, resource_scopes) = match &requested.resource {
        None => (None, Vec::new()),
        Some((prefix, values)) => {
            let Some(resource) = scope::find_resource(conn, client.tenant_id, prefix).await? else {
                return reject(ErrorCode::InvalidScope, "unknown resource");
            };
            let Some(scopes) = scope::resolve_delegated(conn, client.id, &resource, values).await?
            else {
                return reject(
                    ErrorCode::InvalidScope,
                    "the resource does not expose a requested scope",
                );
            };
            (
                Some(resource.id),
                scopes.into_iter().map(|s| s.value).collect(),
            )
        }
    };
    Ok(Ok(AuthRequest {
        client_id: client.client_id.clone(),
        redirect_uri: redirect_uri.to_owned(),
        state: get("state").map(str::to_owned),
        nonce: get("nonce").map(str::to_owned),
        code_challenge: challenge.to_owned(),
        oidc_scopes: requested.oidc,
        resource_id,
        resource_scopes,
        prompt,
        max_age,
    }))
}
