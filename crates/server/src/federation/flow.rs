//! The two halves of an upstream round trip, shared by sign-in and My
//! Account linking: [`begin`] builds the authorization request (code flow,
//! PKCE S256, `state`, `nonce`, `response_mode=query`), [`finish`] checks
//! the callback, redeems the code and verifies the ID token.

use std::collections::HashMap;

use entity::identity_providers;
use url::Url;
use uuid::Uuid;

use super::{
    Failure,
    exchange::Exchange,
    id_token::{Claims, Expected},
    idps,
    state::{self, Consumed, NewState, Owner},
    urls,
};
use crate::{
    app::AppState,
    oidc::params::{AuthRequest, Prompt},
};

/// Re-authentication the local authorize request demanded, passed on to
/// the provider and enforced on its `auth_time`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reauth {
    pub prompt_login: bool,
    pub max_age: Option<i64>,
}

impl Reauth {
    pub fn of(req: &AuthRequest) -> Self {
        Self {
            prompt_login: req.prompt == Some(Prompt::Login),
            max_age: req.max_age,
        }
    }

    /// The earliest acceptable upstream `auth_time`: not before the round
    /// trip began (`prompt=login`), not older than `max_age`.
    pub fn min_auth_time(self, started_at: i64, now: i64) -> Option<i64> {
        let login = self.prompt_login.then_some(started_at);
        let age = self.max_age.map(|age| now.saturating_sub(age));
        login.into_iter().chain(age).max()
    }
}

fn upstream(state: &AppState) -> Result<&super::Upstream, Failure> {
    state
        .upstream
        .as_deref()
        .ok_or(Failure("client_unavailable"))
}

/// The upstream authorization URL for `owner` (never logged: it carries the
/// state). `Ok(Err(_))` = the provider failed.
pub async fn begin(
    state: &AppState,
    tenant_slug: &str,
    idp: &identity_providers::Model,
    owner: Owner,
    binding_hash: &[u8],
    reauth: Reauth,
) -> anyhow::Result<Result<String, Failure>> {
    let meta = match upstream(state) {
        Ok(upstream) => upstream.metadata(idp).await,
        Err(failure) => Err(failure),
    };
    let meta = match meta {
        Ok(meta) => meta,
        Err(failure) => return Ok(Err(failure)),
    };
    let Ok(mut url) = Url::parse(&meta.authorization_endpoint) else {
        return Ok(Err(Failure("discovery_endpoint_refused")));
    };
    let started = state::create(
        &state.db,
        &state.config.master_key,
        NewState {
            tenant_id: idp.tenant_id,
            idp_id: idp.id,
            idp_generation: idp.generation,
            owner,
            binding_hash,
        },
    )
    .await?;
    url.query_pairs_mut()
        .append_pair("response_type", "code")
        .append_pair("response_mode", "query")
        .append_pair("client_id", &idp.client_id)
        .append_pair(
            "redirect_uri",
            &urls::callback_url(&state.config, tenant_slug),
        )
        .append_pair("scope", &idp.scopes.join(" "))
        .append_pair("state", &started.state)
        .append_pair("nonce", &started.nonce)
        .append_pair("code_challenge", &started.code_challenge)
        .append_pair("code_challenge_method", "S256");
    if reauth.prompt_login {
        url.query_pairs_mut().append_pair("prompt", "login");
    }
    if let Some(age) = reauth.max_age {
        url.query_pairs_mut()
            .append_pair("max_age", &age.to_string());
    }
    Ok(Ok(url.into()))
}

/// Verifies the callback `params` of `consumed` and returns the upstream
/// identity. An `error` response, a missing code, a mix-up (`iss` naming
/// another issuer, RFC 9207) or any failure of the provider is a
/// [`Failure`].
pub async fn finish(
    state: &AppState,
    tenant_slug: &str,
    idp: &identity_providers::Model,
    consumed: &Consumed,
    params: &HashMap<String, String>,
    reauth: Reauth,
) -> Result<Claims, Failure> {
    if params.contains_key("error") {
        return Err(Failure("upstream_error"));
    }
    let code = params.get("code").ok_or(Failure("no_code"))?;
    if params.get("iss").is_some_and(|iss| *iss != idp.issuer) {
        return Err(Failure("iss_param"));
    }
    let upstream = upstream(state)?;
    let meta = upstream.metadata(idp).await?;
    let secret = idps::client_secret(&state.config.master_key, idp).map_err(|err| {
        tracing::error!(error = ?err, "identity provider secret can't be unsealed");
        Failure("secret_unsealable")
    })?;
    let redirect_uri = urls::callback_url(&state.config, tenant_slug);
    let id_token = upstream
        .exchange_code(
            &meta,
            Exchange {
                code,
                redirect_uri: &redirect_uri,
                verifier: &consumed.verifier,
                client_id: &idp.client_id,
                client_secret: secret.as_deref().map(String::as_str),
                auth: idp.client_auth,
            },
        )
        .await?;
    let now = chrono::Utc::now().timestamp();
    let expected = Expected {
        issuer: &idp.issuer,
        client_id: &idp.client_id,
        nonce: &consumed.row.nonce,
        now,
        min_auth_time: reauth.min_auth_time(consumed.row.created_at.timestamp(), now),
    };
    upstream.verify_id_token(&meta, &id_token, &expected).await
}

/// Audit `details` of a failed round trip (fixed reason code, ids only).
pub fn failure_details(reason: &str, idp_id: Uuid) -> serde_json::Value {
    serde_json::json!({ "reason": reason, "factor": "federation", "idp_id": idp_id })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reauth_bounds() {
        let none = Reauth::default();
        assert_eq!(none.min_auth_time(100, 1000), None);
        let login = Reauth {
            prompt_login: true,
            max_age: None,
        };
        assert_eq!(login.min_auth_time(100, 1000), Some(100));
        let age = Reauth {
            prompt_login: false,
            max_age: Some(300),
        };
        assert_eq!(age.min_auth_time(100, 1000), Some(700));
        let both = Reauth {
            prompt_login: true,
            max_age: Some(990),
        };
        assert_eq!(both.min_auth_time(100, 1000), Some(100));
    }
}
