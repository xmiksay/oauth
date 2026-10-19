//! Create / update body of identity providers: applying validated fields
//! to a row, sealing the secret, and the per-tenant email-domain rule.

use entity::identity_providers;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement,
};
use serde::Deserialize;
use uuid::Uuid;

use super::{applications::nullable, idp_validate as v, set_changed};
use crate::{
    app::AppState,
    error::{AppError, AppResult},
    federation::idps,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdpBody {
    pub name: Option<String>,
    pub issuer: Option<String>,
    #[serde(default, deserialize_with = "nullable")]
    pub discovery_url: Option<Option<String>>,
    pub client_id: Option<String>,
    /// A string sets the secret, `null` removes it, absent keeps it.
    #[serde(default, deserialize_with = "nullable")]
    pub client_secret: Option<Option<String>>,
    pub client_auth: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub policy: Option<String>,
    pub trust_upstream_mfa: Option<bool>,
    #[serde(default, deserialize_with = "nullable")]
    pub mfa_acr: Option<Option<String>>,
    pub email_domains: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub visible: Option<bool>,
}

/// 409 when another IdP of the tenant already claims one of `domains`.
pub async fn ensure_domains_free(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    except: Uuid,
    domains: &[String],
) -> AppResult<()> {
    // Serialized per tenant: two concurrent writes must not both find a
    // domain free and both claim it.
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        "SELECT pg_advisory_xact_lock(hashtextextended('idp-domains:' || $1::text, 0))",
        [tenant_id.into()],
    ))
    .await?;
    let others = identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .filter(identity_providers::Column::Id.ne(except))
        .all(conn)
        .await?;
    if let Some(taken) = domains
        .iter()
        .find(|d| others.iter().any(|o| o.email_domains.contains(d)))
    {
        return Err(AppError::Conflict(format!(
            "the email domain `{taken}` already belongs to another identity provider"
        )));
    }
    Ok(())
}

/// Applies the body's fields to `row` (validated); returns the changed
/// field names. `secret` = the new plaintext secret, if one is set.
pub fn apply(
    state: &AppState,
    row: &mut identity_providers::ActiveModel,
    body: &IdpBody,
    secret: &mut Option<String>,
) -> AppResult<Vec<&'static str>> {
    let loopback = state.config.idp_allow_http_loopback;
    let mut fields = Vec::new();
    let mut mark = |changed: bool, name: &'static str| {
        if changed {
            fields.push(name);
        }
    };
    if let Some(raw) = &body.name {
        mark(set_changed(&mut row.name, v::name(raw)?), "name");
    }
    if let Some(raw) = &body.issuer {
        mark(
            set_changed(&mut row.issuer, v::url(raw, "issuer", loopback)?),
            "issuer",
        );
    }
    if let Some(raw) = &body.discovery_url {
        let value = raw
            .as_deref()
            .map(|u| v::url(u, "discovery_url", loopback))
            .transpose()?;
        mark(set_changed(&mut row.discovery_url, value), "discovery_url");
    }
    if let Some(raw) = &body.client_id {
        mark(
            set_changed(&mut row.client_id, v::client_id(raw)?),
            "client_id",
        );
    }
    if let Some(raw) = &body.client_secret {
        match raw {
            // Sealed with a fresh nonce: a re-sent secret always counts as set.
            Some(plain) => {
                *secret = Some(v::client_secret(plain)?);
                mark(true, "client_secret");
            }
            None => mark(
                set_changed(&mut row.client_secret_sealed, None),
                "client_secret",
            ),
        }
    }
    if let Some(raw) = &body.client_auth {
        mark(
            set_changed(&mut row.client_auth, v::client_auth(raw)?),
            "client_auth",
        );
    }
    if let Some(raw) = &body.scopes {
        mark(set_changed(&mut row.scopes, v::scopes(raw)?), "scopes");
    }
    if let Some(raw) = &body.policy {
        mark(set_changed(&mut row.policy, v::policy(raw)?), "policy");
    }
    if let Some(trust) = body.trust_upstream_mfa {
        mark(
            set_changed(&mut row.trust_upstream_mfa, trust),
            "trust_upstream_mfa",
        );
    }
    if let Some(raw) = &body.mfa_acr {
        let value = raw.as_deref().map(v::mfa_acr).transpose()?;
        mark(set_changed(&mut row.mfa_acr, value), "mfa_acr");
    }
    if let Some(raw) = &body.email_domains {
        mark(
            set_changed(&mut row.email_domains, v::email_domains(raw)?),
            "email_domains",
        );
    }
    if let Some(enabled) = body.enabled {
        mark(set_changed(&mut row.enabled, enabled), "enabled");
    }
    if let Some(visible) = body.visible {
        mark(set_changed(&mut row.visible, visible), "visible");
    }
    Ok(fields)
}

pub fn seal(
    state: &AppState,
    row: &mut identity_providers::ActiveModel,
    tenant_id: Uuid,
    id: Uuid,
    secret: Option<String>,
) -> AppResult<()> {
    if let Some(plain) = secret {
        let plain = zeroize::Zeroizing::new(plain);
        let sealed = idps::seal_secret(&state.config.master_key, tenant_id, id, &plain)?;
        row.client_secret_sealed = Set(Some(sealed));
    }
    Ok(())
}
