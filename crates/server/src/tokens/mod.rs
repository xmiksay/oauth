//! Token issuance. The access token's shape follows the RESOURCE app
//! (`access_token_format`, `signing_alg`, `access_token_ttl_secs`); the ID
//! token follows the CLIENT app's `signing_alg`. Requests with OIDC scopes
//! only get a JWT (RS256, 1 h) whose audience is the userinfo endpoint.

pub mod claims;
pub mod code;
pub mod inspect;
pub mod jwt;
pub mod opaque;
pub mod principal;
pub mod refresh;

use axum::{
    Json,
    response::{IntoResponse, Response},
};
use chrono::{DateTime, Duration, FixedOffset};
use entity::{
    applications,
    enums::{AccessTokenFormat, SigningAlg},
    tenants, users,
};
use sea_orm::ConnectionTrait;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::oidc::{error::no_store, scope};
use claims::{AccessInput, IdTokenInput, UserContext};

/// TTL of ID tokens and of OIDC-only access tokens.
pub const DEFAULT_TTL_SECS: i64 = 3600;

/// Audience of access tokens requested with OIDC scopes only.
pub fn userinfo_audience(issuer: &str) -> String {
    format!("{issuer}/oauth2/userinfo")
}

pub struct TokenSet {
    pub access_token: String,
    pub expires_in: i64,
    pub scope: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub format: AccessTokenFormat,
}

impl IntoResponse for TokenSet {
    fn into_response(self) -> Response {
        let mut body = json!({
            "access_token": self.access_token,
            "token_type": "Bearer",
            "expires_in": self.expires_in,
            "scope": self.scope,
        });
        if let Some(obj) = body.as_object_mut() {
            if let Some(id_token) = self.id_token {
                obj.insert("id_token".into(), id_token.into());
            }
            if let Some(refresh) = self.refresh_token {
                obj.insert("refresh_token".into(), refresh.into());
            }
        }
        no_store(Json(body).into_response())
    }
}

pub fn format_label(format: AccessTokenFormat) -> &'static str {
    match format {
        AccessTokenFormat::Jwt => "jwt",
        AccessTokenFormat::Opaque => "opaque",
    }
}

struct AccessSpec {
    audience: String,
    format: AccessTokenFormat,
    alg: SigningAlg,
    ttl: i64,
}

fn access_spec(issuer: &str, resource: Option<&applications::Model>) -> AccessSpec {
    match resource {
        Some(r) => AccessSpec {
            audience: scope::audience(r),
            format: r.access_token_format,
            alg: r.signing_alg,
            ttl: i64::from(r.access_token_ttl_secs),
        },
        None => AccessSpec {
            audience: userinfo_audience(issuer),
            format: AccessTokenFormat::Jwt,
            alg: SigningAlg::Rs256,
            ttl: DEFAULT_TTL_SECS,
        },
    }
}

struct Mint<'a> {
    tenant_id: Uuid,
    spec: &'a AccessSpec,
    claims: &'a Map<String, Value>,
    client_app_id: Uuid,
    resource_app_id: Option<Uuid>,
    user_id: Option<Uuid>,
    links: opaque::Links,
    expires_at: DateTime<FixedOffset>,
}

async fn mint_access(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    m: Mint<'_>,
) -> anyhow::Result<String> {
    match m.spec.format {
        AccessTokenFormat::Jwt => {
            jwt::sign(
                conn,
                master_key,
                m.tenant_id,
                m.spec.alg,
                jwt::TYP_ACCESS_TOKEN,
                m.claims,
            )
            .await
        }
        AccessTokenFormat::Opaque => {
            let new = opaque::NewOpaque {
                tenant_id: m.tenant_id,
                client_app_id: m.client_app_id,
                resource_app_id: m.resource_app_id,
                user_id: m.user_id,
                links: m.links,
                claims: m.claims,
                expires_at: m.expires_at,
            };
            opaque::issue(conn, new).await
        }
    }
}

/// A refresh token to issue alongside: a new family, or the next link of an
/// existing one (whose absolute expiry it inherits).
pub struct Refresh {
    pub family_id: Uuid,
    pub expires_at: DateTime<FixedOffset>,
    /// The grant's full scopes (a down-scoped refresh keeps the original).
    pub scopes: Vec<String>,
    /// The grant's resource — kept even when this access token was narrowed
    /// to OIDC scopes only, so the next refresh can widen back.
    pub resource_app_id: Option<Uuid>,
}

pub struct Delegated<'a> {
    pub tenant: &'a tenants::Model,
    pub issuer: &'a str,
    pub client: &'a applications::Model,
    pub user: &'a users::Model,
    pub session_id: Uuid,
    pub amr: &'a [String],
    pub auth_time: DateTime<FixedOffset>,
    pub nonce: Option<&'a str>,
    pub oidc_scopes: &'a [String],
    pub resource: Option<&'a applications::Model>,
    pub resource_scopes: &'a [String],
    pub authorization_code_id: Option<Uuid>,
    pub refresh: Option<Refresh>,
}

pub async fn issue_delegated(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    d: Delegated<'_>,
) -> anyhow::Result<TokenSet> {
    let now = chrono::Utc::now().fixed_offset();
    let spec = access_spec(d.issuer, d.resource);
    let groups = principal::user_groups(conn, d.tenant.id, d.user.id).await?;
    let roles = match d.resource {
        Some(r) => principal::user_roles(conn, d.tenant.id, r.id, d.user.id, &groups).await?,
        None => Vec::new(),
    };
    let user_ctx = || UserContext {
        user: d.user,
        session_id: d.session_id,
        amr: d.amr,
        auth_time: d.auth_time.timestamp(),
    };
    let expires_at = now + Duration::seconds(spec.ttl);
    let access_claims = claims::access_token(&AccessInput {
        issuer: d.issuer,
        tenant_id: d.tenant.id,
        audience: &spec.audience,
        client_id: &d.client.client_id,
        user: Some(user_ctx()),
        client_object_id: d.client.id,
        scopes: if d.resource.is_some() {
            d.resource_scopes
        } else {
            d.oidc_scopes
        },
        roles: &roles,
        groups: &groups,
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        jti: Uuid::now_v7(),
    });
    let links = opaque::Links {
        authorization_code_id: d.authorization_code_id,
        family_id: d.refresh.as_ref().map(|r| r.family_id),
    };
    let access_token = mint_access(
        conn,
        master_key,
        Mint {
            tenant_id: d.tenant.id,
            spec: &spec,
            claims: &access_claims,
            client_app_id: d.client.id,
            resource_app_id: d.resource.map(|r| r.id),
            user_id: Some(d.user.id),
            links,
            expires_at,
        },
    )
    .await?;

    let id_token = if d.oidc_scopes.iter().any(|s| s == "openid") {
        let id_claims = claims::id_token(&IdTokenInput {
            issuer: d.issuer,
            tenant_id: d.tenant.id,
            client_id: &d.client.client_id,
            user: user_ctx(),
            nonce: d.nonce,
            oidc_scopes: d.oidc_scopes,
            access_token: &access_token,
            iat: now.timestamp(),
            exp: (now + Duration::seconds(DEFAULT_TTL_SECS)).timestamp(),
        });
        let alg = d.client.signing_alg;
        Some(
            jwt::sign(
                conn,
                master_key,
                d.tenant.id,
                alg,
                jwt::TYP_ID_TOKEN,
                &id_claims,
            )
            .await?,
        )
    } else {
        None
    };

    let refresh_token = match &d.refresh {
        Some(r) => Some(
            refresh::issue(
                conn,
                refresh::NewRefresh {
                    tenant_id: d.tenant.id,
                    family_id: r.family_id,
                    client_app_id: d.client.id,
                    user_id: d.user.id,
                    session_id: d.session_id,
                    authorization_code_id: d.authorization_code_id,
                    scopes: &r.scopes,
                    resource_app_id: r.resource_app_id,
                    amr: d.amr,
                    auth_time: d.auth_time,
                    expires_at: r.expires_at,
                },
            )
            .await?,
        ),
        None => None,
    };

    let audience = d.resource.map(|_| spec.audience.as_str());
    Ok(TokenSet {
        access_token,
        expires_in: spec.ttl,
        scope: scope::granted_string(d.oidc_scopes, audience, d.resource_scopes),
        id_token,
        refresh_token,
        format: spec.format,
    })
}

/// Client credentials: roles from the client's application permissions.
pub async fn issue_app_only(
    conn: &impl ConnectionTrait,
    master_key: &[u8; 32],
    tenant: &tenants::Model,
    issuer: &str,
    client: &applications::Model,
    resource: &applications::Model,
) -> anyhow::Result<TokenSet> {
    let now = chrono::Utc::now().fixed_offset();
    let spec = access_spec(issuer, Some(resource));
    let roles = principal::app_roles(conn, tenant.id, resource.id, client.id).await?;
    let expires_at = now + Duration::seconds(spec.ttl);
    let access_claims = claims::access_token(&AccessInput {
        issuer,
        tenant_id: tenant.id,
        audience: &spec.audience,
        client_id: &client.client_id,
        user: None,
        client_object_id: client.id,
        scopes: &[],
        roles: &roles,
        groups: &[],
        iat: now.timestamp(),
        exp: expires_at.timestamp(),
        jti: Uuid::now_v7(),
    });
    let access_token = mint_access(
        conn,
        master_key,
        Mint {
            tenant_id: tenant.id,
            spec: &spec,
            claims: &access_claims,
            client_app_id: client.id,
            resource_app_id: Some(resource.id),
            user_id: None,
            links: opaque::Links::default(),
            expires_at,
        },
    )
    .await?;
    Ok(TokenSet {
        access_token,
        expires_in: spec.ttl,
        scope: format!("{}/{}", spec.audience, scope::DEFAULT),
        id_token: None,
        refresh_token: None,
        format: spec.format,
    })
}
