//! Bearer authentication for the management API. A token is accepted when
//! it is a valid access token of the host's tenant (signature against the
//! tenant's published keys, or an active opaque token of the tenant), its
//! `tid` is that tenant, and its audience is the tenant's built-in
//! `management-api`. Delegated tokens must carry the `Directory.AccessAsUser`
//! scope; app-only tokens are authorized by their app roles (`authz`).

use std::net::IpAddr;

use anyhow::Context;
use axum::{
    extract::FromRequestParts,
    http::{HeaderMap, request::Parts},
};
use entity::{applications, directory_role_assignments, tenants};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder};
use serde_json::{Map, Value};
use uuid::Uuid;

use crate::{
    app::AppState,
    audit::{self, Actor, EventType, Target},
    authn::{ip::ClientIp, session},
    authz::{self, Access, Area, Principal},
    directory::builtin_apps::{
        MANAGEMENT_API, ROLE_READ_ALL, ROLE_READ_WRITE_ALL, SCOPE_ACCESS_AS_USER,
    },
    error::{AppError, AppResult},
    oidc::bearer,
    tenancy::Tenant,
    tokens::{inspect, principal},
};

/// An authenticated caller of `/api/v1/…` on its tenant's host.
pub struct Caller {
    pub tenant: Tenant,
    pub principal: Principal,
    /// The token's `sid` (delegated tokens): the caller's own session.
    pub session_id: Option<Uuid>,
    pub ip: Option<IpAddr>,
}

impl Caller {
    pub fn tenant_id(&self) -> Uuid {
        self.tenant.id
    }

    pub fn require(&self, area: Area, access: Access) -> AppResult<()> {
        if authz::allows(&self.principal, area, access) {
            Ok(())
        } else {
            Err(AppError::Forbidden(
                "the caller's roles do not allow this operation".into(),
            ))
        }
    }

    pub fn require_global_admin(&self, what: &str) -> AppResult<()> {
        if self.principal.is_global_admin() {
            Ok(())
        } else {
            Err(AppError::Forbidden(format!(
                "only a Global Admin can {what}"
            )))
        }
    }

    /// The signed-in user (`me/…` endpoints are delegated-only).
    pub fn user_id(&self) -> AppResult<Uuid> {
        match &self.principal {
            Principal::User { id, .. } => Ok(*id),
            Principal::App { .. } => Err(AppError::Forbidden(
                "this endpoint needs a delegated (user) token".into(),
            )),
        }
    }

    fn actor(&self) -> Actor {
        match &self.principal {
            Principal::User { id, .. } => Actor::User(Some(*id)),
            Principal::App { id, .. } => Actor::Application(*id),
        }
    }

    /// Records a successful mutation on `conn` (the mutation's transaction).
    pub async fn audit(
        &self,
        conn: &impl ConnectionTrait,
        event_type: EventType,
        target: Option<Target>,
        details: Value,
    ) -> AppResult<()> {
        self.audit_in(conn, self.tenant_id(), event_type, target, details)
            .await
    }

    /// [`Self::audit`] into another tenant's log (tenant management).
    pub async fn audit_in(
        &self,
        conn: &impl ConnectionTrait,
        tenant_id: Uuid,
        event_type: EventType,
        target: Option<Target>,
        details: Value,
    ) -> AppResult<()> {
        audit::record(
            conn,
            audit::Event {
                tenant_id,
                actor: self.actor(),
                event_type,
                target,
                outcome: entity::enums::Outcome::Success,
                ip: self.ip,
                details,
            },
        )
        .await?;
        Ok(())
    }
}

impl FromRequestParts<AppState> for Caller {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let tenant = Tenant::from_request_parts(parts, state).await?;
        let ClientIp(ip) = match ClientIp::from_request_parts(parts, state).await {
            Ok(ip) => ip,
            Err(never) => match never {},
        };
        let (principal, session_id) = authenticate(state, &tenant, &parts.headers).await?;
        Ok(Self {
            tenant,
            principal,
            session_id,
            ip,
        })
    }
}

/// A Global Admin of the system tenant (`/api/v1/tenants`), calling on the
/// system tenant's host; on any other host the resource does not exist.
pub struct SystemAdmin(pub Caller);

impl FromRequestParts<AppState> for SystemAdmin {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, state: &AppState) -> AppResult<Self> {
        let tenant = Tenant::from_request_parts(parts, state).await?;
        if !tenant.is_system {
            return Err(AppError::NotFound);
        }
        let caller = Caller::from_request_parts(parts, state).await?;
        caller.require_global_admin("manage tenants")?;
        Ok(Self(caller))
    }
}

fn claim_str<'a>(claims: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
    claims.get(name).and_then(Value::as_str)
}

/// The management API app of the tenant (the only accepted audience).
async fn management_api_id(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
) -> anyhow::Result<Option<Uuid>> {
    Ok(applications::Entity::find()
        .filter(applications::Column::TenantId.eq(tenant_id))
        .filter(applications::Column::ClientId.eq(MANAGEMENT_API))
        .filter(applications::Column::Builtin.eq(true))
        .one(conn)
        .await
        .context("loading the management API app")?
        .map(|app| app.id))
}

pub async fn directory_roles(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Vec<entity::enums::DirectoryRole>> {
    Ok(directory_role_assignments::Entity::find()
        .filter(directory_role_assignments::Column::TenantId.eq(tenant_id))
        .filter(directory_role_assignments::Column::UserId.eq(user_id))
        .order_by_asc(directory_role_assignments::Column::Role)
        .all(conn)
        .await
        .context("loading directory roles")?
        .into_iter()
        .map(|a| a.role)
        .collect())
}

async fn authenticate(
    state: &AppState,
    tenant: &tenants::Model,
    headers: &HeaderMap,
) -> AppResult<(Principal, Option<Uuid>)> {
    let unauthorized = |msg: &str| AppError::Unauthorized(msg.to_owned());
    let token = bearer(headers).ok_or_else(|| unauthorized("bearer token required"))?;
    let conn = &state.db;
    let issuer = state.config.issuer(&tenant.slug);
    let found = inspect::access_token(conn, tenant.id, &issuer, token)
        .await?
        .ok_or_else(|| unauthorized("token is invalid or expired"))?;
    let claims = &found.claims;
    if claim_str(claims, "tid") != Some(tenant.id.to_string().as_str()) {
        return Err(unauthorized("token was issued for another tenant"));
    }
    let api = management_api_id(conn, tenant.id).await?;
    let Some(api) = api.filter(|id| found.resource_app_id == Some(*id)) else {
        return Err(unauthorized("token audience is not the management API"));
    };
    let session_id = claim_str(claims, "sid").and_then(|s| Uuid::parse_str(s).ok());
    let principal = match claim_str(claims, "idtyp") {
        Some("user") => {
            let id = inspect::user_of(claims).ok_or_else(|| unauthorized("token has no user"))?;
            // A signed-out session (logout, revoked device, password change)
            // takes its management access with it, JWT or not.
            let live = match session_id {
                Some(sid) => session::find_by_id(conn, tenant.id, sid)
                    .await?
                    .is_some_and(|s| s.user_id == id),
                None => false,
            };
            if !live {
                return Err(unauthorized("the token's session has ended"));
            }
            let scopes = claim_str(claims, "scp").unwrap_or_default();
            if !scopes
                .split_ascii_whitespace()
                .any(|s| s == SCOPE_ACCESS_AS_USER)
            {
                return Err(AppError::Forbidden(format!(
                    "the token lacks the {SCOPE_ACCESS_AS_USER} scope"
                )));
            }
            Principal::User {
                id,
                roles: directory_roles(conn, tenant.id, id).await?,
            }
        }
        Some("app") => {
            let id = claim_str(claims, "oid")
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or_else(|| unauthorized("token has no subject"))?;
            // Live, not the token's frozen `roles` claim: a removed
            // assignment (or a deleted app) loses access at once.
            let roles = principal::app_roles(conn, tenant.id, api, id).await?;
            let has = |role: &str| roles.iter().any(|r| r == role);
            Principal::App {
                id,
                read: has(ROLE_READ_ALL),
                write: has(ROLE_READ_WRITE_ALL),
            }
        }
        _ => return Err(unauthorized("unrecognised token type")),
    };
    Ok((principal, session_id))
}
