//! Consent evaluation of a pending request, shared by `oidc::authorize`,
//! the login steps and the device-code page.

use anyhow::Context;
use entity::{app_scopes, applications};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::{
    consent::{self, Decision},
    oidc::params::{AuthRequest, Prompt},
};

pub fn force_consent(req: &AuthRequest) -> bool {
    req.prompt == Some(Prompt::Consent)
}

pub struct ConsentEval {
    pub decision: Decision,
    /// The requested scopes of the resource.
    pub scopes: Vec<app_scopes::Model>,
}

/// The resource app a pending request names (`req.resource_id`), loaded
/// once per step and shared by the assignment and consent checks.
pub async fn pending_resource(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    resource_id: Option<Uuid>,
) -> anyhow::Result<Option<applications::Model>> {
    let Some(resource_id) = resource_id else {
        return Ok(None);
    };
    let resource = applications::Entity::find_by_id(resource_id)
        .filter(applications::Column::TenantId.eq(client.tenant_id))
        .one(conn)
        .await
        .context("loading resource app")?
        .context("resource app of a pending request vanished")?;
    Ok(Some(resource))
}

/// Consent state of `req` (whose resource is `resource`, from
/// [`pending_resource`]) for `user_id`. Built-in clients are pre-consented.
pub async fn evaluate_consent(
    conn: &impl ConnectionTrait,
    client: &applications::Model,
    req: &AuthRequest,
    resource: Option<&applications::Model>,
    user_id: Uuid,
    force: bool,
) -> anyhow::Result<ConsentEval> {
    let Some(resource) = resource else {
        return Ok(ConsentEval {
            decision: Decision::Granted,
            scopes: Vec::new(),
        });
    };
    let scopes = app_scopes::Entity::find()
        .filter(app_scopes::Column::ApplicationId.eq(resource.id))
        .filter(app_scopes::Column::Value.is_in(req.resource_scopes.clone()))
        .all(conn)
        .await
        .context("loading requested scopes")?;
    let decision = if client.builtin {
        Decision::Granted
    } else {
        let granted =
            consent::granted_scopes(conn, client.tenant_id, client.id, resource.id, user_id)
                .await?;
        consent::evaluate(&scopes, &granted, force)
    };
    Ok(ConsentEval { decision, scopes })
}
