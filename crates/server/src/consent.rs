//! Consent evaluation (Entra model): a delegated scope of a resource is
//! covered when a user grant or a tenant-wide admin grant (`user_id NULL`)
//! for (client, resource) lists it. Scopes marked `admin_consent_required`
//! can only be covered by an admin; users are never offered them.
//!
//! OIDC scopes (`openid profile email offline_access`) need no consent here:
//! `consent_grants` is keyed by a resource app and these belong to none.

use std::collections::HashSet;

use anyhow::Context;
use entity::{app_scopes, consent_grants};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement, sea_query::Condition,
};
use uuid::Uuid;

#[derive(Debug, PartialEq, Eq)]
pub enum Decision {
    Granted,
    /// The user may approve these scope values.
    NeedsUser(Vec<String>),
    /// These scope values need an administrator's grant first.
    NeedsAdmin(Vec<String>),
}

/// `force` = `prompt=consent`: ask again for every user-consentable scope.
pub fn evaluate(
    requested: &[app_scopes::Model],
    granted: &HashSet<String>,
    force: bool,
) -> Decision {
    let missing: Vec<&app_scopes::Model> = requested
        .iter()
        .filter(|s| !granted.contains(&s.value))
        .collect();
    let admin_only: Vec<String> = missing
        .iter()
        .filter(|s| s.admin_consent_required)
        .map(|s| s.value.clone())
        .collect();
    if !admin_only.is_empty() {
        return Decision::NeedsAdmin(admin_only);
    }
    let ask: Vec<String> = if force {
        requested
            .iter()
            .filter(|s| !s.admin_consent_required)
            .map(|s| s.value.clone())
            .collect()
    } else {
        missing.iter().map(|s| s.value.clone()).collect()
    };
    if ask.is_empty() {
        Decision::Granted
    } else {
        Decision::NeedsUser(ask)
    }
}

/// Union of the user's own grant and the tenant-wide admin grant.
pub async fn granted_scopes(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    client_app_id: Uuid,
    resource_app_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<HashSet<String>> {
    let grants = consent_grants::Entity::find()
        .filter(consent_grants::Column::TenantId.eq(tenant_id))
        .filter(consent_grants::Column::ClientApplicationId.eq(client_app_id))
        .filter(consent_grants::Column::ResourceApplicationId.eq(resource_app_id))
        .filter(
            Condition::any()
                .add(consent_grants::Column::UserId.is_null())
                .add(consent_grants::Column::UserId.eq(user_id)),
        )
        .all(conn)
        .await
        .context("loading consent grants")?;
    Ok(grants.into_iter().flat_map(|g| g.scopes).collect())
}

/// Records a user grant, merging with what the user granted before.
pub async fn store_user_grant(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    client_app_id: Uuid,
    resource_app_id: Uuid,
    user_id: Uuid,
    scopes: &[String],
) -> anyhow::Result<()> {
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        r"INSERT INTO consent_grants
              (id, tenant_id, client_application_id, resource_application_id, user_id, scopes)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (client_application_id, resource_application_id, user_id) DO UPDATE
          SET scopes = ARRAY(
                  SELECT DISTINCT unnest(consent_grants.scopes || EXCLUDED.scopes) ORDER BY 1),
              updated_at = now()",
        [
            Uuid::now_v7().into(),
            tenant_id.into(),
            client_app_id.into(),
            resource_app_id.into(),
            user_id.into(),
            scopes.to_vec().into(),
        ],
    ))
    .await
    .context("storing consent grant")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(value: &str, admin: bool) -> app_scopes::Model {
        app_scopes::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            application_id: Uuid::nil(),
            value: value.into(),
            description: String::new(),
            admin_consent_required: admin,
            created_at: chrono::Utc::now().fixed_offset(),
        }
    }

    fn granted(values: &[&str]) -> HashSet<String> {
        values.iter().map(|v| (*v).to_owned()).collect()
    }

    #[test]
    fn covered_scopes_are_granted() {
        let req = [scope("read", false), scope("admin", true)];
        assert_eq!(
            evaluate(&req, &granted(&["read", "admin"]), false),
            Decision::Granted
        );
        assert_eq!(evaluate(&[], &granted(&[]), true), Decision::Granted);
    }

    #[test]
    fn missing_user_scopes_are_asked() {
        let req = [scope("read", false), scope("write", false)];
        assert_eq!(
            evaluate(&req, &granted(&["read"]), false),
            Decision::NeedsUser(vec!["write".into()])
        );
    }

    #[test]
    fn missing_admin_scope_blocks_even_if_user_scopes_missing() {
        let req = [scope("read", false), scope("admin", true)];
        assert_eq!(
            evaluate(&req, &granted(&[]), false),
            Decision::NeedsAdmin(vec!["admin".into()])
        );
    }

    #[test]
    fn prompt_consent_asks_again_for_user_scopes_only() {
        let req = [scope("read", false), scope("admin", true)];
        assert_eq!(
            evaluate(&req, &granted(&["read", "admin"]), true),
            Decision::NeedsUser(vec!["read".into()])
        );
        // Nothing user-consentable: nothing to ask.
        assert_eq!(
            evaluate(&[scope("admin", true)], &granted(&["admin"]), true),
            Decision::Granted
        );
    }
}
