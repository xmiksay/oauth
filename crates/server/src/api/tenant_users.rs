//! `/api/v1/tenants/{slug}/users[/…]` on the system host: a system Global
//! Admin looks up another tenant's users and resets a locked-out user's
//! password or MFA. The tenant's own role protections
//! (`guard::ensure_can_modify_user`) don't apply — the system Global Admin
//! outranks every tenant role. The system tenant itself is managed through
//! its own `/api/v1/users`.

use axum::{extract::State, http::StatusCode};
use entity::{enums::Outcome, tenants};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Deserialize;
use serde_json::{Value, json};
use uuid::Uuid;

use super::{
    Caller,
    auth::SystemAdmin,
    extract::{Json, Path, Query},
    guard::{find_user, lock_user},
    page::Paged,
    tenants::by_slug,
    user_actions::{ChosenPassword, apply_mfa_reset, apply_password_reset, password_reset_body},
    users::{self, ListQuery},
};
use crate::{
    app::AppState,
    audit::{self, Actor, EventType, Target},
    error::{AppError, AppResult},
};

/// The tenant `slug` names: unknown → 404, the system tenant → 400.
/// Disabled tenants are allowed (their admins may be why it was disabled).
async fn target_tenant(conn: &impl ConnectionTrait, slug: &str) -> AppResult<tenants::Model> {
    let tenant = by_slug(conn, slug).await?;
    if tenant.is_system {
        return Err(AppError::BadRequest(
            "manage the system tenant's users through /api/v1/users".into(),
        ));
    }
    Ok(tenant)
}

pub async fn list(
    State(state): State<AppState>,
    _admin: SystemAdmin,
    Path(slug): Path<String>,
    Query(q): Query<ListQuery>,
) -> AppResult<Paged<Value>> {
    let tenant = target_tenant(&state.db, &slug).await?;
    users::page_of(&state.db, tenant.id, &q).await
}

pub async fn get(
    State(state): State<AppState>,
    _admin: SystemAdmin,
    Path((slug, id)): Path<(String, Uuid)>,
) -> AppResult<axum::Json<Value>> {
    let tenant = target_tenant(&state.db, &slug).await?;
    let user = find_user(&state.db, tenant.id, id).await?;
    Ok(axum::Json(users::full_view(&state.db, &user).await?))
}

/// No fields: the system admin can only issue a one-time password.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResetPassword {}

pub async fn reset_password(
    State(state): State<AppState>,
    SystemAdmin(caller): SystemAdmin,
    Path((slug, id)): Path<(String, Uuid)>,
    Json(ResetPassword {}): Json<ResetPassword>,
) -> AppResult<axum::Json<Value>> {
    let chosen = ChosenPassword::new(None, None)?;
    let txn = state.db.begin().await?;
    let tenant = target_tenant(&txn, &slug).await?;
    let user = lock_user(&txn, tenant.id, id).await?;
    let details = apply_password_reset(&txn, &state.config, &tenant, &user, &chosen).await?;
    audit_both(
        &txn,
        &caller,
        &tenant,
        EventType::UserPasswordReset,
        id,
        details,
    )
    .await?;
    txn.commit().await?;
    Ok(password_reset_body(&chosen))
}

pub async fn reset_mfa(
    State(state): State<AppState>,
    SystemAdmin(caller): SystemAdmin,
    Path((slug, id)): Path<(String, Uuid)>,
) -> AppResult<StatusCode> {
    let txn = state.db.begin().await?;
    let tenant = target_tenant(&txn, &slug).await?;
    let user = lock_user(&txn, tenant.id, id).await?;
    let details = apply_mfa_reset(&txn, &state.config, &tenant, &user).await?;
    audit_both(&txn, &caller, &tenant, EventType::UserMfaReset, id, details).await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Records the event in the system tenant's log (actor: the system admin)
/// and in the target tenant's (actor: `system`, since an `actor_id` there
/// must not name another tenant's user), on the mutation's transaction.
async fn audit_both(
    txn: &impl ConnectionTrait,
    caller: &Caller,
    tenant: &tenants::Model,
    event_type: EventType,
    user_id: Uuid,
    details: Value,
) -> AppResult<()> {
    let (own, theirs) = cross_tenant_details(details, tenant, caller.user_id()?);
    let target = Some(Target::User(user_id));
    caller.audit(txn, event_type, target, own).await?;
    let event = audit::Event {
        tenant_id: tenant.id,
        actor: Actor::System,
        event_type,
        target,
        outcome: Outcome::Success,
        ip: caller.ip,
        details: theirs,
    };
    audit::record(txn, event).await?;
    Ok(())
}

/// `details` for the system tenant's log (plus the target tenant) and for
/// the target tenant's log (plus who did it, by id).
fn cross_tenant_details(
    details: Value,
    tenant: &tenants::Model,
    system_admin_id: Uuid,
) -> (Value, Value) {
    let mut own = match details {
        Value::Object(map) => map,
        _ => serde_json::Map::new(),
    };
    own.insert("tenant_id".into(), json!(tenant.id));
    own.insert("tenant_slug".into(), json!(tenant.slug));
    let mut theirs = own.clone();
    theirs.insert("via".into(), json!("system_admin"));
    theirs.insert("system_admin_id".into(), json!(system_admin_id));
    (Value::Object(own), Value::Object(theirs))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tenant() -> tenants::Model {
        let now = chrono::Utc::now().fixed_offset();
        tenants::Model {
            id: Uuid::now_v7(),
            slug: "fabrikam".into(),
            display_name: "Fabrikam".into(),
            is_system: false,
            disabled: false,
            audit_retention_days: 90,
            created_at: now,
            updated_at: now,
        }
    }

    #[test]
    fn details_name_the_tenant_and_the_admin_only_in_the_target_log() {
        let t = tenant();
        let admin = Uuid::now_v7();
        let base = json!({ "must_change_password": true, "generated": true });
        let (own, theirs) = cross_tenant_details(base, &t, admin);
        assert_eq!(
            own,
            json!({
                "must_change_password": true,
                "generated": true,
                "tenant_id": t.id,
                "tenant_slug": "fabrikam",
            })
        );
        assert_eq!(
            theirs,
            json!({
                "must_change_password": true,
                "generated": true,
                "tenant_id": t.id,
                "tenant_slug": "fabrikam",
                "via": "system_admin",
                "system_admin_id": admin,
            })
        );
    }

    #[test]
    fn non_object_details_start_empty() {
        let t = tenant();
        let (own, _) = cross_tenant_details(Value::Null, &t, Uuid::nil());
        assert_eq!(own, json!({ "tenant_id": t.id, "tenant_slug": "fabrikam" }));
    }
}
