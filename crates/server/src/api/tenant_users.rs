//! `/api/v1/tenants/{slug}/users[/…]` on the system host: a system Global
//! Admin looks up another tenant's users and resets a locked-out user's
//! password or MFA. The tenant's own role protections
//! (`guard::ensure_can_modify_user`) don't apply — the system Global Admin
//! outranks every tenant role. The system tenant itself is managed through
//! its own `/api/v1/users`.

use axum::{extract::State, http::StatusCode};
use entity::{tenants, users as user_entity};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde::Deserialize;
use serde_json::{Map, Value, json};
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
    audit::{EventType, Target},
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

/// Deliberately empty: the system admin can only issue a one-time password,
/// and `deny_unknown_fields` rejects `password` / `must_change_password`
/// with a 400 instead of silently ignoring them.
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
        &user,
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
    audit_both(
        &txn,
        &caller,
        &tenant,
        EventType::UserMfaReset,
        &user,
        details,
    )
    .await?;
    txn.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Records the event in the system tenant's log and in the target tenant's
/// (actor: the system admin in both, as `tenants::update` does), on the
/// mutation's transaction.
async fn audit_both(
    txn: &impl ConnectionTrait,
    caller: &Caller,
    tenant: &tenants::Model,
    event_type: EventType,
    user: &user_entity::Model,
    details: Map<String, Value>,
) -> AppResult<()> {
    let (own, theirs) = cross_tenant_details(details, tenant, &user.email);
    let target = Some(Target::User(user.id));
    caller.audit(txn, event_type, target, own).await?;
    caller
        .audit_in(txn, tenant.id, event_type, target, theirs)
        .await
}

/// `details` for the system tenant's log (plus the target tenant and the
/// user's `email`: that log can't resolve a foreign tenant's user id) and
/// for the target tenant's log (the same plus `via: "system_admin"`).
fn cross_tenant_details(
    mut own: Map<String, Value>,
    tenant: &tenants::Model,
    email: &str,
) -> (Value, Value) {
    own.insert("tenant_id".into(), json!(tenant.id));
    own.insert("tenant_slug".into(), json!(tenant.slug));
    own.insert("email".into(), json!(email));
    let mut theirs = own.clone();
    theirs.insert("via".into(), json!("system_admin"));
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
    fn details_name_the_tenant_and_user_and_via_only_in_the_target_log() {
        let t = tenant();
        let base = Map::from_iter([
            ("must_change_password".into(), json!(true)),
            ("generated".into(), json!(true)),
        ]);
        let (own, theirs) = cross_tenant_details(base, &t, "ann@fabrikam.test");
        let expected = json!({
            "must_change_password": true,
            "generated": true,
            "tenant_id": t.id,
            "tenant_slug": "fabrikam",
            "email": "ann@fabrikam.test",
        });
        assert_eq!(own, expected);
        let mut with_via = expected;
        with_via["via"] = json!("system_admin");
        assert_eq!(theirs, with_via);
    }
}
