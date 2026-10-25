//! `/api/v1/tenants/{slug}/users[/…]` on the system host: a system Global
//! Admin looks up another tenant's users and resets a locked-out user's
//! password or MFA. The tenant's own role protections
//! (`guard::ensure_can_modify_user`) don't apply — the system Global Admin
//! outranks every tenant role. The system tenant itself is managed through
//! its own `/api/v1/users`.

use axum::{
    body::Bytes,
    extract::{State, rejection::BytesRejection},
    http::StatusCode,
};
use entity::{tenants, users as user_entity};
use sea_orm::{ConnectionTrait, TransactionTrait};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use super::{
    Caller,
    auth::SystemAdmin,
    extract::{Path, Query},
    guard::{find_user, lock_user},
    page::Paged,
    tenants::by_slug,
    user_actions::{
        ChosenPassword, Resetter, apply_mfa_reset, apply_password_reset, password_reset_body,
    },
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

/// The body is optional, so it is read raw: `Json` would demand a JSON
/// `Content-Type`, and `Option<Json>` turns a body sent without one into
/// `None`, silently dropping fields that must be refused. Empty (or
/// whitespace) is no fields; anything else must be a JSON object with no
/// fields: the system admin can only issue a generated one-time password, so
/// `password` / `must_change_password` are a 400, not silently ignored. (A
/// fieldless serde struct would also accept `[]`, hence the `Map`.) Errors
/// never echo serde's text: it can quote the value sent, e.g. an intended
/// password.
fn parse_reset_body(body: &[u8]) -> AppResult<()> {
    if body.trim_ascii().is_empty() {
        return Ok(());
    }
    let fields: Map<String, Value> = serde_json::from_slice(body).map_err(|_| {
        AppError::BadRequest("the body must be empty or a JSON object without fields".into())
    })?;
    match fields.keys().next() {
        None => Ok(()),
        Some(field) => Err(AppError::BadRequest(format!(
            "unknown field `{field}`: the password is always generated"
        ))),
    }
}

pub async fn reset_password(
    State(state): State<AppState>,
    SystemAdmin(caller): SystemAdmin,
    Path((slug, id)): Path<(String, Uuid)>,
    body: Result<Bytes, BytesRejection>,
) -> AppResult<axum::Json<Value>> {
    // Taken as a `Result` so a failed read (e.g. too large) keeps the JSON error shape.
    let body = body.map_err(|rejection| AppError::BadRequest(rejection.body_text()))?;
    parse_reset_body(&body)?;
    let chosen = ChosenPassword::new(None, None)?;
    let txn = state.db.begin().await?;
    let tenant = target_tenant(&txn, &slug).await?;
    let user = lock_user(&txn, tenant.id, id).await?;
    let details = apply_password_reset(
        &txn,
        &state.config,
        &tenant,
        &user,
        &chosen,
        Resetter::SystemAdmin,
    )
    .await?;
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
    let details =
        apply_mfa_reset(&txn, &state.config, &tenant, &user, Resetter::SystemAdmin).await?;
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
/// for the target tenant's log (plus `email` and `via: "system_admin"`; the
/// row already names its tenant).
fn cross_tenant_details(
    base: Map<String, Value>,
    tenant: &tenants::Model,
    email: &str,
) -> (Value, Value) {
    let mut theirs = base.clone();
    theirs.insert("email".into(), json!(email));
    theirs.insert("via".into(), json!("system_admin"));
    let mut own = base;
    own.insert("tenant_id".into(), json!(tenant.id));
    own.insert("tenant_slug".into(), json!(tenant.slug));
    own.insert("email".into(), json!(email));
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
    fn reset_body_is_empty_or_a_fieldless_object() {
        for ok in ["", "  \n", "{}", " { } "] {
            assert!(parse_reset_body(ok.as_bytes()).is_ok(), "{ok:?}");
        }
        for bad in [
            r#"{"password":"x"}"#,
            r#"{"must_change_password":false}"#,
            "null",
            "[]",
            "{",
            "password=x",
            r#""Hunter2!""#,
        ] {
            assert!(
                matches!(
                    parse_reset_body(bad.as_bytes()),
                    Err(AppError::BadRequest(_))
                ),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn reset_body_errors_never_quote_values() {
        let message = |body: &str| match parse_reset_body(body.as_bytes()) {
            Err(AppError::BadRequest(msg)) => msg,
            other => format!("not a 400: {other:?}"),
        };
        for bad in [
            r#""Hunter2!""#,
            r#"["Hunter2!"]"#,
            r#"{"password":"Hunter2!"}"#,
            "Hunter2!",
        ] {
            let msg = message(bad);
            assert!(
                !msg.contains("Hunter2") && !msg.starts_with("not a 400"),
                "{bad:?}: {msg}"
            );
        }
        let msg = message(r#"{"password":"x"}"#);
        assert!(msg.contains("`password`"), "{msg}");
    }

    #[test]
    fn system_log_names_the_tenant_target_log_says_via() {
        let t = tenant();
        let base = Map::from_iter([
            ("must_change_password".into(), json!(true)),
            ("generated".into(), json!(true)),
        ]);
        let (own, theirs) = cross_tenant_details(base, &t, "ann@fabrikam.test");
        assert_eq!(
            own,
            json!({
                "must_change_password": true,
                "generated": true,
                "tenant_id": t.id,
                "tenant_slug": "fabrikam",
                "email": "ann@fabrikam.test",
            })
        );
        assert_eq!(
            theirs,
            json!({
                "must_change_password": true,
                "generated": true,
                "email": "ann@fabrikam.test",
                "via": "system_admin",
            })
        );
    }
}
