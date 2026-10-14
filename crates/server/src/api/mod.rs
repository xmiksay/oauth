//! Management REST API `/api/v1` (Graph-like) on each tenant host: the
//! directory of that tenant (`/api/v1/users`, …), the signed-in user's
//! self-service under `/api/v1/me`, and — on the system tenant's host only —
//! tenant management (`/api/v1/tenants`, system Global Admins). Bearer tokens
//! only (no cookies, so no CSRF surface). Contract: `docs/api/management.md`.

mod app_rules;
mod applications;
mod apps_permissions;
mod apps_roles;
mod apps_scopes;
mod apps_secrets;
mod audit_events;
mod auth;
mod consents;
mod directory_roles;
mod extract;
mod groups;
mod guard;
mod me;
mod me_email;
mod me_mfa;
pub mod page;
mod role_assignments;
mod tenants;
mod user_actions;
mod user_invite;
mod users;
pub mod validate;

use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use chrono::{DateTime, FixedOffset, SecondsFormat};
use sea_orm::{ActiveValue, ColumnTrait, sea_query::Condition};

use crate::{
    app::AppState,
    error::{AppError, AppResult},
};

pub use auth::Caller;

const T: &str = "/api/v1";

pub fn router() -> Router<AppState> {
    let app = format!("{T}/applications/{{id}}");
    let me = format!("{T}/me");
    Router::new()
        .route(
            &format!("{T}/tenants"),
            get(tenants::list).post(tenants::create),
        )
        .route(
            &format!("{T}/tenants/{{slug}}"),
            get(tenants::get).patch(tenants::update),
        )
        .route(
            &format!("{T}/settings"),
            get(tenants::get_settings).patch(tenants::update_settings),
        )
        .route(&format!("{T}/users"), get(users::list).post(users::create))
        .route(
            &format!("{T}/users/{{id}}"),
            get(users::get).patch(users::update).delete(users::remove),
        )
        .route(
            &format!("{T}/users/{{id}}/reset-password"),
            post(user_actions::reset_password),
        )
        .route(
            &format!("{T}/users/{{id}}/invite"),
            post(user_invite::resend),
        )
        .route(
            &format!("{T}/users/{{id}}/reset-mfa"),
            post(user_actions::reset_mfa),
        )
        .route(
            &format!("{T}/users/{{id}}/sessions"),
            get(user_actions::sessions),
        )
        .route(
            &format!("{T}/users/{{id}}/revoke-sessions"),
            post(user_actions::revoke_sessions),
        )
        .route(
            &format!("{T}/groups"),
            get(groups::list).post(groups::create),
        )
        .route(
            &format!("{T}/groups/{{id}}"),
            get(groups::get)
                .patch(groups::update)
                .delete(groups::remove),
        )
        .route(
            &format!("{T}/groups/{{id}}/members"),
            get(groups::members).post(groups::add_member),
        )
        .route(
            &format!("{T}/groups/{{id}}/members/{{user_id}}"),
            delete(groups::remove_member),
        )
        .route(
            &format!("{T}/directory-roles"),
            get(directory_roles::list).post(directory_roles::assign),
        )
        .route(
            &format!("{T}/directory-roles/{{id}}"),
            delete(directory_roles::unassign),
        )
        .route(
            &format!("{T}/applications"),
            get(applications::list).post(applications::create),
        )
        .route(
            &app,
            get(applications::get)
                .patch(applications::update)
                .delete(applications::remove),
        )
        .route(
            &format!("{app}/secrets"),
            get(apps_secrets::list).post(apps_secrets::create),
        )
        .route(
            &format!("{app}/secrets/{{secret_id}}"),
            delete(apps_secrets::remove),
        )
        .route(
            &format!("{app}/scopes"),
            get(apps_scopes::list_scopes).post(apps_scopes::create_scope),
        )
        .route(
            &format!("{app}/scopes/{{scope_id}}"),
            patch(apps_scopes::update_scope).delete(apps_scopes::remove_scope),
        )
        .route(
            &format!("{app}/roles"),
            get(apps_roles::list_roles).post(apps_roles::create_role),
        )
        .route(
            &format!("{app}/roles/{{role_id}}"),
            patch(apps_roles::update_role).delete(apps_roles::remove_role),
        )
        .route(
            &format!("{app}/required-permissions"),
            get(apps_permissions::list).post(apps_permissions::create),
        )
        .route(
            &format!("{app}/required-permissions/{{permission_id}}"),
            delete(apps_permissions::remove),
        )
        .route(
            &format!("{T}/role-assignments"),
            get(role_assignments::list).post(role_assignments::create),
        )
        .route(
            &format!("{T}/role-assignments/{{id}}"),
            delete(role_assignments::remove),
        )
        .route(
            &format!("{T}/consents"),
            get(consents::list).post(consents::grant),
        )
        .route(&format!("{T}/consents/{{id}}"), delete(consents::revoke))
        .route(&format!("{T}/audit-events"), get(audit_events::list))
        .route(&me, get(me::get).patch(me::update))
        .route(&format!("{me}/change-password"), post(me::change_password))
        .route(&format!("{me}/email"), post(me_email::change_email))
        .route(
            &format!("{me}/verify-email"),
            post(me_email::send_verification),
        )
        .route(
            &format!("{me}/notifications"),
            get(me_email::notifications).put(me_email::update_notifications),
        )
        .route(
            &format!("{me}/totp"),
            post(me_mfa::begin_totp).delete(me_mfa::remove_totp),
        )
        .route(&format!("{me}/totp/confirm"), post(me_mfa::confirm_totp))
        .route(
            &format!("{me}/recovery-codes"),
            post(me_mfa::regenerate_recovery_codes),
        )
        .route(&format!("{me}/sessions"), get(me::sessions))
        .route(
            &format!("{me}/sessions/revoke-all"),
            post(me::revoke_all_sessions),
        )
        .route(&format!("{me}/sessions/{{id}}"), delete(me::revoke_session))
        .route(&format!("{me}/consents"), get(me::consents))
        .route(&format!("{me}/consents/{{id}}"), delete(me::revoke_consent))
}

/// RFC 3339 UTC timestamp for responses.
pub fn ts(at: &DateTime<FixedOffset>) -> String {
    at.to_utc().to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Case-insensitive substring match of `search` on any of `columns`.
/// `None` when no (or an empty) search was given.
pub fn search<C: ColumnTrait>(search: Option<&str>, columns: &[C]) -> AppResult<Option<Condition>> {
    let Some(text) = search.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(None);
    };
    if text.chars().count() > 256 || text.chars().any(char::is_control) {
        return Err(AppError::BadRequest(
            "search must be at most 256 characters without control characters".into(),
        ));
    }
    let pattern = format!("%{}%", escape_like(text));
    Ok(Some(columns.iter().fold(Condition::any(), |cond, col| {
        cond.add(col.ilike(pattern.as_str()))
    })))
}

/// Sets `slot` to `value` only when that changes what is stored; returns
/// whether it did. PATCH handlers use it so unchanged values sent back are
/// neither written, audited nor subject to change-only rules.
pub fn set_changed<V>(slot: &mut ActiveValue<V>, value: V) -> bool
where
    V: Into<sea_orm::Value> + PartialEq,
{
    if slot.try_as_ref() == Some(&value) {
        return false;
    }
    *slot = ActiveValue::Set(value);
    true
}

/// Escapes LIKE wildcards (Postgres' default escape character is `\`).
fn escape_like(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        if matches!(c, '\\' | '%' | '_') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn like_wildcards_are_escaped() {
        assert_eq!(escape_like(r"50%_off\"), r"50\%\_off\\");
        assert_eq!(escape_like("ann"), "ann");
    }

    #[test]
    fn set_changed_only_marks_real_changes() {
        let mut slot = ActiveValue::Unchanged(5_i32);
        assert!(!set_changed(&mut slot, 5));
        assert!(matches!(slot, ActiveValue::Unchanged(5)));
        assert!(set_changed(&mut slot, 6));
        assert!(matches!(slot, ActiveValue::Set(6)));
        let mut unset: ActiveValue<i32> = ActiveValue::NotSet;
        assert!(set_changed(&mut unset, 1));
    }

    #[test]
    fn timestamps_are_utc_rfc3339() {
        let at = DateTime::parse_from_rfc3339("2026-10-13T12:00:00.5+02:00").unwrap();
        assert_eq!(ts(&at), "2026-10-13T10:00:00.500Z");
    }
}
