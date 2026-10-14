//! Append-only audit log (`audit_events`). Mutations record their event on
//! the connection / transaction that performs them, so an event exists iff
//! the change committed. Details never carry secrets, passwords or tokens —
//! only ids, names and changed field names.

use std::net::IpAddr;

use anyhow::Context;
use entity::{
    audit_events,
    enums::{ActorType, Outcome},
};
use sea_orm::{ActiveValue::Set, ConnectionTrait, EntityTrait};
use serde_json::Value;
use uuid::Uuid;

macro_rules! event_types {
    ($($variant:ident => $name:literal,)+) => {
        /// Closed set of audited event types (wire / DB names via [`Self::as_str`]).
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        pub enum EventType { $($variant,)+ }

        impl EventType {
            pub const ALL: &[Self] = &[$(Self::$variant,)+];

            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $name,)+ }
            }
        }
    };
}

event_types! {
    SignIn => "sign_in",
    TokenRefreshReuse => "token.refresh_reuse",
    TokenCodeReplay => "token.code_replay",
    TenantCreate => "tenant.create",
    TenantUpdate => "tenant.update",
    UserCreate => "user.create",
    UserUpdate => "user.update",
    UserDelete => "user.delete",
    UserPasswordReset => "user.password_reset",
    UserPasswordChange => "user.password_change",
    UserMfaReset => "user.mfa_reset",
    UserSessionsRevoke => "user.sessions_revoke",
    UserSessionRevoke => "user.session_revoke",
    UserProfileUpdate => "user.profile_update",
    MfaTotpEnroll => "user.mfa.totp_enroll",
    MfaTotpRemove => "user.mfa.totp_remove",
    MfaRecoveryCodesRegenerate => "user.mfa.recovery_codes_regenerate",
    EmailVerifyRequest => "user.email_verify_request",
    EmailVerify => "user.email_verify",
    PasswordResetRequest => "user.password_reset_request",
    PasswordResetComplete => "user.password_reset_complete",
    UserInvite => "user.invite",
    UserInviteAccept => "user.invite_accept",
    EmailChangeRequest => "user.email_change_request",
    EmailChangeComplete => "user.email_change_complete",
    NotificationPrefsUpdate => "user.notification_prefs_update",
    GroupCreate => "group.create",
    GroupUpdate => "group.update",
    GroupDelete => "group.delete",
    GroupMemberAdd => "group.member_add",
    GroupMemberRemove => "group.member_remove",
    DirectoryRoleAssign => "directory_role.assign",
    DirectoryRoleUnassign => "directory_role.unassign",
    ApplicationCreate => "application.create",
    ApplicationUpdate => "application.update",
    ApplicationDelete => "application.delete",
    ApplicationSecretAdd => "application.secret_add",
    ApplicationSecretRemove => "application.secret_remove",
    ApplicationScopeAdd => "application.scope_add",
    ApplicationScopeUpdate => "application.scope_update",
    ApplicationScopeRemove => "application.scope_remove",
    ApplicationRoleAdd => "application.role_add",
    ApplicationRoleUpdate => "application.role_update",
    ApplicationRoleRemove => "application.role_remove",
    ApplicationPermissionAdd => "application.permission_add",
    ApplicationPermissionRemove => "application.permission_remove",
    RoleAssignmentCreate => "app_role_assignment.create",
    RoleAssignmentDelete => "app_role_assignment.delete",
    ConsentGrant => "consent.grant",
    ConsentRevoke => "consent.revoke",
}

/// The object an event is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Target {
    Tenant(Uuid),
    User(Uuid),
    Group(Uuid),
    Application(Uuid),
    DirectoryRoleAssignment(Uuid),
    AppRoleAssignment(Uuid),
    ConsentGrant(Uuid),
}

impl Target {
    fn parts(self) -> (&'static str, Uuid) {
        match self {
            Self::Tenant(id) => ("tenant", id),
            Self::User(id) => ("user", id),
            Self::Group(id) => ("group", id),
            Self::Application(id) => ("application", id),
            Self::DirectoryRoleAssignment(id) => ("directory_role_assignment", id),
            Self::AppRoleAssignment(id) => ("app_role_assignment", id),
            Self::ConsentGrant(id) => ("consent_grant", id),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Actor {
    /// `None`: anonymous — a sign-in attempt for an account that doesn't
    /// exist, or a password-reset request (whoever sent it).
    User(Option<Uuid>),
    Application(Uuid),
    System,
}

pub struct Event {
    pub tenant_id: Uuid,
    pub actor: Actor,
    pub event_type: EventType,
    pub target: Option<Target>,
    pub outcome: Outcome,
    pub ip: Option<IpAddr>,
    /// A JSON object; `Value::Null` stores `{}`.
    pub details: Value,
}

pub async fn record(conn: &impl ConnectionTrait, event: Event) -> anyhow::Result<()> {
    let (actor_type, actor_id) = match event.actor {
        Actor::User(id) => (ActorType::User, id),
        Actor::Application(id) => (ActorType::Application, Some(id)),
        Actor::System => (ActorType::System, None),
    };
    let target = event.target.map(Target::parts);
    let details = match event.details {
        Value::Null => Value::Object(serde_json::Map::new()),
        other => other,
    };
    let row = audit_events::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(event.tenant_id),
        at: Set(chrono::Utc::now().fixed_offset()),
        actor_type: Set(actor_type),
        actor_id: Set(actor_id),
        event_type: Set(event.event_type.as_str().to_owned()),
        target_type: Set(target.map(|(kind, _)| kind.to_owned())),
        target_id: Set(target.map(|(_, id)| id)),
        outcome: Set(event.outcome),
        ip: Set(event.ip.map(|ip| ip.to_string())),
        details: Set(details),
    };
    audit_events::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("writing audit event")?;
    Ok(())
}

/// A replayed refresh token or authorization code: presented by the client
/// (actor) on behalf of the user (target); always a failure.
pub async fn token_replay(
    conn: &impl ConnectionTrait,
    event_type: EventType,
    tenant_id: Uuid,
    client_app_id: Uuid,
    user_id: Uuid,
    ip: Option<IpAddr>,
    details: Value,
) -> anyhow::Result<()> {
    record(
        conn,
        Event {
            tenant_id,
            actor: Actor::Application(client_app_id),
            event_type,
            target: Some(Target::User(user_id)),
            outcome: Outcome::Failure,
            ip,
            details,
        },
    )
    .await
}

/// Deletes events older than their tenant's `audit_retention_days`.
pub async fn sweep(conn: &impl ConnectionTrait) -> anyhow::Result<u64> {
    let result = conn
        .execute_unprepared(
            "DELETE FROM audit_events a USING tenants t \
             WHERE a.tenant_id = t.id \
               AND a.at < now() - make_interval(days => t.audit_retention_days)",
        )
        .await
        .context("sweeping audit events")?;
    Ok(result.rows_affected())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Mirrors the DB CHECK on `audit_events.event_type`.
    fn shape_ok(name: &str) -> bool {
        name.split('.').all(|part| {
            !part.is_empty() && part.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
        })
    }

    #[test]
    fn event_type_names_are_unique_and_match_the_db_check() {
        let mut seen = std::collections::HashSet::new();
        for event in EventType::ALL {
            let name = event.as_str();
            assert!(shape_ok(name), "{name}");
            assert!(seen.insert(name), "duplicate {name}");
        }
    }

    #[test]
    fn target_types_match_the_db_check() {
        let id = Uuid::nil();
        for target in [
            Target::Tenant(id),
            Target::User(id),
            Target::Group(id),
            Target::Application(id),
            Target::DirectoryRoleAssignment(id),
            Target::AppRoleAssignment(id),
            Target::ConsentGrant(id),
        ] {
            let (kind, _) = target.parts();
            assert!(
                kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "{kind}"
            );
        }
    }
}
