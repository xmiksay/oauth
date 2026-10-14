//! Security notices to the user (password / MFA / email changes, new
//! sign-ins, refresh-token reuse). Opt-out per event and channel
//! (`notification_prefs`, no row = on); queued on the caller's
//! transaction like every outbox message. Email goes only to a verified
//! address (for an email change: the OLD one, if it was verified).

use anyhow::Context;
use chrono::Duration;
use entity::{
    enums::{Channel, NotifyEvent},
    notification_prefs, tenants, users,
};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::OnConflict,
};
use uuid::Uuid;

use crate::{
    config::Config,
    mail::{
        outbox::{self, NewMessage},
        templates::{self, Ctx},
    },
};

pub const EVENTS: [NotifyEvent; 5] = [
    NotifyEvent::PasswordChanged,
    NotifyEvent::MfaChanged,
    NotifyEvent::EmailChanged,
    NotifyEvent::NewSignIn,
    NotifyEvent::TokenReuse,
];

/// A notice nobody received within a day is stale.
const NOTICE_TTL_HOURS: i64 = 24;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pref {
    pub event: NotifyEvent,
    pub email: bool,
    pub telegram: bool,
}

/// The user's preference for every event (defaults filled in).
pub async fn prefs(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Vec<Pref>> {
    let rows = notification_prefs::Entity::find()
        .filter(notification_prefs::Column::TenantId.eq(tenant_id))
        .filter(notification_prefs::Column::UserId.eq(user_id))
        .all(conn)
        .await
        .context("loading notification preferences")?;
    Ok(EVENTS
        .iter()
        .map(|&event| {
            rows.iter().find(|r| r.event == event).map_or(
                Pref {
                    event,
                    email: true,
                    telegram: true,
                },
                |r| Pref {
                    event,
                    email: r.email,
                    telegram: r.telegram,
                },
            )
        })
        .collect())
}

pub async fn set_prefs(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    prefs: &[Pref],
) -> anyhow::Result<()> {
    use notification_prefs::Column;
    let now = chrono::Utc::now().fixed_offset();
    let rows = prefs.iter().map(|p| notification_prefs::ActiveModel {
        tenant_id: Set(tenant_id),
        user_id: Set(user_id),
        event: Set(p.event),
        email: Set(p.email),
        telegram: Set(p.telegram),
        updated_at: Set(now),
    });
    notification_prefs::Entity::insert_many(rows)
        .on_conflict(
            OnConflict::columns([Column::TenantId, Column::UserId, Column::Event])
                .update_columns([Column::Email, Column::Telegram, Column::UpdatedAt])
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .context("storing notification preferences")?;
    Ok(())
}

async fn email_wanted(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    event: NotifyEvent,
) -> anyhow::Result<bool> {
    let row = notification_prefs::Entity::find_by_id((tenant_id, user_id, event))
        .one(conn)
        .await
        .context("loading notification preference")?;
    Ok(row.is_none_or(|r| r.email))
}

async fn deliver(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
    to: &str,
    event: NotifyEvent,
    facts: &[(&str, String)],
) -> anyhow::Result<()> {
    if !config.email_enabled() || !email_wanted(conn, tenant.id, user.id, event).await? {
        return Ok(());
    }
    let ctx = Ctx {
        tenant_name: &tenant.display_name,
        user_name: &user.display_name,
        user_email: &user.email,
    };
    let account_url = format!("{}/myaccount", config.tenant_origin(&tenant.slug));
    let rendered = templates::notice(&ctx, event, facts, &account_url);
    outbox::enqueue(
        conn,
        &config.master_key,
        NewMessage {
            tenant_id: tenant.id,
            channel: Channel::Email,
            recipient: to,
            rendered: &rendered,
            ttl: Duration::hours(NOTICE_TTL_HOURS),
        },
    )
    .await
}

/// Notifies `user` (at their address, if verified) of `event`.
pub async fn event(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
    event: NotifyEvent,
    facts: &[(&str, String)],
) -> anyhow::Result<()> {
    if !user.email_verified {
        return Ok(());
    }
    deliver(conn, config, tenant, user, &user.email, event, facts).await
}

/// The address a user had before an email change.
#[derive(Clone, Copy)]
pub struct OldAddress<'a> {
    pub email: &'a str,
    pub verified: bool,
}

/// Tells the PREVIOUS address that `user`'s email changed — only if it was
/// verified (an unproven address may be a stranger's); the new address is
/// masked, as the old mailbox may no longer be the user's.
pub async fn email_changed(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    user: &users::Model,
    old: OldAddress<'_>,
) -> anyhow::Result<()> {
    if !old.verified {
        return Ok(());
    }
    let facts = [("New address", templates::mask_email(&user.email))];
    deliver(
        conn,
        config,
        tenant,
        user,
        old.email,
        NotifyEvent::EmailChanged,
        &facts,
    )
    .await
}

/// Shorthand for the common "changed via X" fact line.
pub fn change(what: &str) -> [(&'static str, String); 1] {
    [("Change", what.to_owned())]
}
