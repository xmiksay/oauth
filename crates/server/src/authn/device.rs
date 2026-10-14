//! Known devices: every new sign-in records the browser's device cookie
//! (`cookie::Kind::Device`) and notifies the user when that browser is new
//! to their account — except on their very first sign-in ever, when every
//! browser is new (`users.first_device_at`, which no sweep removes, so a
//! user idle past the device lifetime is still warned). The stored hash is
//! keyed by the user, so the rows of two accounts used in one browser can't
//! be linked to each other.

use anyhow::Context;
use axum::http::HeaderValue;
use chrono::{Duration, SecondsFormat};
use entity::{enums::NotifyEvent, known_devices, users};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter,
    sea_query::{Expr, OnConflict},
};
use uuid::Uuid;

use super::{
    cookie::{self, DEVICE_TTL_DAYS, Kind},
    ctx::Ctx,
};
use crate::{notify, secret};

const MAX_USER_AGENT: usize = 512;

/// SHA-256 over user id ‖ cookie value.
fn device_hash(user_id: Uuid, token: &str) -> Vec<u8> {
    secret::hash(&format!("{user_id}:{token}"))
}

/// Only values we could have minted are reused: the cookie is echoed back
/// in `Set-Cookie`, so arbitrary client text must never reach it.
fn well_formed(value: &str) -> bool {
    value.len() == 43
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Records this browser for `user` (call on the sign-in's transaction) and
/// returns the device cookie to set. Queues a "new sign-in" notice when the
/// browser was unknown for the user.
pub async fn on_sign_in(
    conn: &impl ConnectionTrait,
    ctx: &Ctx<'_>,
    user: &users::Model,
) -> anyhow::Result<HeaderValue> {
    let config = &ctx.state.config;
    let presented = cookie::read(ctx.headers, config, Kind::Device).find(|v| well_formed(v));
    let token = match presented {
        Some(value) => value.to_owned(),
        None => secret::random_token()?,
    };
    let hash = device_hash(user.id, &token);
    let now = chrono::Utc::now().fixed_offset();
    let known = known_devices::Entity::find()
        .filter(known_devices::Column::TenantId.eq(ctx.tenant.id))
        .filter(known_devices::Column::UserId.eq(user.id))
        .filter(known_devices::Column::DeviceHash.eq(hash.clone()))
        .filter(known_devices::Column::ExpiresAt.gt(now))
        .one(conn)
        .await
        .context("looking up known device")?
        .is_some();
    // Atomic: of two concurrent first sign-ins only one counts as first.
    let first_sign_in = users::Entity::update_many()
        .col_expr(users::Column::FirstDeviceAt, Expr::value(now))
        .filter(users::Column::TenantId.eq(ctx.tenant.id))
        .filter(users::Column::Id.eq(user.id))
        .filter(users::Column::FirstDeviceAt.is_null())
        .exec(conn)
        .await
        .context("marking the first sign-in device")?
        .rows_affected
        == 1;
    let user_agent: Option<String> = ctx.user_agent.map(|ua| {
        ua.chars()
            .filter(|c| !c.is_control())
            .take(MAX_USER_AGENT)
            .collect()
    });
    let expires_at = now + Duration::days(DEVICE_TTL_DAYS);
    let row = known_devices::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(ctx.tenant.id),
        user_id: Set(user.id),
        device_hash: Set(hash),
        user_agent: Set(user_agent.clone()),
        first_seen: Set(now),
        last_seen: Set(now),
        expires_at: Set(expires_at),
    };
    use known_devices::Column;
    known_devices::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([Column::TenantId, Column::UserId, Column::DeviceHash])
                .update_columns([Column::UserAgent, Column::LastSeen, Column::ExpiresAt])
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .context("recording known device")?;
    if !known && !first_sign_in {
        let facts = [
            (
                "Time",
                now.to_utc().to_rfc3339_opts(SecondsFormat::Secs, true),
            ),
            (
                "IP address",
                ctx.ip
                    .map_or_else(|| "unknown".to_owned(), |ip| ip.to_string()),
            ),
            (
                "Browser",
                user_agent.unwrap_or_else(|| "unknown".to_owned()),
            ),
        ];
        notify::event(
            conn,
            config,
            ctx.tenant,
            user,
            NotifyEvent::NewSignIn,
            &facts,
        )
        .await?;
    }
    cookie::set(config, Kind::Device, &token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_hashes_are_per_user() {
        let (a, b) = (Uuid::now_v7(), Uuid::now_v7());
        assert_ne!(device_hash(a, "same"), device_hash(b, "same"));
        assert_eq!(device_hash(a, "same"), device_hash(a, "same"));
        assert_eq!(device_hash(a, "x").len(), 32);
    }

    #[test]
    fn only_minted_shapes_are_reused() {
        assert!(well_formed(&secret::random_token().unwrap()));
        for bad in [
            "",
            "short",
            &"a".repeat(44),
            &format!("{};x", "a".repeat(41)),
        ] {
            assert!(!well_formed(bad), "{bad}");
        }
    }
}
