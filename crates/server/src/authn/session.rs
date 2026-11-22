//! Browser sessions: a random cookie value (`cookie::Kind::Session`), stored
//! only as SHA-256. The row id is the `sid` claim.

use std::net::IpAddr;

use anyhow::Context;
use axum::http::HeaderMap;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{sessions, tenants, users};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QuerySelect,
};
use uuid::Uuid;

use super::cookie::{self, Kind};
use crate::{config::Config, secret};

const MAX_USER_AGENT: usize = 512;

pub struct NewSession<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub amr: &'a [String],
    pub auth_time: DateTime<FixedOffset>,
    pub ip: Option<IpAddr>,
    pub user_agent: Option<&'a str>,
    /// Keeps the session at least until then (instead of only
    /// `SESSION_TTL_HOURS`): a device's session must outlive its refresh
    /// tokens, or the user could no longer see and revoke it.
    pub min_expires_at: Option<DateTime<FixedOffset>>,
}

/// Creates a session; returns it with the cookie value.
pub async fn create(
    conn: &impl ConnectionTrait,
    config: &Config,
    new: NewSession<'_>,
) -> anyhow::Result<(sessions::Model, String)> {
    let token = secret::random_token()?;
    let now = chrono::Utc::now().fixed_offset();
    let user_agent = new.user_agent.map(|ua| {
        ua.chars()
            .filter(|c| !c.is_control())
            .take(MAX_USER_AGENT)
            .collect()
    });
    let row = sessions::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(new.tenant_id),
        user_id: Set(new.user_id),
        token_hash: Set(secret::hash(&token)),
        amr: Set(new.amr.to_vec()),
        auth_time: Set(new.auth_time),
        ip: Set(new.ip.map(|ip| ip.to_string())),
        user_agent: Set(user_agent),
        expires_at: Set(expires_at(
            now,
            config.session_ttl_hours,
            new.min_expires_at,
        )),
        ..Default::default()
    };
    let session = sessions::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .context("creating session")?;
    Ok((session, token))
}

fn expires_at(
    now: DateTime<FixedOffset>,
    ttl_hours: u32,
    min: Option<DateTime<FixedOffset>>,
) -> DateTime<FixedOffset> {
    let ttl = now + Duration::hours(i64::from(ttl_hours));
    min.map_or(ttl, |min| min.max(ttl))
}

pub async fn find_by_id(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<sessions::Model>> {
    let now = chrono::Utc::now().fixed_offset();
    Ok(sessions::Entity::find_by_id(id)
        .filter(sessions::Column::TenantId.eq(tenant_id))
        .one(conn)
        .await
        .context("loading session")?
        .filter(|s| s.expires_at > now))
}

/// [`find_by_id`] holding the row `FOR UPDATE`, so a concurrent sign-out
/// or revocation can't end it while the caller builds on it.
pub async fn lock_live(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<sessions::Model>> {
    let now = chrono::Utc::now().fixed_offset();
    Ok(sessions::Entity::find_by_id(id)
        .filter(sessions::Column::TenantId.eq(tenant_id))
        .lock_exclusive()
        .one(conn)
        .await
        .context("locking session")?
        .filter(|s| s.expires_at > now))
}

/// The unexpired session of this tenant named by the request's cookie,
/// whoever its user is.
pub async fn from_cookie(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    headers: &HeaderMap,
) -> anyhow::Result<Option<sessions::Model>> {
    let tenant_id = tenant.id;
    let now = chrono::Utc::now().fixed_offset();
    for token in cookie::read(headers, config, Kind::Session) {
        let found = sessions::Entity::find()
            .filter(sessions::Column::TenantId.eq(tenant_id))
            .filter(sessions::Column::TokenHash.eq(secret::hash(token)))
            .one(conn)
            .await
            .context("looking up session")?
            .filter(|s| s.expires_at > now);
        if found.is_some() {
            return Ok(found);
        }
    }
    Ok(None)
}

/// [`from_cookie`], only if its user is enabled.
pub async fn current(
    conn: &impl ConnectionTrait,
    config: &Config,
    tenant: &tenants::Model,
    headers: &HeaderMap,
) -> anyhow::Result<Option<(sessions::Model, users::Model)>> {
    let Some(session) = from_cookie(conn, config, tenant, headers).await? else {
        return Ok(None);
    };
    let user = users::Entity::find_by_id(session.user_id)
        .one(conn)
        .await
        .context("loading session user")?
        .filter(|u| !u.disabled);
    Ok(user.map(|u| (session, u)))
}

pub async fn delete(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<()> {
    sessions::Entity::delete_by_id(id)
        .exec(conn)
        .await
        .context("deleting session")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expiry_is_the_ttl_unless_a_later_minimum_is_asked() {
        let now = chrono::Utc::now().fixed_offset();
        let ttl = now + Duration::hours(24);
        assert_eq!(expires_at(now, 24, None), ttl);
        assert_eq!(expires_at(now, 24, Some(now + Duration::hours(1))), ttl);
        let later = now + Duration::days(14);
        assert_eq!(expires_at(now, 24, Some(later)), later);
    }
}
