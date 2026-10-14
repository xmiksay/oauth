//! Single-use email link tokens (`email_tokens`): 256-bit random values,
//! stored as SHA-256, scoped to the tenant whose host issued them and bound
//! to the user's address at issue time (a token issued just as an admin
//! changed the address names the stale one and never works).

use anyhow::Context;
use chrono::Duration;
use entity::{email_tokens, enums::EmailTokenPurpose, users};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, PaginatorTrait, QueryFilter,
    sea_query::Expr,
};
use uuid::Uuid;

use crate::secret;

pub fn ttl(purpose: EmailTokenPurpose) -> Duration {
    match purpose {
        EmailTokenPurpose::Verify | EmailTokenPurpose::Change => Duration::hours(24),
        EmailTokenPurpose::Reset => Duration::minutes(30),
        EmailTokenPurpose::Invite => Duration::days(7),
    }
}

/// A new token for `purpose`; the user's earlier unused ones of the same
/// purpose stop working (only the newest link is valid).
pub async fn issue(
    conn: &impl ConnectionTrait,
    user: &users::Model,
    purpose: EmailTokenPurpose,
    new_email: Option<&str>,
) -> anyhow::Result<String> {
    let (tenant_id, user_id) = (user.tenant_id, user.id);
    invalidate(conn, tenant_id, user_id, &[purpose]).await?;
    let token = secret::random_token()?;
    let now = chrono::Utc::now().fixed_offset();
    let row = email_tokens::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_id: Set(user_id),
        token_hash: Set(secret::hash(&token)),
        purpose: Set(purpose),
        email: Set(user.email.clone()),
        new_email: Set(new_email.map(str::to_owned)),
        expires_at: Set(now + ttl(purpose)),
        consumed_at: Set(None),
        ..Default::default()
    };
    email_tokens::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing email token")?;
    Ok(token)
}

/// Atomically marks the token used and returns it — only if it belongs to
/// this tenant, has one of `purposes`, is unexpired and unused. One
/// statement, so of two concurrent uses exactly one wins.
pub async fn consume(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    token: &str,
    purposes: &[EmailTokenPurpose],
) -> anyhow::Result<Option<email_tokens::Model>> {
    let now = chrono::Utc::now().fixed_offset();
    let rows = email_tokens::Entity::update_many()
        .col_expr(email_tokens::Column::ConsumedAt, Expr::value(now))
        .filter(email_tokens::Column::TenantId.eq(tenant_id))
        .filter(email_tokens::Column::TokenHash.eq(secret::hash(token)))
        .filter(email_tokens::Column::Purpose.is_in(purposes.iter().copied()))
        .filter(email_tokens::Column::ConsumedAt.is_null())
        .filter(email_tokens::Column::ExpiresAt.gt(now))
        .exec_with_returning(conn)
        .await
        .context("consuming email token")?;
    Ok(rows.into_iter().next())
}

/// Deletes the user's unused tokens of `purposes` (e.g. every link sent to
/// an address that is no longer the user's).
pub async fn invalidate(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    purposes: &[EmailTokenPurpose],
) -> anyhow::Result<()> {
    email_tokens::Entity::delete_many()
        .filter(email_tokens::Column::TenantId.eq(tenant_id))
        .filter(email_tokens::Column::UserId.eq(user_id))
        .filter(email_tokens::Column::Purpose.is_in(purposes.iter().copied()))
        .filter(email_tokens::Column::ConsumedAt.is_null())
        .exec(conn)
        .await
        .context("invalidating email tokens")?;
    Ok(())
}

/// Whether `token` may still act on `user`: same user, still enabled, the
/// address it was sent for is still theirs, and an invitation only while
/// no password has been set.
pub fn still_valid(token: &email_tokens::Model, user: &users::Model) -> bool {
    token.user_id == user.id
        && token.tenant_id == user.tenant_id
        && !user.disabled
        && token.email == user.email
        && (token.purpose != EmailTokenPurpose::Invite || user.password_hash.is_none())
}

/// Every purpose: what an email change voids.
pub const ALL: [EmailTokenPurpose; 4] = [
    EmailTokenPurpose::Verify,
    EmailTokenPurpose::Reset,
    EmailTokenPurpose::Invite,
    EmailTokenPurpose::Change,
];

/// Whether the user holds a live, unused invitation.
pub async fn invite_pending(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<bool> {
    let count = email_tokens::Entity::find()
        .filter(email_tokens::Column::TenantId.eq(tenant_id))
        .filter(email_tokens::Column::UserId.eq(user_id))
        .filter(email_tokens::Column::Purpose.eq(EmailTokenPurpose::Invite))
        .filter(email_tokens::Column::ConsumedAt.is_null())
        .filter(email_tokens::Column::ExpiresAt.gt(chrono::Utc::now().fixed_offset()))
        .count(conn)
        .await
        .context("looking up pending invitation")?;
    Ok(count > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lifetimes() {
        assert_eq!(ttl(EmailTokenPurpose::Reset), Duration::minutes(30));
        assert_eq!(ttl(EmailTokenPurpose::Verify), Duration::hours(24));
        assert_eq!(ttl(EmailTokenPurpose::Change), Duration::hours(24));
        assert_eq!(ttl(EmailTokenPurpose::Invite), Duration::days(7));
    }
}
