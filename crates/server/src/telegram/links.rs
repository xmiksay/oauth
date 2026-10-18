//! Linking a Telegram chat to a user: single-use link codes (the deep
//! link's `/start` parameter) and the links themselves.

use anyhow::Context;
use chrono::{DateTime, Duration, FixedOffset};
use entity::{telegram_link_codes, telegram_links, telegram_otps};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement,
    sea_query::OnConflict,
};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::secret;

pub const LINK_CODE_TTL_MINUTES: i64 = 10;

pub struct IssuedCode {
    pub code: Zeroizing<String>,
    pub expires_at: DateTime<FixedOffset>,
}

/// `https://t.me/{bot}?start={code}`: opens the bot, whose Start button
/// sends `/start {code}`.
pub fn deep_link(bot_username: &str, code: &str) -> String {
    format!("https://t.me/{bot_username}?start={code}")
}

/// A new link code for the user, voiding their earlier ones (so a user has
/// at most one live code and can't pile up rows).
pub async fn issue_code(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<IssuedCode> {
    telegram_link_codes::Entity::delete_many()
        .filter(telegram_link_codes::Column::TenantId.eq(tenant_id))
        .filter(telegram_link_codes::Column::UserId.eq(user_id))
        .exec(conn)
        .await
        .context("voiding older Telegram link codes")?;
    // 256 bits, base64url (43 chars): fits Telegram's 64-char start parameter.
    let code = Zeroizing::new(secret::random_token()?);
    let expires_at = chrono::Utc::now().fixed_offset() + Duration::minutes(LINK_CODE_TTL_MINUTES);
    telegram_link_codes::Entity::insert(telegram_link_codes::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_id: Set(user_id),
        code_hash: Set(secret::hash(&code)),
        expires_at: Set(expires_at),
        ..Default::default()
    })
    .exec_without_returning(conn)
    .await
    .context("storing Telegram link code")?;
    Ok(IssuedCode { code, expires_at })
}

/// Consumes a live code atomically (one `DELETE … RETURNING`, so two racing
/// redemptions can't both succeed); the `(tenant, user)` it was issued for.
pub async fn consume_code(
    conn: &impl ConnectionTrait,
    code: &str,
) -> anyhow::Result<Option<(Uuid, Uuid)>> {
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            "DELETE FROM telegram_link_codes WHERE code_hash = $1 AND expires_at > now() \
             RETURNING tenant_id, user_id",
            [secret::hash(code).into()],
        ))
        .await
        .context("consuming Telegram link code")?;
    row.map(|r| -> anyhow::Result<(Uuid, Uuid)> {
        Ok((
            r.try_get("", "tenant_id").context("link code tenant")?,
            r.try_get("", "user_id").context("link code user")?,
        ))
    })
    .transpose()
}

pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Option<telegram_links::Model>> {
    telegram_links::Entity::find()
        .filter(telegram_links::Column::TenantId.eq(tenant_id))
        .filter(telegram_links::Column::UserId.eq(user_id))
        .one(conn)
        .await
        .context("loading Telegram link")
}

/// Binds `chat_id` to the user, replacing the user's earlier link. Codes
/// already sent (or pending link codes) belong to the old chat and die with
/// it — pass the transaction that consumed the link code.
pub async fn link(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    chat_id: i64,
    username: Option<&str>,
) -> anyhow::Result<()> {
    use telegram_links::Column;
    drop_codes(conn, tenant_id, user_id).await?;
    let row = telegram_links::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        user_id: Set(user_id),
        chat_id: Set(chat_id),
        username: Set(username.map(str::to_owned)),
        linked_at: Set(chrono::Utc::now().fixed_offset()),
    };
    telegram_links::Entity::insert(row)
        .on_conflict(
            OnConflict::columns([Column::TenantId, Column::UserId])
                .update_columns([Column::ChatId, Column::Username, Column::LinkedAt])
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .context("storing Telegram link")?;
    Ok(())
}

/// Deletes the user's pending link codes and sign-in codes.
async fn drop_codes(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<()> {
    telegram_link_codes::Entity::delete_many()
        .filter(telegram_link_codes::Column::TenantId.eq(tenant_id))
        .filter(telegram_link_codes::Column::UserId.eq(user_id))
        .exec(conn)
        .await
        .context("deleting Telegram link codes")?;
    telegram_otps::Entity::delete_many()
        .filter(telegram_otps::Column::TenantId.eq(tenant_id))
        .filter(telegram_otps::Column::UserId.eq(user_id))
        .exec(conn)
        .await
        .context("deleting Telegram sign-in codes")?;
    Ok(())
}

/// Removes the user's link, pending link codes and sign-in codes; `true`
/// if a chat was linked.
pub async fn unlink(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<bool> {
    drop_codes(conn, tenant_id, user_id).await?;
    let deleted = telegram_links::Entity::delete_many()
        .filter(telegram_links::Column::TenantId.eq(tenant_id))
        .filter(telegram_links::Column::UserId.eq(user_id))
        .exec(conn)
        .await
        .context("deleting Telegram link")?;
    Ok(deleted.rows_affected > 0)
}

/// Every link of `chat_id` (across tenants), as `(tenant, user)`.
pub async fn links_of_chat(
    conn: &impl ConnectionTrait,
    chat_id: i64,
) -> anyhow::Result<Vec<(Uuid, Uuid)>> {
    Ok(telegram_links::Entity::find()
        .filter(telegram_links::Column::ChatId.eq(chat_id))
        .all(conn)
        .await
        .context("loading the chat's Telegram links")?
        .into_iter()
        .map(|l| (l.tenant_id, l.user_id))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_links_name_the_bot_and_code() {
        assert_eq!(
            deep_link("oauth_bot", "abc-_1"),
            "https://t.me/oauth_bot?start=abc-_1"
        );
    }
}
