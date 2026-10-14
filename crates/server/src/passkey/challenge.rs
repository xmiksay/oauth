//! Single-use ceremony challenges (`webauthn_challenges`): 256 random bits
//! handed to the browser as base64url, stored as SHA-256, valid 5 minutes,
//! consumed by one atomic DELETE … RETURNING.

use anyhow::Context;
use chrono::Duration;
use entity::{enums::WebauthnPurpose, webauthn_challenges};
use sea_orm::{ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};
use uuid::Uuid;

use crate::secret;

pub const TTL_SECS: i64 = 300;

/// Whom a challenge is for. A login challenge belongs to its transaction
/// (the transaction decides whose credential may answer it); the others
/// to one user.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scope {
    Login {
        tx_id: Uuid,
        user_id: Option<Uuid>,
    },
    User {
        purpose: WebauthnPurpose,
        user_id: Uuid,
    },
}

impl Scope {
    fn purpose(self) -> WebauthnPurpose {
        match self {
            Self::Login { .. } => WebauthnPurpose::Login,
            Self::User { purpose, .. } => purpose,
        }
    }
}

/// A new challenge for `scope`; the scope's earlier ones stop working (the
/// browser only ever answers the newest), which also bounds the rows one
/// transaction or user can create.
pub async fn issue(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    scope: Scope,
) -> anyhow::Result<String> {
    use webauthn_challenges::Column;
    let prior = webauthn_challenges::Entity::delete_many().filter(Column::TenantId.eq(tenant_id));
    let prior = match scope {
        Scope::Login { tx_id, .. } => prior.filter(Column::TxId.eq(tx_id)),
        Scope::User { purpose, user_id } => prior
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Purpose.eq(purpose))
            .filter(Column::TxId.is_null()),
    };
    prior
        .exec(conn)
        .await
        .context("replacing webauthn challenges")?;
    let challenge = secret::random_token()?;
    let (user_id, tx_id) = match scope {
        Scope::Login { tx_id, user_id } => (user_id, Some(tx_id)),
        Scope::User { user_id, .. } => (Some(user_id), None),
    };
    let now = chrono::Utc::now().fixed_offset();
    let row = webauthn_challenges::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(tenant_id),
        challenge_hash: Set(secret::hash(&challenge)),
        purpose: Set(scope.purpose()),
        user_id: Set(user_id),
        tx_id: Set(tx_id),
        created_at: Set(now),
        expires_at: Set(now + Duration::seconds(TTL_SECS)),
    };
    webauthn_challenges::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing webauthn challenge")?;
    Ok(challenge)
}

/// Atomically deletes and returns the challenge `challenge` if it is live
/// and was issued for `scope` (purpose, tenant and transaction / user):
/// of two concurrent uses exactly one gets it. A login challenge matches
/// on the transaction only.
pub async fn consume(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    challenge: &str,
    scope: Scope,
) -> anyhow::Result<Option<webauthn_challenges::Model>> {
    use webauthn_challenges::Column;
    let now = chrono::Utc::now().fixed_offset();
    let query = webauthn_challenges::Entity::delete_many()
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::ChallengeHash.eq(secret::hash(challenge)))
        .filter(Column::Purpose.eq(scope.purpose()))
        .filter(Column::ExpiresAt.gt(now));
    let query = match scope {
        Scope::Login { tx_id, .. } => query.filter(Column::TxId.eq(tx_id)),
        Scope::User { user_id, .. } => query.filter(Column::UserId.eq(user_id)),
    };
    let rows = query
        .exec_with_returning(conn)
        .await
        .context("consuming webauthn challenge")?;
    Ok(rows.into_iter().next())
}
