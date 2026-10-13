//! Refresh tokens: opaque, single use, rotated on every redemption. All
//! rotations of one grant form a family; presenting an already-rotated token
//! means it leaked, so the whole family is revoked (OAuth 2.1 §4.3.1,
//! RFC 9700 §4.14.2). A family's absolute lifetime is fixed when it starts —
//! rotation never extends it.

use anyhow::Context;
use chrono::{DateTime, FixedOffset};
use entity::{opaque_access_tokens, refresh_tokens};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, Statement,
};
use uuid::Uuid;

use crate::{secret, tokens::opaque};

#[derive(Debug, PartialEq, Eq)]
pub enum State {
    Active,
    /// Already exchanged once: replay of a rotated token.
    Reused,
    Revoked,
    Expired,
}

pub fn state(row: &refresh_tokens::Model, now: DateTime<FixedOffset>) -> State {
    if row.revoked_at.is_some() {
        State::Revoked
    } else if row.rotated_at.is_some() {
        State::Reused
    } else if row.expires_at <= now {
        State::Expired
    } else {
        State::Active
    }
}

pub struct NewRefresh<'a> {
    pub tenant_id: Uuid,
    pub family_id: Uuid,
    pub client_app_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub authorization_code_id: Option<Uuid>,
    /// OIDC scopes + bare resource scope values (as on the code).
    pub scopes: &'a [String],
    pub resource_app_id: Option<Uuid>,
    pub amr: &'a [String],
    pub auth_time: DateTime<FixedOffset>,
    pub expires_at: DateTime<FixedOffset>,
}

pub async fn issue(conn: &impl ConnectionTrait, new: NewRefresh<'_>) -> anyhow::Result<String> {
    let token = secret::random_token()?;
    let row = refresh_tokens::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(new.tenant_id),
        token_hash: Set(secret::hash(&token)),
        family_id: Set(new.family_id),
        application_id: Set(new.client_app_id),
        user_id: Set(new.user_id),
        session_id: Set(new.session_id),
        authorization_code_id: Set(new.authorization_code_id),
        scopes: Set(new.scopes.to_vec()),
        resource_application_id: Set(new.resource_app_id),
        amr: Set(new.amr.to_vec()),
        auth_time: Set(new.auth_time),
        expires_at: Set(new.expires_at),
        rotated_at: Set(None),
        revoked_at: Set(None),
        ..Default::default()
    };
    refresh_tokens::Entity::insert(row)
        .exec_without_returning(conn)
        .await
        .context("storing refresh token")?;
    Ok(token)
}

pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    token: &str,
) -> anyhow::Result<Option<refresh_tokens::Model>> {
    refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::TenantId.eq(tenant_id))
        .filter(refresh_tokens::Column::TokenHash.eq(secret::hash(token)))
        .one(conn)
        .await
        .context("looking up refresh token")
}

/// Atomically marks `id` rotated. `false` = somebody else rotated or
/// revoked it first, or its family is (being) revoked — treat as reuse.
///
/// The family check closes a race with [`revoke_family`]: without it a
/// rotation could commit a new token that a concurrent revocation's
/// snapshot never saw.
pub async fn mark_rotated(conn: &impl ConnectionTrait, id: Uuid) -> anyhow::Result<bool> {
    let result = conn
        .execute_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            r"UPDATE refresh_tokens t SET rotated_at = now()
              WHERE t.id = $1 AND t.rotated_at IS NULL AND t.revoked_at IS NULL
                AND NOT EXISTS (SELECT 1 FROM refresh_tokens f
                                WHERE f.family_id = t.family_id AND f.revoked_at IS NOT NULL)",
            [id.into()],
        ))
        .await
        .context("rotating refresh token")?;
    Ok(result.rows_affected() == 1)
}

/// True if any token of the family was revoked: the whole grant is dead.
pub async fn family_revoked(conn: &impl ConnectionTrait, family_id: Uuid) -> anyhow::Result<bool> {
    let revoked = refresh_tokens::Entity::find()
        .filter(refresh_tokens::Column::FamilyId.eq(family_id))
        .filter(refresh_tokens::Column::RevokedAt.is_not_null())
        .one(conn)
        .await
        .context("checking refresh token family")?;
    Ok(revoked.is_some())
}

/// Bound on revocation passes. Rotations racing the passes could in theory
/// keep adding rows; any leftover is still dead, because `mark_rotated`
/// refuses to rotate within a family that has a revoked row and
/// introspection treats such a family as inactive.
const MAX_REVOKE_PASSES: usize = 4;

/// Runs a revoking UPDATE until it changes nothing. A rotation in flight
/// holds the lock on the token it rotates (always an unrevoked one, so the
/// first pass waits for it); once it commits, its new token is visible to
/// the next pass's fresh snapshot.
async fn revoke_until_stable(
    conn: &impl ConnectionTrait,
    sql: &str,
    values: &[sea_orm::Value],
) -> anyhow::Result<()> {
    for _ in 0..MAX_REVOKE_PASSES {
        let result = conn
            .execute_raw(Statement::from_sql_and_values(
                conn.get_database_backend(),
                sql,
                values.to_vec(),
            ))
            .await
            .context("revoking refresh tokens")?;
        if result.rows_affected() == 0 {
            return Ok(());
        }
    }
    tracing::warn!("refresh revocation still changing rows after {MAX_REVOKE_PASSES} passes");
    Ok(())
}

/// Revokes every family `families_sql` (a `SELECT family_id …` over
/// `values`) names, and the opaque access tokens minted from them.
async fn revoke_families_where(
    conn: &impl ConnectionTrait,
    families_sql: &str,
    values: &[sea_orm::Value],
) -> anyhow::Result<()> {
    revoke_until_stable(
        conn,
        &format!(
            "UPDATE refresh_tokens SET revoked_at = now() \
             WHERE revoked_at IS NULL AND family_id IN ({families_sql})"
        ),
        values,
    )
    .await?;
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        format!(
            "UPDATE opaque_access_tokens SET revoked_at = now() \
             WHERE revoked_at IS NULL AND family_id IN ({families_sql})"
        ),
        values.to_vec(),
    ))
    .await
    .context("revoking opaque tokens of revoked families")?;
    Ok(())
}

/// A withdrawn consent grant: revokes what `client` obtained for
/// `resource` — for one user, or (`user_id = None`, an admin grant) for
/// everyone. Refresh families, and every opaque access token for the pair
/// (JWTs can't be recalled; they expire).
pub async fn revoke_grant(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    client_app_id: Uuid,
    resource_app_id: Uuid,
    user_id: Option<Uuid>,
) -> anyhow::Result<()> {
    const MATCH: &str = "tenant_id = $1 AND application_id = $2 \
        AND resource_application_id = $3 AND ($4::uuid IS NULL OR user_id = $4)";
    let values = [
        tenant_id.into(),
        client_app_id.into(),
        resource_app_id.into(),
        user_id.into(),
    ];
    revoke_families_where(
        conn,
        &format!("SELECT family_id FROM refresh_tokens WHERE {MATCH}"),
        &values,
    )
    .await?;
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        format!("UPDATE opaque_access_tokens SET revoked_at = now() WHERE revoked_at IS NULL AND {MATCH}"),
        values.to_vec(),
    ))
    .await
    .context("revoking opaque tokens of a withdrawn grant")?;
    Ok(())
}

/// A deleted scope: every family of `resource_app_id` whose grant holds
/// `value`, and their opaque access tokens.
pub async fn revoke_by_scope(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    resource_app_id: Uuid,
    value: &str,
) -> anyhow::Result<()> {
    revoke_families_where(
        conn,
        "SELECT family_id FROM refresh_tokens \
         WHERE tenant_id = $1 AND resource_application_id = $2 AND $3 = ANY(scopes)",
        &[tenant_id.into(), resource_app_id.into(), value.into()],
    )
    .await
}

/// A signed-out device: the refresh families started in `session_id` and
/// their opaque access tokens.
pub async fn revoke_by_session(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    session_id: Uuid,
) -> anyhow::Result<()> {
    revoke_families_where(
        conn,
        "SELECT family_id FROM refresh_tokens WHERE tenant_id = $1 AND session_id = $2",
        &[tenant_id.into(), session_id.into()],
    )
    .await
}

/// Revokes every refresh token of the family and the opaque access tokens
/// minted from it. (JWT access tokens can't be recalled; they expire.)
pub async fn revoke_family(conn: &impl ConnectionTrait, family_id: Uuid) -> anyhow::Result<()> {
    revoke_until_stable(
        conn,
        "UPDATE refresh_tokens SET revoked_at = now() \
         WHERE family_id = $1 AND revoked_at IS NULL",
        &[family_id.into()],
    )
    .await?;
    opaque::revoke_where(conn, opaque_access_tokens::Column::FamilyId.eq(family_id)).await
}

/// RFC 6749 §4.1.2: a replayed code revokes what it produced — every
/// refresh family started by it and every opaque token from the code or
/// those families.
pub async fn revoke_by_code(conn: &impl ConnectionTrait, code_id: Uuid) -> anyhow::Result<()> {
    const FAMILIES: &str = "SELECT family_id FROM refresh_tokens WHERE authorization_code_id = $1";
    revoke_until_stable(
        conn,
        &format!(
            "UPDATE refresh_tokens SET revoked_at = now() \
             WHERE revoked_at IS NULL AND family_id IN ({FAMILIES})"
        ),
        &[code_id.into()],
    )
    .await?;
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        format!(
            "UPDATE opaque_access_tokens SET revoked_at = now() \
             WHERE revoked_at IS NULL \
               AND (authorization_code_id = $1 OR family_id IN ({FAMILIES}))"
        ),
        [code_id.into()],
    ))
    .await
    .context("revoking opaque tokens of a replayed code")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    fn row() -> refresh_tokens::Model {
        let now = chrono::Utc::now().fixed_offset();
        refresh_tokens::Model {
            id: Uuid::now_v7(),
            tenant_id: Uuid::nil(),
            token_hash: vec![0; 32],
            family_id: Uuid::now_v7(),
            application_id: Uuid::nil(),
            user_id: Uuid::nil(),
            session_id: Uuid::nil(),
            authorization_code_id: None,
            scopes: vec![],
            resource_application_id: None,
            amr: vec![],
            auth_time: now,
            created_at: now,
            expires_at: now + Duration::hours(1),
            rotated_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn family_state_machine() {
        let now = chrono::Utc::now().fixed_offset();
        let mut r = row();
        assert_eq!(state(&r, now), State::Active);
        assert_eq!(state(&r, now + Duration::hours(2)), State::Expired);
        r.rotated_at = Some(now);
        assert_eq!(state(&r, now), State::Reused);
        // Rotation is checked before expiry: replaying a rotated token after
        // it expired still trips family revocation.
        assert_eq!(state(&r, now + Duration::hours(2)), State::Reused);
        r.revoked_at = Some(now);
        assert_eq!(state(&r, now), State::Revoked);
    }
}
