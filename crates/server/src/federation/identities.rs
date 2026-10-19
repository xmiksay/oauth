//! `user_identities`: upstream identities linked to users, and the
//! last-sign-in-method rule, which counts them next to passwords and
//! passkeys.

use anyhow::Context;
use entity::{identity_providers, user_identities, users};
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder,
    Statement, sea_query::Expr,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::profile;
use crate::{directory, passkey};

/// The upstream identity `(idp, subject)` of this tenant, if linked.
pub async fn find(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
    subject: &str,
) -> anyhow::Result<Option<user_identities::Model>> {
    use user_identities::Column;
    user_identities::Entity::find()
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::IdpId.eq(idp_id))
        .filter(Column::Subject.eq(subject))
        .one(conn)
        .await
        .context("looking up linked identity")
}

/// A user's identities with their IdP's name, oldest first.
pub async fn list(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
) -> anyhow::Result<Vec<(user_identities::Model, String)>> {
    use user_identities::Column;
    let rows = user_identities::Entity::find()
        .filter(Column::TenantId.eq(tenant_id))
        .filter(Column::UserId.eq(user_id))
        .order_by_asc(Column::Id)
        .all(conn)
        .await
        .context("listing linked identities")?;
    let idps = identity_providers::Entity::find()
        .filter(identity_providers::Column::TenantId.eq(tenant_id))
        .filter(identity_providers::Column::Id.is_in(rows.iter().map(|r| r.idp_id)))
        .all(conn)
        .await
        .context("loading identity provider names")?;
    Ok(rows
        .into_iter()
        .map(|row| {
            let name = idps
                .iter()
                .find(|idp| idp.id == row.idp_id)
                .map_or_else(String::new, |idp| idp.name.clone());
            (row, name)
        })
        .collect())
}

/// An upstream identity waiting on a login transaction (stage `link`) for
/// the local sign-in that links it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pending {
    pub idp_id: Uuid,
    /// The IdP's `generation` the identity was verified at.
    pub generation: i64,
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
}

/// Why a link was refused.
#[derive(Debug, thiserror::Error)]
pub enum LinkError {
    /// The identity belongs to someone, or the user already has one of
    /// this IdP.
    #[error("the identity is already linked")]
    AlreadyLinked,
    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

pub struct NewIdentity<'a> {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub idp_id: Uuid,
    pub subject: &'a str,
    pub email: Option<&'a str>,
}

pub async fn link(
    conn: &impl ConnectionTrait,
    new: NewIdentity<'_>,
) -> Result<user_identities::Model, LinkError> {
    let now = chrono::Utc::now().fixed_offset();
    let row = user_identities::ActiveModel {
        id: Set(Uuid::now_v7()),
        tenant_id: Set(new.tenant_id),
        user_id: Set(new.user_id),
        idp_id: Set(new.idp_id),
        subject: Set(new.subject.to_owned()),
        email: Set(new.email.and_then(profile::clean_email)),
        linked_at: Set(now),
        last_used_at: Set(Some(now)),
    };
    user_identities::Entity::insert(row)
        .exec_with_returning(conn)
        .await
        .map_err(|err| {
            if directory::violates_any_unique(&err) {
                LinkError::AlreadyLinked
            } else {
                LinkError::Internal(anyhow::Error::new(err).context("linking identity"))
            }
        })
}

/// Records a sign-in with the identity (and the email it came with);
/// `false` = it was unlinked meanwhile.
pub async fn touch(
    conn: &impl ConnectionTrait,
    identity: &user_identities::Model,
    email: Option<&str>,
) -> anyhow::Result<bool> {
    let result = user_identities::Entity::update_many()
        .col_expr(
            user_identities::Column::LastUsedAt,
            Expr::current_timestamp(),
        )
        .col_expr(
            user_identities::Column::Email,
            Expr::value(email.and_then(profile::clean_email)),
        )
        .filter(user_identities::Column::Id.eq(identity.id))
        .exec(conn)
        .await
        .context("recording identity use")?;
    Ok(result.rows_affected == 1)
}

pub async fn find_for_user(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    id: Uuid,
) -> anyhow::Result<Option<user_identities::Model>> {
    user_identities::Entity::find_by_id(id)
        .filter(user_identities::Column::TenantId.eq(tenant_id))
        .filter(user_identities::Column::UserId.eq(user_id))
        .one(conn)
        .await
        .context("loading linked identity")
}

/// The ways a user can sign in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Methods {
    pub password: bool,
    pub passkeys: u64,
    pub identities: u64,
}

impl Methods {
    pub fn any(self) -> bool {
        self.password || self.passkeys > 0 || self.identities > 0
    }

    /// Whether one passkey can go without leaving the user locked out.
    pub fn can_drop_passkey(self) -> bool {
        self.password || self.identities > 0 || self.passkeys > 1
    }

    /// Whether one linked identity can go without leaving the user locked out.
    pub fn can_drop_identity(self) -> bool {
        self.password || self.passkeys > 0 || self.identities > 1
    }

    /// Whether all passkeys can go (an admin's Reset MFA).
    pub fn can_drop_passkeys(self) -> bool {
        self.passkeys == 0 || self.password || self.identities > 0
    }
}

/// Identities at a disabled IdP don't count: they can't sign anyone in.
pub async fn methods(conn: &impl ConnectionTrait, user: &users::Model) -> anyhow::Result<Methods> {
    Ok(Methods {
        password: user.password_hash.is_some(),
        passkeys: passkey::store::count(conn, user.tenant_id, user.id).await?,
        identities: count(
            conn,
            r"SELECT count(*) AS n FROM user_identities i
              JOIN identity_providers p ON p.tenant_id = i.tenant_id AND p.id = i.idp_id
              WHERE i.tenant_id = $1 AND i.user_id = $2 AND p.enabled",
            user.tenant_id,
            user.id,
        )
        .await?,
    })
}

async fn count(
    conn: &impl ConnectionTrait,
    sql: &str,
    tenant_id: Uuid,
    id: Uuid,
) -> anyhow::Result<u64> {
    let row = conn
        .query_one_raw(Statement::from_sql_and_values(
            conn.get_database_backend(),
            sql,
            [tenant_id.into(), id.into()],
        ))
        .await
        .context("counting linked identities")?
        .context("count returned no row")?;
    let n: i64 = row.try_get("", "n").context("reading count")?;
    Ok(u64::try_from(n).unwrap_or(0))
}

/// Identities linked through `idp`.
pub async fn linked_users(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<u64> {
    count(
        conn,
        "SELECT count(*) AS n FROM user_identities WHERE tenant_id = $1 AND idp_id = $2",
        tenant_id,
        idp_id,
    )
    .await
}

/// Unlinks everyone from `idp`, drops its round trips in flight and sends
/// login transactions parked on it back to the password stage (its issuer,
/// client or discovery URL changed: the old subjects mean nothing any
/// more). Returns how many identities went.
pub async fn unlink_all(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<u64> {
    // login_transactions before federation_states: the same table order as
    // the sweeper (and as login completion), so the two never wait on each
    // other's rows the other way round.
    conn.execute_raw(Statement::from_sql_and_values(
        conn.get_database_backend(),
        r"UPDATE login_transactions SET stage = 'password', pending_identity = NULL
          WHERE tenant_id = $1 AND stage = 'link'
            AND pending_identity ->> 'idp_id' = $2::text",
        [tenant_id.into(), idp_id.into()],
    ))
    .await
    .context("releasing parked logins")?;
    entity::federation_states::Entity::delete_many()
        .filter(entity::federation_states::Column::TenantId.eq(tenant_id))
        .filter(entity::federation_states::Column::IdpId.eq(idp_id))
        .exec(conn)
        .await
        .context("dropping federation states")?;
    let removed = user_identities::Entity::delete_many()
        .filter(user_identities::Column::TenantId.eq(tenant_id))
        .filter(user_identities::Column::IdpId.eq(idp_id))
        .exec(conn)
        .await
        .context("unlinking identities")?;
    Ok(removed.rows_affected)
}

/// Users for whom `idp` is the only way in: no password, no passkey, no
/// identity of another enabled IdP. Disabling or deleting the IdP locks them out.
pub async fn users_only_via(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    idp_id: Uuid,
) -> anyhow::Result<u64> {
    count(
        conn,
        r"SELECT count(*) AS n
          FROM user_identities i
          JOIN users u ON u.tenant_id = i.tenant_id AND u.id = i.user_id
          WHERE i.tenant_id = $1 AND i.idp_id = $2 AND u.password_hash IS NULL
            AND NOT EXISTS (SELECT 1 FROM webauthn_credentials w
                            WHERE w.tenant_id = u.tenant_id AND w.user_id = u.id)
            AND NOT EXISTS (SELECT 1 FROM user_identities o
                            JOIN identity_providers op
                              ON op.tenant_id = o.tenant_id AND op.id = o.idp_id
                            WHERE o.tenant_id = i.tenant_id AND o.user_id = i.user_id
                              AND o.idp_id <> i.idp_id AND op.enabled)",
        tenant_id,
        idp_id,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn m(password: bool, passkeys: u64, identities: u64) -> Methods {
        Methods {
            password,
            passkeys,
            identities,
        }
    }

    #[test]
    fn last_method_rule() {
        assert!(!m(false, 0, 0).any());
        assert!(m(false, 0, 1).any());
        assert!(!m(false, 1, 0).can_drop_passkey());
        assert!(m(false, 1, 1).can_drop_passkey());
        assert!(m(false, 2, 0).can_drop_passkey());
        assert!(!m(false, 0, 1).can_drop_identity());
        assert!(m(true, 0, 1).can_drop_identity());
        assert!(m(false, 1, 1).can_drop_identity());
        assert!(m(false, 0, 2).can_drop_identity());
        assert!(!m(false, 2, 0).can_drop_passkeys());
        assert!(m(false, 2, 1).can_drop_passkeys());
        assert!(m(true, 2, 0).can_drop_passkeys());
        assert!(m(false, 0, 0).can_drop_passkeys());
    }
}
