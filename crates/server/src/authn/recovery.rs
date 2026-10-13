//! Recovery codes: one-time second factor. Stored as SHA-256 of the
//! normalized code; generation lives in the `me` API (step 4), which must
//! hash through [`hash`] so both sides normalize alike.

use anyhow::Context;
use entity::user_recovery_codes;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, sea_query::Expr};
use uuid::Uuid;

use crate::secret;

/// Users type codes with or without separators and in any case.
pub fn normalize(code: &str) -> String {
    code.chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

pub fn hash(code: &str) -> Vec<u8> {
    secret::hash(&normalize(code))
}

/// Marks a matching unused code as used. `true` = accepted.
pub async fn redeem(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    user_id: Uuid,
    code: &str,
) -> anyhow::Result<bool> {
    let wanted = hash(code);
    let unused = user_recovery_codes::Entity::find()
        .filter(user_recovery_codes::Column::TenantId.eq(tenant_id))
        .filter(user_recovery_codes::Column::UserId.eq(user_id))
        .filter(user_recovery_codes::Column::UsedAt.is_null())
        .all(conn)
        .await
        .context("loading recovery codes")?;
    // Compare against every code (no early exit) so timing doesn't reveal
    // which one, if any, matched.
    let matched = unused.iter().fold(None, |found, row| {
        if secret::ct_eq(&row.code_hash, &wanted) {
            Some(row.id)
        } else {
            found
        }
    });
    let Some(id) = matched else {
        return Ok(false);
    };
    let result = user_recovery_codes::Entity::update_many()
        .col_expr(
            user_recovery_codes::Column::UsedAt,
            Expr::current_timestamp(),
        )
        .filter(user_recovery_codes::Column::Id.eq(id))
        .filter(user_recovery_codes::Column::UsedAt.is_null())
        .exec(conn)
        .await
        .context("redeeming recovery code")?;
    Ok(result.rows_affected == 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_ignores_case_and_separators() {
        assert_eq!(normalize(" AbCd-EfGh 1234 "), "abcdefgh1234");
        assert_eq!(hash("ABCD-efgh"), hash("abcdefgh"));
        assert_ne!(hash("abcdefgh"), hash("abcdefgi"));
    }
}
