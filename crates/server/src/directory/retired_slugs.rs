//! Slugs the system tenant gave up through a `SYSTEM_TENANT_RENAME`
//! (`retired_tenant_slugs`). Relying parties, bookmarks and upstream IdPs
//! still know the old host and issuer, so a regular tenant must never take
//! one: creating it is a 400, startup refuses one enabled and tenancy never
//! serves one. The system tenant itself may move back to a retired slug.

use anyhow::Context;
use entity::{retired_tenant_slugs, tenants};
use sea_orm::{
    ActiveValue::Set,
    ColumnTrait, Condition, ConnectionTrait, EntityTrait, QuerySelect,
    sea_query::{OnConflict, Query},
};
use uuid::Uuid;

use super::{DirectoryError, slug};

/// Records `slug` as given up by `tenant_id`. A slug retired again keeps
/// its first row.
pub(super) async fn retire(
    conn: &impl ConnectionTrait,
    tenant_id: Uuid,
    slug: &str,
) -> anyhow::Result<()> {
    let row = retired_tenant_slugs::ActiveModel {
        slug: Set(slug.to_owned()),
        tenant_id: Set(tenant_id),
        ..Default::default()
    };
    retired_tenant_slugs::Entity::insert(row)
        .on_conflict(
            OnConflict::column(retired_tenant_slugs::Column::Slug)
                .do_nothing()
                .to_owned(),
        )
        .exec_without_returning(conn)
        .await
        .context("recording the retired tenant slug")?;
    Ok(())
}

/// 400 `reserved` when `slug` is a retired system tenant slug.
pub async fn ensure_not_retired(
    conn: &impl ConnectionTrait,
    slug: &str,
) -> Result<(), DirectoryError> {
    let found = retired_tenant_slugs::Entity::find_by_id(slug.to_owned())
        .one(conn)
        .await
        .context("looking up retired tenant slugs")?;
    match found {
        Some(_) => Err(slug::reserved(slug)),
        None => Ok(()),
    }
}

/// Every retired slug.
pub(super) async fn all(conn: &impl ConnectionTrait) -> anyhow::Result<Vec<String>> {
    retired_tenant_slugs::Entity::find()
        .select_only()
        .column(retired_tenant_slugs::Column::Slug)
        .into_tuple()
        .all(conn)
        .await
        .context("loading retired tenant slugs")
}

/// `tenants` filter: the system tenant, or a tenant whose slug was never
/// retired (one query per request instead of a second lookup).
pub fn servable() -> Condition {
    Condition::any()
        .add(tenants::Column::IsSystem.eq(true))
        .add(
            tenants::Column::Slug.not_in_subquery(
                Query::select()
                    .column(retired_tenant_slugs::Column::Slug)
                    .from(retired_tenant_slugs::Entity)
                    .to_owned(),
            ),
        )
}

#[cfg(test)]
mod tests {
    use sea_orm::{DbBackend, QueryFilter, QueryTrait};

    use super::*;

    #[test]
    fn servable_keeps_the_system_tenant_and_unretired_slugs() {
        let sql = tenants::Entity::find()
            .filter(tenants::Column::Slug.eq("x"))
            .filter(servable())
            .build(DbBackend::Postgres)
            .to_string();
        assert!(
            sql.contains(
                r#"WHERE "tenants"."slug" = 'x' AND ("tenants"."is_system" = TRUE OR "tenants"."slug" NOT IN (SELECT "slug" FROM "retired_tenant_slugs"))"#
            ),
            "{sql}"
        );
    }
}
